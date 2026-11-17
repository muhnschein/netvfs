// SPDX-License-Identifier: LGPL-2.1-or-later
//! GET with ranges (downloads, read handles) and streamed PUT (uploads).

use crate::backend::{Dav, MAX_ERROR_BODY};
use crate::http::{Body, Http, Req};
use crate::status::{Op, error};
use bytes::Bytes;
use http::header::{CONTENT_RANGE, IF_NONE_MATCH, RANGE};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use netvfs_vfs::{
    CancelToken, Disposition, EntryType, ErrorName, Progress, ReadHandle, Sink, Source, Status, WriteOptions,
};
use std::pin::pin;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{Mutex, mpsc};

/// Upload chunk.
pub const CHUNK: usize = 256 * 1024;

fn canceled() -> Status {
    Status::canceled()
}

/// `bytes=<offset>-[<last>]` for `length` bytes from `offset` (`None`: to the end).
///
/// # Errors
/// `Internal` for an empty or overflowing range.
pub fn range(offset: u64, length: Option<u64>) -> Result<HeaderValue, Status> {
    let value = match length {
        None => format!("bytes={offset}-"),
        Some(n) => {
            let last = n
                .checked_sub(1)
                .and_then(|more| offset.checked_add(more))
                .ok_or_else(|| Status::internal("Invalid range"))?;
            format!("bytes={offset}-{last}")
        }
    };
    HeaderValue::from_str(&value).map_err(|_bad| Status::internal("Invalid range"))
}

/// The first byte of `Content-Range: bytes <first>-<last>/<size>`.
#[must_use]
pub fn range_start(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get(CONTENT_RANGE)?.to_str().ok()?;
    let rest = value.trim().strip_prefix("bytes ")?;
    rest.split_once('-')?.0.trim().parse().ok()
}

/// What the body of a GET holds from the wanted offset on.
enum Got {
    /// The body starts `skip` bytes before the wanted offset.
    Body { body: hyper::body::Incoming, skip: u64 },
    /// The offset is at or past the end.
    Nothing,
}

async fn get(http: &mut Http, path: Vec<u8>, offset: u64, length: Option<u64>) -> Result<Got, Status> {
    let mut req = Req::new(Method::GET, path);
    if offset > 0 || length.is_some() {
        req = req.header(RANGE, range(offset, length)?);
    }
    let answer = http.send(req).await?;
    let (head, body) = answer.into_parts();
    match head.status {
        StatusCode::PARTIAL_CONTENT => {
            if range_start(&head.headers) != Some(offset) {
                http.close();
                return Err(Status::new(
                    ErrorName::ProtocolError,
                    "The server sent another part of the file",
                )
                .with_detail(format!("{:?}", head.headers.get(CONTENT_RANGE))));
            }
            Ok(Got::Body { body, skip: 0 })
        }
        // No range support: the whole file.
        StatusCode::OK => Ok(Got::Body { body, skip: offset }),
        StatusCode::RANGE_NOT_SATISFIABLE => {
            http.discard(body, MAX_ERROR_BODY).await;
            Ok(Got::Nothing)
        }
        code => {
            http.discard(body, MAX_ERROR_BODY).await;
            Err(error(code, Op::Other, &head.headers, SystemTime::now()))
        }
    }
}

/// Feeds `body` from `skip` bytes on to `take`, at most `limit` bytes; returns the count. The connection stays
/// usable only when the body was read to its end.
async fn pump(
    http: &mut Http,
    mut body: hyper::body::Incoming,
    mut skip: u64,
    limit: Option<u64>,
    mut take: impl FnMut(&[u8]) -> Result<bool, Status>,
) -> Result<u64, Status> {
    let mut done = 0u64;
    while let Some(chunk) = http.chunk(&mut body).await? {
        let mut data: &[u8] = &chunk;
        if skip > 0 {
            let cut = usize::try_from(skip).unwrap_or(usize::MAX).min(data.len());
            data = data.get(cut..).unwrap_or_default();
            skip = skip.saturating_sub(cut as u64);
        }
        if let Some(limit) = limit {
            let left = usize::try_from(limit.saturating_sub(done)).unwrap_or(usize::MAX);
            data = data.get(..left.min(data.len())).unwrap_or_default();
        }
        if !data.is_empty() {
            done = done.saturating_add(data.len() as u64);
            if !take(data)? {
                http.close();
                return Ok(done);
            }
        }
        if limit.is_some_and(|l| done >= l) {
            // Enough: the rest of the body is not wanted.
            http.close();
            return Ok(done);
        }
    }
    http.done();
    Ok(done)
}

/// `Backend::download`.
///
/// # Errors
/// `IsADirectory`, request errors, the sink's errors, `Canceled`.
pub async fn download(
    dav: &Dav,
    path: &[u8],
    offset: u64,
    length: Option<u64>,
    sink: &mut dyn Sink,
    progress: &mut dyn Progress,
) -> Result<(), Status> {
    let entry = dav.stat(path).await?;
    if entry.kind == EntryType::Directory {
        return Err(Status::new(ErrorName::IsADirectory, "Is a folder"));
    }
    if length == Some(0) {
        return Ok(());
    }
    let total = length.or_else(|| entry.size.map(|s| s.saturating_sub(offset)));
    let decoded = dav.base.resolve(path, false)?;
    let mut http = dav.http.lock().await;
    let Got::Body { body, skip } = get(&mut http, decoded, offset, length).await? else {
        return Ok(());
    };
    let mut moved = 0u64;
    pump(&mut http, body, skip, length, |data| {
        sink.write(data)?;
        moved = moved.saturating_add(data.len() as u64);
        progress.update(moved, total);
        if progress.canceled() { Err(canceled()) } else { Ok(true) }
    })
    .await
    .inspect_err(|_e| http.close())
    .map(drop)
}

/// `Backend::upload`: one PUT, the body streamed from `source`.
///
/// # Errors
/// `AlreadyExists` (`CreateNew`), `Unsupported` (`Resume`), request errors, the source's errors, `Canceled`.
pub async fn upload(
    dav: &Dav,
    path: &[u8],
    options: &WriteOptions,
    source: &mut dyn Source,
    progress: &mut dyn Progress,
) -> Result<(), Status> {
    if options.disposition == Disposition::Resume {
        return Err(Status::unsupported("WebDAV cannot append to a file"));
    }
    let decoded = dav.base.resolve(path, false)?;
    let size = source.size();
    let (tx, rx) = mpsc::channel::<Bytes>(2);
    let mut req = Req::new(Method::PUT, decoded).body(Body::Stream(rx, size));
    if options.disposition == Disposition::CreateNew {
        req = req.header(IF_NONE_MATCH, HeaderValue::from_static("*"));
    }
    let mut http = dav.http.lock().await;
    let feed = async move {
        let mut sent = 0u64;
        loop {
            let mut buf = vec![0u8; CHUNK];
            let n = source.read(&mut buf)?;
            if n == 0 {
                return Ok::<u64, Status>(sent);
            }
            buf.truncate(n);
            sent = sent.saturating_add(n as u64);
            if tx.send(Bytes::from(buf)).await.is_err() {
                // The request ended early; its answer says why.
                return Ok(sent);
            }
            progress.update(sent, size);
            if progress.canceled() {
                return Err(canceled());
            }
        }
    };
    let answer = {
        let mut send = pin!(http.send(req));
        let mut feed = pin!(feed);
        let mut fed = false;
        loop {
            tokio::select! {
                biased;
                answer = &mut send => break answer,
                result = &mut feed, if !fed => {
                    result?;
                    fed = true;
                }
            }
        }
    };
    let (head, body) = answer?.into_parts();
    http.discard(body, MAX_ERROR_BODY).await;
    let ok = head.status.is_success();
    if !ok {
        // The body may be half sent: no reuse.
        http.close();
    }
    drop(http);
    if ok { Ok(()) } else { Err(error(head.status, Op::Put, &head.headers, SystemTime::now())) }
}

/// `Backend::openRead`.
///
/// # Errors
/// `IsADirectory`, request errors.
pub async fn open_read(dav: &Dav, path: &[u8]) -> Result<WebdavRead, Status> {
    let entry = dav.stat(path).await?;
    if entry.kind == EntryType::Directory {
        return Err(Status::new(ErrorName::IsADirectory, "Is a folder"));
    }
    Ok(WebdavRead { http: Arc::clone(&dav.http), path: dav.base.resolve(path, false)?, size: entry.size })
}

/// A file read with one ranged GET per read.
#[derive(Debug)]
pub struct WebdavRead {
    http: Arc<Mutex<Http>>,
    path: Vec<u8>,
    size: Option<u64>,
}

impl ReadHandle for WebdavRead {
    fn size(&self) -> Option<u64> {
        self.size
    }

    async fn read(&mut self, offset: u64, buf: &mut [u8], cancel: &CancelToken) -> Result<usize, Status> {
        if buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len() as u64;
        let work = async {
            let mut http = self.http.lock().await;
            let Got::Body { body, skip } = get(&mut http, self.path.clone(), offset, Some(want)).await?
            else {
                return Ok(0);
            };
            let mut filled = 0usize;
            pump(&mut http, body, skip, Some(want), |data| {
                let end = filled.saturating_add(data.len());
                buf.get_mut(filled..end)
                    .ok_or_else(|| Status::internal("read past the buffer"))?
                    .copy_from_slice(data);
                filled = end;
                Ok(true)
            })
            .await?;
            Ok(filled)
        };
        cancel.guard(work).await
    }

    fn read_ahead(&mut self, _offset: u64, _bytes: u64) {}

    async fn close(self, _cancel: &CancelToken) -> Result<(), Status> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(range(0, None).unwrap(), "bytes=0-");
        assert_eq!(range(5, Some(1)).unwrap(), "bytes=5-5");
        assert_eq!(range(5, Some(10)).unwrap(), "bytes=5-14");
        assert_eq!(range(u64::MAX, Some(1)).unwrap(), format!("bytes={0}-{0}", u64::MAX).as_str());
        range(u64::MAX, Some(2)).unwrap_err();
        range(0, Some(0)).unwrap_err();
    }

    #[test]
    fn range_starts() {
        let mut h = HeaderMap::new();
        assert_eq!(range_start(&h), None);
        for (value, want) in [
            ("bytes 5-9/10", Some(5)),
            (" bytes 0-0/1 ", Some(0)),
            ("bytes */10", None),
            ("items 5-9/10", None),
            ("bytes x-9/10", None),
        ] {
            h.insert(CONTENT_RANGE, HeaderValue::from_static(value));
            assert_eq!(range_start(&h), want, "{value}");
        }
    }
}
