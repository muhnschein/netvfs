// SPDX-License-Identifier: LGPL-2.1-or-later
//! The WebDAV [`Backend`] (provider `webdav`): HTTPS only, Basic auth only over TLS.
//!
//! Options: `base_path` (the account's folder on the server), `host_key` (pinned TLS key). No credentials go
//! out before the identity check: `connect` only shakes hands, `authenticate` sends the first request.

use crate::http::{ALPN, Body, Http, Req, STALE_AFTER, Target};
use crate::io::{self, WebdavRead};
use crate::paths::{Base, child_name, encode, last_name, same};
use crate::status::{Op, error, unresolved};
use crate::xml::{self, PROPFIND_ENTRY, PROPFIND_QUOTA, Props, Response};
use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderName};
use http::{HeaderValue, Method, StatusCode};
use netvfs_tls::{Anchors, Client as Tls};
use netvfs_vfs::{
    Backend, CancelToken, Capabilities, Capability, Credentials, Entry, EntryFlags, EntryType, ErrorName,
    ListOptions, ListSink, NoHandle, Params, Progress, Prompter, RenameMode, ServerIdentity, Sink, Source,
    SpaceInfo, Status, WriteOptions, Zeroizing,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;

/// HTTPS.
pub const DEFAULT_PORT: u16 = 443;
/// Connect timeout when the caller gives none.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Request timeout when the caller gives none.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_mins(1);
/// Largest multistatus read: a folder of some 50 000 entries.
pub const MAX_MULTISTATUS: usize = 32 * 1024 * 1024;
/// Largest error page read before the connection is dropped instead.
pub const MAX_ERROR_BODY: usize = 64 * 1024;

const DEPTH: HeaderName = HeaderName::from_static("depth");
const DESTINATION: HeaderName = HeaderName::from_static("destination");
const OVERWRITE: HeaderName = HeaderName::from_static("overwrite");
const MULTI_STATUS: u16 = 207;

/// What `connect` takes from the parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Where to connect.
    pub target: Target,
    /// The account's folder.
    pub base: Base,
    /// The user name when the credentials name none.
    pub username: String,
    /// `host_key`: the pinned key, `tls-spki-sha256 <base64>`.
    pub pin: Option<String>,
}

impl Settings {
    /// The settings of `params`.
    ///
    /// # Errors
    /// `Internal` for an empty host or one holding `@` or `/`, or a port out of range; `InvalidName` for a bad
    /// `base_path`.
    pub fn of(params: &Params) -> Result<Self, Status> {
        let (host, port) = netvfs_tls::host_port(params, DEFAULT_PORT)?;
        Ok(Self {
            target: Target {
                host,
                port,
                connect_timeout: netvfs_tls::timeout_or(params.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT),
                request_timeout: netvfs_tls::timeout_or(params.request_timeout_ms, DEFAULT_REQUEST_TIMEOUT),
                stale_after: STALE_AFTER,
            },
            base: Base::new(&params.option("base_path").unwrap_or_default())?,
            username: params.username.clone(),
            pin: params.option("host_key").filter(|p| !p.is_empty()),
        })
    }
}

/// The `Authorization` value of `user` and `secret`; `None` for neither.
///
/// # Errors
/// `AuthFailed` for a user name with `:` (Basic cannot carry it) or bytes a header cannot hold.
pub fn basic(user: &str, secret: &[u8]) -> Result<Option<HeaderValue>, Status> {
    if user.is_empty() && secret.is_empty() {
        return Ok(None);
    }
    if user.contains(':') {
        return Err(Status::new(ErrorName::AuthFailed, "A user name with ':' cannot sign in to WebDAV"));
    }
    let mut pair =
        Zeroizing::new(Vec::with_capacity(user.len().saturating_add(secret.len()).saturating_add(1)));
    pair.extend_from_slice(user.as_bytes());
    pair.push(b':');
    pair.extend_from_slice(secret);
    let value = Zeroizing::new(format!("Basic {}", data_encoding::BASE64.encode(&pair)));
    let mut header = HeaderValue::from_str(&value)
        .map_err(|_bad| Status::new(ErrorName::AuthFailed, "Unusable credentials"))?;
    header.set_sensitive(true);
    Ok(Some(header))
}

/// The entry of `name` with `props`.
#[must_use]
pub fn entry(name: &[u8], props: &Props) -> Entry {
    Entry {
        name: name.to_vec(),
        flags: if std::str::from_utf8(name).is_ok() { EntryFlags::NONE } else { EntryFlags::NAME_NOT_UTF8 },
        kind: if props.collection { EntryType::Directory } else { EntryType::File },
        size: if props.collection { None } else { props.length },
        mtime_ms: props.modified_ms,
        etag: props.etag.clone(),
        content_type: props.content_type.clone(),
        ..Entry::default()
    }
}

/// The file operations of a signed-in connection.
#[derive(Debug)]
pub struct Dav {
    /// The connection, shared with read handles.
    pub http: Arc<Mutex<Http>>,
    /// The account's folder.
    pub base: Base,
    /// Whether the account's folder reported a quota at sign-in (`SpaceInfo`).
    pub quota: bool,
}

/// PROPFIND `depth` on decoded `path`.
///
/// # Errors
/// The answer's error; `ProtocolError` for anything but a multistatus.
pub async fn propfind(
    http: &mut Http,
    path: Vec<u8>,
    depth: &'static str,
    body: &'static str,
) -> Result<Vec<Response>, Status> {
    let req = Req::new(Method::from_bytes(b"PROPFIND").map_err(|e| Status::internal(e.to_string()))?, path)
        .header(DEPTH, HeaderValue::from_static(depth))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"))
        .body(Body::Full(Some(Bytes::from_static(body.as_bytes()))));
    let answer = http.send(req).await?;
    let (head, body) = answer.into_parts();
    if head.status.as_u16() != MULTI_STATUS {
        let e = if head.status.is_success() {
            Status::new(ErrorName::ProtocolError, "The server does not speak WebDAV at this address")
                .with_detail(format!("HTTP {}", head.status))
        } else {
            error(head.status, Op::Other, &head.headers, SystemTime::now())
        };
        http.discard(body, MAX_ERROR_BODY).await;
        return Err(e);
    }
    let bytes = http.read_all(body, MAX_MULTISTATUS).await?;
    xml::parse(&bytes)
}

/// A request without body whose answer only counts by its status.
///
/// # Errors
/// The answer's error.
pub async fn simple(http: &mut Http, req: Req, op: Op) -> Result<StatusCode, Status> {
    let answer = http.send(req).await?;
    let (head, body) = answer.into_parts();
    http.discard(body, MAX_ERROR_BODY).await;
    if head.status.is_success() {
        Ok(head.status)
    } else {
        Err(error(head.status, op, &head.headers, SystemTime::now()))
    }
}

impl Dav {
    /// The entry at location path `path`.
    ///
    /// # Errors
    /// `NotFound`, and request errors.
    pub async fn stat(&self, path: &[u8]) -> Result<Entry, Status> {
        let decoded = self.base.resolve(path, false)?;
        let answer = propfind(&mut *self.http.lock().await, decoded, "0", PROPFIND_ENTRY).await;
        let found = match answer {
            Ok(found) => found,
            Err(e) => return Err(self.explain(path, e).await),
        };
        let first = found
            .into_iter()
            .next()
            .ok_or_else(|| Status::new(ErrorName::NotFound, "No such file or folder"))?;
        Ok(entry(last_name(path), &first.props))
    }

    /// The entries of folder `dir`.
    ///
    /// # Errors
    /// `NotADirectory` for a file, and request errors.
    pub async fn entries(
        &self,
        dir: &[u8],
        body: &'static str,
    ) -> Result<(Option<Props>, Vec<Entry>), Status> {
        // No trailing `/` in the request: Apache answers 400 to one after a file's name.
        let target = self.base.resolve(dir, false)?;
        let decoded = self.base.resolve(dir, true)?;
        let answer = propfind(&mut *self.http.lock().await, target, "1", body).await;
        let found = match answer {
            Ok(found) => found,
            Err(e) => return Err(self.explain(dir, e).await),
        };
        let mut own = None;
        let mut entries = Vec::new();
        for r in found {
            if same(&r.path, &decoded) {
                own = Some(r.props);
            } else if let Some(name) = child_name(&decoded, &r.path) {
                entries.push(entry(name, &r.props));
            }
        }
        if own.as_ref().is_some_and(|p| !p.collection) {
            return Err(Status::new(ErrorName::NotADirectory, "Not a folder"));
        }
        Ok((own, entries))
    }

    /// The account's folder with its quota; `NotADirectory` for a file.
    async fn folder(&self) -> Result<Option<Props>, Status> {
        let decoded = self.base.resolve(b"", false)?;
        let found = propfind(&mut *self.http.lock().await, decoded, "0", PROPFIND_QUOTA).await?;
        let own = found.into_iter().next().map(|r| r.props);
        if own.as_ref().is_some_and(|p| !p.collection) {
            return Err(Status::new(ErrorName::NotADirectory, "Not a folder"));
        }
        Ok(own)
    }

    async fn make_dir(&self, path: &[u8], exclusive: bool) -> Result<(), Status> {
        let decoded = self.base.resolve(path, false)?;
        let made = {
            let mut http = self.http.lock().await;
            simple(
                &mut http,
                Req::new(Method::from_bytes(b"MKCOL").map_err(|e| Status::internal(e.to_string()))?, decoded),
                Op::MakeDir,
            )
            .await
        };
        match made {
            Err(e) if e.name == ErrorName::AlreadyExists && !exclusive => {
                if self.stat(path).await?.kind == EntryType::Directory { Ok(()) } else { Err(e) }
            }
            Err(e) => Err(self.explain(path, e).await),
            Ok(_) => Ok(()),
        }
    }

    async fn remove_file(&self, path: &[u8]) -> Result<(), Status> {
        if self.stat(path).await?.kind == EntryType::Directory {
            return Err(Status::new(ErrorName::IsADirectory, "Is a folder"));
        }
        let decoded = self.base.resolve(path, false)?;
        let mut http = self.http.lock().await;
        simple(&mut http, Req::new(Method::DELETE, decoded), Op::Other).await.map(drop)
    }

    async fn remove_dir(&self, path: &[u8]) -> Result<(), Status> {
        if last_name(path).is_empty() {
            return Err(Status::permission_denied("Refusing to remove the account's folder"));
        }
        let (own, entries) = self.entries(path, PROPFIND_ENTRY).await?;
        if own.is_none() {
            return Err(Status::new(ErrorName::NotFound, "No such folder"));
        }
        if !entries.is_empty() {
            return Err(Status::new(ErrorName::DirectoryNotEmpty, "The folder is not empty"));
        }
        let decoded = self.base.resolve(path, true)?;
        let mut http = self.http.lock().await;
        simple(&mut http, Req::new(Method::DELETE, decoded), Op::Other).await.map(drop)
    }

    /// MOVE or COPY `from` to `to`.
    async fn transfer(
        &self,
        method: &'static [u8],
        from: &[u8],
        to: &[u8],
        mode: RenameMode,
        recursive: bool,
    ) -> Result<(), Status> {
        let source = self.stat(from).await?;
        let folder = source.kind == EntryType::Directory;
        if folder && !recursive {
            return Err(Status::new(ErrorName::IsADirectory, "Copying a folder needs a recursive copy"));
        }
        let src = self.base.resolve(from, folder)?;
        let dst = self.base.resolve(to, false)?;
        if same(&src, &dst) {
            return Ok(());
        }
        if mode == RenameMode::Replace {
            match self.stat(to).await {
                Ok(target) if folder || target.kind == EntryType::Directory => {
                    return Err(Status::new(ErrorName::AlreadyExists, "A folder cannot be replaced"));
                }
                Ok(_) => {}
                Err(e) if e.name == ErrorName::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let destination =
            HeaderValue::from_str(&format!("{}{}", self.http.lock().await.origin(), encode(&dst)))
                .map_err(|_bad| Status::invalid_name("Unusable target path"))?;
        let overwrite = HeaderValue::from_static(if mode == RenameMode::Replace { "T" } else { "F" });
        let depth = HeaderValue::from_static(if folder { "infinity" } else { "0" });
        let req = Req::new(Method::from_bytes(method).map_err(|e| Status::internal(e.to_string()))?, src)
            .header(DESTINATION, destination)
            .header(OVERWRITE, overwrite)
            .header(DEPTH, depth);
        let moved = simple(&mut *self.http.lock().await, req, Op::Other).await;
        match moved {
            Ok(_) => Ok(()),
            Err(e) => Err(self.explain(to, e).await),
        }
    }

    /// `e` of a request on `path`, said better when the server could not resolve the path (`unresolved`): the
    /// nearest ancestor that answers tells `NotFound` (missing) or `NotADirectory` (a file).
    async fn explain(&self, path: &[u8], e: Status) -> Status {
        if !unresolved(&e) {
            return e;
        }
        let mut parent = path;
        while let Some(at) = parent.iter().rposition(|b| *b == b'/') {
            parent = parent.get(..at).unwrap_or_default();
            if parent.iter().all(|b| *b == b'/') {
                break;
            }
            let Ok(decoded) = self.base.resolve(parent, false) else { break };
            let answer = propfind(&mut *self.http.lock().await, decoded, "0", PROPFIND_ENTRY).await;
            match answer.map(|found| found.into_iter().next().map(|r| r.props.collection)) {
                Ok(Some(false)) => return Status::new(ErrorName::NotADirectory, "A file is in the path"),
                Err(found) if found.name == ErrorName::NotFound => {
                    return Status::new(ErrorName::NotFound, "The parent folder does not exist");
                }
                Err(again) if unresolved(&again) => {}
                Ok(Some(true) | None) | Err(_) => break,
            }
        }
        e
    }

    async fn space_info(&self, dir: &[u8]) -> Result<SpaceInfo, Status> {
        let decoded = self.base.resolve(dir, false)?;
        let found = propfind(&mut *self.http.lock().await, decoded, "0", PROPFIND_QUOTA).await?;
        let props = found.into_iter().next().map(|r| r.props).unwrap_or_default();
        if props.quota_available.is_none() && props.quota_used.is_none() {
            return Err(Status::unsupported("The server reports no free space"));
        }
        let total = props.quota_available.zip(props.quota_used).and_then(|(a, u)| a.checked_add(u));
        Ok(SpaceInfo { free: props.quota_available, total, used: props.quota_used })
    }

    async fn keep_alive(&self) -> Result<(), Status> {
        let decoded = self.base.resolve(b"", true)?;
        let mut http = self.http.lock().await;
        simple(&mut http, Req::new(Method::OPTIONS, decoded), Op::Other).await.map(drop)
    }
}

/// Connected, not signed in.
#[derive(Debug)]
struct Connected {
    http: Http,
    settings: Settings,
    mismatch: bool,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Idle,
    Connected(Box<Connected>),
    Ready(Box<Dav>),
}

/// One WebDAV connection.
#[derive(Debug)]
pub struct Webdav {
    state: State,
    anchors: Anchors,
}

impl Default for Webdav {
    fn default() -> Self {
        Self::new()
    }
}

fn not_signed_in() -> Status {
    Status::internal("Not signed in")
}

impl Webdav {
    /// Not connected; system CAs.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_anchors(Anchors::System)
    }

    /// Not connected; `anchors` make a certificate system trusted (tests).
    #[must_use]
    pub const fn with_anchors(anchors: Anchors) -> Self {
        Self { state: State::Idle, anchors }
    }

    async fn close(&mut self) {
        match std::mem::take(&mut self.state) {
            State::Idle => {}
            State::Connected(mut c) => c.http.close(),
            State::Ready(dav) => dav.http.lock().await.end(),
        }
    }

    fn dav(&self, cancel: &CancelToken) -> Result<&Dav, Status> {
        let State::Ready(dav) = &self.state else {
            return Err(not_signed_in());
        };
        cancel.check()?;
        Ok(dav)
    }
}

const fn capabilities() -> [Capability; 6] {
    [
        Capability::ReadHandles,
        Capability::NativeNoReplace,
        Capability::ServerCopy,
        Capability::ServerCopyRecursive,
        Capability::SpaceInfo,
        Capability::ETags,
    ]
}

impl Backend for Webdav {
    type Read = WebdavRead;
    type Write = NoHandle;

    async fn connect(
        &mut self,
        params: &Params,
        cancel: &CancelToken,
    ) -> Result<Option<ServerIdentity>, Status> {
        self.close().await;
        cancel.check()?;
        let settings = Settings::of(params)?;
        let tls = Tls::new(&settings.target.host, &[ALPN], &self.anchors)?;
        let mut http = Http::new(tls, settings.target.clone())?;
        cancel.guard(http.open()).await?;
        let identity = http.tls().settle(settings.pin.is_some());
        let mismatch = netvfs_tls::refuses_credentials(settings.pin.as_deref(), http.tls().seen().as_ref());
        self.state = State::Connected(Box::new(Connected { http, settings, mismatch }));
        Ok(identity)
    }

    async fn authenticate(
        &mut self,
        credentials: &Credentials,
        _prompter: Option<&mut dyn Prompter>,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let mut connected = match std::mem::take(&mut self.state) {
            State::Connected(c) => c,
            other => {
                self.state = other;
                return Err(Status::internal("authenticate() needs a fresh connection"));
            }
        };
        if connected.mismatch {
            // No credentials go to a server whose key is not the pin.
            self.state = State::Connected(connected);
            return Err(netvfs_tls::identity_changed());
        }
        let user = if credentials.user.is_empty() { &connected.settings.username } else { &credentials.user };
        match basic(user, &credentials.secret) {
            Ok(Some(auth)) => connected.http.set_auth(auth),
            Ok(None) => {}
            Err(e) => {
                self.state = State::Connected(connected);
                return Err(e);
            }
        }
        let Connected { http, settings, .. } = *connected;
        let mut dav = Dav { http: Arc::new(Mutex::new(http)), base: settings.base, quota: false };
        let probe = cancel.guard(dav.folder()).await;
        match probe {
            Ok(Some(own)) => {
                dav.quota = own.quota_available.is_some() || own.quota_used.is_some();
                self.state = State::Ready(Box::new(dav));
                Ok(())
            }
            Ok(None) => Err(Status::new(ErrorName::ProtocolError, "The server did not describe the folder")),
            Err(e) if e.name == ErrorName::NotFound => {
                Err(Status::new(ErrorName::NotFound, "No WebDAV folder at this address")
                    .with_detail(e.detail))
            }
            Err(e) => Err(e),
        }
    }

    fn capabilities(&self) -> Capabilities {
        match &self.state {
            State::Ready(dav) => Capabilities {
                flags: capabilities()
                    .into_iter()
                    .filter(|c| dav.quota || *c != Capability::SpaceInfo)
                    .collect(),
                ..Capabilities::default()
            },
            State::Idle | State::Connected(_) => Capabilities::default(),
        }
    }

    async fn disconnect(&mut self) {
        self.close().await;
    }

    async fn keep_alive(&mut self, cancel: &CancelToken) -> Result<(), Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(dav.keep_alive()).await
    }

    async fn stat(&mut self, path: &[u8], _follow: bool, cancel: &CancelToken) -> Result<Entry, Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(dav.stat(path)).await
    }

    async fn list(
        &mut self,
        dir: &[u8],
        options: ListOptions,
        sink: &mut dyn ListSink,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let dav = self.dav(cancel)?;
        let (own, entries) = cancel.guard(dav.entries(dir, PROPFIND_ENTRY)).await?;
        if own.is_none() && entries.is_empty() {
            return Err(Status::new(ErrorName::NotFound, "No such folder"));
        }
        for batch in entries.chunks(options.batch_size.max(1)) {
            cancel.check()?;
            if !sink.entries(batch) {
                return Err(Status::canceled());
            }
        }
        Ok(())
    }

    async fn make_dir(&mut self, path: &[u8], exclusive: bool, cancel: &CancelToken) -> Result<(), Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(dav.make_dir(path, exclusive)).await
    }

    async fn remove_file(&mut self, path: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(dav.remove_file(path)).await
    }

    async fn remove_dir(&mut self, path: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(dav.remove_dir(path)).await
    }

    async fn rename(
        &mut self,
        from: &[u8],
        to: &[u8],
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(dav.transfer(b"MOVE", from, to, mode, true)).await
    }

    async fn copy(
        &mut self,
        from: &[u8],
        to: &[u8],
        recursive: bool,
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(dav.transfer(b"COPY", from, to, mode, recursive)).await
    }

    async fn space_info(&mut self, dir: &[u8], cancel: &CancelToken) -> Result<SpaceInfo, Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(dav.space_info(dir)).await
    }

    async fn open_read(&mut self, path: &[u8], cancel: &CancelToken) -> Result<WebdavRead, Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(io::open_read(dav, path)).await
    }

    async fn upload(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        source: &mut dyn Source,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(io::upload(dav, path, options, source, progress)).await
    }

    async fn download(
        &mut self,
        path: &[u8],
        offset: u64,
        length: Option<u64>,
        sink: &mut dyn Sink,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let dav = self.dav(cancel)?;
        cancel.guard(io::download(dav, path, offset, length, sink, progress)).await
    }
}

#[cfg(test)]
mod tests;
