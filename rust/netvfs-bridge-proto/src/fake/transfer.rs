// SPDX-License-Identifier: LGPL-2.1-or-later
//! Jobs and listings of the fake: the work behind `List`, `Upload`, `Download`, `CopyAcross`,
//! `RemoveTree`, `Walk`. Local data moves through the descriptors the client passed, at explicit
//! offsets for regular files, sequentially for pipes.

use super::args::{CopyOpts, Disposition, TransferOpts, WalkOpts};
use super::fail::Fail;
use super::iface::{Iface, ask_question};
use super::state::{InfoValue, JobFailure, RecordedAnswer, Session, Shared};
use super::tree::Tree;
use crate::errors::ErrorName;
use crate::wire::{WireEntry, WireWalkItem};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedValue, Value};

const EBADF: i32 = 9;
const WALK_BATCH: usize = 64;

type Extra = HashMap<String, Value<'static>>;

pub(super) struct Env {
    pub shared: Arc<Shared>,
    pub session: Arc<Session>,
    pub ctx: SignalEmitter<'static>,
}

impl Env {
    pub async fn ask(&self, kind: &str, details: &[(String, InfoValue)]) -> Option<RecordedAnswer> {
        ask_question(&self.shared, &self.session, &self.ctx, kind, details).await
    }

    fn chunk(&self) -> usize {
        self.shared.with(|s| s.chunk).max(1)
    }

    async fn pause(&self) {
        let latency = self.shared.with(|s| s.latency);
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
        }
    }

    async fn progress(&self, job: u32, done: u64, total: Option<u64>) {
        let done = i64::try_from(done).unwrap_or(i64::MAX);
        let total = total.map_or(-1, |t| i64::try_from(t).unwrap_or(i64::MAX));
        Iface::job_progress(&self.ctx, job, done, total).await.ok();
    }

    async fn finish(&self, job: u32, result: Result<Extra, Fail>) {
        let (error, message, extra) = match result {
            Ok(extra) => (String::new(), String::new(), extra),
            Err(f) => (f.bare().to_owned(), f.message().to_owned(), f.extra()),
        };
        self.session.finish_job(job);
        let extra: HashMap<String, OwnedValue> =
            extra.into_iter().filter_map(|(k, v)| OwnedValue::try_from(v).ok().map(|o| (k, o))).collect();
        Iface::job_finished(&self.ctx, job, error, message, extra).await.ok();
    }

    fn job_failure(&self, method: &str) -> Option<JobFailure> {
        self.shared.with(|s| s.due_job_failure(method))
    }
}

fn job_fail(f: &JobFailure) -> Fail {
    Fail::scripted(&f.name, &f.message).with_detail(f.detail.clone(), f.retry_after_ms)
}

fn canceled() -> Fail {
    Fail::net(ErrorName::Canceled, "The job was canceled")
}

fn bytes_extra(done: u64) -> Extra {
    let mut extra = Extra::new();
    extra.insert("bytes".to_owned(), Value::from(i64::try_from(done).unwrap_or(i64::MAX)));
    extra
}

pub(super) struct Source {
    file: Arc<File>,
    fifo: bool,
}

impl Source {
    pub fn new(file: File) -> Result<Self, Fail> {
        let kind = file
            .metadata()
            .map_err(|e| {
                Fail::net(
                    ErrorName::PermissionDenied,
                    &format!("The file descriptor cannot be inspected: {e}"),
                )
            })?
            .file_type();
        let fifo = kind.is_fifo();
        if !fifo && !kind.is_file() {
            return Err(Fail::net(
                ErrorName::PermissionDenied,
                "The descriptor is neither a regular file nor a pipe",
            ));
        }
        Ok(Self { file: Arc::new(file), fifo })
    }

    fn len(&self) -> u64 {
        self.file.metadata().map_or(0, |m| m.len())
    }

    async fn read(&self, at: u64, max: usize) -> Result<Vec<u8>, Fail> {
        let file = Arc::clone(&self.file);
        let fifo = self.fifo;
        let joined = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; max];
            let n = if fifo { (&*file).read(&mut buf) } else { file.read_at(&mut buf, at) }?;
            buf.truncate(n);
            Ok::<_, std::io::Error>(buf)
        })
        .await;
        match joined {
            Ok(Ok(buf)) => Ok(buf),
            Ok(Err(e)) => Err(io_fail(&e)),
            Err(_) => Err(Fail::net(ErrorName::Internal, "The reader stopped")),
        }
    }

    async fn write(&self, at: u64, data: Vec<u8>) -> Result<(), Fail> {
        let file = Arc::clone(&self.file);
        let fifo = self.fifo;
        let joined = tokio::task::spawn_blocking(move || {
            if fifo { std::io::Write::write_all(&mut &*file, &data) } else { file.write_all_at(&data, at) }
        })
        .await;
        match joined {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(io_fail(&e)),
            Err(_) => Err(Fail::net(ErrorName::Internal, "The writer stopped")),
        }
    }
}

fn io_fail(e: &std::io::Error) -> Fail {
    if e.raw_os_error() == Some(EBADF) {
        // Descriptor not opened for what the job needs.
        Fail::net(ErrorName::PermissionDenied, "The descriptor does not allow this access")
    } else {
        Fail::net(ErrorName::Internal, &e.to_string())
    }
}

pub(super) async fn run_list(
    env: Env,
    req: u32,
    listing: Result<Vec<WireEntry>, Fail>,
    batch: usize,
    cancel: Arc<AtomicBool>,
) {
    let outcome = match listing {
        Ok(entries) => send_batches(&env, req, entries, batch, &cancel).await,
        Err(f) => Err(f),
    };
    let (error, message) = match outcome {
        Ok(()) => (String::new(), String::new()),
        Err(f) => (f.bare().to_owned(), f.message().to_owned()),
    };
    env.session.finish_job(req);
    Iface::list_done(&env.ctx, req, error, message).await.ok();
}

async fn send_batches(
    env: &Env,
    req: u32,
    entries: Vec<WireEntry>,
    batch: usize,
    cancel: &AtomicBool,
) -> Result<(), Fail> {
    for chunk in entries.chunks(batch) {
        if cancel.load(Ordering::SeqCst) {
            return Err(canceled());
        }
        env.pause().await;
        Iface::list_batch(&env.ctx, req, chunk.to_vec()).await.ok();
    }
    Ok(())
}

pub(super) async fn run_upload(
    env: Env,
    job: u32,
    cancel: Arc<AtomicBool>,
    loc: String,
    path: Vec<u8>,
    src: Source,
    opts: TransferOpts,
) {
    let failure = env.job_failure("Upload");
    let result = upload(&env, job, &cancel, (&loc, &path), &src, &opts, failure).await;
    env.finish(job, result).await;
}

fn upload_start(tree: &Tree, path: &[u8], opts: &TransferOpts) -> Result<usize, Fail> {
    let existing = tree.node(path).is_some();
    match opts.disposition {
        Disposition::Create if existing => Err(Fail::net(ErrorName::AlreadyExists, "The destination exists")),
        Disposition::Resume => {
            let at = usize::try_from(opts.offset).unwrap_or(usize::MAX);
            if tree.file_len(path) == Some(at) {
                Ok(at)
            } else {
                Err(Fail::net(ErrorName::Internal, "The resume offset does not match the destination"))
            }
        }
        _ => Ok(0),
    }
}

async fn upload(
    env: &Env,
    job: u32,
    cancel: &AtomicBool,
    target: (&str, &[u8]),
    src: &Source,
    opts: &TransferOpts,
    failure: Option<JobFailure>,
) -> Result<Extra, Fail> {
    let (loc, path) = target;
    let at = env.shared.with(|s| upload_start(s.tree_mut(loc), path, opts))?;
    let offset = u64::try_from(opts.offset).unwrap_or(0);
    let size = u64::try_from(opts.size).ok();
    let length = match (src.fifo, size) {
        (false, None) => Some(src.len().saturating_sub(offset)),
        (_, size) => size,
    };
    let mut data = Vec::new();
    let mut done = 0u64;
    let mut outcome = Ok(());
    loop {
        if let Some(f) = failure.as_ref().filter(|f| done >= f.after_bytes) {
            outcome = Err(job_fail(f));
            break;
        }
        match upload_step(env, job, cancel, src, (offset, done, length), &mut data).await {
            Ok(0) => break,
            Ok(n) => done = done.saturating_add(n),
            Err(e) => {
                outcome = Err(e);
                break;
            }
        }
    }
    // A failed upload leaves what arrived so it can be resumed.
    env.shared.with(|s| s.tree_mut(loc).write_file(path, at, &data, opts.mtime_ms))?;
    outcome.map(|()| bytes_extra(done))
}

async fn upload_step(
    env: &Env,
    job: u32,
    cancel: &AtomicBool,
    src: &Source,
    (offset, done, length): (u64, u64, Option<u64>),
    data: &mut Vec<u8>,
) -> Result<u64, Fail> {
    if cancel.load(Ordering::SeqCst) {
        return Err(canceled());
    }
    let remaining = length.map(|l| l.saturating_sub(done));
    if remaining == Some(0) {
        return Ok(0);
    }
    let chunk = env.chunk();
    let want = remaining.map_or(chunk, |r| usize::try_from(r).unwrap_or(usize::MAX).min(chunk));
    let at = if src.fifo { 0 } else { offset.saturating_add(done) };
    let part = src.read(at, want).await?;
    data.extend_from_slice(&part);
    let moved = u64::try_from(part.len()).unwrap_or(u64::MAX);
    env.progress(job, done.saturating_add(moved), length).await;
    env.pause().await;
    Ok(moved)
}

pub(super) async fn run_download(
    env: Env,
    job: u32,
    cancel: Arc<AtomicBool>,
    loc: String,
    path: Vec<u8>,
    dst: Source,
    opts: TransferOpts,
) {
    let failure = env.job_failure("Download");
    let result = download(&env, job, &cancel, (&loc, &path), &dst, &opts, failure).await;
    env.finish(job, result).await;
}

async fn download(
    env: &Env,
    job: u32,
    cancel: &AtomicBool,
    target: (&str, &[u8]),
    dst: &Source,
    opts: &TransferOpts,
    failure: Option<JobFailure>,
) -> Result<Extra, Fail> {
    let (loc, path) = target;
    let data = env.shared.with(|s| s.tree_mut(loc).file_data(path).map(<[u8]>::to_vec))?;
    let start = usize::try_from(opts.offset).unwrap_or(usize::MAX).min(data.len());
    let end = usize::try_from(opts.size).ok().map_or(data.len(), |n| start.saturating_add(n).min(data.len()));
    let body = data.get(start..end).unwrap_or_default();
    let total = u64::try_from(body.len()).unwrap_or(u64::MAX);
    let mut pieces = body.chunks(env.chunk());
    let mut done = 0u64;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(canceled());
        }
        if let Some(f) = failure.as_ref().filter(|f| done >= f.after_bytes) {
            return Err(job_fail(f));
        }
        let Some(piece) = pieces.next() else {
            break;
        };
        let at = if dst.fifo { 0 } else { opts.offset.unsigned_abs().saturating_add(done) };
        dst.write(at, piece.to_vec()).await?;
        done = done.saturating_add(u64::try_from(piece.len()).unwrap_or(u64::MAX));
        env.progress(job, done, Some(total)).await;
        env.pause().await;
    }
    Ok(bytes_extra(done))
}

pub(super) async fn run_remove_tree(env: Env, job: u32, cancel: Arc<AtomicBool>, loc: String, path: Vec<u8>) {
    let failure = env.job_failure("RemoveTree");
    let result = if cancel.load(Ordering::SeqCst) {
        Err(canceled())
    } else if let Some(f) = failure {
        Err(job_fail(&f))
    } else {
        env.shared.with(|s| s.tree_mut(&loc).remove_tree(&path)).map_err(Fail::from).map(|c| {
            let mut extra = Extra::new();
            extra.insert("files".to_owned(), Value::from(c.files));
            extra.insert("dirs".to_owned(), Value::from(c.dirs));
            extra
        })
    };
    env.finish(job, result).await;
}

pub(super) async fn run_walk(
    env: Env,
    job: u32,
    cancel: Arc<AtomicBool>,
    loc: String,
    root: Vec<u8>,
    opts: WalkOpts,
) {
    let listing = env
        .shared
        .with(|s| s.tree_mut(&loc).walk(&root, opts.max_depth, opts.post_order))
        .map_err(Fail::from);
    let result = match listing {
        Ok(items) => walk_batches(&env, job, &cancel, items).await,
        Err(f) => Err(f),
    };
    env.finish(job, result).await;
}

async fn walk_batches(
    env: &Env,
    job: u32,
    cancel: &AtomicBool,
    items: Vec<(Vec<u8>, WireEntry)>,
) -> Result<Extra, Fail> {
    let count = items.len();
    for chunk in items.chunks(WALK_BATCH) {
        if cancel.load(Ordering::SeqCst) {
            return Err(canceled());
        }
        env.pause().await;
        let batch: Vec<WireWalkItem> = chunk
            .iter()
            .map(|(path, entry)| WireWalkItem { path: path.clone(), entry: entry.clone() })
            .collect();
        Iface::walk_batch(&env.ctx, job, batch).await.ok();
    }
    let mut extra = Extra::new();
    extra.insert("entries".to_owned(), Value::from(i64::try_from(count).unwrap_or(i64::MAX)));
    Ok(extra)
}

pub(super) async fn run_copy_across(
    env: Env,
    job: u32,
    cancel: Arc<AtomicBool>,
    src: (String, Vec<u8>),
    dst: (String, Vec<u8>),
    opts: CopyOpts,
) {
    let failure = env.job_failure("CopyAcross");
    let result = if cancel.load(Ordering::SeqCst) {
        Err(canceled())
    } else if let Some(f) = failure {
        Err(job_fail(&f))
    } else {
        copy_across(&env, &src, &dst, &opts)
    };
    if let Ok(extra) = &result {
        let bytes = extra.get("bytes").and_then(|v| crate::wire::value_i64(v)).unwrap_or(0);
        env.progress(job, u64::try_from(bytes).unwrap_or(0), u64::try_from(bytes).ok()).await;
    }
    env.finish(job, result).await;
}

fn copy_across(
    env: &Env,
    src: &(String, Vec<u8>),
    dst: &(String, Vec<u8>),
    opts: &CopyOpts,
) -> Result<Extra, Fail> {
    let items = env.shared.with(|s| s.tree_mut(&src.0).export(&src.1, opts.recursive))?;
    let bytes: u64 = items
        .iter()
        .map(|(_, n)| match n {
            super::tree::Node::File { data, .. } => data.len() as u64,
            _ => 0,
        })
        .sum();
    env.shared.with(|s| s.tree_mut(&dst.0).import(&dst.1, items, opts.replace))?;
    Ok(bytes_extra(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::args::TransferOpts;

    fn opts(disposition: Disposition, offset: i64) -> TransferOpts {
        TransferOpts { offset, disposition, ..TransferOpts::default() }
    }

    #[test]
    fn dispositions_decide_where_an_upload_starts() {
        let mut tree = Tree::default();
        tree.put_file(b"f", b"0123");
        assert_eq!(upload_start(&tree, b"new", &opts(Disposition::Create, 0)).unwrap(), 0);
        let exists = upload_start(&tree, b"f", &opts(Disposition::Create, 0));
        assert_eq!(exists.unwrap_err().bare(), "AlreadyExists");
        assert_eq!(upload_start(&tree, b"f", &opts(Disposition::Truncate, 0)).unwrap(), 0);
        assert_eq!(upload_start(&tree, b"f", &opts(Disposition::Resume, 4)).unwrap(), 4);
        let wrong = upload_start(&tree, b"f", &opts(Disposition::Resume, 3));
        assert_eq!(wrong.unwrap_err().bare(), "Internal");
        let missing = upload_start(&tree, b"zz", &opts(Disposition::Resume, 4));
        assert_eq!(missing.unwrap_err().bare(), "Internal");
    }

    #[test]
    fn only_files_and_pipes_are_accepted_as_sources() {
        let dir = File::open("/").unwrap();
        assert_eq!(Source::new(dir).err().unwrap().bare(), "PermissionDenied");
        let path = crate::fake::tests::temp_path("source");
        let source = Source::new(File::create(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(!source.fifo);
        assert_eq!(source.len(), 0);
    }

    #[test]
    fn a_descriptor_opened_the_wrong_way_is_a_permission_error() {
        assert_eq!(io_fail(&std::io::Error::from_raw_os_error(EBADF)).bare(), "PermissionDenied");
        assert_eq!(io_fail(&std::io::Error::from_raw_os_error(5)).bare(), "Internal");
    }

    #[test]
    fn byte_counts_and_failures_have_their_names() {
        assert_eq!(canceled().bare(), "Canceled");
        let extra = bytes_extra(7);
        assert_eq!(crate::wire::value_i64(&extra["bytes"]), Some(7));
        let f = job_fail(&JobFailure::new("Upload", 1, "Locked", "busy").detail("d", Some(3)));
        assert_eq!(f.bare(), "Locked");
        assert_eq!(f.extra().len(), 2);
    }
}
