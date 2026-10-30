// SPDX-License-Identifier: LGPL-2.1-or-later
//! In-memory backend for tests (feature `testing`), provider `mem`. Connections with the same `store` option
//! (default `default`) share one tree for the process lifetime. Options steer the C ABI's corner cases:
//!
//! | option | effect |
//! |---|---|
//! | `store` | the tree to use |
//! | `secret` | `authenticate` wants this secret, else `AuthFailed` |
//! | `throttle` | `authenticate` fails with `RateLimited`, retry after this many ms |
//! | `interactive`, `answer` | `authenticate` asks the prompter this question and wants this answer |
//! | `identity` | `connect` reports an SSH identity of this algorithm; its fingerprint is `<user>@<host>:<port> <connect>/<request timeout> ms` |
//! | `stall` | `true`: every call after `authenticate` waits for cancel; `ignore`: waits for ever, ignoring cancel |
//! | `panic` | the call of this name (`stat`, `read`, `position`, …) panics |
//!
//! The prompt's instruction is `Sign in as <user>`, or `Sign in as <domain>\<user>` with a domain.

mod tree;

use netvfs_vfs::{
    Attributes, Backend, CancelToken, Capabilities, Capability, Credentials, Entry, ErrorName, ListOptions,
    ListSink, Params, Progress, Prompt, PromptRequest, Prompter, ReadHandle, RenameMode, ServerIdentity,
    Sink, Source, SpaceInfo, Status, WriteHandle, WriteOptions,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::future::{Future, ready};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use tree::Tree;

const CHUNK: usize = 256 * 1024;
const CHUNK_BYTES: u64 = 256 * 1024;
const CAPACITY: u64 = 1 << 40;

type Store = Arc<Mutex<Tree>>;

static STORES: LazyLock<Mutex<BTreeMap<String, Store>>> = LazyLock::new(Mutex::default);

fn store(name: &str) -> Store {
    let mut stores = STORES.lock().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(stores.entry(name.to_owned()).or_default())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stall {
    No,
    UntilCancel,
    Forever,
}

#[derive(Debug)]
struct Session {
    tree: Store,
    open: AtomicBool,
    stall: Stall,
    panic_on: Option<String>,
}

impl Session {
    fn tree(&self) -> MutexGuard<'_, Tree> {
        self.tree.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `ConnectionLost` after `disconnect`.
    fn check(&self) -> Result<(), Status> {
        if self.open.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(Status::new(ErrorName::ConnectionLost, "The connection is closed"))
        }
    }

    /// `panic` option hook: the C ABI must turn the panic into `Internal`.
    fn hook(&self, call: &str) {
        assert!(self.panic_on.as_deref() != Some(call), "mem: {call} panics on request");
    }

    async fn enter(&self, call: &str, cancel: &CancelToken) -> Result<(), Status> {
        self.check()?;
        self.hook(call);
        match self.stall {
            Stall::No => Ok(()),
            Stall::UntilCancel => {
                cancel.canceled().await;
                Err(Status::canceled())
            }
            Stall::Forever => std::future::pending().await,
        }
    }
}

#[derive(Debug, Default)]
pub struct Mem {
    session: Option<Arc<Session>>,
    params: Params,
}

impl Mem {
    pub fn new() -> Self {
        Self::default()
    }

    fn session(&self) -> Result<&Arc<Session>, Status> {
        self.session.as_ref().ok_or_else(|| Status::new(ErrorName::ConnectionLost, "Not connected"))
    }

    async fn enter(&self, call: &str, cancel: &CancelToken) -> Result<&Arc<Session>, Status> {
        let session = self.session()?;
        session.enter(call, cancel).await?;
        Ok(session)
    }

    fn open(&mut self, params: &Params) -> Option<ServerIdentity> {
        let stall = match params.option("stall").as_deref() {
            Some("true") => Stall::UntilCancel,
            Some("ignore") => Stall::Forever,
            _ => Stall::No,
        };
        let session = Session {
            tree: store(params.option("store").as_deref().unwrap_or("default")),
            open: AtomicBool::new(true),
            stall,
            panic_on: params.option("panic"),
        };
        session.hook("connect");
        self.session = Some(Arc::new(session));
        self.params = params.clone();
        params.option("identity").map(|algorithm| ServerIdentity {
            algorithm,
            public_key: b"mem host key".to_vec(),
            fingerprint: format!(
                "{}@{}:{} {}/{} ms",
                params.username,
                params.host,
                params.port,
                params.connect_timeout_ms,
                params.request_timeout_ms
            ),
        })
    }

    fn sign_in(&self, credentials: &Credentials, prompter: Option<&mut dyn Prompter>) -> Result<(), Status> {
        let session = self.session()?;
        session.check()?;
        session.hook("authenticate");
        let refused = || Status::new(ErrorName::AuthFailed, "The credentials were refused");
        if let Some(ms) = self.params.option("throttle") {
            let ms = ms.parse().map_err(|e| Status::internal(format!("mem: throttle {ms}: {e}")))?;
            return Err(Status::new(ErrorName::RateLimited, "Too many attempts").with_retry_after_ms(ms));
        }
        if let Some(secret) = self.params.option("secret")
            && credentials.secret.as_slice() != secret.as_bytes()
        {
            return Err(refused());
        }
        if let Some(question) = self.params.option("interactive") {
            let request = PromptRequest {
                name: "mem".to_owned(),
                instruction: if credentials.domain.is_empty() {
                    format!("Sign in as {}", credentials.user)
                } else {
                    format!("Sign in as {}\\{}", credentials.domain, credentials.user)
                },
                prompts: vec![Prompt { text: question, echo: false }],
            };
            let answers = prompter.and_then(|p| p.answer(&request)).ok_or_else(refused)?;
            let expected = self.params.option("answer").unwrap_or_default();
            if answers.first().map(|a| a.as_slice()) != Some(expected.as_bytes()) {
                return Err(refused());
            }
        }
        Ok(())
    }
}

impl Backend for Mem {
    type Read = MemRead;
    type Write = MemWrite;

    fn connect(
        &mut self,
        params: &Params,
        _: &CancelToken,
    ) -> impl Future<Output = Result<Option<ServerIdentity>, Status>> {
        ready(Ok(self.open(params)))
    }

    fn authenticate(
        &mut self,
        credentials: &Credentials,
        prompter: Option<&mut dyn Prompter>,
        _: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>> {
        ready(self.sign_in(credentials, prompter))
    }

    fn capabilities(&self) -> Capabilities {
        use Capability::{
            AtomicReplace, Checksums, ETags, EfficientRanges, Hardlinks, NativeNoReplace, Ownership,
            PosixModes, ReadHandles, ServerCopy, ServerCopyRecursive, SetModified, SetModifiedOnUpload,
            SpaceInfo, Symlinks, WriteResume,
        };
        if let Ok(session) = self.session() {
            session.hook("capabilities");
        }
        Capabilities {
            flags: [
                Symlinks,
                Hardlinks,
                PosixModes,
                Ownership,
                SetModified,
                SetModifiedOnUpload,
                ReadHandles,
                EfficientRanges,
                WriteResume,
                AtomicReplace,
                NativeNoReplace,
                ServerCopy,
                ServerCopyRecursive,
                SpaceInfo,
                Checksums,
                ETags,
            ]
            .into(),
            checksum_algorithms: vec!["sha256".to_owned()],
            max_name_bytes: Some(tree::MAX_NAME),
        }
    }

    fn disconnect(&mut self) -> impl Future<Output = ()> {
        if let Some(session) = &self.session {
            session.hook("disconnect");
            session.open.store(false, Ordering::SeqCst);
        }
        ready(())
    }

    async fn keep_alive(&mut self, cancel: &CancelToken) -> Result<(), Status> {
        self.enter("keep_alive", cancel).await.map(drop)
    }

    async fn stat(&mut self, path: &[u8], follow: bool, cancel: &CancelToken) -> Result<Entry, Status> {
        self.enter("stat", cancel).await?.tree().stat(path, follow)
    }

    async fn list(
        &mut self,
        dir: &[u8],
        options: ListOptions,
        sink: &mut dyn ListSink,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let entries = self.enter("list", cancel).await?.tree().list(dir, options.resolve_symlink_types)?;
        for batch in entries.chunks(options.batch_size.max(1)) {
            cancel.check()?;
            if !sink.entries(batch) {
                return Err(Status::canceled());
            }
        }
        Ok(())
    }

    async fn make_dir(&mut self, path: &[u8], exclusive: bool, cancel: &CancelToken) -> Result<(), Status> {
        self.enter("make_dir", cancel).await?.tree().make_dir(path, exclusive)
    }

    async fn remove_file(&mut self, path: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        self.enter("remove_file", cancel).await?.tree().remove(path, false)
    }

    async fn remove_dir(&mut self, path: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        self.enter("remove_dir", cancel).await?.tree().remove(path, true)
    }

    async fn rename(
        &mut self,
        from: &[u8],
        to: &[u8],
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        self.enter("rename", cancel).await?.tree().rename(from, to, mode == RenameMode::Replace)
    }

    async fn set_attributes(
        &mut self,
        path: &[u8],
        changes: &Attributes,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        self.enter("set_attributes", cancel).await?.tree().set_attributes(path, changes)
    }

    async fn read_link(&mut self, path: &[u8], cancel: &CancelToken) -> Result<Vec<u8>, Status> {
        self.enter("read_link", cancel).await?.tree().read_link(path)
    }

    async fn make_symlink(&mut self, target: &[u8], link: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        self.enter("make_symlink", cancel).await?.tree().make_symlink(target, link)
    }

    async fn make_hardlink(
        &mut self,
        existing: &[u8],
        link: &[u8],
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        self.enter("make_hardlink", cancel).await?.tree().make_hardlink(existing, link)
    }

    async fn copy(
        &mut self,
        from: &[u8],
        to: &[u8],
        recursive: bool,
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        self.enter("copy", cancel).await?.tree().copy(from, to, recursive, mode == RenameMode::Replace)
    }

    async fn checksum(
        &mut self,
        path: &[u8],
        algorithm: &str,
        cancel: &CancelToken,
    ) -> Result<Vec<u8>, Status> {
        let session = self.enter("checksum", cancel).await?;
        if algorithm != "sha256" {
            return Err(Status::unsupported(format!("Checksum {algorithm} is not supported")));
        }
        session.tree().file_data(path).map(|data| Sha256::digest(data).to_vec())
    }

    async fn space_info(&mut self, dir: &[u8], cancel: &CancelToken) -> Result<SpaceInfo, Status> {
        let session = self.enter("space_info", cancel).await?;
        let used = session.tree().used_seen_from(dir)?;
        Ok(SpaceInfo { free: Some(CAPACITY.saturating_sub(used)), total: Some(CAPACITY), used: Some(used) })
    }

    async fn open_read(&mut self, path: &[u8], cancel: &CancelToken) -> Result<MemRead, Status> {
        let session = self.enter("open_read", cancel).await?;
        let (id, size) = {
            let tree = session.tree();
            let id = tree.file(path)?;
            (id, tree.data(id)?.len())
        };
        Ok(MemRead { session: Arc::clone(session), id, size: u64::try_from(size).ok() })
    }

    async fn open_write(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        cancel: &CancelToken,
    ) -> Result<MemWrite, Status> {
        let session = self.enter("open_write", cancel).await?;
        let (id, at) = session.tree().open_write(path, options)?;
        Ok(MemWrite { session: Arc::clone(session), id, at, mtime_ms: options.mtime_ms })
    }

    async fn upload(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        source: &mut dyn Source,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let session = self.enter("upload", cancel).await?;
        let (id, mut at) = session.tree().open_write(path, options)?;
        let total = options.expected_size.or_else(|| source.size());
        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        loop {
            cancel.check()?;
            if progress.canceled() {
                return Err(Status::canceled());
            }
            let n = source.read(&mut buf)?;
            let Some(chunk) = buf.get(..n).filter(|c| !c.is_empty()) else { break };
            session.tree().write_at(id, at, chunk)?;
            let moved = u64::try_from(n).unwrap_or(u64::MAX);
            at = at.saturating_add(moved);
            done = done.saturating_add(moved);
            progress.update(done, total);
        }
        if let Some(ms) = options.mtime_ms {
            session.tree().set_mtime(id, ms)?;
        }
        Ok(())
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
        let session = self.enter("download", cancel).await?;
        let id = session.tree().file(path)?;
        let size = u64::try_from(session.tree().data(id)?.len()).unwrap_or(u64::MAX);
        let start = offset.min(size);
        let end = length.map_or(size, |n| start.saturating_add(n).min(size));
        let total = end.saturating_sub(start);
        let mut at = start;
        while at < end {
            cancel.check()?;
            if progress.canceled() {
                return Err(Status::canceled());
            }
            let chunk = read_at(&session.tree(), id, at, end.saturating_sub(at).min(CHUNK_BYTES))?;
            sink.write(&chunk)?;
            at = at.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            progress.update(at.saturating_sub(start), Some(total));
        }
        Ok(())
    }
}

fn read_at(tree: &Tree, id: u64, at: u64, len: u64) -> Result<Vec<u8>, Status> {
    let data = tree.data(id)?;
    let start = usize::try_from(at).unwrap_or(usize::MAX).min(data.len());
    let end = start.saturating_add(usize::try_from(len).unwrap_or(usize::MAX)).min(data.len());
    Ok(data.get(start..end).unwrap_or_default().to_vec())
}

#[derive(Debug)]
pub struct MemRead {
    session: Arc<Session>,
    id: u64,
    size: Option<u64>,
}

impl ReadHandle for MemRead {
    fn size(&self) -> Option<u64> {
        self.size
    }

    async fn read(&mut self, offset: u64, buf: &mut [u8], cancel: &CancelToken) -> Result<usize, Status> {
        self.session.enter("read", cancel).await?;
        let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        let chunk = read_at(&self.session.tree(), self.id, offset, len)?;
        let place = buf.get_mut(..chunk.len()).ok_or_else(|| Status::internal("mem: short buffer"))?;
        place.copy_from_slice(&chunk);
        Ok(chunk.len())
    }

    fn read_ahead(&mut self, _: u64, _: u64) {
        self.session.hook("read_ahead");
    }

    async fn close(self, cancel: &CancelToken) -> Result<(), Status> {
        self.session.enter("read_close", cancel).await
    }
}

#[derive(Debug)]
pub struct MemWrite {
    session: Arc<Session>,
    id: u64,
    at: u64,
    mtime_ms: Option<i64>,
}

impl WriteHandle for MemWrite {
    async fn write(&mut self, data: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        self.session.enter("write", cancel).await?;
        self.session.tree().write_at(self.id, self.at, data)?;
        self.at = self.at.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    fn position(&self) -> u64 {
        self.session.hook("position");
        self.at
    }

    async fn commit(self, cancel: &CancelToken) -> Result<(), Status> {
        self.session.enter("commit", cancel).await?;
        if let Some(ms) = self.mtime_ms {
            self.session.tree().set_mtime(self.id, ms)?;
        }
        Ok(())
    }

    async fn abort(self) {
        self.session.hook("abort");
    }
}
