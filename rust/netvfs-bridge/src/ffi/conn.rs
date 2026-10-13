// SPDX-License-Identifier: LGPL-2.1-or-later
//! [`Conn`]: one backend connection, owned by one thread (T4), with its
//! read [`Handle`]s and its [`CancelHandle`], the one part another thread
//! may use.

use super::Ffi;
use super::callback::{self, Ctx, EstablishCtx, EstablishHooks, Progress, ReadAt, WriteAt};
use super::marshal::{self, Params, ParamsBuf};
use super::raw::{
    NVB_DISPOSITION_CREATE_NEW, NVB_DISPOSITION_RESUME, NVB_DISPOSITION_TRUNCATE, NVB_PHASE_AUTHENTICATE,
    NVB_PHASE_CONNECT, NVB_PHASE_CREDENTIALS, NVB_PHASE_DONE, NVB_PHASE_IDENTITY, NVB_SECRET_BYTES,
    NVB_SECRET_NONE, NVB_SECRET_SIGNON, NvbAttributes, NvbBlob, NvbBytes, NvbCapabilities, NvbConn, NvbEntry,
    NvbError, NvbEstablishHooks, NvbHandle, NvbIdentityFn, NvbIo, NvbProgress, NvbPromptFn, NvbSecret,
    NvbSpace, NvbUploadOpts, NvbWalkOpts,
};
use crate::Status;
use netvfs_bridge_proto::{WireCapabilities, WireEntry};
use std::fmt;
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

/// The connection pointer, for `conn_cancel` only.
struct CancelPtr(NonNull<NvbConn>);

// SAFETY: the pointer is used for conn_cancel only, which T4 allows from
// any thread; the mutex around it orders that against conn_free.
unsafe impl Send for CancelPtr {}

/// What a [`CancelHandle`] and its connection share: the pointer while the
/// connection lives, `None` from its `conn_free` on.
struct CancelShared {
    ffi: Ffi,
    conn: Mutex<Option<CancelPtr>>,
}

impl CancelShared {
    fn lock(&self) -> MutexGuard<'_, Option<CancelPtr>> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Cancels a connection's running call from any thread (C-9; also ends a
/// signond wait). T4 says a cancel must never overlap or follow
/// `conn_free`: the handle and the connection share a lock, the connection
/// clears the pointer under it before `conn_free`, so a cancel after that
/// does nothing and one in progress delays the free.
#[derive(Clone)]
pub struct CancelHandle(Arc<CancelShared>);

impl CancelHandle {
    /// Cancels; false when the connection is gone.
    #[must_use = "false: the connection is gone"]
    pub fn cancel(&self) -> bool {
        // SAFETY: the pointer is there only while the connection lives: its
        // free clears it under the lock held for this call (T4: any thread).
        self.0.lock().as_ref().map(|conn| unsafe { (self.0.ffi.t.conn_cancel)(conn.0.as_ptr()) }).is_some()
    }
}

impl fmt::Debug for CancelHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelHandle").field("live", &self.0.lock().is_some()).finish()
    }
}

/// The connection itself; its handles keep it alive (O4: `conn_free`
/// would close them).
struct Core {
    ffi: Ffi,
    raw: NonNull<NvbConn>,
    cancel: Arc<CancelShared>,
}

impl Core {
    /// T6: no connection call from inside a callback.
    fn ready(&self) -> Result<*mut NvbConn, Status> {
        if callback::active() {
            return Err(Status::internal("connection call from inside a callback (T6)"));
        }
        Ok(self.raw.as_ptr())
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        // No cancel can start after this, and one in progress has ended.
        *self.cancel.lock() = None;
        // SAFETY: the owner thread (Core is !Send), no handle left (each
        // holds a Core), no call running, no cancel to follow (T4).
        unsafe { (self.ffi.t.conn_free)(self.raw.as_ptr()) }
    }
}

/// How far `establish` got (`NVB_PHASE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// `Backend::connect`.
    Connect,
    /// The identity verdict (attention-relevant).
    Identity,
    /// The secret lookup (no attention).
    Credentials,
    /// `Backend::authenticate` (attention-relevant).
    Authenticate,
    /// Connected.
    Done,
}

impl Phase {
    /// The phase of `NVB_PHASE_*`; an unknown value is `Connect` (no
    /// attention).
    #[must_use]
    pub const fn from_raw(phase: u32) -> Self {
        match phase {
            NVB_PHASE_IDENTITY => Self::Identity,
            NVB_PHASE_CREDENTIALS => Self::Credentials,
            NVB_PHASE_AUTHENTICATE => Self::Authenticate,
            NVB_PHASE_DONE => Self::Done,
            _ => Self::Connect,
        }
    }
}

/// A failed `establish`: where, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishError {
    /// How far it got.
    pub phase: Phase,
    /// The failure.
    pub status: Status,
}

/// Where the credentials come from (`nvb_secret`).
#[derive(Debug, Clone)]
pub enum Secret {
    /// `Credentials(user, "")`.
    None {
        /// User name.
        user: String,
    },
    /// Ad hoc (XB-16): C++ copies the secret and wipes its copy.
    Bytes {
        /// User name.
        user: String,
        /// The secret, wiped when this goes.
        secret: Zeroizing<Vec<u8>>,
    },
    /// An account's secret from signond, fetched on the Qt thread after the
    /// identity verdict (XA-6, XA-7).
    Signon {
        /// Used when the fetched user name is empty (A-6).
        user: String,
        /// The account's credentials id.
        credentials_id: u32,
        /// No stored secret is fine (XA-7).
        secret_optional: bool,
    },
}

impl Secret {
    /// The C form, borrowing from `self`.
    fn raw(&self) -> NvbSecret {
        let mut raw = NvbSecret {
            source: NVB_SECRET_NONE,
            user: NvbBytes::EMPTY,
            secret: NvbBytes::EMPTY,
            credentials_id: 0,
            secret_optional: 0,
        };
        match self {
            Self::None { user } => raw.user = NvbBytes::of(user.as_bytes()),
            Self::Bytes { user, secret } => {
                (raw.source, raw.user, raw.secret) =
                    (NVB_SECRET_BYTES, NvbBytes::of(user.as_bytes()), NvbBytes::of(secret));
            }
            Self::Signon { user, credentials_id, secret_optional } => {
                (raw.source, raw.user) = (NVB_SECRET_SIGNON, NvbBytes::of(user.as_bytes()));
                (raw.credentials_id, raw.secret_optional) = (*credentials_id, u8::from(*secret_optional));
            }
        }
        raw
    }
}

/// `nvb_space`; each -1 unknown.
pub type Space = NvbSpace;

/// Attribute changes (`nvb_attributes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attributes {
    /// New mode bits.
    pub mode: Option<i32>,
    /// New modification time, ms since the epoch.
    pub mtime_ms: Option<i64>,
    /// New access time, ms since the epoch.
    pub atime_ms: Option<i64>,
}

impl Attributes {
    fn raw(&self) -> NvbAttributes {
        NvbAttributes {
            mode: self.mode.unwrap_or(-1),
            has_mtime: u8::from(self.mtime_ms.is_some()),
            has_atime: u8::from(self.atime_ms.is_some()),
            mtime_ms: self.mtime_ms.unwrap_or(0),
            atime_ms: self.atime_ms.unwrap_or(0),
        }
    }
}

/// Options of an upload (`nvb_upload_opts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadOptions {
    /// Fails when the file exists.
    CreateNew {
        /// Mode of the new file, `None`: the backend's default (XC-23).
        mode: Option<i32>,
        /// Bytes expected, if known.
        expected_size: Option<i64>,
        /// Modification time to set, ms since the epoch.
        mtime_ms: Option<i64>,
    },
    /// Replaces the file's content (creating the file if it is missing).
    Truncate {
        /// Mode of the file if it is created, `None`: the backend's default.
        mode: Option<i32>,
        /// Bytes expected, if known.
        expected_size: Option<i64>,
        /// Modification time to set.
        mtime_ms: Option<i64>,
    },
    /// Continues at `offset`.
    Resume {
        /// Where the data goes in the file.
        offset: i64,
        /// Bytes expected, if known.
        expected_size: Option<i64>,
        /// Modification time to set.
        mtime_ms: Option<i64>,
    },
}

impl UploadOptions {
    fn raw(&self) -> NvbUploadOpts {
        let (disposition, mode, offset, size, mtime) = match *self {
            Self::CreateNew { mode, expected_size, mtime_ms } => {
                (NVB_DISPOSITION_CREATE_NEW, mode, 0, expected_size, mtime_ms)
            }
            Self::Truncate { mode, expected_size, mtime_ms } => {
                (NVB_DISPOSITION_TRUNCATE, mode, 0, expected_size, mtime_ms)
            }
            Self::Resume { offset, expected_size, mtime_ms } => {
                (NVB_DISPOSITION_RESUME, None, offset, expected_size, mtime_ms)
            }
        };
        NvbUploadOpts {
            disposition,
            create_mode: mode.unwrap_or(-1),
            resume_offset: offset,
            expected_size: size.unwrap_or(-1),
            has_mtime: u8::from(mtime.is_some()),
            mtime_ms: mtime.unwrap_or(0),
        }
    }
}

/// Options of a walk (`nvb_walk_opts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WalkOptions {
    /// `None`: unlimited; 0: the root's children only.
    pub max_depth: Option<u32>,
    /// Follow symlinks to folders.
    pub follow_symlinks: bool,
    /// A no-op on the wire (design §6.9).
    pub post_order: bool,
    /// Stop at an unreadable sub-folder instead of skipping it.
    pub stop_on_list_error: bool,
}

impl WalkOptions {
    fn raw(&self) -> NvbWalkOpts {
        NvbWalkOpts {
            max_depth: self.max_depth.and_then(|d| i32::try_from(d).ok()).unwrap_or(-1),
            follow_symlinks: u8::from(self.follow_symlinks),
            post_order: u8::from(self.post_order),
            stop_on_list_error: u8::from(self.stop_on_list_error),
        }
    }
}

/// What `remove_tree` removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TreeCounts {
    /// Files and links.
    pub files: i64,
    /// Folders.
    pub dirs: i64,
}

/// The context of an optional progress, and its C form.
struct ProgressArg<'p, 'q> {
    ctx: Option<Ctx<&'p mut (dyn Progress + 'q)>>,
}

impl<'p, 'q> ProgressArg<'p, 'q> {
    fn new(progress: Option<&'p mut (dyn Progress + 'q)>) -> Self {
        Self { ctx: progress.map(Ctx::new) }
    }

    /// The `nvb_progress`, NULL without one; valid while `self` stays put.
    fn raw(&mut self) -> Option<NvbProgress> {
        self.ctx.as_mut().map(|ctx| NvbProgress {
            ctx: ctx.as_ctx(),
            update: Some(callback::progress_update::<dyn Progress + 'q>),
            canceled: Some(callback::progress_canceled::<dyn Progress + 'q>),
        })
    }

    fn finish<R>(self, result: Result<R, Status>) -> Result<R, Status> {
        match self.ctx {
            Some(ctx) => ctx.finish(result),
            None => result,
        }
    }
}

fn opt_ptr<T>(value: Option<&T>) -> *const T {
    value.map_or(ptr::null(), ptr::from_ref)
}

/// One backend connection (`nvb_conn`), owned by the thread that made it:
/// `!Send`, as are its handles (T4). Freed when it and its handles are
/// gone: the C++ side then closes what is still open and disconnects.
pub struct Conn {
    core: Rc<Core>,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").field("raw", &self.core.raw).finish()
    }
}

/// A conn call that returns only an error.
type PathCall = unsafe extern "C" fn(*mut NvbConn, NvbBytes) -> *mut NvbError;
/// A conn call on two paths.
type TwoPathCall = unsafe extern "C" fn(*mut NvbConn, NvbBytes, NvbBytes) -> *mut NvbError;

impl Conn {
    pub(super) fn new(ffi: Ffi, provider: &str) -> Result<Self, Status> {
        if callback::active() {
            return Err(Status::internal("connection call from inside a callback (T6)"));
        }
        let mut out: *mut NvbConn = ptr::null_mut();
        // SAFETY: this thread becomes the owner (T4); `provider` borrowed (O1).
        let error = unsafe { (ffi.t.conn_new)(NvbBytes::of(provider.as_bytes()), &raw mut out) };
        ffi.check(error)?;
        let raw = NonNull::new(out).ok_or_else(|| Status::internal("conn_new gave no connection"))?;
        let cancel = Arc::new(CancelShared { ffi, conn: Mutex::new(Some(CancelPtr(raw))) });
        Ok(Self { core: Rc::new(Core { ffi, raw, cancel }) })
    }

    fn ffi(&self) -> Ffi {
        self.core.ffi
    }

    /// A handle that cancels this connection's calls from any thread.
    #[must_use]
    pub fn cancel_handle(&self) -> CancelHandle {
        CancelHandle(Arc::clone(&self.core.cancel))
    }

    /// Makes the connection usable again after a cancel.
    ///
    /// # Errors
    /// `Internal` inside a callback.
    pub fn reset_cancel(&mut self) -> Result<(), Status> {
        let conn = self.core.ready()?;
        // SAFETY: owner thread, no call running (T4).
        unsafe { (self.ffi().t.conn_reset_cancel)(conn) };
        Ok(())
    }

    /// Connects, has `hooks` judge the server's identity against `pin`,
    /// gets the credentials and authenticates (C-7, XSEC-1, XA-6), in one
    /// call: nothing is sent before the identity is accepted.
    ///
    /// # Errors
    /// The failure and the phase it happened in; the connection is then
    /// disconnected.
    pub fn establish(
        &mut self,
        params: &Params,
        pin: &str,
        secret: &Secret,
        hooks: &mut EstablishHooks<'_>,
    ) -> Result<(), EstablishError> {
        let conn = self.core.ready().map_err(|status| EstablishError { phase: Phase::Connect, status })?;
        let ffi = self.ffi();
        let params = ParamsBuf::new(params);
        let secret = secret.raw();
        let has = (hooks.identity.is_some(), hooks.prompt.is_some());
        let mut ctx = Ctx::new(EstablishCtx { ffi, hooks });
        let identity: NvbIdentityFn = callback::identity_hook;
        let prompt: NvbPromptFn = callback::prompt_hook;
        let raw_hooks = NvbEstablishHooks {
            ctx: ctx.as_ctx(),
            identity: has.0.then_some(identity),
            prompt: has.1.then_some(prompt),
        };
        let mut phase = NVB_PHASE_CONNECT;
        // SAFETY: owner thread (T4); params, secret and hooks live across
        // the call (O1); the hooks' context is `ctx`, unused until it returns.
        let error = unsafe {
            (ffi.t.conn_establish)(
                conn,
                params.raw(),
                NvbBytes::of(pin.as_bytes()),
                &raw const secret,
                &raw const raw_hooks,
                &raw mut phase,
            )
        };
        let result = ctx.finish(ffi.check(error));
        result.map_err(|status| EstablishError { phase: Phase::from_raw(phase), status })
    }

    /// `Backend::capabilities`.
    ///
    /// # Errors
    /// The backend's failure.
    pub fn capabilities(&mut self) -> Result<WireCapabilities, Status> {
        let conn = self.core.ready()?;
        let mut out: *mut NvbCapabilities = ptr::null_mut();
        // SAFETY: owner thread (T4); `out` is ours.
        let error = unsafe { (self.ffi().t.conn_capabilities)(conn, &raw mut out) };
        self.ffi().check(error)?;
        // SAFETY: the block holds everything it points to (O3).
        self.ffi().take(out, |c| unsafe { marshal::capabilities(c) })
    }

    /// `Backend::stat` of a normalised path (protocol bytes).
    ///
    /// # Errors
    /// The backend's failure.
    pub fn stat(&mut self, path: &[u8], follow: bool) -> Result<WireEntry, Status> {
        let conn = self.core.ready()?;
        let mut out: *mut NvbEntry = ptr::null_mut();
        // SAFETY: owner thread (T4); `path` borrowed (O1); `out` is ours.
        let error =
            unsafe { (self.ffi().t.conn_stat)(conn, NvbBytes::of(path), i32::from(follow), &raw mut out) };
        self.ffi().check(error)?;
        // SAFETY: the block holds everything it points to (O3).
        self.ffi().take(out, |e| unsafe { marshal::entry(e) })
    }

    /// `Backend::list`: `sink` gets each batch the backend gives (at most
    /// `batch_size`) and returns false to stop (then `Canceled`).
    ///
    /// # Errors
    /// The backend's failure; `Internal` when the sink panicked.
    pub fn list<F: FnMut(&[WireEntry]) -> bool>(
        &mut self,
        dir: &[u8],
        batch_size: u32,
        sink: F,
    ) -> Result<(), Status> {
        let conn = self.core.ready()?;
        let mut ctx = Ctx::new(sink);
        // SAFETY: owner thread (T4); `dir` borrowed (O1); the sink's context
        // is `ctx`, unused until the call returns (T6).
        let error = unsafe {
            (self.ffi().t.conn_list)(
                conn,
                NvbBytes::of(dir),
                batch_size,
                Some(callback::list_sink::<F>),
                ctx.as_ctx(),
            )
        };
        ctx.finish(self.ffi().check(error))
    }

    /// `Backend::readLink`: the target, verbatim.
    ///
    /// # Errors
    /// The backend's failure.
    pub fn read_link(&mut self, path: &[u8]) -> Result<Vec<u8>, Status> {
        let conn = self.core.ready()?;
        let mut out: *mut NvbBlob = ptr::null_mut();
        // SAFETY: owner thread (T4); `path` borrowed (O1); `out` is ours.
        let error = unsafe { (self.ffi().t.conn_read_link)(conn, NvbBytes::of(path), &raw mut out) };
        self.ffi().check(error)?;
        self.ffi().take_blob(out)
    }

    /// `Backend::spaceInfo`.
    ///
    /// # Errors
    /// The backend's failure.
    pub fn space_info(&mut self, path: &[u8]) -> Result<Space, Status> {
        let conn = self.core.ready()?;
        // Written in full on success.
        let mut out = Space::default();
        // SAFETY: owner thread (T4); `path` borrowed (O1); `out` is ours.
        let error = unsafe { (self.ffi().t.conn_space_info)(conn, NvbBytes::of(path), &raw mut out) };
        self.ffi().check(error)?;
        Ok(out)
    }

    /// `Backend::checksum`: the raw digest.
    ///
    /// # Errors
    /// The backend's failure.
    pub fn checksum(&mut self, path: &[u8], algorithm: &str) -> Result<Vec<u8>, Status> {
        let conn = self.core.ready()?;
        let mut out: *mut NvbBlob = ptr::null_mut();
        let algorithm = NvbBytes::of(algorithm.as_bytes());
        // SAFETY: owner thread (T4); `path` and `algorithm` borrowed (O1).
        let error =
            unsafe { (self.ffi().t.conn_checksum)(conn, NvbBytes::of(path), algorithm, &raw mut out) };
        self.ffi().check(error)?;
        self.ffi().take_blob(out)
    }

    /// `Backend::makeDir`.
    ///
    /// # Errors
    /// The backend's failure (`AlreadyExists` when `exclusive`).
    pub fn make_dir(&mut self, path: &[u8], exclusive: bool) -> Result<(), Status> {
        let conn = self.core.ready()?;
        // SAFETY: owner thread (T4); `path` borrowed (O1).
        let error = unsafe { (self.ffi().t.conn_make_dir)(conn, NvbBytes::of(path), i32::from(exclusive)) };
        self.ffi().check(error)
    }

    fn path_call(&mut self, call: PathCall, path: &[u8]) -> Result<(), Status> {
        let conn = self.core.ready()?;
        // SAFETY: a conn call of the table: owner thread (T4), `path`
        // borrowed (O1).
        let error = unsafe { call(conn, NvbBytes::of(path)) };
        self.ffi().check(error)
    }

    fn two_path_call(&mut self, call: TwoPathCall, a: &[u8], b: &[u8]) -> Result<(), Status> {
        let conn = self.core.ready()?;
        // SAFETY: a conn call of the table: owner thread (T4), paths
        // borrowed (O1).
        let error = unsafe { call(conn, NvbBytes::of(a), NvbBytes::of(b)) };
        self.ffi().check(error)
    }

    /// `Backend::removeFile`.
    ///
    /// # Errors
    /// The backend's failure.
    pub fn remove_file(&mut self, path: &[u8]) -> Result<(), Status> {
        self.path_call(self.ffi().t.conn_remove_file, path)
    }

    /// `Backend::removeDir`.
    ///
    /// # Errors
    /// The backend's failure (`DirectoryNotEmpty`, …).
    pub fn remove_dir(&mut self, path: &[u8]) -> Result<(), Status> {
        self.path_call(self.ffi().t.conn_remove_dir, path)
    }

    /// `Backend::makeSymlink`: a link at `link_path` to `target` (verbatim).
    ///
    /// # Errors
    /// The backend's failure.
    pub fn make_symlink(&mut self, target: &[u8], link_path: &[u8]) -> Result<(), Status> {
        self.two_path_call(self.ffi().t.conn_make_symlink, target, link_path)
    }

    /// `Backend::makeHardlink`.
    ///
    /// # Errors
    /// The backend's failure.
    pub fn make_hardlink(&mut self, existing: &[u8], new_path: &[u8]) -> Result<(), Status> {
        self.two_path_call(self.ffi().t.conn_make_hardlink, existing, new_path)
    }

    /// `Backend::rename`.
    ///
    /// # Errors
    /// The backend's failure.
    pub fn rename(&mut self, from: &[u8], to: &[u8], replace: bool) -> Result<(), Status> {
        let conn = self.core.ready()?;
        let (from, to) = (NvbBytes::of(from), NvbBytes::of(to));
        // SAFETY: owner thread (T4); paths borrowed (O1).
        let error = unsafe { (self.ffi().t.conn_rename)(conn, from, to, i32::from(replace)) };
        self.ffi().check(error)
    }

    /// `Backend::copy` (ServerCopy).
    ///
    /// # Errors
    /// The backend's failure.
    pub fn copy(&mut self, from: &[u8], to: &[u8], recursive: bool, replace: bool) -> Result<(), Status> {
        let conn = self.core.ready()?;
        let (from, to) = (NvbBytes::of(from), NvbBytes::of(to));
        let (recursive, replace) = (i32::from(recursive), i32::from(replace));
        // SAFETY: owner thread (T4); paths borrowed (O1).
        let error = unsafe { (self.ffi().t.conn_copy)(conn, from, to, recursive, replace) };
        self.ffi().check(error)
    }

    /// `Backend::setAttributes`.
    ///
    /// # Errors
    /// The backend's failure.
    pub fn set_attributes(&mut self, path: &[u8], changes: &Attributes) -> Result<(), Status> {
        let conn = self.core.ready()?;
        let changes = changes.raw();
        // SAFETY: owner thread (T4); `path` and `changes` borrowed (O1).
        let error =
            unsafe { (self.ffi().t.conn_set_attributes)(conn, NvbBytes::of(path), &raw const changes) };
        self.ffi().check(error)
    }

    /// `Backend::openRead`: a handle and the file's size (-1 unknown).
    ///
    /// # Errors
    /// The backend's failure.
    pub fn open_read(&mut self, path: &[u8]) -> Result<(Handle, i64), Status> {
        let conn = self.core.ready()?;
        let mut out: *mut NvbHandle = ptr::null_mut();
        // Written on success.
        let mut size = 0_i64;
        // SAFETY: owner thread (T4); `path` borrowed (O1); outs are ours.
        let error =
            unsafe { (self.ffi().t.conn_open_read)(conn, NvbBytes::of(path), &raw mut out, &raw mut size) };
        self.ffi().check(error)?;
        let raw = NonNull::new(out).ok_or_else(|| Status::internal("conn_open_read gave no handle"))?;
        Ok((Handle { core: Rc::clone(&self.core), raw: Some(raw) }, size))
    }

    /// `Backend::upload`: the data comes from `local` (`size`: bytes in
    /// range, 0 for a FIFO, which is `sequential`).
    ///
    /// # Errors
    /// The backend's failure; `Canceled` when `progress` said so; `Internal`
    /// when a callback panicked.
    pub fn upload(
        &mut self,
        path: &[u8],
        options: &UploadOptions,
        local: &mut dyn ReadAt,
        (sequential, size): (bool, i64),
        progress: Option<&mut dyn Progress>,
    ) -> Result<(), Status> {
        let conn = self.core.ready()?;
        let options = options.raw();
        let mut io_ctx = Ctx::new(local);
        let io = NvbIo {
            ctx: io_ctx.as_ctx(),
            sequential: u8::from(sequential),
            size,
            read: Some(callback::io_read::<dyn ReadAt>),
            write: None,
        };
        let mut progress = ProgressArg::new(progress);
        let raw_progress = progress.raw();
        // SAFETY: owner thread (T4); everything borrowed lives across the
        // call (O1); the contexts are unused until it returns (T6).
        let error = unsafe {
            (self.ffi().t.conn_upload)(
                conn,
                NvbBytes::of(path),
                &raw const options,
                &raw const io,
                opt_ptr(raw_progress.as_ref()),
            )
        };
        progress.finish(io_ctx.finish(self.ffi().check(error)))
    }

    /// `Backend::download` of `length` bytes (-1: to the end) from `offset`
    /// into `local` (`size` and `sequential` as for [`Conn::upload`]).
    ///
    /// # Errors
    /// As [`Conn::upload`].
    pub fn download(
        &mut self,
        path: &[u8],
        (offset, length): (i64, i64),
        local: &mut dyn WriteAt,
        (sequential, size): (bool, i64),
        progress: Option<&mut dyn Progress>,
    ) -> Result<(), Status> {
        let conn = self.core.ready()?;
        let mut io_ctx = Ctx::new(local);
        let io = NvbIo {
            ctx: io_ctx.as_ctx(),
            sequential: u8::from(sequential),
            size,
            read: None,
            write: Some(callback::io_write::<dyn WriteAt>),
        };
        let mut progress = ProgressArg::new(progress);
        let raw_progress = progress.raw();
        // SAFETY: as in `upload`.
        let error = unsafe {
            (self.ffi().t.conn_download)(
                conn,
                NvbBytes::of(path),
                offset,
                length,
                &raw const io,
                opt_ptr(raw_progress.as_ref()),
            )
        };
        progress.finish(io_ctx.finish(self.ffi().check(error)))
    }

    /// `Ops::removeTree`: progress gets files + folders removed so far. The
    /// counts come back also on failure.
    pub fn remove_tree(
        &mut self,
        path: &[u8],
        progress: Option<&mut dyn Progress>,
    ) -> (TreeCounts, Result<(), Status>) {
        let mut counts = TreeCounts::default();
        let conn = match self.core.ready() {
            Ok(conn) => conn,
            Err(status) => return (counts, Err(status)),
        };
        let mut progress = ProgressArg::new(progress);
        let raw_progress = progress.raw();
        // SAFETY: owner thread (T4); `path` and the progress live across the
        // call (O1); its context is unused until it returns (T6).
        let error = unsafe {
            (self.ffi().t.remove_tree)(
                conn,
                NvbBytes::of(path),
                opt_ptr(raw_progress.as_ref()),
                &raw mut counts.files,
                &raw mut counts.dirs,
            )
        };
        (counts, progress.finish(self.ffi().check(error)))
    }

    /// `Ops::walk`: `visit` gets each entry with its full path and returns
    /// false to stop (then `Canceled`).
    ///
    /// # Errors
    /// The backend's failure; `Internal` when `visit` panicked.
    pub fn walk<F: FnMut(&[u8], WireEntry) -> bool>(
        &mut self,
        root: &[u8],
        options: &WalkOptions,
        visit: F,
    ) -> Result<(), Status> {
        let conn = self.core.ready()?;
        let options = options.raw();
        let mut ctx = Ctx::new(visit);
        // SAFETY: owner thread (T4); `root` and `options` borrowed (O1); the
        // visitor's context is unused until the call returns (T6).
        let error = unsafe {
            (self.ffi().t.walk)(
                conn,
                NvbBytes::of(root),
                &raw const options,
                Some(callback::walk_visit::<F>),
                ctx.as_ctx(),
            )
        };
        ctx.finish(self.ffi().check(error))
    }

    /// `Ops::copyAcross` from this connection to `destination`, both owned
    /// by this thread (T5).
    ///
    /// # Errors
    /// The backends' failure; `Internal` when `progress` panicked.
    pub fn copy_across(
        &mut self,
        source_path: &[u8],
        destination: &mut Self,
        destination_path: &[u8],
        (recursive, replace): (bool, bool),
        progress: Option<&mut dyn Progress>,
    ) -> Result<(), Status> {
        let source = self.core.ready()?;
        let target = destination.core.ready()?;
        let mut progress = ProgressArg::new(progress);
        let raw_progress = progress.raw();
        let (source_path, destination_path) = (NvbBytes::of(source_path), NvbBytes::of(destination_path));
        // SAFETY: both connections belong to this thread (T5; `&mut` makes
        // them two); paths and progress live across the call (O1).
        let error = unsafe {
            (self.ffi().t.copy_across)(
                source,
                source_path,
                target,
                destination_path,
                i32::from(recursive),
                i32::from(replace),
                opt_ptr(raw_progress.as_ref()),
            )
        };
        progress.finish(self.ffi().check(error))
    }
}

/// An open read handle (`nvb_handle`, XC-13), owned by its connection's
/// thread; it keeps the connection alive. Closed when it goes.
pub struct Handle {
    core: Rc<Core>,
    raw: Option<NonNull<NvbHandle>>,
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle").field("raw", &self.raw).finish_non_exhaustive()
    }
}

impl Handle {
    fn ready(&self) -> Result<*mut NvbHandle, Status> {
        self.core.ready()?;
        self.raw.map(NonNull::as_ptr).ok_or_else(|| Status::internal("the handle is closed"))
    }

    /// Reads at most `buf.len()` bytes at `offset`; fewer only at the end.
    ///
    /// # Errors
    /// The backend's failure.
    pub fn read(&mut self, offset: i64, buf: &mut [u8]) -> Result<usize, Status> {
        let handle = self.ready()?;
        let mut len = 0;
        // SAFETY: owner thread (T4); `buf` is ours for the call; C++ writes
        // at most `buf.len()` bytes into it.
        let error = unsafe {
            (self.core.ffi.t.handle_read)(handle, offset, buf.as_mut_ptr(), buf.len(), &raw mut len)
        };
        self.core.ffi.check(error)?;
        if len > buf.len() {
            return Err(Status::internal("handle_read reported more than it was given"));
        }
        Ok(len)
    }

    /// `ReadHandle::readAhead`: a hint.
    pub fn read_ahead(&mut self, offset: i64, bytes: i64) {
        if let Ok(handle) = self.ready() {
            // SAFETY: owner thread (T4), a live handle.
            unsafe { (self.core.ffi.t.handle_read_ahead)(handle, offset, bytes) }
        }
    }

    /// Closes the handle.
    ///
    /// # Errors
    /// The backend's failure to close; the handle is gone either way.
    pub fn close(mut self) -> Result<(), Status> {
        self.close_now()
    }

    fn close_now(&mut self) -> Result<(), Status> {
        let Some(handle) = self.raw.take() else { return Ok(()) };
        // SAFETY: owner thread (T4); handle_close always frees, and `raw` no
        // longer holds the pointer.
        let error = unsafe { (self.core.ffi.t.handle_close)(handle.as_ptr()) };
        self.core.ffi.check(error)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // Nobody to tell about a failure to close; the handle is gone.
        self.close_now().unwrap_or_default();
    }
}

#[cfg(test)]
mod tests {
    // Tests call the trampolines and readers as C++ would, on data they
    // made themselves; they may index, count and cast freely.
    #![allow(
        clippy::undocumented_unsafe_blocks,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::items_after_statements,
        clippy::panic,
        trivial_casts
    )]
    use super::*;
    use netvfs_bridge_proto::ErrorName;

    #[test]
    fn phases() {
        assert_eq!(Phase::from_raw(NVB_PHASE_CONNECT), Phase::Connect);
        assert_eq!(Phase::from_raw(NVB_PHASE_IDENTITY), Phase::Identity);
        assert_eq!(Phase::from_raw(NVB_PHASE_CREDENTIALS), Phase::Credentials);
        assert_eq!(Phase::from_raw(NVB_PHASE_AUTHENTICATE), Phase::Authenticate);
        assert_eq!(Phase::from_raw(NVB_PHASE_DONE), Phase::Done);
        assert_eq!(Phase::from_raw(0), Phase::Connect);
        assert_eq!(Phase::from_raw(77), Phase::Connect);
    }

    #[test]
    fn secrets_are_borrowed_not_copied() {
        let secret = Secret::Bytes { user: "u".into(), secret: Zeroizing::new(b"pw".to_vec()) };
        let raw = secret.raw();
        let Secret::Bytes { secret: bytes, user } = &secret else { panic!("not bytes") };
        assert_eq!(raw.source, NVB_SECRET_BYTES);
        assert_eq!((raw.secret.ptr, raw.secret.len), (bytes.as_ptr(), 2));
        assert_eq!((raw.user.ptr, raw.user.len), (user.as_ptr(), 1));
        let none = Secret::None { user: "v".into() }.raw();
        assert_eq!((none.source, none.user.len, none.secret.len), (NVB_SECRET_NONE, 1, 0));
        let signon = Secret::Signon { user: "w".into(), credentials_id: 7, secret_optional: true }.raw();
        assert_eq!((signon.source, signon.credentials_id, signon.secret_optional), (NVB_SECRET_SIGNON, 7, 1));
        assert_eq!(signon.user.len, 1);
        let strict = Secret::Signon { user: String::new(), credentials_id: 0, secret_optional: false }.raw();
        assert_eq!((strict.secret_optional, strict.user.len), (0, 0));
    }

    #[test]
    fn attributes() {
        let none = Attributes::default().raw();
        assert_eq!((none.mode, none.has_mtime, none.has_atime), (-1, 0, 0));
        let all = Attributes { mode: Some(0o600), mtime_ms: Some(5), atime_ms: Some(6) }.raw();
        assert_eq!((all.mode, all.has_mtime, all.has_atime, all.mtime_ms, all.atime_ms), (0o600, 1, 1, 5, 6));
    }

    #[test]
    fn upload_options() {
        let o =
            UploadOptions::CreateNew { mode: Some(0o640), expected_size: Some(10), mtime_ms: Some(5) }.raw();
        assert_eq!((o.disposition, o.create_mode, o.resume_offset), (NVB_DISPOSITION_CREATE_NEW, 0o640, 0));
        assert_eq!((o.expected_size, o.has_mtime, o.mtime_ms), (10, 1, 5));
        let o = UploadOptions::CreateNew { mode: None, expected_size: None, mtime_ms: None }.raw();
        assert_eq!((o.create_mode, o.expected_size, o.has_mtime), (-1, -1, 0));
        let o = UploadOptions::Truncate { mode: None, expected_size: Some(3), mtime_ms: None }.raw();
        assert_eq!((o.disposition, o.create_mode, o.expected_size), (NVB_DISPOSITION_TRUNCATE, -1, 3));
        let o = UploadOptions::Truncate { mode: Some(0o600), expected_size: None, mtime_ms: None }.raw();
        assert_eq!(o.create_mode, 0o600);
        let o = UploadOptions::Resume { offset: 9, expected_size: None, mtime_ms: Some(1) }.raw();
        assert_eq!(
            (o.disposition, o.resume_offset, o.has_mtime, o.mtime_ms),
            (NVB_DISPOSITION_RESUME, 9, 1, 1)
        );
    }

    #[test]
    fn walk_options() {
        let o = WalkOptions::default().raw();
        assert_eq!((o.max_depth, o.follow_symlinks, o.post_order, o.stop_on_list_error), (-1, 0, 0, 0));
        let o = WalkOptions {
            max_depth: Some(0),
            follow_symlinks: true,
            post_order: true,
            stop_on_list_error: true,
        }
        .raw();
        assert_eq!((o.max_depth, o.follow_symlinks, o.post_order, o.stop_on_list_error), (0, 1, 1, 1));
        assert_eq!(WalkOptions { max_depth: Some(u32::MAX), ..WalkOptions::default() }.raw().max_depth, -1);
        assert_eq!(WalkOptions { max_depth: Some(3), ..WalkOptions::default() }.raw().max_depth, 3);
    }

    struct Ticks(Vec<(i64, i64)>);

    impl Progress for Ticks {
        fn update(&mut self, done: i64, total: i64) {
            self.0.push((done, total));
        }
    }

    #[test]
    fn progress_args() {
        let mut none = ProgressArg::new(None);
        assert!(none.raw().is_none());
        assert!(opt_ptr::<NvbProgress>(None).is_null());
        assert_eq!(none.finish(Ok(1)), Ok(1));
        let mut ticks = Ticks(Vec::new());
        let mut arg = ProgressArg::new(Some(&mut ticks));
        let raw = arg.raw().unwrap();
        let ctx_ptr = raw.ctx;
        assert_eq!(ctx_ptr, arg.ctx.as_mut().map(Ctx::as_ctx).unwrap());
        // As C++ calls it.
        unsafe { raw.update.unwrap()(raw.ctx, 3, -1) };
        assert_eq!(unsafe { raw.canceled.unwrap()(raw.ctx) }, 0);
        assert!(!opt_ptr(Some(&raw)).is_null());
        assert_eq!(
            arg.finish(Err::<(), _>(Status::new(ErrorName::Canceled, ""))).unwrap_err().name,
            ErrorName::Canceled
        );
        assert_eq!(ticks.0, [(3, -1)]);
    }
}
