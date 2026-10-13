// SPDX-License-Identifier: LGPL-2.1-or-later
//! The C++ backends through the C ABI of `libnetvfs-bridge-ffi.so`
//! (`src/bridge/ffi/netvfs_bridge_ffi.h`; design §1, §3.3).
//!
//! Plain Rust in, `Result<_, Status>` out. The rules of the header are
//! kept by the types:
//!
//! - T1: [`Ffi::init`] only on the process's main thread, which becomes the
//!   Qt thread; [`Ffi::run`] and [`Ffi::shutdown`] only there.
//! - T3: a [`Discovery`] is made on the Qt thread (inside a function given
//!   to [`Ffi::post`]) and, being `!Send`, stays there.
//! - T4: a [`Conn`] and its [`Handle`]s are `!Send`: the thread that made
//!   the connection is its owner. [`CancelHandle`] is the one part that
//!   crosses threads; it shares a lock with the connection, so a cancel
//!   never overlaps or follows `conn_free`.
//! - T6: callbacks get plain Rust values; inside one, the connection
//!   methods of the thread refuse to run.
//! - T7: a panic in a callback is caught before it reaches C++ and reported
//!   as `Internal` by the call (see [`callback`]).
//! - O3: every block C++ returns is read into Rust values and freed at once.
//! - O5: secrets go in as [`Zeroizing`](zeroize::Zeroizing) buffers, which
//!   C++ copies and wipes; no copy is made on this side.
//!
//! This module and a later `sys` are the only ones with `unsafe`; every
//! block says why it holds.
#![allow(unsafe_code)]

pub mod callback;
mod conn;
mod discovery;
#[cfg(feature = "testing")]
pub mod fake;
mod loader;
pub mod marshal;
pub mod raw;

pub use callback::{
    EstablishHooks, IdentityHook, Progress, PromptHook, ReadAt, Reply, Verdict, WriteAt, take_orphan_panics,
};
pub use conn::{
    Attributes, CancelHandle, Conn, EstablishError, Handle, Phase, Secret, Space, TreeCounts, UploadOptions,
    WalkOptions,
};
pub use discovery::Discovery;
pub use loader::LoadError;
pub use marshal::{
    Identity, IdentityKind, Params, ParamsBuf, ParsedUrl, Prompt, PromptRequest, Value, ValueMap,
};

use crate::Status;
use raw::{NvbBlob, NvbBytes, NvbError, NvbFfiV1, NvbUrl};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread::ThreadId;

/// Where the library is installed (`%{_libdir}/netvfs`).
pub const DEFAULT_PATH: &str = "/usr/lib64/netvfs/libnetvfs-bridge-ffi.so";
/// Overrides [`DEFAULT_PATH`], for tests only.
pub const PATH_ENV: &str = "NETVFS_BRIDGE_FFI";

/// The thread `init` made the Qt thread.
static QT_THREAD: OnceLock<ThreadId> = OnceLock::new();

impl loader::Table for NvbFfiV1 {
    fn header(&self) -> (u32, u32) {
        (self.version, self.struct_size)
    }
}

/// The loaded table. Cheap to copy, `Send` and `Sync`: the library is never
/// unloaded.
#[derive(Clone, Copy)]
pub struct Ffi {
    t: &'static NvbFfiV1,
}

impl std::fmt::Debug for Ffi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ffi").field("version", &self.t.version).finish_non_exhaustive()
    }
}

/// A block C++ allocated (O3), freed when this goes.
struct Owned<T> {
    ffi: Ffi,
    ptr: *mut T,
}

impl<T> Owned<T> {
    const fn new(ffi: Ffi, ptr: *mut T) -> Self {
        Self { ffi, ptr }
    }

    fn get(&self) -> Option<&T> {
        // SAFETY: NULL or a block C++ handed over (O3), valid until freed
        // in `drop`.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        // SAFETY: NULL or a block of this library that nothing else frees.
        unsafe { (self.ffi.t.free)(self.ptr.cast()) }
    }
}

/// The path of the library: `NETVFS_BRIDGE_FFI` or [`DEFAULT_PATH`].
#[must_use]
pub fn library_path() -> PathBuf {
    std::env::var_os(PATH_ENV).map_or_else(|| PathBuf::from(DEFAULT_PATH), PathBuf::from)
}

/// Whether this is the process's main thread.
fn on_main_thread() -> bool {
    // SAFETY: getpid and gettid have no preconditions.
    unsafe { libc::getpid() == libc::gettid() }
}

impl Ffi {
    /// Loads the library at [`library_path`].
    ///
    /// # Errors
    /// When it cannot be loaded or does not offer this build's table.
    pub fn load() -> Result<Self, LoadError> {
        Self::load_from(&library_path())
    }

    /// Loads the library at `path`.
    ///
    /// # Errors
    /// When it cannot be loaded or does not offer this build's table.
    pub fn load_from(path: &Path) -> Result<Self, LoadError> {
        Self::load_version(path, raw::NVB_FFI_VERSION)
    }

    /// Loads `path` asking for another version of the table (tests of the
    /// refusal).
    ///
    /// # Errors
    /// As [`Ffi::load_from`].
    #[cfg(feature = "testing")]
    pub fn load_requesting(path: &Path, version: u32) -> Result<Self, LoadError> {
        Self::load_version(path, version)
    }

    fn load_version(path: &Path, version: u32) -> Result<Self, LoadError> {
        loader::load_table::<NvbFfiV1>(path, c"nvb_ffi_get", version).map(|t| Self { t })
    }

    /// The table's `struct_size`.
    #[must_use]
    pub const fn struct_size(&self) -> u32 {
        self.t.struct_size
    }

    /// `Err` with the block's status, `Ok` for NULL; frees the block.
    fn check(self, error: *mut NvbError) -> Result<(), Status> {
        // SAFETY: the block is readable until `owned` frees it (O3).
        Owned::new(self, error).get().map_or(Ok(()), |e| Err(unsafe { marshal::status(e) }))
    }

    /// Reads and frees a block a call returned through its out-pointer.
    fn take<T, R>(self, ptr: *mut T, read: impl FnOnce(&T) -> R) -> Result<R, Status> {
        let owned = Owned::new(self, ptr);
        owned.get().map(read).ok_or_else(|| Status::internal("no result from the C ABI"))
    }

    /// The bytes of a blob, freed.
    fn take_blob(self, blob: *mut NvbBlob) -> Result<Vec<u8>, Status> {
        // SAFETY: the blob's bytes live in its block (O3).
        self.take(blob, |b| unsafe { marshal::slice(b.data) }.to_vec())
    }

    // ------------------------------------------------ process and Qt loop

    /// Creates the `QCoreApplication` (T1): first of all calls, on the
    /// process's main thread, which becomes the Qt thread.
    ///
    /// # Errors
    /// `Internal` off the main thread or when the application exists.
    pub fn init(&self, app_name: &str) -> Result<(), Status> {
        if !on_main_thread() {
            return Err(Status::internal("init must run on the main thread"));
        }
        // SAFETY: on the main thread (T1); the name is borrowed (O1).
        if unsafe { (self.t.init)(NvbBytes::of(app_name.as_bytes())) } != 0 {
            return Err(Status::internal("the Qt application exists already"));
        }
        // The first init on the main thread wins; a later one was refused.
        QT_THREAD.get_or_init(|| std::thread::current().id());
        Ok(())
    }

    /// Whether this is the Qt thread (`init` succeeded on it).
    #[must_use]
    pub fn on_qt_thread(&self) -> bool {
        QT_THREAD.get().is_some_and(|id| *id == std::thread::current().id())
    }

    fn require_qt_thread(self) -> Result<(), Status> {
        if self.on_qt_thread() { Ok(()) } else { Err(Status::internal("not on the Qt thread")) }
    }

    /// Runs the Qt event loop until [`Ffi::quit`]; its code.
    ///
    /// # Errors
    /// `Internal` off the Qt thread.
    pub fn run(&self) -> Result<i32, Status> {
        self.require_qt_thread()?;
        // SAFETY: on the Qt thread, after init (T1).
        Ok(unsafe { (self.t.run)() })
    }

    /// Ends [`Ffi::run`] with `code`; any thread.
    pub fn quit(&self, code: i32) {
        // SAFETY: any thread (T2).
        unsafe { (self.t.quit)(code) }
    }

    /// Runs `f` on the Qt thread. False when it was not queued (no
    /// application, or quitting): then it never runs. A panic in `f` is
    /// kept for [`take_orphan_panics`].
    pub fn post<F: FnOnce() + Send + 'static>(&self, f: F) -> bool {
        let posted: Box<callback::Posted> = Box::new(Box::new(f));
        let ctx = Box::into_raw(posted);
        // SAFETY: any thread (T2); `ctx` is a leaked box that `run_posted`
        // takes back when C++ runs it.
        if unsafe { (self.t.post)(Some(callback::run_posted), ctx.cast()) } == 1 {
            return true;
        }
        // SAFETY: not queued: C++ never runs it, so the box is still ours.
        drop(unsafe { Box::from_raw(ctx) });
        false
    }

    /// Deletes the application after [`Ffi::run`]; functions posted and
    /// queued before run first.
    ///
    /// # Errors
    /// `Internal` off the Qt thread.
    pub fn shutdown(&self) -> Result<(), Status> {
        self.require_qt_thread()?;
        // SAFETY: on the Qt thread (T1).
        unsafe { (self.t.shutdown)() };
        Ok(())
    }

    // ------------------------------------------------------------ helpers

    /// Whether a backend plugin for `provider` is installed.
    #[must_use]
    pub fn provider_available(&self, provider: &str) -> bool {
        // SAFETY: any thread (T2); borrowed (O1).
        unsafe { (self.t.provider_available)(NvbBytes::of(provider.as_bytes())) == 1 }
    }

    /// `Url::parse` (XH-6): parameters and path of a location URL.
    ///
    /// # Errors
    /// The parser's refusal (`SecurityPolicy` for a password, `Unsupported`
    /// for an unknown scheme, …).
    pub fn url_parse(&self, url: &str) -> Result<ParsedUrl, Status> {
        let mut out: *mut NvbUrl = std::ptr::null_mut();
        // SAFETY: any thread (T2); `url` borrowed (O1); `out` is ours.
        let error = unsafe { (self.t.url_parse)(NvbBytes::of(url.as_bytes()), &raw mut out) };
        self.check(error)?;
        // SAFETY: the block holds everything it points to (O3).
        self.take(out, |u| unsafe {
            ParsedUrl { params: marshal::params(&u.params), path: marshal::slice(u.path).to_vec() }
        })
    }

    /// `Url::format`: the URL of parameters and a path.
    ///
    /// # Errors
    /// `Unsupported` for a provider without a URL form, `ProtocolError` for
    /// unusable parameters.
    pub fn url_format(&self, params: &Params, path: &[u8]) -> Result<String, Status> {
        let buf = ParamsBuf::new(params);
        let mut out: *mut NvbBlob = std::ptr::null_mut();
        // SAFETY: any thread (T2); `buf` and `path` live across the call (O1).
        let error = unsafe { (self.t.url_format)(buf.raw(), NvbBytes::of(path), &raw mut out) };
        self.check(error)?;
        self.take_blob(out).map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// A connection for `provider`, owned by this thread (T4).
    ///
    /// # Errors
    /// `Unsupported` when there is no such backend.
    pub fn conn_new(&self, provider: &str) -> Result<Conn, Status> {
        Conn::new(*self, provider)
    }
}
