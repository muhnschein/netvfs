// SPDX-License-Identifier: LGPL-2.1-or-later
//! The C++ backends through the C ABI of `libnetvfs-bridge-ffi.so` (`src/bridge/ffi/netvfs_bridge_ffi.h`).
//!
//! Plain Rust in, `Result<_, Status>` out. The header's rules are kept by the types:
//!
//! - [`Ffi::init`] only on the process's main thread, which becomes the Qt thread; [`Ffi::run`] and [`Ffi::shutdown`] only there.
//! - A [`Discovery`] is made on the Qt thread (inside a function given to [`Ffi::post`]) and, being `!Send`, stays there.
//! - A [`Conn`] and its [`Handle`]s are `!Send`: the making thread owns them. [`CancelHandle`] crosses threads; it shares a lock with the connection, so a cancel never overlaps or follows `conn_free`.
//! - Callbacks get plain Rust values; inside one, the connection methods of the thread refuse to run.
//! - A panic in a callback is caught before C++ and reported as `Internal` by the call (see [`callback`]).
//! - Every block C++ returns is read into Rust values and freed at once.
//! - Secrets go in as [`Zeroizing`](zeroize::Zeroizing) buffers, which C++ copies and wipes; no copy on this side.
//!
//! With `sys`, the only modules with `unsafe`; every block says why it holds.
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
use raw::{NvbBlob, NvbBytes, NvbError, NvbFfi, NvbUrl};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread::ThreadId;

/// Where the library is installed (`%{_libdir}/netvfs`).
pub const DEFAULT_PATH: &str = "/usr/lib64/netvfs/libnetvfs-bridge-ffi.so";
/// Overrides [`DEFAULT_PATH`], for tests only.
pub const PATH_ENV: &str = "NETVFS_BRIDGE_FFI";

/// The thread `init` made the Qt thread.
static QT_THREAD: OnceLock<ThreadId> = OnceLock::new();

/// The loaded table. Cheap to copy, `Send` and `Sync`: the library is never unloaded.
#[derive(Clone, Copy)]
pub struct Ffi {
    t: &'static NvbFfi,
}

impl std::fmt::Debug for Ffi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ffi").finish_non_exhaustive()
    }
}

/// A block C++ allocated, freed when this goes.
struct Owned<T> {
    ffi: Ffi,
    ptr: *mut T,
}

impl<T> Owned<T> {
    const fn new(ffi: Ffi, ptr: *mut T) -> Self {
        Self { ffi, ptr }
    }

    fn get(&self) -> Option<&T> {
        // SAFETY: NULL or a block C++ handed over, valid until freed in `drop`.
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

fn on_main_thread() -> bool {
    // SAFETY: getpid and gettid have no preconditions.
    unsafe { libc::getpid() == libc::gettid() }
}

impl Ffi {
    /// Loads the library at [`library_path`].
    ///
    /// # Errors
    /// It cannot be loaded.
    pub fn load() -> Result<Self, LoadError> {
        Self::load_from(&library_path())
    }

    /// Loads the library at `path`.
    ///
    /// # Errors
    /// It cannot be loaded.
    pub fn load_from(path: &Path) -> Result<Self, LoadError> {
        loader::load_table::<NvbFfi>(path, c"nvb_ffi_get").map(|t| Self { t })
    }

    fn check(self, error: *mut NvbError) -> Result<(), Status> {
        // SAFETY: the block is readable until `owned` frees it.
        Owned::new(self, error).get().map_or(Ok(()), |e| Err(unsafe { marshal::status(e) }))
    }

    fn take<T, R>(self, ptr: *mut T, read: impl FnOnce(&T) -> R) -> Result<R, Status> {
        let owned = Owned::new(self, ptr);
        owned.get().map(read).ok_or_else(|| Status::internal("no result from the C ABI"))
    }

    fn take_blob(self, blob: *mut NvbBlob) -> Result<Vec<u8>, Status> {
        // SAFETY: the blob's bytes live in its block.
        self.take(blob, |b| unsafe { marshal::slice(b.data) }.to_vec())
    }

    /// Creates the `QCoreApplication`: first of all calls, on the process's main thread, which becomes the Qt thread.
    ///
    /// # Errors
    /// `Internal` off the main thread or when the application exists.
    pub fn init(&self, app_name: &str) -> Result<(), Status> {
        if !on_main_thread() {
            return Err(Status::internal("init must run on the main thread"));
        }
        // SAFETY: main thread; the name is borrowed.
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
        // SAFETY: Qt thread, after init.
        Ok(unsafe { (self.t.run)() })
    }

    /// Ends [`Ffi::run`] with `code`; any thread.
    pub fn quit(&self, code: i32) {
        // SAFETY: any thread.
        unsafe { (self.t.quit)(code) }
    }

    /// Runs `f` on the Qt thread. False when not queued (no application, or quitting): then it never runs. A panic in `f` is kept for [`take_orphan_panics`].
    pub fn post<F: FnOnce() + Send + 'static>(&self, f: F) -> bool {
        let posted: Box<callback::Posted> = Box::new(Box::new(f));
        let ctx = Box::into_raw(posted);
        // SAFETY: any thread; `ctx` is a leaked box that `run_posted` takes back when C++ runs it.
        if unsafe { (self.t.post)(Some(callback::run_posted), ctx.cast()) } == 1 {
            return true;
        }
        // SAFETY: not queued: C++ never runs it, so the box is still ours.
        drop(unsafe { Box::from_raw(ctx) });
        false
    }

    /// Deletes the application after [`Ffi::run`]; functions posted and queued before run first.
    ///
    /// # Errors
    /// `Internal` off the Qt thread.
    pub fn shutdown(&self) -> Result<(), Status> {
        self.require_qt_thread()?;
        // SAFETY: Qt thread.
        unsafe { (self.t.shutdown)() };
        Ok(())
    }

    /// Whether a backend plugin for `provider` is installed.
    #[must_use]
    pub fn provider_available(&self, provider: &str) -> bool {
        // SAFETY: any thread; borrowed.
        unsafe { (self.t.provider_available)(NvbBytes::of(provider.as_bytes())) == 1 }
    }

    /// `Url::parse`: parameters and path of a location URL.
    ///
    /// # Errors
    /// The parser's refusal (`SecurityPolicy` for a password, `Unsupported` for an unknown scheme, …).
    pub fn url_parse(&self, url: &str) -> Result<ParsedUrl, Status> {
        let mut out: *mut NvbUrl = std::ptr::null_mut();
        // SAFETY: any thread; `url` borrowed; `out` is ours.
        let error = unsafe { (self.t.url_parse)(NvbBytes::of(url.as_bytes()), &raw mut out) };
        self.check(error)?;
        // SAFETY: the block holds everything it points to.
        self.take(out, |u| unsafe {
            ParsedUrl { params: marshal::params(&u.params), path: marshal::slice(u.path).to_vec() }
        })
    }

    /// `Url::format`: the URL of parameters and a path.
    ///
    /// # Errors
    /// `Unsupported` for a provider without a URL form, `ProtocolError` for unusable parameters.
    pub fn url_format(&self, params: &Params, path: &[u8]) -> Result<String, Status> {
        let buf = ParamsBuf::new(params);
        let mut out: *mut NvbBlob = std::ptr::null_mut();
        // SAFETY: any thread; `buf` and `path` live across the call.
        let error = unsafe { (self.t.url_format)(buf.raw(), NvbBytes::of(path), &raw mut out) };
        self.check(error)?;
        self.take_blob(out).map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// A connection for `provider`, owned by this thread.
    ///
    /// # Errors
    /// `Unsupported` when there is no such backend.
    pub fn conn_new(&self, provider: &str) -> Result<Conn, Status> {
        Conn::new(*self, provider)
    }
}
