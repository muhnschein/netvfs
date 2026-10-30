// SPDX-License-Identifier: LGPL-2.1-or-later
//! The C ABI of `libnetvfs-bridge-ffi.so`, by hand from `src/bridge/ffi/netvfs_bridge_ffi.h`: data types (shared with netvfs-backend, [`netvfs_vfs::abi`]), handles and the table. Field and slot order are the header's; `layout` tests pin sizes and offsets on LP64 to what the C compiler gives. Ownership and threads rules are in the header.

pub use netvfs_vfs::abi::*;

use std::ffi::c_void;
use std::marker::{PhantomData, PhantomPinned};

/// `NVB_FFI_ENTRY`, NUL-terminated for `dlsym`.
pub const NVB_FFI_ENTRY: &[u8] = b"nvb_ffi_get\0";

/// An opaque C++ object behind a pointer: neither constructible, nor
/// `Send`, `Sync` or `Unpin` (the nomicon's pattern).
macro_rules! opaque {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {$(
        $(#[$doc])*
        #[repr(C)]
        #[derive(Debug)]
        pub struct $name {
            _data: [u8; 0],
            _marker: PhantomData<(*mut u8, PhantomPinned)>,
        }
    )*};
}

opaque! {
    /// `nvb_conn`: one `NetVfs::Backend`.
    NvbConn,
    /// `nvb_handle`: one `NetVfs::ReadHandle`.
    NvbHandle,
    /// `nvb_discovery`: one `NetVfs::Discovery`.
    NvbDiscovery,
}

/// `nvb_ffi`: the table, in the header's order.
#[repr(C)]
#[derive(Debug)]
#[allow(clippy::type_complexity)]
pub struct NvbFfi {
    /// `QCoreApplication`; 0 ok, -1 twice.
    pub init: unsafe extern "C" fn(NvbBytes) -> i32,
    /// `exec()`; returns `quit()`'s code.
    pub run: unsafe extern "C" fn() -> i32,
    /// Queued exit; any thread.
    pub quit: unsafe extern "C" fn(i32),
    /// 1 queued, 0 not: `fn` never runs.
    pub post: unsafe extern "C" fn(Option<NvbPostFn>, *mut c_void) -> i32,
    /// After `run()`: deletes the app.
    pub shutdown: unsafe extern "C" fn(),
    /// Releases a block; NULL is a no-op.
    pub free: unsafe extern "C" fn(*mut c_void),
    /// `BackendLoader::isAvailable`.
    pub provider_available: unsafe extern "C" fn(NvbBytes) -> i32,
    /// `Url::parse`.
    pub url_parse: unsafe extern "C" fn(NvbBytes, *mut *mut NvbUrl) -> *mut NvbError,
    /// `Url::format`.
    pub url_format: unsafe extern "C" fn(*const NvbParams, NvbBytes, *mut *mut NvbBlob) -> *mut NvbError,
    /// `BackendLoader::create`.
    pub conn_new: unsafe extern "C" fn(NvbBytes, *mut *mut NvbConn) -> *mut NvbError,
    /// Closes handles, disconnects, deletes.
    pub conn_free: unsafe extern "C" fn(*mut NvbConn),
    /// `Backend::cancel`; any thread.
    pub conn_cancel: unsafe extern "C" fn(*mut NvbConn),
    /// `Backend::resetCancel`.
    pub conn_reset_cancel: unsafe extern "C" fn(*mut NvbConn),
    /// Connect, identity verdict, secret, authenticate.
    pub conn_establish: unsafe extern "C" fn(
        *mut NvbConn,
        *const NvbParams,
        NvbBytes,
        *const NvbSecret,
        *const NvbEstablishHooks,
        *mut u32,
    ) -> *mut NvbError,
    /// Fills a prompt's answers.
    pub reply_set: unsafe extern "C" fn(*mut NvbReply, *const NvbBytes, usize),
    /// `Backend::capabilities`.
    pub conn_capabilities: unsafe extern "C" fn(*mut NvbConn, *mut *mut NvbCapabilities) -> *mut NvbError,
    /// `Backend::stat`.
    pub conn_stat: unsafe extern "C" fn(*mut NvbConn, NvbBytes, i32, *mut *mut NvbEntry) -> *mut NvbError,
    /// `Backend::list`.
    pub conn_list: unsafe extern "C" fn(
        *mut NvbConn,
        NvbBytes,
        u32,
        Option<NvbListSinkFn>,
        *mut c_void,
    ) -> *mut NvbError,
    /// `Backend::readLink`.
    pub conn_read_link: unsafe extern "C" fn(*mut NvbConn, NvbBytes, *mut *mut NvbBlob) -> *mut NvbError,
    /// `Backend::spaceInfo`.
    pub conn_space_info: unsafe extern "C" fn(*mut NvbConn, NvbBytes, *mut NvbSpace) -> *mut NvbError,
    /// `Backend::checksum`.
    pub conn_checksum:
        unsafe extern "C" fn(*mut NvbConn, NvbBytes, NvbBytes, *mut *mut NvbBlob) -> *mut NvbError,
    /// `Backend::makeDir`.
    pub conn_make_dir: unsafe extern "C" fn(*mut NvbConn, NvbBytes, i32) -> *mut NvbError,
    /// `Backend::removeFile`.
    pub conn_remove_file: unsafe extern "C" fn(*mut NvbConn, NvbBytes) -> *mut NvbError,
    /// `Backend::removeDir`.
    pub conn_remove_dir: unsafe extern "C" fn(*mut NvbConn, NvbBytes) -> *mut NvbError,
    /// `Backend::rename`.
    pub conn_rename: unsafe extern "C" fn(*mut NvbConn, NvbBytes, NvbBytes, i32) -> *mut NvbError,
    /// `Backend::setAttributes`.
    pub conn_set_attributes:
        unsafe extern "C" fn(*mut NvbConn, NvbBytes, *const NvbAttributes) -> *mut NvbError,
    /// `Backend::makeSymlink`.
    pub conn_make_symlink: unsafe extern "C" fn(*mut NvbConn, NvbBytes, NvbBytes) -> *mut NvbError,
    /// `Backend::makeHardlink`.
    pub conn_make_hardlink: unsafe extern "C" fn(*mut NvbConn, NvbBytes, NvbBytes) -> *mut NvbError,
    /// `Backend::copy` (ServerCopy).
    pub conn_copy: unsafe extern "C" fn(*mut NvbConn, NvbBytes, NvbBytes, i32, i32) -> *mut NvbError,
    /// `Backend::openRead`.
    pub conn_open_read:
        unsafe extern "C" fn(*mut NvbConn, NvbBytes, *mut *mut NvbHandle, *mut i64) -> *mut NvbError,
    /// `ReadHandle::read`; short only at EOF.
    pub handle_read: unsafe extern "C" fn(*mut NvbHandle, i64, *mut u8, usize, *mut usize) -> *mut NvbError,
    /// `ReadHandle::readAhead`.
    pub handle_read_ahead: unsafe extern "C" fn(*mut NvbHandle, i64, i64),
    /// `ReadHandle::close` and delete; always frees.
    pub handle_close: unsafe extern "C" fn(*mut NvbHandle) -> *mut NvbError,
    /// `Backend::upload`.
    pub conn_upload: unsafe extern "C" fn(
        *mut NvbConn,
        NvbBytes,
        *const NvbUploadOpts,
        *const NvbIo,
        *const NvbProgress,
    ) -> *mut NvbError,
    /// `Backend::download`.
    pub conn_download: unsafe extern "C" fn(
        *mut NvbConn,
        NvbBytes,
        i64,
        i64,
        *const NvbIo,
        *const NvbProgress,
    ) -> *mut NvbError,
    /// `Ops::removeTree`.
    pub remove_tree:
        unsafe extern "C" fn(*mut NvbConn, NvbBytes, *const NvbProgress, *mut i64, *mut i64) -> *mut NvbError,
    /// `Ops::walk`.
    pub walk: unsafe extern "C" fn(
        *mut NvbConn,
        NvbBytes,
        *const NvbWalkOpts,
        Option<NvbWalkVisitFn>,
        *mut c_void,
    ) -> *mut NvbError,
    /// `Ops::copyAcross`.
    pub copy_across: unsafe extern "C" fn(
        *mut NvbConn,
        NvbBytes,
        *mut NvbConn,
        NvbBytes,
        i32,
        i32,
        *const NvbProgress,
    ) -> *mut NvbError,
    /// `Discovery`; Qt thread.
    pub discovery_new: unsafe extern "C" fn(*const NvbDiscoveryHooks) -> *mut NvbDiscovery,
    /// Idempotent; 1 if a socket is open.
    pub discovery_set_running: unsafe extern "C" fn(*mut NvbDiscovery, i32) -> i32,
    /// No hook call after it returns.
    pub discovery_free: unsafe extern "C" fn(*mut NvbDiscovery),
}

/// `nvb_ffi_get_fn`.
pub type NvbFfiGetFn = unsafe extern "C" fn() -> *const NvbFfi;

#[cfg(all(test, target_pointer_width = "64"))]
mod layout {
    //! Table size and slot offsets as gcc gives them on LP64; data types' are pinned in [`netvfs_vfs::abi`].
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn table() {
        assert_eq!(size_of::<NvbFfi>(), 328);
        assert_eq!((offset_of!(NvbFfi, init), offset_of!(NvbFfi, free)), (0, 40));
        assert_eq!((offset_of!(NvbFfi, conn_new), offset_of!(NvbFfi, reply_set)), (72, 112));
        assert_eq!((offset_of!(NvbFfi, conn_open_read), offset_of!(NvbFfi, copy_across)), (232, 296));
        assert_eq!(offset_of!(NvbFfi, discovery_free), 320);
    }
}
