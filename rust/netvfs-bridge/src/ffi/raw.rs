// SPDX-License-Identifier: LGPL-2.1-or-later
//! The C ABI of `libnetvfs-bridge-ffi.so`, written by hand from
//! `src/bridge/ffi/netvfs_bridge_ffi.h` (frozen; fields are only ever
//! appended). Field order, types and the table's slot order are the
//! header's; `layout` tests below pin sizes and offsets on LP64 to what the
//! C compiler gives. Names are the header's in Rust case (`nvb_bytes` is
//! [`NvbBytes`]). The comments say what each field carries; ownership (O1 to
//! O5) and threads (T1 to T7) are in the header.

use std::ffi::{c_int, c_void};
use std::marker::{PhantomData, PhantomPinned};

/// `NVB_FFI_VERSION`.
pub const NVB_FFI_VERSION: u32 = 1;
/// `NVB_FFI_ENTRY`, NUL-terminated for `dlsym`.
pub const NVB_FFI_ENTRY: &[u8] = b"nvb_ffi_get\0";

/// `NVB_VALUE_STRING`: UTF-8 bytes.
pub const NVB_VALUE_STRING: u32 = 1;
/// `NVB_VALUE_BOOL`: number 0 or 1.
pub const NVB_VALUE_BOOL: u32 = 2;
/// `NVB_VALUE_INT`: number.
pub const NVB_VALUE_INT: u32 = 3;
/// `NVB_VALUE_BYTES`: bytes.
pub const NVB_VALUE_BYTES: u32 = 4;
/// `NVB_VALUE_STRING_LIST`: items, UTF-8 each.
pub const NVB_VALUE_STRING_LIST: u32 = 5;

/// `NVB_IDENTITY_NONE`.
pub const NVB_IDENTITY_NONE: u32 = 0;
/// `NVB_IDENTITY_SSH`.
pub const NVB_IDENTITY_SSH: u32 = 1;
/// `NVB_IDENTITY_TLS`.
pub const NVB_IDENTITY_TLS: u32 = 2;

/// `NVB_SECRET_NONE`: `Credentials(user, "")`.
pub const NVB_SECRET_NONE: u32 = 0;
/// `NVB_SECRET_BYTES`: ad hoc, `Credentials(user, secret)`.
pub const NVB_SECRET_BYTES: u32 = 1;
/// `NVB_SECRET_SIGNON`: an account's secret from signond.
pub const NVB_SECRET_SIGNON: u32 = 2;

/// `NVB_ID_USE_CHECK`.
pub const NVB_ID_USE_CHECK: u32 = 0;
/// `NVB_ID_ACCEPT_UNKNOWN`.
pub const NVB_ID_ACCEPT_UNKNOWN: u32 = 1;
/// `NVB_ID_CANCEL`.
pub const NVB_ID_CANCEL: u32 = 2;

/// `NVB_PHASE_CONNECT`.
pub const NVB_PHASE_CONNECT: u32 = 1;
/// `NVB_PHASE_IDENTITY`.
pub const NVB_PHASE_IDENTITY: u32 = 2;
/// `NVB_PHASE_CREDENTIALS`.
pub const NVB_PHASE_CREDENTIALS: u32 = 3;
/// `NVB_PHASE_AUTHENTICATE`.
pub const NVB_PHASE_AUTHENTICATE: u32 = 4;
/// `NVB_PHASE_DONE`.
pub const NVB_PHASE_DONE: u32 = 5;

/// `NVB_DISPOSITION_CREATE_NEW`.
pub const NVB_DISPOSITION_CREATE_NEW: u32 = 0;
/// `NVB_DISPOSITION_TRUNCATE`.
pub const NVB_DISPOSITION_TRUNCATE: u32 = 1;
/// `NVB_DISPOSITION_RESUME`.
pub const NVB_DISPOSITION_RESUME: u32 = 2;

/// `nvb_bytes`: a byte slice; `ptr` may be NULL when `len` is 0.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbBytes {
    /// First byte.
    pub ptr: *const u8,
    /// Number of bytes.
    pub len: usize,
}

impl NvbBytes {
    /// The empty slice (NULL, 0).
    pub const EMPTY: Self = Self { ptr: std::ptr::null(), len: 0 };

    /// Borrows `data` (O1: for the call only).
    #[must_use]
    pub const fn of(data: &[u8]) -> Self {
        Self { ptr: data.as_ptr(), len: data.len() }
    }
}

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
    /// `nvb_reply`: the answer slot of a prompt.
    NvbReply,
}

/// `nvb_error`: a failure (XC-21, XC-24).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbError {
    /// `errorName()`, e.g. `NotFound`; never empty.
    pub name: NvbBytes,
    /// UTF-8, may be empty.
    pub message: NvbBytes,
    /// UTF-8, may be empty.
    pub detail: NvbBytes,
    /// -1: none.
    pub retry_after_ms: i64,
}

/// `nvb_blob`: a byte string C++ produced.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbBlob {
    /// The bytes.
    pub data: NvbBytes,
}

/// `nvb_value`: a typed option or identity detail.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbValue {
    /// `NVB_VALUE_*`.
    pub kind: u32,
    /// Bool and int.
    pub number: i64,
    /// String and bytes.
    pub bytes: NvbBytes,
    /// String list.
    pub items: *const NvbBytes,
    /// Number of `items`.
    pub n_items: usize,
}

/// `nvb_kv`: one key and value.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbKv {
    /// UTF-8.
    pub key: NvbBytes,
    /// The value.
    pub value: NvbValue,
}

/// `nvb_params`: `NetVfs::ConnectionParams`; strings UTF-8.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbParams {
    /// Backend provider.
    pub provider: NvbBytes,
    /// Host.
    pub host: NvbBytes,
    /// 0: protocol default.
    pub port: i32,
    /// User name.
    pub username: NvbBytes,
    /// Options; keys unique.
    pub options: *const NvbKv,
    /// Number of `options`.
    pub n_options: usize,
    /// Connect timeout.
    pub connect_timeout_ms: i32,
    /// Request timeout.
    pub request_timeout_ms: i32,
}

/// `nvb_url`: what `Url::parse` gives.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbUrl {
    /// The connection parameters.
    pub params: NvbParams,
    /// `Names::encode` of the normalised location path.
    pub path: NvbBytes,
}

/// `nvb_entry`: `NetVfs::Entry` (XC-2) in wire form (XB-9).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbEntry {
    /// `Names::encode(name)`.
    pub name: NvbBytes,
    /// `NetVfs::EntryType`.
    pub kind: u8,
    /// Kind of a symlink's target.
    pub target_kind: u8,
    /// `NetVfs::EntryFlags`.
    pub flags: u16,
    /// -1 unknown.
    pub mode: i32,
    /// -1 unknown.
    pub size: i64,
    /// -1 unknown.
    pub mtime_ms: i64,
    /// -1 unknown.
    pub ctime_ms: i64,
    /// -1 unknown.
    pub atime_ms: i64,
    /// -1 unknown.
    pub uid: i64,
    /// -1 unknown.
    pub gid: i64,
    /// UTF-8; may hold NUL.
    pub owner: NvbBytes,
    /// UTF-8; may hold NUL.
    pub group: NvbBytes,
    /// Opaque.
    pub etag: NvbBytes,
    /// UTF-8.
    pub content_type: NvbBytes,
}

/// `nvb_capabilities`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbCapabilities {
    /// `Capabilities::names()`, sorted.
    pub flags: *const NvbBytes,
    /// Number of `flags`.
    pub n_flags: usize,
    /// Algorithms of `conn_checksum`.
    pub checksum_algorithms: *const NvbBytes,
    /// Number of `checksum_algorithms`.
    pub n_checksum_algorithms: usize,
    /// -1 unknown.
    pub max_name_bytes: i64,
}

/// `nvb_space`; each -1 unknown.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NvbSpace {
    /// Free bytes.
    pub free_bytes: i64,
    /// Total bytes.
    pub total_bytes: i64,
    /// Used bytes.
    pub used_bytes: i64,
}

/// `nvb_attributes`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbAttributes {
    /// -1 unchanged.
    pub mode: i32,
    /// Whether `mtime_ms` is set.
    pub has_mtime: u8,
    /// Whether `atime_ms` is set.
    pub has_atime: u8,
    /// Modification time.
    pub mtime_ms: i64,
    /// Access time.
    pub atime_ms: i64,
}

/// `nvb_identity`: the `ServerIdentity` seen during connect (XC-16).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbIdentity {
    /// `NVB_IDENTITY_*`.
    pub kind: u32,
    /// Key algorithm.
    pub algorithm: NvbBytes,
    /// The key blob.
    pub public_key: NvbBytes,
    /// Filled by C++ when the backend left it empty.
    pub fingerprint: NvbBytes,
    /// `ServerIdentity::toPin()`; empty without identity.
    pub pin: NvbBytes,
    /// Whether the system trusts it.
    pub system_trusted: u8,
    /// `ServerIdentity` bits.
    pub problems: i32,
    /// Wire-able values only.
    pub details: *const NvbKv,
    /// Number of `details`.
    pub n_details: usize,
}

/// `nvb_secret`: where the credentials come from.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbSecret {
    /// `NVB_SECRET_*`.
    pub source: u32,
    /// User name.
    pub user: NvbBytes,
    /// `NVB_SECRET_BYTES` only.
    pub secret: NvbBytes,
    /// `NVB_SECRET_SIGNON` only.
    pub credentials_id: u32,
    /// `NVB_SECRET_SIGNON` only (XA-7).
    pub secret_optional: u8,
}

/// `nvb_prompt`: one keyboard-interactive prompt.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbPrompt {
    /// UTF-8.
    pub text: NvbBytes,
    /// Whether the answer may be shown.
    pub echo: u8,
}

/// `identity` of `nvb_establish_hooks`.
pub type NvbIdentityFn = unsafe extern "C" fn(*mut c_void, *const NvbIdentity, *const NvbError) -> u32;
/// `prompt` of `nvb_establish_hooks`.
pub type NvbPromptFn =
    unsafe extern "C" fn(*mut c_void, NvbBytes, NvbBytes, *const NvbPrompt, usize, *mut NvbReply) -> c_int;

/// `nvb_establish_hooks`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbEstablishHooks {
    /// Passed to both hooks.
    pub ctx: *mut c_void,
    /// NULL: `NVB_ID_USE_CHECK`.
    pub identity: Option<NvbIdentityFn>,
    /// NULL: no prompter.
    pub prompt: Option<NvbPromptFn>,
}

/// `nvb_list_sink_fn`: 1 go on, 0 stop.
pub type NvbListSinkFn = unsafe extern "C" fn(*mut c_void, *const NvbEntry, usize) -> c_int;
/// `nvb_walk_visit_fn`: 1 go on, 0 stop.
pub type NvbWalkVisitFn = unsafe extern "C" fn(*mut c_void, NvbBytes, *const NvbEntry) -> c_int;

/// `nvb_walk_opts`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbWalkOpts {
    /// -1 unlimited, 0: the root's children only.
    pub max_depth: i32,
    /// `SymlinkPolicy::Follow`.
    pub follow_symlinks: u8,
    /// A no-op on the wire (design §6.9).
    pub post_order: u8,
    /// 0: unreadable sub-folders are skipped.
    pub stop_on_list_error: u8,
}

/// `nvb_progress`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbProgress {
    /// Passed to both functions.
    pub ctx: *mut c_void,
    /// `total` -1: unknown.
    pub update: Option<unsafe extern "C" fn(*mut c_void, i64, i64)>,
    /// 1: stop (Canceled).
    pub canceled: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}

/// `read` of `nvb_io`.
pub type NvbIoReadFn = unsafe extern "C" fn(*mut c_void, i64, *mut u8, usize) -> i64;
/// `write` of `nvb_io`.
pub type NvbIoWriteFn = unsafe extern "C" fn(*mut c_void, i64, *const u8, usize) -> i64;

/// `nvb_io`: the local side of Upload and Download.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbIo {
    /// Passed to both functions.
    pub ctx: *mut c_void,
    /// A FIFO.
    pub sequential: u8,
    /// Bytes in range; 0 for FIFOs.
    pub size: i64,
    /// Bytes read, 0 at the end, -1 on error or cancel.
    pub read: Option<NvbIoReadFn>,
    /// Bytes written (may be short), -1 on error or cancel.
    pub write: Option<NvbIoWriteFn>,
}

/// `nvb_upload_opts`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbUploadOpts {
    /// `NVB_DISPOSITION_*`.
    pub disposition: u32,
    /// -1: backend default (XC-23).
    pub create_mode: i32,
    /// Where `Resume` starts.
    pub resume_offset: i64,
    /// -1 unknown.
    pub expected_size: i64,
    /// Whether `mtime_ms` is set.
    pub has_mtime: u8,
    /// Modification time to set.
    pub mtime_ms: i64,
}

/// `nvb_nearby`: a discovered server.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbNearby {
    /// UTF-8.
    pub name: NvbBytes,
    /// Backend provider.
    pub provider: NvbBytes,
    /// Host.
    pub host: NvbBytes,
    /// Port.
    pub port: u16,
    /// `Names::encode(path)`.
    pub path: NvbBytes,
}

/// `changed` of `nvb_discovery_hooks`.
pub type NvbDiscoveryChangedFn = unsafe extern "C" fn(*mut c_void, *const NvbNearby, usize);

/// `nvb_discovery_hooks`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvbDiscoveryHooks {
    /// Passed to `changed`.
    pub ctx: *mut c_void,
    /// The full current list after each change; Qt thread.
    pub changed: Option<NvbDiscoveryChangedFn>,
}

/// A function `post` runs on the Qt thread.
pub type NvbPostFn = unsafe extern "C" fn(*mut c_void);

/// `nvb_ffi_v1`: the table, in the header's order.
#[repr(C)]
#[derive(Debug)]
#[allow(clippy::type_complexity)]
pub struct NvbFfiV1 {
    /// `NVB_FFI_VERSION`.
    pub version: u32,
    /// `sizeof(nvb_ffi_v1)` in the library.
    pub struct_size: u32,
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
    /// Releases a block (O3); NULL is a no-op.
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
    /// `Backend::cancel` (C-9); any thread.
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
pub type NvbFfiGetFn = unsafe extern "C" fn(u32) -> *const NvbFfiV1;

#[cfg(all(test, target_pointer_width = "64"))]
mod layout {
    //! Sizes and offsets as gcc gives them for the header on LP64
    //! (x86_64 and aarch64).
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn plain_structs() {
        assert_eq!((size_of::<NvbBytes>(), align_of::<NvbBytes>()), (16, 8));
        assert_eq!(size_of::<NvbError>(), 56);
        assert_eq!(size_of::<NvbBlob>(), 16);
        assert_eq!(size_of::<NvbValue>(), 48);
        assert_eq!(
            (offset_of!(NvbValue, number), offset_of!(NvbValue, bytes), offset_of!(NvbValue, items)),
            (8, 16, 32)
        );
        assert_eq!(offset_of!(NvbValue, n_items), 40);
        assert_eq!((size_of::<NvbKv>(), offset_of!(NvbKv, value)), (64, 16));
        assert_eq!(size_of::<NvbParams>(), 80);
        assert_eq!((offset_of!(NvbParams, port), offset_of!(NvbParams, username)), (32, 40));
        assert_eq!((offset_of!(NvbParams, options), offset_of!(NvbParams, n_options)), (56, 64));
        assert_eq!(
            (offset_of!(NvbParams, connect_timeout_ms), offset_of!(NvbParams, request_timeout_ms)),
            (72, 76)
        );
        assert_eq!((size_of::<NvbUrl>(), offset_of!(NvbUrl, path)), (96, 80));
        assert_eq!((size_of::<NvbSpace>(), size_of::<NvbBlob>()), (24, 16));
    }

    #[test]
    fn entry_and_capabilities() {
        assert_eq!(size_of::<NvbEntry>(), 136);
        assert_eq!(
            (offset_of!(NvbEntry, kind), offset_of!(NvbEntry, target_kind), offset_of!(NvbEntry, flags)),
            (16, 17, 18)
        );
        assert_eq!((offset_of!(NvbEntry, mode), offset_of!(NvbEntry, size)), (20, 24));
        assert_eq!((offset_of!(NvbEntry, mtime_ms), offset_of!(NvbEntry, uid)), (32, 56));
        assert_eq!((offset_of!(NvbEntry, gid), offset_of!(NvbEntry, owner)), (64, 72));
        assert_eq!((offset_of!(NvbEntry, group), offset_of!(NvbEntry, etag)), (88, 104));
        assert_eq!(offset_of!(NvbEntry, content_type), 120);
        assert_eq!(size_of::<NvbCapabilities>(), 40);
        assert_eq!(
            (offset_of!(NvbCapabilities, checksum_algorithms), offset_of!(NvbCapabilities, max_name_bytes)),
            (16, 32)
        );
        assert_eq!(size_of::<NvbAttributes>(), 24);
        assert_eq!((offset_of!(NvbAttributes, has_mtime), offset_of!(NvbAttributes, has_atime)), (4, 5));
        assert_eq!((offset_of!(NvbAttributes, mtime_ms), offset_of!(NvbAttributes, atime_ms)), (8, 16));
    }

    #[test]
    fn establish_structs() {
        assert_eq!(size_of::<NvbIdentity>(), 96);
        assert_eq!((offset_of!(NvbIdentity, algorithm), offset_of!(NvbIdentity, pin)), (8, 56));
        assert_eq!((offset_of!(NvbIdentity, system_trusted), offset_of!(NvbIdentity, problems)), (72, 76));
        assert_eq!((offset_of!(NvbIdentity, details), offset_of!(NvbIdentity, n_details)), (80, 88));
        assert_eq!(size_of::<NvbSecret>(), 48);
        assert_eq!((offset_of!(NvbSecret, user), offset_of!(NvbSecret, secret)), (8, 24));
        assert_eq!((offset_of!(NvbSecret, credentials_id), offset_of!(NvbSecret, secret_optional)), (40, 44));
        assert_eq!((size_of::<NvbPrompt>(), offset_of!(NvbPrompt, echo)), (24, 16));
        assert_eq!(size_of::<NvbEstablishHooks>(), 24);
    }

    #[test]
    fn streaming_structs() {
        assert_eq!((size_of::<NvbWalkOpts>(), align_of::<NvbWalkOpts>()), (8, 4));
        assert_eq!(
            (
                offset_of!(NvbWalkOpts, follow_symlinks),
                offset_of!(NvbWalkOpts, post_order),
                offset_of!(NvbWalkOpts, stop_on_list_error)
            ),
            (4, 5, 6)
        );
        assert_eq!(size_of::<NvbProgress>(), 24);
        assert_eq!(size_of::<NvbIo>(), 40);
        assert_eq!((offset_of!(NvbIo, sequential), offset_of!(NvbIo, size)), (8, 16));
        assert_eq!((offset_of!(NvbIo, read), offset_of!(NvbIo, write)), (24, 32));
        assert_eq!(size_of::<NvbUploadOpts>(), 40);
        assert_eq!(
            (offset_of!(NvbUploadOpts, create_mode), offset_of!(NvbUploadOpts, resume_offset)),
            (4, 8)
        );
        assert_eq!(
            (offset_of!(NvbUploadOpts, expected_size), offset_of!(NvbUploadOpts, has_mtime)),
            (16, 24)
        );
        assert_eq!(offset_of!(NvbUploadOpts, mtime_ms), 32);
        assert_eq!(size_of::<NvbNearby>(), 72);
        assert_eq!((offset_of!(NvbNearby, port), offset_of!(NvbNearby, path)), (48, 56));
        assert_eq!(size_of::<NvbDiscoveryHooks>(), 16);
    }

    #[test]
    fn table() {
        assert_eq!(size_of::<NvbFfiV1>(), 336);
        assert_eq!((offset_of!(NvbFfiV1, init), offset_of!(NvbFfiV1, free)), (8, 48));
        assert_eq!((offset_of!(NvbFfiV1, conn_new), offset_of!(NvbFfiV1, reply_set)), (80, 120));
        assert_eq!((offset_of!(NvbFfiV1, conn_open_read), offset_of!(NvbFfiV1, copy_across)), (240, 304));
        assert_eq!(offset_of!(NvbFfiV1, discovery_free), 328);
    }

    #[test]
    fn empty_bytes() {
        assert!(NvbBytes::EMPTY.ptr.is_null());
        let data = [1u8, 2];
        let b = NvbBytes::of(&data);
        assert_eq!((b.ptr, b.len), (data.as_ptr(), 2));
    }
}
