// SPDX-License-Identifier: LGPL-2.1-or-later
//! The data types of `src/bridge/ffi/netvfs_bridge_ffi.h`, written by hand:
//! one definition for both C ABIs that use them, the bridge's
//! (`libnetvfs-bridge-ffi.so`, netvfs-bridge's `ffi::raw` adds its table)
//! and the Rust backends' (`libnetvfs-rs.so`, `src/backends/rs/netvfs_rs.h`,
//! netvfs-backend's `ffi::raw` adds its table). Field order and types are
//! the header's; the `layout` tests below pin sizes and offsets on LP64 to
//! what the C compiler gives. Names are the header's in Rust case
//! (`nvb_bytes` is [`NvbBytes`]). The comments say what each field carries;
//! ownership and threads are in the headers.

use std::ffi::{c_int, c_void};
use std::marker::{PhantomData, PhantomPinned};

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

/// An object of the other side behind a pointer: neither constructible, nor
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
    /// `nvb_reply`: the answer slot of a prompt, owned by the side that
    /// asks.
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
        assert_eq!(size_of::<NvbIdentity>(), 72);
        assert_eq!((offset_of!(NvbIdentity, algorithm), offset_of!(NvbIdentity, pin)), (8, 56));
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
        assert_eq!((size_of::<NvbNearby>(), offset_of!(NvbNearby, port)), (56, 48));
        assert_eq!(size_of::<NvbDiscoveryHooks>(), 16);
    }

    #[test]
    fn empty_bytes() {
        assert!(NvbBytes::EMPTY.ptr.is_null());
        let data = [1u8, 2];
        let b = NvbBytes::of(&data);
        assert_eq!((b.ptr, b.len), (data.as_ptr(), 2));
    }
}
