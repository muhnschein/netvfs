// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `nvr_*` types of `src/backends/rs/netvfs_rs.h`, written by hand; the
//! `nvb_*` data types are netvfs-vfs's ([`netvfs_vfs::abi`]). Field order,
//! types and the table's slot order are the header's; the `layout` tests
//! pin sizes and offsets on LP64 to what gcc gives. Ownership (R1 to R5)
//! and threads (S1 to S5) are in the header.

pub use netvfs_vfs::abi::*;

use std::ffi::{c_int, c_void};
use std::marker::{PhantomData, PhantomPinned};

/// `NVR_ENTRY`, NUL-terminated for `dlsym`.
pub const NVR_ENTRY: &[u8] = b"nvr_get\0";

/// What a pointer of the C side stands for: neither constructible, nor
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
    /// `nvr_conn`: one backend connection.
    NvrConn,
    /// `nvr_read`: one `ReadHandle`.
    NvrRead,
    /// `nvr_write`: one `WriteHandle`.
    NvrWrite,
}

/// `nvr_credentials`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvrCredentials {
    /// User name, UTF-8.
    pub user: NvbBytes,
    /// Password, or `netvfs-key-v1:` and a base64 key.
    pub secret: NvbBytes,
    /// SMB only, may be empty.
    pub domain: NvbBytes,
}

/// `prompt` of `nvr_prompter`: fills `reply` with `reply_set` and returns
/// 1, or returns 0 to decline.
pub type NvrPromptFn =
    unsafe extern "C" fn(*mut c_void, NvbBytes, NvbBytes, *const NvbPrompt, usize, *mut NvbReply) -> c_int;

/// `nvr_prompter`: `AuthPrompter` (XC-15).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvrPrompter {
    /// Passed to `prompt`.
    pub ctx: *mut c_void,
    /// NULL: no prompter.
    pub prompt: Option<NvrPromptFn>,
}

/// `nvr_write_opts`: `WriteOptions`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvrWriteOpts {
    /// `NVB_DISPOSITION_*`.
    pub disposition: u32,
    /// -1: backend default.
    pub create_mode: i32,
    /// Where `Resume` starts.
    pub resume_offset: i64,
    /// -1 unknown.
    pub expected_size: i64,
    /// Whether `mtime_ms` is set.
    pub has_mtime: u8,
    /// Modification time to set on commit.
    pub mtime_ms: i64,
}

/// `nvr_key`: `SshKeyMaterial`, one block.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvrKey {
    /// OpenSSH format, unencrypted.
    pub private_key: NvbBytes,
    /// `ssh-ed25519`, ….
    pub algorithm: NvbBytes,
    /// `authorized_keys` line.
    pub public_line: NvbBytes,
    /// `SHA256:` and unpadded base64.
    pub fingerprint: NvbBytes,
}

/// `nvr_table`, in the header's order.
#[repr(C)]
#[derive(Debug)]
#[allow(clippy::type_complexity, reason = "the header's function pointer types")]
pub struct NvrTable {
    /// Releases a block (R3), wiping it; NULL is a no-op.
    pub free: unsafe extern "C" fn(*mut c_void),
    /// Fills a prompt's answers.
    pub reply_set: unsafe extern "C" fn(*mut NvbReply, *const NvbBytes, usize),
    /// A connection of a provider.
    pub conn_new: unsafe extern "C" fn(NvbBytes, *mut *mut NvrConn) -> *mut NvbError,
    /// Frees the handles left, disconnects and frees the connection.
    pub conn_free: unsafe extern "C" fn(*mut NvrConn),
    /// `Backend::cancel` (C-9); any thread.
    pub cancel: unsafe extern "C" fn(*mut NvrConn),
    /// `Backend::resetCancel`.
    pub reset_cancel: unsafe extern "C" fn(*mut NvrConn),
    /// `Backend::connect`; `*seen` NULL: no identity.
    pub connect: unsafe extern "C" fn(*mut NvrConn, *const NvbParams, *mut *mut NvbIdentity) -> *mut NvbError,
    /// `Backend::authenticate`; the prompter may be NULL.
    pub authenticate:
        unsafe extern "C" fn(*mut NvrConn, *const NvrCredentials, *const NvrPrompter) -> *mut NvbError,
    /// `Backend::capabilities`.
    pub capabilities: unsafe extern "C" fn(*mut NvrConn, *mut *mut NvbCapabilities) -> *mut NvbError,
    /// `Backend::disconnect`.
    pub disconnect: unsafe extern "C" fn(*mut NvrConn),
    /// `Backend::keepAlive`.
    pub keep_alive: unsafe extern "C" fn(*mut NvrConn) -> *mut NvbError,
    /// `Backend::stat` (`follow` 1) and `lstat` (0).
    pub stat: unsafe extern "C" fn(*mut NvrConn, NvbBytes, i32, *mut *mut NvbEntry) -> *mut NvbError,
    /// `Backend::list`: batch size, resolve symlink types, sink.
    pub list: unsafe extern "C" fn(
        *mut NvrConn,
        NvbBytes,
        u32,
        i32,
        Option<NvbListSinkFn>,
        *mut c_void,
    ) -> *mut NvbError,
    /// `Backend::makeDir`.
    pub make_dir: unsafe extern "C" fn(*mut NvrConn, NvbBytes, i32) -> *mut NvbError,
    /// `Backend::removeFile`.
    pub remove_file: unsafe extern "C" fn(*mut NvrConn, NvbBytes) -> *mut NvbError,
    /// `Backend::removeDir`.
    pub remove_dir: unsafe extern "C" fn(*mut NvrConn, NvbBytes) -> *mut NvbError,
    /// `Backend::rename`; `replace` 1: `RenameMode::Replace`.
    pub rename: unsafe extern "C" fn(*mut NvrConn, NvbBytes, NvbBytes, i32) -> *mut NvbError,
    /// `Backend::setAttributes`.
    pub set_attributes: unsafe extern "C" fn(*mut NvrConn, NvbBytes, *const NvbAttributes) -> *mut NvbError,
    /// `Backend::readLink`.
    pub read_link: unsafe extern "C" fn(*mut NvrConn, NvbBytes, *mut *mut NvbBlob) -> *mut NvbError,
    /// `Backend::makeSymlink(target, link)`.
    pub make_symlink: unsafe extern "C" fn(*mut NvrConn, NvbBytes, NvbBytes) -> *mut NvbError,
    /// `Backend::makeHardlink(existing, link)`.
    pub make_hardlink: unsafe extern "C" fn(*mut NvrConn, NvbBytes, NvbBytes) -> *mut NvbError,
    /// `Backend::copy`: recursive, replace.
    pub copy: unsafe extern "C" fn(*mut NvrConn, NvbBytes, NvbBytes, i32, i32) -> *mut NvbError,
    /// `Backend::checksum`.
    pub checksum: unsafe extern "C" fn(*mut NvrConn, NvbBytes, NvbBytes, *mut *mut NvbBlob) -> *mut NvbError,
    /// `Backend::spaceInfo`.
    pub space_info: unsafe extern "C" fn(*mut NvrConn, NvbBytes, *mut NvbSpace) -> *mut NvbError,
    /// `Backend::openRead`; `*size` -1 unknown.
    pub open_read: unsafe extern "C" fn(*mut NvrConn, NvbBytes, *mut *mut NvrRead, *mut i64) -> *mut NvbError,
    /// `ReadHandle::read` into `buf[..cap]`.
    pub read: unsafe extern "C" fn(*mut NvrRead, i64, *mut u8, usize, *mut usize) -> *mut NvbError,
    /// `ReadHandle::readAhead`.
    pub read_ahead: unsafe extern "C" fn(*mut NvrRead, i64, i64),
    /// `ReadHandle::close`; always frees.
    pub read_close: unsafe extern "C" fn(*mut NvrRead) -> *mut NvbError,
    /// `Backend::openWrite`.
    pub open_write: unsafe extern "C" fn(
        *mut NvrConn,
        NvbBytes,
        *const NvrWriteOpts,
        *mut *mut NvrWrite,
    ) -> *mut NvbError,
    /// `WriteHandle::write`.
    pub write: unsafe extern "C" fn(*mut NvrWrite, *const u8, usize) -> *mut NvbError,
    /// `WriteHandle::position`.
    pub position: unsafe extern "C" fn(*const NvrWrite) -> i64,
    /// `WriteHandle::commit`; always frees.
    pub commit: unsafe extern "C" fn(*mut NvrWrite) -> *mut NvbError,
    /// `WriteHandle::abort`; always frees.
    pub abort: unsafe extern "C" fn(*mut NvrWrite),
    /// `Backend::upload` from the local side `io`.
    pub upload: unsafe extern "C" fn(
        *mut NvrConn,
        NvbBytes,
        *const NvbUploadOpts,
        *const NvbIo,
        *const NvbProgress,
    ) -> *mut NvbError,
    /// `Backend::download` to the local side `io`; length -1: to the end.
    pub download: unsafe extern "C" fn(
        *mut NvrConn,
        NvbBytes,
        i64,
        i64,
        *const NvbIo,
        *const NvbProgress,
    ) -> *mut NvbError,
    /// `SshKeyTools::generate` (Ed25519).
    pub key_generate: unsafe extern "C" fn(*mut *mut NvrKey) -> *mut NvbError,
    /// `SshKeyTools::importKey(file, passphrase)`.
    pub key_import: unsafe extern "C" fn(NvbBytes, NvbBytes, *mut *mut NvrKey) -> *mut NvbError,
    /// `SshKeyTools::describe(private key)`.
    pub key_describe: unsafe extern "C" fn(NvbBytes, *mut *mut NvrKey) -> *mut NvbError,
}

/// `nvr_get_fn`.
pub type NvrGetFn = unsafe extern "C" fn() -> *const NvrTable;

#[cfg(all(test, target_pointer_width = "64"))]
mod layout {
    //! Sizes and offsets as gcc gives them for the header on LP64.
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn data_types() {
        assert_eq!(size_of::<NvrCredentials>(), 48);
        assert_eq!((offset_of!(NvrCredentials, secret), offset_of!(NvrCredentials, domain)), (16, 32));
        assert_eq!((size_of::<NvrPrompter>(), offset_of!(NvrPrompter, prompt)), (16, 8));
        assert_eq!(size_of::<NvrWriteOpts>(), 40);
        assert_eq!((offset_of!(NvrWriteOpts, create_mode), offset_of!(NvrWriteOpts, resume_offset)), (4, 8));
        assert_eq!((offset_of!(NvrWriteOpts, expected_size), offset_of!(NvrWriteOpts, has_mtime)), (16, 24));
        assert_eq!(offset_of!(NvrWriteOpts, mtime_ms), 32);
        assert_eq!(size_of::<NvrKey>(), 64);
        assert_eq!((offset_of!(NvrKey, algorithm), offset_of!(NvrKey, public_line)), (16, 32));
        assert_eq!(offset_of!(NvrKey, fingerprint), 48);
    }

    #[test]
    fn table() {
        assert_eq!((size_of::<NvrTable>(), align_of::<NvrTable>()), (304, 8));
        assert_eq!((offset_of!(NvrTable, reply_set), offset_of!(NvrTable, conn_new)), (8, 16));
        assert_eq!((offset_of!(NvrTable, connect), offset_of!(NvrTable, keep_alive)), (48, 80));
        assert_eq!((offset_of!(NvrTable, stat), offset_of!(NvrTable, space_info)), (88, 184));
        assert_eq!((offset_of!(NvrTable, open_read), offset_of!(NvrTable, abort)), (192, 256));
        assert_eq!((offset_of!(NvrTable, upload), offset_of!(NvrTable, download)), (264, 272));
        assert_eq!((offset_of!(NvrTable, key_generate), offset_of!(NvrTable, key_describe)), (280, 296));
    }

    #[test]
    fn entry_name() {
        assert_eq!(NVR_ENTRY, b"nvr_get\0");
    }
}
