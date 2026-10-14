// SPDX-License-Identifier: LGPL-2.1-or-later
//! Tests only (feature `testing`): the control table of the fake backend,
//! `libnetvfs-bridge-ffi-fake.so` (`tests/bridge/ffifake/nvb_fake.h`,
//! design §4.1). It drives the same `FakeServer` as the plugin that
//! `conn_new("fake")` loads through `NETVFS_BACKEND_PATH`. Never installed.

use super::loader::{self, LoadError};
use super::marshal;
use super::raw::{NvbBlob, NvbBytes};
use netvfs_bridge_proto::ErrorName;
use std::ffi::c_void;
use std::fmt;
use std::path::{Path, PathBuf};

/// Where the tests find the library.
pub const PATH_ENV: &str = "NETVFS_BRIDGE_FFI_FAKE";

/// `nvb_fake`, in the header's order.
#[repr(C)]
#[derive(Debug)]
#[allow(clippy::struct_field_names)]
pub struct NvbFake {
    /// Empty server, user "user", secret "secret".
    pub reset: unsafe extern "C" fn(),
    /// A file, with missing parents.
    pub add_file: unsafe extern "C" fn(NvbBytes, NvbBytes),
    /// A folder; mode -1: 0755.
    pub add_dir: unsafe extern "C" fn(NvbBytes, i32),
    /// A symlink to a verbatim target.
    pub add_symlink: unsafe extern "C" fn(NvbBytes, NvbBytes),
    /// Whether a node exists.
    pub exists: unsafe extern "C" fn(NvbBytes) -> i32,
    /// A file's data; NULL without such a file.
    pub file_data: unsafe extern "C" fn(NvbBytes) -> *mut NvbBlob,
    /// -1 without such a node.
    pub node_mode: unsafe extern "C" fn(NvbBytes) -> i32,
    /// `ServerIdentity::fromPin`; "" none.
    pub set_identity_pin: unsafe extern "C" fn(NvbBytes),
    /// Non-empty: keyboard-interactive code.
    pub set_otp: unsafe extern "C" fn(NvbBytes),
    /// The accepted credentials.
    pub set_credentials: unsafe extern "C" fn(NvbBytes, NvbBytes),
    /// Delay per 64 KiB chunk and listing batch.
    pub set_chunk_delay_ms: unsafe extern "C" fn(i32),
    /// The next call of an op fails once.
    pub fail_op: unsafe extern "C" fn(NvbBytes, NvbBytes),
    /// Log lines starting with a prefix.
    pub log_count: unsafe extern "C" fn(NvbBytes) -> i32,
    /// `FakeBackend` instances alive.
    pub live_backends: unsafe extern "C" fn() -> i32,
    /// Releases a block.
    pub free: unsafe extern "C" fn(*mut c_void),
}

/// The fake backend's controls; any thread, every call takes the server's
/// lock. Paths are protocol bytes; a leading `/` does not matter.
#[derive(Clone, Copy)]
pub struct Fake {
    t: &'static NvbFake,
}

impl fmt::Debug for Fake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fake").finish_non_exhaustive()
    }
}

fn b(data: &[u8]) -> NvbBytes {
    NvbBytes::of(data)
}

// SAFETY (for every call below): the fake's functions take any thread
// (nvb_fake.h) and only borrow their arguments for the call (O1).
impl Fake {
    /// Loads the library named by `NETVFS_BRIDGE_FFI_FAKE`; `None` when the
    /// variable is not set.
    ///
    /// # Errors
    /// When the library cannot be loaded.
    #[must_use]
    pub fn from_env() -> Option<Result<Self, LoadError>> {
        std::env::var_os(PATH_ENV).map(|p| Self::load_from(&PathBuf::from(p)))
    }

    /// Loads the library at `path`.
    ///
    /// # Errors
    /// When it cannot be loaded.
    pub fn load_from(path: &Path) -> Result<Self, LoadError> {
        loader::load_table::<NvbFake>(path, c"nvb_fake_get").map(|t| Self { t })
    }

    /// Empties the server; user "user", secret "secret".
    pub fn reset(&self) {
        // SAFETY: see above.
        unsafe { (self.t.reset)() }
    }

    /// A file, with its missing parents.
    pub fn add_file(&self, path: &[u8], data: &[u8]) {
        // SAFETY: see above.
        unsafe { (self.t.add_file)(b(path), b(data)) }
    }

    /// A folder; `None`: 0755.
    pub fn add_dir(&self, path: &[u8], mode: Option<i32>) {
        // SAFETY: see above.
        unsafe { (self.t.add_dir)(b(path), mode.unwrap_or(-1)) }
    }

    /// A symlink to `target`, verbatim.
    pub fn add_symlink(&self, path: &[u8], target: &[u8]) {
        // SAFETY: see above.
        unsafe { (self.t.add_symlink)(b(path), b(target)) }
    }

    /// Whether a node exists.
    #[must_use]
    pub fn exists(&self, path: &[u8]) -> bool {
        // SAFETY: see above.
        unsafe { (self.t.exists)(b(path)) == 1 }
    }

    /// A file's data.
    #[must_use]
    pub fn file_data(&self, path: &[u8]) -> Option<Vec<u8>> {
        // SAFETY: see above; the blob is one block (O3), read, then freed.
        unsafe {
            let blob = (self.t.file_data)(b(path));
            let data = blob.as_ref().map(|blob| marshal::slice(blob.data).to_vec());
            (self.t.free)(blob.cast());
            data
        }
    }

    /// A node's mode bits.
    #[must_use]
    pub fn node_mode(&self, path: &[u8]) -> Option<i32> {
        // SAFETY: see above.
        let mode = unsafe { (self.t.node_mode)(b(path)) };
        (mode >= 0).then_some(mode)
    }

    /// The server's identity, from a pin; "" none.
    pub fn set_identity_pin(&self, pin: &str) {
        // SAFETY: see above.
        unsafe { (self.t.set_identity_pin)(b(pin.as_bytes())) }
    }

    /// A keyboard-interactive code to ask for; empty: none.
    pub fn set_otp(&self, otp: &[u8]) {
        // SAFETY: see above.
        unsafe { (self.t.set_otp)(b(otp)) }
    }

    /// The credentials the server accepts.
    pub fn set_credentials(&self, user: &str, secret: &[u8]) {
        // SAFETY: see above.
        unsafe { (self.t.set_credentials)(b(user.as_bytes()), b(secret)) }
    }

    /// Delay per 64 KiB chunk and listing batch.
    pub fn set_chunk_delay_ms(&self, ms: i32) {
        // SAFETY: see above.
        unsafe { (self.t.set_chunk_delay_ms)(ms) }
    }

    /// The next call of `op` (`connect`, `list`, `stat`, …) fails once with
    /// `error` (message "Injected <name>").
    pub fn fail_op(&self, op: &str, error: ErrorName) {
        // SAFETY: see above.
        unsafe { (self.t.fail_op)(b(op.as_bytes()), b(error.as_str().as_bytes())) }
    }

    /// Log lines starting with `prefix` (`connect`, `authenticate`,
    /// `answers:<n>`, `disconnect`, `<op>:<path>`, …).
    #[must_use]
    pub fn log_count(&self, prefix: &str) -> i32 {
        // SAFETY: see above.
        unsafe { (self.t.log_count)(b(prefix.as_bytes())) }
    }

    /// `FakeBackend` instances alive.
    #[must_use]
    pub fn live_backends(&self) -> i32 {
        // SAFETY: see above.
        unsafe { (self.t.live_backends)() }
    }
}
