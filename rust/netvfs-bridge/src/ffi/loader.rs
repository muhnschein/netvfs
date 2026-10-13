// SPDX-License-Identifier: LGPL-2.1-or-later
//! `dlopen` of a versioned function table (design §1): the library is
//! opened with `RTLD_NOW | RTLD_LOCAL`, asked for one version through its
//! one exported symbol, and never closed, so the table lives for the rest
//! of the process.

use std::ffi::{CStr, CString, c_void};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Why a library's table could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// `dlopen` failed.
    Open {
        /// The library.
        path: PathBuf,
        /// `dlerror()`.
        reason: String,
    },
    /// The library has no such entry symbol.
    NoEntry {
        /// The library.
        path: PathBuf,
        /// The symbol.
        entry: String,
    },
    /// The library does not offer the version.
    VersionRefused {
        /// The version asked for.
        version: u32,
    },
    /// The table is not the one asked for, or smaller than this build's.
    BadTable {
        /// The table's `version`.
        version: u32,
        /// The table's `struct_size`.
        struct_size: u32,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, reason } => write!(f, "cannot load {}: {reason}", path.display()),
            Self::NoEntry { path, entry } => write!(f, "{} has no {entry}", path.display()),
            Self::VersionRefused { version } => write!(f, "version {version} of the C ABI is not offered"),
            Self::BadTable { version, struct_size } => {
                write!(f, "unexpected table: version {version}, {struct_size} bytes")
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// The last `dlerror()`, or a generic text.
fn last_dl_error() -> String {
    // SAFETY: dlerror returns NULL or a NUL-terminated string that stays
    // valid until the next dl* call on this thread; it is copied at once.
    unsafe {
        let text = libc::dlerror();
        if text.is_null() {
            "unknown error".to_owned()
        } else {
            CStr::from_ptr(text).to_string_lossy().into_owned()
        }
    }
}

/// Opens `path` for good and returns the address of `entry`.
fn entry_point(path: &Path, entry: &CStr) -> Result<*mut c_void, LoadError> {
    let open_error = |reason: String| LoadError::Open { path: path.to_owned(), reason };
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| open_error(e.to_string()))?;
    // SAFETY: a valid NUL-terminated path; the handle is never closed.
    let lib = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if lib.is_null() {
        return Err(open_error(last_dl_error()));
    }
    // SAFETY: a live handle and a NUL-terminated name.
    let symbol = unsafe { libc::dlsym(lib, entry.as_ptr()) };
    if symbol.is_null() {
        return Err(LoadError::NoEntry {
            path: path.to_owned(),
            entry: entry.to_string_lossy().into_owned(),
        });
    }
    Ok(symbol)
}

/// A table whose first two fields are `version` and `struct_size`.
pub(super) trait Table {
    /// Its header.
    fn header(&self) -> (u32, u32);
}

/// Checks a table's header against the version asked for and this build's
/// size of the table: a library may append fields, never remove them.
pub(super) fn check_header(asked: u32, version: u32, struct_size: u32, size: usize) -> Result<(), LoadError> {
    let big_enough = usize::try_from(struct_size).is_ok_and(|s| s >= size);
    if version == asked && big_enough { Ok(()) } else { Err(LoadError::BadTable { version, struct_size }) }
}

/// Loads `path`, asks its `entry` (`const T *entry(uint32_t version)`) for
/// `version` and checks what comes back.
pub(super) fn load_table<T: Table>(path: &Path, entry: &CStr, version: u32) -> Result<&'static T, LoadError> {
    let symbol = entry_point(path, entry)?;
    // SAFETY: the entry point of these libraries has the C signature
    // `const T *(uint32_t)` (netvfs_bridge_ffi.h, nvb_fake.h).
    let get: unsafe extern "C" fn(u32) -> *const T = unsafe { std::mem::transmute(symbol) };
    // SAFETY: calling the library's entry point; it only looks at its argument.
    let table = unsafe { get(version) };
    // SAFETY: NULL or the library's static table, which lives as long as the
    // library: for the rest of the process, since it is never closed.
    let table = unsafe { table.as_ref() }.ok_or(LoadError::VersionRefused { version })?;
    let (got, struct_size) = table.header();
    check_header(version, got, struct_size, size_of::<T>())?;
    Ok(table)
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

    #[test]
    fn headers() {
        assert_eq!(check_header(1, 1, 336, 336), Ok(()));
        assert_eq!(check_header(1, 1, 400, 336), Ok(()));
        assert_eq!(check_header(1, 1, 335, 336), Err(LoadError::BadTable { version: 1, struct_size: 335 }));
        assert_eq!(check_header(1, 2, 336, 336), Err(LoadError::BadTable { version: 2, struct_size: 336 }));
    }

    #[test]
    fn missing_libraries_and_symbols() {
        let missing = Path::new("/nonexistent/libnothing.so");
        let err = entry_point(missing, c"x").unwrap_err();
        assert!(
            matches!(&err, LoadError::Open { path, reason } if path == missing && reason.contains("libnothing"))
        );
        assert!(err.to_string().starts_with("cannot load /nonexistent/libnothing.so: "));
        let nul = entry_point(Path::new("a\0b"), c"x").unwrap_err();
        assert!(matches!(nul, LoadError::Open { .. }));
        // The C library is there, its symbol is not.
        let err = entry_point(Path::new("libc.so.6"), c"nvb_no_such_symbol").unwrap_err();
        assert_eq!(err.to_string(), "libc.so.6 has no nvb_no_such_symbol");
        assert!(!entry_point(Path::new("libc.so.6"), c"getpid").unwrap().is_null());
    }

    #[test]
    fn messages() {
        assert_eq!(
            LoadError::VersionRefused { version: 2 }.to_string(),
            "version 2 of the C ABI is not offered"
        );
        assert_eq!(
            LoadError::BadTable { version: 1, struct_size: 8 }.to_string(),
            "unexpected table: version 1, 8 bytes"
        );
        let e: &dyn std::error::Error = &LoadError::VersionRefused { version: 0 };
        assert!(e.source().is_none());
    }
}
