// SPDX-License-Identifier: LGPL-2.1-or-later
//! `dlopen` of a function table: opened with `RTLD_NOW | RTLD_LOCAL`, table fetched through its one exported symbol, never closed.

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
    /// The entry symbol returned no table.
    NoTable {
        /// The library.
        path: PathBuf,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, reason } => write!(f, "cannot load {}: {reason}", path.display()),
            Self::NoEntry { path, entry } => write!(f, "{} has no {entry}", path.display()),
            Self::NoTable { path } => write!(f, "{} returned no table", path.display()),
        }
    }
}

impl std::error::Error for LoadError {}

fn last_dl_error() -> String {
    // SAFETY: dlerror returns NULL or a NUL-terminated string valid until the next dl* call on this thread; copied at once.
    unsafe {
        let text = libc::dlerror();
        if text.is_null() {
            "unknown error".to_owned()
        } else {
            CStr::from_ptr(text).to_string_lossy().into_owned()
        }
    }
}

fn entry_point(path: &Path, entry: &CStr) -> Result<*mut c_void, LoadError> {
    let open_error = |reason: String| LoadError::Open { path: path.to_owned(), reason };
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| open_error(e.to_string()))?;
    // SAFETY: valid NUL-terminated path; handle never closed.
    let lib = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if lib.is_null() {
        return Err(open_error(last_dl_error()));
    }
    // SAFETY: live handle, NUL-terminated name.
    let symbol = unsafe { libc::dlsym(lib, entry.as_ptr()) };
    if symbol.is_null() {
        return Err(LoadError::NoEntry {
            path: path.to_owned(),
            entry: entry.to_string_lossy().into_owned(),
        });
    }
    Ok(symbol)
}

/// Loads `path` and asks `entry` (`const T *entry(void)`) for the table. Library is built from this crate's source: the table is this build's `T`.
pub(super) fn load_table<T>(path: &Path, entry: &CStr) -> Result<&'static T, LoadError> {
    let symbol = entry_point(path, entry)?;
    // SAFETY: entry point has C signature `const T *(void)`.
    let get: unsafe extern "C" fn() -> *const T = unsafe { std::mem::transmute(symbol) };
    // SAFETY: calls the entry point, which takes nothing.
    let table = unsafe { get() };
    // SAFETY: NULL or the library's static table, which lives for the process (never closed).
    unsafe { table.as_ref() }.ok_or_else(|| LoadError::NoTable { path: path.to_owned() })
}

#[cfg(test)]
mod tests {
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
    fn tables() {
        let libc = Path::new("libc.so.6");
        let none = load_table::<u8>(libc, c"sched_yield").unwrap_err();
        assert_eq!(none, LoadError::NoTable { path: libc.to_owned() });
        assert_eq!(none.to_string(), "libc.so.6 returned no table");
        // getpid read as a non-NULL address, never dereferenced.
        load_table::<()>(libc, c"getpid").unwrap();
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
        let err = entry_point(Path::new("libc.so.6"), c"nvb_no_such_symbol").unwrap_err();
        assert_eq!(err.to_string(), "libc.so.6 has no nvb_no_such_symbol");
        assert!(!entry_point(Path::new("libc.so.6"), c"getpid").unwrap().is_null());
    }

    #[test]
    fn messages() {
        let e: &dyn std::error::Error = &LoadError::NoTable { path: PathBuf::from("/x.so") };
        assert_eq!(e.to_string(), "/x.so returned no table");
        assert!(e.source().is_none());
    }
}
