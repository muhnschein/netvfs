// SPDX-License-Identifier: LGPL-2.1-or-later
//! SPEC-v2 XB-11: the descriptors a consumer passes to `Upload` and
//! `Download` (port of `fdcheck.cpp`). The bridge never opens a local path;
//! it only uses descriptors the consumer opened, checks them before any
//! network work, and never fsyncs, renames, truncates or deletes anything
//! locally. Reading and writing them is [`super::fdio`].

use crate::Status;
use crate::sys::fd::{self, FileKind};
use netvfs_bridge_proto::ErrorName;
use std::os::fd::RawFd;

/// What the transfer does with the descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdAccess {
    /// Upload: the bridge reads it.
    Read,
    /// Download: the bridge writes it.
    Write,
}

/// A checked descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdInfo {
    /// A FIFO; else a regular file.
    pub fifo: bool,
    /// A regular file's `st_size` at check time; -1 for a FIFO.
    pub size: i64,
}

fn denied(why: &str) -> Status {
    Status::permission_denied(why)
}

/// Whether the access mode of `flags` allows `need` (`O_RDONLY`/`O_RDWR`
/// to read, `O_WRONLY`/`O_RDWR` to write).
fn access_mode_allows(flags: libc::c_int, need: FdAccess) -> bool {
    let mode = flags & libc::O_ACCMODE;
    match need {
        FdAccess::Read => mode == libc::O_RDONLY || mode == libc::O_RDWR,
        FdAccess::Write => mode == libc::O_WRONLY || mode == libc::O_RDWR,
    }
}

/// `checkTransferFd`: `PermissionDenied` unless `fd` is a regular file or
/// FIFO opened with the access `need` asks for. `O_PATH` descriptors are
/// refused, and for writing a regular file `O_APPEND` too, because
/// `pwrite` would ignore the offset. The descriptor is only inspected.
///
/// # Errors
/// `PermissionDenied`, with the reason.
pub fn check_transfer_fd(fd: RawFd, need: FdAccess) -> Result<FdInfo, Status> {
    if fd < 0 {
        return Err(denied("No file descriptor"));
    }
    let st = fd::stat(fd).map_err(|_bad| denied("Invalid file descriptor"))?;
    let (regular, fifo) = (st.kind == FileKind::Regular, st.kind == FileKind::Fifo);
    if !regular && !fifo {
        return Err(denied("Only regular files and pipes can be transferred"));
    }
    let flags = fd::status_flags(fd).map_err(|_bad| denied("Invalid file descriptor"))?;
    if flags & libc::O_PATH != 0 {
        return Err(denied("The file descriptor was opened without access"));
    }
    if !access_mode_allows(flags, need) {
        return Err(denied(match need {
            FdAccess::Read => "The file is not open for reading",
            FdAccess::Write => "The file is not open for writing",
        }));
    }
    if need == FdAccess::Write && regular && flags & libc::O_APPEND != 0 {
        return Err(denied("The file is open for appending"));
    }
    Ok(FdInfo { fifo, size: if regular { st.size } else { -1 } })
}

/// `checkUploadLength`: a FIFO has no size, so an upload from one to a
/// provider that must announce the length up front (WebDAV PUT with
/// Content-Length) needs `opts.size`.
///
/// # Errors
/// `Unsupported` for such an upload without a size.
pub fn check_upload_length(info: &FdInfo, size: i64, provider: &str) -> Result<(), Status> {
    if info.fifo && size < 0 && provider == "webdav" {
        return Err(Status::new(
            ErrorName::Unsupported,
            "Uploading from a pipe to this location needs opts.size",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_support::{TempDir, write_file};
    use std::fs::{File, OpenOptions};
    use std::os::fd::{AsRawFd as _, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt as _;

    fn name(r: Result<FdInfo, Status>) -> (ErrorName, String) {
        let s = r.unwrap_err();
        (s.name, s.message)
    }

    fn denied(why: &str) -> (ErrorName, String) {
        (ErrorName::PermissionDenied, why.to_owned())
    }

    /// The port of `tst_BridgeUnits::fdChecks`.
    #[test]
    fn fd_checks() {
        let dir = TempDir::new();
        let path = dir.path().join("f");
        write_file(&path, b"0123456789");

        // 0 is a descriptor like any other (stdin), not a missing one; what
        // it is depends on how the tests run (a terminal, /dev/null, a pipe).
        if let Err(e) = check_transfer_fd(0, FdAccess::Read) {
            assert_ne!(e.message, "No file descriptor");
        }
        let rd = File::open(&path).unwrap();
        assert_eq!(
            check_transfer_fd(rd.as_raw_fd(), FdAccess::Read).unwrap(),
            FdInfo { fifo: false, size: 10 }
        );
        // A download into a read-only file.
        assert_eq!(
            name(check_transfer_fd(rd.as_raw_fd(), FdAccess::Write)),
            denied("The file is not open for writing")
        );

        let wr = OpenOptions::new().write(true).open(&path).unwrap();
        assert_eq!(
            check_transfer_fd(wr.as_raw_fd(), FdAccess::Write).unwrap(),
            FdInfo { fifo: false, size: 10 }
        );
        assert_eq!(
            name(check_transfer_fd(wr.as_raw_fd(), FdAccess::Read)),
            denied("The file is not open for reading")
        );

        let rw = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        assert!(check_transfer_fd(rw.as_raw_fd(), FdAccess::Read).is_ok());
        assert!(check_transfer_fd(rw.as_raw_fd(), FdAccess::Write).is_ok());

        let append = OpenOptions::new().append(true).open(&path).unwrap();
        assert_eq!(
            name(check_transfer_fd(append.as_raw_fd(), FdAccess::Write)),
            denied("The file is open for appending")
        );
        // Reading is fine from a read-write descriptor in append mode.
        let rw_append = OpenOptions::new().read(true).append(true).open(&path).unwrap();
        assert!(check_transfer_fd(rw_append.as_raw_fd(), FdAccess::Read).is_ok());

        let opath = OpenOptions::new().read(true).custom_flags(libc::O_PATH).open(&path).unwrap();
        assert_eq!(
            name(check_transfer_fd(opath.as_raw_fd(), FdAccess::Read)),
            denied("The file descriptor was opened without access")
        );

        let folder = File::open(dir.path()).unwrap();
        assert_eq!(
            name(check_transfer_fd(folder.as_raw_fd(), FdAccess::Read)),
            denied("Only regular files and pipes can be transferred")
        );

        let (r, w) = std::io::pipe().unwrap();
        let (r, w) = (OwnedFd::from(r), OwnedFd::from(w));
        assert_eq!(
            check_transfer_fd(r.as_raw_fd(), FdAccess::Read).unwrap(),
            FdInfo { fifo: true, size: -1 }
        );
        assert_eq!(
            name(check_transfer_fd(r.as_raw_fd(), FdAccess::Write)),
            denied("The file is not open for writing")
        );
        assert_eq!(
            check_transfer_fd(w.as_raw_fd(), FdAccess::Write).unwrap(),
            FdInfo { fifo: true, size: -1 }
        );
        // O_APPEND does not matter for a FIFO (its write end, reopened with it).
        let w_append =
            OpenOptions::new().append(true).open(format!("/proc/self/fd/{}", w.as_raw_fd())).unwrap();
        assert_ne!(fd::status_flags(w_append.as_raw_fd()).unwrap() & libc::O_APPEND, 0);
        assert!(check_transfer_fd(w_append.as_raw_fd(), FdAccess::Write).is_ok());

        assert_eq!(name(check_transfer_fd(-1, FdAccess::Read)), denied("No file descriptor"));
        assert_eq!(name(check_transfer_fd(9999, FdAccess::Read)), denied("Invalid file descriptor"));
    }

    /// The port of `tst_BridgeUnits::uploadLength`.
    #[test]
    fn upload_length() {
        let fifo = FdInfo { fifo: true, size: -1 };
        let regular = FdInfo { fifo: false, size: 10 };
        let refused = check_upload_length(&fifo, -1, "webdav").unwrap_err();
        assert_eq!(refused.name, ErrorName::Unsupported);
        assert_eq!(refused.message, "Uploading from a pipe to this location needs opts.size");
        assert!(check_upload_length(&fifo, 10, "webdav").is_ok());
        assert!(check_upload_length(&fifo, 0, "webdav").is_ok());
        assert!(check_upload_length(&fifo, -1, "sftp").is_ok());
        assert!(check_upload_length(&regular, -1, "webdav").is_ok());
    }

    #[test]
    fn access_modes() {
        use FdAccess::{Read, Write};
        assert!(access_mode_allows(libc::O_RDONLY, Read));
        assert!(!access_mode_allows(libc::O_RDONLY, Write));
        assert!(access_mode_allows(libc::O_WRONLY, Write));
        assert!(!access_mode_allows(libc::O_WRONLY, Read));
        assert!(access_mode_allows(libc::O_RDWR | libc::O_APPEND, Read));
        assert!(access_mode_allows(libc::O_RDWR | libc::O_APPEND, Write));
        // The access mode 3 (no access, a Linux special): neither.
        assert!(!access_mode_allows(libc::O_ACCMODE, Read));
        assert!(!access_mode_allows(libc::O_ACCMODE, Write));
    }
}
