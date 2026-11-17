// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `Upload` and `Download` bodies: regular files are read and written at explicit offsets, FIFOs sequentially. `JobFinished` carries `bytes`, the bytes read or written locally.

use super::fd::FdInfo;
use super::fdio::FdDevice;
use super::progress::JobProgress;
use super::{Extra, JobOutcome, count};
use crate::ffi::{Conn, UploadOptions};
use crate::server::args::{Disposition, TransferOpts};
use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::atomic::AtomicBool;

/// What an `Upload` or `Download` needs on the worker thread.
#[derive(Debug)]
pub struct Transfer {
    /// The checked descriptor ([`check_transfer_fd`](super::fd::check_transfer_fd)).
    pub fd: OwnedFd,
    /// What [`check_transfer_fd`](super::fd::check_transfer_fd) found.
    pub info: FdInfo,
    /// The remote path.
    pub path: Vec<u8>,
    /// The call's options.
    pub opts: TransferOpts,
    /// An upload (else a download).
    pub upload: bool,
}

/// The bytes to transfer.
#[must_use]
pub fn transfer_length(t: &Transfer) -> i64 {
    let size = t.opts.size;
    if t.upload && !t.info.fifo && size < 0 {
        return t.info.size.saturating_sub(t.opts.offset).max(0);
    }
    size
}

/// The backend's upload options for `t`; `length` -1: unknown.
#[must_use]
pub fn upload_options_for(t: &TransferOpts, length: i64) -> UploadOptions {
    let expected = |base: i64| (length >= 0).then(|| base.saturating_add(length));
    let mode = t.create_mode.and_then(|m| i32::try_from(m).ok());
    let mtime_ms = t.mtime_ms;
    match t.disposition {
        Disposition::CreateNew => UploadOptions::CreateNew { mode, expected_size: expected(0), mtime_ms },
        Disposition::Truncate => UploadOptions::Truncate { mode, expected_size: expected(0), mtime_ms },
        Disposition::Resume => {
            UploadOptions::Resume { offset: t.offset, expected_size: expected(t.offset), mtime_ms }
        }
    }
}

/// `bytes` of `JobFinished`.
#[must_use]
pub fn transfer_extra(bytes: i64) -> Extra {
    let mut extra = Extra::new();
    extra.insert("bytes".to_owned(), count(bytes));
    extra
}

/// Runs the transfer.
pub fn transfer<F: FnMut(i64, i64)>(
    conn: &mut Conn,
    t: &Transfer,
    cancel: &AtomicBool,
    report: F,
) -> JobOutcome {
    let length = transfer_length(t);
    let offset = if t.info.fifo { 0 } else { t.opts.offset };
    let mut device = FdDevice::new(t.fd.as_fd(), t.info, offset, length, cancel);
    let mut progress = JobProgress::new(cancel, report);
    let shape = (device.is_sequential(), device.size());
    let result = if t.upload {
        conn.upload(&t.path, &upload_options_for(&t.opts, length), &mut device, shape, Some(&mut progress))
    } else {
        conn.download(&t.path, (t.opts.offset, t.opts.size), &mut device, shape, Some(&mut progress))
    };
    JobOutcome { result, extra: transfer_extra(device.transferred()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(upload: bool, info: FdInfo, offset: i64, size: i64) -> Transfer {
        let (r, _w) = std::io::pipe().unwrap();
        Transfer {
            fd: OwnedFd::from(r),
            info,
            path: b"/f".to_vec(),
            opts: TransferOpts { offset, size, ..TransferOpts::default() },
            upload,
        }
    }

    const FILE: FdInfo = FdInfo { fifo: false, size: 100 };
    const FIFO: FdInfo = FdInfo { fifo: true, size: -1 };

    #[test]
    fn lengths_of_uploads_and_downloads() {
        assert_eq!(transfer_length(&job(true, FILE, 30, -1)), 70);
        assert_eq!(transfer_length(&job(true, FILE, 130, -1)), 0);
        assert_eq!(transfer_length(&job(true, FILE, 30, 5)), 5);
        assert_eq!(transfer_length(&job(true, FILE, 30, 0)), 0);
        assert_eq!(transfer_length(&job(true, FIFO, 30, -1)), -1);
        assert_eq!(transfer_length(&job(false, FILE, 30, -1)), -1);
        assert_eq!(transfer_length(&job(false, FILE, 30, 8)), 8);
    }

    #[test]
    fn upload_options_by_disposition() {
        let mut t = TransferOpts {
            offset: 10,
            size: -1,
            create_mode: Some(0o640),
            mtime_ms: Some(9),
            ..TransferOpts::default()
        };
        assert_eq!(
            upload_options_for(&t, 5),
            UploadOptions::CreateNew { mode: Some(0o640), expected_size: Some(5), mtime_ms: Some(9) }
        );
        assert_eq!(
            upload_options_for(&t, -1),
            UploadOptions::CreateNew { mode: Some(0o640), expected_size: None, mtime_ms: Some(9) }
        );
        t.disposition = Disposition::Truncate;
        t.mtime_ms = None;
        assert_eq!(
            upload_options_for(&t, 0),
            UploadOptions::Truncate { mode: Some(0o640), expected_size: Some(0), mtime_ms: None }
        );
        t.disposition = Disposition::Resume;
        t.create_mode = None;
        assert_eq!(
            upload_options_for(&t, 5),
            UploadOptions::Resume { offset: 10, expected_size: Some(15), mtime_ms: None }
        );
        assert_eq!(
            upload_options_for(&t, -1),
            UploadOptions::Resume { offset: 10, expected_size: None, mtime_ms: None }
        );
        t.disposition = Disposition::CreateNew;
        t.create_mode = Some(u32::MAX);
        assert_eq!(
            upload_options_for(&t, -1),
            UploadOptions::CreateNew { mode: None, expected_size: None, mtime_ms: None }
        );
    }

    #[test]
    fn extra_counts_bytes() {
        let extra = transfer_extra(42);
        assert_eq!(extra.len(), 1);
        assert_eq!(i64::try_from(&extra["bytes"]).unwrap(), 42);
    }
}
