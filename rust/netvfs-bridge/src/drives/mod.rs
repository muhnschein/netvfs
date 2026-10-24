// SPDX-License-Identifier: LGPL-2.1-or-later
//! Memory cards and USB drives (SPEC-v2 XB-20): which of UDisks2's block
//! devices the bridge lists ([`classify`]), and the UDisks2 client that
//! lists, mounts and unmounts them and follows their changes ([`udisks`]).
//! The core reaches them through a [`DriveSource`], which tests replace.

pub mod classify;
#[cfg(test)]
pub(crate) mod sample;
pub mod udisks;

pub use classify::Drive;

use crate::core::LocalFuture;
use crate::status::Status;

/// The drives, as the core asks for them.
pub trait DriveSource {
    /// What `ListDrives` lists now; nothing when UDisks2 cannot be asked.
    fn list(&self) -> LocalFuture<'_, Vec<Drive>>;
    /// Mounts drive `id` if it is listed: its mount point.
    fn mount<'a>(&'a self, id: &'a str) -> LocalFuture<'a, Result<Vec<u8>, Status>>;
    /// Unmounts drive `id` if it is listed.
    fn unmount<'a>(&'a self, id: &'a str) -> LocalFuture<'a, Result<(), Status>>;
}
