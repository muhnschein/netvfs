// SPDX-License-Identifier: LGPL-2.1-or-later
//! Memory cards and USB drives from UDisks2: [`classify`], [`udisks`] client. Core reaches them through [`DriveSource`].

pub mod classify;
#[cfg(test)]
pub(crate) mod sample;
pub mod udisks;

pub use classify::Drive;

use crate::core::LocalFuture;
use crate::status::Status;

/// The drives, as the core asks for them.
pub trait DriveSource {
    /// What `ListDrives` lists now; nothing when UDisks2 is unreachable.
    fn list(&self) -> LocalFuture<'_, Vec<Drive>>;
    /// Mounts drive `id` if listed; its mount point.
    fn mount<'a>(&'a self, id: &'a str) -> LocalFuture<'a, Result<Vec<u8>, Status>>;
    /// Unmounts drive `id` if listed.
    fn unmount<'a>(&'a self, id: &'a str) -> LocalFuture<'a, Result<(), Status>>;
}
