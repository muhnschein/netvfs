// SPDX-License-Identifier: LGPL-2.1-or-later
//! The drives (XB-20): `ListDrives`, `Mount` and `Unmount` ask the
//! [`DriveSource`](crate::drives::DriveSource) as requests (XB-17), and need
//! no consent; its changes reach every session as `DrivesChanged`.

use super::{Core, Event};
use crate::drives::Drive;
use crate::server::{Reply, ReplyTo, SessionId};
use std::rc::Rc;

/// A call of the drives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DriveCall {
    /// `ListDrives`.
    List,
    /// `Mount(drive)`.
    Mount(String),
    /// `Unmount(drive)`.
    Unmount(String),
}

impl Core {
    /// Runs `call` off the loop; its reply comes back as [`Event::Done`].
    pub(super) fn on_drive_call(&mut self, sid: SessionId, reply: ReplyTo, call: DriveCall) {
        let Some((op, _cancel)) = self.start_request(sid, reply) else { return };
        let (drives, tx) = (Rc::clone(&self.drives), self.tx.clone());
        tokio::task::spawn_local(async move {
            let result = match call {
                DriveCall::List => Ok(Reply::Drives(drives.list().await.iter().map(Drive::wire).collect())),
                DriveCall::Mount(drive) => drives.mount(&drive).await.map(Reply::Bytes),
                DriveCall::Unmount(drive) => drives.unmount(&drive).await.map(|()| Reply::Empty),
            };
            // A closed channel: the core has stopped.
            drop(tx.send(Event::Done { sid, op, result }));
        });
    }
}
