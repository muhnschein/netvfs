// SPDX-License-Identifier: LGPL-2.1-or-later

use super::{Core, Event};
use crate::drives::Drive;
use crate::server::{Reply, ReplyTo, SessionId};
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DriveCall {
    List,
    Mount(String),
    Unmount(String),
}

impl Core {
    pub(super) fn on_get_network(&mut self, sid: SessionId, reply: ReplyTo) {
        let Some((op, _cancel)) = self.start_request(sid, reply) else { return };
        let (network, tx) = (Rc::clone(&self.network), self.tx.clone());
        tokio::task::spawn_local(async move {
            let kind = network.kind().await;
            drop(tx.send(Event::Done { sid, op, result: Ok(Reply::Text(kind)) }));
        });
    }

    pub(super) fn on_drive_call(&mut self, sid: SessionId, reply: ReplyTo, call: DriveCall) {
        let Some((op, _cancel)) = self.start_request(sid, reply) else { return };
        let (drives, tx) = (Rc::clone(&self.drives), self.tx.clone());
        tokio::task::spawn_local(async move {
            let result = match call {
                DriveCall::List => Ok(Reply::Drives(drives.list().await.iter().map(Drive::wire).collect())),
                DriveCall::Mount(drive) => drives.mount(&drive).await.map(Reply::Bytes),
                DriveCall::Unmount(drive) => drives.unmount(&drive).await.map(|()| Reply::Empty),
            };
            drop(tx.send(Event::Done { sid, op, result }));
        });
    }
}
