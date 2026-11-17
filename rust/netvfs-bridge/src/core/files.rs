// SPDX-License-Identifier: LGPL-2.1-or-later
//! Listing, metadata, namespace operations and read handles.

use super::{Core, Event, HandleRef, quota};
use crate::ffi::{Attributes, Conn};
use crate::jobs::batch::{list, list_batches};
use crate::locations::TaskContext;
use crate::locations::connector::Connector;
use crate::locations::worker::{Turn, Work, WorkerId};
use crate::server::args::{AttributeChanges, CopyOpts, LocId};
use crate::server::{NPath, OutSignal, Outbox, Reply, ReplyTo, SessionId};
use crate::status::Status;
use netvfs_bridge_proto::{ErrorName, Lane};

fn handle_lost() -> Status {
    Status::new(ErrorName::ConnectionLost, "The connection of this handle was closed")
}

fn no_such_handle() -> Status {
    Status::new(ErrorName::NotFound, "No such handle")
}

fn attributes(changes: AttributeChanges) -> Attributes {
    Attributes {
        mode: changes.mode.and_then(|m| i32::try_from(m).ok()),
        mtime_ms: changes.mtime_ms,
        atime_ms: changes.atime_ms,
    }
}

const fn no_changes(changes: AttributeChanges) -> bool {
    changes.mode.is_none() && changes.mtime_ms.is_none() && changes.atime_ms.is_none()
}

fn read_on_worker(turn: Turn<'_, Connector>, handle: u32, offset: i64, max: u32) -> Result<Vec<u8>, Status> {
    turn.ready?;
    let h = turn.handles.and_then(|handles| handles.get_mut(handle)).ok_or_else(handle_lost)?;
    let mut data = vec![0; usize::try_from(max).unwrap_or(0)];
    let n = h.read(offset, &mut data)?;
    data.truncate(n);
    Ok(data)
}

impl Core {
    pub(super) fn on_list(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &LocId,
        dir: NPath,
        lane: Lane,
        batch: u32,
    ) {
        if let Err(status) = self.pool_for(loc.as_str()) {
            reply.fail(&status);
            return;
        }
        if !self.quota.acquire_request() {
            reply.fail(&quota::too_many("Too many requests"));
            return;
        }
        let Some(session) = self.session(sid) else {
            self.quota.release_request();
            return;
        };
        let (_, request, cancel) = session.new_op(None, true);
        let outbox: Outbox = session.outbox.clone();
        reply.ok(&Reply::Id(request));
        let tx = self.tx.clone();
        let flag = std::sync::Arc::clone(&cancel);
        let work: Work<Connector> = Box::new(move |turn: Turn<'_, Connector>| {
            let result = turn.ready.and_then(|conn| {
                list(conn, dir.as_bytes(), batch, outbox.flow(), &flag, list_batches(&outbox, request))
            });
            drop(tx.send(Event::ListDone { sid, request, result: result.clone() }));
            result
        });
        self.book.submit(loc.as_str(), lane, TaskContext::new(sid, cancel), work);
    }

    pub(super) fn on_list_done(&mut self, sid: SessionId, request: u32, result: Result<(), Status>) {
        self.quota.release_request();
        let Some(session) = self.session(sid) else { return };
        session.end_public(request);
        session.signal(&OutSignal::ListDone { request, result });
    }

    pub(super) fn on_stat(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &LocId,
        path: NPath,
        follow: bool,
        lane: Lane,
    ) {
        self.run_request(sid, reply, loc.as_str(), lane, move |conn| {
            conn.stat(path.as_bytes(), follow).map(Reply::Entry)
        });
    }

    pub(super) fn on_read_link(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &LocId,
        path: NPath,
        lane: Lane,
    ) {
        self.run_request(sid, reply, loc.as_str(), lane, move |conn| {
            conn.read_link(path.as_bytes()).map(Reply::Bytes)
        });
    }

    pub(super) fn on_space_info(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &LocId,
        path: NPath,
        lane: Lane,
    ) {
        self.run_request(sid, reply, loc.as_str(), lane, move |conn| {
            conn.space_info(path.as_bytes()).map(|s| Reply::Space {
                free: s.free_bytes,
                total: s.total_bytes,
                used: s.used_bytes,
            })
        });
    }

    pub(super) fn on_checksum(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &LocId,
        path: NPath,
        algorithm: String,
        lane: Lane,
    ) {
        self.run_request(sid, reply, loc.as_str(), lane, move |conn| {
            conn.checksum(path.as_bytes(), &algorithm).map(Reply::Bytes)
        });
    }

    pub(super) fn run_empty(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &LocId,
        lane: Lane,
        body: impl FnOnce(&mut Conn) -> Result<(), Status> + Send + 'static,
    ) {
        self.run_request(sid, reply, loc.as_str(), lane, move |conn| body(conn).map(|()| Reply::Empty));
    }

    pub(super) fn on_set_attributes(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &LocId,
        path: NPath,
        changes: AttributeChanges,
        lane: Lane,
    ) {
        if no_changes(changes) {
            reply.ok(&Reply::Empty);
            return;
        }
        let changes = attributes(changes);
        self.run_empty(sid, reply, loc, lane, move |conn| conn.set_attributes(path.as_bytes(), &changes));
    }

    pub(super) fn on_server_copy(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &LocId,
        (from, to): (NPath, NPath),
        opts: CopyOpts,
        lane: Lane,
    ) {
        self.run_empty(sid, reply, loc, lane, move |conn| {
            conn.copy(from.as_bytes(), to.as_bytes(), opts.recursive, opts.replace)
        });
    }

    pub(super) fn on_open_read(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &LocId,
        path: NPath,
        lane: Lane,
    ) {
        if let Err(status) = self.pool_for(loc.as_str()) {
            reply.fail(&status);
            return;
        }
        if !self.quota.acquire_handle() {
            reply.fail(&quota::too_many("Too many open files"));
            return;
        }
        let Some((op, cancel)) = self.start_request(sid, reply) else {
            self.quota.release_handle();
            return;
        };
        let tx = self.tx.clone();
        let location = loc.as_str().to_owned();
        let work: Work<Connector> = Box::new(move |turn: Turn<'_, Connector>| {
            let Turn { ready, handles, worker } = turn;
            let opened = ready.and_then(|conn| conn.open_read(path.as_bytes())).and_then(|(handle, size)| {
                match (handles, worker) {
                    (Some(handles), Some(worker)) => Ok((worker, handles.add(handle), size)),
                    _ => Err(handle_lost()),
                }
            });
            let result = opened.as_ref().map(|_| ()).map_err(Status::clone);
            drop(tx.send(Event::Opened { sid, op, loc: location, opened }));
            result
        });
        self.book.submit(loc.as_str(), lane, TaskContext::new(sid, cancel), work);
    }

    pub(super) fn on_opened(
        &mut self,
        sid: SessionId,
        op: u64,
        loc: String,
        opened: Result<(WorkerId, u32, i64), Status>,
    ) {
        self.quota.release_request();
        let Some(session) = self.sessions.get_mut(&sid).filter(|s| !s.canceled) else {
            self.quota.release_handle();
            if let Ok((worker, handle, _)) = opened {
                self.book.close_worker_handle(&loc, worker, handle);
            }
            return;
        };
        let reply = session.ops.remove(&op).and_then(|op| op.reply);
        match opened {
            Err(status) => {
                self.quota.release_handle();
                if let Some(reply) = reply {
                    reply.fail(&status);
                }
            }
            Ok((worker, handle, size)) => {
                let id = session.next_handle;
                session.next_handle = session.next_handle.wrapping_add(1).max(1);
                session.handles.insert(id, HandleRef { loc, worker, handle });
                if let Some(reply) = reply {
                    reply.ok(&Reply::Opened { handle: id, size });
                }
            }
        }
    }

    fn resolve_handle(&self, sid: SessionId, id: u32) -> Result<HandleRef, Status> {
        let h = self.sessions.get(&sid).and_then(|s| s.handles.get(&id)).ok_or_else(no_such_handle)?;
        if !self.book.has_pool(&h.loc) || !self.book.pools().owns(&h.loc, h.worker) {
            return Err(handle_lost());
        }
        Ok(h.clone())
    }

    pub(super) fn on_read(&mut self, sid: SessionId, reply: ReplyTo, id: u32, offset: i64, max: u32) {
        let h = match self.resolve_handle(sid, id) {
            Ok(h) => h,
            Err(status) => return reply.fail(&status),
        };
        let Some((op, cancel)) = self.start_request(sid, reply) else { return };
        let tx = self.tx.clone();
        let handle = h.handle;
        let work: Work<Connector> = Box::new(move |turn: Turn<'_, Connector>| {
            let result = read_on_worker(turn, handle, offset, max);
            let kept = result.as_ref().map(|_| ()).map_err(Status::clone);
            drop(tx.send(Event::Done { sid, op, result: result.map(Reply::Bytes) }));
            kept
        });
        self.book.submit_to(&h.loc, h.worker, TaskContext::new(sid, cancel), work);
    }

    pub(super) fn on_read_ahead(&mut self, sid: SessionId, reply: ReplyTo, id: u32, offset: i64, bytes: i64) {
        let h = match self.resolve_handle(sid, id) {
            Ok(h) => h,
            Err(status) => return reply.fail(&status),
        };
        let handle = h.handle;
        let work: Work<Connector> = Box::new(move |turn: Turn<'_, Connector>| {
            if turn.ready.is_ok()
                && let Some(h) = turn.handles.and_then(|handles| handles.get_mut(handle))
            {
                h.read_ahead(offset, bytes);
            }
            Ok(())
        });
        self.book.submit_to(&h.loc, h.worker, TaskContext::detached(), work);
        reply.ok(&Reply::Empty); // a hint: answered at once
    }

    pub(super) fn on_close(&mut self, sid: SessionId, reply: ReplyTo, id: u32) {
        let Some(h) = self.session(sid).and_then(|s| s.handles.remove(&id)) else {
            reply.fail(&no_such_handle());
            return;
        };
        self.quota.release_handle();
        self.book.close_worker_handle(&h.loc, h.worker, h.handle);
        reply.ok(&Reply::Empty);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_changes_for_the_backend() {
        let none = AttributeChanges::default();
        assert!(no_changes(none));
        assert_eq!(attributes(none), Attributes::default());
        let mode = AttributeChanges { mode: Some(0o644), ..none };
        assert!(!no_changes(mode));
        assert_eq!(attributes(mode).mode, Some(0o644));
        let mtime = AttributeChanges { mtime_ms: Some(5), ..none };
        assert!(!no_changes(mtime));
        assert_eq!(attributes(mtime), Attributes { mtime_ms: Some(5), ..Attributes::default() });
        let atime = AttributeChanges { atime_ms: Some(-7), ..none };
        assert!(!no_changes(atime));
        assert_eq!(attributes(atime), Attributes { atime_ms: Some(-7), ..Attributes::default() });
        assert_eq!(attributes(AttributeChanges { mode: Some(u32::MAX), ..none }).mode, None);
    }

    #[test]
    fn handle_errors() {
        assert_eq!(handle_lost().name, ErrorName::ConnectionLost);
        assert_eq!(handle_lost().message, "The connection of this handle was closed");
        assert_eq!(no_such_handle().name, ErrorName::NotFound);
        assert_eq!(no_such_handle().message, "No such handle");
    }
}
