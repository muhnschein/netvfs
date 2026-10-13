// SPDX-License-Identifier: LGPL-2.1-or-later
//! Jobs: `Upload`, `Download` (XB-11), `Walk`, `RemoveTree` and
//! `CopyAcross` (`Session::Jobs` of sessionjobs.cpp). A job replies its id
//! at once, reports `JobProgress` at most every 250 ms and ends with
//! `JobFinished`.

use super::{Core, Event, quota};
use crate::ffi::Conn;
use crate::jobs::JobOutcome;
use crate::jobs::fd::{FdAccess, check_transfer_fd, check_upload_length};
use crate::jobs::progress::JobProgress;
use crate::jobs::remove::remove_tree;
use crate::jobs::transfer::{Transfer, transfer};
use crate::jobs::walk::{walk, walk_batches};
use crate::locations::connector::Connector;
use crate::locations::copyjobs::CopyBody;
use crate::locations::worker::{Turn, Work};
use crate::locations::{CancelToken, TaskContext};
use crate::server::args::{CopyOpts, LocId, TransferOpts, WalkOpts};
use crate::server::{NPath, Outbox, Reply, ReplyTo, SessionId};
use netvfs_bridge_proto::Lane;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// What `Upload` and `Download` carry.
#[derive(Debug)]
pub(super) struct TransferCall {
    /// The location.
    pub(super) loc: LocId,
    /// The remote path.
    pub(super) path: NPath,
    /// The local descriptor.
    pub(super) fd: OwnedFd,
    /// The options.
    pub(super) opts: TransferOpts,
    /// The lane.
    pub(super) lane: Lane,
    /// Upload (else download).
    pub(super) upload: bool,
}

impl Core {
    /// Takes a job slot and replies with the job id (`startJob`); `None`
    /// (after an error reply) over the limit.
    fn start_job(&mut self, sid: SessionId, reply: ReplyTo) -> Option<(u32, CancelToken)> {
        if !self.quota.acquire_job() {
            reply.fail(&quota::too_many("Too many running jobs"));
            return None;
        }
        let Some(session) = self.session(sid) else {
            self.quota.release_job();
            return None;
        };
        let (_, job, cancel) = session.new_op(None, true);
        reply.ok(&Reply::Id(job));
        Some((job, cancel))
    }

    /// `JobProgress` of `job` of `sid`, from any thread.
    fn reporter(&self, sid: SessionId, job: u32) -> impl FnMut(i64, i64) + Send + 'static {
        let tx = self.tx.clone();
        move |done, total| drop(tx.send(Event::Progress { sid, job, done, total }))
    }

    /// Runs `body` on a pooled connection of `loc` and reports how it
    /// ended (`runJob`); a failure of a canceled job is `Canceled`.
    fn run_job(
        &mut self,
        sid: SessionId,
        (loc, lane): (&LocId, Lane),
        (job, cancel): (u32, CancelToken),
        body: impl FnOnce(&mut Conn, &AtomicBool) -> JobOutcome + Send + 'static,
    ) {
        let tx = self.tx.clone();
        let flag = Arc::clone(&cancel);
        let work: Work<Connector> = Box::new(move |turn: Turn<'_, Connector>| {
            let outcome = match turn.ready {
                Ok(conn) => body(conn, &flag),
                Err(status) => JobOutcome::failed(status),
            };
            let outcome = outcome.settle(flag.load(Ordering::Acquire));
            let result = outcome.result.clone();
            drop(tx.send(Event::JobFinished { sid, job, outcome }));
            result
        });
        self.book.submit(loc.as_str(), lane, TaskContext::new(sid, cancel), work);
    }

    /// XB-11: the descriptor is checked before any network work; regular
    /// files are read and written at explicit offsets, FIFOs sequentially.
    pub(super) fn on_transfer(&mut self, sid: SessionId, reply: ReplyTo, call: TransferCall) {
        let need = if call.upload { FdAccess::Read } else { FdAccess::Write };
        let info = match check_transfer_fd(call.fd.as_raw_fd(), need) {
            Ok(info) => info,
            Err(status) => {
                crate::log::warning(format_args!("Refused a file descriptor: {}", status.message));
                reply.fail(&status);
                return;
            }
        };
        let spec = match self.pool_for(call.loc.as_str()) {
            Ok(spec) => spec,
            Err(status) => return reply.fail(&status),
        };
        if call.upload
            && let Err(status) = check_upload_length(&info, call.opts.size, &spec.provider)
        {
            reply.fail(&status);
            return;
        }
        let Some(started) = self.start_job(sid, reply) else { return };
        let report = self.reporter(sid, started.0);
        let t = Transfer {
            fd: call.fd,
            info,
            path: call.path.into_bytes(),
            opts: call.opts,
            upload: call.upload,
        };
        self.run_job(sid, (&call.loc, call.lane), started, move |conn, cancel| {
            transfer(conn, &t, cancel, report)
        });
    }

    pub(super) fn on_remove_tree(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        (loc, lane): (&LocId, Lane),
        path: NPath,
    ) {
        if let Err(status) = self.pool_for(loc.as_str()) {
            reply.fail(&status);
            return;
        }
        let Some(started) = self.start_job(sid, reply) else { return };
        let report = self.reporter(sid, started.0);
        self.run_job(sid, (loc, lane), started, move |conn, cancel| {
            remove_tree(conn, path.as_bytes(), cancel, report)
        });
    }

    pub(super) fn on_walk(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        (loc, lane): (&LocId, Lane),
        path: NPath,
        opts: WalkOpts,
    ) {
        if let Err(status) = self.pool_for(loc.as_str()) {
            reply.fail(&status);
            return;
        }
        let Some(outbox) = self.sessions.get(&sid).map(|s| s.outbox.clone()) else { return };
        let Some(started) = self.start_job(sid, reply) else { return };
        let job = started.0;
        self.run_job(sid, (loc, lane), started, move |conn, cancel| {
            let outbox: Outbox = outbox;
            walk(conn, path.as_bytes(), &opts, outbox.flow(), cancel, walk_batches(&outbox, job))
        });
    }

    /// Two connections at once on a thread of their own (`copy_across`
    /// needs both owned by the calling thread).
    pub(super) fn on_copy_across(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        (loc, path): (&LocId, NPath),
        (dest_loc, dest_path): (&LocId, NPath),
        opts: CopyOpts,
    ) {
        let source = match self.pool_for(loc.as_str()) {
            Ok(spec) => spec,
            Err(status) => return reply.fail(&status),
        };
        let destination = match self.pool_for(dest_loc.as_str()) {
            Ok(spec) => spec,
            Err(status) => return reply.fail(&status),
        };
        let Some((job, cancel)) = self.start_job(sid, reply) else { return };
        let report = self.reporter(sid, job);
        let flag = Arc::clone(&cancel);
        let body: CopyBody<Connector> = Box::new(move |src: &mut Conn, dst: &mut Conn| {
            let mut progress = JobProgress::new(&flag, report);
            src.copy_across(
                path.as_bytes(),
                dst,
                dest_path.as_bytes(),
                (opts.recursive, opts.replace),
                Some(&mut progress),
            )
        });
        let task = TaskContext::new(sid, cancel);
        match self.copy_jobs.start(self.book.pools_mut(), source, destination, task, body) {
            Ok(id) => {
                self.copy_owners.insert(id, (sid, job));
            }
            Err(status) => {
                self.quota.release_job();
                self.finish_job(sid, job, JobOutcome::failed(status));
            }
        }
    }

    /// Whether job `job` of `sid` was canceled.
    pub(super) fn job_canceled(&self, sid: SessionId, job: u32) -> bool {
        self.sessions
            .get(&sid)
            .and_then(|s| s.public.get(&job).and_then(|op| s.ops.get(op)))
            .is_some_and(|op| op.cancel.load(Ordering::Acquire))
    }
}
