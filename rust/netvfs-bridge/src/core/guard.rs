// SPDX-License-Identifier: LGPL-2.1-or-later

use super::{Core, Effect};
use crate::access::{self, After, Op, Own, Verdict};
use crate::consent::Level;
use crate::server::args::{CheckItem, Disposition, LocId};
use crate::server::{Call, NPath, ReplyTo, SessionId};
use crate::status::Status;
use netvfs_bridge_proto::{ErrorName, Lane};

#[derive(Debug, Clone, Copy)]
pub(super) struct Admitted {
    pub(super) level: Level,
    pub(super) verdict: Verdict,
}

impl Admitted {
    fn effect(self, loc: &LocId, path: &NPath, after: After) -> Option<Effect> {
        (!self.level.changes()).then(|| Effect {
            loc: loc.as_str().to_owned(),
            path: path.as_bytes().to_vec(),
            after,
        })
    }
}

impl Core {
    pub(super) fn admit(
        &self,
        reply: ReplyTo,
        loc: &LocId,
        path: &NPath,
        op: Op,
    ) -> Option<(ReplyTo, Admitted)> {
        let Some(level) = self.book.find(loc.as_str()).map(|spec| spec.access) else {
            return Some((reply, Admitted { level: Level::Full, verdict: Verdict::Allow }));
        };
        let own = if level.changes() { Own::No } else { self.own_state(loc.as_str(), path.as_bytes()) };
        match access::check(level, op, own) {
            Verdict::Deny => {
                reply.fail(&access::refused(level));
                None
            }
            verdict => Some((reply, Admitted { level, verdict })),
        }
    }

    pub(super) fn on_file_call(&mut self, sid: SessionId, reply: ReplyTo, call: Call, lane: Lane) {
        match call {
            Call::List { loc, dir, lane, batch } => {
                let Some((reply, a)) = self.admit(reply, &loc, &dir, Op::Browse) else { return };
                self.on_list(sid, reply, &loc, (dir, lane, batch), a.verdict == Verdict::FoldersOnly);
            }
            Call::Stat { loc, path, follow, lane } => {
                let Some((reply, a)) = self.admit(reply, &loc, &path, Op::Look) else { return };
                let folders_only = (a.verdict == Verdict::IfFolder).then_some(a.level);
                self.on_stat(sid, reply, &loc, (path, follow, lane), folders_only);
            }
            Call::ReadLink { loc, path } => {
                let Some((reply, _)) = self.admit(reply, &loc, &path, Op::ReadLink) else { return };
                self.on_read_link(sid, reply, &loc, path, lane);
            }
            Call::SpaceInfo { loc, path } => self.on_space_info(sid, reply, &loc, path, lane),
            Call::Checksum { loc, path, algorithm } => {
                let Some((reply, _)) = self.admit(reply, &loc, &path, Op::Read) else { return };
                self.on_checksum(sid, reply, &loc, path, algorithm, lane);
            }
            Call::MakeDir { loc, path, exclusive } => {
                let Some((reply, _)) = self.admit(reply, &loc, &path, Op::MakeDir) else { return };
                self.run_empty(sid, reply, &loc, lane, move |c| c.make_dir(path.as_bytes(), exclusive));
            }
            Call::RemoveFile { loc, path } => self.on_remove(sid, reply, (&loc, lane), path, false),
            Call::RemoveDir { loc, path } => self.on_remove(sid, reply, (&loc, lane), path, true),
            Call::Rename { loc, from, to, replace } => {
                let op = if replace { Op::Unrestricted } else { Op::Rename };
                let Some((reply, a)) = self.admit(reply, &loc, &from, op) else { return };
                let effect = a.effect(&loc, &from, After::Gone);
                let body = move |c: &mut crate::ffi::Conn| c.rename(from.as_bytes(), to.as_bytes(), replace);
                self.run_empty_then(sid, reply, (&loc, lane), body, effect);
            }
            Call::SetAttributes { loc, path, changes } => {
                let Some((reply, _)) = self.admit(reply, &loc, &path, Op::SetAttributes) else { return };
                self.on_set_attributes(sid, reply, &loc, path, changes, lane);
            }
            Call::MakeSymlink { loc, target, link } => {
                let Some((reply, _)) = self.admit(reply, &loc, &link, Op::Unrestricted) else { return };
                self.run_empty(sid, reply, &loc, lane, move |c| c.make_symlink(&target, link.as_bytes()));
            }
            Call::MakeHardlink { loc, existing, link } => {
                let Some((reply, _)) = self.admit(reply, &loc, &link, Op::Unrestricted) else { return };
                self.run_empty(sid, reply, &loc, lane, move |c| {
                    c.make_hardlink(existing.as_bytes(), link.as_bytes())
                });
            }
            Call::ServerCopy { loc, from, to, opts } => {
                let Some((reply, _)) = self.admit(reply, &loc, &from, Op::Read) else { return };
                let op = if opts.replace { Op::Unrestricted } else { Op::Create };
                let Some((reply, a)) = self.admit(reply, &loc, &to, op) else { return };
                let effect = if opts.recursive { None } else { a.effect(&loc, &to, After::Created) };
                self.on_server_copy(sid, reply, &loc, (from, to), opts, (lane, effect));
            }
            Call::OpenRead { loc, path, lane } => {
                let Some((reply, _)) = self.admit(reply, &loc, &path, Op::Read) else { return };
                self.on_open_read(sid, reply, &loc, path, lane);
            }
            Call::Read { handle, offset, max } => self.on_read(sid, reply, handle, offset, max),
            Call::ReadAhead { handle, offset, bytes } => {
                self.on_read_ahead(sid, reply, handle, offset, bytes);
            }
            Call::Close { handle } => self.on_close(sid, reply, handle),
            Call::Upload { loc, path, fd, opts, lane } => {
                let (op, after) = match opts.disposition {
                    Disposition::CreateNew => (Op::Create, After::Created),
                    Disposition::Truncate | Disposition::Resume => (Op::Rewrite, After::Rewritten),
                };
                let Some((reply, a)) = self.admit(reply, &loc, &path, op) else { return };
                let effect = a.effect(&loc, &path, after);
                let call = super::jobs::TransferCall { loc, path, fd, opts, lane, upload: true };
                self.on_transfer(sid, reply, call, effect);
            }
            Call::Download { loc, path, fd, opts, lane } => {
                let Some((reply, _)) = self.admit(reply, &loc, &path, Op::Read) else { return };
                let call = super::jobs::TransferCall { loc, path, fd, opts, lane, upload: false };
                self.on_transfer(sid, reply, call, None);
            }
            Call::CopyAcross { loc, path, dest_loc, dest_path, opts } => {
                let Some((reply, _)) = self.admit(reply, &loc, &path, Op::Read) else { return };
                let op = if opts.replace { Op::Unrestricted } else { Op::Create };
                let Some((reply, a)) = self.admit(reply, &dest_loc, &dest_path, op) else { return };
                let effect =
                    if opts.recursive { None } else { a.effect(&dest_loc, &dest_path, After::Created) };
                self.on_copy_across(sid, reply, (&loc, path), (&dest_loc, dest_path), (opts, effect));
            }
            Call::RemoveTree { loc, path } => {
                let Some((reply, _)) = self.admit(reply, &loc, &path, Op::Unrestricted) else { return };
                self.on_remove_tree(sid, reply, (&loc, lane), path);
            }
            Call::Check { loc, items, lane } => self.on_check_call(sid, reply, &loc, items, lane),
            Call::Walk { loc, path, opts } => {
                let Some((reply, a)) = self.admit(reply, &loc, &path, Op::Browse) else { return };
                self.on_walk(sid, reply, (&loc, lane), path, (opts, a.verdict == Verdict::FoldersOnly));
            }
            other => {
                reply.fail(&Status::new(ErrorName::Internal, format!("{} has no handler", other.name())));
            }
        }
    }

    fn on_check_call(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &LocId,
        items: Vec<CheckItem>,
        lane: Lane,
    ) {
        let Some(level) = self.book.find(loc.as_str()).map(|spec| spec.access) else {
            let only = vec![false; items.len()];
            return self.on_check(sid, reply, (loc, lane), items, only);
        };
        let mut only = Vec::with_capacity(items.len());
        for item in &items {
            let own =
                if level.changes() { Own::No } else { self.own_state(loc.as_str(), item.path.as_bytes()) };
            match access::check(level, Op::Browse, own) {
                Verdict::Deny => return reply.fail(&access::refused(level)),
                verdict => only.push(verdict == Verdict::FoldersOnly),
            }
        }
        self.on_check(sid, reply, (loc, lane), items, only);
    }

    fn on_remove(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        (loc, lane): (&LocId, Lane),
        path: NPath,
        dir: bool,
    ) {
        let Some((reply, a)) = self.admit(reply, loc, &path, Op::Remove) else { return };
        if a.verdict == Verdict::DenyUnlessMissing {
            let refused = access::refused(a.level);
            self.run_request(sid, reply, loc.as_str(), lane, move |conn| {
                match conn.stat(path.as_bytes(), false) {
                    Err(status) if status.name == ErrorName::NotFound => Err(status),
                    _ => Err(refused),
                }
            });
            return;
        }
        let effect = a.effect(loc, &path, After::Gone);
        let body = move |c: &mut crate::ffi::Conn| {
            if dir { c.remove_dir(path.as_bytes()) } else { c.remove_file(path.as_bytes()) }
        };
        self.run_empty_then(sid, reply, (loc, lane), body, effect);
    }
}
