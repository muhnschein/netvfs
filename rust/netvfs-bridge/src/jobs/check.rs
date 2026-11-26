// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `Check` body: stats each folder in order and lists it only when it changed. Results stream in `CheckBatch` signals; a long listing spans results with the same index. `JobFinished` carries `folders` (checked) and `listed`.

use super::batch::{Batcher, drain, entry_wire_size};
use super::{Extra, JobOutcome, count};
use crate::access::is_folder;
use crate::ffi::Conn;
use crate::server::args::CheckItem;
use crate::server::encode::OutSignal;
use crate::server::{FlowBudget, Outbox};
use crate::status::Status;
use netvfs_bridge_proto::limits::{MAX_LIST_BATCH, MAX_LIST_BATCH_BYTES};
use netvfs_bridge_proto::{ErrorName, WireCheckResult, WireEntry};
use std::sync::atomic::AtomicBool;

/// Results per `CheckBatch` at most.
pub const MAX_CHECK_RESULTS: usize = 64;
/// Bytes counted for a result besides its entries and path.
pub const RESULT_FIXED_BYTES: usize = 32;

/// What `Check` needs of a connection.
pub trait Folders {
    /// The folder's entry.
    ///
    /// # Errors
    /// The backend's failure.
    fn stat(&mut self, path: &[u8]) -> Result<WireEntry, Status>;
    /// The folder's entries, batch by batch; `sink` returns false to stop.
    ///
    /// # Errors
    /// The backend's failure.
    fn list(&mut self, path: &[u8], sink: &mut dyn FnMut(&[WireEntry]) -> bool) -> Result<(), Status>;
}

impl Folders for Conn {
    fn stat(&mut self, path: &[u8]) -> Result<WireEntry, Status> {
        Self::stat(self, path, false)
    }

    fn list(&mut self, path: &[u8], sink: &mut dyn FnMut(&[WireEntry]) -> bool) -> Result<(), Status> {
        Self::list(self, path, MAX_LIST_BATCH, sink)
    }
}

/// Whether `now` differs from what `known` says ([`netvfs_bridge_proto::check_changed`]).
#[must_use]
pub fn changed(known: &CheckItem, now: &WireEntry, now_ms: i64) -> bool {
    netvfs_bridge_proto::check_changed(&known.etag, known.mtime_ms.unwrap_or(-1), now, now_ms)
}

/// The wire size of a result, for the batch byte limit.
#[must_use]
pub fn result_wire_size(r: &WireCheckResult) -> usize {
    r.children
        .iter()
        .map(entry_wire_size)
        .fold(RESULT_FIXED_BYTES, usize::saturating_add)
        .saturating_add(entry_wire_size(&r.entry))
        .saturating_add(r.error.len())
}

/// `folders` and `listed` of `JobFinished`.
#[must_use]
pub fn check_extra(folders: i64, listed: i64) -> Extra {
    let mut extra = Extra::new();
    extra.insert("folders".to_owned(), count(folders));
    extra.insert("listed".to_owned(), count(listed));
    extra
}

fn failed(index: u32, status: &Status) -> WireCheckResult {
    WireCheckResult {
        index,
        error: status.name.as_str().to_owned(),
        entry: WireEntry::default(),
        listed: false,
        children: Vec::new(),
    }
}

fn part(index: u32, entry: &WireEntry, listed: bool, children: Vec<WireEntry>) -> WireCheckResult {
    WireCheckResult { index, error: String::new(), entry: entry.clone(), listed, children }
}

fn listing<F: Folders + ?Sized>(
    folders: &mut F,
    path: &[u8],
    folders_only: bool,
) -> Result<Vec<Vec<WireEntry>>, Status> {
    let max = usize::try_from(MAX_LIST_BATCH).unwrap_or(usize::MAX);
    let mut chunks: Vec<Vec<WireEntry>> = vec![Vec::new()];
    let mut bytes = 0_usize;
    folders.list(path, &mut |entries| {
        for e in entries.iter().filter(|e| !folders_only || is_folder(e.kind, e.target_kind)) {
            let size = entry_wire_size(e);
            let full = chunks.last().is_some_and(|c| {
                !c.is_empty() && (c.len() >= max || bytes.saturating_add(size) > MAX_LIST_BATCH_BYTES / 2)
            });
            if full {
                chunks.push(Vec::new());
                bytes = 0;
            }
            bytes = bytes.saturating_add(size);
            if let Some(chunk) = chunks.last_mut() {
                chunk.push(e.clone());
            }
        }
        true
    })?;
    Ok(chunks)
}

fn check_one<F: Folders + ?Sized>(
    folders: &mut F,
    (index, item): (u32, &CheckItem),
    folders_only: bool,
    now_ms: i64,
) -> Result<(Vec<WireCheckResult>, bool), Status> {
    let path = item.path.as_bytes();
    let unless_canceled = |status: Status| {
        if status.name == ErrorName::Canceled {
            Err(status)
        } else {
            Ok((vec![failed(index, &status)], false))
        }
    };
    let entry = match folders.stat(path) {
        Ok(entry) => entry,
        Err(status) => return unless_canceled(status),
    };
    if !changed(item, &entry, now_ms) {
        return Ok((vec![part(index, &entry, false, Vec::new())], false));
    }
    match listing(folders, path, folders_only) {
        Ok(chunks) => Ok((chunks.into_iter().map(|c| part(index, &entry, true, c)).collect(), true)),
        Err(status) => unless_canceled(status),
    }
}

/// Checks `items` in order and hands every batch of results to `emit` (see [`check_batches`]); an item's children are folders only where `folders_only` says so.
pub fn check<F: Folders + ?Sized, E: FnMut(Vec<WireCheckResult>, usize) -> bool>(
    folders: &mut F,
    (items, folders_only, now_ms): (&[CheckItem], &[bool], i64),
    budget: &FlowBudget,
    cancel: &AtomicBool,
    emit: E,
) -> JobOutcome {
    let (mut checked, mut listed) = (0_i64, 0_i64);
    let mut batcher = Batcher::new(MAX_CHECK_RESULTS, result_wire_size, emit, budget, cancel);
    let result = drain(&mut batcher, |b| {
        for (index, item) in items.iter().enumerate() {
            let only_folders = folders_only.get(index).copied().unwrap_or(true);
            let place = (u32::try_from(index).unwrap_or(u32::MAX), item);
            let (results, was_listed) = check_one(folders, place, only_folders, now_ms)?;
            checked = checked.saturating_add(1);
            listed = listed.saturating_add(i64::from(was_listed));
            if !results.into_iter().all(|r| b.add(r)) {
                return Err(crate::locations::canceled());
            }
        }
        Ok(())
    });
    drop(batcher);
    JobOutcome { result, extra: check_extra(checked, listed) }
}

/// An emitter of `CheckBatch` signals of job `job` on `outbox`.
pub fn check_batches(outbox: &Outbox, job: u32) -> impl FnMut(Vec<WireCheckResult>, usize) -> bool + '_ {
    move |results, bytes| outbox.send_streamed(&OutSignal::CheckBatch { job, results }, bytes)
}

#[cfg(test)]
#[path = "check_tests.rs"]
mod tests;
