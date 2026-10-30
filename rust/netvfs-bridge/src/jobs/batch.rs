// SPDX-License-Identifier: LGPL-2.1-or-later
//! Batching of streamed signals and the `List` body.
//!
//! A [`Batcher`] collects items into batches of at most `max_items` items or [`MAX_LIST_BATCH_BYTES`] bytes. Before handing a batch on it takes the batch's bytes from the session's [`FlowBudget`]; the emitter then owns them and gives them to [`Outbox::send_streamed`], which returns them once written.

use crate::ffi::Conn;
use crate::server::encode::OutSignal;
use crate::server::{FlowBudget, Outbox};
use crate::status::Status;
use netvfs_bridge_proto::limits::MAX_LIST_BATCH_BYTES;
use netvfs_bridge_proto::{WireEntry, WireWalkItem};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

/// Bytes counted for an entry besides its variable-size fields.
pub const ENTRY_FIXED_BYTES: usize = 96;

/// The wire size of an entry, for the batch byte limit.
#[must_use]
pub const fn entry_wire_size(entry: &WireEntry) -> usize {
    ENTRY_FIXED_BYTES
        .saturating_add(entry.name.len())
        .saturating_add(entry.owner.len())
        .saturating_add(entry.group.len())
        .saturating_add(entry.content_type.len())
        .saturating_add(entry.etag.len())
}

/// The wire size of a `WalkBatch` item.
#[must_use]
pub const fn walk_item_wire_size(item: &WireWalkItem) -> usize {
    entry_wire_size(&item.entry).saturating_add(item.path.len())
}

/// Collects items into batches and hands each full batch, with the bytes it took from the budget, to `emit` (on the worker thread).
pub struct Batcher<'a, T, E: FnMut(Vec<T>, usize) -> bool> {
    max_items: usize,
    size: fn(&T) -> usize,
    emit: E,
    budget: &'a FlowBudget,
    cancel: &'a AtomicBool,
    items: Vec<T>,
    bytes: usize,
}

impl<T, E: FnMut(Vec<T>, usize) -> bool> fmt::Debug for Batcher<'_, T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Batcher")
            .field("max_items", &self.max_items)
            .field("items", &self.items.len())
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl<'a, T, E: FnMut(Vec<T>, usize) -> bool> Batcher<'a, T, E> {
    /// A batcher of at most `max_items` items (at least 1) per batch.
    pub fn new(
        max_items: usize,
        size: fn(&T) -> usize,
        emit: E,
        budget: &'a FlowBudget,
        cancel: &'a AtomicBool,
    ) -> Self {
        Self { max_items: max_items.max(1), size, emit, budget, cancel, items: Vec::new(), bytes: 0 }
    }

    /// Adds an item, first sending what is collected if the item would take the batch over the byte limit, and sending the batch once it is full.
    pub fn add(&mut self, item: T) -> bool {
        let bytes = (self.size)(&item);
        if !self.items.is_empty() && self.bytes.saturating_add(bytes) > MAX_LIST_BATCH_BYTES && !self.flush()
        {
            return false;
        }
        self.items.push(item);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.items.len() >= self.max_items {
            return self.flush();
        }
        !self.cancel.load(Ordering::Acquire)
    }

    /// Sends what is collected (nothing when empty) once the budget has room.
    pub fn flush(&mut self) -> bool {
        if self.cancel.load(Ordering::Acquire) {
            return false;
        }
        if self.items.is_empty() {
            return true;
        }
        if !self.budget.acquire(self.bytes, self.cancel) {
            return false;
        }
        let bytes = std::mem::take(&mut self.bytes);
        (self.emit)(std::mem::take(&mut self.items), bytes)
    }

    /// Adds every entry of one backend batch, then sends them, so that entries reach the consumer as the protocol produces them.
    pub fn add_all(&mut self, batch: &[T]) -> bool
    where
        T: Clone,
    {
        batch.iter().all(|item| self.add(item.clone())) && self.flush()
    }
}

/// Runs a producer that feeds `batcher`, then sends the rest: a producer
/// that succeeded but whose last batch could not go out ends `Canceled`.
///
/// # Errors
/// The producer's failure; `Canceled` when the rest could not be sent.
pub fn drain<T, E: FnMut(Vec<T>, usize) -> bool>(
    batcher: &mut Batcher<'_, T, E>,
    produce: impl FnOnce(&mut Batcher<'_, T, E>) -> Result<(), Status>,
) -> Result<(), Status> {
    let result = produce(batcher);
    if result.is_ok() && !batcher.flush() {
        return Err(crate::locations::canceled());
    }
    result
}

/// The `List` body: lists `dir` in backend batches of `batch` entries and hands every batch to `emit` (see [`list_batches`]). The caller sends `ListDone` through the core afterwards.
///
/// # Errors
/// The backend's failure; `Canceled` when canceled or when a batch could
/// not be sent.
pub fn list<E: FnMut(Vec<WireEntry>, usize) -> bool>(
    conn: &mut Conn,
    dir: &[u8],
    batch: u32,
    budget: &FlowBudget,
    cancel: &AtomicBool,
    emit: E,
) -> Result<(), Status> {
    let max_items = usize::try_from(batch).unwrap_or(usize::MAX);
    let mut batcher = Batcher::new(max_items, entry_wire_size, emit, budget, cancel);
    drain(&mut batcher, |b| conn.list(dir, batch, |entries| b.add_all(entries)))
}

/// An emitter of `ListBatch` signals of request `request` on `outbox`.
pub fn list_batches(outbox: &Outbox, request: u32) -> impl FnMut(Vec<WireEntry>, usize) -> bool + '_ {
    move |entries, bytes| outbox.send_streamed(&OutSignal::ListBatch { request, entries }, bytes)
}

#[cfg(test)]
#[path = "batch_tests.rs"]
mod tests;
