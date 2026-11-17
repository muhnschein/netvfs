// SPDX-License-Identifier: LGPL-2.1-or-later
//! [`Discovery`] of nearby servers, Qt thread only.

use super::Ffi;
use super::callback::{self, Ctx, NearbyHook};
use super::raw::{NvbDiscovery, NvbDiscoveryHooks};
use crate::Status;
use netvfs_bridge_proto::WireNearby;
use std::fmt;
use std::ptr::NonNull;

/// Nearby-server discovery. Made on the Qt thread via [`Ffi::post`]; `!Send`. The hook gets the full list after each change; not called once dropped.
pub struct Discovery {
    ffi: Ffi,
    raw: NonNull<NvbDiscovery>,
    /// Leaked box: C++ holds its address until `discovery_free`.
    ctx: NonNull<Ctx<NearbyHook>>,
}

impl fmt::Debug for Discovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Discovery").field("raw", &self.raw).finish_non_exhaustive()
    }
}

impl Discovery {
    /// A stopped discovery reporting to `changed`.
    ///
    /// # Errors
    /// `Internal` off the Qt thread or when C++ fails.
    pub fn new(ffi: Ffi, changed: impl FnMut(Vec<WireNearby>) + 'static) -> Result<Self, Status> {
        if !ffi.on_qt_thread() {
            return Err(Status::internal("discovery runs on the Qt thread only"));
        }
        let hook: NearbyHook = Box::new(changed);
        let ctx = NonNull::from(Box::leak(Box::new(Ctx::new(hook))));
        let hooks =
            NvbDiscoveryHooks { ctx: ctx.as_ptr().cast(), changed: Some(callback::discovery_changed) };
        // SAFETY: Qt thread; `hooks` is copied; its context stays valid until `discovery_free` returns.
        let raw = unsafe { (ffi.t.discovery_new)(&raw const hooks) };
        if let Some(raw) = NonNull::new(raw) {
            return Ok(Self { ffi, raw, ctx });
        }
        // SAFETY: C++ kept no reference: it made no discovery.
        drop(unsafe { Box::from_raw(ctx.as_ptr()) });
        Err(Status::internal("discovery_new failed"))
    }

    /// Starts or stops it (idempotent); whether a socket is open.
    pub fn set_running(&mut self, on: bool) -> bool {
        // SAFETY: Qt thread (`!Send`), live discovery.
        unsafe { (self.ffi.t.discovery_set_running)(self.raw.as_ptr(), i32::from(on)) == 1 }
    }

    /// The hook's panic, if any; hook is not called again.
    pub fn take_panic(&mut self) -> Option<String> {
        // SAFETY: box lives until drop; hook runs on this thread only, never during this call.
        unsafe { (*self.ctx.as_ptr()).take_panic() }
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        // SAFETY: Qt thread; no hook call after it returns.
        unsafe { (self.ffi.t.discovery_free)(self.raw.as_ptr()) };
        // SAFETY: box leaked in `new`; C++ no longer holds it.
        let mut ctx = unsafe { Box::from_raw(self.ctx.as_ptr()) };
        // Untaken panic is kept for `take_orphan_panics`.
        if let Some(text) = ctx.take_panic() {
            callback::record_orphan(text);
        }
    }
}
