// SPDX-License-Identifier: LGPL-2.1-or-later
//! Callbacks from C++ into Rust (T6, T7). Every trampoline runs its Rust
//! code through [`enter`]: a panic is caught there and never unwinds into
//! C++; the trampoline returns its "stop" value instead (0, -1 or
//! `NVB_ID_CANCEL`), every later call of the same context returns it at
//! once, and the call that passed the context reports the panic as an
//! `Internal` [`Status`]. (Release builds abort on a panic: nothing unwinds
//! there either.) While a callback runs, the `Conn` and `Handle` methods of
//! this thread refuse to run (T6), see [`active`].

use super::Ffi;
use super::marshal::{self, Identity, PromptRequest};
use super::raw::{
    NVB_ID_ACCEPT_UNKNOWN, NVB_ID_CANCEL, NVB_ID_USE_CHECK, NvbBytes, NvbEntry, NvbError, NvbIdentity,
    NvbNearby, NvbPrompt, NvbReply,
};
use crate::Status;
use netvfs_bridge_proto::{WireEntry, WireNearby};
use std::any::Any;
use std::cell::Cell;
use std::ffi::{c_int, c_void};
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

thread_local! {
    /// How many callbacks this thread is inside.
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Panics of callbacks that no call returns to (posted functions,
/// discovery hooks), oldest first, at most [`MAX_ORPHANS`].
static ORPHANS: Mutex<Vec<String>> = Mutex::new(Vec::new());
const MAX_ORPHANS: usize = 16;

/// Whether this thread is inside a callback from C++.
#[must_use]
pub fn active() -> bool {
    DEPTH.with(|d| d.get() > 0)
}

/// Marks the thread as inside a callback while it lives.
struct Inside;

impl Inside {
    fn enter() -> Self {
        DEPTH.with(|d| d.set(d.get().saturating_add(1)));
        Self
    }
}

impl Drop for Inside {
    fn drop(&mut self) {
        DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// The text of a panic's payload.
fn panic_text(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "a panic without a message".to_owned()
    }
}

/// Keeps the panic of a callback no call returns to.
pub(super) fn record_orphan(text: String) {
    let mut orphans = ORPHANS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if orphans.len() >= MAX_ORPHANS {
        orphans.remove(0);
    }
    orphans.push(text);
}

/// Takes the panics of posted functions and discovery hooks, oldest first.
#[must_use]
pub fn take_orphan_panics() -> Vec<String> {
    std::mem::take(&mut *ORPHANS.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
}

/// The context of one callback target: what the trampolines reach through
/// their `void *ctx`, and the first panic of the target.
#[derive(Debug)]
pub(super) struct Ctx<T> {
    target: T,
    panic: Option<String>,
}

impl<T> Ctx<T> {
    pub(super) const fn new(target: T) -> Self {
        Self { target, panic: None }
    }

    /// The `void *ctx` for C. Valid while `self` stays where it is and is
    /// not otherwise used.
    pub(super) fn as_ctx(&mut self) -> *mut c_void {
        std::ptr::from_mut(self).cast()
    }

    /// The panic, if the target panicked.
    pub(super) fn take_panic(&mut self) -> Option<String> {
        self.panic.take()
    }

    /// `result` of the call that passed this context, unless the target
    /// panicked: then `Internal`.
    pub(super) fn finish<R>(mut self, result: Result<R, Status>) -> Result<R, Status> {
        match self.take_panic() {
            Some(text) => Err(panicked(&text)),
            None => result,
        }
    }
}

/// The `Internal` status of a callback that panicked.
#[must_use]
pub fn panicked(text: &str) -> Status {
    Status::internal(format!("callback panicked: {text}"))
}

/// Runs `f` on the target behind `ctx`, catching a panic. Returns
/// `fallback` when `ctx` is NULL, when the target panicked before, or when
/// it panics now.
///
/// # Safety
/// `ctx` is NULL or the `as_ctx()` of a live `Ctx<T>` that nothing else
/// uses while the callback runs (T6: callbacks run on the calling thread,
/// during the call that passed the context).
pub(super) unsafe fn enter<T, R>(ctx: *mut c_void, fallback: R, f: impl FnOnce(&mut T) -> R) -> R {
    // SAFETY: NULL or a live, otherwise unused `Ctx<T>` (contract).
    let Some(ctx) = (unsafe { ctx.cast::<Ctx<T>>().as_mut() }) else {
        return fallback;
    };
    if ctx.panic.is_some() {
        return fallback;
    }
    let _inside = Inside::enter();
    match catch_unwind(AssertUnwindSafe(|| f(&mut ctx.target))) {
        Ok(r) => r,
        Err(payload) => {
            ctx.panic = Some(panic_text(payload.as_ref()));
            fallback
        }
    }
}

// --------------------------------------------------------- list and walk

/// `nvb_list_sink_fn` over `F`: true goes on.
pub(super) unsafe extern "C" fn list_sink<F: FnMut(&[WireEntry]) -> bool>(
    ctx: *mut c_void,
    entries: *const NvbEntry,
    n: usize,
) -> c_int {
    // SAFETY: `ctx` is the `Ctx<F>` of the conn_list call running on this
    // thread; `entries` are `n` entries borrowed for this callback (O2).
    unsafe {
        enter::<F, c_int>(ctx, 0, |sink| {
            let batch: Vec<WireEntry> =
                marshal::items(entries, n).iter().map(|e| marshal::entry(e)).collect();
            c_int::from(sink(&batch))
        })
    }
}

/// `nvb_walk_visit_fn` over `F`: true goes on.
pub(super) unsafe extern "C" fn walk_visit<F: FnMut(&[u8], WireEntry) -> bool>(
    ctx: *mut c_void,
    path: NvbBytes,
    entry: *const NvbEntry,
) -> c_int {
    // SAFETY: `ctx` is the `Ctx<F>` of the walk call running on this thread;
    // `path` and `entry` are borrowed for this callback (O2).
    unsafe {
        enter::<F, c_int>(ctx, 0, |visit| match entry.as_ref() {
            Some(e) => c_int::from(visit(marshal::slice(path), marshal::entry(e))),
            None => 0,
        })
    }
}

// --------------------------------------------------- progress and local io

/// Progress of a tree operation or transfer (`nvb_progress`).
pub trait Progress {
    /// Bytes or entries done so far; `total` -1: unknown.
    fn update(&mut self, done: i64, total: i64);
    /// Whether to stop (Canceled). Asked between steps.
    fn canceled(&mut self) -> bool {
        false
    }
}

/// The local side of an upload: reads at a position of the range.
pub trait ReadAt {
    /// Fills `buf` from position `pos` (ignored for a FIFO): the bytes read,
    /// 0 at the end, `None` on an error or cancel.
    fn read_at(&mut self, pos: i64, buf: &mut [u8]) -> Option<usize>;
}

/// The local side of a download: writes at a position of the range.
pub trait WriteAt {
    /// Writes `data` at position `pos` (ignored for a FIFO): the bytes
    /// written, which may be fewer, `None` on an error or cancel.
    fn write_at(&mut self, pos: i64, data: &[u8]) -> Option<usize>;
}

pub(super) unsafe extern "C" fn progress_update<P: Progress + ?Sized>(
    ctx: *mut c_void,
    done: i64,
    total: i64,
) {
    // SAFETY: `ctx` is the `Ctx<&mut P>` of the call running on this thread.
    unsafe { enter::<&mut P, ()>(ctx, (), |p| p.update(done, total)) }
}

pub(super) unsafe extern "C" fn progress_canceled<P: Progress + ?Sized>(ctx: *mut c_void) -> c_int {
    // SAFETY: as in `progress_update`; a panic stops the operation.
    unsafe { enter::<&mut P, c_int>(ctx, 1, |p| c_int::from(p.canceled())) }
}

/// -1 unless `n` fits in `cap` (and in an `i64`).
fn io_count(n: Option<usize>, cap: usize) -> i64 {
    n.filter(|n| *n <= cap).and_then(|n| i64::try_from(n).ok()).unwrap_or(-1)
}

pub(super) unsafe extern "C" fn io_read<R: ReadAt + ?Sized>(
    ctx: *mut c_void,
    pos: i64,
    buf: *mut u8,
    cap: usize,
) -> i64 {
    // SAFETY: `ctx` is the `Ctx<&mut R>` of the conn_upload call running on
    // this thread; `buf` is NULL or `cap` writable bytes for this callback.
    unsafe {
        enter::<&mut R, i64>(ctx, -1, |r| {
            let buf: &mut [u8] =
                if buf.is_null() { &mut [] } else { std::slice::from_raw_parts_mut(buf, cap) };
            io_count(r.read_at(pos, buf), cap)
        })
    }
}

pub(super) unsafe extern "C" fn io_write<W: WriteAt + ?Sized>(
    ctx: *mut c_void,
    pos: i64,
    data: *const u8,
    len: usize,
) -> i64 {
    // SAFETY: `ctx` is the `Ctx<&mut W>` of the conn_download call running
    // on this thread; `data` is NULL or `len` bytes for this callback.
    unsafe {
        enter::<&mut W, i64>(ctx, -1, |w| {
            io_count(w.write_at(pos, marshal::slice(NvbBytes { ptr: data, len })), len)
        })
    }
}

// ------------------------------------------------------------- establish

/// The identity hook's verdict (`NVB_ID_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The `checkServerIdentity()` result stands.
    UseCheck,
    /// Proceed; honoured only when the check said `ServerIdentityUnknown`.
    AcceptUnknown,
    /// Fail with `Canceled`.
    Cancel,
}

impl Verdict {
    /// `NVB_ID_*`.
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::UseCheck => NVB_ID_USE_CHECK,
            Self::AcceptUnknown => NVB_ID_ACCEPT_UNKNOWN,
            Self::Cancel => NVB_ID_CANCEL,
        }
    }
}

/// The answer slot of a prompt: [`Reply::set`] fills it; the last call
/// counts. C++ copies the answers and wipes its copies (O5); the caller
/// wipes its own (`Zeroizing`).
#[derive(Debug)]
pub struct Reply<'r> {
    ffi: Ffi,
    raw: *mut NvbReply,
    _slot: PhantomData<&'r mut NvbReply>,
}

impl Reply<'_> {
    /// Gives the answers, one per prompt; another count declines.
    pub fn set<A: AsRef<[u8]>>(&mut self, answers: &[A]) {
        // Pointers to the caller's bytes: no copy of a secret on this side.
        let items: Vec<NvbBytes> = answers.iter().map(|a| NvbBytes::of(a.as_ref())).collect();
        // SAFETY: `raw` is the slot of the prompt hook running now (T6
        // allows reply_set there); `items` are borrowed for the call (O1).
        unsafe { (self.ffi.t.reply_set)(self.raw, items.as_ptr(), items.len()) }
    }
}

/// The identity hook: the identity seen, the check's failure (`None`: it
/// passed).
pub type IdentityHook<'a> = &'a mut dyn FnMut(&Identity, Option<&Status>) -> Verdict;
/// The prompt hook: fill the reply and return true, or decline.
pub type PromptHook<'a> = &'a mut dyn FnMut(&PromptRequest, &mut Reply<'_>) -> bool;

/// The hooks of `conn_establish`. A missing identity hook lets the check
/// stand; without a prompt hook there is no prompter, so a second factor
/// fails.
#[derive(Default)]
pub struct EstablishHooks<'a> {
    /// After connect, before anything is sent.
    pub identity: Option<IdentityHook<'a>>,
    /// Keyboard-interactive (XC-15); may block, should give up on cancel.
    pub prompt: Option<PromptHook<'a>>,
}

impl std::fmt::Debug for EstablishHooks<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstablishHooks")
            .field("identity", &self.identity.is_some())
            .field("prompt", &self.prompt.is_some())
            .finish()
    }
}

/// What the establish trampolines reach: the hooks and the table.
pub(super) struct EstablishCtx<'h, 'a> {
    pub(super) ffi: Ffi,
    pub(super) hooks: &'h mut EstablishHooks<'a>,
}

pub(super) unsafe extern "C" fn identity_hook(
    ctx: *mut c_void,
    seen: *const NvbIdentity,
    check: *const NvbError,
) -> u32 {
    // SAFETY: `ctx` is the `Ctx<EstablishCtx>` of the conn_establish call
    // running on this thread; `seen` and `check` are NULL or borrowed for
    // this callback (O2). A panic cancels: nothing is sent.
    unsafe {
        enter::<EstablishCtx<'_, '_>, u32>(ctx, NVB_ID_CANCEL, |c| {
            let (Some(hook), Some(seen)) = (c.hooks.identity.as_mut(), seen.as_ref()) else {
                return NVB_ID_USE_CHECK;
            };
            let check = check.as_ref().map(|e| marshal::status(e));
            hook(&marshal::identity(seen), check.as_ref()).raw()
        })
    }
}

pub(super) unsafe extern "C" fn prompt_hook(
    ctx: *mut c_void,
    name: NvbBytes,
    instruction: NvbBytes,
    prompts: *const NvbPrompt,
    n: usize,
    reply: *mut NvbReply,
) -> c_int {
    // SAFETY: `ctx` is the `Ctx<EstablishCtx>` of the conn_establish call
    // running on this thread; the rest is borrowed for this callback (O2).
    // A panic declines.
    unsafe {
        enter::<EstablishCtx<'_, '_>, c_int>(ctx, 0, |c| {
            let Some(hook) = c.hooks.prompt.as_mut() else { return 0 };
            let request = PromptRequest {
                name: String::from_utf8_lossy(marshal::slice(name)).into_owned(),
                instruction: String::from_utf8_lossy(marshal::slice(instruction)).into_owned(),
                prompts: marshal::items(prompts, n).iter().map(|p| marshal::prompt(p)).collect(),
            };
            let mut slot = Reply { ffi: c.ffi, raw: reply, _slot: PhantomData };
            c_int::from(hook(&request, &mut slot))
        })
    }
}

// ------------------------------------------------------ discovery, post

/// The discovery hook: the full current list after each change.
pub(super) type NearbyHook = Box<dyn FnMut(Vec<WireNearby>)>;

pub(super) unsafe extern "C" fn discovery_changed(ctx: *mut c_void, items: *const NvbNearby, n: usize) {
    // SAFETY: `ctx` is the `Ctx<NearbyHook>` a live `Discovery` owns; its
    // hook runs on the Qt thread only, where the `Discovery` lives (T3);
    // `items` are borrowed for this callback (O2).
    unsafe {
        enter::<NearbyHook, ()>(ctx, (), |hook| {
            hook(marshal::items(items, n).iter().map(|i| marshal::nearby(i)).collect());
        });
    }
}

/// A function for the Qt thread.
pub(super) type Posted = Box<dyn FnOnce() + Send>;

pub(super) unsafe extern "C" fn run_posted(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is the `Box<Posted>` that `Ffi::post` leaked for this
    // one call; C++ runs each accepted function exactly once.
    let posted = unsafe { Box::from_raw(ctx.cast::<Posted>()) };
    let _inside = Inside::enter();
    if let Err(payload) = catch_unwind(AssertUnwindSafe(posted)) {
        record_orphan(panic_text(payload.as_ref()));
    }
}

#[cfg(test)]
mod tests {
    //! The trampolines called directly, as C++ would call them.
    // Tests call the trampolines and readers as C++ would, on data they
    // made themselves; they may index, count and cast freely.
    #![allow(
        clippy::undocumented_unsafe_blocks,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::items_after_statements,
        clippy::panic,
        trivial_casts
    )]
    use super::*;
    use crate::ffi::marshal::EntryBuf;
    use netvfs_bridge_proto::ErrorName;

    // The contexts must have exactly the trampoline's type.
    type Sink<'a> = &'a mut dyn FnMut(&[WireEntry]) -> bool;
    type Visit<'a> = &'a mut dyn FnMut(&[u8], WireEntry) -> bool;

    fn entry(name: &[u8]) -> WireEntry {
        WireEntry::unknown(name, 1)
    }

    #[test]
    fn list_sink_converts_and_stops() {
        let a = EntryBuf::new(&entry(b"a"));
        let b = EntryBuf::new(&entry(b"b"));
        let batch = [*a.raw(), *b.raw()];
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut sink = |entries: &[WireEntry]| {
            assert!(active());
            seen.extend(entries.iter().map(|e| e.name.clone()));
            seen.len() < 3
        };
        let mut ctx = Ctx::<Sink<'_>>::new(&mut sink);
        let p = ctx.as_ctx();
        assert_eq!(unsafe { list_sink::<Sink<'_>>(p, batch.as_ptr(), 2) }, 1);
        assert!(!active());
        assert_eq!(unsafe { list_sink::<Sink<'_>>(p, batch.as_ptr(), 2) }, 0);
        assert_eq!(unsafe { list_sink::<Sink<'_>>(p, std::ptr::null(), 0) }, 0);
        assert_eq!(ctx.finish(Ok(())), Ok(()));
        assert_eq!(seen, [b"a".to_vec(), b"b".to_vec(), b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn a_panic_stops_and_is_reported_once() {
        let calls = Cell::new(0);
        let mut sink = |_: &[WireEntry]| -> bool {
            calls.set(calls.get() + 1);
            panic!("sink broke");
        };
        let mut ctx = Ctx::<Sink<'_>>::new(&mut sink);
        let p = ctx.as_ctx();
        assert_eq!(unsafe { list_sink::<Sink<'_>>(p, std::ptr::null(), 0) }, 0);
        assert!(!active());
        // Not called again after its panic.
        assert_eq!(unsafe { list_sink::<Sink<'_>>(p, std::ptr::null(), 0) }, 0);
        assert_eq!(calls.get(), 1);
        let err = ctx.finish(Ok(())).unwrap_err();
        assert_eq!(err.name, ErrorName::Internal);
        assert_eq!(err.message, "callback panicked: sink broke");
        // A NULL context is the fallback, not a crash.
        assert_eq!(unsafe { list_sink::<Sink<'_>>(std::ptr::null_mut(), std::ptr::null(), 0) }, 0);
    }

    #[test]
    fn panic_payloads() {
        assert_eq!(panic_text(&"s"), "s");
        assert_eq!(panic_text(&String::from("owned")), "owned");
        assert_eq!(panic_text(&42), "a panic without a message");
    }

    #[test]
    fn walk_visit_passes_path_and_entry() {
        let e = EntryBuf::new(&entry(b"x"));
        let mut got = Vec::new();
        let mut visit = |path: &[u8], entry: WireEntry| {
            got.push((path.to_vec(), entry.name));
            false
        };
        let mut ctx = Ctx::<Visit<'_>>::new(&mut visit);
        let p = ctx.as_ctx();
        assert_eq!(unsafe { walk_visit::<Visit<'_>>(p, NvbBytes::of(b"/t/x"), e.raw()) }, 0);
        // A NULL entry stops without calling the visitor.
        assert_eq!(unsafe { walk_visit::<Visit<'_>>(p, NvbBytes::of(b"/t/y"), std::ptr::null()) }, 0);
        drop(ctx);
        assert_eq!(got, [(b"/t/x".to_vec(), b"x".to_vec())]);
    }

    struct Counter {
        updates: Vec<(i64, i64)>,
        cancel_after: usize,
        data: Vec<u8>,
        max_write: usize,
        fail: bool,
    }

    impl Progress for Counter {
        fn update(&mut self, done: i64, total: i64) {
            self.updates.push((done, total));
        }
        fn canceled(&mut self) -> bool {
            self.updates.len() >= self.cancel_after
        }
    }

    impl ReadAt for Counter {
        fn read_at(&mut self, pos: i64, buf: &mut [u8]) -> Option<usize> {
            if self.fail {
                return Some(buf.len() + 1);
            }
            let start = usize::try_from(pos).ok()?.min(self.data.len());
            let n = buf.len().min(self.data.len() - start);
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            Some(n)
        }
    }

    impl WriteAt for Counter {
        fn write_at(&mut self, _pos: i64, data: &[u8]) -> Option<usize> {
            if self.fail {
                return None;
            }
            let n = data.len().min(self.max_write);
            self.data.extend_from_slice(&data[..n]);
            Some(n)
        }
    }

    fn counter() -> Counter {
        Counter { updates: Vec::new(), cancel_after: 2, data: b"hello".to_vec(), max_write: 2, fail: false }
    }

    #[test]
    fn progress_trampolines() {
        let mut c = counter();
        let mut ctx = Ctx::new(&mut c as &mut dyn Progress);
        let p = ctx.as_ctx();
        unsafe { progress_update::<dyn Progress>(p, 1, -1) };
        assert_eq!(unsafe { progress_canceled::<dyn Progress>(p) }, 0);
        unsafe { progress_update::<dyn Progress>(p, 2, 10) };
        assert_eq!(unsafe { progress_canceled::<dyn Progress>(p) }, 1);
        drop(ctx);
        assert_eq!(c.updates, [(1, -1), (2, 10)]);
    }

    #[test]
    fn io_trampolines_check_counts() {
        let mut c = counter();
        let mut ctx = Ctx::new(&mut c as &mut dyn ReadAt);
        let p = ctx.as_ctx();
        let mut buf = [0u8; 3];
        assert_eq!(unsafe { io_read::<dyn ReadAt>(p, 1, buf.as_mut_ptr(), 3) }, 3);
        assert_eq!(&buf, b"ell");
        assert_eq!(unsafe { io_read::<dyn ReadAt>(p, 4, buf.as_mut_ptr(), 3) }, 1);
        assert_eq!(unsafe { io_read::<dyn ReadAt>(p, 9, buf.as_mut_ptr(), 3) }, 0);
        assert_eq!(unsafe { io_read::<dyn ReadAt>(p, 0, std::ptr::null_mut(), 0) }, 0);
        drop(ctx);
        // More than asked for is an error.
        c.fail = true;
        let mut ctx = Ctx::new(&mut c as &mut dyn ReadAt);
        assert_eq!(unsafe { io_read::<dyn ReadAt>(ctx.as_ctx(), 0, buf.as_mut_ptr(), 3) }, -1);
        drop(ctx);

        let mut w = counter();
        w.data.clear();
        let mut ctx = Ctx::new(&mut w as &mut dyn WriteAt);
        let p = ctx.as_ctx();
        assert_eq!(unsafe { io_write::<dyn WriteAt>(p, 0, b"abc".as_ptr(), 3) }, 2);
        assert_eq!(unsafe { io_write::<dyn WriteAt>(p, 2, b"c".as_ptr(), 1) }, 1);
        drop(ctx);
        assert_eq!(w.data, b"abc");
        w.fail = true;
        let mut ctx = Ctx::new(&mut w as &mut dyn WriteAt);
        assert_eq!(unsafe { io_write::<dyn WriteAt>(ctx.as_ctx(), 0, b"x".as_ptr(), 1) }, -1);
        assert_eq!(io_count(Some(4), 3), -1);
        assert_eq!(io_count(Some(3), 3), 3);
        assert_eq!(io_count(None, 3), -1);
    }

    #[test]
    fn verdicts() {
        assert_eq!(Verdict::UseCheck.raw(), NVB_ID_USE_CHECK);
        assert_eq!(Verdict::AcceptUnknown.raw(), NVB_ID_ACCEPT_UNKNOWN);
        assert_eq!(Verdict::Cancel.raw(), NVB_ID_CANCEL);
        let hooks = EstablishHooks::default();
        assert_eq!(format!("{hooks:?}"), "EstablishHooks { identity: false, prompt: false }");
    }

    #[test]
    fn posted_panics_are_kept() {
        drop(take_orphan_panics());
        for i in 0..20 {
            let posted: Box<Posted> = Box::new(Box::new(move || panic!("posted {i}")));
            unsafe { run_posted(Box::into_raw(posted).cast()) };
        }
        unsafe { run_posted(std::ptr::null_mut()) };
        let kept = take_orphan_panics();
        assert_eq!(kept.len(), MAX_ORPHANS);
        assert_eq!(kept.first().map(String::as_str), Some("posted 4"));
        assert_eq!(kept.last().map(String::as_str), Some("posted 19"));
        assert_eq!(take_orphan_panics().len(), 0);
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&ran);
        let posted: Box<Posted> =
            Box::new(Box::new(move || flag.store(active(), std::sync::atomic::Ordering::SeqCst)));
        unsafe { run_posted(Box::into_raw(posted).cast()) };
        assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!active());
    }
}
