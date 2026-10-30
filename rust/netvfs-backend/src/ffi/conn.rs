// SPDX-License-Identifier: LGPL-2.1-or-later
//! Table functions: argument checks, one call at a time per connection, the call on the runtime, results as
//! blocks, panics as `Internal`.
//!
//! `cancel` may come from any thread during a call, so the token sits apart from the rest, which sits behind a lock
//! a call holds from start to end; a second call (other thread or callback) fails with `Internal` instead of waiting.
//! Handles (`nvr_read *`, `nvr_write *`) point back to their connection, which lists them for `conn_free`.

use super::callback::{IoSink, IoSource, ListAdapter, ProgressAdapter, PromptAdapter};
use super::marshal::{
    RawWriteOptions, attributes, blob, capabilities as caps_block, credentials as read_credentials, entry,
    error, identity, key, no_memory, optional, params as read_params, slice, space, text, unsigned,
    write_options,
};
use super::raw::{
    NvbAttributes, NvbBlob, NvbBytes, NvbCapabilities, NvbEntry, NvbError, NvbIdentity, NvbIo, NvbListSinkFn,
    NvbParams, NvbProgress, NvbSpace, NvbUploadOpts, NvrConn, NvrCredentials, NvrKey, NvrPrompter, NvrRead,
    NvrWrite, NvrWriteOpts,
};
use crate::erased::{DynBackend, DynRead, DynWrite};
use crate::providers;
use crate::runtime::{finish, run};
use netvfs_vfs::{CancelToken, ListOptions, Prompter, RenameMode, Status};
use std::any::Any;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};

struct Conn {
    cancel: Mutex<CancelToken>,
    state: Mutex<State>,
}

struct State {
    backend: Box<dyn DynBackend>,
    reads: Vec<*mut ReadSlot>,
    writes: Vec<*mut WriteSlot>,
}

struct ReadSlot {
    conn: *const Conn,
    handle: Box<dyn DynRead>,
}

struct WriteSlot {
    conn: *const Conn,
    handle: Box<dyn DynWrite>,
}

thread_local! {
    static OBJECTS: Cell<isize> = const { Cell::new(0) };
}

fn count(delta: isize) {
    OBJECTS.with(|n| n.set(n.get().wrapping_add(delta)));
}

/// Connections and handles this thread made minus those it freed (tests check for leaks with it).
pub fn live_objects() -> isize {
    OBJECTS.with(Cell::get)
}

impl Conn {
    fn token(&self) -> CancelToken {
        self.cancel.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn enter(&self) -> Result<(MutexGuard<'_, State>, CancelToken), Status> {
        let state = match self.state.try_lock() {
            Ok(state) => state,
            // Poisoned by a panicked call (reported as Internal); state is still usable.
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(Status::internal(
                    "The connection is busy: one call at a time, none from a callback",
                ));
            }
        };
        Ok((state, self.token()))
    }
}

fn panicked(payload: &(dyn Any + Send)) -> Status {
    let what = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or_default();
    Status::internal("The Rust backend failed").with_detail(format!("panic: {what}"))
}

fn status(call: impl FnOnce() -> Result<(), Status>) -> *mut NvbError {
    match catch_unwind(AssertUnwindSafe(call)) {
        Ok(Ok(())) => ptr::null_mut(),
        Ok(Err(status)) => error(&status),
        Err(payload) => error(&panicked(payload.as_ref())),
    }
}

fn quietly(call: impl FnOnce()) {
    catch_unwind(AssertUnwindSafe(call)).unwrap_or_default();
}

fn bad(what: &str) -> Status {
    Status::invalid_args(format!("Missing {what} from the plugin"))
}

/// # Safety
/// `c` is NULL or a connection of `conn_new` not yet freed.
unsafe fn conn<'a>(c: *mut NvrConn) -> Result<&'a Conn, Status> {
    // SAFETY: contract.
    unsafe { c.cast::<Conn>().as_ref() }.ok_or_else(|| bad("connection"))
}

/// # Safety
/// `p` is NULL or valid for the call.
unsafe fn arg<'a, T>(p: *const T, what: &str) -> Result<&'a T, Status> {
    // SAFETY: contract.
    unsafe { p.as_ref() }.ok_or_else(|| bad(what))
}

/// # Safety
/// `out` is NULL or writable.
unsafe fn out<'a, T>(out: *mut *mut T) -> Result<&'a mut *mut T, Status> {
    // SAFETY: contract.
    let slot = unsafe { out.as_mut() }.ok_or_else(|| bad("result pointer"))?;
    *slot = ptr::null_mut();
    Ok(slot)
}

fn give<T>(slot: &mut *mut T, block: Option<*mut T>) -> Result<(), Status> {
    *slot = block.ok_or_else(no_memory)?;
    Ok(())
}

/// # Safety
/// `provider` is readable; `out` is writable.
pub unsafe extern "C" fn conn_new(provider: NvbBytes, out_conn: *mut *mut NvrConn) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (slot, provider) = unsafe { (out(out_conn)?, slice(provider)) };
        let backend = providers::create(provider)?;
        let state = State { backend, reads: Vec::new(), writes: Vec::new() };
        let conn = Box::new(Conn { cancel: Mutex::new(CancelToken::new()), state: Mutex::new(state) });
        *slot = Box::into_raw(conn).cast::<NvrConn>();
        count(1);
        Ok(())
    })
}

/// Closes left-open handles, disconnects and frees `c`, also if a step panics. A connection in use is left alone.
///
/// # Safety
/// `c` is NULL or a connection not yet freed; no cancel overlaps.
pub unsafe extern "C" fn conn_free(c: *mut NvrConn) {
    let conn = c.cast::<Conn>();
    if conn.is_null() {
        return;
    }
    let mut busy = false;
    quietly(|| {
        // SAFETY: live connection.
        let Ok((mut state, cancel)) = (unsafe { &*conn }).enter() else {
            busy = true;
            return;
        };
        // SAFETY: listed slots are live boxes of `open_read`/`open_write`; unlisted here, so owned.
        let (reads, writes): (Vec<Box<ReadSlot>>, Vec<Box<WriteSlot>>) = unsafe {
            (
                std::mem::take(&mut state.reads).into_iter().map(|p| Box::from_raw(p)).collect(),
                std::mem::take(&mut state.writes).into_iter().map(|p| Box::from_raw(p)).collect(),
            )
        };
        for slot in reads {
            count(-1);
            quietly(|| finish(&cancel, async { drop(slot.handle.close(&cancel).await) }));
        }
        for slot in writes {
            count(-1);
            quietly(|| finish(&cancel, slot.handle.abort()));
        }
        finish(&cancel, state.backend.disconnect());
    });
    if !busy {
        // SAFETY: box of `conn_new`, no other reference.
        quietly(|| drop(unsafe { Box::from_raw(conn) }));
        count(-1);
    }
}

/// # Safety
/// `c` is NULL or a live connection; it is not freed meanwhile.
pub unsafe extern "C" fn cancel(c: *mut NvrConn) {
    // SAFETY: contract.
    quietly(|| unsafe { conn(c) }.map_or((), |conn| conn.token().cancel()));
}

/// # Safety
/// `c` is NULL or a live connection.
pub unsafe extern "C" fn reset_cancel(c: *mut NvrConn) {
    quietly(|| {
        // SAFETY: contract.
        if let Ok(conn) = unsafe { conn(c) } {
            *conn.cancel.lock().unwrap_or_else(PoisonError::into_inner) = CancelToken::new();
        }
    });
}

/// `*seen` stays NULL without an identity.
///
/// # Safety
/// `c` is a live connection; `p` and what it points to are readable;
/// `seen` is writable.
pub unsafe extern "C" fn connect(
    c: *mut NvrConn,
    p: *const NvbParams,
    seen: *mut *mut NvbIdentity,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, params, seen) = unsafe { (conn(c)?, read_params(arg(p, "parameters")?)?, out(seen)?) };
        let (mut state, cancel) = conn.enter()?;
        if let Some(id) = run(&cancel, state.backend.connect(&params, &cancel))? {
            give(seen, identity(&id))?;
        }
        Ok(())
    })
}

/// A NULL prompter or prompt function is none.
///
/// # Safety
/// `c` is a live connection; `cr` and its bytes are readable; `pr` is NULL
/// or readable, its function callable for the call.
pub unsafe extern "C" fn authenticate(
    c: *mut NvrConn,
    cr: *const NvrCredentials,
    pr: *const NvrPrompter,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, credentials, prompter) =
            unsafe { (conn(c)?, read_credentials(arg(cr, "credentials")?), pr.as_ref()) };
        let mut adapter = prompter.and_then(|p| p.prompt.map(|f| PromptAdapter::new(f, p.ctx)));
        let (mut state, cancel) = conn.enter()?;
        let prompter: Option<&mut dyn Prompter> = match adapter.as_mut() {
            Some(a) => Some(a),
            None => None,
        };
        run(&cancel, state.backend.authenticate(&credentials, prompter, &cancel))
    })
}

/// # Safety
/// `c` is a live connection; `out_caps` is writable.
pub unsafe extern "C" fn capabilities(c: *mut NvrConn, out_caps: *mut *mut NvbCapabilities) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, slot) = unsafe { (conn(c)?, out(out_caps)?) };
        let (state, _) = conn.enter()?;
        give(slot, caps_block(&state.backend.capabilities()))
    })
}

/// # Safety
/// `c` is NULL or a live connection.
pub unsafe extern "C" fn disconnect(c: *mut NvrConn) {
    quietly(|| {
        // SAFETY: contract.
        if let Ok((mut state, cancel)) = unsafe { conn(c) }.and_then(Conn::enter) {
            finish(&cancel, state.backend.disconnect());
        }
    });
}

/// # Safety
/// `c` is a live connection.
pub unsafe extern "C" fn keep_alive(c: *mut NvrConn) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (mut state, cancel) = unsafe { conn(c) }?.enter()?;
        run(&cancel, state.backend.keep_alive(&cancel))
    })
}

/// # Safety
/// `c` is a live connection; `path` is readable; `out_entry` is writable.
pub unsafe extern "C" fn stat(
    c: *mut NvrConn,
    path: NvbBytes,
    follow: i32,
    out_entry: *mut *mut NvbEntry,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path, slot) = unsafe { (conn(c)?, slice(path), out(out_entry)?) };
        let (mut state, cancel) = conn.enter()?;
        let found = run(&cancel, state.backend.stat(path, follow != 0, &cancel))?;
        give(slot, entry(&found))
    })
}

/// # Safety
/// `c` is a live connection; `dir` is readable; `sink` is callable with
/// `ctx` for the call.
pub unsafe extern "C" fn list(
    c: *mut NvrConn,
    dir: NvbBytes,
    batch: u32,
    resolve_symlinks: i32,
    sink: Option<NvbListSinkFn>,
    ctx: *mut std::ffi::c_void,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, dir) = unsafe { (conn(c)?, slice(dir)) };
        let mut sink = ListAdapter::new(sink.ok_or_else(|| bad("list sink"))?, ctx);
        let batch_size = usize::try_from(batch).ok().filter(|n| *n > 0).ok_or_else(|| bad("batch size"))?;
        let options = ListOptions { batch_size, resolve_symlink_types: resolve_symlinks != 0 };
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.list(dir, options, &mut sink, &cancel))
    })
}

/// # Safety
/// `c` is a live connection; `path` is readable.
pub unsafe extern "C" fn make_dir(c: *mut NvrConn, path: NvbBytes, exclusive: i32) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path) = unsafe { (conn(c)?, slice(path)) };
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.make_dir(path, exclusive != 0, &cancel))
    })
}

/// # Safety
/// `c` is a live connection; `path` is readable.
pub unsafe extern "C" fn remove_file(c: *mut NvrConn, path: NvbBytes) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path) = unsafe { (conn(c)?, slice(path)) };
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.remove_file(path, &cancel))
    })
}

/// # Safety
/// `c` is a live connection; `path` is readable.
pub unsafe extern "C" fn remove_dir(c: *mut NvrConn, path: NvbBytes) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path) = unsafe { (conn(c)?, slice(path)) };
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.remove_dir(path, &cancel))
    })
}

const fn mode(replace: i32) -> RenameMode {
    if replace != 0 { RenameMode::Replace } else { RenameMode::NoReplace }
}

/// # Safety
/// `c` is a live connection; the paths are readable.
pub unsafe extern "C" fn rename(
    c: *mut NvrConn,
    from: NvbBytes,
    to: NvbBytes,
    replace: i32,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, from, to) = unsafe { (conn(c)?, slice(from), slice(to)) };
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.rename(from, to, mode(replace), &cancel))
    })
}

/// # Safety
/// `c` is a live connection; `path` and `a` are readable.
pub unsafe extern "C" fn set_attributes(
    c: *mut NvrConn,
    path: NvbBytes,
    a: *const NvbAttributes,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path, changes) = unsafe { (conn(c)?, slice(path), attributes(arg(a, "attributes")?)?) };
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.set_attributes(path, &changes, &cancel))
    })
}

/// # Safety
/// `c` is a live connection; `path` is readable; `target` is writable.
pub unsafe extern "C" fn read_link(
    c: *mut NvrConn,
    path: NvbBytes,
    target: *mut *mut NvbBlob,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path, slot) = unsafe { (conn(c)?, slice(path), out(target)?) };
        let (mut state, cancel) = conn.enter()?;
        let link = run(&cancel, state.backend.read_link(path, &cancel))?;
        give(slot, blob(&link))
    })
}

/// # Safety
/// `c` is a live connection; the paths are readable.
pub unsafe extern "C" fn make_symlink(c: *mut NvrConn, target: NvbBytes, link: NvbBytes) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, target, link) = unsafe { (conn(c)?, slice(target), slice(link)) };
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.make_symlink(target, link, &cancel))
    })
}

/// # Safety
/// `c` is a live connection; the paths are readable.
pub unsafe extern "C" fn make_hardlink(c: *mut NvrConn, existing: NvbBytes, link: NvbBytes) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, existing, link) = unsafe { (conn(c)?, slice(existing), slice(link)) };
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.make_hardlink(existing, link, &cancel))
    })
}

/// # Safety
/// `c` is a live connection; the paths are readable.
pub unsafe extern "C" fn copy(
    c: *mut NvrConn,
    from: NvbBytes,
    to: NvbBytes,
    recursive: i32,
    replace: i32,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, from, to) = unsafe { (conn(c)?, slice(from), slice(to)) };
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.copy(from, to, recursive != 0, mode(replace), &cancel))
    })
}

/// # Safety
/// `c` is a live connection; `path` and `algorithm` are readable;
/// `digest` is writable.
pub unsafe extern "C" fn checksum(
    c: *mut NvrConn,
    path: NvbBytes,
    algorithm: NvbBytes,
    digest: *mut *mut NvbBlob,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path, algorithm, slot) = unsafe { (conn(c)?, slice(path), text(algorithm), out(digest)?) };
        let (mut state, cancel) = conn.enter()?;
        let sum = run(&cancel, state.backend.checksum(path, &algorithm, &cancel))?;
        give(slot, blob(&sum))
    })
}

/// # Safety
/// `c` is a live connection; `dir` is readable; `out_space` is writable.
pub unsafe extern "C" fn space_info(
    c: *mut NvrConn,
    dir: NvbBytes,
    out_space: *mut NvbSpace,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, dir, slot) =
            unsafe { (conn(c)?, slice(dir), out_space.as_mut().ok_or_else(|| bad("result pointer"))?) };
        let (mut state, cancel) = conn.enter()?;
        *slot = space(&run(&cancel, state.backend.space_info(dir, &cancel))?);
        Ok(())
    })
}

/// `*size` -1 unknown.
///
/// # Safety
/// `c` is a live connection; `path` is readable; `out_read` is writable,
/// `size` NULL or writable.
pub unsafe extern "C" fn open_read(
    c: *mut NvrConn,
    path: NvbBytes,
    out_read: *mut *mut NvrRead,
    size: *mut i64,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path, slot, size) = unsafe { (conn(c)?, slice(path), out(out_read)?, size.as_mut()) };
        let (mut state, cancel) = conn.enter()?;
        let handle = run(&cancel, state.backend.open_read(path, &cancel))?;
        if let Some(size) = size {
            *size = handle.size().map_or(-1, |n| i64::try_from(n).unwrap_or(i64::MAX));
        }
        let read = Box::into_raw(Box::new(ReadSlot { conn, handle }));
        state.reads.push(read);
        count(1);
        *slot = read.cast::<NvrRead>();
        Ok(())
    })
}

/// # Safety
/// `h` is NULL or a live handle.
unsafe fn read_slot<'a>(
    h: *mut NvrRead,
) -> Result<(&'a mut ReadSlot, MutexGuard<'a, State>, CancelToken), Status> {
    // SAFETY: contract; slot's connection outlives it, and its state is held, so this is the only reference.
    unsafe {
        let slot = h.cast::<ReadSlot>().as_mut().ok_or_else(|| bad("read handle"))?;
        let (state, cancel) = (*slot.conn).enter()?;
        Ok((slot, state, cancel))
    }
}

/// Fills `buf[..cap]` from `offset`; short only at end of file.
///
/// # Safety
/// `h` is a live handle; `buf` is writable for `cap` bytes (NULL only with
/// `cap` 0); `len` is writable.
pub unsafe extern "C" fn read(
    h: *mut NvrRead,
    offset: i64,
    buf: *mut u8,
    cap: usize,
    len: *mut usize,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (slot, _state, cancel) = unsafe { read_slot(h)? };
        // SAFETY: contract.
        let len = unsafe { len.as_mut() }.ok_or_else(|| bad("length pointer"))?;
        *len = 0;
        let offset = unsigned(offset, "offset")?;
        let buf: &mut [u8] = if cap == 0 {
            &mut []
        } else if buf.is_null() {
            return Err(bad("buffer"));
        } else {
            // SAFETY: contract.
            unsafe { std::slice::from_raw_parts_mut(buf, cap) }
        };
        let handle = &mut slot.handle;
        *len = run(&cancel, async {
            let mut filled = 0usize;
            while let Some(rest) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) {
                let at = offset.saturating_add(u64::try_from(filled).unwrap_or(u64::MAX));
                let n = handle.read(at, rest, &cancel).await?;
                if n == 0 {
                    break;
                }
                if n > rest.len() {
                    return Err(Status::internal("The backend read more than asked"));
                }
                filled = filled.saturating_add(n);
            }
            Ok(filled)
        })?;
        Ok(())
    })
}

/// Hint; negative numbers ignored.
///
/// # Safety
/// `h` is NULL or a live handle.
pub unsafe extern "C" fn read_ahead(h: *mut NvrRead, offset: i64, bytes: i64) {
    quietly(|| {
        // SAFETY: contract.
        let handle = unsafe { read_slot(h) };
        if let (Ok((slot, _state, _)), Ok(offset), Ok(bytes)) =
            (handle, u64::try_from(offset), u64::try_from(bytes))
        {
            slot.handle.read_ahead(offset, bytes);
        }
    });
}

fn unlist<T>(list: &mut Vec<*mut T>, p: *mut T) -> Result<Box<T>, Status> {
    let at = list.iter().position(|q| *q == p).ok_or_else(|| Status::internal("Unknown handle"))?;
    list.swap_remove(at);
    count(-1);
    // SAFETY: listed pointer is a live box, now unlisted: sole owner.
    Ok(unsafe { Box::from_raw(p) })
}

/// Frees the handle.
///
/// # Safety
/// `h` is a live handle; it is not used afterwards.
pub unsafe extern "C" fn read_close(h: *mut NvrRead) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (_, mut state, cancel) = unsafe { read_slot(h)? };
        let slot = unlist(&mut state.reads, h.cast::<ReadSlot>())?;
        run(&cancel, slot.handle.close(&cancel))
    })
}

/// # Safety
/// `c` is a live connection; `path` and `o` are readable; `out_write` is
/// writable.
pub unsafe extern "C" fn open_write(
    c: *mut NvrConn,
    path: NvbBytes,
    o: *const NvrWriteOpts,
    out_write: *mut *mut NvrWrite,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path, o, slot) =
            unsafe { (conn(c)?, slice(path), arg(o, "write options")?, out(out_write)?) };
        let options = write_options(RawWriteOptions {
            disposition: o.disposition,
            create_mode: o.create_mode,
            resume_offset: o.resume_offset,
            expected_size: o.expected_size,
            has_mtime: o.has_mtime,
            mtime_ms: o.mtime_ms,
        })?;
        let (mut state, cancel) = conn.enter()?;
        let handle = run(&cancel, state.backend.open_write(path, &options, &cancel))?;
        let write = Box::into_raw(Box::new(WriteSlot { conn, handle }));
        state.writes.push(write);
        count(1);
        *slot = write.cast::<NvrWrite>();
        Ok(())
    })
}

/// # Safety
/// `h` is NULL or a live handle.
unsafe fn write_slot<'a>(
    h: *mut NvrWrite,
) -> Result<(&'a mut WriteSlot, MutexGuard<'a, State>, CancelToken), Status> {
    // SAFETY: as for `read_slot`.
    unsafe {
        let slot = h.cast::<WriteSlot>().as_mut().ok_or_else(|| bad("write handle"))?;
        let (state, cancel) = (*slot.conn).enter()?;
        Ok((slot, state, cancel))
    }
}

/// # Safety
/// `h` is a live handle; `data` is readable for `len` bytes (NULL only
/// with `len` 0).
pub unsafe extern "C" fn write(h: *mut NvrWrite, data: *const u8, len: usize) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (slot, _state, cancel) = unsafe { write_slot(h)? };
        if data.is_null() && len > 0 {
            return Err(bad("data"));
        }
        // SAFETY: contract.
        let data = unsafe { slice(NvbBytes { ptr: data, len }) };
        run(&cancel, slot.handle.write(data, &cancel))
    })
}

/// -1 for a bad or busy handle.
///
/// # Safety
/// `h` is NULL or a live handle.
pub unsafe extern "C" fn position(h: *const NvrWrite) -> i64 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: contract; handle unchanged.
        unsafe { write_slot(h.cast_mut()) }
            .map_or(-1, |(slot, _, _)| i64::try_from(slot.handle.position()).unwrap_or(i64::MAX))
    }))
    .unwrap_or(-1)
}

/// Frees the handle; a canceled connection aborts the write instead.
///
/// # Safety
/// `h` is a live handle; it is not used afterwards.
pub unsafe extern "C" fn commit(h: *mut NvrWrite) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (_, mut state, cancel) = unsafe { write_slot(h)? };
        let slot = unlist(&mut state.writes, h.cast::<WriteSlot>())?;
        if let Err(canceled) = cancel.check() {
            finish(&cancel, slot.handle.abort());
            return Err(canceled);
        }
        run(&cancel, slot.handle.commit(&cancel))
    })
}

/// Frees the handle.
///
/// # Safety
/// `h` is NULL or a live handle; it is not used afterwards.
pub unsafe extern "C" fn abort(h: *mut NvrWrite) {
    quietly(|| {
        // SAFETY: contract.
        if let Ok((_, mut state, cancel)) = unsafe { write_slot(h) }
            && let Ok(slot) = unlist(&mut state.writes, h.cast::<WriteSlot>())
        {
            finish(&cancel, slot.handle.abort());
        }
    });
}

/// # Safety
/// `c` is a live connection; `path`, `o` and `io` are readable, `pr` NULL
/// or readable; their functions are callable for the call.
pub unsafe extern "C" fn upload(
    c: *mut NvrConn,
    path: NvbBytes,
    o: *const NvbUploadOpts,
    io: *const NvbIo,
    pr: *const NvbProgress,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path, o, io, pr) =
            unsafe { (conn(c)?, slice(path), arg(o, "upload options")?, arg(io, "io")?, pr.as_ref()) };
        let options = write_options(RawWriteOptions {
            disposition: o.disposition,
            create_mode: o.create_mode,
            resume_offset: o.resume_offset,
            expected_size: o.expected_size,
            has_mtime: o.has_mtime,
            mtime_ms: o.mtime_ms,
        })?;
        let mut source = IoSource::new(*io).ok_or_else(|| bad("read function"))?;
        let mut progress = ProgressAdapter::new(pr.copied());
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.upload(path, &options, &mut source, &mut progress, &cancel))
    })
}

/// `length` -1: to the end.
///
/// # Safety
/// `c` is a live connection; `path` and `io` are readable, `pr` NULL or
/// readable; their functions are callable for the call.
pub unsafe extern "C" fn download(
    c: *mut NvrConn,
    path: NvbBytes,
    offset: i64,
    length: i64,
    io: *const NvbIo,
    pr: *const NvbProgress,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let (conn, path, io, pr) = unsafe { (conn(c)?, slice(path), arg(io, "io")?, pr.as_ref()) };
        let (offset, length) = (unsigned(offset, "offset")?, optional(length, "length")?);
        let mut sink = IoSink::new(*io).ok_or_else(|| bad("write function"))?;
        let mut progress = ProgressAdapter::new(pr.copied());
        let (mut state, cancel) = conn.enter()?;
        run(&cancel, state.backend.download(path, offset, length, &mut sink, &mut progress, &cancel))
    })
}

/// # Safety
/// `out_key` is NULL or writable.
unsafe fn give_key(
    out_key: *mut *mut NvrKey,
    tool: impl FnOnce() -> Result<netvfs_sftp::keys::KeyMaterial, Status>,
) -> *mut NvbError {
    status(|| {
        // SAFETY: contract.
        let slot = unsafe { out(out_key) }?;
        give(slot, key(&tool()?))
    })
}

/// # Safety
/// `out_key` is NULL or writable.
pub unsafe extern "C" fn key_generate(out_key: *mut *mut NvrKey) -> *mut NvbError {
    // SAFETY: contract.
    unsafe { give_key(out_key, netvfs_sftp::keys::generate) }
}

/// Decrypts with `passphrase` if encrypted.
///
/// # Safety
/// `file` and `passphrase` are readable; `out_key` is NULL or writable.
pub unsafe extern "C" fn key_import(
    file: NvbBytes,
    passphrase: NvbBytes,
    out_key: *mut *mut NvrKey,
) -> *mut NvbError {
    // SAFETY: contract.
    let (file, passphrase) = unsafe { (slice(file), slice(passphrase)) };
    // SAFETY: contract.
    unsafe { give_key(out_key, || netvfs_sftp::keys::import(file, passphrase)) }
}

/// # Safety
/// `private_key` is readable; `out_key` is NULL or writable.
pub unsafe extern "C" fn key_describe(private_key: NvbBytes, out_key: *mut *mut NvrKey) -> *mut NvbError {
    // SAFETY: contract.
    let private_key = unsafe { slice(private_key) };
    // SAFETY: contract.
    unsafe { give_key(out_key, || netvfs_sftp::keys::describe(private_key)) }
}
