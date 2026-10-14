// SPDX-License-Identifier: LGPL-2.1-or-later
//! The C ABI of libnetvfs-rs.so (`src/backends/rs/netvfs_rs.h`) against the
//! `mem` backend, called through the table the way the shim calls it:
//! ownership (blocks freed, no leaks), threads (callbacks on the caller's
//! thread, two runtime workers, one call at a time), cancel within the
//! C-9 bound, panics as `Internal`, and the argument checks. Each test uses
//! its own `mem` store.
#![allow(
    unsafe_code,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::undocumented_unsafe_blocks,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::many_single_char_names,
    clippy::type_complexity
)]

use netvfs_rs::ffi::raw::*;
use netvfs_rs::ffi::{live_blocks, live_objects};
use netvfs_rs::{GRACE, THREAD_PREFIX, WORKERS, nvr_get};
use std::cell::RefCell;
use std::ffi::{c_int, c_void};
use std::panic;
use std::ptr;
use std::sync::Once;
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

// ------------------------------------------------------------- helpers

/// C-9.
const CANCEL_LIMIT: Duration = Duration::from_secs(2);

fn t() -> &'static NvrTable {
    // nvr_get returns the address of a static table.
    unsafe { &*nvr_get() }
}

fn b(data: &[u8]) -> NvbBytes {
    NvbBytes::of(data)
}

fn bytes(x: NvbBytes) -> Vec<u8> {
    if x.ptr.is_null() || x.len == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(x.ptr, x.len) }.to_vec()
}

fn text(x: NvbBytes) -> String {
    String::from_utf8(bytes(x)).unwrap()
}

fn free<T>(p: *mut T) {
    unsafe { (t().free)(p.cast()) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fail {
    name: String,
    message: String,
    detail: String,
}

/// A table call's result; the error block is freed.
fn res(e: *mut NvbError) -> Result<(), Fail> {
    if e.is_null() {
        return Ok(());
    }
    let r = unsafe { &*e };
    assert_eq!(r.retry_after_ms, -1);
    let fail = Fail { name: text(r.name), message: text(r.message), detail: text(r.detail) };
    free(e);
    Err(fail)
}

/// The error name of a failed call.
fn name<T: std::fmt::Debug>(r: Result<T, Fail>) -> String {
    r.unwrap_err().name
}

fn assert_no_leaks() {
    assert_eq!((live_blocks(), live_objects()), (0, 0), "blocks and objects of this thread");
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct E {
    name: Vec<u8>,
    kind: u8,
    target_kind: u8,
    flags: u16,
    mode: i32,
    size: i64,
    mtime: i64,
    atime: i64,
    uid: i64,
    owner: Vec<u8>,
    etag: Vec<u8>,
}

fn entry_of(r: &NvbEntry) -> E {
    E {
        name: bytes(r.name),
        kind: r.kind,
        target_kind: r.target_kind,
        flags: r.flags,
        mode: r.mode,
        size: r.size,
        mtime: r.mtime_ms,
        atime: r.atime_ms,
        uid: r.uid,
        owner: bytes(r.owner),
        etag: bytes(r.etag),
    }
}

const FILE: u8 = 1;
const DIR: u8 = 2;
const LINK: u8 = 3;
const NAME_NOT_UTF8: u16 = 0x0008;
const TARGET_UNKNOWN: u16 = 0x0010;

// ---- panics

thread_local! {
    static PANICS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// The panic messages of this thread while `f` runs.
fn panics_in(f: impl FnOnce()) -> Vec<String> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let default = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let message = info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_default();
            if message.starts_with("mem: ") {
                PANICS.with(|p| p.borrow_mut().push(message));
            } else {
                default(info);
            }
        }));
    });
    PANICS.with(|p| p.borrow_mut().clear());
    f();
    PANICS.with(RefCell::take)
}

// ---- local side of transfers

#[derive(Default)]
struct Local {
    data: Vec<u8>,
    at: usize,
    sequential: bool,
    fail: bool,
    positions: Vec<i64>,
}

unsafe extern "C" fn io_read(ctx: *mut c_void, pos: i64, buf: *mut u8, cap: usize) -> i64 {
    let l = unsafe { &mut *ctx.cast::<Local>() };
    l.positions.push(pos);
    if l.fail {
        return -1;
    }
    let n = cap.min(l.data.len() - l.at);
    unsafe { ptr::copy_nonoverlapping(l.data.as_ptr().add(l.at), buf, n) };
    l.at += n;
    n as i64
}

unsafe extern "C" fn io_write(ctx: *mut c_void, pos: i64, data: *const u8, len: usize) -> i64 {
    let l = unsafe { &mut *ctx.cast::<Local>() };
    l.positions.push(pos);
    if l.fail {
        return -1;
    }
    l.data.extend_from_slice(unsafe { std::slice::from_raw_parts(data, len) });
    len as i64
}

fn io(l: &mut Local) -> NvbIo {
    let size = if l.sequential { 0 } else { (l.data.len() - l.at) as i64 };
    NvbIo {
        ctx: ptr::from_mut(l).cast(),
        sequential: u8::from(l.sequential),
        size,
        read: Some(io_read),
        write: Some(io_write),
    }
}

struct Prog {
    updates: Vec<(i64, i64)>,
    stop_after: Option<usize>,
    cancel: *mut NvrConn,
    thread: Option<ThreadId>,
}

impl Default for Prog {
    fn default() -> Self {
        Self { updates: Vec::new(), stop_after: None, cancel: ptr::null_mut(), thread: None }
    }
}

unsafe extern "C" fn prog_update(ctx: *mut c_void, done: i64, total: i64) {
    let p = unsafe { &mut *ctx.cast::<Prog>() };
    p.updates.push((done, total));
    p.thread = Some(thread::current().id());
    if !p.cancel.is_null() {
        unsafe { (t().cancel)(p.cancel) };
    }
}

unsafe extern "C" fn prog_canceled(ctx: *mut c_void) -> c_int {
    let p = unsafe { &*ctx.cast::<Prog>() };
    c_int::from(p.stop_after.is_some_and(|n| p.updates.len() >= n))
}

fn progress(p: &mut Prog) -> NvbProgress {
    NvbProgress { ctx: ptr::from_mut(p).cast(), update: Some(prog_update), canceled: Some(prog_canceled) }
}

fn truncate() -> NvbUploadOpts {
    NvbUploadOpts {
        disposition: NVB_DISPOSITION_TRUNCATE,
        create_mode: -1,
        resume_offset: 0,
        expected_size: -1,
        has_mtime: 0,
        mtime_ms: 0,
    }
}

fn write_opts(disposition: u32) -> NvrWriteOpts {
    NvrWriteOpts {
        disposition,
        create_mode: -1,
        resume_offset: 0,
        expected_size: -1,
        has_mtime: 0,
        mtime_ms: 0,
    }
}

// ---- listing

#[derive(Default)]
struct Lister {
    batches: Vec<Vec<E>>,
    stop_after: Option<usize>,
    cancel: Option<*mut NvrConn>,
    inside: Option<Box<dyn FnMut()>>,
    thread: Option<ThreadId>,
}

unsafe extern "C" fn sink(ctx: *mut c_void, entries: *const NvbEntry, n: usize) -> c_int {
    let l = unsafe { &mut *ctx.cast::<Lister>() };
    l.thread = Some(thread::current().id());
    let batch = unsafe { std::slice::from_raw_parts(entries, n) };
    l.batches.push(batch.iter().map(entry_of).collect());
    if let Some(c) = l.cancel {
        unsafe { (t().cancel)(c) };
    }
    if let Some(inside) = &mut l.inside {
        inside();
    }
    c_int::from(l.stop_after.is_none_or(|stop| l.batches.len() < stop))
}

// ---- prompts

#[derive(Default)]
struct Asker {
    answers: Vec<Vec<u8>>,
    result: c_int,
    asked: Vec<(String, String, Vec<(String, u8)>)>,
    thread: Option<ThreadId>,
}

unsafe extern "C" fn ask(
    ctx: *mut c_void,
    name: NvbBytes,
    instruction: NvbBytes,
    prompts: *const NvbPrompt,
    n: usize,
    reply: *mut NvbReply,
) -> c_int {
    let a = unsafe { &mut *ctx.cast::<Asker>() };
    a.thread = Some(thread::current().id());
    let prompts = unsafe { std::slice::from_raw_parts(prompts, n) };
    a.asked.push((text(name), text(instruction), prompts.iter().map(|p| (text(p.text), p.echo)).collect()));
    let answers: Vec<NvbBytes> = a.answers.iter().map(|x| b(x)).collect();
    unsafe { (t().reply_set)(reply, answers.as_ptr(), answers.len()) };
    a.result
}

// ---- a connection

/// A `mem` connection, freed on drop.
struct Conn(*mut NvrConn);

impl Drop for Conn {
    fn drop(&mut self) {
        unsafe { (t().conn_free)(self.0) };
    }
}

/// A connection's pointer, for another thread (the test serialises).
struct SendPtr(*mut NvrConn);
unsafe impl Send for SendPtr {}

impl Conn {
    fn new() -> Self {
        let mut c = ptr::null_mut();
        res(unsafe { (t().conn_new)(b(b"mem"), &raw mut c) }).unwrap();
        assert!(!c.is_null());
        Self(c)
    }

    /// Connected to store `store` and signed in.
    fn open(store: &str, options: &[(&str, &str)]) -> Self {
        let c = Self::new();
        let mut all = vec![("store", store)];
        all.extend_from_slice(options);
        assert_eq!(c.connect(&all).unwrap(), None);
        c.auth(b"", ptr::null()).unwrap();
        c
    }

    /// `connect`; the identity seen as (kind, algorithm, key, fingerprint, pin).
    #[allow(clippy::type_complexity)]
    fn connect(
        &self,
        options: &[(&str, &str)],
    ) -> Result<Option<(u32, String, Vec<u8>, String, String)>, Fail> {
        let kvs: Vec<NvbKv> = options
            .iter()
            .map(|(k, v)| NvbKv {
                key: b(k.as_bytes()),
                value: NvbValue {
                    kind: NVB_VALUE_STRING,
                    number: 0,
                    bytes: b(v.as_bytes()),
                    items: ptr::null(),
                    n_items: 0,
                },
            })
            .collect();
        let p = NvbParams {
            provider: b(b"mem"),
            host: b(b"localhost"),
            port: 0,
            username: b(b"alice"),
            options: kvs.as_ptr(),
            n_options: kvs.len(),
            connect_timeout_ms: 1000,
            request_timeout_ms: 1000,
        };
        let mut seen: *mut NvbIdentity = ptr::null_mut();
        res(unsafe { (t().connect)(self.0, &raw const p, &raw mut seen) })?;
        if seen.is_null() {
            return Ok(None);
        }
        let id = unsafe { &*seen };
        let out = (id.kind, text(id.algorithm), bytes(id.public_key), text(id.fingerprint), text(id.pin));
        free(seen);
        Ok(Some(out))
    }

    fn auth(&self, secret: &[u8], prompter: *const NvrPrompter) -> Result<(), Fail> {
        let cr = NvrCredentials { user: b(b"alice"), secret: b(secret), domain: b(b"WORK") };
        res(unsafe { (t().authenticate)(self.0, &raw const cr, prompter) })
    }

    fn caps(&self) -> Result<(Vec<String>, Vec<String>, i64), Fail> {
        let mut out: *mut NvbCapabilities = ptr::null_mut();
        res(unsafe { (t().capabilities)(self.0, &raw mut out) })?;
        let c = unsafe { &*out };
        let list = |p: *const NvbBytes, n: usize| -> Vec<String> {
            unsafe { std::slice::from_raw_parts(p, n) }.iter().map(|x| text(*x)).collect()
        };
        let got = (
            list(c.flags, c.n_flags),
            list(c.checksum_algorithms, c.n_checksum_algorithms),
            c.max_name_bytes,
        );
        free(out);
        Ok(got)
    }

    fn stat(&self, path: &[u8], follow: bool) -> Result<E, Fail> {
        let mut out: *mut NvbEntry = ptr::null_mut();
        res(unsafe { (t().stat)(self.0, b(path), i32::from(follow), &raw mut out) })?;
        let e = entry_of(unsafe { &*out });
        free(out);
        Ok(e)
    }

    fn list_with(&self, dir: &[u8], batch: u32, resolve: bool, lister: &mut Lister) -> Result<(), Fail> {
        res(unsafe {
            (t().list)(self.0, b(dir), batch, i32::from(resolve), Some(sink), ptr::from_mut(lister).cast())
        })
    }

    fn names(&self, dir: &[u8]) -> Vec<Vec<u8>> {
        let mut l = Lister::default();
        self.list_with(dir, 100, false, &mut l).unwrap();
        l.batches.into_iter().flatten().map(|e| e.name).collect()
    }

    fn mkdir(&self, path: &[u8], exclusive: bool) -> Result<(), Fail> {
        res(unsafe { (t().make_dir)(self.0, b(path), i32::from(exclusive)) })
    }

    fn rm(&self, path: &[u8]) -> Result<(), Fail> {
        res(unsafe { (t().remove_file)(self.0, b(path)) })
    }

    fn rmdir(&self, path: &[u8]) -> Result<(), Fail> {
        res(unsafe { (t().remove_dir)(self.0, b(path)) })
    }

    fn rename(&self, from: &[u8], to: &[u8], replace: bool) -> Result<(), Fail> {
        res(unsafe { (t().rename)(self.0, b(from), b(to), i32::from(replace)) })
    }

    fn put(&self, path: &[u8], data: &[u8]) -> Result<(), Fail> {
        let mut l = Local { data: data.to_vec(), ..Local::default() };
        let io = io(&mut l);
        res(unsafe { (t().upload)(self.0, b(path), &truncate(), &raw const io, ptr::null()) })
    }

    fn download(
        &self,
        path: &[u8],
        offset: i64,
        length: i64,
        p: Option<&mut Prog>,
    ) -> (Result<(), Fail>, Vec<u8>) {
        let mut l = Local::default();
        let io = io(&mut l);
        let pr = p.map(progress);
        let pr = pr.as_ref().map_or(ptr::null(), ptr::from_ref);
        let r = res(unsafe { (t().download)(self.0, b(path), offset, length, &raw const io, pr) });
        (r, l.data)
    }

    fn get(&self, path: &[u8]) -> Result<Vec<u8>, Fail> {
        let (r, data) = self.download(path, 0, -1, None);
        r.map(|()| data)
    }

    fn open_read(&self, path: &[u8]) -> Result<(*mut NvrRead, i64), Fail> {
        let mut h = ptr::null_mut();
        let mut size = -7;
        res(unsafe { (t().open_read)(self.0, b(path), &raw mut h, &raw mut size) })?;
        assert!(!h.is_null());
        Ok((h, size))
    }

    fn open_write(&self, path: &[u8], o: &NvrWriteOpts) -> Result<*mut NvrWrite, Fail> {
        let mut h = ptr::dangling_mut();
        let r = res(unsafe { (t().open_write)(self.0, b(path), ptr::from_ref(o), &raw mut h) });
        if r.is_err() {
            assert!(h.is_null());
        }
        r.map(|()| h)
    }

    fn keep_alive(&self) -> Result<(), Fail> {
        res(unsafe { (t().keep_alive)(self.0) })
    }

    fn cancel(&self) {
        unsafe { (t().cancel)(self.0) };
    }

    fn reset(&self) {
        unsafe { (t().reset_cancel)(self.0) };
    }

    fn disconnect(&self) {
        unsafe { (t().disconnect)(self.0) };
    }
}

/// The blob a call returns.
fn blob(call: impl FnOnce(*mut *mut NvbBlob) -> *mut NvbError) -> Result<Vec<u8>, Fail> {
    let mut out: *mut NvbBlob = ptr::null_mut();
    res(call(&raw mut out))?;
    let data = bytes(unsafe { &*out }.data);
    free(out);
    Ok(data)
}

fn read(h: *mut NvrRead, offset: i64, cap: usize) -> Result<Vec<u8>, Fail> {
    let mut buf = vec![0u8; cap];
    let mut len = 99usize;
    res(unsafe { (t().read)(h, offset, buf.as_mut_ptr(), cap, &raw mut len) })?;
    buf.truncate(len);
    Ok(buf)
}

fn write(h: *mut NvrWrite, data: &[u8]) -> Result<(), Fail> {
    res(unsafe { (t().write)(h, data.as_ptr(), data.len()) })
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// Runs `call` while another thread cancels `c` after `delay`; the call's
/// result and the time from cancel to return.
fn canceled_after<R>(c: &Conn, delay: Duration, call: impl FnOnce() -> R) -> (R, Duration) {
    let target = SendPtr(c.0);
    let canceler = thread::spawn(move || {
        let target = target;
        thread::sleep(delay);
        let at = Instant::now();
        unsafe { (t().cancel)(target.0) };
        at
    });
    let r = call();
    let returned = Instant::now();
    let at = canceler.join().unwrap();
    (r, returned.duration_since(at))
}

// ------------------------------------------------------------- tests

#[test]
fn the_table_is_one_static() {
    assert_eq!(nvr_get(), nvr_get());
    assert_eq!(NVR_ENTRY, b"nvr_get\0");
    free(ptr::null_mut::<u8>());
    unsafe {
        (t().reply_set)(ptr::null_mut(), ptr::null(), 0);
        (t().conn_free)(ptr::null_mut());
        (t().cancel)(ptr::null_mut());
        (t().reset_cancel)(ptr::null_mut());
        (t().disconnect)(ptr::null_mut());
    }
    assert_no_leaks();
}

#[test]
fn providers() {
    let mut c = ptr::dangling_mut();
    let e = res(unsafe { (t().conn_new)(b(b"sftp"), &raw mut c) }).unwrap_err();
    assert_eq!(
        (e.name.as_str(), e.message.as_str()),
        ("Unsupported", "No Rust backend for provider \"sftp\"")
    );
    assert!(c.is_null());
    let e = res(unsafe { (t().conn_new)(b(b"mem"), ptr::null_mut()) }).unwrap_err();
    assert_eq!(
        (e.name.as_str(), e.message.as_str()),
        ("ProtocolError", "Missing result pointer from the plugin")
    );
    {
        let conn = Conn::new();
        assert_eq!(live_objects(), 1);
        // Not connected yet.
        assert_eq!(name(conn.keep_alive()), "ConnectionLost");
        assert_eq!(name(conn.auth(b"", ptr::null())), "ConnectionLost");
        conn.disconnect();
    }
    assert_no_leaks();
}

#[test]
fn connect_and_authenticate() {
    let c = Conn::new();
    let seen = c.connect(&[("store", "auth"), ("identity", "ssh-ed25519")]).unwrap().unwrap();
    assert_eq!(
        seen,
        (NVB_IDENTITY_SSH, "ssh-ed25519".to_owned(), b"mem host key".to_vec(), String::new(), String::new())
    );
    assert_eq!(c.connect(&[("store", "auth"), ("secret", "pw")]).unwrap(), None);
    assert_eq!(name(c.auth(b"wrong", ptr::null())), "AuthFailed");
    c.auth(b"pw", ptr::null()).unwrap();
    // NULL arguments are the plugin's bug.
    let e = res(unsafe { (t().connect)(c.0, ptr::null(), ptr::null_mut()) }).unwrap_err();
    assert_eq!(
        (e.name.as_str(), e.message.as_str()),
        ("ProtocolError", "Missing parameters from the plugin")
    );
    assert_eq!(name(res(unsafe { (t().authenticate)(c.0, ptr::null(), ptr::null()) })), "ProtocolError");
    // An option of a kind no build knows.
    let kv = NvbKv {
        key: b(b"x"),
        value: NvbValue { kind: 77, number: 0, bytes: b(b""), items: ptr::null(), n_items: 0 },
    };
    let p = NvbParams {
        provider: b(b"mem"),
        host: b(b""),
        port: 0,
        username: b(b""),
        options: &raw const kv,
        n_options: 1,
        connect_timeout_ms: 0,
        request_timeout_ms: 0,
    };
    let mut seen = ptr::null_mut();
    assert_eq!(name(res(unsafe { (t().connect)(c.0, &raw const p, &raw mut seen) })), "ProtocolError");
    drop(c);
    assert_no_leaks();
}

#[test]
fn keyboard_interactive() {
    let options = [("store", "kbd"), ("interactive", "Code?"), ("answer", "42")];
    let c = Conn::new();
    c.connect(&options).unwrap();
    let mut asker = Asker { answers: vec![b"42".to_vec()], result: 1, ..Asker::default() };
    let prompter = NvrPrompter { ctx: ptr::from_mut(&mut asker).cast(), prompt: Some(ask) };
    c.auth(b"", &raw const prompter).unwrap();
    assert_eq!(
        asker.asked,
        [("mem".to_owned(), "Sign in as alice".to_owned(), vec![("Code?".to_owned(), 0)])]
    );
    assert_eq!(asker.thread, Some(thread::current().id()));
    asker.answers = vec![b"41".to_vec()];
    assert_eq!(name(c.auth(b"", &raw const prompter)), "AuthFailed");
    asker.answers = vec![b"42".to_vec()];
    asker.result = 0;
    assert_eq!(name(c.auth(b"", &raw const prompter)), "AuthFailed");
    assert_eq!(name(c.auth(b"", ptr::null())), "AuthFailed");
    let silent = NvrPrompter { ctx: ptr::null_mut(), prompt: None };
    assert_eq!(name(c.auth(b"", &raw const silent)), "AuthFailed");
    assert_eq!(asker.asked.len(), 3);
    drop(c);
    assert_no_leaks();
}

#[test]
fn capabilities() {
    let c = Conn::open("caps", &[]);
    let (flags, algorithms, max) = c.caps().unwrap();
    assert_eq!(
        flags,
        [
            "AtomicReplace",
            "Checksums",
            "ETags",
            "EfficientRanges",
            "Hardlinks",
            "NativeNoReplace",
            "Ownership",
            "PosixModes",
            "ReadHandles",
            "ServerCopy",
            "ServerCopyRecursive",
            "SetModified",
            "SetModifiedOnUpload",
            "SpaceInfo",
            "Symlinks",
            "WriteResume",
        ]
    );
    assert_eq!((algorithms, max), (vec!["sha256".to_owned()], 255));
    assert_eq!(name(res(unsafe { (t().capabilities)(c.0, ptr::null_mut()) })), "ProtocolError");
    drop(c);
    assert_no_leaks();
}

#[test]
fn namespace() {
    let c = Conn::open("namespace", &[]);
    c.mkdir(b"d", true).unwrap();
    assert_eq!(name(c.mkdir(b"d", true)), "AlreadyExists");
    c.mkdir(b"d", false).unwrap();
    assert_eq!(name(c.mkdir(b"missing/child", false)), "NotFound");
    c.put(b"d/f", b"12345").unwrap();
    let f = c.stat(b"d/f", true).unwrap();
    assert_eq!((f.name.as_slice(), f.kind, f.size, f.mode, f.uid), (&b"f"[..], FILE, 5, 0o644, 1000));
    assert_eq!(f.owner, b"mem");
    assert!(!f.etag.is_empty());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    assert!((now - f.mtime).abs() < 60_000);
    assert_eq!(c.stat(b"d", false).unwrap().kind, DIR);
    assert_eq!(name(c.stat(b"nope", true)), "NotFound");
    let odd = b"d/caf\xe9";
    c.put(odd, b"x").unwrap();
    assert_eq!(c.stat(odd, false).unwrap().flags, NAME_NOT_UTF8);
    assert_eq!(c.names(b"d"), [b"caf\xe9".to_vec(), b"f".to_vec()]);
    assert_eq!(name(c.rm(b"d")), "IsADirectory");
    assert_eq!(name(c.rmdir(b"d")), "DirectoryNotEmpty");
    assert_eq!(name(c.rmdir(b"d/f")), "NotADirectory");
    c.rm(odd).unwrap();
    assert_eq!(name(c.rename(b"d/f", b"d/f", false)), "AlreadyExists");
    c.put(b"g", b"g").unwrap();
    assert_eq!(name(c.rename(b"g", b"d/f", false)), "AlreadyExists");
    c.rename(b"g", b"d/f", true).unwrap();
    assert_eq!(c.get(b"d/f").unwrap(), b"g");
    c.rename(b"d/f", b"h", false).unwrap();
    c.rmdir(b"d").unwrap();
    assert_eq!(c.names(b""), [b"h".to_vec()]);
    c.keep_alive().unwrap();
    drop(c);
    assert_no_leaks();
}

#[test]
fn listing() {
    let c = Conn::open("listing", &[]);
    for i in 0..25 {
        c.put(format!("e{i:02}").as_bytes(), b"").unwrap();
    }
    let mut l = Lister::default();
    c.list_with(b"", 10, false, &mut l).unwrap();
    assert_eq!(l.batches.iter().map(Vec::len).collect::<Vec<_>>(), [10, 10, 5]);
    assert_eq!(l.batches[2][4].name, b"e24");
    assert_eq!(l.thread, Some(thread::current().id()));
    // The sink stops: Canceled after that batch.
    let mut l = Lister { stop_after: Some(1), ..Lister::default() };
    assert_eq!(name(c.list_with(b"", 10, false, &mut l)), "Canceled");
    assert_eq!(l.batches.len(), 1);
    // cancel() from the sink: no further batch.
    let mut l = Lister { cancel: Some(c.0), ..Lister::default() };
    assert_eq!(name(c.list_with(b"", 10, false, &mut l)), "Canceled");
    assert_eq!(l.batches.len(), 1);
    assert_eq!(name(c.keep_alive()), "Canceled");
    c.reset();
    // Symlink types, resolved on request.
    c.mkdir(b"dir", true).unwrap();
    res(unsafe { (t().make_symlink)(c.0, b(b"dir"), b(b"dir/self")) }).unwrap();
    res(unsafe { (t().make_symlink)(c.0, b(b".."), b(b"dir/up")) }).unwrap();
    res(unsafe { (t().make_symlink)(c.0, b(b"gone"), b(b"dir/dangling")) }).unwrap();
    let mut l = Lister::default();
    c.list_with(b"dir", 100, true, &mut l).unwrap();
    let kinds: Vec<(Vec<u8>, u8, u8, u16)> =
        l.batches.concat().into_iter().map(|e| (e.name, e.kind, e.target_kind, e.flags)).collect();
    assert_eq!(
        kinds,
        [
            (b"dangling".to_vec(), LINK, 0, TARGET_UNKNOWN),
            (b"self".to_vec(), LINK, 0, TARGET_UNKNOWN),
            (b"up".to_vec(), LINK, DIR, 0),
        ]
    );
    let mut l = Lister::default();
    c.list_with(b"dir", 100, false, &mut l).unwrap();
    assert!(l.batches.concat().iter().all(|e| e.target_kind == 0 && e.flags == 0));
    assert_eq!(name(c.list_with(b"e00", 10, false, &mut Lister::default())), "NotADirectory");
    // Batch 0 and a NULL sink are the plugin's bugs.
    assert_eq!(name(c.list_with(b"", 0, false, &mut Lister::default())), "ProtocolError");
    let e = res(unsafe { (t().list)(c.0, b(b""), 10, 0, None, ptr::null_mut()) }).unwrap_err();
    assert_eq!(e.message, "Missing list sink from the plugin");
    drop(c);
    assert_no_leaks();
}

#[test]
fn links_attributes_copies() {
    let c = Conn::open("links", &[]);
    c.put(b"target", b"data").unwrap();
    res(unsafe { (t().make_symlink)(c.0, b(b"target"), b(b"link")) }).unwrap();
    assert_eq!(name(res(unsafe { (t().make_symlink)(c.0, b(b"x"), b(b"link")) })), "AlreadyExists");
    assert_eq!(blob(|out| unsafe { (t().read_link)(c.0, b(b"link"), out) }).unwrap(), b"target");
    assert_eq!(name(blob(|out| unsafe { (t().read_link)(c.0, b(b"target"), out) })), "InvalidName");
    let link = c.stat(b"link", false).unwrap();
    assert_eq!((link.kind, link.target_kind), (LINK, FILE));
    assert_eq!(c.stat(b"link", true).unwrap().size, 4);
    res(unsafe { (t().make_hardlink)(c.0, b(b"target"), b(b"hard")) }).unwrap();
    assert_eq!(name(res(unsafe { (t().make_hardlink)(c.0, b(b"target"), b(b"hard")) })), "AlreadyExists");
    c.put(b"hard", b"new").unwrap();
    assert_eq!(c.get(b"target").unwrap(), b"new");

    let a = NvbAttributes { mode: 0o600, has_mtime: 1, has_atime: 1, mtime_ms: 981_173_106_000, atime_ms: 5 };
    res(unsafe { (t().set_attributes)(c.0, b(b"target"), &raw const a) }).unwrap();
    let e = c.stat(b"target", true).unwrap();
    assert_eq!((e.mode, e.mtime, e.atime), (0o600, 981_173_106_000, 5));
    let keep = NvbAttributes { mode: -1, has_mtime: 0, has_atime: 0, mtime_ms: 1, atime_ms: 1 };
    res(unsafe { (t().set_attributes)(c.0, b(b"target"), &raw const keep) }).unwrap();
    let e = c.stat(b"target", true).unwrap();
    assert_eq!((e.mode, e.mtime, e.atime), (0o600, 981_173_106_000, 5));
    let invalid = NvbAttributes { mode: 0o170_644, has_mtime: 1, has_atime: 0, mtime_ms: 7, atime_ms: 0 };
    assert_eq!(
        name(res(unsafe { (t().set_attributes)(c.0, b(b"target"), &raw const invalid) })),
        "ProtocolError"
    );
    assert_eq!(c.stat(b"target", true).unwrap().mtime, 981_173_106_000);
    assert_eq!(name(res(unsafe { (t().set_attributes)(c.0, b(b"target"), ptr::null()) })), "ProtocolError");
    let negative = NvbAttributes { mode: -5, ..keep };
    assert_eq!(
        name(res(unsafe { (t().set_attributes)(c.0, b(b"target"), &raw const negative) })),
        "ProtocolError"
    );

    c.mkdir(b"dir", true).unwrap();
    c.put(b"dir/inner", b"in").unwrap();
    res(unsafe { (t().copy)(c.0, b(b"target"), b(b"copy"), 0, 0) }).unwrap();
    assert_eq!(c.get(b"copy").unwrap(), b"new");
    assert_eq!(name(res(unsafe { (t().copy)(c.0, b(b"target"), b(b"copy"), 0, 0) })), "AlreadyExists");
    c.put(b"target", b"newer").unwrap();
    res(unsafe { (t().copy)(c.0, b(b"target"), b(b"copy"), 0, 1) }).unwrap();
    assert_eq!(c.get(b"copy").unwrap(), b"newer");
    assert_eq!(name(res(unsafe { (t().copy)(c.0, b(b"dir"), b(b"dir2"), 0, 0) })), "IsADirectory");
    res(unsafe { (t().copy)(c.0, b(b"dir"), b(b"dir2"), 1, 0) }).unwrap();
    assert_eq!(c.get(b"dir2/inner").unwrap(), b"in");

    let inner_digest =
        blob(|out| unsafe { (t().checksum)(c.0, b(b"dir/inner"), b(b"sha256"), out) }).unwrap();
    assert_eq!(inner_digest.len(), 32);
    c.put(b"empty", b"").unwrap();
    let digest = blob(|out| unsafe { (t().checksum)(c.0, b(b"empty"), b(b"sha256"), out) }).unwrap();
    assert_eq!(
        digest,
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        ]
    );
    assert_eq!(name(blob(|out| unsafe { (t().checksum)(c.0, b(b"empty"), b(b"md5"), out) })), "Unsupported");
    assert_eq!(
        name(blob(|out| unsafe { (t().checksum)(c.0, b(b"dir"), b(b"sha256"), out) })),
        "IsADirectory"
    );

    let mut space = NvbSpace::default();
    res(unsafe { (t().space_info)(c.0, b(b""), &raw mut space) }).unwrap();
    assert_eq!(space.total_bytes, 1 << 40);
    assert_eq!(space.free_bytes + space.used_bytes, space.total_bytes);
    assert!(space.used_bytes >= 12);
    assert_eq!(name(res(unsafe { (t().space_info)(c.0, b(b"missing"), &raw mut space) })), "NotFound");
    assert_eq!(name(res(unsafe { (t().space_info)(c.0, b(b""), ptr::null_mut()) })), "ProtocolError");
    drop(c);
    assert_no_leaks();
}

#[test]
fn read_handles() {
    let c = Conn::open("read", &[]);
    let data = pattern(600_000, 1);
    c.put(b"data", &data).unwrap();
    let (h, size) = c.open_read(b"data").unwrap();
    assert_eq!(size, 600_000);
    assert_eq!(live_objects(), 2);
    assert_eq!(read(h, 0, 1000).unwrap(), &data[..1000]);
    assert_eq!(read(h, 599_990, 100).unwrap(), &data[599_990..]);
    assert!(read(h, 600_000, 10).unwrap().is_empty());
    assert!(read(h, 700_000, 10).unwrap().is_empty());
    assert_eq!(read(h, 1, 599_999).unwrap(), &data[1..]);
    let mut len = 5;
    res(unsafe { (t().read)(h, 3, ptr::null_mut(), 0, &raw mut len) }).unwrap();
    assert_eq!(len, 0);
    assert_eq!(name(res(unsafe { (t().read)(h, 3, ptr::null_mut(), 4, &raw mut len) })), "ProtocolError");
    assert_eq!(name(read(h, -1, 4)), "ProtocolError");
    let mut buf = [0u8; 4];
    assert_eq!(name(res(unsafe { (t().read)(h, 0, buf.as_mut_ptr(), 4, ptr::null_mut()) })), "ProtocolError");
    unsafe { (t().read_ahead)(h, 100, 1000) };
    res(unsafe { (t().read_close)(h) }).unwrap();
    assert_eq!(live_objects(), 1);
    let mut h = ptr::dangling_mut();
    assert_eq!(
        name(res(unsafe { (t().open_read)(c.0, b(b"missing"), &raw mut h, ptr::null_mut()) })),
        "NotFound"
    );
    assert!(h.is_null());
    c.mkdir(b"dir", true).unwrap();
    assert_eq!(name(c.open_read(b"dir")), "IsADirectory");
    // The size pointer may be NULL.
    res(unsafe { (t().open_read)(c.0, b(b"data"), &raw mut h, ptr::null_mut()) }).unwrap();
    res(unsafe { (t().read_close)(h) }).unwrap();
    drop(c);
    assert_no_leaks();
}

#[test]
fn write_handles() {
    let c = Conn::open("write", &[]);
    let mut o = write_opts(NVB_DISPOSITION_CREATE_NEW);
    o.create_mode = 0o600;
    o.has_mtime = 1;
    o.mtime_ms = 981_173_106_000;
    let h = c.open_write(b"w", &o).unwrap();
    assert_eq!(unsafe { (t().position)(h) }, 0);
    write(h, b"hello ").unwrap();
    write(h, b"world").unwrap();
    res(unsafe { (t().write)(h, ptr::null(), 0) }).unwrap();
    assert_eq!(name(res(unsafe { (t().write)(h, ptr::null(), 3) })), "ProtocolError");
    assert_eq!(unsafe { (t().position)(h) }, 11);
    res(unsafe { (t().commit)(h) }).unwrap();
    let e = c.stat(b"w", true).unwrap();
    assert_eq!((e.size, e.mode, e.mtime), (11, 0o600, 981_173_106_000));
    assert_eq!(c.get(b"w").unwrap(), b"hello world");
    assert_eq!(name(c.open_write(b"w", &o)), "AlreadyExists");
    let mut resume = write_opts(NVB_DISPOSITION_RESUME);
    for wrong in [0, 10, 12] {
        resume.resume_offset = wrong;
        assert_eq!(name(c.open_write(b"w", &resume)), "ProtocolError");
    }
    resume.resume_offset = 11;
    let h = c.open_write(b"w", &resume).unwrap();
    assert_eq!(unsafe { (t().position)(h) }, 11);
    write(h, b"!").unwrap();
    unsafe { (t().abort)(h) };
    assert_eq!(c.get(b"w").unwrap(), b"hello world!");
    assert_eq!(live_objects(), 1);
    for bad in [
        NvrWriteOpts { disposition: 9, ..write_opts(0) },
        NvrWriteOpts { create_mode: -2, ..write_opts(0) },
        NvrWriteOpts { resume_offset: -1, ..write_opts(0) },
        NvrWriteOpts { expected_size: -3, ..write_opts(0) },
    ] {
        assert_eq!(name(c.open_write(b"other", &bad)), "ProtocolError");
    }
    let mut out = ptr::null_mut();
    assert_eq!(
        name(res(unsafe { (t().open_write)(c.0, b(b"x"), ptr::null(), &raw mut out) })),
        "ProtocolError"
    );
    let h = c.open_write(b"t", &write_opts(NVB_DISPOSITION_TRUNCATE)).unwrap();
    res(unsafe { (t().commit)(h) }).unwrap();
    assert_eq!(c.stat(b"t", true).unwrap().size, 0);
    assert!(!c.names(b"").contains(&b"other".to_vec()));
    drop(c);
    assert_no_leaks();
}

#[test]
fn handles_after_disconnect_and_conn_free() {
    let c = Conn::open("lost", &[]);
    c.put(b"f", b"data").unwrap();
    let (r, _) = c.open_read(b"f").unwrap();
    let w = c.open_write(b"g", &write_opts(NVB_DISPOSITION_CREATE_NEW)).unwrap();
    c.disconnect();
    assert_eq!(name(read(r, 0, 4)), "ConnectionLost");
    assert_eq!(name(write(w, b"x")), "ConnectionLost");
    assert_eq!(name(c.keep_alive()), "ConnectionLost");
    assert_eq!(name(c.stat(b"f", true)), "ConnectionLost");
    assert_eq!(unsafe { (t().position)(w) }, 0);
    assert_eq!(name(res(unsafe { (t().commit)(w) })), "ConnectionLost");
    assert_eq!(live_objects(), 2);
    // conn_free frees the handles still open (R4).
    drop(c);
    assert_no_leaks();
    let c = Conn::open("lost", &[]);
    let _r = c.open_read(b"f").unwrap();
    let _w = c.open_write(b"h", &write_opts(NVB_DISPOSITION_CREATE_NEW)).unwrap();
    assert_eq!(live_objects(), 3);
    drop(c);
    assert_no_leaks();
}

#[test]
fn uploads_and_downloads() {
    let c = Conn::open("transfer", &[]);
    let data = pattern(700_000, 2);
    let mut l = Local { data: data.clone(), ..Local::default() };
    let io_up = io(&mut l);
    let mut p = Prog::default();
    let pr = progress(&mut p);
    res(unsafe { (t().upload)(c.0, b(b"big"), &truncate(), &raw const io_up, &raw const pr) }).unwrap();
    assert_eq!(p.updates, [(262_144, 700_000), (524_288, 700_000), (700_000, 700_000)]);
    assert_eq!(l.positions, [0, 262_144, 524_288, 700_000]);
    assert_eq!(p.thread, Some(thread::current().id()));
    let mut p = Prog::default();
    let (r, got) = c.download(b"big", 0, -1, Some(&mut p));
    r.unwrap();
    assert_eq!(got, data);
    assert_eq!(p.updates, [(262_144, 700_000), (524_288, 700_000), (700_000, 700_000)]);
    let (r, got) = c.download(b"big", 5, 10, None);
    r.unwrap();
    assert_eq!(got, &data[5..15]);
    let (r, got) = c.download(b"big", 699_990, 100, None);
    r.unwrap();
    assert_eq!(got, &data[699_990..]);
    for (offset, length) in [(700_000, -1), (800_000, 10), (7, 0)] {
        let (r, got) = c.download(b"big", offset, length, None);
        r.unwrap();
        assert!(got.is_empty());
    }
    assert_eq!(name(c.download(b"big", -1, 1, None).0), "ProtocolError");
    assert_eq!(name(c.download(b"big", 0, -2, None).0), "ProtocolError");
    assert_eq!(name(c.download(b"missing", 0, -1, None).0), "NotFound");

    // A FIFO source: no size; expected_size gives the total. Options apply.
    let mut l = Local { data: b"options".to_vec(), sequential: true, ..Local::default() };
    let io_seq = io(&mut l);
    let mut p = Prog::default();
    let pr = progress(&mut p);
    let o = NvbUploadOpts {
        disposition: NVB_DISPOSITION_CREATE_NEW,
        create_mode: 0o600,
        expected_size: 7,
        has_mtime: 1,
        mtime_ms: 981_173_106_000,
        ..truncate()
    };
    res(unsafe { (t().upload)(c.0, b(b"opts"), &raw const o, &raw const io_seq, &raw const pr) }).unwrap();
    assert_eq!(p.updates, [(7, 7)]);
    let e = c.stat(b"opts", true).unwrap();
    assert_eq!((e.size, e.mode, e.mtime), (7, 0o600, 981_173_106_000));
    let mut l = Local { data: b"x".to_vec(), sequential: true, ..Local::default() };
    let io_seq = io(&mut l);
    let mut p = Prog::default();
    let pr = progress(&mut p);
    res(unsafe { (t().upload)(c.0, b(b"seq"), &truncate(), &raw const io_seq, &raw const pr) }).unwrap();
    assert_eq!(p.updates, [(1, -1)]);
    // CreateNew on an existing file; Resume appends.
    assert_eq!(
        name(res(unsafe { (t().upload)(c.0, b(b"opts"), &raw const o, &raw const io_seq, ptr::null()) })),
        "AlreadyExists"
    );
    let mut l = Local { data: b"+more".to_vec(), ..Local::default() };
    let io_more = io(&mut l);
    let resume = NvbUploadOpts { disposition: NVB_DISPOSITION_RESUME, resume_offset: 7, ..truncate() };
    res(unsafe { (t().upload)(c.0, b(b"opts"), &raw const resume, &raw const io_more, ptr::null()) })
        .unwrap();
    assert_eq!(c.get(b"opts").unwrap(), b"options+more");

    // The local side fails.
    let mut l = Local { data: b"abc".to_vec(), fail: true, ..Local::default() };
    let failing = io(&mut l);
    let e =
        res(unsafe { (t().upload)(c.0, b(b"f"), &truncate(), &raw const failing, ptr::null()) }).unwrap_err();
    assert_eq!((e.name.as_str(), e.message.as_str()), ("Internal", "Cannot read the local file"));
    let e =
        res(unsafe { (t().download)(c.0, b(b"big"), 0, -1, &raw const failing, ptr::null()) }).unwrap_err();
    assert_eq!((e.name.as_str(), e.message.as_str()), ("NoSpace", "Cannot write the local file"));
    // Missing pieces.
    let no_read = NvbIo { read: None, ..failing };
    let no_write = NvbIo { write: None, ..failing };
    let e =
        res(unsafe { (t().upload)(c.0, b(b"f"), &truncate(), &raw const no_read, ptr::null()) }).unwrap_err();
    assert_eq!(e.message, "Missing read function from the plugin");
    let e =
        res(unsafe { (t().download)(c.0, b(b"big"), 0, -1, &raw const no_write, ptr::null()) }).unwrap_err();
    assert_eq!(e.message, "Missing write function from the plugin");
    assert_eq!(
        name(res(unsafe { (t().upload)(c.0, b(b"f"), ptr::null(), &raw const failing, ptr::null()) })),
        "ProtocolError"
    );
    assert_eq!(
        name(res(unsafe { (t().upload)(c.0, b(b"f"), &truncate(), ptr::null(), ptr::null()) })),
        "ProtocolError"
    );
    assert_eq!(
        name(res(unsafe { (t().download)(c.0, b(b"big"), 0, -1, ptr::null(), ptr::null()) })),
        "ProtocolError"
    );
    let bad = NvbUploadOpts { disposition: 7, ..truncate() };
    assert_eq!(
        name(res(unsafe { (t().upload)(c.0, b(b"f"), &raw const bad, &raw const io_more, ptr::null()) })),
        "ProtocolError"
    );

    // Progress::canceled stops a transfer.
    let mut p = Prog { stop_after: Some(1), ..Prog::default() };
    let (r, got) = c.download(b"big", 0, -1, Some(&mut p));
    assert_eq!(name(r), "Canceled");
    assert_eq!(got.len(), 262_144);
    let mut l = Local { data, ..Local::default() };
    let io_up = io(&mut l);
    let mut p = Prog { stop_after: Some(1), ..Prog::default() };
    let pr = progress(&mut p);
    assert_eq!(
        name(res(unsafe { (t().upload)(c.0, b(b"up"), &truncate(), &raw const io_up, &raw const pr) })),
        "Canceled"
    );
    assert_eq!(p.updates.len(), 1);
    drop(c);
    assert_no_leaks();
}

#[test]
fn cancel_stays_until_reset() {
    let c = Conn::open("cancel", &[]);
    c.put(b"f", b"data").unwrap();
    let (r, _) = c.open_read(b"f").unwrap();
    let w = c.open_write(b"g", &write_opts(NVB_DISPOSITION_CREATE_NEW)).unwrap();
    write(w, b"partial").unwrap();
    c.cancel();
    c.cancel();
    assert_eq!(name(c.stat(b"f", true)), "Canceled");
    assert_eq!(name(c.keep_alive()), "Canceled");
    assert_eq!(name(read(r, 0, 4)), "Canceled");
    assert_eq!(name(write(w, b"x")), "Canceled");
    // A canceled commit aborts and frees the handle.
    assert_eq!(name(res(unsafe { (t().commit)(w) })), "Canceled");
    assert_eq!(live_objects(), 2);
    // A canceled close still frees the handle.
    assert_eq!(name(res(unsafe { (t().read_close)(r) })), "Canceled");
    assert_eq!(live_objects(), 1);
    c.reset();
    c.stat(b"f", true).unwrap();
    assert_eq!(c.get(b"g").unwrap(), b"partial");
    // cancel() from inside a transfer (C-9), then reset.
    c.put(b"big", &pattern(600_000, 3)).unwrap();
    let mut p = Prog { cancel: c.0, ..Prog::default() };
    let (r, got) = c.download(b"big", 0, -1, Some(&mut p));
    assert_eq!(name(r), "Canceled");
    assert_eq!(got.len(), 262_144);
    c.reset();
    c.keep_alive().unwrap();
    drop(c);
    assert_no_leaks();
}

#[test]
fn cancel_ends_a_stalled_call() {
    let quiet = Conn::open("stall", &[]);
    quiet.put(b"f", b"data").unwrap();
    let c = Conn::open("stall", &[("stall", "true")]);
    let (r, after) = canceled_after(&c, Duration::from_millis(200), || c.stat(b"f", true));
    assert_eq!(name(r), "Canceled");
    assert!(after < Duration::from_millis(500), "{after:?}");
    c.reset();
    let (r, after) = canceled_after(&c, Duration::from_millis(200), || c.get(b"f"));
    assert_eq!(name(r), "Canceled");
    assert!(after < Duration::from_millis(500), "{after:?}");
    drop(c);
    drop(quiet);
    assert_no_leaks();
}

#[test]
fn a_call_that_ignores_cancel_is_cut() {
    let c = Conn::open("ignore", &[("stall", "ignore")]);
    let (r, after) = canceled_after(&c, Duration::from_millis(200), || c.keep_alive());
    assert_eq!(name(r), "Canceled");
    assert!(after >= GRACE.checked_sub(Duration::from_millis(50)).unwrap(), "{after:?}");
    assert!(after < CANCEL_LIMIT, "{after:?}");
    // The connection takes calls again after reset_cancel; teardown is
    // bounded as well (conn_free after a cancel).
    c.reset();
    c.cancel();
    let started = Instant::now();
    drop(c);
    assert!(started.elapsed() < CANCEL_LIMIT);
    assert_no_leaks();
}

#[test]
fn one_call_at_a_time() {
    let c = Conn::open("busy", &[]);
    let other = Conn::open("busy", &[]);
    c.put(b"f", b"data").unwrap();
    let (h, _) = c.open_read(b"f").unwrap();
    let inner: std::rc::Rc<RefCell<Vec<Result<(), Fail>>>> = std::rc::Rc::default();
    let (conn, conn_other, seen) = (SendPtr(c.0), SendPtr(other.0), std::rc::Rc::clone(&inner));
    let mut l = Lister {
        inside: Some(Box::new(move || {
            let mut out = ptr::null_mut();
            let mut r = seen.borrow_mut();
            r.push(res(unsafe { (t().stat)(conn.0, b(b"f"), 1, &raw mut out) }));
            r.push(read(h, 0, 4).map(drop));
            r.push(res(unsafe { (t().stat)(conn_other.0, b(b"f"), 1, &raw mut out) }));
        })),
        ..Lister::default()
    };
    c.list_with(b"", 10, false, &mut l).unwrap();
    let results = inner.take();
    let busy = "The connection is busy: one call at a time, none from a callback";
    assert_eq!(results[0].as_ref().unwrap_err().message, busy);
    assert_eq!(results[1].as_ref().unwrap_err().message, busy);
    // Another connection from inside a callback: tokio refuses to nest
    // block_on, which comes back as Internal instead of a crash.
    let nested = results[2].as_ref().unwrap_err();
    assert_eq!((nested.name.as_str(), nested.message.as_str()), ("Internal", "The Rust backend failed"));
    assert!(nested.detail.starts_with("panic: "), "{}", nested.detail);
    // Both connections work afterwards.
    other.stat(b"f", true).unwrap();
    assert_eq!(read(h, 0, 4).unwrap(), b"data");
    res(unsafe { (t().read_close)(h) }).unwrap();
    drop(l);
    drop((c, other));
    assert_no_leaks();
}

#[test]
fn panics_become_internal() {
    let c = Conn::open("panics", &[("panic", "stat")]);
    let mut r = Ok(E::default());
    let panics = panics_in(|| r = c.stat(b"", true));
    let e = r.unwrap_err();
    assert_eq!((e.name.as_str(), e.message.as_str()), ("Internal", "The Rust backend failed"));
    assert_eq!(e.detail, "panic: mem: stat panics on request");
    assert_eq!(panics, ["mem: stat panics on request"]);
    // The connection survives.
    c.keep_alive().unwrap();
    drop(c);

    for call in ["read_ahead", "abort", "position", "disconnect", "read_close", "capabilities"] {
        let c = Conn::open(&format!("panics-{call}"), &[("panic", call)]);
        c.put(b"f", b"data").unwrap();
        let panics = panics_in(|| match call {
            "read_ahead" => {
                let (h, _) = c.open_read(b"f").unwrap();
                unsafe { (t().read_ahead)(h, 0, 10) };
                unsafe { (t().read_ahead)(h, -1, 10) };
                unsafe { (t().read_ahead)(h, 0, -1) };
                res(unsafe { (t().read_close)(h) }).unwrap();
            }
            "abort" => {
                let h = c.open_write(b"g", &write_opts(NVB_DISPOSITION_CREATE_NEW)).unwrap();
                unsafe { (t().abort)(h) };
                assert_eq!(live_objects(), 1);
            }
            "position" => {
                let h = c.open_write(b"g", &write_opts(NVB_DISPOSITION_CREATE_NEW)).unwrap();
                assert_eq!(unsafe { (t().position)(h) }, -1);
                res(unsafe { (t().commit)(h) }).unwrap();
            }
            "disconnect" => c.disconnect(),
            "read_close" => {
                let (h, _) = c.open_read(b"f").unwrap();
                assert_eq!(name(res(unsafe { (t().read_close)(h) })), "Internal");
                assert_eq!(live_objects(), 1);
            }
            _ => assert_eq!(name(c.caps()), "Internal"),
        });
        assert_eq!(panics, [format!("mem: {call} panics on request")], "{call}");
        // conn_free disconnects (panicking again for "disconnect") and
        // frees all the same.
        let panics = panics_in(|| drop(c));
        assert_eq!(panics.len(), usize::from(call == "disconnect"), "{call}");
        assert_no_leaks();
    }

    // conn_free with handles whose teardown panics.
    for call in ["read_close", "abort"] {
        let c = Conn::open(&format!("panics-free-{call}"), &[("panic", call)]);
        c.put(b"f", b"data").unwrap();
        let _r = c.open_read(b"f").unwrap();
        let _w = c.open_write(b"g", &write_opts(NVB_DISPOSITION_TRUNCATE)).unwrap();
        let panics = panics_in(|| drop(c));
        assert_eq!(panics, [format!("mem: {call} panics on request")]);
        assert_no_leaks();
    }

    // A panic in connect.
    let c = Conn::new();
    let panics = panics_in(|| assert_eq!(name(c.connect(&[("panic", "connect")])), "Internal"));
    assert_eq!(panics.len(), 1);
    drop(c);
    assert_no_leaks();
}

fn runtime_threads() -> Vec<String> {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|task| std::fs::read_to_string(task.unwrap().path().join("comm")).ok())
        .map(|comm| comm.trim().to_owned())
        .filter(|comm| comm.starts_with(THREAD_PREFIX))
        .collect()
}

#[test]
fn two_named_workers() {
    let c = Conn::open("threads", &[]);
    c.keep_alive().unwrap();
    let mut names = runtime_threads();
    names.sort();
    assert_eq!(names.len(), WORKERS);
    assert_eq!(names, ["nvr-io-0", "nvr-io-1"]);
    drop(c);
    assert_no_leaks();
}

#[test]
fn a_connection_may_move_between_threads() {
    // Made here, used and freed on another thread (C-8: one thread at a
    // time, not always the one that made it).
    let c = Conn::new();
    let c = std::mem::ManuallyDrop::new(c);
    let moved = SendPtr(c.0);
    thread::spawn(move || {
        let moved = moved;
        let c = Conn(moved.0);
        c.connect(&[("store", "moved")]).unwrap();
        c.put(b"f", b"x").unwrap();
        assert_eq!(c.get(b"f").unwrap(), b"x");
        drop(c);
        assert_eq!(live_blocks(), 0);
    })
    .join()
    .unwrap();
}

#[test]
fn keys_are_not_supported_yet() {
    let mut key: *mut NvrKey = ptr::dangling_mut();
    let e = res(unsafe { (t().key_generate)(&raw mut key) }).unwrap_err();
    assert_eq!(
        (e.name.as_str(), e.message.as_str()),
        ("Unsupported", "SSH keys are not supported by the Rust backends")
    );
    assert!(key.is_null());
    key = ptr::dangling_mut();
    assert_eq!(name(res(unsafe { (t().key_import)(b(b"file"), b(b""), &raw mut key) })), "Unsupported");
    assert!(key.is_null());
    assert_eq!(name(res(unsafe { (t().key_describe)(b(b"key"), &raw mut key) })), "Unsupported");
    assert_eq!(name(res(unsafe { (t().key_generate)(ptr::null_mut()) })), "ProtocolError");
    assert_no_leaks();
}

#[test]
fn null_connections_and_handles() {
    let none: *mut NvrConn = ptr::null_mut();
    let missing = |e: *mut NvbError| {
        let f = res(e).unwrap_err();
        assert_eq!(f.name, "ProtocolError");
        f.message
    };
    let mut out = ptr::null_mut();
    let conn = "Missing connection from the plugin";
    unsafe {
        assert_eq!(missing((t().keep_alive)(none)), conn);
        assert_eq!(missing((t().stat)(none, b(b""), 1, &raw mut out)), conn);
        assert_eq!(missing((t().make_dir)(none, b(b"d"), 1)), conn);
        assert_eq!(missing((t().remove_file)(none, b(b"d"))), conn);
        assert_eq!(missing((t().remove_dir)(none, b(b"d"))), conn);
        assert_eq!(missing((t().rename)(none, b(b"a"), b(b"b"), 0)), conn);
        assert_eq!(missing((t().make_symlink)(none, b(b"a"), b(b"b"))), conn);
        assert_eq!(missing((t().make_hardlink)(none, b(b"a"), b(b"b"))), conn);
        assert_eq!(missing((t().copy)(none, b(b"a"), b(b"b"), 0, 0)), conn);
        let mut buf = [0u8; 2];
        let mut len = 0;
        assert_eq!(
            missing((t().read)(ptr::null_mut(), 0, buf.as_mut_ptr(), 2, &raw mut len)),
            "Missing read handle from the plugin"
        );
        assert_eq!(missing((t().read_close)(ptr::null_mut())), "Missing read handle from the plugin");
        assert_eq!(
            missing((t().write)(ptr::null_mut(), buf.as_ptr(), 2)),
            "Missing write handle from the plugin"
        );
        assert_eq!(missing((t().commit)(ptr::null_mut())), "Missing write handle from the plugin");
        assert_eq!((t().position)(ptr::null()), -1);
        (t().read_ahead)(ptr::null_mut(), 0, 0);
        (t().abort)(ptr::null_mut());
    }
    let c = Conn::open("nulls", &[]);
    unsafe {
        assert_eq!(
            missing((t().stat)(c.0, b(b""), 1, ptr::null_mut())),
            "Missing result pointer from the plugin"
        );
        assert_eq!(
            missing((t().read_link)(c.0, b(b""), ptr::null_mut())),
            "Missing result pointer from the plugin"
        );
        assert_eq!(
            missing((t().checksum)(c.0, b(b""), b(b"sha256"), ptr::null_mut())),
            "Missing result pointer from the plugin"
        );
        assert_eq!(
            missing((t().open_read)(c.0, b(b""), ptr::null_mut(), ptr::null_mut())),
            "Missing result pointer from the plugin"
        );
    }
    drop(c);
    assert_no_leaks();
}
