// SPDX-License-Identifier: LGPL-2.1-or-later
//! The callbacks C++ passes to a call, as the netvfs-vfs traits the
//! backends take. The backend's future calls them while `block_on` polls it
//! on the caller's thread (S3), so they are plain calls into C++; C++
//! catches its own exceptions (S5). What they receive is borrowed for the
//! callback only (R2).

use super::marshal::{fill_entry, items, slice};
use super::raw::{
    NvbBytes, NvbEntry, NvbIo, NvbIoReadFn, NvbIoWriteFn, NvbListSinkFn, NvbProgress, NvbPrompt, NvbReply,
    NvrPromptFn,
};
use netvfs_vfs::{
    Entry, ErrorName, ListSink, Progress, PromptRequest, Prompter, Sink, Source, Status, Zeroizing,
};
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// `nvb_list_sink_fn` as a [`ListSink`].
#[derive(Debug)]
pub struct ListAdapter {
    sink: NvbListSinkFn,
    ctx: *mut c_void,
}

impl ListAdapter {
    /// The sink of a `list` call.
    pub const fn new(sink: NvbListSinkFn, ctx: *mut c_void) -> Self {
        Self { sink, ctx }
    }
}

impl ListSink for ListAdapter {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        // Views into `batch`, which outlives the callback (R2).
        let views: Vec<NvbEntry> = batch.iter().map(|e| fill_entry(e, NvbBytes::of)).collect();
        // SAFETY: `sink` and `ctx` are the caller's for this call; the views
        // and the bytes they point to live until the call returns.
        unsafe { (self.sink)(self.ctx, views.as_ptr(), views.len()) != 0 }
    }
}

/// What `nvb_reply *` points to during a prompt: the answers `reply_set`
/// gives.
#[derive(Debug, Default)]
pub struct Reply {
    answers: Option<Vec<Zeroizing<Vec<u8>>>>,
}

/// The table's `reply_set`: copies the answers into wiped-on-drop buffers
/// (R5); a later call replaces earlier answers. NULL `r` is a no-op.
///
/// # Safety
/// `r` is NULL or the reply of a prompt that is running; `answers` points
/// to `n` items whose bytes are readable.
pub unsafe extern "C" fn reply_set(r: *mut NvbReply, answers: *const NvbBytes, n: usize) {
    let set = || {
        // SAFETY: `r` is NULL or a live `Reply` (the prompt adapter made it
        // and waits for the callback); the answers are readable (the
        // caller's contract).
        unsafe {
            if let Some(reply) = r.cast::<Reply>().as_mut() {
                let copied = items(answers, n).iter().map(|a| Zeroizing::new(slice(*a).to_vec())).collect();
                reply.answers = Some(copied);
            }
        }
    };
    catch_unwind(AssertUnwindSafe(set)).unwrap_or_default();
}

/// `nvr_prompter` as a [`Prompter`].
#[derive(Debug)]
pub struct PromptAdapter {
    prompt: NvrPromptFn,
    ctx: *mut c_void,
}

impl PromptAdapter {
    /// The prompter of an `authenticate` call.
    pub const fn new(prompt: NvrPromptFn, ctx: *mut c_void) -> Self {
        Self { prompt, ctx }
    }
}

impl Prompter for PromptAdapter {
    fn answer(&mut self, request: &PromptRequest) -> Option<Vec<Zeroizing<Vec<u8>>>> {
        let prompts: Vec<NvbPrompt> = request
            .prompts
            .iter()
            .map(|p| NvbPrompt { text: NvbBytes::of(p.text.as_bytes()), echo: u8::from(p.echo) })
            .collect();
        let mut reply = Reply::default();
        // SAFETY: `prompt` and `ctx` are the caller's for this call; the
        // texts, the prompts and `reply` live until it returns, and
        // `reply_set` is the only way the caller writes `reply`.
        let given = unsafe {
            (self.prompt)(
                self.ctx,
                NvbBytes::of(request.name.as_bytes()),
                NvbBytes::of(request.instruction.as_bytes()),
                prompts.as_ptr(),
                prompts.len(),
                (&raw mut reply).cast::<NvbReply>(),
            )
        };
        // One answer per prompt, or the user declined.
        reply.answers.filter(|a| given != 0 && a.len() == prompts.len())
    }
}

/// The bytes moved so far as `nvb_io`'s `pos`.
fn position(done: u64) -> i64 {
    i64::try_from(done).unwrap_or(i64::MAX)
}

/// The local side of an upload: `nvb_io.read`, in order.
#[derive(Debug)]
pub struct IoSource {
    read: NvbIoReadFn,
    io: NvbIo,
    done: u64,
}

impl IoSource {
    /// `None` without a `read` function.
    pub fn new(io: NvbIo) -> Option<Self> {
        io.read.map(|read| Self { read, io, done: 0 })
    }
}

impl Source for IoSource {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        // SAFETY: `read` and `ctx` are the caller's for this call; `buf` is
        // writable for `buf.len()` bytes.
        let n = unsafe { (self.read)(self.io.ctx, position(self.done), buf.as_mut_ptr(), buf.len()) };
        let n = usize::try_from(n)
            .ok()
            .filter(|n| *n <= buf.len())
            .ok_or_else(|| Status::internal("Cannot read the local file"))?;
        self.done = self.done.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }

    fn size(&self) -> Option<u64> {
        if self.io.sequential != 0 { None } else { u64::try_from(self.io.size).ok() }
    }
}

/// The local side of a download: `nvb_io.write`, in order, until each
/// chunk is written.
#[derive(Debug)]
pub struct IoSink {
    write: NvbIoWriteFn,
    io: NvbIo,
    done: u64,
}

impl IoSink {
    /// `None` without a `write` function.
    pub fn new(io: NvbIo) -> Option<Self> {
        io.write.map(|write| Self { write, io, done: 0 })
    }
}

impl Sink for IoSink {
    fn write(&mut self, data: &[u8]) -> Result<(), Status> {
        let mut rest = data;
        while !rest.is_empty() {
            // SAFETY: `write` and `ctx` are the caller's for this call; `rest`
            // is readable for `rest.len()` bytes.
            let n = unsafe { (self.write)(self.io.ctx, position(self.done), rest.as_ptr(), rest.len()) };
            rest = usize::try_from(n)
                .ok()
                .filter(|n| *n > 0)
                .and_then(|n| rest.get(n..))
                .ok_or_else(|| Status::new(ErrorName::NoSpace, "Cannot write the local file"))?;
            self.done = self.done.saturating_add(n.unsigned_abs());
        }
        Ok(())
    }
}

/// `nvb_progress` (may be absent) as [`Progress`].
#[derive(Debug)]
pub struct ProgressAdapter {
    progress: Option<NvbProgress>,
}

impl ProgressAdapter {
    /// The progress of a transfer; `None`: no progress.
    pub const fn new(progress: Option<NvbProgress>) -> Self {
        Self { progress }
    }
}

impl Progress for ProgressAdapter {
    fn update(&mut self, done: u64, total: Option<u64>) {
        if let Some(p) = self.progress
            && let Some(update) = p.update
        {
            let total = total.map_or(-1, position);
            // SAFETY: `update` and `ctx` are the caller's for this call.
            unsafe { update(p.ctx, position(done), total) };
        }
    }

    fn canceled(&mut self) -> bool {
        match self.progress {
            // SAFETY: `canceled` and `ctx` are the caller's for this call.
            Some(NvbProgress { ctx, canceled: Some(canceled), .. }) => unsafe { canceled(ctx) != 0 },
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netvfs_vfs::{EntryType, Prompt};
    use std::ffi::c_int;

    // ---- list

    unsafe extern "C" fn record(ctx: *mut c_void, entries: *const NvbEntry, n: usize) -> c_int {
        // SAFETY: test: ctx is a Vec<(Vec<u8>, u8)>, entries valid for the call.
        unsafe {
            let seen = &mut *ctx.cast::<Vec<(Vec<u8>, u8)>>();
            for e in items(entries, n) {
                seen.push((slice(e.name).to_vec(), e.kind));
            }
            c_int::from(seen.len() < 3)
        }
    }

    #[test]
    fn list_adapter_passes_batches_and_stops() {
        let mut seen: Vec<(Vec<u8>, u8)> = Vec::new();
        let mut sink = ListAdapter::new(record, (&raw mut seen).cast());
        let batch = [
            Entry { name: b"a".to_vec(), kind: EntryType::File, ..Entry::default() },
            Entry { name: b"b".to_vec(), kind: EntryType::Directory, ..Entry::default() },
        ];
        assert!(sink.entries(&batch));
        assert!(!sink.entries(&batch[..1]));
        assert_eq!(seen, [(b"a".to_vec(), 1), (b"b".to_vec(), 2), (b"a".to_vec(), 1)]);
    }

    // ---- prompts

    struct Asked {
        name: Vec<u8>,
        instruction: Vec<u8>,
        prompts: Vec<(Vec<u8>, u8)>,
        answers: Vec<&'static [u8]>,
        result: c_int,
    }

    unsafe extern "C" fn answer(
        ctx: *mut c_void,
        name: NvbBytes,
        instruction: NvbBytes,
        prompts: *const NvbPrompt,
        n: usize,
        reply: *mut NvbReply,
    ) -> c_int {
        // SAFETY: test: ctx is an Asked; the arguments are valid for the call.
        unsafe {
            let asked = &mut *ctx.cast::<Asked>();
            asked.name = slice(name).to_vec();
            asked.instruction = slice(instruction).to_vec();
            asked.prompts = items(prompts, n).iter().map(|p| (slice(p.text).to_vec(), p.echo)).collect();
            let answers: Vec<NvbBytes> = asked.answers.iter().map(|a| NvbBytes::of(a)).collect();
            reply_set(reply, [NvbBytes::of(b"replaced")].as_ptr(), 1);
            reply_set(reply, answers.as_ptr(), answers.len());
            asked.result
        }
    }

    fn request() -> PromptRequest {
        PromptRequest {
            name: "mem".to_owned(),
            instruction: "say".to_owned(),
            prompts: vec![
                Prompt { text: "Code:".to_owned(), echo: true },
                Prompt { text: "PIN:".to_owned(), echo: false },
            ],
        }
    }

    #[test]
    fn prompt_adapter_answers_and_declines() {
        let mut asked = Asked {
            name: vec![],
            instruction: vec![],
            prompts: vec![],
            answers: vec![b"123", b"9"],
            result: 1,
        };
        let mut prompter = PromptAdapter::new(answer, (&raw mut asked).cast());
        let got = prompter.answer(&request()).unwrap();
        assert_eq!(got.iter().map(|a| a.as_slice()).collect::<Vec<_>>(), [&b"123"[..], b"9"]);
        assert_eq!((asked.name.as_slice(), asked.instruction.as_slice()), (&b"mem"[..], &b"say"[..]));
        assert_eq!(asked.prompts, [(b"Code:".to_vec(), 1), (b"PIN:".to_vec(), 0)]);
        // Declined: 0 even with answers set.
        asked.result = 0;
        let mut prompter = PromptAdapter::new(answer, (&raw mut asked).cast());
        assert!(prompter.answer(&request()).is_none());
        // One answer for two prompts: declined.
        asked.result = 1;
        asked.answers = vec![b"123"];
        let mut prompter = PromptAdapter::new(answer, (&raw mut asked).cast());
        assert!(prompter.answer(&request()).is_none());
    }

    unsafe extern "C" fn says_yes_without_answers(
        _: *mut c_void,
        _: NvbBytes,
        _: NvbBytes,
        _: *const NvbPrompt,
        _: usize,
        _: *mut NvbReply,
    ) -> c_int {
        1
    }

    #[test]
    fn prompt_without_reply_is_declined_and_null_reply_is_ignored() {
        let mut prompter = PromptAdapter::new(says_yes_without_answers, std::ptr::null_mut());
        assert!(prompter.answer(&request()).is_none());
        // SAFETY: NULL is allowed.
        unsafe { reply_set(std::ptr::null_mut(), std::ptr::null(), 0) };
    }

    // ---- io

    struct Local {
        data: Vec<u8>,
        positions: Vec<i64>,
        step: usize,
        fail_at: Option<usize>,
        overrun: bool,
    }

    unsafe extern "C" fn local_read(ctx: *mut c_void, pos: i64, buf: *mut u8, cap: usize) -> i64 {
        // SAFETY: test: ctx is a Local, buf writable for cap.
        unsafe {
            let local = &mut *ctx.cast::<Local>();
            local.positions.push(pos);
            if local.fail_at == Some(local.positions.len()) {
                return -1;
            }
            if local.overrun {
                return i64::try_from(cap).unwrap().checked_add(1).unwrap();
            }
            let at = usize::try_from(pos).unwrap();
            let n = local.step.min(cap).min(local.data.len().checked_sub(at).unwrap());
            std::ptr::copy_nonoverlapping(local.data.as_ptr().add(at), buf, n);
            i64::try_from(n).unwrap()
        }
    }

    unsafe extern "C" fn local_write(ctx: *mut c_void, pos: i64, data: *const u8, len: usize) -> i64 {
        // SAFETY: test: ctx is a Local, data readable for len.
        unsafe {
            let local = &mut *ctx.cast::<Local>();
            local.positions.push(pos);
            if local.fail_at == Some(local.positions.len()) {
                return -1;
            }
            if local.overrun {
                return i64::try_from(len).unwrap().checked_add(1).unwrap();
            }
            let n = local.step.min(len);
            local.data.extend_from_slice(items(data, n));
            i64::try_from(n).unwrap()
        }
    }

    fn local(data: &[u8], step: usize) -> Local {
        Local { data: data.to_vec(), positions: vec![], step, fail_at: None, overrun: false }
    }

    fn io(local: &mut Local, sequential: u8, size: i64) -> NvbIo {
        NvbIo {
            ctx: (&raw mut *local).cast(),
            sequential,
            size,
            read: Some(local_read),
            write: Some(local_write),
        }
    }

    #[test]
    fn source_reads_in_order() {
        let mut l = local(b"0123456789", 4);
        let mut source = IoSource::new(io(&mut l, 0, 10)).unwrap();
        assert_eq!(source.size(), Some(10));
        let mut buf = [0u8; 8];
        let mut got = Vec::new();
        loop {
            let n = source.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"0123456789");
        assert_eq!(l.positions, [0, 4, 8, 10]);
        let mut l = local(b"", 4);
        assert_eq!(IoSource::new(io(&mut l, 1, 99)).unwrap().size(), None);
        assert_eq!(IoSource::new(io(&mut l, 0, -1)).unwrap().size(), None);
        assert!(IoSource::new(NvbIo { read: None, ..io(&mut l, 0, 0) }).is_none());
    }

    #[test]
    fn source_failures() {
        let mut l = local(b"0123", 4);
        l.fail_at = Some(1);
        let e = IoSource::new(io(&mut l, 0, 4)).unwrap().read(&mut [0u8; 4]).unwrap_err();
        assert_eq!((e.name, e.message.as_str()), (ErrorName::Internal, "Cannot read the local file"));
        let mut l = local(b"0123", 4);
        l.overrun = true;
        let e = IoSource::new(io(&mut l, 0, 4)).unwrap().read(&mut [0u8; 4]).unwrap_err();
        assert_eq!(e.name, ErrorName::Internal);
    }

    #[test]
    fn sink_writes_everything_in_order() {
        let mut l = local(b"", 3);
        let mut sink = IoSink::new(io(&mut l, 0, 0)).unwrap();
        sink.write(b"abcdefgh").unwrap();
        sink.write(b"").unwrap();
        sink.write(b"ij").unwrap();
        assert_eq!(l.data, b"abcdefghij");
        assert_eq!(l.positions, [0, 3, 6, 8]);
        assert!(IoSink::new(NvbIo { write: None, ..io(&mut l, 0, 0) }).is_none());
    }

    #[test]
    fn sink_failures() {
        for (fail, overrun, step) in [(Some(2), false, 1), (None, true, 1), (None, false, 0)] {
            let mut l = local(b"", step);
            l.fail_at = fail;
            l.overrun = overrun;
            let e = IoSink::new(io(&mut l, 0, 0)).unwrap().write(b"abc").unwrap_err();
            assert_eq!((e.name, e.message.as_str()), (ErrorName::NoSpace, "Cannot write the local file"));
        }
    }

    // ---- progress

    #[derive(Default)]
    struct Seen {
        updates: Vec<(i64, i64)>,
        stop: c_int,
    }

    unsafe extern "C" fn update(ctx: *mut c_void, done: i64, total: i64) {
        // SAFETY: test: ctx is a Seen.
        unsafe { (*ctx.cast::<Seen>()).updates.push((done, total)) };
    }

    unsafe extern "C" fn stop(ctx: *mut c_void) -> c_int {
        // SAFETY: test: ctx is a Seen.
        unsafe { (*ctx.cast::<Seen>()).stop }
    }

    #[test]
    fn progress_adapter() {
        let mut seen = Seen::default();
        let raw = NvbProgress { ctx: (&raw mut seen).cast(), update: Some(update), canceled: Some(stop) };
        let mut p = ProgressAdapter::new(Some(raw));
        p.update(5, Some(10));
        p.update(7, None);
        p.update(u64::MAX, Some(u64::MAX));
        assert!(!p.canceled());
        seen.stop = 1;
        let mut p = ProgressAdapter::new(Some(raw));
        assert!(p.canceled());
        assert_eq!(seen.updates, [(5, 10), (7, -1), (i64::MAX, i64::MAX)]);
        let mut none = ProgressAdapter::new(None);
        none.update(1, None);
        assert!(!none.canceled());
        let mut empty = ProgressAdapter::new(Some(NvbProgress {
            ctx: std::ptr::null_mut(),
            update: None,
            canceled: None,
        }));
        empty.update(1, None);
        assert!(!empty.canceled());
    }
}
