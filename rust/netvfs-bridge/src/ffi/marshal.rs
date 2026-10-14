// SPDX-License-Identifier: LGPL-2.1-or-later
//! Plain Rust values on both sides of the C ABI: what Rust hands to C
//! ([`Params`] through [`ParamsBuf`]) and what it reads out of C++'s blocks
//! and callback arguments (entries, identities, URLs, capabilities,
//! errors). Readers copy: nothing returned borrows C memory (O2, O3).

use super::raw::{
    NVB_IDENTITY_NONE, NVB_IDENTITY_SSH, NVB_VALUE_BOOL, NVB_VALUE_BYTES, NVB_VALUE_INT, NVB_VALUE_STRING,
    NVB_VALUE_STRING_LIST, NvbBytes, NvbCapabilities, NvbEntry, NvbError, NvbIdentity, NvbKv, NvbNearby,
    NvbParams, NvbPrompt, NvbValue,
};
use crate::Status;
use netvfs_bridge_proto::{ErrorName, WireCapabilities, WireEntry, WireNearby};
pub use netvfs_vfs::{Params, Prompt, PromptRequest, Value, ValueMap};

/// What `Url::parse` gives: parameters and the location's path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedUrl {
    /// The connection parameters.
    pub params: Params,
    /// The normalised path, protocol bytes (XC-4).
    pub path: Vec<u8>,
}

/// Kind of a server identity (`NVB_IDENTITY_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdentityKind {
    /// No identity (or one this build does not know).
    #[default]
    None,
    /// An SSH host key.
    Ssh,
}

impl IdentityKind {
    /// The kind for `NVB_IDENTITY_*`; an unknown value is `None`.
    #[must_use]
    pub const fn from_raw(kind: u32) -> Self {
        match kind {
            NVB_IDENTITY_SSH => Self::Ssh,
            _ => Self::None,
        }
    }

    /// `NVB_IDENTITY_*`.
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::None => NVB_IDENTITY_NONE,
            Self::Ssh => NVB_IDENTITY_SSH,
        }
    }
}

/// The `ServerIdentity` seen during connect (XC-16).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Identity {
    /// Its kind.
    pub kind: IdentityKind,
    /// Key algorithm.
    pub algorithm: String,
    /// The key blob.
    pub public_key: Vec<u8>,
    /// OpenSSH form (`SHA256:…`).
    pub fingerprint: String,
    /// `ServerIdentity::toPin()`; empty without identity.
    pub pin: String,
}

// ----------------------------------------------------------- C -> Rust

/// The bytes of `b`.
///
/// # Safety
/// `b.ptr` is NULL or points to `b.len` readable bytes that stay valid and
/// unchanged for `'a` (O2: the callback, O3: until the block is freed).
#[must_use]
pub unsafe fn slice<'a>(b: NvbBytes) -> &'a [u8] {
    if b.ptr.is_null() || b.len == 0 {
        return &[];
    }
    // SAFETY: non-NULL, `len` bytes readable for 'a (this function's contract).
    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }
}

/// The `n` items at `ptr`.
///
/// # Safety
/// `ptr` is NULL or points to `n` initialised `T` valid for `'a`.
#[must_use]
pub unsafe fn items<'a, T>(ptr: *const T, n: usize) -> &'a [T] {
    if ptr.is_null() || n == 0 {
        return &[];
    }
    // SAFETY: non-NULL, `n` valid items for 'a (this function's contract).
    unsafe { std::slice::from_raw_parts(ptr, n) }
}

/// UTF-8 text from C++ (`QString::toUtf8`); never fails.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// UTF-8 text for a D-Bus string (`owner`, `group`, `contentType`): lossy
/// and without NUL, which a D-Bus string cannot hold.
#[must_use]
pub fn wire_text(bytes: &[u8]) -> String {
    let mut s = text(bytes);
    s.retain(|c| c != '\0');
    s
}

/// # Safety
/// `b` as for [`slice`].
unsafe fn text_of(b: NvbBytes) -> String {
    // SAFETY: forwarded contract.
    text(unsafe { slice(b) })
}

/// # Safety
/// `b` as for [`slice`].
unsafe fn bytes_of(b: NvbBytes) -> Vec<u8> {
    // SAFETY: forwarded contract.
    unsafe { slice(b) }.to_vec()
}

/// # Safety
/// `ptr`/`n` as for [`items`], each item as for [`slice`].
unsafe fn texts(ptr: *const NvbBytes, n: usize) -> Vec<String> {
    // SAFETY: forwarded contract.
    unsafe { items(ptr, n) }
        .iter()
        .map(|b| {
            // SAFETY: each item as for `slice` (this function's contract).
            unsafe { text_of(*b) }
        })
        .collect()
}

/// A value; `None` for a kind this build does not know.
///
/// # Safety
/// The bytes and items `v` points to are valid (as for [`slice`]).
#[must_use]
pub unsafe fn value(v: &NvbValue) -> Option<Value> {
    // SAFETY: forwarded contract, for each arm.
    unsafe {
        match v.kind {
            NVB_VALUE_STRING => Some(Value::Str(text_of(v.bytes))),
            NVB_VALUE_BOOL => Some(Value::Bool(v.number != 0)),
            NVB_VALUE_INT => Some(Value::Int(v.number)),
            NVB_VALUE_BYTES => Some(Value::Bytes(bytes_of(v.bytes))),
            NVB_VALUE_STRING_LIST => Some(Value::StrList(texts(v.items, v.n_items))),
            _ => None,
        }
    }
}

/// A map; values of unknown kinds are left out.
///
/// # Safety
/// `ptr`/`n` as for [`items`], each key and value as for [`slice`].
#[must_use]
pub unsafe fn value_map(ptr: *const NvbKv, n: usize) -> ValueMap {
    // SAFETY: forwarded contract.
    let kvs = unsafe { items(ptr, n) };
    kvs.iter()
        .filter_map(|kv| {
            // SAFETY: each key and value as for `slice` (this function's contract).
            unsafe { value(&kv.value).map(|v| (text_of(kv.key), v)) }
        })
        .collect()
}

/// Connection parameters.
///
/// # Safety
/// Everything `p` points to is valid (as for [`slice`] and [`items`]).
#[must_use]
pub unsafe fn params(p: &NvbParams) -> Params {
    // SAFETY: forwarded contract.
    unsafe {
        Params {
            provider: text_of(p.provider),
            host: text_of(p.host),
            port: p.port,
            username: text_of(p.username),
            options: value_map(p.options, p.n_options),
            connect_timeout_ms: p.connect_timeout_ms,
            request_timeout_ms: p.request_timeout_ms,
        }
    }
}

/// An entry in wire form (XB-9): `owner`, `group` and `contentType` lossy
/// UTF-8 without NUL.
///
/// # Safety
/// Everything `e` points to is valid (as for [`slice`]).
#[must_use]
pub unsafe fn entry(e: &NvbEntry) -> WireEntry {
    // SAFETY: forwarded contract.
    unsafe {
        WireEntry {
            name: bytes_of(e.name),
            kind: e.kind,
            target_kind: e.target_kind,
            size: e.size,
            mtime_ms: e.mtime_ms,
            ctime_ms: e.ctime_ms,
            atime_ms: e.atime_ms,
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            owner: wire_text(slice(e.owner)),
            group: wire_text(slice(e.group)),
            flags: e.flags,
            etag: bytes_of(e.etag),
            content_type: wire_text(slice(e.content_type)),
        }
    }
}

/// A server identity.
///
/// # Safety
/// Everything `i` points to is valid (as for [`slice`] and [`items`]).
#[must_use]
pub unsafe fn identity(i: &NvbIdentity) -> Identity {
    // SAFETY: forwarded contract.
    unsafe {
        Identity {
            kind: IdentityKind::from_raw(i.kind),
            algorithm: text_of(i.algorithm),
            public_key: bytes_of(i.public_key),
            fingerprint: text_of(i.fingerprint),
            pin: text_of(i.pin),
        }
    }
}

/// Capabilities in wire form.
///
/// # Safety
/// Everything `c` points to is valid (as for [`slice`] and [`items`]).
#[must_use]
pub unsafe fn capabilities(c: &NvbCapabilities) -> WireCapabilities {
    // SAFETY: forwarded contract.
    unsafe {
        WireCapabilities {
            flags: texts(c.flags, c.n_flags),
            checksum_algorithms: texts(c.checksum_algorithms, c.n_checksum_algorithms),
            max_name_bytes: c.max_name_bytes,
        }
    }
}

/// A discovered server in wire form.
///
/// # Safety
/// Everything `n` points to is valid (as for [`slice`]).
#[must_use]
pub unsafe fn nearby(n: &NvbNearby) -> WireNearby {
    // SAFETY: forwarded contract.
    unsafe {
        WireNearby {
            name: text_of(n.name),
            provider: text_of(n.provider),
            host: text_of(n.host),
            port: n.port,
        }
    }
}

/// A prompt.
///
/// # Safety
/// `p.text` as for [`slice`].
#[must_use]
pub unsafe fn prompt(p: &NvbPrompt) -> Prompt {
    // SAFETY: forwarded contract.
    Prompt { text: unsafe { text_of(p.text) }, echo: p.echo != 0 }
}

/// A failure. A name this build does not know becomes `Internal`, with the
/// name in front of the message.
///
/// # Safety
/// Everything `e` points to is valid (as for [`slice`]).
#[must_use]
pub unsafe fn status(e: &NvbError) -> Status {
    // SAFETY: forwarded contract.
    let (raw_name, message, detail) = unsafe { (text_of(e.name), text_of(e.message), text_of(e.detail)) };
    let (name, message) = match ErrorName::parse(&raw_name) {
        Some(name) => (name, message),
        None => (ErrorName::Internal, format!("{raw_name}: {message}")),
    };
    Status { name, message, detail, retry_after_ms: e.retry_after_ms }
}

// ----------------------------------------------------------- Rust -> C

/// Owns the bytes and arrays that `nvb_*` structs built for one call point
/// to. Append-only: nothing it handed out moves or goes until it is dropped
/// (the heap blocks of the inner `Vec`s stay where they are when the outer
/// `Vec`s grow).
#[derive(Debug, Default)]
struct Arena {
    bytes: Vec<Vec<u8>>,
    lists: Vec<Vec<NvbBytes>>,
    kvs: Vec<Vec<NvbKv>>,
}

impl Arena {
    /// A copy of `data`; the empty slice is (NULL, 0).
    fn bytes(&mut self, data: &[u8]) -> NvbBytes {
        if data.is_empty() {
            return NvbBytes::EMPTY;
        }
        self.bytes.push(data.to_vec());
        self.bytes.last().map_or(NvbBytes::EMPTY, |held| NvbBytes::of(held))
    }

    fn list(&mut self, texts: &[String]) -> (*const NvbBytes, usize) {
        let list: Vec<NvbBytes> = texts.iter().map(|t| self.bytes(t.as_bytes())).collect();
        let n = list.len();
        self.lists.push(list);
        (self.lists.last().map_or(std::ptr::null(), Vec::as_ptr), n)
    }

    fn value(&mut self, v: &Value) -> NvbValue {
        let mut out =
            NvbValue { kind: 0, number: 0, bytes: NvbBytes::EMPTY, items: std::ptr::null(), n_items: 0 };
        match v {
            Value::Str(s) => (out.kind, out.bytes) = (NVB_VALUE_STRING, self.bytes(s.as_bytes())),
            Value::Bool(b) => (out.kind, out.number) = (NVB_VALUE_BOOL, i64::from(*b)),
            Value::Int(n) => (out.kind, out.number) = (NVB_VALUE_INT, *n),
            Value::Bytes(b) => (out.kind, out.bytes) = (NVB_VALUE_BYTES, self.bytes(b)),
            Value::StrList(items) => {
                out.kind = NVB_VALUE_STRING_LIST;
                (out.items, out.n_items) = self.list(items);
            }
        }
        out
    }

    fn map(&mut self, map: &ValueMap) -> (*const NvbKv, usize) {
        let kvs: Vec<NvbKv> =
            map.iter().map(|(k, v)| NvbKv { key: self.bytes(k.as_bytes()), value: self.value(v) }).collect();
        let n = kvs.len();
        self.kvs.push(kvs);
        (self.kvs.last().map_or(std::ptr::null(), Vec::as_ptr), n)
    }

    fn params(&mut self, p: &Params) -> NvbParams {
        let (options, n_options) = self.map(&p.options);
        NvbParams {
            provider: self.bytes(p.provider.as_bytes()),
            host: self.bytes(p.host.as_bytes()),
            port: p.port,
            username: self.bytes(p.username.as_bytes()),
            options,
            n_options,
            connect_timeout_ms: p.connect_timeout_ms,
            request_timeout_ms: p.request_timeout_ms,
        }
    }
}

/// `nvb_params` for one call, with the `nvb_kv` and `nvb_bytes` arrays it
/// points to. It holds copies, so the [`Params`] it came from may change
/// or go while it lives.
#[derive(Debug)]
pub struct ParamsBuf {
    arena: Arena,
    raw: NvbParams,
}

impl ParamsBuf {
    /// Builds the C form of `p`.
    #[must_use]
    pub fn new(p: &Params) -> Self {
        let mut arena = Arena::default();
        let raw = arena.params(p);
        Self { arena, raw }
    }

    /// The C form; its pointers are valid while `self` lives.
    #[must_use]
    pub const fn raw(&self) -> &NvbParams {
        &self.raw
    }

    /// Reads the C form back, as C++ would see it.
    #[must_use]
    pub fn read_back(&self) -> Params {
        // SAFETY: every pointer in `raw` points into `arena`, which lives
        // and does not change as long as `self`.
        unsafe { params(&self.raw) }
    }

    /// The number of separate byte strings it holds (empty ones need none).
    #[must_use]
    pub fn byte_strings(&self) -> usize {
        self.arena.bytes.len()
    }
}

/// `nvb_entry` built from a wire entry, as C++ hands entries to the list
/// sink; for tests and the `ffi_marshal` fuzz target.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct EntryBuf {
    _arena: Arena,
    raw: NvbEntry,
}

#[cfg(any(test, feature = "testing"))]
impl EntryBuf {
    /// Builds the C form of `e`.
    #[must_use]
    pub fn new(e: &WireEntry) -> Self {
        let mut a = Arena::default();
        let raw = NvbEntry {
            name: a.bytes(&e.name),
            kind: e.kind,
            target_kind: e.target_kind,
            flags: e.flags,
            mode: e.mode,
            size: e.size,
            mtime_ms: e.mtime_ms,
            ctime_ms: e.ctime_ms,
            atime_ms: e.atime_ms,
            uid: e.uid,
            gid: e.gid,
            owner: a.bytes(e.owner.as_bytes()),
            group: a.bytes(e.group.as_bytes()),
            etag: a.bytes(&e.etag),
            content_type: a.bytes(e.content_type.as_bytes()),
        };
        Self { _arena: a, raw }
    }

    /// The C form; its pointers are valid while `self` lives.
    #[must_use]
    pub const fn raw(&self) -> &NvbEntry {
        &self.raw
    }

    /// Reads it back as the list sink does.
    #[must_use]
    pub fn read_back(&self) -> WireEntry {
        // SAFETY: every pointer in `raw` points into the arena.
        unsafe { entry(&self.raw) }
    }
}

/// `nvb_identity` built from an identity, as C++ hands it to the identity
/// hook; for tests and the `ffi_marshal` fuzz target.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct IdentityBuf {
    _arena: Arena,
    raw: NvbIdentity,
}

#[cfg(any(test, feature = "testing"))]
impl IdentityBuf {
    /// Builds the C form of `i`.
    #[must_use]
    pub fn new(i: &Identity) -> Self {
        let mut a = Arena::default();
        let raw = NvbIdentity {
            kind: i.kind.raw(),
            algorithm: a.bytes(i.algorithm.as_bytes()),
            public_key: a.bytes(&i.public_key),
            fingerprint: a.bytes(i.fingerprint.as_bytes()),
            pin: a.bytes(i.pin.as_bytes()),
        };
        Self { _arena: a, raw }
    }

    /// The C form; its pointers are valid while `self` lives.
    #[must_use]
    pub const fn raw(&self) -> &NvbIdentity {
        &self.raw
    }

    /// Reads it back as the identity hook does.
    #[must_use]
    pub fn read_back(&self) -> Identity {
        // SAFETY: every pointer in `raw` points into the arena.
        unsafe { identity(&self.raw) }
    }
}

#[cfg(test)]
mod tests {
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
    use std::ptr;

    fn sample_params() -> Params {
        let mut options = ValueMap::new();
        options.insert("share".into(), Value::Str("data".into()));
        options.insert("anon".into(), Value::Bool(true));
        options.insert("off".into(), Value::Bool(false));
        options.insert("n".into(), Value::Int(-7));
        options.insert("raw".into(), Value::Bytes(vec![0, 0xff]));
        options.insert("list".into(), Value::StrList(vec!["a".into(), String::new(), "ü".into()]));
        options.insert("empty".into(), Value::StrList(vec![]));
        Params {
            provider: "sftp".into(),
            host: "höst".into(),
            port: 2222,
            username: "alice".into(),
            options,
            connect_timeout_ms: 15000,
            request_timeout_ms: 60000,
        }
    }

    #[test]
    fn params_round_trip_and_own_their_bytes() {
        let mut p = sample_params();
        let buf = ParamsBuf::new(&p);
        let expected = p.clone();
        // A copy, not a borrow: changing the source changes nothing.
        p.host.push('x');
        p.options.clear();
        drop(p);
        assert_eq!(buf.read_back(), expected);
        let raw = buf.raw();
        assert_eq!(raw.n_options, 7);
        assert_eq!((raw.port, raw.connect_timeout_ms, raw.request_timeout_ms), (2222, 15000, 60000));
        // SAFETY: the arrays are owned by `buf`.
        let kvs = unsafe { items(raw.options, raw.n_options) };
        // Sorted, unique keys.
        let keys: Vec<String> = kvs.iter().map(|kv| text(unsafe { slice(kv.key) })).collect();
        assert_eq!(keys, ["anon", "empty", "list", "n", "off", "raw", "share"]);
        assert_eq!((kvs[0].value.kind, kvs[0].value.number), (NVB_VALUE_BOOL, 1));
        assert_eq!((kvs[4].value.kind, kvs[4].value.number), (NVB_VALUE_BOOL, 0));
        assert_eq!(kvs[1].value.n_items, 0);
        assert_eq!(kvs[2].value.n_items, 3);
    }

    #[test]
    fn empty_strings_are_null_and_hold_nothing() {
        let buf = ParamsBuf::new(&Params::default());
        assert!(buf.raw().provider.ptr.is_null());
        assert_eq!(buf.raw().provider.len, 0);
        assert_eq!(buf.raw().n_options, 0);
        assert_eq!(buf.byte_strings(), 0);
        assert_eq!(buf.read_back(), Params::default());
        let one = ParamsBuf::new(&Params { host: "h".into(), ..Params::default() });
        assert_eq!(one.byte_strings(), 1);
        assert_eq!(one.raw().host.len, 1);
        assert_eq!(unsafe { slice(one.raw().host) }, b"h");
    }

    #[test]
    fn readers_accept_null_with_a_length() {
        // A NULL pointer reads as empty, whatever the length says.
        let b = NvbBytes { ptr: ptr::null(), len: 5 };
        assert!(unsafe { slice(b) }.is_empty());
        assert!(unsafe { items::<NvbKv>(ptr::null(), 3) }.is_empty());
        let data = [1u8];
        assert!(unsafe { slice(NvbBytes { ptr: data.as_ptr(), len: 0 }) }.is_empty());
    }

    #[test]
    fn unknown_value_kinds_are_left_out() {
        let key = b"k";
        let kvs = [
            NvbKv {
                key: NvbBytes::of(key),
                value: NvbValue {
                    kind: 99,
                    number: 1,
                    bytes: NvbBytes::EMPTY,
                    items: ptr::null(),
                    n_items: 0,
                },
            },
            NvbKv {
                key: NvbBytes::of(b"j"),
                value: NvbValue {
                    kind: NVB_VALUE_INT,
                    number: 5,
                    bytes: NvbBytes::EMPTY,
                    items: ptr::null(),
                    n_items: 0,
                },
            },
        ];
        let map = unsafe { value_map(kvs.as_ptr(), kvs.len()) };
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("j"), Some(&Value::Int(5)));
        assert_eq!(unsafe { value(&kvs[0].value) }, None);
    }

    #[test]
    fn entries_round_trip_with_wire_text() {
        let e = WireEntry {
            name: b"n\xff".to_vec(),
            kind: 3,
            target_kind: 2,
            size: 10,
            mtime_ms: 1,
            ctime_ms: 2,
            atime_ms: 3,
            mode: 0o644,
            uid: 4,
            gid: 5,
            owner: "o\0wn".into(),
            group: "grp".into(),
            flags: 0x18,
            etag: vec![0, 1],
            content_type: "text/plain".into(),
        };
        let buf = EntryBuf::new(&e);
        let back = buf.read_back();
        assert_eq!(back.owner, "own");
        assert_eq!(back, WireEntry { owner: "own".into(), ..e });
        assert_eq!(buf.raw().flags, 0x18);
    }

    #[test]
    fn wire_text_is_lossy_and_without_nul() {
        assert_eq!(wire_text(b"a\0b\xffc"), "ab\u{fffd}c");
        assert_eq!(wire_text(b""), "");
    }

    #[test]
    fn identities_round_trip() {
        for kind in [IdentityKind::None, IdentityKind::Ssh] {
            let i = Identity {
                kind,
                algorithm: "ssh-ed25519".into(),
                public_key: vec![1, 2, 3],
                fingerprint: "SHA256:x".into(),
                pin: "ssh-ed25519 AQID".into(),
            };
            let buf = IdentityBuf::new(&i);
            assert_eq!(buf.raw().kind, kind.raw());
            assert_eq!(buf.read_back(), i);
        }
        assert_eq!(IdentityKind::from_raw(9), IdentityKind::None);
        assert_eq!(IdentityKind::from_raw(NVB_IDENTITY_SSH), IdentityKind::Ssh);
    }

    #[test]
    fn status_fields_and_unknown_names() {
        let e = NvbError {
            name: NvbBytes::of(b"RateLimited"),
            message: NvbBytes::of("slow döwn".as_bytes()),
            detail: NvbBytes::of(b"HTTP 429"),
            retry_after_ms: 1500,
        };
        let s = unsafe { status(&e) };
        assert_eq!(
            s,
            Status {
                name: ErrorName::RateLimited,
                message: "slow döwn".into(),
                detail: "HTTP 429".into(),
                retry_after_ms: 1500
            }
        );
        let newer = NvbError { name: NvbBytes::of(b"FromTheFuture"), ..e };
        let s = unsafe { status(&newer) };
        assert_eq!((s.name, s.message.as_str()), (ErrorName::Internal, "FromTheFuture: slow döwn"));
        assert_eq!((s.detail.as_str(), s.retry_after_ms), ("HTTP 429", 1500));
    }

    #[test]
    fn capabilities_nearby_and_prompts() {
        let flags = [NvbBytes::of(b"Symlinks"), NvbBytes::of(b"ServerCopy")];
        let algorithms = [NvbBytes::of(b"sha256")];
        let c = NvbCapabilities {
            flags: flags.as_ptr(),
            n_flags: 2,
            checksum_algorithms: algorithms.as_ptr(),
            n_checksum_algorithms: 1,
            max_name_bytes: 255,
        };
        let w = unsafe { capabilities(&c) };
        assert_eq!(w.flags, ["Symlinks", "ServerCopy"]);
        assert_eq!(w.checksum_algorithms, ["sha256"]);
        assert_eq!(w.max_name_bytes, 255);
        let n = NvbNearby {
            name: NvbBytes::of(b"NAS"),
            provider: NvbBytes::of(b"smb"),
            host: NvbBytes::of(b"nas.local"),
            port: 445,
        };
        assert_eq!(
            unsafe { nearby(&n) },
            WireNearby { name: "NAS".into(), provider: "smb".into(), host: "nas.local".into(), port: 445 }
        );
        let p = NvbPrompt { text: NvbBytes::of(b"Code: "), echo: 0 };
        assert_eq!(unsafe { prompt(&p) }, Prompt { text: "Code: ".into(), echo: false });
        let p = NvbPrompt { echo: 1, ..p };
        assert!(unsafe { prompt(&p) }.echo);
    }
}
