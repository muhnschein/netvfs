// SPDX-License-Identifier: LGPL-2.1-or-later
//! Between C values and netvfs-vfs values. Readers copy what the caller
//! passed (R1); writers make the blocks the caller frees (R3) or, for a
//! callback, views into Rust values that live for the callback (R2).
//! Out-of-range numbers from C++ are `ProtocolError`: the shim is built
//! from the same commit, so they are bugs, not old callers.

use super::alloc::{Out, pack};
use super::raw::{
    NVB_DISPOSITION_CREATE_NEW, NVB_DISPOSITION_RESUME, NVB_DISPOSITION_TRUNCATE, NVB_IDENTITY_SSH,
    NVB_VALUE_BOOL, NVB_VALUE_BYTES, NVB_VALUE_INT, NVB_VALUE_STRING, NVB_VALUE_STRING_LIST, NvbAttributes,
    NvbBlob, NvbBytes, NvbCapabilities, NvbEntry, NvbError, NvbIdentity, NvbKv, NvbParams, NvbSpace,
    NvbValue, NvrCredentials,
};
use netvfs_vfs::{
    Attributes, Capabilities, Credentials, Disposition, Entry, Params, ServerIdentity, SpaceInfo, Status,
    Value, ValueMap, WriteOptions, Zeroizing,
};

// ------------------------------------------------------------- C -> Rust

/// The bytes `b` points to.
///
/// # Safety
/// `b.ptr` is NULL or points to `b.len` bytes readable for `'a`.
pub unsafe fn slice<'a>(b: NvbBytes) -> &'a [u8] {
    if b.ptr.is_null() || b.len == 0 {
        return &[];
    }
    // SAFETY: non-NULL and `len` readable bytes for 'a (the contract).
    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }
}

/// The `n` items at `p`.
///
/// # Safety
/// `p` is NULL or points to `n` initialised items readable for `'a`.
pub unsafe fn items<'a, T>(p: *const T, n: usize) -> &'a [T] {
    if p.is_null() || n == 0 {
        return &[];
    }
    // SAFETY: non-NULL and `n` items for 'a (the contract).
    unsafe { std::slice::from_raw_parts(p, n) }
}

/// UTF-8 from C++ (`QString::toUtf8`), lossy.
///
/// # Safety
/// As for [`slice`].
pub unsafe fn text(b: NvbBytes) -> String {
    // SAFETY: forwarded.
    String::from_utf8_lossy(unsafe { slice(b) }).into_owned()
}

/// A `ProtocolError` naming the field C++ got wrong.
fn bad(what: &str) -> Status {
    Status::invalid_args(format!("Invalid {what} from the plugin"))
}

/// A count or offset that must not be negative.
///
/// # Errors
/// `ProtocolError` when it is.
pub fn unsigned(value: i64, what: &str) -> Result<u64, Status> {
    u64::try_from(value).map_err(|_negative| bad(what))
}

/// -1: `None`; other negatives: `ProtocolError`.
///
/// # Errors
/// `ProtocolError` below -1.
pub fn optional(value: i64, what: &str) -> Result<Option<u64>, Status> {
    if value == -1 { Ok(None) } else { unsigned(value, what).map(Some) }
}

/// A mode (`create_mode`, `nvb_attributes.mode`); -1: `None`.
fn mode(value: i32, what: &str) -> Result<Option<u32>, Status> {
    if value == -1 { Ok(None) } else { u32::try_from(value).map(Some).map_err(|_negative| bad(what)) }
}

/// # Safety
/// What `v` points to is valid (as for [`slice`] and [`items`]).
unsafe fn value(v: &NvbValue) -> Result<Value, Status> {
    // SAFETY: forwarded, for each arm.
    unsafe {
        Ok(match v.kind {
            NVB_VALUE_STRING => Value::Str(text(v.bytes)),
            NVB_VALUE_BOOL => Value::Bool(v.number != 0),
            NVB_VALUE_INT => Value::Int(v.number),
            NVB_VALUE_BYTES => Value::Bytes(slice(v.bytes).to_vec()),
            NVB_VALUE_STRING_LIST => {
                Value::StrList(items(v.items, v.n_items).iter().map(|b| text(*b)).collect())
            }
            _ => return Err(bad("option kind")),
        })
    }
}

/// `nvb_params` as [`Params`].
///
/// # Safety
/// Everything `p` points to is valid (as for [`slice`] and [`items`]).
///
/// # Errors
/// `ProtocolError` for an option of unknown kind.
pub unsafe fn params(p: &NvbParams) -> Result<Params, Status> {
    let mut options = ValueMap::new();
    // SAFETY: forwarded.
    for kv in unsafe { items::<NvbKv>(p.options, p.n_options) } {
        // SAFETY: forwarded, for each option.
        let (key, value) = unsafe { (text(kv.key), value(&kv.value)?) };
        options.insert(key, value);
    }
    // SAFETY: forwarded.
    let (provider, host, username) = unsafe { (text(p.provider), text(p.host), text(p.username)) };
    Ok(Params {
        provider,
        host,
        port: p.port,
        username,
        options,
        connect_timeout_ms: p.connect_timeout_ms,
        request_timeout_ms: p.request_timeout_ms,
    })
}

/// `nvr_credentials` as [`Credentials`]; the secret goes straight into a
/// wiped-on-drop buffer (R5).
///
/// # Safety
/// As for [`slice`], for each field.
pub unsafe fn credentials(c: &NvrCredentials) -> Credentials {
    // SAFETY: forwarded.
    unsafe {
        Credentials {
            user: text(c.user),
            secret: Zeroizing::new(slice(c.secret).to_vec()),
            domain: text(c.domain),
        }
    }
}

/// `nvb_attributes` as [`Attributes`].
///
/// # Errors
/// `ProtocolError` for a mode below -1.
pub fn attributes(a: &NvbAttributes) -> Result<Attributes, Status> {
    Ok(Attributes {
        mode: mode(a.mode, "mode")?,
        mtime_ms: (a.has_mtime != 0).then_some(a.mtime_ms),
        atime_ms: (a.has_atime != 0).then_some(a.atime_ms),
    })
}

/// The fields of `nvr_write_opts` and `nvb_upload_opts`.
#[derive(Debug, Clone, Copy)]
pub struct RawWriteOptions {
    /// `NVB_DISPOSITION_*`.
    pub disposition: u32,
    /// -1: backend default.
    pub create_mode: i32,
    /// `Resume`'s offset.
    pub resume_offset: i64,
    /// -1 unknown.
    pub expected_size: i64,
    /// Whether `mtime_ms` is set.
    pub has_mtime: u8,
    /// Modification time.
    pub mtime_ms: i64,
}

/// [`WriteOptions`] from their C fields.
///
/// # Errors
/// `ProtocolError` for an unknown disposition or a negative number.
pub fn write_options(o: RawWriteOptions) -> Result<WriteOptions, Status> {
    let disposition = match o.disposition {
        NVB_DISPOSITION_CREATE_NEW => Disposition::CreateNew,
        NVB_DISPOSITION_TRUNCATE => Disposition::Truncate,
        NVB_DISPOSITION_RESUME => Disposition::Resume,
        _ => return Err(bad("disposition")),
    };
    Ok(WriteOptions {
        disposition,
        create_mode: mode(o.create_mode, "create mode")?,
        resume_offset: unsigned(o.resume_offset, "resume offset")?,
        expected_size: optional(o.expected_size, "expected size")?,
        mtime_ms: (o.has_mtime != 0).then_some(o.mtime_ms),
    })
}

// ------------------------------------------------------------- Rust -> C

/// -1 for unknown; a value past `i64::MAX` is clamped.
fn known(value: Option<u64>) -> i64 {
    value.map_or(-1, |v| i64::try_from(v).unwrap_or(i64::MAX))
}

/// `status` as an `nvb_error` block; aborts the process when not even
/// that can be allocated (nothing else could report the failure).
pub fn error(status: &Status) -> *mut NvbError {
    let block = pack(|out| NvbError {
        name: out.bytes(status.name.as_str().as_bytes()),
        message: out.bytes(status.message.as_bytes()),
        detail: out.bytes(status.detail.as_bytes()),
        retry_after_ms: status.retry_after_ms,
    });
    match block {
        Some(p) => p,
        None => std::process::abort(),
    }
}

/// The `Internal` status of a block that could not be allocated.
pub fn no_memory() -> Status {
    Status::internal("Out of memory in the Rust backends")
}

/// `e` with each field's bytes from `put`: copies into a block, or views
/// of `e` itself for a callback.
pub fn fill_entry(e: &Entry, mut put: impl FnMut(&[u8]) -> NvbBytes) -> NvbEntry {
    NvbEntry {
        name: put(&e.name),
        kind: e.kind.raw(),
        target_kind: e.target_kind.raw(),
        flags: e.flags.bits(),
        mode: e.mode.map_or(-1, |m| i32::try_from(m).unwrap_or(-1)),
        size: known(e.size),
        mtime_ms: e.mtime_ms.unwrap_or(-1),
        ctime_ms: e.ctime_ms.unwrap_or(-1),
        atime_ms: e.atime_ms.unwrap_or(-1),
        uid: known(e.uid),
        gid: known(e.gid),
        owner: put(e.owner.as_bytes()),
        group: put(e.group.as_bytes()),
        etag: put(&e.etag),
        content_type: put(e.content_type.as_bytes()),
    }
}

/// An entry block.
pub fn entry(e: &Entry) -> Option<*mut NvbEntry> {
    pack(|out| fill_entry(e, |data| out.bytes(data)))
}

/// A blob block.
pub fn blob(data: &[u8]) -> Option<*mut NvbBlob> {
    pack(|out| NvbBlob { data: out.bytes(data) })
}

/// An identity block: an SSH host key; `pin` is left empty (C++ computes
/// `ServerIdentity::toPin()`), so is the fingerprint when the backend left
/// it empty.
pub fn identity(id: &ServerIdentity) -> Option<*mut NvbIdentity> {
    pack(|out| NvbIdentity {
        kind: NVB_IDENTITY_SSH,
        algorithm: out.bytes(id.algorithm.as_bytes()),
        public_key: out.bytes(&id.public_key),
        fingerprint: out.bytes(id.fingerprint.as_bytes()),
        pin: out.bytes(&[]),
    })
}

/// A capabilities block; flags by name, sorted.
pub fn capabilities(c: &Capabilities) -> Option<*mut NvbCapabilities> {
    let names: Vec<&[u8]> = c.names().into_iter().map(str::as_bytes).collect();
    let algorithms: Vec<&[u8]> = c.checksum_algorithms.iter().map(String::as_bytes).collect();
    pack(|out: &mut dyn Out| NvbCapabilities {
        flags: out.list(&names),
        n_flags: names.len(),
        checksum_algorithms: out.list(&algorithms),
        n_checksum_algorithms: algorithms.len(),
        max_name_bytes: known(c.max_name_bytes),
    })
}

/// `nvb_space`; each -1 unknown.
pub fn space(s: &SpaceInfo) -> NvbSpace {
    NvbSpace { free_bytes: known(s.free), total_bytes: known(s.total), used_bytes: known(s.used) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::alloc::free;
    use netvfs_vfs::{Capability, EntryFlags, EntryType, ErrorName};
    use std::collections::BTreeSet;

    fn b(data: &[u8]) -> NvbBytes {
        NvbBytes::of(data)
    }

    fn read(x: NvbBytes) -> Vec<u8> {
        // SAFETY: test: `x` points into a live block or a test buffer.
        unsafe { slice(x) }.to_vec()
    }

    fn release<T>(p: *mut T) {
        // SAFETY: test: a block of this library, released once.
        unsafe { free(p.cast()) };
    }

    #[test]
    fn slices_and_items_accept_null() {
        // SAFETY: NULL with any length is allowed.
        unsafe {
            assert_eq!(slice(NvbBytes { ptr: std::ptr::null(), len: 5 }), []);
            assert_eq!(items::<u8>(std::ptr::null(), 3), []);
            let data = [7u8, 8];
            assert_eq!(slice(NvbBytes { ptr: data.as_ptr(), len: 0 }), []);
            assert_eq!(slice(b(&data)), &data);
            assert_eq!(items(data.as_ptr(), 2), &data);
            assert_eq!(items(data.as_ptr(), 0), []);
            assert_eq!(text(b(b"caf\xc3\xa9 \xff")), "café \u{fffd}");
        }
    }

    #[test]
    fn numbers_from_the_plugin() {
        assert_eq!(unsigned(0, "x"), Ok(0));
        assert_eq!(unsigned(5, "x"), Ok(5));
        let e = unsigned(-1, "offset").unwrap_err();
        assert_eq!(
            (e.name, e.message.as_str()),
            (ErrorName::ProtocolError, "Invalid offset from the plugin")
        );
        assert_eq!(optional(-1, "x"), Ok(None));
        assert_eq!(optional(0, "x"), Ok(Some(0)));
        assert_eq!(optional(-2, "x").map_err(|s| s.name), Err(ErrorName::ProtocolError));
        assert_eq!(mode(-1, "m"), Ok(None));
        assert_eq!(mode(0o644, "m"), Ok(Some(0o644)));
        assert_eq!(mode(-2, "m").map_err(|s| s.name), Err(ErrorName::ProtocolError));
        assert_eq!(known(None), -1);
        assert_eq!(known(Some(9)), 9);
        assert_eq!(known(Some(u64::MAX)), i64::MAX);
    }

    #[test]
    fn params_with_every_value_kind() {
        let list = [b(b"a"), b(b"b")];
        let value =
            |kind, number, bytes| NvbValue { kind, number, bytes, items: std::ptr::null(), n_items: 0 };
        let kvs = [
            NvbKv { key: b(b"s"), value: value(NVB_VALUE_STRING, 0, b(b"text")) },
            NvbKv { key: b(b"t"), value: value(NVB_VALUE_BOOL, 1, NvbBytes::EMPTY) },
            NvbKv { key: b(b"f"), value: value(NVB_VALUE_BOOL, 0, NvbBytes::EMPTY) },
            NvbKv { key: b(b"i"), value: value(NVB_VALUE_INT, -42, NvbBytes::EMPTY) },
            NvbKv { key: b(b"y"), value: value(NVB_VALUE_BYTES, 0, b(b"\x00\xff")) },
            NvbKv {
                key: b(b"l"),
                value: NvbValue {
                    kind: NVB_VALUE_STRING_LIST,
                    number: 0,
                    bytes: NvbBytes::EMPTY,
                    items: list.as_ptr(),
                    n_items: 2,
                },
            },
        ];
        let raw = NvbParams {
            provider: b(b"mem"),
            host: b(b"h"),
            port: 22,
            username: b(b"u"),
            options: kvs.as_ptr(),
            n_options: kvs.len(),
            connect_timeout_ms: 1000,
            request_timeout_ms: 2000,
        };
        // SAFETY: test: everything points to live test data.
        let p = unsafe { params(&raw) }.unwrap();
        assert_eq!(
            (p.provider.as_str(), p.host.as_str(), p.port, p.username.as_str()),
            ("mem", "h", 22, "u")
        );
        assert_eq!((p.connect_timeout_ms, p.request_timeout_ms), (1000, 2000));
        assert_eq!(p.options.get("s"), Some(&Value::Str("text".to_owned())));
        assert_eq!(p.options.get("t"), Some(&Value::Bool(true)));
        assert_eq!(p.options.get("f"), Some(&Value::Bool(false)));
        assert_eq!(p.options.get("i"), Some(&Value::Int(-42)));
        assert_eq!(p.options.get("y"), Some(&Value::Bytes(vec![0, 0xff])));
        assert_eq!(p.options.get("l"), Some(&Value::StrList(vec!["a".to_owned(), "b".to_owned()])));
        assert_eq!(p.options.len(), 6);

        let unknown = [NvbKv { key: b(b"x"), value: value(99, 0, NvbBytes::EMPTY) }];
        let raw = NvbParams { options: unknown.as_ptr(), n_options: 1, ..raw };
        // SAFETY: as above.
        let e = unsafe { params(&raw) }.unwrap_err();
        assert_eq!(
            (e.name, e.message.as_str()),
            (ErrorName::ProtocolError, "Invalid option kind from the plugin")
        );
    }

    #[test]
    fn credentials_and_attributes() {
        let raw = NvrCredentials { user: b(b"alice"), secret: b(b"pw"), domain: b(b"WORK") };
        // SAFETY: test data.
        let c = unsafe { credentials(&raw) };
        assert_eq!((c.user.as_str(), c.secret.as_slice(), c.domain.as_str()), ("alice", &b"pw"[..], "WORK"));
        let a = NvbAttributes { mode: 0o640, has_mtime: 1, has_atime: 0, mtime_ms: 5, atime_ms: 6 };
        assert_eq!(attributes(&a), Ok(Attributes { mode: Some(0o640), mtime_ms: Some(5), atime_ms: None }));
        let a = NvbAttributes { mode: -1, has_mtime: 0, has_atime: 1, mtime_ms: 5, atime_ms: 6 };
        assert_eq!(attributes(&a), Ok(Attributes { mode: None, mtime_ms: None, atime_ms: Some(6) }));
        let a = NvbAttributes { mode: -3, ..a };
        assert_eq!(attributes(&a).map_err(|s| s.name), Err(ErrorName::ProtocolError));
    }

    #[test]
    fn write_options_from_c() {
        let raw = RawWriteOptions {
            disposition: NVB_DISPOSITION_RESUME,
            create_mode: 0o600,
            resume_offset: 100,
            expected_size: 250,
            has_mtime: 1,
            mtime_ms: 7,
        };
        let o = write_options(raw).unwrap();
        assert_eq!(o.disposition, Disposition::Resume);
        assert_eq!(
            (o.create_mode, o.resume_offset, o.expected_size, o.mtime_ms),
            (Some(0o600), 100, Some(250), Some(7))
        );
        let o = write_options(RawWriteOptions {
            disposition: NVB_DISPOSITION_TRUNCATE,
            create_mode: -1,
            expected_size: -1,
            has_mtime: 0,
            ..raw
        })
        .unwrap();
        assert_eq!(o.disposition, Disposition::Truncate);
        assert_eq!((o.create_mode, o.expected_size, o.mtime_ms), (None, None, None));
        let o = write_options(RawWriteOptions { disposition: NVB_DISPOSITION_CREATE_NEW, ..raw }).unwrap();
        assert_eq!(o.disposition, Disposition::CreateNew);
        for wrong in [
            RawWriteOptions { disposition: 3, ..raw },
            RawWriteOptions { create_mode: -2, ..raw },
            RawWriteOptions { resume_offset: -1, ..raw },
            RawWriteOptions { expected_size: -2, ..raw },
        ] {
            assert_eq!(write_options(wrong).map_err(|s| s.name), Err(ErrorName::ProtocolError));
        }
    }

    #[test]
    fn error_blocks() {
        let s = Status::new(ErrorName::RateLimited, "slow").with_detail("429").with_retry_after_ms(1500);
        let p = error(&s);
        // SAFETY: test: a live block.
        let e = unsafe { p.read() };
        assert_eq!(
            (read(e.name), read(e.message), read(e.detail)),
            (b"RateLimited".to_vec(), b"slow".to_vec(), b"429".to_vec())
        );
        assert_eq!(e.retry_after_ms, 1500);
        release(p);
        assert_eq!(no_memory().name, ErrorName::Internal);
    }

    #[test]
    fn entries_as_blocks_and_views() {
        let e = Entry {
            name: b"n\xff".to_vec(),
            kind: EntryType::Symlink,
            target_kind: EntryType::Directory,
            flags: EntryFlags::NAME_NOT_UTF8,
            mode: Some(0o755),
            size: Some(12),
            mtime_ms: Some(1),
            ctime_ms: Some(2),
            atime_ms: None,
            uid: Some(1000),
            gid: None,
            owner: "o".to_owned(),
            group: "g".to_owned(),
            etag: b"e1".to_vec(),
            content_type: "text/plain".to_owned(),
        };
        let p = entry(&e).unwrap();
        // SAFETY: test: a live block.
        let raw = unsafe { p.read() };
        assert_eq!(read(raw.name), b"n\xff");
        assert_eq!((raw.kind, raw.target_kind, raw.flags), (3, 2, 8));
        assert_eq!((raw.mode, raw.size, raw.mtime_ms, raw.ctime_ms, raw.atime_ms), (0o755, 12, 1, 2, -1));
        assert_eq!((raw.uid, raw.gid), (1000, -1));
        assert_eq!(
            (read(raw.owner), read(raw.group), read(raw.etag)),
            (b"o".to_vec(), b"g".to_vec(), b"e1".to_vec())
        );
        assert_eq!(read(raw.content_type), b"text/plain");
        release(p);

        let view = fill_entry(&e, NvbBytes::of);
        assert_eq!(view.name.ptr, e.name.as_ptr());
        let empty = fill_entry(&Entry { mode: Some(u32::MAX), ..Entry::default() }, NvbBytes::of);
        assert_eq!((empty.mode, empty.size, empty.uid, empty.mtime_ms), (-1, -1, -1, -1));
    }

    #[test]
    fn blobs_identities_capabilities_space() {
        let p = blob(b"target").unwrap();
        // SAFETY: test: a live block.
        assert_eq!(read(unsafe { p.read() }.data), b"target");
        release(p);

        let id = ServerIdentity {
            algorithm: "ssh-ed25519".to_owned(),
            public_key: vec![1, 2],
            fingerprint: String::new(),
        };
        let p = identity(&id).unwrap();
        // SAFETY: test: a live block.
        let raw = unsafe { p.read() };
        assert_eq!(raw.kind, NVB_IDENTITY_SSH);
        assert_eq!((read(raw.algorithm), read(raw.public_key)), (b"ssh-ed25519".to_vec(), vec![1, 2]));
        assert!(read(raw.fingerprint).is_empty() && read(raw.pin).is_empty());
        release(p);

        let caps = Capabilities {
            flags: BTreeSet::from([Capability::Symlinks, Capability::AtomicPut]),
            checksum_algorithms: vec!["sha256".to_owned()],
            max_name_bytes: Some(255),
        };
        let p = capabilities(&caps).unwrap();
        // SAFETY: test: a live block.
        let raw = unsafe { p.read() };
        // SAFETY: test: the lists are in the block.
        let (flags, algos) = unsafe {
            (items(raw.flags, raw.n_flags), items(raw.checksum_algorithms, raw.n_checksum_algorithms))
        };
        let flags: Vec<Vec<u8>> = flags.iter().map(|x| read(*x)).collect();
        assert_eq!(flags, [b"AtomicPut".to_vec(), b"Symlinks".to_vec()]);
        assert_eq!(algos.iter().map(|x| read(*x)).collect::<Vec<_>>(), [b"sha256".to_vec()]);
        assert_eq!(raw.max_name_bytes, 255);
        release(p);
        let p = capabilities(&Capabilities::default()).unwrap();
        // SAFETY: test: a live block.
        let raw = unsafe { p.read() };
        assert_eq!((raw.n_flags, raw.n_checksum_algorithms, raw.max_name_bytes), (0, 0, -1));
        release(p);

        let s = space(&SpaceInfo { free: Some(1), total: None, used: Some(3) });
        assert_eq!(s, NvbSpace { free_bytes: 1, total_bytes: -1, used_bytes: 3 });
    }
}
