// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-bridge's FFI marshalling without C++ (design §4.4): arbitrary
//! connection parameters, entries and identities built into their C form
//! (`ParamsBuf`, `EntryBuf`, `IdentityBuf`) and read back through the
//! readers C++'s blocks and callback arguments go through. The read-back
//! equals the input (lengths, `nvb_kv` and `nvb_bytes` arrays), also after
//! the input is gone (the C form holds copies, never borrows), and the
//! strings of an entry come back as D-Bus strings (no NUL).
#![no_main]

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use netvfs_bridge::ffi::marshal::{EntryBuf, IdentityBuf, wire_text};
use netvfs_bridge::ffi::{Identity, IdentityKind, Params, ParamsBuf, Value, ValueMap};
use netvfs_bridge_proto::WireEntry;

fn value(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0..=4)? {
        0 => Value::Str(u.arbitrary()?),
        1 => Value::Bool(u.arbitrary()?),
        2 => Value::Int(u.arbitrary()?),
        3 => Value::Bytes(u.arbitrary()?),
        _ => Value::StrList(u.arbitrary()?),
    })
}

fn values(u: &mut Unstructured<'_>) -> Result<ValueMap> {
    let mut map = ValueMap::new();
    for _ in 0..u.int_in_range(0..=8)? {
        map.insert(u.arbitrary()?, value(u)?);
    }
    Ok(map)
}

fn params(u: &mut Unstructured<'_>) -> Result<Params> {
    Ok(Params {
        provider: u.arbitrary()?,
        host: u.arbitrary()?,
        port: u.arbitrary()?,
        username: u.arbitrary()?,
        options: values(u)?,
        connect_timeout_ms: u.arbitrary()?,
        request_timeout_ms: u.arbitrary()?,
    })
}

fn entry(u: &mut Unstructured<'_>) -> Result<WireEntry> {
    Ok(WireEntry {
        name: u.arbitrary()?,
        kind: u.arbitrary()?,
        target_kind: u.arbitrary()?,
        size: u.arbitrary()?,
        mtime_ms: u.arbitrary()?,
        ctime_ms: u.arbitrary()?,
        atime_ms: u.arbitrary()?,
        mode: u.arbitrary()?,
        uid: u.arbitrary()?,
        gid: u.arbitrary()?,
        owner: u.arbitrary()?,
        group: u.arbitrary()?,
        flags: u.arbitrary()?,
        etag: u.arbitrary()?,
        content_type: u.arbitrary()?,
    })
}

fn identity(u: &mut Unstructured<'_>) -> Result<Identity> {
    let kind = [IdentityKind::None, IdentityKind::Ssh][u.choose_index(2)?];
    Ok(Identity {
        kind,
        algorithm: u.arbitrary()?,
        public_key: u.arbitrary()?,
        fingerprint: u.arbitrary()?,
        pin: u.arbitrary()?,
    })
}

fn check(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);

    let mut p = params(&mut u)?;
    let expected = p.clone();
    let buf = ParamsBuf::new(&p);
    // Copies, not borrows: the source may change or go.
    p.host.push('x');
    p.options.clear();
    drop(p);
    assert_eq!(buf.raw().n_options, expected.options.len());
    assert_eq!(buf.raw().host.len, expected.host.len());
    assert_eq!(buf.read_back(), expected);

    let e = entry(&mut u)?;
    let back = EntryBuf::new(&e).read_back();
    let expected = WireEntry {
        owner: wire_text(e.owner.as_bytes()),
        group: wire_text(e.group.as_bytes()),
        content_type: wire_text(e.content_type.as_bytes()),
        ..e
    };
    assert!(!back.owner.contains('\0') && !back.group.contains('\0') && !back.content_type.contains('\0'));
    assert_eq!(back, expected);

    let i = identity(&mut u)?;
    let buf = IdentityBuf::new(&i);
    assert_eq!(buf.raw().public_key.len, i.public_key.len());
    assert_eq!(buf.read_back(), i);
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Running out of input is not a finding.
    let _ = check(data);
});
