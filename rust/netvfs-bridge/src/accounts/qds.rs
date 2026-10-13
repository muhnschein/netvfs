// SPDX-License-Identifier: LGPL-2.1-or-later
//! The answers of netvfs-accounts, `netvfs-accounts/1`: a `QDataStream` of
//! version `Qt_5_6` (big-endian; strings UTF-16 with a byte length, a null
//! string as length `0xffffffff`). Every answer starts with the
//! `QByteArray` magic, the `qint32` error and the `QString` message; then
//!
//! - `list`: `qint32` count, per account `qint32` id, `QString` provider and
//!   display name, the parameters, `QString` files root, `qint32` attention;
//! - `files`: the parameters, `quint32` credentials id, `bool` secret
//!   optional;
//!
//! where the parameters are `QString` provider, host, `qint32` port,
//! `QString` username, `QVariantMap` options, `qint32` connect and request
//! timeout. Anything else, a short answer or bytes left over is a
//! `ProtocolError`.

use super::{AccountLocation, Attention, ConnectionParams, FilesAccess, Value};
use crate::status::Status;
use netvfs_bridge_proto::ErrorName;
use std::collections::BTreeMap;

/// The first item of every answer.
pub const MAGIC: &[u8] = b"netvfs-accounts/1";
/// More accounts than this is a malformed list.
pub const MAX_ACCOUNTS: i32 = 10_000;
/// Nested maps deeper than this are a malformed answer (Qt has no limit;
/// the helper writes one level).
const MAX_DEPTH: u32 = 32;

/// `QMetaType` ids of Qt 5.
mod type_id {
    pub const INVALID: u32 = 0;
    pub const BOOL: u32 = 1;
    pub const INT: u32 = 2;
    pub const UINT: u32 = 3;
    pub const LONG_LONG: u32 = 4;
    pub const ULONG_LONG: u32 = 5;
    pub const VARIANT_MAP: u32 = 8;
    pub const STRING: u32 = 10;
    pub const STRING_LIST: u32 = 11;
    pub const BYTE_ARRAY: u32 = 12;
}

/// A null `QString` or `QByteArray`.
const NULL_LENGTH: u32 = u32::MAX;

fn malformed() -> Status {
    Status::new(ErrorName::ProtocolError, "netvfs-accounts gave a malformed answer")
}

/// `Names::encode`: UTF-16 to protocol bytes. The escapes U+DC80 to
/// U+DCFF stand for the bytes 0x80 to 0xFF that are not UTF-8; other lone
/// surrogates become U+FFFD.
#[must_use]
pub fn names_encode(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len());
    for decoded in char::decode_utf16(units.iter().copied()) {
        match decoded {
            Ok(c) => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
            Err(e) => match u8::try_from(e.unpaired_surrogate().wrapping_sub(0xdc00)) {
                Ok(byte) if byte >= 0x80 => out.push(byte),
                _ => out.extend_from_slice("\u{fffd}".as_bytes()),
            },
        }
    }
    out
}

/// Reads a `QDataStream`; `None` is a failed read (short or corrupt).
#[derive(Debug)]
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(n)?;
        self.rest = tail;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn bool(&mut self) -> Option<bool> {
        Some(self.array::<1>()? != [0])
    }

    fn i32(&mut self) -> Option<i32> {
        self.array().map(i32::from_be_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_be_bytes)
    }

    fn i64(&mut self) -> Option<i64> {
        self.array().map(i64::from_be_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_be_bytes)
    }

    /// A length-prefixed block; null reads as empty.
    fn block(&mut self) -> Option<&'a [u8]> {
        match self.u32()? {
            NULL_LENGTH => Some(&[]),
            n => self.take(usize::try_from(n).ok()?),
        }
    }

    fn byte_array(&mut self) -> Option<Vec<u8>> {
        self.block().map(<[u8]>::to_vec)
    }

    /// A `QString` as UTF-16 code units; an odd byte length is corrupt.
    fn utf16(&mut self) -> Option<Vec<u16>> {
        let (pairs, odd) = self.block()?.as_chunks::<2>();
        odd.is_empty().then(|| pairs.iter().map(|p| u16::from_be_bytes(*p)).collect())
    }

    fn string(&mut self) -> Option<String> {
        self.utf16().map(|units| String::from_utf16_lossy(&units))
    }

    fn string_list(&mut self) -> Option<Vec<String>> {
        let count = self.u32()?;
        (0..count).map(|_| self.string()).collect()
    }

    /// A `QVariant`: type id, null flag, value.
    fn variant(&mut self, depth: u32) -> Option<Value> {
        let id = self.u32()?;
        self.take(1)?; // the null flag: no value is null here
        Some(match id {
            type_id::INVALID => Value::Invalid,
            type_id::BOOL => Value::Bool(self.bool()?),
            type_id::INT => Value::Int(self.i32()?),
            type_id::UINT => Value::UInt(self.u32()?),
            type_id::LONG_LONG => Value::LongLong(self.i64()?),
            type_id::ULONG_LONG => Value::ULongLong(self.u64()?),
            type_id::VARIANT_MAP if depth < MAX_DEPTH => {
                Value::Map(self.variant_map(depth.saturating_add(1))?)
            }
            type_id::STRING => Value::String(self.string()?),
            type_id::STRING_LIST => Value::StringList(self.string_list()?),
            type_id::BYTE_ARRAY => Value::ByteArray(self.byte_array()?),
            _ => return None,
        })
    }

    /// A `QVariantMap`, read with `insertMulti` and used with `value()`:
    /// the last value of a key wins; keys in `QMap` order.
    fn variant_map(&mut self, depth: u32) -> Option<Vec<(String, Value)>> {
        let count = self.u32()?;
        let mut map = BTreeMap::new();
        for _ in 0..count {
            let key = self.utf16()?;
            let value = self.variant(depth)?;
            map.insert(key, value);
        }
        Some(map.into_iter().map(|(key, value)| (String::from_utf16_lossy(&key), value)).collect())
    }

    fn params(&mut self) -> Option<ConnectionParams> {
        Some(ConnectionParams {
            provider: self.string()?,
            host: self.string()?,
            port: self.i32()?,
            username: self.string()?,
            options: self.variant_map(0)?,
            connect_timeout_ms: self.i32()?,
            request_timeout_ms: self.i32()?,
        })
    }

    fn attention(&mut self) -> Option<Attention> {
        match self.i32()? {
            0 => Some(Attention::None),
            1 => Some(Attention::AuthFailed),
            2 => Some(Attention::ServerIdentityChanged),
            _ => None,
        }
    }

    fn account(&mut self) -> Option<AccountLocation> {
        Some(AccountLocation {
            account_id: self.i32()?,
            provider: self.string()?,
            display_name: self.string()?,
            params: self.params()?,
            files_root: names_encode(&self.utf16()?),
            attention: self.attention()?,
        })
    }

    fn files(&mut self) -> Option<FilesAccess> {
        Some(FilesAccess {
            params: self.params()?,
            credentials_id: self.u32()?,
            secret_optional: self.bool()?,
        })
    }

    /// The header: `Err` is the helper's failure or a malformed header.
    fn header(&mut self) -> Result<(), Status> {
        let magic = self.byte_array().ok_or_else(malformed)?;
        let error = self.i32().ok_or_else(malformed)?;
        let message = self.string().ok_or_else(malformed)?;
        if magic != MAGIC {
            return Err(malformed());
        }
        if error == 0 {
            return Ok(());
        }
        let name = usize::try_from(error)
            .ok()
            .and_then(|e| e.checked_sub(1))
            .and_then(|index| ErrorName::ALL.get(index))
            .ok_or_else(malformed)?;
        Err(Status::new(*name, message))
    }

    /// The end of a payload read with `read`.
    fn finish<T>(&self, read: Option<T>) -> Result<T, Status> {
        read.filter(|_| self.rest.is_empty()).ok_or_else(malformed)
    }
}

/// The answer to `list`.
///
/// # Errors
/// The helper's failure, or `ProtocolError` for a malformed answer.
pub fn decode_list(answer: &[u8]) -> Result<Vec<AccountLocation>, Status> {
    let mut reader = Reader::new(answer);
    reader.header()?;
    let count = reader.i32().filter(|n| (0..=MAX_ACCOUNTS).contains(n)).ok_or_else(malformed)?;
    let accounts = (0..count).map(|_| reader.account()).collect();
    reader.finish(accounts)
}

/// The answer to `files <id>`.
///
/// # Errors
/// The helper's failure, or `ProtocolError` for a malformed answer.
pub fn decode_files(answer: &[u8]) -> Result<FilesAccess, Status> {
    let mut reader = Reader::new(answer);
    reader.header()?;
    let access = reader.files();
    reader.finish(access)
}

/// The answer to `attention`: the header alone.
///
/// # Errors
/// The helper's failure, or `ProtocolError` for a malformed answer.
pub fn decode_status(answer: &[u8]) -> Result<(), Status> {
    let mut reader = Reader::new(answer);
    reader.header()?;
    reader.finish(Some(()))
}

/// Writes answers as netvfs-accounts does (`wire.rs`), for the fake helper.
#[cfg(any(test, feature = "test-bins"))]
#[derive(Debug, Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

#[cfg(any(test, feature = "test-bins"))]
impl Writer {
    /// The header: magic, error (`0` for success) and message (null for
    /// success).
    #[must_use]
    pub fn answer(failure: Option<&Status>) -> Self {
        let mut w = Self::default();
        w.byte_array(MAGIC);
        let error = failure
            .and_then(|s| ErrorName::ALL.iter().position(|n| *n == s.name))
            .map_or(0, |i| i.saturating_add(1));
        w.i32(i32::try_from(error).unwrap_or_default());
        w.string(failure.map(|s| s.message.as_str()));
        w
    }

    /// The bytes written.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// `bool`.
    pub fn bool(&mut self, value: bool) {
        self.bytes.push(u8::from(value));
    }

    /// `qint32`.
    pub fn i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// `quint32`.
    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn length(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(NULL_LENGTH - 1));
    }

    /// `QByteArray`.
    pub fn byte_array(&mut self, value: &[u8]) {
        self.length(value.len());
        self.bytes.extend_from_slice(value);
    }

    /// `QString`; `None` is the null string.
    pub fn string(&mut self, value: Option<&str>) {
        let Some(text) = value else {
            return self.u32(NULL_LENGTH);
        };
        let units: Vec<u16> = text.encode_utf16().collect();
        self.length(units.len().saturating_mul(2));
        for unit in units {
            self.bytes.extend_from_slice(&unit.to_be_bytes());
        }
    }

    /// `QVariantMap`: Qt 5 writes a `QMap` from its last key to its first.
    pub fn variant_map(&mut self, map: &[(String, Value)]) {
        // A key given twice: the first counts, as in the helper.
        let mut sorted = BTreeMap::new();
        for (key, value) in map {
            sorted.entry(key.encode_utf16().collect::<Vec<_>>()).or_insert(value);
        }
        self.length(sorted.len());
        for (key, value) in sorted.into_iter().rev() {
            self.string(Some(&String::from_utf16_lossy(&key)));
            self.variant(value);
        }
    }

    /// `QVariant`: type id, null flag, value.
    pub fn variant(&mut self, value: &Value) {
        let id = match value {
            Value::Invalid => type_id::INVALID,
            Value::Bool(_) => type_id::BOOL,
            Value::Int(_) => type_id::INT,
            Value::UInt(_) => type_id::UINT,
            Value::LongLong(_) => type_id::LONG_LONG,
            Value::ULongLong(_) => type_id::ULONG_LONG,
            Value::Map(_) => type_id::VARIANT_MAP,
            Value::String(_) => type_id::STRING,
            Value::StringList(_) => type_id::STRING_LIST,
            Value::ByteArray(_) => type_id::BYTE_ARRAY,
        };
        self.u32(id);
        self.bool(matches!(value, Value::Invalid));
        match value {
            Value::Invalid => {}
            Value::Bool(b) => self.bool(*b),
            Value::Int(i) => self.i32(*i),
            Value::UInt(u) => self.u32(*u),
            Value::LongLong(i) => self.bytes.extend_from_slice(&i.to_be_bytes()),
            Value::ULongLong(u) => self.bytes.extend_from_slice(&u.to_be_bytes()),
            Value::Map(m) => self.variant_map(m),
            Value::String(s) => self.string(Some(s)),
            Value::StringList(list) => {
                self.length(list.len());
                for item in list {
                    self.string(Some(item));
                }
            }
            Value::ByteArray(b) => self.byte_array(b),
        }
    }

    /// The parameters.
    pub fn params(&mut self, p: &ConnectionParams) {
        self.string(Some(&p.provider));
        self.string(Some(&p.host));
        self.i32(p.port);
        self.string(Some(&p.username));
        self.variant_map(&p.options);
        self.i32(p.connect_timeout_ms);
        self.i32(p.request_timeout_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/data/accounts/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn full_params() -> ConnectionParams {
        ConnectionParams {
            provider: "sftp".into(),
            host: "files.example".into(),
            port: 2222,
            username: "alice".into(),
            options: vec![
                ("Upper".into(), Value::String(String::new())),
                ("compress".into(), Value::Bool(true)),
                ("key-file".into(), Value::String("/home/a/.ssh/id_ed25519".into())),
                ("list".into(), Value::StringList(vec!["a".into(), "b c".into()])),
                ("long".into(), Value::LongLong(-1 << 40)),
                ("map".into(), Value::Map(vec![("x".into(), Value::Invalid), ("é".into(), Value::Int(1))])),
                ("negative".into(), Value::Int(-5)),
                ("none".into(), Value::Invalid),
                ("ulong".into(), Value::ULongLong(u64::MAX)),
                ("unsigned".into(), Value::UInt(7)),
            ],
            connect_timeout_ms: 15000,
            request_timeout_ms: 30000,
        }
    }

    fn listed() -> Vec<AccountLocation> {
        vec![
            AccountLocation {
                account_id: 3,
                provider: "sftp".into(),
                display_name: "Café ☕ 😀".into(),
                params: full_params(),
                files_root: "/srv/ä".into(),
                attention: Attention::None,
            },
            AccountLocation {
                account_id: 4,
                provider: "webdav".into(),
                attention: Attention::ServerIdentityChanged,
                ..AccountLocation::default()
            },
            AccountLocation {
                account_id: i32::MAX,
                display_name: "x".into(),
                attention: Attention::AuthFailed,
                ..AccountLocation::default()
            },
        ]
    }

    #[test]
    fn decodes_helper_encoder_output() {
        assert_eq!(decode_list(&golden("list.bin")).unwrap(), listed());
        assert_eq!(decode_list(&golden("list-empty.bin")).unwrap(), []);
        let files = decode_files(&golden("files.bin")).unwrap();
        assert_eq!(files, FilesAccess { params: full_params(), credentials_id: 42, secret_optional: true });
        decode_status(&golden("ok.bin")).unwrap();
        let failure = decode_status(&golden("not-found.bin")).unwrap_err();
        assert_eq!(failure.to_string(), "NotFound: No such account");
        // Failures carry over whatever the command.
        assert_eq!(decode_list(&golden("not-found.bin")).unwrap_err(), failure);
        assert_eq!(decode_files(&golden("not-found.bin")).unwrap_err(), failure);
        assert_eq!(decode_files(&golden("internal-empty.bin")).unwrap_err().to_string(), "Internal");
    }

    #[test]
    fn writer_writes_what_the_helper_writes() {
        let mut w = Writer::answer(None);
        w.i32(3);
        for (i, a) in listed().iter().enumerate() {
            w.i32(a.account_id);
            w.string(Some(&a.provider));
            w.string((i != 1).then_some(a.display_name.as_str()));
            if i == 0 {
                w.params(&a.params);
            } else {
                w.string(None);
                w.string(None);
                w.i32(0);
                w.string(None);
                w.variant_map(&[]);
                w.i32(0);
                w.i32(0);
            }
            w.string((i != 1).then(|| String::from_utf8(a.files_root.clone()).unwrap()).as_deref());
            w.i32(a.attention as i32);
        }
        assert_eq!(w.into_bytes(), golden("list.bin"));
        let mut w = Writer::answer(None);
        w.params(&full_params());
        w.u32(42);
        w.bool(true);
        assert_eq!(w.into_bytes(), golden("files.bin"));
        let not_found = Status::new(ErrorName::NotFound, "No such account");
        assert_eq!(Writer::answer(Some(&not_found)).into_bytes(), golden("not-found.bin"));
        assert_eq!(Writer::answer(None).into_bytes(), golden("ok.bin"));
        // Values the helper does not write, and a key given twice.
        let mut w = Writer::answer(None);
        let options = vec![("b".into(), Value::ByteArray(vec![0, 0xff])), ("b".into(), Value::Int(1))];
        w.variant_map(&options);
        let mut r = Reader::new(&w.bytes);
        r.header().unwrap();
        assert_eq!(r.variant_map(0).unwrap(), [("b".into(), Value::ByteArray(vec![0, 0xff]))]);
    }

    #[test]
    fn malformed_answers() {
        // tst_BridgeAccounts::malformedAnswers
        let good = golden("list.bin");
        let protocol = |r: Result<(), Status>| r.unwrap_err().to_string();
        let expected = "ProtocolError: netvfs-accounts gave a malformed answer";
        assert_eq!(protocol(decode_list(&[]).map(drop)), expected);
        assert_eq!(protocol(decode_list(b"garbage").map(drop)), expected);
        assert_eq!(protocol(decode_list(&good[..good.len() - 1]).map(drop)), expected);
        assert_eq!(protocol(decode_list(&[good.as_slice(), b"x"].concat()).map(drop)), expected);
        assert_eq!(protocol(decode_files(&good).map(drop)), expected);
        assert_eq!(protocol(decode_status(&good)), expected);
        assert_eq!(protocol(decode_list(&golden("files.bin")).map(drop)), expected);
        assert_eq!(protocol(decode_files(&golden("ok.bin")).map(drop)), expected);
        // Every cut of a good answer is malformed.
        for cut in 0..good.len() {
            assert_eq!(protocol(decode_list(&good[..cut]).map(drop)), expected, "{cut}");
        }
    }

    fn header(magic: &[u8], error: i32, message: Option<&str>) -> Writer {
        let mut w = Writer::default();
        w.byte_array(magic);
        w.i32(error);
        w.string(message);
        w
    }

    #[test]
    fn headers() {
        let status = |w: Writer| decode_status(&w.into_bytes()).map_err(|s| s.to_string());
        assert_eq!(status(header(MAGIC, 0, Some("ignored"))), Ok(()));
        assert_eq!(status(header(MAGIC, 1, None)), Err("Canceled".into()));
        assert_eq!(status(header(MAGIC, 24, Some("m"))), Err("NotModified: m".into()));
        let malformed = Err("ProtocolError: netvfs-accounts gave a malformed answer".into());
        assert_eq!(status(header(MAGIC, 25, None)), malformed);
        assert_eq!(status(header(MAGIC, -1, None)), malformed);
        assert_eq!(status(header(b"netvfs-accounts/2", 0, None)), malformed);
        assert_eq!(status(header(b"", 0, None)), malformed);
        // A null magic.
        let mut null = Writer::default();
        null.u32(NULL_LENGTH);
        null.i32(0);
        null.string(None);
        assert_eq!(status(null), malformed);
        // An odd string length is corrupt.
        let mut odd = header(MAGIC, 9, None).into_bytes();
        let at = odd.len() - 4;
        odd.splice(at.., [0, 0, 0, 1, b'x']);
        assert_eq!(decode_status(&odd).unwrap_err().name, ErrorName::ProtocolError);
        // A failure ignores what follows it; a success may not have more.
        let mut failed = header(MAGIC, 9, Some("gone"));
        failed.i32(5);
        assert_eq!(status(failed), Err("NotFound: gone".into()));
        let mut extra = header(MAGIC, 0, None);
        extra.bool(false);
        assert_eq!(status(extra), malformed);
    }

    fn list_with(count: i32, account: impl FnOnce(&mut Writer)) -> Result<Vec<AccountLocation>, ErrorName> {
        let mut w = Writer::answer(None);
        w.i32(count);
        account(&mut w);
        decode_list(&w.into_bytes()).map_err(|s| s.name)
    }

    fn account(w: &mut Writer, attention: i32, value: &[u8]) {
        w.i32(1);
        w.string(Some("p"));
        w.string(Some("n"));
        w.string(None);
        w.string(None);
        w.i32(0);
        w.string(None);
        w.u32(1);
        w.string(Some("k"));
        w.bytes.extend_from_slice(value);
        w.i32(0);
        w.i32(0);
        w.string(Some("/"));
        w.i32(attention);
    }

    #[test]
    fn lists() {
        let invalid = [0, 0, 0, 0, 1];
        assert_eq!(list_with(0, |_| ()), Ok(vec![]));
        assert_eq!(list_with(-1, |_| ()), Err(ErrorName::ProtocolError));
        assert_eq!(list_with(MAX_ACCOUNTS + 1, |_| ()), Err(ErrorName::ProtocolError));
        // The limit itself is fine (the answer is short here).
        assert_eq!(list_with(MAX_ACCOUNTS, |_| ()), Err(ErrorName::ProtocolError));
        assert_eq!(
            list_with(1, |w| account(w, 2, &invalid)).unwrap()[0].attention,
            Attention::ServerIdentityChanged
        );
        assert_eq!(list_with(1, |w| account(w, 3, &invalid)), Err(ErrorName::ProtocolError));
        assert_eq!(list_with(1, |w| account(w, -1, &invalid)), Err(ErrorName::ProtocolError));
        let options =
            |value: &[u8]| list_with(1, |w| account(w, 0, value)).map(|l| l[0].params.options.clone());
        assert_eq!(options(&invalid), Ok(vec![("k".into(), Value::Invalid)]));
        // The null flag is read and ignored; a boolean is any non-zero byte.
        assert_eq!(options(&[0, 0, 0, 1, 1, 2]), Ok(vec![("k".into(), Value::Bool(true))]));
        assert_eq!(
            options(&[0, 0, 0, 12, 0, 0xff, 0xff, 0xff, 0xff]),
            Ok(vec![("k".into(), Value::ByteArray(vec![]))])
        );
        assert_eq!(
            options(&[0, 0, 0, 11, 0, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff]),
            Ok(vec![("k".into(), Value::StringList(vec![String::new()]))])
        );
        // Types the helper never writes: double, char, list, user types.
        for id in [6_u8, 7, 9, 13, 127] {
            assert_eq!(
                options(&[0, 0, 0, id, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                Err(ErrorName::ProtocolError),
                "{id}"
            );
        }
        assert_eq!(options(&[0, 0, 4, 0, 0, 0, 0, 0, 1, b'x']), Err(ErrorName::ProtocolError));
        // A key read twice: the last value wins (insertMulti, then value()).
        let mut twice = Writer::answer(None);
        twice.u32(2);
        for value in [Value::Int(1), Value::Int(2)] {
            twice.string(Some("k"));
            twice.variant(&value);
        }
        let mut r = Reader::new(&twice.bytes);
        r.header().unwrap();
        assert_eq!(r.variant_map(0), Some(vec![("k".into(), Value::Int(2))]));
        assert!(r.rest.is_empty());
    }

    #[test]
    fn nested_maps_are_limited() {
        let nested = |depth: u32| {
            let mut value = Value::Invalid;
            for _ in 0..depth {
                value = Value::Map(vec![("m".into(), value)]);
            }
            let mut w = Writer::answer(None);
            w.params(&ConnectionParams { options: vec![("m".into(), value)], ..ConnectionParams::default() });
            w.u32(0);
            w.bool(false);
            decode_files(&w.into_bytes()).map(drop).map_err(|s| s.name)
        };
        assert_eq!(nested(MAX_DEPTH), Ok(()));
        assert_eq!(nested(MAX_DEPTH + 1), Err(ErrorName::ProtocolError));
    }

    #[test]
    fn names_are_encoded() {
        let encode = |s: &[u16]| names_encode(s);
        assert_eq!(encode(&"a/ä😀".encode_utf16().collect::<Vec<_>>()), "a/ä😀".as_bytes());
        // Escapes stand for their byte; other lone surrogates are replaced.
        assert_eq!(encode(&[0x61, 0xdc80, 0xdcff, 0x62]), [0x61, 0x80, 0xff, 0x62]);
        assert_eq!(encode(&[0xdc7f]), "\u{fffd}".as_bytes());
        assert_eq!(encode(&[0xdd00]), "\u{fffd}".as_bytes());
        assert_eq!(encode(&[0xd800]), "\u{fffd}".as_bytes());
        assert_eq!(encode(&[0xd800, 0x61]), "\u{fffd}a".as_bytes());
        // A pair wins over an escape.
        assert_eq!(encode(&[0xd800, 0xdc80]), "\u{10080}".as_bytes());
        assert_eq!(encode(&[]), b"");
    }
}
