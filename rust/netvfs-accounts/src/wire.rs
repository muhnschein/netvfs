// SPDX-License-Identifier: LGPL-2.1-or-later
//! The answer on stdout in the format of a `QDataStream` of version
//! `Qt_5_6`, which the C++ bridge of netvfs 0.4 read and netvfs-bridge's
//! `accounts::qds` reads: big-endian, strings as UTF-16 with a byte length,
//! a null string as length `0xffffffff`.

use crate::qvariant::{QString, Value};

/// The first item of every answer.
pub const ANSWER_MAGIC: &[u8] = b"netvfs-accounts/1";

/// `NetVfs::Error` (src/core/error.h), as far as the helper reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No error.
    None = 0,
    /// The request breaks a security policy.
    SecurityPolicy = 7,
    /// The accounts database cannot be used.
    PermissionDenied = 8,
    /// No such account.
    NotFound = 9,
    /// An unknown command or state.
    Unsupported = 12,
    /// An internal failure, such as a failed write.
    Internal = 14,
}

/// `NetVfs::Result`: an error and its message, null for success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The error; `None` on success.
    pub error: Error,
    /// The message; the null string on success.
    pub message: QString,
}

impl Outcome {
    /// A successful outcome: no error, no message.
    #[must_use]
    pub fn success() -> Self {
        Self { error: Error::None, message: None }
    }

    /// A failed outcome with `error` and its `message`.
    #[must_use]
    pub fn failure(error: Error, message: impl Into<String>) -> Self {
        Self { error, message: Some(message.into()) }
    }

    /// Whether no error is set.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.error == Error::None
    }
}

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
}

/// A `QDataStream` that writes.
#[derive(Debug, Default)]
pub struct Stream {
    bytes: Vec<u8>,
}

impl Stream {
    /// An empty stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The header of every answer: magic, error, message.
    #[must_use]
    pub fn answer(outcome: &Outcome) -> Self {
        let mut s = Self::new();
        s.byte_array(ANSWER_MAGIC);
        s.i32(outcome.error as i32);
        s.string(outcome.message.as_deref());
        s
    }

    /// The bytes written.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Appends a boolean as one byte.
    pub fn bool(&mut self, value: bool) {
        self.bytes.push(u8::from(value));
    }

    /// Appends a signed byte.
    pub fn i8(&mut self, value: i8) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `i32`.
    pub fn i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `u32`.
    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `i64`.
    pub fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a big-endian `u64`.
    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// A length as Qt writes it: a 32-bit count. Nothing the helper writes
    /// comes near 4 GiB; a longer one would be cut to what fits.
    fn length(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX - 1));
    }

    /// Appends a byte array: its length, then the bytes.
    pub fn byte_array(&mut self, value: &[u8]) {
        self.length(value.len());
        self.bytes.extend_from_slice(value);
    }

    /// A `QString`; `None` is the null string.
    pub fn string(&mut self, value: Option<&str>) {
        let Some(text) = value else {
            self.u32(u32::MAX);
            return;
        };
        let units: Vec<u16> = text.encode_utf16().collect();
        self.length(units.len().saturating_mul(2));
        for unit in units {
            self.bytes.extend_from_slice(&unit.to_be_bytes());
        }
    }

    /// Appends a string list: its length, then each string.
    pub fn string_list(&mut self, items: &[String]) {
        self.length(items.len());
        for item in items {
            self.string(Some(item));
        }
    }

    /// A `QVariantMap`. Qt 5 writes a `QMap` from its last key to its first.
    pub fn variant_map(&mut self, map: &[(String, Value)]) {
        let mut sorted: Vec<&(String, Value)> = map.iter().collect();
        sorted.sort_by(|a, b| crate::qvariant::compare_qstring(&a.0, &b.0));
        sorted.dedup_by(|a, b| a.0 == b.0);
        self.length(sorted.len());
        for (key, value) in sorted.into_iter().rev() {
            self.string(Some(key));
            self.variant(value);
        }
    }

    /// A `QVariant`: type id, null flag, value.
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
        };
        self.u32(id);
        self.i8(i8::from(matches!(value, Value::Invalid)));
        match value {
            Value::Invalid => {}
            Value::Bool(b) => self.bool(*b),
            Value::Int(i) => self.i32(*i),
            Value::UInt(u) => self.u32(*u),
            Value::LongLong(i) => self.i64(*i),
            Value::ULongLong(u) => self.u64(*u),
            Value::Map(m) => self.variant_map(m),
            Value::String(s) => self.string(Some(s)),
            Value::StringList(l) => self.string_list(l),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(f: impl FnOnce(&mut Stream)) -> Vec<u8> {
        let mut s = Stream::new();
        f(&mut s);
        s.into_bytes()
    }

    #[test]
    fn strings_are_utf16_with_a_byte_length() {
        assert_eq!(bytes(|s| s.string(Some("aé"))), [0, 0, 0, 4, 0, b'a', 0, 0xe9]);
        assert_eq!(bytes(|s| s.string(Some("\u{1f600}"))), [0, 0, 0, 4, 0xd8, 0x3d, 0xde, 0x00]);
        assert_eq!(bytes(|s| s.string(Some(""))), [0, 0, 0, 0]);
        assert_eq!(bytes(|s| s.string(None)), [0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn numbers_are_big_endian() {
        assert_eq!(bytes(|s| s.i32(-2)), [0xff, 0xff, 0xff, 0xfe]);
        assert_eq!(bytes(|s| s.u32(7)), [0, 0, 0, 7]);
        assert_eq!(bytes(|s| s.i64(1)), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bytes(|s| s.u64(1 << 40)), [0, 0, 1, 0, 0, 0, 0, 0]);
        assert_eq!(bytes(|s| s.bool(true)), [1]);
        assert_eq!(bytes(|s| s.bool(false)), [0]);
    }

    #[test]
    fn variants_carry_type_and_null_flag() {
        assert_eq!(bytes(|s| s.variant(&Value::Invalid)), [0, 0, 0, 0, 1]);
        assert_eq!(bytes(|s| s.variant(&Value::Bool(true))), [0, 0, 0, 1, 0, 1]);
        assert_eq!(bytes(|s| s.variant(&Value::Int(5))), [0, 0, 0, 2, 0, 0, 0, 0, 5]);
        assert_eq!(bytes(|s| s.variant(&Value::UInt(5))), [0, 0, 0, 3, 0, 0, 0, 0, 5]);
        assert_eq!(bytes(|s| s.variant(&Value::LongLong(-1)))[..5], [0, 0, 0, 4, 0]);
        assert_eq!(bytes(|s| s.variant(&Value::ULongLong(1)))[..5], [0, 0, 0, 5, 0]);
        assert_eq!(bytes(|s| s.variant(&Value::String("a".into()))), [0, 0, 0, 10, 0, 0, 0, 0, 2, 0, b'a']);
        assert_eq!(
            bytes(|s| s.variant(&Value::StringList(vec!["a".into()]))),
            [0, 0, 0, 11, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, b'a']
        );
        assert_eq!(bytes(|s| s.variant(&Value::Map(Vec::new()))), [0, 0, 0, 8, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn maps_run_from_the_last_key_to_the_first() {
        let map = vec![("b".to_owned(), Value::Bool(true)), ("a".to_owned(), Value::Bool(false))];
        let mut expected = vec![0, 0, 0, 2];
        expected.extend([0, 0, 0, 2, 0, b'b', 0, 0, 0, 1, 0, 1]);
        expected.extend([0, 0, 0, 2, 0, b'a', 0, 0, 0, 1, 0, 0]);
        assert_eq!(bytes(|s| s.variant_map(&map)), expected);
        // A QMap holds a key once.
        let twice = vec![("a".to_owned(), Value::Bool(true)), ("a".to_owned(), Value::Bool(true))];
        assert_eq!(bytes(|s| s.variant_map(&twice))[..4], [0, 0, 0, 1]);
    }

    #[test]
    fn answers_start_with_magic_error_and_message() {
        let ok = Stream::answer(&Outcome::success()).into_bytes();
        let mut expected = vec![0, 0, 0, 17];
        expected.extend_from_slice(ANSWER_MAGIC);
        expected.extend([0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(ok, expected);
        let failed = Stream::answer(&Outcome::failure(Error::NotFound, "x")).into_bytes();
        assert_eq!(failed[21..25], [0, 0, 0, 9]);
        assert_eq!(failed[25..], [0, 0, 0, 2, 0, b'x']);
        assert!(Outcome::success().ok());
        assert!(!Outcome::failure(Error::Internal, "").ok());
    }
}
