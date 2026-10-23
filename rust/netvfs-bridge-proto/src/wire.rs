// SPDX-License-Identifier: LGPL-2.1-or-later
//! Wire types of `org.netvfs.Bridge1` (netvfs SPEC-v2 XB-9). Paths and names
//! are `ay` (raw protocol bytes, XC-4), never `s`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zbus::zvariant::{OwnedValue, Type, Value};

/// Entry kinds (`type` and `targetType` of an entry, XB-9).
pub mod entry_kind {
    /// Not known.
    pub const UNKNOWN: u8 = 0;
    /// A regular file.
    pub const FILE: u8 = 1;
    /// A folder.
    pub const DIRECTORY: u8 = 2;
    /// A symbolic link.
    pub const SYMLINK: u8 = 3;
    /// A device, socket or pipe.
    pub const SPECIAL: u8 = 4;
}

/// Entry flags (XB-9).
pub mod entry_flags {
    /// A hidden file.
    pub const HIDDEN: u16 = 0x1;
    /// Read-only.
    pub const READ_ONLY: u16 = 0x2;
    /// A system file.
    pub const SYSTEM: u16 = 0x4;
    /// The server's name is not UTF-8; `name` carries its raw bytes.
    pub const NAME_NOT_UTF8: u16 = 0x8;
    /// A symlink whose target's kind is not known.
    pub const TARGET_UNKNOWN: u16 = 0x10;
}

/// `(ayyyxxxxixxssqays)`; -1 or empty means unknown.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Type)]
pub struct WireEntry {
    /// Name (protocol bytes, XC-4).
    pub name: Vec<u8>,
    /// Kind ([`entry_kind`]).
    pub kind: u8,
    /// Kind of a symlink's target ([`entry_kind`]).
    pub target_kind: u8,
    /// Size in bytes.
    pub size: i64,
    /// Modification time, ms since the epoch.
    pub mtime_ms: i64,
    /// Status change time, ms since the epoch.
    pub ctime_ms: i64,
    /// Access time, ms since the epoch.
    pub atime_ms: i64,
    /// POSIX mode bits.
    pub mode: i32,
    /// Owner id.
    pub uid: i64,
    /// Group id.
    pub gid: i64,
    /// Owner name.
    pub owner: String,
    /// Group name.
    pub group: String,
    /// Flags ([`entry_flags`]).
    pub flags: u16,
    /// Entity tag of the server, opaque.
    pub etag: Vec<u8>,
    /// MIME type the server reported.
    pub content_type: String,
}

impl WireEntry {
    /// An entry with every optional field unknown.
    #[must_use]
    pub fn unknown(name: &[u8], kind: u8) -> Self {
        Self {
            name: name.to_vec(),
            kind,
            // target_kind keeps its default, entry_kind::UNKNOWN.
            size: -1,
            mtime_ms: -1,
            ctime_ms: -1,
            atime_ms: -1,
            mode: -1,
            uid: -1,
            gid: -1,
            ..Self::default()
        }
    }
}

/// `(asasx)`
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Type)]
pub struct WireCapabilities {
    /// Capability names (`Symlinks`, `ServerCopy`, …).
    pub flags: Vec<String>,
    /// Algorithms `Checksum` accepts.
    pub checksum_algorithms: Vec<String>,
    /// Longest name in bytes, -1 if not known.
    pub max_name_bytes: i64,
}

/// The connection state of a location: info key `state` of
/// `ListLocations` (SPEC-v2 XB-10, XB-12), with `stateError` (the XC-21
/// name) when it is [`FAILED`](location_state::FAILED).
pub mod location_state {
    /// The info key of the state.
    pub const KEY: &str = "state";
    /// The info key of the error of a failed state.
    pub const ERROR_KEY: &str = "stateError";
    /// No connection of the consumer's pool is established or being
    /// established.
    pub const DISCONNECTED: &str = "disconnected";
    /// None is established, at least one is being established.
    pub const CONNECTING: &str = "connecting";
    /// At least one is established (connected and authenticated).
    pub const CONNECTED: &str = "connected";
    /// As [`DISCONNECTED`], but the last attempt to connect failed.
    pub const FAILED: &str = "failed";
}

/// `(sssa{sv})`: id, provider, display name, info.
#[derive(Debug, Serialize, Deserialize, Type)]
pub struct WireLocation {
    /// Location id (`account:<n>`, `adhoc:<run>-<n>`; opaque, SPEC-v2 XB-10).
    pub id: String,
    /// Backend provider (`sftp`, `smb`, …).
    pub provider: String,
    /// Display name.
    pub name: String,
    /// More facts (`kind`, `host`, `path`, `attention`, `state`, …).
    pub info: HashMap<String, OwnedValue>,
}

/// `(sssq)`: a discovered server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct WireNearby {
    /// Announced name.
    pub name: String,
    /// Backend provider.
    pub provider: String,
    /// Host name or address.
    pub host: String,
    /// Port, 0 for the provider's default.
    pub port: u16,
}

/// `(ssaya{sv})`: a memory card or USB drive of `ListDrives` (SPEC-v2 XB-20).
#[derive(Debug, Serialize, Deserialize, Type)]
pub struct WireDrive {
    /// Drive id (opaque, `[A-Za-z0-9_]{1,64}`).
    pub id: String,
    /// The filesystem's label, empty without one.
    pub label: String,
    /// Where it is mounted, empty when it is not.
    pub mount_point: Vec<u8>,
    /// More facts ([`drive_info`]).
    pub info: HashMap<String, OwnedValue>,
}

/// The info keys of a [`WireDrive`] (SPEC-v2 XB-20).
pub mod drive_info {
    /// `s`: [`KIND_SD`] or [`KIND_USB`].
    pub const KIND: &str = "kind";
    /// `x`: bytes.
    pub const SIZE: &str = "size";
    /// `s`: the filesystem type (`vfat`, `exfat`, `ext4`, …).
    pub const FS_TYPE: &str = "fsType";
    /// `b`.
    pub const READ_ONLY: &str = "readOnly";
    /// `s`, when known.
    pub const UUID: &str = "uuid";
    /// `s`: the drive's vendor and model, when known.
    pub const MODEL: &str = "model";
    /// A memory card.
    pub const KIND_SD: &str = "sd";
    /// A USB drive.
    pub const KIND_USB: &str = "usb";

    /// `[A-Za-z0-9_]{1,64}`: the last element of a UDisks2 object path.
    #[must_use]
    pub fn is_valid_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= crate::limits::MAX_ID
            && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    }
}

/// `(ay(ayyyxxxxixxssqays))` of `WalkBatch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct WireWalkItem {
    /// Path relative to the walk's root.
    pub path: Vec<u8>,
    /// The entry.
    pub entry: WireEntry,
}

/// An `a{sv}` argument built from plain Rust values.
pub type Opts = HashMap<String, Value<'static>>;

/// Builder for option dictionaries (`opts`, `changes`, `answer`).
#[derive(Debug, Default)]
pub struct OptsBuilder(Opts);

impl OptsBuilder {
    /// An empty dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A boolean.
    #[must_use]
    pub fn bool(mut self, key: &str, v: bool) -> Self {
        self.0.insert(key.to_owned(), Value::from(v));
        self
    }

    /// An integer (`x`).
    #[must_use]
    pub fn int(mut self, key: &str, v: i64) -> Self {
        self.0.insert(key.to_owned(), Value::from(v));
        self
    }

    /// A string.
    #[must_use]
    pub fn str(mut self, key: &str, v: &str) -> Self {
        self.0.insert(key.to_owned(), Value::from(v.to_owned()));
        self
    }

    /// A byte array (`ay`), as `info.path` carries a path.
    #[must_use]
    pub fn bytes(mut self, key: &str, v: &[u8]) -> Self {
        self.0.insert(key.to_owned(), Value::from(v.to_vec()));
        self
    }

    /// An array of byte arrays (`aay`), as `Answer` carries keyboard answers.
    #[must_use]
    pub fn byte_arrays(mut self, key: &str, v: &[Vec<u8>]) -> Self {
        let items: Vec<Vec<u8>> = v.to_vec();
        self.0.insert(key.to_owned(), Value::from(items));
        self
    }

    /// The dictionary.
    #[must_use]
    pub fn build(self) -> Opts {
        self.0
    }

    /// The dictionary as the bridge sends it (`a{sv}` with owned values), for
    /// building server-side messages and test fixtures.
    #[must_use]
    pub fn build_owned(self) -> HashMap<String, OwnedValue> {
        self.0
            .into_iter()
            // Plain values hold no file descriptors, the only case that fails.
            .filter_map(|(k, v)| OwnedValue::try_from(v).ok().map(|o| (k, o)))
            .collect()
    }
}

/// Reads a string out of an `a{sv}` value.
#[must_use]
pub fn value_str(v: &Value<'_>) -> Option<String> {
    match v {
        Value::Str(s) => Some(s.as_str().to_owned()),
        _ => None,
    }
}

/// Reads any integer out of an `a{sv}` value.
#[must_use]
pub fn value_i64(v: &Value<'_>) -> Option<i64> {
    match v {
        Value::U8(n) => Some(i64::from(*n)),
        Value::I16(n) => Some(i64::from(*n)),
        Value::U16(n) => Some(i64::from(*n)),
        Value::I32(n) => Some(i64::from(*n)),
        Value::U32(n) => Some(i64::from(*n)),
        Value::I64(n) => Some(*n),
        Value::U64(n) => i64::try_from(*n).ok(),
        _ => None,
    }
}

/// Reads a boolean out of an `a{sv}` value.
#[must_use]
pub fn value_bool(v: &Value<'_>) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

/// Reads a byte array out of an `a{sv}` value (`ay`, as `info.path`).
#[must_use]
pub fn value_bytes(v: &Value<'_>) -> Option<Vec<u8>> {
    match v {
        Value::Array(a) => a
            .iter()
            .map(|item| match item {
                Value::U8(b) => Some(*b),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// Reads an array of strings out of an `a{sv}` value.
#[must_use]
pub fn value_strings(v: &Value<'_>) -> Option<Vec<String>> {
    match v {
        Value::Array(a) => a
            .iter()
            .map(|item| match item {
                Value::Str(s) => Some(s.as_str().to_owned()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_match_the_contract() {
        assert_eq!(WireEntry::SIGNATURE.to_string(), "(ayyyxxxxixxssqays)");
        assert_eq!(WireCapabilities::SIGNATURE.to_string(), "(asasx)");
        assert_eq!(WireLocation::SIGNATURE.to_string(), "(sssa{sv})");
        assert_eq!(WireNearby::SIGNATURE.to_string(), "(sssq)");
        assert_eq!(WireWalkItem::SIGNATURE.to_string(), "(ay(ayyyxxxxixxssqays))");
        assert_eq!(WireDrive::SIGNATURE.to_string(), "(ssaya{sv})");
    }

    #[test]
    fn drive_ids_are_object_path_elements() {
        for id in ["mmcblk1p1", "sda1", "dm_2d3", "A", &"x".repeat(64)] {
            assert!(drive_info::is_valid_id(id), "{id}");
        }
        for id in ["", "sd-a", "../sda", "sda/1", "sda1 ", &"x".repeat(65), "äö"] {
            assert!(!drive_info::is_valid_id(id), "{id}");
        }
    }

    #[test]
    fn unknown_entry_uses_minus_one() {
        let e = WireEntry::unknown(b"a", entry_kind::FILE);
        assert_eq!(e.name, b"a".to_vec());
        assert_eq!(e.kind, entry_kind::FILE);
        assert_eq!(e.target_kind, entry_kind::UNKNOWN);
        assert_eq!(
            (e.size, e.mtime_ms, e.ctime_ms, e.atime_ms, e.mode, e.uid, e.gid),
            (-1, -1, -1, -1, -1, -1, -1)
        );
        assert_eq!(e.flags, 0);
        assert!(e.owner.is_empty() && e.group.is_empty() && e.etag.is_empty() && e.content_type.is_empty());
    }

    #[test]
    fn byte_options_and_owned_dictionaries() {
        let o = OptsBuilder::new().bytes("path", b"/a\xff").build();
        assert_eq!(value_bytes(&o["path"]), Some(b"/a\xff".to_vec()));
        assert_eq!(o["path"].value_signature().to_string(), "ay");
        let owned = OptsBuilder::new().bytes("path", b"/a").str("s", "x").build_owned();
        assert_eq!(owned.len(), 2);
        assert_eq!(value_bytes(&owned["path"]), Some(b"/a".to_vec()));
        assert_eq!(value_str(&owned["s"]).as_deref(), Some("x"));
        assert!(OptsBuilder::new().build_owned().is_empty());
    }

    #[test]
    fn value_i64_reads_every_integer_type() {
        assert_eq!(value_i64(&Value::from(7u8)), Some(7));
        assert_eq!(value_i64(&Value::from(-3i16)), Some(-3));
        assert_eq!(value_i64(&Value::from(7u16)), Some(7));
        assert_eq!(value_i64(&Value::from(-4i32)), Some(-4));
        assert_eq!(value_i64(&Value::from(4_000_000_000u32)), Some(4_000_000_000));
        assert_eq!(value_i64(&Value::from(-5i64)), Some(-5));
        assert_eq!(value_i64(&Value::from(9u64)), Some(9));
        assert_eq!(value_i64(&Value::from("9")), None);
    }

    #[test]
    fn opts_builder_values_read_back() {
        let o = OptsBuilder::new()
            .bool("b", true)
            .int("n", -5)
            .str("s", "x")
            .byte_arrays("a", &[b"p".to_vec()])
            .build();
        assert_eq!(o.len(), 4);
        assert_eq!(value_bool(&o["b"]), Some(true));
        assert_eq!(value_i64(&o["n"]), Some(-5));
        assert_eq!(value_str(&o["s"]).as_deref(), Some("x"));
        assert_eq!(value_i64(&o["s"]), None);
        assert_eq!(o["a"].value_signature().to_string(), "aay");
    }

    #[test]
    fn value_helpers_decode_arrays_and_reject_other_types() {
        let s = Value::from("x");
        assert_eq!(value_bool(&s), None);
        assert_eq!(value_strings(&s), None);
        assert_eq!(value_bytes(&s), None);
        assert_eq!(value_bytes(&Value::from(vec![1u8, 2])), Some(vec![1, 2]));
        assert_eq!(value_strings(&Value::from(vec!["a".to_owned()])), Some(vec!["a".to_owned()]));
        assert_eq!(value_i64(&Value::from(7u16)), Some(7));
        assert_eq!(value_i64(&Value::from(u64::MAX)), None);
    }
}
