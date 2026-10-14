// SPDX-License-Identifier: LGPL-2.1-or-later
//! The values of `src/core/types.h` as a Rust backend sees them: entries
//! (XC-2), capabilities (XC-5), connection parameters, credentials, prompts
//! (XC-15), attributes (XC-11), write options (XC-13, XC-23) and space
//! (XC-19). Paths and names are protocol bytes (`Names::encode`, XC-4);
//! "unknown" is `None` where C++ has -1 or an invalid date.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::Zeroizing;

/// `NetVfs::EntryType`; the values are the C++ enum's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum EntryType {
    /// Not known.
    #[default]
    Unknown = 0,
    /// A regular file.
    File = 1,
    /// A folder.
    Directory = 2,
    /// A symbolic link.
    Symlink = 3,
    /// Anything else (device, FIFO, socket).
    Special = 4,
}

impl EntryType {
    /// The C++ enum's value (`nvb_entry.type`).
    #[must_use]
    pub const fn raw(self) -> u8 {
        self as u8
    }
}

/// `NetVfs::EntryFlags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EntryFlags(u16);

impl EntryFlags {
    /// No flag.
    pub const NONE: Self = Self(0);
    /// SMB hidden attribute (dot names are not flagged).
    pub const HIDDEN: Self = Self(0x0001);
    /// SMB read-only attribute.
    pub const READ_ONLY: Self = Self(0x0002);
    /// SMB system attribute.
    pub const SYSTEM: Self = Self(0x0004);
    /// XC-4: the name is not well-formed UTF-8.
    pub const NAME_NOT_UTF8: Self = Self(0x0008);
    /// A symlink whose target type could not be determined.
    pub const TARGET_UNKNOWN: Self = Self(0x0010);

    /// The bits (`nvb_entry.flags`).
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether every flag of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// These flags and those of `other`.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// `NetVfs::Entry` (XC-2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Entry {
    /// The name, protocol bytes (XC-4).
    pub name: Vec<u8>,
    /// Its type.
    pub kind: EntryType,
    /// For a symlink, its target's type when resolved (XC-6).
    pub target_kind: EntryType,
    /// Flags.
    pub flags: EntryFlags,
    /// Permission bits (`& 0o7777`).
    pub mode: Option<u32>,
    /// Size in bytes.
    pub size: Option<u64>,
    /// Modification time, milliseconds since the epoch (UTC).
    pub mtime_ms: Option<i64>,
    /// Creation time.
    pub ctime_ms: Option<i64>,
    /// Access time.
    pub atime_ms: Option<i64>,
    /// Owner id.
    pub uid: Option<u64>,
    /// Group id.
    pub gid: Option<u64>,
    /// Owner name, when the server gives one.
    pub owner: String,
    /// Group name, when the server gives one.
    pub group: String,
    /// Opaque change token; empty if none.
    pub etag: Vec<u8>,
    /// Server-declared content type; advisory only.
    pub content_type: String,
}

macro_rules! capabilities {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        /// `NetVfs::Capability` (XC-5).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Capability {
            $($(#[$doc])* $name,)*
        }

        impl Capability {
            /// Every capability, in the order of `src/core/types.h`.
            pub const ALL: [Self; capabilities!(@count $($name)*)] = [$(Self::$name,)*];

            /// The stable name (`capabilityName()`, XB-9).
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$name => stringify!($name),)*
                }
            }
        }
    };
    (@count) => { 0 };
    (@count $head:ident $($tail:ident)*) => { 1 + capabilities!(@count $($tail)*) };
}

capabilities! {
    /// `makeSymlink`, `readLink`, symlink entries.
    Symlinks,
    /// `makeHardlink`.
    Hardlinks,
    /// Permission bits in entries and `setAttributes`.
    PosixModes,
    /// Owner and group in entries.
    Ownership,
    /// `setAttributes` with a modification time.
    SetModified,
    /// Upload and write options apply the modification time.
    SetModifiedOnUpload,
    /// `openRead`.
    ReadHandles,
    /// Ranged reads without reopening per call.
    EfficientRanges,
    /// `openWrite` with `Resume`.
    WriteResume,
    /// A write is atomic: no temporary name needed.
    AtomicPut,
    /// `rename(Replace)` is atomic.
    AtomicReplace,
    /// `rename(NoReplace)` is enforced by the server.
    NativeNoReplace,
    /// `copy` of a file.
    ServerCopy,
    /// `copy` of a folder tree.
    ServerCopyRecursive,
    /// A native tree delete exists (XC-9).
    RecursiveDelete,
    /// `spaceInfo`.
    SpaceInfo,
    /// `checksum`.
    Checksums,
    /// Names compare case-insensitively.
    CaseInsensitive,
    /// The name rules of `Paths::checkWindowsPath` apply.
    WindowsNames,
    /// SMB server mode can list shares.
    ShareEnumeration,
    /// XS-9.
    ShellExec,
    /// Entries carry an etag.
    ETags,
}

impl Capability {
    /// The capability of a stable name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

/// `NetVfs::Capabilities` (XC-5): valid after `authenticate`, stable for
/// the connection's life.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// The capabilities.
    pub flags: BTreeSet<Capability>,
    /// Algorithms of `checksum` (`sha256`, …); empty without `Checksums`.
    pub checksum_algorithms: Vec<String>,
    /// The longest name the server takes, in bytes.
    pub max_name_bytes: Option<u64>,
}

impl Capabilities {
    /// Whether `c` is reported.
    #[must_use]
    pub fn has(&self, c: Capability) -> bool {
        self.flags.contains(&c)
    }

    /// The names of the flags, sorted as `Capabilities::names()` sorts them.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.flags.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        names
    }
}

/// A typed value of `ConnectionParams::options` (`nvb_value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `QString`.
    Str(String),
    /// `bool`.
    Bool(bool),
    /// `qlonglong`.
    Int(i64),
    /// `QByteArray`.
    Bytes(Vec<u8>),
    /// `QStringList`.
    StrList(Vec<String>),
}

/// Options: keys are unique and sorted.
pub type ValueMap = BTreeMap<String, Value>;

/// `NetVfs::ConnectionParams`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Params {
    /// Backend provider (`sftp`, `smb`, …).
    pub provider: String,
    /// Host name or address.
    pub host: String,
    /// 0: the protocol's default.
    pub port: i32,
    /// User name.
    pub username: String,
    /// Provider options (`share`, `host_key`, …), without the
    /// `netvfs/<provider>/` prefix.
    pub options: ValueMap,
    /// Connect timeout.
    pub connect_timeout_ms: i32,
    /// Request timeout.
    pub request_timeout_ms: i32,
}

impl Params {
    /// The option `key` as text: a string as it is, a bool as `true` or
    /// `false`, a number in decimal (`ConnectionParams::option`); `None`
    /// when it is not set or is bytes or a list.
    #[must_use]
    pub fn option(&self, key: &str) -> Option<String> {
        match self.options.get(key)? {
            Value::Str(s) => Some(s.clone()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Int(n) => Some(n.to_string()),
            Value::Bytes(_) | Value::StrList(_) => None,
        }
    }

    /// The option `key` as a flag: `true` or `1` (`ConnectionParams::flag`).
    #[must_use]
    pub fn flag(&self, key: &str) -> bool {
        self.option(key).is_some_and(|v| v == "true" || v == "1")
    }
}

/// `NetVfs::Credentials` and the SMB domain. The secret is wiped when this
/// goes (SEC-5) and never printed.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Credentials {
    /// User name.
    pub user: String,
    /// Password, or `netvfs-key-v1:` and a base64 key (SPEC-sftp 2).
    pub secret: Zeroizing<Vec<u8>>,
    /// SMB only, may be empty.
    pub domain: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("secret", &format_args!("<{} bytes>", self.secret.len()))
            .field("domain", &self.domain)
            .finish()
    }
}

/// The server identity seen during `connect` (XC-16): an SSH host key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerIdentity {
    /// Key algorithm (`ssh-ed25519`).
    pub algorithm: String,
    /// The key blob.
    pub public_key: Vec<u8>,
    /// `SHA256:` and unpadded base64; empty lets C++ compute it.
    pub fingerprint: String,
}

/// One keyboard-interactive prompt (XC-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    /// The question.
    pub text: String,
    /// Whether the answer may be shown.
    pub echo: bool,
}

/// What the server asks for, keyboard-interactive (XC-15).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PromptRequest {
    /// The method's name.
    pub name: String,
    /// The server's instruction.
    pub instruction: String,
    /// One per answer expected.
    pub prompts: Vec<Prompt>,
}

/// `NetVfs::ListOptions` (XC-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListOptions {
    /// Entries per batch at most; at least 1.
    pub batch_size: usize,
    /// Stat each symlink target to fill `target_kind`.
    pub resolve_symlink_types: bool,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self { batch_size: 256, resolve_symlink_types: false }
    }
}

/// `NetVfs::RenameMode` (XC-10), also the mode of `copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RenameMode {
    /// An existing target is `AlreadyExists`.
    #[default]
    NoReplace,
    /// An existing file is replaced; a folder is `AlreadyExists`.
    Replace,
}

/// `NetVfs::AttributeChanges` (XC-11); `None` leaves a field unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attributes {
    /// Permission bits; more than `0o7777` is invalid.
    pub mode: Option<u32>,
    /// Modification time, ms since the epoch.
    pub mtime_ms: Option<i64>,
    /// Access time, ms since the epoch.
    pub atime_ms: Option<i64>,
}

/// `WriteOptions::Disposition` (XC-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Disposition {
    /// An existing file is `AlreadyExists`.
    #[default]
    CreateNew,
    /// Creates or truncates.
    Truncate,
    /// Appends at `resume_offset`, which must be the file's size.
    Resume,
}

/// `NetVfs::WriteOptions` (XC-13, XC-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriteOptions {
    /// What happens to an existing file.
    pub disposition: Disposition,
    /// Mode of a new file; `None`: the backend's default.
    pub create_mode: Option<u32>,
    /// `Resume`: the remote size the write continues at.
    pub resume_offset: u64,
    /// The size the file will have, when known.
    pub expected_size: Option<u64>,
    /// Applied on commit (`SetModified`, `SetModifiedOnUpload`).
    pub mtime_ms: Option<i64>,
}

/// `NetVfs::SpaceInfo` (XC-19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpaceInfo {
    /// Free bytes.
    pub free: Option<u64>,
    /// Total bytes.
    pub total: Option<u64>,
    /// Used bytes.
    pub used: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_types_have_the_cpp_values() {
        let raw: Vec<u8> = [
            EntryType::Unknown,
            EntryType::File,
            EntryType::Directory,
            EntryType::Symlink,
            EntryType::Special,
        ]
        .iter()
        .map(|t| t.raw())
        .collect();
        assert_eq!(raw, [0, 1, 2, 3, 4]);
        assert_eq!(EntryType::default(), EntryType::Unknown);
    }

    #[test]
    fn flags_have_the_cpp_bits_and_combine() {
        let bits: Vec<u16> = [
            EntryFlags::HIDDEN,
            EntryFlags::READ_ONLY,
            EntryFlags::SYSTEM,
            EntryFlags::NAME_NOT_UTF8,
            EntryFlags::TARGET_UNKNOWN,
        ]
        .iter()
        .map(|f| f.bits())
        .collect();
        assert_eq!(bits, [1, 2, 4, 8, 16]);
        let both = EntryFlags::HIDDEN.union(EntryFlags::SYSTEM);
        assert_eq!(both.bits(), 5);
        assert!(both.contains(EntryFlags::HIDDEN));
        assert!(both.contains(EntryFlags::SYSTEM));
        assert!(both.contains(both));
        assert!(!both.contains(EntryFlags::READ_ONLY));
        assert!(!EntryFlags::HIDDEN.contains(both));
        assert!(both.contains(EntryFlags::NONE));
        assert_eq!(EntryFlags::default(), EntryFlags::NONE);
    }

    // The 22 names of capabilityName() (src/core/types.cpp), in order.
    #[test]
    fn capabilities_are_the_cpp_names() {
        let names: Vec<&str> = Capability::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            names,
            [
                "Symlinks",
                "Hardlinks",
                "PosixModes",
                "Ownership",
                "SetModified",
                "SetModifiedOnUpload",
                "ReadHandles",
                "EfficientRanges",
                "WriteResume",
                "AtomicPut",
                "AtomicReplace",
                "NativeNoReplace",
                "ServerCopy",
                "ServerCopyRecursive",
                "RecursiveDelete",
                "SpaceInfo",
                "Checksums",
                "CaseInsensitive",
                "WindowsNames",
                "ShareEnumeration",
                "ShellExec",
                "ETags",
            ]
        );
        for c in Capability::ALL {
            assert_eq!(Capability::parse(c.as_str()), Some(c));
        }
        assert_eq!(Capability::parse("symlinks"), None);
    }

    #[test]
    fn capability_names_are_sorted_by_name() {
        let caps = Capabilities {
            flags: [Capability::Symlinks, Capability::AtomicPut, Capability::ETags].into(),
            ..Capabilities::default()
        };
        assert_eq!(caps.names(), ["AtomicPut", "ETags", "Symlinks"]);
        assert!(caps.has(Capability::ETags));
        assert!(!caps.has(Capability::Hardlinks));
        assert!(Capabilities::default().names().is_empty());
    }

    #[test]
    fn options_as_text_and_flags() {
        let mut p = Params::default();
        p.options.insert("s".into(), Value::Str("on".into()));
        p.options.insert("t".into(), Value::Str("true".into()));
        p.options.insert("one".into(), Value::Str("1".into()));
        p.options.insert("b".into(), Value::Bool(true));
        p.options.insert("f".into(), Value::Bool(false));
        p.options.insert("n".into(), Value::Int(-3));
        p.options.insert("i".into(), Value::Int(1));
        p.options.insert("raw".into(), Value::Bytes(vec![b'1']));
        p.options.insert("l".into(), Value::StrList(vec!["true".into()]));
        assert_eq!(p.option("s").as_deref(), Some("on"));
        assert_eq!(p.option("b").as_deref(), Some("true"));
        assert_eq!(p.option("f").as_deref(), Some("false"));
        assert_eq!(p.option("n").as_deref(), Some("-3"));
        assert_eq!((p.option("raw"), p.option("l"), p.option("missing")), (None, None, None));
        let flags: Vec<bool> =
            ["s", "t", "one", "b", "f", "n", "i", "raw", "l", "missing"].iter().map(|k| p.flag(k)).collect();
        assert_eq!(flags, [false, true, true, true, false, false, true, false, false, false]);
    }

    #[test]
    fn credentials_never_print_the_secret() {
        let c = Credentials {
            user: "alice".into(),
            secret: Zeroizing::new(b"hunter2".to_vec()),
            domain: "WORK".into(),
        };
        let printed = format!("{c:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
        assert!(printed.contains("<7 bytes>") && printed.contains("alice") && printed.contains("WORK"));
    }

    #[test]
    fn defaults() {
        assert_eq!(ListOptions::default(), ListOptions { batch_size: 256, resolve_symlink_types: false });
        assert_eq!(RenameMode::default(), RenameMode::NoReplace);
        assert_eq!(Disposition::default(), Disposition::CreateNew);
        let w = WriteOptions::default();
        assert_eq!((w.create_mode, w.resume_offset, w.expected_size, w.mtime_ms), (None, 0, None, None));
    }
}
