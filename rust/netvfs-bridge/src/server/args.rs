// SPDX-License-Identifier: LGPL-2.1-or-later
//! Argument validation of the bridge protocol (SPEC-v2 XSEC-7, XB-10): the
//! port of the C++ bridge's `args.cpp` (netvfs 0.4). A method call becomes a
//! typed [`Call`]: every path is normalised ([`super::paths`]), every number
//! range-checked, every string length- and charset-checked, unknown option
//! keys are refused. File descriptors are checked later (they need the
//! descriptor).
//!
//! Errors: `InvalidName` for paths and link targets, `ProtocolError` for
//! everything else (the dispatch replies
//! `org.freedesktop.DBus.Error.InvalidArgs` for it), `Unsupported` for an
//! unknown method (`org.freedesktop.DBus.Error.UnknownMethod`).
//!
//! Secrets (the `ConnectAdHoc` secret, the keyboard-interactive answers of
//! `Answer`) are copied once, into [`Secret`]s, which wipe their bytes on
//! drop (XB-16, XSEC-6). zbus's received message and its decoding buffers
//! are not wiped (design §6.4).

use super::paths::{NPath, normalize};
use crate::status::Status;
use netvfs_bridge_proto::limits::{
    DECODE_MAX_DEPTH, DECODE_MAX_ELEMENTS, DEFAULT_LIST_BATCH, MAX_ANSWERS, MAX_ID, MAX_LIST_BATCH,
    MAX_OFFSET, MAX_PATH, MAX_READ, MAX_READ_AHEAD, MAX_SECRET, MAX_SHORT, MAX_TIME_MS, MAX_URL,
    MAX_WALK_DEPTH, MIN_TIME_MS,
};
use netvfs_bridge_proto::methods::find_method;
use netvfs_bridge_proto::{ErrorName, Lane, MethodInfo};
use std::collections::BTreeMap;
use std::fmt;
use std::os::fd::OwnedFd;
use zbus::Message;
use zbus::message::Body;
use zbus::zvariant::{self, Value};
use zeroize::Zeroizing;

/// Longest `Checksum` algorithm and `AddAccount` provider name.
const MAX_TOKEN: usize = 32;
/// Longest keyboard-interactive answer, in bytes.
const MAX_ANSWER_BYTES: usize = MAX_SHORT * 4;
/// Largest file mode an option may set.
const MAX_MODE: i64 = 0o7777;
/// Largest body of a call. The largest legitimate one is `ConnectAdHoc`
/// (64 KiB secret, a URL of 4096 UTF-16 units, short options), under 96 KiB.
/// A bound well below the 2 MiB message limit, because zvariant decodes a
/// byte array inside a variant into 64 bytes per byte (an `a{sv}` argument
/// of 2 MiB would take 128 MiB).
pub const MAX_CALL_BODY: usize = 128 * 1024;
/// The SMB security profiles `ConnectAdHoc` accepts.
const SECURITY_PROFILES: [&str; 3] = ["strict", "signed", "guest"];

/// A validated location id (`account:12`, `adhoc:3`): `[a-z0-9:-]{1,64}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocId(String);

impl LocId {
    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Secret bytes, wiped on drop; `Debug` never shows them.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// The bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The wiping container, taken.
    #[must_use]
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

/// `ConnectAdHoc` options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdHocOpts {
    /// `user`: the user name instead of the URL's.
    pub user: Option<String>,
    /// `security_profile` (SMB only): `strict`, `signed` or `guest`.
    pub security_profile: Option<String>,
}

/// `SetAttributes` changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttributeChanges {
    /// `mode`: 0..=0o7777.
    pub mode: Option<u32>,
    /// `mtimeMs`, ms since the epoch.
    pub mtime_ms: Option<i64>,
    /// `atimeMs`, ms since the epoch.
    pub atime_ms: Option<i64>,
}

/// `ServerCopy` and `CopyAcross` options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CopyOpts {
    /// Copy folders with their content.
    pub recursive: bool,
    /// Replace an existing target.
    pub replace: bool,
}

/// How `Upload` writes the target (XC-13).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Disposition {
    /// `create`: the target must not exist (default).
    #[default]
    CreateNew,
    /// `truncate`: replace the target's content.
    Truncate,
    /// `resume`: append at `offset`.
    Resume,
}

/// `Upload` and `Download` options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferOpts {
    /// First byte, in the local file and remotely.
    pub offset: i64,
    /// Upload: bytes to send (-1: to the end); Download: the length (-1: all).
    pub size: i64,
    /// Upload only.
    pub disposition: Disposition,
    /// Upload only: the mode of a created file.
    pub create_mode: Option<u32>,
    /// Upload only: the modification time to set, ms since the epoch.
    pub mtime_ms: Option<i64>,
}

impl Default for TransferOpts {
    fn default() -> Self {
        Self { offset: 0, size: -1, disposition: Disposition::CreateNew, create_mode: None, mtime_ms: None }
    }
}

/// `Walk` options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkOpts {
    /// -1: unlimited; 0: the root's children only.
    pub max_depth: i32,
    /// Follow symbolic links to folders.
    pub follow_symlinks: bool,
    /// Accepted and passed on; a no-op on the wire (design §7).
    pub post_order: bool,
}

impl Default for WalkOpts {
    fn default() -> Self {
        Self { max_depth: -1, follow_symlinks: false, post_order: false }
    }
}

/// One validated call of `org.netvfs.Bridge1`, one variant per method (XB-10).
#[derive(Debug)]
#[allow(missing_docs)] // the fields are the XB-10 arguments of the same names
pub enum Call {
    Hello {
        client: String,
    },
    GetConsent,
    RequestConsent,
    ListLocations,
    Capabilities {
        loc: LocId,
    },
    Disconnect {
        loc: LocId,
    },
    ConnectAdHoc {
        url: String,
        secret: Secret,
        opts: AdHocOpts,
    },
    ForgetAdHoc {
        loc: LocId,
    },
    Discover {
        on: bool,
    },
    /// `batch`: 1..=512 (0 on the wire is the default 256).
    List {
        loc: LocId,
        dir: NPath,
        lane: Lane,
        batch: u32,
    },
    Stat {
        loc: LocId,
        path: NPath,
        follow: bool,
        lane: Lane,
    },
    ReadLink {
        loc: LocId,
        path: NPath,
    },
    SpaceInfo {
        loc: LocId,
        path: NPath,
    },
    Checksum {
        loc: LocId,
        path: NPath,
        algorithm: String,
    },
    MakeDir {
        loc: LocId,
        path: NPath,
        exclusive: bool,
    },
    RemoveFile {
        loc: LocId,
        path: NPath,
    },
    RemoveDir {
        loc: LocId,
        path: NPath,
    },
    Rename {
        loc: LocId,
        from: NPath,
        to: NPath,
        replace: bool,
    },
    SetAttributes {
        loc: LocId,
        path: NPath,
        changes: AttributeChanges,
    },
    /// `target` verbatim (XC-12: not normalised, may be relative).
    MakeSymlink {
        loc: LocId,
        target: Vec<u8>,
        link: NPath,
    },
    MakeHardlink {
        loc: LocId,
        existing: NPath,
        link: NPath,
    },
    ServerCopy {
        loc: LocId,
        from: NPath,
        to: NPath,
        opts: CopyOpts,
    },
    OpenRead {
        loc: LocId,
        path: NPath,
        lane: Lane,
    },
    /// `max`: at most 1 MiB.
    Read {
        handle: u32,
        offset: i64,
        max: u32,
    },
    /// `bytes`: capped at 16 MiB (a hint).
    ReadAhead {
        handle: u32,
        offset: i64,
        bytes: i64,
    },
    Close {
        handle: u32,
    },
    Upload {
        loc: LocId,
        path: NPath,
        fd: OwnedFd,
        opts: TransferOpts,
        lane: Lane,
    },
    Download {
        loc: LocId,
        path: NPath,
        fd: OwnedFd,
        opts: TransferOpts,
        lane: Lane,
    },
    CopyAcross {
        loc: LocId,
        path: NPath,
        dest_loc: LocId,
        dest_path: NPath,
        opts: CopyOpts,
    },
    RemoveTree {
        loc: LocId,
        path: NPath,
    },
    Walk {
        loc: LocId,
        path: NPath,
        opts: WalkOpts,
    },
    Cancel {
        id: u32,
    },
    Answer {
        id: String,
        accept: bool,
        answers: Vec<Secret>,
    },
    OpenAccountSettings {
        loc: LocId,
    },
    AddAccount {
        provider: String,
    },
}

impl Call {
    /// The method's name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "Hello",
            Self::GetConsent => "GetConsent",
            Self::RequestConsent => "RequestConsent",
            Self::ListLocations => "ListLocations",
            Self::Capabilities { .. } => "Capabilities",
            Self::Disconnect { .. } => "Disconnect",
            Self::ConnectAdHoc { .. } => "ConnectAdHoc",
            Self::ForgetAdHoc { .. } => "ForgetAdHoc",
            Self::Discover { .. } => "Discover",
            Self::List { .. } => "List",
            Self::Stat { .. } => "Stat",
            Self::ReadLink { .. } => "ReadLink",
            Self::SpaceInfo { .. } => "SpaceInfo",
            Self::Checksum { .. } => "Checksum",
            Self::MakeDir { .. } => "MakeDir",
            Self::RemoveFile { .. } => "RemoveFile",
            Self::RemoveDir { .. } => "RemoveDir",
            Self::Rename { .. } => "Rename",
            Self::SetAttributes { .. } => "SetAttributes",
            Self::MakeSymlink { .. } => "MakeSymlink",
            Self::MakeHardlink { .. } => "MakeHardlink",
            Self::ServerCopy { .. } => "ServerCopy",
            Self::OpenRead { .. } => "OpenRead",
            Self::Read { .. } => "Read",
            Self::ReadAhead { .. } => "ReadAhead",
            Self::Close { .. } => "Close",
            Self::Upload { .. } => "Upload",
            Self::Download { .. } => "Download",
            Self::CopyAcross { .. } => "CopyAcross",
            Self::RemoveTree { .. } => "RemoveTree",
            Self::Walk { .. } => "Walk",
            Self::Cancel { .. } => "Cancel",
            Self::Answer { .. } => "Answer",
            Self::OpenAccountSettings { .. } => "OpenAccountSettings",
            Self::AddAccount { .. } => "AddAccount",
        }
    }

    /// The method's entry of the method table.
    #[must_use]
    pub fn method(&self) -> &'static MethodInfo {
        let name = self.name();
        // Every variant names a method of the table (tested); Hello is the
        // harmless stand-in that never happens.
        find_method(name).unwrap_or(&netvfs_bridge_proto::METHODS[0])
    }

    /// The lane the call runs in: the hint of the call where it has one,
    /// else the method's default (XB-12).
    #[must_use]
    pub fn lane(&self) -> Lane {
        match self {
            Self::List { lane, .. }
            | Self::Stat { lane, .. }
            | Self::OpenRead { lane, .. }
            | Self::Upload { lane, .. }
            | Self::Download { lane, .. } => *lane,
            _ => self.method().lane,
        }
    }

    /// XB-6: the call fails with `PermissionDenied` until the user granted
    /// consent (the core enforces it).
    #[must_use]
    pub fn needs_consent(&self) -> bool {
        self.method().needs_consent
    }
}

// ------------------------------------------------------------ entry point

/// Validates a method call of `org.netvfs.Bridge1`: method, signature, then
/// the arguments (the C++ `validateCall`). The caller has checked path and
/// interface.
///
/// # Errors
/// `Unsupported` for an unknown method, `ProtocolError` for a wrong
/// signature or argument, `InvalidName` for a bad path.
pub fn decode(msg: &Message) -> Result<Call, Status> {
    let header = msg.header();
    let member = header.member().map_or("", |m| m.as_str());
    let method = find_method(member).ok_or_else(|| Status::new(ErrorName::Unsupported, "No such method"))?;
    if *header.signature() != method.input {
        return Err(Status::invalid_args(format!("{member} takes ({})", method.input)));
    }
    let body = msg.body();
    if body.len() > MAX_CALL_BODY {
        return Err(Status::invalid_args("Arguments too large"));
    }
    decoder(method.name)(&body)
}

type Decoder = fn(&Body) -> Result<Call, Status>;

/// The rules, in the order of the method table (`args.cpp` `rules()`).
const DECODERS: [(&str, Decoder); 35] = [
    ("Hello", hello),
    ("GetConsent", |_| Ok(Call::GetConsent)),
    ("RequestConsent", |_| Ok(Call::RequestConsent)),
    ("ListLocations", |_| Ok(Call::ListLocations)),
    ("Capabilities", |b| loc_only(b).map(|loc| Call::Capabilities { loc })),
    ("Disconnect", |b| loc_only(b).map(|loc| Call::Disconnect { loc })),
    ("ConnectAdHoc", connect_ad_hoc),
    ("ForgetAdHoc", |b| loc_only(b).map(|loc| Call::ForgetAdHoc { loc })),
    ("Discover", |b| deserialize::<(bool,)>(b).map(|(on,)| Call::Discover { on })),
    ("List", list),
    ("Stat", stat),
    ("ReadLink", |b| loc_path(b).map(|(loc, path)| Call::ReadLink { loc, path })),
    ("SpaceInfo", |b| loc_path(b).map(|(loc, path)| Call::SpaceInfo { loc, path })),
    ("Checksum", checksum),
    ("MakeDir", make_dir),
    ("RemoveFile", |b| loc_path(b).map(|(loc, path)| Call::RemoveFile { loc, path })),
    ("RemoveDir", |b| loc_path(b).map(|(loc, path)| Call::RemoveDir { loc, path })),
    ("Rename", rename),
    ("SetAttributes", set_attributes),
    ("MakeSymlink", make_symlink),
    ("MakeHardlink", make_hardlink),
    ("ServerCopy", server_copy),
    ("OpenRead", open_read),
    ("Read", read),
    ("ReadAhead", read_ahead),
    ("Close", |b| deserialize::<(u32,)>(b).map(|(handle,)| Call::Close { handle })),
    ("Upload", upload),
    ("Download", download),
    ("CopyAcross", copy_across),
    ("RemoveTree", |b| loc_path(b).map(|(loc, path)| Call::RemoveTree { loc, path })),
    ("Walk", walk),
    ("Cancel", |b| deserialize::<(u32,)>(b).map(|(id,)| Call::Cancel { id })),
    ("Answer", answer),
    ("OpenAccountSettings", |b| loc_only(b).map(|loc| Call::OpenAccountSettings { loc })),
    ("AddAccount", add_account),
];

fn decoder(name: &str) -> Decoder {
    DECODERS.iter().find(|(n, _)| *n == name).map_or(unknown, |(_, d)| *d)
}

fn unknown(_: &Body) -> Result<Call, Status> {
    Err(Status::new(ErrorName::Unsupported, "No such method"))
}

fn deserialize<'b, T: zvariant::DynamicDeserialize<'b>>(body: &'b Body) -> Result<T, Status> {
    body.deserialize::<T>().map_err(|e| Status::invalid_args(format!("Malformed arguments: {e}")))
}

// ------------------------------------------------------------- building blocks

/// The length of `s` in UTF-16 code units, as the C++ bridge counted
/// (`QString::size`).
fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn short_string(s: String, index: usize, max: usize) -> Result<String, Status> {
    if utf16_len(&s) > max {
        return Err(Status::invalid_args(format!("Argument {index} is too long")));
    }
    Ok(s)
}

/// `[a-z0-9-]{1,max}`.
#[must_use]
pub fn is_valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// `[a-z0-9:-]{1,64}`: location ids (`account:12`, `adhoc:3`) and question
/// ids (`q7`).
#[must_use]
pub fn is_valid_location_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b':')
}

fn token(s: String, index: usize) -> Result<String, Status> {
    let s = short_string(s, index, MAX_TOKEN)?;
    if !is_valid_token(&s, MAX_TOKEN) {
        return Err(Status::invalid_args(format!("Argument {index} is not a valid name")));
    }
    Ok(s)
}

/// A location id argument.
///
/// # Errors
/// `ProtocolError` "Invalid location id".
pub fn location_id(s: String) -> Result<LocId, Status> {
    if !is_valid_location_id(&s) {
        return Err(Status::invalid_args("Invalid location id"));
    }
    Ok(LocId(s))
}

/// A lane hint: empty selects `fallback`.
///
/// # Errors
/// `ProtocolError` "Unknown lane".
pub fn lane_hint(hint: &str, fallback: Lane) -> Result<Lane, Status> {
    Lane::from_hint(hint, fallback).ok_or_else(|| Status::invalid_args("Unknown lane"))
}

fn offset(v: i64, index: usize) -> Result<i64, Status> {
    if !(0..=MAX_OFFSET).contains(&v) {
        return Err(Status::invalid_args(format!("Argument {index} is out of range")));
    }
    Ok(v)
}

fn loc_only(body: &Body) -> Result<LocId, Status> {
    let (loc,): (String,) = deserialize(body)?;
    location_id(loc)
}

fn loc_path(body: &Body) -> Result<(LocId, NPath), Status> {
    let (loc, path): (String, Vec<u8>) = deserialize(body)?;
    Ok((location_id(loc)?, normalize(&path)?))
}

// --------------------------------------------------------------- the methods

fn hello(body: &Body) -> Result<Call, Status> {
    let (client,): (String,) = deserialize(body)?;
    Ok(Call::Hello { client: short_string(client, 1, MAX_SHORT)? })
}

fn connect_ad_hoc(body: &Body) -> Result<Call, Status> {
    let (url, secret, opts): (String, &[u8], Options<'_>) = deserialize(body)?;
    let url = short_string(url, 1, MAX_URL)?;
    // XB-16: the only copy of the secret in our hands, wiped on drop.
    let secret = Secret(Zeroizing::new(secret.to_vec()));
    if secret.expose().len() > MAX_SECRET {
        return Err(Status::invalid_args("Secret too long"));
    }
    let mut parsed = AdHocOpts::default();
    each_option(&opts, |key, value| ad_hoc_option(key, value, &mut parsed))?;
    Ok(Call::ConnectAdHoc { url, secret, opts: parsed })
}

fn list(body: &Body) -> Result<Call, Status> {
    let (loc, dir, lane, batch): (String, Vec<u8>, String, u32) = deserialize(body)?;
    let (loc, dir) = (location_id(loc)?, normalize(&dir)?);
    let lane = lane_hint(&lane, Lane::Interactive)?;
    let batch = if batch == 0 { DEFAULT_LIST_BATCH } else { batch };
    if batch > MAX_LIST_BATCH {
        return Err(Status::invalid_args(format!("Batch size above {MAX_LIST_BATCH}")));
    }
    Ok(Call::List { loc, dir, lane, batch })
}

fn stat(body: &Body) -> Result<Call, Status> {
    let (loc, path, follow, lane): (String, Vec<u8>, bool, String) = deserialize(body)?;
    let (loc, path) = (location_id(loc)?, normalize(&path)?);
    Ok(Call::Stat { loc, path, follow, lane: lane_hint(&lane, Lane::Interactive)? })
}

fn checksum(body: &Body) -> Result<Call, Status> {
    let (loc, path, algorithm): (String, Vec<u8>, String) = deserialize(body)?;
    let (loc, path) = (location_id(loc)?, normalize(&path)?);
    Ok(Call::Checksum { loc, path, algorithm: token(algorithm, 3)? })
}

fn make_dir(body: &Body) -> Result<Call, Status> {
    let (loc, path, exclusive): (String, Vec<u8>, bool) = deserialize(body)?;
    Ok(Call::MakeDir { loc: location_id(loc)?, path: normalize(&path)?, exclusive })
}

fn rename(body: &Body) -> Result<Call, Status> {
    let (loc, from, to, replace): (String, Vec<u8>, Vec<u8>, bool) = deserialize(body)?;
    Ok(Call::Rename { loc: location_id(loc)?, from: normalize(&from)?, to: normalize(&to)?, replace })
}

fn set_attributes(body: &Body) -> Result<Call, Status> {
    let (loc, path, opts): (String, Vec<u8>, Options<'_>) = deserialize(body)?;
    let (loc, path) = (location_id(loc)?, normalize(&path)?);
    let mut changes = AttributeChanges::default();
    each_option(&opts, |key, value| attribute_option(key, value, &mut changes))?;
    Ok(Call::SetAttributes { loc, path, changes })
}

/// XC-12: the link target is stored verbatim (not normalised, may be
/// relative); only its size and NUL bytes are checked.
fn make_symlink(body: &Body) -> Result<Call, Status> {
    let (loc, target, link): (String, Vec<u8>, Vec<u8>) = deserialize(body)?;
    let loc = location_id(loc)?;
    if target.is_empty() || target.len() > MAX_PATH || target.contains(&0) {
        return Err(Status::invalid_name("Invalid link target"));
    }
    Ok(Call::MakeSymlink { loc, target, link: normalize(&link)? })
}

fn make_hardlink(body: &Body) -> Result<Call, Status> {
    let (loc, existing, link): (String, Vec<u8>, Vec<u8>) = deserialize(body)?;
    Ok(Call::MakeHardlink {
        loc: location_id(loc)?,
        existing: normalize(&existing)?,
        link: normalize(&link)?,
    })
}

fn server_copy(body: &Body) -> Result<Call, Status> {
    let (loc, from, to, opts): (String, Vec<u8>, Vec<u8>, Options<'_>) = deserialize(body)?;
    let (loc, from, to) = (location_id(loc)?, normalize(&from)?, normalize(&to)?);
    Ok(Call::ServerCopy { loc, from, to, opts: copy_options(&opts)? })
}

fn open_read(body: &Body) -> Result<Call, Status> {
    let (loc, path, lane): (String, Vec<u8>, String) = deserialize(body)?;
    let (loc, path) = (location_id(loc)?, normalize(&path)?);
    Ok(Call::OpenRead { loc, path, lane: lane_hint(&lane, Lane::Stream)? })
}

fn read(body: &Body) -> Result<Call, Status> {
    let (handle, start, max): (u32, i64, u32) = deserialize(body)?;
    let offset = offset(start, 2)?;
    if max > MAX_READ {
        return Err(Status::invalid_args("Read size above 1 MiB"));
    }
    Ok(Call::Read { handle, offset, max })
}

fn read_ahead(body: &Body) -> Result<Call, Status> {
    let (handle, start, bytes): (u32, i64, i64) = deserialize(body)?;
    let offset = offset(start, 2)?;
    // A hint: capped, not refused.
    let bytes = self::offset(bytes, 3)?.min(MAX_READ_AHEAD);
    Ok(Call::ReadAhead { handle, offset, bytes })
}

fn transfer(body: &Body, upload: bool) -> Result<(LocId, NPath, OwnedFd, TransferOpts, Lane), Status> {
    let (loc, path, fd, opts): (String, Vec<u8>, zvariant::OwnedFd, Options<'_>) = deserialize(body)?;
    let (loc, path) = (location_id(loc)?, normalize(&path)?);
    let mut parsed = TransferOpts::default();
    let mut lane = Lane::Bulk;
    each_option(&opts, |key, value| transfer_option(key, value, upload, &mut parsed, &mut lane))?;
    if parsed.disposition == Disposition::Resume && parsed.offset == 0 {
        return Err(Status::invalid_args("Resume needs an offset"));
    }
    Ok((loc, path, fd.into(), parsed, lane))
}

fn upload(body: &Body) -> Result<Call, Status> {
    let (loc, path, fd, opts, lane) = transfer(body, true)?;
    Ok(Call::Upload { loc, path, fd, opts, lane })
}

fn download(body: &Body) -> Result<Call, Status> {
    let (loc, path, fd, opts, lane) = transfer(body, false)?;
    Ok(Call::Download { loc, path, fd, opts, lane })
}

fn copy_across(body: &Body) -> Result<Call, Status> {
    let (loc, path, dest_loc, dest_path, opts): (String, Vec<u8>, String, Vec<u8>, Options<'_>) =
        deserialize(body)?;
    let (loc, path) = (location_id(loc)?, normalize(&path)?);
    let (dest_loc, dest_path) = (location_id(dest_loc)?, normalize(&dest_path)?);
    Ok(Call::CopyAcross { loc, path, dest_loc, dest_path, opts: copy_options(&opts)? })
}

fn walk(body: &Body) -> Result<Call, Status> {
    let (loc, path, opts): (String, Vec<u8>, Options<'_>) = deserialize(body)?;
    let (loc, path) = (location_id(loc)?, normalize(&path)?);
    let mut parsed = WalkOpts::default();
    each_option(&opts, |key, value| walk_option(key, value, &mut parsed))?;
    Ok(Call::Walk { loc, path, opts: parsed })
}

fn answer(body: &Body) -> Result<Call, Status> {
    let (id, opts): (String, Options<'_>) = deserialize(body)?;
    let id = short_string(id, 1, MAX_ID)?;
    if !is_valid_location_id(&id) {
        return Err(Status::invalid_args("Invalid question id"));
    }
    let mut accept = false;
    let mut answers = Vec::new();
    each_option(&opts, |key, value| answer_option(key, value, &mut accept, &mut answers))?;
    Ok(Call::Answer { id, accept, answers })
}

fn add_account(body: &Body) -> Result<Call, Status> {
    let (provider,): (String,) = deserialize(body)?;
    Ok(Call::AddAccount { provider: token(provider, 1)? })
}

// ----------------------------------------------------------------- options

/// An `a{sv}` argument, in key order (as the C++ `QVariantMap`).
type Options<'a> = BTreeMap<String, Value<'a>>;

fn too_complex() -> Status {
    Status::invalid_args("Argument too complex")
}

/// `wire.h` `DecodeLimits` over a decoded value: containers nest at most
/// [`DECODE_MAX_DEPTH`] deep, and hold at most [`DECODE_MAX_ELEMENTS`]
/// elements (byte arrays excepted). `depth` counts as the C++ decoder did.
fn check_value(value: &Value<'_>, depth: usize) -> Result<(), Status> {
    let deeper = depth.checked_add(1).ok_or_else(too_complex)?;
    let container = matches!(value, Value::Value(_) | Value::Array(_) | Value::Dict(_) | Value::Structure(_));
    if container && depth >= DECODE_MAX_DEPTH {
        return Err(too_complex());
    }
    match value {
        Value::Value(inner) => check_value(inner, deeper),
        Value::Array(array) if array.element_signature() == "y" => Ok(()),
        Value::Array(array) => check_items(array.inner().iter(), deeper),
        Value::Dict(dict) => check_items(dict.iter().map(|(_, v)| v), deeper),
        Value::Structure(s) => check_items(s.fields().iter(), deeper),
        _ => Ok(()),
    }
}

fn check_items<'v, 'a: 'v>(items: impl Iterator<Item = &'v Value<'a>>, depth: usize) -> Result<(), Status> {
    for (count, item) in items.enumerate() {
        if count >= DECODE_MAX_ELEMENTS {
            return Err(too_complex());
        }
        check_value(item, depth)?;
    }
    Ok(())
}

/// Runs `handle` on each option, in key order, with nested variants
/// unwrapped; first checks the decode limits.
fn each_option<'a>(
    opts: &Options<'a>,
    mut handle: impl FnMut(&str, &Value<'a>) -> Result<(), Status>,
) -> Result<(), Status> {
    if opts.len() > DECODE_MAX_ELEMENTS {
        return Err(too_complex());
    }
    // The values are the contents of the dict's variants: depth 2 for the
    // C++ decoder (the array is 0, its entries and their variants 1).
    for value in opts.values() {
        check_value(value, 2)?;
    }
    for (key, value) in opts {
        handle(key, unwrap_variant(value))?;
    }
    Ok(())
}

/// The value inside nested variants (the C++ decoder unwrapped them).
fn unwrap_variant<'v, 'a>(mut value: &'v Value<'a>) -> &'v Value<'a> {
    while let Value::Value(inner) = value {
        value = inner;
    }
    value
}

fn unknown_option(key: &str) -> Status {
    let shown: String = key.chars().take(MAX_SHORT).collect();
    Status::invalid_args(format!("Unknown option \"{shown}\""))
}

/// Any integer type, as the C++ bridge accepted (`toInt64`).
fn as_int(value: &Value<'_>) -> Option<i64> {
    match value {
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

fn as_str<'v>(value: &'v Value<'_>) -> Option<&'v str> {
    match value {
        Value::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

fn option_bool(key: &str, value: &Value<'_>) -> Result<bool, Status> {
    match value {
        Value::Bool(b) => Ok(*b),
        _ => Err(Status::invalid_args(format!("Option \"{key}\" must be a boolean"))),
    }
}

fn option_int(key: &str, value: &Value<'_>, min: i64, max: i64) -> Result<i64, Status> {
    let v =
        as_int(value).ok_or_else(|| Status::invalid_args(format!("Option \"{key}\" must be an integer")))?;
    if !(min..=max).contains(&v) {
        return Err(Status::invalid_args(format!("Option \"{key}\" is out of range")));
    }
    Ok(v)
}

fn option_mode(key: &str, value: &Value<'_>) -> Result<u32, Status> {
    let mode = option_int(key, value, 0, MAX_MODE)?;
    u32::try_from(mode).ok().ok_or_else(|| Status::invalid_args(format!("Option \"{key}\" is out of range")))
}

fn option_time(key: &str, value: &Value<'_>) -> Result<i64, Status> {
    option_int(key, value, MIN_TIME_MS, MAX_TIME_MS)
}

fn attribute_option(key: &str, value: &Value<'_>, changes: &mut AttributeChanges) -> Result<(), Status> {
    match key {
        "mode" => changes.mode = Some(option_mode(key, value)?),
        "mtimeMs" => changes.mtime_ms = Some(option_time(key, value)?),
        "atimeMs" => changes.atime_ms = Some(option_time(key, value)?),
        _ => return Err(unknown_option(key)),
    }
    Ok(())
}

fn copy_options(opts: &Options<'_>) -> Result<CopyOpts, Status> {
    let mut parsed = CopyOpts::default();
    each_option(opts, |key, value| {
        match key {
            "recursive" => parsed.recursive = option_bool(key, value)?,
            "replace" => parsed.replace = option_bool(key, value)?,
            _ => return Err(unknown_option(key)),
        }
        Ok(())
    })?;
    Ok(parsed)
}

fn walk_option(key: &str, value: &Value<'_>, opts: &mut WalkOpts) -> Result<(), Status> {
    match key {
        "maxDepth" => {
            let depth = option_int(key, value, -1, MAX_WALK_DEPTH)?;
            opts.max_depth = i32::try_from(depth).ok().ok_or_else(too_complex)?;
        }
        "followSymlinks" => opts.follow_symlinks = option_bool(key, value)?,
        "postOrder" => opts.post_order = option_bool(key, value)?,
        _ => return Err(unknown_option(key)),
    }
    Ok(())
}

fn disposition(key: &str, value: &Value<'_>) -> Result<Disposition, Status> {
    match as_str(value) {
        Some("create") => Ok(Disposition::CreateNew),
        Some("truncate") => Ok(Disposition::Truncate),
        Some("resume") => Ok(Disposition::Resume),
        _ => Err(Status::invalid_args(format!("Option \"{key}\" must be create, truncate or resume"))),
    }
}

/// Upload and Download share the keys; Download refuses the write-only ones.
fn transfer_option(
    key: &str,
    value: &Value<'_>,
    upload: bool,
    opts: &mut TransferOpts,
    lane: &mut Lane,
) -> Result<(), Status> {
    match (key, upload) {
        ("offset", _) => opts.offset = option_int(key, value, 0, MAX_OFFSET)?,
        ("size", _) => opts.size = option_int(key, value, -1, MAX_OFFSET)?,
        ("lane", _) => {
            let hint = as_str(value)
                .ok_or_else(|| Status::invalid_args(format!("Option \"{key}\" must be a string")))?;
            *lane = lane_hint(hint, *lane)?;
        }
        ("disposition", true) => opts.disposition = disposition(key, value)?,
        ("createMode", true) => opts.create_mode = Some(option_mode(key, value)?),
        ("mtimeMs", true) => opts.mtime_ms = Some(option_time(key, value)?),
        _ => return Err(unknown_option(key)),
    }
    Ok(())
}

fn ad_hoc_option(key: &str, value: &Value<'_>, opts: &mut AdHocOpts) -> Result<(), Status> {
    let s = as_str(value)
        .filter(|s| utf16_len(s) <= MAX_SHORT)
        .ok_or_else(|| Status::invalid_args(format!("Option \"{key}\" must be a short string")))?;
    match key {
        "user" if s.contains('\0') => Err(Status::invalid_args("Option \"user\" contains NUL")),
        "user" => {
            opts.user = (!s.is_empty()).then(|| s.to_owned());
            Ok(())
        }
        "security_profile" if !SECURITY_PROFILES.contains(&s) => {
            Err(Status::invalid_args("Unknown security profile"))
        }
        "security_profile" => {
            opts.security_profile = Some(s.to_owned());
            Ok(())
        }
        _ => Err(unknown_option(key)),
    }
}

fn answer_option(
    key: &str,
    value: &Value<'_>,
    accept: &mut bool,
    answers: &mut Vec<Secret>,
) -> Result<(), Status> {
    match key {
        "accept" => {
            *accept = option_bool(key, value)?;
            Ok(())
        }
        "answers" => {
            *answers = answer_list(value)?;
            Ok(())
        }
        _ => Err(unknown_option(key)),
    }
}

/// The keyboard-interactive answers: an array of byte arrays (`aay`, or
/// `av` of `ay`), at most [`MAX_ANSWERS`], each at most 1 KiB.
fn answer_list(value: &Value<'_>) -> Result<Vec<Secret>, Status> {
    let items = match value {
        Value::Array(a) if a.element_signature() != "y" && a.element_signature() != "s" => a.inner(),
        _ => return Err(Status::invalid_args("Option \"answers\" must be an array of byte arrays")),
    };
    if items.len() > MAX_ANSWERS {
        return Err(Status::invalid_args("Too many answers"));
    }
    items.iter().map(|item| answer_bytes(unwrap_variant(item))).collect()
}

fn answer_bytes(item: &Value<'_>) -> Result<Secret, Status> {
    let invalid = || Status::invalid_args("Invalid answer");
    let Value::Array(bytes) = item else { return Err(invalid()) };
    if bytes.element_signature() != "y" || bytes.len() > MAX_ANSWER_BYTES {
        return Err(invalid());
    }
    let mut secret = Zeroizing::new(Vec::with_capacity(bytes.len()));
    for b in bytes.inner() {
        match b {
            Value::U8(b) => secret.push(*b),
            _ => return Err(invalid()),
        }
    }
    Ok(Secret(secret))
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
