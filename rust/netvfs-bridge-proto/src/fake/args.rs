// SPDX-License-Identifier: LGPL-2.1-or-later
//! Argument validation as the C++ bridge does it (`args.cpp`): malformed call is `InvalidArgs`, bad
//! path `InvalidName`.

use super::fail::Fail;
use super::tree::normalize;
use crate::limits::{
    DEFAULT_LIST_BATCH, MAX_ANSWERS, MAX_ID, MAX_LIST_BATCH, MAX_OFFSET, MAX_READ, MAX_SECRET, MAX_SHORT,
    MAX_TIME_MS, MAX_URL, MAX_WALK_DEPTH, MIN_TIME_MS,
};
use crate::methods::Lane;
use crate::wire::{value_bool, value_bytes, value_i64, value_str};
use std::collections::HashMap;
use zbus::zvariant::OwnedValue;

pub type Dict = HashMap<String, OwnedValue>;

pub fn location(id: &str) -> Result<String, Fail> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b':');
    if ok { Ok(id.to_owned()) } else { Err(Fail::args("Invalid location id")) }
}

pub fn drive(id: &str) -> Result<String, Fail> {
    if crate::wire::drive_info::is_valid_id(id) {
        Ok(id.to_owned())
    } else {
        Err(Fail::args("Invalid drive id"))
    }
}

pub fn path(raw: &[u8]) -> Result<Vec<u8>, Fail> {
    Ok(normalize(raw)?)
}

/// Lane names; empty selects the method's default.
pub fn lane(given: &str, default: Lane) -> Result<Lane, Fail> {
    Lane::from_hint(given, default).ok_or_else(|| Fail::args("Unknown lane"))
}

pub fn list_batch(n: u32) -> Result<usize, Fail> {
    if n > MAX_LIST_BATCH {
        return Err(Fail::args(&format!("Batch size above {MAX_LIST_BATCH}")));
    }
    let n = if n == 0 { DEFAULT_LIST_BATCH } else { n };
    usize::try_from(n).map_err(|e| Fail::args(&e.to_string()))
}

pub fn offset(v: i64) -> Result<i64, Fail> {
    if (0..=MAX_OFFSET).contains(&v) { Ok(v) } else { Err(Fail::args("Argument is out of range")) }
}

pub fn read_size(max: u32) -> Result<usize, Fail> {
    if max > MAX_READ {
        return Err(Fail::args("Read size above 1 MiB"));
    }
    usize::try_from(max).map_err(|e| Fail::args(&e.to_string()))
}

/// A token of `[a-z0-9-]`.
pub fn token(s: &str, max: usize) -> Result<String, Fail> {
    let ok = !s.is_empty()
        && s.len() <= max
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok { Ok(s.to_owned()) } else { Err(Fail::args("Argument is not a valid name")) }
}

pub fn url(s: &str) -> Result<(), Fail> {
    if s.len() > MAX_URL {
        return Err(Fail::args("Argument is too long"));
    }
    Ok(())
}

pub fn secret(s: &[u8]) -> Result<(), Fail> {
    if s.len() > MAX_SECRET {
        return Err(Fail::args("Secret too long"));
    }
    Ok(())
}

fn int_option(key: &str, v: &OwnedValue, min: i64, max: i64) -> Result<i64, Fail> {
    let n = value_i64(v).ok_or_else(|| Fail::args(&format!("Option \"{key}\" must be an integer")))?;
    if n < min || n > max {
        return Err(Fail::args(&format!("Option \"{key}\" is out of range")));
    }
    Ok(n)
}

fn bool_option(key: &str, v: &OwnedValue) -> Result<bool, Fail> {
    value_bool(v).ok_or_else(|| Fail::args(&format!("Option \"{key}\" must be a boolean")))
}

fn unknown(key: &str) -> Fail {
    Fail::args(&format!("Unknown option \"{key}\""))
}

/// `SetAttributes.changes`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Attributes {
    pub mode: Option<i32>,
    pub mtime_ms: Option<i64>,
    pub atime_ms: Option<i64>,
}

impl Attributes {
    pub fn is_empty(&self) -> bool {
        self.mode.is_none() && self.mtime_ms.is_none() && self.atime_ms.is_none()
    }
}

pub fn attributes(changes: &Dict) -> Result<Attributes, Fail> {
    let mut out = Attributes::default();
    for (key, v) in changes {
        match key.as_str() {
            "mode" => out.mode = Some(i32::try_from(int_option(key, v, 0, 0o7777)?).unwrap_or(0)),
            "mtimeMs" => out.mtime_ms = Some(int_option(key, v, MIN_TIME_MS, MAX_TIME_MS)?),
            "atimeMs" => out.atime_ms = Some(int_option(key, v, MIN_TIME_MS, MAX_TIME_MS)?),
            _ => return Err(unknown(key)),
        }
    }
    Ok(out)
}

/// `ServerCopy.opts` (and the tree options of `CopyAcross`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CopyOpts {
    pub recursive: bool,
    pub replace: bool,
}

pub fn copy_opts(opts: &Dict) -> Result<CopyOpts, Fail> {
    let mut out = CopyOpts::default();
    for (key, v) in opts {
        match key.as_str() {
            "recursive" => out.recursive = bool_option(key, v)?,
            "replace" => out.replace = bool_option(key, v)?,
            _ => return Err(unknown(key)),
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Disposition {
    #[default]
    Create,
    Truncate,
    Resume,
}

/// `Upload.opts` / `Download.opts`.
#[derive(Debug, PartialEq, Eq)]
pub struct TransferOpts {
    pub offset: i64,
    /// -1: unknown.
    pub size: i64,
    pub lane: Lane,
    pub disposition: Disposition,
    pub create_mode: Option<i32>,
    pub mtime_ms: Option<i64>,
}

impl Default for TransferOpts {
    fn default() -> Self {
        Self {
            offset: 0,
            size: -1,
            lane: Lane::Bulk,
            disposition: Disposition::Create,
            create_mode: None,
            mtime_ms: None,
        }
    }
}

fn disposition(key: &str, v: &OwnedValue) -> Result<Disposition, Fail> {
    match value_str(v).as_deref() {
        Some("create") => Ok(Disposition::Create),
        Some("truncate") => Ok(Disposition::Truncate),
        Some("resume") => Ok(Disposition::Resume),
        _ => Err(Fail::args(&format!("Option \"{key}\" must be create, truncate or resume"))),
    }
}

pub fn transfer_opts(opts: &Dict, upload: bool) -> Result<TransferOpts, Fail> {
    let mut out = TransferOpts::default();
    for (key, v) in opts {
        match key.as_str() {
            "offset" => out.offset = int_option(key, v, 0, MAX_OFFSET)?,
            "size" => out.size = int_option(key, v, -1, MAX_OFFSET)?,
            "lane" => {
                out.lane = lane(
                    &value_str(v).ok_or_else(|| Fail::args("Option \"lane\" must be a string"))?,
                    Lane::Bulk,
                )?;
            }
            "disposition" if upload => out.disposition = disposition(key, v)?,
            "createMode" if upload => {
                out.create_mode = Some(i32::try_from(int_option(key, v, 0, 0o7777)?).unwrap_or(0));
            }
            "mtimeMs" if upload => out.mtime_ms = Some(int_option(key, v, MIN_TIME_MS, MAX_TIME_MS)?),
            _ => return Err(unknown(key)),
        }
    }
    if out.disposition == Disposition::Resume && out.offset == 0 {
        return Err(Fail::args("Resume needs an offset"));
    }
    Ok(out)
}

/// `Walk.opts`.
#[derive(Debug, PartialEq, Eq)]
pub struct WalkOpts {
    pub max_depth: i64,
    pub follow_symlinks: bool,
    pub post_order: bool,
}

pub fn walk_opts(opts: &Dict) -> Result<WalkOpts, Fail> {
    let mut out = WalkOpts { max_depth: -1, follow_symlinks: false, post_order: false };
    for (key, v) in opts {
        match key.as_str() {
            "maxDepth" => out.max_depth = int_option(key, v, -1, MAX_WALK_DEPTH)?,
            "followSymlinks" => out.follow_symlinks = bool_option(key, v)?,
            "postOrder" => out.post_order = bool_option(key, v)?,
            _ => return Err(unknown(key)),
        }
    }
    Ok(out)
}

/// `ConnectAdHoc.opts`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AdHocOpts {
    pub user: Option<String>,
    pub security_profile: Option<String>,
}

pub fn adhoc_opts(opts: &Dict) -> Result<AdHocOpts, Fail> {
    let mut out = AdHocOpts::default();
    for (key, v) in opts {
        let s = value_str(v)
            .filter(|s| s.len() <= MAX_SHORT)
            .ok_or_else(|| Fail::args(&format!("Option \"{key}\" must be a short string")))?;
        match key.as_str() {
            "user" if !s.contains('\0') => out.user = Some(s),
            "security_profile" if ["strict", "signed", "guest"].contains(&s.as_str()) => {
                out.security_profile = Some(s);
            }
            "user" | "security_profile" => return Err(Fail::args("Invalid option value")),
            _ => return Err(unknown(key)),
        }
    }
    Ok(out)
}

/// `Answer.answer`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AnswerOpts {
    pub accept: bool,
    pub answers: Vec<Vec<u8>>,
}

pub fn answer_opts(opts: &Dict) -> Result<AnswerOpts, Fail> {
    let mut out = AnswerOpts::default();
    for (key, v) in opts {
        match key.as_str() {
            "accept" => out.accept = bool_option(key, v)?,
            "answers" => out.answers = byte_arrays(v)?,
            _ => return Err(unknown(key)),
        }
    }
    Ok(out)
}

fn byte_arrays(v: &OwnedValue) -> Result<Vec<Vec<u8>>, Fail> {
    let bad = || Fail::args("Option \"answers\" must be an array of byte arrays");
    match &**v {
        zbus::zvariant::Value::Array(items) if items.len() <= MAX_ANSWERS => items
            .iter()
            .map(|item| value_bytes(item).filter(|b| b.len() <= MAX_SHORT.saturating_mul(4)).ok_or_else(bad))
            .collect(),
        _ => Err(bad()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::OptsBuilder;

    fn dict(o: OptsBuilder) -> Dict {
        o.build().into_iter().map(|(k, v)| (k, OwnedValue::try_from(v).unwrap())).collect()
    }

    #[test]
    fn simple_values() {
        location("account:1").unwrap();
        location("no such").unwrap_err();
        location("").unwrap_err();
        assert_eq!(lane("", Lane::Bulk).unwrap(), Lane::Bulk);
        lane("fast", Lane::Bulk).unwrap_err();
        assert_eq!(list_batch(0).unwrap(), 256);
        assert_eq!(list_batch(512).unwrap(), 512);
        list_batch(513).unwrap_err();
        offset(-1).unwrap_err();
        offset(MAX_OFFSET + 1).unwrap_err();
        read_size(MAX_READ + 1).unwrap_err();
        assert_eq!(read_size(5).unwrap(), 5);
        token("sha256", 32).unwrap();
        token("SHA", 32).unwrap_err();
        assert!(url(&"x".repeat(5000)).is_err());
        assert!(secret(&vec![0; 70_000]).is_err());
        assert_eq!(path(b"a/./b").unwrap(), b"a/b");
        assert_eq!(path(b"a/../b").unwrap_err().bare(), "InvalidName");
    }

    #[test]
    fn attributes_keys() {
        let a = attributes(&dict(OptsBuilder::new().int("mode", 0o644).int("mtimeMs", 5))).unwrap();
        assert_eq!((a.mode, a.mtime_ms, a.atime_ms), (Some(0o644), Some(5), None));
        assert!(!a.is_empty());
        assert!(attributes(&Dict::new()).unwrap().is_empty());
        attributes(&dict(OptsBuilder::new().str("owner", "root"))).unwrap_err();
        attributes(&dict(OptsBuilder::new().int("mode", 0o10000))).unwrap_err();
        attributes(&dict(OptsBuilder::new().str("mode", "x"))).unwrap_err();
    }

    #[test]
    fn copy_and_walk_options() {
        let c = copy_opts(&dict(OptsBuilder::new().bool("recursive", true))).unwrap();
        assert_eq!(c, CopyOpts { recursive: true, replace: false });
        copy_opts(&dict(OptsBuilder::new().int("recursive", 1))).unwrap_err();
        copy_opts(&dict(OptsBuilder::new().bool("x", true))).unwrap_err();
        let w = walk_opts(&dict(OptsBuilder::new().int("maxDepth", 2).bool("postOrder", true))).unwrap();
        assert_eq!((w.max_depth, w.post_order, w.follow_symlinks), (2, true, false));
        walk_opts(&dict(OptsBuilder::new().int("maxDepth", 4097))).unwrap_err();
        walk_opts(&dict(OptsBuilder::new().int("maxDepth", -2))).unwrap_err();
    }

    #[test]
    fn transfer_options() {
        let t = transfer_opts(
            &dict(OptsBuilder::new().int("offset", 4).str("disposition", "resume").int("size", 6)),
            true,
        )
        .unwrap();
        assert_eq!((t.offset, t.size, t.disposition), (4, 6, Disposition::Resume));
        transfer_opts(&dict(OptsBuilder::new().str("disposition", "resume")), true).unwrap_err();
        transfer_opts(&dict(OptsBuilder::new().str("disposition", "create")), false).unwrap_err();
        transfer_opts(&dict(OptsBuilder::new().str("disposition", "x")), true).unwrap_err();
        let t = transfer_opts(&dict(OptsBuilder::new().str("lane", "stream").int("createMode", 0o600)), true)
            .unwrap();
        assert_eq!((t.lane, t.create_mode), (Lane::Stream, Some(0o600)));
        transfer_opts(&dict(OptsBuilder::new().int("lane", 1)), false).unwrap_err();
        transfer_opts(&dict(OptsBuilder::new().int("size", -2)), false).unwrap_err();
    }

    #[test]
    fn adhoc_and_answer_options() {
        let o = adhoc_opts(&dict(OptsBuilder::new().str("user", "me").str("security_profile", "strict")))
            .unwrap();
        assert_eq!(o.user.as_deref(), Some("me"));
        assert_eq!(o.security_profile.as_deref(), Some("strict"));
        adhoc_opts(&dict(OptsBuilder::new().str("security_profile", "loose"))).unwrap_err();
        adhoc_opts(&dict(OptsBuilder::new().str("password", "x"))).unwrap_err();
        adhoc_opts(&dict(OptsBuilder::new().bool("user", true))).unwrap_err();
        let a = answer_opts(&dict(
            OptsBuilder::new().bool("accept", true).byte_arrays("answers", &[b"1".to_vec(), b"2".to_vec()]),
        ))
        .unwrap();
        assert!(a.accept);
        assert_eq!(a.answers, vec![b"1".to_vec(), b"2".to_vec()]);
        answer_opts(&dict(OptsBuilder::new().str("answers", "x"))).unwrap_err();
        answer_opts(&dict(OptsBuilder::new().str("x", "x"))).unwrap_err();
    }
}
