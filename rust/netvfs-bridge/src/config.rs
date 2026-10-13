// SPDX-License-Identifier: LGPL-2.1-or-later
//! Consumer registration (SPEC-v2 XB-3), the environment the bridge reads
//! and the paths it derives from it.
//!
//! A consumer file `/usr/share/netvfs/consumers/<id>.conf`:
//!
//! ```ini
//! [Consumer]
//! Id=lautta
//! DisplayName=Lautta
//! Executable=/usr/bin/harbour-lautta
//! DataDir=.local/share/org.netvfs/lautta
//! ```
//!
//! is valid only when both of its readers accept it: the C++ reader
//! (`ConsentStore::parseConsumerFile`, a strict line reader, not QSettings)
//! and the systemd generator (`netvfs-bridge-generator.c`), which made the
//! bridge's units from it. The bridge thus serves exactly the consumers the
//! generator set up: the same consumers folder (the generator's checks of
//! `NETVFS_CONSUMERS_DIR`), the file inside it after resolving links, values
//! within the generator's buffers, no control characters in `DisplayName`.

use crate::status::Status;
use netvfs_bridge_proto::ErrorName;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The consumers folder of the package.
pub const CONSUMERS_DIR: &str = "/usr/share/netvfs/consumers";
/// The installed accounts helper (XB-2a).
pub const ACCOUNTS_HELPER: &str = "/usr/libexec/netvfs/netvfs-accounts";
/// The idle exit (XB-2): 30 s after the last client left and no job runs.
pub const IDLE_EXIT_MS: u64 = 30_000;

const MAX_ID: usize = 64;
/// `MaxPathLength` (C++) and `MAX_VALUE` (generator).
const MAX_VALUE: usize = 1024;
const MAX_FILE_BYTES: u64 = 16 * 1024;
/// The generator's `fgets` buffer (`MAX_LINE`), less the NUL.
const GENERATOR_LINE: usize = 2047;
/// `MAX_PATH_LENGTH / 2` of the generator.
const MAX_CONSUMERS_DIR: usize = 2048;

/// The environment variables the bridge reads.
const VARIABLES: [&str; 7] = [
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "NETVFS_CONSUMERS_DIR",
    "NETVFS_ACCOUNTS_HELPER",
    "NETVFS_BRIDGE_IDLE_EXIT_MS",
    "QT_LOGGING_RULES",
];

/// A registered consumer (`NetVfs::ConsumerInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumerInfo {
    /// `[a-z0-9-]{1,64}`, the file name's stem.
    pub id: String,
    /// Non-empty, no control characters.
    pub display_name: String,
    /// Absolute, `[A-Za-z0-9._/+-]`, no empty, `.` or `..` component.
    pub executable: String,
    /// Relative to `$HOME`, same characters and components.
    pub data_dir: String,
}

/// `ConsumerInfo::isValidId`: `[a-z0-9-]{1,64}`.
#[must_use]
pub fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Characters allowed in paths that end up in systemd unit files.
fn is_path_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'+')
}

/// No empty, `.` or `..` component.
fn has_clean_components(path: &str) -> bool {
    path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

/// `ConsumerInfo::isValidDataDir`.
#[must_use]
pub fn is_valid_data_dir(dir: &str) -> bool {
    !dir.is_empty()
        && dir.len() <= MAX_VALUE
        && !dir.starts_with('/')
        && dir.bytes().all(is_path_char)
        && has_clean_components(dir)
}

/// `ConsumerInfo::isValidExecutable`.
#[must_use]
pub fn is_valid_executable(executable: &str) -> bool {
    executable.len() > 1
        && executable.len() <= MAX_VALUE
        && executable.bytes().all(is_path_char)
        && executable.strip_prefix('/').is_some_and(has_clean_components)
}

/// The environment, captured once (tests build their own).
#[derive(Clone, Debug, Default)]
pub struct Env {
    vars: BTreeMap<&'static str, OsString>,
}

impl Env {
    /// The process's values of the variables the bridge reads.
    #[must_use]
    pub fn from_process() -> Self {
        let vars = VARIABLES.iter().filter_map(|name| std::env::var_os(name).map(|v| (*name, v))).collect();
        Self { vars }
    }

    /// This environment with `name` set to `value`.
    #[must_use]
    pub fn with(mut self, name: &'static str, value: impl Into<OsString>) -> Self {
        self.vars.insert(name, value.into());
        self
    }

    fn get(&self, name: &str) -> Option<&OsStr> {
        self.vars.get(name).map(OsString::as_os_str)
    }

    /// A variable that is set and not empty.
    fn non_empty(&self, name: &str) -> Option<&OsStr> {
        self.get(name).filter(|v| !v.is_empty())
    }

    /// `QDir::homePath()`: `$HOME`, or `/`.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        PathBuf::from(self.non_empty("HOME").unwrap_or_else(|| OsStr::new("/")))
    }

    /// `QStandardPaths::GenericConfigLocation`: `$XDG_CONFIG_HOME` or
    /// `~/.config`.
    #[must_use]
    pub fn config_home(&self) -> PathBuf {
        self.non_empty("XDG_CONFIG_HOME").map_or_else(|| self.home().join(".config"), PathBuf::from)
    }

    /// `QStandardPaths::GenericDataLocation`: `$XDG_DATA_HOME` or
    /// `~/.local/share`.
    #[must_use]
    pub fn data_home(&self) -> PathBuf {
        self.non_empty("XDG_DATA_HOME").map_or_else(|| self.home().join(".local/share"), PathBuf::from)
    }

    /// The consent file (XB-6): `~/.config/netvfs/bridge.conf`.
    #[must_use]
    pub fn consent_file(&self) -> PathBuf {
        self.config_home().join("netvfs/bridge.conf")
    }

    /// The accepted ad-hoc identities of `consumer` (XB-14):
    /// `~/.local/share/netvfs/bridge/<id>/known_hosts`.
    #[must_use]
    pub fn known_hosts_file(&self, consumer: &str) -> PathBuf {
        self.data_home().join("netvfs/bridge").join(consumer).join("known_hosts")
    }

    /// The accounts helper: `NETVFS_ACCOUNTS_HELPER` when set (tests; even
    /// empty, as `qEnvironmentVariableIsSet`), else the installed one.
    #[must_use]
    pub fn accounts_helper(&self) -> PathBuf {
        self.get("NETVFS_ACCOUNTS_HELPER").map_or_else(|| PathBuf::from(ACCOUNTS_HELPER), PathBuf::from)
    }

    /// The consumers folder: `NETVFS_CONSUMERS_DIR` when the generator
    /// would take it (absolute, at most 2048 bytes, no control character,
    /// no `..` component), else the package's.
    #[must_use]
    pub fn consumers_dir(&self) -> PathBuf {
        match self.non_empty("NETVFS_CONSUMERS_DIR") {
            Some(dir) if is_acceptable_consumers_dir(dir.as_bytes()) => PathBuf::from(dir),
            _ => PathBuf::from(CONSUMERS_DIR),
        }
    }

    /// The idle exit: `NETVFS_BRIDGE_IDLE_EXIT_MS` when it is a positive
    /// `int` (`qEnvironmentVariableIntValue`, tests), else 30 s.
    #[must_use]
    pub fn idle_exit_ms(&self) -> u64 {
        self.get("NETVFS_BRIDGE_IDLE_EXIT_MS")
            .and_then(|v| qt_env_int(v.as_bytes()))
            .and_then(|ms| u64::try_from(ms).ok())
            .filter(|ms| *ms > 0)
            .unwrap_or(IDLE_EXIT_MS)
    }

    /// `QT_LOGGING_RULES`.
    #[must_use]
    pub fn logging_rules(&self) -> Option<String> {
        self.get("QT_LOGGING_RULES").map(|v| v.to_string_lossy().into_owned())
    }
}

/// The generator's `consumers_dir()` checks.
fn is_acceptable_consumers_dir(dir: &[u8]) -> bool {
    dir.first() == Some(&b'/')
        && dir.len() <= MAX_CONSUMERS_DIR
        && !dir.iter().any(|b| *b < 0x20 || *b == 0x7f)
        && !dir.split(|b| *b == b'/').any(|part| part == b"..")
}

/// `qEnvironmentVariableIntValue`: `strtoll` with base 0 (leading white
/// space, a sign, `0x` hex or `0` octal), the whole value, in `int` range.
fn qt_env_int(value: &[u8]) -> Option<i32> {
    // Qt refuses what does not fit its buffer.
    if value.len() > 13 {
        return None;
    }
    let text = value.trim_ascii();
    let (negative, text) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, text),
    };
    let (radix, digits) = if let Some(hex) = text.strip_prefix(b"0x").or_else(|| text.strip_prefix(b"0X")) {
        (16, hex)
    } else if text.len() > 1 && text.first() == Some(&b'0') {
        (8, text.get(1..).unwrap_or_default())
    } else {
        (10, text)
    };
    let magnitude = i64::from_str_radix(std::str::from_utf8(digits).ok()?, radix).ok()?;
    if digits.first().is_some_and(|b| !b.is_ascii_alphanumeric()) {
        return None;
    }
    i32::try_from(if negative { magnitude.checked_neg()? } else { magnitude }).ok()
}

// ------------------------------------------------------------------ files

fn invalid(path: &Path, why: &str) -> Status {
    Status::new(ErrorName::InvalidName, format!("Invalid consumer file {}: {why}", path.display()))
}

fn unreadable(path: &Path) -> Status {
    Status::new(ErrorName::NotFound, format!("Cannot read consumer file {}", path.display()))
}

/// `ConsentStore::loadConsumer`: loads and validates `<consumers>/<id>.conf`.
///
/// # Errors
/// `InvalidName` for a bad id or file, `NotFound` when it cannot be read.
pub fn load_consumer(env: &Env, id: &str) -> Result<ConsumerInfo, Status> {
    if !is_valid_id(id) {
        return Err(Status::new(ErrorName::InvalidName, "Invalid consumer id"));
    }
    let dir = env.consumers_dir();
    let path = dir.join(format!("{id}.conf"));
    // The generator reads the file only below the folder's real path.
    let base = dir.canonicalize().map_err(|_e| unreadable(&path))?;
    let resolved = path.canonicalize().map_err(|_e| unreadable(&path))?;
    if resolved.parent().is_none_or(|parent| !parent.starts_with(&base)) {
        return Err(invalid(&path, "is not a file of the consumers folder"));
    }
    let size = std::fs::metadata(&resolved).map_err(|_e| unreadable(&path))?.len();
    if size > MAX_FILE_BYTES {
        return Err(invalid(&path, "too large"));
    }
    let content = std::fs::read(&resolved).map_err(|_e| unreadable(&path))?;
    let info = parse_consumer(&content, id).map_err(|why| invalid(&path, why))?;
    check_as_generator(&content, id).map_err(|why| invalid(&path, why))?;
    Ok(info)
}

/// Every valid consumer in the consumers folder, sorted by id; invalid
/// files are skipped with a warning (`ConsentStore::consumers`).
#[must_use]
pub fn consumers(env: &Env) -> Vec<ConsumerInfo> {
    let Ok(entries) = std::fs::read_dir(env.consumers_dir()) else { return Vec::new() };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension() == Some(OsStr::new("conf")))
        .filter(|p| p.file_name().is_some_and(|n| !n.as_bytes().starts_with(b".")))
        .collect();
    files.sort();
    files
        .iter()
        .filter_map(|path| {
            let stem = path.file_stem().and_then(OsStr::to_str).unwrap_or_default();
            let loaded = if is_valid_id(stem) {
                load_consumer(env, stem)
            } else {
                Err(invalid(path, "Id must match [a-z0-9-]+ and the file name"))
            };
            loaded.map_err(|e| crate::log::warning(format_args!("{}", e.message))).ok()
        })
        .collect()
}

/// The C++ reader: `[Consumer]` lines, each trimmed as `QString::trimmed`.
fn parse_consumer(content: &[u8], stem: &str) -> Result<ConsumerInfo, &'static str> {
    let mut info = ConsumerInfo {
        id: String::new(),
        display_name: String::new(),
        executable: String::new(),
        data_dir: String::new(),
    };
    let mut in_group = false;
    for raw in content.split(|b| *b == b'\n') {
        let decoded = String::from_utf8_lossy(raw);
        let line = decoded.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            in_group = line == "[Consumer]";
            continue;
        }
        let Some((key, value)) = line.split_once('=').filter(|(key, _)| in_group && !key.is_empty()) else {
            continue;
        };
        let slot = match key.trim() {
            "Id" => &mut info.id,
            "DisplayName" => &mut info.display_name,
            "Executable" => &mut info.executable,
            "DataDir" => &mut info.data_dir,
            _ => continue,
        };
        value.trim().clone_into(slot);
    }
    if !is_valid_id(&info.id) || info.id != stem {
        return Err("Id must match [a-z0-9-]+ and the file name");
    }
    if info.display_name.is_empty() {
        return Err("DisplayName is empty");
    }
    if !is_valid_executable(&info.executable) {
        return Err("Executable must be an absolute path");
    }
    if !is_valid_data_dir(&info.data_dir) {
        return Err("DataDir must be relative to the home folder, without \"..\"");
    }
    Ok(info)
}

/// The generator's reading of the same file (`parse_consumer`, `validate`):
/// `fgets` lines of at most 2047 bytes, cut at a NUL, trimmed of spaces and
/// tabs; values within its buffers; no control characters in DisplayName.
fn check_as_generator(content: &[u8], stem: &str) -> Result<(), &'static str> {
    let mut fields: [&[u8]; 4] = [b""; 4];
    let mut in_group = false;
    for chunk in fgets_lines(content) {
        let line = chunk.split(|b| *b == 0).next().unwrap_or_default();
        let s = trim_generator(line);
        if s.is_empty() || matches!(s.first(), Some(b'#' | b';')) {
            continue;
        }
        if s.first() == Some(&b'[') {
            in_group = s == b"[Consumer]";
            continue;
        }
        let Some(eq) = s.iter().position(|b| *b == b'=').filter(|eq| in_group && *eq > 0) else { continue };
        let key = trim_generator(s.get(..eq).unwrap_or_default());
        let value = trim_generator(s.get(eq.saturating_add(1)..).unwrap_or_default());
        let (slot, limit) = match key {
            b"Id" => (0, MAX_ID),
            b"DisplayName" => (1, MAX_VALUE),
            b"Executable" => (2, MAX_VALUE),
            b"DataDir" => (3, MAX_VALUE),
            _ => continue,
        };
        if value.len() > limit {
            return Err("has a value that is too long");
        }
        if let Some(field) = fields.get_mut(slot) {
            *field = value;
        }
    }
    let [id, display_name, _, _] = fields;
    if id != stem.as_bytes() {
        return Err("Id must match [a-z0-9-]+ and the file name");
    }
    if display_name.is_empty() || display_name.iter().any(|b| *b < 0x20 || *b == 0x7f) {
        return Err("DisplayName is empty or has control characters");
    }
    // Executable and DataDir: the C++ rules on the same bytes.
    Ok(())
}

/// The lines `fgets` returns with a 2048-byte buffer.
fn fgets_lines(content: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = content;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let newline = rest.iter().position(|b| *b == b'\n').map_or(rest.len(), |p| p.saturating_add(1));
        let (line, tail) = rest.split_at(newline.min(GENERATOR_LINE));
        rest = tail;
        Some(line)
    })
}

/// The generator's `trim`: spaces and tabs in front; spaces, tabs, `\r`
/// and `\n` at the end.
fn trim_generator(s: &[u8]) -> &[u8] {
    let start = s.iter().take_while(|b| matches!(b, b' ' | b'\t')).count();
    let s = s.get(start..).unwrap_or_default();
    let end = s
        .len()
        .saturating_sub(s.iter().rev().take_while(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')).count());
    s.get(..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    const LAUTTA: &str = "[Consumer]\nId=lautta\nDisplayName=Lautta, the browser\n\
                          Executable=/usr/bin/harbour-lautta\nDataDir=.local/share/org.netvfs/lautta\n";

    fn consumer(id: &str, display: &str, executable: &str, data_dir: &str) -> String {
        format!("[Consumer]\nId={id}\nDisplayName={display}\nExecutable={executable}\nDataDir={data_dir}\n")
    }

    fn env_for(dir: &TempDir) -> Env {
        Env::default().with("NETVFS_CONSUMERS_DIR", dir.path())
    }

    /// The C++ case `consumers`.
    #[test]
    fn consumers_case() {
        let dir = TempDir::new();
        dir.write("lautta.conf", LAUTTA);
        dir.write("dotdot.conf", consumer("dotdot", "X", "/usr/bin/x", ".local/../../etc"));
        dir.write("absolute.conf", consumer("absolute", "X", "/usr/bin/x", "/etc"));
        dir.write("mismatch.conf", consumer("other", "X", "/usr/bin/x", "a"));
        dir.write("relexe.conf", consumer("relexe", "X", "bin/x", "a"));
        dir.write("percent.conf", consumer("percent", "X", "/usr/bin/x", "a%h"));
        let env = env_for(&dir);
        let list = consumers(&env);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "lautta");
        assert_eq!(list[0].display_name, "Lautta, the browser");
        let info = load_consumer(&env, "lautta").unwrap();
        assert_eq!(info.data_dir, ".local/share/org.netvfs/lautta");
        assert_eq!(info.executable, "/usr/bin/harbour-lautta");
        load_consumer(&env, "dotdot").unwrap_err();
        assert_eq!(
            load_consumer(&env, "../x").unwrap_err(),
            Status::new(ErrorName::InvalidName, "Invalid consumer id")
        );
        assert!(!is_valid_id("Lautta"));
        assert!(!is_valid_data_dir("a//b"));
        assert!(is_valid_executable("/usr/bin/harbour-lautta"));
        assert!(!is_valid_executable("/usr/../bin/sh"));
    }

    /// The generator's test consumers (tests/bridge/generator/consumers):
    /// the bridge loads what it generated units for, and nothing else.
    #[test]
    fn generator_consumers() {
        let shipped = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/bridge/generator/consumers")
            .canonicalize()
            .unwrap();
        let env = Env::default().with("NETVFS_CONSUMERS_DIR", &shipped);
        let ids: Vec<String> = consumers(&env).into_iter().map(|c| c.id).collect();
        assert_eq!(ids, ["lautta", "photos"]);
        assert_eq!(load_consumer(&env, "photos").unwrap().display_name, "Photo 100% Sync");
        for id in ["absolute", "escape", "mismatch", "newline", "specifier"] {
            assert_eq!(load_consumer(&env, id).unwrap_err().name, ErrorName::InvalidName, "{id}");
        }
        let lautta = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src/bridge/data/lautta.conf");
        let dir = TempDir::new();
        std::fs::copy(lautta, dir.join("lautta.conf")).unwrap();
        assert_eq!(
            load_consumer(&env_for(&dir), "lautta").unwrap(),
            ConsumerInfo {
                id: "lautta".into(),
                display_name: "Lautta".into(),
                executable: "/usr/bin/harbour-lautta".into(),
                data_dir: ".local/share/org.netvfs/lautta".into(),
            }
        );
    }

    #[test]
    fn messages() {
        let dir = TempDir::new();
        let env = env_for(&dir);
        let path = dir.join("x.conf");
        let invalid = |why: &str| {
            Status::new(ErrorName::InvalidName, format!("Invalid consumer file {}: {why}", path.display()))
        };
        assert_eq!(
            load_consumer(&env, "x").unwrap_err(),
            Status::new(ErrorName::NotFound, format!("Cannot read consumer file {}", path.display()))
        );
        for (content, why) in [
            (consumer("y", "X", "/x/y", "a"), "Id must match [a-z0-9-]+ and the file name"),
            (consumer("x", " ", "/x/y", "a"), "DisplayName is empty"),
            (consumer("x", "X", "/", "a"), "Executable must be an absolute path"),
            (consumer("x", "X", "/x/y", ""), "DataDir must be relative to the home folder, without \"..\""),
            (consumer("x", "A\u{7f}B", "/x/y", "a"), "DisplayName is empty or has control characters"),
            (consumer("x", &"d".repeat(1025), "/x/y", "a"), "has a value that is too long"),
            (format!("{}\n{}", consumer("x", "X", "/x/y", "a"), "#".repeat(16 * 1024)), "too large"),
        ] {
            dir.write("x.conf", &content);
            assert_eq!(load_consumer(&env, "x").unwrap_err(), invalid(why), "{content:?}");
        }
        dir.write("x.conf", consumer("x", &"d".repeat(1024), "/x/y", "a"));
        assert_eq!(load_consumer(&env, "x").unwrap().display_name.len(), 1024);
    }

    #[test]
    fn both_readers_must_accept() {
        let dir = TempDir::new();
        let env = env_for(&dir);
        let load = |content: &str| {
            dir.write("x.conf", content);
            load_consumer(&env, "x")
        };
        let ok = consumer("x", "X", "/x/y", "a");
        load(&ok).unwrap();
        // Qt trims what the generator keeps.
        load(&consumer("x", "X\u{b}", "/x/y", "a")).unwrap_err();
        load(&ok.replace("Id=x", "\u{a0}Id=x")).unwrap_err();
        assert_eq!(load(&consumer("x", "X\u{a0}", "/x/y", "a")).unwrap().display_name, "X");
        // CRLF, comments, other groups, unknown keys, keys without value.
        let crlf =
            format!("; c\r\n[Other]\r\nId=y\r\n{}\r\nKey=v\r\n=v\r\nnoequals\r\n", ok.replace('\n', "\r\n"));
        assert_eq!(load(&crlf).unwrap().id, "x");
        // A line the generator splits at 2047 bytes: its tail is a line of
        // its own to the generator only.
        let split = format!("{ok}# {}Id=evil\n", "x".repeat(GENERATOR_LINE - 2));
        assert!(load(&split).unwrap_err().message.ends_with("Id must match [a-z0-9-]+ and the file name"));
        load(&format!("{ok}# {}Id=evil\n", "x".repeat(GENERATOR_LINE - 1))).unwrap();
        // Text after a NUL is gone for the generator.
        load(&ok.replace("Id=x", "Id=x\0z")).unwrap_err();
        load(&format!("{ok}DisplayName=\0\n")).unwrap_err();
        // Values of exactly the generator's buffers.
        load(&consumer("x", "X", &format!("/{}", "a".repeat(1023)), "a")).unwrap();
        load(&consumer("x", "X", &format!("/{}", "a".repeat(1024)), "a")).unwrap_err();
    }

    #[test]
    fn folder_and_links() {
        let dir = TempDir::new();
        let outside = TempDir::new();
        outside.write("x.conf", consumer("x", "X", "/x/y", "a"));
        std::os::unix::fs::symlink(outside.join("x.conf"), dir.join("x.conf")).unwrap();
        let env = env_for(&dir);
        assert_eq!(
            load_consumer(&env, "x").unwrap_err().message.rsplit(": ").next(),
            Some("is not a file of the consumers folder")
        );
        dir.write("sub/y.conf", consumer("y", "Y", "/x/y", "a"));
        std::os::unix::fs::symlink("sub/y.conf", dir.join("y.conf")).unwrap();
        assert_eq!(load_consumer(&env, "y").unwrap().id, "y");
        std::os::unix::fs::symlink(".", dir.join("z.conf")).unwrap();
        load_consumer(&env, "z").unwrap_err();
        dir.write(".hidden.conf", "");
        dir.write("Upper.conf", consumer("Upper", "X", "/x/y", "a"));
        assert_eq!(consumers(&env).iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), ["y"]);
        let missing = Env::default().with("NETVFS_CONSUMERS_DIR", dir.join("missing"));
        assert!(consumers(&missing).is_empty());
        assert_eq!(load_consumer(&missing, "y").unwrap_err().name, ErrorName::NotFound);
    }

    #[test]
    fn consumers_dir_override() {
        let dir = |v: &str| Env::default().with("NETVFS_CONSUMERS_DIR", v).consumers_dir();
        assert_eq!(dir("/tmp/c"), Path::new("/tmp/c"));
        assert_eq!(dir(""), Path::new(CONSUMERS_DIR));
        assert_eq!(dir("relative"), Path::new(CONSUMERS_DIR));
        assert_eq!(dir("/tmp/../etc"), Path::new(CONSUMERS_DIR));
        assert_eq!(dir("/tmp/..x/a.."), Path::new("/tmp/..x/a.."));
        assert_eq!(dir("/tmp/\u{1}"), Path::new(CONSUMERS_DIR));
        assert_eq!(dir("/tmp/\u{7f}"), Path::new(CONSUMERS_DIR));
        assert_eq!(dir(&format!("/{}", "a".repeat(2047))).as_os_str().len(), 2048);
        assert_eq!(dir(&format!("/{}", "a".repeat(2048))), Path::new(CONSUMERS_DIR));
        assert_eq!(Env::default().consumers_dir(), Path::new(CONSUMERS_DIR));
    }

    #[test]
    fn paths() {
        let env = Env::default().with("HOME", "/home/u");
        assert_eq!(env.consent_file(), Path::new("/home/u/.config/netvfs/bridge.conf"));
        assert_eq!(
            env.known_hosts_file("lautta"),
            Path::new("/home/u/.local/share/netvfs/bridge/lautta/known_hosts")
        );
        let xdg = env.clone().with("XDG_CONFIG_HOME", "/c").with("XDG_DATA_HOME", "/d");
        assert_eq!(xdg.consent_file(), Path::new("/c/netvfs/bridge.conf"));
        assert_eq!(xdg.known_hosts_file("p"), Path::new("/d/netvfs/bridge/p/known_hosts"));
        let empty = Env::default().with("HOME", "").with("XDG_CONFIG_HOME", "");
        assert_eq!(empty.consent_file(), Path::new("/.config/netvfs/bridge.conf"));
        assert_eq!(env.accounts_helper(), Path::new(ACCOUNTS_HELPER));
        assert_eq!(env.clone().with("NETVFS_ACCOUNTS_HELPER", "/b/h").accounts_helper(), Path::new("/b/h"));
        assert_eq!(env.clone().with("NETVFS_ACCOUNTS_HELPER", "").accounts_helper(), Path::new(""));
        assert_eq!(env.logging_rules(), None);
        assert_eq!(env.with("QT_LOGGING_RULES", "a=b").logging_rules().as_deref(), Some("a=b"));
        let process = Env::from_process();
        assert_eq!(process.get("HOME"), std::env::var_os("HOME").as_deref());
        assert_eq!(process.get("PATH"), None);
    }

    #[test]
    fn idle_exit() {
        let idle = |v: &str| Env::default().with("NETVFS_BRIDGE_IDLE_EXIT_MS", v).idle_exit_ms();
        assert_eq!(Env::default().idle_exit_ms(), 30_000);
        assert_eq!(idle("500"), 500);
        assert_eq!(idle(" 500 "), 500);
        assert_eq!(idle("+500"), 500);
        assert_eq!(idle("0x1f4"), 500);
        assert_eq!(idle("0764"), 500);
        for bad in ["", "0", "-5", "abc", "5x", "08", "0x", "0x-5", "2147483648", "00000000000500"] {
            assert_eq!(idle(bad), 30_000, "{bad:?}");
        }
        assert_eq!(qt_env_int(b"-0x10"), Some(-16));
        assert_eq!(qt_env_int(b"2147483647"), Some(i32::MAX));
        assert_eq!(qt_env_int(b"-2147483648"), Some(i32::MIN));
    }
}
