// SPDX-License-Identifier: LGPL-2.1-or-later
//! Remote paths: the C-15 rules for the paths a caller gives, the start
//! folder relative paths are resolved against (S-19), and names as text
//! for messages.

use netvfs_vfs::Status;

/// A path with empty components dropped; `.`, `..` and NUL refused (C-15).
///
/// # Errors
/// `InvalidName`.
pub fn normalize(path: &[u8]) -> Result<Vec<u8>, Status> {
    if path.contains(&0) {
        return Err(Status::invalid_name("Path contains a NUL character"));
    }
    let mut out = Vec::with_capacity(path.len());
    if path.first() == Some(&b'/') {
        out.push(b'/');
    }
    for part in path.split(|&b| b == b'/').filter(|p| !p.is_empty()) {
        if part == b"." || part == b".." {
            return Err(Status::invalid_name("Path components \".\" and \"..\" are not allowed"));
        }
        if out.last().is_some_and(|&b| b != b'/') {
            out.push(b'/');
        }
        out.extend_from_slice(part);
    }
    Ok(out)
}

/// `dir` and `name` with one `/` between them.
#[must_use]
pub fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    if dir.is_empty() {
        return name.to_vec();
    }
    let mut out = Vec::with_capacity(dir.len().saturating_add(name.len()).saturating_add(1));
    out.extend_from_slice(dir);
    if !dir.ends_with(b"/") {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}

/// Whether a name a server lists (READDIR) names an entry of the folder:
/// not `.` or `..`, not empty, without `/` and NUL. Joined to the folder's
/// path, any other name would be a path elsewhere, or none.
#[must_use]
pub fn is_entry_name(name: &[u8]) -> bool {
    !(name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0))
}

/// What follows the last `/`.
#[must_use]
pub fn last_component(path: &[u8]) -> &[u8] {
    path.rsplit(|&b| b == b'/').next().unwrap_or(path)
}

/// The remote path of a caller's path: absolute as it is, relative below
/// `home` (the start folder), empty as `home` (or `.` without one).
///
/// # Errors
/// `InvalidName` (C-15).
pub fn resolve(home: &[u8], path: &[u8]) -> Result<Vec<u8>, Status> {
    let normalized = normalize(path)?;
    Ok(if normalized.first() == Some(&b'/') {
        normalized
    } else if normalized.is_empty() {
        if home.is_empty() { b".".to_vec() } else { home.to_vec() }
    } else {
        join(home, &normalized)
    })
}

/// Bytes as text for a message: one U+FFFD for each byte that is not
/// part of well-formed UTF-8 (as `Names::display` shows escapes).
#[must_use]
pub fn display(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for _ in chunk.invalid() {
            out.push('\u{fffd}');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use netvfs_vfs::ErrorName;

    #[test]
    fn normalize_drops_empty_components_and_keeps_the_root() {
        let cases: [(&[u8], &[u8]); 8] = [
            (b"", b""),
            (b"/", b"/"),
            (b"//", b"/"),
            (b"a//b/", b"a/b"),
            (b"/a/b", b"/a/b"),
            (b"///a", b"/a"),
            (b"a", b"a"),
            (b"a/.b/..c", b"a/.b/..c"),
        ];
        for (input, expected) in cases {
            assert_eq!(normalize(input).unwrap(), expected, "{}", display(input));
        }
    }

    #[test]
    fn normalize_refuses_dots_and_nul() {
        for bad in [&b"."[..], b"..", b"a/./b", b"/a/..", b"../x", b"a/."] {
            let e = normalize(bad).unwrap_err();
            assert_eq!(e.name, ErrorName::InvalidName);
            assert_eq!(e.message, "Path components \".\" and \"..\" are not allowed");
        }
        let e = normalize(b"a\0b").unwrap_err();
        assert_eq!((e.name, e.message.as_str()), (ErrorName::InvalidName, "Path contains a NUL character"));
    }

    #[test]
    fn resolve_against_the_start_folder() {
        assert_eq!(resolve(b"/home/u", b"").unwrap(), b"/home/u");
        assert_eq!(resolve(b"", b"").unwrap(), b".");
        assert_eq!(resolve(b"/home/u", b"a/b").unwrap(), b"/home/u/a/b");
        assert_eq!(resolve(b"/", b"a").unwrap(), b"/a");
        assert_eq!(resolve(b"", b"a").unwrap(), b"a");
        assert_eq!(resolve(b"/home/u", b"/etc//x").unwrap(), b"/etc/x");
        assert_eq!(resolve(b"/home/u", b"a/../b").unwrap_err().name, ErrorName::InvalidName);
    }

    #[test]
    fn join_and_last_component() {
        assert_eq!(join(b"", b"n"), b"n");
        assert_eq!(join(b"/", b"n"), b"/n");
        assert_eq!(join(b"/d", b"n"), b"/d/n");
        assert_eq!(join(b"d/", b"n"), b"d/n");
        assert_eq!(last_component(b"/a/b"), b"b");
        assert_eq!(last_component(b"b"), b"b");
        assert_eq!(last_component(b"/"), b"");
        assert_eq!(last_component(b""), b"");
    }

    #[test]
    fn entry_names() {
        for name in [&b"a"[..], b"...", b".a", b"a.", b"..a", b" ", b"\\", b"\xff"] {
            assert!(is_entry_name(name), "{name:?}");
        }
        for name in [&b""[..], b".", b"..", b"/", b"a/b", b"/a", b"a/", b"\0", b"a\0b", b"a\0"] {
            assert!(!is_entry_name(name), "{name:?}");
        }
    }

    #[test]
    fn display_marks_each_invalid_byte() {
        assert_eq!(display(b"caf\xc3\xa9"), "café");
        assert_eq!(display(b"a\xff\xfeb"), "a\u{fffd}\u{fffd}b");
        // A truncated sequence: one mark per byte, not one per sequence.
        assert_eq!(display(b"\xe2\x82"), "\u{fffd}\u{fffd}");
        assert_eq!(display(b""), "");
    }
}
