// SPDX-License-Identifier: LGPL-2.1-or-later
//! Names and paths: SMB's UTF-16LE and netvfs's protocol bytes (XC-4), the
//! path rules of `Paths::normalize` (C-15, M-8) and `Paths::checkWindowsPath`
//! (M-9), and share names (XM-2).
//!
//! Protocol bytes are WTF-8: UTF-8, with a lone surrogate of a UTF-16 name
//! in its three-byte form, so that every name a server sends maps to bytes
//! and back without loss (patch 0006 of the libsmb2 era). A name that is not
//! well-formed UTF-8 is flagged `NAME_NOT_UTF8` in entries.

use netvfs_vfs::Status;

/// A share name's longest length in UTF-16 units (NNLEN).
pub const MAX_SHARE_NAME: usize = 80;
/// Characters Windows refuses in a file name.
const WINDOWS_FORBIDDEN: &str = "\\:*?\"<>|";
/// Characters Windows refuses in a share name; ',' also separates the
/// account option `shares`.
const SHARE_FORBIDDEN: &str = "/\\:*?\"<>|[]+=;,";

/// UTF-16 to WTF-8: pairs as UTF-8, a lone surrogate in its 3-byte form.
#[must_use]
pub fn wtf8_from_utf16(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in char::decode_utf16(units.iter().copied()) {
        let code = match unit {
            Ok(c) => u32::from(c),
            Err(lone) => u32::from(lone.unpaired_surrogate()),
        };
        push_utf8(&mut out, code);
    }
    out
}

/// Generalised UTF-8 of one code point (surrogates included).
fn push_utf8(out: &mut Vec<u8>, code: u32) {
    let byte = |v: u32| u8::try_from(v & 0xFF).unwrap_or_default();
    if code < 0x80 {
        out.push(byte(code));
    } else if code < 0x800 {
        out.extend_from_slice(&[byte(0xC0 | code >> 6), byte(0x80 | (code & 0x3F))]);
    } else if code < 0x1_0000 {
        out.extend_from_slice(&[
            byte(0xE0 | code >> 12),
            byte(0x80 | (code >> 6 & 0x3F)),
            byte(0x80 | (code & 0x3F)),
        ]);
    } else {
        out.extend_from_slice(&[
            byte(0xF0 | code >> 18),
            byte(0x80 | (code >> 12 & 0x3F)),
            byte(0x80 | (code >> 6 & 0x3F)),
            byte(0x80 | (code & 0x3F)),
        ]);
    }
}

/// WTF-8 to UTF-16; `None` for bytes that are not WTF-8 (malformed or
/// overlong sequences, code points above U+10FFFF, and a surrogate pair
/// written as two 3-byte sequences, which [`wtf8_from_utf16`] never makes).
#[must_use]
pub fn utf16_from_wtf8(bytes: &[u8]) -> Option<Vec<u16>> {
    let mut units: Vec<u16> = Vec::new();
    let mut rest = bytes;
    while let Some((&lead, tail)) = rest.split_first() {
        let (len, min, initial) = match lead {
            0x00..=0x7F => (0usize, 0u32, u32::from(lead)),
            0xC0..=0xDF => (1, 0x80, u32::from(lead & 0x1F)),
            0xE0..=0xEF => (2, 0x800, u32::from(lead & 0x0F)),
            0xF0..=0xF7 => (3, 0x1_0000, u32::from(lead & 0x07)),
            _ => return None,
        };
        let continuation = tail.get(..len)?;
        let mut code = initial;
        for &c in continuation {
            if c & 0xC0 != 0x80 {
                return None;
            }
            code = code << 6 | u32::from(c & 0x3F);
        }
        if code < min || code > 0x10_FFFF {
            return None;
        }
        rest = tail.get(len..)?;
        if let Ok(c) = char::try_from(code) {
            let mut buf = [0u16; 2];
            units.extend_from_slice(c.encode_utf16(&mut buf));
        } else {
            // A surrogate: a low one right after a high one would be a
            // pair that WTF-8 writes as one 4-byte sequence.
            let unit = u16::try_from(code).ok()?;
            if (0xDC00..=0xDFFF).contains(&unit)
                && units.last().is_some_and(|u| (0xD800..=0xDBFF).contains(u))
            {
                return None;
            }
            units.push(unit);
        }
    }
    Some(units)
}

/// UTF-16LE bytes of `units`.
#[must_use]
pub fn utf16le(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|u| u.to_le_bytes()).collect()
}

/// The UTF-16 units of UTF-16LE bytes; `None` for an odd length.
#[must_use]
pub fn units_of(bytes: &[u8]) -> Option<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    Some(bytes.chunks_exact(2).filter_map(|c| <[u8; 2]>::try_from(c).ok()).map(u16::from_le_bytes).collect())
}

/// Text of WTF-8 bytes for messages (lossy).
#[must_use]
pub fn display(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The components of a path: `Paths::normalize` (C-15), then relative to
/// the share root (M-8: a leading `/` is dropped).
///
/// # Errors
/// `InvalidName` for a NUL or a `.`/`..` component.
pub fn components(path: &[u8]) -> Result<Vec<&[u8]>, Status> {
    if path.contains(&0) {
        return Err(Status::invalid_name("Path contains a NUL character"));
    }
    let parts: Vec<&[u8]> = path.split(|b| *b == b'/').filter(|p| !p.is_empty()).collect();
    if parts.iter().any(|p| *p == b"." || *p == b"..") {
        return Err(Status::invalid_name("Path components \".\" and \"..\" are not allowed"));
    }
    Ok(parts)
}

/// `Paths::windowsComponentProblem` (M-9), for a component given as UTF-16.
fn windows_problem(component: &[u8], units: &[u16]) -> Option<String> {
    let shown = display(component);
    for c in char::decode_utf16(units.iter().copied()) {
        let Ok(c) = c else { continue };
        if WINDOWS_FORBIDDEN.contains(c) {
            return Some(format!("\"{shown}\" contains the character {c}"));
        }
        if u32::from(c) < 0x20 {
            return Some(format!("\"{shown}\" contains a control character"));
        }
    }
    if matches!(units.last(), Some(0x20 | 0x2E)) {
        return Some(format!("\"{shown}\" ends in a space or a dot"));
    }
    None
}

/// The SMB path (UTF-16, `\`-separated, relative to the share root) of the
/// components: each must be WTF-8 and a valid Windows name.
///
/// # Errors
/// `InvalidName` for bytes that are not WTF-8; `Internal` for a name
/// Windows servers cannot store (M-9, as `Paths::checkWindowsPath`).
pub fn smb_path(components: &[&[u8]]) -> Result<Vec<u16>, Status> {
    let mut out = Vec::new();
    for (i, component) in components.iter().enumerate() {
        let units = utf16_from_wtf8(component)
            .ok_or_else(|| Status::invalid_name(format!("\"{}\" is not a valid name", display(component))))?;
        if let Some(problem) = windows_problem(component, &units) {
            return Err(Status::internal(problem));
        }
        if i > 0 {
            out.push(u16::from(b'\\'));
        }
        out.extend_from_slice(&units);
    }
    Ok(out)
}

/// `validShareName` (XM-2, XM-3): not empty, at most 80 UTF-16 units, not
/// `.` or `..`, no character Windows refuses in share names, no control
/// character, no surrogate.
#[must_use]
pub fn valid_share_name(name: &str) -> bool {
    if name.is_empty() || name.encode_utf16().count() > MAX_SHARE_NAME || name == "." || name == ".." {
        return false;
    }
    !name.chars().any(|c| u32::from(c) < 0x20 || c == '\u{7f}' || SHARE_FORBIDDEN.contains(c))
}

/// Text cleaned of control characters, at most `max` characters (share
/// remarks).
#[must_use]
pub fn clean_text(text: &str, max: usize) -> String {
    text.chars().take(max).filter(|c| u32::from(*c) >= 0x20 && *c != '\u{7f}').collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use netvfs_vfs::ErrorName;

    fn u(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn utf8_names_round_trip() {
        for s in [
            "",
            "a",
            "Ünïcödé",
            "日本語",
            "emoji 😀 x",
            "\u{7f}\u{80}\u{7ff}\u{800}\u{ffff}\u{10000}\u{10ffff}",
        ] {
            let bytes = wtf8_from_utf16(&u(s));
            assert_eq!(bytes, s.as_bytes(), "{s}");
            assert_eq!(utf16_from_wtf8(&bytes).unwrap(), u(s), "{s}");
        }
    }

    #[test]
    fn lone_surrogates_are_wtf8_and_come_back() {
        for units in
            [vec![0xD800], vec![0xDC00], vec![0x61, 0xDBFF], vec![0xDFFF, 0x62], vec![0xDC00, 0xD800]]
        {
            let bytes = wtf8_from_utf16(&units);
            std::str::from_utf8(&bytes).unwrap_err();
            assert_eq!(utf16_from_wtf8(&bytes).unwrap(), units, "{units:x?}");
        }
        assert_eq!(wtf8_from_utf16(&[0xD800]), [0xED, 0xA0, 0x80]);
        assert_eq!(wtf8_from_utf16(&[0xDFFF]), [0xED, 0xBF, 0xBF]);
    }

    #[test]
    fn malformed_bytes_are_refused() {
        for bad in [
            &[0x80][..],
            &[0xC3],
            &[0xC3, 0x41],
            &[0xC0, 0x80],             // overlong NUL
            &[0xE0, 0x80, 0x80],       // overlong
            &[0xF0, 0x80, 0x80, 0x80], // overlong
            &[0xF4, 0x90, 0x80, 0x80], // above U+10FFFF
            &[0xF8, 0x88, 0x80, 0x80, 0x80],
            &[0xFF],
            &[0xED, 0xA0, 0x80, 0xED, 0xB0, 0x80], // a pair as two 3-byte sequences
            &[0xE2, 0x82],
        ] {
            assert_eq!(utf16_from_wtf8(bad), None, "{bad:x?}");
        }
        // A low surrogate before a high one is not a pair.
        assert_eq!(utf16_from_wtf8(&[0xED, 0xB0, 0x80, 0xED, 0xA0, 0x80]).unwrap(), [0xDC00, 0xD800]);
        // The boundaries of each length.
        assert_eq!(utf16_from_wtf8(&[0xC2, 0x80]).unwrap(), [0x80]);
        assert_eq!(utf16_from_wtf8(&[0xE0, 0xA0, 0x80]).unwrap(), [0x800]);
        assert_eq!(utf16_from_wtf8(&[0xF0, 0x90, 0x80, 0x80]).unwrap(), [0xD800, 0xDC00]);
        assert_eq!(utf16_from_wtf8(&[0xF4, 0x8F, 0xBF, 0xBF]).unwrap(), [0xDBFF, 0xDFFF]);
    }

    #[test]
    fn utf16le_and_back() {
        assert_eq!(utf16le(&[0x41, 0x20AC]), [0x41, 0, 0xAC, 0x20]);
        assert_eq!(units_of(&[0x41, 0, 0xAC, 0x20]).unwrap(), [0x41, 0x20AC]);
        assert_eq!(units_of(&[0x41]), None);
        assert_eq!(units_of(&[]).unwrap(), Vec::<u16>::new());
    }

    #[test]
    fn components_normalise() {
        assert_eq!(components(b"").unwrap(), Vec::<&[u8]>::new());
        assert_eq!(components(b"/").unwrap(), Vec::<&[u8]>::new());
        assert_eq!(components(b"//a//b/").unwrap(), [&b"a"[..], b"b"]);
        assert_eq!(components(b"a/.b/c..").unwrap(), [&b"a"[..], b".b", b"c.."]);
        let e = components(b"a/../b").unwrap_err();
        assert_eq!(
            (e.name, e.message.as_str()),
            (ErrorName::InvalidName, "Path components \".\" and \"..\" are not allowed")
        );
        assert_eq!(components(b"./a").unwrap_err().name, ErrorName::InvalidName);
        let e = components(b"a\0b").unwrap_err();
        assert_eq!((e.name, e.message.as_str()), (ErrorName::InvalidName, "Path contains a NUL character"));
    }

    #[test]
    fn smb_paths_are_backslashed_utf16() {
        assert_eq!(smb_path(&[]).unwrap(), Vec::<u16>::new());
        assert_eq!(smb_path(&[b"dir", "f\u{fc}r.txt".as_bytes()]).unwrap(), u("dir\\f\u{fc}r.txt"));
        assert_eq!(smb_path(&[&[0xED, 0xA0, 0x80]]).unwrap(), [0xD800]);
        let e = smb_path(&[&[0xFF]]).unwrap_err();
        assert_eq!(e.name, ErrorName::InvalidName);
    }

    #[test]
    fn windows_rules_are_internal_errors() {
        for (name, message) in [
            ("bad|name", "\"bad|name\" contains the character |"),
            ("a:b", "\"a:b\" contains the character :"),
            ("a\\b", "\"a\\b\" contains the character \\"),
            ("q?", "\"q?\" contains the character ?"),
            ("s*", "\"s*\" contains the character *"),
            ("\"", "\"\"\" contains the character \""),
            ("<", "\"<\" contains the character <"),
            (">", "\">\" contains the character >"),
            ("tab\there", "\"tab\there\" contains a control character"),
            ("\u{1f}", "\"\u{1f}\" contains a control character"),
            ("trailing ", "\"trailing \" ends in a space or a dot"),
            ("trailing.", "\"trailing.\" ends in a space or a dot"),
        ] {
            let e = smb_path(&[b"ok", name.as_bytes()]).unwrap_err();
            assert_eq!((e.name, e.message.as_str()), (ErrorName::Internal, message), "{name}");
        }
        for fine in [" lead", ".hidden", "a.b", "x y"] {
            smb_path(&[fine.as_bytes()]).unwrap();
        }
        smb_path(&[b" "]).unwrap_err();
    }

    #[test]
    fn share_names() {
        for good in ["backup", "hidden$", "Films & music", "a-b_c", &"x".repeat(80), "日本"] {
            assert!(valid_share_name(good), "{good}");
        }
        for bad in [
            "",
            ".",
            "..",
            &"x".repeat(81),
            "a/b",
            "a\\b",
            "a:b",
            "a*",
            "a?",
            "a\"",
            "a<",
            "a>",
            "a|",
            "a[",
            "a]",
            "a+",
            "a=",
            "a;",
            "a,",
            "a\u{1}",
            "a\u{7f}",
        ] {
            assert!(!valid_share_name(bad), "{bad}");
        }
    }

    #[test]
    fn remarks_are_cleaned_and_capped() {
        assert_eq!(clean_text("Films\tand\u{7f} music\n", 256), "Filmsand music");
        assert_eq!(clean_text("abcdef", 3), "abc");
        assert_eq!(clean_text("\u{1}\u{1}abc", 3), "a");
        assert_eq!(display(&[0x61, 0xFF]), "a\u{fffd}");
    }
}
