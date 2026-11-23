// SPDX-License-Identifier: LGPL-2.1-or-later
//! Location paths to request paths and back: the account's base path, percent-encoding, and `href`s of a
//! multistatus, which come from the server and are checked before use.

use netvfs_vfs::Status;

/// Longest decoded `href` taken from a server.
pub const MAX_HREF: usize = 8 * 1024;

/// The account's folder on the server: decoded, leading `/`, no trailing `/` (empty for the server root).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Base(Vec<u8>);

impl Base {
    /// `base_path` as the account stores it.
    ///
    /// # Errors
    /// `InvalidName` for a `.` or `..` component or a NUL.
    pub fn new(base_path: &str) -> Result<Self, Status> {
        let mut out = Vec::new();
        for part in base_path.split('/').filter(|p| !p.is_empty()) {
            check_component(part.as_bytes())?;
            out.push(b'/');
            out.extend_from_slice(part.as_bytes());
        }
        Ok(Self(out))
    }

    /// The decoded server path of location path `path` (`Names::encode` bytes, `/` separated, may be relative to
    /// the base); a folder gets a trailing `/`.
    ///
    /// # Errors
    /// `InvalidName` for a `.` or `..` component, an empty one inside, or a NUL.
    pub fn resolve(&self, path: &[u8], folder: bool) -> Result<Vec<u8>, Status> {
        let mut out = self.0.clone();
        for part in path.split(|b| *b == b'/').filter(|p| !p.is_empty()) {
            check_component(part)?;
            out.push(b'/');
            out.extend_from_slice(part);
        }
        if folder || out.is_empty() {
            out.push(b'/');
        }
        Ok(out)
    }
}

fn check_component(part: &[u8]) -> Result<(), Status> {
    if part == b"." || part == b".." || part.contains(&0) {
        return Err(Status::invalid_name(format!(
            "Invalid path component \"{}\"",
            String::from_utf8_lossy(part)
        )));
    }
    Ok(())
}

/// A request target: every byte but unreserved ones and `/` as `%XX`.
#[must_use]
pub fn encode(path: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(path.len());
    for &b in path {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            let digit = |d: u8| char::from(HEX.get(usize::from(d)).copied().unwrap_or(b'0'));
            out.push('%');
            out.push(digit(b >> 4));
            out.push(digit(b & 0xF));
        }
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Percent-decoding; `None` for a broken escape.
#[must_use]
pub fn decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.iter();
    while let Some(&b) = it.next() {
        if b == b'%' {
            let hi = hex(*it.next()?)?;
            let lo = hex(*it.next()?)?;
            out.push(hi.checked_mul(16)?.checked_add(lo)?);
        } else {
            out.push(b);
        }
    }
    Some(out)
}

/// The decoded path of an `href` (absolute URL or absolute path); `None` for anything else, a broken escape, a
/// NUL, or one longer than [`MAX_HREF`].
#[must_use]
pub fn href_path(href: &[u8]) -> Option<Vec<u8>> {
    let href = href.trim_ascii();
    let rest = match href.windows(3).position(|w| w == b"://") {
        Some(at) if href.get(..at)?.iter().all(u8::is_ascii_alphabetic) => {
            let after = href.get(at.checked_add(3)?..)?;
            after.get(after.iter().position(|b| *b == b'/')?..)?
        }
        _ => href,
    };
    if rest.first() != Some(&b'/') {
        return None;
    }
    let path = decode(rest)?;
    (path.len() <= MAX_HREF && !path.contains(&0)).then_some(path)
}

/// The name of `child` (decoded server path) when it is a direct entry of folder `dir` (decoded, trailing `/`):
/// one component, not `.` or `..`. `None` for `dir` itself and for anything else.
#[must_use]
pub fn child_name<'a>(dir: &[u8], child: &'a [u8]) -> Option<&'a [u8]> {
    let rest = child.strip_prefix(dir)?;
    let name = rest.strip_suffix(b"/").unwrap_or(rest);
    if name.is_empty() || name.contains(&b'/') || name == b"." || name == b".." {
        return None;
    }
    Some(name)
}

/// Whether `a` and `b` name the same resource: equal but for a trailing `/`.
#[must_use]
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.strip_suffix(b"/").unwrap_or(a) == b.strip_suffix(b"/").unwrap_or(b)
}

/// The last component of a location path; empty for the root.
#[must_use]
pub fn last_name(path: &[u8]) -> &[u8] {
    path.split(|b| *b == b'/').rfind(|p| !p.is_empty()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use netvfs_vfs::ErrorName;

    #[test]
    fn bases_are_normalised() {
        assert_eq!(Base::new("").unwrap(), Base(Vec::new()));
        assert_eq!(Base::new("/").unwrap(), Base(Vec::new()));
        assert_eq!(Base::new("remote.php//dav/").unwrap(), Base(b"/remote.php/dav".to_vec()));
        for bad in ["/a/../b", "/./a", "a\0b"] {
            assert_eq!(Base::new(bad).unwrap_err().name, ErrorName::InvalidName, "{bad}");
        }
    }

    #[test]
    fn paths_resolve_below_the_base() {
        let base = Base::new("/dav/files/al ice").unwrap();
        assert_eq!(base.resolve(b"", false).unwrap(), b"/dav/files/al ice");
        assert_eq!(base.resolve(b"/", true).unwrap(), b"/dav/files/al ice/");
        assert_eq!(base.resolve(b"/a//b", false).unwrap(), b"/dav/files/al ice/a/b");
        assert_eq!(base.resolve(b"a/b/", true).unwrap(), b"/dav/files/al ice/a/b/");
        let root = Base::default();
        assert_eq!(root.resolve(b"", false).unwrap(), b"/");
        assert_eq!(root.resolve(b"/", true).unwrap(), b"/");
        assert_eq!(root.resolve(b"/x", false).unwrap(), b"/x");
        for bad in [&b"/a/.."[..], b"./a", b"/a\0"] {
            assert_eq!(base.resolve(bad, false).unwrap_err().name, ErrorName::InvalidName);
        }
    }

    #[test]
    fn encoding_keeps_only_unreserved_bytes_and_slashes() {
        assert_eq!(encode(b"/a-b._~/Z9"), "/a-b._~/Z9");
        assert_eq!(encode(b"/a b/%?#+:\xff\x00"), "/a%20b/%25%3F%23%2B%3A%FF%00");
        assert_eq!(encode("/ä".as_bytes()), "/%C3%A4");
    }

    #[test]
    fn decoding_reverses_encoding() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(encode(&all).as_bytes()).unwrap(), all);
        assert_eq!(decode(b"%c3%A4+").unwrap(), "ä+".as_bytes());
        for bad in [&b"%"[..], b"%4", b"%4g", b"%g4", b"a%"] {
            assert_eq!(decode(bad), None);
        }
    }

    #[test]
    fn hrefs_give_paths() {
        assert_eq!(href_path(b"/a%20b/").unwrap(), b"/a b/");
        assert_eq!(href_path(b" https://nas:8443/x/y \n").unwrap(), b"/x/y");
        assert_eq!(href_path(b"HTTP://nas/").unwrap(), b"/");
        for bad in [&b"x/y"[..], b"https://nas", b"https://nas?x", b"/a%zz", b"/a%00", b"", b"1a://nas/x"] {
            assert_eq!(href_path(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        let long = [b"/".as_slice(), &[b'a'; 8 * 1024 - 1]].concat();
        assert!(href_path(&long).is_some());
        let longer = [long.as_slice(), b"b"].concat();
        assert_eq!(href_path(&longer), None);
    }

    #[test]
    fn children_are_one_level_down() {
        assert_eq!(child_name(b"/d/", b"/d/f"), Some(&b"f"[..]));
        assert_eq!(child_name(b"/d/", b"/d/sub/"), Some(&b"sub"[..]));
        for other in [&b"/d/"[..], b"/d", b"/d/a/b", b"/e/f", b"/d/./", b"/d/../", b"/d//"] {
            assert_eq!(child_name(b"/d/", other), None, "{}", String::from_utf8_lossy(other));
        }
    }

    #[test]
    fn same_ignores_a_trailing_slash() {
        assert!(same(b"/d/", b"/d"));
        assert!(same(b"/d", b"/d"));
        assert!(!same(b"/d", b"/e"));
        assert!(!same(b"/d//", b"/d"));
    }

    #[test]
    fn last_names() {
        assert_eq!(last_name(b"/a/b"), b"b");
        assert_eq!(last_name(b"a/b/"), b"b");
        assert_eq!(last_name(b"/"), b"");
        assert_eq!(last_name(b""), b"");
    }
}
