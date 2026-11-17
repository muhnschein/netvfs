// SPDX-License-Identifier: LGPL-2.1-or-later
//! Path validation on protocol bytes. `/`, `.` and NUL are ASCII and never occur inside a UTF-8 sequence or a surrogate-escaped byte (0x80–0xFF), so normalising the bytes equals normalising the decoded name.

use crate::status::Status;
use netvfs_bridge_proto::limits::MAX_PATH;
use std::fmt;

/// A normalised path in protocol bytes.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct NPath(Vec<u8>);

impl NPath {
    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, taken.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Whether it starts with `/`.
    #[must_use]
    pub fn is_absolute(&self) -> bool {
        self.0.first() == Some(&b'/')
    }
}

impl fmt::Debug for NPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NPath({:?})", String::from_utf8_lossy(&self.0))
    }
}

/// Validates and normalises a protocol path: `/docs//a/` becomes `/docs/a`.
///
/// # Errors
/// `InvalidName` for a path longer than [`MAX_PATH`] bytes, with a NUL byte,
/// or with a `.` or `..` component.
pub fn normalize(raw: &[u8]) -> Result<NPath, Status> {
    if raw.len() > MAX_PATH {
        return Err(Status::invalid_name("Path too long"));
    }
    if raw.contains(&0) {
        return Err(Status::invalid_name("Path contains NUL"));
    }
    let mut out = Vec::with_capacity(raw.len());
    if raw.first() == Some(&b'/') {
        out.push(b'/');
    }
    let mut first = true;
    for part in raw.split(|&b| b == b'/').filter(|p| !p.is_empty()) {
        if part == b"." || part == b".." {
            return Err(Status::invalid_name("Path components \".\" and \"..\" are not allowed"));
        }
        if !first {
            out.push(b'/');
        }
        out.extend_from_slice(part);
        first = false;
    }
    Ok(NPath(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netvfs_bridge_proto::ErrorName;

    fn ok(raw: &[u8]) -> Vec<u8> {
        normalize(raw).unwrap().into_bytes()
    }

    fn err(raw: &[u8]) -> ErrorName {
        normalize(raw).unwrap_err().name
    }

    #[test]
    fn normalize_table() {
        assert_eq!(ok(b"docs/a.txt"), b"docs/a.txt");
        assert_eq!(ok(b"/docs//a/"), b"/docs/a");
        assert_eq!(err(b"docs/../etc"), ErrorName::InvalidName);
        assert_eq!(err(b"./a"), ErrorName::InvalidName);
        assert_eq!(err(b"a\0b"), ErrorName::InvalidName);
        assert_eq!(ok(b"caf\xe9"), b"caf\xe9");
        assert_eq!(err(&vec![b'a'; MAX_PATH + 1]), ErrorName::InvalidName);
        assert_eq!(ok(&vec![b'a'; MAX_PATH]), vec![b'a'; MAX_PATH]);
    }

    #[test]
    fn roots_and_messages() {
        assert_eq!(ok(b""), b"");
        assert_eq!(ok(b"/"), b"/");
        assert_eq!(ok(b"///"), b"/");
        assert_eq!(ok(b"a//b"), b"a/b");
        assert_eq!(ok(b"..."), b"...");
        assert_eq!(ok(b".a/b."), b".a/b.");
        assert!(normalize(b"/x").unwrap().is_absolute());
        assert!(!normalize(b"x").unwrap().is_absolute());
        assert!(!normalize(b"").unwrap().is_absolute());
        assert_eq!(
            normalize(b"a/..").unwrap_err().message,
            "Path components \".\" and \"..\" are not allowed"
        );
        assert_eq!(normalize(b"a\0").unwrap_err().message, "Path contains NUL");
        assert_eq!(normalize(&vec![b'/'; MAX_PATH + 1]).unwrap_err().message, "Path too long");
        assert_eq!(normalize(b"/a/").unwrap().as_bytes(), b"/a");
        assert_eq!(format!("{:?}", normalize(b"/a").unwrap()), "NPath(\"/a\")");
    }
}
