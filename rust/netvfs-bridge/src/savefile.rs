// SPDX-License-Identifier: LGPL-2.1-or-later
//! Atomic file replacement, as `QSaveFile` does it: a temporary file in the
//! same folder, written and synced, then renamed over the target. Readers
//! see the old file or the new one, never a part.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// The mode of the new file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The replaced file's permission bits; a new file gets `0666` less
    /// the umask (`QSaveFile`).
    KeepOrDefault,
    /// Exactly these bits (`QFileDevice::setPermissions` after opening).
    Exactly(u32),
}

/// Replaces `path` by `contents`, creating it if needed.
///
/// # Errors
/// When the folder is not writable or the disk is full; `path` is then
/// unchanged and no temporary file is left.
pub fn save(path: &Path, contents: &[u8], mode: Mode) -> io::Result<()> {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let (temp, mut file) = create_temporary(path, &NEXT)?;
    let written = write_synced(&mut file, path, contents, mode).and_then(|()| fs::rename(&temp, path));
    if written.is_err() {
        fs::remove_file(&temp).ok();
    }
    written
}

fn write_synced(file: &mut File, path: &Path, contents: &[u8], mode: Mode) -> io::Result<()> {
    let bits = match mode {
        Mode::Exactly(bits) => Some(bits),
        Mode::KeepOrDefault => fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o777),
    };
    if let Some(bits) = bits {
        file.set_permissions(fs::Permissions::from_mode(bits))?;
    }
    file.write_all(contents)?;
    file.sync_all()
}

/// `<name>.<pid>-<n>` next to `path`, created exclusively; `next` counts
/// the names tried. A name left by an earlier process is skipped.
fn create_temporary(path: &Path, next: &AtomicU32) -> io::Result<(PathBuf, File)> {
    let name = path.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut last = io::Error::from(io::ErrorKind::AlreadyExists);
    for _ in 0..16 {
        let n = next.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = name.to_os_string();
        temp_name.push(format!(".{}-{n}", std::process::id()));
        let temp = path.with_file_name(temp_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o666)
            .custom_flags(libc::O_CLOEXEC)
            .open(&temp)
        {
            Ok(file) => return Ok((temp, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn replaces_atomically_with_its_mode() {
        let dir = TempDir::new();
        let path = dir.join("f");
        save(&path, b"one", Mode::Exactly(0o600)).unwrap();
        assert_eq!((fs::read(&path).unwrap(), mode(&path)), (b"one".to_vec(), 0o600));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        save(&path, b"two", Mode::KeepOrDefault).unwrap();
        assert_eq!((fs::read(&path).unwrap(), mode(&path)), (b"two".to_vec(), 0o640));
        save(&path, b"three", Mode::Exactly(0o600)).unwrap();
        assert_eq!(mode(&path), 0o600);
        // A new file: 0666 less the umask, as the temporary file was created.
        let fresh = dir.join("g");
        save(&fresh, b"", Mode::KeepOrDefault).unwrap();
        let probe = dir.join("probe");
        OpenOptions::new().write(true).create_new(true).mode(0o666).open(&probe).unwrap();
        assert_eq!(mode(&fresh), mode(&probe));
        // Nothing else is left in the folder.
        let mut names: Vec<_> = fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        names.sort();
        assert_eq!(names, ["f", "g", "probe"]);
    }

    #[test]
    fn failures_leave_nothing() {
        let dir = TempDir::new();
        save(&dir.join("missing/f"), b"x", Mode::KeepOrDefault).unwrap_err();
        // Renaming over a folder fails after the write.
        fs::create_dir(dir.join("d")).unwrap();
        fs::write(dir.join("d/inside"), b"").unwrap();
        save(&dir.join("d"), b"x", Mode::KeepOrDefault).unwrap_err();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(
            save(Path::new("/"), b"x", Mode::KeepOrDefault).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn temporary_names_do_not_collide() {
        let dir = TempDir::new();
        let path = dir.join("f");
        let next = AtomicU32::new(0);
        let (a, _) = create_temporary(&path, &next).unwrap();
        let (b, _) = create_temporary(&path, &next).unwrap();
        assert_eq!(a, dir.join(&format!("f.{}-0", std::process::id())));
        assert_eq!(b, dir.join(&format!("f.{}-1", std::process::id())));
        // Names in use are skipped; up to 16 are tried.
        for n in 2..4 {
            dir.write(&format!("f.{}-{n}", std::process::id()), "");
        }
        let (c, _) = create_temporary(&path, &next).unwrap();
        assert_eq!(c, dir.join(&format!("f.{}-4", std::process::id())));
        for n in 5..21 {
            dir.write(&format!("f.{}-{n}", std::process::id()), "");
        }
        assert_eq!(create_temporary(&path, &next).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(next.load(Ordering::Relaxed), 21);
        // Other failures are not retried.
        let missing = dir.join("missing/f");
        assert_eq!(create_temporary(&missing, &next).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(next.load(Ordering::Relaxed), 22);
    }
}
