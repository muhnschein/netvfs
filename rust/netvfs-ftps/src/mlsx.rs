// SPDX-License-Identifier: LGPL-2.1-or-later
//! `MLSD` and `MLST` entries (RFC 3659 7): `fact=value;...; name`. Server data: every line is parsed or
//! skipped, never trusted.

use netvfs_vfs::{Entry, EntryFlags, EntryType};

/// Most entries one listing may hold: a folder of 200 000 entries.
pub const MAX_ENTRIES: usize = 200_000;
/// Largest listing read.
pub const MAX_LISTING: usize = 32 * 1024 * 1024;

/// What a line names: the folder itself, its parent, or an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// `type=cdir`: the listed folder.
    Current(Entry),
    /// `type=pdir`, or a line without a usable name.
    Skip,
    /// A child.
    Child(Entry),
}

/// `YYYYMMDDHHMMSS[.fff]`, UTC, to milliseconds since the epoch.
#[must_use]
#[allow(clippy::arithmetic_side_effects, reason = "14 digits checked: years below 10 000")]
pub fn time_ms(value: &[u8]) -> Option<i64> {
    let (whole, frac) = match value.iter().position(|b| *b == b'.') {
        Some(at) => (value.get(..at)?, value.get(at.saturating_add(1)..)?),
        None => (value, &b""[..]),
    };
    if whole.len() != 14 || !whole.iter().all(u8::is_ascii_digit) || !frac.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let num = |from: usize, to: usize| -> i64 {
        whole.get(from..to).unwrap_or_default().iter().fold(0i64, |n, d| n * 10 + i64::from(d - b'0'))
    };
    let (y, mo, d, h, mi, s) = (num(0, 4), num(4, 6), num(6, 8), num(8, 10), num(10, 12), num(12, 14));
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let ms = frac
        .iter()
        .take(3)
        .enumerate()
        .fold(0i64, |n, (i, d)| n + i64::from(d - b'0') * [100, 10, 1].get(i).copied().unwrap_or(0));
    Some(((days * 24 + h) * 60 + mi) * 60_000 + s * 1000 + ms)
}

fn number(value: &[u8]) -> Option<u64> {
    if !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

fn octal(value: &[u8]) -> Option<u32> {
    if value.len() > 7 || !value.iter().all(|b| (b'0'..=b'7').contains(b)) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(value).ok()?, 8).ok().map(|m| m & 0o7777)
}

/// One entry line. `name` is the last path component when the server sends a path (`MLST`).
#[must_use]
pub fn parse(line: &[u8]) -> Line {
    let (facts, path) = if let Some(rest) = line.strip_prefix(b" ") {
        (&b""[..], rest)
    } else {
        match line.windows(2).position(|w| w == b"; ") {
            Some(at) => {
                (line.get(..at).unwrap_or_default(), line.get(at.saturating_add(2)..).unwrap_or_default())
            }
            None => return Line::Skip,
        }
    };
    let name = path.rsplit(|b| *b == b'/').next().unwrap_or_default();
    let mut entry = Entry { name: name.to_vec(), ..Entry::default() };
    let mut kind = None;
    for fact in facts.split(|b| *b == b';') {
        let Some(eq) = fact.iter().position(|b| *b == b'=') else { continue };
        let key = fact.get(..eq).unwrap_or_default().to_ascii_lowercase();
        let value = fact.get(eq.saturating_add(1)..).unwrap_or_default();
        match key.as_slice() {
            b"type" => kind = Some(value.to_ascii_lowercase()),
            b"size" => entry.size = number(value),
            b"modify" => entry.mtime_ms = time_ms(value),
            b"unix.mode" => entry.mode = octal(value),
            _ => {}
        }
    }
    entry.kind = match kind.as_deref() {
        Some(b"file") => EntryType::File,
        Some(b"dir" | b"cdir" | b"pdir") => EntryType::Directory,
        Some(t) if t.starts_with(b"os.unix=slink") || t.starts_with(b"os.unix=symlink") => EntryType::Symlink,
        Some(t) if t.starts_with(b"os.unix=") => EntryType::Special,
        _ => EntryType::Unknown,
    };
    if entry.kind == EntryType::Directory {
        entry.size = None;
    }
    if std::str::from_utf8(&entry.name).is_err() {
        entry.flags = EntryFlags::NAME_NOT_UTF8;
    }
    match kind.as_deref() {
        Some(b"cdir") => Line::Current(entry),
        Some(b"pdir") => Line::Skip,
        _ if entry.name.is_empty() || entry.name == b"." || entry.name == b".." => Line::Skip,
        _ => Line::Child(entry),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child(line: &[u8]) -> Entry {
        match parse(line) {
            Line::Child(e) => e,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn times_are_utc_milliseconds() {
        assert_eq!(time_ms(b"19700101000000"), Some(0));
        assert_eq!(time_ms(b"20261028000000"), Some(1_793_145_600_000));
        assert_eq!(time_ms(b"20000229235959.5"), Some(951_868_799_500));
        assert_eq!(time_ms(b"20000301000000.123456"), Some(951_868_800_123));
        assert_eq!(time_ms(b"19691231235959"), Some(-1000));
        for bad in [
            &b""[..],
            b"2026102800000",
            b"202610280000000",
            b"20261328000000",
            b"20261000000000",
            b"20261028240000",
            b"20261028006000",
            b"20261028000061",
            b"2026102800000x",
            b"20261028000000.x",
        ] {
            assert_eq!(time_ms(bad), None, "{bad:?}");
        }
        assert_eq!(time_ms(b"20261028000000."), Some(1_793_145_600_000));
        assert_eq!(time_ms(b"20261028000060"), Some(1_793_145_660_000));
    }

    #[test]
    fn entries_of_a_listing() {
        let e = child(b"type=file;size=28;modify=20261028000000;UNIX.mode=0644;unique=801g1; readme.txt");
        assert_eq!(e.name, b"readme.txt");
        assert_eq!(
            (e.kind, e.size, e.mtime_ms, e.mode),
            (EntryType::File, Some(28), Some(1_793_145_600_000), Some(0o644))
        );
        let d = child(b"Type=DIR;Size=4096;Modify=20261028000000; Deep");
        assert_eq!((d.kind, d.size), (EntryType::Directory, None));
        assert_eq!(child(b"type=OS.unix=slink:/x; l").kind, EntryType::Symlink);
        assert_eq!(child(b"type=OS.unix=symlink; l").kind, EntryType::Symlink);
        assert_eq!(child(b"type=OS.unix=chr-13/29; c").kind, EntryType::Special);
        assert_eq!(child(b"size=1; odd").kind, EntryType::Unknown);
        assert_eq!(
            child(b"type=file; name with spaces; and semicolons").name,
            b"name with spaces; and semicolons"
        );
        assert_eq!(child(b" no facts").name, b"no facts");
        assert_eq!(
            child(b"type=file;size=x;modify=bad;UNIX.mode=999; f"),
            Entry { name: b"f".to_vec(), kind: EntryType::File, ..Entry::default() }
        );
        assert_eq!(child(b"type=file;size=99999999999999999999999; f").size, None);
        assert_eq!(child(b"type=file;UNIX.mode=104755; f").mode, Some(0o4755));
        assert_eq!(child(b"type=file;UNIX.mode=10475577; f").mode, None);
        assert_eq!(child(b"type=file;UNIX.mode=0100644; f").mode, Some(0o644));
        assert_eq!(child(b"type=file;UNIX.mode=; f").mode, None);
        assert_eq!(child(b"type=file;size=; f").size, None);
        assert_eq!(child(b"type=file;size=+1; f").size, None);
        assert_eq!(child(b"type=file;size=00000000000000000000028; f").size, Some(28));
        assert_eq!(child(b"type=weird; w").kind, EntryType::Unknown);
        let latin = child(b"type=file; caf\xe9");
        assert_eq!(latin.flags, EntryFlags::NAME_NOT_UTF8);
        assert_eq!(child(b"type=file; caf\xc3\xa9").flags, EntryFlags::NONE);
    }

    #[test]
    fn folders_themselves_and_bad_lines() {
        assert!(
            matches!(parse(b"type=cdir;modify=20261028000000; /Documents"), Line::Current(e) if e.name == b"Documents" && e.kind == EntryType::Directory)
        );
        assert_eq!(parse(b"type=pdir; .."), Line::Skip);
        assert_eq!(parse(b"type=pdir; /srv"), Line::Skip);
        assert_eq!(parse(b"type=dir; ."), Line::Skip);
        assert_eq!(parse(b"type=dir; .."), Line::Skip);
        assert_eq!(parse(b"type=file;size=1;"), Line::Skip);
        assert_eq!(parse(b"type=file; "), Line::Skip);
        assert_eq!(parse(b""), Line::Skip);
        assert_eq!(child(b"type=file; /srv/a/b.txt").name, b"b.txt");
    }
}
