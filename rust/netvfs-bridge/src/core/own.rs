// SPDX-License-Identifier: LGPL-2.1-or-later
//! The items an app added at an add level ([`crate::access`]), kept in `~/.local/share/netvfs/bridge/<id>/added`, one per line `<since ms> <P|W> <location> <path hex>` (`P`: being written, `W`: written), so that a resume or clean-up works after the bridge restarted.

use crate::access::{OWN_LIFETIME, Own};
use crate::savefile::{self, Mode};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// At most this many items are kept; the oldest go first.
pub const MAX_ITEMS: usize = 4096;

/// Milliseconds since the epoch, now.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn lifetime_ms() -> i64 {
    i64::try_from(OWN_LIFETIME.as_millis()).unwrap_or(i64::MAX)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Item {
    written: bool,
    since_ms: i64,
}

/// The app's own items.
#[derive(Debug)]
pub struct OwnItems {
    path: PathBuf,
    items: BTreeMap<(String, Vec<u8>), Item>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len().saturating_mul(2)), |mut s, b| {
        write!(s, "{b:02x}").ok();
        s
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digits = text.as_bytes().chunks(2).map(|pair| std::str::from_utf8(pair).ok());
    digits.map(|d| d.and_then(|d| u8::from_str_radix(d, 16).ok())).collect()
}

fn parse_line(line: &str) -> Option<((String, Vec<u8>), Item)> {
    let mut fields = line.split(' ');
    let since_ms = fields.next()?.parse::<i64>().ok()?;
    let written = match fields.next()? {
        "W" => true,
        "P" => false,
        _ => return None,
    };
    let loc = fields.next().filter(|l| !l.is_empty())?.to_owned();
    let path = unhex(fields.next()?)?;
    fields.next().is_none().then_some(((loc, path), Item { written, since_ms }))
}

impl OwnItems {
    /// The items stored in `path` that are still the app's at `now_ms`.
    #[must_use]
    pub fn load(path: impl Into<PathBuf>, now_ms: i64) -> Self {
        let path = path.into();
        let text = std::fs::read(&path).unwrap_or_default();
        let items = String::from_utf8_lossy(&text).lines().filter_map(parse_line).collect();
        let mut own = Self { path, items };
        own.prune(now_ms);
        own
    }

    /// Whether `path` in `loc` is the app's at `now_ms`.
    #[must_use]
    pub fn own(&self, loc: &str, path: &[u8], now_ms: i64) -> Own {
        match self.items.get(&(loc.to_owned(), path.to_vec())) {
            Some(item) if now_ms.saturating_sub(item.since_ms) < lifetime_ms() => {
                if item.written {
                    Own::Written
                } else {
                    Own::Writing
                }
            }
            _ => Own::No,
        }
    }

    /// Records `own` for `path` in `loc` (`Own::No` forgets it) and saves the file when that changed something.
    pub fn set(&mut self, loc: &str, path: &[u8], own: Own, now_ms: i64) {
        let key = (loc.to_owned(), path.to_vec());
        let before = self.items.get(&key).copied();
        match own {
            Own::No => {
                self.items.remove(&key);
            }
            Own::Writing | Own::Written => {
                let since_ms = before.map_or(now_ms, |item| item.since_ms);
                self.items.insert(key, Item { written: own == Own::Written, since_ms });
            }
        }
        let pruned = self.prune(now_ms);
        if pruned || self.items.get(&(loc.to_owned(), path.to_vec())).copied() != before {
            self.save();
        }
    }

    fn prune(&mut self, now_ms: i64) -> bool {
        let before = self.items.len();
        self.items.retain(|_, item| now_ms.saturating_sub(item.since_ms) < lifetime_ms());
        while self.items.len() > MAX_ITEMS {
            let oldest = self.items.iter().min_by_key(|(_, item)| item.since_ms).map(|(key, _)| key.clone());
            if let Some(key) = oldest {
                self.items.remove(&key);
            }
        }
        self.items.len() != before
    }

    fn save(&self) {
        let mut text = String::new();
        for ((loc, path), item) in &self.items {
            let state = if item.written { 'W' } else { 'P' };
            writeln!(text, "{} {state} {loc} {}", item.since_ms, hex(path)).ok();
        }
        let saved = self
            .path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| savefile::save(&self.path, text.as_bytes(), Mode::KeepOrDefault));
        if let Err(e) = saved {
            crate::log::warning(format_args!("Cannot store the items this app added: {e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    const HOUR: i64 = 3_600_000;

    #[test]
    fn items_live_a_day_and_survive_a_restart() {
        let dir = TempDir::new();
        let file = dir.join("sub/added");
        let mut own = OwnItems::load(&file, 0);
        assert_eq!(own.own("account:1", b"/a", 0), Own::No);
        own.set("account:1", b"/a", Own::Writing, 10);
        own.set("account:1", b"/a b\n", Own::Written, 20);
        own.set("account:2", b"/a", Own::Written, 30);
        assert_eq!(own.own("account:1", b"/a", 11), Own::Writing);
        assert_eq!(own.own("account:1", b"/a b\n", 21), Own::Written);
        assert_eq!(own.own("account:3", b"/a", 21), Own::No);
        assert_eq!(own.own("account:1", b"/b", 21), Own::No);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "10 P account:1 2f61\n20 W account:1 2f6120620a\n30 W account:2 2f61\n"
        );
        let again = OwnItems::load(&file, 40);
        assert_eq!(again.own("account:1", b"/a", 40), Own::Writing);
        assert_eq!(again.own("account:2", b"/a", 40), Own::Written);
        own.set("account:1", b"/a", Own::Written, 24 * HOUR);
        assert_eq!(own.own("account:1", b"/a", 24 * HOUR + 9), Own::Written);
        assert_eq!(own.own("account:1", b"/a", 24 * HOUR + 10), Own::No);
        let later = OwnItems::load(&file, 24 * HOUR + 25);
        assert_eq!(later.own("account:2", b"/a", 24 * HOUR + 25), Own::Written);
        assert_eq!(later.own("account:1", b"/a", 24 * HOUR + 25), Own::No);
        own.set("account:1", b"/a b\n", Own::No, 50);
        assert_eq!(own.own("account:1", b"/a b\n", 50), Own::No);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "10 W account:1 2f61\n30 W account:2 2f61\n");
    }

    #[test]
    fn expired_items_go_when_anything_changes() {
        let dir = TempDir::new();
        let file = dir.join("added");
        let mut own = OwnItems::load(&file, 0);
        own.set("l", b"/old", Own::Written, 0);
        own.set("l", b"/new", Own::Writing, 24 * HOUR);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{} P l 2f6e6577\n", 24 * HOUR));
        std::fs::remove_file(&file).unwrap();
        own.set("l", b"/new", Own::Writing, 24 * HOUR + 1);
        assert!(!file.exists(), "no change, no write");
        own.set("l", b"/gone", Own::No, 24 * HOUR + 1);
        assert!(!file.exists());
    }

    #[test]
    fn the_oldest_go_beyond_the_cap() {
        let dir = TempDir::new();
        let mut own = OwnItems::load(dir.join("added"), 0);
        for n in 0..MAX_ITEMS {
            let item = Item { written: true, since_ms: i64::try_from(n).unwrap() };
            own.items.insert(("l".to_owned(), format!("/{n}").into_bytes()), item);
        }
        own.set("l", format!("/{MAX_ITEMS}").as_bytes(), Own::Written, 4096);
        assert_eq!(own.items.len(), MAX_ITEMS);
        assert_eq!(own.own("l", b"/0", 5000), Own::No);
        assert_eq!(own.own("l", b"/1", 5000), Own::Written);
        assert_eq!(own.own("l", format!("/{MAX_ITEMS}").as_bytes(), 5000), Own::Written);
    }

    #[test]
    fn bad_lines_are_skipped() {
        let dir = TempDir::new();
        let file = dir.join("added");
        std::fs::write(
            &file,
            "5 W l 2f61\nx W l 2f62\n5 X l 2f63\n5 W  2f64\n5 W l 2f6\n5 W l zz\n5 W l 2f65 x\n5 P m\n\n6 P m 2f66\n",
        )
        .unwrap();
        let own = OwnItems::load(&file, 10);
        assert_eq!(own.items.len(), 2);
        assert_eq!(own.own("l", b"/a", 10), Own::Written);
        assert_eq!(own.own("m", b"/f", 10), Own::Writing);
        assert_eq!(unhex(""), Some(vec![]));
        assert_eq!(hex(&[0, 0xff, 0x10]), "00ff10");
    }

    #[test]
    fn unwritable_files_are_logged() {
        let dir = TempDir::new();
        std::fs::write(dir.join("f"), b"").unwrap();
        let mut own = OwnItems::load(dir.join("f/added"), 0);
        own.set("l", b"/a", Own::Writing, 0);
        assert_eq!(own.own("l", b"/a", 1), Own::Writing, "kept in memory");
        assert!(now_ms() > 1_700_000_000_000);
    }
}
