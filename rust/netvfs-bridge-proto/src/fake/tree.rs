// SPDX-License-Identifier: LGPL-2.1-or-later
//! The fake server's in-memory file tree for one location. Errors use netvfs error names so they
//! travel as `org.netvfs.Error.<Name>`.

use crate::errors::ErrorName;
use crate::limits::MAX_PATH;
use crate::wire::{WireEntry, entry_flags};
use std::collections::BTreeMap;

/// A tree error: name plus message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeError {
    /// The error name.
    pub name: ErrorName,
    /// The message.
    pub message: String,
}

type TResult<T> = Result<T, TreeError>;

fn err<T>(name: ErrorName, message: &str) -> TResult<T> {
    Err(TreeError { name, message: message.to_owned() })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    File { data: Vec<u8>, mtime_ms: i64, mode: i32 },
    Dir { mtime_ms: i64, mode: i32 },
    Link { target: Vec<u8> },
}

impl Node {
    fn kind(&self) -> u8 {
        match self {
            Self::File { .. } => 1,
            Self::Dir { .. } => 2,
            Self::Link { .. } => 3,
        }
    }
}

/// Counts of a removed tree (`JobFinished.extra`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub files: i64,
    pub dirs: i64,
}

/// Normalised path (no empty or `.` components) as bytes; `..` is refused.
pub fn normalize(raw: &[u8]) -> TResult<Vec<u8>> {
    if raw.len() > MAX_PATH {
        return err(ErrorName::InvalidName, "Path too long");
    }
    let mut out: Vec<u8> = Vec::new();
    for comp in raw.split(|b| *b == b'/') {
        if comp.is_empty() || comp == b"." {
            continue;
        }
        if comp == b".." || comp.contains(&0) {
            return err(ErrorName::InvalidName, "Path component not allowed");
        }
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(comp);
    }
    Ok(out)
}

fn parent_of(path: &[u8]) -> Vec<u8> {
    let end = path.iter().rposition(|b| *b == b'/').unwrap_or(0);
    path.get(..end).unwrap_or_default().to_vec()
}

fn name_of(path: &[u8]) -> &[u8] {
    path.rsplit(|b| *b == b'/').next().unwrap_or(path)
}

fn is_under(path: &[u8], dir: &[u8]) -> bool {
    if dir.is_empty() {
        return !path.is_empty();
    }
    path.strip_prefix(dir).is_some_and(|rest| rest.first() == Some(&b'/'))
}

#[derive(Debug, Clone)]
pub struct Tree {
    nodes: BTreeMap<Vec<u8>, Node>,
    /// Fixed timestamp so entries are reproducible.
    pub now_ms: i64,
}

impl Default for Tree {
    fn default() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(Vec::new(), Node::Dir { mtime_ms: 1_700_000_000_000, mode: 0o755 });
        Self { nodes, now_ms: 1_700_000_000_000 }
    }
}

impl Tree {
    #[must_use]
    pub fn node(&self, path: &[u8]) -> Option<&Node> {
        self.nodes.get(path)
    }

    #[must_use]
    pub fn used_bytes(&self) -> i64 {
        self.nodes
            .values()
            .map(|n| match n {
                Node::File { data, .. } => i64::try_from(data.len()).unwrap_or(i64::MAX),
                _ => 0,
            })
            .sum()
    }

    pub fn put_file(&mut self, path: &[u8], data: &[u8]) {
        self.put_dirs(&parent_of(path));
        self.nodes
            .insert(path.to_vec(), Node::File { data: data.to_vec(), mtime_ms: self.now_ms, mode: 0o644 });
    }

    pub fn put_dirs(&mut self, path: &[u8]) {
        let mut cur: Vec<u8> = Vec::new();
        for comp in path.split(|b| *b == b'/').filter(|c| !c.is_empty()) {
            if !cur.is_empty() {
                cur.push(b'/');
            }
            cur.extend_from_slice(comp);
            self.nodes.entry(cur.clone()).or_insert(Node::Dir { mtime_ms: self.now_ms, mode: 0o755 });
        }
    }

    pub fn put_symlink(&mut self, path: &[u8], target: &[u8]) {
        self.put_dirs(&parent_of(path));
        self.nodes.insert(path.to_vec(), Node::Link { target: target.to_vec() });
    }

    fn resolve(&self, path: &[u8]) -> TResult<Vec<u8>> {
        let mut cur = path.to_vec();
        for _ in 0..16 {
            match self.nodes.get(&cur) {
                Some(Node::Link { target }) => {
                    let base = if target.starts_with(b"/") { Vec::new() } else { parent_of(&cur) };
                    let mut joined = base;
                    joined.push(b'/');
                    joined.extend_from_slice(target);
                    cur = normalize(&joined)?;
                }
                Some(_) => return Ok(cur),
                None => return err(ErrorName::NotFound, "No such file or directory"),
            }
        }
        err(ErrorName::ProtocolError, "Too many levels of symbolic links")
    }

    fn entry_of(&self, path: &[u8], node: &Node) -> WireEntry {
        let name = name_of(path);
        let mut e = WireEntry::unknown(name, node.kind());
        if name.first() == Some(&b'.') {
            e.flags |= entry_flags::HIDDEN;
        }
        if std::str::from_utf8(name).is_err() {
            e.flags |= entry_flags::NAME_NOT_UTF8;
        }
        match node {
            Node::File { data, mtime_ms, mode } => {
                e.size = i64::try_from(data.len()).unwrap_or(i64::MAX);
                e.mtime_ms = *mtime_ms;
                e.mode = *mode;
            }
            Node::Dir { mtime_ms, mode } => {
                e.mtime_ms = *mtime_ms;
                e.mode = *mode;
            }
            Node::Link { target } => {
                e.size = i64::try_from(target.len()).unwrap_or(i64::MAX);
                match self.resolve(path).ok().and_then(|p| self.nodes.get(&p)) {
                    Some(t) => e.target_kind = t.kind(),
                    None => e.flags |= entry_flags::TARGET_UNKNOWN,
                }
            }
        }
        e
    }

    pub fn stat(&self, path: &[u8], follow: bool) -> TResult<WireEntry> {
        let real = if follow { self.resolve(path)? } else { path.to_vec() };
        match self.nodes.get(&real) {
            Some(node) => Ok(self.entry_of(&real, node)),
            None => err(ErrorName::NotFound, "No such file or directory"),
        }
    }

    pub fn list(&self, dir: &[u8]) -> TResult<Vec<WireEntry>> {
        let real = self.resolve(dir)?;
        match self.nodes.get(&real) {
            Some(Node::Dir { .. }) => {}
            _ => return err(ErrorName::NotADirectory, "Not a directory"),
        }
        Ok(self
            .nodes
            .iter()
            .filter(|(p, _)| !p.is_empty() && parent_of(p) == real)
            .map(|(p, n)| self.entry_of(p, n))
            .collect())
    }

    fn require_parent_dir(&self, path: &[u8]) -> TResult<()> {
        if path.is_empty() {
            return err(ErrorName::InvalidName, "The root cannot be changed");
        }
        match self.nodes.get(&parent_of(path)) {
            Some(Node::Dir { .. }) => Ok(()),
            Some(_) => err(ErrorName::NotADirectory, "Parent is not a directory"),
            None => err(ErrorName::NotFound, "Parent folder does not exist"),
        }
    }

    pub fn make_dir(&mut self, path: &[u8], exclusive: bool) -> TResult<()> {
        if path.is_empty() {
            return if exclusive { err(ErrorName::AlreadyExists, "Exists") } else { Ok(()) };
        }
        self.require_parent_dir(path)?;
        match self.nodes.get(path) {
            Some(Node::Dir { .. }) if !exclusive => Ok(()),
            Some(_) => err(ErrorName::AlreadyExists, "Exists"),
            None => {
                self.nodes.insert(path.to_vec(), Node::Dir { mtime_ms: self.now_ms, mode: 0o755 });
                Ok(())
            }
        }
    }

    pub fn remove_file(&mut self, path: &[u8]) -> TResult<()> {
        match self.nodes.get(path) {
            None => err(ErrorName::NotFound, "No such file"),
            Some(Node::Dir { .. }) => err(ErrorName::IsADirectory, "Is a directory"),
            Some(_) => {
                self.nodes.remove(path);
                Ok(())
            }
        }
    }

    pub fn remove_dir(&mut self, path: &[u8]) -> TResult<()> {
        match self.nodes.get(path) {
            None => err(ErrorName::NotFound, "No such folder"),
            Some(Node::Dir { .. }) if path.is_empty() => {
                err(ErrorName::InvalidName, "The root cannot be removed")
            }
            Some(Node::Dir { .. }) => {
                if self.nodes.keys().any(|p| is_under(p, path)) {
                    return err(ErrorName::DirectoryNotEmpty, "Folder is not empty");
                }
                self.nodes.remove(path);
                Ok(())
            }
            Some(_) => err(ErrorName::NotADirectory, "Not a directory"),
        }
    }

    pub fn remove_tree(&mut self, path: &[u8]) -> TResult<Counts> {
        if !self.nodes.contains_key(path) {
            return err(ErrorName::NotFound, "No such file or folder");
        }
        if path.is_empty() {
            return err(ErrorName::InvalidName, "The root cannot be removed");
        }
        let doomed: Vec<Vec<u8>> =
            self.nodes.keys().filter(|p| p.as_slice() == path || is_under(p, path)).cloned().collect();
        let mut counts = Counts::default();
        for p in doomed {
            if let Some(Node::Dir { .. }) = self.nodes.remove(&p) {
                counts.dirs = counts.dirs.saturating_add(1);
            } else {
                counts.files = counts.files.saturating_add(1);
            }
        }
        Ok(counts)
    }

    pub fn rename(&mut self, from: &[u8], to: &[u8], replace: bool) -> TResult<()> {
        if !self.nodes.contains_key(from) {
            return err(ErrorName::NotFound, "No such file or folder");
        }
        self.require_parent_dir(to)?;
        if is_under(to, from) {
            return err(ErrorName::InvalidName, "Cannot move a folder into itself");
        }
        if from == to {
            return Ok(());
        }
        if let Some(existing) = self.nodes.get(to) {
            if !replace {
                return err(ErrorName::AlreadyExists, "Destination exists");
            }
            let src_dir = matches!(self.nodes.get(from), Some(Node::Dir { .. }));
            match (existing, src_dir) {
                (Node::Dir { .. }, false) => return err(ErrorName::IsADirectory, "Destination is a folder"),
                (Node::Dir { .. }, true) if self.nodes.keys().any(|p| is_under(p, to)) => {
                    return err(ErrorName::DirectoryNotEmpty, "Destination folder is not empty");
                }
                (Node::File { .. } | Node::Link { .. }, true) => {
                    return err(ErrorName::NotADirectory, "Destination is not a folder");
                }
                _ => {}
            }
            self.nodes.remove(to);
        }
        let moving: Vec<Vec<u8>> =
            self.nodes.keys().filter(|p| p.as_slice() == from || is_under(p, from)).cloned().collect();
        for old in moving {
            if let Some(node) = self.nodes.remove(&old) {
                let mut new = to.to_vec();
                new.extend_from_slice(old.get(from.len()..).unwrap_or_default());
                self.nodes.insert(new, node);
            }
        }
        Ok(())
    }

    pub fn set_attributes(&mut self, path: &[u8], mode: Option<i32>, mtime_ms: Option<i64>) -> TResult<()> {
        match self.nodes.get_mut(path) {
            None => err(ErrorName::NotFound, "No such file or folder"),
            Some(Node::Link { .. }) => err(ErrorName::Unsupported, "Cannot change a link"),
            Some(Node::File { mtime_ms: m, mode: md, .. } | Node::Dir { mtime_ms: m, mode: md }) => {
                if let Some(v) = mode {
                    *md = v;
                }
                if let Some(v) = mtime_ms {
                    *m = v;
                }
                Ok(())
            }
        }
    }

    pub fn make_symlink(&mut self, target: &[u8], link: &[u8]) -> TResult<()> {
        self.require_parent_dir(link)?;
        if self.nodes.contains_key(link) {
            return err(ErrorName::AlreadyExists, "Exists");
        }
        self.nodes.insert(link.to_vec(), Node::Link { target: target.to_vec() });
        Ok(())
    }

    pub fn make_hardlink(&mut self, existing: &[u8], new_path: &[u8]) -> TResult<()> {
        let node = match self.nodes.get(existing) {
            Some(n @ Node::File { .. }) => n.clone(),
            Some(_) => return err(ErrorName::PermissionDenied, "Only files can be linked"),
            None => return err(ErrorName::NotFound, "No such file"),
        };
        self.require_parent_dir(new_path)?;
        if self.nodes.contains_key(new_path) {
            return err(ErrorName::AlreadyExists, "Exists");
        }
        self.nodes.insert(new_path.to_vec(), node);
        Ok(())
    }

    pub fn server_copy(&mut self, from: &[u8], to: &[u8], recursive: bool, replace: bool) -> TResult<()> {
        let src = match self.nodes.get(from) {
            Some(n) => n.clone(),
            None => return err(ErrorName::NotFound, "No such file or folder"),
        };
        self.require_parent_dir(to)?;
        if self.nodes.contains_key(to) && !replace {
            return err(ErrorName::AlreadyExists, "Destination exists");
        }
        if matches!(src, Node::Dir { .. }) && !recursive {
            return err(ErrorName::IsADirectory, "Folders need the recursive option");
        }
        let items: Vec<(Vec<u8>, Node)> = self
            .nodes
            .iter()
            .filter(|(p, _)| p.as_slice() == from || (recursive && is_under(p, from)))
            .map(|(p, n)| (p.clone(), n.clone()))
            .collect();
        for (old, node) in items {
            let mut new = to.to_vec();
            new.extend_from_slice(old.get(from.len()..).unwrap_or_default());
            self.nodes.insert(new, node);
        }
        Ok(())
    }

    /// Nodes below `path` (and `path` itself, empty relative path) for copying between locations.
    pub fn export(&self, path: &[u8], recursive: bool) -> TResult<Vec<(Vec<u8>, Node)>> {
        let root = match self.nodes.get(path) {
            Some(n) => n.clone(),
            None => return err(ErrorName::NotFound, "No such file or folder"),
        };
        if matches!(root, Node::Dir { .. }) && !recursive {
            return err(ErrorName::IsADirectory, "Folders need the recursive option");
        }
        let mut items = vec![(Vec::new(), root)];
        if recursive {
            for (p, n) in &self.nodes {
                if is_under(p, path) {
                    let rel = if path.is_empty() {
                        p.clone()
                    } else {
                        p.get(path.len().saturating_add(1)..).unwrap_or_default().to_vec()
                    };
                    items.push((rel, n.clone()));
                }
            }
        }
        Ok(items)
    }

    /// Places exported nodes at `to`.
    pub fn import(&mut self, to: &[u8], items: Vec<(Vec<u8>, Node)>, replace: bool) -> TResult<()> {
        self.require_parent_dir(to)?;
        if self.nodes.contains_key(to) && !replace {
            return err(ErrorName::AlreadyExists, "Destination exists");
        }
        for (rel, node) in items {
            let mut dst = to.to_vec();
            if !rel.is_empty() {
                dst.push(b'/');
                dst.extend_from_slice(&rel);
            }
            self.nodes.insert(dst, node);
        }
        Ok(())
    }

    /// Entries below `root` in depth-first order (children before their folder
    /// when `post_order`), as `(full path, entry)`; depth 1 are the children.
    pub fn walk(&self, root: &[u8], max_depth: i64, post_order: bool) -> TResult<Vec<(Vec<u8>, WireEntry)>> {
        match self.nodes.get(root) {
            Some(Node::Dir { .. }) => {}
            Some(_) => return err(ErrorName::NotADirectory, "Not a directory"),
            None => return err(ErrorName::NotFound, "No such folder"),
        }
        let mut found: Vec<(&Vec<u8>, &Node)> = self
            .nodes
            .iter()
            .filter(|(p, _)| is_under(p, root))
            .filter(|(p, _)| {
                let depth = p
                    .get(root.len()..)
                    .unwrap_or_default()
                    .split(|b| *b == b'/')
                    .filter(|c| !c.is_empty())
                    .count();
                max_depth < 0 || i64::try_from(depth).unwrap_or(i64::MAX) <= max_depth
            })
            .collect();
        found.sort_by(|a, b| a.0.split(|c| *c == b'/').cmp(b.0.split(|c| *c == b'/')));
        if post_order {
            found.reverse();
        }
        Ok(found.into_iter().map(|(p, n)| (p.clone(), self.entry_of(p, n))).collect())
    }

    pub fn read_link(&self, path: &[u8]) -> TResult<Vec<u8>> {
        match self.nodes.get(path) {
            Some(Node::Link { target }) => Ok(target.clone()),
            Some(_) => err(ErrorName::ProtocolError, "Not a link"),
            None => err(ErrorName::NotFound, "No such file"),
        }
    }

    pub fn file_data(&self, path: &[u8]) -> TResult<&[u8]> {
        let real = self.resolve(path)?;
        match self.nodes.get(&real) {
            Some(Node::File { data, .. }) => Ok(data),
            Some(Node::Dir { .. }) => err(ErrorName::IsADirectory, "Is a directory"),
            _ => err(ErrorName::NotFound, "No such file"),
        }
    }

    #[must_use]
    pub fn file_len(&self, path: &[u8]) -> Option<usize> {
        match self.nodes.get(path) {
            Some(Node::File { data, .. }) => Some(data.len()),
            _ => None,
        }
    }

    /// Replaces or extends a file (`Upload`). `at` is where `data` starts; the
    /// file is truncated to `at` first, so resuming rewrites nothing before it.
    pub fn write_file(&mut self, path: &[u8], at: usize, data: &[u8], mtime_ms: Option<i64>) -> TResult<()> {
        self.require_parent_dir(path)?;
        let mtime = mtime_ms.unwrap_or(self.now_ms);
        match self.nodes.get_mut(path) {
            Some(Node::Dir { .. }) => err(ErrorName::IsADirectory, "Is a directory"),
            Some(Node::File { data: old, mtime_ms: m, .. }) => {
                old.truncate(at);
                old.extend_from_slice(data);
                *m = mtime;
                Ok(())
            }
            _ => {
                self.nodes
                    .insert(path.to_vec(), Node::File { data: data.to_vec(), mtime_ms: mtime, mode: 0o644 });
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Tree {
        let mut t = Tree::default();
        t.put_file(b"docs/a.txt", b"hello");
        t.put_file(b"docs/sub/b", b"b");
        t.put_symlink(b"ln", b"docs/a.txt");
        t.put_symlink(b"dangling", b"nowhere");
        t
    }

    #[test]
    fn normalize_rules() {
        assert_eq!(normalize(b"/a//b/./c/").unwrap(), b"a/b/c");
        assert_eq!(normalize(b"").unwrap(), b"");
        assert_eq!(normalize(b"a/../b").unwrap_err().name, ErrorName::InvalidName);
        assert_eq!(normalize(b"a\0b").unwrap_err().name, ErrorName::InvalidName);
        assert_eq!(normalize(&vec![b'a'; 5000]).unwrap_err().name, ErrorName::InvalidName);
    }

    #[test]
    fn stat_and_links() {
        let t = sample();
        assert_eq!(t.stat(b"docs/a.txt", true).unwrap().size, 5);
        let l = t.stat(b"ln", false).unwrap();
        assert_eq!((l.kind, l.target_kind), (3, 1));
        assert_eq!(t.stat(b"ln", true).unwrap().kind, 1);
        let d = t.stat(b"dangling", false).unwrap();
        assert_eq!(d.flags & entry_flags::TARGET_UNKNOWN, entry_flags::TARGET_UNKNOWN);
        assert_eq!(t.stat(b"dangling", true).unwrap_err().name, ErrorName::NotFound);
        assert_eq!(t.read_link(b"ln").unwrap(), b"docs/a.txt");
        assert_eq!(t.read_link(b"docs").unwrap_err().name, ErrorName::ProtocolError);
    }

    #[test]
    fn list_marks_odd_names() {
        let mut t = Tree::default();
        t.put_file(b".hidden", b"");
        t.put_file(b"caf\xe9", b"");
        let all = t.list(b"").unwrap();
        assert_eq!(all.len(), 2);
        let hidden = all.iter().find(|e| e.name == b".hidden").unwrap();
        assert_eq!(hidden.flags & entry_flags::HIDDEN, entry_flags::HIDDEN);
        let odd = all.iter().find(|e| e.name == b"caf\xe9").unwrap();
        assert_eq!(odd.flags & entry_flags::NAME_NOT_UTF8, entry_flags::NAME_NOT_UTF8);
        assert_eq!(t.list(b"nothing").unwrap_err().name, ErrorName::NotFound);
        assert_eq!(sample().list(b"docs/a.txt").unwrap_err().name, ErrorName::NotADirectory);
    }

    #[test]
    fn make_dir_modes() {
        let mut t = Tree::default();
        t.make_dir(b"new", true).unwrap();
        assert_eq!(t.make_dir(b"new", true).unwrap_err().name, ErrorName::AlreadyExists);
        t.make_dir(b"new", false).unwrap();
        assert_eq!(t.make_dir(b"x/y", false).unwrap_err().name, ErrorName::NotFound);
        t.put_file(b"f", b"");
        assert_eq!(t.make_dir(b"f", false).unwrap_err().name, ErrorName::AlreadyExists);
        assert_eq!(t.make_dir(b"f/x", false).unwrap_err().name, ErrorName::NotADirectory);
    }

    #[test]
    fn removal() {
        let mut t = sample();
        assert_eq!(t.remove_file(b"docs").unwrap_err().name, ErrorName::IsADirectory);
        assert_eq!(t.remove_dir(b"docs").unwrap_err().name, ErrorName::DirectoryNotEmpty);
        assert_eq!(t.remove_dir(b"ln").unwrap_err().name, ErrorName::NotADirectory);
        assert_eq!(t.remove_dir(b"").unwrap_err().name, ErrorName::InvalidName);
        let c = t.remove_tree(b"docs").unwrap();
        assert_eq!((c.files, c.dirs), (2, 2));
        assert_eq!(t.remove_tree(b"docs").unwrap_err().name, ErrorName::NotFound);
        t.remove_file(b"ln").unwrap();
    }

    #[test]
    fn rename_rules() {
        let mut t = sample();
        t.put_file(b"other", b"o");
        assert_eq!(t.rename(b"other", b"docs/a.txt", false).unwrap_err().name, ErrorName::AlreadyExists);
        t.rename(b"other", b"docs/a.txt", true).unwrap();
        assert_eq!(t.file_data(b"docs/a.txt").unwrap(), b"o");
        assert_eq!(t.rename(b"docs", b"docs/sub/x", false).unwrap_err().name, ErrorName::InvalidName);
        t.rename(b"docs", b"moved", false).unwrap();
        assert_eq!(t.file_data(b"moved/sub/b").unwrap(), b"b");
        assert_eq!(t.rename(b"gone", b"x", false).unwrap_err().name, ErrorName::NotFound);
        t.put_file(b"f", b"");
        assert_eq!(t.rename(b"moved", b"f", true).unwrap_err().name, ErrorName::NotADirectory);
        assert_eq!(t.rename(b"f", b"moved", true).unwrap_err().name, ErrorName::IsADirectory);
    }

    #[test]
    fn attributes_links_and_copy() {
        let mut t = sample();
        t.set_attributes(b"docs/a.txt", Some(0o600), Some(5)).unwrap();
        let e = t.stat(b"docs/a.txt", true).unwrap();
        assert_eq!((e.mode, e.mtime_ms), (0o600, 5));
        assert_eq!(t.set_attributes(b"ln", Some(1), None).unwrap_err().name, ErrorName::Unsupported);
        assert_eq!(t.set_attributes(b"zz", Some(1), None).unwrap_err().name, ErrorName::NotFound);
        t.make_symlink(b"x", b"newlink").unwrap();
        assert_eq!(t.make_symlink(b"x", b"newlink").unwrap_err().name, ErrorName::AlreadyExists);
        t.make_hardlink(b"docs/a.txt", b"hard").unwrap();
        assert_eq!(t.make_hardlink(b"docs", b"h2").unwrap_err().name, ErrorName::PermissionDenied);
        assert_eq!(t.make_hardlink(b"nope", b"h2").unwrap_err().name, ErrorName::NotFound);
        t.server_copy(b"docs", b"copy", true, false).unwrap();
        assert_eq!(t.file_data(b"copy/sub/b").unwrap(), b"b");
        assert_eq!(t.server_copy(b"docs", b"copy2", false, false).unwrap_err().name, ErrorName::IsADirectory);
        assert_eq!(t.server_copy(b"hard", b"copy", false, false).unwrap_err().name, ErrorName::AlreadyExists);
    }

    #[test]
    fn export_import_and_walk() {
        let mut t = sample();
        let items = t.export(b"docs", true).unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(t.export(b"docs", false).unwrap_err().name, ErrorName::IsADirectory);
        assert_eq!(t.export(b"docs/a.txt", false).unwrap().len(), 1);
        assert_eq!(t.export(b"zz", true).unwrap_err().name, ErrorName::NotFound);
        t.import(b"copy", items.clone(), false).unwrap();
        assert_eq!(t.file_data(b"copy/sub/b").unwrap(), b"b");
        assert_eq!(t.import(b"copy", items.clone(), false).unwrap_err().name, ErrorName::AlreadyExists);
        t.import(b"copy", items, true).unwrap();
        let pre: Vec<Vec<u8>> = t.walk(b"docs", -1, false).unwrap().into_iter().map(|(p, _)| p).collect();
        assert_eq!(pre, vec![b"docs/a.txt".to_vec(), b"docs/sub".to_vec(), b"docs/sub/b".to_vec()]);
        let post: Vec<Vec<u8>> = t.walk(b"docs", -1, true).unwrap().into_iter().map(|(p, _)| p).collect();
        assert_eq!(post[0], b"docs/sub/b");
        assert_eq!(t.walk(b"docs", 1, false).unwrap().len(), 2);
        assert_eq!(t.walk(b"docs/a.txt", -1, false).unwrap_err().name, ErrorName::NotADirectory);
        assert_eq!(t.walk(b"zz", -1, false).unwrap_err().name, ErrorName::NotFound);
    }

    #[test]
    fn writes_truncate_to_the_resume_offset() {
        let mut t = Tree::default();
        t.write_file(b"f", 0, b"0123", None).unwrap();
        assert_eq!(t.file_len(b"f"), Some(4));
        t.write_file(b"f", 4, b"45", Some(9)).unwrap();
        assert_eq!(t.file_data(b"f").unwrap(), b"012345");
        t.write_file(b"f", 2, b"x", None).unwrap();
        assert_eq!(t.file_data(b"f").unwrap(), b"01x");
        assert_eq!(t.write_file(b"d/f", 0, b"", None).unwrap_err().name, ErrorName::NotFound);
        assert_eq!(t.used_bytes(), 3);
        assert_eq!(t.file_data(b"").unwrap_err().name, ErrorName::IsADirectory);
    }
}
