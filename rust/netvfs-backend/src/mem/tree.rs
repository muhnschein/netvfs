// SPDX-License-Identifier: LGPL-2.1-or-later
//! The file tree of a `mem` store: numbered nodes (files, folders,
//! symlinks), folders mapping names to nodes, hard links as two names of
//! one node. Paths are bytes split at `/`; every path starts at the root.
//! Errors follow the local backend's errno mapping (ELOOP is `NotFound`).

use netvfs_vfs::{Attributes, Disposition, Entry, EntryFlags, EntryType, ErrorName, Status, WriteOptions};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// The root folder's node.
const ROOT: u64 = 1;
/// Symlinks followed in one lookup at most (Linux's 40).
const MAX_HOPS: u32 = 40;
/// The longest name, in bytes (`maxNameBytes`).
pub const MAX_NAME: u64 = 255;
/// Owner and group ids of every node.
const OWNER_ID: u64 = 1000;
/// Owner and group names of every node.
const OWNER: &str = "mem";
/// Mode of a new file without `create_mode`, of a new folder.
const FILE_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;

/// Milliseconds since the epoch.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// What a node holds.
#[derive(Debug, Clone)]
enum Data {
    File(Vec<u8>),
    Dir(BTreeMap<Vec<u8>, u64>),
    Link(Vec<u8>),
}

#[derive(Debug, Clone)]
struct Node {
    data: Data,
    mode: u32,
    mtime_ms: i64,
    atime_ms: i64,
    ctime_ms: i64,
    /// Names of the node (hard links).
    links: u32,
    /// The folder of a folder (the root's is the root).
    parent: u64,
    /// Bumped on every change: the etag.
    version: u64,
}

impl Node {
    fn new(data: Data, mode: u32, parent: u64) -> Self {
        let now = now_ms();
        Self { data, mode, mtime_ms: now, atime_ms: now, ctime_ms: now, links: 1, parent, version: 0 }
    }

    const fn kind(&self) -> EntryType {
        match self.data {
            Data::File(_) => EntryType::File,
            Data::Dir(_) => EntryType::Directory,
            Data::Link(_) => EntryType::Symlink,
        }
    }

    fn touch(&mut self) {
        self.mtime_ms = now_ms();
        self.ctime_ms = self.mtime_ms;
        self.version = self.version.wrapping_add(1);
    }
}

fn not_found() -> Status {
    Status::new(ErrorName::NotFound, "No such file or folder")
}

fn exists() -> Status {
    Status::new(ErrorName::AlreadyExists, "The target exists")
}

fn not_a_dir() -> Status {
    Status::new(ErrorName::NotADirectory, "Not a folder")
}

fn is_a_dir() -> Status {
    Status::new(ErrorName::IsADirectory, "Is a folder")
}

/// The components of `path`, without empty ones.
fn components(path: &[u8]) -> Vec<&[u8]> {
    path.split(|b| *b == b'/').filter(|c| !c.is_empty()).collect()
}

/// A name a new entry may have.
fn check_name(name: &[u8]) -> Result<(), Status> {
    if u64::try_from(name.len()).map_or(true, |n| n > MAX_NAME) {
        return Err(Status::new(ErrorName::InvalidName, "The name is too long"));
    }
    Ok(())
}

/// A store's tree.
#[derive(Debug)]
pub struct Tree {
    nodes: BTreeMap<u64, Node>,
    next: u64,
}

impl Default for Tree {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::from([(ROOT, Node::new(Data::Dir(BTreeMap::new()), DIR_MODE, ROOT))]),
            next: ROOT.wrapping_add(1),
        }
    }
}

impl Tree {
    fn node(&self, id: u64) -> Result<&Node, Status> {
        self.nodes.get(&id).ok_or_else(|| Status::new(ErrorName::NotFound, "The file is gone"))
    }

    fn node_mut(&mut self, id: u64) -> Result<&mut Node, Status> {
        self.nodes.get_mut(&id).ok_or_else(|| Status::new(ErrorName::NotFound, "The file is gone"))
    }

    fn children(&self, dir: u64) -> Result<&BTreeMap<Vec<u8>, u64>, Status> {
        match &self.node(dir)?.data {
            Data::Dir(children) => Ok(children),
            _ => Err(not_a_dir()),
        }
    }

    fn children_mut(&mut self, dir: u64) -> Result<&mut BTreeMap<Vec<u8>, u64>, Status> {
        match &mut self.node_mut(dir)?.data {
            Data::Dir(children) => Ok(children),
            _ => Err(not_a_dir()),
        }
    }

    fn is_dir(&self, id: u64) -> bool {
        self.node(id).is_ok_and(|n| matches!(n.data, Data::Dir(_)))
    }

    fn child(&self, dir: u64, name: &[u8]) -> Result<Option<u64>, Status> {
        Ok(self.children(dir)?.get(name).copied())
    }

    /// Walks `comps` from `start`; symlinks are followed in every
    /// component but the last, and in the last with `follow_last`.
    fn walk(&self, start: u64, comps: &[&[u8]], follow_last: bool, hops: &mut u32) -> Result<u64, Status> {
        let last = comps.len().saturating_sub(1);
        let mut at = start;
        for (i, name) in comps.iter().enumerate() {
            let parent = at;
            at = match *name {
                b"." => at,
                b".." => {
                    self.children(at)?;
                    self.node(at)?.parent
                }
                _ => self.children(at)?.get(*name).copied().ok_or_else(not_found)?,
            };
            if let Data::Link(target) = &self.node(at)?.data
                && (i != last || follow_last)
            {
                *hops = hops.saturating_add(1);
                if *hops > MAX_HOPS {
                    return Err(Status::new(ErrorName::NotFound, "Too many levels of symbolic links"));
                }
                let base = if target.starts_with(b"/") { ROOT } else { parent };
                at = self.walk(base, &components(target), true, hops)?;
            }
        }
        Ok(at)
    }

    /// The node at `path`, following a final symlink with `follow`.
    pub fn resolve(&self, path: &[u8], follow: bool) -> Result<u64, Status> {
        self.walk(ROOT, &components(path), follow, &mut 0)
    }

    /// The folder `path` is in and its last name.
    fn parent_of<'p>(&self, path: &'p [u8]) -> Result<(u64, &'p [u8]), Status> {
        let comps = components(path);
        let Some((name, dirs)) = comps.split_last() else {
            return Err(Status::new(ErrorName::InvalidName, "The path has no name"));
        };
        if *name == b"." || *name == b".." {
            return Err(Status::new(ErrorName::InvalidName, "The path ends in . or .."));
        }
        let dir = self.walk(ROOT, dirs, true, &mut 0)?;
        self.children(dir)?;
        Ok((dir, name))
    }

    fn add(&mut self, dir: u64, name: &[u8], data: Data, mode: u32) -> Result<u64, Status> {
        check_name(name)?;
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.nodes.insert(id, Node::new(data, mode, dir));
        self.children_mut(dir)?.insert(name.to_vec(), id);
        self.node_mut(dir)?.touch();
        Ok(id)
    }

    /// Removes the name; the node goes with its last name.
    fn unlink(&mut self, dir: u64, name: &[u8]) -> Result<(), Status> {
        let id = self.children_mut(dir)?.remove(name).ok_or_else(not_found)?;
        self.node_mut(dir)?.touch();
        let node = self.node_mut(id)?;
        node.links = node.links.saturating_sub(1);
        node.ctime_ms = now_ms();
        if node.links == 0 {
            self.nodes.remove(&id);
        }
        Ok(())
    }

    /// Whether `dir` is `ancestor` or below it.
    fn within(&self, dir: u64, ancestor: u64) -> bool {
        let mut at = dir;
        loop {
            if at == ancestor {
                return true;
            }
            match self.node(at) {
                Ok(node) if at != ROOT => at = node.parent,
                _ => return false,
            }
        }
    }

    /// The entry of node `id` under `name`; a symlink's target type is
    /// resolved from `dir` (the folder holding it) with `targets`.
    fn entry(&self, dir: u64, name: &[u8], id: u64, targets: bool) -> Result<Entry, Status> {
        let node = self.node(id)?;
        let mut flags =
            if std::str::from_utf8(name).is_ok() { EntryFlags::NONE } else { EntryFlags::NAME_NOT_UTF8 };
        let (size, mut target_kind) = match &node.data {
            Data::File(data) => (data.len(), EntryType::Unknown),
            Data::Dir(_) => (0, EntryType::Unknown),
            Data::Link(target) => (target.len(), EntryType::Unknown),
        };
        if let Data::Link(target) = &node.data
            && targets
        {
            let base = if target.starts_with(b"/") { ROOT } else { dir };
            match self.walk(base, &components(target), true, &mut 1) {
                Ok(found) => target_kind = self.node(found)?.kind(),
                Err(_) => flags = flags.union(EntryFlags::TARGET_UNKNOWN),
            }
        }
        // A symlink has no mode and only its modification time, as on
        // servers that report no more (an entry's fields may be unknown).
        let link = matches!(node.data, Data::Link(_));
        Ok(Entry {
            name: name.to_vec(),
            kind: node.kind(),
            target_kind,
            flags,
            mode: (!link).then_some(node.mode),
            size: u64::try_from(size).ok(),
            mtime_ms: Some(node.mtime_ms),
            ctime_ms: (!link).then_some(node.ctime_ms),
            atime_ms: (!link).then_some(node.atime_ms),
            uid: Some(OWNER_ID),
            gid: Some(OWNER_ID),
            owner: OWNER.to_owned(),
            group: OWNER.to_owned(),
            etag: format!("{id:x}-{:x}", node.version).into_bytes(),
            content_type: String::new(),
        })
    }

    /// `stat` (`follow`) or `lstat` of `path`; the root's name is empty.
    pub fn stat(&self, path: &[u8], follow: bool) -> Result<Entry, Status> {
        let id = self.resolve(path, follow)?;
        let comps = components(path);
        let name = comps.last().copied().unwrap_or_default();
        let dir = match comps.split_last() {
            Some((_, dirs)) => self.walk(ROOT, dirs, true, &mut 0)?,
            None => ROOT,
        };
        self.entry(dir, name, id, true)
    }

    /// The entries of the folder at `path`, sorted by name.
    pub fn list(&self, path: &[u8], targets: bool) -> Result<Vec<Entry>, Status> {
        let dir = self.resolve(path, true)?;
        self.children(dir)?.iter().map(|(name, id)| self.entry(dir, name, *id, targets)).collect()
    }

    /// XC-8.
    pub fn make_dir(&mut self, path: &[u8], exclusive: bool) -> Result<(), Status> {
        let (dir, name) = self.parent_of(path)?;
        if self.child(dir, name)?.is_some() {
            let folder = self.resolve(path, true).is_ok_and(|id| self.is_dir(id));
            return if folder && !exclusive { Ok(()) } else { Err(exists()) };
        }
        self.add(dir, name, Data::Dir(BTreeMap::new()), DIR_MODE).map(drop)
    }

    /// XC-9: `removeFile` (`folder` false) or `removeDir`.
    pub fn remove(&mut self, path: &[u8], folder: bool) -> Result<(), Status> {
        let (dir, name) = self.parent_of(path)?;
        let id = self.child(dir, name)?.ok_or_else(not_found)?;
        match (&self.node(id)?.data, folder) {
            (Data::Dir(_), false) => return Err(is_a_dir()),
            (Data::Dir(children), true) if !children.is_empty() => {
                return Err(Status::new(ErrorName::DirectoryNotEmpty, "The folder is not empty"));
            }
            (Data::File(_) | Data::Link(_), true) => return Err(not_a_dir()),
            _ => {}
        }
        self.unlink(dir, name)
    }

    /// XC-10.
    pub fn rename(&mut self, from: &[u8], to: &[u8], replace: bool) -> Result<(), Status> {
        let (from_dir, from_name) = self.parent_of(from)?;
        let id = self.child(from_dir, from_name)?.ok_or_else(not_found)?;
        let (to_dir, to_name) = self.parent_of(to)?;
        if from_dir == to_dir && from_name == to_name {
            return if replace { Ok(()) } else { Err(exists()) };
        }
        let folder = self.is_dir(id);
        if folder && self.within(to_dir, id) {
            return Err(Status::new(ErrorName::InvalidName, "A folder cannot move below itself"));
        }
        if let Some(target) = self.child(to_dir, to_name)? {
            if !replace || folder || self.is_dir(target) {
                return Err(exists());
            }
            if target == id {
                // Two names of one file: the source name goes.
                return self.unlink(from_dir, from_name);
            }
            self.unlink(to_dir, to_name)?;
        }
        check_name(to_name)?;
        self.children_mut(from_dir)?.remove(from_name);
        self.node_mut(from_dir)?.touch();
        self.children_mut(to_dir)?.insert(to_name.to_vec(), id);
        self.node_mut(to_dir)?.touch();
        let node = self.node_mut(id)?;
        node.ctime_ms = now_ms();
        if folder {
            node.parent = to_dir;
        }
        Ok(())
    }

    /// XC-11: everything is checked before anything changes.
    pub fn set_attributes(&mut self, path: &[u8], changes: &Attributes) -> Result<(), Status> {
        let id = self.resolve(path, true)?;
        if changes.mode.is_some_and(|m| m > 0o7777) {
            return Err(Status::invalid_args("The mode has bits beyond 07777"));
        }
        let node = self.node_mut(id)?;
        if let Some(mode) = changes.mode {
            node.mode = mode;
        }
        if let Some(ms) = changes.mtime_ms {
            node.mtime_ms = ms;
        }
        if let Some(ms) = changes.atime_ms {
            node.atime_ms = ms;
        }
        node.ctime_ms = now_ms();
        node.version = node.version.wrapping_add(1);
        Ok(())
    }

    /// XC-12: the target, verbatim.
    pub fn read_link(&self, path: &[u8]) -> Result<Vec<u8>, Status> {
        let (dir, name) = self.parent_of(path)?;
        let id = self.child(dir, name)?.ok_or_else(not_found)?;
        match &self.node(id)?.data {
            Data::Link(target) => Ok(target.clone()),
            _ => Err(Status::new(ErrorName::InvalidName, "Not a symbolic link")),
        }
    }

    /// XC-12: `link` pointing to `target`, verbatim.
    pub fn make_symlink(&mut self, target: &[u8], link: &[u8]) -> Result<(), Status> {
        if target.is_empty() {
            return Err(Status::new(ErrorName::InvalidName, "The link target is empty"));
        }
        let (dir, name) = self.parent_of(link)?;
        if self.child(dir, name)?.is_some() {
            return Err(exists());
        }
        self.add(dir, name, Data::Link(target.to_vec()), 0o777).map(drop)
    }

    /// XC-12: a second name of a file (not of a folder).
    pub fn make_hardlink(&mut self, existing: &[u8], link: &[u8]) -> Result<(), Status> {
        let id = self.resolve(existing, false)?;
        if self.is_dir(id) {
            return Err(Status::permission_denied("Folders cannot have hard links"));
        }
        let (dir, name) = self.parent_of(link)?;
        if self.child(dir, name)?.is_some() {
            return Err(exists());
        }
        check_name(name)?;
        self.children_mut(dir)?.insert(name.to_vec(), id);
        let node = self.node_mut(id)?;
        node.links = node.links.saturating_add(1);
        node.ctime_ms = now_ms();
        Ok(())
    }

    /// A copy of node `id` (and below it) as `name` in `dir`.
    fn duplicate(&mut self, id: u64, dir: u64, name: &[u8]) -> Result<(), Status> {
        let node = self.node(id)?.clone();
        let copy = self.add(
            dir,
            name,
            match &node.data {
                Data::Dir(_) => Data::Dir(BTreeMap::new()),
                other => other.clone(),
            },
            node.mode,
        )?;
        if let Data::Dir(children) = node.data {
            for (child_name, child) in children {
                self.duplicate(child, copy, &child_name)?;
            }
        }
        Ok(())
    }

    /// XC-17.
    pub fn copy(&mut self, from: &[u8], to: &[u8], recursive: bool, replace: bool) -> Result<(), Status> {
        let id = self.resolve(from, true)?;
        let folder = self.is_dir(id);
        if folder && !recursive {
            return Err(is_a_dir());
        }
        let (dir, name) = self.parent_of(to)?;
        if folder && self.within(dir, id) {
            return Err(Status::new(ErrorName::InvalidName, "A folder cannot be copied below itself"));
        }
        if let Some(target) = self.child(dir, name)? {
            if !replace || folder || self.is_dir(target) {
                return Err(exists());
            }
            if target == id {
                return Ok(());
            }
            self.unlink(dir, name)?;
        }
        self.duplicate(id, dir, name)
    }

    /// The file at `path` (symlinks followed).
    pub fn file(&self, path: &[u8]) -> Result<u64, Status> {
        let id = self.resolve(path, true)?;
        match self.node(id)?.data {
            Data::File(_) => Ok(id),
            Data::Dir(_) => Err(is_a_dir()),
            Data::Link(_) => Err(not_found()),
        }
    }

    /// The bytes of file `id`.
    pub fn data(&self, id: u64) -> Result<&[u8], Status> {
        match &self.node(id)?.data {
            Data::File(data) => Ok(data),
            _ => Err(is_a_dir()),
        }
    }

    /// XC-13: opens `path` for writing; the node and the offset to write
    /// at.
    pub fn open_write(&mut self, path: &[u8], options: &WriteOptions) -> Result<(u64, u64), Status> {
        let (dir, name) = self.parent_of(path)?;
        let existing = match self.child(dir, name)? {
            Some(_) => Some(self.resolve(path, true)?),
            None => None,
        };
        let Some(id) = existing else {
            if options.disposition == Disposition::Resume {
                return Err(not_found());
            }
            let mode = options.create_mode.unwrap_or(FILE_MODE) & 0o7777;
            return Ok((self.add(dir, name, Data::File(Vec::new()), mode)?, 0));
        };
        let size = u64::try_from(self.data(id)?.len()).unwrap_or(u64::MAX);
        match options.disposition {
            Disposition::CreateNew => Err(exists()),
            Disposition::Truncate => {
                let node = self.node_mut(id)?;
                if let Data::File(data) = &mut node.data {
                    data.clear();
                }
                node.touch();
                Ok((id, 0))
            }
            Disposition::Resume if options.resume_offset == size => Ok((id, size)),
            Disposition::Resume => Err(Status::invalid_args(format!(
                "Cannot resume at {}: the file has {size} bytes",
                options.resume_offset
            ))),
        }
    }

    /// Writes `data` at `at` in file `id`, filling a gap with zeros.
    pub fn write_at(&mut self, id: u64, at: u64, data: &[u8]) -> Result<(), Status> {
        let node = self.node_mut(id)?;
        let Data::File(content) = &mut node.data else { return Err(is_a_dir()) };
        let start = usize::try_from(at).map_err(|_too_large| Status::new(ErrorName::NoSpace, "Too large"))?;
        let end =
            start.checked_add(data.len()).ok_or_else(|| Status::new(ErrorName::NoSpace, "Too large"))?;
        if content.len() < end {
            content.resize(end, 0);
        }
        if let Some(place) = content.get_mut(start..end) {
            place.copy_from_slice(data);
        }
        node.touch();
        Ok(())
    }

    /// Sets the modification time of `id`.
    pub fn set_mtime(&mut self, id: u64, ms: i64) -> Result<(), Status> {
        self.node_mut(id)?.mtime_ms = ms;
        Ok(())
    }

    /// Bytes in files, if `dir` exists (`spaceInfo`).
    pub fn used_seen_from(&self, dir: &[u8]) -> Result<u64, Status> {
        self.resolve(dir, true)?;
        Ok(self.used())
    }

    /// The bytes of the file at `path` (`checksum`).
    pub fn file_data(&self, path: &[u8]) -> Result<&[u8], Status> {
        self.data(self.file(path)?)
    }

    /// Bytes in files.
    pub fn used(&self) -> u64 {
        self.nodes
            .values()
            .map(|n| match &n.data {
                Data::File(data) => u64::try_from(data.len()).unwrap_or(u64::MAX),
                _ => 0,
            })
            .fold(0, u64::saturating_add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err<T: std::fmt::Debug>(r: Result<T, Status>) -> ErrorName {
        r.unwrap_err().name
    }

    fn file(t: &mut Tree, path: &[u8], data: &[u8]) {
        let (id, at) = t
            .open_write(path, &WriteOptions { disposition: Disposition::Truncate, ..WriteOptions::default() })
            .unwrap();
        t.write_at(id, at, data).unwrap();
    }

    fn read(t: &Tree, path: &[u8]) -> Vec<u8> {
        t.data(t.file(path).unwrap()).unwrap().to_vec()
    }

    fn names(t: &Tree, path: &[u8]) -> Vec<Vec<u8>> {
        t.list(path, false).unwrap().into_iter().map(|e| e.name).collect()
    }

    #[test]
    fn folders_and_files() {
        let mut t = Tree::default();
        t.make_dir(b"a", true).unwrap();
        assert_eq!(err(t.make_dir(b"a", true)), ErrorName::AlreadyExists);
        t.make_dir(b"/a/", false).unwrap();
        assert_eq!(err(t.make_dir(b"x/y", false)), ErrorName::NotFound);
        file(&mut t, b"a/f", b"data");
        assert_eq!(err(t.make_dir(b"a/f", false)), ErrorName::AlreadyExists);
        assert_eq!(err(t.make_dir(b"a/f/g", false)), ErrorName::NotADirectory);
        assert_eq!(err(t.make_dir(b"", false)), ErrorName::InvalidName);
        assert_eq!(err(t.make_dir(b"a/..", false)), ErrorName::InvalidName);
        assert_eq!(read(&t, b"a/./f"), b"data");
        assert_eq!(read(&t, b"a/../a/f"), b"data");
        assert_eq!(read(&t, b"../a/f"), b"data");
        let e = t.stat(b"a/f", true).unwrap();
        assert_eq!(
            (e.name.as_slice(), e.kind, e.size, e.mode),
            (&b"f"[..], EntryType::File, Some(4), Some(0o644))
        );
        assert_eq!((e.uid, e.owner.as_str(), e.flags), (Some(1000), "mem", EntryFlags::NONE));
        assert_ne!(e.etag, Vec::<u8>::new());
        let root = t.stat(b"/", true).unwrap();
        assert_eq!((root.name.len(), root.kind), (0, EntryType::Directory));
        assert_eq!(err(t.stat(b"a/f/below", true)), ErrorName::NotADirectory);
        assert_eq!(err(t.list(b"a/f", false)), ErrorName::NotADirectory);
        assert_eq!(err(t.list(b"nope", false)), ErrorName::NotFound);
        assert_eq!(names(&t, b""), [b"a".to_vec()]);
        assert_eq!(t.used(), 4);
    }

    #[test]
    fn removal() {
        let mut t = Tree::default();
        t.make_dir(b"d", true).unwrap();
        file(&mut t, b"d/f", b"x");
        file(&mut t, b"f", b"x");
        assert_eq!(err(t.remove(b"d", false)), ErrorName::IsADirectory);
        assert_eq!(err(t.remove(b"d", true)), ErrorName::DirectoryNotEmpty);
        assert_eq!(err(t.remove(b"f", true)), ErrorName::NotADirectory);
        assert_eq!(err(t.remove(b"missing", false)), ErrorName::NotFound);
        t.remove(b"d/f", false).unwrap();
        t.remove(b"d", true).unwrap();
        t.remove(b"f", false).unwrap();
        assert_eq!(names(&t, b""), Vec::<Vec<u8>>::new());
        assert_eq!(t.nodes.len(), 1);
    }

    #[test]
    fn renames() {
        let mut t = Tree::default();
        file(&mut t, b"one", b"1");
        file(&mut t, b"two", b"2");
        t.make_dir(b"dir", true).unwrap();
        t.make_dir(b"dir/sub", true).unwrap();
        assert_eq!(err(t.rename(b"one", b"two", false)), ErrorName::AlreadyExists);
        assert_eq!(err(t.rename(b"one", b"one", false)), ErrorName::AlreadyExists);
        t.rename(b"one", b"one", true).unwrap();
        assert_eq!(err(t.rename(b"one", b"dir", true)), ErrorName::AlreadyExists);
        assert_eq!(err(t.rename(b"dir", b"two", true)), ErrorName::AlreadyExists);
        assert_eq!(err(t.rename(b"dir", b"dir/sub/x", false)), ErrorName::InvalidName);
        assert_eq!(err(t.rename(b"dir", b"dir/x", false)), ErrorName::InvalidName);
        assert_eq!(err(t.rename(b"missing", b"x", false)), ErrorName::NotFound);
        assert_eq!(err(t.rename(b"one", b"nowhere/x", false)), ErrorName::NotFound);
        t.rename(b"one", b"two", true).unwrap();
        assert_eq!(read(&t, b"two"), b"1");
        t.rename(b"dir", b"moved", false).unwrap();
        t.rename(b"two", b"moved/sub/two", false).unwrap();
        assert_eq!(read(&t, b"moved/sub/two"), b"1");
        assert_eq!(names(&t, b""), [b"moved".to_vec()]);
        assert_eq!(t.stat(b"moved/sub/..", true).unwrap().kind, EntryType::Directory);
        assert_eq!(names(&t, b"moved/sub/.."), [b"sub".to_vec()]);
        let long = vec![b'n'; 256];
        let mut to = b"moved/".to_vec();
        to.extend_from_slice(&long);
        assert_eq!(err(t.rename(b"moved/sub/two", &to, false)), ErrorName::InvalidName);
    }

    #[test]
    fn symlinks() {
        let mut t = Tree::default();
        t.make_dir(b"real", true).unwrap();
        file(&mut t, b"real/inner", b"in");
        t.make_symlink(b"real", b"dirlink").unwrap();
        t.make_symlink(b"/real/inner", b"abs").unwrap();
        t.make_symlink(b"nowhere", b"dangling").unwrap();
        t.make_symlink(b"b", b"a").unwrap();
        t.make_symlink(b"a", b"b").unwrap();
        assert_eq!(err(t.make_symlink(b"x", b"a")), ErrorName::AlreadyExists);
        assert_eq!(err(t.make_symlink(b"", b"empty")), ErrorName::InvalidName);
        assert_eq!(read(&t, b"dirlink/inner"), b"in");
        assert_eq!(read(&t, b"abs"), b"in");
        assert_eq!(t.read_link(b"dirlink").unwrap(), b"real");
        assert_eq!(err(t.read_link(b"real")), ErrorName::InvalidName);
        let link = t.stat(b"dirlink", false).unwrap();
        assert_eq!((link.kind, link.target_kind), (EntryType::Symlink, EntryType::Directory));
        assert_eq!(t.stat(b"dirlink", true).unwrap().kind, EntryType::Directory);
        assert_eq!(err(t.stat(b"dangling", true)), ErrorName::NotFound);
        assert_eq!(err(t.stat(b"a", true)), ErrorName::NotFound);
        assert_eq!(err(t.file(b"a")), ErrorName::NotFound);
        let listed = t.list(b"", true).unwrap();
        let kinds: Vec<(Vec<u8>, EntryType, bool)> = listed
            .into_iter()
            .map(|e| (e.name, e.target_kind, e.flags.contains(EntryFlags::TARGET_UNKNOWN)))
            .collect();
        assert_eq!(
            kinds,
            [
                (b"a".to_vec(), EntryType::Unknown, true),
                (b"abs".to_vec(), EntryType::File, false),
                (b"b".to_vec(), EntryType::Unknown, true),
                (b"dangling".to_vec(), EntryType::Unknown, true),
                (b"dirlink".to_vec(), EntryType::Directory, false),
                (b"real".to_vec(), EntryType::Unknown, false),
            ]
        );
        let unresolved = t.list(b"", false).unwrap();
        assert!(
            unresolved.iter().all(|e| e.target_kind == EntryType::Unknown && e.flags == EntryFlags::NONE)
        );
        assert_eq!(err(t.remove(b"dirlink", true)), ErrorName::NotADirectory);
        t.remove(b"dirlink", false).unwrap();
        assert_eq!(read(&t, b"real/inner"), b"in");
    }

    #[test]
    fn hardlinks() {
        let mut t = Tree::default();
        file(&mut t, b"file", b"first");
        t.make_hardlink(b"file", b"hard").unwrap();
        assert_eq!(err(t.make_hardlink(b"file", b"hard")), ErrorName::AlreadyExists);
        assert_eq!(err(t.make_hardlink(b"", b"x")), ErrorName::PermissionDenied);
        file(&mut t, b"hard", b"second");
        assert_eq!(read(&t, b"file"), b"second");
        assert_eq!(err(t.rename(b"hard", b"file", false)), ErrorName::AlreadyExists);
        t.rename(b"hard", b"file", true).unwrap();
        assert_eq!(names(&t, b""), [b"file".to_vec()]);
        assert_eq!(read(&t, b"file"), b"second");
        t.make_hardlink(b"file", b"again").unwrap();
        t.remove(b"file", false).unwrap();
        assert_eq!(read(&t, b"again"), b"second");
    }

    #[test]
    fn attributes() {
        let mut t = Tree::default();
        file(&mut t, b"f", b"x");
        let before = t.stat(b"f", true).unwrap();
        t.set_attributes(b"f", &Attributes { mode: Some(0o600), mtime_ms: Some(5), atime_ms: Some(6) })
            .unwrap();
        let e = t.stat(b"f", true).unwrap();
        assert_eq!((e.mode, e.mtime_ms, e.atime_ms), (Some(0o600), Some(5), Some(6)));
        assert_ne!(e.etag, before.etag);
        let bad = Attributes { mode: Some(0o170_644), mtime_ms: Some(9), atime_ms: None };
        assert_eq!(err(t.set_attributes(b"f", &bad)), ErrorName::ProtocolError);
        assert_eq!(t.stat(b"f", true).unwrap().mtime_ms, Some(5));
        assert_eq!(err(t.set_attributes(b"missing", &Attributes::default())), ErrorName::NotFound);
        t.set_attributes(b"f", &Attributes { mode: Some(0o7777), ..Attributes::default() }).unwrap();
        assert_eq!(t.stat(b"f", true).unwrap().mode, Some(0o7777));
    }

    #[test]
    fn copies() {
        let mut t = Tree::default();
        file(&mut t, b"src", b"data");
        file(&mut t, b"other", b"other");
        t.make_dir(b"dir", true).unwrap();
        file(&mut t, b"dir/inner", b"in");
        t.make_symlink(b"inner", b"dir/link").unwrap();
        t.copy(b"src", b"copy", false, false).unwrap();
        assert_eq!(read(&t, b"copy"), b"data");
        file(&mut t, b"copy", b"changed");
        assert_eq!(read(&t, b"src"), b"data");
        assert_eq!(err(t.copy(b"src", b"other", false, false)), ErrorName::AlreadyExists);
        assert_eq!(err(t.copy(b"src", b"dir", false, true)), ErrorName::AlreadyExists);
        assert_eq!(err(t.copy(b"dir", b"d2", false, false)), ErrorName::IsADirectory);
        assert_eq!(err(t.copy(b"dir", b"dir/d2", true, false)), ErrorName::InvalidName);
        assert_eq!(err(t.copy(b"dir", b"other", true, true)), ErrorName::AlreadyExists);
        assert_eq!(err(t.copy(b"missing", b"x", false, false)), ErrorName::NotFound);
        t.copy(b"src", b"src", false, true).unwrap();
        t.copy(b"src", b"other", false, true).unwrap();
        assert_eq!(read(&t, b"other"), b"data");
        t.copy(b"dir", b"d2", true, false).unwrap();
        assert_eq!(read(&t, b"d2/inner"), b"in");
        assert_eq!(t.read_link(b"d2/link").unwrap(), b"inner");
    }

    #[test]
    fn writes() {
        let mut t = Tree::default();
        let create = WriteOptions { create_mode: Some(0o600), ..WriteOptions::default() };
        let (id, at) = t.open_write(b"f", &create).unwrap();
        assert_eq!(at, 0);
        t.write_at(id, 0, b"head").unwrap();
        assert_eq!(t.stat(b"f", true).unwrap().mode, Some(0o600));
        assert_eq!(err(t.open_write(b"f", &create)), ErrorName::AlreadyExists);
        let resume = |offset| WriteOptions {
            disposition: Disposition::Resume,
            resume_offset: offset,
            ..WriteOptions::default()
        };
        for wrong in [0, 3, 5] {
            assert_eq!(err(t.open_write(b"f", &resume(wrong))), ErrorName::ProtocolError);
        }
        assert_eq!(t.open_write(b"f", &resume(4)).unwrap(), (id, 4));
        assert_eq!(err(t.open_write(b"missing", &resume(0))), ErrorName::NotFound);
        assert_eq!(err(t.file(b"missing")), ErrorName::NotFound);
        t.write_at(id, 6, b"!").unwrap();
        assert_eq!(read(&t, b"f"), b"head\0\0!");
        let truncate = WriteOptions {
            disposition: Disposition::Truncate,
            create_mode: Some(0o640),
            ..WriteOptions::default()
        };
        assert_eq!(t.open_write(b"f", &truncate).unwrap(), (id, 0));
        assert_eq!(read(&t, b"f"), Vec::<u8>::new());
        assert_eq!(t.stat(b"f", true).unwrap().mode, Some(0o600));
        t.make_dir(b"d", true).unwrap();
        assert_eq!(err(t.open_write(b"d", &truncate)), ErrorName::IsADirectory);
        assert_eq!(err(t.file(b"d")), ErrorName::IsADirectory);
        let dir = t.resolve(b"d", true).unwrap();
        assert_eq!(err(t.data(dir)), ErrorName::IsADirectory);
        assert_eq!(err(t.write_at(dir, 0, b"x")), ErrorName::IsADirectory);
        let long = vec![b'x'; 256];
        assert_eq!(err(t.open_write(&long, &create)), ErrorName::InvalidName);
        t.open_write(&long[..255], &create).unwrap();
        t.set_mtime(id, 42).unwrap();
        assert_eq!(t.stat(b"f", true).unwrap().mtime_ms, Some(42));
        assert_eq!(err(t.set_mtime(999, 1)), ErrorName::NotFound);
        let odd = t.stat(&[b'c', 0xe9], false);
        assert_eq!(err(odd), ErrorName::NotFound);
        file(&mut t, &[b'c', 0xe9], b"x");
        assert!(t.stat(&[b'c', 0xe9], false).unwrap().flags.contains(EntryFlags::NAME_NOT_UTF8));
    }
}
