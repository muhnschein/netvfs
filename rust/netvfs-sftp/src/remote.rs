// SPDX-License-Identifier: LGPL-2.1-or-later
//! The file operations over an SFTP [`Client`] (SPEC-sftp 6, 7; SPEC-v2
//! XS-1..XS-8): paths against the start folder, entries, the server's
//! extensions, and the checks that turn OpenSSH's plain failures into the
//! XC-21 names (an existing target, a folder, a non-empty folder).

use crate::client::{Client, Field, PathOf, Simple, ok};
use crate::errors::Failure;
use crate::paths::{display, is_entry_name, join, last_component, resolve};
use crate::proto::{
    Attrs, FX_FAILURE, FXF_CREAT, FXF_EXCL, FXF_READ, FXF_WRITE, Limits, Reply, ServerVersion, Statvfs,
    decode_owner_names,
};
use netvfs_vfs::{
    Attributes, CancelToken, Capabilities, Capability, Entry, EntryFlags, EntryType, ErrorName, ListOptions,
    ListSink, RenameMode, SpaceInfo, Status,
};
use std::collections::{BTreeSet, HashMap};

/// Largest READ or WRITE (S-21).
pub const MAX_CHUNK: u32 = 256 * 1024;
/// READ and WRITE size without `limits@openssh.com`.
pub const FALLBACK_CHUNK: u32 = 32 * 1024;
/// Requests in flight per transfer or handle.
pub const WINDOW: usize = 16;
/// Symlink targets stat'ed per listing (XS-3).
const MAX_SYMLINK_RESOLUTIONS: u32 = 512;
/// Names cached per kind (XS-2).
const MAX_CACHED_NAMES: usize = 4096;
/// Mode of a new folder without `dir_mode` (S-20 comes through options).
pub const DEFAULT_DIR_MODE: u32 = 0o777;
/// Mode of a new file without a create mode.
pub const DEFAULT_FILE_MODE: u32 = 0o666;
/// The permission bits.
pub const MODE_BITS: u32 = 0o7777;

/// The extensions this backend uses, as the server offers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools, reason = "one flag per extension")]
pub struct Extensions {
    /// `posix-rename@openssh.com`.
    pub posix_rename: bool,
    /// `statvfs@openssh.com`.
    pub statvfs: bool,
    /// `fsync@openssh.com`.
    pub fsync: bool,
    /// `hardlink@openssh.com`.
    pub hardlink: bool,
    /// `limits@openssh.com`.
    pub limits: bool,
    /// `users-groups-by-id@openssh.com`.
    pub users_groups: bool,
    /// `copy-data`.
    pub copy_data: bool,
}

impl Extensions {
    /// The extensions of `VERSION`, each with the version it must have.
    #[must_use]
    pub fn of(version: &ServerVersion) -> Self {
        Self {
            posix_rename: version.offers("posix-rename@openssh.com", "1"),
            statvfs: version.offers("statvfs@openssh.com", "2"),
            fsync: version.offers("fsync@openssh.com", "1"),
            hardlink: version.offers("hardlink@openssh.com", "1"),
            limits: version.offers("limits@openssh.com", "1"),
            users_groups: version.offers("users-groups-by-id@openssh.com", "1"),
            copy_data: version.offers("copy-data", "1"),
        }
    }
}

/// READ and WRITE sizes (S-21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunks {
    /// READ length.
    pub read: u32,
    /// WRITE length.
    pub write: u32,
}

/// The chunk for a server limit: the limit up to [`MAX_CHUNK`], or
/// [`FALLBACK_CHUNK`] without one.
#[must_use]
pub fn chunk(limit: Option<u64>) -> u32 {
    match limit {
        None | Some(0) => FALLBACK_CHUNK,
        Some(n) => u32::try_from(n.min(u64::from(MAX_CHUNK))).unwrap_or(MAX_CHUNK),
    }
}

/// Owner and group names by id (XS-2).
#[derive(Debug, Default)]
struct Owners {
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
}

fn remember(cache: &mut HashMap<u32, String>, ids: &[u32], names: Vec<Vec<u8>>) {
    if cache.len().saturating_add(ids.len()) > MAX_CACHED_NAMES {
        cache.clear();
    }
    for (id, name) in ids.iter().zip(names) {
        cache.insert(*id, String::from_utf8_lossy(&name).into_owned());
    }
}

/// The type of an entry from its mode (`S_IFMT`).
#[must_use]
pub const fn kind_of(attrs: &Attrs) -> EntryType {
    match attrs.permissions {
        None => EntryType::Unknown,
        Some(mode) => match mode & 0o170_000 {
            0o100_000 => EntryType::File,
            0o040_000 => EntryType::Directory,
            0o120_000 => EntryType::Symlink,
            0 => EntryType::Unknown,
            _ => EntryType::Special,
        },
    }
}

/// An entry named `name` with `attrs`.
#[must_use]
pub fn entry_from(attrs: &Attrs, name: &[u8]) -> Entry {
    let mut entry = Entry {
        name: name.to_vec(),
        kind: kind_of(attrs),
        mode: attrs.permissions.map(|m| m & MODE_BITS),
        size: attrs.size,
        ..Entry::default()
    };
    if let Some((atime, mtime)) = attrs.times {
        entry.mtime_ms = Some(i64::from(mtime).saturating_mul(1000));
        entry.atime_ms = Some(i64::from(atime).saturating_mul(1000));
    }
    if let Some((uid, gid)) = attrs.ids {
        entry.uid = Some(u64::from(uid));
        entry.gid = Some(u64::from(gid));
    }
    // XS-2: Hidden is never set; dot names are a consumer convention.
    if std::str::from_utf8(name).is_err() {
        entry.flags = entry.flags.union(EntryFlags::NAME_NOT_UTF8);
    }
    entry
}

/// Whether `f` ends the call by itself: the connection is gone or the call
/// was canceled, so no follow-up request is worth sending.
fn fatal(s: &Status) -> bool {
    matches!(s.name, ErrorName::ConnectionLost | ErrorName::Canceled | ErrorName::Timeout)
}

/// Seconds of SFTP v3 times (`uint32`), from milliseconds.
fn seconds(ms: i64) -> Option<u32> {
    u32::try_from(ms.checked_div(1000)?).ok()
}

/// XC-11, XS-5: the mode and both times fit SFTP v3.
///
/// # Errors
/// `Internal`, before anything changes.
pub fn check_attributes(changes: &Attributes) -> Result<(), Status> {
    if let Some(mode) = changes.mode
        && mode & !MODE_BITS != 0
    {
        return Err(Status::internal(format!("Invalid mode {mode:o}")));
    }
    if [changes.mtime_ms, changes.atime_ms].into_iter().flatten().any(|ms| seconds(ms).is_none()) {
        return Err(Status::internal("SFTP cannot store times before 1970 or after 2106"));
    }
    Ok(())
}

/// The space of `statvfs` in bytes (XS-8).
#[must_use]
pub fn space_from(s: &Statvfs) -> SpaceInfo {
    let unit = if s.frsize == 0 { s.bsize } else { s.frsize };
    let scaled = |blocks: u64| blocks.saturating_mul(unit).min(i64::MAX.unsigned_abs());
    SpaceInfo {
        free: Some(scaled(s.bavail)),
        total: Some(scaled(s.blocks)),
        used: s.blocks.checked_sub(s.bfree).map(scaled),
    }
}

/// `statvfs@openssh.com` of `remote`.
///
/// # Errors
/// The server's status, or a local failure.
pub async fn statvfs(client: &Client, remote: &[u8], cancel: &CancelToken) -> Result<Statvfs, Failure> {
    match client.extended("statvfs@openssh.com", &[Field::Str(remote)], cancel).await? {
        Reply::Extended(data) => {
            Statvfs::decode(&data).map_err(|e| Failure::Local(crate::errors::malformed(e)))
        }
        other => Err(crate::client::not_ok(other)),
    }
}

/// The failure of a WRITE, CLOSE or fsync of `remote`: `NoSpace` when the
/// server reports a plain failure and its free space is below `attempted`
/// bytes.
pub async fn write_failure(
    client: &Client,
    ext: &Extensions,
    remote: &[u8],
    failure: &Failure,
    attempted: u64,
    cancel: &CancelToken,
) -> Status {
    let status = failure.status(&display(remote));
    if failure.code() != Some(FX_FAILURE) || !ext.statvfs || cancel.is_canceled() {
        return status;
    }
    match statvfs(client, remote, cancel).await {
        Ok(s) if space_from(&s).free.is_some_and(|free| free < attempted) => {
            Status::new(ErrorName::NoSpace, format!("The server has no space left for {}", display(remote)))
        }
        _ => status,
    }
}

/// SETSTAT of `remote`: `mode`, and the two times (SFTP v3 sets both
/// together: one not given keeps its value).
///
/// # Errors
/// The status of the STAT or SETSTAT.
pub async fn set_times(
    client: &Client,
    remote: &[u8],
    mtime_ms: Option<i64>,
    atime_ms: Option<i64>,
    mode: Option<u32>,
    cancel: &CancelToken,
) -> Result<(), Status> {
    let mut attrs = Attrs { permissions: mode, ..Attrs::default() };
    if mtime_ms.is_some() || atime_ms.is_some() {
        let current = if mtime_ms.is_none() || atime_ms.is_none() {
            entry_from(&client.stat(remote, true, cancel).await.map_err(|f| f.status(&display(remote)))?, b"")
        } else {
            Entry::default()
        };
        let mtime = mtime_ms.or(current.mtime_ms);
        let atime = atime_ms.or(current.atime_ms);
        let secs = |ms: Option<i64>| ms.and_then(seconds).unwrap_or(0);
        attrs.times = Some((secs(atime.or(mtime)), secs(mtime.or(atime))));
    }
    client.simple(Simple::Setstat(remote, attrs), cancel).await.map_err(|f| f.status(&display(remote)))
}

/// One signed-in SFTP session's file operations.
#[derive(Debug)]
pub struct Remote {
    client: Client,
    home: Vec<u8>,
    ext: Extensions,
    chunks: Chunks,
    dir_mode: u32,
    /// Owner names, when `users-groups-by-id@openssh.com` answered.
    owners: Option<Owners>,
}

impl Remote {
    /// Learns what the server offers: limits, the start folder (S-19), and
    /// whether it names owners (XS-2).
    ///
    /// # Errors
    /// The failure of the limits request.
    pub async fn new(
        client: Client,
        version: &ServerVersion,
        dir_mode: u32,
        cancel: &CancelToken,
    ) -> Result<Self, Status> {
        let ext = Extensions::of(version);
        let limits = if ext.limits {
            match client.extended("limits@openssh.com", &[], cancel).await.map_err(|f| f.status("limits"))? {
                Reply::Extended(data) => Some(Limits::decode(&data).map_err(crate::errors::malformed)?),
                other => return Err(crate::client::not_ok(other).status("limits")),
            }
        } else {
            None
        };
        let chunks =
            Chunks { read: chunk(limits.map(|l| l.max_read)), write: chunk(limits.map(|l| l.max_write)) };
        let home = match client.path_of(PathOf::Realpath(b"."), cancel).await {
            Ok(home) => home,
            Err(Failure::Local(s)) => return Err(s),
            Err(Failure::Server(_)) => Vec::new(),
        };
        let mut remote = Self { client, home, ext, chunks, dir_mode, owners: None };
        remote.detect_owners(cancel).await;
        cancel.check()?;
        Ok(remote)
    }

    /// The client (for handles and transfers).
    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// The extensions offered.
    #[must_use]
    pub const fn extensions(&self) -> &Extensions {
        &self.ext
    }

    /// The READ and WRITE sizes.
    #[must_use]
    pub const fn chunks(&self) -> Chunks {
        self.chunks
    }

    /// The start folder.
    #[must_use]
    pub fn home(&self) -> &[u8] {
        &self.home
    }

    /// XC-5: what this backend implements on this server.
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        let mut flags: BTreeSet<Capability> = [
            Capability::ReadHandles,
            Capability::EfficientRanges,
            Capability::WriteResume,
            Capability::PosixModes,
            Capability::SetModified,
            Capability::SetModifiedOnUpload,
            Capability::Symlinks,
            Capability::NativeNoReplace,
        ]
        .into();
        for (offered, capability) in [
            (self.ext.hardlink, Capability::Hardlinks),
            (self.owners.is_some(), Capability::Ownership),
            (self.ext.statvfs, Capability::SpaceInfo),
            (self.ext.posix_rename, Capability::AtomicReplace),
            (self.ext.copy_data, Capability::ServerCopy),
        ] {
            if offered {
                flags.insert(capability);
            }
        }
        Capabilities { flags, ..Capabilities::default() }
    }

    /// The remote path of a caller's path.
    ///
    /// # Errors
    /// `InvalidName` (C-15).
    pub fn resolve(&self, path: &[u8]) -> Result<Vec<u8>, Status> {
        resolve(&self.home, path)
    }

    async fn detect_owners(&mut self, cancel: &CancelToken) {
        if !self.ext.users_groups {
            return;
        }
        let home = if self.home.is_empty() { b".".to_vec() } else { self.home.clone() };
        let Ok(Attrs { ids: Some((uid, gid)), .. }) = self.client.stat(&home, true, cancel).await else {
            return;
        };
        let mut owners = Owners::default();
        if let Ok((users, groups)) = self.owner_names(&[uid], &[gid], cancel).await {
            remember(&mut owners.users, &[uid], users);
            remember(&mut owners.groups, &[gid], groups);
            self.owners = Some(owners);
        }
    }

    async fn owner_names(
        &self,
        uids: &[u32],
        gids: &[u32],
        cancel: &CancelToken,
    ) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), Failure> {
        let pack = |ids: &[u32]| ids.iter().flat_map(|id| id.to_be_bytes()).collect::<Vec<u8>>();
        let (users, groups) = (pack(uids), pack(gids));
        let fields = [Field::Str(&users), Field::Str(&groups)];
        match self.client.extended("users-groups-by-id@openssh.com", &fields, cancel).await? {
            Reply::Extended(data) => decode_owner_names(&data, uids.len(), gids.len())
                .map_err(|e| Failure::Local(crate::errors::malformed(e))),
            other => Err(crate::client::not_ok(other)),
        }
    }

    /// XS-2: names the owners of `entries`, one request for the ids the
    /// cache does not know yet.
    async fn name_owners(&mut self, entries: &mut [Entry], cancel: &CancelToken) {
        let Some(owners) = &self.owners else {
            return;
        };
        let id = |v: Option<u64>| v.and_then(|v| u32::try_from(v).ok());
        let uids: Vec<u32> = entries
            .iter()
            .filter_map(|e| id(e.uid))
            .filter(|u| !owners.users.contains_key(u))
            .collect::<BTreeSet<u32>>()
            .into_iter()
            .collect();
        let gids: Vec<u32> = entries
            .iter()
            .filter_map(|e| id(e.gid))
            .filter(|g| !owners.groups.contains_key(g))
            .collect::<BTreeSet<u32>>()
            .into_iter()
            .collect();
        let answer = if uids.is_empty() && gids.is_empty() {
            None
        } else {
            self.owner_names(&uids, &gids, cancel).await.ok()
        };
        let Some(owners) = self.owners.as_mut() else {
            return;
        };
        if let Some((users, groups)) = answer {
            remember(&mut owners.users, &uids, users);
            remember(&mut owners.groups, &gids, groups);
        }
        for entry in entries {
            if entry.owner.is_empty()
                && let Some(name) = id(entry.uid).and_then(|u| owners.users.get(&u))
            {
                entry.owner.clone_from(name);
            }
            if entry.group.is_empty()
                && let Some(name) = id(entry.gid).and_then(|g| owners.groups.get(&g))
            {
                entry.group.clone_from(name);
            }
        }
    }

    /// STAT or LSTAT of `remote`, without owner names.
    async fn stat_remote(&self, remote: &[u8], follow: bool, cancel: &CancelToken) -> Result<Entry, Status> {
        self.client
            .stat(remote, follow, cancel)
            .await
            .map(|a| entry_from(&a, last_component(remote)))
            .map_err(|f| f.status(&display(remote)))
    }

    /// `stat` (`follow`) or `lstat`.
    ///
    /// # Errors
    /// As the server reports it.
    pub async fn stat(&mut self, path: &[u8], follow: bool, cancel: &CancelToken) -> Result<Entry, Status> {
        let remote = self.resolve(path)?;
        let mut one = [self.stat_remote(&remote, follow, cancel).await?];
        self.name_owners(&mut one, cancel).await;
        let [entry] = one;
        Ok(entry)
    }

    /// XC-6: batches of at most `batch_size` entries, one per READDIR reply
    /// at least; `.` and `..` dropped; symlink targets stat'ed on request
    /// (XS-3).
    ///
    /// # Errors
    /// As the server reports it; `Canceled` when the sink stops.
    pub async fn list(
        &mut self,
        dir: &[u8],
        options: ListOptions,
        sink: &mut dyn ListSink,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let remote = self.resolve(dir)?;
        let handle = match self.client.opendir(&remote, cancel).await {
            Ok(handle) => handle,
            Err(f) => {
                let status = f.status(&display(&remote));
                // OpenSSH reports ENOTDIR as "no such file".
                if !fatal(&status)
                    && let Ok(entry) = self.stat_remote(&remote, true, cancel).await
                    && entry.kind != EntryType::Directory
                {
                    return Err(Status::new(
                        ErrorName::NotADirectory,
                        format!("{} is not a folder", display(&remote)),
                    ));
                }
                return Err(status);
            }
        };
        let result = self.read_entries(&handle, &remote, options, sink, cancel).await;
        if result.is_ok() {
            // The listing is complete; a failed CLOSE changes nothing.
            drop(self.client.close(&handle, cancel).await);
        } else {
            self.client.close_detached(&handle);
        }
        result
    }

    async fn read_entries(
        &mut self,
        handle: &[u8],
        remote: &[u8],
        options: ListOptions,
        sink: &mut dyn ListSink,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let batch_size = options.batch_size.max(1);
        let mut budget = MAX_SYMLINK_RESOLUTIONS;
        let mut batch = Vec::new();
        loop {
            cancel.check()?;
            let Some(names) =
                self.client.readdir(handle, cancel).await.map_err(|f| f.status(&display(remote)))?
            else {
                return Ok(());
            };
            // A name that is no entry of this folder is left out; the
            // rest of the listing stays.
            for name in names.into_iter().filter(|n| is_entry_name(&n.filename)) {
                let mut entry = entry_from(&name.attrs, &name.filename);
                if options.resolve_symlink_types && entry.kind == EntryType::Symlink {
                    self.resolve_target(remote, &mut entry, &mut budget, cancel).await;
                }
                batch.push(entry);
                if batch.len() >= batch_size {
                    self.deliver(&mut batch, sink, cancel).await?;
                }
            }
            if !batch.is_empty() {
                self.deliver(&mut batch, sink, cancel).await?;
            }
        }
    }

    /// XS-3: at most [`MAX_SYMLINK_RESOLUTIONS`] per listing; beyond, and
    /// for targets that cannot be stat'ed, `TARGET_UNKNOWN`.
    async fn resolve_target(&self, dir: &[u8], entry: &mut Entry, budget: &mut u32, cancel: &CancelToken) {
        let target = if *budget > 0 {
            self.stat_remote(&join(dir, &entry.name), true, cancel).await.ok()
        } else {
            None
        };
        *budget = budget.saturating_sub(1);
        match target {
            Some(t) => entry.target_kind = t.kind,
            None => entry.flags = entry.flags.union(EntryFlags::TARGET_UNKNOWN),
        }
    }

    async fn deliver(
        &mut self,
        batch: &mut Vec<Entry>,
        sink: &mut dyn ListSink,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        self.name_owners(batch, cancel).await;
        let more = sink.entries(batch);
        batch.clear();
        if more { Ok(()) } else { Err(Status::new(ErrorName::Canceled, "The listing was stopped")) }
    }

    /// XC-8: MKDIR with the folder mode; an existing folder is success
    /// unless `exclusive`.
    ///
    /// # Errors
    /// As the server reports it; `AlreadyExists`.
    pub async fn make_dir(
        &mut self,
        path: &[u8],
        exclusive: bool,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let remote = self.resolve(path)?;
        let attrs = Attrs { permissions: Some(self.dir_mode), ..Attrs::default() };
        let Err(f) = self.client.simple(Simple::Mkdir(&remote, attrs), cancel).await else {
            return Ok(());
        };
        let status = f.status(&display(&remote));
        // OpenSSH reports EEXIST as a plain failure; a concurrent creator is fine.
        if fatal(&status) {
            return Err(status);
        }
        let Ok(existing) = self.stat_remote(&remote, true, cancel).await else {
            return Err(status);
        };
        if exclusive {
            return Err(Status::new(ErrorName::AlreadyExists, format!("{} exists", display(&remote))));
        }
        if existing.kind == EntryType::Directory {
            return Ok(());
        }
        Err(Status::new(ErrorName::AlreadyExists, format!("{} exists and is not a folder", display(&remote))))
    }

    /// XC-9: a folder is `IsADirectory`.
    ///
    /// # Errors
    /// As the server reports it.
    pub async fn remove_file(&mut self, path: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        let remote = self.resolve(path)?;
        let Err(f) = self.client.simple(Simple::Remove(&remote), cancel).await else {
            return Ok(());
        };
        let status = f.status(&display(&remote));
        // XC-9: OpenSSH reports EISDIR as a plain failure.
        if !fatal(&status)
            && let Ok(entry) = self.stat_remote(&remote, false, cancel).await
            && entry.kind == EntryType::Directory
        {
            return Err(Status::new(ErrorName::IsADirectory, format!("{} is a folder", display(&remote))));
        }
        Err(status)
    }

    /// XC-9: a non-empty folder is `DirectoryNotEmpty`.
    ///
    /// # Errors
    /// As the server reports it.
    pub async fn remove_dir(&mut self, path: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        let remote = self.resolve(path)?;
        let Err(f) = self.client.simple(Simple::Rmdir(&remote), cancel).await else {
            return Ok(());
        };
        let status = f.status(&display(&remote));
        if fatal(&status) {
            return Err(status);
        }
        let Ok(entry) = self.stat_remote(&remote, false, cancel).await else {
            return Err(status);
        };
        // XC-9: OpenSSH reports ENOTDIR as "no such file" and ENOTEMPTY as
        // a plain failure.
        if entry.kind != EntryType::Directory {
            return Err(Status::new(
                ErrorName::NotADirectory,
                format!("{} is not a folder", display(&remote)),
            ));
        }
        if status.name != ErrorName::PermissionDenied && self.has_children(&remote, cancel).await {
            return Err(Status::new(
                ErrorName::DirectoryNotEmpty,
                format!("{} is not empty", display(&remote)),
            ));
        }
        Err(status)
    }

    async fn has_children(&self, remote: &[u8], cancel: &CancelToken) -> bool {
        let Ok(handle) = self.client.opendir(remote, cancel).await else {
            return false;
        };
        let mut found = false;
        while let Ok(Some(names)) = self.client.readdir(&handle, cancel).await {
            if names.iter().any(|n| n.filename != b"." && n.filename != b"..") {
                found = true;
                break;
            }
        }
        self.client.close_detached(&handle);
        found
    }

    /// `AlreadyExists` when something is at `remote` now, else `failure`
    /// (OpenSSH reports EEXIST as a plain failure).
    async fn exists_as(&self, remote: &[u8], failure: Status, cancel: &CancelToken) -> Status {
        if fatal(&failure) || self.stat_remote(remote, false, cancel).await.is_err() {
            return failure;
        }
        Status::new(ErrorName::AlreadyExists, format!("{} exists", display(remote)))
    }

    /// XC-10, XS-6.
    ///
    /// # Errors
    /// As the server reports it; `AlreadyExists`.
    pub async fn rename(
        &mut self,
        from: &[u8],
        to: &[u8],
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let source = self.resolve(from)?;
        let target = self.resolve(to)?;
        match mode {
            RenameMode::NoReplace => self.rename_no_replace(&source, &target, cancel).await,
            RenameMode::Replace => self.rename_replacing(&source, &target, cancel).await,
        }
    }

    async fn rename_no_replace(
        &self,
        source: &[u8],
        target: &[u8],
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        // XS-6: OpenSSH fails a plain RENAME on an existing target,
        // atomically for files (NativeNoReplace).
        let Err(f) = self.client.simple(Simple::Rename(source, target), cancel).await else {
            return Ok(());
        };
        let status = f.status(&display(source));
        if status.name == ErrorName::NotFound {
            return Err(status);
        }
        Err(self.exists_as(target, status, cancel).await)
    }

    async fn rename_replacing(
        &self,
        source: &[u8],
        target: &[u8],
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let existing = match self.stat_remote(target, false, cancel).await {
            Ok(entry) => Some(entry),
            Err(s) if s.name == ErrorName::NotFound => None,
            Err(s) => return Err(s),
        };
        if let Some(entry) = &existing {
            if source == target {
                return Ok(());
            }
            // XC-10: a folder is never replaced.
            if entry.kind == EntryType::Directory {
                return Err(Status::new(
                    ErrorName::AlreadyExists,
                    format!("{} is a folder", display(target)),
                ));
            }
        }
        // With posix-rename@openssh.com the target is replaced atomically
        // (AtomicReplace); a plain RENAME does not replace (S-22): remove
        // first.
        if !self.ext.posix_rename && existing.is_some() {
            self.client
                .simple(Simple::Remove(target), cancel)
                .await
                .map_err(|f| f.status(&display(target)))?;
        }
        let renamed = if self.ext.posix_rename {
            let fields = [Field::Str(source), Field::Str(target)];
            match self.client.extended("posix-rename@openssh.com", &fields, cancel).await {
                Ok(reply) => ok(reply),
                Err(f) => Err(f),
            }
        } else {
            self.client.simple(Simple::Rename(source, target), cancel).await
        };
        renamed.map_err(|f| f.status(&display(source)))?;
        // rename(2) of one hard link onto another of the same file succeeds
        // and keeps both names; XC-10 leaves one.
        if self.ext.posix_rename
            && existing.is_some_and(|e| e.kind == EntryType::File)
            && self.stat_remote(source, false, cancel).await.is_ok()
        {
            self.client
                .simple(Simple::Remove(source), cancel)
                .await
                .map_err(|f| f.status(&display(source)))?;
        }
        Ok(())
    }

    /// XC-11, XS-5: every field is checked first.
    ///
    /// # Errors
    /// `Internal` for values SFTP v3 cannot store; as the server reports it.
    pub async fn set_attributes(
        &mut self,
        path: &[u8],
        changes: &Attributes,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        check_attributes(changes)?;
        let remote = self.resolve(path)?;
        if *changes == Attributes::default() {
            return self.stat_remote(&remote, true, cancel).await.map(drop);
        }
        set_times(&self.client, &remote, changes.mtime_ms, changes.atime_ms, changes.mode, cancel).await
    }

    /// XC-12: the target verbatim.
    ///
    /// # Errors
    /// `InvalidName` for an entry that is no link; as the server reports it.
    pub async fn read_link(&mut self, path: &[u8], cancel: &CancelToken) -> Result<Vec<u8>, Status> {
        let remote = self.resolve(path)?;
        match self.client.path_of(PathOf::Readlink(&remote), cancel).await {
            Ok(target) => Ok(target),
            Err(f) => {
                let status = f.status(&display(&remote));
                if !fatal(&status)
                    && let Ok(entry) = self.stat_remote(&remote, false, cancel).await
                    && entry.kind != EntryType::Symlink
                {
                    return Err(Status::invalid_name(format!("{} is not a symbolic link", display(&remote))));
                }
                Err(status)
            }
        }
    }

    /// XC-12: `target` verbatim.
    ///
    /// # Errors
    /// `InvalidName` for an empty target or one with NUL; `AlreadyExists`.
    pub async fn make_symlink(
        &mut self,
        target: &[u8],
        link: &[u8],
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let remote = self.resolve(link)?;
        if target.is_empty() || target.contains(&0) {
            return Err(Status::invalid_name("Invalid link target"));
        }
        let Err(f) = self.client.simple(Simple::Symlink { target, link: &remote }, cancel).await else {
            return Ok(());
        };
        Err(self.exists_as(&remote, f.status(&display(&remote)), cancel).await)
    }

    /// XC-12 with `hardlink@openssh.com`.
    ///
    /// # Errors
    /// `Unsupported` without the extension; `AlreadyExists`.
    pub async fn make_hardlink(
        &mut self,
        existing: &[u8],
        link: &[u8],
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        if !self.ext.hardlink {
            return Err(Status::unsupported("The server cannot create hard links"));
        }
        let source = self.resolve(existing)?;
        let target = self.resolve(link)?;
        let fields = [Field::Str(&source), Field::Str(&target)];
        let result = match self.client.extended("hardlink@openssh.com", &fields, cancel).await {
            Ok(reply) => ok(reply),
            Err(f) => Err(f),
        };
        let Err(f) = result else {
            return Ok(());
        };
        let status = f.status(&display(&target));
        if status.name == ErrorName::NotFound {
            return Err(status);
        }
        Err(self.exists_as(&target, status, cancel).await)
    }

    /// XC-19 with `statvfs@openssh.com`.
    ///
    /// # Errors
    /// `Unsupported` without the extension; as the server reports it.
    pub async fn space_info(&mut self, dir: &[u8], cancel: &CancelToken) -> Result<SpaceInfo, Status> {
        if !self.ext.statvfs {
            return Err(Status::unsupported("The server cannot report free space"));
        }
        let remote = self.resolve(dir)?;
        statvfs(&self.client, &remote, cancel)
            .await
            .map(|s| space_from(&s))
            .map_err(|f| f.status(&display(&remote)))
    }

    /// XC-17 with `copy-data`: a file, never a folder (`ServerCopy` only).
    ///
    /// # Errors
    /// `Unsupported` without the extension or for a folder with
    /// `recursive`; `IsADirectory`, `AlreadyExists`, `NotFound`.
    pub async fn copy(
        &mut self,
        from: &[u8],
        to: &[u8],
        recursive: bool,
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        if !self.ext.copy_data {
            return Err(Status::unsupported("The server cannot copy files"));
        }
        let source = self.resolve(from)?;
        let target = self.resolve(to)?;
        let entry = self.stat_remote(&source, true, cancel).await?;
        if entry.kind == EntryType::Directory {
            if recursive {
                return Err(Status::unsupported("The server cannot copy folders"));
            }
            return Err(Status::new(ErrorName::IsADirectory, format!("{} is a folder", display(&source))));
        }
        match self.stat_remote(&target, false, cancel).await {
            Ok(existing) if existing.kind == EntryType::Directory => {
                return Err(Status::new(
                    ErrorName::AlreadyExists,
                    format!("{} is a folder", display(&target)),
                ));
            }
            Ok(_) if mode == RenameMode::NoReplace => {
                return Err(Status::new(ErrorName::AlreadyExists, format!("{} exists", display(&target))));
            }
            Ok(existing) if existing.kind != EntryType::File => {
                // A link or special file is replaced, not written through.
                self.client
                    .simple(Simple::Remove(&target), cancel)
                    .await
                    .map_err(|f| f.status(&display(&target)))?;
            }
            Ok(_) => {}
            Err(s) if s.name == ErrorName::NotFound => {}
            Err(s) => return Err(s),
        }
        self.copy_data(&source, &target, &entry, mode, cancel).await
    }

    async fn copy_data(
        &self,
        source: &[u8],
        target: &[u8],
        entry: &Entry,
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let c = &self.client;
        let read = c
            .open(source, FXF_READ, &Attrs::default(), cancel)
            .await
            .map_err(|f| f.status(&display(source)))?;
        // No TRUNC: the target may be the source under another name; the
        // size is set after the copy.
        let create = if mode == RenameMode::NoReplace { FXF_CREAT | FXF_EXCL } else { FXF_CREAT };
        let attrs =
            Attrs { permissions: Some(entry.mode.unwrap_or(DEFAULT_FILE_MODE) & 0o777), ..Attrs::default() };
        let write = match c.open(target, FXF_WRITE | create, &attrs, cancel).await {
            Ok(handle) => handle,
            Err(f) => {
                c.close_detached(&read);
                return Err(self.exists_as(target, f.status(&display(target)), cancel).await);
            }
        };
        let fields = [Field::Str(&read), Field::U64(0), Field::U64(0), Field::Str(&write), Field::U64(0)];
        let mut result = match c.extended("copy-data", &fields, cancel).await {
            Ok(reply) => ok(reply),
            Err(f) => Err(f),
        };
        if result.is_ok() {
            let size = Attrs { size: Some(entry.size.unwrap_or(0)), ..Attrs::default() };
            result = c.simple(Simple::Setstat(target, size), cancel).await;
        }
        c.close_detached(&read);
        if result.is_ok() {
            result = c.close(&write, cancel).await;
        } else {
            c.close_detached(&write);
        }
        let Err(f) = result else {
            return Ok(());
        };
        let status = f.status(&display(target));
        if mode == RenameMode::NoReplace && !fatal(&status) {
            // The target is ours: no half copy stays behind.
            drop(c.simple(Simple::Remove(target), cancel).await);
        }
        Err(status)
    }
}

#[cfg(test)]
mod tests;
