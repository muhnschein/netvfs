// SPDX-License-Identifier: LGPL-2.1-or-later
//! Namespace operations on a tree, one round trip where a compound chain allows: CREATE with the related requests and the CLOSE in one chain. Paths are UTF-16 from the share root ([`crate::names::smb_path`]).

use netvfs_vfs::{CancelToken, Entry, EntryFlags, EntryType, ErrorName, ListSink, SpaceInfo, Status};

use crate::conn::{Conn, Element, Response, Target};
use crate::error::{Error, Result};
use crate::msg::Command;
use crate::msg::file::{
    self, Create, Created, DirEntry, FileId, RELATED_FILE_ID, Times, access, attributes, close_request,
    disposition, ms_of_filetime, options,
};
use crate::names::{is_entry_name, wtf8_from_utf16};
use crate::status::NtStatus;

/// OutputBufferLength of QUERY_DIRECTORY: one credit.
pub const DIR_BUFFER: usize = 65_536;
/// OutputBufferLength of QUERY_INFO for FileFsFullSizeInformation.
const FS_INFO_BUFFER: usize = 32;
/// Largest number of bytes of `SpaceInfo` (C++ `qint64`).
const MAX_BYTES: u64 = i64::MAX.unsigned_abs();

/// What a CREATE response says about a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    /// Its times.
    pub times: Times,
    /// EndofFile.
    pub size: u64,
    /// FileAttributes.
    pub attributes: u32,
}

impl Info {
    /// Of a CREATE response.
    #[must_use]
    pub const fn of(created: &Created) -> Self {
        Self { times: created.times, size: created.end_of_file, attributes: created.attributes }
    }

    /// A folder.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.attributes & attributes::DIRECTORY != 0
    }

    /// The entry named `name` (protocol bytes).
    #[must_use]
    pub fn entry(&self, name: Vec<u8>) -> Entry {
        let a = self.attributes;
        // A reparse point is reported as a link.
        let kind = if a & attributes::REPARSE_POINT != 0 {
            EntryType::Symlink
        } else if a & attributes::DIRECTORY != 0 {
            EntryType::Directory
        } else {
            EntryType::File
        };
        let mut flags = EntryFlags::NONE;
        for (bit, flag) in [
            (attributes::HIDDEN, EntryFlags::HIDDEN),
            (attributes::READONLY, EntryFlags::READ_ONLY),
            (attributes::SYSTEM, EntryFlags::SYSTEM),
        ] {
            if a & bit != 0 {
                flags = flags.union(flag);
            }
        }
        if std::str::from_utf8(&name).is_err() {
            flags = flags.union(EntryFlags::NAME_NOT_UTF8);
        }
        Entry {
            name,
            kind,
            flags,
            size: (kind != EntryType::Directory).then_some(self.size.min(MAX_BYTES)),
            mtime_ms: ms_of_filetime(self.times.last_write),
            atime_ms: ms_of_filetime(self.times.last_access),
            ctime_ms: ms_of_filetime(self.times.creation),
            ..Entry::default()
        }
    }
}

/// The entry of a QUERY_DIRECTORY record.
#[must_use]
pub fn dir_entry(d: &DirEntry) -> Entry {
    Info { times: d.times, size: d.size, attributes: d.attributes }.entry(wtf8_from_utf16(&d.name))
}

/// A CREATE request element.
fn create(path: &[u16], access: u32, disposition: u32, options: u32, attributes: u32) -> Result<Element> {
    let body = Create { name: path, access, attributes, disposition, options }.encode()?;
    Ok(Element::new(Command::Create, body))
}

/// An element on the file the chain's CREATE opened.
fn related(command: Command, body: Vec<u8>) -> Element {
    Element::new(command, body).related()
}

fn close_related() -> Element {
    related(Command::Close, close_request(&RELATED_FILE_ID))
}

/// The status of a chain: the first element that failed (a related
/// element fails with its CREATE).
fn chain_ok(responses: &[Response]) -> Result<()> {
    responses.iter().try_for_each(Response::ok)
}

/// The CREATE response of a chain.
fn created(responses: &[Response]) -> Result<Created> {
    let first = responses.first().ok_or_else(|| crate::error::protocol("empty compound response"))?;
    first.ok()?;
    Created::decode(&first.msg)
}

/// A status decided here.
fn local(name: ErrorName, message: &str) -> Error {
    Error::Local(Status::new(name, message))
}

/// The entry at `path` (CREATE for attributes, CLOSE).
///
/// # Errors
/// The server's refusal, the connection's failures.
pub async fn stat(conn: &Conn, target: Target, path: &[u16], cancel: &CancelToken) -> Result<Info> {
    let chain = vec![
        create(path, access::READ_ATTRIBUTES | access::SYNCHRONIZE, disposition::OPEN, 0, 0)?,
        close_related(),
    ];
    let responses = conn.compound(target, chain, cancel).await?;
    Ok(Info::of(&created(&responses)?))
}

/// A folder; an existing one is `AlreadyExists` with `exclusive`, success without it (a file of that name is `AlreadyExists`).
///
/// # Errors
/// As described, the server's refusal, the connection's failures.
pub async fn make_dir(
    conn: &Conn,
    target: Target,
    path: &[u16],
    exclusive: bool,
    cancel: &CancelToken,
) -> Result<()> {
    let chain = vec![
        create(
            path,
            access::READ_ATTRIBUTES | access::SYNCHRONIZE,
            disposition::CREATE,
            options::DIRECTORY,
            attributes::DIRECTORY,
        )?,
        close_related(),
    ];
    let responses = conn.compound(target, chain, cancel).await?;
    match created(&responses) {
        Err(Error::Status(NtStatus::OBJECT_NAME_COLLISION)) if !exclusive => {
            // An existing folder is success (also one made concurrently).
            if stat(conn, target, path, cancel).await?.is_dir() {
                Ok(())
            } else {
                Err(local(ErrorName::AlreadyExists, "create folder: a file has the folder's name"))
            }
        }
        other => other.map(drop),
    }
}

/// CREATE for DELETE, delete disposition, CLOSE.
async fn delete(conn: &Conn, target: Target, path: &[u16], options: u32, cancel: &CancelToken) -> Result<()> {
    let chain = vec![
        create(
            path,
            access::DELETE | access::READ_ATTRIBUTES | access::SYNCHRONIZE,
            disposition::OPEN,
            options,
            0,
        )?,
        related(
            Command::SetInfo,
            file::set_info_request(
                &RELATED_FILE_ID,
                file::DISPOSITION_INFORMATION,
                &file::delete_on_close(),
            )?,
        ),
        close_related(),
    ];
    chain_ok(&conn.compound(target, chain, cancel).await?)
}

/// A file; a folder is `IsADirectory`.
///
/// # Errors
/// As described, the server's refusal, the connection's failures.
pub async fn remove_file(conn: &Conn, target: Target, path: &[u16], cancel: &CancelToken) -> Result<()> {
    match delete(conn, target, path, options::NON_DIRECTORY, cancel).await {
        Err(Error::Status(NtStatus::FILE_IS_A_DIRECTORY)) => {
            Err(local(ErrorName::IsADirectory, "remove: a folder"))
        }
        other => other,
    }
}

/// An empty folder; a non-empty one is `DirectoryNotEmpty`, a file `NotADirectory`.
///
/// # Errors
/// As described, the server's refusal, the connection's failures.
pub async fn remove_dir(conn: &Conn, target: Target, path: &[u16], cancel: &CancelToken) -> Result<()> {
    match delete(conn, target, path, options::DIRECTORY, cancel).await {
        Err(Error::Status(NtStatus::NOT_A_DIRECTORY)) => {
            return Err(local(ErrorName::NotADirectory, "remove folder: not a folder"));
        }
        other => other?,
    }
    // A server may accept the delete disposition of a non-empty folder and keep it: it must be gone afterwards.
    match stat(conn, target, path, cancel).await {
        Ok(_) => Err(local(ErrorName::DirectoryNotEmpty, "remove folder: the folder is not empty")),
        Err(Error::Status(NtStatus::OBJECT_NAME_NOT_FOUND | NtStatus::OBJECT_PATH_NOT_FOUND)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// `from` to `to` on one tree. Without `replace` the server refuses an existing target (NativeNoReplace); with it a file is replaced atomically (ReplaceIfExists, AtomicReplace), a folder never.
///
/// # Errors
/// As described, the server's refusal, the connection's failures.
pub async fn rename(
    conn: &Conn,
    target: Target,
    from: &[u16],
    to: &[u16],
    replace: bool,
    cancel: &CancelToken,
) -> Result<()> {
    if replace {
        match stat(conn, target, to, cancel).await {
            Ok(info) if info.is_dir() => {
                return Err(local(ErrorName::AlreadyExists, "rename: the target is a folder"));
            }
            Ok(_) | Err(Error::Status(NtStatus::OBJECT_NAME_NOT_FOUND | NtStatus::OBJECT_PATH_NOT_FOUND)) => {
            }
            Err(e) => return Err(e),
        }
    }
    let chain = vec![
        create(
            from,
            access::DELETE | access::READ_ATTRIBUTES | access::SYNCHRONIZE,
            disposition::OPEN,
            0,
            0,
        )?,
        related(
            Command::SetInfo,
            file::set_info_request(
                &RELATED_FILE_ID,
                file::RENAME_INFORMATION,
                &file::rename_information(to, replace)?,
            )?,
        ),
        close_related(),
    ];
    chain_ok(&conn.compound(target, chain, cancel).await?)
}

/// Sets the times given (FILETIME; `None` leaves one alone).
///
/// # Errors
/// The server's refusal, the connection's failures.
pub async fn set_times(
    conn: &Conn,
    target: Target,
    path: &[u16],
    last_write: Option<u64>,
    last_access: Option<u64>,
    cancel: &CancelToken,
) -> Result<()> {
    let info = file::basic_information(last_write, last_access);
    let chain = vec![
        create(path, access::WRITE_ATTRIBUTES | access::SYNCHRONIZE, disposition::OPEN, 0, 0)?,
        related(Command::SetInfo, file::set_info_request(&RELATED_FILE_ID, file::BASIC_INFORMATION, &info)?),
        close_related(),
    ];
    chain_ok(&conn.compound(target, chain, cancel).await?)
}

/// FileFsFullSizeInformation of the volume `path` is on.
///
/// # Errors
/// The server's refusal, the connection's failures.
pub async fn space_info(
    conn: &Conn,
    target: Target,
    path: &[u16],
    cancel: &CancelToken,
) -> Result<SpaceInfo> {
    let query =
        file::query_fs_info_request(&RELATED_FILE_ID, file::FS_FULL_SIZE_INFORMATION, FS_INFO_BUFFER)?;
    let chain = vec![
        create(path, access::READ_ATTRIBUTES | access::SYNCHRONIZE, disposition::OPEN, 0, 0)?,
        related(Command::QueryInfo, query).payload(FS_INFO_BUFFER),
        close_related(),
    ];
    let responses = conn.compound(target, chain, cancel).await?;
    chain_ok(&responses)?;
    let fs = file::fs_full_size_response(
        &responses.get(1).ok_or_else(|| crate::error::protocol("short chain"))?.msg,
    )?;
    let bytes = |units: u64| units.saturating_mul(fs.unit_bytes).min(MAX_BYTES);
    Ok(SpaceInfo {
        free: Some(bytes(fs.caller_available_units)),
        total: Some(bytes(fs.total_units)),
        used: fs.total_units.checked_sub(fs.caller_available_units).map(bytes),
    })
}

/// The entries of the folder `path` in batches of `batch` (names that are no entry of it left out: [`is_entry_name`]); `false` from the sink stops with `Canceled`.
///
/// # Errors
/// A file is `NotADirectory`; the server's refusal, the connection's
/// failures.
pub async fn list(
    conn: &Conn,
    target: Target,
    path: &[u16],
    batch: usize,
    sink: &mut dyn ListSink,
    cancel: &CancelToken,
) -> Result<()> {
    let out_len = DIR_BUFFER;
    let chain = vec![
        create(
            path,
            access::READ_DATA | access::READ_ATTRIBUTES | access::SYNCHRONIZE,
            disposition::OPEN,
            options::DIRECTORY,
            0,
        )?
        .owning(),
        related(Command::QueryDirectory, file::query_directory_request(&RELATED_FILE_ID, true, out_len)?)
            .payload(out_len),
    ];
    let responses = conn.compound(target, chain, cancel).await?;
    let dir = match created(&responses) {
        Ok(dir) => dir,
        Err(Error::Status(NtStatus::NOT_A_DIRECTORY)) => {
            return Err(local(ErrorName::NotADirectory, "list: not a folder"));
        }
        Err(e) => return Err(e),
    };
    // Closed however the listing ends, also when the call is dropped.
    let _open = Opened { conn, target, file_id: dir.file_id };
    let first = responses.into_iter().nth(1).ok_or_else(|| crate::error::protocol("short chain"))?;
    deliver(conn, target, &dir.file_id, first, batch.max(1), sink, cancel).await
}

/// A handle closed (without waiting) when this goes.
struct Opened<'a> {
    conn: &'a Conn,
    target: Target,
    file_id: FileId,
}

impl Drop for Opened<'_> {
    fn drop(&mut self) {
        self.conn.close_detached(self.target, &self.file_id);
    }
}

/// The QUERY_DIRECTORY rounds after the first.
async fn deliver(
    conn: &Conn,
    target: Target,
    file_id: &FileId,
    mut response: Response,
    batch: usize,
    sink: &mut dyn ListSink,
    cancel: &CancelToken,
) -> Result<()> {
    let mut pending: Vec<Entry> = Vec::new();
    loop {
        if response.expect(&[NtStatus::NO_MORE_FILES])? == NtStatus::NO_MORE_FILES {
            break;
        }
        let entries = file::query_directory_response(&response.msg, DIR_BUFFER)?;
        for d in entries.iter().filter(|d| is_entry_name(&d.name)) {
            pending.push(dir_entry(d));
            if pending.len() == batch {
                give(sink, &mut pending)?;
            }
        }
        let next =
            Element::new(Command::QueryDirectory, file::query_directory_request(file_id, false, DIR_BUFFER)?)
                .payload(DIR_BUFFER);
        response = conn.call(target, next, cancel).await?;
    }
    if !pending.is_empty() {
        give(sink, &mut pending)?;
    }
    Ok(())
}

/// One batch to the sink.
fn give(sink: &mut dyn ListSink, pending: &mut Vec<Entry>) -> Result<()> {
    let more = sink.entries(pending);
    pending.clear();
    if more { Ok(()) } else { Err(local(ErrorName::Canceled, "The listing was stopped")) }
}

#[cfg(test)]
mod tests;
