// SPDX-License-Identifier: LGPL-2.1-or-later
//! [`Smb`]: the [`Backend`] of provider `smb` (SPEC-smb, SPEC-v2 XM-*).
//!
//! One TCP connection and one session per backend (design §5.1). Share
//! mode works in the share of option `share`; server mode (no `share`)
//! shows the shares as the root's folders, keeps IPC$ as its main tree and
//! connects up to [`MAX_SHARE_TREES`] shares, the least recently used one
//! disconnected for another unless files are open on it (XM-2). The
//! password is used for the sign-in only and not kept.

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use netvfs_vfs::{
    Attributes, Backend, CancelToken, Capabilities, Capability, Credentials, Disposition, Entry, EntryType,
    ErrorName, ListOptions, ListSink, Params, Progress, Prompter, ReadHandle, RenameMode, ServerIdentity,
    Sink, Source, SpaceInfo, Status, Value, WriteHandle, WriteOptions,
};
use zeroize::Zeroizing;

use crate::auth::Account;
use crate::conn::{Conn, Element};
use crate::error::{Error, Phase, Result};
use crate::files::{Open, SmbRead, SmbWrite, chunk};
use crate::fs;
use crate::msg::Command;
use crate::msg::file::{Create, Created, access, attributes, disposition, filetime_of_ms, options};
use crate::names::{components, smb_path, valid_share_name};
use crate::profile::Profile;
use crate::rpc;
use crate::session::{self, Session, Tree};
use crate::status::NtStatus;
use crate::transport;

/// Shares connected at once in server mode (XM-2).
pub const MAX_SHARE_TREES: usize = 4;
/// UTF-8 bytes of a name (Samba on Linux file systems, NTFS in ASCII).
pub const MAX_NAME_BYTES: u64 = 255;
/// The share of server mode's main tree.
pub const IPC_SHARE: &str = "IPC$";
/// C-14.
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 15_000;
/// C-14.
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 60_000;
/// The times SMB stores, in ms: after 1970-01-01T00:00:01 and before the
/// end of 30828 (FILETIME).
const TIME_RANGE_MS: std::ops::Range<i64> = 1000..910_692_730_085_000;
/// XC-11.
pub const TIMES_UNSUPPORTED: &str = "SMB stores times between 1970 and 30828 only";

/// XM-2: what the root of server mode allows.
fn root_denied(what: &str) -> Status {
    Status::permission_denied(format!("{what}: the server root holds only the shares"))
}

fn share_root_denied(what: &str) -> Status {
    Status::permission_denied(format!("{what}: a share cannot be removed or renamed"))
}

fn established(e: Error, context: &str) -> Status {
    e.status(context, Phase::Established)
}

/// A refused TREE_CONNECT reads like the sign-in it was in libsmb2 (one
/// sign-in per share): the share's statuses and policies with the setup
/// texts, the connection's failures as they are.
fn tree_refused(e: Error) -> Status {
    let phase =
        if matches!(e, Error::Status(_) | Error::Policy(_)) { Phase::Setup } else { Phase::Established };
    e.status("Sign-in failed", phase)
}

/// Whether `ms` is a time SMB stores.
#[must_use]
pub fn representable(ms: Option<i64>) -> bool {
    ms.is_none_or(|ms| TIME_RANGE_MS.contains(&ms))
}

fn timeout_of(ms: i32, default_ms: u64) -> Duration {
    Duration::from_millis(u64::try_from(ms).ok().filter(|ms| *ms > 0).unwrap_or(default_ms))
}

/// `ConnectionParams::flag(key, fallback)`.
fn flag_or(params: &Params, key: &str, fallback: bool) -> bool {
    if params.options.contains_key(key) { params.flag(key) } else { fallback }
}

/// XM-3: the valid names of option `shares` (a list, or comma-separated),
/// each once, ignoring case.
#[must_use]
pub fn configured_shares(params: &Params) -> Vec<String> {
    let raw: Vec<String> = match params.options.get("shares") {
        Some(Value::StrList(list)) => list.clone(),
        Some(_) => params.option("shares").unwrap_or_default().split(',').map(str::to_owned).collect(),
        None => Vec::new(),
    };
    let mut shares = Vec::new();
    merge_share_names(
        &mut shares,
        raw.iter().map(|s| s.trim()).filter(|s| valid_share_name(s)).map(str::to_owned),
    );
    shares
}

/// Appends the names not in `list` yet, ignoring case.
pub fn merge_share_names(list: &mut Vec<String>, more: impl IntoIterator<Item = String>) {
    for name in more {
        if !list.iter().any(|n| n.to_lowercase() == name.to_lowercase()) {
            list.push(name);
        }
    }
}

/// `work`, or `Canceled` as soon as `cancel` trips.
async fn or_canceled<T>(cancel: &CancelToken, work: impl Future<Output = Result<T>>) -> Result<T> {
    let mut work = pin!(work);
    let mut canceled = pin!(cancel.canceled());
    poll_fn(|cx| {
        if let Poll::Ready(r) = work.as_mut().poll(cx) {
            return Poll::Ready(r);
        }
        if canceled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Error::Canceled));
        }
        Poll::Pending
    })
    .await
}

/// A connected share of server mode.
#[derive(Debug)]
struct ShareTree {
    name: String,
    /// One reference here, one per open file.
    tree: Arc<Tree>,
    last_use: u64,
}

/// The signed-in state.
#[derive(Debug)]
struct SignedIn {
    session: Session,
    /// The share, or IPC$ in server mode.
    main: Arc<Tree>,
    shares: Vec<ShareTree>,
    clock: u64,
    read_chunk: usize,
    write_chunk: usize,
}

impl SignedIn {
    fn conn(&self) -> &Conn {
        &self.session.conn
    }
}

/// Where a path is: its share (`None`: the server root), the path in the
/// share and the entry's name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Place {
    share: Option<String>,
    path: Vec<u16>,
    name: Vec<u8>,
}

/// The backend.
#[derive(Debug, Default)]
pub struct Smb {
    params: Params,
    /// The address that answered `connect`.
    address: Option<SocketAddr>,
    signed: Option<SignedIn>,
}

impl Smb {
    /// A new, unconnected backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Option `share`: share mode in it; server mode without.
    fn share_option(&self) -> Option<String> {
        self.params.option("share").map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
    }

    fn server_mode(&self) -> bool {
        self.share_option().is_none()
    }

    fn host(&self) -> String {
        self.params.host.trim().to_owned()
    }

    /// The share, the path in it and the name (M-8, M-9: invalid names
    /// are refused before anything else).
    fn split(&self, path: &[u8]) -> std::result::Result<Place, Status> {
        let parts = components(path)?;
        let name = parts.last().map(|p| p.to_vec()).unwrap_or_default();
        if let Some(share) = self.share_option() {
            return Ok(Place { share: Some(share), path: smb_path(&parts)?, name });
        }
        let Some((first, rest)) = parts.split_first() else {
            return Ok(Place { share: None, path: Vec::new(), name });
        };
        let share = std::str::from_utf8(first)
            .ok()
            .filter(|s| valid_share_name(s))
            .ok_or_else(|| Status::invalid_name("not a valid share name"))?;
        Ok(Place { share: Some(share.to_owned()), path: smb_path(rest)?, name })
    }

    fn signed_in(&self) -> std::result::Result<&SignedIn, Status> {
        let s = self.signed.as_ref().ok_or_else(|| Status::internal("Not signed in"))?;
        s.conn().usable().map_err(|e| established(e, ""))?;
        Ok(s)
    }

    /// [`Self::split`] and the signed-in check.
    fn place(&self, path: &[u8]) -> std::result::Result<Place, Status> {
        let place = self.split(path)?;
        self.signed_in()?;
        Ok(place)
    }

    /// XM-2: a share itself, or the root, in server mode.
    fn share_level(&self, path: &[u8]) -> bool {
        self.server_mode() && self.split(path).is_ok_and(|p| p.path.is_empty())
    }

    /// The tree of `place` (which is not the root): the main one, or in
    /// server mode that of its share, connected when needed (XM-2).
    async fn tree(&mut self, place: &Place, cancel: &CancelToken) -> std::result::Result<Arc<Tree>, Status> {
        let host = self.host();
        let server_mode = self.server_mode();
        let s = self.signed.as_mut().ok_or_else(|| Status::internal("Not signed in"))?;
        let Some(share) = place.share.as_deref() else {
            return Err(Status::internal("the server root has no tree"));
        };
        if !server_mode {
            return Ok(Arc::clone(&s.main));
        }
        s.clock = s.clock.saturating_add(1);
        let clock = s.clock;
        let wanted = share.to_lowercase();
        if let Some(t) = s.shares.iter_mut().find(|t| t.name.to_lowercase() == wanted) {
            t.last_use = clock;
            return Ok(Arc::clone(&t.tree));
        }
        if s.shares.len() >= MAX_SHARE_TREES {
            let oldest = s
                .shares
                .iter()
                .enumerate()
                .filter(|(_, t)| Arc::strong_count(&t.tree) == 1)
                .min_by_key(|(_, t)| t.last_use)
                .map(|(i, _)| i)
                .ok_or_else(|| {
                    Status::new(
                        ErrorName::TooManyConnections,
                        format!("Files are open on {MAX_SHARE_TREES} shares already; close some first"),
                    )
                })?;
            let gone = s.shares.remove(oldest);
            // Best effort: the tree goes with the session at the latest.
            drop(session::tree_disconnect(s.conn(), &gone.tree, cancel).await);
        }
        let tree =
            Arc::new(session::tree_connect(s.conn(), &host, share, cancel).await.map_err(tree_refused)?);
        s.shares.push(ShareTree { name: share.to_owned(), tree: Arc::clone(&tree), last_use: clock });
        Ok(tree)
    }

    /// XM-3: the shares the user saved, then what enumeration finds.
    async fn list_root(
        &self,
        options: ListOptions,
        sink: &mut dyn ListSink,
        cancel: &CancelToken,
    ) -> Result<()> {
        let mut names = configured_shares(&self.params);
        if self.enumerates() {
            let s = self.signed.as_ref().ok_or_else(|| Error::Local(Status::internal("Not signed in")))?;
            let found = rpc::list_shares(s.conn(), &s.main, &self.host(), cancel)
                .await
                .map_err(|e| Error::Local(established(e, "Cannot list the shares")))?;
            let show_admin = flag_or(&self.params, "show_admin_shares", false);
            merge_share_names(
                &mut names,
                found.into_iter().filter(|s| s.visible(show_admin)).map(|s| s.name),
            );
        }
        let batch_size = options.batch_size.max(1);
        let entries: Vec<Entry> = names
            .into_iter()
            .map(|name| Entry { name: name.into_bytes(), kind: EntryType::Directory, ..Entry::default() })
            .collect();
        for batch in entries.chunks(batch_size) {
            if cancel.is_canceled() {
                return Err(Error::Canceled);
            }
            if !sink.entries(batch) {
                return Err(Error::Local(Status::new(ErrorName::Canceled, "The listing was stopped")));
            }
        }
        Ok(())
    }

    /// XM-7: on by default in server mode.
    fn enumerates(&self) -> bool {
        self.server_mode() && flag_or(&self.params, "share_enumeration", true)
    }

    /// A file for reading: its handle and size.
    async fn open_file(
        &mut self,
        place: &Place,
        cancel: &CancelToken,
    ) -> std::result::Result<SmbRead, Status> {
        let tree = self.tree(place, cancel).await?;
        let s = self.signed_in()?;
        let create = Create {
            name: &place.path,
            access: access::READ_DATA | access::READ_ATTRIBUTES | access::SYNCHRONIZE,
            attributes: 0,
            disposition: disposition::OPEN,
            options: options::NON_DIRECTORY,
        };
        let created = create_file(s.conn(), &tree, &create, cancel).await.map_err(|e| match e {
            Error::Status(NtStatus::FILE_IS_A_DIRECTORY) => {
                Status::new(ErrorName::IsADirectory, "open: a folder")
            }
            e => established(e, "open"),
        })?;
        let open = Open { conn: s.conn().clone(), tree, file_id: created.file_id };
        if created.attributes & attributes::DIRECTORY != 0 {
            drop(SmbRead::new(open, 0, 1));
            return Err(Status::new(ErrorName::IsADirectory, "open: a folder"));
        }
        Ok(SmbRead::new(open, created.end_of_file, s.read_chunk))
    }

    async fn open_writer(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        cancel: &CancelToken,
    ) -> std::result::Result<SmbWrite, Status> {
        // XM-2: no files beside the shares ("/name" is a share, not a file).
        if self.share_level(path) {
            return Err(root_denied("open"));
        }
        if !representable(options.mtime_ms) {
            return Err(Status::unsupported(TIMES_UNSUPPORTED));
        }
        let place = self.place(path)?;
        let tree = self.tree(&place, cancel).await?;
        let s = self.signed_in()?;
        let (disposition, access) = match options.disposition {
            Disposition::CreateNew => (disposition::CREATE, access::WRITE_DATA),
            Disposition::Truncate => (disposition::OVERWRITE_IF, access::WRITE_DATA),
            Disposition::Resume => (disposition::OPEN, access::WRITE_DATA | access::READ_DATA),
        };
        let create = Create {
            name: &place.path,
            access: access | access::READ_ATTRIBUTES | access::SYNCHRONIZE,
            attributes: attributes::NORMAL,
            disposition,
            options: options::NON_DIRECTORY,
        };
        let created = match create_file(s.conn(), &tree, &create, cancel).await {
            Ok(created) => created,
            Err(e) => {
                let folder = !matches!(e, Error::Lost(_) | Error::Canceled | Error::Timeout)
                    && fs::stat(s.conn(), tree.target(), &place.path, cancel).await.is_ok_and(|i| i.is_dir());
                if folder {
                    return Err(Status::new(ErrorName::IsADirectory, "open: a folder"));
                }
                return Err(established(e, "open"));
            }
        };
        let position = if options.disposition == Disposition::Resume { options.resume_offset } else { 0 };
        let open = Open { conn: s.conn().clone(), tree, file_id: created.file_id };
        let writer = SmbWrite::new(open, place.path, position, options.mtime_ms, s.write_chunk);
        // Resume: the remote size must be where the caller continues.
        if options.disposition == Disposition::Resume && created.end_of_file != options.resume_offset {
            writer.abort().await;
            return Err(Status::new(
                ErrorName::ProtocolError,
                format!(
                    "Cannot resume at {}: the file has {} bytes",
                    options.resume_offset, created.end_of_file
                ),
            ));
        }
        Ok(writer)
    }

    #[cfg(test)]
    fn signed_in_with(params: Params, session: Session, main: Tree) -> Self {
        let negotiated = &session.negotiated;
        let read_chunk = chunk(negotiated.max_read, negotiated.multi_credit);
        let write_chunk = chunk(negotiated.max_write, negotiated.multi_credit);
        let signed =
            SignedIn { session, main: Arc::new(main), shares: Vec::new(), clock: 0, read_chunk, write_chunk };
        Self { params, address: None, signed: Some(signed) }
    }
}

/// CREATE of one file, its handle owned (closed should the call go).
async fn create_file(conn: &Conn, tree: &Tree, create: &Create<'_>, cancel: &CancelToken) -> Result<Created> {
    let resp =
        conn.call(tree.target(), Element::new(Command::Create, create.encode()?).owning(), cancel).await?;
    resp.ok()?;
    Created::decode(&resp.msg)
}

impl Drop for Smb {
    fn drop(&mut self) {
        if let Some(s) = self.signed.take() {
            s.conn().abort();
        }
    }
}

impl Backend for Smb {
    type Read = SmbRead;
    type Write = SmbWrite;

    async fn connect(
        &mut self,
        params: &Params,
        cancel: &CancelToken,
    ) -> std::result::Result<Option<ServerIdentity>, Status> {
        self.disconnect().await;
        params.clone_into(&mut self.params);
        let port = match params.port {
            p if p <= 0 => transport::DEFAULT_PORT,
            p => u16::try_from(p).map_err(|_range| {
                Status::new(
                    ErrorName::NetworkUnreachable,
                    format!("Cannot connect to the server: port {p} is out of range"),
                )
            })?,
        };
        let timeout = timeout_of(params.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS);
        let host = self.host();
        // M-10: resolve and check that the port answers; the session needs
        // the credentials and starts in authenticate(). SMB has no server
        // identity (SPEC-smb 3): the session key, from the password, signs
        // the server's answers instead.
        let addr = or_canceled(cancel, async {
            let addrs = transport::resolve(&host, port).await?;
            let (stream, addr) = transport::connect(&addrs, timeout).await?;
            drop(stream);
            Ok(addr)
        })
        .await
        .map_err(|e| e.status("Cannot connect to the server", Phase::Setup))?;
        self.address = Some(addr);
        Ok(None)
    }

    async fn authenticate(
        &mut self,
        credentials: &Credentials,
        _prompter: Option<&mut dyn Prompter>,
        cancel: &CancelToken,
    ) -> std::result::Result<(), Status> {
        // NTLMSSP has no interactive step.
        let Some(addr) = self.address.filter(|_| self.signed.is_none()) else {
            return Err(Status::internal("authenticate() needs a successful connect()"));
        };
        // XM-1: the profile given is enforced; XSEC-2: a failure is never
        // retried with a weaker one.
        let profile = Profile::parse(self.params.option("security_profile").as_deref())?;
        let share = self.share_option();
        if share.as_deref().is_some_and(|s| !valid_share_name(s)) {
            return Err(Status::invalid_name("not a valid share name"));
        }
        let account = if profile == Profile::Guest {
            Account::Anonymous
        } else {
            let user = if credentials.user.is_empty() {
                self.params.username.clone()
            } else {
                credentials.user.clone()
            };
            if user.is_empty() || credentials.secret.is_empty() {
                return Err(Status::new(ErrorName::AuthFailed, "A user name and a password are required"));
            }
            let password = std::str::from_utf8(&credentials.secret)
                .map_err(|_not_utf8| Status::new(ErrorName::AuthFailed, "The password is not valid UTF-8"))?;
            let domain = if credentials.domain.is_empty() {
                self.params.option("domain").unwrap_or_default()
            } else {
                credentials.domain.clone()
            };
            Account::User { user, domain, password: Zeroizing::new(password.to_owned()) }
        };
        let host = self.host();
        let connect_timeout = timeout_of(self.params.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS);
        let request_timeout = timeout_of(self.params.request_timeout_ms, DEFAULT_REQUEST_TIMEOUT_MS);
        let session = or_canceled(cancel, async {
            let (stream, _) = transport::connect(&[addr], connect_timeout).await?;
            session::sign_in(stream, profile, &account, &host, request_timeout, cancel).await
        })
        .await
        .map_err(|e| e.status("Sign-in failed", Phase::Setup))?;
        drop(account);
        let main_share = share.as_deref().unwrap_or(IPC_SHARE);
        let main = match session::tree_connect(&session.conn, &host, main_share, cancel).await {
            Ok(tree) => tree,
            Err(e) => {
                session.conn.abort();
                return Err(e.status("Sign-in failed", Phase::Setup));
            }
        };
        let negotiated = &session.negotiated;
        let read_chunk = chunk(negotiated.max_read, negotiated.multi_credit);
        let write_chunk = chunk(negotiated.max_write, negotiated.multi_credit);
        self.signed = Some(SignedIn {
            session,
            main: Arc::new(main),
            shares: Vec::new(),
            clock: 0,
            read_chunk,
            write_chunk,
        });
        Ok(())
    }

    fn capabilities(&self) -> Capabilities {
        let mut caps = Capabilities::default();
        if self.signed.is_none() {
            return caps;
        }
        caps.flags.extend([
            Capability::NativeNoReplace, // XM-5
            Capability::AtomicReplace,
            Capability::ReadHandles, // XM-6
            Capability::EfficientRanges,
            Capability::WriteResume,
            Capability::SetModified,
            Capability::SetModifiedOnUpload,
            Capability::SpaceInfo, // XM-8
            // XM-4, M-9: SMB clients treat every share as case-insensitive
            // (Windows does, Samba's default "case sensitive = auto" does
            // for clients without POSIX extensions).
            Capability::CaseInsensitive,
            Capability::WindowsNames,
        ]);
        if self.enumerates() {
            caps.flags.insert(Capability::ShareEnumeration);
        }
        caps.max_name_bytes = Some(MAX_NAME_BYTES);
        caps
    }

    async fn disconnect(&mut self) {
        if let Some(s) = self.signed.take() {
            s.conn().close(true).await;
        }
        self.address = None;
    }

    async fn keep_alive(&mut self, cancel: &CancelToken) -> std::result::Result<(), Status> {
        // XM-8: SMB2 ECHO.
        let s = self.signed_in()?;
        session::echo(s.conn(), cancel).await.map_err(|e| established(e, "keep-alive"))
    }

    async fn stat(
        &mut self,
        path: &[u8],
        _follow: bool,
        cancel: &CancelToken,
    ) -> std::result::Result<Entry, Status> {
        let place = self.place(path)?;
        let Some(share) = place.share.clone() else {
            // XM-2: the server root is a folder of shares.
            return Ok(Entry { kind: EntryType::Directory, ..Entry::default() });
        };
        let tree = self.tree(&place, cancel).await?;
        let s = self.signed_in()?;
        let info = fs::stat(s.conn(), tree.target(), &place.path, cancel)
            .await
            .map_err(|e| established(e, "stat"))?;
        let name = if place.path.is_empty() && self.server_mode() { share.into_bytes() } else { place.name };
        Ok(info.entry(name))
    }

    async fn list(
        &mut self,
        dir: &[u8],
        options: ListOptions,
        sink: &mut dyn ListSink,
        cancel: &CancelToken,
    ) -> std::result::Result<(), Status> {
        let place = self.place(dir)?;
        if place.share.is_none() {
            return self.list_root(options, sink, cancel).await.map_err(|e| established(e, "list"));
        }
        let tree = self.tree(&place, cancel).await?;
        let s = self.signed_in()?;
        fs::list(s.conn(), tree.target(), &place.path, options.batch_size, sink, cancel)
            .await
            .map_err(|e| established(e, "list"))
    }

    async fn make_dir(
        &mut self,
        path: &[u8],
        exclusive: bool,
        cancel: &CancelToken,
    ) -> std::result::Result<(), Status> {
        const WHAT: &str = "create folder";
        let place = self.place(path)?;
        if place.share.is_none() {
            return Err(root_denied(WHAT));
        }
        let tree = match self.tree(&place, cancel).await {
            Ok(tree) => tree,
            // XM-2: a share that does not exist cannot be made.
            Err(e) if e.name == ErrorName::NotFound && self.server_mode() && place.path.is_empty() => {
                return Err(root_denied(WHAT));
            }
            Err(e) => return Err(e),
        };
        if place.path.is_empty() {
            // The share root exists.
            return if exclusive {
                Err(Status::new(ErrorName::AlreadyExists, "create folder: the share root exists"))
            } else {
                Ok(())
            };
        }
        let s = self.signed_in()?;
        fs::make_dir(s.conn(), tree.target(), &place.path, exclusive, cancel)
            .await
            .map_err(|e| established(e, WHAT))
    }

    async fn remove_file(&mut self, path: &[u8], cancel: &CancelToken) -> std::result::Result<(), Status> {
        let place = self.place(path)?;
        if place.share.is_none() {
            return Err(root_denied("remove"));
        }
        let tree = self.tree(&place, cancel).await?;
        if place.path.is_empty() {
            return Err(Status::new(ErrorName::IsADirectory, "remove: a folder"));
        }
        let s = self.signed_in()?;
        fs::remove_file(s.conn(), tree.target(), &place.path, cancel)
            .await
            .map_err(|e| established(e, "remove"))
    }

    async fn remove_dir(&mut self, path: &[u8], cancel: &CancelToken) -> std::result::Result<(), Status> {
        const WHAT: &str = "remove folder";
        let place = self.place(path)?;
        if place.share.is_none() {
            return Err(root_denied(WHAT));
        }
        let tree = self.tree(&place, cancel).await?;
        if place.path.is_empty() {
            return Err(share_root_denied(WHAT));
        }
        let s = self.signed_in()?;
        fs::remove_dir(s.conn(), tree.target(), &place.path, cancel).await.map_err(|e| established(e, WHAT))
    }

    async fn rename(
        &mut self,
        from: &[u8],
        to: &[u8],
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> std::result::Result<(), Status> {
        // XM-2: the root and the shares themselves are refused before any
        // share is connected.
        if self.share_level(from) || self.share_level(to) {
            return Err(share_root_denied("rename"));
        }
        let source = self.place(from)?;
        let target = self.place(to)?;
        let source_tree = self.tree(&source, cancel).await?;
        let target_tree = self.tree(&target, cancel).await?;
        if source.path.is_empty() || target.path.is_empty() {
            return Err(share_root_denied("rename"));
        }
        if !Arc::ptr_eq(&source_tree, &target_tree) {
            return Err(Status::unsupported("rename: SMB cannot move between shares"));
        }
        let s = self.signed_in()?;
        // XM-5, XC-10: without Replace the server refuses an existing
        // target (NativeNoReplace); with it ReplaceIfExists replaces it in
        // the same request (AtomicReplace).
        let replace = mode == RenameMode::Replace;
        fs::rename(s.conn(), source_tree.target(), &source.path, &target.path, replace, cancel)
            .await
            .map_err(|e| established(e, "rename"))
    }

    async fn set_attributes(
        &mut self,
        path: &[u8],
        changes: &Attributes,
        cancel: &CancelToken,
    ) -> std::result::Result<(), Status> {
        const WHAT: &str = "set attributes";
        // XC-11: every field is checked before anything changes.
        if changes.mode.is_some() {
            return Err(Status::unsupported("SMB has no permission bits"));
        }
        if !representable(changes.mtime_ms) || !representable(changes.atime_ms) {
            return Err(Status::unsupported(TIMES_UNSUPPORTED));
        }
        let place = self.place(path)?;
        if place.share.is_none() {
            return Err(root_denied(WHAT));
        }
        let tree = self.tree(&place, cancel).await?;
        let s = self.signed_in()?;
        if changes.mtime_ms.is_none() && changes.atime_ms.is_none() {
            return fs::stat(s.conn(), tree.target(), &place.path, cancel)
                .await
                .map(drop)
                .map_err(|e| established(e, "stat"));
        }
        let mtime = changes.mtime_ms.and_then(filetime_of_ms);
        let atime = changes.atime_ms.and_then(filetime_of_ms);
        fs::set_times(s.conn(), tree.target(), &place.path, mtime, atime, cancel)
            .await
            .map_err(|e| established(e, WHAT))
    }

    async fn space_info(
        &mut self,
        dir: &[u8],
        cancel: &CancelToken,
    ) -> std::result::Result<SpaceInfo, Status> {
        let place = self.place(dir)?;
        if place.share.is_none() {
            return Err(root_denied("free space"));
        }
        let tree = self.tree(&place, cancel).await?;
        let s = self.signed_in()?;
        fs::space_info(s.conn(), tree.target(), &place.path, cancel)
            .await
            .map_err(|e| established(e, "free space"))
    }

    async fn open_read(&mut self, path: &[u8], cancel: &CancelToken) -> std::result::Result<SmbRead, Status> {
        let place = self.place(path)?;
        if place.share.is_none() {
            return Err(root_denied("open"));
        }
        self.open_file(&place, cancel).await
    }

    async fn open_write(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        cancel: &CancelToken,
    ) -> std::result::Result<SmbWrite, Status> {
        self.open_writer(path, options, cancel).await
    }

    async fn upload(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        source: &mut dyn Source,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> std::result::Result<(), Status> {
        let mut writer = self.open_writer(path, options, cancel).await?;
        let base = if options.disposition == Disposition::Resume { options.resume_offset } else { 0 };
        let total = source.size().map(|s| s.saturating_add(base));
        let chunk = self.signed.as_ref().map_or(1, |s| s.write_chunk);
        let mut buffer = vec![0u8; chunk];
        let result = async {
            loop {
                if cancel.is_canceled() || progress.canceled() {
                    return Err(Status::canceled());
                }
                let n = source.read(&mut buffer)?;
                let Some(data) = buffer.get(..n).filter(|d| !d.is_empty()) else { return Ok(()) };
                writer.write(data, cancel).await?;
                progress.update(writer.position(), total);
            }
        }
        .await;
        match result {
            Ok(()) => writer.commit(cancel).await,
            Err(e) => {
                writer.abort().await;
                Err(e)
            }
        }
    }

    async fn download(
        &mut self,
        path: &[u8],
        offset: u64,
        length: Option<u64>,
        sink: &mut dyn Sink,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> std::result::Result<(), Status> {
        let place = self.place(path)?;
        if place.share.is_none() {
            return Err(root_denied("download"));
        }
        let mut reader = self.open_file(&place, cancel).await?;
        let known = reader.size().unwrap_or(0);
        let end = length.map_or(known, |l| known.min(offset.saturating_add(l)));
        let chunk = self.signed.as_ref().map_or(1, |s| s.read_chunk);
        let mut buffer = vec![0u8; chunk];
        let mut at = offset;
        let result = async {
            while at < end {
                if progress.canceled() {
                    return Err(Status::canceled());
                }
                // XM-6: up to 4 MiB on the way while this chunk is stored.
                reader.read_ahead(at, end.saturating_sub(at));
                let want = usize::try_from(end.saturating_sub(at)).unwrap_or(usize::MAX).min(chunk);
                let buf = buffer.get_mut(..want).unwrap_or_default();
                let n = reader.read(at, buf, cancel).await?;
                let Some(data) = buf.get(..n).filter(|d| !d.is_empty()) else {
                    break; // the file shrank; the caller compares sizes
                };
                sink.write(data)?;
                at = at.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                progress.update(at.saturating_sub(offset), Some(end.saturating_sub(offset)));
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => reader.close(cancel).await,
            Err(e) => {
                drop(reader);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests;
