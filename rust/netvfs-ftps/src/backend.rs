// SPDX-License-Identifier: LGPL-2.1-or-later
//! The FTPS [`Backend`] (provider `ftps`): explicit TLS 1.3 only, protected data only, `MLSD`/`MLST` and
//! `EPSV` only. No plain FTP, no `LIST` parsing, no `PASV`.
//!
//! Options: `host_key` (pinned TLS key). No credentials go out before the identity check: `connect` only
//! shakes hands, `authenticate` sends `USER`.

use crate::ctrl::{Data, Session, Target, arg};
use crate::mlsx::{self, Line, MAX_ENTRIES, MAX_LISTING};
use crate::reply;
use netvfs_tls::{Anchors, Client as Tls};
use netvfs_vfs::{
    Backend, CancelToken, Capabilities, Credentials, Disposition, Entry, EntryType, ErrorName, ListOptions,
    ListSink, NoHandle, Params, Progress, Prompter, RenameMode, ServerIdentity, Sink, Source, Status,
    WriteOptions, Zeroizing,
};
use std::time::Duration;

/// Explicit FTPS shares the FTP port.
pub const DEFAULT_PORT: u16 = 21;
/// Connect timeout when the caller gives none.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Reply timeout when the caller gives none.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_mins(1);
/// Upload and download block.
pub const CHUNK: usize = 256 * 1024;

/// What `connect` takes from the parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Where to connect.
    pub target: Target,
    /// The user name when the credentials name none.
    pub username: String,
    /// `host_key`: the pinned key, `tls-spki-sha256 <base64>`.
    pub pin: Option<String>,
}

fn timeout_or(ms: i32, default: Duration) -> Duration {
    match u64::try_from(ms) {
        Ok(ms) if ms > 0 => Duration::from_millis(ms),
        _ => default,
    }
}

impl Settings {
    /// The settings of `params`.
    ///
    /// # Errors
    /// `Internal` for an empty host or one holding `@` or `/`, or a port out of range.
    pub fn of(params: &Params) -> Result<Self, Status> {
        if params.host.is_empty() || params.host.contains(['@', '/']) {
            return Err(Status::internal("Invalid server name"));
        }
        let port = if params.port <= 0 {
            DEFAULT_PORT
        } else {
            u16::try_from(params.port)
                .map_err(|_e| Status::internal(format!("Invalid port {}", params.port)))?
        };
        Ok(Self {
            target: Target {
                host: params.host.trim_start_matches('[').trim_end_matches(']').to_owned(),
                port,
                connect_timeout: timeout_or(params.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT),
                request_timeout: timeout_or(params.request_timeout_ms, DEFAULT_REQUEST_TIMEOUT),
            },
            username: params.username.clone(),
            pin: params.option("host_key").filter(|p| !p.is_empty()),
        })
    }
}

fn command(verb: &[u8], path: &[u8]) -> Result<Vec<u8>, Status> {
    let path = arg(path)?;
    let mut line = Vec::with_capacity(verb.len().saturating_add(path.len()).saturating_add(1));
    line.extend_from_slice(verb);
    line.push(b' ');
    line.extend_from_slice(path);
    Ok(line)
}

fn parent(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(0) | None => b"/",
        Some(at) => path.get(..at).unwrap_or(b"/"),
    }
}

fn is_root(path: &[u8]) -> bool {
    path.iter().all(|b| *b == b'/')
}

fn not_found() -> Status {
    Status::new(ErrorName::NotFound, "No such file or folder")
}

/// A signed-in connection.
#[derive(Debug)]
pub struct Ftp {
    session: Session,
}

impl Ftp {
    /// The entry at `path` (`MLST`); a refusal is `NotFound`.
    ///
    /// # Errors
    /// `NotFound`, connection errors.
    pub async fn stat(&mut self, path: &[u8]) -> Result<Entry, Status> {
        let r = self.session.cmd(&command(b"MLST", path)?).await?;
        match r.code {
            250 => {}
            450 | 550 => return Err(not_found().with_detail(r.text())),
            _ => return Err(reply::error(&r, "Reading the entry")),
        }
        let line = r.lines.iter().find_map(|l| l.strip_prefix(b" ")).ok_or_else(|| {
            Status::new(ErrorName::ProtocolError, "The server did not describe the entry")
                .with_detail(r.text())
        })?;
        let mut entry = match mlsx::parse(line) {
            Line::Current(e) | Line::Child(e) => e,
            Line::Skip => Entry { kind: EntryType::Directory, ..Entry::default() },
        };
        entry.name = path.rsplit(|b| *b == b'/').next().unwrap_or_default().to_vec();
        Ok(entry)
    }

    /// Whether `path` exists, with its entry.
    async fn find(&mut self, path: &[u8]) -> Result<Option<Entry>, Status> {
        match self.stat(path).await {
            Ok(e) => Ok(Some(e)),
            Err(e) if e.name == ErrorName::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `e` of an operation on `path`, said better: `NotFound` for a missing parent, `NotADirectory` for a file
    /// in the path. Servers answer 550 to all of these.
    async fn explain(&mut self, path: &[u8], e: Status) -> Status {
        if e.name != ErrorName::PermissionDenied {
            return e;
        }
        match self.find(parent(path)).await {
            Ok(None) => Status::new(ErrorName::NotFound, "The parent folder does not exist"),
            Ok(Some(p)) if p.kind != EntryType::Directory => {
                Status::new(ErrorName::NotADirectory, "A file is in the path")
            }
            _ => e,
        }
    }

    /// The entries of folder `dir`.
    ///
    /// # Errors
    /// `NotFound`, `NotADirectory`, `ProtocolError` over the caps, connection errors.
    pub async fn entries(&mut self, dir: &[u8]) -> Result<Vec<Entry>, Status> {
        let line = command(b"MLSD", dir)?;
        let data = match self.session.data(&line, "Listing the folder").await {
            Ok(d) => d,
            // 550, or 501 (pyftpdlib) for a missing folder.
            Err(e) if matches!(e.name, ErrorName::PermissionDenied | ErrorName::ProtocolError) => {
                return Err(match self.find(dir).await {
                    Ok(None) => not_found(),
                    Ok(Some(d)) if d.kind != EntryType::Directory => {
                        Status::new(ErrorName::NotADirectory, "Not a folder")
                    }
                    _ => e,
                });
            }
            Err(e) => return Err(e),
        };
        let bytes = self.session.read_all(data, MAX_LISTING, "Listing the folder").await?;
        let mut out = Vec::new();
        for l in bytes.split(|b| *b == b'\n') {
            let l = l.strip_suffix(b"\r").unwrap_or(l);
            if let Line::Child(e) = mlsx::parse(l) {
                if out.len() >= MAX_ENTRIES {
                    return Err(Status::new(ErrorName::ProtocolError, "The folder has too many entries"));
                }
                out.push(e);
            }
        }
        Ok(out)
    }

    async fn make_dir(&mut self, path: &[u8], exclusive: bool) -> Result<(), Status> {
        if is_root(path) {
            return if exclusive {
                Err(Status::new(ErrorName::AlreadyExists, "The folder exists"))
            } else {
                Ok(())
            };
        }
        let r = self.session.cmd(&command(b"MKD", path)?).await?;
        if r.code == 257 {
            return Ok(());
        }
        let e = reply::error(&r, "Creating the folder");
        match self.find(path).await? {
            Some(d) if d.kind == EntryType::Directory && !exclusive => Ok(()),
            Some(_) => Err(Status::new(ErrorName::AlreadyExists, "The name is taken")),
            None => Err(self.explain(path, e).await),
        }
    }

    async fn remove_file(&mut self, path: &[u8]) -> Result<(), Status> {
        if self.stat(path).await?.kind == EntryType::Directory {
            return Err(Status::new(ErrorName::IsADirectory, "Is a folder"));
        }
        self.session.expect(&command(b"DELE", path)?, &[250, 200], "Removing the file").await.map(drop)
    }

    async fn remove_dir(&mut self, path: &[u8]) -> Result<(), Status> {
        if is_root(path) {
            return Err(Status::permission_denied("Refusing to remove the root folder"));
        }
        if self.stat(path).await?.kind != EntryType::Directory {
            return Err(Status::new(ErrorName::NotADirectory, "Not a folder"));
        }
        if !self.entries(path).await?.is_empty() {
            return Err(Status::new(ErrorName::DirectoryNotEmpty, "The folder is not empty"));
        }
        self.session.expect(&command(b"RMD", path)?, &[250, 200], "Removing the folder").await.map(drop)
    }

    async fn rename(&mut self, from: &[u8], to: &[u8], mode: RenameMode) -> Result<(), Status> {
        let source = self.stat(from).await?;
        if from == to {
            return Ok(());
        }
        if let Some(target) = self.find(to).await? {
            if mode == RenameMode::NoReplace {
                return Err(Status::new(ErrorName::AlreadyExists, "The target exists"));
            }
            if source.kind == EntryType::Directory || target.kind == EntryType::Directory {
                return Err(Status::new(ErrorName::AlreadyExists, "A folder cannot be replaced"));
            }
        }
        self.session.expect(&command(b"RNFR", from)?, &[350], "Renaming").await?;
        let r = self.session.cmd(&command(b"RNTO", to)?).await?;
        if r.code == 250 {
            return Ok(());
        }
        let e = reply::error(&r, "Renaming");
        Err(self.explain(to, e).await)
    }

    async fn upload(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        source: &mut dyn Source,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        match options.disposition {
            Disposition::Resume => return Err(Status::unsupported("Resuming uploads is not supported")),
            Disposition::CreateNew if cancel.guard(self.find(path)).await?.is_some() => {
                return Err(Status::new(ErrorName::AlreadyExists, "The file exists"));
            }
            Disposition::CreateNew | Disposition::Truncate => {}
        }
        let size = source.size();
        let mut data = match cancel.guard(self.session.data(&command(b"STOR", path)?, "Uploading")).await {
            Ok(d) => d,
            Err(e) => return Err(self.explain(path, e).await),
        };
        let mut sent = 0u64;
        let mut buf = vec![0u8; CHUNK];
        let stopped = loop {
            let n = match source.read(&mut buf) {
                Ok(0) => break None,
                Ok(n) => n,
                Err(e) => break Some(e),
            };
            if let Err(e) = self.session.write(&mut data, buf.get(..n).unwrap_or_default(), cancel).await {
                break Some(e);
            }
            sent = sent.saturating_add(n as u64);
            progress.update(sent, size);
            if progress.canceled() {
                break Some(Status::canceled());
            }
        };
        if let Some(e) = stopped {
            self.session.abort(data).await?;
            return Err(e);
        }
        self.session.close_data(data).await?;
        self.session.finish("Uploading").await.map(drop)
    }

    async fn download(
        &mut self,
        path: &[u8],
        offset: u64,
        length: Option<u64>,
        sink: &mut dyn Sink,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let entry = cancel.guard(self.stat(path)).await?;
        if entry.kind == EntryType::Directory {
            return Err(Status::new(ErrorName::IsADirectory, "Is a folder"));
        }
        if length == Some(0) || entry.size.is_some_and(|s| offset >= s) {
            return Ok(());
        }
        if offset > 0 {
            let rest = format!("REST {offset}");
            cancel.guard(self.session.expect(rest.as_bytes(), &[350], "Reading from an offset")).await?;
        }
        let mut data: Data = cancel.guard(self.session.data(&command(b"RETR", path)?, "Downloading")).await?;
        let total =
            entry.size.map(|s| s.saturating_sub(offset)).map(|left| length.map_or(left, |l| l.min(left)));
        let mut left = length;
        let mut got = 0u64;
        let mut buf = vec![0u8; CHUNK];
        let stopped = loop {
            if left == Some(0) {
                break Some(None);
            }
            let want = left.map_or(buf.len(), |l| usize::try_from(l).unwrap_or(usize::MAX).min(buf.len()));
            let n = match self.session.read(&mut data, buf.get_mut(..want).unwrap_or_default(), cancel).await
            {
                Ok(0) => break None,
                Ok(n) => n,
                Err(e) => break Some(Some(e)),
            };
            if let Err(e) = sink.write(buf.get(..n).unwrap_or_default()) {
                break Some(Some(e));
            }
            got = got.saturating_add(n as u64);
            left = left.map(|l| l.saturating_sub(n as u64));
            progress.update(got, total);
            if progress.canceled() {
                break Some(Some(Status::canceled()));
            }
        };
        // `Some`: stopped before the end, with the error to return, if any.
        if let Some(e) = stopped {
            self.session.abort(data).await?;
            return e.map_or(Ok(()), Err);
        }
        drop(data);
        self.session.finish("Downloading").await.map(drop)
    }
}

/// Connected, not signed in.
#[derive(Debug)]
struct Connected {
    session: Session,
    settings: Settings,
    mismatch: bool,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Idle,
    Connected(Box<Connected>),
    Ready(Box<Ftp>),
}

/// One FTPS connection.
#[derive(Debug)]
pub struct Ftps {
    state: State,
    anchors: Anchors,
}

impl Default for Ftps {
    fn default() -> Self {
        Self::new()
    }
}

impl Ftps {
    /// Not connected; system CAs.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_anchors(Anchors::System)
    }

    /// Not connected; `anchors` make a certificate system trusted (tests).
    #[must_use]
    pub const fn with_anchors(anchors: Anchors) -> Self {
        Self { state: State::Idle, anchors }
    }

    async fn close(&mut self) {
        match std::mem::take(&mut self.state) {
            State::Idle => {}
            State::Connected(c) => c.session.quit().await,
            State::Ready(f) => f.session.quit().await,
        }
    }

    fn ftp(&mut self, cancel: &CancelToken) -> Result<&mut Ftp, Status> {
        let State::Ready(ftp) = &mut self.state else {
            return Err(Status::internal("Not signed in"));
        };
        cancel.check()?;
        Ok(ftp)
    }
}

/// Signs in on `session`: `USER`, `PASS`, then protected data, binary type, UTF-8 names, and a check for
/// `MLST`.
async fn sign_in(session: &mut Session, user: &str, secret: &[u8]) -> Result<(), Status> {
    if user.is_empty() {
        return Err(Status::new(ErrorName::AuthFailed, "FTP needs a user name"));
    }
    let r = session.cmd(&command(b"USER", user.as_bytes())?).await?;
    match r.code {
        230 => {}
        331 => {
            let mut pass = Zeroizing::new(b"PASS ".to_vec());
            if secret.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
                return Err(Status::new(ErrorName::AuthFailed, "Unusable password"));
            }
            pass.extend_from_slice(secret);
            let r = session.cmd(&pass).await?;
            match r.code {
                230 | 202 => {}
                332 => return Err(Status::unsupported("The server asks for an account (ACCT)")),
                _ => return Err(reply::error(&r, "Signing in")),
            }
        }
        332 => return Err(Status::unsupported("The server asks for an account (ACCT)")),
        _ => return Err(reply::error(&r, "Signing in")),
    }
    session.expect(b"PBSZ 0", &[200], "Protecting data").await?;
    let prot = session.cmd(b"PROT P").await?;
    if prot.code != 200 {
        return Err(Status::new(ErrorName::SecurityPolicy, "The server does not protect file transfers")
            .with_detail(prot.text()));
    }
    session.expect(b"TYPE I", &[200], "Binary mode").await?;
    let feat = session.cmd(b"FEAT").await?;
    let features: Vec<Vec<u8>> = if feat.code == 211 {
        feat.lines.iter().map(|l| l.trim_ascii().to_ascii_uppercase()).collect()
    } else {
        Vec::new()
    };
    if !features.iter().any(|f| f.starts_with(b"MLST")) {
        return Err(Status::unsupported(
            "The server lists folders only in the old way; it needs MLSD (RFC 3659)",
        )
        .with_detail(feat.text()));
    }
    if features.iter().any(|f| f == b"UTF8") {
        // Most servers use UTF-8 anyway; some only after this.
        session.cmd(b"OPTS UTF8 ON").await?;
    }
    Ok(())
}

impl Backend for Ftps {
    type Read = NoHandle;
    type Write = NoHandle;

    async fn connect(
        &mut self,
        params: &Params,
        cancel: &CancelToken,
    ) -> Result<Option<ServerIdentity>, Status> {
        self.close().await;
        cancel.check()?;
        let settings = Settings::of(params)?;
        let tls = Tls::new(&settings.target.host, &[], &self.anchors)?;
        let session = cancel.guard(Session::open(tls, settings.target.clone())).await?;
        let identity = session.tls().settle(settings.pin.is_some());
        let mismatch = match (&settings.pin, session.tls().seen()) {
            (Some(pin), Some(seen)) => !netvfs_tls::pin_matches(pin, &seen.spki),
            (Some(_), None) => true,
            (None, _) => false,
        };
        self.state = State::Connected(Box::new(Connected { session, settings, mismatch }));
        Ok(identity)
    }

    async fn authenticate(
        &mut self,
        credentials: &Credentials,
        _prompter: Option<&mut dyn Prompter>,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let mut connected = match std::mem::take(&mut self.state) {
            State::Connected(c) => c,
            other => {
                self.state = other;
                return Err(Status::internal("authenticate() needs a fresh connection"));
            }
        };
        if connected.mismatch {
            // No credentials go to a server whose key is not the pin.
            self.state = State::Connected(connected);
            return Err(Status::new(
                ErrorName::ServerIdentityChanged,
                "The server certificate does not match the saved one; not signing in",
            ));
        }
        let user = if credentials.user.is_empty() {
            connected.settings.username.clone()
        } else {
            credentials.user.clone()
        };
        cancel.guard(sign_in(&mut connected.session, &user, &credentials.secret)).await?;
        self.state = State::Ready(Box::new(Ftp { session: connected.session }));
        Ok(())
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }

    async fn disconnect(&mut self) {
        self.close().await;
    }

    async fn keep_alive(&mut self, cancel: &CancelToken) -> Result<(), Status> {
        let ftp = self.ftp(cancel)?;
        cancel.guard(ftp.session.expect(b"NOOP", &[200], "Keeping the connection")).await.map(drop)
    }

    async fn stat(&mut self, path: &[u8], _follow: bool, cancel: &CancelToken) -> Result<Entry, Status> {
        let ftp = self.ftp(cancel)?;
        cancel.guard(ftp.stat(path)).await
    }

    async fn list(
        &mut self,
        dir: &[u8],
        options: ListOptions,
        sink: &mut dyn ListSink,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let ftp = self.ftp(cancel)?;
        let entries = cancel.guard(ftp.entries(dir)).await?;
        for batch in entries.chunks(options.batch_size.max(1)) {
            cancel.check()?;
            if !sink.entries(batch) {
                return Err(Status::canceled());
            }
        }
        Ok(())
    }

    async fn make_dir(&mut self, path: &[u8], exclusive: bool, cancel: &CancelToken) -> Result<(), Status> {
        let ftp = self.ftp(cancel)?;
        cancel.guard(ftp.make_dir(path, exclusive)).await
    }

    async fn remove_file(&mut self, path: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        let ftp = self.ftp(cancel)?;
        cancel.guard(ftp.remove_file(path)).await
    }

    async fn remove_dir(&mut self, path: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        let ftp = self.ftp(cancel)?;
        cancel.guard(ftp.remove_dir(path)).await
    }

    async fn rename(
        &mut self,
        from: &[u8],
        to: &[u8],
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let ftp = self.ftp(cancel)?;
        cancel.guard(ftp.rename(from, to, mode)).await
    }

    async fn upload(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        source: &mut dyn Source,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let ftp = self.ftp(cancel)?;
        ftp.upload(path, options, source, progress, cancel).await
    }

    async fn download(
        &mut self,
        path: &[u8],
        offset: u64,
        length: Option<u64>,
        sink: &mut dyn Sink,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let ftp = self.ftp(cancel)?;
        ftp.download(path, offset, length, sink, progress, cancel).await
    }
}

#[cfg(test)]
mod tests;
