// SPDX-License-Identifier: LGPL-2.1-or-later
//! The SFTP [`Backend`] (provider `sftp`): [`crate::session`] connects, [`crate::auth`] signs in, then [`Remote`] does
//! file operations and [`crate::io`] transfers and handles.
//!
//! A sign-in owns the session while it runs: if its future is dropped part way, the session goes with it and the
//! connection is left signed out, never half signed in with russh's replies out of step.

use crate::auth::{Login, Mode};
use crate::client::Client;
use crate::errors::{connection_closed, connection_lost};
use crate::io::{Download, SftpRead, SftpWrite, Upload, open_for_read, open_for_write};
use crate::remote::{DEFAULT_DIR_MODE, MODE_BITS, Remote};
use crate::session::{self, DEFAULT_PORT, Session, Target, sftp_not_enabled};
use data_encoding::BASE64;
use netvfs_vfs::{
    Attributes, Backend, CancelToken, Capabilities, Credentials, Entry, ErrorName, ListOptions, ListSink,
    Params, Progress, Prompter, RenameMode, ServerIdentity, Sink, Source, SpaceInfo, Status, WriteOptions,
};
use std::time::Duration;

/// Connect timeout when the caller gives none.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Request timeout when the caller gives none.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_mins(1);

/// What `connect` takes from the parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Where to connect.
    pub target: Target,
    /// Each SFTP request's bound.
    pub request_timeout: Duration,
    /// The user name when the credentials name none.
    pub username: String,
    /// `auth_mode`, checked when signing in.
    pub auth_mode: Option<String>,
    /// `dir_mode` (octal), for new folders.
    pub dir_mode: u32,
    /// `host_key`: the pinned key, `<algorithm> <base64>`.
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
    /// `Internal` for an empty host or one holding `@`, or a port out of range.
    pub fn of(params: &Params) -> Result<Self, Status> {
        if params.host.is_empty() || params.host.contains('@') {
            return Err(Status::internal("Invalid server name"));
        }
        let port = if params.port <= 0 {
            DEFAULT_PORT
        } else {
            u16::try_from(params.port)
                .map_err(|_e| Status::internal(format!("Invalid port {}", params.port)))?
        };
        let pin = params.option("host_key").filter(|p| !p.is_empty());
        let pinned_type = pin.as_deref().and_then(parse_pin).map(|(algorithm, _)| algorithm);
        let dir_mode = params
            .option("dir_mode")
            .and_then(|m| u32::from_str_radix(&m, 8).ok())
            .filter(|m| *m <= MODE_BITS)
            .unwrap_or(DEFAULT_DIR_MODE);
        Ok(Self {
            target: Target {
                host: params.host.clone(),
                port,
                connect_timeout: timeout_or(params.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT),
                pinned_type,
            },
            request_timeout: timeout_or(params.request_timeout_ms, DEFAULT_REQUEST_TIMEOUT),
            username: params.username.clone(),
            auth_mode: params.option("auth_mode"),
            dir_mode,
            pin,
        })
    }

    /// Whether `identity` differs from the pin; a pin that cannot be read matches nothing.
    #[must_use]
    pub fn mismatch(&self, identity: &ServerIdentity) -> bool {
        self.pin.as_deref().is_some_and(|pin| {
            parse_pin(pin).is_none_or(|(algorithm, blob)| {
                algorithm != identity.algorithm || blob != identity.public_key
            })
        })
    }
}

/// A pin, `<algorithm> <base64 blob>`, read as strictly as the C++ `ServerIdentity::fromPin`: two fields, canonical
/// base64, non-empty blob.
#[must_use]
pub fn parse_pin(pin: &str) -> Option<(String, Vec<u8>)> {
    let fields: Vec<&str> = pin.trim().split(' ').filter(|f| !f.is_empty()).collect();
    let [algorithm, blob] = fields.as_slice() else {
        return None;
    };
    let blob = BASE64.decode(blob.as_bytes()).ok().filter(|b| !b.is_empty())?;
    Some(((*algorithm).to_owned(), blob))
}

/// Connected, not signed in.
#[derive(Debug)]
struct Connected {
    session: Session,
    settings: Settings,
    mismatch: bool,
}

/// Signed in, SFTP running.
#[derive(Debug)]
struct Ready {
    session: Session,
    remote: Remote,
    settings: Settings,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Idle,
    Connected(Box<Connected>),
    Ready(Box<Ready>),
}

/// One SFTP connection.
#[derive(Debug, Default)]
pub struct Sftp {
    state: State,
}

/// `Internal` for a file operation before sign-in.
fn not_signed_in() -> Status {
    Status::internal("Not signed in")
}

/// The user to sign in as: the credentials', the account's, else the local user's (as ssh does).
fn user_name(credentials: &Credentials, settings: &Settings) -> String {
    if !credentials.user.is_empty() {
        return credentials.user.clone();
    }
    if !settings.username.is_empty() {
        return settings.username.clone();
    }
    std::env::var("USER").or_else(|_e| std::env::var("LOGNAME")).unwrap_or_default()
}

/// Signs in, starts SFTP and learns what the server offers.
async fn sign_in(
    session: &mut Session,
    settings: &Settings,
    mode: Mode,
    credentials: &Credentials,
    prompter: Option<&mut dyn Prompter>,
    cancel: &CancelToken,
) -> Result<Remote, Status> {
    let user = user_name(credentials, settings);
    let timeout = settings.target.connect_timeout;
    Login::new(session, &user, &credentials.secret, prompter, mode, timeout, cancel).run().await?;
    let (reader, channel) = session.open_sftp(timeout, cancel).await?;
    let writer = channel.make_writer();
    // Runs when the client ends: the channel is always closed.
    let on_end = async move { drop(channel.close().await) };
    let (client, version) =
        Client::start(reader, writer, on_end, settings.request_timeout, cancel).await.map_err(|e| {
            // Subsystem ended before answering: SFTP is not set up for this account (a forced command, say).
            if e.name == ErrorName::ConnectionLost { sftp_not_enabled() } else { e }
        })?;
    Remote::new(client, &version, settings.dir_mode, cancel).await
}

impl Sftp {
    /// A backend that is not connected.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Closes whatever is open.
    async fn close(&mut self) {
        match std::mem::take(&mut self.state) {
            State::Idle => {}
            State::Connected(c) => c.session.close().await,
            State::Ready(r) => {
                r.remote.client().end(connection_closed());
                r.session.close().await;
            }
        }
    }

    fn ready(&mut self, cancel: &CancelToken) -> Result<&mut Ready, Status> {
        let State::Ready(ready) = &mut self.state else {
            return Err(not_signed_in());
        };
        cancel.check()?;
        Ok(ready)
    }

    fn remote(&mut self, cancel: &CancelToken) -> Result<&mut Remote, Status> {
        Ok(&mut self.ready(cancel)?.remote)
    }
}

impl Backend for Sftp {
    type Read = SftpRead;
    type Write = SftpWrite;

    async fn connect(
        &mut self,
        params: &Params,
        cancel: &CancelToken,
    ) -> Result<Option<ServerIdentity>, Status> {
        self.close().await;
        cancel.check()?;
        let settings = Settings::of(params)?;
        let session = session::connect(&settings.target, cancel).await?;
        if cancel.is_canceled() {
            session.close().await;
            return Err(Status::canceled());
        }
        let identity = session.identity().clone();
        let mismatch = settings.mismatch(&identity);
        self.state = State::Connected(Box::new(Connected { session, settings, mismatch }));
        Ok(Some(identity))
    }

    async fn authenticate(
        &mut self,
        credentials: &Credentials,
        prompter: Option<&mut dyn Prompter>,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let connected = match std::mem::take(&mut self.state) {
            State::Connected(c) => c,
            other => {
                self.state = other;
                return Err(Status::internal("authenticate() needs a fresh connection"));
            }
        };
        let checked = if connected.mismatch {
            // No credentials go to a server whose key is not the pin.
            Err(Status::new(
                ErrorName::ServerIdentityChanged,
                "The server key does not match the saved key; not signing in",
            ))
        } else {
            cancel.check().and_then(|()| Mode::parse(connected.settings.auth_mode.as_deref())).and_then(
                |mode| {
                    mode.check_secret(&credentials.secret)?;
                    Ok(mode)
                },
            )
        };
        let mode = match checked {
            Ok(mode) => mode,
            Err(e) => {
                self.state = State::Connected(connected);
                return Err(e);
            }
        };
        let Connected { mut session, settings, .. } = *connected;
        match sign_in(&mut session, &settings, mode, credentials, prompter, cancel).await {
            // A cancel that comes after the last step finds the next call.
            Ok(remote) => {
                self.state = State::Ready(Box::new(Ready { session, remote, settings }));
                Ok(())
            }
            Err(e) => {
                session.close().await;
                Err(e)
            }
        }
    }

    fn capabilities(&self) -> Capabilities {
        match &self.state {
            State::Ready(r) => r.remote.capabilities(),
            State::Idle | State::Connected(_) => Capabilities::default(),
        }
    }

    async fn disconnect(&mut self) {
        self.close().await;
    }

    async fn keep_alive(&mut self, cancel: &CancelToken) -> Result<(), Status> {
        let ready = self.ready(cancel)?;
        let client = ready.remote.client();
        if client.is_ended() {
            return Err(connection_lost().with_detail(client.end_reason().message));
        }
        ready.session.keep_alive(ready.settings.request_timeout, cancel).await
    }

    async fn stat(&mut self, path: &[u8], follow: bool, cancel: &CancelToken) -> Result<Entry, Status> {
        self.remote(cancel)?.stat(path, follow, cancel).await
    }

    async fn list(
        &mut self,
        dir: &[u8],
        options: ListOptions,
        sink: &mut dyn ListSink,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        self.remote(cancel)?.list(dir, options, sink, cancel).await
    }

    async fn make_dir(&mut self, path: &[u8], exclusive: bool, cancel: &CancelToken) -> Result<(), Status> {
        self.remote(cancel)?.make_dir(path, exclusive, cancel).await
    }

    async fn remove_file(&mut self, path: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        self.remote(cancel)?.remove_file(path, cancel).await
    }

    async fn remove_dir(&mut self, path: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        self.remote(cancel)?.remove_dir(path, cancel).await
    }

    async fn rename(
        &mut self,
        from: &[u8],
        to: &[u8],
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        self.remote(cancel)?.rename(from, to, mode, cancel).await
    }

    async fn set_attributes(
        &mut self,
        path: &[u8],
        changes: &Attributes,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        self.remote(cancel)?.set_attributes(path, changes, cancel).await
    }

    async fn read_link(&mut self, path: &[u8], cancel: &CancelToken) -> Result<Vec<u8>, Status> {
        self.remote(cancel)?.read_link(path, cancel).await
    }

    async fn make_symlink(&mut self, target: &[u8], link: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        self.remote(cancel)?.make_symlink(target, link, cancel).await
    }

    async fn make_hardlink(
        &mut self,
        existing: &[u8],
        link: &[u8],
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        self.remote(cancel)?.make_hardlink(existing, link, cancel).await
    }

    async fn copy(
        &mut self,
        from: &[u8],
        to: &[u8],
        recursive: bool,
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        self.remote(cancel)?.copy(from, to, recursive, mode, cancel).await
    }

    async fn space_info(&mut self, dir: &[u8], cancel: &CancelToken) -> Result<SpaceInfo, Status> {
        self.remote(cancel)?.space_info(dir, cancel).await
    }

    async fn open_read(&mut self, path: &[u8], cancel: &CancelToken) -> Result<SftpRead, Status> {
        let remote = self.remote(cancel)?;
        let target = remote.resolve(path)?;
        let client = remote.client();
        let (handle, size) = open_for_read(client, &target, cancel).await?;
        Ok(SftpRead::new(client.clone(), handle, target, size, remote.chunks().read))
    }

    async fn open_write(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        cancel: &CancelToken,
    ) -> Result<SftpWrite, Status> {
        let remote = self.remote(cancel)?;
        let target = remote.resolve(path)?;
        let client = remote.client();
        let handle = open_for_write(client, &target, options, cancel).await?;
        Ok(SftpWrite::new(
            client.clone(),
            *remote.extensions(),
            handle,
            target,
            options,
            remote.chunks().write,
        ))
    }

    async fn upload(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        source: &mut dyn Source,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let remote = self.remote(cancel)?;
        let target = remote.resolve(path)?;
        let upload =
            Upload { client: remote.client(), ext: remote.extensions(), chunk: remote.chunks().write };
        upload.run(&target, options, source, progress, cancel).await
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
        let remote = self.remote(cancel)?;
        let target = remote.resolve(path)?;
        let download = Download { client: remote.client(), chunk: remote.chunks().read };
        download.run(&target, offset, length, sink, progress, cancel).await
    }
}

#[cfg(test)]
mod tests;
