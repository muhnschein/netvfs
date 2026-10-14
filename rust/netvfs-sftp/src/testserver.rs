// SPDX-License-Identifier: LGPL-2.1-or-later
//! An SSH server in the test process, for the session, sign-in and
//! backend tests: russh's server with a scripted sign-in, the `sftp`
//! subsystem served by [`Fake`], and a [`Proxy`] in front of it that can
//! stall or cut the connection.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    clippy::redundant_closure_call,
    reason = "test server: a script it cannot follow is a bug in the test; handler bodies run in place \
              (a closure for `?` and `return`) and are returned as ready futures"
)]

use crate::fake::Fake;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Response, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, SshId};
use std::borrow::Cow;
use std::collections::HashMap;
use std::future::{Future, ready};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One keyboard-interactive round: what the server asks and the answers
/// it wants.
#[derive(Debug, Clone)]
pub struct Round {
    pub name: &'static str,
    pub instruction: &'static str,
    pub prompts: Vec<(&'static str, bool)>,
    pub answers: Vec<&'static str>,
}

impl Round {
    /// One non-echo prompt.
    pub fn one(prompt: &'static str, answer: &'static str) -> Self {
        Self { name: "", instruction: "", prompts: vec![(prompt, false)], answers: vec![answer] }
    }

    /// No prompt at all (OpenSSH after PAM).
    pub fn empty() -> Self {
        Self { name: "", instruction: "", prompts: Vec::new(), answers: Vec::new() }
    }
}

/// A method that must succeed.
#[derive(Debug, Clone)]
pub enum Step {
    Password(&'static str),
    Key(PublicKey),
    Interactive(Vec<Round>),
}

impl Step {
    fn kind(&self) -> MethodKind {
        match self {
            Self::Password(_) => MethodKind::Password,
            Self::Key(_) => MethodKind::PublicKey,
            Self::Interactive(_) => MethodKind::KeyboardInteractive,
        }
    }
}

/// What a session channel's `sftp` request gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subsystem {
    /// Success, then the fake SFTP server.
    Sftp,
    /// Failure.
    Refuse,
    /// Success, then EOF and close (a forced command that exits).
    Exit,
    /// Success, then data "ab", stderr "err", data "cd", EOF, close.
    Raw,
}

/// How the server behaves.
#[derive(Debug, Clone)]
pub struct Script {
    /// Named after `none` and after a failure of the first step.
    pub offered: Vec<MethodKind>,
    /// The methods that must succeed, in order; each but the last is a
    /// partial success that names the next one.
    pub chain: Vec<Step>,
    /// `none` succeeds.
    pub open: bool,
    pub subsystem: Subsystem,
    /// Session channels are refused with this.
    pub refuse_session: Option<ChannelOpenFailure>,
    /// After this many failed attempts the server disconnects.
    pub max_failures: Option<usize>,
    /// Once signed in, the server tries to open a channel of every kind
    /// to the client and logs `probe <kind> refused|accepted`.
    pub probe_channels: bool,
}

impl Script {
    /// Password `secret` for anyone.
    pub fn password() -> Self {
        Self {
            offered: vec![MethodKind::PublicKey, MethodKind::Password],
            chain: vec![Step::Password("secret")],
            open: false,
            subsystem: Subsystem::Sftp,
            refuse_session: None,
            max_failures: None,
            probe_channels: false,
        }
    }
}

/// The server's log and SFTP tree.
#[derive(Debug, Clone)]
pub struct Server {
    pub addr: SocketAddr,
    pub fake: Fake,
    log: Arc<Mutex<Vec<String>>>,
    script: Arc<Mutex<Script>>,
    pub keys: Vec<PublicKey>,
}

/// A host key from the fixtures.
pub fn host_key(file: &str) -> PrivateKey {
    let path = format!("{}/testdata/keys/{file}", env!("CARGO_MANIFEST_DIR"));
    PrivateKey::from_openssh(std::fs::read_to_string(path).unwrap()).unwrap()
}

impl Server {
    /// A server with an Ed25519 host key and `script`, banner OpenSSH's.
    pub async fn start(script: Script) -> Self {
        Self::with_keys(script, vec![host_key("ed25519-openssh")], "SSH-2.0-OpenSSH_9.6").await
    }

    /// A server with `keys` (in the server's order) and `banner`.
    pub async fn with_keys(script: Script, keys: Vec<PrivateKey>, banner: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let public = keys.iter().map(|k| k.public_key().clone()).collect();
        let config = Arc::new(server::Config {
            server_id: SshId::Standard(Cow::Borrowed(banner)),
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys,
            inactivity_timeout: None,
            ..server::Config::default()
        });
        let server = Self {
            addr,
            fake: Fake::new(),
            log: Arc::default(),
            script: Arc::new(Mutex::new(script)),
            keys: public,
        };
        let shared = server.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let handler = Handler {
                    server: shared.clone(),
                    stage: 0,
                    round: 0,
                    failures: 0,
                    channels: HashMap::new(),
                };
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(config, socket, handler).await {
                        drop(session.await);
                    }
                });
            }
        });
        server
    }

    /// What the server saw, then cleared.
    pub fn take_log(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }

    /// Changes the script.
    pub fn script(&self) -> MutexGuard<'_, Script> {
        self.script.lock().unwrap()
    }

    fn note(&self, line: String) {
        self.log.lock().unwrap().push(line);
    }
}

struct Handler {
    server: Server,
    stage: usize,
    round: usize,
    failures: usize,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

fn methods(kinds: &[MethodKind]) -> MethodSet {
    MethodSet::from(kinds)
}

fn partial(round: &Round) -> Auth {
    Auth::Partial {
        name: Cow::Borrowed(round.name),
        instructions: Cow::Borrowed(round.instruction),
        prompts: Cow::Owned(round.prompts.iter().map(|(p, e)| (Cow::Borrowed(*p), *e)).collect()),
    }
}

impl Handler {
    fn script(&self) -> Script {
        self.server.script().clone()
    }

    fn step(&self) -> Option<Step> {
        self.script().chain.get(self.stage).cloned()
    }

    /// What a failure names.
    fn offered(&self) -> MethodSet {
        let script = self.script();
        if self.stage == 0 {
            return methods(&script.offered);
        }
        script.chain.get(self.stage).map_or_else(MethodSet::empty, |s| methods(&[s.kind()]))
    }

    fn reject(&mut self) -> Result<Auth, russh::Error> {
        self.failures += 1;
        if self.script().max_failures.is_some_and(|max| self.failures >= max) {
            // As OpenSSH after MaxAuthTries.
            return Err(russh::Error::Disconnect);
        }
        Ok(Auth::Reject { proceed_with_methods: Some(self.offered()), partial_success: false })
    }

    fn advance(&mut self) -> Auth {
        self.stage += 1;
        self.round = 0;
        match self.step() {
            None => Auth::Accept,
            Some(next) => {
                Auth::Reject { proceed_with_methods: Some(methods(&[next.kind()])), partial_success: true }
            }
        }
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    fn auth_none(&mut self, user: &str) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        ready((|| {
            self.server.note(format!("none {user}"));
            if self.script().open {
                return Ok(Auth::Accept);
            }
            Ok(Auth::Reject { proceed_with_methods: Some(self.offered()), partial_success: false })
        })())
    }

    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        ready((|| {
            self.server.note(format!("password {user} {password}"));
            match self.step() {
                Some(Step::Password(p)) if p == password => Ok(self.advance()),
                _ => self.reject(),
            }
        })())
    }

    fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        ready((|| {
            self.server.note(format!("offered {user} {}", key.algorithm()));
            match self.step() {
                Some(Step::Key(k)) if k.key_data() == key.key_data() => Ok(Auth::Accept),
                _ => self.reject(),
            }
        })())
    }

    fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        ready((|| {
            self.server.note(format!("publickey {user} {}", key.algorithm()));
            match self.step() {
                Some(Step::Key(k)) if k.key_data() == key.key_data() => Ok(self.advance()),
                _ => self.reject(),
            }
        })())
    }

    fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _: &str,
        response: Option<Response<'a>>,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        ready((|| {
            let Some(Step::Interactive(rounds)) = self.step() else {
                self.server.note(format!("kbd {user}"));
                return self.reject();
            };
            let Some(response) = response else {
                self.server.note(format!("kbd {user}"));
                self.round = 0;
                return Ok(match rounds.first() {
                    Some(first) => partial(first),
                    None => self.advance(),
                });
            };
            let answers: Vec<String> = response.map(|a| String::from_utf8_lossy(&a).into_owned()).collect();
            self.server.note(format!("answers {}", answers.join(",")));
            if answers != rounds[self.round].answers {
                self.round = 0;
                return self.reject();
            }
            self.round += 1;
            Ok(match rounds.get(self.round) {
                Some(next) => partial(next),
                None => self.advance(),
            })
        })())
    }

    fn auth_succeeded(
        &mut self,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        if !self.script().probe_channels {
            return ready(Ok(()));
        }
        let handle = session.handle();
        let server = self.server.clone();
        tokio::spawn(async move {
            let outcome = |kind: &str, r: Result<Channel<Msg>, russh::Error>| {
                server.note(format!("probe {kind} {}", if r.is_ok() { "accepted" } else { "refused" }));
            };
            outcome("session", handle.channel_open_session().await);
            outcome("agent", handle.channel_open_agent().await);
            outcome("x11", handle.channel_open_x11("10.0.0.1", 6000).await);
            outcome(
                "forwarded-tcpip",
                handle.channel_open_forwarded_tcpip("10.0.0.1", 80, "10.0.0.2", 1234).await,
            );
            outcome("direct-tcpip", handle.channel_open_direct_tcpip("10.0.0.1", 80, "10.0.0.2", 1234).await);
            outcome("forwarded-streamlocal", handle.channel_open_forwarded_streamlocal("/s").await);
            outcome("direct-streamlocal", handle.channel_open_direct_streamlocal("/s").await);
            server.note("probe done".to_owned());
        });
        ready(Ok(()))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server.note("session".to_owned());
        if let Some(reason) = self.script().refuse_session {
            reply.reject(reason).await;
            return Ok(());
        }
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready((|| {
            self.server.note(format!("subsystem {name}"));
            let channel = self.channels.remove(&id);
            match (self.script().subsystem, channel) {
                (Subsystem::Sftp, Some(channel)) if name == "sftp" => {
                    session.channel_success(id)?;
                    self.server.fake.serve_stream(channel.into_stream());
                }
                (Subsystem::Exit, Some(_)) => {
                    session.channel_success(id)?;
                    session.eof(id)?;
                    session.close(id)?;
                }
                (Subsystem::Raw, Some(_)) => {
                    session.channel_success(id)?;
                    session.data(id, &b"ab"[..])?;
                    session.extended_data(id, 1, &b"err"[..])?;
                    session.data(id, &b"cd"[..])?;
                    session.eof(id)?;
                    session.close(id)?;
                }
                _ => session.channel_failure(id)?,
            }
            Ok(())
        })())
    }
}

/// A TCP relay in front of a server: it can hold everything back
/// (stall) or close both sides (cut), and counts the client connections
/// still open.
#[derive(Debug, Clone)]
pub struct Proxy {
    pub addr: SocketAddr,
    stalled: Arc<AtomicBool>,
    cut: Arc<AtomicBool>,
    open: Arc<AtomicUsize>,
    accepted: Arc<AtomicUsize>,
}

impl Proxy {
    /// A relay to `upstream`.
    pub async fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Self {
            addr: listener.local_addr().unwrap(),
            stalled: Arc::default(),
            cut: Arc::default(),
            open: Arc::default(),
            accepted: Arc::default(),
        };
        let shared = proxy.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                shared.accepted.fetch_add(1, Ordering::SeqCst);
                shared.open.fetch_add(1, Ordering::SeqCst);
                let server = TcpStream::connect(upstream).await.unwrap();
                let (client_read, client_write) = client.into_split();
                let (server_read, server_write) = server.into_split();
                let up = tokio::spawn(relay(client_read, server_write, shared.clone()));
                tokio::spawn(relay(server_read, client_write, shared.clone()));
                let open = Arc::clone(&shared.open);
                tokio::spawn(async move {
                    drop(up.await);
                    open.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        proxy
    }

    /// Holds back everything from now on.
    pub fn stall(&self, on: bool) {
        self.stalled.store(on, Ordering::SeqCst);
    }

    /// Closes every connection (and refuses to relay any more).
    pub fn cut(&self) {
        self.cut.store(true, Ordering::SeqCst);
    }

    /// Client connections whose client has not closed its side.
    pub fn open_connections(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }

    /// Client connections made so far.
    pub fn connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Waits until no client connection is open (up to 5 s).
    pub async fn all_closed(&self) -> bool {
        for _ in 0..500 {
            if self.open_connections() == 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }
}

/// Copies `from` to `to`; holds data while stalled; stops when either
/// side closes or the proxy is cut. Returns when `from` is closed.
async fn relay(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    proxy: Proxy,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let forward = {
        let proxy = proxy.clone();
        tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                while proxy.stalled.load(Ordering::SeqCst) && !proxy.cut.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                if proxy.cut.load(Ordering::SeqCst) || to.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            drop(to.shutdown().await);
        })
    };
    let mut buf = vec![0; 64 * 1024];
    loop {
        let read = tokio::select! {
            r = from.read(&mut buf) => r,
            () = async {
                while !proxy.cut.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            } => break,
        };
        match read {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        }
    }
    drop(tx);
    if proxy.cut.load(Ordering::SeqCst) {
        forward.abort();
    }
}
