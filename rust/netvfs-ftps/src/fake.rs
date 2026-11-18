// SPDX-License-Identifier: LGPL-2.1-or-later
//! An FTPS server in memory (explicit TLS 1.3, `EPSV`, `MLSD`/`MLST`), for tests: enough of RFC 959, 3659 and
//! 4217 for the backend, plus knobs for odd servers.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    clippy::missing_panics_doc,
    reason = "tests"
)]

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{HandshakeKind, ServerConfig};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

pub const CA: &[u8] = include_bytes!("../../netvfs-tls/testdata/ca.der");
pub const LEAF: &[u8] = include_bytes!("../../netvfs-tls/testdata/leaf.der");
const LEAF_KEY: &[u8] = include_bytes!("../../netvfs-tls/testdata/leaf.key.der");
pub const SELF: &[u8] = include_bytes!("../../netvfs-tls/testdata/self.der");
const SELF_KEY: &[u8] = include_bytes!("../../netvfs-tls/testdata/self.key.der");

/// `modify` of every node.
pub const MODIFY: &str = "20261028000000";
pub const MTIME_MS: i64 = 1_793_145_600_000;
pub const USER: &str = "alice";
pub const PASSWORD: &str = "secret";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Dir,
    File(Vec<u8>),
}

#[derive(Debug)]
pub struct State {
    /// Absolute paths without trailing `/`; "/" is the root.
    pub tree: BTreeMap<Vec<u8>, Node>,
    /// Every command line, `PASS` masked.
    pub seen: Vec<Vec<u8>>,
    /// `FEAT` lines.
    pub features: Vec<&'static str>,
    /// Answer `AUTH TLS` with this code instead of 234.
    pub auth_code: u16,
    /// Answer `PROT P` with this code instead of 200.
    pub prot_code: u16,
    /// Data connections whose TLS session was not resumed are refused (as proftpd and vsftpd do).
    pub require_reuse: bool,
    /// Data connections that resumed the control session.
    pub resumed: usize,
    /// Control connections accepted.
    pub connections: usize,
    /// Answer this path's commands 550 (no permission).
    pub forbidden: Option<Vec<u8>>,
    /// Answer this verb on this path with this reply.
    pub refuse: Option<(&'static str, Vec<u8>, &'static str)>,
    /// Send `120` before the greeting.
    pub greeting_wait: bool,
    /// The whole `MLSD` payload instead of the tree's.
    pub listing: Option<Vec<u8>>,
    /// The reply ending a `RETR` instead of 226.
    pub retr_end: Option<&'static str>,
    /// One more reply after `ABOR`'s, as proftpd sends at times.
    pub abort_extra: Option<&'static str>,
    /// Extra raw `MLSD` lines.
    pub extra_lines: Vec<Vec<u8>>,
}

impl Default for State {
    fn default() -> Self {
        let mut tree = BTreeMap::new();
        tree.insert(b"/".to_vec(), Node::Dir);
        Self {
            tree,
            seen: Vec::new(),
            features: vec!["MLST type*;size*;modify*;UNIX.mode*;", "EPSV", "UTF8", "REST STREAM"],
            auth_code: 234,
            prot_code: 200,
            require_reuse: true,
            resumed: 0,
            connections: 0,
            forbidden: None,
            refuse: None,
            greeting_wait: false,
            listing: None,
            retr_end: None,
            abort_extra: None,
            extra_lines: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Cert {
    /// Signed by the test CA for localhost and 127.0.0.1.
    Trusted,
    /// Self-signed.
    SelfSigned,
}

fn config(cert: Cert) -> Arc<ServerConfig> {
    let (c, k) = match cert {
        Cert::Trusted => (LEAF, LEAF_KEY),
        Cert::SelfSigned => (SELF, SELF_KEY),
    };
    let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(c.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.to_vec())),
        )
        .unwrap();
    Arc::new(config)
}

#[derive(Debug, Clone)]
pub struct Fake {
    pub state: Arc<Mutex<State>>,
    pub addr: SocketAddr,
}

impl Fake {
    pub async fn start(cert: Cert) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let config = config(cert);
        // As proftpd: no session ticket on a connection the server never writes to.
        let mut quiet = (*config).clone();
        quiet.send_tls13_tickets = 0;
        let acceptor = TlsAcceptor::from(config);
        let uploads = TlsAcceptor::from(Arc::new(quiet));
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                shared.lock().unwrap().connections += 1;
                tokio::spawn(serve(tcp, acceptor.clone(), uploads.clone(), Arc::clone(&shared)));
            }
        });
        Self { state, addr }
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }

    pub fn put(&self, path: &str, node: Node) {
        self.with(|s| s.tree.insert(path.as_bytes().to_vec(), node));
    }

    pub fn get(&self, path: &str) -> Option<Node> {
        self.with(|s| s.tree.get(path.as_bytes()).cloned())
    }

    /// The verbs seen, in order.
    pub fn verbs(&self) -> Vec<String> {
        self.with(|s| {
            s.seen
                .iter()
                .map(|l| {
                    String::from_utf8_lossy(l.split(|b| *b == b' ').next().unwrap_or_default()).into_owned()
                })
                .collect()
        })
    }
}

async fn say(w: &mut (impl AsyncWrite + Unpin), text: &str) {
    w.write_all(format!("{text}\r\n").as_bytes()).await.ok();
    w.flush().await.ok();
}

fn parent(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|b| *b == b'/') {
        Some(0) | None => b"/".to_vec(),
        Some(at) => path[..at].to_vec(),
    }
}

fn norm(arg: &[u8]) -> Vec<u8> {
    let mut p = arg.to_vec();
    while p.len() > 1 && p.ends_with(b"/") {
        p.pop();
    }
    if p.is_empty() { b"/".to_vec() } else { p }
}

fn facts(node: &Node, cdir: bool) -> String {
    match node {
        Node::Dir => format!("type={};modify={MODIFY};UNIX.mode=0755;", if cdir { "cdir" } else { "dir" }),
        Node::File(d) => format!("type=file;size={};modify={MODIFY};UNIX.mode=0644;", d.len()),
    }
}

fn children(tree: &BTreeMap<Vec<u8>, Node>, dir: &[u8]) -> Vec<(Vec<u8>, Node)> {
    let prefix = if dir == b"/" { b"/".to_vec() } else { [dir, b"/"].concat() };
    tree.iter()
        .filter(|(p, _)| {
            p.starts_with(&prefix) && p.len() > prefix.len() && !p[prefix.len()..].contains(&b'/')
        })
        .map(|(p, n)| (p[prefix.len()..].to_vec(), n.clone()))
        .collect()
}

type Ctrl = BufReader<TlsStream<TcpStream>>;

async fn serve(tcp: TcpStream, acceptor: TlsAcceptor, uploads: TlsAcceptor, state: Arc<Mutex<State>>) {
    let Some(tcp) = plain(tcp, &state).await else { return };
    let Ok(tls) = acceptor.accept(tcp).await else { return };
    let mut conn = Conn {
        ctrl: BufReader::new(tls),
        acceptor,
        uploads,
        state,
        user: false,
        account: false,
        signed_in: false,
        listener: None,
        rest: 0,
        rename_from: None,
    };
    let mut line = Vec::new();
    loop {
        line.clear();
        if conn.ctrl.read_until(b'\n', &mut line).await.unwrap_or(0) == 0 || !conn.command(&line).await {
            return;
        }
    }
}

/// The plain part: greeting, then `AUTH TLS`.
async fn plain(tcp: TcpStream, state: &Mutex<State>) -> Option<TcpStream> {
    let mut plain = BufReader::new(tcp);
    let wait = state.lock().unwrap().greeting_wait;
    if wait {
        say(plain.get_mut(), "120 Ready soon").await;
    }
    say(plain.get_mut(), "220 fake FTPS").await;
    let mut line = Vec::new();
    loop {
        line.clear();
        if plain.read_until(b'\n', &mut line).await.unwrap_or(0) == 0 {
            return None;
        }
        let cmd = line.trim_ascii_end().to_vec();
        state.lock().unwrap().seen.push(cmd.clone());
        if !cmd.eq_ignore_ascii_case(b"AUTH TLS") {
            say(plain.get_mut(), "530 Use AUTH TLS first").await;
            continue;
        }
        let code = state.lock().unwrap().auth_code;
        if code == 234 {
            say(plain.get_mut(), "234 AUTH TLS ok").await;
            return Some(plain.into_inner());
        }
        say(plain.get_mut(), &format!("{code} no TLS here")).await;
    }
}

/// One protected control connection.
struct Conn {
    ctrl: Ctrl,
    acceptor: TlsAcceptor,
    uploads: TlsAcceptor,
    state: Arc<Mutex<State>>,
    user: bool,
    account: bool,
    signed_in: bool,
    listener: Option<TcpListener>,
    rest: usize,
    rename_from: Option<Vec<u8>>,
}

impl Conn {
    async fn say(&mut self, text: &str) {
        say(self.ctrl.get_mut(), text).await;
    }

    /// Answers `line`; false ends the session.
    async fn command(&mut self, line: &[u8]) -> bool {
        let raw = line.trim_ascii_end().to_vec();
        let (verb, arg) = match raw.iter().position(|b| *b == b' ') {
            Some(at) => (raw[..at].to_ascii_uppercase(), raw[at + 1..].to_vec()),
            None => (raw.to_ascii_uppercase(), Vec::new()),
        };
        self.state.lock().unwrap().seen.push(if verb == b"PASS" {
            b"PASS ***".to_vec()
        } else {
            raw.clone()
        });
        let path = norm(&arg);
        if let Some(reply) = self.refusal(&verb, &path) {
            self.say(&reply).await;
            return true;
        }
        match verb.as_slice() {
            b"USER" | b"PASS" => self.sign_in(&verb, &arg).await,
            b"MLSD" | b"RETR" | b"STOR" => return self.transfer(&verb, &path).await,
            b"MLST" | b"MKD" | b"DELE" | b"RMD" | b"RNFR" | b"RNTO" => self.tree(&verb, &path).await,
            b"QUIT" => {
                self.say("221 Bye").await;
                return false;
            }
            _ => self.setting(&verb, &arg).await,
        }
        true
    }

    /// The reply refusing `verb` on `path` before it runs, if any.
    fn refusal(&self, verb: &[u8], path: &[u8]) -> Option<String> {
        if !self.signed_in && !matches!(verb, b"USER" | b"PASS" | b"QUIT" | b"FEAT") {
            return Some("530 Please sign in".into());
        }
        let s = self.state.lock().unwrap();
        if s.forbidden.as_deref() == Some(path)
            && !matches!(verb, b"USER" | b"PASS" | b"EPSV" | b"REST" | b"TYPE" | b"PBSZ" | b"PROT")
        {
            return Some("550 Permission denied".into());
        }
        s.refuse
            .as_ref()
            .filter(|(v, p, _)| v.as_bytes() == verb && p == path)
            .map(|(_, _, r)| (*r).to_owned())
    }

    async fn sign_in(&mut self, verb: &[u8], arg: &[u8]) {
        match (verb, arg) {
            (b"USER", b"guest") => {
                self.signed_in = true;
                self.say("230 No password needed").await;
            }
            (b"USER", b"acct") => self.say("332 Need account").await,
            (b"USER", _) => {
                self.user = arg == USER.as_bytes() || arg == b"pacct";
                self.account = arg == b"pacct";
                self.say("331 Password please").await;
            }
            _ if self.account => self.say("332 Need account").await,
            _ if self.user && arg == PASSWORD.as_bytes() => {
                self.signed_in = true;
                self.say("230 Welcome").await;
            }
            _ => self.say("530 Login incorrect").await,
        }
    }

    async fn setting(&mut self, verb: &[u8], arg: &[u8]) {
        match verb {
            b"PBSZ" => self.say("200 PBSZ=0").await,
            b"PROT" => {
                let code = self.state.lock().unwrap().prot_code;
                self.say(&format!("{code} PROT")).await;
            }
            b"TYPE" | b"OPTS" => self.say("200 OK").await,
            b"NOOP" => self.say("200 NOOP").await,
            b"FEAT" => {
                let features = self.state.lock().unwrap().features.clone();
                let mut out = String::from("211-Features:\r\n");
                for f in features {
                    out.push(' ');
                    out.push_str(f);
                    out.push_str("\r\n");
                }
                out.push_str("211 End");
                self.say(&out).await;
            }
            b"EPSV" => {
                let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                let port = l.local_addr().unwrap().port();
                self.listener = Some(l);
                self.say(&format!("229 Entering Extended Passive Mode (|||{port}|)")).await;
            }
            b"REST" => {
                self.rest = std::str::from_utf8(arg).ok().and_then(|a| a.parse().ok()).unwrap_or(0);
                self.say("350 Restarting").await;
            }
            b"ABOR" => {
                self.say("226 Abort done").await;
                let extra = self.state.lock().unwrap().abort_extra;
                if let Some(extra) = extra {
                    self.say(extra).await;
                }
            }
            _ => self.say("502 Not implemented").await,
        }
    }

    async fn tree(&mut self, verb: &[u8], path: &[u8]) {
        let reply = {
            let mut s = self.state.lock().unwrap();
            match verb {
                b"MLST" => s.tree.get(path).map_or_else(
                    || "550 No such file".to_owned(),
                    |n| {
                        let name = String::from_utf8_lossy(path);
                        format!("250-Listing {name}\r\n {} {name}\r\n250 End", facts(n, false))
                    },
                ),
                b"MKD" => change(
                    !s.tree.contains_key(path) && s.tree.get(&parent(path)) == Some(&Node::Dir),
                    || s.tree.insert(path.to_vec(), Node::Dir),
                    "257 Created",
                    "550 Cannot create",
                ),
                b"DELE" => change(
                    matches!(s.tree.get(path), Some(Node::File(_))),
                    || s.tree.remove(path),
                    "250 Deleted",
                    "550 Cannot delete",
                ),
                b"RMD" => change(
                    s.tree.get(path) == Some(&Node::Dir) && children(&s.tree, path).is_empty(),
                    || s.tree.remove(path),
                    "250 Removed",
                    "550 Cannot remove",
                ),
                b"RNFR" => {
                    let exists = s.tree.contains_key(path);
                    self.rename_from = exists.then(|| path.to_vec());
                    (if exists { "350 Ready" } else { "550 No such file" }).to_owned()
                }
                _ => match self.rename_from.take() {
                    None => "503 RNFR first".to_owned(),
                    Some(from) => rename(&mut s.tree, &from, path),
                },
            }
        };
        self.say(&reply).await;
    }

    /// What `verb` sends or accepts on `path`, if it can run.
    fn payload(&mut self, verb: &[u8], path: &[u8]) -> Option<Vec<u8>> {
        let rest = std::mem::take(&mut self.rest);
        let s = self.state.lock().unwrap();
        match (verb, s.tree.get(path)) {
            (b"MLSD", Some(Node::Dir)) if s.listing.is_some() => s.listing.clone(),
            (b"MLSD", Some(Node::Dir)) => {
                let mut out =
                    format!("{} {}\r\n", facts(&Node::Dir, true), String::from_utf8_lossy(path)).into_bytes();
                out.extend_from_slice(b"type=pdir; ..\r\n");
                for (name, n) in children(&s.tree, path) {
                    out.extend_from_slice(facts(&n, false).as_bytes());
                    out.push(b' ');
                    out.extend_from_slice(&name);
                    out.extend_from_slice(b"\r\n");
                }
                for extra in &s.extra_lines {
                    out.extend_from_slice(extra);
                    out.extend_from_slice(b"\r\n");
                }
                Some(out)
            }
            (b"RETR", Some(Node::File(d))) => Some(d.get(rest.min(d.len())..).unwrap_or_default().to_vec()),
            (b"STOR", None | Some(Node::File(_))) if s.tree.get(&parent(path)) == Some(&Node::Dir) => {
                Some(Vec::new())
            }
            _ => None,
        }
    }

    /// `MLSD`, `RETR`, `STOR`; false ends the session.
    async fn transfer(&mut self, verb: &[u8], path: &[u8]) -> bool {
        let Some(l) = self.listener.take() else {
            self.say("425 Use EPSV first").await;
            return true;
        };
        let Some(payload) = self.payload(verb, path) else {
            self.say("550 No such file or folder").await;
            return true;
        };
        self.say("150 Opening data connection").await;
        let Ok((tcp, _)) = l.accept().await else { return false };
        let acceptor = if verb == b"STOR" { &self.uploads } else { &self.acceptor };
        let Ok(mut data) = acceptor.accept(tcp).await else {
            self.say("425 TLS failed").await;
            return true;
        };
        let resumed = data.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed);
        let require = {
            let mut s = self.state.lock().unwrap();
            s.resumed += usize::from(resumed);
            s.require_reuse
        };
        if require && !resumed {
            drop(data);
            self.say("425 TLS session of data connection not resumed").await;
            return true;
        }
        if verb == b"STOR" {
            let mut got = Vec::new();
            let whole = data.read_to_end(&mut got).await.is_ok() && data.shutdown().await.is_ok();
            self.state.lock().unwrap().tree.insert(path.to_vec(), Node::File(got));
            self.say(if whole { "226 Stored" } else { "426 Transfer aborted" }).await;
            return true;
        }
        let mut left = Vec::new();
        let sent = data.write_all(&payload).await.and(data.shutdown().await);
        if sent.and(data.read_to_end(&mut left).await).is_err() {
            // As proftpd: a data connection reset or closed without TLS close ends the session.
            return false;
        }
        let end = self.state.lock().unwrap().retr_end.filter(|_| verb == b"RETR");
        self.say(end.unwrap_or("226 Done")).await;
        true
    }
}

/// `ok` → runs `apply`, `yes`; else `no`.
fn change<T>(ok: bool, apply: impl FnOnce() -> T, yes: &str, no: &str) -> String {
    if ok {
        drop(apply());
        yes.to_owned()
    } else {
        no.to_owned()
    }
}

/// Moves `from` and all below it to `to`, if `to`'s folder exists.
fn rename(tree: &mut BTreeMap<Vec<u8>, Node>, from: &[u8], to: &[u8]) -> String {
    if tree.get(&parent(to)) != Some(&Node::Dir) {
        return "550 Cannot rename".to_owned();
    }
    let below = [from, b"/"].concat();
    let moved: Vec<(Vec<u8>, Node)> = tree
        .iter()
        .filter(|(p, _)| p.as_slice() == from || p.starts_with(&below))
        .map(|(p, n)| (p.clone(), n.clone()))
        .collect();
    for (p, n) in moved {
        tree.remove(&p);
        tree.insert([to, &p[from.len()..]].concat(), n);
    }
    "250 Renamed".to_owned()
}
