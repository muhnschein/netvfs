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
        let acceptor = TlsAcceptor::from(config(cert));
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                shared.lock().unwrap().connections += 1;
                tokio::spawn(serve(tcp, acceptor.clone(), Arc::clone(&shared)));
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

async fn serve(tcp: TcpStream, acceptor: TlsAcceptor, state: Arc<Mutex<State>>) {
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
            return;
        }
        let cmd = line.trim_ascii_end().to_vec();
        state.lock().unwrap().seen.push(cmd.clone());
        if cmd.eq_ignore_ascii_case(b"AUTH TLS") {
            let code = state.lock().unwrap().auth_code;
            if code == 234 {
                say(plain.get_mut(), "234 AUTH TLS ok").await;
                break;
            }
            say(plain.get_mut(), &format!("{code} no TLS here")).await;
        } else {
            say(plain.get_mut(), "530 Use AUTH TLS first").await;
        }
    }
    let Ok(tls) = acceptor.accept(plain.into_inner()).await else { return };
    let mut ctrl: Ctrl = BufReader::new(tls);
    let mut user = false;
    let mut account = false;
    let mut signed_in = false;
    let mut listener: Option<TcpListener> = None;
    let mut rest = 0usize;
    let mut rename_from: Option<Vec<u8>> = None;
    loop {
        line.clear();
        if ctrl.read_until(b'\n', &mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let raw = line.trim_ascii_end().to_vec();
        let (verb, arg) = match raw.iter().position(|b| *b == b' ') {
            Some(at) => (raw[..at].to_ascii_uppercase(), raw[at + 1..].to_vec()),
            None => (raw.to_ascii_uppercase(), Vec::new()),
        };
        state.lock().unwrap().seen.push(if verb == b"PASS" { b"PASS ***".to_vec() } else { raw.clone() });
        let w = ctrl.get_mut();
        if !signed_in && !matches!(verb.as_slice(), b"USER" | b"PASS" | b"QUIT" | b"FEAT") {
            say(w, "530 Please sign in").await;
            continue;
        }
        let path = norm(&arg);
        if state.lock().unwrap().forbidden.as_deref() == Some(path.as_slice())
            && !matches!(verb.as_slice(), b"USER" | b"PASS" | b"EPSV" | b"REST" | b"TYPE" | b"PBSZ" | b"PROT")
        {
            say(w, "550 Permission denied").await;
            continue;
        }
        let refuse = state.lock().unwrap().refuse.clone();
        if let Some((_, _, reply)) = refuse.filter(|(v, p, _)| v.as_bytes() == verb && *p == path) {
            say(w, reply).await;
            continue;
        }
        match verb.as_slice() {
            b"USER" if arg == b"guest" => {
                signed_in = true;
                say(w, "230 No password needed").await;
            }
            b"USER" if arg == b"acct" => say(w, "332 Need account").await,
            b"USER" => {
                user = arg == USER.as_bytes() || arg == b"pacct";
                account = arg == b"pacct";
                say(w, "331 Password please").await;
            }
            b"PASS" if account => say(w, "332 Need account").await,
            b"PASS" => {
                if user && arg == PASSWORD.as_bytes() {
                    signed_in = true;
                    say(w, "230 Welcome").await;
                } else {
                    say(w, "530 Login incorrect").await;
                }
            }
            b"PBSZ" => say(w, "200 PBSZ=0").await,
            b"PROT" => {
                let code = state.lock().unwrap().prot_code;
                say(w, &format!("{code} PROT")).await;
            }
            b"TYPE" | b"OPTS" => say(w, "200 OK").await,
            b"NOOP" => say(w, "200 NOOP").await,
            b"QUIT" => {
                say(w, "221 Bye").await;
                return;
            }
            b"FEAT" => {
                let features = state.lock().unwrap().features.clone();
                let mut out = String::from("211-Features:\r\n");
                for f in features {
                    out.push(' ');
                    out.push_str(f);
                    out.push_str("\r\n");
                }
                out.push_str("211 End");
                say(w, &out).await;
            }
            b"EPSV" => {
                let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                let port = l.local_addr().unwrap().port();
                listener = Some(l);
                say(w, &format!("229 Entering Extended Passive Mode (|||{port}|)")).await;
            }
            b"REST" => {
                rest = std::str::from_utf8(&arg).ok().and_then(|a| a.parse().ok()).unwrap_or(0);
                say(w, "350 Restarting").await;
            }
            b"MLST" => {
                let node = state.lock().unwrap().tree.get(&path).cloned();
                match node {
                    Some(n) => {
                        let f = facts(&n, false);
                        let name = String::from_utf8_lossy(&path).into_owned();
                        say(w, &format!("250-Listing {name}\r\n {f} {name}\r\n250 End")).await;
                    }
                    None => say(w, "550 No such file").await,
                }
            }
            b"MKD" => {
                let ok = {
                    let mut s = state.lock().unwrap();
                    let ok = !s.tree.contains_key(&path) && s.tree.get(&parent(&path)) == Some(&Node::Dir);
                    if ok {
                        s.tree.insert(path.clone(), Node::Dir);
                    }
                    ok
                };
                say(w, if ok { "257 Created" } else { "550 Cannot create" }).await;
            }
            b"DELE" => {
                let ok = {
                    let mut s = state.lock().unwrap();
                    let ok = matches!(s.tree.get(&path), Some(Node::File(_)));
                    if ok {
                        s.tree.remove(&path);
                    }
                    ok
                };
                say(w, if ok { "250 Deleted" } else { "550 Cannot delete" }).await;
            }
            b"RMD" => {
                let ok = {
                    let mut s = state.lock().unwrap();
                    let ok = s.tree.get(&path) == Some(&Node::Dir) && children(&s.tree, &path).is_empty();
                    if ok {
                        s.tree.remove(&path);
                    }
                    ok
                };
                say(w, if ok { "250 Removed" } else { "550 Cannot remove" }).await;
            }
            b"RNFR" => {
                let exists = state.lock().unwrap().tree.contains_key(&path);
                rename_from = exists.then(|| path.clone());
                say(w, if exists { "350 Ready" } else { "550 No such file" }).await;
            }
            b"RNTO" => {
                let Some(from) = rename_from.take() else {
                    say(w, "503 RNFR first").await;
                    continue;
                };
                let ok = {
                    let mut s = state.lock().unwrap();
                    let ok = s.tree.get(&parent(&path)) == Some(&Node::Dir);
                    if ok {
                        let moved: Vec<(Vec<u8>, Node)> = s
                            .tree
                            .iter()
                            .filter(|(p, _)| **p == from || p.starts_with(&[from.as_slice(), b"/"].concat()))
                            .map(|(p, n)| (p.clone(), n.clone()))
                            .collect();
                        for (p, n) in moved {
                            s.tree.remove(&p);
                            s.tree.insert([path.as_slice(), &p[from.len()..]].concat(), n);
                        }
                    }
                    ok
                };
                say(w, if ok { "250 Renamed" } else { "550 Cannot rename" }).await;
            }
            b"MLSD" | b"RETR" | b"STOR" => {
                let Some(l) = listener.take() else {
                    say(w, "425 Use EPSV first").await;
                    continue;
                };
                let payload = {
                    let s = state.lock().unwrap();
                    match (verb.as_slice(), s.tree.get(&path)) {
                        (b"MLSD", Some(Node::Dir)) if s.listing.is_some() => s.listing.clone(),
                        (b"MLSD", Some(Node::Dir)) => {
                            let mut out =
                                format!("{} {}\r\n", facts(&Node::Dir, true), String::from_utf8_lossy(&path))
                                    .into_bytes();
                            out.extend_from_slice(b"type=pdir; ..\r\n");
                            for (name, n) in children(&s.tree, &path) {
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
                        (b"RETR", Some(Node::File(d))) => {
                            Some(d.get(rest.min(d.len())..).unwrap_or_default().to_vec())
                        }
                        (b"STOR", None | Some(Node::File(_)))
                            if s.tree.get(&parent(&path)) == Some(&Node::Dir) =>
                        {
                            Some(Vec::new())
                        }
                        _ => None,
                    }
                };
                rest = 0;
                let Some(payload) = payload else {
                    say(w, "550 No such file or folder").await;
                    continue;
                };
                say(w, "150 Opening data connection").await;
                let Ok((tcp, _)) = l.accept().await else { return };
                let Ok(mut data) = acceptor.accept(tcp).await else {
                    say(ctrl.get_mut(), "425 TLS failed").await;
                    continue;
                };
                let resumed = data.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed);
                let require = {
                    let mut s = state.lock().unwrap();
                    if resumed {
                        s.resumed += 1;
                    }
                    s.require_reuse
                };
                if require && !resumed {
                    drop(data);
                    say(ctrl.get_mut(), "425 TLS session of data connection not resumed").await;
                    continue;
                }
                if verb == b"STOR" {
                    let mut got = Vec::new();
                    let whole = data.read_to_end(&mut got).await.is_ok() && data.shutdown().await.is_ok();
                    state.lock().unwrap().tree.insert(path.clone(), Node::File(got));
                    say(ctrl.get_mut(), if whole { "226 Stored" } else { "426 Transfer aborted" }).await;
                } else {
                    let sent = data.write_all(&payload).await.and(data.shutdown().await);
                    let end = state.lock().unwrap().retr_end.filter(|_| verb == b"RETR");
                    let done = end.unwrap_or("226 Done");
                    say(ctrl.get_mut(), if sent.is_ok() { done } else { "426 Transfer aborted" }).await;
                }
            }
            _ => say(w, "502 Not implemented").await,
        }
    }
}
