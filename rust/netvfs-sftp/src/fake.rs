// SPDX-License-Identifier: LGPL-2.1-or-later
//! A small SFTP v3 server over an in-memory tree, for the unit tests: it
//! answers like OpenSSH's sftp-server (errno as OpenSSH maps it, `.` and
//! `..` in listings, SYMLINK as (target, link)), offers the extensions a
//! test picks, logs every request, and follows [`Rule`]s that change or
//! hold back answers.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::unwrap_in_result,
    reason = "test fake: a request it cannot parse is a bug in the test"
)]

use crate::client::Client;
use crate::proto::*;
use crate::remote::{Quirks, Remote};
use crate::wire::{MAX_PACKET, Reader};
use netvfs_vfs::CancelToken;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

/// A node of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A regular file.
    File { data: Vec<u8>, mode: u32, mtime: u32, atime: u32 },
    /// A folder.
    Dir { mode: u32, mtime: u32 },
    /// A symbolic link.
    Link { target: Vec<u8> },
}

/// What a rule does to a request it matches.
#[derive(Debug, Clone)]
pub enum Action {
    /// Answer with this STATUS code and message instead.
    Status(u32, &'static str),
    /// Answer with these raw packet bytes (length included) instead.
    Raw(Vec<u8>),
    /// Answer with a reply of this type and body after the request's id.
    Reply(u8, Vec<u8>),
    /// Do not answer at all.
    Ignore,
    /// Answer after this long.
    Delay(Duration),
    /// Answer READ with at most this many bytes.
    ShortRead(u32),
    /// Close the connection.
    Hangup,
}

/// Changes the answer to requests of `kind` (and of `ext` for EXTENDED)
/// whose first string argument ends with `path` (empty: any); `times` is
/// how often (0: always).
#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: u8,
    pub ext: &'static str,
    pub path: &'static str,
    pub action: Action,
    pub times: u32,
}

impl Rule {
    pub fn new(kind: u8, action: Action) -> Self {
        Self { kind, ext: "", path: "", action, times: 0 }
    }

    pub fn ext(name: &'static str, action: Action) -> Self {
        Self { kind: FXP_EXTENDED, ext: name, path: "", action, times: 0 }
    }

    pub fn on(mut self, path: &'static str) -> Self {
        self.path = path;
        self
    }

    pub fn once(mut self) -> Self {
        self.times = 1;
        self
    }
}

/// One request as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logged {
    pub kind: u8,
    pub id: u32,
    /// The extension name for EXTENDED.
    pub ext: String,
    /// The string arguments in order (paths, handles, data).
    pub strings: Vec<Vec<u8>>,
    /// The first uint64 (READ/WRITE offset), if any.
    pub offset: Option<u64>,
    /// The pflags of OPEN.
    pub pflags: Option<u32>,
    /// The length of READ.
    pub len: Option<u32>,
    /// The attributes of OPEN, MKDIR, SETSTAT.
    pub attrs: Option<Attrs>,
}

#[derive(Debug)]
pub struct State {
    pub nodes: BTreeMap<Vec<u8>, Node>,
    pub home: Vec<u8>,
    pub extensions: Vec<(&'static str, &'static str)>,
    pub limits: Limits,
    pub statvfs: [u64; 11],
    pub users: BTreeMap<u32, &'static str>,
    pub groups: BTreeMap<u32, &'static str>,
    pub uid: u32,
    pub gid: u32,
    /// READDIR names per reply.
    pub batch: usize,
    /// LSTAT follows links (ProFTPD).
    pub lstat_follows: bool,
    pub rules: Vec<Rule>,
    pub log: Vec<Logged>,
    handles: BTreeMap<Vec<u8>, Open>,
    next_handle: u32,
    pub version: u32,
}

#[derive(Debug, Clone)]
enum Open {
    File(Vec<u8>),
    Dir { listing: Vec<(Vec<u8>, Attrs)>, at: usize },
}

/// The server's shared state: the tree, the rules, the log.
#[derive(Debug, Clone)]
pub struct Fake {
    state: Arc<Mutex<State>>,
}

pub const ALL_EXTENSIONS: [(&str, &str); 7] = [
    ("posix-rename@openssh.com", "1"),
    ("statvfs@openssh.com", "2"),
    ("fsync@openssh.com", "1"),
    ("hardlink@openssh.com", "1"),
    ("limits@openssh.com", "1"),
    ("users-groups-by-id@openssh.com", "1"),
    ("copy-data", "1"),
];

impl Fake {
    /// A server with home `/home/u` (a folder) and every extension.
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        for dir in [&b"/"[..], b"/home", b"/home/u"] {
            nodes.insert(dir.to_vec(), Node::Dir { mode: 0o755, mtime: 1000 });
        }
        let state = State {
            nodes,
            home: b"/home/u".to_vec(),
            extensions: ALL_EXTENSIONS.to_vec(),
            limits: Limits {
                max_packet: 262_144,
                max_read: 261_120,
                max_write: 261_120,
                max_open_handles: 0,
            },
            statvfs: [4096, 4096, 1000, 600, 500, 100, 50, 50, 1, 0, 255],
            users: [(1000, "alice")].into(),
            groups: [(100, "users")].into(),
            uid: 1000,
            gid: 100,
            batch: 100,
            lstat_follows: false,
            rules: Vec::new(),
            log: Vec::new(),
            handles: BTreeMap::new(),
            next_handle: 1,
            version: 3,
        };
        Self { state: Arc::new(Mutex::new(state)) }
    }

    pub fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    pub fn with_extensions(self, extensions: &[(&'static str, &'static str)]) -> Self {
        self.state().extensions = extensions.to_vec();
        self
    }

    pub fn rule(&self, rule: Rule) {
        self.state().rules.push(rule);
    }

    pub fn file(&self, path: &str, data: &[u8]) {
        self.state().nodes.insert(
            path.as_bytes().to_vec(),
            Node::File { data: data.to_vec(), mode: 0o644, mtime: 2000, atime: 1500 },
        );
    }

    pub fn dir(&self, path: &str) {
        self.state().nodes.insert(path.as_bytes().to_vec(), Node::Dir { mode: 0o755, mtime: 3000 });
    }

    pub fn link(&self, path: &str, target: &str) {
        self.state()
            .nodes
            .insert(path.as_bytes().to_vec(), Node::Link { target: target.as_bytes().to_vec() });
    }

    pub fn node(&self, path: &str) -> Option<Node> {
        self.state().nodes.get(path.as_bytes()).cloned()
    }

    pub fn data(&self, path: &str) -> Option<Vec<u8>> {
        match self.node(path)? {
            Node::File { data, .. } => Some(data),
            _ => None,
        }
    }

    /// Requests of `kind` received so far.
    pub fn requests(&self, kind: u8) -> Vec<Logged> {
        self.state().log.iter().filter(|l| l.kind == kind).cloned().collect()
    }

    pub fn open_handles(&self) -> usize {
        self.state().handles.len()
    }

    /// Serves one client on `stream` until it closes.
    pub fn serve(&self, stream: DuplexStream) -> tokio::task::JoinHandle<()> {
        let fake = self.clone();
        tokio::spawn(async move { fake.run(stream).await })
    }

    /// A connected pair: the client's end, and the server task.
    pub fn connect(&self) -> (DuplexStream, tokio::task::JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(4 * MAX_PACKET);
        (client, self.serve(server))
    }

    /// A started client.
    pub async fn client(&self) -> (Client, ServerVersion) {
        let (stream, _task) = self.connect();
        let (r, w) = tokio::io::split(stream);
        Client::start(r, w, async {}, Duration::from_secs(10), &CancelToken::new()).await.unwrap()
    }

    /// The file operations of a server with `quirks`, folders made with
    /// mode 0o750.
    pub async fn remote_with(&self, quirks: Quirks) -> Remote {
        let (client, version) = self.client().await;
        Remote::new(client, &version, quirks, 0o750, &CancelToken::new()).await.unwrap()
    }

    /// The file operations of an OpenSSH server.
    pub async fn remote(&self) -> Remote {
        self.remote_with(Quirks::of(b"SSH-2.0-OpenSSH_9.9")).await
    }

    /// The log so far, then cleared.
    pub fn take_log(&self) -> Vec<Logged> {
        std::mem::take(&mut self.state().log)
    }

    /// The kinds of the requests so far (extension names for EXTENDED).
    pub fn kinds(&self) -> Vec<String> {
        self.state()
            .log
            .iter()
            .map(|l| if l.kind == FXP_EXTENDED { l.ext.clone() } else { kind_name(l.kind).to_owned() })
            .collect()
    }

    async fn run<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(&self, stream: S) {
        let (mut read, write) = tokio::io::split(stream);
        let write = Arc::new(tokio::sync::Mutex::new(write));
        loop {
            let mut len = [0; 4];
            if read.read_exact(&mut len).await.is_err() {
                return;
            }
            let len = u32::from_be_bytes(len) as usize;
            let mut body = vec![0; len];
            if read.read_exact(&mut body).await.is_err() {
                return;
            }
            let (answer, delay) = {
                let mut state = self.state();
                state.answer(&body)
            };
            match answer {
                Answer::None => {}
                Answer::Hangup => return,
                Answer::Bytes(bytes) => {
                    let write = Arc::clone(&write);
                    let send = async move {
                        if let Some(d) = delay {
                            tokio::time::sleep(d).await;
                        }
                        let mut w = write.lock().await;
                        drop(w.write_all(&bytes).await);
                        drop(w.flush().await);
                        drop(w);
                    };
                    if delay.is_some() {
                        tokio::spawn(send);
                    } else {
                        send.await;
                    }
                }
            }
        }
    }
}

enum Answer {
    None,
    Hangup,
    Bytes(Vec<u8>),
}

/// A request type's name, for readable assertions.
pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        FXP_OPEN => "OPEN",
        FXP_CLOSE => "CLOSE",
        FXP_READ => "READ",
        FXP_WRITE => "WRITE",
        FXP_LSTAT => "LSTAT",
        FXP_FSTAT => "FSTAT",
        FXP_SETSTAT => "SETSTAT",
        FXP_OPENDIR => "OPENDIR",
        FXP_READDIR => "READDIR",
        FXP_REMOVE => "REMOVE",
        FXP_MKDIR => "MKDIR",
        FXP_RMDIR => "RMDIR",
        FXP_REALPATH => "REALPATH",
        FXP_STAT => "STAT",
        FXP_RENAME => "RENAME",
        FXP_READLINK => "READLINK",
        FXP_SYMLINK => "SYMLINK",
        _ => "?",
    }
}

fn packet(kind: u8, id: u32, rest: &[u8]) -> Vec<u8> {
    let mut out = ((rest.len() + 5) as u32).to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(rest);
    out
}

pub fn string(v: &[u8]) -> Vec<u8> {
    let mut out = (v.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(v);
    out
}

fn status(id: u32, code: u32, message: &str) -> Vec<u8> {
    let mut rest = code.to_be_bytes().to_vec();
    rest.extend(string(message.as_bytes()));
    rest.extend(string(b""));
    packet(FXP_STATUS, id, &rest)
}

pub fn encode_attrs(a: &Attrs) -> Vec<u8> {
    let bytes = a.encode(crate::wire::Packet::request(0)).finish(0).unwrap();
    bytes[9..].to_vec()
}

fn parent(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) => b"/".to_vec(),
        Some(i) => path[..i].to_vec(),
        None => b".".to_vec(),
    }
}

fn base(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// `/a/b/../c` → `/a/c`; `.` components dropped.
fn normalize(path: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in path.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    let mut out = Vec::new();
    for p in parts {
        out.push(b'/');
        out.extend_from_slice(p);
    }
    if out.is_empty() { b"/".to_vec() } else { out }
}

const NO_SUCH_FILE: (u32, &str) = (FX_NO_SUCH_FILE, "No such file");
const FAILURE: (u32, &str) = (FX_FAILURE, "Failure");

impl State {
    fn absolute(&self, path: &[u8]) -> Vec<u8> {
        if path.starts_with(b"/") {
            normalize(path)
        } else {
            let mut full = self.home.clone();
            full.push(b'/');
            full.extend_from_slice(path);
            normalize(&full)
        }
    }

    /// Follows symlinks of the final component (`follow`) and of parents.
    fn resolve(&self, path: &[u8], follow: bool) -> Result<Vec<u8>, (u32, &'static str)> {
        let mut current = self.absolute(path);
        for _ in 0..16 {
            let par = parent(&current);
            if current != b"/" {
                match self.nodes.get(&par) {
                    Some(Node::Dir { .. }) => {}
                    Some(Node::Link { .. }) => {
                        let p = self.resolve(&par, true)?;
                        let mut joined = p;
                        joined.push(b'/');
                        joined.extend_from_slice(base(&current));
                        current = normalize(&joined);
                        continue;
                    }
                    Some(Node::File { .. }) | None => return Err(NO_SUCH_FILE),
                }
            }
            match self.nodes.get(&current) {
                Some(Node::Link { target }) if follow => {
                    current = if target.starts_with(b"/") {
                        normalize(target)
                    } else {
                        let mut t = parent(&current);
                        t.push(b'/');
                        t.extend_from_slice(target);
                        normalize(&t)
                    };
                }
                _ => return Ok(current),
            }
        }
        Err((FX_FAILURE, "Too many levels of symbolic links"))
    }

    fn attrs_of(&self, node: &Node) -> Attrs {
        let (size, permissions, times) = match node {
            Node::File { data, mode, mtime, atime } => {
                (data.len() as u64, 0o100_000 | mode, (*atime, *mtime))
            }
            Node::Dir { mode, mtime } => (4096, 0o040_000 | mode, (*mtime, *mtime)),
            Node::Link { target } => (target.len() as u64, 0o120_777, (0, 0)),
        };
        Attrs {
            size: Some(size),
            ids: Some((self.uid, self.gid)),
            permissions: Some(permissions),
            times: Some(times),
        }
    }

    fn stat(&self, path: &[u8], follow: bool) -> Result<Attrs, (u32, &'static str)> {
        let p = self.resolve(path, follow)?;
        self.nodes.get(&p).map(|n| self.attrs_of(n)).ok_or(NO_SUCH_FILE)
    }

    fn new_handle(&mut self, open: Open) -> Vec<u8> {
        let h = format!("h{}", self.next_handle).into_bytes();
        self.next_handle += 1;
        self.handles.insert(h.clone(), open);
        h
    }

    fn file_of(&self, handle: &[u8]) -> Result<Vec<u8>, (u32, &'static str)> {
        match self.handles.get(handle) {
            Some(Open::File(p)) => Ok(p.clone()),
            _ => Err((FX_FAILURE, "bad handle")),
        }
    }

    fn data_mut(&mut self, handle: &[u8]) -> Result<(&mut Vec<u8>, &mut u32), (u32, &'static str)> {
        let p = self.file_of(handle)?;
        match self.nodes.get_mut(&p) {
            Some(Node::File { data, mtime, .. }) => Ok((data, mtime)),
            _ => Err((FX_FAILURE, "gone")),
        }
    }

    fn check_parent(&self, path: &[u8]) -> Result<(), (u32, &'static str)> {
        match self.nodes.get(&parent(path)) {
            Some(Node::Dir { .. }) => Ok(()),
            _ => Err(NO_SUCH_FILE),
        }
    }

    fn answer(&mut self, body: &[u8]) -> (Answer, Option<Duration>) {
        let mut r = Reader::new(body);
        let kind = r.u8().unwrap();
        if kind == FXP_INIT {
            let mut rest = self.version.to_be_bytes().to_vec();
            for (n, d) in &self.extensions {
                rest.extend(string(n.as_bytes()));
                rest.extend(string(d.as_bytes()));
            }
            let mut out = ((rest.len() + 1) as u32).to_be_bytes().to_vec();
            out.push(FXP_VERSION);
            out.extend(rest);
            return (Answer::Bytes(out), None);
        }
        let id = r.u32().unwrap();
        let logged = log_entry(kind, id, body);
        let rule = self.rules.iter_mut().position(|rule| {
            rule.kind == kind
                && (rule.ext.is_empty() || rule.ext == logged.ext)
                && (rule.path.is_empty()
                    || logged.strings.first().is_some_and(|s| s.ends_with(rule.path.as_bytes())))
        });
        let action = rule.map(|i| {
            let rule = &mut self.rules[i];
            let action = rule.action.clone();
            if rule.times == 1 {
                self.rules.remove(i);
            } else if rule.times > 1 {
                rule.times -= 1;
            }
            action
        });
        self.log.push(logged);
        let mut delay = None;
        let mut short = None;
        match action {
            Some(Action::Status(code, message)) => return (Answer::Bytes(status(id, code, message)), None),
            Some(Action::Raw(bytes)) => return (Answer::Bytes(bytes), None),
            Some(Action::Reply(kind, rest)) => return (Answer::Bytes(packet(kind, id, &rest)), None),
            Some(Action::Ignore) => return (Answer::None, None),
            Some(Action::Hangup) => return (Answer::Hangup, None),
            Some(Action::Delay(d)) => delay = Some(d),
            Some(Action::ShortRead(n)) => short = Some(n),
            None => {}
        }
        let reply = match self.handle(kind, id, &mut r, short) {
            Ok(bytes) => bytes,
            Err((code, message)) => status(id, code, message),
        };
        (Answer::Bytes(reply), delay)
    }

    #[allow(clippy::too_many_lines, reason = "one arm per request type")]
    fn handle(
        &mut self,
        kind: u8,
        id: u32,
        r: &mut Reader<'_>,
        short: Option<u32>,
    ) -> Result<Vec<u8>, (u32, &'static str)> {
        let ok = |id| status(id, FX_OK, "Success");
        let s = |r: &mut Reader<'_>| r.string(MAX_PACKET, "").unwrap().to_vec();
        match kind {
            FXP_OPEN => {
                let path = s(r);
                let flags = r.u32().unwrap();
                let attrs = Attrs::decode(r).unwrap();
                let p = self.resolve(&path, true)?;
                match self.nodes.get_mut(&p) {
                    Some(Node::Dir { .. }) if flags & FXF_WRITE != 0 => {
                        return Err((FX_FAILURE, "Is a directory"));
                    }
                    Some(_) if flags & FXF_CREAT != 0 && flags & FXF_EXCL != 0 => return Err(FAILURE),
                    Some(Node::File { data, .. }) if flags & FXF_TRUNC != 0 => data.clear(),
                    Some(_) => {}
                    None if flags & FXF_CREAT != 0 => {
                        self.check_parent(&p)?;
                        let mode = attrs.permissions.unwrap_or(0o666) & 0o7777;
                        self.nodes.insert(
                            p.clone(),
                            Node::File { data: Vec::new(), mode, mtime: 5000, atime: 5000 },
                        );
                    }
                    None => return Err(NO_SUCH_FILE),
                }
                let h = self.new_handle(Open::File(p));
                Ok(packet(FXP_HANDLE, id, &string(&h)))
            }
            FXP_OPENDIR => {
                let path = s(r);
                let p = self.resolve(&path, true)?;
                match self.nodes.get(&p) {
                    Some(Node::Dir { .. }) => {}
                    _ => return Err(NO_SUCH_FILE),
                }
                let dot = self.attrs_of(&Node::Dir { mode: 0o755, mtime: 0 });
                let mut listing = vec![(b".".to_vec(), dot), (b"..".to_vec(), dot)];
                let prefix = if p == b"/" { b"/".to_vec() } else { [&p[..], b"/"].concat() };
                for (name, node) in &self.nodes {
                    if name.starts_with(&prefix)
                        && name.len() > prefix.len()
                        && !name[prefix.len()..].contains(&b'/')
                    {
                        listing.push((name[prefix.len()..].to_vec(), self.attrs_of(node)));
                    }
                }
                let h = self.new_handle(Open::Dir { listing, at: 0 });
                Ok(packet(FXP_HANDLE, id, &string(&h)))
            }
            FXP_READDIR => {
                let h = s(r);
                let batch = self.batch;
                let Some(Open::Dir { listing, at }) = self.handles.get_mut(&h) else {
                    return Err((FX_FAILURE, "bad handle"));
                };
                if *at >= listing.len() {
                    return Err((FX_EOF, "End of file"));
                }
                let end = (*at + batch).min(listing.len());
                let mut rest = ((end - *at) as u32).to_be_bytes().to_vec();
                for (name, attrs) in &listing[*at..end] {
                    rest.extend(string(name));
                    rest.extend(string(b"long name"));
                    rest.extend(encode_attrs(attrs));
                }
                *at = end;
                Ok(packet(FXP_NAME, id, &rest))
            }
            FXP_CLOSE => {
                let h = s(r);
                self.handles.remove(&h).ok_or((FX_FAILURE, "bad handle"))?;
                Ok(ok(id))
            }
            FXP_READ => {
                let h = s(r);
                let offset = r.u64().unwrap() as usize;
                let len = r.u32().unwrap().min(short.unwrap_or(u32::MAX)) as usize;
                let len = len.min(self.limits.max_read as usize);
                let (data, _) = self.data_mut(&h)?;
                if offset >= data.len() {
                    return Err((FX_EOF, "End of file"));
                }
                let end = (offset + len).min(data.len());
                Ok(packet(FXP_DATA, id, &string(&data[offset..end])))
            }
            FXP_WRITE => {
                let h = s(r);
                let offset = r.u64().unwrap() as usize;
                let chunk = s(r);
                let (data, mtime) = self.data_mut(&h)?;
                if data.len() < offset + chunk.len() {
                    data.resize(offset + chunk.len(), 0);
                }
                data[offset..offset + chunk.len()].copy_from_slice(&chunk);
                *mtime = 6000;
                Ok(ok(id))
            }
            FXP_STAT | FXP_LSTAT => {
                let path = s(r);
                let attrs = self.stat(&path, kind == FXP_STAT || self.lstat_follows)?;
                Ok(packet(FXP_ATTRS, id, &encode_attrs(&attrs)))
            }
            FXP_FSTAT => {
                let h = s(r);
                let p = self.file_of(&h)?;
                let attrs = self.stat(&p, true)?;
                Ok(packet(FXP_ATTRS, id, &encode_attrs(&attrs)))
            }
            FXP_SETSTAT => {
                let path = s(r);
                let attrs = Attrs::decode(r).unwrap();
                let p = self.resolve(&path, true)?;
                match self.nodes.get_mut(&p) {
                    Some(Node::File { data, mode, mtime, atime }) => {
                        if let Some(size) = attrs.size {
                            data.resize(size as usize, 0);
                        }
                        if let Some(m) = attrs.permissions {
                            *mode = m & 0o7777;
                        }
                        if let Some((a, m)) = attrs.times {
                            *atime = a;
                            *mtime = m;
                        }
                    }
                    Some(Node::Dir { mode, mtime }) => {
                        if let Some(m) = attrs.permissions {
                            *mode = m & 0o7777;
                        }
                        if let Some((_, m)) = attrs.times {
                            *mtime = m;
                        }
                    }
                    Some(Node::Link { .. }) => {}
                    None => return Err(NO_SUCH_FILE),
                }
                Ok(ok(id))
            }
            FXP_REMOVE => {
                let path = s(r);
                let p = self.resolve(&path, false)?;
                match self.nodes.get(&p) {
                    Some(Node::Dir { .. }) => Err(FAILURE),
                    Some(_) => {
                        self.nodes.remove(&p);
                        Ok(ok(id))
                    }
                    None => Err(NO_SUCH_FILE),
                }
            }
            FXP_MKDIR => {
                let path = s(r);
                let attrs = Attrs::decode(r).unwrap();
                let p = self.resolve(&path, false)?;
                if self.nodes.contains_key(&p) {
                    return Err(FAILURE);
                }
                self.check_parent(&p)?;
                let mode = attrs.permissions.unwrap_or(0o777) & 0o7777;
                self.nodes.insert(p, Node::Dir { mode, mtime: 7000 });
                Ok(ok(id))
            }
            FXP_RMDIR => {
                let path = s(r);
                let p = self.resolve(&path, false)?;
                match self.nodes.get(&p) {
                    Some(Node::Dir { .. }) => {}
                    _ => return Err(NO_SUCH_FILE),
                }
                let prefix = [&p[..], b"/"].concat();
                if self.nodes.keys().any(|k| k.starts_with(&prefix)) {
                    return Err(FAILURE);
                }
                self.nodes.remove(&p);
                Ok(ok(id))
            }
            FXP_REALPATH => {
                let path = s(r);
                let p = self.absolute(&path);
                let mut rest = 1u32.to_be_bytes().to_vec();
                rest.extend(string(&p));
                rest.extend(string(&p));
                rest.extend(0u32.to_be_bytes());
                Ok(packet(FXP_NAME, id, &rest))
            }
            FXP_RENAME => {
                let from = self.resolve(&s(r), false)?;
                let to = self.resolve(&s(r), false)?;
                if !self.nodes.contains_key(&from) {
                    return Err(NO_SUCH_FILE);
                }
                if self.nodes.contains_key(&to) {
                    return Err(FAILURE);
                }
                self.check_parent(&to)?;
                self.move_tree(&from, &to);
                Ok(ok(id))
            }
            FXP_READLINK => {
                let p = self.resolve(&s(r), false)?;
                match self.nodes.get(&p) {
                    Some(Node::Link { target }) => {
                        let mut rest = 1u32.to_be_bytes().to_vec();
                        rest.extend(string(target));
                        rest.extend(string(target));
                        rest.extend(0u32.to_be_bytes());
                        Ok(packet(FXP_NAME, id, &rest))
                    }
                    Some(_) => Err((FX_BAD_MESSAGE, "Invalid argument")),
                    None => Err(NO_SUCH_FILE),
                }
            }
            FXP_SYMLINK => {
                let target = s(r);
                let link = self.resolve(&s(r), false)?;
                if self.nodes.contains_key(&link) {
                    return Err(FAILURE);
                }
                self.check_parent(&link)?;
                self.nodes.insert(link, Node::Link { target });
                Ok(ok(id))
            }
            FXP_EXTENDED => self.extended(id, r),
            _ => Err((FX_OP_UNSUPPORTED, "Operation unsupported")),
        }
    }

    fn move_tree(&mut self, from: &[u8], to: &[u8]) {
        let prefix = [from, b"/"].concat();
        let moved: Vec<Vec<u8>> =
            self.nodes.keys().filter(|k| k.as_slice() == from || k.starts_with(&prefix)).cloned().collect();
        for old in moved {
            let node = self.nodes.remove(&old).unwrap();
            let new = [to, &old[from.len()..]].concat();
            self.nodes.insert(new, node);
        }
    }

    fn extended(&mut self, id: u32, r: &mut Reader<'_>) -> Result<Vec<u8>, (u32, &'static str)> {
        let s = |r: &mut Reader<'_>| r.string(MAX_PACKET, "").unwrap().to_vec();
        let name = String::from_utf8(s(r)).unwrap();
        if !self.extensions.iter().any(|(n, _)| *n == name) {
            return Err((FX_OP_UNSUPPORTED, "Operation unsupported"));
        }
        let ok = status(id, FX_OK, "Success");
        match name.as_str() {
            "posix-rename@openssh.com" => {
                let from = self.resolve(&s(r), false)?;
                let to = self.resolve(&s(r), false)?;
                match (self.nodes.get(&from), self.nodes.get(&to)) {
                    (None, _) => return Err(NO_SUCH_FILE),
                    (Some(Node::Dir { .. }), Some(Node::File { .. } | Node::Link { .. })) => {
                        return Err((FX_FAILURE, "Not a directory"));
                    }
                    (Some(_), Some(Node::Dir { .. })) => return Err((FX_FAILURE, "Is a directory")),
                    _ => {}
                }
                if from != to {
                    self.nodes.remove(&to);
                    self.move_tree(&from, &to);
                }
                Ok(ok)
            }
            "statvfs@openssh.com" => {
                self.stat(&s(r), true)?;
                let rest: Vec<u8> = self.statvfs.iter().flat_map(|v| v.to_be_bytes()).collect();
                Ok(packet(FXP_EXTENDED_REPLY, id, &rest))
            }
            "fsync@openssh.com" => {
                self.file_of(&s(r))?;
                Ok(ok)
            }
            "hardlink@openssh.com" => {
                let from = self.resolve(&s(r), false)?;
                let to = self.resolve(&s(r), false)?;
                let node = self.nodes.get(&from).cloned().ok_or(NO_SUCH_FILE)?;
                if self.nodes.contains_key(&to) {
                    return Err(FAILURE);
                }
                self.nodes.insert(to, node);
                Ok(ok)
            }
            "limits@openssh.com" => {
                let l = self.limits;
                let rest: Vec<u8> = [l.max_packet, l.max_read, l.max_write, l.max_open_handles]
                    .iter()
                    .flat_map(|v| v.to_be_bytes())
                    .collect();
                Ok(packet(FXP_EXTENDED_REPLY, id, &rest))
            }
            "users-groups-by-id@openssh.com" => {
                let ids = |blob: Vec<u8>| -> Vec<u32> {
                    blob.chunks(4).map(|c| u32::from_be_bytes(c.try_into().unwrap())).collect()
                };
                let (uids, gids) = (ids(s(r)), ids(s(r)));
                let names = |ids: &[u32], map: &BTreeMap<u32, &str>| -> Vec<u8> {
                    ids.iter().flat_map(|i| string(map.get(i).copied().unwrap_or("").as_bytes())).collect()
                };
                let rest = [string(&names(&uids, &self.users)), string(&names(&gids, &self.groups))].concat();
                Ok(packet(FXP_EXTENDED_REPLY, id, &rest))
            }
            "copy-data" => {
                let rh = s(r);
                let roff = r.u64().unwrap() as usize;
                let len = r.u64().unwrap() as usize;
                let wh = s(r);
                let woff = r.u64().unwrap() as usize;
                let (src, _) = self.data_mut(&rh)?;
                let end = if len == 0 { src.len() } else { (roff + len).min(src.len()) };
                let chunk = src.get(roff..end).unwrap_or_default().to_vec();
                let (dst, _) = self.data_mut(&wh)?;
                if dst.len() < woff + chunk.len() {
                    dst.resize(woff + chunk.len(), 0);
                }
                dst[woff..woff + chunk.len()].copy_from_slice(&chunk);
                Ok(ok)
            }
            _ => Err((FX_OP_UNSUPPORTED, "Operation unsupported")),
        }
    }
}

fn log_entry(kind: u8, id: u32, body: &[u8]) -> Logged {
    let mut r = Reader::new(body.get(5..).unwrap_or_default());
    let mut logged = Logged {
        kind,
        id,
        ext: String::new(),
        strings: Vec::new(),
        offset: None,
        pflags: None,
        len: None,
        attrs: None,
    };
    let one = |r: &mut Reader<'_>, logged: &mut Logged| {
        if let Ok(v) = r.string(MAX_PACKET, "") {
            logged.strings.push(v.to_vec());
        }
    };
    let all = |r: &mut Reader<'_>, logged: &mut Logged| {
        while let Ok(v) = r.string(MAX_PACKET, "") {
            logged.strings.push(v.to_vec());
        }
    };
    match kind {
        FXP_OPEN => {
            one(&mut r, &mut logged);
            logged.pflags = r.u32().ok();
            logged.attrs = Attrs::decode(&mut r).ok();
        }
        FXP_MKDIR | FXP_SETSTAT => {
            one(&mut r, &mut logged);
            logged.attrs = Attrs::decode(&mut r).ok();
        }
        FXP_READ => {
            one(&mut r, &mut logged);
            logged.offset = r.u64().ok();
            logged.len = r.u32().ok();
        }
        FXP_WRITE => {
            one(&mut r, &mut logged);
            logged.offset = r.u64().ok();
            one(&mut r, &mut logged);
        }
        FXP_EXTENDED => {
            if let Ok(name) = r.string(MAX_PACKET, "") {
                logged.ext = String::from_utf8_lossy(name).into_owned();
            }
            if logged.ext == "copy-data" {
                // read handle, offset, length, write handle, offset
                one(&mut r, &mut logged);
                logged.offset = r.u64().ok();
                let _length = r.u64();
                one(&mut r, &mut logged);
            } else {
                all(&mut r, &mut logged);
            }
        }
        _ => all(&mut r, &mut logged),
    }
    logged
}
