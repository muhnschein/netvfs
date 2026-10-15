// SPDX-License-Identifier: LGPL-2.1-or-later
//! Helpers of the in-crate tests.
// Restriction lints that only add noise to tests (doc/RUST.md "Lints").
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A temporary folder, removed on drop.
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("nvb-test-{}-{n}", std::process::id()));
        drop(std::fs::remove_dir_all(&path));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// Writes `data` to `path`, creating the folders.
pub fn write_file(path: &Path, data: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
}

/// Both ends of a session after the p2p handshake: the server's message
/// stream (with the bridge's inbound limits), a duplicate of the server
/// socket (the shutdown handle) and a zbus client.
pub struct Pair {
    pub server: zbus::MessageStream,
    pub shutdown: std::os::unix::net::UnixStream,
    pub client: zbus::Connection,
}

impl std::fmt::Debug for Pair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pair")
    }
}

/// A connected [`Pair`] over a socket pair.
pub async fn pair() -> Pair {
    use std::os::fd::AsFd as _;
    let (a, b) = tokio::net::UnixStream::pair().unwrap();
    let shutdown = std::os::unix::net::UnixStream::from(a.as_fd().try_clone_to_owned().unwrap());
    let (server, client) = tokio::join!(
        crate::server::session::handshake(a),
        zbus::connection::Builder::unix_stream(b).p2p().build()
    );
    Pair { server: server.unwrap(), shutdown, client: client.unwrap() }
}

/// A consumer that speaks the wire by hand: it can pipeline a call behind
/// `BEGIN`, send oversized frames, and stop reading.
#[derive(Debug)]
pub struct RawClient {
    pub stream: tokio::net::UnixStream,
}

impl RawClient {
    /// Connects and authenticates (EXTERNAL); `BEGIN` is still to be sent.
    pub async fn authenticate(mut stream: tokio::net::UnixStream) -> Self {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let uid = crate::sys::peer::effective_uid().to_string();
        let hex: String = uid
            .bytes()
            .flat_map(|b| [b >> 4, b & 15])
            .map(|d| char::from_digit(d.into(), 16).unwrap())
            .collect();
        stream.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes()).await.unwrap();
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            let mut byte = [0u8; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1, "the server closed the handshake");
            line.push(byte[0]);
        }
        assert!(line.starts_with(b"OK "), "{}", String::from_utf8_lossy(&line));
        Self { stream }
    }

    /// `BEGIN` and `messages` in one write.
    pub async fn begin_with(&mut self, messages: &[&zbus::Message]) {
        let mut bytes = b"BEGIN\r\n".to_vec();
        for message in messages {
            bytes.extend_from_slice(&message.data()[..]);
        }
        self.write(&bytes).await;
    }

    pub async fn write(&mut self, bytes: &[u8]) {
        use tokio::io::AsyncWriteExt as _;
        self.stream.write_all(bytes).await.unwrap();
    }

    /// The next message, or `None` at the end of the stream.
    pub async fn receive(&mut self) -> Option<zbus::Message> {
        read_message(&mut self.stream).await
    }

    /// Reads until the server closes the connection; false after `limit`.
    pub async fn closed_within(&mut self, limit: std::time::Duration) -> bool {
        use tokio::io::AsyncReadExt as _;
        let drain = async {
            let mut buf = vec![0u8; 64 * 1024];
            while self.stream.read(&mut buf).await.is_ok_and(|n| n > 0) {}
        };
        tokio::time::timeout(limit, drain).await.is_ok()
    }
}

/// The server end of a session (after the handshake), its shutdown handle,
/// and a [`RawClient`] that sent `BEGIN`.
pub async fn raw_pair() -> (zbus::MessageStream, std::os::unix::net::UnixStream, RawClient) {
    use std::os::fd::AsFd as _;
    let (a, b) = tokio::net::UnixStream::pair().unwrap();
    let shutdown = std::os::unix::net::UnixStream::from(a.as_fd().try_clone_to_owned().unwrap());
    let client = async {
        let mut client = RawClient::authenticate(b).await;
        client.begin_with(&[]).await;
        client
    };
    let (server, client) = tokio::join!(crate::server::session::handshake(a), client);
    (server.unwrap(), shutdown, client)
}

/// The next message from a raw stream, or `None` at its end.
pub async fn read_message<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Option<zbus::Message> {
    use tokio::io::AsyncReadExt as _;
    let mut header = [0u8; 16];
    reader.read_exact(&mut header).await.ok()?;
    let size = crate::server::inbound::frame_size(&header).unwrap();
    let mut bytes = header.to_vec();
    bytes.resize(usize::try_from(size.total).unwrap(), 0);
    reader.read_exact(&mut bytes[16..]).await.ok()?;
    Some(crate::sys::frame::message_from_frame(bytes, Vec::new(), size.endian).unwrap())
}

/// The resident set of this process in bytes.
pub fn resident_bytes() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
    let kib: usize = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    kib * 1024
}

/// An entry of about 300 bytes on the wire.
pub fn wire_entry() -> netvfs_bridge_proto::WireEntry {
    netvfs_bridge_proto::WireEntry {
        name: vec![b'x'; 200],
        kind: 1,
        target_kind: 0,
        size: 1,
        mtime_ms: -1,
        ctime_ms: -1,
        atime_ms: -1,
        mode: 0o644,
        uid: -1,
        gid: -1,
        owner: "owner".to_owned(),
        group: "group".to_owned(),
        flags: 0,
        etag: Vec::new(),
        content_type: "text/plain".to_owned(),
    }
}

/// What the [`stub_core`] saw, in order.
#[derive(Debug)]
pub enum Seen {
    Accepted(crate::server::SessionId, crate::server::Outbox),
    Call(crate::server::SessionId, &'static str),
    Closed(crate::server::SessionId),
    Refused(crate::Status),
}

/// A core for the server's tests: answers `Hello` (not to client "old"),
/// `GetConsent` ("unknown"), `RequestConsent`, `ListLocations` (empty),
/// `Upload` (the number of bytes its descriptor holds); refuses other
/// consent-gated calls with `PermissionDenied` and drops the rest
/// unanswered. Reports every event.
pub fn stub_core() -> (crate::server::EventSink, tokio::sync::mpsc::UnboundedReceiver<Seen>) {
    use crate::server::{Event, EventSink};
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let sink = EventSink::new(move |event| {
        let seen = match event {
            Event::Accepted { sid, outbox } => Seen::Accepted(sid, outbox),
            Event::Closed { sid } => Seen::Closed(sid),
            Event::Refused { reason } => Seen::Refused(reason),
            Event::Call { sid, reply, call } => {
                let name = call.name();
                stub_answer(reply, call);
                Seen::Call(sid, name)
            }
        };
        drop(tx.send(seen));
    });
    (sink, rx)
}

fn stub_answer(reply: crate::server::ReplyTo, call: crate::server::Call) {
    use crate::server::{Call, Reply};
    use netvfs_bridge_proto::ErrorName;
    match call {
        Call::Hello { client } if client == "old" => {
            reply.fail(&crate::Status::new(ErrorName::ProtocolError, "Refused client"));
        }
        Call::Hello { .. } => reply.ok(&Reply::Hello),
        Call::GetConsent => reply.ok(&Reply::Text("unknown".to_owned())),
        Call::RequestConsent => reply.ok(&Reply::Empty),
        Call::ListLocations => reply.ok(&Reply::Locations(Vec::new())),
        Call::Upload { fd, .. } => {
            let mut content = Vec::new();
            std::io::Read::read_to_end(&mut std::fs::File::from(fd), &mut content).unwrap();
            reply.ok(&Reply::Id(u32::try_from(content.len()).unwrap()));
        }
        call if call.needs_consent() => reply.fail(&crate::Status::permission_denied("No consent")),
        _ => drop(reply),
    }
}
