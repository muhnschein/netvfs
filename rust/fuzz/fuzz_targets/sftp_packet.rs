// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-sftp against a hostile SFTP server (design §3.2): every reply
//! decoder on arbitrary bytes, each result within its caps, and the
//! client with the backend's file operations over a server that answers
//! each request with the next of the input's packets (its request id put
//! in, or as it is). Nothing panics, nothing hangs, and what comes back is
//! a value or a status.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_sftp::client::Client;
use netvfs_sftp::proto::{
    self, Limits, MAX_EXTENSION_FIELD, MAX_EXTENSIONS, MAX_HANDLE, MAX_NAME, MAX_NAMES, MAX_OWNER_NAME, Reply,
    Statvfs,
};
use netvfs_sftp::remote::{Quirks, Remote};
use netvfs_sftp::wire::MAX_PACKET;
use netvfs_vfs::{Attributes, CancelToken, Entry, ListOptions, ListSink, RenameMode};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    /// Bytes for the decoders on their own.
    raw: Vec<u8>,
    /// Ids asked for by `decode_owner_names`.
    users: u8,
    groups: u8,
    /// The server's banner decides the quirks.
    openssh: bool,
    /// The server's packets: the first answers INIT (VERSION), each next
    /// one the next request. With `true` its request id is put in after
    /// the type byte.
    replies: Vec<(bool, Vec<u8>)>,
}

fn decoders(input: &Input) {
    let data = &input.raw[..];
    if let Ok((_, reply)) = proto::decode_reply(data) {
        match reply {
            Reply::Status(s) => assert!(s.message.chars().count() <= proto::MAX_MESSAGE),
            Reply::Handle(h) => assert!(h.len() <= MAX_HANDLE),
            Reply::Name(names) => {
                assert!(names.len() <= MAX_NAMES as usize);
                assert!(names.iter().all(|n| n.filename.len() <= MAX_NAME));
            }
            Reply::Data(d) | Reply::Extended(d) => assert!(d.len() <= data.len()),
            Reply::Attrs(_) => {}
        }
    }
    if let Ok(version) = proto::decode_version(data) {
        assert!(version.extensions.len() <= MAX_EXTENSIONS);
        for e in &version.extensions {
            assert!(e.name.len() <= MAX_EXTENSION_FIELD && e.data.len() <= MAX_EXTENSION_FIELD);
        }
    }
    assert_eq!(Statvfs::decode(data).is_ok(), data.len() == 88);
    assert_eq!(Limits::decode(data).is_ok(), data.len() == 32);
    let (users, groups) = (usize::from(input.users), usize::from(input.groups));
    if let Ok((u, g)) = proto::decode_owner_names(data, users, groups) {
        assert_eq!((u.len(), g.len()), (users, groups));
        assert!(u.iter().chain(&g).all(|n| n.len() <= MAX_OWNER_NAME));
    }
}

/// Answers INIT and then each request with the next reply, until there
/// are no more (then it hangs up).
async fn serve(io: tokio::io::DuplexStream, replies: Vec<(bool, Vec<u8>)>) {
    let (mut read, mut write) = tokio::io::split(io);
    for (put_id, reply) in replies {
        let mut len = [0; 4];
        if read.read_exact(&mut len).await.is_err() {
            return;
        }
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_PACKET + 4 {
            return;
        }
        let mut request = vec![0; len];
        if read.read_exact(&mut request).await.is_err() {
            return;
        }
        let mut body = reply;
        if put_id && !body.is_empty() && request.len() >= 5 {
            body.splice(1..1, request[1..5].iter().copied());
        }
        let Ok(body_len) = u32::try_from(body.len()) else { return };
        if write.write_all(&body_len.to_be_bytes()).await.is_err() || write.write_all(&body).await.is_err() {
            return;
        }
    }
}

struct Sink;
impl ListSink for Sink {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        assert!(!batch.is_empty());
        assert!(batch.iter().all(|e| e.name != b"." && e.name != b".." && !e.name.is_empty()));
        true
    }
}

async fn session(input: Input) {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(serve(server_io, input.replies));
    let (read, write) = tokio::io::split(client_io);
    let cancel = CancelToken::new();
    let Ok((client, version)) = Client::start(read, write, async {}, Duration::from_secs(5), &cancel).await else {
        return;
    };
    let banner: &[u8] = if input.openssh { b"SSH-2.0-OpenSSH_9.6" } else { b"SSH-2.0-mod_sftp" };
    let Ok(mut remote) = Remote::new(client, &version, Quirks::of(banner), 0o700, &cancel).await else {
        return;
    };
    let _ = remote.capabilities();
    let _ = remote.stat(b"a", true, &cancel).await;
    let _ = remote.stat(b"/b", false, &cancel).await;
    let options = ListOptions { batch_size: 3, resolve_symlink_types: true };
    let _ = remote.list(b"dir", options, &mut Sink, &cancel).await;
    let _ = remote.read_link(b"link", &cancel).await;
    let _ = remote.make_dir(b"x/y", false, &cancel).await;
    let _ = remote.rename(b"a", b"b", RenameMode::NoReplace, &cancel).await;
    let _ = remote.rename(b"a", b"b", RenameMode::Replace, &cancel).await;
    let changes = Attributes { mode: Some(0o600), mtime_ms: Some(1), atime_ms: None };
    let _ = remote.set_attributes(b"a", &changes, &cancel).await;
    if let Ok(space) = remote.space_info(b"", &cancel).await {
        if let (Some(free), Some(total)) = (space.free, space.total) {
            assert!(free <= total);
        }
    }
    let _ = remote.copy(b"a", b"c", false, RenameMode::NoReplace, &cancel).await;
    let _ = remote.remove_file(b"a", &cancel).await;
    let _ = remote.remove_dir(b"x", &cancel).await;
}

fuzz_target!(|input: Input| {
    decoders(&input);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().expect("a runtime");
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), session(input)).await.expect("the session ends");
    });
});
