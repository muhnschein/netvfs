// SPDX-License-Identifier: LGPL-2.1-or-later
// Restriction lints that only add noise to tests.
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    Duration, ErrorName, ListenAddress, Listener, PathBuf, PeerChecker, SessionId, UnixStream, bind, io,
    is_transient, systemd_socket, unescape,
};
use crate::test_support::{Seen, TempDir, stub_core};

#[test]
fn addresses() {
    assert_eq!(ListenAddress::parse("systemd:").unwrap(), ListenAddress::Systemd);
    assert_eq!(ListenAddress::parse("unix:path=/run/a").unwrap(), ListenAddress::Path("/run/a".into()));
    assert_eq!(
        ListenAddress::parse("unix:path=/run/a%20b%2c%3B%ff").unwrap(),
        ListenAddress::Path(PathBuf::from(
            <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(b"/run/a b,;\xff".to_vec())
        ))
    );
    for bad in [
        "",
        "systemd:x",
        "unix:path=",
        "unix:abstract=x",
        "tcp:host=localhost",
        "unix:path=/a,guid=1",
        "unix:path=/a;unix:path=/b",
        "unix:path=/a%",
        "unix:path=/a%2",
        "unix:path=/a%zz",
        "unix:path=/a%+1",
    ] {
        let error = ListenAddress::parse(bad).unwrap_err();
        assert_eq!(error.name, ErrorName::NetworkUnreachable, "{bad}");
        assert_eq!(error.message, format!("Cannot listen on {bad}"));
    }
}

#[test]
fn unescaping() {
    assert_eq!(unescape("").unwrap(), b"");
    assert_eq!(unescape("abc").unwrap(), b"abc");
    assert_eq!(unescape("%41%62%7e").unwrap(), b"Ab~");
    assert_eq!(unescape("%00").unwrap(), b"\0");
    assert_eq!(unescape("a,b"), None);
    assert_eq!(unescape("a;b"), None);
    assert_eq!(unescape("%4"), None);
    assert_eq!(unescape("%g0"), None);
}

#[test]
fn socket_activation_is_checked_before_taking_a_descriptor() {
    let own = std::process::id().to_string();
    let other = std::process::id().wrapping_add(1).to_string();
    let cases = [
        (None, Some("1"), "no LISTEN_PID"),
        (Some("x"), Some("1"), "no LISTEN_PID"),
        (Some(other.as_str()), Some("1"), "LISTEN_PID is another process"),
        (Some(own.as_str()), None, "no LISTEN_FDS"),
        (Some(own.as_str()), Some("-1"), "no LISTEN_FDS"),
        (Some(own.as_str()), Some("0"), "LISTEN_FDS is 0"),
    ];
    for (pid, fds, why) in cases {
        let error = systemd_socket(pid, fds).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), format!("not socket-activated: {why}"));
    }
}

#[tokio::test]
async fn binding() {
    let dir = TempDir::new();
    let path = dir.path().join("bridge");
    let listener = bind(&ListenAddress::Path(path.clone())).unwrap();
    let client = UnixStream::connect(&path).await.unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    assert_eq!(accepted.peer_cred().unwrap().pid(), client.peer_cred().unwrap().pid());
    let error = bind(&ListenAddress::Path(path.clone())).unwrap_err();
    assert_eq!(error.name, ErrorName::NetworkUnreachable);
    assert!(error.message.starts_with("Cannot listen on Path("), "{}", error.message);
    if std::env::var_os("LISTEN_PID").is_none() {
        let error = bind(&ListenAddress::Systemd).unwrap_err();
        assert!(error.message.contains("not socket-activated: no LISTEN_PID"), "{}", error.message);
    }
}

#[test]
fn transient_accept_failures() {
    for kind in [
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::Interrupted,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::OutOfMemory,
    ] {
        assert!(is_transient(&io::Error::from(kind)), "{kind:?}");
    }
    for errno in [
        libc::EMFILE,
        libc::ENFILE,
        libc::ENOBUFS,
        libc::ENOMEM,
        libc::EPROTO,
        libc::ECONNABORTED,
        libc::EINTR,
    ] {
        assert!(is_transient(&io::Error::from_raw_os_error(errno)), "{errno}");
    }
    for errno in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK, libc::EOPNOTSUPP] {
        assert!(!is_transient(&io::Error::from_raw_os_error(errno)), "{errno}");
    }
    assert!(!is_transient(&io::Error::other("x")));
}

fn serving(checker: PeerChecker) -> (TempDir, PathBuf, tokio::sync::mpsc::UnboundedReceiver<Seen>) {
    let dir = TempDir::new();
    let path = dir.path().join("bridge");
    let (sink, seen) = stub_core();
    let listener = Listener::new(bind(&ListenAddress::Path(path.clone())).unwrap(), checker, sink);
    tokio::spawn(listener.serve());
    (dir, path, seen)
}

async fn next(seen: &mut tokio::sync::mpsc::UnboundedReceiver<Seen>) -> Seen {
    tokio::time::timeout(Duration::from_secs(5), seen.recv()).await.unwrap().unwrap()
}

#[tokio::test]
async fn accepted_peers_are_numbered() {
    let (_dir, path, mut seen) = serving(PeerChecker::new(std::env::current_exe().unwrap()));
    let mut clients = Vec::new();
    for n in 1..=3 {
        let stream = UnixStream::connect(&path).await.unwrap();
        clients.push(zbus::connection::Builder::unix_stream(stream).p2p().build().await.unwrap());
        assert!(matches!(next(&mut seen).await, Seen::Accepted(SessionId(sid), _) if sid == n));
    }
    drop(clients.remove(1));
    assert!(matches!(next(&mut seen).await, Seen::Closed(SessionId(2))));
}

#[tokio::test]
async fn refused_peers_are_closed_unanswered() {
    let (_dir, path, mut seen) = serving(PeerChecker::new("/nonexistent/netvfs-consumer"));
    let mut stream = UnixStream::connect(&path).await.unwrap();
    match next(&mut seen).await {
        Seen::Refused(reason) => assert_eq!(reason.name, ErrorName::PermissionDenied),
        other => panic!("expected Refused, got {other:?}"),
    }
    let mut buf = [0u8; 16];
    let n =
        tokio::time::timeout(Duration::from_secs(5), tokio::io::AsyncReadExt::read(&mut stream, &mut buf))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(n, 0);
    let _again = UnixStream::connect(&path).await.unwrap();
    assert!(matches!(next(&mut seen).await, Seen::Refused(_)));
}
