// SPDX-License-Identifier: LGPL-2.1-or-later
use super::*;
use crate::testserver::{Proxy, Script, Server, Subsystem, host_key};
use russh::{cipher, kex};
use std::borrow::Cow;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ED25519_FINGERPRINT: &str = "SHA256:ZGPW31uwJF+/lR0hhEstPwJCRwMYsx0C3T2YPcRL/3c";

fn target(addr: SocketAddr) -> Target {
    Target {
        host: addr.ip().to_string(),
        port: addr.port(),
        connect_timeout: Duration::from_secs(10),
        pinned_type: None,
    }
}

fn pinned(addr: SocketAddr, key_type: &str) -> Target {
    Target { pinned_type: Some(key_type.to_owned()), ..target(addr) }
}

fn open_script() -> Script {
    Script { open: true, ..Script::password() }
}

/// A session to `server` through a proxy.
async fn through_proxy(server: &Server) -> (Session, Proxy) {
    let proxy = Proxy::start(server.addr).await;
    let session = connect(&target(proxy.addr), &CancelToken::new()).await.unwrap();
    (session, proxy)
}

/// Signed in with `none` (the open script), ready for channels.
async fn signed_in(server: &Server) -> Session {
    let mut session = connect(&target(server.addr), &CancelToken::new()).await.unwrap();
    assert!(session.handle().authenticate_none("u").await.unwrap().success());
    session
}

#[tokio::test]
async fn the_identity_is_the_host_key() {
    let server = Server::start(Script::password()).await;
    let session = connect(&target(server.addr), &CancelToken::new()).await.unwrap();
    let id = session.identity();
    assert_eq!(id.algorithm, "ssh-ed25519");
    assert_eq!(id.fingerprint, ED25519_FINGERPRINT);
    assert_eq!(id.public_key, server.keys[0].to_bytes().unwrap());
    assert_eq!(*id, identity_of(&server.keys[0]));
    assert_eq!(session.banner(), b"SSH-2.0-OpenSSH_9.6");
    assert!(!session.is_closed());
    assert_eq!(session.end(), None);
    // Nothing was sent for signing in.
    assert_eq!(server.take_log(), Vec::<String>::new());
    session.close().await;
}

#[tokio::test]
async fn a_pin_picks_the_host_key_of_its_type() {
    let keys = vec![host_key("rsa-openssh"), host_key("ecdsa384-openssh"), host_key("ed25519-openssh")];
    let server = Server::with_keys(Script::password(), keys, "SSH-2.0-OpenSSH_9.6").await;
    let c = CancelToken::new();
    // Unpinned, the client's order decides: Ed25519 first.
    assert_eq!(connect(&target(server.addr), &c).await.unwrap().identity().algorithm, "ssh-ed25519");
    for (key_type, index) in [("ssh-rsa", 0), ("ecdsa-sha2-nistp384", 1), ("ssh-ed25519", 2)] {
        let session = connect(&pinned(server.addr, key_type), &c).await.unwrap();
        assert_eq!(*session.identity(), identity_of(&server.keys[index]), "{key_type}");
    }
}

#[tokio::test]
async fn a_pinned_type_the_server_dropped_shows_the_new_key() {
    let server = Server::start(Script::password()).await;
    let proxy = Proxy::start(server.addr).await;
    let c = CancelToken::new();
    let session = connect(&pinned(proxy.addr, "ecdsa-sha2-nistp256"), &c).await.unwrap();
    assert_eq!(session.identity().algorithm, "ssh-ed25519");
    assert_eq!(proxy.connections(), 2);
    // A type this app does not accept narrows nothing: one connection.
    let other = Proxy::start(server.addr).await;
    connect(&pinned(other.addr, "ssh-dss"), &c).await.unwrap();
    assert_eq!(other.connections(), 1);
    // Neither does a pin of the type the server has.
    let same = Proxy::start(server.addr).await;
    connect(&pinned(same.addr, "ssh-ed25519"), &c).await.unwrap();
    assert_eq!(same.connections(), 1);
}

#[tokio::test]
async fn no_common_algorithm_is_a_security_policy_failure() {
    for (kind, list) in [("kex", "key exchange"), ("cipher", "cipher")] {
        let server = Server::start(Script::password()).await;
        let mut config = russh::server::Config::default();
        if kind == "kex" {
            config.preferred.kex = Cow::Borrowed(&[kex::DH_G14_SHA256]);
        } else {
            config.preferred.cipher = Cow::Borrowed(&[cipher::AES_256_CTR]);
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        config.keys = vec![host_key("ed25519-openssh")];
        let config = Arc::new(config);
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            drop(russh::server::run_stream(config, socket, NoAuth).await);
        });
        let e = connect(&target(addr), &CancelToken::new()).await.unwrap_err();
        assert_eq!(e.name, ErrorName::SecurityPolicy, "{e:?}");
        assert_eq!(e.message, format!("The server offers no {list} algorithm this app accepts"));
        let offered = if kind == "kex" { "diffie-hellman-group14-sha256" } else { "aes256-ctr" };
        assert_eq!(e.detail, format!("The server offers: {offered}"));
        drop(server);
    }
}

/// A server handler that takes nobody.
struct NoAuth;
impl russh::server::Handler for NoAuth {
    type Error = russh::Error;
}

#[tokio::test]
async fn transport_failures_before_ssh() {
    let c = CancelToken::new();
    // Refused.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let e = connect(&target(addr), &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NetworkUnreachable);
    assert_eq!(e.message, format!("Cannot connect to 127.0.0.1 port {}", addr.port()));
    assert_ne!(e.detail, "");
    // Accepted and closed at once.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });
    let e = connect(&target(addr), &c).await.unwrap_err();
    assert_eq!(
        (e.name, e.message.as_str()),
        (ErrorName::NetworkUnreachable, "The server closed the connection")
    );
    // Not SSH: a line longer than an identification may be.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(&[b'x'; 300]).await.unwrap();
        let mut sink = Vec::new();
        drop(socket.read_to_end(&mut sink).await);
    });
    let e = connect(&target(addr), &c).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::ProtocolError, "The SSH handshake failed"));
}

#[tokio::test]
async fn a_stalled_handshake_times_out_and_leaves_nothing_running() {
    let server = Server::start(Script::password()).await;
    let proxy = Proxy::start(server.addr).await;
    proxy.stall(true);
    let t = Target { connect_timeout: Duration::from_millis(300), ..target(proxy.addr) };
    let started = tokio::time::Instant::now();
    let e = connect(&t, &CancelToken::new()).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::Timeout, "The server did not answer within 1 s"));
    assert!(started.elapsed() < Duration::from_secs(3));
    // The session task russh started is gone: its socket closed.
    assert!(proxy.all_closed().await);
}

#[tokio::test]
async fn a_canceled_handshake_leaves_nothing_running() {
    let server = Server::start(Script::password()).await;
    let proxy = Proxy::start(server.addr).await;
    proxy.stall(true);
    let cancel = CancelToken::new();
    let canceler = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        canceler.cancel();
    });
    let e = connect(&target(proxy.addr), &cancel).await.unwrap_err();
    assert_eq!(e, Status::canceled());
    assert!(proxy.all_closed().await);
    // Tripped before: nothing is tried.
    let before = Proxy::start(server.addr).await;
    assert_eq!(connect(&target(before.addr), &cancel).await.unwrap_err(), Status::canceled());
    assert_eq!(before.connections(), 0);
}

#[tokio::test]
async fn a_dropped_connect_leaves_nothing_running() {
    let server = Server::start(Script::password()).await;
    let proxy = Proxy::start(server.addr).await;
    proxy.stall(true);
    let t = target(proxy.addr);
    let c = CancelToken::new();
    let connecting = connect(&t, &c);
    tokio::time::timeout(Duration::from_millis(200), connecting).await.unwrap_err();
    assert_eq!(proxy.connections(), 1);
    assert!(proxy.all_closed().await);
}

#[tokio::test]
async fn dropping_or_closing_a_session_closes_the_connection() {
    let server = Server::start(Script::password()).await;
    let (session, proxy) = through_proxy(&server).await;
    drop(session);
    assert!(proxy.all_closed().await);
    let (session, proxy) = through_proxy(&server).await;
    session.close().await;
    assert!(proxy.all_closed().await);
}

#[tokio::test]
async fn keep_alive_proves_the_connection() {
    let server = Server::start(open_script()).await;
    let (mut session, proxy) = through_proxy(&server).await;
    assert!(session.handle().authenticate_none("u").await.unwrap().success());
    let c = CancelToken::new();
    // russh's server, like OpenSSH, refuses the request: that is an answer.
    session.keep_alive(Duration::from_secs(5), &c).await.unwrap();
    proxy.stall(true);
    let e = session.keep_alive(Duration::from_millis(200), &c).await.unwrap_err();
    assert_eq!(e, Status::new(ErrorName::Timeout, "The server did not answer the keep-alive request"));
    let cancel = CancelToken::new();
    cancel.cancel();
    assert_eq!(session.keep_alive(Duration::from_secs(5), &cancel).await, Err(Status::canceled()));
    proxy.stall(false);
    session.keep_alive(Duration::from_secs(5), &c).await.unwrap();
    proxy.cut();
    let mut lost = None;
    for _ in 0..100 {
        if let Err(e) = session.keep_alive(Duration::from_secs(5), &c).await {
            lost = Some(e);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let lost = lost.unwrap();
    assert_eq!(
        (lost.name, lost.message.as_str()),
        (ErrorName::ConnectionLost, "The connection to the server was lost")
    );
    assert!(session.is_closed());
    assert!(matches!(session.end(), Some(End::Failed(_))), "{:?}", session.end());
}

#[tokio::test]
async fn the_sftp_subsystem_starts_on_a_session_channel() {
    let server = Server::start(open_script()).await;
    let session = signed_in(&server).await;
    let c = CancelToken::new();
    let (reader, write) = session.open_sftp(Duration::from_secs(5), &c).await.unwrap();
    let (client, version) =
        crate::client::Client::start(reader, write.make_writer(), async {}, Duration::from_secs(5), &c)
            .await
            .unwrap();
    assert_eq!(version.version, 3);
    let attrs = client.stat(b"/home/u", true, &c).await.unwrap();
    assert_eq!(crate::remote::kind_of(&attrs), netvfs_vfs::EntryType::Directory);
    assert_eq!(server.take_log(), ["none u", "session", "subsystem sftp"]);
}

#[tokio::test]
async fn refused_subsystems_and_sessions() {
    let c = CancelToken::new();
    let five = Duration::from_secs(5);
    let server = Server::start(Script { subsystem: Subsystem::Refuse, ..open_script() }).await;
    let session = signed_in(&server).await;
    assert_eq!(session.open_sftp(five, &c).await.unwrap_err(), sftp_not_enabled());
    assert_eq!(sftp_not_enabled(), Status::unsupported("SFTP is not enabled for this user"));
    for (reason, name, message) in [
        (
            russh::ChannelOpenFailure::ConnectFailed,
            ErrorName::TooManyConnections,
            "The server allows no further session on this connection",
        ),
        (
            russh::ChannelOpenFailure::AdministrativelyProhibited,
            ErrorName::TooManyConnections,
            "The server allows no further session on this connection",
        ),
        (
            russh::ChannelOpenFailure::ResourceShortage,
            ErrorName::TooManyConnections,
            "The server allows no further session on this connection",
        ),
        (
            russh::ChannelOpenFailure::UnknownChannelType,
            ErrorName::ProtocolError,
            "The server refused a session: UnknownChannelType",
        ),
    ] {
        let server = Server::start(Script { refuse_session: Some(reason), ..open_script() }).await;
        let session = signed_in(&server).await;
        let e = session.open_sftp(five, &c).await.unwrap_err();
        assert_eq!((e.name, e.message.as_str()), (name, message));
    }
}

#[tokio::test]
async fn channels_the_server_opens_are_refused() {
    let server = Server::start(Script { probe_channels: true, ..open_script() }).await;
    let _session = signed_in(&server).await;
    let mut log = Vec::new();
    for _ in 0..500 {
        log.extend(server.take_log());
        if log.last().is_some_and(|l| l == "probe done") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        log,
        [
            "none u",
            "probe session refused",
            "probe agent refused",
            "probe x11 refused",
            "probe forwarded-tcpip refused",
            "probe direct-tcpip refused",
            "probe forwarded-streamlocal refused",
            "probe direct-streamlocal refused",
            "probe done"
        ]
    );
}

#[tokio::test]
async fn a_server_disconnect_is_recorded() {
    let server = Server::start(Script { max_failures: Some(1), ..Script::password() }).await;
    let mut session = connect(&target(server.addr), &CancelToken::new()).await.unwrap();
    let r = session.handle().authenticate_password("u", "wrong").await;
    // The server hung up instead of answering.
    assert!(!r.unwrap().success());
    for _ in 0..100 {
        if session.end().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let end = session.end().unwrap();
    assert!(matches!(end, End::Failed(_) | End::Disconnected { .. }), "{end:?}");
    assert_eq!(end.status().name, ErrorName::ConnectionLost);
    assert!(session.is_closed());
}

#[test]
fn ends_name_the_reason() {
    let d = End::Disconnected { code: 2, message: "Too many authentication failures".to_owned() };
    assert_eq!(
        d.status(),
        connection_lost()
            .with_detail("The server closed the connection (2): Too many authentication failures")
    );
    assert_eq!(End::NoAuthMethod.status().detail, "The server named no sign-in method");
    assert_eq!(End::Failed("reset".to_owned()).status(), connection_lost().with_detail("reset"));
}

#[test]
fn handshake_failures() {
    let e = handshake_failure(&russh::Error::Disconnect);
    assert_eq!(
        (e.name, e.message.as_str()),
        (ErrorName::NetworkUnreachable, "The server closed the connection")
    );
    let e = handshake_failure(&russh::Error::IO(io::Error::from(io::ErrorKind::ConnectionReset)));
    assert_eq!(e.name, ErrorName::NetworkUnreachable);
    assert_eq!(handshake_failure(&russh::Error::HUP).name, ErrorName::NetworkUnreachable);
    let e = handshake_failure(&russh::Error::WrongServerSig);
    assert_eq!((e.name, e.message.as_str()), (ErrorName::ProtocolError, "The SSH handshake failed"));
    assert_eq!(e.detail, russh::Error::WrongServerSig.to_string());
}

#[tokio::test]
async fn a_cut_stream_fails_waiting_reads_and_writes() {
    let (a, mut b) = tokio::io::duplex(16);
    let (mut a, cut) = Cuttable::new(a);
    let reader = tokio::spawn(async move {
        let mut buf = [0; 4];
        let first = a.read(&mut buf).await.unwrap();
        let second = a.read(&mut buf).await;
        (first, second.map_err(|e| e.kind()), a)
    });
    b.write_all(b"hi").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!cut.is_cut());
    cut.cut();
    let (first, second, mut a) = tokio::time::timeout(Duration::from_secs(5), reader).await.unwrap().unwrap();
    assert_eq!((first, second), (2, Err(io::ErrorKind::ConnectionAborted)));
    assert_eq!(a.write(b"x").await.map_err(|e| e.kind()), Err(io::ErrorKind::ConnectionAborted));
    assert_eq!(a.flush().await.map_err(|e| e.kind()), Err(io::ErrorKind::ConnectionAborted));
    a.shutdown().await.unwrap();
    // A writer blocked on a full pipe is woken too.
    let (a, _b) = tokio::io::duplex(4);
    let (mut a, cut) = Cuttable::new(a);
    let writer = tokio::spawn(async move { a.write_all(&[0; 64]).await.map_err(|e| e.kind()) });
    tokio::time::sleep(Duration::from_millis(50)).await;
    cut.cut();
    let written = tokio::time::timeout(Duration::from_secs(5), writer).await.unwrap().unwrap();
    assert_eq!(written, Err(io::ErrorKind::ConnectionAborted));
}

#[tokio::test]
async fn the_channel_reader_reads_data_only() {
    let server = Server::start(Script { subsystem: Subsystem::Raw, ..open_script() }).await;
    let session = signed_in(&server).await;
    let (mut reader, _write) = session.open_sftp(Duration::from_secs(5), &CancelToken::new()).await.unwrap();
    let mut all = Vec::new();
    let mut buf = [0; 1];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut buf)).await.unwrap().unwrap();
        if n == 0 {
            break;
        }
        all.extend_from_slice(&buf[..n]);
    }
    assert_eq!(all, b"abcd");
    // Ended for good.
    assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
    assert!(format!("{reader:?}").contains("ChannelReader"));
}
