// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::arithmetic_side_effects, reason = "tests")]
use super::*;
use crate::backend::MAX_ERROR_BODY;
use crate::fake::{CA, Cert, Fake, acceptor};
use http::StatusCode;
use netvfs_tls::Anchors;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const LONG: Duration = Duration::from_secs(20);

fn http_to(addr: SocketAddr, request_timeout: Duration, stale_after: Duration) -> Http {
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(CA.to_vec())).unwrap();
    let tls = Tls::new("localhost", &[ALPN], &Anchors::Custom(Arc::new(store))).unwrap();
    let target = Target {
        host: "localhost".into(),
        port: addr.port(),
        connect_timeout: LONG,
        request_timeout,
        stale_after,
    };
    Http::new(tls, target).unwrap()
}

fn connections(fake: &Fake) -> usize {
    fake.state.lock().unwrap().connections
}

async fn round_trip(http: &mut Http, req: Req) -> StatusCode {
    let (head, body) = http.send(req).await.unwrap().into_parts();
    http.discard(body, MAX_ERROR_BODY).await;
    head.status
}

fn options() -> Req {
    Req::new(Method::OPTIONS, b"/".to_vec())
}

fn stream_put(path: &[u8]) -> Req {
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(Bytes::from_static(b"data")).unwrap();
    Req::new(Method::PUT, path.to_vec()).body(Body::Stream(rx, Some(4)))
}

#[tokio::test]
async fn only_a_stream_needs_a_recently_used_connection() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut http = http_to(fake.addr, LONG, Duration::ZERO);
    round_trip(&mut http, options()).await;
    round_trip(&mut http, options()).await;
    assert_eq!(connections(&fake), 1, "a replayable body goes on an idle connection");
    assert_eq!(round_trip(&mut http, stream_put(b"/a")).await, StatusCode::CREATED);
    assert_eq!(connections(&fake), 2, "a stream does not");
    let mut http = http_to(fake.addr, LONG, Duration::from_hours(1));
    round_trip(&mut http, options()).await;
    assert_eq!(round_trip(&mut http, stream_put(b"/b")).await, StatusCode::CREATED);
    assert_eq!(connections(&fake), 3, "nor one idle longer than stale_after");
}

#[tokio::test]
async fn empty_bodies_have_a_length_except_on_get_and_options() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut http = http_to(fake.addr, LONG, STALE_AFTER);
    for method in [Method::GET, Method::OPTIONS, Method::DELETE] {
        round_trip(&mut http, Req::new(method, b"/".to_vec())).await;
    }
    let lengths: Vec<_> = fake.seen().iter().map(|s| s.headers.get(CONTENT_LENGTH).cloned()).collect();
    assert_eq!(lengths, [None, None, Some(HeaderValue::from_static("0"))]);
}

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

#[tokio::test]
async fn error_pages_up_to_64_kib_are_read_to_keep_the_connection() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut http = http_to(fake.addr, LONG, STALE_AFTER);
    round_trip(&mut http, options()).await;
    for (size, kept) in [(65_536, true), (65_537, false)] {
        let before = connections(&fake);
        fake.with(|s| s.canned.push((Method::GET, StatusCode::FORBIDDEN, vec![], leak("x".repeat(size)))));
        assert_eq!(round_trip(&mut http, Req::new(Method::GET, b"/".to_vec())).await, StatusCode::FORBIDDEN);
        round_trip(&mut http, options()).await;
        assert_eq!(connections(&fake) == before, kept, "{size} bytes");
    }
}

const CAP: usize = 1024 * 1024;

async fn read_body(http: &mut Http, cap: usize) -> Result<Vec<u8>, Status> {
    let (_, body) = http.send(Req::new(Method::GET, b"/".to_vec())).await?.into_parts();
    let mut reader = BodyReader::new(http, body, cap);
    let mut out = Vec::new();
    let read = reader.read_to_end(&mut out).await.map(|_| out).map_err(|e| Status::internal(e.to_string()));
    reader.finish(read)
}

#[tokio::test]
async fn a_body_up_to_its_cap_is_read_whole_and_keeps_the_connection() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut http = http_to(fake.addr, LONG, STALE_AFTER);
    round_trip(&mut http, options()).await;
    fake.with(|s| s.canned.push((Method::GET, StatusCode::OK, vec![], leak("x".repeat(CAP)))));
    assert_eq!(read_body(&mut http, CAP).await.unwrap().len(), CAP);
    round_trip(&mut http, options()).await;
    assert_eq!(connections(&fake), 1);
}

#[tokio::test]
async fn a_body_one_byte_over_its_cap_is_too_large_and_drops_the_connection() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut http = http_to(fake.addr, LONG, STALE_AFTER);
    fake.with(|s| s.canned.push((Method::GET, StatusCode::OK, vec![], leak("x".repeat(CAP + 1)))));
    let e = read_body(&mut http, CAP).await.unwrap_err();
    assert_eq!((e.name, e.detail.as_str()), (ErrorName::ProtocolError, "more than 1048576 bytes"));
    round_trip(&mut http, options()).await;
    assert_eq!(connections(&fake), 2);
}

#[tokio::test]
async fn a_body_left_unread_drops_the_connection() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut http = http_to(fake.addr, LONG, STALE_AFTER);
    fake.with(|s| s.canned.push((Method::GET, StatusCode::OK, vec![], "unread")));
    let (_, body) = http.send(Req::new(Method::GET, b"/".to_vec())).await.unwrap().into_parts();
    BodyReader::new(&mut http, body, CAP).finish(Ok(())).unwrap();
    round_trip(&mut http, options()).await;
    assert_eq!(connections(&fake), 2);
}

async fn trickled(parts: &'static [&'static [u8]], gap: Duration, request_timeout: Duration) -> Http {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let (sender, conn) = http1::handshake::<_, Body>(TokioIo::new(client)).await.unwrap();
    tokio::spawn(async move { drop(conn.await) });
    tokio::spawn(async move {
        let mut head = Vec::new();
        let mut buf = vec![0u8; 4096];
        while !head.ends_with(b"\r\n\r\n") {
            let got = server.read(&mut buf).await.unwrap();
            head.extend_from_slice(&buf[..got]);
        }
        for part in parts {
            server.write_all(part).await.unwrap();
            tokio::time::sleep(gap).await;
        }
        while server.read(&mut buf).await.is_ok_and(|got| got > 0) {}
    });
    let mut http = http_to(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)), request_timeout, STALE_AFTER);
    http.conn = Some(Conn { sender, busy: false, idle_since: Instant::now() });
    http
}

const TRICKLE: &[&[u8]] = &[b"HTTP/1.1 200 OK\r\ncontent-length: 12\r\n\r\nabcd", b"efgh", b"ijkl"];

#[tokio::test(start_paused = true)]
async fn a_body_whose_every_chunk_comes_in_time_is_read_however_long_it_takes() {
    let mut http = trickled(TRICKLE, Duration::from_secs(40), Duration::from_mins(1)).await;
    assert_eq!(read_body(&mut http, CAP).await.unwrap(), b"abcdefghijkl");
}

#[tokio::test(start_paused = true)]
async fn a_body_that_stalls_times_out_and_drops_the_connection() {
    let mut http = trickled(TRICKLE, Duration::from_mins(2), Duration::from_mins(1)).await;
    assert_eq!(read_body(&mut http, CAP).await.unwrap_err().name, ErrorName::Timeout);
    assert!(http.conn.is_none());
}

#[tokio::test]
async fn a_body_cut_short_is_a_lost_connection() {
    let (addr, _) =
        scripted(vec![(vec![b"HTTP/1.1 200 OK\r\ncontent-length: 12\r\n\r\nabcd"], Then::Close)]).await;
    let mut http = http_to(addr, LONG, STALE_AFTER);
    assert_eq!(read_body(&mut http, CAP).await.unwrap_err().name, ErrorName::ConnectionLost);
    assert!(http.conn.is_none());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Then {
    Close,
    AwaitClose,
}

async fn scripted(script: Vec<(Vec<&'static [u8]>, Then)>) -> (SocketAddr, mpsc::UnboundedReceiver<usize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (closed, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for (n, (answers, then)) in script.into_iter().enumerate() {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor(Cert::Trusted).accept(tcp).await.unwrap();
            let mut buf = vec![0u8; 4096];
            for answer in answers {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let got = tls.read(&mut buf).await.unwrap();
                    assert!(got > 0, "the client closed before its request");
                    head.extend_from_slice(&buf[..got]);
                }
                tls.write_all(answer).await.unwrap();
                tls.flush().await.unwrap();
            }
            if then == Then::AwaitClose {
                while tls.read(&mut buf).await.is_ok_and(|got| got > 0) {}
                closed.send(n).unwrap();
            }
        }
    });
    (addr, rx)
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";

#[tokio::test]
async fn an_answer_cut_short_on_a_reused_connection_is_sent_again() {
    let (addr, _) =
        scripted(vec![(vec![OK, b"HTTP/1.1 200 OK\r\n"], Then::Close), (vec![OK], Then::Close)]).await;
    let mut http = http_to(addr, LONG, STALE_AFTER);
    assert_eq!(round_trip(&mut http, options()).await, StatusCode::OK);
    assert_eq!(round_trip(&mut http, options()).await, StatusCode::OK);
}

#[tokio::test]
async fn a_garbled_answer_is_not_sent_again() {
    let (addr, _) =
        scripted(vec![(vec![OK, b"garbage\r\n\r\n"], Then::Close), (vec![OK], Then::Close)]).await;
    let mut http = http_to(addr, LONG, STALE_AFTER);
    assert_eq!(round_trip(&mut http, options()).await, StatusCode::OK);
    assert_eq!(http.send(options()).await.unwrap_err().name, ErrorName::ConnectionLost);
}

#[tokio::test]
async fn a_request_that_times_out_closes_its_connection() {
    let (addr, mut closed) = scripted(vec![(vec![OK], Then::AwaitClose)]).await;
    let mut http = http_to(addr, Duration::from_millis(100), STALE_AFTER);
    round_trip(&mut http, options()).await;
    let started = http.send(options());
    assert_eq!(started.await.unwrap_err().name, ErrorName::Timeout);
    let seen = tokio::time::timeout(LONG, closed.recv()).await;
    assert_eq!(seen.ok().flatten(), Some(0));
}

#[tokio::test]
async fn closed_and_canceled_count_as_dropped_unanswered() {
    let (client, _server) = tokio::io::duplex(64);
    let (mut sender, conn) = http1::handshake::<_, Body>(TokioIo::new(client)).await.unwrap();
    drop(conn);
    let e = std::future::poll_fn(|cx| sender.poll_ready(cx)).await.unwrap_err();
    assert!(e.is_closed() && !e.is_canceled() && !e.is_incomplete_message(), "{e:?}");
    assert!(dropped_unanswered(&e));
    let e = sender.send_request(Request::new(Body::Empty)).await.unwrap_err();
    assert!(e.is_canceled() && !e.is_closed() && !e.is_incomplete_message(), "{e:?}");
    assert!(dropped_unanswered(&e));
}
