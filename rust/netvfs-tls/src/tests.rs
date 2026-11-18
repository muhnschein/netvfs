// SPDX-License-Identifier: LGPL-2.1-or-later
use super::*;
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const CA: &[u8] = include_bytes!("../testdata/ca.der");
const LEAF: &[u8] = include_bytes!("../testdata/leaf.der");
const LEAF_KEY: &[u8] = include_bytes!("../testdata/leaf.key.der");
const SELF: &[u8] = include_bytes!("../testdata/self.der");
const SELF_KEY: &[u8] = include_bytes!("../testdata/self.key.der");
const LONG: Duration = Duration::from_secs(20);

fn anchors() -> Anchors {
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(CA.to_vec())).unwrap();
    Anchors::Custom(Arc::new(store))
}

fn server_config(
    cert: &[u8],
    key: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ServerConfig> {
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .unwrap();
    Arc::new(config)
}

/// A server answering each connection with the next of `certs`: it echoes one byte, then closes.
async fn server(certs: Vec<(&'static [u8], &'static [u8])>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for (cert, key) in certs {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(server_config(cert, key, &[&rustls::version::TLS13]));
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut b = [0u8; 1];
                    if tls.read_exact(&mut b).await.is_ok() {
                        tls.write_all(&b).await.ok();
                        tls.shutdown().await.ok();
                    }
                }
            });
        }
    });
    addr
}

async fn shake(client: &Client, addr: SocketAddr) -> Result<TlsStream<TcpStream>, Status> {
    let tcp = connect_tcp(&[addr], LONG).await.unwrap();
    let mut tls = client.handshake(tcp, LONG).await?;
    // A full round trip: the handshake is over on both sides.
    tls.write_all(b"x").await.unwrap();
    let mut b = [0u8; 1];
    tls.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"x");
    Ok(tls)
}

fn spki(cert: &[u8]) -> Vec<u8> {
    spki_of(&CertificateDer::from(cert.to_vec())).unwrap()
}

#[test]
fn the_spki_is_the_certificates_own() {
    for cert in [LEAF, SELF, CA] {
        let key = spki(cert);
        // P-256: SEQUENCE of 89 bytes, algorithm id-ecPublicKey.
        assert_eq!(key.len(), 91);
        assert_eq!(key[..4], [0x30, 0x59, 0x30, 0x13]);
        assert!(cert.windows(key.len()).any(|w| w == key.as_slice()), "SPKI not inside the certificate");
    }
    assert_ne!(spki(LEAF), spki(SELF));
    assert_eq!(
        spki_of(&CertificateDer::from(b"not a certificate".to_vec())),
        Err(rustls::Error::InvalidCertificate(CertificateError::BadEncoding))
    );
}

#[tokio::test]
async fn a_system_trusted_certificate_needs_no_pin() {
    let addr = server(vec![(LEAF, LEAF_KEY)]).await;
    let client = Client::new("localhost", &[], &anchors()).unwrap();
    assert_eq!(client.seen(), None);
    assert_eq!(client.settle(false), None, "nothing seen yet");
    shake(&client, addr).await.unwrap();
    assert_eq!(client.seen(), Some(Seen { spki: spki(LEAF), system_trusted: true }));
    assert_eq!(client.settle(false), None);
}

#[tokio::test]
async fn a_pinned_account_gets_the_key_even_when_trusted() {
    let addr = server(vec![(LEAF, LEAF_KEY)]).await;
    let client = Client::new("127.0.0.1", &[], &anchors()).unwrap();
    shake(&client, addr).await.unwrap();
    assert!(client.seen().unwrap().system_trusted, "IP SAN matches");
    let id = client.settle(true).unwrap();
    assert_eq!(
        id,
        ServerIdentity {
            kind: IdentityKind::Tls,
            algorithm: "tls-spki-sha256".to_owned(),
            public_key: spki(LEAF),
            // openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
            fingerprint: "SHA256:YRJNT1raOBF1/lvOiGJd7ek5P0kbBz/nm/WIOLFcoA0".to_owned(),
        }
    );
}

#[tokio::test]
async fn a_self_signed_certificate_is_reported() {
    let addr = server(vec![(SELF, SELF_KEY)]).await;
    let client = Client::new("localhost", &[], &anchors()).unwrap();
    shake(&client, addr).await.unwrap();
    assert_eq!(client.seen(), Some(Seen { spki: spki(SELF), system_trusted: false }));
    assert_eq!(client.settle(false), Some(identity(spki(SELF))));
}

#[tokio::test]
async fn another_host_name_is_not_trusted() {
    let addr = server(vec![(LEAF, LEAF_KEY)]).await;
    let client = Client::new("nas.example", &[], &anchors()).unwrap();
    shake(&client, addr).await.unwrap();
    assert!(!client.seen().unwrap().system_trusted);
    assert_eq!(client.settle(false), Some(identity(spki(LEAF))));
}

#[tokio::test]
async fn without_anchors_nothing_is_trusted() {
    let addr = server(vec![(LEAF, LEAF_KEY)]).await;
    let client = Client::new("localhost", &[], &Anchors::Custom(Arc::new(RootCertStore::empty()))).unwrap();
    shake(&client, addr).await.unwrap();
    assert!(!client.seen().unwrap().system_trusted);
}

#[tokio::test]
async fn later_handshakes_must_present_the_settled_key() {
    let addr = server(vec![(SELF, SELF_KEY), (SELF, SELF_KEY), (LEAF, LEAF_KEY)]).await;
    let client = Client::new("localhost", &[], &anchors()).unwrap();
    shake(&client, addr).await.unwrap();
    client.settle(false).unwrap();
    shake(&client, addr).await.unwrap();
    // Even a system-trusted certificate is refused once a key is settled.
    let e = shake(&client, addr).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ServerIdentityChanged, "{e:?}");
    assert_eq!(client.seen().unwrap().spki, spki(LEAF));
}

#[tokio::test]
async fn later_handshakes_must_stay_system_trusted() {
    let addr = server(vec![(LEAF, LEAF_KEY), (LEAF, LEAF_KEY), (SELF, SELF_KEY)]).await;
    let client = Client::new("localhost", &[], &anchors()).unwrap();
    shake(&client, addr).await.unwrap();
    assert_eq!(client.settle(false), None);
    shake(&client, addr).await.unwrap();
    let e = shake(&client, addr).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ServerIdentityChanged, "{e:?}");
}

#[tokio::test]
async fn tls_1_2_is_refused() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let acceptor = TlsAcceptor::from(server_config(LEAF, LEAF_KEY, &[&rustls::version::TLS12]));
        acceptor.accept(tcp).await.ok();
    });
    let client = Client::new("localhost", &[], &anchors()).unwrap();
    let tcp = connect_tcp(&[addr], LONG).await.unwrap();
    let e = client.handshake(tcp, LONG).await.unwrap_err();
    assert_eq!(e.name, ErrorName::SecurityPolicy, "{e:?}");
    assert_eq!(client.seen(), None, "no certificate was looked at");
}

#[tokio::test]
async fn alpn_is_offered() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut config = (*server_config(LEAF, LEAF_KEY, &[&rustls::version::TLS13])).clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls = TlsAcceptor::from(Arc::new(config)).accept(tcp).await.unwrap();
        tx.send(tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)).unwrap();
    });
    let client = Client::new("localhost", &[b"http/1.1"], &anchors()).unwrap();
    let tcp = connect_tcp(&[addr], LONG).await.unwrap();
    client.handshake(tcp, LONG).await.unwrap();
    assert_eq!(rx.await.unwrap(), Some(b"http/1.1".to_vec()));
}

#[tokio::test]
async fn a_silent_server_times_out() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (keep_tx, keep_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (_tcp, _) = listener.accept().await.unwrap();
        // Holds the socket open without a word until the test ends.
        keep_rx.await.ok();
    });
    let client = Client::new("localhost", &[], &anchors()).unwrap();
    let tcp = connect_tcp(&[addr], LONG).await.unwrap();
    let e = client.handshake(tcp, Duration::from_millis(200)).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Timeout);
    drop(keep_tx);
}

#[tokio::test]
async fn a_closed_connection_is_lost() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        drop(tcp);
    });
    let client = Client::new("localhost", &[], &anchors()).unwrap();
    let tcp = connect_tcp(&[addr], LONG).await.unwrap();
    let e = client.handshake(tcp, LONG).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ConnectionLost, "{e:?}");
}

#[test]
fn host_names_and_literals() {
    for host in ["nas.local", "127.0.0.1", "[::1]", "::1"] {
        Client::new(host, &[], &anchors()).unwrap();
    }
    for host in ["", "a b", "nas..local"] {
        assert_eq!(Client::new(host, &[], &anchors()).unwrap_err().name, ErrorName::InvalidName, "{host}");
    }
}

#[tokio::test]
async fn names_resolve_and_closed_ports_are_unreachable() {
    let addrs = resolve("127.0.0.1", 9).await.unwrap();
    assert_eq!(addrs, vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 9))]);
    assert_eq!(resolve("[::1]", 9).await.unwrap()[0].port(), 9);
    assert_eq!(resolve("nas.invalid", 9).await.unwrap_err().name, ErrorName::NetworkUnreachable);
    // A port nobody listens on: bound, then released.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    assert_eq!(connect_tcp(&[addr], LONG).await.unwrap_err().name, ErrorName::NetworkUnreachable);
    assert_eq!(connect_tcp(&[], LONG).await.unwrap_err().name, ErrorName::NetworkUnreachable);
}

#[test]
fn the_system_store_loads_once() {
    let a = system_roots();
    let b = system_roots();
    assert!(Arc::ptr_eq(&a, &b));
    Client::new("localhost", &[], &Anchors::System).unwrap();
}

#[test]
fn pins_name_one_key() {
    let key = spki(SELF);
    let pin = format!("tls-spki-sha256 {}", data_encoding::BASE64.encode(&key));
    assert!(pin_matches(&pin, &key));
    assert!(pin_matches(&format!("  {pin} \n"), &key));
    assert!(!pin_matches(&pin, &spki(LEAF)));
    let other_algorithm = format!("ssh-ed25519 {}", data_encoding::BASE64.encode(&key));
    for bad in [
        String::new(),
        "tls-spki-sha256".to_owned(),
        format!("{pin} extra"),
        other_algorithm,
        "tls-spki-sha256 not*base64".to_owned(),
        "tls-spki-sha256 =".to_owned(),
    ] {
        assert!(!pin_matches(&bad, &key), "{bad}");
    }
    assert!(!pin_matches("tls-spki-sha256 ", &[]));
}

#[test]
fn debug_names_the_host_and_whether_system_trust_applies() {
    let trusting = Client::new("nas.example", &[], &anchors()).unwrap();
    assert_eq!(
        format!("{trusting:?}"),
        "Client { name: DnsName(\"nas.example\"), verifier: Verifier { anchors: true, .. }, .. }"
    );
    let bare = Client::new("nas.example", &[], &Anchors::Custom(Arc::new(RootCertStore::empty()))).unwrap();
    assert!(format!("{bare:?}").contains("anchors: false"), "{bare:?}");
}

/// A server answering connection `i` with the `i`-th of `tickets` (tickets it sends), sessions shared: echoes one
/// byte, then closes; reports whether each resumed.
async fn resuming_server(tickets: Vec<usize>) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<bool>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = server_config(LEAF, LEAF_KEY, &[&rustls::version::TLS13]);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        for n in tickets {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut config = (*base).clone();
            config.send_tls13_tickets = n;
            let mut tls = TlsAcceptor::from(Arc::new(config)).accept(tcp).await.unwrap();
            tx.send(tls.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed)).unwrap();
            let mut b = [0u8; 1];
            tls.read_exact(&mut b).await.unwrap();
            tls.write_all(&b).await.unwrap();
            tls.shutdown().await.ok();
        }
    });
    (addr, rx)
}

#[tokio::test]
async fn tickets_are_counted_used_once_and_capped() {
    let (addr, mut resumed) = resuming_server(vec![3, 0, 10]).await;
    let client = Client::new("localhost", &[], &anchors()).unwrap();
    assert_eq!(client.tickets(), 0);
    shake(&client, addr).await.unwrap();
    assert!(!resumed.recv().await.unwrap());
    assert_eq!(client.tickets(), 3);
    shake(&client, addr).await.unwrap();
    assert!(resumed.recv().await.unwrap());
    assert_eq!(client.tickets(), 2);
    shake(&client, addr).await.unwrap();
    assert!(resumed.recv().await.unwrap());
    assert_eq!(client.tickets(), Tickets::MAX);
}
