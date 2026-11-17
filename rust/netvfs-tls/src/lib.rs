// SPDX-License-Identifier: LGPL-2.1-or-later
//! TLS client side of the WebDAV backend: rustls with ring, TLS 1.3 only, no client certificates.
//!
//! Trust: a certificate valid for the host under the system CAs needs no pin. Any other certificate
//! is the server's identity (`tls-spki-sha256`, its SubjectPublicKeyInfo): `connect` reports it,
//! C++ compares it with the account's pin (`checkServerIdentity`) before credentials go out. Later
//! handshakes of the same connection must present the same key, or a system-trusted certificate
//! when the first one was system trusted.
#![forbid(unsafe_code)]

use netvfs_vfs::{ErrorName, IdentityKind, ServerIdentity, Status};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
pub use tokio_rustls::client::TlsStream;

/// `ServerIdentity::algorithm` of a TLS identity: the key is a DER SubjectPublicKeyInfo.
pub const ALGORITHM: &str = "tls-spki-sha256";

/// The certificate of the last handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// DER SubjectPublicKeyInfo of the leaf.
    pub spki: Vec<u8>,
    /// Chain and host name verified against the trust anchors.
    pub system_trusted: bool,
}

/// What later handshakes must present.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Policy {
    /// Before the first handshake ends: anything, recorded.
    Open,
    /// This key.
    Key(Vec<u8>),
    /// Any system-trusted certificate.
    System,
}

#[derive(Debug)]
struct State {
    policy: Policy,
    last: Option<Seen>,
}

struct Verifier {
    webpki: Option<Arc<WebPkiServerVerifier>>,
    algorithms: WebPkiSupportedAlgorithms,
    state: Mutex<State>,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier").field("anchors", &self.webpki.is_some()).finish_non_exhaustive()
    }
}

impl Verifier {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The SubjectPublicKeyInfo of a DER certificate.
fn spki_of(cert: &CertificateDer<'_>) -> Result<Vec<u8>, rustls::Error> {
    let parsed = webpki::EndEntityCert::try_from(cert)
        .map_err(|_bad| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    Ok(parsed.subject_public_key_info().as_ref().to_vec())
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let spki = spki_of(end_entity)?;
        let system_trusted = self.webpki.as_ref().is_some_and(|v| {
            v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).is_ok()
        });
        let mut state = self.state();
        let allowed = match &state.policy {
            Policy::Open => true,
            Policy::Key(key) => *key == spki,
            Policy::System => system_trusted,
        };
        state.last = Some(Seen { spki, system_trusted });
        drop(state);
        if allowed {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The trust anchors that make a certificate system trusted.
#[derive(Debug, Clone)]
pub enum Anchors {
    /// The system CA store, read once per process.
    System,
    /// These (tests).
    Custom(Arc<RootCertStore>),
}

fn system_roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    Arc::clone(ROOTS.get_or_init(|| {
        let mut store = RootCertStore::empty();
        // Unreadable or unparsable entries are skipped; with none left nothing is system trusted.
        store.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        Arc::new(store)
    }))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// TLS for one server: the handshakes of one backend connection share it.
#[derive(Clone)]
pub struct Client {
    connector: TlsConnector,
    verifier: Arc<Verifier>,
    name: ServerName<'static>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("name", &self.name)
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// TLS 1.3 to `host` (name or address literal), offering `alpn`.
    ///
    /// # Errors
    /// `InvalidName` for a host that is neither a DNS name nor an address; `Internal` when rustls refuses the
    /// configuration.
    pub fn new(host: &str, alpn: &[&[u8]], anchors: &Anchors) -> Result<Self, Status> {
        let name = ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']'))
            .map_err(|_bad| Status::invalid_name(format!("Not a host name: {host}")))?
            .to_owned();
        let roots = match anchors {
            Anchors::System => system_roots(),
            Anchors::Custom(roots) => Arc::clone(roots),
        };
        let provider = provider();
        let webpki = if roots.is_empty() {
            None
        } else {
            Some(
                WebPkiServerVerifier::builder_with_provider(roots, Arc::clone(&provider))
                    .build()
                    .map_err(|e| Status::internal(format!("TLS trust anchors: {e}")))?,
            )
        };
        let verifier = Arc::new(Verifier {
            webpki,
            algorithms: provider.signature_verification_algorithms,
            state: Mutex::new(State { policy: Policy::Open, last: None }),
        });
        let dyn_verifier: Arc<dyn ServerCertVerifier> = Arc::<Verifier>::clone(&verifier);
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Status::internal(format!("TLS configuration: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(dyn_verifier)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(Self { connector: TlsConnector::from(Arc::new(config)), verifier, name })
    }

    /// The handshake over `tcp`, within `timeout`.
    ///
    /// # Errors
    /// `ServerIdentityChanged` for a certificate later handshakes may not present; `SecurityPolicy` when the
    /// server offers no TLS 1.3; `Timeout`; `ConnectionLost` for other failures.
    pub async fn handshake(&self, tcp: TcpStream, timeout: Duration) -> Result<TlsStream<TcpStream>, Status> {
        let shake = self.connector.connect(self.name.clone(), tcp);
        let stream = tokio::time::timeout(timeout, shake)
            .await
            .map_err(|_elapsed| Status::new(ErrorName::Timeout, "The TLS handshake timed out"))?;
        stream.map_err(|e| handshake_error(&e))
    }

    /// The certificate of the last handshake.
    #[must_use]
    pub fn seen(&self) -> Option<Seen> {
        self.verifier.state().last.clone()
    }

    /// What `connect` reports after the first handshake, `pinned` telling whether the account has a pin:
    /// no identity for a system-trusted certificate without a pin, else the key. Fixes what later handshakes
    /// must present. `None` as well before any handshake.
    #[must_use]
    pub fn settle(&self, pinned: bool) -> Option<ServerIdentity> {
        let mut state = self.verifier.state();
        let seen = state.last.clone()?;
        if seen.system_trusted && !pinned {
            state.policy = Policy::System;
            return None;
        }
        state.policy = Policy::Key(seen.spki.clone());
        drop(state);
        Some(identity(seen.spki))
    }
}

/// Whether `pin` (`tls-spki-sha256 <base64>`, as C++ `ServerIdentity::toPin` writes it) names `spki`; a pin that
/// cannot be read names nothing.
#[must_use]
pub fn pin_matches(pin: &str, spki: &[u8]) -> bool {
    let fields: Vec<&str> = pin.split_ascii_whitespace().collect();
    let [algorithm, key] = fields.as_slice() else {
        return false;
    };
    *algorithm == ALGORITHM
        && data_encoding::BASE64.decode(key.as_bytes()).is_ok_and(|k| !k.is_empty() && k == spki)
}

/// The `ServerIdentity` of a key; fingerprint `SHA256:` + unpadded base64 of the SPKI's digest, as for SSH keys.
#[must_use]
pub fn identity(spki: Vec<u8>) -> ServerIdentity {
    let digest = ::ring::digest::digest(&::ring::digest::SHA256, &spki);
    ServerIdentity {
        kind: IdentityKind::Tls,
        algorithm: ALGORITHM.to_owned(),
        fingerprint: format!("SHA256:{}", data_encoding::BASE64_NOPAD.encode(digest.as_ref())),
        public_key: spki,
    }
}

fn handshake_error(e: &std::io::Error) -> Status {
    let tls = e.get_ref().and_then(<dyn std::error::Error + Send + Sync>::downcast_ref::<rustls::Error>);
    match tls {
        Some(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)) => {
            Status::new(
                ErrorName::ServerIdentityChanged,
                "The server presented another certificate than at the start of the connection",
            )
        }
        Some(
            rustls::Error::PeerIncompatible(_)
            | rustls::Error::AlertReceived(
                rustls::AlertDescription::ProtocolVersion | rustls::AlertDescription::HandshakeFailure,
            ),
        ) => Status::new(ErrorName::SecurityPolicy, "The server does not offer TLS 1.3")
            .with_detail(e.to_string()),
        Some(other) => {
            Status::new(ErrorName::ConnectionLost, "The TLS handshake failed").with_detail(other.to_string())
        }
        None => Status::new(ErrorName::ConnectionLost, "The TLS handshake failed").with_detail(e.to_string()),
    }
}

/// The addresses of `host`.
///
/// # Errors
/// `NetworkUnreachable` when the name does not resolve.
pub async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, Status> {
    let unresolved = |why: &str| {
        Status::new(ErrorName::NetworkUnreachable, format!("Cannot resolve the server name: {why}"))
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let found = tokio::net::lookup_host((bare, port)).await.map_err(|e| unresolved(&e.kind().to_string()))?;
    let addrs: Vec<SocketAddr> = found.collect();
    if addrs.is_empty() {
        return Err(unresolved("no address"));
    }
    Ok(addrs)
}

/// A TCP connection to the first of `addrs` that answers, within `timeout` in all.
///
/// # Errors
/// `Timeout` when the time is up, else `NetworkUnreachable` with the last failure.
pub async fn connect_tcp(addrs: &[SocketAddr], timeout: Duration) -> Result<TcpStream, Status> {
    let attempt = async {
        let mut last = String::from("no address");
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    // Small requests: no Nagle delay.
                    stream.set_nodelay(true).map_err(|e| unreachable(&e.to_string()))?;
                    return Ok(stream);
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(unreachable(&last))
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .map_err(|_elapsed| Status::new(ErrorName::Timeout, "The server did not answer in time"))?
}

fn unreachable(why: &str) -> Status {
    Status::new(ErrorName::NetworkUnreachable, "Cannot reach the server").with_detail(why)
}

#[cfg(test)]
mod tests;
