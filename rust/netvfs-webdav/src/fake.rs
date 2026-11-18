// SPDX-License-Identifier: LGPL-2.1-or-later
//! A WebDAV server in memory over TLS 1.3, for tests: enough of RFC 4918 for the backend, plus knobs for the
//! odd servers (no ranges, no keep-alive, canned answers).
#![allow(
    clippy::arithmetic_side_effects,
    clippy::format_push_string,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::significant_drop_tightening,
    reason = "tests"
)]

use crate::paths::{decode, encode, href_path};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub const CA: &[u8] = include_bytes!("../../netvfs-tls/testdata/ca.der");
pub const LEAF: &[u8] = include_bytes!("../../netvfs-tls/testdata/leaf.der");
const LEAF_KEY: &[u8] = include_bytes!("../../netvfs-tls/testdata/leaf.key.der");
pub const SELF: &[u8] = include_bytes!("../../netvfs-tls/testdata/self.der");
const SELF_KEY: &[u8] = include_bytes!("../../netvfs-tls/testdata/self.key.der");

/// Last modified of every node: Sun, 06 Nov 1994 08:49:37 GMT.
pub const MTIME_MS: i64 = 784_111_777_000;
const MTIME: &str = "Sun, 06 Nov 1994 08:49:37 GMT";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Dir,
    File(Vec<u8>),
}

/// One request as the server saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: Method,
    pub path: Vec<u8>,
    pub headers: HeaderMap,
}

#[derive(Debug, Default)]
pub struct State {
    /// Decoded paths without trailing `/`; "" is the root.
    pub tree: BTreeMap<Vec<u8>, Node>,
    pub seen: Vec<Seen>,
    /// `Authorization` every request must carry, if set.
    pub auth: Option<String>,
    /// Ignore `Range`.
    pub no_ranges: bool,
    /// Close the connection after each answer.
    pub close: bool,
    /// Canned answers by method, used once each, in order.
    pub canned: Vec<(Method, StatusCode, Vec<(&'static str, &'static str)>, &'static str)>,
    /// Quota props on PROPFIND, as text.
    pub quota: Option<(&'static str, &'static str)>,
    /// Connections accepted.
    pub connections: usize,
    /// A connection that served this many requests drops the next one unanswered, as a server closing an idle
    /// connection just when a request arrives.
    pub drop_after: Option<usize>,
    /// Every request on this path (no trailing `/`) is answered 403.
    pub forbidden: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Fake {
    pub state: Arc<Mutex<State>>,
    pub addr: SocketAddr,
}

/// The certificate the server presents.
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
    let mut config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(c.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.to_vec())),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// TLS for a hand-scripted server.
pub fn acceptor(cert: Cert) -> TlsAcceptor {
    TlsAcceptor::from(config(cert))
}

impl Fake {
    /// A server with an empty root folder.
    pub async fn start(cert: Cert) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut state = State::default();
        state.tree.insert(Vec::new(), Node::Dir);
        let state = Arc::new(Mutex::new(state));
        let acceptor = TlsAcceptor::from(config(cert));
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                shared.lock().unwrap().connections += 1;
                let acceptor = acceptor.clone();
                let state = Arc::clone(&shared);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                    let service = service_fn(move |req| {
                        let state = Arc::clone(&state);
                        let n = served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        async move {
                            if state.lock().unwrap().drop_after.is_some_and(|d| n >= d) {
                                return Err("dropped");
                            }
                            Ok(handle(&state, req).await)
                        }
                    });
                    http1::Builder::new().serve_connection(TokioIo::new(tls), service).await.ok();
                });
            }
        });
        Self { state, addr }
    }

    pub fn put(&self, path: &str, node: Node) {
        self.state.lock().unwrap().tree.insert(path.as_bytes().to_vec(), node);
    }

    pub fn get(&self, path: &str) -> Option<Node> {
        self.state.lock().unwrap().tree.get(path.as_bytes()).cloned()
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    pub fn methods(&self) -> Vec<String> {
        self.seen().iter().map(|s| s.method.to_string()).collect()
    }

    pub fn clear_seen(&self) {
        self.state.lock().unwrap().seen.clear();
    }

    pub fn with(&self, f: impl FnOnce(&mut State)) {
        f(&mut self.state.lock().unwrap());
    }
}

type Answer = Response<Full<Bytes>>;

fn answer(code: StatusCode, body: impl Into<Bytes>) -> Answer {
    Response::builder().status(code).body(Full::new(body.into())).unwrap()
}

fn parent(path: &[u8]) -> Vec<u8> {
    path.iter().rposition(|b| *b == b'/').map_or_else(Vec::new, |at| path[..at].to_vec())
}

fn props(path: &[u8], node: &Node, quota: Option<(&str, &str)>) -> String {
    let href = encode(&[path, if *node == Node::Dir { b"/" } else { b"" }].concat());
    let href = if href == "//" { "/".to_owned() } else { href };
    let mut p = String::new();
    match node {
        Node::Dir => p.push_str("<d:resourcetype><d:collection/></d:resourcetype>"),
        Node::File(data) => {
            p.push_str("<d:resourcetype/>");
            p.push_str(&format!("<d:getcontentlength>{}</d:getcontentlength>", data.len()));
            p.push_str("<d:getcontenttype>application/octet-stream</d:getcontenttype>");
            p.push_str(&format!("<d:getetag>\"{}\"</d:getetag>", data.len()));
        }
    }
    p.push_str(&format!("<d:getlastmodified>{MTIME}</d:getlastmodified>"));
    if let Some((available, used)) = quota {
        p.push_str(&format!(
            "<d:quota-available-bytes>{available}</d:quota-available-bytes><d:quota-used-bytes>{used}</d:quota-used-bytes>"
        ));
    }
    format!(
        "<d:response><d:href>{href}</d:href><d:propstat><d:prop>{p}</d:prop>\
         <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )
}

fn key(path: &[u8]) -> Vec<u8> {
    path.strip_suffix(b"/").unwrap_or(path).to_vec()
}

fn byte_range(headers: &HeaderMap, len: usize) -> Option<Result<(usize, usize), ()>> {
    let value = headers.get(header::RANGE)?.to_str().ok()?;
    let (first, last) = value.strip_prefix("bytes=")?.split_once('-')?;
    let first: usize = first.parse().ok()?;
    if first >= len {
        return Some(Err(()));
    }
    let last = if last.is_empty() { len - 1 } else { last.parse::<usize>().ok()?.min(len - 1) };
    Some(Ok((first, last)))
}

async fn handle(state: &Mutex<State>, req: Request<Incoming>) -> Answer {
    let (head, body) = req.into_parts();
    // A body cut short (the client gave up) changes nothing.
    let Ok(body) = body.collect().await.map(http_body_util::Collected::to_bytes) else {
        return answer(StatusCode::BAD_REQUEST, "");
    };
    let path = decode(head.uri.path().as_bytes()).unwrap();
    let mut s = state.lock().unwrap();
    s.seen.push(Seen { method: head.method.clone(), path: path.clone(), headers: head.headers.clone() });
    let mut out = respond(&mut s, &head.method, &path, &head.headers, &body);
    if s.close {
        out.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    out
}

fn respond(s: &mut State, method: &Method, path: &[u8], headers: &HeaderMap, body: &Bytes) -> Answer {
    if let Some(at) = s.canned.iter().position(|(m, ..)| m == method) {
        let (_, code, extra, text) = s.canned.remove(at);
        let mut out = answer(code, text);
        for (k, v) in extra {
            out.headers_mut().insert(k, HeaderValue::from_static(v));
        }
        return out;
    }
    if let Some(want) = &s.auth
        && headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some(want.as_str())
    {
        return answer(StatusCode::UNAUTHORIZED, "who?");
    }
    let k = key(path);
    if s.forbidden.as_ref() == Some(&k) {
        return answer(StatusCode::FORBIDDEN, "");
    }
    match method.as_str() {
        "OPTIONS" => {
            let mut out = answer(StatusCode::OK, "");
            out.headers_mut().insert("dav", HeaderValue::from_static("1, 2"));
            out
        }
        "PROPFIND" => propfind(s, &k, headers),
        "MKCOL" => mkcol(s, k),
        "DELETE" => delete(s, &k),
        "PUT" => put(s, k, headers, body),
        "GET" => get(s, &k, headers),
        "MOVE" | "COPY" => transfer(s, &k, method.as_str() == "MOVE", headers),
        _ => answer(StatusCode::NOT_IMPLEMENTED, ""),
    }
}

fn propfind(s: &State, k: &[u8], headers: &HeaderMap) -> Answer {
    let Some(node) = s.tree.get(k).cloned() else { return answer(StatusCode::NOT_FOUND, "") };
    let mut xml = props(k, &node, s.quota);
    if node == Node::Dir && headers.get("depth").is_some_and(|d| d == "1") {
        let prefix = [k, b"/"].concat();
        for (p, n) in &s.tree {
            if let Some(rest) = p.strip_prefix(prefix.as_slice())
                && !rest.is_empty()
                && !rest.contains(&b'/')
            {
                xml.push_str(&props(p, n, None));
            }
        }
    }
    let body = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">{xml}</d:multistatus>"#
    );
    answer(StatusCode::MULTI_STATUS, body)
}

fn mkcol(s: &mut State, k: Vec<u8>) -> Answer {
    if s.tree.contains_key(&k) {
        answer(StatusCode::METHOD_NOT_ALLOWED, "")
    } else if s.tree.get(&parent(&k)) != Some(&Node::Dir) {
        answer(StatusCode::CONFLICT, "")
    } else {
        s.tree.insert(k, Node::Dir);
        answer(StatusCode::CREATED, "")
    }
}

fn delete(s: &mut State, k: &[u8]) -> Answer {
    if !s.tree.contains_key(k) {
        return answer(StatusCode::NOT_FOUND, "");
    }
    let prefix = [k, b"/"].concat();
    s.tree.retain(|p, _| p != k && !p.starts_with(&prefix));
    answer(StatusCode::NO_CONTENT, "")
}

fn put(s: &mut State, k: Vec<u8>, headers: &HeaderMap, body: &Bytes) -> Answer {
    match s.tree.get(&k) {
        Some(Node::Dir) => answer(StatusCode::METHOD_NOT_ALLOWED, ""),
        Some(_) if headers.get(header::IF_NONE_MATCH).is_some_and(|v| v == "*") => {
            answer(StatusCode::PRECONDITION_FAILED, "")
        }
        existing => {
            if s.tree.get(&parent(&k)) != Some(&Node::Dir) {
                return answer(StatusCode::CONFLICT, "");
            }
            let code = if existing.is_some() { StatusCode::NO_CONTENT } else { StatusCode::CREATED };
            s.tree.insert(k, Node::File(body.to_vec()));
            answer(code, "")
        }
    }
}

fn get(s: &State, k: &[u8], headers: &HeaderMap) -> Answer {
    match s.tree.get(k).cloned() {
        None => answer(StatusCode::NOT_FOUND, ""),
        Some(Node::Dir) => answer(StatusCode::OK, "<html>index</html>"),
        Some(Node::File(data)) => match byte_range(headers, data.len()) {
            Some(Ok((first, last))) if !s.no_ranges => {
                let mut out = answer(StatusCode::PARTIAL_CONTENT, data[first..=last].to_vec());
                let cr = format!("bytes {first}-{last}/{}", data.len());
                out.headers_mut().insert(header::CONTENT_RANGE, HeaderValue::from_str(&cr).unwrap());
                out
            }
            Some(Err(())) if !s.no_ranges => answer(StatusCode::RANGE_NOT_SATISFIABLE, ""),
            _ => answer(StatusCode::OK, data),
        },
    }
}

/// MOVE (`remove` the source) or COPY.
fn transfer(s: &mut State, k: &[u8], remove: bool, headers: &HeaderMap) -> Answer {
    let Some(dest) = headers.get("destination").and_then(|d| href_path(d.as_bytes())) else {
        return answer(StatusCode::BAD_REQUEST, "");
    };
    let dk = key(&dest);
    let overwrite = headers.get("overwrite").is_none_or(|o| o == "T");
    if !s.tree.contains_key(k) {
        return answer(StatusCode::NOT_FOUND, "");
    }
    if s.tree.get(&parent(&dk)) != Some(&Node::Dir) {
        return answer(StatusCode::CONFLICT, "");
    }
    let existed = s.tree.contains_key(&dk);
    if existed && !overwrite {
        return answer(StatusCode::PRECONDITION_FAILED, "");
    }
    let dprefix = [dk.as_slice(), b"/"].concat();
    s.tree.retain(|p, _| *p != dk && !p.starts_with(&dprefix));
    let prefix = [k, b"/"].concat();
    let moved: Vec<(Vec<u8>, Node)> = s
        .tree
        .iter()
        .filter(|(p, _)| p.as_slice() == k || p.starts_with(&prefix))
        .map(|(p, n)| ([dk.as_slice(), &p[k.len()..]].concat(), n.clone()))
        .collect();
    if remove {
        s.tree.retain(|p, _| p != k && !p.starts_with(&prefix));
    }
    s.tree.extend(moved);
    answer(if existed { StatusCode::NO_CONTENT } else { StatusCode::CREATED }, "")
}
