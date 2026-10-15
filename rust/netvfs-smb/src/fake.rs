// SPDX-License-Identifier: LGPL-2.1-or-later
//! A scripted server for the tests: the test reads each request and writes
//! the responses it wants, signed or sealed with the server's side of the
//! session keys.

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::crypto::{
    Cipher, OpenKey, PreauthHash, SealKey, SessionKeys, SigningKey, derive_session_keys, server_side_keys,
};
use crate::msg::file::FileId;
use crate::msg::{Command, HEADER_LEN, Header, build, flags, split_chain};
use crate::status::NtStatus;
use crate::transport::{frame, read_frame};
use crate::wire::Writer;

/// The GSS key of the tests' sessions.
pub const GSS_KEY: [u8; 16] = [0x5a; 16];
/// Their SessionId.
pub const SESSION_ID: u64 = 0x0000_4400_0000_0021;

/// A client socket and the server's end.
pub async fn pair() -> (TcpStream, Peer) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (client.unwrap(), Peer { stream: server.unwrap().0, keys: None })
}

/// The server's keys of a session.
pub struct ServerKeys {
    /// Signs responses, checks requests.
    pub signing: SigningKey,
    /// Seals responses.
    pub seal: Option<SealKey>,
    /// Opens requests.
    pub open: Option<OpenKey>,
}

/// The client's and the server's keys of one session.
pub fn session_keys(cipher: Option<Cipher>) -> (SessionKeys, ServerKeys) {
    let preauth = PreauthHash::default();
    let client = derive_session_keys(&GSS_KEY, &preauth, cipher, SESSION_ID).unwrap();
    let signing = derive_session_keys(&GSS_KEY, &preauth, None, SESSION_ID).unwrap().signing;
    let (seal, open) = match cipher {
        Some(c) => {
            let (seal, open) = server_side_keys(&GSS_KEY, &preauth, c, SESSION_ID).unwrap();
            (Some(seal), Some(open))
        }
        None => (None, None),
    };
    (client, ServerKeys { signing, seal, open })
}

/// One received request message.
#[derive(Debug, Clone)]
pub struct Req {
    /// Its header.
    pub header: Header,
    /// The message (padding included for a chain element).
    pub msg: Vec<u8>,
    /// It came in a transform.
    pub encrypted: bool,
}

impl Req {
    /// The command.
    pub fn command(&self) -> Command {
        Command::from_code(self.header.command).unwrap()
    }

    /// The body.
    pub fn body(&self) -> &[u8] {
        &self.msg[HEADER_LEN..]
    }
}

/// The server's end of the connection.
pub struct Peer {
    /// The socket.
    pub stream: TcpStream,
    /// Set once the session has keys.
    pub keys: Option<ServerKeys>,
}

impl Peer {
    /// The next frame, raw.
    pub async fn frame(&mut self) -> Vec<u8> {
        read_frame(&mut self.stream, 16 * 1024 * 1024).await.unwrap()
    }

    /// The requests of the next frame (opened when sealed, signatures
    /// checked when signed).
    pub async fn recv(&mut self) -> Vec<Req> {
        let raw = self.frame().await;
        let encrypted = raw.starts_with(&[0xFD, b'S', b'M', b'B']);
        let msg = if encrypted {
            self.keys.as_ref().unwrap().open.as_ref().unwrap().open(&raw).unwrap()
        } else {
            raw
        };
        split_chain(&msg)
            .unwrap()
            .into_iter()
            .map(|r| {
                let element = msg[r].to_vec();
                let header = Header::decode(&element).unwrap();
                assert!(!header.is_response());
                if header.is_signed() {
                    self.keys.as_ref().unwrap().signing.verify(&element).unwrap();
                }
                Req { header, msg: element, encrypted }
            })
            .collect()
    }

    /// The single request of the next frame.
    pub async fn recv_one(&mut self) -> Req {
        let mut reqs = self.recv().await;
        assert_eq!(reqs.len(), 1, "{reqs:?}");
        reqs.pop().unwrap()
    }

    /// Sends one frame as it is.
    pub async fn send_raw(&mut self, wire: &[u8]) {
        self.stream.write_all(&frame(wire).unwrap()).await.unwrap();
    }

    /// Sends messages as one frame, sealed when `seal`.
    pub async fn send(&mut self, msgs: &[Vec<u8>], seal: bool) {
        let chain: Vec<u8> = msgs.concat();
        let wire = if seal {
            self.keys.as_mut().unwrap().seal.as_mut().unwrap().seal(&chain).unwrap()
        } else {
            chain
        };
        self.send_raw(&wire).await;
    }

    /// Signs `msg` with the server's key (SIGNED set first).
    pub fn sign(&self, msg: &mut [u8]) {
        let f = u32::from_le_bytes(msg[16..20].try_into().unwrap()) | flags::SIGNED;
        msg[16..20].copy_from_slice(&f.to_le_bytes());
        self.keys.as_ref().unwrap().signing.sign(msg).unwrap();
    }
}

/// A response to `req` with `status`, `body` and `credits` granted.
pub fn response(req: &Req, status: NtStatus, body: &[u8], credits: u16) -> Vec<u8> {
    let mut h = req.header.clone();
    h.status = status;
    h.flags = flags::SERVER_TO_REDIR | (h.flags & flags::RELATED_OPERATIONS);
    h.credits = credits;
    h.next_command = 0;
    h.signature = [0; 16];
    if h.session_id == 0 && req.command() == Command::SessionSetup {
        h.session_id = SESSION_ID;
    }
    build(&h, body)
}

/// An ERROR response body (StructureSize 9).
pub fn error_body() -> Vec<u8> {
    vec![9, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// An error response.
pub fn error(req: &Req, status: NtStatus, credits: u16) -> Vec<u8> {
    response(req, status, &error_body(), credits)
}

/// An interim STATUS_PENDING response with `async_id`.
pub fn interim(req: &Req, async_id: u64, credits: u16) -> Vec<u8> {
    let mut h = req.header.clone();
    h.status = NtStatus::PENDING;
    h.flags = flags::SERVER_TO_REDIR | flags::ASYNC_COMMAND;
    h.async_id = Some(async_id);
    h.credits = credits;
    h.next_command = 0;
    h.signature = [0; 16];
    build(&h, &error_body())
}

/// Chains messages: pads each but the last to 8 bytes and sets
/// NextCommand (before any signing).
pub fn chain(mut msgs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let n = msgs.len();
    for m in msgs.iter_mut().take(n.saturating_sub(1)) {
        let padded = m.len().next_multiple_of(8);
        m.resize(padded, 0);
        m[20..24].copy_from_slice(&u32::try_from(padded).unwrap().to_le_bytes());
    }
    msgs
}

/// An ECHO response body.
pub fn four() -> Vec<u8> {
    vec![4, 0, 0, 0]
}

/// 2021-01-01T00:00:00Z as FILETIME.
pub const FT: u64 = 132_539_328_000_000_000;

/// A CREATE response body: times around [`FT`], `size`, `attributes` and
/// `file_id`.
pub fn created_body(attributes: u32, size: u64, file_id: FileId) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(89).u8(0).u8(0).u32(1);
    w.u64(FT + 10_000).u64(FT + 20_000).u64(FT).u64(FT);
    w.u64(size).u64(size).u32(attributes).u32(0).bytes(&file_id).u32(0).u32(0);
    w.into_vec()
}

/// A CLOSE response body without attributes.
pub fn close_body() -> Vec<u8> {
    let mut b = vec![0u8; 60];
    b[0] = 60;
    b
}

/// sspi's SPNEGO/NTLM acceptor for one account: the server's side of the
/// exchange, which yields the session key the client derives too.
pub struct Acceptor {
    ctx: sspi::Negotiate,
    creds: Option<sspi::CredentialsBuffers>,
}

impl Acceptor {
    /// An acceptor that knows `user` (in `domain`, may be empty) with
    /// `password`.
    pub fn new(user: &str, domain: &str, password: &str) -> Self {
        use sspi::Sspi;
        let identity = sspi::AuthIdentity {
            username: sspi::Username::new(user, (!domain.is_empty()).then_some(domain)).unwrap(),
            password: password.to_owned().into(),
        };
        let config = sspi::NegotiateConfig::new(
            Box::new(sspi::ntlm::NtlmConfig::default()),
            Some("ntlm".to_owned()),
            String::new(),
        );
        let mut ctx = sspi::Negotiate::new_server(config, vec![identity.clone()]).unwrap();
        let acquired = ctx
            .acquire_credentials_handle()
            .with_credential_use(sspi::CredentialUse::Inbound)
            .with_auth_data(&sspi::Credentials::AuthIdentity(identity))
            .execute(&mut ctx)
            .unwrap();
        Self { ctx, creds: acquired.credentials_handle }
    }

    /// The client's token in, the server's out.
    pub fn step(&mut self, token: &[u8]) -> Vec<u8> {
        use sspi::{Sspi, SspiImpl};
        let mut input = vec![sspi::SecurityBuffer::new(token.to_vec(), sspi::BufferType::Token)];
        let mut output = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
        let builder = self
            .ctx
            .accept_security_context()
            .with_credentials_handle(&mut self.creds)
            .with_context_requirements(sspi::ServerRequestFlags::empty())
            .with_target_data_representation(sspi::DataRepresentation::Native)
            .with_input(&mut input)
            .with_output(&mut output);
        self.ctx.accept_security_context_impl(builder).unwrap().resolve_to_result().unwrap();
        output.remove(0).buffer
    }

    /// The exported session key, once the exchange is complete.
    pub fn session_key(&mut self) -> Vec<u8> {
        use sspi::Sspi;
        self.ctx.query_context_session_key().unwrap().session_key.as_ref().clone()
    }
}
