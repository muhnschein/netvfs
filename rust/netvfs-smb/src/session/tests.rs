// SPDX-License-Identifier: LGPL-2.1-or-later
//! Sign-in against the scripted server: NEGOTIATE refusals, the guest
//! profile's anonymous exchange, the NTLM exchange with sspi's own acceptor
//! as the server's side (so the final response is signed with the session's
//! real key), TREE_CONNECT. tests/samba.rs runs the same against Samba.

use std::time::Duration;

use super::*;
use crate::crypto::server_side_keys;
use crate::error::Error;
use crate::fake::{self, Peer, Req, SESSION_ID, ServerKeys, error, four, pair};
use crate::msg::negotiate::tests::response as negotiate_message;
use crate::msg::negotiate::{DIALECT_311, ciphers, encryption_context, preauth_context, signing_context};
use crate::wire::Writer;

const T: Duration = Duration::from_secs(5);

/// The body of a NEGOTIATE response for `dialect` with `cipher` (0: no
/// encryption context).
fn negotiate_body(dialect: u16, cipher: u16) -> Vec<u8> {
    let mut contexts = vec![preauth_context(&[3; 32]), signing_context()];
    if cipher != 0 {
        contexts.push(encryption_context(&[cipher]).unwrap());
    }
    negotiate_message(dialect, &contexts)[64..].to_vec()
}

fn setup_body(flags: u16, token: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(9).u16(flags).u16(72).u16(u16::try_from(token.len()).unwrap()).bytes(token);
    w.into_vec()
}

fn challenge() -> Vec<u8> {
    let mut t = b"NTLMSSP\0".to_vec();
    t.extend_from_slice(&2u32.to_le_bytes());
    t
}

async fn answer_negotiate(peer: &mut Peer, cipher: u16) -> Req {
    let req = peer.recv_one().await;
    assert_eq!(req.command(), Command::Negotiate);
    peer.send(&[fake::response(&req, NtStatus::SUCCESS, &negotiate_body(DIALECT_311, cipher), 1)], false)
        .await;
    req
}

/// The anonymous exchange; the final response has `flags`.
async fn answer_anonymous(peer: &mut Peer, flags: u16) {
    let req = peer.recv_one().await;
    assert_eq!(req.command(), Command::SessionSetup);
    assert_eq!(req.body()[3], 0x01, "guest: signing enabled, not required");
    peer.send(
        &[fake::response(&req, NtStatus::MORE_PROCESSING_REQUIRED, &setup_body(0, &challenge()), 8)],
        false,
    )
    .await;
    let req = peer.recv_one().await;
    assert_eq!(req.header.session_id, SESSION_ID);
    assert!(req.body().windows(8).any(|w| w == b"NTLMSSP\0"));
    peer.send(&[fake::response(&req, NtStatus::SUCCESS, &setup_body(flags, &[]), 8)], false).await;
}

async fn guest_session(flags: u16) -> (Result<Session>, Peer) {
    let (client, mut peer) = pair().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(sign_in(client, Profile::Guest, &Account::Anonymous, "srv", T, &c), async {
        answer_negotiate(&mut peer, 0).await;
        answer_anonymous(&mut peer, flags).await;
    });
    (r, peer)
}

#[tokio::test]
async fn the_guest_profile_signs_in_anonymously_and_protects_nothing() {
    let (r, mut peer) = guest_session(session_flags::IS_GUEST | session_flags::IS_NULL).await;
    let s = r.unwrap();
    assert_eq!(s.flags, 3);
    assert_eq!(s.conn.session_id(), SESSION_ID);
    assert!(!s.conn.can_encrypt() && !s.conn.encrypts());
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(echo(&s.conn, &c), async {
        let req = peer.recv_one().await;
        assert!(!req.header.is_signed() && !req.encrypted);
        peer.send(&[fake::response(&req, NtStatus::SUCCESS, &four(), 1)], false).await;
    });
    r.unwrap();
}

#[tokio::test]
async fn a_guest_session_cannot_take_an_encrypting_session() {
    let (r, _peer) = guest_session(session_flags::ENCRYPT_DATA).await;
    let e = r.unwrap_err();
    assert!(matches!(e, Error::Policy(ref m) if m.contains("guest session cannot")), "{e}");
}

#[tokio::test]
async fn the_profile_and_the_account_must_match() {
    let c = CancelToken::new();
    let user = Account::User { user: "u".into(), domain: String::new(), password: "p".to_owned().into() };
    for (profile, account) in [(Profile::Guest, &user), (Profile::Signed, &Account::Anonymous)] {
        let (client, mut peer) = pair().await;
        let (r, _) =
            tokio::join!(sign_in(client, profile, account, "srv", T, &c), answer_negotiate(&mut peer, 0));
        assert!(matches!(r, Err(Error::Policy(_))), "{profile:?}: {r:?}");
    }
}

#[tokio::test]
async fn the_offer_is_smb_311_with_gcm_and_cmac() {
    let (client, mut peer) = pair().await;
    let c = CancelToken::new();
    let user = Account::User { user: "u".into(), domain: String::new(), password: "p".to_owned().into() };
    let (r, ()) = tokio::join!(sign_in(client, Profile::Strict, &user, "srv", T, &c), async {
        let req = peer.recv_one().await;
        let body = req.body();
        // One dialect, 3.1.1; signing required.
        assert_eq!(&body[2..6], &[1, 0, 0x03, 0]);
        assert_eq!(&body[36..38], &[0x11, 0x03]);
        // The encryption context: AES-128-GCM, then AES-256-GCM.
        assert!(body.windows(10).any(|w| w == [0x02, 0x00, 0x06, 0x00, 0, 0, 0, 0, 0x02, 0x00]));
        assert!(body.windows(4).any(|w| w == [0x02, 0x00, 0x04, 0x00]));
        peer.send(&[error(&req, NtStatus::NOT_SUPPORTED, 1)], false).await;
    });
    assert_eq!(r.unwrap_err(), Error::Policy(NO_SMB311.into()));
}

#[tokio::test]
async fn negotiate_refusals() {
    let c = CancelToken::new();
    let user = Account::User { user: "u".into(), domain: String::new(), password: "p".to_owned().into() };
    // 3.0.2 is not what was offered; strict needs a cipher; a server error.
    for (dialect, cipher, profile, status, what) in [
        (0x0302, ciphers::AES128_GCM, Profile::Signed, NtStatus::SUCCESS, "only SMB 3.1.1"),
        (DIALECT_311, 0, Profile::Strict, NtStatus::SUCCESS, "no cipher in common"),
        (DIALECT_311, ciphers::AES128_GCM, Profile::Signed, NtStatus::ACCESS_DENIED, ""),
    ] {
        let (client, mut peer) = pair().await;
        let (r, ()) = tokio::join!(sign_in(client, profile, &user, "srv", T, &c), async {
            let req = peer.recv_one().await;
            let msg = if status == NtStatus::SUCCESS {
                fake::response(&req, status, &negotiate_body(dialect, cipher), 1)
            } else {
                error(&req, status, 1)
            };
            peer.send(&[msg], false).await;
        });
        let e = r.unwrap_err();
        if what.is_empty() {
            assert_eq!(e, Error::Status(status));
        } else {
            assert!(matches!(e, Error::Policy(ref m) if m.contains(what)), "{e}");
        }
    }
}

#[tokio::test]
async fn the_server_closing_during_sign_in_is_a_lost_connection() {
    let (client, mut peer) = pair().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(sign_in(client, Profile::Guest, &Account::Anonymous, "srv", T, &c), async {
        answer_negotiate(&mut peer, 0).await;
        drop(peer.recv_one().await);
        drop(peer);
    });
    assert_eq!(r.unwrap_err(), Error::Lost("the server closed the connection".into()));
}

#[tokio::test]
async fn session_setup_ids_and_rounds() {
    // A response without a SessionId; then one that changes it.
    for change in [0u64, 99] {
        let (client, mut peer) = pair().await;
        let c = CancelToken::new();
        let (r, ()) =
            tokio::join!(sign_in(client, Profile::Guest, &Account::Anonymous, "srv", T, &c), async {
                answer_negotiate(&mut peer, 0).await;
                let req = peer.recv_one().await;
                let mut msg =
                    fake::response(&req, NtStatus::MORE_PROCESSING_REQUIRED, &setup_body(0, &challenge()), 8);
                if change == 0 {
                    msg[40..48].fill(0);
                    peer.send(&[msg], false).await;
                    return;
                }
                peer.send(&[msg], false).await;
                let mut req = peer.recv_one().await;
                req.header.session_id = change;
                peer.send(&[fake::response(&req, NtStatus::SUCCESS, &setup_body(0, &[]), 8)], false).await;
            });
        assert!(matches!(r, Err(Error::Protocol(ref m)) if m.contains("SessionId")), "{r:?}");
    }
    // A third round for anonymous: refused.
    let (client, mut peer) = pair().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(sign_in(client, Profile::Guest, &Account::Anonymous, "srv", T, &c), async {
        answer_negotiate(&mut peer, 0).await;
        for _ in 0..2 {
            let req = peer.recv_one().await;
            peer.send(
                &[fake::response(&req, NtStatus::MORE_PROCESSING_REQUIRED, &setup_body(0, &challenge()), 8)],
                false,
            )
            .await;
        }
    });
    assert!(matches!(r, Err(Error::Policy(ref m)) if m.contains("another round")), "{r:?}");
    // A refusal.
    let (client, mut peer) = pair().await;
    let (r, ()) = tokio::join!(sign_in(client, Profile::Guest, &Account::Anonymous, "srv", T, &c), async {
        answer_negotiate(&mut peer, 0).await;
        let req = peer.recv_one().await;
        let mut msg = error(&req, NtStatus::LOGON_FAILURE, 1);
        msg[40..48].copy_from_slice(&SESSION_ID.to_le_bytes());
        peer.send(&[msg], false).await;
    });
    assert_eq!(r.unwrap_err(), Error::Status(NtStatus::LOGON_FAILURE));
}

const USER: &str = "alice";
const PASSWORD: &str = "correct horse";

fn user() -> Account {
    Account::User { user: USER.into(), domain: String::new(), password: PASSWORD.to_owned().into() }
}

/// sspi's SPNEGO/NTLM acceptor for `USER` and `PASSWORD`: the server's side
/// of the exchange, which yields the session key the client derives too.
struct Acceptor {
    ctx: sspi::Negotiate,
    creds: Option<sspi::CredentialsBuffers>,
}

impl Acceptor {
    fn new() -> Self {
        use sspi::Sspi;
        let identity = sspi::AuthIdentity {
            username: sspi::Username::new(USER, None).unwrap(),
            password: PASSWORD.to_owned().into(),
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
    fn step(&mut self, token: &[u8]) -> Vec<u8> {
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

    fn session_key(&mut self) -> Vec<u8> {
        use sspi::Sspi;
        self.ctx.query_context_session_key().unwrap().session_key.as_ref().clone()
    }
}

/// The security token of a SESSION_SETUP request.
fn setup_token(req: &Req) -> Vec<u8> {
    let body = req.body();
    let offset = usize::from(u16::from_le_bytes([body[12], body[13]]));
    let len = usize::from(u16::from_le_bytes([body[14], body[15]]));
    req.msg[offset..][..len].to_vec()
}

/// How the server sends the final SESSION_SETUP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Final {
    /// Signed with the session's signing key.
    Signed,
    /// Neither flagged nor signed.
    Unsigned,
    /// Flagged signed, one signature bit flipped.
    BadSignature,
    /// Signed, but without the SPNEGO token (no mechListMIC).
    NoToken,
}

/// NTLM sign-in with `profile` against a server that negotiates `cipher`
/// (0: none) and ends SESSION_SETUP with session `flags`, sent as `how`. The
/// server keeps the preauth hash and derives the keys on its side.
async fn ntlm_session(profile: Profile, cipher: u16, flags: u16, how: Final) -> (Result<Session>, Peer) {
    let (client, mut peer) = pair().await;
    let c = CancelToken::new();
    let account = user();
    let (r, ()) = tokio::join!(sign_in(client, profile, &account, "srv", T, &c), async {
        let mut hash = PreauthHash::default();
        let req = peer.recv_one().await;
        let resp = fake::response(&req, NtStatus::SUCCESS, &negotiate_body(DIALECT_311, cipher), 1);
        hash.update(&req.msg);
        hash.update(&resp);
        peer.send(&[resp], false).await;
        let mut acceptor = Acceptor::new();
        let req = peer.recv_one().await;
        assert_eq!(req.body()[3], 0x02, "signing required");
        let challenge = acceptor.step(&setup_token(&req));
        let resp = fake::response(&req, NtStatus::MORE_PROCESSING_REQUIRED, &setup_body(0, &challenge), 8);
        hash.update(&req.msg);
        hash.update(&resp);
        peer.send(&[resp], false).await;
        let req = peer.recv_one().await;
        assert_eq!(req.header.session_id, SESSION_ID);
        hash.update(&req.msg);
        let accepted = acceptor.step(&setup_token(&req));
        let token = if how == Final::NoToken { Vec::new() } else { accepted };
        let mut resp = fake::response(&req, NtStatus::SUCCESS, &setup_body(flags, &token), 8);
        let key = acceptor.session_key();
        let cipher = match cipher {
            ciphers::AES128_GCM => Some(Cipher::Aes128Gcm),
            ciphers::AES256_GCM => Some(Cipher::Aes256Gcm),
            _ => None,
        };
        let signing = derive_session_keys(&key, &hash, None, SESSION_ID).unwrap().signing;
        let (seal, open) = cipher.map(|c| server_side_keys(&key, &hash, c, SESSION_ID).unwrap()).unzip();
        peer.keys = Some(ServerKeys { signing, seal, open });
        match how {
            Final::Unsigned => {}
            Final::Signed | Final::NoToken => peer.sign(&mut resp),
            Final::BadSignature => {
                peer.sign(&mut resp);
                resp[63] ^= 0x80;
            }
        }
        peer.send(&[resp], false).await;
    });
    (r, peer)
}

/// One ECHO on `s`, answered as the session's protection requires.
async fn echo_round_trip(s: &Session, peer: &mut Peer, encrypted: bool) {
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(echo(&s.conn, &c), async {
        let req = peer.recv_one().await;
        assert_eq!(req.encrypted, encrypted);
        assert_eq!(req.header.is_signed(), !encrypted);
        let mut resp = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
        if !encrypted {
            peer.sign(&mut resp);
        }
        peer.send(&[resp], encrypted).await;
    });
    r.unwrap();
}

#[tokio::test]
async fn ntlm_sign_in_signs_or_seals_as_the_profile_says() {
    // signed: signing only; strict: sealing with either cipher; signed on a
    // session the server marks ENCRYPT_DATA: sealing.
    for (profile, cipher, flags, encrypted) in [
        (Profile::Signed, ciphers::AES128_GCM, 0, false),
        (Profile::Strict, ciphers::AES128_GCM, 0, true),
        (Profile::Strict, ciphers::AES256_GCM, 0, true),
        (Profile::Signed, ciphers::AES256_GCM, session_flags::ENCRYPT_DATA, true),
    ] {
        let (r, mut peer) = ntlm_session(profile, cipher, flags, Final::Signed).await;
        let s = r.unwrap();
        assert_eq!(s.flags, flags);
        assert_eq!(s.conn.session_id(), SESSION_ID);
        assert_eq!(s.conn.encrypts(), encrypted, "{profile:?} {cipher}");
        echo_round_trip(&s, &mut peer, encrypted).await;
    }
}

#[tokio::test]
async fn ntlm_final_response_refusals() {
    let policy_error = |r: Result<Session>| match r {
        Err(Error::Policy(m)) => m,
        other => panic!("{other:?}"),
    };
    // XM-1: a guest or anonymous session for an account.
    for flags in [session_flags::IS_GUEST, session_flags::IS_NULL] {
        let (r, _peer) = ntlm_session(Profile::Signed, ciphers::AES128_GCM, flags, Final::Signed).await;
        assert_eq!(policy_error(r), GUEST_MAPPED);
    }
    for (how, what) in [
        (Final::Unsigned, "the final SESSION_SETUP response is not signed"),
        (Final::BadSignature, "the final SESSION_SETUP response: message signature does not verify"),
        (Final::NoToken, "the server's final SPNEGO token is missing (no mechListMIC)"),
    ] {
        let (r, _peer) = ntlm_session(Profile::Strict, ciphers::AES128_GCM, 0, how).await;
        assert_eq!(policy_error(r), what, "{how:?}");
    }
    // A session marked for encryption without a common cipher.
    let (r, _peer) = ntlm_session(Profile::Signed, 0, session_flags::ENCRYPT_DATA, Final::Signed).await;
    let m = policy_error(r);
    assert!(m.contains("marks the session for encryption") && m.contains("0x0004"), "{m}");
}

fn tree_body(share_type: u8, flags: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(16).u8(share_type).u8(0).u32(flags).u32(0).u32(0x001F_01FF);
    w.into_vec()
}

#[tokio::test]
async fn tree_connect_and_disconnect() {
    let (r, mut peer) = guest_session(0).await;
    let s = r.unwrap();
    let c = CancelToken::new();
    let (r, mut peer) = tokio::join!(tree_connect(&s.conn, "srv", "Backups ü", &c), async {
        let req = peer.recv_one().await;
        assert_eq!(req.command(), Command::TreeConnect);
        let path: Vec<u8> = r"\\srv\Backups ü".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(req.body().ends_with(&path));
        let mut answer = req.clone();
        answer.header.tree_id = 7;
        peer.send(&[fake::response(&answer, NtStatus::SUCCESS, &tree_body(1, 0), 1)], false).await;
        peer
    });
    let tree = r.unwrap();
    assert_eq!(tree, Tree { id: 7, encrypt: false, share_type: 1 });
    assert_eq!(tree.target(), Target { tree_id: 7, encrypt: false });
    let (r, mut peer) = tokio::join!(tree_disconnect(&s.conn, &tree, &c), async {
        let req = peer.recv_one().await;
        assert_eq!((req.command(), req.header.tree_id), (Command::TreeDisconnect, 7));
        peer.send(&[fake::response(&req, NtStatus::SUCCESS, &four(), 1)], false).await;
        peer
    });
    r.unwrap();
    // An unknown share; a share that wants encryption; no TreeId.
    let (r, mut peer) = tokio::join!(tree_connect(&s.conn, "srv", "nope", &c), async {
        let req = peer.recv_one().await;
        peer.send(&[error(&req, NtStatus::BAD_NETWORK_NAME, 1)], false).await;
        peer
    });
    assert_eq!(r.unwrap_err(), Error::Status(NtStatus::BAD_NETWORK_NAME));
    let (r, mut peer) = tokio::join!(tree_connect(&s.conn, "srv", "enc", &c), async {
        let req = peer.recv_one().await;
        let mut answer = req.clone();
        answer.header.tree_id = 8;
        peer.send(
            &[fake::response(&answer, NtStatus::SUCCESS, &tree_body(1, share_flags::ENCRYPT_DATA), 1)],
            false,
        )
        .await;
        peer
    });
    assert!(matches!(r, Err(Error::Policy(ref m)) if m.contains("requires encryption")), "{r:?}");
    let (r, ()) = tokio::join!(tree_connect(&s.conn, "srv", "x", &c), async {
        let req = peer.recv_one().await;
        peer.send(&[fake::response(&req, NtStatus::SUCCESS, &tree_body(1, 0), 1)], false).await;
    });
    assert!(matches!(r, Err(Error::Protocol(ref m)) if m.contains("TreeId")), "{r:?}");
}
