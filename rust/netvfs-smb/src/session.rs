// SPDX-License-Identifier: LGPL-2.1-or-later
//! Sign-in (NEGOTIATE, SESSION_SETUP) and the session-level requests:
//! TREE_CONNECT, TREE_DISCONNECT, ECHO.
//!
//! The session is the one connection's only one; every share is a tree
//! of it (design §5.1). Its keys come from the NTLM session key and the
//! preauth hash of every NEGOTIATE and SESSION_SETUP message; the final
//! SESSION_SETUP response must be signed with them (MS-SMB2 3.2.5.3.1),
//! which also proves that the server knows the password.

use std::time::Duration;

use netvfs_vfs::CancelToken;
use tokio::net::TcpStream;

use crate::auth::{Account, Authenticator, Step};
use crate::conn::{Conn, Element, Response, Target};
use crate::crypto::{Cipher, PreauthHash, TRANSFORM_HEADER_LEN, derive_session_keys};
use crate::error::{Result, policy, protocol};
use crate::msg::Command;
use crate::msg::negotiate::{NegotiateResponse, security_mode};
use crate::msg::session::{
    SetupResponse, check_four_byte_response, four_byte_request, session_flags, setup_request,
};
use crate::msg::tree::{TreeConnectResponse, share_flags};
use crate::negotiate::{Negotiated, Offer, check_response};
use crate::profile::Profile;
use crate::status::NtStatus;

/// SESSION_SETUP rounds before giving up (NTLM in SPNEGO needs two).
const MAX_SETUP_ROUNDS: usize = 4;
/// What a frame may hold beyond the largest READ or IOCTL output: headers,
/// a compound's other responses, the transform header.
const FRAME_SLACK: usize = 65_536 + TRANSFORM_HEADER_LEN;

/// XM-1: a session the server mapped to guest or anonymous.
pub const GUEST_MAPPED: &str = "the server signed this account in as a guest instead of checking the password; \
     the security profile does not allow that";
/// NEGOTIATE refused: no SMB 3.1.1 (M-T7, M-T9, M-T20).
pub const NO_SMB311: &str = "the server does not support SMB 3.1.1 (NEGOTIATE: NT status 0xc00000bb, \
     STATUS_NOT_SUPPORTED: no common dialect); servers limited to SMB 2.x or 3.0.x are refused";

/// A signed-in connection.
#[derive(Debug)]
pub struct Session {
    /// The connection.
    pub conn: Conn,
    /// The outcome of NEGOTIATE.
    pub negotiated: Negotiated,
    /// SessionFlags of the final SESSION_SETUP response.
    pub flags: u16,
}

/// A connected share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// TreeId.
    pub id: u32,
    /// The share demands encryption (ENCRYPT_DATA).
    pub encrypt: bool,
    /// ShareType.
    pub share_type: u8,
}

impl Tree {
    /// Where its requests go.
    #[must_use]
    pub const fn target(&self) -> Target {
        Target { tree_id: self.id, encrypt: self.encrypt }
    }
}

/// The ciphers offered, in order of preference.
pub const CIPHERS: [Cipher; 2] = [Cipher::Aes128Gcm, Cipher::Aes256Gcm];

/// Signs in on `stream`: NEGOTIATE, then SESSION_SETUP as `account` under
/// `profile`. `host` names the server in the NTLM target (`cifs/<host>`).
///
/// # Errors
/// A refusal of the profile's terms is [`Error::Policy`](crate::error::Error::Policy); the server's
/// refusals are [`Error::Status`](crate::error::Error::Status).
pub async fn sign_in(
    stream: TcpStream,
    profile: Profile,
    account: &Account,
    host: &str,
    timeout: Duration,
    cancel: &CancelToken,
) -> Result<Session> {
    let conn = Conn::start(stream, timeout);
    let result = async {
        let (negotiated, preauth) = negotiate(&conn, profile, cancel).await?;
        let flags = session_setup(&conn, profile, account, host, &negotiated, preauth, cancel).await?;
        Ok((negotiated, flags))
    }
    .await;
    match result {
        Ok((negotiated, flags)) => Ok(Session { conn, negotiated, flags }),
        Err(e) => {
            conn.abort();
            Err(e)
        }
    }
}

/// NEGOTIATE: SMB 3.1.1 and nothing else.
async fn negotiate(conn: &Conn, profile: Profile, cancel: &CancelToken) -> Result<(Negotiated, PreauthHash)> {
    let offer = Offer::new(profile.signs(), CIPHERS.to_vec())?;
    let (resp, sent) = conn.call_raw(Element::new(Command::Negotiate, offer.request()?), cancel).await?;
    // MS-SMB2 3.3.5.4: no common dialect. Only 3.1.1 is offered, so this is
    // a 2.x or 3.0.x server, or one with 3.1.1 switched off.
    if resp.status() == NtStatus::NOT_SUPPORTED {
        return Err(policy(NO_SMB311));
    }
    resp.ok()?;
    let mut preauth = PreauthHash::default();
    preauth.update(&sent);
    preauth.update(&resp.msg);
    let negotiated = check_response(&offer, &NegotiateResponse::decode(&resp.msg)?)?;
    if profile.encrypts() && negotiated.cipher.is_none() {
        return Err(policy(
            "profile strict needs encryption, but the server has no cipher in common (AES-GCM)",
        ));
    }
    let largest = negotiated.max_read.max(negotiated.max_transact).saturating_add(FRAME_SLACK);
    conn.set_limits(largest, negotiated.multi_credit);
    Ok((negotiated, preauth))
}

/// SESSION_SETUP rounds; returns the SessionFlags.
async fn session_setup(
    conn: &Conn,
    profile: Profile,
    account: &Account,
    host: &str,
    negotiated: &Negotiated,
    mut hash: PreauthHash,
    cancel: &CancelToken,
) -> Result<u16> {
    match (profile, account) {
        (Profile::Guest, Account::User { .. }) => {
            return Err(policy("profile guest signs in anonymously; no user name may be given"));
        }
        (Profile::Strict | Profile::Signed, Account::Anonymous) => {
            return Err(policy("anonymous sign-in is allowed only with profile guest"));
        }
        _ => {}
    }
    let (mut auth, mut token) = Authenticator::start(account, host)?;
    let mode = if profile.signs() { security_mode::SIGNING_REQUIRED } else { security_mode::SIGNING_ENABLED };
    let mode = u8::try_from(mode).map_err(|e| protocol(format!("security mode: {e}")))?;
    let mut session_id = 0u64;
    for _ in 0..MAX_SETUP_ROUNDS {
        let request = Element::new(Command::SessionSetup, setup_request(mode, &token)?);
        let (resp, sent) = conn.call_raw(request, cancel).await?;
        hash.update(&sent);
        let id = resp.header.session_id;
        if id == 0 || (session_id != 0 && id != session_id) {
            return Err(protocol("a SESSION_SETUP response with a missing or changed SessionId"));
        }
        session_id = id;
        conn.set_session_id(id);
        if resp.status() == NtStatus::SUCCESS {
            return finish(conn, profile, &mut auth, &hash, negotiated.cipher, &resp);
        }
        resp.expect(&[NtStatus::MORE_PROCESSING_REQUIRED])?;
        hash.update(&resp.msg);
        let setup = SetupResponse::decode(&resp.msg)?;
        token = match auth.step(&setup.token)? {
            Step::Continue(next) => next,
            Step::Done => return Err(policy("the server wants another sign-in round")),
        };
    }
    Err(policy("too many SESSION_SETUP rounds"))
}

/// The final SESSION_SETUP response: the profile's checks, the keys, the
/// signature.
fn finish(
    conn: &Conn,
    profile: Profile,
    auth: &mut Authenticator,
    hash: &PreauthHash,
    cipher: Option<Cipher>,
    resp: &Response,
) -> Result<u16> {
    let setup = SetupResponse::decode(&resp.msg)?;
    let flags = setup.session_flags;
    let wants_encryption = flags & session_flags::ENCRYPT_DATA != 0;
    if profile == Profile::Guest {
        auth.finish(&setup.token)?;
        if wants_encryption {
            return Err(policy("the server requires encryption, which a guest session cannot do"));
        }
        conn.establish(None, false);
        return Ok(flags);
    }
    // XM-1: never a guest or anonymous session in place of the account's
    // own; checked first, as such a session cannot sign its responses.
    if flags & (session_flags::IS_GUEST | session_flags::IS_NULL) != 0 {
        return Err(policy(GUEST_MAPPED));
    }
    let gss_key = auth.session_key()?;
    let keys = derive_session_keys(&gss_key, hash, cipher, resp.header.session_id)
        .map_err(|e| policy(format!("session keys: {e}")))?;
    // MS-SMB2 3.3.5.5.3: a 3.1.1 server signs the final response.
    if !resp.header.is_signed() {
        return Err(policy("the final SESSION_SETUP response is not signed"));
    }
    keys.signing.verify(&resp.msg).map_err(|e| policy(format!("the final SESSION_SETUP response: {e}")))?;
    // SPNEGO accept-completed with the server's mechListMIC (sspi checks it).
    auth.finish(&setup.token)?;
    let encrypt = profile.encrypts() || wants_encryption;
    if encrypt && keys.seal.is_none() {
        return Err(policy(format!(
            "the server marks the session for encryption (session flags 0x{flags:04X}) but no common cipher \
             was negotiated"
        )));
    }
    conn.establish(Some(keys), encrypt);
    Ok(flags)
}

/// TREE_CONNECT to `\\host\share`.
///
/// # Errors
/// [`Error::Status`](crate::error::Error::Status) (BAD_NETWORK_NAME for an unknown share), or
/// [`Error::Policy`](crate::error::Error::Policy) for a share that wants encryption the session cannot
/// do.
pub async fn tree_connect(conn: &Conn, host: &str, share: &str, cancel: &CancelToken) -> Result<Tree> {
    let unc: Vec<u16> = format!(r"\\{host}\{share}").encode_utf16().collect();
    let body = crate::msg::tree::request(&unc)?;
    let resp = conn.call(Target::SESSION, Element::new(Command::TreeConnect, body), cancel).await?;
    resp.ok()?;
    let tc = TreeConnectResponse::decode(&resp.msg)?;
    if resp.header.tree_id == 0 {
        return Err(protocol("a TREE_CONNECT response without a TreeId"));
    }
    let encrypt = tc.share_flags & share_flags::ENCRYPT_DATA != 0;
    if encrypt && !conn.can_encrypt() {
        return Err(policy("the share requires encryption, which this session cannot do"));
    }
    Ok(Tree { id: resp.header.tree_id, encrypt, share_type: tc.share_type })
}

/// TREE_DISCONNECT.
///
/// # Errors
/// The server's refusal, the connection's failures.
pub async fn tree_disconnect(conn: &Conn, tree: &Tree, cancel: &CancelToken) -> Result<()> {
    let resp =
        conn.call(tree.target(), Element::new(Command::TreeDisconnect, four_byte_request()), cancel).await?;
    resp.ok()?;
    check_four_byte_response(&resp.msg, "TREE_DISCONNECT")
}

/// ECHO (XM-8, XC-20).
///
/// # Errors
/// The server's refusal, the connection's failures.
pub async fn echo(conn: &Conn, cancel: &CancelToken) -> Result<()> {
    let resp = conn.call(Target::SESSION, Element::new(Command::Echo, four_byte_request()), cancel).await?;
    resp.ok()?;
    check_four_byte_response(&resp.msg, "ECHO")
}

#[cfg(test)]
mod tests;
