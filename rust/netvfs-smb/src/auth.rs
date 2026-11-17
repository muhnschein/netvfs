// SPDX-License-Identifier: LGPL-2.1-or-later
//! SESSION_SETUP security tokens.
//!
//! - Users: SPNEGO and NTLMv2 by `sspi`'s `Negotiate` package limited to NTLM (`package_list = "ntlm"`: no Kerberos, no KDC lookup, no krb5.conf or environment reads). Tokens pass through; sspi does the NTLMv2 response, MIC, mechListMIC (and verifies the server's), session key.
//! - Guest profile: NTLMSSP anonymous (MS-NLMP 3.1.5.1.2), built here: no key, no crypto (empty NT response, one zero byte LM response). sspi refuses an empty user name.

use std::fmt;

use netvfs_vfs::{ErrorName, Status};
use sspi::ntlm::NtlmConfig;
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, CredentialsBuffers, DataRepresentation,
    Negotiate, NegotiateConfig, SecurityBuffer, SecurityStatus, Sspi, SspiImpl, Username,
};
use zeroize::Zeroizing;

use crate::error::{Error, Result, policy};
use crate::wire::Reader;

/// Account credentials.
pub enum Account {
    /// A user account (NTLMv2).
    User {
        /// User name.
        user: String,
        /// Domain or workgroup, may be empty.
        domain: String,
        /// Password.
        password: Zeroizing<String>,
    },
    /// Anonymous (guest profile only).
    Anonymous,
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User { user, domain, .. } => {
                f.debug_struct("User").field("user", user).field("domain", domain).finish_non_exhaustive()
            }
            Self::Anonymous => f.write_str("Anonymous"),
        }
    }
}

/// Result of one authentication step.
#[derive(Debug)]
pub enum Step {
    /// Send this token in the next SESSION_SETUP request.
    Continue(Vec<u8>),
    /// The mechanism is done on our side.
    Done,
}

/// One authentication exchange.
pub enum Authenticator {
    /// NTLMv2 in SPNEGO through sspi.
    Ntlm(Box<NtlmSpnego>),
    /// NTLMSSP anonymous.
    Anonymous(AnonymousState),
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ntlm(_) => f.write_str("Authenticator::Ntlm"),
            Self::Anonymous(s) => write!(f, "Authenticator::Anonymous({s:?})"),
        }
    }
}

impl Authenticator {
    /// Starts an exchange; returns the authenticator and the first token.
    ///
    /// # Errors
    /// sspi refuses the credentials (e.g. an empty user name).
    pub fn start(account: &Account, target_host: &str) -> Result<(Self, Vec<u8>)> {
        match account {
            Account::User { user, domain, password } => {
                let (ntlm, token) = NtlmSpnego::start(user, domain, password, target_host)?;
                Ok((Self::Ntlm(Box::new(ntlm)), token))
            }
            Account::Anonymous => Ok((Self::Anonymous(AnonymousState::SentNegotiate), anonymous_negotiate())),
        }
    }

    /// Processes a server token from a STATUS_MORE_PROCESSING_REQUIRED response.
    ///
    /// # Errors
    /// Malformed token, NTLM failure.
    pub fn step(&mut self, server_token: &[u8]) -> Result<Step> {
        match self {
            Self::Ntlm(n) => n.step(server_token),
            Self::Anonymous(s) => {
                if *s != AnonymousState::SentNegotiate {
                    return Err(policy("anonymous sign-in: the server wants another round"));
                }
                check_challenge(server_token)?;
                *s = AnonymousState::SentAuthenticate;
                Ok(Step::Continue(anonymous_authenticate()))
            }
        }
    }

    /// Processes the token of the final STATUS_SUCCESS response. For NTLM in SPNEGO this
    /// verifies the server's mechListMIC; an absent MIC fails.
    ///
    /// # Errors
    /// The exchange is not complete afterwards.
    pub fn finish(&mut self, server_token: &[u8]) -> Result<()> {
        match self {
            Self::Ntlm(n) => n.finish(server_token),
            Self::Anonymous(s) if *s == AnonymousState::SentAuthenticate => Ok(()),
            Self::Anonymous(_) => Err(policy("anonymous sign-in: the exchange is incomplete")),
        }
    }

    /// The exported GSS session key (NTLM: 16 bytes). Anonymous has none.
    ///
    /// # Errors
    /// Not available.
    pub fn session_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Ntlm(n) => n.session_key(),
            Self::Anonymous(_) => Err(policy("anonymous sessions have no session key")),
        }
    }
}

/// sspi's SPNEGO/NTLM client context.
pub struct NtlmSpnego {
    ctx: Negotiate,
    creds: Option<CredentialsBuffers>,
    target: String,
    complete: bool,
}

impl fmt::Debug for NtlmSpnego {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmSpnego")
            .field("target", &self.target)
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

/// User name for which sspi skips the SPNEGO mechListMIC check.
const SSPI_GUEST_USER: &str = "/GUEST";

/// A failure inside sspi: sign-in cannot be trusted.
fn sspi_err(e: &sspi::Error) -> Error {
    policy(format!("NTLM sign-in failed: {:?}: {}", e.error_type, e.description))
}

/// Credentials this client refuses to use.
fn refused(message: String) -> Error {
    Error::Local(Status::new(ErrorName::AuthFailed, message))
}

impl NtlmSpnego {
    const FLAGS: ClientRequestFlags = ClientRequestFlags::MUTUAL_AUTH
        .union(ClientRequestFlags::INTEGRITY)
        // CONFIDENTIALITY makes sspi request NTLMSSP_NEGOTIATE_KEY_EXCH (random exported session key).
        .union(ClientRequestFlags::CONFIDENTIALITY)
        .union(ClientRequestFlags::ALLOCATE_MEMORY);

    fn start(user: &str, domain: &str, password: &str, target_host: &str) -> Result<(Self, Vec<u8>)> {
        let username = Username::new(user, (!domain.is_empty()).then_some(domain))
            .map_err(|e| refused(format!("the user name is not valid: {e:?}")))?;
        if username.account_name().eq_ignore_ascii_case(SSPI_GUEST_USER) {
            // sspi 0.23 skips the mechListMIC requirement for this account name (src/negotiate/mod.rs:35, 405-409), also as "DOMAIN\/GUEST".
            return Err(refused(format!("the user name {SSPI_GUEST_USER} is not supported")));
        }
        if password.starts_with(sspi::NTLM_HASH_PREFIX) {
            // sspi takes the rest of such a password as an NT hash.
            return Err(refused(format!(
                "passwords starting with {} are not supported",
                sspi::NTLM_HASH_PREFIX
            )));
        }
        let identity = AuthIdentity { username, password: password.to_owned().into() };
        // NTLM only: no Kerberos, no PKU2U. No workstation name sent (NtlmConfig::default()).
        let config =
            NegotiateConfig::new(Box::new(NtlmConfig::default()), Some("ntlm".to_owned()), String::new());
        let mut ctx = Negotiate::new_client(config).map_err(|e| sspi_err(&e))?;
        let acquired = ctx
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&sspi::Credentials::AuthIdentity(identity))
            .execute(&mut ctx)
            .map_err(|e| sspi_err(&e))?;
        let mut me = Self {
            ctx,
            creds: acquired.credentials_handle,
            target: format!("cifs/{target_host}"),
            complete: false,
        };
        let (status, token) = me.call(None)?;
        if status != SecurityStatus::ContinueNeeded {
            return Err(policy(format!("NTLM sign-in failed: unexpected first status {status:?}")));
        }
        Ok((me, token))
    }

    fn call(&mut self, input: Option<&[u8]>) -> Result<(SecurityStatus, Vec<u8>)> {
        let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input_bufs = input.map(|t| vec![SecurityBuffer::new(t.to_vec(), BufferType::Token)]);
        let mut creds = self.creds.clone();
        let mut builder = self
            .ctx
            .initialize_security_context()
            .with_credentials_handle(&mut creds)
            .with_context_requirements(Self::FLAGS)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(&self.target)
            .with_output(&mut output);
        if let Some(bufs) = input_bufs.as_mut() {
            builder = builder.with_input(bufs);
        }
        let result = self
            .ctx
            .initialize_security_context_impl(&mut builder)
            .and_then(|mut g| g.resolve_to_result())
            .map_err(|e| sspi_err(&e))?;
        let token = output.into_iter().next().map(|b| b.buffer).unwrap_or_default();
        Ok((result.status, token))
    }

    fn step(&mut self, server_token: &[u8]) -> Result<Step> {
        if self.complete {
            return Err(policy("NTLM sign-in failed: the server wants a round after completion"));
        }
        let (status, token) = self.call(Some(server_token))?;
        match status {
            SecurityStatus::ContinueNeeded => Ok(Step::Continue(token)),
            SecurityStatus::Ok => {
                self.complete = true;
                if token.is_empty() { Ok(Step::Done) } else { Ok(Step::Continue(token)) }
            }
            other => Err(policy(format!("NTLM sign-in failed: unexpected status {other:?}"))),
        }
    }

    fn finish(&mut self, server_token: &[u8]) -> Result<()> {
        if self.complete {
            return Ok(());
        }
        if server_token.is_empty() {
            return Err(policy("the server's final SPNEGO token is missing (no mechListMIC)"));
        }
        let (status, _) = self.call(Some(server_token))?;
        if status == SecurityStatus::Ok {
            self.complete = true;
            Ok(())
        } else {
            Err(policy(format!("SPNEGO not complete after the server's final token ({status:?})")))
        }
    }

    fn session_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let keys = self.ctx.query_context_session_key().map_err(|e| sspi_err(&e))?;
        Ok(Zeroizing::new(keys.session_key.as_ref().clone()))
    }
}

/// Progress of the anonymous exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymousState {
    /// NEGOTIATE_MESSAGE sent.
    SentNegotiate,
    /// AUTHENTICATE_MESSAGE sent.
    SentAuthenticate,
}

const NTLMSSP: &[u8; 8] = b"NTLMSSP\0";
const NEG_UNICODE: u32 = 0x0000_0001;
const NEG_REQUEST_TARGET: u32 = 0x0000_0004;
const NEG_NTLM: u32 = 0x0000_0200;
const NEG_ANONYMOUS: u32 = 0x0000_0800;
const NEG_ALWAYS_SIGN: u32 = 0x0000_8000;
const NEG_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;

/// NEGOTIATE_MESSAGE without domain, workstation or version.
fn anonymous_negotiate() -> Vec<u8> {
    let flags = NEG_UNICODE | NEG_REQUEST_TARGET | NEG_NTLM | NEG_ALWAYS_SIGN | NEG_EXTENDED_SESSIONSECURITY;
    let mut m = Vec::new();
    m.extend_from_slice(NTLMSSP);
    m.extend_from_slice(&1u32.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&[0u8; 16]);
    m
}

/// Checks that a token is an NTLMSSP CHALLENGE_MESSAGE (its content is irrelevant for
/// anonymous: no response is computed from it).
fn check_challenge(token: &[u8]) -> Result<()> {
    let mut r = Reader::new(token);
    if r.array::<8>().ok().as_ref() != Some(NTLMSSP) || r.u32().ok() != Some(2) {
        return Err(policy("anonymous sign-in: the server token is not an NTLMSSP challenge"));
    }
    Ok(())
}

/// AUTHENTICATE_MESSAGE for anonymous: LmChallengeResponse = Z(1), everything else empty,
/// NTLMSSP_NEGOTIATE_ANONYMOUS set, no MIC, no session key.
fn anonymous_authenticate() -> Vec<u8> {
    const PAYLOAD: u32 = 64;
    let flags = NEG_UNICODE | NEG_REQUEST_TARGET | NEG_NTLM | NEG_ANONYMOUS | NEG_EXTENDED_SESSIONSECURITY;
    let field = |len: u16, offset: u32| {
        let mut f = [0u8; 8];
        for (d, s) in f
            .iter_mut()
            .zip(len.to_le_bytes().iter().chain(len.to_le_bytes().iter()).chain(offset.to_le_bytes().iter()))
        {
            *d = *s;
        }
        f
    };
    let mut m = Vec::new();
    m.extend_from_slice(NTLMSSP);
    m.extend_from_slice(&3u32.to_le_bytes());
    m.extend_from_slice(&field(1, PAYLOAD));
    for _ in 0..5 {
        // NtChallengeResponse, DomainName, UserName, Workstation, EncryptedRandomSessionKey
        m.extend_from_slice(&field(0, PAYLOAD + 1));
    }
    m.extend_from_slice(&flags.to_le_bytes());
    m.push(0);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_messages() {
        let n = anonymous_negotiate();
        assert_eq!(n.len(), 32);
        assert_eq!(&n[..12], b"NTLMSSP\0\x01\0\0\0");
        let a = anonymous_authenticate();
        assert_eq!(a.len(), 65);
        assert_eq!(&a[8..12], &[3, 0, 0, 0]);
        assert_eq!(&a[12..20], &[1, 0, 1, 0, 64, 0, 0, 0]);
        assert_eq!(&a[20..28], &[0, 0, 0, 0, 65, 0, 0, 0]);
        let flags = u32::from_le_bytes(a[60..64].try_into().unwrap());
        assert_ne!(flags & NEG_ANONYMOUS, 0);
        assert_eq!(a[64], 0);
    }

    #[test]
    fn anonymous_flags_are_exact() {
        let n = anonymous_negotiate();
        assert_eq!(u32::from_le_bytes(n[12..16].try_into().unwrap()), 0x0008_8205);
        let a = anonymous_authenticate();
        assert_eq!(u32::from_le_bytes(a[60..64].try_into().unwrap()), 0x0008_0a05);
    }

    #[test]
    fn a_challenge_needs_the_signature_and_the_type() {
        let mut chal = b"NTLMSSP\0".to_vec();
        chal.extend_from_slice(&3u32.to_le_bytes());
        check_challenge(&chal).unwrap_err();
        chal[8] = 2;
        chal[6] = b'X';
        check_challenge(&chal).unwrap_err();
        chal[6] = b'P';
        check_challenge(&chal).unwrap();
    }

    #[test]
    fn anonymous_finish_needs_the_authenticate_message() {
        let (mut a, _) = Authenticator::start(&Account::Anonymous, "h").unwrap();
        let e = a.finish(&[]).unwrap_err();
        assert_eq!(e, policy("anonymous sign-in: the exchange is incomplete"));
    }

    #[test]
    fn debug_output_has_no_password() {
        let account = Account::User {
            user: "backup".into(),
            domain: "CORP".into(),
            password: Zeroizing::new("hunter2".into()),
        };
        assert_eq!(format!("{account:?}"), r#"User { user: "backup", domain: "CORP", .. }"#);
        assert_eq!(format!("{:?}", Account::Anonymous), "Anonymous");
        let (a, _) = Authenticator::start(&account, "server").unwrap();
        assert_eq!(format!("{a:?}"), "Authenticator::Ntlm");
        assert!(matches!(&a, Authenticator::Ntlm(n)
            if format!("{n:?}") == r#"NtlmSpnego { target: "cifs/server", complete: false, .. }"#));
        let (a, _) = Authenticator::start(&Account::Anonymous, "h").unwrap();
        assert_eq!(format!("{a:?}"), "Authenticator::Anonymous(SentNegotiate)");
    }

    #[test]
    fn the_domain_goes_into_the_authenticate_message() {
        let account = Account::User {
            user: "alice".into(),
            domain: "CORP".into(),
            password: Zeroizing::new("pw".into()),
        };
        let (mut a, first) = Authenticator::start(&account, "server").unwrap();
        let challenge = crate::fake::Acceptor::new("alice", "CORP", "pw").step(&first);
        let token = match a.step(&challenge).unwrap() {
            Step::Continue(token) => token,
            Step::Done => panic!("no AUTHENTICATE_MESSAGE"),
        };
        let at = token.windows(12).position(|w| w == b"NTLMSSP\0\x03\0\0\0").unwrap();
        let m = &token[at..];
        let len = usize::from(u16::from_le_bytes([m[28], m[29]]));
        let offset = usize::try_from(u32::from_le_bytes(m[32..36].try_into().unwrap())).unwrap();
        let units: Vec<u16> =
            m[offset..][..len].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        assert_eq!(String::from_utf16(&units).unwrap(), "CORP");
    }

    #[test]
    fn a_der_length_of_usize_max_is_refused() {
        // Fuzz target spnego reproducer (rust/fuzz/seeds/spnego): NegTokenResp with DER length usize::MAX; picky-asn1-der adds the header length (rust/vendor/picky-asn1-der), overflow must be an error, not a panic. Final token takes the same decode.
        let mut token = vec![0xa1, 0x23, 0x61, 0x2b, 0xa2, 0x00, 0x25, 0x88];
        token.resize(108, 0xff);
        let account = Account::User {
            user: "alice".into(),
            domain: "CORP".into(),
            password: Zeroizing::new("pw".into()),
        };
        let (mut a, _) = Authenticator::start(&account, "server").unwrap();
        let e = a.step(&token).unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
    }

    #[test]
    fn anonymous_flow_checks_the_challenge() {
        let (mut a, first) = Authenticator::start(&Account::Anonymous, "h").unwrap();
        assert_eq!(first, anonymous_negotiate());
        a.step(b"garbage").unwrap_err();
        let mut chal = b"NTLMSSP\0".to_vec();
        chal.extend_from_slice(&2u32.to_le_bytes());
        assert!(matches!(a.step(&chal).unwrap(), Step::Continue(t) if t == anonymous_authenticate()));
        a.finish(&[]).unwrap();
        a.session_key().unwrap_err();
    }

    #[test]
    fn sspi_spnego_first_token_is_a_neg_token_init_with_ntlm_only() {
        let account = Account::User {
            user: "backup".into(),
            domain: String::new(),
            password: Zeroizing::new("pw".into()),
        };
        let (_a, token) = Authenticator::start(&account, "server").unwrap();
        assert_eq!(token[0], 0x60);
        assert!(token.windows(8).any(|w| w == [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]));
        assert!(
            token
                .windows(12)
                .any(|w| w == [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
        );
        assert!(
            !token
                .windows(11)
                .any(|w| w == [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02])
        );
        assert!(
            !token
                .windows(11)
                .any(|w| w == [0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02])
        );
        let at = token.windows(8).position(|w| w == b"NTLMSSP\0").unwrap();
        let flags = u32::from_le_bytes(token[at + 12..at + 16].try_into().unwrap());
        assert_eq!(flags & 0x2000, 0, "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED");
        assert_ne!(flags & 0x4000_0000, 0, "KEY_EXCH requested");
    }

    #[test]
    fn empty_user_hash_prefix_and_sspi_guest_name_are_refused() {
        let empty = Account::User {
            user: String::new(),
            domain: String::new(),
            password: Zeroizing::new("x".into()),
        };
        // sspi accepts the handle but fails at the latest when the challenge is processed.
        if let Ok((mut a, _)) = Authenticator::start(&empty, "h") {
            a.step(b"not a token").unwrap_err();
        }
        let hashy = Account::User {
            user: "u".into(),
            domain: String::new(),
            password: Zeroizing::new("$NTLM$:00".into()),
        };
        Authenticator::start(&hashy, "h").unwrap_err();
        for (user, domain) in [("/Guest", ""), ("/GUEST", "WORKGROUP"), ("WORKGROUP\\/guest", "")] {
            let guest = Account::User {
                user: user.into(),
                domain: domain.into(),
                password: Zeroizing::new("x".into()),
            };
            let e = Authenticator::start(&guest, "h").unwrap_err();
            assert!(matches!(e, Error::Local(ref s) if s.name == ErrorName::AuthFailed), "{user}: {e}");
        }
    }
}
