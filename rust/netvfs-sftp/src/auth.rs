// SPDX-License-Identifier: LGPL-2.1-or-later
//! Signing in.
//!
//! Without a prompter: exactly the configured method; keyboard-interactive only when the stored password answers one
//! non-echo prompt; a partial success is `AuthFailed`.
//!
//! With a prompter:
//!  - keyboard-interactive is tried after the configured method failed, and is the method of `auth_mode=interactive`;
//!    every round the stored password does not answer goes to the prompter, up to [`MAX_ROUNDS`];
//!  - a partial success continues with keyboard-interactive, or a password asked through the prompter, so
//!    publickey + OTP and password + OTP chains work;
//!  - answers are wiped after use as far as this code holds them.
//!
//! Every russh call is bounded by the connect timeout and the cancel token. A call that stops part way leaves
//! russh's reply queue out of step: the caller must drop the session after any failure here.

use crate::keys;
use crate::session::{Session, bounded};
use netvfs_vfs::{CancelToken, ErrorName, Prompt, PromptRequest, Prompter, Status};
use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg};
use russh::{MethodKind, MethodSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Keyboard-interactive rounds answered in one attempt.
pub const MAX_ROUNDS: usize = 8;
/// Methods tried in one sign-in, partial successes included.
pub const MAX_STEPS: usize = 4;

/// `remotefs/sftp/auth_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `password` (the default).
    Password,
    /// `publickey`: the secret is a key secret.
    PublicKey,
    /// `interactive`: the secret, if any, is a password.
    Interactive,
}

impl Mode {
    /// The mode of an `auth_mode` value; `None` (absent) is `Password`.
    ///
    /// # Errors
    /// `Internal` for an unknown value.
    pub fn parse(value: Option<&str>) -> Result<Self, Status> {
        match value.unwrap_or("password") {
            "password" => Ok(Self::Password),
            "publickey" => Ok(Self::PublicKey),
            "interactive" => Ok(Self::Interactive),
            other => Err(Status::internal(format!("Unknown sign-in method \"{other}\""))),
        }
    }

    /// Secret and mode must agree: a key is never sent as a password, a password never read as a key.
    ///
    /// # Errors
    /// `AuthFailed` when they do not.
    pub fn check_secret(self, secret: &[u8]) -> Result<(), Status> {
        let refused = |message: &str| Err(Status::new(ErrorName::AuthFailed, message));
        match self {
            Self::Password if keys::is_key_secret(secret) => {
                refused("The account uses a password, but the stored credential is a key")
            }
            Self::PublicKey if keys::decode_key_secret(secret).is_none() => {
                refused("The account uses an SSH key, but no valid key is stored")
            }
            Self::Interactive if keys::is_key_secret(secret) => {
                refused("The account signs in interactively, but the stored credential is a key")
            }
            _ => Ok(()),
        }
    }
}

/// The methods the server accepts, for the denial message.
#[must_use]
pub fn accepted_methods_text(methods: &[MethodKind]) -> String {
    if methods == [MethodKind::PublicKey] {
        return "This server only accepts SSH keys (publickey).".to_owned();
    }
    let names: Vec<&str> = [
        MethodKind::PublicKey,
        MethodKind::Password,
        MethodKind::KeyboardInteractive,
        MethodKind::HostBased,
        MethodKind::GssapiWithMic,
    ]
    .iter()
    .filter(|m| methods.contains(m))
    .map(<&str>::from)
    .collect();
    if names.is_empty() {
        return "The server named no sign-in method it accepts.".to_owned();
    }
    format!("The server accepts: {}.", names.join(", "))
}

/// Sign-in refused; names the accepted methods.
#[must_use]
pub fn auth_denied(methods: &[MethodKind]) -> Status {
    Status::new(ErrorName::AuthFailed, format!("Sign-in was refused. {}", accepted_methods_text(methods)))
}

/// The server needs a second sign-in step.
#[must_use]
pub fn auth_partial() -> Status {
    Status::new(
        ErrorName::AuthFailed,
        "The server requires a second sign-in step (multi-factor sign-in), which is not supported",
    )
}

/// A prompt shape the stored password cannot answer, no prompter.
#[must_use]
pub fn interactive_not_supported() -> Status {
    Status::new(ErrorName::AuthFailed, "The server needs interactive sign-in, which is not supported")
}

/// The prompter declined, or gave no answer for every prompt.
#[must_use]
pub fn interactive_declined() -> Status {
    Status::new(ErrorName::AuthFailed, "Interactive sign-in was not completed")
}

/// The stored key cannot sign in.
#[must_use]
pub fn unusable_key() -> Status {
    Status::new(ErrorName::AuthFailed, "The stored SSH key cannot be used")
}

/// What to do with one keyboard-interactive round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundAction {
    /// No prompts (OpenSSH sends one after PAM succeeded).
    Acknowledge,
    /// The stored password answers a single non-echo prompt.
    AnswerWithSecret,
    /// Ask the prompter.
    AskPrompter,
    /// Any other shape without a prompter.
    Refuse,
}

/// What to do with a round of `prompts`. `secret_usable`: password mode and the stored password has not answered
/// a round yet. With a prompter the stored password answers only a prompt that asks for a password, never a
/// one-time code.
#[must_use]
pub fn round_action(prompts: &[Prompt], secret_usable: bool, has_prompter: bool) -> RoundAction {
    let [first, rest @ ..] = prompts else {
        return RoundAction::Acknowledge;
    };
    if secret_usable && rest.is_empty() && !first.echo && (is_password_prompt(&first.text) || !has_prompter) {
        return RoundAction::AnswerWithSecret;
    }
    if has_prompter { RoundAction::AskPrompter } else { RoundAction::Refuse }
}

/// Whether a prompt asks for a password.
#[must_use]
pub fn is_password_prompt(text: &str) -> bool {
    text.to_lowercase().contains("password")
}

/// A russh call that did not return: canceled, timed out, or russh's error.
#[derive(Debug)]
enum Stopped {
    Bounded(Status),
    Ssh(russh::Error),
}

/// Runs a russh call under `cancel` and `timeout`.
async fn guarded<T>(
    call: impl Future<Output = Result<T, russh::Error>>,
    timeout: Duration,
    cancel: &CancelToken,
) -> Result<T, Stopped> {
    match bounded(async { Ok(call.await) }, timeout, cancel).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(Stopped::Ssh(e)),
        Err(status) => Err(Stopped::Bounded(status)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Success,
    Partial(MethodSet),
    Denied(MethodSet),
}

fn offers(methods: &[MethodKind], method: MethodKind) -> bool {
    methods.contains(&method)
}

fn password_text(secret: &[u8]) -> Result<String, Status> {
    String::from_utf8(secret.to_vec())
        .map_err(|_e| Status::new(ErrorName::AuthFailed, "The password is not valid UTF-8 text"))
}

/// The stored key: Ed25519 or ECDSA in a key secret.
fn stored_key(secret: &[u8]) -> Result<PrivateKey, Status> {
    let text = keys::decode_key_secret(secret).ok_or_else(unusable_key)?;
    let text = std::str::from_utf8(&text).map_err(|_e| unusable_key())?;
    let key = PrivateKey::from_openssh(text).map_err(|_e| unusable_key())?;
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } if !key.is_encrypted() => Ok(key),
        _ => Err(unusable_key()),
    }
}

/// One sign-in.
pub struct Login<'a, 'p> {
    session: &'a mut Session,
    user: &'a str,
    secret: &'a [u8],
    prompter: Option<&'p mut dyn Prompter>,
    mode: Mode,
    timeout: Duration,
    cancel: &'a CancelToken,
    /// The stored password answered a round.
    secret_used: bool,
    tried_interactive: bool,
}

impl std::fmt::Debug for Login<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Login")
            .field("user", &self.user)
            .field("mode", &self.mode)
            .field("prompter", &self.prompter.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a, 'p> Login<'a, 'p> {
    /// A sign-in as `user` with `secret` in `mode`; russh calls bounded by `timeout`.
    pub fn new(
        session: &'a mut Session,
        user: &'a str,
        secret: &'a [u8],
        prompter: Option<&'p mut dyn Prompter>,
        mode: Mode,
        timeout: Duration,
        cancel: &'a CancelToken,
    ) -> Self {
        Self {
            session,
            user,
            secret,
            prompter,
            mode,
            timeout,
            cancel,
            secret_used: false,
            tried_interactive: false,
        }
    }

    /// Signs in.
    ///
    /// # Errors
    /// `AuthFailed` with the reason; `Canceled`, `Timeout`,
    /// `ConnectionLost`, `ProtocolError`.
    pub async fn run(mut self) -> Result<(), Status> {
        // Learn the offered methods first.
        let methods = match self.none().await? {
            Outcome::Success => return Ok(()),
            Outcome::Partial(m) | Outcome::Denied(m) => m,
        };
        let mut step = self.first(&methods).await?;
        let mut steps = 1;
        loop {
            let another = steps < MAX_STEPS && self.prompter.is_some();
            step = match step {
                Outcome::Success => return Ok(()),
                Outcome::Partial(m) if another => self.after_partial(&m).await?,
                Outcome::Partial(_) => return Err(auth_partial()),
                Outcome::Denied(m)
                    if another && !self.tried_interactive && offers(&m, MethodKind::KeyboardInteractive) =>
                {
                    self.keyboard_interactive().await?
                }
                Outcome::Denied(m) => return Err(auth_denied(&m)),
            };
            steps = steps.saturating_add(1);
        }
    }

    async fn first(&mut self, methods: &[MethodKind]) -> Result<Outcome, Status> {
        match self.mode {
            Mode::PublicKey => self.public_key(methods).await,
            Mode::Password => self.password(methods).await,
            // A stored password where the server takes one, else keyboard-interactive, which needs a prompter.
            Mode::Interactive => {
                if !self.secret.is_empty() && offers(methods, MethodKind::Password) {
                    let password = password_text(self.secret)?;
                    return self.send_password(password).await;
                }
                if self.prompter.is_none() {
                    return Err(interactive_not_supported());
                }
                if !offers(methods, MethodKind::KeyboardInteractive) {
                    return Err(auth_denied(methods));
                }
                self.keyboard_interactive().await
            }
        }
    }

    async fn after_partial(&mut self, methods: &[MethodKind]) -> Result<Outcome, Status> {
        if offers(methods, MethodKind::KeyboardInteractive) {
            return self.keyboard_interactive().await;
        }
        if offers(methods, MethodKind::Password) {
            return self.prompted_password().await;
        }
        Err(auth_partial())
    }

    async fn password(&mut self, methods: &[MethodKind]) -> Result<Outcome, Status> {
        if offers(methods, MethodKind::Password) {
            let password = password_text(self.secret)?;
            return self.send_password(password).await;
        }
        if offers(methods, MethodKind::KeyboardInteractive) {
            return self.keyboard_interactive().await;
        }
        Ok(Outcome::Denied(methods.into()))
    }

    /// The key comes from the secret only, never from files or an agent.
    async fn public_key(&mut self, methods: &[MethodKind]) -> Result<Outcome, Status> {
        if !offers(methods, MethodKind::PublicKey) {
            return Ok(Outcome::Denied(methods.into()));
        }
        let key = PrivateKeyWithHashAlg::new(Arc::new(stored_key(self.secret)?), None);
        let user = self.user.to_owned();
        let result =
            guarded(self.session.handle().authenticate_publickey(user, key), self.timeout, self.cancel).await;
        self.outcome(result)
    }

    async fn none(&mut self) -> Result<Outcome, Status> {
        let user = self.user.to_owned();
        let result = guarded(self.session.handle().authenticate_none(user), self.timeout, self.cancel).await;
        self.outcome(result)
    }

    async fn send_password(&mut self, password: String) -> Result<Outcome, Status> {
        let password = Zeroizing::new(password);
        let user = self.user.to_owned();
        let result = guarded(
            self.session.handle().authenticate_password(user, password.as_str()),
            self.timeout,
            self.cancel,
        )
        .await;
        self.outcome(result)
    }

    /// russh reports a session that ended while it waited as a failure without methods: that is the end of the
    /// session, not a refusal.
    fn outcome(&self, result: Result<AuthResult, Stopped>) -> Result<Outcome, Status> {
        let reply = result.map_err(|e| self.call_failure(e))?;
        Ok(match reply {
            AuthResult::Success => Outcome::Success,
            AuthResult::Failure { remaining_methods, partial_success } => {
                self.refusal(remaining_methods, partial_success)?
            }
        })
    }

    fn refusal(&self, remaining: MethodSet, partial: bool) -> Result<Outcome, Status> {
        if remaining.is_empty()
            && !partial
            && let Some(end) = self.session.end()
            && end != crate::session::End::NoAuthMethod
        {
            return Err(end.status());
        }
        Ok(if partial { Outcome::Partial(remaining) } else { Outcome::Denied(remaining) })
    }

    fn call_failure(&self, e: Stopped) -> Status {
        match e {
            Stopped::Bounded(status) => status,
            Stopped::Ssh(e) => self.session.failure(&e),
        }
    }

    /// Rounds without prompts are acknowledged, the others go to the prompter.
    async fn keyboard_interactive(&mut self) -> Result<Outcome, Status> {
        self.tried_interactive = true;
        let user = self.user.to_owned();
        let start = guarded(
            self.session.handle().authenticate_keyboard_interactive_start(user, None::<String>),
            self.timeout,
            self.cancel,
        )
        .await;
        let mut reply = start.map_err(|e| self.call_failure(e))?;
        for _ in 0..MAX_ROUNDS {
            let (name, instructions, prompts) = match reply {
                KeyboardInteractiveAuthResponse::Success => return Ok(Outcome::Success),
                KeyboardInteractiveAuthResponse::Failure { remaining_methods, partial_success } => {
                    return self.refusal(remaining_methods, partial_success);
                }
                KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                    (name, instructions, prompts)
                }
            };
            let prompts: Vec<Prompt> =
                prompts.into_iter().map(|p| Prompt { text: p.prompt, echo: p.echo }).collect();
            let answers = self.round(name, instructions, prompts)?;
            let answered = guarded(
                self.session.handle().authenticate_keyboard_interactive_respond(answers),
                self.timeout,
                self.cancel,
            )
            .await;
            reply = answered.map_err(|e| self.call_failure(e))?;
        }
        match reply {
            KeyboardInteractiveAuthResponse::Success => Ok(Outcome::Success),
            KeyboardInteractiveAuthResponse::Failure { remaining_methods, partial_success } => {
                self.refusal(remaining_methods, partial_success)
            }
            KeyboardInteractiveAuthResponse::InfoRequest { .. } => Err(interactive_not_supported()),
        }
    }

    /// The answers to one round.
    fn round(
        &mut self,
        name: String,
        instruction: String,
        prompts: Vec<Prompt>,
    ) -> Result<Vec<String>, Status> {
        let secret_usable = self.mode == Mode::Password && !self.secret_used;
        match round_action(&prompts, secret_usable, self.prompter.is_some()) {
            RoundAction::Acknowledge => Ok(Vec::new()),
            RoundAction::AnswerWithSecret => {
                self.secret_used = true;
                Ok(vec![password_text(self.secret)?])
            }
            RoundAction::Refuse => Err(interactive_not_supported()),
            RoundAction::AskPrompter => self.ask(&PromptRequest { name, instruction, prompts }),
        }
    }

    /// Asks the prompter: one UTF-8 answer per prompt, or the round fails.
    fn ask(&mut self, request: &PromptRequest) -> Result<Vec<String>, Status> {
        self.cancel.check()?;
        let Some(prompter) = self.prompter.as_deref_mut() else {
            return Err(interactive_not_supported());
        };
        let answers = prompter.answer(request);
        self.cancel.check()?;
        let answers = answers.ok_or_else(interactive_declined)?;
        if answers.len() != request.prompts.len() {
            return Err(interactive_declined());
        }
        answers.iter().map(|a| String::from_utf8(a.to_vec()).map_err(|_e| interactive_declined())).collect()
    }

    /// A password through the prompter, after a partial success.
    async fn prompted_password(&mut self) -> Result<Outcome, Status> {
        let request = PromptRequest {
            name: String::new(),
            instruction: String::new(),
            prompts: vec![Prompt { text: "Password: ".to_owned(), echo: false }],
        };
        let mut answers = self.ask(&request)?;
        let password = answers.pop().unwrap_or_default();
        self.send_password(password).await
    }
}

#[cfg(test)]
mod tests;
