// SPDX-License-Identifier: LGPL-2.1-or-later
use super::*;
use crate::session::{Target, connect};
use crate::testserver::{Proxy, Round, Script, Server, Step};
use std::collections::VecDeque;
use std::net::SocketAddr;

const PK: MethodKind = MethodKind::PublicKey;
const PW: MethodKind = MethodKind::Password;
const KI: MethodKind = MethodKind::KeyboardInteractive;

fn target(addr: SocketAddr) -> Target {
    Target {
        host: addr.ip().to_string(),
        port: addr.port(),
        connect_timeout: Duration::from_secs(10),
        pinned_type: None,
    }
}

/// A prompter that gives the replies it holds, in turn, and records what
/// it was asked.
#[derive(Default)]
struct Answers {
    replies: VecDeque<Option<Vec<&'static [u8]>>>,
    asked: Vec<PromptRequest>,
    /// Tripped while answering.
    cancel: Option<CancelToken>,
}

impl Answers {
    fn with(replies: Vec<Option<Vec<&'static [u8]>>>) -> Self {
        Self { replies: replies.into(), ..Self::default() }
    }

    fn texts(&self) -> Vec<Vec<String>> {
        self.asked.iter().map(|r| r.prompts.iter().map(|p| p.text.clone()).collect()).collect()
    }
}

impl Prompter for Answers {
    fn answer(&mut self, request: &PromptRequest) -> Option<Vec<Zeroizing<Vec<u8>>>> {
        self.asked.push(request.clone());
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        let reply = self.replies.pop_front().flatten()?;
        Some(reply.into_iter().map(|a| Zeroizing::new(a.to_vec())).collect())
    }
}

async fn sign_in_with(
    server: &Server,
    secret: &[u8],
    mode: Mode,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), Status> {
    let mut session = connect(&target(server.addr), &CancelToken::new()).await.unwrap();
    Login::new(&mut session, "alice", secret, prompter, mode, Duration::from_secs(5), &CancelToken::new())
        .run()
        .await
}

async fn sign_in(server: &Server, secret: &[u8], mode: Mode) -> Result<(), Status> {
    sign_in_with(server, secret, mode, None).await
}

fn script(offered: Vec<MethodKind>, chain: Vec<Step>) -> Script {
    Script { offered, chain, ..Script::password() }
}

fn denied(text: &str) -> Status {
    Status::new(ErrorName::AuthFailed, format!("Sign-in was refused. {text}"))
}

/// The key secret of a fixture, and the public key the server wants.
fn key_secret(file: &str) -> (Zeroizing<Vec<u8>>, russh::keys::PublicKey) {
    let path = format!("{}/testdata/keys/{file}", env!("CARGO_MANIFEST_DIR"));
    let key = keys::import(&std::fs::read(path).unwrap(), b"").unwrap();
    let public = PrivateKey::from_openssh(std::str::from_utf8(&key.private_key).unwrap())
        .unwrap()
        .public_key()
        .clone();
    (keys::encode_key_secret(&key.private_key), public)
}

#[test]
fn modes() {
    assert_eq!(Mode::parse(None), Ok(Mode::Password));
    assert_eq!(Mode::parse(Some("password")), Ok(Mode::Password));
    assert_eq!(Mode::parse(Some("publickey")), Ok(Mode::PublicKey));
    assert_eq!(Mode::parse(Some("interactive")), Ok(Mode::Interactive));
    assert_eq!(Mode::parse(Some("Password")), Err(Status::internal("Unknown sign-in method \"Password\"")));
    assert_eq!(Mode::parse(Some("")), Err(Status::internal("Unknown sign-in method \"\"")));
}

#[test]
fn secrets_must_fit_the_mode() {
    let (key, _) = key_secret("ed25519-openssh");
    let auth = |m: &str| Err(Status::new(ErrorName::AuthFailed, m));
    assert_eq!(Mode::Password.check_secret(b"hunter2"), Ok(()));
    assert_eq!(Mode::Password.check_secret(b""), Ok(()));
    assert_eq!(
        Mode::Password.check_secret(&key),
        auth("The account uses a password, but the stored credential is a key")
    );
    // A broken key secret is still a key: never sent as a password.
    assert_eq!(
        Mode::Password.check_secret(b"netvfs-key-v1:!!"),
        auth("The account uses a password, but the stored credential is a key")
    );
    assert_eq!(Mode::PublicKey.check_secret(&key), Ok(()));
    for bad in [&b"hunter2"[..], b"", b"netvfs-key-v1:", b"netvfs-key-v1:!!"] {
        assert_eq!(
            Mode::PublicKey.check_secret(bad),
            auth("The account uses an SSH key, but no valid key is stored"),
            "{bad:?}"
        );
    }
    assert_eq!(Mode::Interactive.check_secret(b""), Ok(()));
    assert_eq!(Mode::Interactive.check_secret(b"hunter2"), Ok(()));
    assert_eq!(
        Mode::Interactive.check_secret(&key),
        auth("The account signs in interactively, but the stored credential is a key")
    );
}

#[test]
fn denials_name_the_methods() {
    assert_eq!(accepted_methods_text(&[PK]), "This server only accepts SSH keys (publickey).");
    assert_eq!(accepted_methods_text(&[]), "The server named no sign-in method it accepts.");
    assert_eq!(accepted_methods_text(&[MethodKind::None]), "The server named no sign-in method it accepts.");
    assert_eq!(accepted_methods_text(&[PW, PK]), "The server accepts: publickey, password.");
    assert_eq!(
        accepted_methods_text(&[MethodKind::GssapiWithMic, KI, MethodKind::HostBased, PW, PK]),
        "The server accepts: publickey, password, keyboard-interactive, hostbased, gssapi-with-mic."
    );
    assert_eq!(accepted_methods_text(&[KI]), "The server accepts: keyboard-interactive.");
    assert_eq!(auth_denied(&[PW]), denied("The server accepts: password."));
    assert_eq!(auth_partial().name, ErrorName::AuthFailed);
    assert_eq!(
        auth_partial().message,
        "The server requires a second sign-in step (multi-factor sign-in), which is not supported"
    );
    assert_eq!(
        interactive_not_supported().message,
        "The server needs interactive sign-in, which is not supported"
    );
    assert_eq!(interactive_declined().message, "Interactive sign-in was not completed");
    assert_eq!(unusable_key(), Status::new(ErrorName::AuthFailed, "The stored SSH key cannot be used"));
}

fn prompts(shape: &[(&str, bool)]) -> Vec<Prompt> {
    shape.iter().map(|(t, e)| Prompt { text: (*t).to_owned(), echo: *e }).collect()
}

#[test]
fn what_a_round_gets() {
    use RoundAction::{Acknowledge, AnswerWithSecret, AskPrompter, Refuse};
    let pass = prompts(&[("Password: ", false)]);
    let code = prompts(&[("Verification code: ", false)]);
    let echo = prompts(&[("Password: ", true)]);
    let two = prompts(&[("Password: ", false), ("Code: ", false)]);
    for has in [false, true] {
        for usable in [false, true] {
            assert_eq!(round_action(&[], usable, has), Acknowledge);
        }
    }
    // Without a prompter: S-11 exactly, whatever the text.
    assert_eq!(round_action(&pass, true, false), AnswerWithSecret);
    assert_eq!(round_action(&code, true, false), AnswerWithSecret);
    assert_eq!(round_action(&pass, false, false), Refuse);
    assert_eq!(round_action(&echo, true, false), Refuse);
    assert_eq!(round_action(&two, true, false), Refuse);
    // With one: the stored password answers a password prompt only.
    assert_eq!(round_action(&pass, true, true), AnswerWithSecret);
    assert_eq!(round_action(&code, true, true), AskPrompter);
    assert_eq!(round_action(&pass, false, true), AskPrompter);
    assert_eq!(round_action(&echo, true, true), AskPrompter);
    assert_eq!(round_action(&two, true, true), AskPrompter);
}

#[test]
fn password_prompts() {
    for yes in ["Password: ", "password", "alice@host's PASSWORD:", "New Password"] {
        assert!(is_password_prompt(yes), "{yes}");
    }
    for no in ["Verification code: ", "passwd:", "", "PIN"] {
        assert!(!is_password_prompt(no), "{no}");
    }
}

#[test]
fn stored_keys() {
    for file in ["ed25519-openssh", "ecdsa384-openssh", "ecdsa521-openssh"] {
        let (secret, public) = key_secret(file);
        assert_eq!(stored_key(&secret).unwrap().public_key(), &public, "{file}");
    }
    let rsa = std::fs::read(format!("{}/testdata/keys/rsa-openssh", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let enc =
        std::fs::read(format!("{}/testdata/keys/ed25519-openssh-enc", env!("CARGO_MANIFEST_DIR"))).unwrap();
    for bad in [
        keys::encode_key_secret(&rsa),
        keys::encode_key_secret(&enc),
        keys::encode_key_secret(b"not a key"),
        keys::encode_key_secret(b"\xff\xfe"),
        Zeroizing::new(b"hunter2".to_vec()),
    ] {
        assert_eq!(stored_key(&bad).unwrap_err(), unusable_key());
    }
    assert_eq!(
        password_text(b"\xffpw"),
        Err(Status::new(ErrorName::AuthFailed, "The password is not valid UTF-8 text"))
    );
    assert_eq!(password_text("pässword".as_bytes()), Ok("pässword".to_owned()));
}

#[tokio::test]
async fn password_sign_in() {
    let server = Server::start(Script::password()).await;
    sign_in(&server, b"secret", Mode::Password).await.unwrap();
    assert_eq!(server.take_log(), ["none alice", "password alice secret"]);
    let e = sign_in(&server, b"wrong", Mode::Password).await.unwrap_err();
    assert_eq!(e, denied("The server accepts: publickey, password."));
    assert_eq!(server.take_log(), ["none alice", "password alice wrong"]);
    // Not UTF-8: refused before anything is sent.
    let e = sign_in(&server, b"\xff", Mode::Password).await.unwrap_err();
    assert_eq!(e.message, "The password is not valid UTF-8 text");
    assert_eq!(server.take_log(), ["none alice"]);
}

#[tokio::test]
async fn a_password_is_never_sent_to_a_key_only_server() {
    // S-T7.
    let server = Server::start(script(vec![PK], vec![Step::Password("secret")])).await;
    let e = sign_in(&server, b"secret", Mode::Password).await.unwrap_err();
    assert_eq!(e, denied("This server only accepts SSH keys (publickey)."));
    assert_eq!(server.take_log(), ["none alice"]);
}

#[tokio::test]
async fn a_server_that_signs_in_anyone() {
    let server = Server::start(Script { open: true, ..Script::password() }).await;
    sign_in(&server, b"", Mode::Password).await.unwrap();
    assert_eq!(server.take_log(), ["none alice"]);
}

#[tokio::test]
async fn a_server_that_names_no_method() {
    let server = Server::start(script(vec![], vec![Step::Password("secret")])).await;
    let e = sign_in(&server, b"secret", Mode::Password).await.unwrap_err();
    assert_eq!(e, denied("The server named no sign-in method it accepts."));
    assert_eq!(server.take_log(), ["none alice"]);
}

#[tokio::test]
async fn keyboard_interactive_takes_the_stored_password() {
    // S-11, S-T11: only keyboard-interactive, one non-echo prompt.
    let server =
        Server::start(script(vec![KI], vec![Step::Interactive(vec![Round::one("Password: ", "secret")])]))
            .await;
    sign_in(&server, b"secret", Mode::Password).await.unwrap();
    assert_eq!(server.take_log(), ["none alice", "kbd alice", "answers secret"]);
    // OpenSSH's empty round after PAM is acknowledged.
    let rounds = vec![Round::one("Password: ", "secret"), Round::empty()];
    let server = Server::start(script(vec![KI], vec![Step::Interactive(rounds)])).await;
    sign_in(&server, b"secret", Mode::Password).await.unwrap();
    assert_eq!(server.take_log(), ["none alice", "kbd alice", "answers secret", "answers "]);
    // The stored password answers one round only.
    let rounds = vec![Round::one("Password: ", "secret"), Round::one("Password again: ", "secret")];
    let server = Server::start(script(vec![KI], vec![Step::Interactive(rounds)])).await;
    assert_eq!(sign_in(&server, b"secret", Mode::Password).await.unwrap_err(), interactive_not_supported());
    // A wrong password: refused with the methods.
    let server =
        Server::start(script(vec![KI], vec![Step::Interactive(vec![Round::one("Password: ", "secret")])]))
            .await;
    let e = sign_in(&server, b"wrong", Mode::Password).await.unwrap_err();
    assert_eq!(e, denied("The server accepts: keyboard-interactive."));
}

#[tokio::test]
async fn other_prompt_shapes_need_a_prompter() {
    let shapes = [
        Round { name: "", instruction: "", prompts: vec![("Code: ", true)], answers: vec!["1"] },
        Round {
            name: "",
            instruction: "",
            prompts: vec![("Password: ", false), ("Code: ", false)],
            answers: vec!["a", "b"],
        },
    ];
    for round in shapes {
        let server = Server::start(script(vec![KI], vec![Step::Interactive(vec![round])])).await;
        assert_eq!(
            sign_in(&server, b"secret", Mode::Password).await.unwrap_err(),
            interactive_not_supported()
        );
        assert_eq!(server.take_log(), ["none alice", "kbd alice"]);
    }
}

#[tokio::test]
async fn too_many_rounds() {
    let rounds = |n| vec![Round::empty(); n];
    let server = Server::start(script(vec![KI], vec![Step::Interactive(rounds(MAX_ROUNDS))])).await;
    sign_in(&server, b"secret", Mode::Password).await.unwrap();
    let server = Server::start(script(vec![KI], vec![Step::Interactive(rounds(MAX_ROUNDS + 1))])).await;
    assert_eq!(sign_in(&server, b"secret", Mode::Password).await.unwrap_err(), interactive_not_supported());
    let log = server.take_log();
    assert_eq!(log.iter().filter(|l| l.starts_with("answers")).count(), MAX_ROUNDS);
}

#[tokio::test]
async fn key_sign_in() {
    // S-12, S-T12: Ed25519 and ECDSA keys from the secret.
    for (file, algorithm) in [("ed25519-openssh", "ssh-ed25519"), ("ecdsa384-openssh", "ecdsa-sha2-nistp384")]
    {
        let (secret, public) = key_secret(file);
        let server = Server::start(script(vec![PK, PW], vec![Step::Key(public)])).await;
        sign_in(&server, &secret, Mode::PublicKey).await.unwrap();
        let log = server.take_log();
        assert_eq!(log.first().map(String::as_str), Some("none alice"));
        assert_eq!(log.last().unwrap(), &format!("publickey alice {algorithm}"), "{log:?}");
    }
    // Another key: refused.
    let (secret, _) = key_secret("ed25519-openssh");
    let (_, other) = key_secret("ecdsa384-openssh");
    let server = Server::start(script(vec![PK, PW], vec![Step::Key(other.clone())])).await;
    let e = sign_in(&server, &secret, Mode::PublicKey).await.unwrap_err();
    assert_eq!(e, denied("The server accepts: publickey, password."));
    // A server without publickey: nothing is sent.
    let server = Server::start(script(vec![PW], vec![Step::Key(other)])).await;
    let e = sign_in(&server, &secret, Mode::PublicKey).await.unwrap_err();
    assert_eq!(e, denied("The server accepts: password."));
    assert_eq!(server.take_log(), ["none alice"]);
    // A stored key that cannot be used.
    let server = Server::start(script(vec![PK], vec![])).await;
    let rsa = std::fs::read(format!("{}/testdata/keys/rsa-openssh", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let e = sign_in(&server, &keys::encode_key_secret(&rsa), Mode::PublicKey).await.unwrap_err();
    assert_eq!(e, unusable_key());
}

#[tokio::test]
async fn partial_success_without_a_prompter_fails() {
    // S-13.
    let chain =
        vec![Step::Password("secret"), Step::Interactive(vec![Round::one("Verification code: ", "123456")])];
    let server = Server::start(script(vec![PW], chain)).await;
    assert_eq!(sign_in(&server, b"secret", Mode::Password).await.unwrap_err(), auth_partial());
}

#[tokio::test]
async fn password_and_one_time_code() {
    // XS-11: the code goes to the prompter, never the stored password.
    let chain =
        vec![Step::Password("secret"), Step::Interactive(vec![Round::one("Verification code: ", "123456")])];
    let server = Server::start(script(vec![PW], chain)).await;
    let mut answers = Answers::with(vec![Some(vec![b"123456"])]);
    sign_in_with(&server, b"secret", Mode::Password, Some(&mut answers)).await.unwrap();
    assert_eq!(answers.texts(), [["Verification code: "]]);
    assert_eq!(server.take_log(), ["none alice", "password alice secret", "kbd alice", "answers 123456"]);
}

#[tokio::test]
async fn key_and_prompted_password() {
    let (secret, public) = key_secret("ed25519-openssh");
    let server = Server::start(script(vec![PK], vec![Step::Key(public), Step::Password("second")])).await;
    let mut answers = Answers::with(vec![Some(vec![b"second"])]);
    sign_in_with(&server, &secret, Mode::PublicKey, Some(&mut answers)).await.unwrap();
    assert_eq!(answers.texts(), [["Password: "]]);
    assert!(!answers.asked[0].prompts[0].echo);
    assert_eq!(server.take_log().last().unwrap(), "password alice second");
    // A partial success that names nothing this app does.
    let (secret, public) = key_secret("ed25519-openssh");
    let (_, other) = key_secret("ecdsa384-openssh");
    let server = Server::start(script(vec![PK], vec![Step::Key(public), Step::Key(other)])).await;
    let mut answers = Answers::default();
    let e = sign_in_with(&server, &secret, Mode::PublicKey, Some(&mut answers)).await.unwrap_err();
    assert_eq!(e, auth_partial());
}

#[tokio::test]
async fn keyboard_interactive_after_the_configured_method_failed() {
    // XS-11: with a prompter.
    let rounds = vec![Round::one("Password: ", "secret"), Round::one("Code: ", "42")];
    let server = Server::start(script(vec![PW, KI], vec![Step::Interactive(rounds)])).await;
    let mut answers = Answers::with(vec![Some(vec![b"42"])]);
    sign_in_with(&server, b"secret", Mode::Password, Some(&mut answers)).await.unwrap();
    assert_eq!(
        server.take_log(),
        ["none alice", "password alice secret", "kbd alice", "answers secret", "answers 42"]
    );
    assert_eq!(answers.texts(), [["Code: "]]);
    // Without a prompter the denial stands.
    let rounds = vec![Round::one("Password: ", "secret")];
    let server = Server::start(script(vec![PW, KI], vec![Step::Interactive(rounds)])).await;
    let e = sign_in(&server, b"secret", Mode::Password).await.unwrap_err();
    assert_eq!(e, denied("The server accepts: password, keyboard-interactive."));
    assert_eq!(server.take_log(), ["none alice", "password alice secret"]);
}

#[tokio::test]
async fn the_prompter_can_say_no() {
    let round = || vec![Step::Interactive(vec![Round::one("Code: ", "42")])];
    let cases: Vec<Option<Vec<&'static [u8]>>> =
        vec![None, Some(vec![]), Some(vec![b"4", b"2"]), Some(vec![b"\xff"])];
    for reply in cases {
        let server = Server::start(script(vec![KI], round())).await;
        let mut answers = Answers::with(vec![reply.clone()]);
        let e = sign_in_with(&server, b"", Mode::Interactive, Some(&mut answers)).await.unwrap_err();
        assert_eq!(e, interactive_declined(), "{reply:?}");
        assert_eq!(server.take_log(), ["none alice", "kbd alice"], "{reply:?}");
    }
    // A wrong code: refused by the server.
    let server = Server::start(script(vec![KI], round())).await;
    let mut answers = Answers::with(vec![Some(vec![b"41"])]);
    let e = sign_in_with(&server, b"", Mode::Interactive, Some(&mut answers)).await.unwrap_err();
    assert_eq!(e, denied("The server accepts: keyboard-interactive."));
}

#[tokio::test]
async fn interactive_mode() {
    let rounds = || vec![Step::Interactive(vec![Round::one("Code: ", "42")])];
    // No secret: keyboard-interactive through the prompter.
    let server = Server::start(script(vec![PW, KI], rounds())).await;
    let mut answers = Answers::with(vec![Some(vec![b"42"])]);
    sign_in_with(&server, b"", Mode::Interactive, Some(&mut answers)).await.unwrap();
    assert_eq!(server.take_log(), ["none alice", "kbd alice", "answers 42"]);
    // Without a prompter it cannot work.
    let server = Server::start(script(vec![KI], rounds())).await;
    assert_eq!(sign_in(&server, b"", Mode::Interactive).await.unwrap_err(), interactive_not_supported());
    // Nor without keyboard-interactive.
    let server = Server::start(script(vec![PK], rounds())).await;
    let mut answers = Answers::default();
    let e = sign_in_with(&server, b"", Mode::Interactive, Some(&mut answers)).await.unwrap_err();
    assert_eq!(e, denied("This server only accepts SSH keys (publickey)."));
    // A stored password goes where the server takes one.
    let server = Server::start(Script::password()).await;
    sign_in(&server, b"secret", Mode::Interactive).await.unwrap();
    assert_eq!(server.take_log(), ["none alice", "password alice secret"]);
    // The stored password never answers a round in this mode.
    let server =
        Server::start(script(vec![KI], vec![Step::Interactive(vec![Round::one("Password: ", "secret")])]))
            .await;
    let mut answers = Answers::with(vec![Some(vec![b"secret"])]);
    sign_in_with(&server, b"secret", Mode::Interactive, Some(&mut answers)).await.unwrap();
    assert_eq!(answers.texts(), [["Password: "]]);
}

#[tokio::test]
async fn at_most_four_methods() {
    let chain = |n: usize| (0..n).map(|_| Step::Interactive(vec![Round::empty()])).collect::<Vec<_>>();
    let server = Server::start(script(vec![KI], chain(MAX_STEPS))).await;
    let mut answers = Answers::default();
    sign_in_with(&server, b"", Mode::Interactive, Some(&mut answers)).await.unwrap();
    let server = Server::start(script(vec![KI], chain(MAX_STEPS + 1))).await;
    let mut answers = Answers::default();
    let e = sign_in_with(&server, b"", Mode::Interactive, Some(&mut answers)).await.unwrap_err();
    assert_eq!(e, auth_partial());
    assert_eq!(server.take_log().iter().filter(|l| l.starts_with("kbd")).count(), MAX_STEPS);
}

#[tokio::test]
async fn cancel_while_the_prompter_answers() {
    let server =
        Server::start(script(vec![KI], vec![Step::Interactive(vec![Round::one("Code: ", "42")])])).await;
    let cancel = CancelToken::new();
    let mut answers = Answers { cancel: Some(cancel.clone()), ..Answers::with(vec![Some(vec![b"42"])]) };
    let mut session = connect(&target(server.addr), &CancelToken::new()).await.unwrap();
    let login = Login::new(
        &mut session,
        "alice",
        b"",
        Some(&mut answers),
        Mode::Interactive,
        Duration::from_secs(5),
        &cancel,
    );
    assert_eq!(login.run().await, Err(Status::canceled()));
    // The answer was not sent.
    assert_eq!(server.take_log(), ["none alice", "kbd alice"]);
    // Tripped before: nothing is sent at all.
    let mut session = connect(&target(server.addr), &CancelToken::new()).await.unwrap();
    let login =
        Login::new(&mut session, "alice", b"secret", None, Mode::Password, Duration::from_secs(5), &cancel);
    assert_eq!(login.run().await, Err(Status::canceled()));
    assert_eq!(server.take_log(), Vec::<String>::new());
}

#[tokio::test]
async fn a_server_that_hangs_up_is_a_lost_connection() {
    let server = Server::start(Script { max_failures: Some(1), ..Script::password() }).await;
    let e = sign_in(&server, b"wrong", Mode::Password).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ConnectionLost, "{e:?}");
    assert_eq!(e.message, "The connection to the server was lost");
}

#[tokio::test]
async fn a_server_that_stops_answering_times_out() {
    let server = Server::start(Script::password()).await;
    let proxy = Proxy::start(server.addr).await;
    let mut session = connect(&target(proxy.addr), &CancelToken::new()).await.unwrap();
    proxy.stall(true);
    let c = CancelToken::new();
    let login =
        Login::new(&mut session, "alice", b"secret", None, Mode::Password, Duration::from_millis(200), &c);
    let e = login.run().await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::Timeout, "The server did not answer within 1 s"));
    assert!(
        format!("{:?}", Login::new(&mut session, "bob", b"pw", None, Mode::Password, Duration::ZERO, &c))
            .contains("bob")
    );
}
