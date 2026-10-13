// SPDX-License-Identifier: LGPL-2.1-or-later
// The connector's policy without C++: waits, questions, details, attention
// and the ad-hoc identity verdict. Its establish paths run against the
// C++ fake backend in tests/backend.rs.
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::*;
use crate::ffi::Prompt;
use crate::server::SessionId;
use std::sync::Mutex;
use std::thread;
use zbus::zvariant::Signature;

type Events = tokio::sync::mpsc::UnboundedReceiver<WorkerEvent>;

fn events() -> (WorkerEvents, Events) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (WorkerEvents::channel(tx), rx)
}

fn task() -> TaskContext {
    TaskContext::new(SessionId(7), Arc::new(AtomicBool::new(false)))
}

fn sig(v: &OwnedValue) -> String {
    v.value_signature().to_string()
}

fn string(d: &HashMap<String, OwnedValue>, k: &str) -> String {
    String::try_from(d[k].try_clone().unwrap()).unwrap()
}

/// The core's side of one question: what was asked, answered with `reply`.
fn answer_one(
    rx: &mut Events,
    reply: Option<Answer>,
) -> (AskId, SessionId, &'static str, HashMap<String, OwnedValue>) {
    match rx.blocking_recv() {
        Some(WorkerEvent::Ask { ask, session, kind, details, answer }) => {
            answer.send(reply).unwrap();
            (ask, session, kind, details)
        }
        other => panic!("not a question: {other:?}"),
    }
}

fn yes(answers: &[&[u8]]) -> Answer {
    Answer { accept: true, answers: answers.iter().map(|a| Zeroizing::new(a.to_vec())).collect() }
}

#[test]
fn waits_end_with_a_value_a_cancel_a_timeout_or_a_gone_core() {
    let flag = AtomicBool::new(false);
    let (tx, rx) = mpsc::channel();
    tx.send(1).unwrap();
    // A value already there wins, even over a cancel.
    flag.store(true, Ordering::Release);
    assert_eq!(wait_for(&rx, &flag, Duration::ZERO), Waited::Got(1));
    assert_eq!(wait_for(&rx, &flag, Duration::from_secs(5)), Waited::Canceled);
    flag.store(false, Ordering::Release);
    let start = Instant::now();
    assert_eq!(wait_for(&rx, &flag, Duration::from_millis(250)), Waited::TimedOut);
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(250) && waited < Duration::from_secs(2), "{waited:?}");
    assert_eq!(wait_for(&rx, &flag, Duration::ZERO), Waited::TimedOut);
    // A value that comes while waiting; also with no time limit at all.
    let later = tx.clone();
    let sender = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        later.send(2).unwrap();
    });
    assert_eq!(wait_for(&rx, &flag, Duration::MAX), Waited::Got(2));
    sender.join().unwrap();
    // A cancel while waiting is seen within a slice.
    let flag = Arc::new(AtomicBool::new(false));
    let setter = Arc::clone(&flag);
    let canceler = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        setter.store(true, Ordering::Release);
    });
    let start = Instant::now();
    assert_eq!(wait_for(&rx, &flag, Duration::from_secs(10)), Waited::Canceled);
    assert!(start.elapsed() < WAIT_SLICE * 4, "{:?}", start.elapsed());
    canceler.join().unwrap();
    // The core dropped its sender.
    drop(tx);
    assert_eq!(wait_for(&rx, &AtomicBool::new(false), Duration::from_secs(10)), Waited::Gone);
    let (tx, rx) = mpsc::channel::<u8>();
    let dropper = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        drop(tx);
    });
    assert_eq!(wait_for(&rx, &AtomicBool::new(false), Duration::from_secs(10)), Waited::Gone);
    dropper.join().unwrap();
}

#[test]
fn asker_relays_through_the_core() {
    let (events, mut rx) = events();
    let asker = Asker::new(events, Duration::from_secs(10));
    let t = task();
    let core = thread::spawn(move || {
        let first = answer_one(&mut rx, Some(yes(&[b"1"])));
        let second = answer_one(&mut rx, None);
        (first, second, rx)
    });
    let mut details = HashMap::new();
    details.insert("k".to_owned(), text("v"));
    let answer = asker.ask(&t, KEYBOARD_INTERACTIVE, details).unwrap();
    assert!(answer.accept);
    assert_eq!(answer.answers[0].as_slice(), b"1");
    assert!(asker.ask(&t, IDENTITY_UNKNOWN, HashMap::new()).is_none());
    let (first, second, mut rx) = core.join().unwrap();
    assert_eq!((first.1, first.2), (SessionId(7), KEYBOARD_INTERACTIVE));
    assert_eq!(string(&first.3, "k"), "v");
    assert_eq!(second.2, IDENTITY_UNKNOWN);
    assert!(second.0 > first.0);
    // Answered "none": nothing to withdraw.
    assert!(rx.try_recv().is_err());
}

#[test]
fn a_question_nobody_answers_is_withdrawn() {
    let (events, mut rx) = events();
    let asker = Asker::new(events, Duration::from_millis(200));
    let t = task();
    let start = Instant::now();
    assert!(asker.ask(&t, IDENTITY_UNKNOWN, HashMap::new()).is_none());
    assert!(start.elapsed() >= Duration::from_millis(200));
    let Some(WorkerEvent::Ask { ask, answer, .. }) = rx.blocking_recv() else { panic!("no question") };
    assert!(matches!(rx.blocking_recv(), Some(WorkerEvent::CancelQuestion(id)) if id == ask));
    drop(answer);
    // Canceled while waiting: withdrawn as well.
    let asker = Asker::new(asker.events, QUESTION_TIMEOUT);
    let flag = Arc::clone(&t.cancel);
    let canceler = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        flag.store(true, Ordering::Release);
    });
    assert!(asker.ask(&t, IDENTITY_UNKNOWN, HashMap::new()).is_none());
    canceler.join().unwrap();
    let Some(WorkerEvent::Ask { ask, .. }) = rx.blocking_recv() else { panic!("no question") };
    assert!(matches!(rx.blocking_recv(), Some(WorkerEvent::CancelQuestion(id)) if id == ask));
    // The core dropped the question without an answer: nothing to withdraw.
    let (events, mut rx) = self::events();
    let asker = Asker::new(events, QUESTION_TIMEOUT);
    let core = thread::spawn(move || {
        let Some(WorkerEvent::Ask { answer, .. }) = rx.blocking_recv() else { panic!("no question") };
        drop(answer);
        rx
    });
    assert!(asker.ask(&task(), IDENTITY_UNKNOWN, HashMap::new()).is_none());
    let mut rx = core.join().unwrap();
    assert!(rx.try_recv().is_err());
}

fn spec() -> LocationSpec {
    let params = Params { provider: "sftp".into(), host: "Srv".into(), port: 2222, ..Params::default() };
    LocationSpec::ad_hoc("adhoc:3", "n", params, Vec::new(), None)
}

fn identity(kind: IdentityKind) -> Identity {
    let mut details = crate::ffi::ValueMap::new();
    details.insert("notAfter".into(), Value::Str("2030-01-01T00:00:00Z".into()));
    details.insert("depth".into(), Value::Int(2));
    details.insert("selfSigned".into(), Value::Bool(true));
    details.insert("der".into(), Value::Bytes(vec![1, 2]));
    details.insert("names".into(), Value::StrList(vec!["a".into(), "b".into()]));
    details.insert("host".into(), Value::Str("from details".into()));
    Identity {
        kind,
        algorithm: "ssh-ed25519".into(),
        public_key: vec![9, 8, 7],
        fingerprint: "SHA256:abc".into(),
        pin: "ssh-ed25519 AAAA".into(),
        system_trusted: true,
        problems: 5,
        details,
    }
}

#[test]
fn identity_details_as_the_question_carries_them() {
    let d = identity_details(&identity(IdentityKind::Ssh), &spec());
    assert_eq!(string(&d, "location"), "adhoc:3");
    assert_eq!(string(&d, "provider"), "sftp");
    assert_eq!(string(&d, "kind"), "ssh");
    assert_eq!(string(&d, "algorithm"), "ssh-ed25519");
    assert_eq!(string(&d, "fingerprint"), "SHA256:abc");
    assert_eq!(i32::try_from(&d["port"]).unwrap(), 2222);
    assert_eq!(Vec::<u8>::try_from(d["publicKey"].try_clone().unwrap()).unwrap(), [9, 8, 7]);
    assert!(bool::try_from(&d["systemTrusted"]).unwrap());
    assert_eq!(i32::try_from(&d["problems"]).unwrap(), 5);
    // The backend's details, typed, after the fixed ones (and over them).
    assert_eq!(string(&d, "host"), "from details");
    assert_eq!(string(&d, "notAfter"), "2030-01-01T00:00:00Z");
    assert_eq!(i64::try_from(&d["depth"]).unwrap(), 2);
    assert!(bool::try_from(&d["selfSigned"]).unwrap());
    assert_eq!(sig(&d["der"]), "ay");
    assert_eq!(sig(&d["names"]), "as");
    assert_eq!(sig(&d["port"]), "i");
    assert_eq!(sig(&d["depth"]), "x");
    assert_eq!(d.len(), 15);
    let tls = identity_details(&identity(IdentityKind::Tls), &spec());
    assert_eq!(string(&tls, "kind"), "tls");
    let none = identity_details(&Identity::default(), &spec());
    assert_eq!(string(&none, "kind"), "ssh");
    assert_eq!(string(&none, "host"), "Srv");
}

fn request(n: usize) -> PromptRequest {
    PromptRequest {
        name: "otp".into(),
        instruction: "Enter the code".into(),
        prompts: (0..n).map(|i| Prompt { text: format!("Code {i}: "), echo: i % 2 == 1 }).collect(),
    }
}

#[test]
fn prompt_details_as_the_question_carries_them() {
    let d = prompt_details(&request(2));
    assert_eq!(string(&d, "name"), "otp");
    assert_eq!(string(&d, "instruction"), "Enter the code");
    assert_eq!(sig(&d["prompts"]), "as");
    assert_eq!(Vec::<String>::try_from(d["prompts"].try_clone().unwrap()).unwrap(), ["Code 0: ", "Code 1: "]);
    assert_eq!(d["echo"].value_signature(), &Signature::static_array(&Signature::Variant));
    let echo: Vec<OwnedValue> = Vec::try_from(d["echo"].try_clone().unwrap()).unwrap();
    let echo: Vec<bool> = echo
        .iter()
        .map(|v| match &**v {
            zvariant::Value::Value(inner) => bool::try_from(&**inner).unwrap(),
            other => panic!("not a variant: {other:?}"),
        })
        .collect();
    assert_eq!(echo, [false, true]);
    assert_eq!(d.len(), 4);
}

#[test]
fn prompt_answers_need_acceptance_and_one_per_prompt() {
    let (events, mut rx) = events();
    let asker = Asker::new(events, Duration::from_secs(10));
    let core = thread::spawn(move || {
        let (_, _, kind, details) = answer_one(&mut rx, Some(yes(&[b"1", b"2"])));
        answer_one(&mut rx, Some(yes(&[b"1"])));
        answer_one(&mut rx, Some(Answer { accept: false, answers: vec![Zeroizing::new(b"1".to_vec())] }));
        answer_one(&mut rx, None);
        (kind, details)
    });
    let t = task();
    let answers = prompt_answers(&asker, &t, &request(2)).unwrap();
    assert_eq!(answers.iter().map(|a| a.to_vec()).collect::<Vec<_>>(), [b"1".to_vec(), b"2".to_vec()]);
    assert!(prompt_answers(&asker, &t, &request(2)).is_none()); // one answer for two prompts
    assert!(prompt_answers(&asker, &t, &request(1)).is_none()); // declined
    assert!(prompt_answers(&asker, &t, &request(1)).is_none()); // no answer
    let (kind, details) = core.join().unwrap();
    assert_eq!(kind, KEYBOARD_INTERACTIVE);
    assert_eq!(string(&details, "name"), "otp");
}

#[test]
fn attention_after_a_failed_account_connection() {
    let failed = |phase, name| EstablishError { phase, status: Status::new(name, "x") };
    for phase in [Phase::Identity, Phase::Authenticate] {
        assert_eq!(
            attention_for(&failed(phase, ErrorName::AuthFailed), "pin"),
            Some((Attention::AuthFailed, String::new()))
        );
        assert_eq!(
            attention_for(&failed(phase, ErrorName::ServerIdentityChanged), "pin"),
            Some((Attention::ServerIdentityChanged, "pin".to_owned()))
        );
        assert_eq!(
            attention_for(&failed(phase, ErrorName::ServerIdentityUnknown), "pin"),
            Some((Attention::ServerIdentityChanged, "pin".to_owned()))
        );
        assert_eq!(attention_for(&failed(phase, ErrorName::Timeout), "pin"), None);
    }
    // Before the identity check, or while fetching the secret: none.
    for phase in [Phase::Connect, Phase::Credentials, Phase::Done] {
        assert_eq!(attention_for(&failed(phase, ErrorName::AuthFailed), "pin"), None);
        assert_eq!(attention_for(&failed(phase, ErrorName::ServerIdentityChanged), "pin"), None);
    }
}

#[test]
fn account_pins_come_from_host_key() {
    let mut params = Params::default();
    assert_eq!(account_pin(&params), "");
    params.options.insert("host_key".into(), Value::Str("ssh-ed25519 AAAA".into()));
    assert_eq!(account_pin(&params), "ssh-ed25519 AAAA");
    params.options.insert("host_key".into(), Value::Bytes(b"ssh-rsa BBBB".to_vec()));
    assert_eq!(account_pin(&params), "ssh-rsa BBBB");
    params.options.insert("host_key".into(), Value::Int(1));
    assert_eq!(account_pin(&params), "");
}

#[derive(Default)]
struct Pins {
    pins: Mutex<HashMap<String, String>>,
    refuse: bool,
}

impl PinStore for Pins {
    fn pin(&self, key: &str) -> String {
        self.pins.lock().unwrap().get(key).cloned().unwrap_or_default()
    }

    fn set_pin(&self, key: &str, pin: &str) -> bool {
        self.pins.lock().unwrap().insert(key.to_owned(), pin.to_owned());
        !self.refuse
    }

    fn remove(&self, key: &str) -> bool {
        self.pins.lock().unwrap().remove(key).is_some()
    }
}

#[test]
fn ad_hoc_identity_verdicts() {
    let (events, mut rx) = events();
    let asker = Asker::new(events.clone(), Duration::from_secs(10));
    let pins = Pins::default();
    let t = task();
    let spec = spec();
    let seen = identity(IdentityKind::Ssh);
    let unknown = Status::new(ErrorName::ServerIdentityUnknown, "unknown");
    let changed = Status::new(ErrorName::ServerIdentityChanged, "changed");
    let mut judge =
        AdHocIdentity { asker: &asker, pins: &pins, events: &events, task: &t, spec: &spec, declined: false };
    // The check passed, or the identity changed: the check stands, no
    // question.
    assert_eq!(judge.verdict(&seen, None), Verdict::UseCheck);
    assert_eq!(judge.verdict(&seen, Some(&changed)), Verdict::UseCheck);
    assert!(rx.try_recv().is_err());
    assert!(!judge.declined);
    // Unknown and declined.
    let core = thread::spawn(move || {
        let first = answer_one(&mut rx, Some(Answer { accept: false, answers: Vec::new() }));
        answer_one(&mut rx, Some(yes(&[])));
        (first, rx)
    });
    assert_eq!(judge.verdict(&seen, Some(&unknown)), Verdict::UseCheck);
    assert!(judge.declined);
    assert_eq!(pins.pin("sftp://srv:2222"), "");
    // Unknown and accepted: pinned under the host key.
    judge.declined = false;
    assert_eq!(judge.verdict(&seen, Some(&unknown)), Verdict::AcceptUnknown);
    assert!(!judge.declined);
    assert_eq!(pins.pin("sftp://srv:2222"), "ssh-ed25519 AAAA");
    let ((_, session, kind, details), mut rx) = core.join().unwrap();
    assert_eq!((session, kind), (SessionId(7), IDENTITY_UNKNOWN));
    assert_eq!(string(&details, "fingerprint"), "SHA256:abc");
    assert!(rx.try_recv().is_err());
    // A pin that cannot be saved: accepted anyway, with a warning.
    let refusing = Pins { refuse: true, ..Pins::default() };
    let mut judge = AdHocIdentity {
        asker: &asker,
        pins: &refusing,
        events: &events,
        task: &t,
        spec: &spec,
        declined: false,
    };
    let core = thread::spawn(move || {
        answer_one(&mut rx, Some(yes(&[])));
        let warning = rx.blocking_recv();
        (warning, rx)
    });
    assert_eq!(judge.verdict(&seen, Some(&unknown)), Verdict::AcceptUnknown);
    let (warning, mut rx) = core.join().unwrap();
    assert!(
        matches!(warning, Some(WorkerEvent::Warning(w)) if w == "Cannot store an accepted server identity")
    );
    // Canceled while asking: Cancel, not a declined identity.
    let mut judge =
        AdHocIdentity { asker: &asker, pins: &pins, events: &events, task: &t, spec: &spec, declined: false };
    t.cancel.store(true, Ordering::Release);
    assert_eq!(judge.verdict(&seen, Some(&unknown)), Verdict::Cancel);
    assert!(!judge.declined);
    assert!(matches!(rx.blocking_recv(), Some(WorkerEvent::Ask { .. })));
    assert!(matches!(rx.blocking_recv(), Some(WorkerEvent::CancelQuestion(_))));
    assert!(PinStore::remove(&pins, "sftp://srv:2222"));
}
