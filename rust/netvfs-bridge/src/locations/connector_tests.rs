// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    AccountAccess, AdHocIdentity, Answer, Arc, AskId, Asker, AtomicBool, Attention, Duration, ErrorName,
    EstablishError, HashMap, IDENTITY_UNKNOWN, Identity, Instant, KEYBOARD_INTERACTIVE, LocationSpec,
    Ordering, OwnedValue, Params, Phase, PinStore, PromptRequest, QUESTION_TIMEOUT, Status, TaskContext,
    Value, Verdict, WAIT_SLICE, Waited, WorkerEvent, WorkerEvents, Zeroizing, account_pin, attention_for,
    identity_details, mpsc, prompt_answers, prompt_details, text, wait_for, zvariant,
};
use crate::ffi::{IdentityKind, Prompt};
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
    flag.store(true, Ordering::Release);
    assert_eq!(wait_for(&rx, &flag, Duration::ZERO), Waited::Got(1));
    assert_eq!(wait_for(&rx, &flag, Duration::from_secs(5)), Waited::Canceled);
    flag.store(false, Ordering::Release);
    let start = Instant::now();
    assert_eq!(wait_for(&rx, &flag, Duration::from_millis(250)), Waited::TimedOut);
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(250) && waited < Duration::from_secs(2), "{waited:?}");
    assert_eq!(wait_for(&rx, &flag, Duration::ZERO), Waited::TimedOut);
    let later = tx.clone();
    let sender = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        later.send(2).unwrap();
    });
    assert_eq!(wait_for(&rx, &flag, Duration::MAX), Waited::Got(2));
    sender.join().unwrap();
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

fn identity() -> Identity {
    Identity {
        kind: IdentityKind::Ssh,
        algorithm: "ssh-ed25519".into(),
        public_key: vec![9, 8, 7],
        fingerprint: "SHA256:abc".into(),
        pin: "ssh-ed25519 AAAA".into(),
    }
}

#[test]
fn identity_details_as_the_question_carries_them() {
    let d = identity_details(&identity(), &spec());
    assert_eq!(string(&d, "location"), "adhoc:3");
    assert_eq!(string(&d, "provider"), "sftp");
    assert_eq!(string(&d, "host"), "Srv");
    assert_eq!(string(&d, "algorithm"), "ssh-ed25519");
    assert_eq!(string(&d, "fingerprint"), "SHA256:abc");
    assert_eq!(i32::try_from(&d["port"]).unwrap(), 2222);
    assert_eq!(Vec::<u8>::try_from(d["publicKey"].try_clone().unwrap()).unwrap(), [9, 8, 7]);
    assert_eq!(sig(&d["port"]), "i");
    assert_eq!(d.len(), 7);
    let none = identity_details(&Identity::default(), &spec());
    assert_eq!(string(&none, "fingerprint"), "");
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
    assert!(prompt_answers(&asker, &t, &request(2)).is_none());
    assert!(prompt_answers(&asker, &t, &request(1)).is_none());
    assert!(prompt_answers(&asker, &t, &request(1)).is_none());
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
    let seen = identity();
    let unknown = Status::new(ErrorName::ServerIdentityUnknown, "unknown");
    let changed = Status::new(ErrorName::ServerIdentityChanged, "changed");
    let mut judge =
        AdHocIdentity { asker: &asker, pins: &pins, events: &events, task: &t, spec: &spec, declined: false };
    assert_eq!(judge.verdict(&seen, None), Verdict::UseCheck);
    assert_eq!(judge.verdict(&seen, Some(&changed)), Verdict::UseCheck);
    assert!(rx.try_recv().is_err());
    assert!(!judge.declined);
    let core = thread::spawn(move || {
        let first = answer_one(&mut rx, Some(Answer { accept: false, answers: Vec::new() }));
        answer_one(&mut rx, Some(yes(&[])));
        (first, rx)
    });
    assert_eq!(judge.verdict(&seen, Some(&unknown)), Verdict::UseCheck);
    assert!(judge.declined);
    assert_eq!(pins.pin("sftp://srv:2222"), "");
    judge.declined = false;
    assert_eq!(judge.verdict(&seen, Some(&unknown)), Verdict::AcceptUnknown);
    assert!(!judge.declined);
    assert_eq!(pins.pin("sftp://srv:2222"), "ssh-ed25519 AAAA");
    let ((_, session, kind, details), mut rx) = core.join().unwrap();
    assert_eq!((session, kind), (SessionId(7), IDENTITY_UNKNOWN));
    assert_eq!(string(&details, "fingerprint"), "SHA256:abc");
    assert!(rx.try_recv().is_err());
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
    let mut judge =
        AdHocIdentity { asker: &asker, pins: &pins, events: &events, task: &t, spec: &spec, declined: false };
    t.cancel.store(true, Ordering::Release);
    assert_eq!(judge.verdict(&seen, Some(&unknown)), Verdict::Cancel);
    assert!(!judge.declined);
    assert!(matches!(rx.blocking_recv(), Some(WorkerEvent::Ask { .. })));
    assert!(matches!(rx.blocking_recv(), Some(WorkerEvent::CancelQuestion(_))));
    assert!(PinStore::remove(&pins, "sftp://srv:2222"));
}

#[test]
fn files_answers_become_account_access() {
    use crate::accounts::{ConnectionParams, FilesAccess, Value as Helper};
    let access = AccountAccess::from(FilesAccess {
        params: ConnectionParams {
            provider: "sftp".into(),
            host: "h".into(),
            options: vec![("host_key".into(), Helper::String("pin".into()))],
            ..ConnectionParams::default()
        },
        credentials_id: 9,
        secret_optional: true,
    });
    assert_eq!((access.credentials_id, access.secret_optional), (9, true));
    assert_eq!((access.params.provider.as_str(), access.params.host.as_str()), ("sftp", "h"));
    assert_eq!(account_pin(&access.params), "pin");
}
