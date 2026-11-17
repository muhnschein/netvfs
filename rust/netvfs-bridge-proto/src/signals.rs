// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed signals of the bridge, read from one ordered stream (`Connection::signals`): per-signal
//! proxy streams may be observed out of order (`ListBatch` before `ListDone`).

use crate::errors::BridgeError;
use crate::methods::INTERFACE;
use crate::wire::{WireEntry, WireNearby, WireWalkItem};
use std::collections::HashMap;
use zbus::Message;
use zbus::message::Type as MessageType;
use zbus::zvariant::OwnedValue;

/// A signal of `org.netvfs.Bridge1` (the `SIGNALS` of [`crate::methods`]).
#[derive(Debug)]
pub enum Signal {
    /// The consent changed: `granted`, `denied` or `unknown`.
    ConsentChanged(String),
    /// The locations changed; `ListLocations` has the new list.
    LocationsChanged,
    /// Servers discovered nearby (while `Discover(true)`).
    NearbyChanged(Vec<WireNearby>),
    /// Entries of a `List` request.
    ListBatch {
        /// Request id.
        req: u32,
        /// Entries.
        entries: Vec<WireEntry>,
    },
    /// A `List` request ended.
    ListDone {
        /// Request id.
        req: u32,
        /// Bare error name, empty on success.
        error: String,
        /// Error message.
        message: String,
    },
    /// Bytes moved by a job.
    JobProgress {
        /// Job id.
        job: u32,
        /// Bytes done.
        done: i64,
        /// Bytes in all, -1 if not known.
        total: i64,
    },
    /// Entries of a `Walk` job.
    WalkBatch {
        /// Job id.
        job: u32,
        /// Entries with their paths.
        entries: Vec<WireWalkItem>,
    },
    /// A job ended.
    JobFinished {
        /// Job id.
        job: u32,
        /// Bare error name, empty on success.
        error: String,
        /// Error message.
        message: String,
        /// `detail`, `retryAfterMs` and job results.
        extra: HashMap<String, OwnedValue>,
    },
    /// The bridge asks the user something; `Answer` answers.
    Question {
        /// Question id.
        id: String,
        /// `identity-unknown`, `keyboard-interactive`, `insecure-consent`, …
        kind: String,
        /// What to show.
        details: HashMap<String, OwnedValue>,
    },
    /// The drives changed; `ListDrives` has the new list.
    DrivesChanged,
}

fn body<T>(msg: &Message) -> Result<T, BridgeError>
where
    T: serde::de::DeserializeOwned + zbus::zvariant::Type,
{
    msg.body().deserialize::<T>().map_err(|e| BridgeError::Protocol(e.to_string()))
}

/// Decodes a message into a [`Signal`]. `Ok(None)` for messages that are no `org.netvfs.Bridge1`
/// signal, and for newer signals this client does not know.
///
/// # Errors
/// [`BridgeError::Protocol`] for a known signal with another body.
pub fn decode_signal(msg: &Message) -> Result<Option<Signal>, BridgeError> {
    let header = msg.header();
    if header.primary().msg_type() != MessageType::Signal {
        return Ok(None);
    }
    if header.interface().map(zbus::names::InterfaceName::as_str) != Some(INTERFACE) {
        return Ok(None);
    }
    let Some(member) = header.member() else {
        return Ok(None);
    };
    decode_member(member.as_str(), msg)
}

fn decode_member(member: &str, msg: &Message) -> Result<Option<Signal>, BridgeError> {
    Ok(Some(match member {
        "ConsentChanged" => Signal::ConsentChanged(body::<(String,)>(msg)?.0),
        "LocationsChanged" => Signal::LocationsChanged,
        "NearbyChanged" => Signal::NearbyChanged(body::<(Vec<WireNearby>,)>(msg)?.0),
        "ListBatch" => {
            let (req, entries) = body::<(u32, Vec<WireEntry>)>(msg)?;
            Signal::ListBatch { req, entries }
        }
        "ListDone" => {
            let (req, error, message) = body::<(u32, String, String)>(msg)?;
            Signal::ListDone { req, error, message }
        }
        "JobProgress" => {
            let (job, done, total) = body::<(u32, i64, i64)>(msg)?;
            Signal::JobProgress { job, done, total }
        }
        "WalkBatch" => {
            let (job, entries) = body::<(u32, Vec<WireWalkItem>)>(msg)?;
            Signal::WalkBatch { job, entries }
        }
        "JobFinished" => {
            let (job, error, message, extra) =
                body::<(u32, String, String, HashMap<String, OwnedValue>)>(msg)?;
            Signal::JobFinished { job, error, message, extra }
        }
        "Question" => {
            let (id, kind, details) = body::<(String, String, HashMap<String, OwnedValue>)>(msg)?;
            Signal::Question { id, kind, details }
        }
        "DrivesChanged" => Signal::DrivesChanged,
        _ => return Ok(None),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{entry_kind, value_i64, value_str};
    use zbus::zvariant::{DynamicType, Value};

    fn signal<B: serde::Serialize + DynamicType>(iface: &str, member: &str, body: &B) -> Message {
        Message::signal("/org/netvfs/Bridge", iface, member).unwrap().build(body).unwrap()
    }

    #[test]
    fn job_progress_decodes_its_counts() {
        let msg = signal(INTERFACE, "JobProgress", &(7u32, 512i64, -1i64));
        assert!(matches!(
            decode_signal(&msg).unwrap(),
            Some(Signal::JobProgress { job: 7, done: 512, total: -1 })
        ));
    }

    #[test]
    fn question_decodes_its_details() {
        let details = HashMap::from([("detail".to_owned(), Value::from("HTTP 429"))]);
        let msg =
            signal(INTERFACE, "Question", &("q1".to_owned(), "keyboard-interactive".to_owned(), details));
        match decode_signal(&msg).unwrap() {
            Some(Signal::Question { id, kind, details }) => {
                assert_eq!((id.as_str(), kind.as_str()), ("q1", "keyboard-interactive"));
                assert_eq!(value_str(&details["detail"]).as_deref(), Some("HTTP 429"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn the_other_signals_decode_to_their_variants() {
        let consent = signal(INTERFACE, "ConsentChanged", &("denied".to_owned(),));
        match decode_signal(&consent).unwrap() {
            Some(Signal::ConsentChanged(state)) => assert_eq!(state, "denied"),
            other => panic!("unexpected {other:?}"),
        }
        let locations = signal(INTERFACE, "LocationsChanged", &());
        assert!(matches!(decode_signal(&locations).unwrap(), Some(Signal::LocationsChanged)));
        let drives = signal(INTERFACE, "DrivesChanged", &());
        assert!(matches!(decode_signal(&drives).unwrap(), Some(Signal::DrivesChanged)));
        let server = WireNearby { name: "NAS".into(), provider: "smb".into(), host: "nas".into(), port: 445 };
        let nearby = signal(INTERFACE, "NearbyChanged", &(vec![server.clone()],));
        match decode_signal(&nearby).unwrap() {
            Some(Signal::NearbyChanged(list)) => assert_eq!(list, vec![server]),
            other => panic!("unexpected {other:?}"),
        }
        let entry = WireEntry::unknown(b"a", entry_kind::FILE);
        let batch = signal(INTERFACE, "ListBatch", &(5u32, vec![entry.clone()]));
        match decode_signal(&batch).unwrap() {
            Some(Signal::ListBatch { req, entries }) => assert_eq!((req, entries), (5, vec![entry])),
            other => panic!("unexpected {other:?}"),
        }
        let done = signal(INTERFACE, "ListDone", &(5u32, "NotFound".to_owned(), "gone".to_owned()));
        match decode_signal(&done).unwrap() {
            Some(Signal::ListDone { req, error, message }) => {
                assert_eq!((req, error.as_str(), message.as_str()), (5, "NotFound", "gone"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let item = WireWalkItem { path: b"t/a".to_vec(), entry: WireEntry::unknown(b"a", entry_kind::FILE) };
        let walk = signal(INTERFACE, "WalkBatch", &(3u32, vec![item.clone()]));
        match decode_signal(&walk).unwrap() {
            Some(Signal::WalkBatch { job, entries }) => assert_eq!((job, entries), (3, vec![item])),
            other => panic!("unexpected {other:?}"),
        }
        let extra = HashMap::from([("bytes".to_owned(), Value::from(6i64))]);
        let finished = signal(INTERFACE, "JobFinished", &(3u32, String::new(), String::new(), extra));
        match decode_signal(&finished).unwrap() {
            Some(Signal::JobFinished { job, error, extra, .. }) => {
                assert_eq!((job, error.as_str()), (3, ""));
                assert_eq!(value_i64(&extra["bytes"]), Some(6));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn only_signals_of_the_bridge_are_decoded() {
        let other = signal("org.example.Other", "JobProgress", &(1u32, 2i64, 3i64));
        assert!(decode_signal(&other).unwrap().is_none());
        let call = Message::method_call("/org/netvfs/Bridge", "JobProgress")
            .unwrap()
            .interface(INTERFACE)
            .unwrap()
            .build(&(1u32, 2i64, 3i64))
            .unwrap();
        assert!(decode_signal(&call).unwrap().is_none());
        let newer = signal(INTERFACE, "SomethingNew", &(1u32,));
        assert!(decode_signal(&newer).unwrap().is_none());
    }

    #[test]
    fn a_known_signal_with_another_body_is_a_protocol_error() {
        let msg = signal(INTERFACE, "JobProgress", &("seven",));
        assert!(matches!(decode_signal(&msg), Err(BridgeError::Protocol(_))));
    }
}
