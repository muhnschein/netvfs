// SPDX-License-Identifier: LGPL-2.1-or-later
use std::time::Duration;

use super::*;
use crate::crypto::Cipher;
use crate::fake::{self, Peer, SESSION_ID, chain, error, four, interim, pair, session_keys};
use crate::msg::file::{Create, attributes, disposition};

const T: Duration = Duration::from_secs(5);

async fn started() -> (Conn, Peer) {
    let (client, peer) = pair().await;
    (Conn::start(client, T), peer)
}

/// A connection whose session has keys (`cipher`: sealing too) and
/// `credits` credits.
async fn established(cipher: Option<Cipher>, encrypt: bool, credits: u32) -> (Conn, Peer) {
    let (conn, mut peer) = started().await;
    let (client, server) = session_keys(cipher);
    conn.set_session_id(SESSION_ID);
    conn.establish(Some(client), encrypt);
    conn.set_limits(1 << 20, true);
    conn.0.lock().credits = credits;
    peer.keys = Some(server);
    (conn, peer)
}

fn echo() -> Element {
    Element::new(Command::Echo, four_byte_request())
}

#[tokio::test]
async fn an_unprotected_call_and_its_credits() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let server = async {
        let req = peer.recv_one().await;
        assert_eq!(req.command(), Command::Echo);
        assert_eq!((req.header.message_id, req.header.credit_charge), (0, 1));
        assert_eq!(req.header.credits, 128);
        assert!(!req.header.is_signed() && !req.encrypted);
        peer.send(&[fake::response(&req, NtStatus::SUCCESS, &four(), 10)], false).await;
        peer
    };
    let (r, mut peer) = tokio::join!(conn.call(Target::SESSION, echo(), &c), server);
    r.unwrap().ok().unwrap();
    assert_eq!(conn.credits(), 10);
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        assert_eq!((req.header.message_id, req.header.credits), (1, 119));
        peer.send(&[error(&req, NtStatus::ACCESS_DENIED, 1)], false).await;
    });
    assert_eq!(r.unwrap().ok(), Err(Error::Status(NtStatus::ACCESS_DENIED)));
    assert_eq!(conn.credits(), 10);
}

#[tokio::test]
async fn statuses_and_error_bodies() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        peer.send(&[fake::response(&req, NtStatus::ACCESS_DENIED, &[9, 0], 1)], false).await;
    });
    let r = r.unwrap();
    assert!(matches!(r.ok(), Err(Error::Protocol(_))));
    assert_eq!(r.expect(&[NtStatus::ACCESS_DENIED]), Ok(NtStatus::ACCESS_DENIED));
}

#[tokio::test]
async fn a_response_to_nothing_ends_the_connection() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let mut req = peer.recv_one().await;
        req.header.message_id = 7;
        peer.send(&[fake::response(&req, NtStatus::SUCCESS, &four(), 1)], false).await;
    });
    let e = r.unwrap_err();
    assert!(matches!(e, Error::Protocol(ref m) if m.contains("no outstanding request")), "{e}");
    assert_eq!(conn.usable(), Err(e));
}

#[tokio::test]
async fn a_response_with_another_command_ends_the_connection() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let mut req = peer.recv_one().await;
        req.header.command = Command::Logoff.code();
        peer.send(&[fake::response(&req, NtStatus::SUCCESS, &four(), 1)], false).await;
    });
    assert!(matches!(r, Err(Error::Protocol(ref m)) if m.contains("LOGOFF response to a ECHO")), "{r:?}");
}

#[tokio::test]
async fn requests_and_compressed_frames_end_the_connection() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
        msg[16] = 0; // no SERVER_TO_REDIR
        peer.send(&[msg], false).await;
    });
    assert!(matches!(r, Err(Error::Protocol(ref m)) if m.contains("sent a request")), "{r:?}");
    let (conn, mut peer) = started().await;
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        drop(peer.recv_one().await);
        peer.send_raw(&[0xFC, b'S', b'M', b'B', 0, 0, 0, 0]).await;
    });
    assert!(matches!(r, Err(Error::Policy(ref m)) if m.contains("compressed")), "{r:?}");
}

#[tokio::test]
async fn notifications_are_skipped() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        let mut note = req.clone();
        note.header.message_id = NOTIFICATION_MID;
        note.header.command = Command::OplockBreak.code();
        peer.send(&[fake::response(&note, NtStatus::SUCCESS, &[24, 0], 500)], false).await;
        peer.send(&[fake::response(&req, NtStatus::SUCCESS, &four(), 3)], false).await;
    });
    r.unwrap().ok().unwrap();
    assert_eq!(conn.credits(), 3);
}

#[tokio::test]
async fn signed_requests_need_signed_responses() {
    let (conn, mut peer) = established(None, false, 8).await;
    let c = CancelToken::new();
    let (r, mut peer) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        assert!(req.header.is_signed() && !req.encrypted);
        assert_eq!(req.header.session_id, SESSION_ID);
        let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
        peer.sign(&mut msg);
        peer.send(&[msg], false).await;
        peer
    });
    r.unwrap().ok().unwrap();
    // Unsigned: refused, and the connection is gone.
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        peer.send(&[error(&req, NtStatus::ACCESS_DENIED, 1)], false).await;
    });
    let e = r.unwrap_err();
    assert!(matches!(e, Error::Lost(ref m) if m.contains("unsigned ECHO response")), "{e}");
    assert!(matches!(conn.usable(), Err(Error::Lost(_))));
}

#[tokio::test]
async fn a_bad_signature_ends_the_connection() {
    for flip in [0usize, 30, 60, 66] {
        let (conn, mut peer) = established(None, false, 8).await;
        let c = CancelToken::new();
        let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
            let req = peer.recv_one().await;
            let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
            peer.sign(&mut msg);
            msg[flip] ^= 0x01;
            peer.send(&[msg], false).await;
        });
        let e = r.unwrap_err();
        assert!(matches!(e, Error::Lost(_)), "{flip}: {e}");
    }
}

#[tokio::test]
async fn a_signed_response_must_name_the_session() {
    let (conn, mut peer) = established(None, false, 8).await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let mut req = peer.recv_one().await;
        req.header.session_id = 1;
        let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
        peer.sign(&mut msg);
        peer.send(&[msg], false).await;
    });
    assert!(matches!(r, Err(Error::Lost(ref m)) if m.contains("another session")), "{r:?}");
}

#[tokio::test]
async fn interim_responses_may_be_unsigned_and_extend_the_deadline() {
    let (client, mut peer) = pair().await;
    let conn = Conn::start(client, Duration::from_millis(300));
    let (keys, server) = session_keys(None);
    conn.set_session_id(SESSION_ID);
    conn.establish(Some(keys), false);
    peer.keys = Some(server);
    conn.0.lock().credits = 4;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        peer.send(&[interim(&req, 77, 2)], false).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        peer.send(&[interim(&req, 77, 0)], false).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
        msg[16..20].copy_from_slice(&(flags::SERVER_TO_REDIR | flags::ASYNC_COMMAND).to_le_bytes());
        msg[32..40].copy_from_slice(&77u64.to_le_bytes());
        peer.sign(&mut msg);
        peer.send(&[msg], false).await;
    });
    r.unwrap().ok().unwrap();
    assert_eq!(conn.credits(), 3 + 2 + 1);
}

#[tokio::test]
async fn too_many_interim_responses_end_the_connection() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        for _ in 0..=MAX_INTERIM {
            peer.send(&[interim(&req, 5, 0)], false).await;
        }
    });
    assert!(matches!(r, Err(Error::Protocol(ref m)) if m.contains("interim")), "{r:?}");
}

#[tokio::test]
async fn before_negotiate_frames_up_to_64_kib_are_taken() {
    for (len, ok) in [(65_536, true), (65_537, false)] {
        let (conn, mut peer) = started().await;
        let c = CancelToken::new();
        let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
            let req = peer.recv_one().await;
            let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
            msg.resize(len, 0);
            peer.send(&[msg], false).await;
        });
        assert_eq!(r.is_ok(), ok, "{len}: {r:?}");
    }
}

#[tokio::test]
async fn up_to_max_interim_responses_are_fine() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        for _ in 0..MAX_INTERIM {
            peer.send(&[interim(&req, 5, 0)], false).await;
        }
        let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
        msg[16..20].copy_from_slice(&(flags::SERVER_TO_REDIR | flags::ASYNC_COMMAND).to_le_bytes());
        msg[32..40].copy_from_slice(&5u64.to_le_bytes());
        peer.send(&[msg], false).await;
    });
    r.unwrap().ok().unwrap();
}

#[tokio::test]
async fn message_ids_run_up_to_the_notification_id() {
    let (conn, mut peer) = established(None, false, 8).await;
    let c = CancelToken::new();
    conn.0.lock().next_mid = NOTIFICATION_MID - 1;
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        assert_eq!(req.header.message_id, NOTIFICATION_MID - 1);
        let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
        peer.sign(&mut msg);
        peer.send(&[msg], false).await;
    });
    r.unwrap().ok().unwrap();
    let e = conn.call(Target::SESSION, echo(), &c).await.unwrap_err();
    assert_eq!(e, Error::Protocol("message ids used up".into()));
}

#[tokio::test]
async fn send_now_goes_only_with_enough_credits() {
    let (conn, mut peer) = established(None, false, 1).await;
    let tickets = conn.send_now(Target::SESSION, &[echo()]).unwrap().unwrap();
    assert_eq!(tickets.len(), 1);
    assert_eq!(peer.recv_one().await.command(), Command::Echo);
    assert!(conn.send_now(Target::SESSION, &[echo()]).unwrap().is_none());
    assert_eq!(conn.0.lock().next_mid, 1);
}

#[tokio::test]
async fn encrypted_requests_need_encrypted_responses() {
    for cipher in [Cipher::Aes128Gcm, Cipher::Aes256Gcm] {
        let (conn, mut peer) = established(Some(cipher), true, 8).await;
        let c = CancelToken::new();
        let (r, mut peer) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
            let req = peer.recv_one().await;
            assert!(req.encrypted && !req.header.is_signed());
            peer.send(&[fake::response(&req, NtStatus::SUCCESS, &four(), 1)], true).await;
            peer
        });
        r.unwrap().ok().unwrap();
        let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
            let req = peer.recv_one().await;
            let mut msg = error(&req, NtStatus::ACCESS_DENIED, 1);
            peer.sign(&mut msg);
            peer.send(&[msg], false).await;
        });
        assert!(matches!(r, Err(Error::Lost(ref m)) if m.contains("unencrypted ECHO")), "{r:?}");
    }
}

#[tokio::test]
async fn a_tampered_transform_ends_the_connection() {
    for at in [0usize, 20, 40, 44, 52, 60, 100] {
        let (conn, mut peer) = established(Some(Cipher::Aes128Gcm), true, 8).await;
        let c = CancelToken::new();
        let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
            let req = peer.recv_one().await;
            let msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
            let mut wire = peer.keys.as_mut().unwrap().seal.as_mut().unwrap().seal(&msg).unwrap();
            wire[at] ^= 0x80;
            peer.send_raw(&wire).await;
        });
        assert!(matches!(r, Err(Error::Lost(_))), "{at}: {r:?}");
    }
}

#[tokio::test]
async fn an_encrypting_tree_on_a_signing_session() {
    let (conn, mut peer) = established(Some(Cipher::Aes128Gcm), false, 8).await;
    let c = CancelToken::new();
    let tree = Target { tree_id: 9, encrypt: true };
    let (r, ()) = tokio::join!(conn.call(tree, echo(), &c), async {
        let req = peer.recv_one().await;
        assert!(req.encrypted);
        assert_eq!(req.header.tree_id, 9);
        peer.send(&[fake::response(&req, NtStatus::SUCCESS, &four(), 1)], true).await;
    });
    r.unwrap().ok().unwrap();
    let (conn, _peer) = established(None, false, 8).await;
    assert!(!conn.can_encrypt());
    assert!(matches!(conn.call(tree, echo(), &c).await, Err(Error::Protocol(_))));
}

#[tokio::test]
async fn an_encrypted_message_before_keys_is_refused() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        drop(peer.recv_one().await);
        let (_, mut server) = session_keys(Some(Cipher::Aes128Gcm));
        let wire = server.seal.as_mut().unwrap().seal(&[0u8; 70]).unwrap();
        peer.send_raw(&wire).await;
    });
    assert!(matches!(r, Err(Error::Policy(ref m)) if m.contains("no key")), "{r:?}");
}

#[tokio::test]
async fn compounds_are_padded_signed_per_element_and_split_back() {
    let (conn, mut peer) = established(None, false, 8).await;
    let c = CancelToken::new();
    let create = Create {
        name: &[u16::from(b'a')],
        access: 0x80,
        attributes: attributes::NORMAL,
        disposition: disposition::OPEN,
        options: 0,
    };
    let elements = vec![
        Element::new(Command::Create, create.encode().unwrap()),
        Element::new(Command::Close, close_request(&[0xFF; 16])).related(),
    ];
    let (r, ()) = tokio::join!(conn.compound(Target { tree_id: 3, encrypt: false }, elements, &c), async {
        let reqs = peer.recv().await;
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].msg.len() % 8, 0);
        assert_eq!(reqs[0].header.next_command as usize, reqs[0].msg.len());
        assert_eq!(reqs[0].header.flags & flags::RELATED_OPERATIONS, 0);
        assert_ne!(reqs[1].header.flags & flags::RELATED_OPERATIONS, 0);
        assert_eq!((reqs[0].header.message_id, reqs[1].header.message_id), (0, 1));
        assert_eq!((reqs[0].header.credits, reqs[1].header.credits), (122, 1));
        let mut msgs = chain(vec![
            error(&reqs[0], NtStatus::OBJECT_NAME_NOT_FOUND, 1),
            error(&reqs[1], NtStatus::OBJECT_NAME_NOT_FOUND, 1),
        ]);
        for m in &mut msgs {
            peer.sign(m);
        }
        peer.send(&msgs, false).await;
    });
    let r = r.unwrap();
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|x| x.status() == NtStatus::OBJECT_NAME_NOT_FOUND));
    assert_eq!(conn.credits(), 8);
}

#[tokio::test]
async fn sealed_compounds_and_responses_in_separate_frames() {
    let (conn, mut peer) = established(Some(Cipher::Aes256Gcm), true, 8).await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.compound(Target::SESSION, vec![echo(), echo()], &c), async {
        let reqs = peer.recv().await;
        assert!(reqs.iter().all(|r| r.encrypted && !r.header.is_signed()));
        peer.send(&[fake::response(&reqs[1], NtStatus::SUCCESS, &four(), 1)], true).await;
        peer.send(&[fake::response(&reqs[0], NtStatus::SUCCESS, &four(), 1)], true).await;
    });
    assert_eq!(r.unwrap().len(), 2);
}

#[tokio::test]
async fn large_requests_take_several_credits() {
    let (conn, mut peer) = established(None, false, 40).await;
    let c = CancelToken::new();
    let big = Element::new(Command::Echo, four_byte_request()).payload(CREDIT_UNIT * 16);
    let (r, ()) = tokio::join!(conn.compound(Target::SESSION, vec![big, echo()], &c), async {
        let reqs = peer.recv().await;
        assert_eq!((reqs[0].header.credit_charge, reqs[0].header.message_id), (16, 0));
        assert_eq!((reqs[1].header.credit_charge, reqs[1].header.message_id), (1, 16));
        assert_eq!(reqs[0].header.credits, 128 - 23);
        let mut msgs = chain(vec![
            fake::response(&reqs[0], NtStatus::SUCCESS, &four(), 16),
            fake::response(&reqs[1], NtStatus::SUCCESS, &four(), 1),
        ]);
        for m in &mut msgs {
            peer.sign(m);
        }
        peer.send(&msgs, false).await;
    });
    r.unwrap();
    assert_eq!(conn.credits(), 40);
    conn.set_limits(1 << 20, false);
    let big = Element::new(Command::Read, vec![]).payload(CREDIT_UNIT + 1);
    assert!(matches!(conn.call(Target::SESSION, big, &c).await, Err(Error::Local(_))));
}

#[tokio::test]
async fn requests_wait_for_credits() {
    let (conn, mut peer) = established(None, false, 1).await;
    let c = CancelToken::new();
    let first = conn.send(Target::SESSION, vec![echo()], &c).await.unwrap();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
        peer.sign(&mut msg);
        peer.send(&[msg], false).await;
        let req = peer.recv_one().await;
        assert_eq!(req.header.message_id, 1);
        let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
        peer.sign(&mut msg);
        peer.send(&[msg], false).await;
    });
    r.unwrap();
    for t in first {
        t.wait(&c).await.unwrap();
    }
    conn.0.lock().credits = 0;
    let e = conn.call(Target::SESSION, echo(), &c).await.unwrap_err();
    assert!(matches!(e, Error::Protocol(ref m) if m.contains("granted 0 credits")), "{e}");
}

#[tokio::test]
async fn cancel_sends_cancel_and_keeps_the_connection() {
    let (conn, mut peer) = established(None, false, 8).await;
    let c = CancelToken::new();
    let canceler = c.clone();
    let (r, mut peer) = tokio::join!(conn.call(Target { tree_id: 5, encrypt: false }, echo(), &c), async {
        let req = peer.recv_one().await;
        canceler.cancel();
        let cancel = peer.recv_one().await;
        assert_eq!(cancel.command(), Command::Cancel);
        assert_eq!((cancel.header.message_id, cancel.header.tree_id), (req.header.message_id, 5));
        assert_eq!((cancel.header.credit_charge, cancel.header.credits), (0, 0));
        assert!(cancel.header.is_signed());
        let mut msg = error(&req, NtStatus::CANCELLED, 1);
        peer.sign(&mut msg);
        peer.send(&[msg], false).await;
        peer
    });
    assert_eq!(r, Err(Error::Canceled));
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        assert_eq!(req.header.message_id, 1);
        let mut msg = fake::response(&req, NtStatus::SUCCESS, &four(), 1);
        peer.sign(&mut msg);
        peer.send(&[msg], false).await;
    });
    r.unwrap().ok().unwrap();
}

#[tokio::test]
async fn cancel_of_an_async_request_names_its_async_id() {
    let (conn, mut peer) = established(Some(Cipher::Aes128Gcm), true, 8).await;
    let c = CancelToken::new();
    let canceler = c.clone();
    let (r, ()) = tokio::join!(conn.call(Target::SESSION, echo(), &c), async {
        let req = peer.recv_one().await;
        peer.send(&[interim(&req, 0x1234, 1)], true).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        canceler.cancel();
        let cancel = peer.recv_one().await;
        assert!(cancel.encrypted);
        assert_eq!(cancel.header.async_id, Some(0x1234));
        assert_ne!(cancel.header.flags & flags::ASYNC_COMMAND, 0);
    });
    assert_eq!(r, Err(Error::Canceled));
}

#[tokio::test]
async fn an_abandoned_create_is_closed() {
    let (conn, mut peer) = established(None, false, 8).await;
    let c = CancelToken::new();
    let create = Create {
        name: &[u16::from(b'f')],
        access: 1,
        attributes: attributes::NORMAL,
        disposition: disposition::OPEN,
        options: 0,
    };
    let tree = Target { tree_id: 4, encrypt: false };
    let tickets = conn
        .send(tree, vec![Element::new(Command::Create, create.encode().unwrap()).owning()], &c)
        .await
        .unwrap();
    let req = peer.recv_one().await;
    drop(tickets);
    let cancel = peer.recv_one().await;
    assert_eq!(cancel.command(), Command::Cancel);
    let mut body = vec![0u8; 88];
    body[..2].copy_from_slice(&89u16.to_le_bytes());
    body[64..80].copy_from_slice(&[0xAB; 16]);
    let mut msg = fake::response(&req, NtStatus::SUCCESS, &body, 1);
    peer.sign(&mut msg);
    peer.send(&[msg], false).await;
    let close = peer.recv_one().await;
    assert_eq!(close.command(), Command::Close);
    assert_eq!(close.header.tree_id, 4);
    assert_eq!(&close.body()[8..24], &[0xAB; 16]);
    let tickets = conn
        .send(tree, vec![Element::new(Command::Create, create.encode().unwrap()).owning()], &c)
        .await
        .unwrap();
    let req = peer.recv_one().await;
    let mut msg = fake::response(&req, NtStatus::SUCCESS, &body, 1);
    peer.sign(&mut msg);
    peer.send(&[msg], false).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(tickets);
    assert_eq!(peer.recv_one().await.command(), Command::Close);
}

#[tokio::test]
async fn a_request_times_out_and_the_connection_ends() {
    let (client, mut peer) = pair().await;
    let conn = Conn::start(client, Duration::from_millis(100));
    let c = CancelToken::new();
    let (r, _req) = tokio::join!(conn.call(Target::SESSION, echo(), &c), peer.recv_one());
    assert_eq!(r, Err(Error::Timeout));
    assert_eq!(conn.usable(), Err(Error::Timeout));
    conn.0.lock().established = true;
    assert_eq!(conn.usable(), Err(Error::Lost("the server did not answer in time".into())));
}

#[tokio::test]
async fn the_server_going_away_fails_every_request() {
    let (conn, mut peer) = established(None, false, 8).await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(conn.compound(Target::SESSION, vec![echo(), echo()], &c), async {
        drop(peer.recv().await);
        drop(peer);
    });
    assert_eq!(r, Err(Error::Lost("the server closed the connection".into())));
    assert_eq!(
        conn.call(Target::SESSION, echo(), &c).await,
        Err(Error::Lost("the server closed the connection".into()))
    );
}

#[tokio::test]
async fn close_logs_off_and_later_calls_fail() {
    let (conn, mut peer) = established(Some(Cipher::Aes128Gcm), true, 8).await;
    conn.close(true).await;
    let logoff = peer.recv_one().await;
    assert_eq!(logoff.command(), Command::Logoff);
    assert!(logoff.encrypted);
    let c = CancelToken::new();
    assert_eq!(conn.call(Target::SESSION, echo(), &c).await, Err(Error::Lost(CLOSED.into())));
    assert!(read_frame_eof(&mut peer).await);
    conn.abort();
}

#[tokio::test]
async fn close_logs_off_only_an_established_session_when_asked() {
    let (conn, mut peer) = established(None, false, 8).await;
    conn.close(false).await;
    assert!(read_frame_eof(&mut peer).await);
    let (conn, mut peer) = started().await;
    conn.close(true).await;
    assert!(read_frame_eof(&mut peer).await);
}

#[tokio::test]
async fn abort_closes_the_socket_at_once() {
    let (conn, mut peer) = established(None, false, 8).await;
    conn.abort();
    let c = CancelToken::new();
    assert_eq!(conn.call(Target::SESSION, echo(), &c).await, Err(Error::Lost(CLOSED.into())));
    assert!(read_frame_eof(&mut peer).await);
}

/// Whether the client closed its end (and sent nothing before).
async fn read_frame_eof(peer: &mut Peer) -> bool {
    tokio::time::timeout(fake::WAIT, transport::read_frame(&mut peer.stream, 1 << 16))
        .await
        .is_ok_and(|r| r.is_err())
}

#[tokio::test]
async fn a_canceled_token_sends_nothing() {
    let (conn, _peer) = established(None, false, 8).await;
    let c = CancelToken::new();
    c.cancel();
    assert_eq!(conn.call(Target::SESSION, echo(), &c).await, Err(Error::Canceled));
    assert_eq!(conn.0.lock().next_mid, 0);
}
