// SPDX-License-Identifier: LGPL-2.1-or-later
// The inbound frame limits (design §8): size from the primary header,
// oversized and fd-heavy messages refused, bytes the handshake read first.
// Restriction lints that only add noise to tests (doc/RUST.md "Lints").
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::*;
use netvfs_bridge_proto::methods::{INTERFACE, OBJECT_PATH};
use std::os::fd::AsFd as _;
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use zbus::connection::socket::WriteHalf;
use zbus::zvariant::Fd;

fn call_with_bytes(n: usize) -> Message {
    Message::method_call(OBJECT_PATH, "Upload")
        .unwrap()
        .interface(INTERFACE)
        .unwrap()
        .build(&(vec![7u8; n],))
        .unwrap()
}

/// A message of exactly `total` bytes on the wire.
fn message_of(total: usize) -> Message {
    let overhead = call_with_bytes(0).data().len();
    let message = call_with_bytes(total - overhead);
    assert_eq!(message.data().len(), total);
    message
}

fn reader() -> (LimitedRead, OwnedWriteHalf, UnixStream) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let (read, _write) = ours.into_split();
    let (_, write) = theirs.into_split();
    let (spare, _) = UnixStream::pair().unwrap();
    (LimitedRead::new(Box::new(read)), write, spare)
}

async fn receive(reader: &mut LimitedRead, carried: &mut Vec<u8>) -> zbus::Result<Message> {
    reader.receive_message(0, carried, &mut Vec::new()).await
}

#[test]
fn frame_sizes() {
    let msg = call_with_bytes(5);
    let size = frame_size(&msg.data()[..16]).unwrap();
    assert_eq!(size.endian, Endian::Little);
    assert_eq!(size.total, u64::try_from(msg.data().len()).unwrap());

    // Header fields of 1 byte are padded to 8 (16 + 1 → 24), then the body.
    let mut big = *b"B\x01\x00\x01\x00\x00\x00\x0a\x00\x00\x00\x01\x00\x00\x00\x01";
    assert_eq!(frame_size(&big).unwrap(), FrameSize { endian: Endian::Big, total: 24 + 10 });
    big[15] = 8;
    assert_eq!(frame_size(&big).unwrap().total, 24 + 10);
    big[15] = 9;
    assert_eq!(frame_size(&big).unwrap().total, 32 + 10);
    big[15] = 0;
    assert_eq!(frame_size(&big).unwrap().total, 16 + 10);
    let little = *b"l\x01\x00\x01\x0a\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00";
    assert_eq!(frame_size(&little).unwrap(), FrameSize { endian: Endian::Little, total: 24 + 10 });
    // Largest sizes do not overflow.
    let huge = *b"l\x01\x00\x01\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff";
    assert_eq!(frame_size(&huge).unwrap().total, 0x1_0000_0010 + 0xffff_ffff);

    assert!(frame_size(&little[..15]).is_err());
    assert!(frame_size(&little[..12]).is_err());
    assert!(frame_size(&[]).is_err());
    let mut other = little;
    other[0] = b'x';
    assert_eq!(frame_size(&other).unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn delegates_to_the_stream() {
    let (mut reader, _write, _spare) = reader();
    assert!(reader.can_pass_unix_fd());
    assert_eq!(reader.auth_mechanism(), zbus::AuthMechanism::External);
    let credentials = reader.peer_credentials().await.unwrap();
    assert_eq!(credentials.unix_user_id(), Some(crate::sys::peer::effective_uid()));
    assert!(format!("{reader:?}").starts_with("LimitedRead"));
}

#[tokio::test]
async fn reads_messages_up_to_the_limit() {
    let (mut reader, mut write, _spare) = reader();
    let small = call_with_bytes(3);
    let largest = message_of(MAX_MESSAGE_BYTES);
    write.send_message(&small).await.unwrap();
    let sender = tokio::spawn(async move {
        write.send_message(&largest).await.unwrap();
        write
    });
    let got = receive(&mut reader, &mut Vec::new()).await.unwrap();
    assert_eq!(got.data()[..], small.data()[..]);
    let got = receive(&mut reader, &mut Vec::new()).await.unwrap();
    assert_eq!(got.data().len(), MAX_MESSAGE_BYTES);
    assert_eq!(
        got.body().deserialize::<(Vec<u8>,)>().unwrap().0.len(),
        MAX_MESSAGE_BYTES - call_with_bytes(0).data().len()
    );
    drop(sender.await.unwrap());
    // The peer is gone.
    assert!(receive(&mut reader, &mut Vec::new()).await.is_err());
}

#[tokio::test]
async fn refuses_an_oversized_message_before_its_body() {
    let (mut reader, mut write, _spare) = reader();
    let too_big = message_of(MAX_MESSAGE_BYTES + 1);
    // Only the header is sent: the refusal does not wait for the body.
    write.sendmsg(&too_big.data()[..64], &[]).await.unwrap();
    let error =
        tokio::time::timeout(std::time::Duration::from_secs(5), receive(&mut reader, &mut Vec::new()))
            .await
            .unwrap()
            .unwrap_err();
    assert!(error.to_string().contains("larger than 2 MiB"), "{error}");
}

#[tokio::test]
async fn refuses_too_many_descriptors() {
    let (mut reader, mut write, _spare) = reader();
    let file = std::fs::File::open("/dev/null").unwrap();
    let fd = || Fd::from(file.as_fd());
    let two = Message::method_call(OBJECT_PATH, "Upload").unwrap().build(&(fd(), fd())).unwrap();
    write.send_message(&two).await.unwrap();
    let got = receive(&mut reader, &mut Vec::new()).await.unwrap();
    assert_eq!(got.data().fds().len(), MAX_MESSAGE_FDS);
    let three = Message::method_call(OBJECT_PATH, "Upload").unwrap().build(&(fd(), fd(), fd())).unwrap();
    write.send_message(&three).await.unwrap();
    let error = receive(&mut reader, &mut Vec::new()).await.unwrap_err();
    assert!(error.to_string().contains("too many descriptors"), "{error}");
}

#[tokio::test]
async fn continues_from_the_handshake_bytes() {
    let (mut reader, mut write, _spare) = reader();
    let first = call_with_bytes(40);
    let second = call_with_bytes(50);
    // The handshake read all of the first message and 5 bytes of the second.
    let mut carried = first.data().to_vec();
    carried.extend_from_slice(&second.data()[..5]);
    write.sendmsg(&second.data()[5..], &[]).await.unwrap();
    let got = receive(&mut reader, &mut carried).await.unwrap();
    assert_eq!(got.data()[..], first.data()[..]);
    assert_eq!(carried.len(), 5);
    let got = receive(&mut reader, &mut carried).await.unwrap();
    assert_eq!(got.data()[..], second.data()[..]);
    assert!(carried.is_empty());

    // Carried descriptors belong to the next message.
    let file = std::fs::File::open("/dev/null").unwrap();
    let mut fds = vec![file.as_fd().try_clone_to_owned().unwrap()];
    let third = call_with_bytes(1);
    let mut carried = third.data().to_vec();
    let got = reader.receive_message(0, &mut carried, &mut fds).await.unwrap();
    assert_eq!(got.data().fds().len(), 1);
    assert!(fds.is_empty());
}

#[tokio::test]
async fn refuses_garbage_and_end_of_stream() {
    let (mut reader, mut write, _spare) = reader();
    write.sendmsg(b"x\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", &[]).await.unwrap();
    assert!(receive(&mut reader, &mut Vec::new()).await.is_err());

    let (mut reader, mut write, _spare) = self::reader();
    // A header whose fields are not valid.
    write
        .sendmsg(
            b"l\x01\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x08\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff",
            &[],
        )
        .await
        .unwrap();
    assert!(receive(&mut reader, &mut Vec::new()).await.is_err());

    let (mut reader, mut write, _spare) = self::reader();
    let msg = call_with_bytes(10);
    write.sendmsg(&msg.data()[..30], &[]).await.unwrap();
    drop(write);
    // zbus's tokio half reports the end of the stream as an error itself.
    let error = receive(&mut reader, &mut Vec::new()).await.unwrap_err();
    assert!(
        matches!(&error, zbus::Error::InputOutput(e) if e.kind() == io::ErrorKind::BrokenPipe),
        "{error:?}"
    );
}
