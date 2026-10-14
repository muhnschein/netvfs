// SPDX-License-Identifier: LGPL-2.1-or-later
//! A zbus [`Message`] from a frame the bridge read itself
//! (`crate::server::inbound` reads frames so that it can refuse oversized
//! ones before reading their body, design §8).

use std::os::fd::OwnedFd;
use zbus::Message;
use zbus::zvariant::Endian;
use zbus::zvariant::serialized::{Context, Data};

/// The message in `bytes` (one complete frame: header, padding, body) with
/// the descriptors that came with it.
///
/// # Errors
/// zbus refuses a malformed header or header fields.
pub fn message_from_frame(bytes: Vec<u8>, fds: Vec<OwnedFd>, endian: Endian) -> zbus::Result<Message> {
    let data = Data::new_fds(bytes, Context::new_dbus(endian, 0), fds);
    // SAFETY: `from_bytes` is unsafe only because the bytes may be malformed;
    // it runs the same checks as zbus's own socket reader
    // (`Message::from_raw_parts`: endianness, primary header, header fields)
    // and the body is checked when it is deserialised. No memory safety
    // depends on the content.
    unsafe { Message::from_bytes(data) }
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_message_and_refuses_garbage() {
        let msg = Message::method_call("/org/netvfs/Bridge", "Hello").unwrap().build(&("x",)).unwrap();
        let bytes = msg.data().to_vec();
        let back = message_from_frame(bytes, vec![], Endian::native()).unwrap();
        assert_eq!(back.header().member().unwrap().as_str(), "Hello");
        assert_eq!(back.body().deserialize::<(String,)>().unwrap(), ("x".to_owned(),));
        assert!(message_from_frame(vec![b'x'; 32], vec![], Endian::Little).is_err());
    }
}
