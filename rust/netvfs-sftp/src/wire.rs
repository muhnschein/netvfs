// SPDX-License-Identifier: LGPL-2.1-or-later
//! SSH wire types of SFTP: [`Reader`] over a received packet (every read and string cap checked), [`Packet`] for
//! outgoing packets with length and request id filled in at the end.

use std::fmt;

/// Longest packet body accepted or sent: OpenSSH's 256 KiB plus the header of a full `DATA` or `WRITE`.
pub const MAX_PACKET: usize = 256 * 1024 + 1024;

/// A malformed or over-long reply: what was wrong with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireError(pub &'static str);

/// A cursor over a received packet.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

const SHORT: WireError = WireError("the packet ends early");

impl<'a> Reader<'a> {
    /// A reader over `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let (head, rest) = self.buf.split_at_checked(n).ok_or(SHORT)?;
        self.buf = rest;
        Ok(head)
    }

    /// One byte.
    ///
    /// # Errors
    /// When the packet ends.
    pub fn u8(&mut self) -> Result<u8, WireError> {
        let (&b, rest) = self.buf.split_first().ok_or(SHORT)?;
        self.buf = rest;
        Ok(b)
    }

    /// A big-endian `uint32`.
    ///
    /// # Errors
    /// When the packet ends.
    pub fn u32(&mut self) -> Result<u32, WireError> {
        let (bytes, rest) = self.buf.split_first_chunk::<4>().ok_or(SHORT)?;
        self.buf = rest;
        Ok(u32::from_be_bytes(*bytes))
    }

    /// A big-endian `uint64`.
    ///
    /// # Errors
    /// When the packet ends.
    pub fn u64(&mut self) -> Result<u64, WireError> {
        let (bytes, rest) = self.buf.split_first_chunk::<8>().ok_or(SHORT)?;
        self.buf = rest;
        Ok(u64::from_be_bytes(*bytes))
    }

    /// A `string` of at most `cap` bytes, borrowed from the packet.
    ///
    /// # Errors
    /// `what` when it is longer than `cap`; when the packet ends.
    pub fn string(&mut self, cap: usize, what: &'static str) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        if len > cap {
            return Err(WireError(what));
        }
        self.take(len)
    }

    /// Skips a `string` of any length that fits in the packet.
    ///
    /// # Errors
    /// When the packet ends.
    pub fn skip_string(&mut self) -> Result<(), WireError> {
        let len = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        self.take(len).map(drop)
    }

    /// Everything not read yet, consumed.
    pub fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }

    /// Whether everything was read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Offset of the request id in a packet: after the length and the type.
const ID_AT: usize = 5;

/// An outgoing packet: `uint32 length`, `byte type`, `uint32 id`, fields.
#[derive(Clone, PartialEq, Eq)]
pub struct Packet {
    buf: Vec<u8>,
}

impl fmt::Debug for Packet {
    // Only type and size shown: packets carry file data.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet").field("type", &self.buf.get(4)).field("len", &self.buf.len()).finish()
    }
}

impl Packet {
    /// A request of `kind`; the id is set when it is sent.
    #[must_use]
    pub fn request(kind: u8) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0; 4]);
        buf.push(kind);
        buf.extend_from_slice(&[0; 4]);
        Self { buf }
    }

    /// `SSH_FXP_INIT`, which has a version where requests have their id.
    #[must_use]
    pub fn init(version: u32) -> Self {
        let mut buf = Vec::with_capacity(9);
        buf.extend_from_slice(&[0; 4]);
        buf.push(crate::proto::FXP_INIT);
        buf.extend_from_slice(&version.to_be_bytes());
        Self { buf }
    }

    /// Appends a `uint32`.
    #[must_use]
    pub fn u32(mut self, value: u32) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a `uint64`.
    #[must_use]
    pub fn u64(mut self, value: u64) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a `string`. One longer than `u32::MAX` is written with a
    /// wrong length, and [`finish`](Self::finish) refuses the packet.
    #[must_use]
    pub fn string(mut self, value: &[u8]) -> Self {
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(value);
        self
    }

    /// The bytes to send with `id` as the request id and the length filled
    /// in; `None` when the body is longer than [`MAX_PACKET`].
    #[must_use]
    pub fn finish(mut self, id: u32) -> Option<Vec<u8>> {
        let body = self.buf.len().checked_sub(4)?;
        if body > MAX_PACKET {
            return None;
        }
        let len = u32::try_from(body).ok()?;
        self.buf.get_mut(..4)?.copy_from_slice(&len.to_be_bytes());
        if self.buf.get(4) != Some(&crate::proto::FXP_INIT) {
            self.buf.get_mut(ID_AT..ID_AT.checked_add(4)?)?.copy_from_slice(&id.to_be_bytes());
        }
        Some(self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_numbers_and_strings_in_order() {
        let buf =
            [&[7, 0, 0, 1, 2][..], &[0, 0, 0, 1, 0, 0, 0, 0], &[0, 0, 0, 2, b'h', b'i'], &[0, 0, 0, 1, b'x']]
                .concat();
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8(), Ok(7));
        assert_eq!(r.u32(), Ok(0x102));
        assert_eq!(r.u64(), Ok(0x1_0000_0000));
        assert!(!r.is_empty());
        assert_eq!(r.string(2, "long"), Ok(&b"hi"[..]));
        assert_eq!(r.skip_string(), Ok(()));
        assert!(r.is_empty());
        assert_eq!(r.rest(), b"");
        let mut r = Reader::new(b"abc");
        assert_eq!(r.u8(), Ok(b'a'));
        assert_eq!(r.rest(), b"bc");
        assert!(r.is_empty());
        assert_eq!(r.u8(), Err(SHORT));
    }

    #[test]
    fn short_reads_fail_without_consuming_past_the_end() {
        assert_eq!(Reader::new(&[1, 2, 3]).u32(), Err(SHORT));
        assert_eq!(Reader::new(&[0; 7]).u64(), Err(SHORT));
        assert_eq!(Reader::new(&[]).u8(), Err(SHORT));
        // A string whose length runs past the packet.
        assert_eq!(Reader::new(&[0, 0, 0, 3, b'a', b'b']).string(10, "x"), Err(SHORT));
        assert_eq!(Reader::new(&[0, 0, 0, 3, b'a', b'b']).skip_string(), Err(SHORT));
        assert_eq!(Reader::new(&[0, 0, 0]).skip_string(), Err(SHORT));
    }

    #[test]
    fn strings_over_the_cap_are_refused_before_reading() {
        // The length claims 4 GiB: refused by the cap, nothing allocated.
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, b'a']);
        assert_eq!(r.string(4096, "name too long"), Err(WireError("name too long")));
        // Exactly at the cap is fine; one past it is not.
        let buf = [0, 0, 0, 2, b'a', b'b'];
        assert_eq!(Reader::new(&buf).string(2, "x"), Ok(&b"ab"[..]));
        assert_eq!(Reader::new(&buf).string(1, "x"), Err(WireError("x")));
        assert_eq!(Reader::new(&[0, 0, 0, 0]).string(0, "x"), Ok(&b""[..]));
    }

    #[test]
    fn packets_carry_length_type_and_id() {
        let p = Packet::request(17).u32(9).u64(2).string(b"ab").finish(0x0102_0304).unwrap();
        assert_eq!(
            p,
            [0, 0, 0, 23, 17, 1, 2, 3, 4, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, b'a', b'b']
        );
        assert_eq!(Packet::init(3).finish(99).unwrap(), [0, 0, 0, 5, 1, 0, 0, 0, 3]);
        assert_eq!(Packet::request(4).finish(1).unwrap(), [0, 0, 0, 5, 4, 0, 0, 0, 1]);
    }

    #[test]
    fn packets_over_the_cap_are_refused() {
        // OpenSSH's 256 KiB and 1 KiB for the header.
        assert_eq!(MAX_PACKET, 263_168);
        // Header 9 bytes + string 4 + data: exactly MAX_PACKET body is fine.
        let fits = vec![0; MAX_PACKET - 4 - 4 - 1];
        let p = Packet::request(6).string(&fits).finish(1).unwrap();
        assert_eq!(p.len(), MAX_PACKET + 4);
        let over = vec![0; MAX_PACKET - 4 - 4];
        assert_eq!(Packet::request(6).string(&over).finish(1), None);
        let printed = format!("{:?}", Packet::request(6).string(b"secret"));
        assert!(!printed.contains("secret") && printed.contains("len: 19"), "{printed}");
    }
}
