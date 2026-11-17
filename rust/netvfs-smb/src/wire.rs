// SPDX-License-Identifier: LGPL-2.1-or-later
//! Bounds-checked little-endian reader and writer. No indexing, no panics:
//! every read returns `Err` when the buffer is too short.

use crate::error::{Result, protocol};

/// A cursor over a received buffer.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Current position from the start of the buffer.
    #[must_use]
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes left after the position.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Takes `n` bytes.
    ///
    /// # Errors
    /// Buffer too short.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| protocol("length overflow"))?;
        let out = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| protocol(format!("message truncated: need {n} bytes at {}", self.pos)))?;
        self.pos = end;
        Ok(out)
    }

    /// Takes `N` bytes as an array.
    ///
    /// # Errors
    /// Buffer too short.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let b = self.bytes(N)?;
        b.try_into().map_err(|e| protocol(format!("array length: {e}")))
    }

    /// Skips `n` bytes.
    ///
    /// # Errors
    /// Buffer too short.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }

    /// Reads a byte.
    ///
    /// # Errors
    /// Buffer too short.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian `u16`.
    ///
    /// # Errors
    /// Buffer too short.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian `u32`.
    ///
    /// # Errors
    /// Buffer too short.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian `u64`.
    ///
    /// # Errors
    /// Buffer too short.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Moves to an absolute offset (only forwards or to the same place).
    ///
    /// # Errors
    /// Offset behind the position or past the end.
    pub fn seek(&mut self, offset: usize) -> Result<()> {
        if offset < self.pos || offset > self.buf.len() {
            return Err(protocol(format!("offset {offset} outside the message")));
        }
        self.pos = offset;
        Ok(())
    }
}

/// A slice of `buf` given by an offset and a length from the wire, checked against the buffer.
///
/// # Errors
/// The range is outside `buf`.
pub fn slice_at(buf: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset.checked_add(len).ok_or_else(|| protocol("length overflow"))?;
    buf.get(offset..end)
        .ok_or_else(|| protocol(format!("field at {offset}+{len} outside a {}-byte message", buf.len())))
}

/// Builds a message body.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Nothing written yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Appends a byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Appends a little-endian `u16`.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Appends a little-endian `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Appends a little-endian `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Appends bytes.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Pads with zeros to a multiple of 8 (negotiate contexts, compound elements, directory entries).
    pub fn align8(&mut self) -> &mut Self {
        while !self.buf.len().is_multiple_of(8) {
            self.buf.push(0);
        }
        self
    }

    /// The bytes written.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// `usize` to a wire `u16`, failing instead of truncating.
///
/// # Errors
/// Value out of range.
pub fn to_u16(v: usize) -> Result<u16> {
    u16::try_from(v).map_err(|e| protocol(format!("{v} does not fit a 16-bit field: {e}")))
}

/// `usize` to a wire `u32`, failing instead of truncating.
///
/// # Errors
/// Value out of range.
pub fn to_u32(v: usize) -> Result<u32> {
    u32::try_from(v).map_err(|e| protocol(format!("{v} does not fit a 32-bit field: {e}")))
}

/// Wire `u32` to `usize`.
///
/// # Errors
/// Value out of range.
pub fn from_u32(v: u32) -> Result<usize> {
    usize::try_from(v).map_err(|e| protocol(format!("length does not fit usize: {e}")))
}

#[cfg(test)]
mod tests {
    use super::{Reader, Writer, slice_at};

    #[test]
    fn round_trip() {
        let mut w = Writer::new();
        w.u8(1).u16(0x0302).u32(0x0706_0504).u64(0x0f0e_0d0c_0b0a_0908).align8();
        assert!(!w.is_empty());
        let v = w.into_vec();
        assert_eq!(v, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]);
        let mut r = Reader::new(&v);
        assert_eq!(r.u8().ok(), Some(1));
        assert_eq!(r.u16().ok(), Some(0x0302));
        assert_eq!(r.u32().ok(), Some(0x0706_0504));
        assert_eq!(r.u64().ok(), Some(0x0f0e_0d0c_0b0a_0908));
        assert_eq!(r.remaining(), 1);
        assert_eq!(r.pos(), 15);
        let mut w = Writer::new();
        assert!(w.is_empty());
        w.align8();
        assert_eq!(w.len(), 0);
        w.bytes(&[7; 8]).align8();
        assert_eq!(w.len(), 8);
        w.u8(1).align8();
        assert_eq!(w.len(), 16);
    }

    #[test]
    fn arrays_skip_and_seek() {
        let data = [1u8, 2, 3, 4, 5, 6];
        let mut r = Reader::new(&data);
        assert_eq!(r.array::<2>().unwrap(), [1, 2]);
        r.skip(1).unwrap();
        assert_eq!(r.u8().unwrap(), 4);
        r.seek(4).unwrap();
        assert_eq!(r.pos(), 4);
        r.seek(3).unwrap_err();
        r.seek(6).unwrap();
        assert_eq!(r.remaining(), 0);
        r.u8().unwrap_err();
        r.skip(1).unwrap_err();
        assert!(r.bytes(0).unwrap().is_empty());
    }

    #[test]
    fn conversions_refuse_instead_of_truncating() {
        assert_eq!(super::to_u16(65_535).unwrap(), 65_535);
        super::to_u16(65_536).unwrap_err();
        assert_eq!(super::to_u32(7).unwrap(), 7);
        assert_eq!(super::from_u32(u32::MAX).unwrap(), 4_294_967_295);
        #[cfg(target_pointer_width = "64")]
        super::to_u32(1 << 32).unwrap_err();
    }

    #[test]
    fn short_reads_fail() {
        let mut r = Reader::new(&[1, 2, 3]);
        r.u32().unwrap_err();
        r.bytes(usize::MAX).unwrap_err();
        r.seek(4).unwrap_err();
        slice_at(&[0; 4], 2, 3).unwrap_err();
        slice_at(&[0; 4], usize::MAX, 2).unwrap_err();
        assert_eq!(slice_at(&[0, 1, 2, 3], 1, 2).ok(), Some(&[1u8, 2][..]));
    }
}
