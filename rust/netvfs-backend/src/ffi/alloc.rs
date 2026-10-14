// SPDX-License-Identifier: LGPL-2.1-or-later
//! R3: an object returned through an out-pointer is one `calloc`'d block
//! holding the object and every byte it points to; the table's `free`
//! wipes the whole block and releases it. A hidden header in front of the
//! object keeps the block's size for the wipe.
//!
//! [`pack`] builds a block in two passes over the same function: the first
//! counts what the object needs, the second writes it.

use super::raw::NvbBytes;
use std::cell::Cell;
use std::ffi::c_void;
use std::mem::{align_of, size_of};
use std::ptr;
use zeroize::Zeroize;

/// Bytes in front of the object: its size, padded so that the object keeps
/// `calloc`'s 16-byte alignment.
const HEADER: usize = 16;

thread_local! {
    /// Blocks this thread made minus blocks it freed.
    static LIVE: Cell<isize> = const { Cell::new(0) };
}

fn count(delta: isize) {
    LIVE.with(|live| live.set(live.get().wrapping_add(delta)));
}

/// Blocks this thread made minus blocks it freed: tests check for leaks
/// with it (a block freed on another thread counts there).
pub fn live_blocks() -> isize {
    LIVE.with(Cell::get)
}

/// Where [`pack`]'s function puts the bytes and lists an object points to.
pub trait Out {
    /// A copy of `data` in the block.
    fn bytes(&mut self, data: &[u8]) -> NvbBytes;
    /// A copy of `items` (an array of `nvb_bytes` and their bytes) in the
    /// block; `items.len()` is its length.
    fn list(&mut self, items: &[&[u8]]) -> *const NvbBytes;
}

/// The first pass: counts list slots and bytes; `None` on overflow.
struct Count {
    slots: Option<usize>,
    bytes: Option<usize>,
}

impl Out for Count {
    fn bytes(&mut self, data: &[u8]) -> NvbBytes {
        self.bytes = self.bytes.and_then(|n| n.checked_add(data.len()));
        NvbBytes::EMPTY
    }

    fn list(&mut self, items: &[&[u8]]) -> *const NvbBytes {
        self.slots = self.slots.and_then(|n| n.checked_add(items.len()));
        for item in items {
            self.bytes(item);
        }
        ptr::null()
    }
}

/// The second pass: writes slots and bytes where the first pass made room.
struct Fill {
    slots: *mut NvbBytes,
    bytes: *mut u8,
}

impl Out for Fill {
    fn bytes(&mut self, data: &[u8]) -> NvbBytes {
        let at = self.bytes;
        // SAFETY: the first pass counted `data.len()` bytes for this call, so
        // `at` has room for them inside the block; source and block do not
        // overlap (the block is new). `add` stays within the block (or one
        // past its end).
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), at, data.len());
            self.bytes = at.add(data.len());
        }
        NvbBytes { ptr: at, len: data.len() }
    }

    fn list(&mut self, items: &[&[u8]]) -> *const NvbBytes {
        let first = self.slots;
        for item in items {
            let slot = self.bytes(item);
            // SAFETY: the first pass counted one slot per item, so `self.slots`
            // points to room for one `NvbBytes` in the block, aligned (the
            // slots start at a multiple of 8 and are 16 bytes each).
            unsafe {
                self.slots.write(slot);
                self.slots = self.slots.add(1);
            }
        }
        first
    }
}

/// One block holding what `build` makes: `build` runs twice and must
/// produce the same calls to [`Out`] each time. `None` when the size
/// overflows or `calloc` fails.
#[allow(clippy::cast_ptr_alignment, reason = "calloc's blocks are aligned for any type; the offsets keep 8")]
pub fn pack<T>(build: impl Fn(&mut dyn Out) -> T) -> Option<*mut T> {
    const { assert!(align_of::<T>() <= HEADER && align_of::<NvbBytes>() <= HEADER) };
    let mut needs = Count { slots: Some(0), bytes: Some(0) };
    drop(build(&mut needs));
    let slots_at = size_of::<T>().checked_next_multiple_of(align_of::<NvbBytes>())?;
    let slot_bytes = needs.slots?.checked_mul(size_of::<NvbBytes>())?;
    let size = slots_at.checked_add(slot_bytes)?.checked_add(needs.bytes?)?;
    let total = size.checked_add(HEADER)?;
    // SAFETY: calloc with a non-zero size; the result is checked for NULL.
    let base = unsafe { libc::calloc(1, total) }.cast::<u8>();
    if base.is_null() {
        return None;
    }
    // SAFETY: `base` is a fresh, zeroed block of `total` bytes, aligned for
    // any type (16 on LP64): the header (a usize at its start) and the
    // object at `HEADER` fit and are aligned (the const assert above); the
    // slots start at `HEADER + slots_at`, the bytes after them, all inside.
    unsafe {
        base.cast::<usize>().write(size);
        let object = base.add(HEADER);
        let mut fill = Fill {
            slots: object.add(slots_at).cast::<NvbBytes>(),
            bytes: object.add(slots_at).add(slot_bytes),
        };
        let head = build(&mut fill);
        object.cast::<T>().write(head);
        count(1);
        Some(object.cast::<T>())
    }
}

/// Wipes the block of `p` and returns its start, for `libc::free`.
///
/// # Safety
/// `p` is an object [`pack`] returned and not yet released.
#[allow(clippy::cast_ptr_alignment, reason = "the header is at the block's start, which calloc aligned")]
unsafe fn wipe(p: *mut c_void) -> *mut u8 {
    // SAFETY: `pack` put the size in the header right in front of `p`; the
    // block holds `HEADER + size` initialised bytes (calloc).
    unsafe {
        let base = p.cast::<u8>().sub(HEADER);
        let size = base.cast::<usize>().read();
        std::slice::from_raw_parts_mut(base, HEADER.saturating_add(size)).zeroize();
        base
    }
}

/// The table's `free` (R3): wipes and releases a block; NULL is a no-op.
/// Nothing in it can panic.
///
/// # Safety
/// `p` is NULL or an object this library returned and not yet released.
pub unsafe extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is a live block of this library (the caller's contract).
    unsafe { libc::free(wipe(p).cast()) };
    count(-1);
}

#[cfg(test)]
#[allow(clippy::cast_ptr_alignment, reason = "the tests read the size header calloc aligned")]
mod tests {
    use super::*;
    use crate::ffi::raw::NvbCapabilities;

    fn slice(b: NvbBytes) -> Vec<u8> {
        // SAFETY: test: `b` points into a live block.
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
    }

    #[test]
    fn a_block_holds_the_object_its_lists_and_bytes() {
        let names: [&[u8]; 3] = [b"AtomicPut", b"", b"Symlinks"];
        let algos: [&[u8]; 1] = [b"sha256"];
        let before = live_blocks();
        let p = pack(|out| NvbCapabilities {
            flags: out.list(&names),
            n_flags: names.len(),
            checksum_algorithms: out.list(&algos),
            n_checksum_algorithms: 1,
            max_name_bytes: 255,
        })
        .unwrap();
        assert_eq!(live_blocks(), before + 1);
        assert_eq!(p as usize % 16, 0);
        // SAFETY: test: `p` is a live block.
        let caps = unsafe { p.read() };
        // SAFETY: test: the lists are inside the block.
        let flags = unsafe { std::slice::from_raw_parts(caps.flags, caps.n_flags) };
        let got: Vec<Vec<u8>> = flags.iter().map(|b| slice(*b)).collect();
        assert_eq!(got, [b"AtomicPut".to_vec(), Vec::new(), b"Symlinks".to_vec()]);
        assert!(!flags[1].ptr.is_null());
        // SAFETY: as above.
        let algos = unsafe { std::slice::from_raw_parts(caps.checksum_algorithms, 1) };
        assert_eq!(slice(algos[0]), b"sha256");
        assert_eq!(caps.max_name_bytes, 255);
        // Everything lies inside the block: header, object, slots, bytes.
        // SAFETY: test: the header is in front of `p`.
        let size = unsafe { p.cast::<u8>().sub(HEADER).cast::<usize>().read() };
        assert_eq!(size, size_of::<NvbCapabilities>() + 4 * 16 + 9 + 8 + 6);
        let end = p as usize + size;
        for b in flags.iter().chain(algos) {
            assert!(
                b.ptr as usize >= p as usize + size_of::<NvbCapabilities>() && b.ptr as usize + b.len <= end
            );
        }
        assert!(caps.flags as usize >= p as usize + size_of::<NvbCapabilities>());
        // SAFETY: test: releases the live block once.
        unsafe { free(p.cast()) };
        assert_eq!(live_blocks(), before);
    }

    #[test]
    fn wipe_clears_the_whole_block() {
        let p = pack(|out| out.bytes(b"secret secret secret")).unwrap();
        // SAFETY: test: `p` is a live block; it is wiped, read and released
        // by hand instead of `free`.
        unsafe {
            let size = p.cast::<u8>().sub(HEADER).cast::<usize>().read();
            let base = wipe(p.cast());
            assert_eq!(base, p.cast::<u8>().sub(HEADER));
            let all = std::slice::from_raw_parts(base, HEADER + size);
            assert!(all.iter().all(|b| *b == 0));
            libc::free(base.cast());
        }
        count(-1);
    }

    #[test]
    fn free_of_null_is_a_no_op() {
        let before = live_blocks();
        // SAFETY: NULL is allowed.
        unsafe { free(ptr::null_mut()) };
        assert_eq!(live_blocks(), before);
    }

    #[test]
    fn sizes_that_overflow_are_refused() {
        let huge = [0u8; 1];
        // Each call adds one byte; a forged count past usize::MAX must fail.
        let mut count = Count { slots: Some(usize::MAX), bytes: Some(usize::MAX) };
        count.bytes(&huge);
        count.list(&[&huge]);
        assert_eq!((count.slots, count.bytes), (None, None));
    }
}
