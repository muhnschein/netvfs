// SPDX-License-Identifier: LGPL-2.1-or-later
//! Limits of the protocol (SPEC-v2 XB-17, XSEC-7) and of the bridge (XB-12,
//! C-10). The values are those of the C++ bridge: `src/bridge/lib/args.h`
//! (`Limits`), `bridgeserver.h` (`ConsumerLimits`), `pool.h` (`PoolLimits`),
//! `streaming.h` (`FlowControl`) and `wire.h` (`DecodeLimits`).
//!
//! String lengths (`MAX_URL`, `MAX_SHORT`, `MAX_ID`) were counted by the C++
//! bridge in UTF-16 code units (`QString::size`); location ids are ASCII, so
//! only `MAX_URL` and `MAX_SHORT` can differ for non-ASCII text.

use crate::methods::Lane;

// ---- calls (args.h Limits) ------------------------------------------------

/// Largest `List` batch a client may ask for, and the entries per `WalkBatch`.
pub const MAX_LIST_BATCH: u32 = 512;
/// The batch size of `List` when the client asks for 0.
pub const DEFAULT_LIST_BATCH: u32 = 256;
/// Largest wire size of one `ListBatch` or `WalkBatch`, in bytes.
pub const MAX_LIST_BATCH_BYTES: usize = 1 << 20;
/// Largest `Read` (`max`), in bytes.
pub const MAX_READ: u32 = 1 << 20;
/// Largest `ReadAhead` (`bytes`): a hint, so larger values are capped, not refused.
pub const MAX_READ_AHEAD: i64 = 16 << 20;
/// Largest offset of `Read` and `ReadAhead`, and of the `offset` and `size`
/// transfer options.
pub const MAX_OFFSET: i64 = 1 << 62;
/// Largest path, in bytes.
pub const MAX_PATH: usize = 4096;
/// Largest `ConnectAdHoc` secret, in bytes.
pub const MAX_SECRET: usize = 64 * 1024;
/// Longest `ConnectAdHoc` URL.
pub const MAX_URL: usize = 4096;
/// Longest short string (`Hello` client name, string options). A
/// keyboard-interactive answer may have four times this many bytes.
pub const MAX_SHORT: usize = 256;
/// Longest location or question id.
pub const MAX_ID: usize = 64;
/// Largest `maxDepth` of `Walk` (-1: unlimited).
pub const MAX_WALK_DEPTH: i64 = 4096;
/// Most keyboard-interactive answers in one `Answer`.
pub const MAX_ANSWERS: usize = 16;
/// Earliest time an option may set: 0001-01-01T00:00:00Z, in ms since the epoch.
pub const MIN_TIME_MS: i64 = -62_135_596_800_000;
/// Latest time an option may set: 9999-12-31T23:59:59.999Z, in ms since the epoch.
pub const MAX_TIME_MS: i64 = 253_402_300_799_999;

// ---- per consumer (bridgeserver.h ConsumerLimits, XB-17) -------------------

/// Requests (calls and listings) in flight per consumer.
pub const MAX_REQUESTS: usize = 64;
/// Open read handles per consumer.
pub const MAX_HANDLES: usize = 16;
/// Running jobs per consumer.
pub const MAX_JOBS: usize = 8;
/// `retryAfterMs` of a `TooManyConnections` refusal by these limits.
pub const RETRY_AFTER_MS: u64 = 1000;

const _: () = assert!(DEFAULT_LIST_BATCH <= MAX_LIST_BATCH);

// ---- connection pools (pool.h PoolLimits, XB-12) ---------------------------

/// Connections of the interactive lane per location.
pub const POOL_INTERACTIVE: usize = 1;
/// Connections of the bulk lane per location.
pub const POOL_BULK: usize = 2;
/// Connections of the stream lane per location.
pub const POOL_STREAM: usize = 1;
/// Connections per host across all locations of a consumer.
pub const POOL_PER_HOST: usize = 4;

/// Connections of `lane` per location.
#[must_use]
pub const fn pool_size(lane: Lane) -> usize {
    match lane {
        Lane::Interactive => POOL_INTERACTIVE,
        Lane::Bulk => POOL_BULK,
        Lane::Stream => POOL_STREAM,
    }
}

// ---- flow control (streaming.h FlowControl, C-10) --------------------------

/// Bytes of streamed signals (`ListBatch`, `WalkBatch`) not yet written to
/// the socket above which producers wait.
pub const FLOW_LIMIT: usize = 4 << 20;

// ---- decoding (wire.h DecodeLimits, design §3.5) ---------------------------

/// Deepest nesting of containers in a decoded argument.
pub const DECODE_MAX_DEPTH: usize = 8;
/// Most elements of one decoded array or dictionary.
pub const DECODE_MAX_ELEMENTS: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pools_by_lane() {
        assert_eq!(pool_size(Lane::Interactive), 1);
        assert_eq!(pool_size(Lane::Bulk), 2);
        assert_eq!(pool_size(Lane::Stream), 1);
    }

    #[test]
    fn sizes_are_the_documented_ones() {
        assert_eq!(MAX_LIST_BATCH_BYTES, 1_048_576);
        assert_eq!(MAX_READ, 1_048_576);
        assert_eq!(MAX_READ_AHEAD, 16_777_216);
        assert_eq!(MAX_OFFSET, 4_611_686_018_427_387_904);
        assert_eq!(FLOW_LIMIT, 4_194_304);
    }
}
