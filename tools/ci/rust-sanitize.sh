#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# The Rust workspace's tests under AddressSanitizer with LeakSanitizer
# (weekly, scheduled.yml): std rebuilt instrumented (-Zbuild-std), so the
# sanitizer sees every allocation. With a second argument, netvfs-bridge's
# FFI test (rust/netvfs-bridge/tests/ffi.rs) runs against the C++
# libraries that `tools/ci/ffi-libs.sh <dir> --asan` built there with
# clang's ASan, so the boundary is checked from both sides; without it,
# that test says it is skipped.
# Usage: rust-sanitize.sh <nightly toolchain> [<ffi-libs.sh --asan dir>]
set -eu
toolchain=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
if [ $# -ge 2 ]; then
    lib=$(cd "$2" && pwd)/lib
    export NETVFS_BRIDGE_FFI="$lib/netvfs/libnetvfs-bridge-ffi.so"
    export NETVFS_BRIDGE_FFI_FAKE="$lib/libnetvfs-bridge-ffi-fake.so"
    export NETVFS_BACKEND_PATH="$lib/netvfs/test-backends"
    export QT_QPA_PLATFORM=offscreen
fi
cd "$root/rust"
host=$(rustc +"$toolchain" -vV | sed -n 's/^host: //p')
# The test binaries carry ASan's runtime statically; --export-dynamic lets
# the C++ libraries they load bind their __asan_* references to it.
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Zsanitizer=address -Cforce-frame-pointers=yes \
-Clink-arg=-Wl,--export-dynamic"
export RUSTDOCFLAGS="$RUSTFLAGS"
# std rebuilt under the workspace's panic = "abort" fails ("panic_abort does
# not have the panic strategy abort"); tests unwind anyway.
export CARGO_PROFILE_DEV_PANIC=unwind
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:detect_stack_use_after_return=1"
# Third-party leaks only (Qt, libaccounts), as for the C++ sanitizer job.
export LSAN_OPTIONS="suppressions=$root/tools/sanitizer/lsan.supp:print_suppressions=0"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/asan}"
cargo +"$toolchain" nextest run -Zbuild-std --target "$host" --locked --workspace --all-features \
    --profile ci
