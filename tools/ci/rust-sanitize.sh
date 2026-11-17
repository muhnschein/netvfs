#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Rust workspace tests under AddressSanitizer with LeakSanitizer (weekly, scheduled.yml): std rebuilt instrumented
# (-Zbuild-std) so every allocation is seen, incl. netvfs-backend's tests/ffi.rs driving libnetvfs-rs.so's C ABI. With a
# second argument, netvfs-bridge's C-ABI tests (rust/netvfs-bridge/tests) run against the C++ libraries `ffi-libs.sh
# <dir> --asan` built with clang's ASan, checking the boundary from both sides; without it they say they are skipped.
# The libraries must come from a clang of rustc's LLVM major: their __asan_* references bind to the runtime rustc links
# into the Rust executables, and older instrumentation against a newer runtime is unsupported. A mismatch fails here.
# Usage: rust-sanitize.sh <nightly toolchain> [<ffi-libs.sh --asan dir>]
set -eu
toolchain=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
llvm=$(rustc +"$toolchain" -vV | sed -n 's/^LLVM version: \([0-9]*\).*/\1/p')
if [ $# -ge 2 ]; then
    lib=$(cd "$2" && pwd)/lib
    export NETVFS_BRIDGE_FFI="$lib/netvfs/libnetvfs-bridge-ffi.so"
    export NETVFS_BRIDGE_FFI_FAKE="$lib/libnetvfs-bridge-ffi-fake.so"
    export NETVFS_BACKEND_PATH="$lib/netvfs/test-backends"
    export QT_QPA_PLATFORM=offscreen
    for so in "$NETVFS_BRIDGE_FFI" "$NETVFS_BRIDGE_FFI_FAKE" "$NETVFS_BACKEND_PATH/libnetvfs-fake.so" \
        "$lib/libnetvfs.so" "$lib/libnetvfstest.so"; do
        if ! nm -D --undefined-only "$so" | grep -q ' __asan_init$'; then
            echo "$so is not instrumented with ASan (ffi-libs.sh --asan)" >&2
            exit 1
        fi
        clang=$(readelf -p .comment "$so" | sed -n 's/.*clang version \([0-9]*\).*/\1/p' | head -n 1)
        if [ "$clang" != "$llvm" ]; then
            echo "$so: built by clang ${clang:-(none)}, rustc +$toolchain has LLVM $llvm;" \
                "build it with clang $llvm" >&2
            exit 1
        fi
    done
fi
cd "$root/rust"
host=$(rustc +"$toolchain" -vV | sed -n 's/^host: //p')
# Test binaries carry ASan's runtime statically; --export-dynamic lets the C++ libraries they load bind __asan_* to it.
# --cfg netvfs_asan: set-id binaries carry their ASan options (netvfs-accounts' __asan_default_options); they cannot read
# ASAN_OPTIONS.
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Zsanitizer=address -Cforce-frame-pointers=yes \
-Clink-arg=-Wl,--export-dynamic --cfg netvfs_asan"
export RUSTDOCFLAGS="$RUSTFLAGS"
# std rebuilt under the workspace's panic = "abort" fails ("panic_abort does not have the panic strategy abort"); tests
# unwind anyway.
export CARGO_PROFILE_DEV_PANIC=unwind
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:detect_stack_use_after_return=1"
# RSS tests skip under ASan (quarantine).
export NETVFS_TEST_SANITIZER=address
# Third-party leaks only (Qt, libaccounts), as in the C++ sanitizer job.
export LSAN_OPTIONS="suppressions=$root/tools/sanitizer/lsan.supp:print_suppressions=0"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/asan}"
# ASan heavy: one test per core.
run() {
    cargo +"$toolchain" nextest run -Zbuild-std --target "$host" --locked --workspace --all-features \
        --profile ci --test-threads num-cpus "$@"
}
# The helper confined by its own seccomp filter cannot be stopped by LeakSanitizer (no ptrace): sandbox tests run with ASan alone.
sandbox='binary_id(netvfs-accounts::sandbox)'
run -E "not $sandbox"
ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:detect_stack_use_after_return=1" \
    run -E "$sandbox"
