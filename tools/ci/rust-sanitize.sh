#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
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
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Zsanitizer=address -Cforce-frame-pointers=yes \
-Clink-arg=-Wl,--export-dynamic --cfg netvfs_asan"
export RUSTDOCFLAGS="$RUSTFLAGS"
export CARGO_PROFILE_DEV_PANIC=unwind
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:detect_stack_use_after_return=1"
export NETVFS_TEST_SANITIZER=address
export LSAN_OPTIONS="suppressions=$root/tools/sanitizer/lsan.supp:print_suppressions=0"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/asan}"
run() {
    cargo +"$toolchain" nextest run -Zbuild-std --target "$host" --locked --workspace --all-features \
        --profile ci --test-threads num-cpus "$@"
}
sandbox='binary_id(netvfs-accounts::sandbox)'
run -E "not $sandbox"
ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:detect_stack_use_after_return=1" \
    run -E "$sandbox"
