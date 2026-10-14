#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# The Rust workspace's tests under AddressSanitizer with LeakSanitizer
# (weekly, scheduled.yml): std rebuilt instrumented (-Zbuild-std), so the
# sanitizer sees every allocation.
# Usage: rust-sanitize.sh <nightly toolchain>
set -eu
toolchain=$1
cd "$(dirname "$0")/../../rust"
host=$(rustc +"$toolchain" -vV | sed -n 's/^host: //p')
export RUSTFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes"
export RUSTDOCFLAGS="$RUSTFLAGS"
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:detect_stack_use_after_return=1"
export CARGO_TARGET_DIR="$PWD/target/asan"
cargo +"$toolchain" nextest run -Zbuild-std --target "$host" --locked --workspace --all-features \
    --profile ci
