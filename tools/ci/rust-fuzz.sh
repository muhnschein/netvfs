#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Runs each cargo-fuzz target of the Rust helper (rust/fuzz) for a fixed
# time with a nightly toolchain, which libFuzzer needs; crashes land in
# rust/fuzz/artifacts. The committed seeds of a target
# (rust/fuzz/seeds/<target>: reproducers of what it found) run first; new
# inputs go to rust/fuzz/corpus/<target>.
# Usage: rust-fuzz.sh <seconds per target>
set -eu
seconds=$1
cd "$(dirname "$0")/../../rust"
fuzz=$PWD/fuzz
rustup toolchain install nightly --profile minimal
cargo +nightly install --locked cargo-fuzz@0.13.2
for target in $(cargo +nightly fuzz list); do
    echo "== $target"
    mkdir -p "$fuzz/corpus/$target" "$fuzz/seeds/$target"
    cargo +nightly fuzz run "$target" "$fuzz/corpus/$target" "$fuzz/seeds/$target" -- -max_total_time="$seconds"
done
