#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Runs each cargo-fuzz target of the Rust helper (rust/fuzz) for a fixed
# time with a nightly toolchain, which libFuzzer needs; crashes land in
# rust/fuzz/artifacts.
# Usage: rust-fuzz.sh <seconds per target>
set -eu
seconds=$1
cd "$(dirname "$0")/../../rust"
rustup toolchain install nightly --profile minimal
cargo +nightly install --locked cargo-fuzz@0.13.2
for target in $(cargo +nightly fuzz list); do
    echo "== $target"
    cargo +nightly fuzz run "$target" -- -max_total_time="$seconds"
done
