#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
build=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root/rust"
host=$(rustc -vV | sed -n 's/^host: //p')
tools=$(rustc --print sysroot)/lib/rustlib/$host/bin
[ -x "$tools/llvm-cov" ] || { echo "rust-coverage.sh: no llvm-cov; rustup component add llvm-tools"; exit 1; }

objects="$build/rust-target/release/netvfs-accounts $build/rust-target/release/netvfs-bridge"
objects="$objects $build/rust-target/rs-test/libnetvfs_rs.so"
objects="$objects $(RUSTFLAGS="-C instrument-coverage" NETVFS_RUST_COVERAGE_DIR="$build/rust-coverage" \
    CARGO_TARGET_DIR="$build/rust-test-target" \
    cargo test --locked --workspace --features netvfs-accounts/probe,netvfs-bridge/testing,netvfs-bridge/test-bins,netvfs-backend/testing \
    --no-run --message-format=json 2>/dev/null \
    | python3 -c '
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if message.get("reason") == "compiler-artifact" and message.get("executable"):
        print(message["executable"])
')"

profiles=$(find "$build/rust-coverage" -name '*.profraw')
[ -n "$profiles" ] || { echo "rust-coverage.sh: no counters in $build/rust-coverage"; exit 1; }
"$tools/llvm-profdata" merge -sparse $profiles -o "$build/rust-coverage.profdata"
first=${objects%% *}
rest=$(for o in ${objects#* }; do printf -- '-object %s ' "$o"; done)
ignore='/\.cargo/|/rustc/|/vendor/|/tests/|/build/[^/]*/out/'
"$tools/llvm-cov" export -format=lcov -instr-profile="$build/rust-coverage.profdata" \
    -ignore-filename-regex="$ignore" "$first" $rest > "$build/rust-lcov.info"
"$tools/llvm-cov" report -instr-profile="$build/rust-coverage.profdata" \
    -ignore-filename-regex="$ignore" "$first" $rest | tail -n 1
