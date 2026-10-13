#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# The Rust coverage of `make coverage` as lcov for SonarQube: the counters
# that the instrumented netvfs-accounts (built by qmake) wrote while the C++
# tests ran it, and those of the workspace's own tests (netvfs-bridge's ffi
# test against the C++ library included: `make check-rust-ffi`), merged
# with the llvm-tools of the pinned toolchain.
# Usage: rust-coverage.sh <build-coverage dir>; writes <dir>/rust-lcov.info.
set -eu
build=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root/rust"
host=$(rustc -vV | sed -n 's/^host: //p')
tools=$(rustc --print sysroot)/lib/rustlib/$host/bin
[ -x "$tools/llvm-cov" ] || { echo "rust-coverage.sh: no llvm-cov; rustup component add llvm-tools"; exit 1; }

# The binaries the counters belong to: the helper as qmake built it, and the
# workspace's test and probe binaries (as `make check-rust` and
# `make check-rust-ffi` built them: the same features as RUST_FEATURES).
objects=$build/rust-target/release/netvfs-accounts
objects="$objects $(RUSTFLAGS="-C instrument-coverage" NETVFS_RUST_COVERAGE_DIR="$build/rust-coverage" \
    CARGO_TARGET_DIR="$build/rust-test-target" \
    cargo test --locked --workspace --features netvfs-accounts/probe,netvfs-bridge/testing --no-run --message-format=json 2>/dev/null \
    | python3 -c '
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if message.get("reason") == "compiler-artifact" and message.get("executable"):
        print(message["executable"])
')"

profiles=$(find "$build/rust-coverage" -name '*.profraw')
[ -n "$profiles" ] || { echo "rust-coverage.sh: no counters in $build/rust-coverage"; exit 1; }
# shellcheck disable=SC2086 # one word per file
"$tools/llvm-profdata" merge -sparse $profiles -o "$build/rust-coverage.profdata"
first=${objects%% *}
rest=$(for o in ${objects#* }; do printf -- '-object %s ' "$o"; done)
ignore='/\.cargo/|/rustc/|/vendor/|/tests/|/build/[^/]*/out/'
# shellcheck disable=SC2086 # one word per argument
"$tools/llvm-cov" export -format=lcov -instr-profile="$build/rust-coverage.profdata" \
    -ignore-filename-regex="$ignore" "$first" $rest > "$build/rust-lcov.info"
# shellcheck disable=SC2086
"$tools/llvm-cov" report -instr-profile="$build/rust-coverage.profdata" \
    -ignore-filename-regex="$ignore" "$first" $rest | tail -n 1
