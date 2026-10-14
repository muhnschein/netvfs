#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# cargo-mutants on the Rust lines changed since <base> (CI job "Tests bite
# (Rust, changed code)"): every mutant there must be caught by a test or be
# unviable; a missed one fails. A timeout counts as caught: the mutant made a
# test hang, which nextest's slow-timeout ends. Results in rust/mutants.out.
# With a second argument, netvfs-bridge's FFI test runs against the C++
# libraries `tools/ci/ffi-libs.sh <dir>` built there (else it is skipped and
# catches nothing). Exclusions, each with its reason: rust/.cargo/mutants.toml.
# With a third argument k/n, only shard k (from 0) of n runs, every n-th
# mutant (CI runs the shards as parallel jobs).
# Usage: rust-mutants.sh <base revision> [<ffi-libs.sh dir> [<k>/<n>]]
set -eu
base=$1
shard=
if [ $# -ge 3 ]; then
    shard="--shard=$3 --sharding=round-robin"
fi
root=$(cd "$(dirname "$0")/../.." && pwd)
if [ $# -ge 2 ]; then
    lib=$(cd "$2" && pwd)/lib
    export NETVFS_BRIDGE_FFI="$lib/netvfs/libnetvfs-bridge-ffi.so"
    export NETVFS_BRIDGE_FFI_FAKE="$lib/libnetvfs-bridge-ffi-fake.so"
    export NETVFS_BACKEND_PATH="$lib/netvfs/test-backends"
    export QT_QPA_PLATFORM=offscreen
fi
cd "$root"
diff=$(mktemp)
trap 'rm -f "$diff"' EXIT
git diff "$base...HEAD" -- 'rust/*.rs' ':!rust/fuzz' > "$diff"
if [ ! -s "$diff" ]; then
    echo "no Rust source changed since $base"
    exit 0
fi
cd rust
# --in-diff takes paths relative to the workspace root.
sed -i -e 's|^--- a/rust/|--- a/|' -e 's|^+++ b/rust/|+++ b/|' "$diff"
status=0
# All features: --in-diff selects the packages it touches, and naming a
# feature of one it left out is an error. In place: tests read files outside
# rust/ (the shared contract), which a copy of the workspace would not have;
# each mutated file is restored after its test run.
cargo mutants --in-place --in-diff "$diff" --workspace --all-features \
    --test-tool nextest --no-shuffle --timeout-multiplier 3 $shard || status=$?
# Its exit status says "timeouts" also when mutants were missed, so the
# outcome is read from the lists: 0 ok, 2 missed, 3 timeouts, anything
# else (the baseline failed, a usage error) stands.
case "$status" in
    0|2|3) ;;
    *) exit "$status" ;;
esac
if [ -s mutants.out/missed.txt ]; then
    echo "missed mutants:"
    cat mutants.out/missed.txt
    exit 1
fi
