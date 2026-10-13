#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# cargo-mutants on the Rust lines changed since <base> (CI job "Tests bite
# (Rust, changed code)"): every mutant there must be caught by a test or be
# unviable; a missed one or a timeout fails. Results in rust/mutants.out.
# With a second argument, netvfs-bridge's FFI test runs against the C++
# libraries `tools/ci/ffi-libs.sh <dir>` built there (else it is skipped and
# catches nothing). Exclusions, each with its reason: rust/.cargo/mutants.toml.
# Usage: rust-mutants.sh <base revision> [<ffi-libs.sh dir>]
set -eu
base=$1
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
cargo mutants --in-diff "$diff" --workspace --features netvfs-accounts/probe,netvfs-bridge/testing \
    --test-tool nextest --no-shuffle --timeout-multiplier 3
