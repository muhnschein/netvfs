#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# cargo-mutants on the Rust lines changed since <base> (CI job "Tests bite
# (Rust, changed code)"): every mutant there must be caught by a test or be
# unviable; a missed one or a timeout fails. Results in rust/mutants.out.
# Usage: rust-mutants.sh <base revision>
set -eu
base=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
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
cargo mutants --in-diff "$diff" --workspace --features netvfs-accounts/probe \
    --test-tool nextest --no-shuffle --timeout-multiplier 3
