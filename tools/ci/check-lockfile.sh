#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Guards a Rust lockfile for the SDK's cargo 1.75 (doc/RUST.md):
#   - lockfile version 3: cargo 1.75 cannot read version 4, which a newer
#     cargo writes on any `cargo update`;
#   - no locked crate needs a newer Rust (rust-version) or edition 2024:
#     cargo 1.75 cannot read such a manifest, which breaks the vendored SDK
#     build even when nothing compiles that crate.
# Usage: check-lockfile.sh <Cargo.lock>
set -eu
lock=$1
version=$(sed -n 's/^version = \([0-9]*\)$/\1/p' "$lock" | head -n 1)
if [ "$version" != 3 ]; then
    echo "$lock: lockfile version ${version:-unknown}; cargo 1.75 reads version 3 only"
    exit 1
fi
cd "$(dirname "$lock")"
cargo metadata --locked --format-version 1 | python3 -c '
import json, sys
msrv = (1, 75)
bad = []
for p in json.load(sys.stdin)["packages"]:
    if int(p["edition"]) >= 2024:
        bad.append("%s %s: edition %s" % (p["name"], p["version"], p["edition"]))
    rust = p.get("rust_version")
    if rust and tuple(int(x) for x in rust.split(".")[:2]) > msrv:
        bad.append("%s %s: rust-version %s" % (p["name"], p["version"], rust))
for line in bad:
    print("needs more than Rust 1.75:", line)
sys.exit(1 if bad else 0)
'
