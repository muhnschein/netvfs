#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Guards the Rust lockfile for the toolchain of rust-version (doc/RUST.md):
#   - a lockfile version that cargo of rust-version reads (3 or 4);
#   - no locked crate needs a newer Rust (rust-version) than the workspace's,
#     which the SDK's cargo could not build once the spec runs cargo again.
# Usage: check-lockfile.sh <Cargo.lock>
set -eu
lock=$1
version=$(sed -n 's/^version = \([0-9]*\)$/\1/p' "$lock" | head -n 1)
case "$version" in
    3|4) ;;
    *) echo "$lock: lockfile version ${version:-unknown}; cargo 1.95 reads versions 3 and 4"; exit 1 ;;
esac
cd "$(dirname "$lock")"
msrv=$(sed -n 's/^rust-version = "\([0-9.]*\)"/\1/p' Cargo.toml)
cargo metadata --locked --format-version 1 | python3 -c '
import json, sys
msrv = tuple(int(x) for x in sys.argv[1].split(".")[:2])
bad = []
for p in json.load(sys.stdin)["packages"]:
    rust = p.get("rust_version")
    if rust and tuple(int(x) for x in rust.split(".")[:2]) > msrv:
        bad.append("%s %s: rust-version %s" % (p["name"], p["version"], rust))
for line in bad:
    print("needs more than Rust %s:" % sys.argv[1], line)
sys.exit(1 if bad else 0)
' "$msrv"
