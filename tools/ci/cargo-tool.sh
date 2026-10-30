#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Installs a pinned cargo tool (cargo-nextest, cargo-mutants, cargo-deny, cargo-fuzz) into ~/.cargo/bin unless that version is there (CI caches per tool and version). Built from crates.io with current stable and the tool's lockfile.
# Usage: cargo-tool.sh <crate> <version>
set -eu
crate=$1
version=$2
if cargo "${crate#cargo-}" --version 2> /dev/null | grep -qF " $version"; then
    exit 0
fi
rustup toolchain install stable --profile minimal > /dev/null
cargo +stable install --locked "$crate@$version"
