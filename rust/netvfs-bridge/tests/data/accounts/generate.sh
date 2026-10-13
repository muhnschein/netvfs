#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Regenerates the netvfs-accounts answers of netvfs-bridge's `accounts::qds`
# tests with the helper's own encoder (golden.rs includes its wire.rs and
# qvariant.rs). Built with rustc alone, outside the workspace and its lints;
# run from anywhere:
#
#   rust/netvfs-bridge/tests/data/accounts/generate.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
rustc --edition 2024 -O -o "$work/golden" "$here/golden.rs"
cd "$here"
"$work/golden"
