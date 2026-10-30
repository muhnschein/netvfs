#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Regenerates the netvfs-accounts answers for the `accounts::qds` tests with the helper's own encoder.
# Built with rustc alone, outside the workspace.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
rustc --edition 2024 -O -o "$work/golden" "$here/golden.rs"
cd "$here"
"$work/golden"
