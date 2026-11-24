#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
crate=$1
version=$2
if cargo "${crate#cargo-}" --version 2> /dev/null | grep -qF " $version"; then
    exit 0
fi
rustup toolchain install stable --profile minimal > /dev/null
cargo +stable install --locked "$crate@$version"
