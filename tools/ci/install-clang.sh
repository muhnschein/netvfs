#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Installs clang-<major> and its sanitizer runtimes from apt.llvm.org on the Ubuntu 24.04 runner, for
# the C++ side of the weekly ASan run, which must be built by a clang of
# rustc's LLVM major (rust-sanitize.sh; design §6.6). The repository's
# signing key is pinned by fingerprint; the suite is the release branch of
# that major, or the development branch when the major is not released yet.
# Usage: install-clang.sh <major>
set -eu
major=$1
case "$major" in
    '' | *[!0-9]*) echo "install-clang.sh: not a version: $major" >&2; exit 2 ;;
esac
command -v "clang-$major" >/dev/null && exit 0

base=https://apt.llvm.org/noble
fingerprint=6084F3CF814B57C1CF12EFD515CF4D18AF4F7421
keyring=/usr/share/keyrings/apt-llvm-org.gpg
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsSL --proto '=https' --tlsv1.2 -o "$work/key.asc" https://apt.llvm.org/llvm-snapshot.gpg.key
gpg --batch --dearmor -o "$work/key.gpg" "$work/key.asc"
if ! gpg --batch --show-keys --with-colons "$work/key.gpg" | grep -qx "fpr:::::::::$fingerprint:"; then
    echo "install-clang.sh: the apt.llvm.org key is not $fingerprint" >&2
    exit 1
fi
suite=llvm-toolchain-noble-$major
if ! curl -fsSI --proto '=https' --tlsv1.2 "$base/dists/$suite/Release" >/dev/null; then
    suite=llvm-toolchain-noble
fi
sudo install -m 0644 "$work/key.gpg" "$keyring"
echo "deb [signed-by=$keyring] $base/ $suite main" | sudo tee /etc/apt/sources.list.d/apt-llvm-org.list >/dev/null
sudo apt-get update -q
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    "clang-$major" "libclang-rt-$major-dev"
"clang-$major" --version
