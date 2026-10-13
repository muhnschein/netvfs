#!/bin/sh
# Host packages for building and testing on Ubuntu 24.04 (CI runners, dev boxes),
# the Rust toolchain that rust/rust-toolchain.toml pins (with clippy,
# rustfmt and the llvm-tools for coverage). libc6-i386 and
# qemu-user-static are for the cross build (tools/ci/lift-sdk.sh: the SDK's
# compilers are i486 binaries; the smoke run uses qemu).
set -eu
sudo=""
[ "$(id -u)" -eq 0 ] || sudo=sudo
$sudo apt-get update -q
DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y -q --no-install-recommends \
    build-essential cmake pkg-config git python3 \
    qtbase5-dev qtbase5-dev-tools qtdeclarative5-dev qttools5-dev-tools \
    libqt5sql5-sqlite libqt5xmlpatterns5-dev \
    libaccounts-qt5-dev libsignon-qt5-dev signond signon-plugin-password \
    libssl-dev zlib1g-dev libcurl4-openssl-dev libsqlite3-dev \
    dbus dbus-x11 libdbus-1-dev openssh-client smbclient \
    bear gcovr \
    clang libclang-rt-dev \
    libc6-i386 qemu-user-static
cd "$(dirname "$0")/../../rust"
# rustup 1.28 installs the pinned toolchain this way, older ones on `show`.
rustup toolchain install || rustup show active-toolchain
