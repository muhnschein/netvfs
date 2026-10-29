#!/bin/sh
# Host packages for building and testing on Ubuntu 24.04 (CI runners, dev boxes),
# the Rust toolchain that rust/rust-toolchain.toml pins (with clippy,
# rustfmt and the llvm-tools for coverage). libc6-i386 and
# qemu-user-static are for the cross build (tools/ci/lift-sdk.sh: the SDK's
# compilers are i486 binaries; the smoke run uses qemu).
# CI runner: through apt-install.sh (third-party lists dropped, fastest
# mirror, stall cut off). Dev box: plain apt-get, its lists untouched.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
if [ "${GITHUB_ACTIONS:-}" = true ]; then
    install() { DEBIAN_FRONTEND=noninteractive "$here/apt-install.sh" --no-install-recommends "$@"; }
else
    sudo=""
    [ "$(id -u)" -eq 0 ] || sudo=sudo
    $sudo apt-get update -q
    install() { DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y -q --no-install-recommends "$@"; }
fi
install \
    build-essential pkg-config git python3 \
    qtbase5-dev qtbase5-dev-tools qtdeclarative5-dev qttools5-dev-tools \
    libqt5sql5-sqlite libqt5xmlpatterns5-dev \
    libaccounts-qt5-dev libsignon-qt5-dev signond signon-plugin-password \
    zlib1g-dev libsqlite3-dev \
    dbus dbus-x11 libdbus-1-dev openssh-client smbclient \
    bear gcovr \
    clang libclang-rt-dev \
    libc6-i386 qemu-user-static
cd "$here/../../rust"
# rustup 1.28 installs the pinned toolchain this way, older ones on `show`.
rustup toolchain install || rustup show active-toolchain
