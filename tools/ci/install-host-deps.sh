#!/bin/sh
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
rustup toolchain install || rustup show active-toolchain
