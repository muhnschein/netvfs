#!/bin/sh
# Host packages for building and testing on Ubuntu 24.04 (CI runners, dev boxes).
set -eu
sudo=""
[ "$(id -u)" -eq 0 ] || sudo=sudo
$sudo apt-get update -q
DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y -q --no-install-recommends \
    build-essential cmake pkg-config git python3 \
    qtbase5-dev qtbase5-dev-tools qtdeclarative5-dev qttools5-dev-tools \
    libqt5sql5-sqlite libqt5xmlpatterns5-dev \
    libaccounts-qt5-dev libsignon-qt5-dev signond signon-plugin-password \
    libssl-dev zlib1g-dev libcurl4-openssl-dev \
    dbus dbus-x11 libdbus-1-dev openssh-client smbclient \
    bear gcovr \
    clang libclang-rt-dev
