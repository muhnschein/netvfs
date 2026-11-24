#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
SDK_IMAGE=${SDK_IMAGE:-sfos:5.2}
TARGET=${TARGET:-SailfishOS-5.2.0.15-aarch64}
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work" 2>/dev/null || sudo rm -rf "$work"' EXIT

mkdir -p "$work/src" "$work/accounts" "$work/tests"
cp "$root/common.pri" "$root/.qmake.conf" "$work/"
cp -r "$root/src/core" "$root/src/qml" "$work/src/"
cp -r "$root/accounts/ui" "$root/accounts/descriptors" "$work/accounts/"
cp -r "$root/tests/qmltarget" "$work/tests/"
chmod -R a+rwX "$work"

docker run --rm -v "$work:/home/mersdk/src" "$SDK_IMAGE" bash -euc "
    sb2() { command sb2 -t '$TARGET' \"\$@\"; }
    cd ~/src && mkdir -p build/tests/qmltarget && cd build/tests/qmltarget
    sb2 qmake -r ~/src/tests/qmltarget/qmltarget.pro NETVFS_WERROR=1
    sb2 make -j\$(nproc)
    cd ~/src
    # Provider descriptors, so the account dialogs render their fields.
    QT_QPA_PLATFORM=minimal NETVFS_PROVIDERS_DIR=~/src/accounts/descriptors sb2 build/tests/qmltarget/qmlcheck/qmlcheck --create \
        -I ~/src/tests/qmltarget/stubs -I ~/src/build/qml src/qml/*.qml accounts/ui/*.qml \
        tests/qmltarget/selftest/*.qml
"
