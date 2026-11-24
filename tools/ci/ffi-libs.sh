#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
mkdir -p "$1"
build=$(cd "$1" && pwd)
asan=${2:-}
root=$(cd "$(dirname "$0")/../.." && pwd)
qmake=$(command -v qmake-qt5 || command -v qmake)
set --
if [ "$asan" = "--asan" ]; then
    flags="-fsanitize=address -fno-omit-frame-pointer"
    cc=clang${CLANG_MAJOR:+-$CLANG_MAJOR}
    cxx=clang++${CLANG_MAJOR:+-$CLANG_MAJOR}
    set -- -spec linux-clang "QMAKE_CC=$cc" "QMAKE_CXX=$cxx" "QMAKE_LINK=$cxx" "QMAKE_LINK_SHLIB=$cxx" \
        "QMAKE_CXXFLAGS+=$flags" "QMAKE_CFLAGS+=$flags" "QMAKE_LFLAGS+=-fsanitize=address"
fi
for dir in src/core tests/common tests/fakeplugin src/bridge/ffi tests/bridge/ffifake; do
    mkdir -p "$build/$dir"
    (cd "$build/$dir" && "$qmake" "$@" "$root/$dir"/*.pro && make -j"$(getconf _NPROCESSORS_ONLN)")
done
