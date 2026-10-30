#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Only the C++ libraries netvfs-bridge's FFI test needs (rust/netvfs-bridge/tests/ffi.rs): libnetvfs, libnetvfstest, fake
# backend plugin, libnetvfs-bridge-ffi.so and its fake control table, for CI jobs without a full build.
#
# --asan: instrumented for the Rust tests under ASan (rust-sanitize.sh). The runtime is the one `rustc -Zsanitizer=address`
# links into the test binary (LLVM's), so build with clang, not gcc (a second runtime), ASan only (no UBSan runtime in the
# Rust binary); clang leaves a shared library's __asan_* symbols to the executable. CLANG_MAJOR (optional) picks
# clang-<major> and clang++-<major>: rustc's LLVM major (install-clang.sh installs it).
# Usage: [CLANG_MAJOR=<major>] ffi-libs.sh <build dir> [--asan]
# Then: NETVFS_BRIDGE_FFI=<dir>/lib/netvfs/libnetvfs-bridge-ffi.so,
# NETVFS_BRIDGE_FFI_FAKE=<dir>/lib/libnetvfs-bridge-ffi-fake.so,
# NETVFS_BACKEND_PATH=<dir>/lib/netvfs/test-backends.
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
