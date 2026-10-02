#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Builds the FTP plugin and its tests against the libcurl in <prefix> (built
# by build-curl.sh; found through pkg-config, linked with an rpath) and runs
# the FTP unit tests and the FTP interop suite (needs docker) with it.
# Only the pieces the FTP tests need are built, in their own build tree.
#
# Usage: ftp-against-curl.sh <curl prefix> [build dir]
set -eu
prefix=$(cd "$1" && pwd)
root=$(cd "$(dirname "$0")/../.." && pwd)
build=${2:-$root/build-curl}
mkdir -p "$build"
build=$(cd "$build" && pwd)
qmake=$(command -v qmake-qt5 || command -v qmake)
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export QT_QPA_PLATFORM=offscreen

dirs="src/core src/backends/ftp tests/common tests/unit/ftp tests/interop/ftp"
for d in $dirs; do
    mkdir -p "$build/$d"
    (cd "$build/$d" && "$qmake" "$root/$d/$(basename "$d").pro" NETVFS_WERROR=1 "QMAKE_LFLAGS+=-Wl,-rpath,$prefix/lib")
done
for d in $dirs; do
    make -C "$build/$d" -j"$(nproc)"
done

ldd "$build/lib/netvfs/backends/libnetvfs-ftp.so" | grep "libcurl.so.4 => $prefix/lib/" \
    || { echo "the FTP plugin does not use the libcurl in $prefix"; exit 1; }
"$build/tests/unit/ftp/tst_ftp"
sh "$root/tests/interop/ftp/run.sh" "$build"
