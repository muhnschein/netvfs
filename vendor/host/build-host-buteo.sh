#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Builds only libbuteosyncfw5 from the pinned upstream submodule
# (vendor/host/buteo-syncfw) into <prefix>/lib and <prefix>/include/buteosyncfw5,
# so that the Buteo plugins and their tests build on a development host that
# has no buteo-syncfw packages. Never used by the Sailfish SDK / RPM build,
# which takes buteosyncfw5 from pkg-config (buteo-syncfw-qt5-devel).
#
# Usage: build-host-buteo.sh <prefix>
set -eu

here=$(cd "$(dirname "$0")" && pwd)
src="$here/buteo-syncfw/libbuteosyncfw"
prefix=$1
work="$prefix/work"
stage="$prefix/stage"
qmake=${QMAKE:-$(command -v qmake-qt5 || command -v qmake)}
jobs=${NETVFS_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}

if [ ! -f "$src/libbuteosyncfw.pro" ]; then
    echo "build-host-buteo.sh: $src is missing; run: git submodule update --init vendor/host/buteo-syncfw" >&2
    exit 1
fi

stamp="$prefix/.buteo-syncfw.stamp"
rev=$(git -C "$here/buteo-syncfw" rev-parse HEAD 2>/dev/null || echo unknown)
want="$rev $($qmake -query QT_VERSION)"
if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$want" ] && [ -f "$prefix/lib/libbuteosyncfw5.so" ]; then
    exit 0
fi

rm -rf "$work" "$stage" "$prefix/lib" "$prefix/include"
mkdir -p "$work" "$prefix/lib" "$prefix/include"
(cd "$work" && "$qmake" "$src/libbuteosyncfw.pro" && make -j"$jobs" && make install INSTALL_ROOT="$stage")

libdir=$($qmake -query QT_INSTALL_LIBS)
cp -a "$stage$libdir"/libbuteosyncfw5.so* "$prefix/lib/"
cp -a "$stage/usr/include/buteosyncfw5" "$prefix/include/"
rm -rf "$stage"
printf '%s' "$want" > "$stamp"
