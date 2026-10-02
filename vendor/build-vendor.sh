#!/bin/sh
# Builds the vendored protocol libraries static and position-independent into
# a build-local prefix (SPEC P-1..P-3). Usage: build-vendor.sh <prefix> [extra cmake args]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
prefix=$1
shift
work="$prefix/work"
jobs=${NETVFS_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}

mkdir -p "$work"

build() {
    name=$1
    shift
    stamp="$prefix/.$name.stamp"
    rev=$(git -C "$here/$name" rev-parse HEAD 2>/dev/null || echo unknown)
    patches=$(cat "$here/patches/$name"/*.patch 2>/dev/null | cksum)
    want="$rev $patches ${CFLAGS:-} $*"
    if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$want" ]; then
        return 0
    fi
    # Local fixes on top of the pin (vendor/patches/<name>/*.patch) are
    # applied to a copy, so the submodule checkout stays pristine.
    src="$here/$name"
    if ls "$here/patches/$name"/*.patch >/dev/null 2>&1; then
        src="$work/$name-src"
        rm -rf "$src"
        mkdir -p "$src"
        (cd "$here/$name" && tar --exclude=.git -cf - .) | (cd "$src" && tar -xf -)
        for patch in "$here/patches/$name"/*.patch; do
            patch -d "$src" -p1 --batch --forward --quiet < "$patch"
        done
    fi
    rm -rf "$work/$name"
    cmake -S "$src" -B "$work/$name" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_INSTALL_PREFIX="$prefix" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF \
        "$@"
    cmake --build "$work/$name" -j "$jobs"
    cmake --install "$work/$name"
    printf '%s' "$want" > "$stamp"
}

build libssh \
    -DWITH_SERVER=OFF -DWITH_EXAMPLES=OFF -DWITH_GSSAPI=OFF -DWITH_PCAP=OFF \
    -DUNIT_TESTING=OFF -DCLIENT_TESTING=OFF -DWITH_ZLIB=OFF -DWITH_NACL=OFF \
    "$@"

build libsmb2 \
    -DENABLE_LIBKRB5=OFF -DENABLE_GSSAPI=OFF -DENABLE_EXAMPLES=OFF \
    -DENABLE_LIBDCERPC=OFF \
    "$@"
