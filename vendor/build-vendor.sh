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

# build <library> <variant> [cmake args]: the variant "main" installs into
# <prefix>, any other into <prefix>/<variant> (own stamp and work folder).
build() {
    name=$1
    variant=$2
    shift 2
    dest=$prefix
    tag=$name
    if [ "$variant" != main ]; then
        dest="$prefix/$variant"
        tag="$name-$variant"
    fi
    stamp="$prefix/.$tag.stamp"
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
        src="$work/$tag-src"
        rm -rf "$src"
        mkdir -p "$src"
        (cd "$here/$name" && tar --exclude=.git -cf - .) | (cd "$src" && tar -xf -)
        for patch in "$here/patches/$name"/*.patch; do
            patch -d "$src" -p1 --batch --forward --quiet < "$patch"
        done
    fi
    rm -rf "$work/$tag"
    cmake -S "$src" -B "$work/$tag" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_INSTALL_PREFIX="$dest" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF \
        "$@"
    cmake --build "$work/$tag" -j "$jobs"
    cmake --install "$work/$tag"
    printf '%s' "$want" > "$stamp"
}

build libssh main \
    -DWITH_SERVER=OFF -DWITH_EXAMPLES=OFF -DWITH_GSSAPI=OFF -DWITH_PCAP=OFF \
    -DUNIT_TESTING=OFF -DCLIENT_TESTING=OFF -DWITH_ZLIB=OFF -DWITH_NACL=OFF \
    "$@"

# The backend plugin's copy: no Kerberos, no libdcerpc (G-SMB item 4; the
# plugin also links src/backends/smb/noshareenum.c).
build libsmb2 main \
    -DENABLE_LIBKRB5=OFF -DENABLE_GSSAPI=OFF -DENABLE_EXAMPLES=OFF \
    -DENABLE_LIBDCERPC=OFF \
    "$@"

# SPEC-v2 XM-7: a second build, with DCE/RPC, for the share enumeration
# helper netvfs-smb-shares only. It runs as its own process, so the
# plugin keeps G-SMB item 4. Same pin and patches.
build libsmb2 dcerpc \
    -DENABLE_LIBKRB5=OFF -DENABLE_GSSAPI=OFF -DENABLE_EXAMPLES=OFF \
    -DENABLE_LIBDCERPC=ON \
    "$@"
