#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Builds a vanilla libcurl (OpenSSL, no extras) from the official release
# tarball into a prefix, for the job that tests the FTP backend against the
# libcurl generation of the Sailfish OS target. The tarball is pinned by its
# SHA-256. Does nothing when the prefix already holds that version (cache).
#
# Usage: build-curl.sh <version> <sha256> <prefix>
set -eu
version=$1
sha256=$2
prefix=$3

if [ -f "$prefix/lib/pkgconfig/libcurl.pc" ] && grep -q "^Version: $version\$" "$prefix/lib/pkgconfig/libcurl.pc"; then
    echo "libcurl $version already built in $prefix"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tarball="curl-$version.tar.xz"
tag=$(echo "curl-$version" | tr . _)
curl -fsSL -o "$work/$tarball" "https://github.com/curl/curl/releases/download/$tag/$tarball"
echo "$sha256  $work/$tarball" | sha256sum -c -
tar -xf "$work/$tarball" -C "$work"
cd "$work/curl-$version"
./configure --prefix="$prefix" --with-openssl --without-libpsl --without-brotli --without-zstd \
    --without-nghttp2 --disable-ldap --disable-docs --disable-manual --disable-static > "$work/configure.log" 2>&1 \
    || { tail -n 30 "$work/configure.log"; exit 1; }
make -j"$(nproc)" > "$work/make.log" 2>&1 || { tail -n 30 "$work/make.log"; exit 1; }
make install > "$work/install.log" 2>&1 || { tail -n 30 "$work/install.log"; exit 1; }
"$prefix/bin/curl-config" --version
