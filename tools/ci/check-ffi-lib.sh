#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Checks libnetvfs-bridge-ffi.so (C ABI of the C++ backends, dlopen'd by netvfs-bridge) from ELF headers:
#   - exports one symbol, nvb_ffi_get;
#   - links libnetvfs.so.1, whose BackendLoader finds the backends;
#   - no GLIBC symbol version above the given one (target glibc is the floor);
#   - full RELRO, immediate binding, no executable stack;
#   - netvfs-bridge contains the installed path (compiled-in default, rust/netvfs-bridge/src/ffi/mod.rs).
# Usage: check-ffi-lib.sh <library> <installed path> <netvfs-bridge> <max glibc version>
set -eu
library=$1
installed=$2
bridge=$3
max_glibc=$4
name=$(basename "$library")
status=0
fail() {
    echo "FAIL: $name: $1"
    status=1
}

exports=$(readelf -W --dyn-syms "$library" \
    | awk '$1 ~ /^[0-9]+:$/ && $5 != "LOCAL" && $7 != "UND" && $7 != "ABS" { sub(/@.*/, "", $8); print $8 }' \
    | sort -u | tr '\n' ' ' | sed 's/ $//')
[ "$exports" = nvb_ffi_get ] || fail "exports \"$exports\", expected only nvb_ffi_get"

readelf -d "$library" | grep -q '(NEEDED).*\[libnetvfs\.so\.1\]' || fail "does not link libnetvfs.so.1"

highest=$(readelf -W --dyn-syms "$library" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -n 1)
if [ -n "$highest" ] && [ "$(printf '%s\n%s\n' "$highest" "$max_glibc" | sort -V | tail -n 1)" != "$max_glibc" ]; then
    fail "needs GLIBC_$highest, the target has $max_glibc"
fi

readelf -lW "$library" | grep -q GNU_RELRO || fail "no RELRO"
readelf -d "$library" | grep -Eq 'FLAGS.*(BIND_NOW| NOW)' || fail "does not bind now"
stack=$(readelf -lW "$library" | grep GNU_STACK || true)
case "$stack" in
    *RWE*) fail "executable stack" ;;
    "") fail "no GNU_STACK header" ;;
esac

grep -qaF "$installed" "$bridge" || fail "$(basename "$bridge") does not load it from $installed"
[ "$status" -ne 0 ] || echo "$name: exports nvb_ffi_get, links libnetvfs.so.1, GLIBC_${highest:-none} <= $max_glibc, RELRO, BIND_NOW, NX stack, loaded from $installed"
exit $status
