#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Checks libnetvfs-rs.so, the Rust backends that the backend plugins load
# with dlopen (doc/RUST.md), from its ELF headers and against those plugins:
#   - it exports one symbol, nvr_get (rustc's export list for a cdylib);
#   - it links only the C runtime: libc, libgcc_s, libm, libpthread, libdl
#     and the dynamic loader (no Qt, no libnetvfs: its Rust std, tokio and
#     crypto stay inside);
#   - no GLIBC symbol version above the given one (the target's glibc is the
#     floor, as for the Rust binaries: check-linked-libs.sh);
#   - full RELRO, immediate binding, no executable stack;
#   - each given plugin looks for it where it is installed (the shim's
#     compiled-in path, src/backends/rs/rs.pri).
# Usage: check-rs-lib.sh <library> <max glibc version> <installed path> [<plugin>...]
set -eu
library=$1
max_glibc=$2
installed=$3
shift 3
name=$(basename "$library")
status=0
fail() {
    echo "FAIL: $name: $1"
    status=1
}

exports=$(readelf -W --dyn-syms "$library" \
    | awk '$1 ~ /^[0-9]+:$/ && $5 != "LOCAL" && $7 != "UND" && $7 != "ABS" { sub(/@.*/, "", $8); print $8 }' \
    | sort -u | tr '\n' ' ' | sed 's/ $//')
[ "$exports" = nvr_get ] || fail "exports \"$exports\", expected only nvr_get"

needed=$(readelf -d "$library" | sed -n 's/.*(NEEDED).*\[\(.*\)\]$/\1/p')
for lib in $needed; do
    case "$lib" in
        libc.so.6 | libgcc_s.so.1 | libm.so.6 | libpthread.so.0 | libdl.so.2 | ld-linux*.so.*) ;;
        *) fail "links $lib" ;;
    esac
done

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

for plugin in "$@"; do
    grep -qaF "$installed" "$plugin" || fail "$(basename "$plugin") does not load it from $installed"
done
[ "$status" -ne 0 ] || echo "$name: exports nvr_get, links $(echo "$needed" | tr '\n' ' ' | sed 's/ $//'), GLIBC_${highest:-none} <= $max_glibc, RELRO, BIND_NOW, NX stack, loaded from $installed by $# plugin(s)"
exit $status
