#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Compares RPMs with a rebuild's (tools/verify-rpm.sh runs it in the SDK
# image, which has rpm, rpm2cpio and cpio).
#
#     compare-rpms.sh <rebuilt dir> <rpm>...
#
# Each RPM against the rebuilt one of the same name and architecture, a line
# each:
#   VERIFIED    same file, byte for byte
#   SAME FILES  same files, modes, owners and links inside; packaging differs
#               (build time, file dates, host, signature)
#   DIFFERENT   files differ, or the rebuild made no such package
# Exit, worst of all: 0 VERIFIED, 1 SAME FILES, 2 DIFFERENT, 3 can't compare.
set -eu

[ $# -ge 2 ] || { echo "usage: $0 <rebuilt dir> <rpm>..." >&2; exit 3; }
rebuilt=$1
shift
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

worst=0
result() {
    level=$1
    [ "$level" -le "$worst" ] || worst=$level
}
package() {
    file=$1
    rpm -qp --qf '%{NAME}.%{ARCH}' "$file" 2>/dev/null
}
# What a package holds: content hash of each file; mode, owner, link target of
# each entry.
inside() {
    file=$1 dir=$2
    mkdir "$dir"
    rpm2cpio "$file" | (cd "$dir" && cpio -idm --quiet) || return 1
    (cd "$dir" && find . -type f -exec sha256sum {} + | sort -k 2) > "$dir.sums"
    rpm -qp --qf '[%{FILEMODES:perms} %{FILEUSERNAME}:%{FILEGROUPNAME} %{FILENAMES} %{FILELINKTOS}\n]' "$file" |
        sort -k 3 > "$dir.meta"
}

n=0
for copy in "$@"; do
    n=$((n + 1))
    label=$(basename "$copy")
    if ! name=$(package "$copy"); then
        echo "$label: not an RPM"
        result 3
        continue
    fi
    ours=""
    for candidate in "$rebuilt"/*.rpm; do
        if [ "$(package "$candidate")" = "$name" ]; then
            ours=$candidate
            break
        fi
    done
    if [ -z "$ours" ]; then
        echo "$label: DIFFERENT: the rebuild made no $name"
        result 2
    elif cmp -s "$copy" "$ours"; then
        echo "$label: VERIFIED: same file as the rebuild, byte for byte"
    elif ! inside "$copy" "$tmp/$n.copy" || ! inside "$ours" "$tmp/$n.ours"; then
        echo "$label: can't unpack it or the rebuild's $name"
        result 3
    elif cmp -s "$tmp/$n.copy.sums" "$tmp/$n.ours.sums" && cmp -s "$tmp/$n.copy.meta" "$tmp/$n.ours.meta"; then
        echo "$label: SAME FILES: every file, mode, owner and link inside matches;" \
             "packaging differs (build time, file dates, host or signature)"
        result 1
    else
        echo "$label: DIFFERENT: differing (< $label, > rebuild):"
        cat "$tmp/$n.copy.sums" "$tmp/$n.copy.meta" > "$tmp/$n.copy.all"
        cat "$tmp/$n.ours.sums" "$tmp/$n.ours.meta" > "$tmp/$n.ours.all"
        diff "$tmp/$n.copy.all" "$tmp/$n.ours.all" | grep '^[<>]' | head -n 50 || true
        result 2
    fi
done
exit "$worst"
