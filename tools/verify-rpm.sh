#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

prog=verify-rpm
repo=${NETVFS_REPO:-https://github.com/muhnschein/netvfs.git}
here=$(cd "$(dirname "$0")/.." && pwd)

usage() {
    sed -n '6,9p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 3
}
fail() {
    echo "$prog: $*" >&2
    exit 3
}

ref=""
while [ $# -gt 0 ]; do
    case "$1" in
        --ref) [ $# -ge 2 ] || usage; ref=$2; shift ;;
        -h | --help) usage ;;
        -*) echo "$prog: unknown option $1" >&2; usage ;;
        *) break ;;
    esac
    shift
done
if [ -z "$ref" ] || [ $# -eq 0 ]; then
    usage
fi
for rpm in "$@"; do
    [ -f "$rpm" ] || fail "no such file: $rpm"
done

command -v docker > /dev/null || fail "needs Docker"
docker info > /dev/null 2>&1 || fail "Docker is not running, or not for this user"
command -v rustup > /dev/null || fail "needs rustup"
[ -e /lib/ld-linux.so.2 ] || fail "needs the i386 C library for the SDK's compiler (Ubuntu: libc6-i386)"
need_gb=6
parent=${NETVFS_WORKDIR:-${XDG_CACHE_HOME:-$HOME/.cache}/netvfs-verify}
mkdir -p "$parent" || fail "can't create $parent"
free_gb=$(df -Pk "$parent" | awk 'NR == 2 { print int($4 / 1048576) }')
[ "${free_gb:-0}" -ge "$need_gb" ] ||
    fail "$parent: ${free_gb:-?} GB free, build needs $need_gb GB; set NETVFS_WORKDIR to a roomier disk"
work=$(mktemp -d "$parent/run.XXXXXX")
cleanup() {
    if [ "${NETVFS_KEEP:-0}" = 1 ]; then
        echo "kept: $work"
    else
        rm -rf "$work" 2> /dev/null || echo "$prog: could not remove all of $work" >&2
    fi
}
trap cleanup EXIT
mkdir -p "$work/cmp/rebuilt"
n=0
for rpm in "$@"; do
    n=$((n + 1))
    mkdir "$work/cmp/$n"
    cp "$rpm" "$work/cmp/$n/"
done

echo ">> fetching $ref from $repo"
src=$work/netvfs
git init -q "$src"
if git -C "$src" fetch -q --depth 1 "$repo" "$ref" 2> /dev/null; then
    git -C "$src" checkout -q --detach FETCH_HEAD
else
    git -C "$src" fetch -q "$repo" '+refs/heads/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*' ||
        fail "can't fetch from $repo"
    git -C "$src" checkout -q --detach "$ref^{commit}" 2> /dev/null || fail "no commit $ref in $repo"
fi
echo ">> building $(git -C "$src" log -1 --format='%h %s')"

unset SOURCE_DATE_EPOCH
SDK_IMAGE=$(sed -n 's/^ *SDK_IMAGE: *//p' "$src/.github/workflows/ci.yml" | head -n 1)
TARGET=$(sed -n 's/^ *TARGET: *//p' "$src/.github/workflows/ci.yml" | head -n 1)
if [ -z "$SDK_IMAGE" ] || [ -z "$TARGET" ]; then
    fail "$ref names no SDK image in .github/workflows/ci.yml"
fi
export SDK_IMAGE TARGET
(cd "$src/rust" && rustup toolchain install > /dev/null) || fail "can't install the commit's Rust toolchain"
"$src/tools/ci/build-rpm.sh" || fail "the build failed"
cp "$src"/RPMS/*.rpm "$work/cmp/rebuilt/"
image=$SDK_IMAGE

echo
cp "$here/tools/compare-rpms.sh" "$work/cmp/"
chmod -R a+rX "$work/cmp"
status=0
docker run --rm --user 0 -v "$work/cmp:/cmp:ro" "$image" \
    sh -c 'sh /cmp/compare-rpms.sh /cmp/rebuilt /cmp/[0-9]*/*.rpm' || status=$?
echo
case "$status" in
    0) echo "VERIFIED: $ref rebuilds to every RPM checked, byte for byte." ;;
    1) echo "SAME FILES: contents match, packaging differs." ;;
    2) echo "DIFFERENT: see above." ;;
    *) echo "$prog: couldn't compare" >&2 ;;
esac
exit "$status"
