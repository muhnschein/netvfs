#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Checks the built RPMs (RPMS/*.rpm) in the Sailfish OS Platform SDK:
#   - the package dependencies of SPEC-v2 XP-1: every package requires
#     netvfs-core of the same build (XC-1a), libnetvfs requires QtNetwork
#     (discovery, XD-1), only netvfs-backup-* depend on Buteo (XP-4), the
#     bridge requires no backend (XP-5);
#   - libnetvfs-smb.so contains no share enumeration code (XP-3, SPEC 10.2
#     G-SMB item 4; tools/ci/check-noshareenum.sh), and the check finds that
#     code in the share helper when it is built;
#   - all packages install into the SDK target (resolving Requires from the
#     release repositories), every ELF file resolves its libraries and none
#     carries a library search path from the build.
# Env: SDK_IMAGE (container image), TARGET (sb2 target name).
set -eu
: "${SDK_IMAGE:?}" "${TARGET:?}"

if [ "${1:-}" != --in-sdk ]; then
    root=$(cd "$(dirname "$0")/../.." && pwd)
    # The SDK runs as mersdk (uid 100000).
    sudo chown -R 100000:100000 "$root"
    trap 'sudo chown -R "$(id -u):$(id -g)" "$root"' EXIT
    docker run --rm -e TARGET -e SDK_IMAGE -v "$root:/home/mersdk/src" -w /home/mersdk/src "$SDK_IMAGE" \
        sh tools/ci/check-rpm.sh --in-sdk
    exit 0
fi

# In the SDK container, in the source tree.
target_root=/srv/mer/targets/$TARGET
work=$(mktemp -d)
status=0

fail() {
    message=$1
    echo "FAIL: $message"
    status=1
}

rpms=$(ls RPMS/*.rpm | grep -v -e debuginfo -e debugsource)
rpm_of() {
    package=$1
    for candidate in $rpms; do
        if [ "$(rpm -qp --qf '%{NAME}' "$candidate")" = "$package" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

core_rpm=$(rpm_of netvfs-core) || { echo "no netvfs-core RPM"; exit 1; }
core_dependency="netvfs-core = $(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$core_rpm")"

for r in $rpms; do
    name=$(rpm -qp --qf '%{NAME}' "$r")
    requires=$(rpm -qp --requires "$r")
    echo "== $name"
    echo "$requires" | sed 's/^/  requires: /'
    rpm -qp --recommends "$r" | sed 's/^/  recommends: /'
    rpm -qp --obsoletes "$r" | sed 's/^/  obsoletes: /'
    # XC-1a
    if [ "$name" != netvfs-core ] && ! echo "$requires" | grep -qxF "$core_dependency"; then
        fail "$name does not require $core_dependency"
    fi
    # XP-4: Buteo only for the backup packages.
    case $name in
        netvfs-backup-*) ;;
        *) if echo "$requires" | grep -qi buteo; then fail "$name depends on Buteo"; fi ;;
    esac
    # XP-5
    if [ "$name" = netvfs-bridge ] && echo "$requires" | grep -q 'netvfs-backend'; then
        fail "netvfs-bridge requires a backend"
    fi
done

# SPEC-v2 XD-1: libnetvfs links QtNetwork, so netvfs-core requires it.
if ! rpm -qp --requires "$core_rpm" | grep -q '^libQt5Network\.so\.5'; then
    fail "netvfs-core does not require libQt5Network.so.5"
fi

# XP-3 on the packaged plugin, and on its debug file (full symbol table).
extract() {
    package_file=$1
    destination=$2
    mkdir -p "$destination"
    (cd "$destination" && rpm2cpio "$OLDPWD/$package_file" | cpio -idm --quiet)
}
smb_rpm=$(rpm_of netvfs-backend-smb) || { echo "no netvfs-backend-smb RPM"; exit 1; }
extract "$smb_rpm" "$work/smb"
smb_files=$(find "$work/smb" -name 'libnetvfs-smb.so')
for debuginfo in $(ls RPMS/*.rpm | grep -e '-debuginfo-'); do
    extract "$debuginfo" "$work/debuginfo"
done
smb_files="$smb_files $(find "$work/smb" "$work/debuginfo" -name 'libnetvfs-smb.so*.debug' 2>/dev/null || true)"
# shellcheck disable=SC2086 # one word per file
sh tools/ci/check-noshareenum.sh $smb_files || fail "libnetvfs-smb.so contains share enumeration code"
# The positive control: the helper links libsmb2 with DCE/RPC (XM-7).
if shares_rpm=$(rpm_of netvfs-backend-smb-shares); then
    extract "$shares_rpm" "$work/shares"
    if sh tools/ci/check-noshareenum.sh "$(find "$work/shares" -name netvfs-smb-shares)" >/dev/null; then
        fail "check-noshareenum.sh finds no share enumeration code in netvfs-smb-shares"
    fi
fi

# shellcheck disable=SC2086 # one word per file
sb2 -t "$TARGET" -m sdk-install -R zypper --non-interactive in --allow-unsigned-rpm $rpms
names=$(for r in $rpms; do rpm -qp --qf '%{NAME} ' "$r"; done)
# shellcheck disable=SC2086 # one word per package
for file in $(sb2 -t "$TARGET" rpm -ql $names); do
    installed=$target_root$file
    [ -f "$installed" ] && [ ! -L "$installed" ] || continue
    [ "$(head -c 4 "$installed" | od -An -c | tr -d ' ')" = '177ELF' ] || continue
    if sb2 -t "$TARGET" ldd "$file" | grep 'not found'; then
        fail "unresolved libraries in $file"
    fi
    if readelf -d "$installed" | grep -E 'RPATH|RUNPATH'; then
        fail "$file carries a library search path from the build"
    fi
done
rm -rf "$work"
exit $status
