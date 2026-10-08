#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Checks the built RPMs (RPMS/*.rpm) in the Sailfish OS Platform SDK:
#   - the package dependencies of SPEC-v2 XP-1: every package requires
#     netvfs of the same build (XC-1a), libnetvfs requires QtNetwork
#     (discovery, XD-1), only netvfs-backup depends on Buteo (XP-4), no
#     package requires the bridge (XP-5) and only its accounts helper is
#     setgid privileged (XB-2a);
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

main_rpm=$(rpm_of netvfs) || { echo "no netvfs RPM"; exit 1; }
main_dependency="netvfs = $(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$main_rpm")"

for r in $rpms; do
    name=$(rpm -qp --qf '%{NAME}' "$r")
    requires=$(rpm -qp --requires "$r")
    echo "== $name"
    echo "$requires" | sed 's/^/  requires: /'
    rpm -qp --recommends "$r" | sed 's/^/  recommends: /'
    rpm -qp --obsoletes "$r" | sed 's/^/  obsoletes: /'
    # XC-1a
    if [ "$name" != netvfs ] && ! echo "$requires" | grep -qxF "$main_dependency"; then
        fail "$name does not require $main_dependency"
    fi
    # XP-4: Buteo only for the backup package.
    if [ "$name" != netvfs-backup ] && echo "$requires" | grep -qi buteo; then
        fail "$name depends on Buteo"
    fi
    # XP-5: the setgid helper only where it is asked for.
    if echo "$requires" | grep -q '^netvfs-bridge'; then
        fail "$name requires netvfs-bridge"
    fi
done

# SPEC-v2 XB-2a: the accounts helper reads the accounts database as group
# privileged; the bridge itself runs without it.
if bridge_rpm=$(rpm_of netvfs-bridge); then
    modes=$(rpm -qp --qf '[%{FILEMODES:perms} %{FILEUSERNAME}:%{FILEGROUPNAME} %{FILENAMES}\n]' "$bridge_rpm")
    helper_mode=$(echo "$modes" | grep ' /usr/libexec/netvfs/netvfs-accounts$' || true)
    if [ "${helper_mode%% *}" != "-rwxr-sr-x" ] || ! echo "$helper_mode" | grep -q ' root:privileged '; then
        fail "netvfs-accounts is not setgid privileged: $helper_mode"
    fi
    bridge_mode=$(echo "$modes" | grep ' /usr/libexec/netvfs/netvfs-bridge$' || true)
    if [ "${bridge_mode%% *}" != "-rwxr-xr-x" ]; then
        fail "netvfs-bridge is set-id: $bridge_mode"
    fi
fi

# SPEC-v2 XD-1: libnetvfs links QtNetwork, so netvfs requires it.
if ! rpm -qp --requires "$main_rpm" | grep -q '^libQt5Network\.so\.5'; then
    fail "netvfs does not require libQt5Network.so.5"
fi

# XP-3 on the packaged plugin, and on its debug file (full symbol table).
extract() {
    package_file=$1
    destination=$2
    mkdir -p "$destination"
    (cd "$destination" && rpm2cpio "$OLDPWD/$package_file" | cpio -idm --quiet)
}
extract "$main_rpm" "$work/main"
smb_files=$(find "$work/main" -name 'libnetvfs-smb.so')
for debuginfo in $(ls RPMS/*.rpm | grep -e '-debuginfo-'); do
    extract "$debuginfo" "$work/debuginfo"
done
smb_files="$smb_files $(find "$work/main" "$work/debuginfo" -name 'libnetvfs-smb.so*.debug' 2>/dev/null || true)"
# shellcheck disable=SC2086 # one word per file
sh tools/ci/check-noshareenum.sh $smb_files || fail "libnetvfs-smb.so contains share enumeration code"
# The positive control: the helper links libsmb2 with DCE/RPC (XM-7).
shares_helper=$(find "$work/main" -name netvfs-smb-shares)
if [ -z "$shares_helper" ]; then
    fail "netvfs contains no netvfs-smb-shares"
elif sh tools/ci/check-noshareenum.sh "$shares_helper" >/dev/null; then
    fail "check-noshareenum.sh finds no share enumeration code in netvfs-smb-shares"
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
