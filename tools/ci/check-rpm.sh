#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Checks the built RPMs (RPMS/*.rpm) in the Sailfish OS Platform SDK:
#   - the package dependencies of SPEC-v2 XP-1: every package requires
#     netvfs of the same build (XC-1a), libnetvfs requires QtNetwork
#     (discovery, XD-1), only netvfs-backup depends on Buteo (XP-4), no
#     package requires the bridge (XP-5) and only its accounts helper is
#     setgid privileged (XB-2a);
#   - the Rust binaries of the bridge package link only the libraries they
#     should (the setgid helper libc, libgcc_s and SQLite; netvfs-bridge no
#     Qt, which it reaches only through its C ABI), need no newer glibc than
#     the target's and are hardened (check-linked-libs.sh);
#   - that C ABI, libnetvfs-bridge-ffi.so, exports one symbol, is hardened and
#     sits where netvfs-bridge loads it from, next to the backend folder of
#     libnetvfs's BackendLoader (check-ffi-lib.sh; doc/RUST.md);
#   - libnetvfs-rs.so, the Rust backends, exports one symbol, links only the
#     C runtime, needs no newer glibc than the target's, is hardened and sits
#     where the plugins that load it look for it (check-rs-lib.sh), the SMB
#     plugin among them;
#   - no file of the main package links libssh or libcrypto (SSH is in
#     libnetvfs-rs.so);
#   - no packaged file or folder is writable by group or others (%license
#     packages LICENSE with the mode it has in the build tree);
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
    writable=$(rpm -qp --qf '[%{FILEMODES:perms} %{FILENAMES}\n]' "$r" | grep -E '^[^l].{4}w|^[^l].{7}w' || true)
    if [ -n "$writable" ]; then
        fail "$name has files writable by group or others: $writable"
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

extract() {
    package_file=$1
    destination=$2
    mkdir -p "$destination"
    (cd "$destination" && rpm2cpio "$OLDPWD/$package_file" | cpio -idm --quiet)
}
extract "$main_rpm" "$work/main"

# SPEC-v2 XB-2a: the setgid helper links only libc, libgcc_s and the
# system SQLite (no Qt, GLib or libaccounts); netvfs-bridge only libc,
# libgcc_s and libm (Qt and the backends come with its C ABI, by dlopen).
# Both need no newer glibc than the target's and are hardened PIEs
# (check-linked-libs.sh).
target_glibc=$(sb2 -t "$TARGET" rpm -q --qf '%{VERSION}' glibc)
if bridge_rpm=$(rpm_of netvfs-bridge); then
    extract "$bridge_rpm" "$work/bridge"
    sh tools/ci/check-linked-libs.sh "$work/bridge/usr/libexec/netvfs/netvfs-accounts" \
        "libc.so.6 libgcc_s.so.1 libsqlite3.so.0" "$target_glibc" || fail "netvfs-accounts: see above"
    sh tools/ci/check-linked-libs.sh "$work/bridge/usr/libexec/netvfs/netvfs-bridge" \
        "libc.so.6 libgcc_s.so.1 libm.so.6" "$target_glibc" || fail "netvfs-bridge: see above"
    # The C ABI where the package puts it: the path compiled into the
    # bridge, and next to the backend folder compiled into libnetvfs
    # (BackendLoader::searchPaths, a UTF-16 string literal).
    ffi_path=$(rpm -qpl "$bridge_rpm" | grep '/libnetvfs-bridge-ffi\.so$' || true)
    if [ -z "$ffi_path" ]; then
        fail "netvfs-bridge contains no libnetvfs-bridge-ffi.so"
    else
        sh tools/ci/check-ffi-lib.sh "$work/bridge$ffi_path" "$ffi_path" \
            "$work/bridge/usr/libexec/netvfs/netvfs-bridge" "$target_glibc" || fail "libnetvfs-bridge-ffi.so: see above"
        backend_dir=$(dirname "$ffi_path")/backends
        libnetvfs=$(find "$work/main" -name 'libnetvfs.so.*' -type f | head -n 1)
        if [ -z "$libnetvfs" ] || ! strings -a -el "$libnetvfs" | grep -qxF "$backend_dir"; then
            fail "libnetvfs does not load its backends from $backend_dir"
        fi
        if ! rpm -qpl "$main_rpm" | grep -q "^$backend_dir/libnetvfs-[a-z]*\.so$"; then
            fail "netvfs installs no backends in $backend_dir"
        fi
    fi
fi

# The Rust backends: the library in the main package, and every plugin of it
# (a backend that looks up nvr_get) looks for it where the package puts it.
rs_path=$(rpm -qpl "$main_rpm" | grep '/libnetvfs-rs\.so$' || true)
if [ -z "$rs_path" ]; then
    fail "netvfs contains no libnetvfs-rs.so"
else
    rs_plugins=$(grep -laF nvr_get "$work/main$(dirname "$rs_path")"/backends/libnetvfs-*.so || true)
    case "$rs_plugins" in
        *libnetvfs-smb.so*) ;;
        *) fail "libnetvfs-smb.so is not a plugin of libnetvfs-rs.so" ;;
    esac
    # shellcheck disable=SC2086 # one word per file
    sh tools/ci/check-rs-lib.sh "$work/main$rs_path" "$target_glibc" "$rs_path" $rs_plugins \
        || fail "libnetvfs-rs.so: see above"
fi

# SSH comes from libnetvfs-rs.so (russh over ring): no file of the main
# package links libssh or the platform's libcrypto.
for file in $(find "$work/main" -type f); do
    [ "$(head -c 4 "$file" | od -An -c | tr -d ' ')" = '177ELF' ] || continue
    if readelf -d "$file" | grep -E '\(NEEDED\).*\[lib(ssh|crypto)\.so'; then
        fail "${file#"$work/main"} links libssh or libcrypto"
    fi
done

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
