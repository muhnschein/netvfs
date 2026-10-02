#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# SMB interop suite (SPEC-smb section 7, SPEC 12.2): containerised Samba
# servers, the QtTest driver tst_interop_smb and one netvfs-cli round trip.
# Usage: run.sh <build dir> [test functions...]   (the latter are passed to the driver)
#
# Environment:
#   NETVFS_SMB_CURRENT_BASE  base image for the "current Samba" server (M-T10),
#                            default mirror.gcr.io/library/ubuntu:26.04
set -eu

here=$(cd "$(dirname "$0")" && pwd)
build=$(cd "$1" && pwd)
shift
prefix="netvfs-smb-$$"
image=netvfs-smb-samba:ubuntu24.04
current_image=netvfs-smb-samba:current
current_base=${NETVFS_SMB_CURRENT_BASE:-mirror.gcr.io/library/ubuntu:26.04}
work=$(mktemp -d)
# A fresh password per run; it exists only in this process tree and the containers.
password=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')

cleanup() {
    ids=$(docker ps -aq --filter "name=^${prefix}-")
    [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

docker build -q -t "$image" "$here/server" >/dev/null
docker build -q --build-arg BASE="$current_base" -t "$current_image" "$here/server" >/dev/null

samba() {
    name=$1
    img=$2
    variant=$3
    shift 3
    docker run -d --name "$prefix-$name" -e SMB_PASSWORD="$password" "$@" "$img" samba "$variant" >/dev/null
}

address() {
    server=$1
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$prefix-$server"
}

ready() {
    server=$1
    i=0
    until docker exec "$prefix-$server" smbclient //localhost/backup -A /etc/netvfs-auth -c ls >/dev/null 2>&1; do
        i=$((i + 1))
        if [ $i -ge 60 ]; then
            echo "Samba server $server did not come up:" >&2
            docker logs "$prefix-$server" >&2
            return 1
        fi
        sleep 0.5
    done
}

# M-T16: "small" is a 16 MiB tmpfs on the strict server.
samba strict "$image" strict --tmpfs /srv/smb/small:size=16m
samba default "$image" default
samba encoff "$image" encoff
samba smb2only "$image" smb2only
samba aes256 "$image" aes256
samba gmac "$image" gmac
samba current "$current_image" strict
for s in strict default encoff smb2only aes256 gmac current; do
    ready "$s"
done

# M-T12 and the stall tests: proxies on 4450.. in front of the servers.
encoff=$(address encoff)
strict=$(address strict)
docker run -d --name "$prefix-proxy" "$image" proxy \
    "4450:pass:0:$encoff" "4451:flip:5:$encoff" "4452:flip:5:$strict" \
    "4453:stall:5:$strict" "4454:stall:2:$strict" "4455:drop:5:$strict" "4456:drop:2:$strict" \
    "4457:dialect:1:$strict" >/dev/null
i=0
until docker logs "$prefix-proxy" 2>&1 | grep -q "proxies ready"; do
    i=$((i + 1))
    [ $i -lt 40 ] || { docker logs "$prefix-proxy" >&2; exit 1; }
    sleep 0.25
done

echo "Samba: $(docker exec "$prefix-strict" smbd --version), current: $(docker exec "$prefix-current" smbd --version)"

# Sanitizer builds (M-T19): every UBSan report is fatal except the reviewed
# ones in libsmb2 listed in ubsan-libsmb2.supp. No effect on other builds.
export UBSAN_OPTIONS="${UBSAN_OPTIONS:+$UBSAN_OPTIONS:}print_stacktrace=1:halt_on_error=1:suppressions=$here/ubsan-libsmb2.supp"
export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
export NETVFS_SMB_PREFIX="$prefix"
export NETVFS_SMB_PASSWORD="$password"
status=0
"$build/tests/interop/smb/tst_interop_smb" "$@" || status=1

# SPEC 12.2: the command-line tool end to end.
cli() {
    NETVFS_SECRET="$password" "$build/bin/netvfs-cli" --provider smb --host "$strict" --user backup \
        --option share=backup "$@"
}
head -c 3000000 /dev/urandom > "$work/cli.bin"
if cli verify "CLI run" >/dev/null \
    && cli put "$work/cli.bin" "CLI run/cli.bin" \
    && cli ls "CLI run" | grep -q " 3000000 cli.bin$" \
    && cli get "CLI run/cli.bin" "$work/cli.out" \
    && cmp -s "$work/cli.bin" "$work/cli.out" \
    && [ "$(docker exec "$prefix-strict" sha256sum "/srv/smb/backup/CLI run/cli.bin" | cut -d' ' -f1)" \
         = "$(sha256sum "$work/cli.bin" | cut -d' ' -f1)" ] \
    && cli rm "CLI run/cli.bin"; then
    echo "PASS   : netvfs-cli round trip"
else
    echo "FAIL!  : netvfs-cli round trip"
    status=1
fi
exit $status
