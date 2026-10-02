#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# SMB interop suite (SPEC-smb section 7, SPEC 12.2, SPEC-v2 XT-1/XT-2):
# containerised Samba servers, the QtTest driver tst_interop_smb, one
# netvfs-cli round trip and the backend conformance suite (two targets: a
# share, and server mode).
# Usage: run.sh <build dir> [test functions...]   (the latter are passed to the
# driver; the CLI round trip and the conformance suite then do not run)
#
# Environment:
#   NETVFS_SMB_CURRENT_BASE  base image for the "current Samba" server (M-T10),
#                            default mirror.gcr.io/library/ubuntu:26.04
#   NETVFS_SMB_CONFORMANCE_ONLY  1: run only the conformance suite
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
# XT-1: "conf" is a strict server of its own for the conformance suite, which
# ends its connections; its backup share is a folder of this host (hostPath).
mkdir -p "$work/conf-data"
chmod 777 "$work/conf-data"
samba strict "$image" strict --tmpfs /srv/smb/small:size=16m
samba default "$image" default
samba encoff "$image" encoff
samba smb2only "$image" smb2only
samba aes256 "$image" aes256
samba gmac "$image" gmac
samba guest "$image" guest
samba conf "$image" strict -v "$work/conf-data:/srv/smb/backup"
samba current "$current_image" strict
for s in strict default encoff smb2only aes256 gmac guest conf current; do
    ready "$s"
done

# M-T12 and the stall tests: proxies on 4450.. in front of the servers.
encoff=$(address encoff)
strict=$(address strict)
conf=$(address conf)
docker run -d --name "$prefix-proxy" "$image" proxy \
    "4450:pass:0:$encoff" "4451:flip:5:$encoff" "4452:flip:5:$strict" \
    "4453:stall:5:$strict" "4454:stall:2:$strict" "4455:drop:5:$strict" "4456:drop:2:$strict" \
    "4457:dialect:1:$strict" "4458:stall:5:$conf" >/dev/null
i=0
until docker logs "$prefix-proxy" 2>&1 | grep -q "proxies ready"; do
    i=$((i + 1))
    [ $i -lt 40 ] || { docker logs "$prefix-proxy" >&2; exit 1; }
    sleep 0.25
done
proxy=$(address proxy)

echo "Samba: $(docker exec "$prefix-strict" smbd --version), current: $(docker exec "$prefix-current" smbd --version)"

# Sanitizer builds (M-T19, gate G-SMB item 3): every UBSan report is fatal,
# including in the vendored libsmb2. No effect on other builds.
export UBSAN_OPTIONS="${UBSAN_OPTIONS:+$UBSAN_OPTIONS:}print_stacktrace=1:halt_on_error=1"
export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
# XM-7: the build tree's share enumeration helper.
export NETVFS_SMB_SHARES_HELPER="$build/libexec/netvfs/netvfs-smb-shares"
export NETVFS_SMB_PREFIX="$prefix"
export NETVFS_SMB_PASSWORD="$password"
# SPEC 12.2, SPEC-v2 XC-CLI: the command-line tool end to end.
cli() {
    NETVFS_SECRET="$password" "$build/bin/netvfs-cli" --provider smb --host "$strict" --user backup \
        --option share=backup "$@"
}

# cli_expect <exit code> <cli arguments>: the CLI must fail with exactly that code.
cli_expect() {
    want=$1
    shift
    expect_code "$want" env NETVFS_SECRET="$password" "$build/bin/netvfs-cli" --provider smb --host "$strict" \
        --user backup --option share=backup "$@"
}

# expect_code <exit code> <command...>: the command must fail with exactly that code.
expect_code() {
    want=$1
    shift
    set +e
    "$@" >/dev/null 2>&1
    got=$?
    set -e
    if [ "$got" -ne "$want" ]; then
        echo "expected exit code $want, got $got: $*" >&2
        return 1
    fi
}

cli_round_trip() {
    cli verify "CLI run" >/dev/null
    cli put "$work/cli.bin" "CLI run/cli.bin"
    cli ls "CLI run" | grep -q " 3000000 cli.bin$"
    cli ls -l "CLI run" | grep -Eq "^-[-rwx?]+ [^ ]+ [^ ]+ 3000000 [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z [-A-Z]+ cli.bin$"
    cli stat --json "CLI run/cli.bin" | grep -q '"size": 3000000'
    cli get "CLI run/cli.bin" "$work/cli.out"
    cmp -s "$work/cli.bin" "$work/cli.out"
    [ "$(docker exec "$prefix-strict" sha256sum "/srv/smb/backup/CLI run/cli.bin" | cut -d' ' -f1)" \
      = "$(sha256sum "$work/cli.bin" | cut -d' ' -f1)" ]
    # cat with a range
    cli cat --offset 1000 --length 500 "CLI run/cli.bin" > "$work/cli.range"
    tail -c +1001 "$work/cli.bin" | head -c 500 | cmp - "$work/cli.range"
    # capabilities, free space
    caps=$(cli caps | sed -n 's/^capabilities: //p')
    case " $caps " in *" WindowsNames "*) ;; *) echo "SMB does not report WindowsNames" >&2; return 1 ;; esac
    cli caps --json | grep -q '"capabilities"'
    cli df "CLI run" | grep -q '^[0-9][0-9]*$'
    # mkdir -p, --exclusive, touch creating an empty file
    cli mkdir -p "CLI run/tree/inner"
    cli mkdir "CLI run/tree"
    cli_expect 20 mkdir --exclusive "CLI run/tree"
    cli touch "CLI run/empty"
    cli stat "CLI run/empty" | grep -Eq "^-[-rwx?]+ .* 0 "
    # mv does not replace unless asked
    cli put "$work/cli.bin" "CLI run/other.bin"
    cli_expect 20 mv "CLI run/other.bin" "CLI run/cli.bin"
    cli mv --replace "CLI run/other.bin" "CLI run/cli.bin"
    cli put "$work/cli.bin" "CLI run/tree/inner/f"
    # cp across two locations (--to-url): a local tree into the share, NoReplace by default.
    mkdir -p "$work/cpsrc/sub"
    cp "$work/cli.bin" "$work/cpsrc/sub/f"
    NETVFS_SECRET="$password" "$build/bin/netvfs-cli" --url "file://$work/cpsrc" cp -r \
        --to-url "smb://backup@$strict/backup/CLI%20run" sub tree2
    cli ls "CLI run/tree2" | grep -q " f$"
    cli get "CLI run/tree2/f" "$work/cli.out"
    cmp -s "$work/cli.bin" "$work/cli.out"
    expect_code 20 env NETVFS_SECRET="$password" "$build/bin/netvfs-cli" --url "file://$work/cpsrc" cp -r \
        --to-url "smb://backup@$strict/backup/CLI%20run" sub tree2
    # and back: the share as the source, read on copyAcross's worker thread (M-13 hand-over)
    mkdir -p "$work/cpdst"
    NETVFS_SECRET="$password" "$build/bin/netvfs-cli" --url "smb://backup@$strict/backup/CLI%20run" cp -r \
        --to-url "file://$work/cpdst" tree2 back
    cmp -s "$work/cli.bin" "$work/cpdst/back/f"
    # rm refuses folders, rmdir only empty ones, rm -r removes the tree
    cli_expect 27 rm "CLI run/tree"
    cli_expect 28 rmdir "CLI run/tree/inner"
    cli rm -r "CLI run/tree"
    cli rm -r "CLI run/tree2"
    cli rm "CLI run/empty"
    # --url and --profile; a password in the URL is refused (exit 17)
    NETVFS_SECRET="$password" "$build/bin/netvfs-cli" --url "smb://backup@$strict/backup/CLI%20run" ls "" | grep -q "cli.bin$"
    cli --profile signed ls "CLI run" | grep -q "cli.bin$"
    expect_code 17 "$build/bin/netvfs-cli" --url "smb://backup:pw@$strict/backup" ls ""
    cli rm "CLI run/cli.bin"
    # shares: the server's shares (server mode, XM-2/XM-7)
    NETVFS_SECRET="$password" "$build/bin/netvfs-cli" --provider smb --host "$strict" --user backup shares \
        > "$work/cli.shares"
    grep -qx backup "$work/cli.shares"
    grep -qx media "$work/cli.shares"
    if grep -qx 'hidden\$' "$work/cli.shares"; then echo "admin share listed" >&2; return 1; fi
}

status=0
if [ "${NETVFS_SMB_CONFORMANCE_ONLY:-0}" != 1 ]; then
    "$build/tests/interop/smb/tst_interop_smb" "$@" || status=1
    [ $# -eq 0 ] || exit $status
    head -c 3000000 /dev/urandom > "$work/cli.bin"
    # A subshell of its own: "set -e" is ignored inside a function that is called as a condition.
    set +e
    (set -e; cli_round_trip)
    cli_status=$?
    set -e
    if [ $cli_status -eq 0 ]; then
        echo "PASS   : netvfs-cli round trip"
    else
        echo "FAIL!  : netvfs-cli round trip"
        status=1
    fi
fi

# SPEC-v2 XT-1: the conformance suite, strict profile, against a share and
# in server mode. The proxy on 4458 stalls every connection after sign-in.
# "restart" ends every client connection of "conf" the way a restarting smbd
# does (keepAlive -> ConnectionLost); a real container restart would change
# the server's address under the following tests.
mkdir -p "$work/conf-data/conformance" "$work/conf-data/conformance-server"
chmod 777 "$work/conf-data/conformance" "$work/conf-data/conformance-server"
cat > "$work/conformance.json" <<JSON
{ "targets": [
  { "name": "smb-share", "provider": "smb", "host": "$conf", "user": "backup",
    "options": { "share": "backup", "security_profile": "strict" },
    "secretEnv": "NETVFS_CONFORMANCE_SECRET",
    "baseDir": "conformance", "hostPath": "$work/conf-data/conformance",
    "stallProxy": { "host": "$proxy", "port": 4458 },
    "restart": "docker exec $prefix-conf pkill -f 'smbd: client'" },
  { "name": "smb-server", "provider": "smb", "host": "$conf", "user": "backup",
    "options": { "shares": "backup", "security_profile": "strict" },
    "secretEnv": "NETVFS_CONFORMANCE_SECRET",
    "baseDir": "/backup/conformance-server", "hostPath": "$work/conf-data/conformance-server",
    "stallProxy": { "host": "$proxy", "port": 4458 },
    "restart": "docker exec $prefix-conf pkill -f 'smbd: client'" }
] }
JSON
# Files the suite creates under hostPath (as root) must be writable by the
# share's user inside the container (resume of the > 4 GiB file).
(umask 000 && NETVFS_CONFORMANCE_SECRET="$password" NETVFS_CONFORMANCE_CONFIG="$work/conformance.json" \
    "$build/tests/conformance/tst_conformance") || status=1
exit $status
