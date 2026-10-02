#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# SFTP interop suite (SPEC-sftp 8, SPEC 12.2, SPEC-v2 XT-1, XT-2). Builds
# the OpenSSH and ProFTPD server images, starts one container per server
# version, runs the QtTest driver tst_interop_sftp, netvfs-cli and the
# backend conformance suite (tests/conformance) against them, and removes
# the containers again, also when a step fails or the run is interrupted.
#
# Usage: run.sh <build dir> [tst_interop_sftp arguments]
# With driver arguments (for example a list of test functions) only the
# driver runs, not the CLI check and not the conformance suite.
# NETVFS_SFTP_CONFORMANCE=0 skips the conformance suite; NETVFS_SFTP_KEEP=1
# leaves the containers running for inspection.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
build=$(cd "$1" && pwd)
shift
work="$build/interop-sftp"
prefix="netvfs-sftp-it-$$"
openssh_tag=V_10_3_P1
openssh_src="$work/openssh-portable-$openssh_tag"
containers=""
mkdir -p "$work"

cleanup() {
    if [ "${NETVFS_SFTP_KEEP:-0}" = 1 ]; then
        log "keeping containers:$containers"
        return
    fi
    for container in $containers; do
        docker rm -f "$container" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

log() {
    echo "-- sftp interop: $*"
}

build_images() {
    if [ ! -d "$openssh_src" ]; then
        log "fetching OpenSSH $openssh_tag"
        rm -rf "$openssh_src.tmp"
        git -c advice.detachedHead=false clone -q --depth 1 --branch "$openssh_tag" https://github.com/openssh/openssh-portable "$openssh_src.tmp"
        mv "$openssh_src.tmp" "$openssh_src"
    fi
    context="$work/context-source"
    rm -rf "$context"
    mkdir -p "$context"
    cp "$here"/docker/* "$context"/
    cp -R "$openssh_src" "$context/openssh-portable"
    printf 'openssh-portable/.git\n' > "$context/.dockerignore"
    log "building server images"
    docker build -q -f "$context/Dockerfile.source" -t netvfs-sftp-openssh103:test "$context" >/dev/null
    docker build -q -f "$here/docker/Dockerfile.distro" -t netvfs-sftp-openssh96:test "$here/docker" >/dev/null
    docker build -q -f "$here/docker/Dockerfile.distro" --build-arg BASE=mirror.gcr.io/library/ubuntu:22.04 \
        -t netvfs-sftp-openssh89:test "$here/docker" >/dev/null
    docker build -q -f "$here/docker/Dockerfile.proftpd" -t netvfs-sftp-proftpd:test "$here/docker" >/dev/null
}

instance_port() {
    name=$1
    case "$name" in
    default) echo 2201 ;;
    hardened) echo 2202 ;;
    kbdint) echo 2203 ;;
    nosftp) echo 2204 ;;
    noext) echo 2205 ;;
    legacy) echo 2206 ;;
    hold) echo 2207 ;;
    otp) echo 2208 ;;
    stall) echo 2209 ;;
    sftp) echo 2222 ;;
    sftpstall) echo 2223 ;;
    *) echo "unknown instance $name" >&2; return 1 ;;
    esac
}

# start <key> <image> "<instances>" [docker run options...]
start() {
    key=$1
    image=$2
    instances=$3
    shift 3
    container="$prefix-$key"
    publish=""
    for instance in $instances; do
        publish="$publish -p 127.0.0.1::$(instance_port "$instance")"
    done
    # shellcheck disable=SC2086 # $publish is a list of options
    docker run -d --name "$container" -e TEST_PASSWORD="$password" -e TEST_OTP="$otp" -e INSTANCES="$instances" \
        $publish "$@" "$image" >/dev/null
    containers="$containers $container"
}

wait_ready() {
    server=$1
    container="$prefix-$server"
    tries=0
    until docker exec "$container" test -f /run/netvfs-ready 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -gt 120 ] || [ "$(docker inspect -f '{{.State.Running}}' "$container")" != true ]; then
            log "server $server did not become ready"
            docker logs "$container" >&2 || true
            return 1
        fi
        sleep 0.5
    done
}

# JSON object {"<instance>": <host port>, ...} for one container.
ports_json() {
    server=$1
    instances=$2
    container="$prefix-$server"
    separator=""
    printf '{'
    for instance in $instances; do
        port=$(docker port "$container" "$(instance_port "$instance")/tcp" | head -n 1 | sed 's/.*://')
        printf '%s "%s": %s' "$separator" "$instance" "$port"
        separator=","
    done
    printf ' }'
}

server_json() {
    server=$1
    instances=$2
    printf '    "%s": { "container": "%s", "ports": %s }' "$server" "$prefix-$server" "$(ports_json "$server" "$instances")"
}

cli_check() {
    cli="$build/bin/netvfs-cli"
    container="$prefix-o103"
    port=$(docker port "$container" 2201/tcp | head -n 1 | sed 's/.*://')
    set -- --provider sftp --host 127.0.0.1 --port "$port" --user alice
    log "netvfs-cli end to end"
    identity=$("$cli" "$@" identify)
    fingerprint=$(echo "$identity" | sed -n 1p)
    pin=$(echo "$identity" | sed -n 2p)
    # S-6: the fingerprint is the one ssh-keygen -lf prints on the server.
    if ! docker exec "$container" sh -c 'for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done' \
            | cut -d ' ' -f 2 | grep -qx -- "$fingerprint"; then
        log "CLI fingerprint $fingerprint is not one of the server's host keys"
        return 1
    fi
    set -- "$@" --option "host_key=$pin"
    head -c 3000000 /dev/urandom > "$work/cli.bin"
    rm -f "$work/cli.out"
    export NETVFS_SECRET="$password"
    "$cli" "$@" verify "cli check"
    "$cli" "$@" put "$work/cli.bin" "cli check/cli.bin"
    "$cli" "$@" ls "cli check" | grep -q -- "- 3000000 cli.bin\$"
    "$cli" "$@" stat "cli check/cli.bin" | grep -q -- "^- 3000000 "
    "$cli" "$@" get "cli check/cli.bin" "$work/cli.out"
    cmp "$work/cli.bin" "$work/cli.out"
    test "$(docker exec "$container" sha256sum "/home/alice/cli check/cli.bin" | cut -d ' ' -f 1)" \
        = "$(sha256sum "$work/cli.bin" | cut -d ' ' -f 1)"
    "$cli" "$@" df "cli check" | grep -q '^[0-9][0-9]*$'
    "$cli" "$@" mv "cli check/cli.bin" "cli check/moved.bin"
    "$cli" "$@" rm "cli check/moved.bin"
    if "$cli" "$@" stat "cli check/moved.bin" 2>/dev/null; then
        log "removed file still present"
        return 1
    fi
    # A wrong pin is refused before sign-in (exit code 10 + ServerIdentityChanged).
    set +e
    "$cli" --provider sftp --host 127.0.0.1 --port "$port" --user alice \
        --option "host_key=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" \
        ls "cli check" 2>/dev/null
    code=$?
    set -e
    unset NETVFS_SECRET
    if [ "$code" -ne 15 ]; then
        log "wrong pin gave exit code $code"
        return 1
    fi
    log "netvfs-cli ok"
}

# SPEC-v2 XT-1: the conformance suite against OpenSSH 10.3p1 and ProFTPD.
# Each target works in a folder bind-mounted from here (hostPath), so that
# the suite creates its large fixtures directly; the files it creates are
# world-writable (umask 000) because the server's user changes them.
conformance() {
    conformance_config="$work/conformance.json"
    o103_port=$(docker port "$prefix-o103" 2201/tcp | head -n 1 | sed 's/.*://')
    o103_stall=$(docker port "$prefix-o103" 2209/tcp | head -n 1 | sed 's/.*://')
    pro_port=$(docker port "$prefix-pro" 2222/tcp | head -n 1 | sed 's/.*://')
    pro_stall=$(docker port "$prefix-pro" 2223/tcp | head -n 1 | sed 's/.*://')
    cat > "$conformance_config" <<JSON
{ "targets": [
  { "name": "sftp-openssh103", "provider": "sftp", "host": "127.0.0.1", "port": $o103_port,
    "user": "conf", "secretEnv": "NETVFS_CONFORMANCE_SECRET", "trustOnFirstUse": true,
    "options": { "allow_shell": "true" },
    "baseDir": "/srv/conformance", "hostPath": "$work/conformance-o103",
    "stallProxy": { "port": $o103_stall,
                    "engage": "docker exec $prefix-o103 touch /tmp/stall",
                    "release": "docker exec $prefix-o103 rm -f /tmp/stall" },
    "restart": "docker exec $prefix-o103 /setup/restart-instance.sh default conf" },
  { "name": "sftp-proftpd", "provider": "sftp", "host": "127.0.0.1", "port": $pro_port,
    "user": "conf", "secretEnv": "NETVFS_CONFORMANCE_SECRET", "trustOnFirstUse": true,
    "options": { "allow_shell": "true" },
    "baseDir": "/srv/conformance", "hostPath": "$work/conformance-pro",
    "stallProxy": { "port": $pro_stall,
                    "engage": "docker exec $prefix-pro touch /tmp/stall",
                    "release": "docker exec $prefix-pro rm -f /tmp/stall" },
    "restart": "docker exec $prefix-pro /setup/restart-instance.sh - conf",
    "skip": {
      "symlinks": "ProFTPD mod_sftp answers READLINK with a relative target made absolute (XC-12 verbatim impossible)",
      "symlinkDangling": "ProFTPD mod_sftp answers READLINK with a relative target made absolute (XC-12 verbatim impossible)"
    } }
] }
JSON
    log "running tst_conformance"
    (
        umask 000
        NETVFS_CONFORMANCE_SECRET="$password" NETVFS_CONFORMANCE_CONFIG="$conformance_config" \
            "$build/tests/conformance/tst_conformance"
    )
}

build_images

password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
otp=$(od -An -N4 -tu4 /dev/urandom | tr -d ' \n' | cut -c 1-6)
for folder in conformance-o103 conformance-pro; do
    rm -rf "${work:?}/$folder"
    mkdir -p "$work/$folder"
    chmod 0777 "$work/$folder"
done
o103="default hardened nosftp noext stall"
o96="default kbdint noext legacy otp"
o89="default hold"
pro="sftp sftpstall"
start o103 netvfs-sftp-openssh103:test "$o103" --tmpfs /srv/small:size=8m \
    -v "$work/conformance-o103:/srv/conformance"
start o96 netvfs-sftp-openssh96:test "$o96"
start o89 netvfs-sftp-openssh89:test "$o89"
start pro netvfs-sftp-proftpd:test "$pro" -v "$work/conformance-pro:/srv/conformance"
for key in o103 o96 o89 pro; do
    wait_ready "$key"
done

config="$work/config.json"
{
    printf '{\n  "password": "%s",\n  "otp": "%s",\n  "servers": {\n' "$password" "$otp"
    server_json o103 "$o103"
    printf ',\n'
    server_json o96 "$o96"
    printf ',\n'
    server_json o89 "$o89"
    printf ',\n'
    server_json pro "$pro"
    printf '\n  }\n}\n'
} > "$config"

export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
export NETVFS_SFTP_INTEROP_CONFIG="$config"
status=0
log "running tst_interop_sftp"
if ! "$build/tests/interop/sftp/tst_interop_sftp" "$@"; then
    status=1
fi
if [ $# -eq 0 ] && ! cli_check; then
    status=1
fi
if [ $# -eq 0 ] && [ "${NETVFS_SFTP_CONFORMANCE:-1}" != 0 ] && ! conformance; then
    status=1
fi
exit $status
