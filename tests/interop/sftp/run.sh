#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# SFTP interop suite (SPEC-sftp 8, SPEC 12.2). Builds the OpenSSH server
# images, starts one container per server version, runs the QtTest driver
# tst_interop_sftp and netvfs-cli against them, and removes the containers
# again, also when a step fails or the run is interrupted.
#
# Usage: run.sh <build dir> [tst_interop_sftp arguments]
# With driver arguments (for example a list of test functions) only the
# driver runs, not the CLI check. With NETVFS_INTEROP_CLI_ONLY=1 only the
# CLI check runs.
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
    docker run -d --name "$container" -e TEST_PASSWORD="$password" -e INSTANCES="$instances" \
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

# expect_code <exit code> <command...>: the command must fail with exactly that code.
expect_code() {
    want=$1
    shift
    set +e
    "$@" >/dev/null 2>&1
    got=$?
    set -e
    if [ "$got" -ne "$want" ]; then
        log "expected exit code $want, got $got: $*"
        return 1
    fi
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
    # XC-CLI: the full entry. ls -l: mode owner group size mtime(UTC) flags name.
    "$cli" "$@" ls -l "cli check" | grep -Eq -- "^-rw[-rwx]+ [^ ]+ [^ ]+ 3000000 [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z [-A-Z]+ cli.bin\$"
    "$cli" "$@" stat "cli check/cli.bin" | grep -Eq -- "^-rw[-rwx]+ .* 3000000 .* cli check/cli.bin\$"
    "$cli" "$@" stat --json "cli check/cli.bin" | grep -q -- '"size": 3000000'
    "$cli" "$@" ls --json "cli check" | grep -q -- '"name": "cli.bin"'
    "$cli" "$@" caps | grep -q -- "^capabilities: "
    "$cli" "$@" get "cli check/cli.bin" "$work/cli.out"
    cmp "$work/cli.bin" "$work/cli.out"
    test "$(docker exec "$container" sha256sum "/home/alice/cli check/cli.bin" | cut -d ' ' -f 1)" \
        = "$(sha256sum "$work/cli.bin" | cut -d ' ' -f 1)"
    # cat with a range (DownloadOptions)
    "$cli" "$@" cat --offset 1000 --length 500 "cli check/cli.bin" > "$work/cli.range"
    tail -c +1001 "$work/cli.bin" | head -c 500 | cmp - "$work/cli.range"
    "$cli" "$@" cat "cli check/cli.bin" | cmp - "$work/cli.bin"
    # mkdir without -p needs the parent; --exclusive refuses an existing entry (exit 10 + AlreadyExists)
    expect_code 19 "$cli" "$@" mkdir "cli check/no/parent"
    "$cli" "$@" mkdir -p "cli check/tree/inner"
    "$cli" "$@" mkdir "cli check/tree"
    expect_code 20 "$cli" "$@" mkdir --exclusive "cli check/tree"
    # What the server can do decides which attribute and link checks apply.
    caps=$("$cli" "$@" caps | sed -n 's/^capabilities: //p')
    has_cap() {
        case " $caps " in *" $1 "*) return 0 ;; esac
        return 1
    }
    # touch creates an empty file; chmod and touch --mtime need the capabilities
    "$cli" "$@" touch "cli check/empty"
    "$cli" "$@" stat "cli check/empty" | grep -Eq -- "^-[-rwx?]+ .* 0 "
    if has_cap PosixModes; then
        "$cli" "$@" chmod 640 "cli check/cli.bin"
        "$cli" "$@" stat "cli check/cli.bin" | grep -q -- "^-rw-r----- "
    fi
    if has_cap SetModified; then
        "$cli" "$@" touch --mtime 2020-02-03T04:05:06Z "cli check/cli.bin"
        "$cli" "$@" stat "cli check/cli.bin" | grep -q -- " 2020-02-03T04:05:06Z "
    fi
    if has_cap Symlinks; then
        "$cli" "$@" ln -s cli.bin "cli check/link"
        test "$("$cli" "$@" readlink "cli check/link")" = cli.bin
        "$cli" "$@" lstat "cli check/link" | grep -q -- "^l"
        "$cli" "$@" stat "cli check/link" | grep -q -- "^-"
        "$cli" "$@" rm "cli check/link"
    fi
    # mv refuses to replace unless asked (exit 10 + AlreadyExists)
    "$cli" "$@" put "$work/cli.bin" "cli check/other.bin"
    expect_code 20 "$cli" "$@" mv "cli check/other.bin" "cli check/cli.bin"
    "$cli" "$@" mv --replace "cli check/other.bin" "cli check/cli.bin"
    "$cli" "$@" stat "cli check/other.bin" 2>/dev/null && { log "mv left the source"; return 1; }
    # cp: server side or across, files and trees; NoReplace by default
    "$cli" "$@" cp "cli check/cli.bin" "cli check/copy.bin"
    "$cli" "$@" get "cli check/copy.bin" "$work/cli.out"
    cmp "$work/cli.bin" "$work/cli.out"
    expect_code 20 "$cli" "$@" cp "cli check/cli.bin" "cli check/copy.bin"
    "$cli" "$@" cp -r "cli check/tree" "cli check/tree2"
    "$cli" "$@" ls "cli check/tree2" | grep -q -- "inner\$"
    # sum, when the server computes checksums
    if has_cap Checksums; then
        "$cli" "$@" sum --algo sha256 "cli check/cli.bin" | grep -q -- "^$(sha256sum "$work/cli.bin" | cut -d ' ' -f 1)  "
    fi
    # rm without -r refuses folders, rmdir only empty ones, rm -r removes a tree
    expect_code 27 "$cli" "$@" rm "cli check/tree"
    "$cli" "$@" put "$work/cli.bin" "cli check/tree/inner/f"
    expect_code 28 "$cli" "$@" rmdir "cli check/tree/inner"
    "$cli" "$@" rm -r "cli check/tree"
    "$cli" "$@" rm -r "cli check/tree2"
    "$cli" "$@" stat "cli check/tree" 2>/dev/null && { log "rm -r left the tree"; return 1; }
    "$cli" "$@" rm "cli check/copy.bin"
    "$cli" "$@" rm "cli check/empty"
    # --url instead of --provider/--host/--port/--user; a password in the URL is refused (exit 17)
    "$cli" --url "sftp://alice@127.0.0.1:$port" --option "host_key=$pin" ls "cli check" | grep -q -- "cli.bin\$"
    "$cli" --host-key "$pin" --url "sftp://alice@127.0.0.1:$port/home/alice/cli%20check" ls "" | grep -q -- "cli.bin\$"
    expect_code 17 "$cli" --url "sftp://alice:pw@127.0.0.1:$port/" ls ""
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

build_images

password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
o103="default hardened nosftp noext"
o96="default kbdint noext legacy"
o89="default hold"
start o103 netvfs-sftp-openssh103:test "$o103" --tmpfs /srv/small:size=8m
start o96 netvfs-sftp-openssh96:test "$o96"
start o89 netvfs-sftp-openssh89:test "$o89"
for key in o103 o96 o89; do
    wait_ready "$key"
done

config="$work/config.json"
{
    printf '{\n  "password": "%s",\n  "servers": {\n' "$password"
    server_json o103 "$o103"
    printf ',\n'
    server_json o96 "$o96"
    printf ',\n'
    server_json o89 "$o89"
    printf '\n  }\n}\n'
} > "$config"

export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
export NETVFS_SFTP_INTEROP_CONFIG="$config"
status=0
if [ -z "${NETVFS_INTEROP_CLI_ONLY:-}" ]; then
    log "running tst_interop_sftp"
    if ! "$build/tests/interop/sftp/tst_interop_sftp" "$@"; then
        status=1
    fi
fi
if [ $# -eq 0 ]; then
    # A subshell of its own: "set -e" is ignored inside a function that is
    # called as a condition, and a failed check must stop the CLI run.
    set +e
    (set -e; cli_check)
    [ $? -eq 0 ] || status=1
    set -e
fi
exit $status
