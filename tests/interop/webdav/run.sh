#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

here=$(cd "$(dirname "$0")" && pwd)
build=$(cd "$1" && pwd)
image=netvfs-webdav-apache:2.4
reuse=0
[ -z "${NETVFS_INTEROP_WEBDAV_PREFIX:-}" ] || reuse=1
keep=$reuse
[ "${NETVFS_WEBDAV_SERVERS_ONLY:-0}" != 1 ] || keep=1

if [ "$reuse" = 1 ]; then
    prefix=$NETVFS_INTEROP_WEBDAV_PREFIX
    work=${NETVFS_INTEROP_WEBDAV_WORK:?}
    password=${NETVFS_INTEROP_WEBDAV_PASSWORD:?}
else
    prefix="netvfs-webdav-$$"
    work=$(mktemp -d)
    password=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
fi

cleanup() {
    [ "$keep" = 0 ] || return 0
    docker rm -f "$prefix-apache" >/dev/null 2>&1 || true
    docker run --rm -v "$work:/w" "$image" sh -c 'rm -rf /w/dav' >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

port() {
    docker port "$prefix-apache" "$1/tcp" | head -n 1 | sed 's/.*://'
}

if [ "$reuse" = 0 ]; then
    certs=$work/certs
    mkdir -p "$certs" "$work/dav"
    chmod 777 "$work/dav"
    ec="-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
    openssl req -x509 $ec -keyout "$certs/ca.key" -out "$certs/ca.crt" -days 2 -subj "/CN=netvfs interop CA" \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
    openssl req $ec -keyout "$certs/signed.key" -out "$certs/signed.csr" -subj "/CN=localhost" 2>/dev/null
    printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$certs/signed.ext"
    openssl x509 -req -in "$certs/signed.csr" -CA "$certs/ca.crt" -CAkey "$certs/ca.key" -CAcreateserial \
        -days 2 -extfile "$certs/signed.ext" -out "$certs/signed.crt" 2>/dev/null
    openssl req -x509 $ec -keyout "$certs/self.key" -out "$certs/self.crt" -days 2 -subj "/CN=localhost" \
        -addext subjectAltName=DNS:localhost 2>/dev/null
    openssl x509 -in "$certs/ca.crt" -outform der -out "$certs/ca.der"
    openssl x509 -in "$certs/self.crt" -outform der -out "$certs/self.der"
    chmod 644 "$certs"/*

    docker build -q -t "$image" "$here/server" >/dev/null
    docker run -d --name "$prefix-apache" -e TEST_PASSWORD="$password" -v "$certs:/etc/netvfs:ro" \
        -v "$work/dav:/srv/dav" --tmpfs /srv/small:size=1m,uid=1,gid=1 \
        -p 127.0.0.1::443 -p 127.0.0.1::8443 -p 127.0.0.1::9443 "$image" >/dev/null
    i=0
    until curl -sf --cacert "$certs/ca.crt" -u "alice:$password" -X PROPFIND -H 'Depth: 0' \
        "https://localhost:$(port 8443)/dav/" >/dev/null 2>&1; do
        i=$((i + 1))
        if [ $i -ge 60 ]; then
            echo "Apache did not come up:" >&2
            docker logs "$prefix-apache" >&2
            exit 1
        fi
        sleep 0.5
    done
fi

settings() {
    echo "NETVFS_INTEROP_WEBDAV_PREFIX=$prefix"
    echo "NETVFS_INTEROP_WEBDAV_WORK=$work"
    echo "NETVFS_INTEROP_WEBDAV_PASSWORD=$password"
    echo "NETVFS_INTEROP_WEBDAV_SELF=$(port 443)"
    echo "NETVFS_INTEROP_WEBDAV_SIGNED=$(port 8443)"
    echo "NETVFS_INTEROP_WEBDAV_TLS12=$(port 9443)"
}
if [ "${NETVFS_WEBDAV_SERVERS_ONLY:-0}" = 1 ]; then
    settings
    exit 0
fi
for setting in $(settings); do
    export "${setting?}"
done

echo "Apache: $(docker exec "$prefix-apache" httpd -v | head -n 1)"

export UBSAN_OPTIONS="${UBSAN_OPTIONS:+$UBSAN_OPTIONS:}print_stacktrace=1:halt_on_error=1"
export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
export NETVFS_RS_LIB="$build/lib/netvfs/libnetvfs-rs.so"
self=$NETVFS_INTEROP_WEBDAV_SELF
signed=$NETVFS_INTEROP_WEBDAV_SIGNED

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
    cli="$build/bin/netvfs-cli"
    expect_code 14 env NETVFS_SECRET="$password" "$cli" --url "davs://alice@127.0.0.1:$self/dav" ls ""
    pin=$("$cli" --url "davs://alice@127.0.0.1:$self/dav" identify | sed -n 2p)
    case "$pin" in "tls-spki-sha256 "*) ;; *) echo "identify printed no TLS pin: $pin" >&2; return 1 ;; esac
    dav() {
        NETVFS_SECRET="$password" "$cli" --url "davs://alice@127.0.0.1:$self/dav" --host-key "$pin" "$@"
    }
    dav verify "CLI run" >/dev/null
    dav put "$work/cli.bin" "CLI run/cli.bin"
    dav ls "CLI run" | grep -q " 3000000 cli.bin$"
    dav get "CLI run/cli.bin" "$work/cli.out"
    cmp -s "$work/cli.bin" "$work/cli.out"
    cmp -s "$work/cli.bin" "$work/dav/CLI run/cli.bin"
    dav cat --offset 1000 --length 500 "CLI run/cli.bin" > "$work/cli.range"
    tail -c +1001 "$work/cli.bin" | head -c 500 | cmp - "$work/cli.range"
    dav mkdir -p "CLI run/tree/inner"
    dav put "$work/cli.bin" "CLI run/other.bin"
    expect_code 20 dav mv "CLI run/other.bin" "CLI run/cli.bin"
    dav mv --replace "CLI run/other.bin" "CLI run/cli.bin"
    expect_code 28 dav rmdir "CLI run/tree"
    dav rm -r "CLI run"
    SSL_CERT_FILE="$work/certs/ca.crt" NETVFS_SECRET="$password" "$cli" --url "https://alice@localhost:$signed/dav" \
        ls "" >/dev/null
    [ "$(SSL_CERT_FILE="$work/certs/ca.crt" "$cli" --url "davs://localhost:$signed/dav" identify)" = none ]
    expect_code 17 "$cli" --url "http://alice@127.0.0.1:$self/dav" ls ""
    expect_code 17 "$cli" --url "davs://alice:pw@127.0.0.1:$self/dav" ls ""
}

status=0
if (cd "$here/../../../rust" && cargo test --locked -q -p netvfs-webdav --test apache); then
    echo "PASS   : rust/netvfs-webdav/tests/apache.rs"
else
    echo "FAIL!  : rust/netvfs-webdav/tests/apache.rs"
    status=1
fi
rm -rf "$work/dav/CLI run"
head -c 3000000 /dev/urandom > "$work/cli.bin"
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

mkdir -p "$work/dav/conformance"
chmod 777 "$work/dav/conformance"
pin=$("$build/bin/netvfs-cli" --url "davs://127.0.0.1:$self/dav" identify | sed -n 2p)
cat > "$work/conformance.json" <<JSON
{ "targets": [
  { "name": "webdav", "provider": "webdav", "host": "127.0.0.1", "port": $self, "user": "alice",
    "options": { "base_path": "/dav", "host_key": "$pin" },
    "secretEnv": "NETVFS_CONFORMANCE_SECRET",
    "baseDir": "conformance", "hostPath": "$work/dav/conformance" }
] }
JSON
(umask 000 && NETVFS_CONFORMANCE_SECRET="$password" NETVFS_CONFORMANCE_CONFIG="$work/conformance.json" \
    "$build/tests/conformance/tst_conformance") || status=1
exit $status
