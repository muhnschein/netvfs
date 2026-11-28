#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

here=$(cd "$(dirname "$0")" && pwd)
build=$(cd "$1" && pwd)
image=netvfs-ftps-proftpd:1.3.8
prefix="netvfs-ftps-$$"
work=$(mktemp -d)
password=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
port=$((20000 + $$ % 1200 * 10))
first=$((port + 1))
last=$((port + 9))

cleanup() {
    docker rm -f "$prefix" >/dev/null 2>&1 || true
    docker run --rm -v "$work:/w" "$image" sh -c 'rm -rf /w/ftp' >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

certs=$work/certs
mkdir -p "$certs" "$work/ftp"
chmod 777 "$work/ftp"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$certs/self.key" \
    -out "$certs/self.crt" -days 2 -subj "/CN=localhost" -addext subjectAltName=DNS:localhost 2>/dev/null
chmod 644 "$certs"/*

docker build -q -t "$image" "$here/server" >/dev/null
docker run -d --name "$prefix" --network host -e TEST_PASSWORD="$password" -e FTP_PORT=$port \
    -e PASV_FIRST=$first -e PASV_LAST=$last -v "$certs:/etc/netvfs:ro" -v "$work/ftp:/srv/ftp" "$image" >/dev/null
i=0
until printf 'QUIT\r\n' | timeout 2 openssl s_client -quiet -starttls ftp -connect "127.0.0.1:$port" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ $i -ge 60 ]; then
        echo "proftpd did not come up:" >&2
        docker logs "$prefix" >&2
        exit 1
    fi
    sleep 0.5
done
echo "proftpd: $(docker exec "$prefix" proftpd -v 2>&1 | head -n 1)"

export NETVFS_INTEROP_FTPS_PORT=$port NETVFS_INTEROP_FTPS_PASSWORD=$password
export UBSAN_OPTIONS="${UBSAN_OPTIONS:+$UBSAN_OPTIONS:}print_stacktrace=1:halt_on_error=1"
export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
export NETVFS_RS_LIB="$build/lib/netvfs/libnetvfs-rs.so"

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
    url="ftps://alice@127.0.0.1:$port"
    expect_code 14 env NETVFS_SECRET="$password" "$cli" --url "$url" ls /
    pin=$("$cli" --url "$url" identify | sed -n 2p)
    case "$pin" in "tls-spki-sha256 "*) ;; *) echo "identify printed no TLS pin: $pin" >&2; return 1 ;; esac
    ftps() {
        NETVFS_SECRET="$password" "$cli" --url "$url" --host-key "$pin" "$@"
    }
    ftps verify "/CLI run" >/dev/null
    ftps put "$work/cli.bin" "/CLI run/cli.bin"
    ftps ls "/CLI run" | grep -q " 3000000 cli.bin$"
    ftps get "/CLI run/cli.bin" "$work/cli.out"
    cmp -s "$work/cli.bin" "$work/cli.out"
    cmp -s "$work/cli.bin" "$work/ftp/CLI run/cli.bin"
    ftps cat --offset 1000 --length 500 "/CLI run/cli.bin" > "$work/cli.range"
    tail -c +1001 "$work/cli.bin" | head -c 500 | cmp - "$work/cli.range"
    ftps mkdir -p "/CLI run/tree/inner"
    ftps put "$work/cli.bin" "/CLI run/other.bin"
    expect_code 20 ftps mv "/CLI run/other.bin" "/CLI run/cli.bin"
    ftps mv --replace "/CLI run/other.bin" "/CLI run/cli.bin"
    expect_code 28 ftps rmdir "/CLI run/tree"
    ftps rm -r "/CLI run"
    expect_code 17 "$cli" --url "ftp://alice@127.0.0.1:$port/" ls /
    expect_code 17 "$cli" --url "ftps://alice:pw@127.0.0.1:$port/" ls /
}

status=0
if (cd "$here/../../../rust" && cargo test --locked -q -p netvfs-ftps --test server -- --test-threads=1); then
    echo "PASS   : rust/netvfs-ftps/tests/server.rs"
else
    echo "FAIL!  : rust/netvfs-ftps/tests/server.rs"
    docker logs "$prefix" 2>&1 | tail -n 40
    status=1
fi
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

mkdir -p "$work/ftp/conformance"
chmod 777 "$work/ftp/conformance"
pin=$("$build/bin/netvfs-cli" --url "ftps://127.0.0.1:$port" identify | sed -n 2p)
cat > "$work/conformance.json" <<JSON
{ "targets": [
  { "name": "ftps", "provider": "ftps", "host": "127.0.0.1", "port": $port, "user": "alice",
    "options": { "host_key": "$pin" },
    "secretEnv": "NETVFS_CONFORMANCE_SECRET",
    "baseDir": "/conformance", "hostPath": "$work/ftp/conformance" }
] }
JSON
(umask 000 && NETVFS_CONFORMANCE_SECRET="$password" NETVFS_CONFORMANCE_CONFIG="$work/conformance.json" \
    "$build/tests/conformance/tst_conformance") || status=1
exit $status
