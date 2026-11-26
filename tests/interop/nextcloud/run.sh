#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

here=$(cd "$(dirname "$0")" && pwd)
build=$(cd "$1" && pwd)
image=netvfs-nextcloud:31.0.14
prefix="netvfs-nextcloud-$$"
work=$(mktemp -d)
password=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')

cleanup() {
    docker rm -fv "$prefix" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

certs=$work/certs
mkdir -p "$certs"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$certs/self.key" \
    -out "$certs/self.crt" -days 2 -subj "/CN=localhost" -addext subjectAltName=DNS:localhost 2>/dev/null
chmod 644 "$certs"/*

docker build -q -t "$image" "$here/server" >/dev/null
docker run -d --name "$prefix" -e SQLITE_DATABASE=nextcloud -e NEXTCLOUD_ADMIN_USER=alice \
    -e NEXTCLOUD_ADMIN_PASSWORD="$password" -e NEXTCLOUD_TRUSTED_DOMAINS="127.0.0.1 localhost" \
    -v "$certs:/etc/netvfs:ro" -p 127.0.0.1::443 "$image" >/dev/null
port=$(docker port "$prefix" 443/tcp | head -n 1 | sed 's/.*://')

status_of() {
    curl -sfk --noproxy 127.0.0.1 "https://127.0.0.1:$port/status.php" 2>/dev/null
}
i=0
until status_of | grep -q '"installed":true'; do
    i=$((i + 1))
    if [ $i -ge 360 ]; then
        echo "Nextcloud did not come up:" >&2
        docker logs "$prefix" >&2
        exit 1
    fi
    sleep 0.5
done
echo "Nextcloud: $(status_of | sed 's/.*"versionstring":"\([^"]*\)".*/\1/')"

export NETVFS_INTEROP_NEXTCLOUD_PORT="$port"
export NETVFS_INTEROP_NEXTCLOUD_PASSWORD="$password"
export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
export NETVFS_RS_LIB="$build/lib/netvfs/libnetvfs-rs.so"

status=0
if (cd "$here/../../../rust" && cargo test --locked -q -p netvfs-webdav --test nextcloud); then
    echo "PASS   : rust/netvfs-webdav/tests/nextcloud.rs"
else
    echo "FAIL!  : rust/netvfs-webdav/tests/nextcloud.rs"
    status=1
fi

cli_capabilities() {
    cli="$build/bin/netvfs-cli"
    url="davs://alice@127.0.0.1:$port/remote.php/dav/files/alice"
    pin=$("$cli" --url "$url" identify | sed -n 2p)
    caps=$(NETVFS_SECRET="$password" "$cli" --url "$url" --host-key "$pin" caps)
    echo "$caps" | grep -q DeepETags
    echo "$caps" | grep -q Search
}
set +e
(set -e; cli_capabilities)
cli_status=$?
set -e
if [ $cli_status -eq 0 ]; then
    echo "PASS   : netvfs-cli reports DeepETags and Search"
else
    echo "FAIL!  : netvfs-cli reports DeepETags and Search"
    status=1
fi
exit $status
