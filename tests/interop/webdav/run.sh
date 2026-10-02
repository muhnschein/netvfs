#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# WebDAV interop suite (SPEC-v2 XT-2, XT-5, 6.3): Apache httpd + mod_dav with
# a self-signed and a test-CA-signed certificate, rclone "serve webdav" for
# quirk coverage, and the QtTest driver tst_interop_webdav (which starts the
# stalling proxy httpstall.py itself). Containers are removed on exit.
#
# Usage: run.sh <build dir> [tst_interop_webdav arguments]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
build=$(cd "$1" && pwd)
shift
prefix="netvfs-webdav-$$"
image="netvfs-webdav-apache:test"
rclone_image=${NETVFS_RCLONE_IMAGE:-mirror.gcr.io/rclone/rclone:1.68}
work=$(mktemp -d)
password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')

cleanup() {
    ids=$(docker ps -aq --filter "name=^${prefix}-")
    [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

log() {
    echo "-- webdav interop: $*"
}

# Certificates of this run: a self-signed one, and a test CA with a leaf.
make_certificates() {
    san="subjectAltName=DNS:localhost,IP:127.0.0.1"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
        -subj "/O=netvfs interop/CN=localhost" -addext "$san" \
        -keyout "$work/self.key" -out "$work/self.crt" 2>/dev/null
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
        -subj "/O=netvfs interop/CN=netvfs interop CA" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$work/ca.key" -out "$work/ca.crt" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/O=netvfs interop/CN=localhost" -keyout "$work/signed.key" -out "$work/signed.csr" 2>/dev/null
    printf '%s\nbasicConstraints=CA:FALSE\n' "$san" > "$work/leaf.ext"
    openssl x509 -req -in "$work/signed.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
        -days 7 -extfile "$work/leaf.ext" -out "$work/leaf.crt" 2>/dev/null
    cat "$work/leaf.crt" "$work/ca.crt" > "$work/signed.crt"
    chmod 0644 "$work"/*.key
}

wait_http() {
    url=$1
    i=0
    until [ "$(curl -s -k -o /dev/null -w '%{http_code}' "$url" || true)" != "000" ]; do
        i=$((i + 1))
        if [ $i -ge 120 ]; then
            log "$url did not come up"
            return 1
        fi
        sleep 0.5
    done
}

port_of() {
    docker port "$1" "$2/tcp" | head -n 1 | sed 's/.*://'
}

log "building the Apache image"
docker build -q -t "$image" "$here/server" >/dev/null
make_certificates

apache="$prefix-apache"
docker create --name "$apache" -e TEST_PASSWORD="$password" \
    --tmpfs /srv/small:size=1m,uid=1,gid=1 \
    -p 127.0.0.1::80 -p 127.0.0.1::443 -p 127.0.0.1::8443 "$image" >/dev/null
for file in self.crt self.key signed.crt signed.key; do
    docker cp "$work/$file" "$apache:/etc/netvfs/$file"
done
docker start "$apache" >/dev/null

rclone="$prefix-rclone"
docker run -d --name "$rclone" -p 127.0.0.1::8080 "$rclone_image" \
    serve webdav /data --addr :8080 --user alice --pass "$password" >/dev/null

apache_http=$(port_of "$apache" 80)
apache_self=$(port_of "$apache" 443)
apache_ca=$(port_of "$apache" 8443)
rclone_http=$(port_of "$rclone" 8080)
wait_http "http://127.0.0.1:$apache_http/"
wait_http "https://127.0.0.1:$apache_self/"
wait_http "https://127.0.0.1:$apache_ca/"
wait_http "http://127.0.0.1:$rclone_http/"

config="$work/config.json"
cat > "$config" <<EOF
{
  "password": "$password",
  "apache_container": "$apache",
  "ca_file": "$work/ca.crt",
  "apache": { "http": $apache_http, "https_self": $apache_self, "https_ca": $apache_ca },
  "rclone": { "http": $rclone_http }
}
EOF

export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
export NETVFS_WEBDAV_INTEROP_CONFIG="$config"
log "running tst_interop_webdav"
if ! "$build/tests/interop/webdav/tst_interop_webdav" "$@"; then
    log "Apache error log:"
    docker logs "$apache" 2>&1 >/dev/null | tail -n 40 >&2
    exit 1
fi
