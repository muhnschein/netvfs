#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Nextcloud interop for the WebDAV backend (SPEC-v2 XT-2): nightly only, the
# image is large and the first start installs Nextcloud (SQLite). Runs the
# data-driven driver functions for the "nextcloud" server and the Nextcloud
# flavor test (X-OC-MTime, oc:* properties).
#
# Usage: nextcloud.sh <build dir>
set -eu

build=$(cd "$1" && pwd)
prefix="netvfs-nextcloud-$$"
image=${NETVFS_NEXTCLOUD_IMAGE:-mirror.gcr.io/library/nextcloud:apache}
work=$(mktemp -d)
password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')

cleanup() {
    docker rm -f "$prefix" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

echo "-- nextcloud interop: starting $image"
docker run -d --name "$prefix" -p 127.0.0.1::80 \
    -e SQLITE_DATABASE=nextcloud -e NEXTCLOUD_ADMIN_USER=alice -e NEXTCLOUD_ADMIN_PASSWORD="$password" \
    -e NEXTCLOUD_TRUSTED_DOMAINS="127.0.0.1 localhost" "$image" >/dev/null
port=$(docker port "$prefix" 80/tcp | head -n 1 | sed 's/.*://')
i=0
until curl -s "http://127.0.0.1:$port/status.php" | grep -q '"installed":true'; do
    i=$((i + 1))
    if [ $i -ge 360 ]; then
        echo "-- nextcloud interop: Nextcloud did not finish installing" >&2
        docker logs "$prefix" 2>&1 | tail -n 40 >&2
        exit 1
    fi
    sleep 1
done

cat > "$work/config.json" <<EOF
{
  "password": "$password",
  "nextcloud": { "http": $port }
}
EOF
export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
export NETVFS_WEBDAV_INTEROP_CONFIG="$work/config.json"
"$build/tests/interop/webdav/tst_interop_webdav" \
    roundTrip:nextcloud names:nextcloud renameAndCopy:nextcloud handles:nextcloud errors:nextcloud nextcloudFlavor
