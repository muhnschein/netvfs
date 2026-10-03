#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# FTP/FTPS interop suite (SPEC-v2 6.4, XT-1, XT-2, XT-5). Creates a test CA
# and server certificates, builds the vsftpd and pure-ftpd images, starts
# one container of each, runs the QtTest driver tst_interop_ftp against
# them, and removes the containers again, also when a step fails or the run
# is interrupted.
#
# FTP data connections go to the port the server announces (EPSV, or PASV
# with 127.0.0.1): the passive port ranges are published 1:1 on the host's
# loopback, in a free range below the ephemeral ports (chosen at start, see
# below) so that parallel runs and outgoing connections do not collide.
#
# The driver compiles the backend in with NETVFS_TLS_TEST_HOOKS and passes
# the test CA as the option test_ca_file, so the vsftpd explicit instance,
# whose certificate the CA signed, is "system trusted".
#
# Usage: run.sh <build dir> [tst_interop_ftp arguments]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
build=$(cd "$1" && pwd)
shift
work="$build/interop-ftp"
prefix="netvfs-ftp-it-$$"
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
    echo "-- ftp interop: $*"
}

make_certs() {
    certs="$work/certs"
    rm -rf "$certs"
    mkdir -p "$certs"
    (
        cd "$certs"
        openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=netvfs-test-ca \
            -keyout ca.key -out ca.crt 2>/dev/null
        openssl req -newkey rsa:2048 -nodes -subj /CN=localhost -keyout trusted.key -out trusted.csr 2>/dev/null
        printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n' > trusted.ext
        openssl x509 -req -in trusted.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
            -extfile trusted.ext -out trusted.crt 2>/dev/null
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
            -subj /CN=selfsigned.test -keyout selfsigned.key -out selfsigned.crt 2>/dev/null
        chmod 644 ./*.key
    )
}

build_images() {
    log "building server images"
    docker build -q -f "$here/docker/Dockerfile.vsftpd" -t netvfs-ftp-vsftpd:test "$here/docker" >/dev/null
    docker build -q -f "$here/docker/Dockerfile.pureftpd" -t netvfs-ftp-pureftpd:test "$here/docker" >/dev/null
}

wait_ready() {
    container=$1
    tries=0
    until docker exec "$container" test -f /run/netvfs-ready 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -gt 120 ] || [ "$(docker inspect -f '{{.State.Running}}' "$container")" != true ]; then
            log "server $container did not become ready"
            docker logs "$container" >&2 || true
            return 1
        fi
        sleep 0.5
    done
}

host_port() {
    container=$1
    port=$2
    docker port "$container" "$port/tcp" | head -n 1 | sed 's/.*://'
}

make_certs
build_images

password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
# 50 consecutive free loopback ports below the kernel's ephemeral range, so
# that neither parallel runs nor outgoing connections can take them first.
base=$(python3 - "$$" <<'PY'
import socket, sys
lo = int(open("/proc/sys/net/ipv4/ip_local_port_range").read().split()[0])
start = 10000
slots = max(1, (lo - start - 50) // 50)
for i in range(slots):
    base = start + ((int(sys.argv[1]) + i) % slots) * 50
    socks = []
    try:
        for port in range(base, base + 50):
            s = socket.socket()
            s.bind(("127.0.0.1", port))
            socks.append(s)
    except OSError:
        continue
    finally:
        for s in socks:
            s.close()
    print(base)
    break
else:
    sys.exit("no free passive port range")
PY
)
vsftpd="$prefix-vsftpd"
pureftpd="$prefix-pureftpd"
docker run -d --name "$vsftpd" -e TEST_PASSWORD="$password" -e PASV_BASE="$base" \
    -v "$work/certs:/certs:ro" --tmpfs /home/alice/small:size=2m \
    -p 127.0.0.1::21 -p 127.0.0.1::990 -p 127.0.0.1::2121 -p 127.0.0.1::2122 \
    -p "127.0.0.1:$base-$((base + 39)):$base-$((base + 39))" netvfs-ftp-vsftpd:test >/dev/null
containers="$containers $vsftpd"
# pure-ftpd drops privileges with capabilities docker does not grant by default.
docker run -d --name "$pureftpd" -e TEST_PASSWORD="$password" -e PASV_BASE="$base" \
    --cap-add DAC_READ_SEARCH --cap-add SYS_NICE -v "$work/certs:/certs:ro" \
    -p 127.0.0.1::21 -p "127.0.0.1:$((base + 40))-$((base + 49)):$((base + 40))-$((base + 49))" \
    netvfs-ftp-pureftpd:test >/dev/null
containers="$containers $pureftpd"
wait_ready "$vsftpd"
wait_ready "$pureftpd"

config="$work/config.json"
cat > "$config" <<EOF
{
  "password": "$password",
  "certs": "$work/certs",
  "proxy": "$here/ftpstall.py",
  "servers": {
    "vsftpd": { "container": "$vsftpd", "port": $(host_port "$vsftpd" 21), "tls": "explicit", "home": "/home/alice" },
    "vsftpd-implicit": { "container": "$vsftpd", "port": $(host_port "$vsftpd" 990), "tls": "implicit", "home": "/home/alice" },
    "vsftpd-plain": { "container": "$vsftpd", "port": $(host_port "$vsftpd" 2121), "tls": "none", "home": "/home/alice" },
    "vsftpd-limited": { "container": "$vsftpd", "port": $(host_port "$vsftpd" 2122), "tls": "none", "home": "/home/alice" },
    "pureftpd": { "container": "$pureftpd", "port": $(host_port "$pureftpd" 21), "tls": "explicit", "home": "/home/alice" }
  }
}
EOF

export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
export NETVFS_FTP_INTEROP_CONFIG="$config"
log "running tst_interop_ftp"
status=0
"$build/tests/interop/ftp/tst_interop_ftp" "$@" || status=1
if [ "$status" -ne 0 ]; then
    log "server logs (tail)"
    docker exec "$vsftpd" sh -c 'tail -n 40 /var/log/vsftpd-*.log' >&2 || true
    docker logs --tail 40 "$pureftpd" >&2 || true
fi
exit $status
