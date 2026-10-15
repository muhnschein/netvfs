#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Container entry point of the Dropbear interop server: user "alice" with
# password $TEST_PASSWORD (keys in ~/.ssh/authorized_keys, added by the
# tests) and one Dropbear on port 2201 ("default") with its Ed25519, ECDSA
# and RSA host keys, logging to /var/log/dropbear-default.log.
# /run/netvfs-ready appears when it accepts connections.
set -eu

: "${TEST_PASSWORD:?}"

id alice >/dev/null 2>&1 || useradd -m -s /bin/sh alice
echo "alice:$TEST_PASSWORD" | chpasswd

rm -f /run/netvfs-ready
dropbear -F -E -p 2201 \
    -r /etc/dropbear/dropbear_ed25519_host_key \
    -r /etc/dropbear/dropbear_ecdsa_host_key \
    -r /etc/dropbear/dropbear_rsa_host_key 2> /var/log/dropbear-default.log &

# No network tools in the image: port 2201 (0x0899) listening, from /proc.
tries=0
until grep -q ':0899 0*:0000 0A' /proc/net/tcp /proc/net/tcp6 2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -gt 100 ]; then
        echo "dropbear did not start" >&2
        cat /var/log/dropbear-default.log >&2
        exit 1
    fi
    sleep 0.2
done
touch /run/netvfs-ready
exec sleep infinity
