#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Container entry point of the ProFTPD mod_sftp server (Dockerfile.proftpd):
#   2222  SFTP, password sign-in for alice and conf ($TEST_PASSWORD)
#   2223  TCP relay to 2222 (sftpproxy.py --relay) that forwards nothing
#         while /tmp/stall exists
# /srv/conformance, when mounted, belongs to conf. /run/netvfs-ready
# appears when the server accepts connections.
set -eu

: "${TEST_PASSWORD:?}"

for user in alice conf; do
    id "$user" >/dev/null 2>&1 || useradd -m -s /bin/sh "$user"
    echo "$user:$TEST_PASSWORD" | chpasswd
done
if [ -d /srv/conformance ]; then
    chown conf /srv/conformance
fi

cat > /etc/proftpd/netvfs.conf <<'EOF'
Include /etc/proftpd/modules.conf
LoadModule mod_sftp.c
ServerName "netvfs interop"
ServerType standalone
DefaultServer on
Port 2222
UseIPv6 off
User proftpd
Group nogroup
PidFile /run/proftpd.pid
ScoreboardFile /run/proftpd.scoreboard
RequireValidShell off
AuthOrder mod_auth_unix.c
WtmpLog off
TransferLog none
Umask 022 022
AllowOverwrite on
MaxInstances 64
SFTPEngine on
SFTPLog /var/log/proftpd/sftp.log
SFTPHostKey /etc/proftpd/hostkeys/rsa
SFTPHostKey /etc/proftpd/hostkeys/ecdsa
SFTPAuthMethods password
SFTPCompression off
EOF

rm -f /run/netvfs-ready /tmp/stall
proftpd --nodaemon -c /etc/proftpd/netvfs.conf > /var/log/proftpd/server.log 2>&1 &
python3 /setup/sftpproxy.py --relay 2223 2222 --hold-file /tmp/stall &

tries=0
until python3 -c 'import socket; socket.create_connection(("127.0.0.1", 2222), 1).close()' 2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -gt 100 ]; then
        echo "proftpd did not start" >&2
        cat /var/log/proftpd/server.log >&2
        exit 1
    fi
    sleep 0.2
done
touch /run/netvfs-ready
exec sleep infinity
