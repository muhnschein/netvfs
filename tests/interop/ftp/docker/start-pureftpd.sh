#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# pure-ftpd for the virtual user alice ($TEST_PASSWORD) on port 21: TLS
# required for control and data (TLS 3), certificate /certs/selfsigned.*,
# passive ports $PASV_BASE + 40..49 announced as 127.0.0.1, UTF8 in FEAT.
set -eu
useradd -m -s /bin/sh ftpuser
mkdir -p /home/alice
chown -R ftpuser:ftpuser /home/alice
printf '%s\n%s\n' "$TEST_PASSWORD" "$TEST_PASSWORD" \
    | pure-pw useradd alice -u ftpuser -d /home/alice -f /etc/pure-ftpd/pureftpd.passwd >/dev/null
pure-pw mkdb /etc/pure-ftpd/pureftpd.pdb -f /etc/pure-ftpd/pureftpd.passwd
mkdir -p /etc/ssl/private
cat /certs/selfsigned.key /certs/selfsigned.crt > /etc/ssl/private/pure-ftpd.pem
chmod 600 /etc/ssl/private/pure-ftpd.pem
cat > /etc/pure-ftpd/netvfs.conf <<CONF
ChrootEveryone no
Daemonize no
PureDB /etc/pure-ftpd/pureftpd.pdb
NoAnonymous yes
DontResolve yes
TLS 3
CertFile /etc/ssl/private/pure-ftpd.pem
Bind ,21
PassivePortRange $((PASV_BASE + 40)) $((PASV_BASE + 49))
ForcePassiveIP 127.0.0.1
MaxClientsNumber 50
MaxClientsPerIP 50
MinUID 100
CONF
/usr/sbin/pure-ftpd /etc/pure-ftpd/netvfs.conf &
touch /run/netvfs-ready
wait
