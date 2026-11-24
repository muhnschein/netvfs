#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
uid=$(id -u proftpd)
hash=$(openssl passwd -6 "$TEST_PASSWORD")
printf 'alice:%s:%s:65534::/srv/ftp:/bin/false\n' "$hash" "$uid" > /etc/proftpd/ftpd.passwd
chmod 0600 /etc/proftpd/ftpd.passwd
exec proftpd --nodaemon -c /etc/proftpd/netvfs.conf
