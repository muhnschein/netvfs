#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Container entry point.
#   start.sh samba VARIANT      smbd with conf/VARIANT.conf (+ conf/shares.conf);
#                               VARIANT "default" keeps the distribution's smb.conf
#   start.sh proxy SPEC...      TCP proxies in front of SMB servers, see flipproxy.py
# The account "backup" gets the password from $SMB_PASSWORD.
set -eu

mode=$1
shift
if [ "$mode" = proxy ]; then
    exec python3 -u /opt/netvfs/flipproxy.py "$@"
fi

variant=$1
: "${SMB_PASSWORD:?}"

id backup >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin backup
printf '%s\n%s\n' "$SMB_PASSWORD" "$SMB_PASSWORD" | smbpasswd -a -s backup >/dev/null
printf 'username = backup\npassword = %s\n' "$SMB_PASSWORD" > /etc/netvfs-auth
chmod 600 /etc/netvfs-auth

mkdir -p /srv/smb/backup /srv/smb/readonly /srv/smb/small /srv/smb/media /srv/smb/hidden /srv/smb/dfs \
    /srv/smb/public /srv/work
chown backup /srv/smb/backup /srv/smb/small /srv/smb/media /srv/smb/hidden
chmod 777 /srv/smb/public
echo "read-only share" > /srv/smb/readonly/existing.txt
# XM-9: a DFS link to a server that does not exist.
ln -sfn 'msdfs:elsewhere.invalid\share' /srv/smb/dfs/away

if [ "$variant" = default ]; then
    cp /etc/samba/smb.conf.dist /etc/samba/smb.conf
else
    cp "/opt/netvfs/conf/$variant.conf" /etc/samba/smb.conf
fi
cat /opt/netvfs/conf/shares.conf >> /etc/samba/smb.conf
# HOST_WRITABLE=1: the backup share is a host folder that the conformance
# suite also writes to directly (as an unprivileged CI user), so everything
# smbd creates there must stay writable for that user.
if [ "${HOST_WRITABLE:-0}" = 1 ]; then
    sed -i '/^\[backup\]/a\  force create mode = 0666\n  force directory mode = 0777' /etc/samba/smb.conf
fi
testparm -s >/dev/null 2>&1 || { testparm -s; exit 1; }

exec smbd --foreground --no-process-group --debug-stdout
