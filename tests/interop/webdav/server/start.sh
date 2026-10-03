#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Writes the Basic and Digest password files for user alice from
# $TEST_PASSWORD, then runs httpd in the foreground.
set -eu
conf=/usr/local/apache2/conf
htpasswd -bc "$conf/htpasswd" alice "$TEST_PASSWORD" >/dev/null 2>&1
digest=$(printf '%s' "alice:netvfs:$TEST_PASSWORD" | md5sum | cut -d ' ' -f 1)
printf 'alice:netvfs:%s\n' "$digest" > "$conf/htdigest"
chmod 0644 "$conf/htpasswd" "$conf/htdigest"
exec httpd-foreground
