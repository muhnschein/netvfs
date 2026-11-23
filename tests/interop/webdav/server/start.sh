#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
conf=/usr/local/apache2/conf
htpasswd -bc "$conf/htpasswd" alice "$TEST_PASSWORD" >/dev/null 2>&1
chmod 0644 "$conf/htpasswd"
exec httpd-foreground
