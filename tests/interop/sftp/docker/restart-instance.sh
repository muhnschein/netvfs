#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

instance=$1
user=$2
conf="/etc/ssh/sshd-$instance.conf"
log="/var/log/sshd-$instance.log"

if [ -f "/run/sshd-$instance.pid" ]; then
    listener=$(cat "/run/sshd-$instance.pid")
    kill "$listener" 2>/dev/null || true
    while grep -q '^State:.*[^Z] (' "/proc/$listener/status" 2>/dev/null; do
        sleep 0.1
    done
fi
uid=$(id -u "$user")
for p in /proc/[0-9]*; do
    if [ "$(stat -c %u "$p" 2>/dev/null)" = "$uid" ]; then
        kill -9 "${p#/proc/}" 2>/dev/null || true
    fi
done

port=$(sed -n 's/^Port //p' "$conf")
: > "$log"
setsid "$SSHD" -D -f "$conf" -E "$log" < /dev/null > /dev/null 2>&1 &
tries=0
until grep -q "Server listening on 0.0.0.0 port $port" "$log"; do
    tries=$((tries + 1))
    if [ "$tries" -gt 100 ]; then
        echo "sshd instance $instance did not restart" >&2
        cat "$log" >&2
        exit 1
    fi
    sleep 0.1
done
