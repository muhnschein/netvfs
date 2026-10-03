#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Restarts one sshd instance of start-sshd.sh, as a server restart would
# look to a client of USER: the listener and every session of USER end,
# then the listener starts again on the same port (the container and its
# published ports stay). Used by the conformance suite's keepAlive case.
# Usage: restart-instance.sh INSTANCE USER
# INSTANCE "-": a server that is not one of start-sshd.sh's instances
# (ProFTPD); only the sessions of USER end.
set -eu

instance=$1
user=$2
conf="/etc/ssh/sshd-$instance.conf"
log="/var/log/sshd-$instance.log"

if [ "$instance" != - ] && [ -f "/run/sshd-$instance.pid" ]; then
    listener=$(cat "/run/sshd-$instance.pid")
    kill "$listener" 2>/dev/null || true
    # Gone, or a zombie (PID 1 of the container does not reap).
    while grep -q '^State:.*[^Z] (' "/proc/$listener/status" 2>/dev/null; do
        sleep 0.1
    done
fi
# No procps in the images: find the user's processes in /proc.
uid=$(id -u "$user")
for p in /proc/[0-9]*; do
    if [ "$(stat -c %u "$p" 2>/dev/null)" = "$uid" ]; then
        kill -9 "${p#/proc/}" 2>/dev/null || true
    fi
done

if [ "$instance" = - ]; then
    exit 0
fi
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
