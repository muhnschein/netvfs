#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Starts four vsftpd instances for user alice ($TEST_PASSWORD):
#   explicit  port 21   AUTH TLS required, require_ssl_reuse=YES, /certs/trusted.*
#   implicit  port 990  implicit TLS, require_ssl_reuse=YES, /certs/selfsigned.*
#   plain     port 2121 no TLS
#   limited   port 2122 no TLS, one client at a time (421 for the next)
# Passive ports: $PASV_BASE + 0..9 / 10..19 / 20..29 / 30..39, announced
# as 127.0.0.1 (run.sh publishes them 1:1 on the host's loopback).
set -eu
useradd -m -s /bin/sh alice
echo "alice:$TEST_PASSWORD" | chpasswd
chown -R alice:alice /home/alice

instance() {
    name=$1
    port=$2
    offset=$3
    shift 3
    conf=/etc/vsftpd-$name.conf
    cat > "$conf" <<CONF
listen=YES
listen_ipv6=NO
listen_port=$port
background=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
chmod_enable=YES
utf8_filesystem=YES
seccomp_sandbox=NO
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
pasv_enable=YES
port_enable=NO
pasv_address=127.0.0.1
pasv_min_port=$((PASV_BASE + offset))
pasv_max_port=$((PASV_BASE + offset + 9))
xferlog_enable=YES
log_ftp_protocol=YES
vsftpd_log_file=/var/log/vsftpd-$name.log
max_per_ip=0
CONF
    for line in "$@"; do
        echo "$line" >> "$conf"
    done
    /usr/sbin/vsftpd "$conf" &
}

tls="ssl_enable=YES force_local_logins_ssl=YES force_local_data_ssl=YES ssl_ciphers=HIGH require_ssl_reuse=YES"
# shellcheck disable=SC2086 # $tls is a list of configuration lines
instance explicit 21 0 $tls rsa_cert_file=/certs/trusted.crt rsa_private_key_file=/certs/trusted.key
# shellcheck disable=SC2086
instance implicit 990 10 $tls implicit_ssl=YES rsa_cert_file=/certs/selfsigned.crt rsa_private_key_file=/certs/selfsigned.key
instance plain 2121 20 ssl_enable=NO
instance limited 2122 30 ssl_enable=NO max_clients=1
touch /run/netvfs-ready
wait
