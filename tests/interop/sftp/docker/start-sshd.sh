#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Container entry point for the SFTP interop servers (SPEC-sftp 8, 9).
# Creates the test users and starts one sshd per instance named in
# $INSTANCES, each on its own port and log file:
#   default  2201  password and keys; user "twofactor" needs key + password
#   hardened 2202  SPEC-sftp section 9 (OpenSSH 10.x only)
#   kbdint   2203  keyboard-interactive only, via PAM (distribution sshd)
#   nosftp   2204  no sftp subsystem
#   noext    2205  sftp-server behind noext.py, which hides all extensions
#   legacy   2206  only a key exchange that libssh does not offer (SHA-1)
# The password of every password user is $TEST_PASSWORD. /run/netvfs-ready
# appears when all instances accept connections.
set -eu

: "${TEST_PASSWORD:?}"
: "${INSTANCES:=default nosftp noext}"

for user in alice carol twofactor; do
    id "$user" >/dev/null 2>&1 || useradd -m -s /bin/sh "$user"
    echo "$user:$TEST_PASSWORD" | chpasswd
done

# Chrooted, key-only account of the hardened configuration. The jail is
# root-owned; the account writes below /data. Its keys live outside the jail.
id backup >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin backup
# Ubuntu already has a system user "backup"; section 9 uses that name.
usermod -d /data -s /usr/sbin/nologin backup
usermod -p '*' backup
mkdir -p /srv/sftpjail/data /etc/ssh/authorized_keys
chown root:root /srv/sftpjail
chmod 755 /srv/sftpjail
chown backup:backup /srv/sftpjail/data
chmod 700 /srv/sftpjail/data

# A small file system for the full-disk case, when the container has one.
if [ -d /srv/small ]; then
    mkdir -p /srv/small/alice
    chown alice:alice /srv/small/alice
fi

# Key of the reference OpenSSH client inside this container (S-T8).
if [ ! -f /setup/client_key ]; then
    "$SSH_KEYGEN" -q -t ed25519 -N '' -C crosscheck -f /setup/client_key
fi
for user in alice backup; do
    cat /setup/client_key.pub >> "/etc/ssh/authorized_keys/$user"
done
chmod 755 /etc/ssh/authorized_keys
chmod 644 /etc/ssh/authorized_keys/*

common() {
    cat <<EOF
Port $1
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key
PidFile /run/sshd-$2.pid
LogLevel DEBUG1
AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/authorized_keys/%u
EOF
    if [ "${USE_PAM:-0}" = 1 ]; then
        echo "UsePAM yes"
    fi
    penalties
}

# OpenSSH 9.8+ penalises sources with many failed or unauthenticated
# connections; the suite makes such connections on purpose, all from the
# Docker gateway address.
penalties() {
    if [ "${PENALTIES:-0}" = 1 ]; then
        echo "PerSourcePenalties no"
    fi
}

instance_config() {
    case "$1" in
    default)
        common 2201 default
        cat <<'EOF'
PasswordAuthentication yes
KbdInteractiveAuthentication no
Subsystem sftp internal-sftp
Match User twofactor
  AuthenticationMethods publickey,password
EOF
        ;;
    hardened)
        penalties
        cat <<'EOF'
Port 2202
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/sshd-hardened.pid
LogLevel DEBUG1
AuthorizedKeysFile /etc/ssh/authorized_keys/%u
KexAlgorithms mlkem768x25519-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
HostKeyAlgorithms ssh-ed25519
PubkeyAcceptedAlgorithms ssh-ed25519
PasswordAuthentication no
KbdInteractiveAuthentication no
Subsystem sftp internal-sftp
Match User backup
  ChrootDirectory /srv/sftpjail
  ForceCommand internal-sftp
  AllowTcpForwarding no
EOF
        ;;
    kbdint)
        common 2203 kbdint
        cat <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication yes
PubkeyAuthentication no
Subsystem sftp internal-sftp
EOF
        ;;
    nosftp)
        common 2204 nosftp
        echo "PasswordAuthentication yes"
        ;;
    noext)
        common 2205 noext
        echo "PasswordAuthentication yes"
        echo "Subsystem sftp /usr/bin/python3 /setup/noext.py $SFTP_SERVER"
        ;;
    legacy)
        common 2206 legacy
        echo "KexAlgorithms diffie-hellman-group14-sha1"
        echo "Subsystem sftp internal-sftp"
        ;;
    *)
        echo "unknown instance $1" >&2
        exit 1
        ;;
    esac
}

mkdir -p /run/sshd /var/empty/sshd
rm -f /run/netvfs-ready
for name in $INSTANCES; do
    instance_config "$name" > "/etc/ssh/sshd-$name.conf"
    : > "/var/log/sshd-$name.log"
    "$SSHD" -D -f "/etc/ssh/sshd-$name.conf" -E "/var/log/sshd-$name.log" &
done

for name in $INSTANCES; do
    port=$(sed -n 's/^Port //p' "/etc/ssh/sshd-$name.conf")
    tries=0
    until grep -q "Server listening on 0.0.0.0 port $port" "/var/log/sshd-$name.log"; do
        tries=$((tries + 1))
        if [ "$tries" -gt 100 ]; then
            echo "sshd instance $name did not start" >&2
            cat "/var/log/sshd-$name.log" >&2
            exit 1
        fi
        sleep 0.2
    done
done
touch /run/netvfs-ready
exec sleep infinity
