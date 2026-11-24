#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

: "${TEST_PASSWORD:?}"
: "${INSTANCES:=default nosftp noext}"

for user in alice carol twofactor conf otp keyotp pwotp twoprompt nosession; do
    id "$user" >/dev/null 2>&1 || useradd -m -s /bin/sh "$user"
    echo "$user:$TEST_PASSWORD" | chpasswd
done

id backup >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin backup
usermod -d /data -s /usr/sbin/nologin backup
usermod -p '*' backup
mkdir -p /srv/sftpjail/data /etc/ssh/authorized_keys
chown root:root /srv/sftpjail
chmod 755 /srv/sftpjail
chown backup:backup /srv/sftpjail/data
chmod 700 /srv/sftpjail/data

if [ -d /srv/small ]; then
    mkdir -p /srv/small/alice
    chown alice:alice /srv/small/alice
fi

if [ -d /srv/conformance ]; then
    chown conf /srv/conformance
fi

if [ "${USE_PAM:-0}" = 1 ] && [ -n "${TEST_OTP:-}" ] && ! grep -q pam_netvfs_otp /etc/pam.d/sshd; then
    {
        echo "# netvfs interop: one-time password stub (start-sshd.sh)"
        echo "auth [success=ignore default=2] pam_succeed_if.so quiet user = otp"
        echo "auth requisite pam_unix.so"
        echo "auth [success=done default=die] pam_netvfs_otp.so code=$TEST_OTP"
        echo "auth [success=ignore default=1] pam_succeed_if.so quiet user = keyotp"
        echo "auth [success=done default=die] pam_netvfs_otp.so code=$TEST_OTP"
        echo "auth [success=ignore default=2] pam_succeed_if.so quiet user = pwotp"
        echo "auth [success=done ignore=ignore default=die] pam_netvfs_otp.so code=$TEST_OTP wrong=ignore"
        echo "auth [success=done default=die] pam_unix.so"
        echo "auth [success=ignore default=1] pam_succeed_if.so quiet user = twoprompt"
        echo "auth [success=done default=die] pam_netvfs_otp.so code=$TEST_OTP first=echo"
        cat /etc/pam.d/sshd
    } > /etc/pam.d/sshd.new
    mv /etc/pam.d/sshd.new /etc/pam.d/sshd
fi

if [ ! -f /setup/client_key ]; then
    "$SSH_KEYGEN" -q -t ed25519 -N '' -C crosscheck -f /setup/client_key
fi
for user in alice backup; do
    if ! grep -q crosscheck "/etc/ssh/authorized_keys/$user" 2>/dev/null; then
        cat /setup/client_key.pub >> "/etc/ssh/authorized_keys/$user"
    fi
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

penalties() {
    if [ "${PENALTIES:-0}" = 1 ]; then
        echo "PerSourcePenalties no"
    fi
}

instance_config() {
    instance=$1
    case "$instance" in
    default)
        common 2201 default
        cat <<'EOF'
PasswordAuthentication yes
KbdInteractiveAuthentication no
Subsystem sftp internal-sftp
Match User twofactor
  AuthenticationMethods publickey,password
Match User nosession
  MaxSessions 0
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
        echo "Subsystem sftp /usr/bin/python3 /setup/sftpproxy.py --no-extensions $SFTP_SERVER"
        ;;
    hold)
        common 2207 hold
        echo "PasswordAuthentication yes"
        echo "Subsystem sftp /usr/bin/python3 /setup/sftpproxy.py --hold-file /tmp/hold $SFTP_SERVER"
        ;;
    otp)
        common 2208 otp
        cat <<'EOF'
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
Subsystem sftp internal-sftp
Match User otp,twoprompt
  AuthenticationMethods keyboard-interactive
Match User keyotp
  AuthenticationMethods publickey,keyboard-interactive
Match User pwotp
  AuthenticationMethods password,keyboard-interactive
EOF
        ;;
    legacy)
        common 2206 legacy
        echo "KexAlgorithms diffie-hellman-group14-sha1"
        echo "Subsystem sftp internal-sftp"
        ;;
    curve)
        common 2210 curve
        echo "PasswordAuthentication yes"
        echo "KexAlgorithms curve25519-sha256"
        echo "Subsystem sftp internal-sftp"
        ;;
    dh)
        common 2211 dh
        echo "KexAlgorithms diffie-hellman-group16-sha512,diffie-hellman-group14-sha256"
        echo "Subsystem sftp internal-sftp"
        ;;
    cbc)
        common 2212 cbc
        echo "Ciphers aes256-cbc,aes128-cbc"
        echo "Subsystem sftp internal-sftp"
        ;;
    sha1rsa)
        common 2213 sha1rsa
        echo "HostKeyAlgorithms ssh-rsa"
        echo "Subsystem sftp internal-sftp"
        ;;
    *)
        echo "unknown instance $instance" >&2
        exit 1
        ;;
    esac
}

mkdir -p /run/sshd /var/empty/sshd
rm -f /run/netvfs-ready
for name in $INSTANCES; do
    if [ "$name" = stall ]; then
        rm -f /tmp/stall
        python3 /setup/sftpproxy.py --relay 2209 2201 --hold-file /tmp/stall &
        continue
    fi
    instance_config "$name" > "/etc/ssh/sshd-$name.conf"
    : > "/var/log/sshd-$name.log"
    "$SSHD" -D -f "/etc/ssh/sshd-$name.conf" -E "/var/log/sshd-$name.log" &
done

for name in $INSTANCES; do
    [ "$name" = stall ] && continue
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
