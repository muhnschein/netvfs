#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# WebDAV interop suite (SPEC-v2 XT-2, XT-5, 6.3): Apache httpd + mod_dav with
# a self-signed and a test-CA-signed certificate, rclone "serve webdav" for
# quirk coverage, and the QtTest driver tst_interop_webdav (which starts the
# stalling proxy httpstall.py itself), then netvfs-cli against the self-signed
# Apache. Containers are removed on exit.
#
# Usage: run.sh <build dir> [tst_interop_webdav arguments]
# With driver arguments only the driver runs, not the CLI check. With
# NETVFS_INTEROP_CLI_ONLY=1 only the CLI check runs.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
build=$(cd "$1" && pwd)
shift
prefix="netvfs-webdav-$$"
image="netvfs-webdav-apache:test"
rclone_image=${NETVFS_RCLONE_IMAGE:-mirror.gcr.io/rclone/rclone:1.68}
work=$(mktemp -d)
password=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')

cleanup() {
    ids=$(docker ps -aq --filter "name=^${prefix}-")
    [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

log() {
    echo "-- webdav interop: $*"
}

# Certificates of this run: a self-signed one, and a test CA with a leaf.
make_certificates() {
    san="subjectAltName=DNS:localhost,IP:127.0.0.1"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
        -subj "/O=netvfs interop/CN=localhost" -addext "$san" \
        -keyout "$work/self.key" -out "$work/self.crt" 2>/dev/null
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
        -subj "/O=netvfs interop/CN=netvfs interop CA" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$work/ca.key" -out "$work/ca.crt" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/O=netvfs interop/CN=localhost" -keyout "$work/signed.key" -out "$work/signed.csr" 2>/dev/null
    printf '%s\nbasicConstraints=CA:FALSE\n' "$san" > "$work/leaf.ext"
    openssl x509 -req -in "$work/signed.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
        -days 7 -extfile "$work/leaf.ext" -out "$work/leaf.crt" 2>/dev/null
    cat "$work/leaf.crt" "$work/ca.crt" > "$work/signed.crt"
    chmod 0644 "$work"/*.key
}

wait_http() {
    url=$1
    i=0
    until [ "$(curl -s -k -o /dev/null -w '%{http_code}' "$url" || true)" != "000" ]; do
        i=$((i + 1))
        if [ $i -ge 120 ]; then
            log "$url did not come up"
            return 1
        fi
        sleep 0.5
    done
}

port_of() {
    docker port "$1" "$2/tcp" | head -n 1 | sed 's/.*://'
}

log "building the Apache image"
docker build -q -t "$image" "$here/server" >/dev/null
make_certificates

apache="$prefix-apache"
docker create --name "$apache" -e TEST_PASSWORD="$password" \
    --tmpfs /srv/small:size=1m,uid=1,gid=1 \
    -p 127.0.0.1::80 -p 127.0.0.1::443 -p 127.0.0.1::8443 "$image" >/dev/null
for file in self.crt self.key signed.crt signed.key; do
    docker cp "$work/$file" "$apache:/etc/netvfs/$file"
done
docker start "$apache" >/dev/null

rclone="$prefix-rclone"
docker run -d --name "$rclone" -p 127.0.0.1::8080 "$rclone_image" \
    serve webdav /data --addr :8080 --user alice --pass "$password" >/dev/null

apache_http=$(port_of "$apache" 80)
apache_self=$(port_of "$apache" 443)
apache_ca=$(port_of "$apache" 8443)
rclone_http=$(port_of "$rclone" 8080)
wait_http "http://127.0.0.1:$apache_http/"
wait_http "https://127.0.0.1:$apache_self/"
wait_http "https://127.0.0.1:$apache_ca/"
wait_http "http://127.0.0.1:$rclone_http/"

config="$work/config.json"
cat > "$config" <<EOF
{
  "password": "$password",
  "apache_container": "$apache",
  "ca_file": "$work/ca.crt",
  "apache": { "http": $apache_http, "https_self": $apache_self, "https_ca": $apache_ca },
  "rclone": { "http": $rclone_http }
}
EOF

export NETVFS_BACKEND_PATH="$build/lib/netvfs/backends"
export NETVFS_WEBDAV_INTEROP_CONFIG="$config"
if [ -z "${NETVFS_INTEROP_CLI_ONLY:-}" ]; then
    log "running tst_interop_webdav"
    if ! "$build/tests/interop/webdav/tst_interop_webdav" "$@"; then
        log "Apache error log:"
        docker logs "$apache" 2>&1 >/dev/null | tail -n 40 >&2
        exit 1
    fi
fi

# expect_code <exit code> <command...>: the command must fail with exactly that code.
expect_code() {
    want=$1
    shift
    set +e
    "$@" >/dev/null 2>&1
    got=$?
    set -e
    if [ "$got" -ne "$want" ]; then
        log "expected exit code $want, got $got: $*"
        return 1
    fi
}

# SPEC-v2 XC-CLI against Apache over TLS with the self-signed certificate: the
# identity flow (identify, pin, refusal without a pin) and the file commands.
cli_check() {
    cli="$build/bin/netvfs-cli"
    url="https://alice@127.0.0.1:$apache_self/dav"
    export NETVFS_SECRET="$password"
    log "netvfs-cli end to end"
    identity=$("$cli" --url "$url" identify)
    # XC-16: the fingerprint is the SHA-256 of the SubjectPublicKeyInfo, base64 (the curl pin form).
    spki=$(openssl x509 -in "$work/self.crt" -pubkey -noout | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary | openssl base64)
    test "$(echo "$identity" | sed -n 1p)" = "$spki"
    pin=$(echo "$identity" | sed -n 2p)
    case "$pin" in "tls-spki-sha256 "*) ;; *) log "not a TLS pin: $pin"; return 1 ;; esac
    echo "$identity" | grep -q '^system-trusted: no$'
    echo "$identity" | grep -q '^problems: .*self-signed'
    echo "$identity" | grep -q '^advice: .*tls_verify_peer'
    # Not trusted and not pinned: refused before sign-in (14 = ServerIdentityUnknown); a wrong pin: 15.
    expect_code 14 "$cli" --url "$url" ls ""
    expect_code 15 "$cli" --url "$url" --host-key "tls-spki-sha256 $(printf '%s' wrong | openssl base64)" ls ""
    set -- --url "$url" --host-key "$pin"
    "$cli" "$@" mkdir -p "cli/tree/inner"
    head -c 300000 /dev/urandom > "$work/cli.bin"
    "$cli" "$@" put "$work/cli.bin" "cli/cli.bin"
    "$cli" "$@" ls "cli" | grep -q -- "- 300000 cli.bin\$"
    "$cli" "$@" ls -l "cli" | grep -Eq -- "^-[-rwx?]+ [^ ]+ [^ ]+ 300000 [0-9T:Z-]+ [-A-Z]+ cli.bin\$"
    "$cli" "$@" stat --json "cli/cli.bin" | grep -q -- '"size": 300000'
    "$cli" "$@" caps | grep -q -- "^capabilities: "
    "$cli" "$@" cat "cli/cli.bin" | cmp - "$work/cli.bin"
    "$cli" "$@" cat --offset 1000 --length 500 "cli/cli.bin" > "$work/cli.range"
    tail -c +1001 "$work/cli.bin" | head -c 500 | cmp - "$work/cli.range"
    "$cli" "$@" touch "cli/empty"
    "$cli" "$@" stat "cli/empty" | grep -Eq -- "^-[-rwx?]+ .* 0 "
    # mv and cp do not replace unless asked
    "$cli" "$@" put "$work/cli.bin" "cli/other.bin"
    expect_code 20 "$cli" "$@" mv "cli/other.bin" "cli/cli.bin"
    "$cli" "$@" mv --replace "cli/other.bin" "cli/cli.bin"
    "$cli" "$@" cp "cli/cli.bin" "cli/copy.bin"
    "$cli" "$@" cat "cli/copy.bin" | cmp - "$work/cli.bin"
    expect_code 20 "$cli" "$@" cp "cli/cli.bin" "cli/copy.bin"
    "$cli" "$@" put "$work/cli.bin" "cli/tree/inner/f"
    "$cli" "$@" cp -r "cli/tree" "cli/tree2"
    "$cli" "$@" ls "cli/tree2/inner" | grep -q -- "- 300000 f\$"
    "$cli" "$@" rm -r "cli/tree"
    "$cli" "$@" rm -r "cli/tree2"
    "$cli" "$@" rm "cli/copy.bin"
    "$cli" "$@" rm "cli/empty"
    if "$cli" "$@" stat "cli/tree" 2>/dev/null; then
        log "rm -r left the tree"
        return 1
    fi
    "$cli" "$@" rm "cli/cli.bin"
    "$cli" "$@" rmdir "cli"
    # A password in the URL is refused (exit 17); plain http needs the explicit consent option.
    expect_code 17 "$cli" --url "https://alice:pw@127.0.0.1:$apache_self/dav" ls ""
    "$cli" --url "dav://alice@127.0.0.1:$apache_http/dav" --option allow_insecure=true ls "" >/dev/null
    log "netvfs-cli ok"
}

if [ $# -eq 0 ]; then
    # A subshell of its own: "set -e" is ignored inside a function that is
    # called as a condition, and a failed check must stop the CLI run.
    set +e
    (set -e; cli_check)
    cli_status=$?
    set -e
    exit $cli_status
fi
