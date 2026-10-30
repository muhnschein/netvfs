#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Crypto fence of netvfs-smb: MS-SMB2 crypto glue lives in rust/netvfs-smb/src/crypto.rs (tests in src/crypto/); no other source file of the crate names a RustCrypto crate or the OS random generator. The list covers every RustCrypto crate a file could name, so a new dependency cannot slip past.
# Usage: check-crypto-fence.sh [<crate dir>]
set -eu
crate=${1:-$(cd "$(dirname "$0")/../.." && pwd)/rust/netvfs-smb}
crates='aead|aes|aes_gcm|aes_gcm_siv|aes_siv|ccm|chacha20|chacha20poly1305|cipher|cmac|crypto_bigint|crypto_common|ctr|des|digest|getrandom|ghash|hkdf|hmac|md4|md5|pbkdf2|poly1305|polyval|rand|rand_core|rc4|sha1|sha2|sha3|subtle|universal_hash'
# Path starting with one of the crates (`use aes::..`, `::aes::..`, `aes::Aes128`, `{sha2::..}`), a crate imported whole (`use aes as a;`, `extern crate aes`); not `crate::crypto::..` or `x.aes::..`.
word="($crates)([^A-Za-z0-9_]|$)"
pattern="(^|[^A-Za-z0-9_:.])(::)?($crates)::|(use|extern[[:space:]]+crate)[[:space:]]+(::)?$word"
found=$(find "$crate/src" -name '*.rs' ! -path "$crate/src/crypto.rs" ! -path "$crate/src/crypto/*" \
    -exec grep -nHE "$pattern" {} + || true)
if [ -n "$found" ]; then
    echo "RustCrypto or getrandom outside netvfs-smb's crypto module:"
    echo "$found"
    exit 1
fi
if [ ! -f "$crate/src/crypto.rs" ] || ! grep -qE "^use ($crates)::" "$crate/src/crypto.rs"; then
    echo "$crate/src/crypto.rs is missing or imports no RustCrypto crate: the check would prove nothing"
    exit 1
fi
echo "crypto fence: RustCrypto only in $crate/src/crypto.rs"
