# ssh-key 0.7.0-rc.11, with one change

netvfs builds russh's key format crate `ssh-key` from this copy
(`[patch.crates-io]` in `rust/Cargo.toml` and `rust/fuzz/Cargo.toml`).
Everything in this folder but this file is the crate as published on
crates.io (`ssh-key-0.7.0-rc.11.crate`, SHA-256
`f9a32fae177b74a22aa9c5b01bf7e68b33545be32d9e381e248058d2adc15ce3`;
RustCrypto/SSH commit `7a1c757d2e2fcde32680e373d5226481de6d434e`, folder
`ssh-key`), except one line, and without the crate's `tests` folder
(netvfs does not run the crate's own tests, and their sample private keys
would only be dead weight) and its `Cargo.lock` (cargo ignores a path
dependency's lockfile; its old pins only drew advisory alerts).

## What was changed

`src/private/ecdsa.rs`, in `EcdsaPrivateKey::decode`:

```diff
--- a/src/private/ecdsa.rs
+++ b/src/private/ecdsa.rs
@@ -61,7 +61,7 @@
             }
 
             // Minimum allowed key size: may be smaller than modulus size
-            const MIN_SIZE: usize = 32;
+            const MIN_SIZE: usize = 1;
             if len < MIN_SIZE || len > SIZE {
                 return Err(encoding::Error::Length.into());
             }
```

## Why

OpenSSH stores an ECDSA private scalar as an SSH `mpint`, which carries no
leading zero bytes. A P-256 scalar whose first byte is zero, about one key
in 256 that `ssh-keygen` makes, is stored as 31 bytes (or fewer), and the
published crate refuses every scalar shorter than 32 bytes: such a key
could not be imported ("not a key this app can use").

With a minimum of one byte, the code after the check pads a shorter scalar
with leading zeros to the field size, which is the same number. An empty
scalar and one longer than the field size are refused as before.

`rust/netvfs-sftp` tests it with such a key, unencrypted and encrypted
(`testdata/keys/ecdsa256-short-scalar*`): it imports, signs, its signature
verifies, and it signs in to an SSH server.

This folder is not part of the netvfs workspace: no formatting, lints,
tests, coverage, Sonar analysis or cargo-mutants run on it.
