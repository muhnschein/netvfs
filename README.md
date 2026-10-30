# netvfs

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=muhnschein_netvfs&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=muhnschein_netvfs)[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=muhnschein_netvfs&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=muhnschein_netvfs)[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=muhnschein_netvfs&metric=coverage)](https://sonarcloud.io/summary/new_code?id=muhnschein_netvfs)[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=muhnschein_netvfs&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=muhnschein_netvfs)

## Overview

netvfs adds SFTP and SMB servers to Sailfish OS as a platform service:

- **Accounts.** SFTP and SMB appear in *Settings → Accounts*, next to the
  stock account types. Passwords and keys stay in the system's credential
  store.
- **Backups.** The same accounts appear as targets in *Settings → Backup*.
  Backup, scheduled backup and restore work as they do for Nextcloud.
- **Files for apps.** Sandboxed apps such as
  [Lautta](https://github.com/muhnschein/lautta) browse the servers through
  a bridge. They link nothing from netvfs, need no extra permission, and
  never see a secret.

The SFTP client is for OpenSSH servers; the SMB client speaks SMB 3.1.1 only
(Samba, Windows). Both are written in Rust.

## Where it sits

```
  Settings                          Apps (sandboxed)
 ┌──────────┐  ┌──────────┐        ┌───────────────┐
 │ Accounts │  │  Backup  │        │    Lautta     │
 └────┬─────┘  └────┬─────┘        └───────┬───────┘
      │             │ backup service,      │ socket in the
      │             │ sync framework       │ app's own folder
      │        ┌────▼─────┐        ┌───────▼───────┐
      │        │  backup  │        │ netvfs-bridge ├───► UDisks2: memory
      │        │  plugins │        │ one per app   │     cards, USB drives
      │        └────┬─────┘        └───────┬───────┘
 ┌────▼─────────────▼──────────────────────▼───────┐
 │ libnetvfs: accounts, sessions                   ├───► accounts and
 ├─────────────────────────────────────────────────┤     credential store
 │ SFTP and SMB clients (Rust)                     │
 └────────────────────────┬────────────────────────┘
                          ▼
                 SFTP and SMB servers
```

- An account is made and edited only in Settings. Apps hand off to Settings
  for that; the bridge never changes an account.
- The first time an app asks, netvfs posts a notification: allow or don't
  allow. *Settings → Accounts* lists the apps and can revoke them.
- The bridge serves one app over a socket in that app's own data folder,
  checks that the program on the other end is that app, and exits when idle.
  It reads and writes local files only through descriptors the app opened.
- A sandboxed app cannot mount drives, so the bridge also lists, mounts and
  unmounts memory cards and USB drives, as *Settings → Storage* does.

## Packages

| Package | For |
|---|---|
| `netvfs` | the accounts, the library, `netvfs-cli` |
| `netvfs-backup` | backups to SFTP and SMB (comes with `netvfs`, can be removed) |
| `netvfs-bridge` | apps such as Lautta |
| `netvfs-devel` | building against the library |

Install `netvfs`, `netvfs-backup` and `netvfs-bridge` from the same build, in
one go.

## Limitations

- No protocol or crypto of our own: the cryptography comes from established
  Rust crates.
- No legacy crypto: SSH only with Curve25519 or hybrid post-quantum key
  exchange, AEAD ciphers, no SHA-1 or DSA host keys; SMB 3.1.1 only.
- No folder sync, no mounting servers as file systems.
- Not for the Jolla Store: it installs system files and a setgid helper.

## Building

The device packages, built in the Sailfish OS SDK image (needs Docker):

```
$ git clone https://github.com/muhnschein/netvfs.git
$ cd netvfs
$ git submodule update --init --depth 1
$ export SDK_IMAGE=mirror.gcr.io/coderus/sailfishos-platform-sdk-aarch64:5.2.0.15
$ export TARGET=SailfishOS-5.2.0.15-aarch64
$ tools/ci/build-rpm.sh
```

Everything else runs on the host:

```
# Host dependencies on Ubuntu 24.04.
$ ./tools/ci/install-host-deps.sh
$ ./tools/ci/cargo-tool.sh cargo-nextest 0.9.148

# Rust checks, C++ unit tests, bridge tests, and interop tests against
# OpenSSH and Samba containers (those need Docker).
$ make check
```

## License

Licensed LGPL-2.1-or-later, see the LICENSE file for details.

Copyright © netvfs contributors.
