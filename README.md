# netvfs

Remote file access over SFTP and SMB for Sailfish OS 5.2+ (aarch64).

Adds account providers to *Settings → Accounts*; SFTP and SMB accounts also
appear as storage targets in *Settings → Backup*. Sandboxed apps reach the
accounts through `netvfs-bridge`. The library (`libnetvfs`) is reusable.

The SFTP client is for OpenSSH servers; the SMB client speaks SMB 3.1.1 only
(Samba, Windows). Both are Rust code in `libnetvfs-rs.so`, with the
cryptography from russh and ring, sspi and the RustCrypto crates
(`doc/RUST.md`).

## Packages

| Package | Contents |
|---|---|
| `netvfs` | `libnetvfs`, the `sftp`, `smb` and `local` backends with `libnetvfs-rs.so`, account providers and UI, the *Files* services, `netvfs-cli` |
| `netvfs-backup` | SFTP and SMB backups: services, Buteo plugins and profiles |
| `netvfs-bridge` | network locations for sandboxed apps (with a setgid helper) |
| `netvfs-devel` | headers and pkg-config file |

Install `netvfs` for the accounts; it brings `netvfs-backup` along as a weak
dependency (remove it to use the accounts for files only). Install
`netvfs-bridge` for sandboxed apps such as Lautta. See `doc/SPEC-v2.md`
section 10 and `rpm/netvfs.spec`.

Licence: LGPL-2.1-or-later.
