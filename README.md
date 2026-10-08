# netvfs

Remote file access over SFTP, SMB, WebDAV and FTP for Sailfish OS 5.2+ (aarch64).

Adds account providers to *Settings → Accounts*; SFTP and SMB accounts also
appear as storage targets in *Settings → Backup*. Sandboxed apps reach the
accounts through `netvfs-bridge`. The library (`libnetvfs`) is reusable.

## Packages

| Package | Contents |
|---|---|
| `netvfs` | `libnetvfs`, the `sftp`, `smb`, `webdav`, `ftp` and `local` backends, the SMB share helper, account providers and UI, the *Files* services, `netvfs-cli`, translations |
| `netvfs-backup` | SFTP and SMB backups: services, Buteo plugins and profiles |
| `netvfs-bridge` | network locations for sandboxed apps (with a setgid helper) |
| `netvfs-devel` | headers and pkg-config file |

Install `netvfs` for the accounts; it brings `netvfs-backup` along as a weak
dependency (remove it to use the accounts for files only). Install
`netvfs-bridge` for sandboxed apps such as Lautta. See `doc/SPEC-v2.md`
section 10 and `rpm/netvfs.spec`.

Licence: LGPL-2.1-or-later.
