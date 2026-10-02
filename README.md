# netvfs

Remote file access over SFTP, SMB, WebDAV and FTP for Sailfish OS 5.2+ (aarch64).

Adds account providers to *Settings → Accounts*; SFTP and SMB accounts also
appear as storage targets in *Settings → Backup*. Sandboxed apps reach the
accounts through `netvfs-bridge`. The library (`libnetvfs`) is reusable.

## Packages

| Package | Contents |
|---|---|
| `netvfs-core` | `libnetvfs`, backend folder, translations |
| `netvfs-ui` | QML module `org.netvfs.accounts`, provider descriptors |
| `netvfs-backend-<p>` | protocol plugin: `sftp`, `smb`, `webdav`, `ftp`, `local` |
| `netvfs-backend-smb-shares` | share enumeration helper of the SMB backend (optional) |
| `netvfs-account-<p>` | account provider, account UI and icon: `sftp`, `smb`, `webdav`, `ftp` |
| `netvfs-backup-<p>` | backup service, Buteo plugins and profiles: `sftp`, `smb` |
| `netvfs-files-services` | the *Files* services used by apps |
| `netvfs-bridge` | network locations for sandboxed apps |
| `netvfs-cli` | command line tool |
| `netvfs-core-devel` | headers and pkg-config file |

Install `netvfs-account-<p>` for an account; for SFTP and SMB it brings
`netvfs-backup-<p>` along as a weak dependency (remove it to use the account
for files only). See `doc/SPEC-v2.md` section 10 and `rpm/netvfs.spec`.

Licence: LGPL-2.1-or-later.
