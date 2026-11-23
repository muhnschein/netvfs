# Changelog

## Unreleased

- WebDAV accounts, such as Nextcloud, over HTTPS in *Settings › Accounts* and for apps through the bridge. Connections use TLS 1.3 only. A certificate the phone does not trust can be accepted once by its fingerprint; it is then checked on every connection.
- FTPS accounts (FTP over TLS) in *Settings › Accounts* and for apps through the bridge. Only explicit TLS 1.3 with protected transfers: plain FTP is refused. Server certificates are trusted as for WebDAV.
- Backups to WebDAV and FTPS servers in *Settings › Backup*: manual, scheduled and restore, as for SFTP and SMB.
- New icons for the four account types in *Settings › Accounts*: the netvfs mark with the protocol name below.
- A refused sign-in no longer mentions a key for accounts that have none.
- When a server's identity changes, apps now show that warning instead of "Cancelled" for the folder they were opening.
- Breaking: you now choose per app and per account what an app may do: full access, read and add, read only, add only, or not allowed. Tapping an app's request opens the choice in Settings, where every account starts at not allowed; *Settings › Accounts › Apps using network locations* changes it later. An app you allowed before keeps full access. Apps need an update for this bridge, such as the next Lautta.
- SFTP accounts no longer offer the sign-in "Ask each time (one-time codes)", and servers that ask for a one-time code or a second factor cannot be used for now. Existing such accounts fail to sign in until you switch them to a password or key in Settings.
- Breaking: apps only reach servers set up as accounts in *Settings › Accounts*. The bridge no longer takes a server address, password or one-time code from an app, and no longer asks an app to trust a server. Apps need an update for this bridge, such as the next Lautta.

## 1.0.0 - 2026-11-17

First release, for Sailfish OS 5.2 on aarch64.

- SFTP and SMB 3.1.1 accounts in *Settings › Accounts*. SFTP signs in with a password or a key made on the phone or imported. Passwords and keys stay in the system's credential store.
- Backups to SFTP and SMB servers in *Settings › Backup*: manual, scheduled and restore, as for Nextcloud.
- Sandboxed apps such as Lautta browse SFTP and SMB servers through the netvfs bridge once you allow them. They never see a password or key.
- Apps see each server's connection state: connected, connecting, not connected, or why connecting failed.
- Apps such as Lautta can list, mount and unmount memory cards and USB drives through netvfs, including encrypted ones and drives Sailfish OS does not mount by itself, and can open *Settings › Storage*.
- Updating netvfs restarts its bridge, so apps use the new version without a reboot. A transfer running during the update stops.
- Reproducible builds: a commit always builds to the same RPMs, byte for byte. `tools/verify-rpm.sh` checks them for you (`doc/VERIFYING.md`).
