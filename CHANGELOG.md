# Changelog

## Unreleased

- Apps using netvfs, such as Lautta, now show each server's real connection state: connected, connecting, not connected, or why connecting failed.
- Lautta can mount and unmount memory cards and USB drives through netvfs, including drives Sailfish OS does not mount by itself.
- Lautta can open Settings › Storage through netvfs.
- Encrypted memory cards and USB drives show up in Lautta: a locked one as locked, an unlocked one as a normal drive.
- Reproducible builds: a commit always builds to the same RPMs, byte for byte. `tools/verify-rpm.sh` checks them for you (doc/VERIFYING.md).
