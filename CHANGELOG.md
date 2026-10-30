# Changelog

## Unreleased

- After a canceled upload to an SMB server, the unfinished `.part` file no longer stays visible in the folder for a moment.
- Updating netvfs restarts its bridge, so apps such as Lautta use the new version without a reboot. A transfer running during the update stops.
- Apps using netvfs, such as Lautta, now show each server's real connection state: connected, connecting, not connected, or why connecting failed.
- Lautta can mount and unmount memory cards and USB drives through netvfs, including drives Sailfish OS does not mount by itself.
- Lautta can open Settings › Storage through netvfs.
- Encrypted memory cards and USB drives show up in Lautta: a locked one as locked, an unlocked one as a normal drive.
