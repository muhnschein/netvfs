# Specifications

| Document | Scope |
|---|---|
| [SPEC.md](SPEC.md) | v1 core specification (backup accounts) |
| [SPEC-sftp.md](SPEC-sftp.md) | v1 SFTP account and backend |
| [SPEC-smb.md](SPEC-smb.md) | v1 SMB account and backend |
| [SPEC-v2.md](SPEC-v2.md) | API v2: file-browser extensions, new backends, bridge |
| [SPEC-v2-review.md](SPEC-v2-review.md) | SPEC-v2 checked against the v1 documents (section 0 action item) |

The v1 documents were written under the working name `remotefs`. The project
is now `netvfs`: read `remotefs`, `RemoteFs`, `libremotefs`,
`org.remotefs.accounts` and the `remotefs/` settings prefix as `netvfs`,
`NetVfs`, `libnetvfs`, `org.netvfs.accounts` and `netvfs/`. Requirement ids
(C-*, S-*, M-*, ...) are unchanged and are cited by the code.
