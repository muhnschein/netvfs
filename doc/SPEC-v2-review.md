# SPEC-v2 review points

A review of SPEC-v2 against SPEC, SPEC-sftp and SPEC-smb raised points where SPEC-v2
changed a requirement of those documents in effect. The points below are resolved in the
code, which cites them by number, and in the specs. Each states the rule as implemented.

## 2. Requirements of SPEC, SPEC-sftp and SPEC-smb that SPEC-v2 changes

**2.1 SEC-2, M-4.** The only SMB profile without signing or encryption is `guest`. It is
allowed only for the Files service, with the account's consent (`allow_insecure`),
and is never chosen automatically (XSEC-2) or used for backups (XA-4). The SSH
algorithm lists have no setting (SPEC SEC-2, SPEC-sftp S-2).

**2.9 M-8.** With the `share` option empty, SMB paths are `/<share>/<rest>` (server mode,
XM-2). Backups need a share: a configuration without one is refused for the Backup
service (XA-4).

**2.15 A-6, V7.** Accounts that have no stored secret by design, `auth_mode=interactive`
and the SMB profile `guest`, get empty credentials instead of `AuthFailed` (XA-7). The
update flow verifies them with the stored settings, which also clears the "not signed
in" state a device restore leaves (SPEC 3.5).

**2.17 SPEC 6.2.** `files_root` is a setting of the `<p>-files` service, as `backups_path`
is of `<p>-backup`; it is read from and written to that service.

**2.18 SPEC 6.4.** A Files run records attention with the same keys and values as a
backup run, because both services share the server identity and the credentials. It
therefore also pauses backups until the update flow clears it.
`CredentialsNeedUpdateFrom` names the service that noticed it (`<p>-files` or
`<p>-backup`).

**2.19 SPEC 7.2, 7.3, 7.5.** Verification depends on the service. For backups it is SPEC
7.2 (`makePath`, probe file, free space). For Files it authenticates, checks that the
start folder (`files_root`, empty for the backend's base folder) is a folder
(`NotADirectory` otherwise) and queries free space where available; nothing is
created or written, so read-only shares and guest access verify. The creation and
update flows verify for backups when the account backs up, else for Files.

**2.20 SPEC 7.3 step 3.** The server identity confirmation is shown when the server
presents an identity that is not pinned (`ServerIdentityUnknown`, XC-16), which only
SFTP does.
