# SMB account and backend

Companion to [SPEC.md](SPEC.md). That document defines the architecture, the account model, the UI flows and the Buteo plugins; this one defines everything specific to SMB.

| | |
|---|---|
| Provider id | `smb` |
| Service | `smb-backup` (type `storage`) |
| Backend plugin | `libremotefs-smb.so`, statically containing libsmb2 |
| Library | libsmb2, upstream `master` at commit `e80c1a48019ac975e0065b8d0a99ed71fc3ab8df` (2026-09-30) or a later reviewed commit. **Not** the 6.2 release |
| Reference peer | Samba `smbd` and `smbclient` |
| Ships only if | gate G-SMB holds (SPEC.md 10.2) |

Evidence tags are as in SPEC.md. **[test]** refers to the runs listed in section 7.

---

## 1. Account fields

| Field | Default | Notes |
|---|---|---|
| Server | | DNS name or IP literal |
| Port | 445 | |
| Share | | share name, typed by the user (no browsing) |
| User name | | |
| Domain | empty | optional workgroup or domain |
| Password | | must not be empty |
| Require encryption | on | see M-3 |
| Backups folder | `Sailfish OS/Backups` | relative to the share root |

## 2. Settings keys and secret

In addition to the common keys (SPEC.md 6.2):

| Key | Type | Meaning |
|---|---|---|
| `remotefs/smb/share` | string | share name |
| `remotefs/smb/domain` | string | optional |
| `remotefs/smb/require_encryption` | bool | default true |

The secret stored in signond is the password, unchanged.

---

## 3. Protocol policy

- **M-1 Dialects.** SMB 3.0, 3.0.2 and 3.1.1 only: `smb2_set_version(SMB2_VERSION_ANY3)`. There is no fallback to SMB 2.x or SMB1 and no setting to enable one. Samba negotiated 3.1.1 **[test]**.
- **M-2 Signing.** Always required: `smb2_set_security_mode(SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED)` and `smb2_set_sign(smb2, 1)`.
- **M-3 Encryption.**
  - *Require encryption* on (default): `smb2_set_seal(smb2, 1)`. The connection fails if the server does not negotiate encryption **[test]**.
  - Off: `smb2_set_seal()` is not called. The library then still uses encryption where the server or share mandates it and otherwise runs signed but unencrypted **[test]**. The settings page labels this state "Signed, not encrypted".
- **M-4 Authentication.** NTLMv2 through NTLMSSP only: `smb2_set_authentication(smb2, SMB2_SEC_NTLMSSP)`, with user, password and optional domain set explicitly. Guest and anonymous sessions are not offered.
- **M-5** The password is always set with `smb2_set_password()`. libsmb2 can also read passwords from a file named by the `NTLM_USER_FILE` environment variable **[src: `lib/init.c`]**; code review of the pinned commit MUST confirm that an explicit password takes precedence.
- **M-6** Kerberos and DCE/RPC (share enumeration) are compiled out (SPEC.md P-3).
- **M-7** `smb2_set_timeout()` is set to the request timeout of SPEC.md C-14.

### Server identity

SMB has nothing equivalent to an SSH host key, so `Backend::connect()` returns an empty `ServerIdentity` and the creation flow skips the confirmation step.

What protects the session instead:

- Signing keys derive from the password. A peer that does not know the password cannot produce valid signatures, so mandatory signing authenticates the server to the client as well. This depends on the library checking the signature of every response; the pinned commit includes the August 2026 fix for a case where that check was skipped, and test M-T12 exists to keep it that way.
- With encryption required, file contents and names are not visible on the network.

What remains:

- Any server the device connects to under this account name receives an NTLMv2 challenge response, which allows offline password guessing. The account's password should be strong and used for nothing else. The creation dialog says so in one line.
- NTLM is being phased out by Microsoft. Servers that disable NTLM cannot be used by this backend. Samba standalone servers and NAS products are unaffected.

---

## 4. Paths

- **M-8** Paths are relative to the share root and use `/` at the libsmb2 API **[test]**. A leading `/` in the backups folder is stripped.
- **M-9** Path components containing any of `\ : * ? " < > |`, or ending in a space or a dot, are rejected in the UI before any connection is made.

---

## 5. Operations

| `Backend` call | libsmb2 |
|---|---|
| `authenticate` | `smb2_init_context`, policy calls of section 3, `smb2_connect_share(server[:port], share, user)` |
| `stat` | `smb2_stat` |
| `list` | `smb2_opendir`, `smb2_readdir`, `smb2_closedir` |
| `makePath` | `smb2_stat` then `smb2_mkdir` per component |
| `remove` | `smb2_unlink` |
| `rename` | `smb2_unlink(to)` if it exists, then `smb2_rename` |
| `freeSpace` | `smb2_statvfs` |
| `upload` | `smb2_open(O_WRONLY\|O_CREAT\|O_TRUNC)`, `smb2_write` loop, `smb2_fsync`, `smb2_close` |
| `download` | `smb2_open(O_RDONLY)`, `smb2_read` loop |
| `disconnect` | `smb2_disconnect_share`, `smb2_destroy_context` |

- **M-10** libsmb2 performs negotiation, session setup and tree connect in one call, which needs the credentials. `Backend::connect()` therefore only resolves the server and checks that the port answers, and `Backend::authenticate()` makes that one library call.
- **M-11** Chunk size is the smaller of `smb2_get_max_write_size()` (or the read equivalent) and 1 MiB. Samba offered 8 MiB; a 64 MiB transfer in 1 MiB chunks over an encrypted session completed and verified **[test]**.
- **M-12** `cancel()` sets a flag checked between chunks. Using the library's asynchronous API with a poll loop, so that a stalled request can be abandoned at once, is a permitted refinement.
- **M-13** An `smb2_context` is used from one thread only.

### Error mapping

The error string from `smb2_get_error()` is not reliable: a wrong password and an unknown share both produced "Read from socket failed" **[test]**. `smb2_get_nterror()` was correct in every case tried **[test]** and is the only input to classification.

| NT status | Core error |
|---|---|
| `STATUS_LOGON_FAILURE` (0xC000006D, seen for wrong password and unknown user **[test]**), account disabled, locked or expired, password expired | `AuthFailed` |
| `STATUS_BAD_NETWORK_NAME` (0xC00000CC, seen for unknown share **[test]**) | `NotFound` ("share not found") |
| `STATUS_ACCESS_DENIED` | `PermissionDenied` |
| `STATUS_OBJECT_NAME_NOT_FOUND`, `STATUS_OBJECT_PATH_NOT_FOUND` | `NotFound` |
| `STATUS_OBJECT_NAME_COLLISION` | `AlreadyExists` |
| `STATUS_DISK_FULL`, quota exceeded | `NoSpace` |
| no NT status, TCP connect failed | `NetworkUnreachable` or `Timeout` |
| no NT status, failure after TCP connect | `SecurityPolicy` ("the server closed the connection; it may not support SMB 3, signing or encryption") |
| anything else | `ProtocolError` with the status code |

Only `AuthFailed` sets the attention state (SPEC.md 6.4). `SecurityPolicy` does not, because a server reboot or a transient fault looks the same.

---

## 6. Limitations of the library

- Encryption cipher AES-128-CCM and signing algorithm AES-128-CMAC only **[test, src: `lib/smb2-cmd-negotiate.c`]**. A server configured to accept only AES-GCM or only AES-256 will refuse the session.
- Crypto primitives are the library's own implementation, not the platform's OpenSSL.
- The public headers are not self-contained: `<stdint.h>` and `<time.h>` must be included before `<smb2/smb2.h>` **[test]**.
- No multichannel; DFS referrals are untested and unsupported.

---

## 7. Interoperability matrix

This is the pass criterion for the SMB part of the interop suite (SPEC.md 12.2) and item 2 of gate G-SMB. Every positive case performs: connect with the policy of section 3, `makePath`, 64 MiB upload, list, free space, download, and SHA-256 comparison on the client and on the server's disk.

| # | Case | Expected | Status |
|---|---|---|---|
| M-T1 | Samba 4.19.5 strict: `server min protocol = SMB3_11`, `server signing = mandatory`, `server smb encrypt = required`, `ntlm auth = ntlmv2-only` | pass; `smbstatus` shows SMB3_11, AES-128-CCM, AES-128-CMAC | verified |
| M-T2 | Samba 4.19.5 with distribution-default security settings, encryption required by the account | pass, dialect 3.1.1 | verified (see note) |
| M-T3 | server with `server smb encrypt = off`, encryption required by the account | refused | verified |
| M-T4 | same server, *Require encryption* off | pass | verified |
| M-T5 | wrong password; unknown user | refused, `STATUS_LOGON_FAILURE` | verified |
| M-T6 | unknown share | refused, `STATUS_BAD_NETWORK_NAME` | verified |
| M-T7 | client pinned to SMB 2.1 against a server that requires 3.1.1 | refused | verified |
| M-T8 | file uploaded by us is fetched by `smbclient`; file uploaded by `smbclient` is listed by us | identical SHA-256 | verified |
| M-T9 | server limited to SMB 2.x (`server max protocol = SMB2_10`) | refused with `SecurityPolicy` | to do |
| M-T10 | current Samba release | pass | to do |
| M-T11 | Windows Server or Windows 11 share | pass | to do |
| M-T12 | proxy that alters one byte of a signed response | connection aborted | to do |
| M-T13 | packet capture with encryption required: no cleartext payload or file names | confirmed | to do |
| M-T14 | server accepting only AES-256 or only GCM ciphers | refused with `SecurityPolicy`; documented for users | to do |
| M-T15 | at least one NAS product (Samba-based or not) | pass | to do |
| M-T16 | full share or quota | `NoSpace`, no partial file left | to do |
| M-T17 | cancel during upload and during download | `Canceled`, `.part` removed | to do |
| M-T18 | backups folder containing a space and a non-ASCII character | pass | to do |
| M-T19 | all of the above under AddressSanitizer and UndefinedBehaviorSanitizer | clean | to do (gate item 3) |

Note on M-T2: during the transfer `smbstatus` printed the session's encryption as `partial(AES-128-CCM)`. M-T13 settles what is actually on the wire in that configuration.

Environment of the verified runs: x86_64, Ubuntu 24.04; libsmb2 at the pinned commit built static with `-DENABLE_LIBKRB5=OFF -DENABLE_EXAMPLES=OFF` and linked without its DCE/RPC library; Samba 4.19.5 `smbd` and `smbclient` from the distribution.

Strict server used for M-T1:

```
[global]
  server role = standalone server
  server min protocol = SMB3_11
  server signing = mandatory
  server smb encrypt = required
  ntlm auth = ntlmv2-only
  map to guest = never
[backup]
  path = /srv/smb/backup
  valid users = backup
  read only = no
```
