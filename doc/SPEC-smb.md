# SMB account and backend

Companion to [SPEC.md](SPEC.md). That document defines the architecture, the account model, the UI flows and the Buteo plugins; this one defines everything specific to SMB.

| | |
|---|---|
| Provider id | `smb` |
| Services | `smb-backup` (type `storage`), `smb-files` (type `netvfs-files`, SPEC-v2 XA-1) |
| Backend plugin | `libnetvfs-smb.so`, a shim over the Rust backends in `libnetvfs-rs.so` (provider `smb`) |
| Implementation | `rust/netvfs-smb`: netvfs's own SMB client, SMB 3.1.1 only ([RUST.md](RUST.md) "netvfs-smb") |
| Supported servers | SMB 3.1.1 servers: Samba and Windows. The interop suite runs Samba 4.19.5 and a current Samba release; a CI job runs Windows's own server |

netvfs-smb implements no cryptographic primitive. NTLMv2 and SPNEGO come from the `sspi` crate (0.23). AES-128-GCM, AES-256-GCM, AES-128-CMAC, HMAC-SHA256 and SHA-512 come from the RustCrypto crates `aes`, `aes-gcm`, `cmac`, `hmac` and `sha2`, and random numbers from `getrandom`; only the module `crypto.rs` uses them (RUST.md "The crypto fence").

Evidence tags are as in SPEC.md. **[test]** means a case of the interop suite of section 7 checks it.

---

## 1. Account fields

The creation dialog renders the provider descriptor `accounts/descriptors/smb.json` (SPEC-v2 XA-5):

| Field | Default | Notes |
|---|---|---|
| Server | | DNS name or IP literal |
| Port | 445 | optional |
| Share | empty | empty: server mode, the shares are the root's folders (SPEC-v2 XM-2) |
| Show admin shares | off | server mode only |
| Security profile | `strict` | `strict`, `signed` or `guest` (SPEC-v2 XM-1) |
| Allow insecure connections | off | `guest` only; the account's consent (SPEC-v2 XA-4) |
| User name | | not with `guest` |
| Domain | empty | optional workgroup or domain; not with `guest` |
| Password | | must not be empty; not with `guest` |
| Backups folder | `Sailfish OS/Backups` | Backup service only; relative to the share root |
| Files folder | empty | Files service only (`files_root`) |

## 2. Settings keys and secret

In addition to the common keys (SPEC.md 6.2):

| Key | Type | Meaning |
|---|---|---|
| `netvfs/smb/share` | string | share name; empty for server mode |
| `netvfs/smb/domain` | string | optional |
| `netvfs/smb/security_profile` | string | default `strict` (XM-1) |
| `netvfs/smb/shares` | string list | share names the user saved (XM-3) |
| `netvfs/smb/show_admin_shares` | bool | list shares whose names end in `$` (XM-7) |
| `netvfs/smb/allow_insecure` | bool | consent to the `guest` profile (XA-4) |

The secret stored in signond is the password, unchanged. A `guest` account has no secret (SPEC-v2 XA-7).

---

## 3. Protocol policy

- **M-1 Dialects.** SMB 3.1.1 only: NEGOTIATE offers dialect 0x0311 alone. A server without SMB 3.1.1 answers `STATUS_NOT_SUPPORTED` and the sign-in fails with `SecurityPolicy` "the server does not support SMB 3.1.1" **[test]**. A response that selects another dialect, a cipher or signing algorithm that was not offered, a preauth hash other than SHA-512, or compression is refused (`SecurityPolicy`). There is no setting that offers another dialect.
- **M-2 Signing.** Profiles `strict` and `signed` set SIGNING_REQUIRED; the only signing algorithm offered is AES-128-CMAC. The final SESSION_SETUP response must be signed with the new session's key and verify (MS-SMB2 3.2.5.3.1). That key derives from the preauth hash over NEGOTIATE and every SESSION_SETUP message, so a change to any of them, or a server that does not know the password, fails the sign-in **[test]**.
- **M-3 Encryption.** The ciphers offered are AES-128-GCM and AES-256-GCM, in that order.
  - Profile `strict` (default): a server without a common cipher is refused before SESSION_SETUP; every request after SESSION_SETUP is encrypted, and every response must be encrypted **[test]**.
  - Profile `signed`: requests are encrypted where the server marks the session or the share for encryption (ENCRYPT_DATA); otherwise the session runs signed but unencrypted. A session or share marked for encryption without a common cipher is refused **[test]**.
  - Profile `guest`: no signing and no encryption; a server that marks the session or the share for encryption is refused.
- **M-4 Authentication.** Profiles `strict` and `signed` sign in with NTLMv2 in SPNEGO (`sspi`), with user, password and optional domain set explicitly; they refuse an empty user name or password before anything is sent. Profile `guest` signs in with NTLMSSP anonymous and ignores the account's credentials. A session the server marks IS_GUEST or IS_NULL is refused outside `guest` (SPEC-v2 XM-1) **[test]**. The user name `/GUEST` (also with a domain) is refused, because sspi skips the mechListMIC check for it; so is a password starting with `$NTLM$`, which sspi would take for an NT hash.
- **M-5** The password comes only from the account's credentials. netvfs-smb reads no environment variable and no file for credentials; `NTLM_USER_FILE` has no effect **[test]**.
- **M-6** No Kerberos: sspi's Negotiate package is limited to NTLM, with no KDC lookup and no `krb5.conf` or environment reads.
- **M-7** Requests time out after the request timeout of SPEC.md C-14 **[test]**. A request timeout ends the connection: later calls return `ConnectionLost`.

### Server identity

SMB has nothing equivalent to an SSH host key, so `Backend::connect()` returns no `ServerIdentity` and the creation flow skips the confirmation step.

What protects the session instead:

- The signing and encryption keys derive from the password. A peer that does not know the password cannot produce the signed final SESSION_SETUP response (M-2), so the sign-in authenticates the server to the client.
- After sign-in every response must be encrypted (`strict`, or a marked session or share) or validly signed (`signed`), error responses included. A response for another session, one that answers no outstanding request, a compressed frame, or a request from the server ends the connection. Compound responses are checked element by element **[test]**.
- With encryption, file contents and names are not visible on the network **[test]**.

What remains:

- On a signed, unencrypted connection an interim `STATUS_PENDING` response is not verified, as MS-SMB2 3.2.5.1.3 specifies. The client takes its credit grant (the credit count is capped at 8192) and lets it extend the request's deadline, at most 8 times per request. An attacker on the path can therefore delay a request's timeout or inflate the credit window. With encryption interim responses must be encrypted too.
- The NTLM key exchange (KEY_EXCH) uses sspi's own RC4 implementation. `rust/netvfs-smb/tests/sspi_ntlm.rs` checks sspi's NTLMv2 output against the MS-NLMP 4.2.4 test vectors, recomputed with the RustCrypto crates `md-5` and `rc4`.
- Any server the device connects to under this account name receives an NTLMv2 challenge response, which allows offline password guessing. The account's password should be strong and used for nothing else. The creation dialog says so in one line.
- Servers that disable NTLM cannot be used by this backend. Samba standalone servers and NAS products are unaffected.
- Profile `guest` has no integrity, confidentiality or server authentication; it needs the account's insecure consent and is never used for backups (SPEC-v2 XA-4).

---

## 4. Paths

- **M-8** Paths are relative to the share root and use `/` at the backend API; on the wire they are UTF-16LE with `\` separators **[test]**. A leading `/` in the backups folder is stripped. In server mode paths are `/<share>/<rest>` (SPEC-v2 XM-2).
- **M-9** Path components containing any of `\ : * ? " < > |` or a control character, or ending in a space or a dot, are rejected in the UI before any connection is made, and the backend refuses them before any request is sent (`WindowsNames`, SPEC-v2 XM-4).

---

## 5. Operations

| `Backend` call | SMB requests |
|---|---|
| `connect` | DNS lookup and a TCP connection to the port, closed again (M-10) |
| `authenticate` | NEGOTIATE, SESSION_SETUP rounds, TREE_CONNECT to the share (server mode: `IPC$`) |
| `stat` | compound CREATE, CLOSE |
| `list` | compound CREATE and QUERY_DIRECTORY, then QUERY_DIRECTORY until `STATUS_NO_MORE_FILES`, CLOSE |
| `makeDir` | compound CREATE of a folder, CLOSE |
| `removeFile`, `removeDir` | compound CREATE, SET_INFO FileDispositionInformation, CLOSE |
| `rename` | compound CREATE, SET_INFO FileRenameInformation (`ReplaceIfExists` for `Replace`), CLOSE |
| `setAttributes` | compound CREATE, SET_INFO FileBasicInformation, CLOSE |
| `spaceInfo` | compound CREATE, QUERY_INFO FileFsFullSizeInformation, CLOSE |
| `upload`, `openWrite` | CREATE, pipelined WRITE, FLUSH, CLOSE |
| `download`, `openRead` | CREATE, pipelined READ, CLOSE |
| `keepAlive` | ECHO |
| `disconnect` | LOGOFF, then the TCP connection is closed |

- **M-10** `Backend::connect()` sends nothing: NEGOTIATE and SESSION_SETUP need the profile and the credentials, so `connect()` only resolves the server and checks that the port answers, and `authenticate()` signs in.
- **M-11** READ and WRITE chunks are the server's MaxReadSize and MaxWriteSize, each capped at 1 MiB, or 64 KiB when the server does not allow multi-credit requests **[test]**. Up to 4 MiB is in flight per transfer or handle.
- **M-12** `cancel()` makes the waiting call return `Canceled` at once. The client sends SMB2 CANCEL for the abandoned request and keeps the connection; a CREATE whose caller went away is closed when its response comes **[test]**.
- **M-13** Each backend has its own TCP connection and session; backends share no state, so several run in parallel on different threads. A backend is used by one thread at a time (SPEC.md C-8) **[test]**.

A listing skips entries named `""`, `.` or `..` and entries whose name contains `/` or NUL; the rest of the listing is delivered without an error (SPEC-v2 XC-6).

### Error mapping

The NT status of a response is the only input to classification. During sign-in (NEGOTIATE, SESSION_SETUP, TREE_CONNECT) a refusal that is about neither the credentials nor the share name is `SecurityPolicy`.

| NT status | Core error |
|---|---|
| `STATUS_LOGON_FAILURE` (wrong password, unknown user), `STATUS_WRONG_PASSWORD`, `STATUS_NO_SUCH_USER`, account disabled, locked out, expired or restricted, invalid logon hours, password expired or to be changed | `AuthFailed` |
| `STATUS_BAD_NETWORK_NAME` (unknown share) | `NotFound` ("share not found") |
| `STATUS_ACCESS_DENIED` | `PermissionDenied`; during sign-in `SecurityPolicy` (the account may not use the share, or no common cipher) |
| `STATUS_OBJECT_NAME_NOT_FOUND`, `STATUS_OBJECT_PATH_NOT_FOUND` | `NotFound` |
| `STATUS_OBJECT_NAME_COLLISION` | `AlreadyExists` |
| `STATUS_DISK_FULL`, `STATUS_QUOTA_EXCEEDED` | `NoSpace` |
| `STATUS_FILE_IS_A_DIRECTORY`, `STATUS_NOT_A_DIRECTORY`, `STATUS_DIRECTORY_NOT_EMPTY` | `IsADirectory`, `NotADirectory`, `DirectoryNotEmpty` |
| `STATUS_SHARING_VIOLATION` | `Locked` |
| `STATUS_IO_TIMEOUT` | `Timeout` |
| `STATUS_PATH_NOT_COVERED`, `STATUS_DFS_UNAVAILABLE` | `Unsupported`, detail "DFS referral" (SPEC-v2 XM-9) |
| no response, TCP connect failed | `NetworkUnreachable` or `Timeout` |
| connection closed during sign-in | `SecurityPolicy` ("the server closed the connection; it may not support SMB 3.1.1, signing or encryption") |
| connection closed, or a response that breaks an integrity rule, after sign-in | `ConnectionLost` |
| anything else | `ProtocolError` with the status code |

Every message names the NT status in hex, and the detail carries its name (SPEC-v2 XC-24). Only `AuthFailed` sets the attention state (SPEC.md 6.4). `SecurityPolicy` does not, because a server reboot or a transient fault looks the same.

---

## 6. Limitations

- Encryption with AES-128-GCM and AES-256-GCM only, signing with AES-128-CMAC only. A server that accepts only AES-CCM ciphers, or signs only with AES-GMAC or HMAC-SHA256, is refused with `SecurityPolicy` **[test]**.
- No multichannel, no DFS referrals, no Kerberos, no compression, no oplocks or leases (server notifications are dropped unread).

---

## 7. Interoperability matrix

The pass criterion for the SMB part of the interop suite (SPEC.md 12.2, `tests/interop/smb`), and items 2 and 3 of gate G-SMB (SPEC.md 10.2). Every positive case performs: connect with the policy of section 3, `makePath`, 64 MiB upload, list, free space, download, and SHA-256 comparison on the client and on the server's disk. Cases run with profile `strict` unless the row names another. The last column names where the case runs: `tst_interop_smb` (the C++ driver through the shim) and `samba.rs` (`rust/netvfs-smb/tests/samba.rs`).

| # | Case | Expected | Where |
|---|---|---|---|
| M-T1 | Samba 4.19.5 strict: `server min protocol = SMB3_11`, `server signing = mandatory`, `server smb encrypt = required`, `ntlm auth = ntlmv2-only` | pass; `smbstatus` shows SMB3_11, AES-128-GCM, AES-128-CMAC | `strictServer`, `samba.rs` |
| M-T2 | Samba 4.19.5 with distribution-default security settings | pass, SMB 3.1.1 with AES-128-GCM | `defaultServer` |
| M-T3 | server with `server smb encrypt = off` | refused before SESSION_SETUP | `encryptionRequiredServerOff`, `samba.rs` |
| M-T4 | same server, profile `signed` | pass, signed, not encrypted | `encryptionOffSigned`, `samba.rs` |
| M-T5 | wrong password; unknown user | `AuthFailed`, `STATUS_LOGON_FAILURE` | `wrongCredentials`, `samba.rs` |
| M-T6 | unknown share | `NotFound`, `STATUS_BAD_NETWORK_NAME` | `unknownShare`, `samba.rs` |
| M-T7 | a NEGOTIATE that offers SMB 2.1 only, against a server that requires 3.1.1; a server limited to SMB 3.0 | refused | `samba.rs`, `profilesOnOldDialects` |
| M-T8 | file uploaded by us is fetched by `smbclient`; file uploaded by `smbclient` is listed and fetched by us | identical SHA-256 | `strictServer` |
| M-T9 | server limited to SMB 2.x (`server max protocol = SMB2_10`) | `SecurityPolicy`, NT status 0xc00000bb named | `smb2OnlyServer` |
| M-T10 | current Samba release, strict configuration | pass | `currentSamba` |
| M-T11 | Windows's own SMB server, local account | pass | CI job `windows-smb` (`rust/netvfs-smb/tests/windows.rs`) |
| M-T12 | proxy that alters one byte of a signed or encrypted response after sign-in; of the final SESSION_SETUP response | `ConnectionLost`; `SecurityPolicy` naming the signature | `tamperedResponse`, `tamperedSessionSetup`, `samba.rs` |
| M-T13 | packet capture with encryption required: no cleartext payload or file names | confirmed | `noCleartextOnWire` |
| M-T14 | server with AES-256-GCM as its only cipher; servers with only AES-CCM ciphers (encryption required or desired); a server signing only with AES-GMAC or HMAC-SHA256 | AES-256-GCM passes; the others `SecurityPolicy` | `aes256GcmOnly`, `unsupportedAlgorithms`, `samba.rs` |
| M-T15 | at least one NAS product | pass | no case |
| M-T16 | full share | `NoSpace`, no partial file left | `fullShare`, `samba.rs` |
| M-T17 | cancel during upload and during download | `Canceled` within 2 s, `.part` removed | `cancelUpload`, `cancelDownload` |
| M-T18 | backups folder containing a space and a non-ASCII character | pass | `nonAsciiFolder` |
| M-T19 | the suite on a build with AddressSanitizer and UndefinedBehaviorSanitizer | clean | `tests/interop/smb/run.sh` on the sanitizer build |

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

The servers run in containers started by `tests/interop/smb/run.sh`; `tests/interop/smb/server/conf` holds one configuration per case. Proxies in front of them alter or stall replies (`flipproxy.py`).

---

## 8. API v2 implementation notes (SPEC-v2 §6.2)

How the backend implements XM-1..XM-9, where the v2 text leaves a choice.

| Item | Decision |
|---|---|
| XM-1 profiles | Option `security_profile` = `strict` (default) / `signed` / `guest`; without it, or empty, the profile is `strict`. Any other value is `SecurityPolicy` "unknown SMB security profile" (nothing weaker is guessed, XSEC-2). Every profile negotiates SMB 3.1.1. The "allowed for service" column is enforced by `AccountSession` (XA-4), not here. |
| XM-1 guest mapping | The SessionFlags of the final SESSION_SETUP response: `IS_GUEST` or `IS_NULL` on a session of `strict` or `signed` is `SecurityPolicy`, checked before any key is derived. Verified against Samba with `map to guest = Bad User`, in share and in server mode. |
| XM-2 server mode | Empty `share`. One TCP connection and one session; `IPC$` is its main tree, connected by `authenticate()`, and serves the share list. Shares are trees of the same session, connected on first use of `/<share>/…`; at most four at a time. A fifth disconnects the least recently used one without open files, or fails with `TooManyConnections` when every one has open files. The password is not kept after sign-in. `/`: `list`, `stat` only, everything else `PermissionDenied`; `/<share>`: `removeDir`, `rename`, `openWrite`/`upload` `PermissionDenied`, `makeDir` succeeds for an existing share (needed by `makePath`) and is `PermissionDenied` for a missing one. Moving between shares is `Unsupported`. |
| XM-3 share list | `shares` (a string list, or a comma-separated string), trimmed, invalid names dropped, de-duplicated without regard to case; then the enumerated shares not yet listed. Entries are `Directory`. |
| XM-4 entries | `created` from the birth time; `Hidden`/`ReadOnly`/`System` from the file attributes. `CaseInsensitive` and `WindowsNames` are reported unconditionally: Windows and Samba's default `case sensitive = auto` behave case-insensitively for SMB clients without POSIX extensions. `maxNameBytes` 255. No `Symlinks` capability; `lstat` is `stat`. |
| XC-4 names | UTF-16LE on the wire, WTF-8 in netvfs: an unpaired surrogate becomes its three-byte form, the entry carries `NameNotUtf8`, and the name maps back to the same UTF-16 unit, so such files remain usable. |
| XM-5 rename | `rename(NoReplace)` is FileRenameInformation without `ReplaceIfExists` (`NativeNoReplace`); `rename(Replace)` sets `ReplaceIfExists` (`AtomicReplace`). A folder target is refused first (XC-10). |
| XM-6 handles | `ReadHandle`/`WriteHandle` keep one open file; reads and writes are pipelined in chunks of M-11 with at most 4 MiB requested and not yet consumed per handle; `readAhead()` starts requests up to that bound. `Resume` opens without truncating and requires size == `resumeOffset`, else `ProtocolError`. `setAttributes` sets `modified`/`accessed` with one CREATE + SET_INFO (FileBasicInformation) + CLOSE compound on files and folders; `mode` is `Unsupported` before anything is sent; times before 1970 are `Unsupported`. `WriteOptions::modified` is applied after the close (`SetModifiedOnUpload`). |
| XM-7 enumeration | Option `share_enumeration` (default true, server mode only); `ShareEnumeration` is reported in server mode when it is on. In process: srvsvc NetrShareEnum level 1 over the `IPC$` tree's pipe (DCE/RPC bind, request and fragments, NDR decoding). Every count and string is capped before anything is allocated: at most 4096 shares, strings of at most 1024 UTF-16 units, a reply stub of at most 1 MiB. Disk shares only (`type & 0xff == STYPE_DISKTREE`); names ending in `$` are hidden unless `show_admin_shares=true`. |
| XM-9 DFS | `STATUS_PATH_NOT_COVERED` and `STATUS_DFS_UNAVAILABLE` are `Unsupported` with detail "DFS referral". Verified with a Samba `msdfs root` share. |
| XT-5 | SMB has no server identity (section 3): `connect()` sends nothing, `authenticate()` sends the NTLMSSP exchange. What the identity check does elsewhere is done here by the profile failing closed: the signed final SESSION_SETUP response proves the server knows the password, required encryption ends the session when the server cannot provide it, and a guest mapping is refused. |

Interop matrix additions (`tst_interop_smb`):

| # | Case | Expected | Case |
|---|---|---|---|
| M-T20 | SMB 2.1-only and SMB 3.0-only servers, every profile, share and server mode | `SecurityPolicy` | `profilesOnOldDialects` |
| M-T22 | `map to guest = Bad User`, unknown user, `strict`/`signed` | `SecurityPolicy` (guest mapping) | `guestMappingRefused` |
| M-T23 | guest share, `guest` profile | pass | `guestProfile` |
| M-T24 | server mode: share list (saved and enumerated, disk shares, `$` hidden), root and share-level refusals, four-share limit with open files | pass | `serverModeRoot`, `serverModeOperations`, `serverModeContextLimit` |
| M-T26 | DFS link | `Unsupported`, detail "DFS referral" | `dfsReferral` |
