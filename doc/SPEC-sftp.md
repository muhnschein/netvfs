# SFTP account and backend

Companion to [SPEC.md](SPEC.md). That document defines the architecture, the account model, the UI flows and the Buteo plugins; this one defines everything specific to SFTP.

| | |
|---|---|
| Provider id | `sftp` |
| Services | `sftp-backup` (type `storage`), `sftp-files` (type `netvfs-files`, SPEC-v2 XA-1) |
| Backend plugin | `libnetvfs-sftp.so`, a shim over the Rust backends in `libnetvfs-rs.so` (provider `sftp`); its root object is the SSH key tools |
| Implementation | `rust/netvfs-sftp`: the SSH transport is russh 0.64.1 with ring as its crypto provider; the SFTP v3 client is netvfs's own ([RUST.md](RUST.md) "netvfs-sftp") |
| Supported servers | OpenSSH `sshd` with its `sftp-server` or `internal-sftp`. The interop suite runs OpenSSH 10.3p1, 9.6p1 and 8.9p1 |

netvfs-sftp implements no cryptographic primitive. The SSH cryptography is russh's, done by ring and by the RustCrypto crates in russh's dependency tree; key files are read and written by the `ssh-key` crate (RUST.md "Dependencies").

Evidence tags are as in SPEC.md. **[test]** means a case of the interop suite of section 8 checks it.

---

## 1. Account fields

The creation dialog renders the provider descriptor `accounts/descriptors/sftp.json` (SPEC-v2 XA-5):

| Field | Default | Notes |
|---|---|---|
| Server | | DNS name or IP literal |
| Port | 22 | optional |
| User name | | |
| Sign-in method | Password | *Password*, *Generate new key*, *Import key file* or *Interactive* (SPEC-v2 XS-11) |
| Backups folder | `Sailfish OS/Backups` | Backup service only; see section 6 |
| Files folder | empty | Files service only (`files_root`); empty is the start folder |

## 2. Settings keys and secret

In addition to the common keys (SPEC.md 6.2):

| Key | Type | Meaning |
|---|---|---|
| `netvfs/sftp/auth_mode` | string | `password` (the default), `publickey` or `interactive` |
| `netvfs/sftp/host_key` | string | pinned server key, `<algorithm> <base64 blob>` |
| `netvfs/sftp/host_key_seen` | string | set together with attention `server-identity-changed`; same format |
| `netvfs/sftp/public_key` | string | the account's own public key as an `authorized_keys` line (key mode); for display |

Secret stored in signond (SPEC.md 6.3):

| Mode | `Secret` |
|---|---|
| `password` | the password, unchanged |
| `publickey` | `netvfs-key-v1:` followed by the base64 encoding of the unencrypted private key in OpenSSH format |
| `interactive` | empty, or a password that answers password prompts (SPEC-v2 XA-7) |

The backend checks that the secret fits the mode before it sends anything: a key secret is never sent as a password, and a password is never read as a key (`AuthFailed`) **[test]**.

---

## 3. Connection policy

- **S-1** Client configuration on every connection: TCP connect and SSH handshake within the connect timeout (15 s, SPEC.md C-14); no compression; no automatic keep-alive and no inactivity timer (keep-alive is the caller's, SPEC-v2 XS-12); the host-key list narrowed to the pinned type when a key is pinned (S-5). The backend reads no SSH configuration, no `known_hosts` file and no agent.
- **S-2** The algorithm lists are fixed in `rust/netvfs-sftp/src/policy.rs`. No option, hidden or visible, widens them.

  | List | Algorithms, in order of preference |
  |---|---|
  | Key exchange | `mlkem768x25519-sha256`, `curve25519-sha256`, `curve25519-sha256@libssh.org` |
  | Ciphers | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` |
  | MACs | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com` (not used with these ciphers) |
  | Host keys | `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `rsa-sha2-512`, `rsa-sha2-256` |
  | Compression | `none` |

  The key exchange list also carries the client markers for RFC 8308 ext-info and OpenSSH's strict key exchange. There are no `ssh-rsa` (SHA-1) signatures, no DSA, no CBC ciphers, no finite-field Diffie-Hellman and no certificates. A server with nothing in common in one list fails with `SecurityPolicy` "The server offers no <list> algorithm this app accepts (it offers <the server's names>)", the offer capped at 512 bytes **[test]**.
- **S-3** The backend opens one session channel and requests the `sftp` subsystem on it, nothing else: no shell and no exec channel. Channels the server opens are refused. Servers that force `internal-sftp` work **[test]**.
- **S-4** One SSH connection per backend instance. A backend is used by one thread at a time (SPEC.md C-8); russh runs the connection in a task on the runtime of `libnetvfs-rs.so`.

Negotiated against the interop servers **[test]**:

| Server | Key exchange |
|---|---|
| OpenSSH 10.3p1 | `mlkem768x25519-sha256` |
| OpenSSH 9.6p1, 8.9p1 | `curve25519-sha256` |
| OpenSSH 10.3p1 limited to `curve25519-sha256` | `curve25519-sha256` |

---

## 4. Server identity (trust on first use)

- **S-5** When `netvfs/sftp/host_key` is set, the host-key list is narrowed to the signature algorithms of the pinned key type, so that a server holding several host keys presents the pinned one:

  | Pinned type | Requested |
  |---|---|
  | `ssh-ed25519` | `ssh-ed25519` |
  | `ecdsa-sha2-nistp256/384/521` | the same single algorithm |
  | `ssh-rsa` | `rsa-sha2-512,rsa-sha2-256` |

  A server that no longer offers the pinned type is connected to once more without the restriction, so that the caller sees the key the server presents now.
- **S-6** `Backend::connect()` returns the server's host key as `ServerIdentity`: algorithm, key blob, and the `SHA256:` fingerprint, which is identical to the output of `ssh-keygen -lf` **[test]**.
- **S-7** The caller compares the key with the pin:
  - no pin (account creation): `ServerIdentityUnknown`; the UI shows algorithm and fingerprint and requires explicit acceptance;
  - equal: continue;
  - different: disconnect, record `host_key_seen`, return `ServerIdentityChanged`. No authentication request has been sent at this point **[test]**. `authenticate()` itself also refuses with `ServerIdentityChanged` when the key differs from the pin.
- **S-8** The confirmation dialog shows the algorithm and the `SHA256:` fingerprint in full, in a monospace face, with the hint that the same value is printed on the server by `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
- **S-9** A changed key is never accepted silently and never by the background plugin. Only the update flow (SPEC.md 7.5) can replace a pin.

---

## 5. Authentication

- **S-10** The backend first sends the `none` method to learn the offered methods, then uses the method of `auth_mode`.
- **S-11** Password mode: method `password` if it is offered. If only `keyboard-interactive` is offered, the stored password answers a single non-echo prompt; without a prompter any other prompt shape fails with `AuthFailed` "The server needs interactive sign-in, which is not supported" **[test]**. With a prompter, SPEC-v2 XS-11 applies.
- **S-12** Key mode: the stored Ed25519 or ECDSA key signs the `publickey` request **[test]**.
- **S-13** Without a prompter, a partial success (the server wants a second factor) is `AuthFailed` with a message that names multi-factor sign-in **[test]**. With a prompter, SPEC-v2 XS-11 applies.
- **S-14** When authentication is denied, the error text names the methods the server accepts, for example "This server only accepts SSH keys (publickey)." **[test]**.

### 5.1 Key handling (`SshKeyTool`)

The SFTP plugin's root object provides the key tools (`org.netvfs.SshKeyTools`, implemented in `rust/netvfs-sftp/src/keys.rs`).

| Method | Behaviour |
|---|---|
| `generate()` | creates an Ed25519 key; returns the public line and holds the private key in memory until the account is created |
| `importFile(path, passphrase)` | reads a private key file chosen with the system file picker; accepts Ed25519 and ECDSA (P-256, P-384, P-521) keys in OpenSSH, PKCS#8 (also encrypted) and SEC1 format; asks for the passphrase if the file is encrypted; re-exports unencrypted in OpenSSH format |
| `publicKey` | `authorized_keys` line `<algorithm> <base64> sailfish-backup` |
| `installWithPassword(params, password)` | signs in once with a password and appends the public line to `.ssh/authorized_keys` over SFTP |

- **S-15** Import refuses, each with a message that says what to do instead: RSA and DSA keys, security-key (`sk-`) keys, certificates, public key lines, PuTTY files, and PEM files encrypted with OpenSSL's `Proc-Type: 4,ENCRYPTED` scheme **[test]**. Before a passphrase is tried, the cost of the key derivation is bounded: bcrypt at most 1024 rounds, PBKDF2 at most 1,000,000 iterations, scrypt at most 64 MiB and parallelism 4; a file beyond that is refused whatever the passphrase. ECDSA keys whose private scalar OpenSSH stored without its leading zero byte import, also when passphrase-encrypted (RUST.md "Dependencies") **[test]**.
- **S-16** The key page shows the public line with *Copy to clipboard*, and offers *Install on server using password*. The password entered for that action is used once and is not stored.
- **S-17** `installWithPassword` creates `.ssh` with mode 0700 and `authorized_keys` with mode 0600 if missing, and appends only if the line is not already present **[test]**.
- **S-18** After a device restore the private key is gone (SPEC.md 3.5). The update flow offers the same choices as creation: generate, import, or switch to password.

---

## 6. Paths

- **S-19** A folder that starts with `/` is absolute on the server. Any other value is relative to the folder the SFTP session starts in, which the backend resolves once with `REALPATH "."`. On a chrooted account the chroot is the root **[test]**.
- **S-20** Backups create folders with mode 0700 and files with mode 0600 (SPEC-v2 XC-23). Existing modes are not changed **[test]**.

---

## 7. Operations

| `Backend` call | SFTP requests |
|---|---|
| `stat`, `lstat` | `STAT`, `LSTAT` (SPEC-v2 XC-7: `lstat` does not follow links) |
| `list` | `OPENDIR`, `READDIR` until end of file, `CLOSE` (SPEC-v2 XC-6) |
| `makeDir` | `MKDIR` with the connection option `dir_mode` (backups set 0700), else 0777; the server's umask applies |
| `removeFile`, `removeDir` | `REMOVE`, `RMDIR` |
| `rename` | `NoReplace`: `RENAME`. `Replace`: `posix-rename@openssh.com` when offered, else `REMOVE` of an existing target and `RENAME` (SPEC-v2 XS-6) |
| `setAttributes` | `SETSTAT` |
| `readLink`, `makeSymlink`, `makeHardlink` | `READLINK`, `SYMLINK` (arguments in OpenSSH's order: target, then link), `hardlink@openssh.com` |
| `spaceInfo` | `statvfs@openssh.com` when offered, else `Unsupported` |
| `upload`, `openWrite` | `OPEN` for writing (`CREAT\|TRUNC`, `CREAT\|EXCL` for `CreateNew`, neither for `Resume`), pipelined `WRITE`, `fsync@openssh.com` when offered, `CLOSE` |
| `download`, `openRead` | `OPEN` for reading, pipelined `READ`, `CLOSE` |
| `copy` | `copy-data` when offered (files only), else `Unsupported` |
| `keepAlive` | global request `keepalive@openssh.com` with want-reply |
| `cancel` | every request waits under the connection's cancel token and the request timeout; a request whose caller stopped waiting is abandoned: its reply is dropped when it comes, and a handle it opened is closed |

- **S-21** READ and WRITE chunks are the server's `limits@openssh.com` read and write limits, each capped at 256 KiB, or 32 KiB if the server gives no limits. Up to 16 requests are in flight per transfer or handle. OpenSSH's `sftp-server` reports read and write limits of 261120 bytes.
- **S-22** OpenSSH 8.9p1, 9.6p1 and 10.3p1 offer `posix-rename`, `statvfs` and `hardlink`; 9.6p1 and 10.3p1 also offer `copy-data` and `users-groups-by-id` **[test]**. The backend works, with the capabilities reduced accordingly, against an `sftp-server` that offers none of them **[test]**.

A listing skips entries named `""`, `.` or `..` and entries whose name contains `/` or NUL; the rest of the listing is delivered without an error (XC-6). When RMDIR fails, `removeDir` reports `DirectoryNotEmpty` if the folder lists any name other than `.` and `..`. NativeNoReplace is always reported: OpenSSH's plain `RENAME` fails on an existing target.

### Error mapping

| Condition | Core error |
|---|---|
| TCP connect refused or unreachable; connection closed during the handshake | `NetworkUnreachable` |
| no response within the timeout | `Timeout` |
| no common algorithm | `SecurityPolicy` |
| authentication denied; partial success without a prompter | `AuthFailed` |
| session channel refused (OpenSSH `MaxSessions`) | `TooManyConnections` |
| `sftp` subsystem refused | `Unsupported` ("SFTP is not enabled for this user") |
| `SSH_FX_NO_SUCH_FILE`, `SSH_FX_NO_SUCH_PATH` | `NotFound` |
| `SSH_FX_PERMISSION_DENIED`, `SSH_FX_WRITE_PROTECT` | `PermissionDenied` |
| `SSH_FX_FILE_ALREADY_EXISTS` | `AlreadyExists` |
| `SSH_FX_OP_UNSUPPORTED` | `Unsupported` |
| `SSH_FX_NO_CONNECTION`, `SSH_FX_CONNECTION_LOST`; the connection dropped after sign-in | `ConnectionLost` |
| `SSH_FX_FAILURE` during a write while `statvfs@openssh.com` reports less free space than the write needs | `NoSpace` |
| anything else | `ProtocolError` with the server's message (at most 1024 bytes) |

OpenSSH answers most failures with `SSH_FX_FAILURE` and no reason. Where SPEC-v2 XC-21 needs a specific error (an existing target, a folder, a non-empty folder, not a folder), the backend checks the target with `STAT` or `LSTAT` after the failure.

---

## 8. Interoperability matrix

The pass criterion for the SFTP part of the interop suite (SPEC.md 12.2, `tests/interop/sftp`). Every positive case performs: identify, authenticate, `makePath`, 64 MiB upload, list, free space, download, and SHA-256 comparison on the client and on the server's disk. The last column names the case of `tst_interop_sftp`.

| # | Case | Expected | Case |
|---|---|---|---|
| S-T1 | OpenSSH 10.3p1, default configuration, password | pass, `mlkem768x25519-sha256` | `openssh103Password` |
| S-T2 | OpenSSH 10.3p1, hardened (section 9), key generated by the key tools | pass | `openssh103Hardened` |
| S-T3 | OpenSSH 9.6p1, default configuration, password and key | pass, `curve25519-sha256` | `openssh96PasswordAndKey` |
| S-T4 | OpenSSH 10.3p1 offering only `curve25519-sha256` | pass | `curve25519Only` |
| S-T5 | pinned host key differs; pinned type not offered | `ServerIdentityChanged` before authentication | `pinnedKeyDiffers` |
| S-T6 | wrong password | `AuthFailed` | `wrongPassword` |
| S-T7 | password sign-in on a key-only server | `AuthFailed`, message names `publickey` | `passwordOnKeyOnlyServer` |
| S-T8 | file uploaded by us is fetched by OpenSSH `sftp` (9.6p1 and 10.3p1); file uploaded by `sftp` is listed and fetched by us | identical SHA-256 | `referenceClient` |
| S-T9 | OpenSSH 8.9p1 | pass | `openssh89` |
| S-T10 | server with Ed25519, ECDSA and RSA host keys; each pinned in turn | pinned key presented, no false mismatch | `hostKeyTypes` |
| S-T11 | server offering only `keyboard-interactive` | password mode works | `keyboardInteractive` |
| S-T12 | imported keys: ECDSA P-256 and P-384, passphrase-protected Ed25519; RSA 3072 | pass; RSA refused with what to do instead | `importedKeys` |
| S-T13 | `installWithPassword`, then key sign-in | pass; file modes correct | `installKeyWithPassword` |
| S-T14 | relative backups folder containing a space (`Sailfish OS/Backups`) | pass | `relativeFolderWithSpace` |
| S-T15 | full disk | `NoSpace`, no partial file left | `fullDisk` |
| S-T16 | cancel during upload and during download | `Canceled` within 2 s, `.part` removed | `cancelTransfers` |
| S-T17 | `sftp-server` without the OpenSSH SFTP extensions | pass | `withoutExtensions` |
| S-T18 | servers offering only finite-field Diffie-Hellman, only CBC ciphers, or only `ssh-rsa` host key signatures | `SecurityPolicy` naming the server's offer | `noCommonAlgorithm` |

`rust/netvfs-sftp/tests/openssh.rs` runs the crate against the same servers: negotiated algorithms, refusals, pins of each key type, sign-in methods, capabilities per server, cancel and timeouts.

---

## 9. Test configurations

Hardened server used for S-T2 (OpenSSH 10.3p1):

```
KexAlgorithms mlkem768x25519-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
HostKeyAlgorithms ssh-ed25519
PubkeyAcceptedAlgorithms ssh-ed25519
PasswordAuthentication no
KbdInteractiveAuthentication no
Subsystem sftp internal-sftp
Match User backup
  ChrootDirectory /srv/sftpjail
  ForceCommand internal-sftp
  AllowTcpForwarding no
```

The servers run in containers started by `tests/interop/sftp/run.sh`: OpenSSH 10.3p1 built from the upstream portable sources, and 9.6p1 and 8.9p1 from Ubuntu 24.04 and 22.04. Each container runs several `sshd` instances; `tests/interop/sftp/docker/start-sshd.sh` lists them (default, hardened, keyboard-interactive, no `sftp` subsystem, no extensions, held replies, one-time passwords, a stalling relay, curve25519 only, and the refused algorithm sets of S-T18).
