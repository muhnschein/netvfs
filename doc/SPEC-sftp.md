# SFTP account and backend

Companion to [SPEC.md](SPEC.md). That document defines the architecture, the account model, the UI flows and the Buteo plugins; this one defines everything specific to SFTP.

| | |
|---|---|
| Provider id | `sftp` |
| Service | `sftp-backup` (type `storage`) |
| Backend plugin | `libremotefs-sftp.so`, statically containing libssh |
| Library | libssh 0.12.2 (tag `libssh-0.12.2`, 2026-07-28), OpenSSL backend |
| Reference peer | OpenSSH `sshd` and `sftp`, with 10.3p1 as the primary version (it is what Sailfish OS 5.2 itself ships) |

Evidence tags are as in SPEC.md. **[test]** refers to the runs listed in section 9.

---

## 1. Account fields

Creation dialog (SPEC.md 7.3, step 1):

| Field | Default | Notes |
|---|---|---|
| Server | | DNS name or IP literal |
| Port | 22 | |
| User name | | |
| Sign-in method | Password | *Password* or *SSH key* |
| Password | | password mode only |
| Key | Generate new | key mode only: *Generate new key* or *Import key file* |
| Backups folder | `Sailfish OS/Backups` | see section 6 |

## 2. Settings keys and secret

In addition to the common keys (SPEC.md 6.2):

| Key | Type | Meaning |
|---|---|---|
| `remotefs/sftp/auth_mode` | string | `password` or `publickey` |
| `remotefs/sftp/host_key` | string | pinned server key, `<algorithm> <base64 blob>` |
| `remotefs/sftp/host_key_seen` | string | set together with attention `server-identity-changed`; same format |
| `remotefs/sftp/public_key` | string | the account's own public key as an `authorized_keys` line (key mode); for display |

Secret stored in signond (SPEC.md 6.3):

| Mode | `Secret` |
|---|---|
| `password` | the password, unchanged |
| `publickey` | `remotefs-key-v1:` followed by the base64 encoding of the unencrypted private key in OpenSSH format |

The prefix lets the backend refuse to send a private key as a password if the settings and the secret ever disagree.

---

## 3. Connection policy

- **S-1** Session options set on every connection:

  | Option | Value | Reason |
  |---|---|---|
  | `SSH_OPTIONS_PROCESS_CONFIG` | off | never read `~/.ssh/config` or system configuration |
  | `SSH_OPTIONS_KNOWNHOSTS`, `SSH_OPTIONS_GLOBAL_KNOWNHOSTS` | `/dev/null` | the pin lives in the account |
  | `SSH_OPTIONS_TIMEOUT` | 15 s | SPEC.md C-14 |
  | `SSH_OPTIONS_COMPRESSION` | `no` | archives are already compressed |
  | `SSH_OPTIONS_HOSTKEYS` | see S-5 | only when a key is pinned |

- **S-2** Key exchange, cipher, MAC and public-key algorithm lists are left at libssh defaults. No option, hidden or visible, widens them. A server with no algorithm in common fails with `SecurityPolicy`.
- **S-3** The backend never calls `ssh_userauth_publickey_auto()`, `ssh_userauth_agent()` or `ssh_session_is_known_server()`. It never opens a shell or exec channel; only the `sftp` subsystem is requested, so servers that force `internal-sftp` work **[test]**.
- **S-4** One `ssh_session` per `Backend` instance, used from one thread. `ssh_init()` is called once per process.

With these defaults libssh 0.12.2 negotiated the following against stock servers **[test]**:

| Server | Key exchange | Cipher |
|---|---|---|
| OpenSSH 10.3p1 | `mlkem768x25519-sha256` | `chacha20-poly1305@openssh.com` |
| OpenSSH 9.6p1 | `sntrup761x25519-sha512@openssh.com` | `chacha20-poly1305@openssh.com` |

Both are hybrid post-quantum exchanges. Restricting the client to `curve25519-sha256`, to emulate servers without them, also connects **[test]**.

---

## 4. Server identity (trust on first use)

- **S-5** When `remotefs/sftp/host_key` is set, `SSH_OPTIONS_HOSTKEYS` is restricted to the signature algorithms that belong to the pinned key type, so that a server holding several host keys presents the pinned one:

  | Pinned type | Requested |
  |---|---|
  | `ssh-ed25519` | `ssh-ed25519` |
  | `ecdsa-sha2-nistp256/384/521` | the same single algorithm |
  | `ssh-rsa` | `rsa-sha2-512,rsa-sha2-256` |

- **S-6** `Backend::connect()` runs `ssh_connect()`, then `ssh_get_server_publickey()`, and returns the key as `ServerIdentity` with the fingerprint from `ssh_get_publickey_hash(SSH_PUBLICKEY_HASH_SHA256)` and `ssh_get_fingerprint_hash()`. The string is identical to the output of `ssh-keygen -lf` **[test]**.
- **S-7** The caller compares the raw key blob with the pin:
  - no pin (account creation): `ServerIdentityUnknown`; the UI shows algorithm and fingerprint and requires explicit acceptance;
  - equal: continue;
  - different: disconnect, record `host_key_seen`, return `ServerIdentityChanged`. No authentication request has been sent at this point **[test]**.
- **S-8** The confirmation dialog shows the algorithm and the `SHA256:` fingerprint in full, in a monospace face, with the hint that the same value is printed on the server by `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
- **S-9** A changed key is never accepted silently and never by the background plugin. Only the update flow (SPEC.md 7.5) can replace a pin.

---

## 5. Authentication

- **S-10** The backend first calls `ssh_userauth_none()` and `ssh_userauth_list()` to learn the offered methods, then uses exactly one method according to `auth_mode`.
- **S-11** Password mode: `ssh_userauth_password()` if `password` is offered. If only `keyboard-interactive` is offered, `ssh_userauth_kbdint()` is used and the stored password answers a single non-echo prompt; any other prompt shape fails with `AuthFailed` and a message saying the server needs interactive sign-in.
- **S-12** Key mode: the private key is imported from memory with `ssh_pki_import_privkey_base64()` and used with `ssh_userauth_publickey()` **[test]**.
- **S-13** `SSH_AUTH_PARTIAL` (the server wants a second factor) is `AuthFailed` with a specific message. Multi-factor sign-in is not supported.
- **S-14** When authentication is denied, the error text names the methods the server does accept, for example "this server only accepts SSH keys" **[test: the denial carries the list]**.

### 5.1 Key handling (`SshKeyTool`)

| Method | Behaviour |
|---|---|
| `generate()` | creates an Ed25519 key with `ssh_pki_generate_key()`; returns the public line and holds the private key in memory until the account is created |
| `importFile(path, passphrase)` | reads a private key file chosen with the system file picker; accepts Ed25519, ECDSA and RSA in OpenSSH or PEM format; asks for the passphrase if the file is encrypted; re-exports unencrypted in OpenSSH format |
| `publicKey` | `authorized_keys` line `<algorithm> <base64> sailfish-backup` |
| `installWithPassword(params, password)` | signs in once with a password and appends the public line to `~/.ssh/authorized_keys` over SFTP |

- **S-15** RSA keys below libssh's default minimum size, DSA keys, security-key (`sk-`) keys and certificates are rejected at import with a clear message.
- **S-16** The key page shows the public line with *Copy to clipboard*, and offers *Install on server using password*. The password entered for that action is used once and is not stored.
- **S-17** `installWithPassword` creates `~/.ssh` with mode 0700 and `authorized_keys` with mode 0600 if missing, and appends only if the line is not already present.
- **S-18** After a device restore the private key is gone (SPEC.md 3.5). The update flow offers the same three choices as creation: generate, import, or switch to password.

`ssh_pki_generate()` is deprecated in 0.12 and produces a compiler warning **[test]**; use `ssh_pki_generate_key()`.

---

## 6. Paths

- **S-19** A backups folder that starts with `/` is absolute on the server. Any other value is relative to the directory the SFTP session starts in, which the backend resolves once with `sftp_canonicalize_path(".")`. On a chrooted account the chroot is the root **[test: absolute paths inside a chroot]**.
- **S-20** Directories are created with mode 0700 and files with mode 0600. Existing modes are not changed.

---

## 7. Operations

| `Backend` call | libssh |
|---|---|
| `stat` | `sftp_stat` |
| `list` | `sftp_opendir`, `sftp_readdir`, `sftp_closedir` |
| `makePath` | `sftp_stat` then `sftp_mkdir` per component |
| `remove` | `sftp_unlink` |
| `rename` | `sftp_unlink(to)` if it exists, then `sftp_rename` (plain SFTP rename does not replace) |
| `freeSpace` | `sftp_statvfs` if `statvfs@openssh.com` is advertised, else `Unsupported` |
| `upload` | `sftp_open(O_WRONLY\|O_CREAT\|O_TRUNC, 0600)`, pipelined `sftp_aio_begin_write` and `sftp_aio_wait_write`, `sftp_fsync` if `fsync@openssh.com` is advertised, `sftp_close` |
| `download` | `sftp_open(O_RDONLY)`, `sftp_aio_begin_read` and `sftp_aio_wait_read` (or sequential `sftp_read`) |
| `cancel` | sets a flag checked between request windows; outstanding requests are released with `sftp_aio_free` |

- **S-21** Chunk size is the smaller of the server's `limits@openssh.com` write limit (via `sftp_limits()`) and 256 KiB, or 32 KiB if the server gives no limits. The request window is 16. OpenSSH reported a limit of 261120 bytes, and a 64 MiB upload with that chunk size and window completed and verified **[test]**.
- **S-22** OpenSSH 9.6p1 and 10.3p1 both advertise `posix-rename`, `fsync`, `statvfs` and `limits` **[test]**. The backend must work, with reduced guarantees, against servers that advertise none of them.

### Error mapping

| Condition | Core error |
|---|---|
| TCP connect refused or unreachable | `NetworkUnreachable` |
| no response within the timeout | `Timeout` |
| no common algorithm | `SecurityPolicy` |
| `SSH_AUTH_DENIED`, `SSH_AUTH_PARTIAL` | `AuthFailed` |
| `sftp` subsystem refused | `Unsupported` ("SFTP is not enabled for this user") |
| `SSH_FX_NO_SUCH_FILE` | `NotFound` |
| `SSH_FX_PERMISSION_DENIED` | `PermissionDenied` |
| `SSH_FX_FILE_ALREADY_EXISTS` | `AlreadyExists` |
| `SSH_FX_FAILURE` during write while `statvfs` reports no free space | `NoSpace` |
| anything else | `ProtocolError` with the server's message |

---

## 8. Interoperability matrix

This is the pass criterion for the SFTP part of the interop suite (SPEC.md 12.2). Every positive case performs: identify, authenticate, `makePath`, 64 MiB upload, list, free space, download, and SHA-256 comparison on the client and on the server's disk.

| # | Case | Expected | Status |
|---|---|---|---|
| S-T1 | OpenSSH 10.3p1, default configuration, password | pass, `mlkem768x25519-sha256` | verified |
| S-T2 | OpenSSH 10.3p1, hardened (section 9), key generated by libssh | pass | verified |
| S-T3 | OpenSSH 9.6p1, default configuration, password and key | pass, `sntrup761x25519-sha512@openssh.com` | verified |
| S-T4 | client limited to `curve25519-sha256` | pass | verified |
| S-T5 | pinned host key differs | refused before authentication | verified |
| S-T6 | wrong password | `AuthFailed` | verified |
| S-T7 | password sign-in on a key-only server | `AuthFailed`, message lists `publickey` | verified |
| S-T8 | file uploaded by us is fetched by OpenSSH `sftp` (9.6p1 and 10.3p1); file uploaded by `sftp` is listed by us | identical SHA-256 | verified |
| S-T9 | OpenSSH 8.x server (older NAS firmware) | pass | to do |
| S-T10 | server with Ed25519, ECDSA and RSA host keys; each pinned in turn | pinned key presented, no false mismatch | to do |
| S-T11 | server offering only `keyboard-interactive` | password mode works | to do |
| S-T12 | imported keys: RSA 3072, ECDSA P-256, passphrase-protected Ed25519 | pass | to do |
| S-T13 | `installWithPassword`, then key sign-in | pass; file modes correct | to do |
| S-T14 | relative backups folder containing a space (`Sailfish OS/Backups`) | pass | to do |
| S-T15 | quota or full disk | `NoSpace`, no partial file left | to do |
| S-T16 | cancel during upload and during download | `Canceled` within 2 s, `.part` removed | to do |
| S-T17 | server without the OpenSSH SFTP extensions | pass | to do |

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

Environment of the verified runs: x86_64, Ubuntu 24.04, OpenSSL 3.0.13; libssh 0.12.2 built static with `-DWITH_SERVER=OFF -DWITH_GSSAPI=OFF -DWITH_EXAMPLES=OFF -DUNIT_TESTING=OFF`; OpenSSH 9.6p1 from the distribution and 10.3p1 built from the upstream portable tarball. The device build uses OpenSSL 3.5.7 on aarch64 and is covered by SPEC.md V1.
