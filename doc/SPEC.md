# netvfs: what it is and the rules it keeps

What code can't show: platform contract, trust model, budgets, limits, open questions. Details: code and tests.

## Goals

1. SFTP or SMB account in *Settings → Accounts* shows up as target in stock *Settings → Backup*: manual and scheduled backup, list, restore, as for Nextcloud.
2. Same accounts reusable by a file browser, sandboxed Harbour app included (Lautta), without weakening any backup guarantee and without handing it secrets, pins or local paths.
3. Backends give what a file manager needs: full metadata, lossless names, streamed listings, clear rename/remove semantics, symlinks, random-access handles, resume, server copy, space info. Plus a local backend.
4. SMB browsable: server mode (shares as top folders), share enumeration, explicit security profiles.

Non-goals: share sheet, Gallery, folder sync, photo upload, FUSE or kernel mount, sync engine, transfer queue, cache or UI inside netvfs (consumers' job); SFOS < 5.2, non-aarch64; SSH agent, certificates, FIDO keys, jump hosts, `~/.ssh`; SMB other than 3.1.1, Kerberos, DFS; encrypting archive at rest; async backend API (blocking, thread-confined model keeps backends simple and cancel testable).

## Platform

- SFOS 5.2.0.18 aarch64: Qt 5.6.3, gcc 13.4 / glibc 2.41, OpenSSH 10.3p1 reference peer, libaccounts-qt5 1.17, signon-qt5 8.61, buteo-syncfw-qt5 0.11.11, jolla-settings-accounts 0.6.15 (closed), jolla-vault 1.1.46 (closed), sailfish-account-nextcloud 1.1.3 (reference backup account).
- Not Harbour: uses privileged account and sync APIs. Lautta is Harbour; netvfs is what platform would have to ship for it.
- Accounts&SSO documented as slated for replacement, no roadmap; Jolla still added Mastodon on it in 5.2: supported path for now.
- SFTP and SMB clients: own Rust code in `libnetvfs-rs.so`; no protocol or crypto library of platform.

## Stack

```
 Settings → Accounts        Settings → Backup         Lautta (Sailjail, Harbour)
 jolla-settings             jolla-vault               consumer
   account UI QML             sailfish-backup           │ p2p D-Bus on socket in app's
   org.netvfs.accounts        │ D-Bus                   │ own data folder
        │                     msyncd ─ buteo-oopp-runner│
        │                       6 Buteo plugins       netvfs-bridge (per consumer,
        │                       (provider × op)         systemd socket activation)
        │                          │                    ├ netvfs-accounts (setgid privileged)
        └──────────────┬───────────┘                    │ libnetvfs-bridge-ffi.so
                    libnetvfs (C++: accounts, credentials, session, ops, discovery)
                 ┌─────────┼──────────┐
           sftp plugin  smb plugin  local plugin
                 └────┬────┘
               libnetvfs-rs.so (Rust: netvfs-sftp, netvfs-smb)
 accounts db + signond (secrets)      UDisks2 (drives, via bridge)
```

| Process | Loads | Sandbox |
|---|---|---|
| `jolla-settings` | account UI QML, its C++ QML plugin | none |
| `buteo-oopp-runner` (from `msyncd`) | one Buteo plugin per run | none; `msyncd` holds accounts privilege |
| `sailfish-backup` | nothing of ours | — |
| `netvfs-bridge` | `libnetvfs-bridge-ffi.so`, libnetvfs, backends | none; user's own groups |
| `netvfs-accounts` | SQLite only | setgid `privileged`, self-confined |
| consumers (Lautta) | nothing of ours | Sailjail |

Packages: `netvfs` (library, backends, `libnetvfs-rs.so`, account UI, providers, `<p>-files` services, `netvfs-cli`), `netvfs-backup` (backup services, Buteo plugins and profiles; only package depending on Buteo), `netvfs-bridge` (bridge, FFI library, helper, systemd generator, `consumers/lautta.conf`; nothing requires it, so only devices with a sandboxed consumer carry the setgid helper), `netvfs-devel`. All require exact same `%{version}-%{release}` of `netvfs`. Bridge install or upgrade stops running bridges; next connection starts new one.

## Lautta with and without netvfs

- Without netvfs: Lautta is a plain Harbour file manager on local folders; no trace of bridge in UI.
- With `netvfs-bridge`: `consumers/lautta.conf` registers it. After user's consent Lautta sees netvfs accounts whose *Files* service is on, ad-hoc locations it created itself, nearby servers (mDNS), and memory cards / USB drives with mount and unmount. It links nothing of netvfs, needs no extra Sailjail permission, never sees a secret, pin or local path outside its sandbox. Account changes hand off to Settings.
- Harbour consumer can't install outside own paths, so registration file ships with netvfs.

## Backup platform contract

Platform finds and drives a backup account purely by names and keys:

- Provider `/usr/share/accounts/providers/<p>.provider`; no `user-group:` tag = visible to all. UI from `/usr/share/accounts/ui/<p>.qml`, `<p>-settings.qml`, `<p>-update.qml`; root types from closed `com.jolla.settings.accounts 1.0` (`AccountCreationAgent`, `AccountSettingsAgent`, `AccountCredentialsAgent`, `AccountBusyPage`, `StandardAccountSettingsPullDownMenu`). Closed: use only these; no `OnlineSync*`, `AccountFactory` (assume HTTP), no `StandardAccountSettingsDisplay`.
- Backup page lists every enabled account with enabled service of type `storage`; no allow-list. Label `<provider name> (<default_credentials_username>)`. `CredentialsNeedUpdate` → "not signed in", not queried. Queried only while connection manager says *online* (see limits).
- Names: service `<p>-backup`; sync profile templates `<p>.Backup`, `<p>.BackupQuery`, `<p>.BackupRestore`; platform makes per-account `<p>.Backup-<accountId>`; client profile `<name>` loads `/usr/lib64/buteo-plugins-qt5/oopp/lib<name>-client.so`. Profile keys mirror Nextcloud's, incl. `Sync Transport = HTTP` (platform reads as "network").
- `org.sailfishos.backup` on session bus, `/sailfishbackup`: `backupFileDeviceId()` (per-device remote subfolder), `createBackupForSyncProfile(s) → s` (local archive path), `setCloudBackups(s, as)`, signals `cloudBackupStatusChanged(i, s)`, `cloudBackupError`, `cloudRestoreStatusChanged`, `cloudRestoreError`. Restore target in profile key `sfos-backuprestore-file`.
- Credentials: signond password identity (`UserName`, `Secret`) via `Account::createSignInCredentials()`. `Account::remove()` deletes only identities referenced by `segregated_credentials` keys. Stock `AccountAuthenticator` rejects accounts without `server_address` or with empty password: not used. Device restore re-creates accounts without secrets and sets `CredentialsNeedUpdate`. Private keys live in signond only, never a path.
- Attention: `AuthFailed` / `ServerIdentityChanged` → `netvfs/attention` = `auth-failed` / `server-identity-changed`, `CredentialsNeedUpdate = true`, `CredentialsNeedUpdateFrom = <p>-backup`. Only "needs attention" channel platform has; update flow clears all three.
- Backup run: pre-flight (connect, identity, auth, `makePath`, drop `*.part` older than 24 h) before archive is built; upload on fresh connection to `.part`, then rename; local archive deleted either way. Query lists regular files not ending `.part`. Restore downloads to `<local>.part`, renames. Internet-connectivity drops ignored (LAN server). `cleanUp()` after account delete removes nothing on server. Exactly one `success()` or `error()` per run.

## Accounts: Backup vs Files

Second service per provider `<p>-files`, type `netvfs-files` (not `storage`, so Backup doesn't list it). Session open refuses (`SecurityPolicy`) configs a service may not use:

| Configuration | Backup | Files |
|---|---|---|
| SMB `strict`, `signed` | yes | yes |
| SMB `guest` | no | with `allow_insecure` |
| SMB unknown profile | no | no |
| SMB without share (server mode) | no | yes |
| `allow_insecure=true` | no | yes |
| `auth_mode=interactive` | no | yes |
| else | yes | yes |

Secrets read only by Buteo plugins (in msyncd) and the bridge. Interactive and guest accounts may have no secret.

## Bridge: sandboxed consumers

Trust model: bridge acts on netvfs accounts for a consumer the user approved. Never acts on local paths, never discloses secrets or pins, never changes accounts (hands off to Settings). Only netvfs part reachable from a sandbox.

- Registration: `/usr/share/netvfs/consumers/<id>.conf` (`Id`, `DisplayName`, `Executable`, `DataDir`). User generator makes `netvfs-bridge@<id>.socket`, `.service`, `.path`.
- Rendezvous: Sailjail always whitelists app's own `~/.local/share/<Org>/<App>`. Socket `%h/<DataDir>/netvfs/bridge.sock`, mode 0600, dir 0700. `.path` unit re-creates socket when app's data is cleared or app reinstalled. Bridge writes nothing else there. Fallback idea if fragile: call into consumer's own D-Bus name, hand over socketpair.
- One bridge per consumer, socket activated, idle exit 30 s after last client and job. Runs with user's groups: everything parsing server data stays outside `privileged`. No Qt in binary; backends' Qt loop on main thread via FFI library.
- Peer check every connection: `SO_PEERCRED` uid = own uid; `/proc/<pid>/exe` (via pidfd, start-time reads around open against pid reuse) same file as registered `Executable`, or same size and bytes: Sailjail's `firejail --private-bin` runs a tmpfs copy at another inode. Else closed silently, warning logged.
- Consent per consumer `unknown`/`granted`/`denied` in `~/.config/netvfs/bridge.conf`. First `Hello` while unknown: notification "*Lautta* wants to use your network locations", Allow / Don't allow. Until granted: no locations, calls `PermissionDenied`. *Settings → Accounts → Apps using network locations* grants or revokes; revoke closes connections at once. Drives and `OpenStorageSettings` need no consent (show no network locations; polkit lets any user process do same).
- Scope: Files-enabled accounts, consumer's own ad-hoc locations, discovery results. Nothing else.
- Local files: consumer passes fds. Bridge checks type (regular or FIFO) and access mode before any network work; `pread`/`pwrite` at explicit offsets; never fsyncs, renames, deletes, opens a local path.
- Secrets: asked from signond only after server identity accepted, same step as auth. Ad-hoc secrets arrive as bytes, wiped after use, never stored; URL with password rejected. Wiped copies: bridge's own; zbus's received message buffer holds secret until dropped.
- Identity: accounts → error plus attention, fixed in Settings only. Ad-hoc → `Question(identity-unknown)`; pins per consumer in `~/.local/share/netvfs/bridge/<id>/known_hosts`; changed ad-hoc key = error, re-pin needs forget and new first contact.
- Handoff: Settings account page, add-account flow, Settings → Storage, via platform settings D-Bus per `/usr/share/netvfs/bridge/handoff.conf`. Sandboxed app can't: jolla-settings has no URL scheme, `com.jolla.settings.ui` open only to a few platform apps' profiles.
- Drives: consumer can't reach UDisks2. Bridge lists SD (`flash_sd` medium) and USB block devices with mountable filesystem or locked LUKS, not `HintSystem`/`HintIgnore`; internal eMMC (`flash_mmc`) never. Mount with `auth.no_user_interaction` (UDisks2 picks `/run/media/<user>`); acts only on a drive `ListDrives` lists now. Locked LUKS: `Unsupported`, Settings unlocks; no passphrase through bridge. Polkit on 5.2 allows mount and unmount-others to anyone; eject and power-off need `auth_admin`: not offered. System bus only on first drive call.
- Location ids opaque: `account:<n>`, `adhoc:<run>-<n>` (`<run>` random per start); never reused, so stale ad-hoc id is `NotFound`.
- `GetFeatures` names extras (`storage-settings`, `drives`) so consumer shows an action only where it works; unknown names ignored.

### Accounts helper `netvfs-accounts`

Accounts DB (`~/.local/share/system/privileged/Accounts/`) readable by group `privileged` only. Helper setgid `privileged` (`%attr(2755,root,privileged)`, group from `sailfish-setup`), one run per request: `list`, `files <id>`, `attention <id> <state> [pin]`. Never reads or returns a secret, never clears attention, never touches an account bridge wouldn't list, links no backend, no Qt/GLib/libaccounts.

Any process can start it, so it trusts nothing of caller:

- Env: keeps only `LANG`, `LANGUAGE`, `LC_*`, `TZ`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`; `HOME` from passwd of real uid; signal only on bus of `/run/user/<uid>`. Core limit 0.
- Confinement, first thing, single-threaded: only fds 0–2, umask 077, default signals, Landlock best effort (ABI 1–7: read-only system dirs and `/run/user/<uid>`, read-write `/dev/null` and DB folder; no exec, TCP, device ioctls, foreign signals or abstract sockets), `no_new_privs`, seccomp EPERM for exec, ptrace, non-`AF_UNIX` sockets, namespaces, mounts, modules, BPF, io_uring, userfaultfd, perf, keyrings, set-id modes (`clone3`, `openat2`: ENOSYS so glibc falls back). Drops group (`setresgid`) before writing answer. Jolla Phone 2026 kernel 6.12: seccomp yes, Landlock no.
- Bridge service has no `NoNewPrivileges=` (would void setgid). invoker's `privileges.d` can't be used: doesn't pass socket-activated fd.
- Changes: libaccounts writers send `AccountChanged`; bridge relists 200 ms after last one, and right after own attention write (set-id helper may fail to signal). Helper failure: warning, no accounts.

## Security rules

- Server identity checked before any credential is sent (SFTP; SMB has none to pin).
- Algorithm lists fixed in code; no setting weakens SSH algorithms or SMB dialect. Never automatic downgrade or retry with weaker profile, dialect, auth method.
- Private keys generated on device or imported once, signond only, never written to disk. Never reads `~/.ssh`, system SSH config, agent, Samba config, `NTLM_USER_FILE`, `krb5.conf`.
- Secrets in memory only during an operation, wiped (best effort).
- Every parser of server data is Rust in `libnetvfs-rs.so`; every count and length capped before allocating; each has a fuzz target.
- Bridge attack surface: zbus parser within inbound limits, plus own validation: paths normalized, numbers range-checked, fds validated, drives only from own list.
- Plugins hidden visibility, `--exclude-libs,ALL`; `libnetvfs-rs.so` exports only `nvr_get`; no package links libssh or libcrypto. Crates locked, `cargo deny`; advisories resolved before release; interop rerun after every bump.
- `.part` and probe files carry nothing device-identifying beyond platform's backup names.
- SMB code ships only while: every mutant of `crypto.rs` caught, known-answer tests pass with published 3.1.1 vectors, full interop suite incl. fail-closed cases passes, interop clean under ASan/UBSan.

### SFTP

- KEX `mlkem768x25519-sha256`, `curve25519-sha256`; ciphers `chacha20-poly1305`, `aes256-gcm`, `aes128-gcm`; host keys Ed25519, ECDSA P-256/384/521, `rsa-sha2-512/256`. No `ssh-rsa` SHA-1, DSA, CBC, finite-field DH, certificates, compression. `sftp` subsystem only; no shell, exec, server-opened channels. One SSH connection per backend.
- Trust on first use: no pin → `ServerIdentityUnknown`, UI shows algorithm and full `SHA256:` fingerprint (as `ssh-keygen -lf`), explicit accept. Mismatch → disconnect before any auth request, `ServerIdentityChanged`. Pinned key narrows host-key list to its type; server without that type retried once unrestricted so caller sees current key. Never silent re-pin, never by background plugin: only update flow.
- Auth: `none` first to learn methods. Without prompter: stored password answers one non-echo keyboard-interactive prompt only; partial success (2FA) = `AuthFailed` naming multi-factor. Denied → message names accepted methods.
- Keys: generate Ed25519; import Ed25519, ECDSA (OpenSSH, PKCS#8 incl. encrypted, SEC1). KDF cost capped before trying passphrase: bcrypt ≤ 1024 rounds, PBKDF2 ≤ 1,000,000, scrypt ≤ 64 MiB, parallelism 4.

### SMB

SMB 3.1.1 only, NEGOTIATE offers 0x0311 alone, preauth SHA-512; ciphers AES-128-GCM, AES-256-GCM; signing AES-128-CMAC. Anything else picked → refused.

| Profile | Signing | Encryption | Auth |
|---|---|---|---|
| `strict` (default) | required | every request after SESSION_SETUP, every response must be encrypted | NTLMv2 |
| `signed` | required | where server marks session or share | NTLMv2 |
| `guest` | none | none (marked server refused) | NTLMSSP anonymous; Files only, with insecure consent |

- No host key: final SESSION_SETUP response signed with session key (MS-SMB2 3.2.5.3.1) proves server knows password. After that: unencrypted/unsigned response, other session's, unsolicited, compressed, or a request ends connection.
- IS_GUEST / IS_NULL session refused outside `guest`; user `/GUEST` refused (sspi skips mechListMIC); password `$NTLM$…` refused (sspi takes it for NT hash).
- Remaining risk: unencrypted signed connection can't verify interim STATUS_PENDING (MS-SMB2 3.2.5.1.3): ≤ 8 per request, credits capped 8192. Every server contacted gets an NTLMv2 response → offline guessing; password should be strong and unique (creation dialog says so). NTLM-disabled servers unusable. No multichannel, DFS (`Unsupported` "DFS referral"), Kerberos, compression, oplocks, leases, AES-CCM, GMAC.
- Server mode: no `share` → root lists disk shares via srvsvc over IPC$ (saved `shares` first, `$` shares with `show_admin_shares`); ≤ 4 shares connected, least recently used without open handles dropped.
- Names: `\ : * ? " < > |`, control chars, trailing space or dot → `InvalidName` before any request.

## Budgets

- `cancel()` from any thread ends in-flight call with `Canceled` within 2 s on healthy connection (Rust: 1 s grace then call dropped).
- Timeouts: connect 15 s, single request 60 s; no automatic retry in library. SMB request timeout ends connection.
- Transfers stream in bounded memory. SFTP: 16 requests in flight, chunks ≤ 256 KiB (32 KiB without `limits@openssh.com`), read-ahead ≤ 4 MiB. SMB: ≤ 4 MiB in flight, chunks ≤ 1 MiB.
- Backend calls block; one thread at a time per backend; owner keeps event loop running.
- Bridge per consumer: 64 concurrent requests, 16 handles, 8 jobs, `ListBatch` ≤ 512 entries or 1 MiB, `Read` ≤ 1 MiB; over → `TooManyConnections` + `retryAfterMs`. Message header > 2 MiB or > 2 fds closes connection before body; ≤ 16 received messages waiting. Outgoing in order, only as fast as consumer reads: batches pause at 4 MiB unwritten, reading stops at 64 queued.
- Pools per location: lanes interactive 1, bulk 2, stream ≤ 1; ≤ 4 per host; idle connection closed after 1 min. `LocationsChanged` ≤ every 250 ms, only on real change. `JobProgress` ≤ 4 Hz. Drives relist 200 ms after first UDisks2 signal of a burst; UDisks2 call ≤ 60 s.
- Discovery (own mDNS on 224.0.0.251 / ff02::fb, no avahi): PTR for `_sftp-ssh._tcp`, `_ssh._tcp`, `_smb._tcp`; backoff 1, 2, 4 … 60 s; only while a consumer asks; never connects.
- Battery: no polling, no timer without work; bridge idle exit; backups when Buteo schedules.

## Confirm on device

| Check | If it fails |
|---|---|
| Plugins load `libnetvfs-rs.so` and connect | fix install paths |
| Provider without `user-group` shows in *Add account* | add group and `manage-groups` scriptlets as Nextcloud |
| Account in *Settings → Backup* as `SFTP (user@host)` | adjust `default_credentials_username` |
| Plugin reads and deletes archive from `createBackupForSyncProfile` | follow reference exactly |
| Account delete removes signond identity | remove identity in settings agent before `accountDeletionRequested()` |
| ≤ 5 kB single-line secret round-trips signond | store key in Sailfish Secrets, reference in signond |
| After device restore account shows not signed in | set `CredentialsNeedUpdate` when identity missing |
| `msyncd` loads plugins after `%post` restart | document reboot |
| `backupFileDeviceId()` on replacement device; restore finds old device's backups | "restore from another device's folder" picker later |
| Backup page schedules and runs profile unattended | none; reference path |
| signond ACL lets bridge read `createSignInCredentials("netvfs", …)` identities | ACL with msyncd's and bridge's tokens only, never `*` |
| Settings D-Bus entry points for account page and creation flow | adjust `handoff.conf` |

Acceptance: account per auth mode (wrong input: specific message, no account); backup, list, restore byte-identical; scheduled with screen off; server unreachable: connection error, nothing left locally; upload cut: no file without `.part`, stale part removed after 24 h; changed host key or password: fails before auth, not signed in, update flow fixes; account delete: profiles and identity gone, server files untouched; device restore: account present, flagged, usable after update.

## Risks and limits

- Agent base types closed; stable Nextcloud (2019) to Mastodon (2026) but can change. Only listed members used.
- Accounts&SSO may be replaced: coupling kept to UI files, QML plugin, two core classes.
- Own SMB client: ships behind gate above.
- Backup page talks to storage accounts only while *online*: NAS on LAN without internet unusable from stock UI; unfixable from plugin.
- `.local` names depend on platform resolver; may need IP or DNS name.
- New or restored device needs a way in before restore: password, imported key, or new key someone authorises.
- Archive protected in transit, not at rest. Plugin sits on both paths: client-side encryption possible later without platform change.

## Roadmap

- Rust rewrite continues on user's go: libnetvfs core, local backend, ops, discovery, account UI glue, Buteo plugins, `netvfs-cli` still C++.
- SDK target ships rustc 1.95 → drop cross job, spec runs cargo, OBS/Chum rebuild possible.
- Restore from another device's folder (if `backupFileDeviceId()` check fails).
- Client-side archive encryption.
- Platform adoption: something like netvfs shipped by Jolla, so Harbour apps get network locations without a third-party bridge.
- qmake stays until platform moves past Qt 5.6.
