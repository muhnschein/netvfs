# SPEC-v2 checked against the v1 specification

Inputs: v1 `SPEC.md`, `SPEC-sftp.md`, `SPEC-smb.md` (working name `remotefs`, read as `netvfs`), `doc/SPEC-v2.md` (draft 2), and `src/` for what v1 ids mean in practice (checked at `599828d` for the pre-port behaviour).
Citations: `SPEC §n` = v1 SPEC.md; `SFTP S-n`/`SMB M-n` = companion specs. v2 items are cited by id.

Verdicts: **correct**, **inaccurate** (v1 text quoted), **nuance** (correct but incomplete).

---

## 1. v2 §2 table and "What stays exactly as is"

### 1.1 Table rows

| Row | Verdict | v1 text / comment |
|---|---|---|
| `Backend` | **correct, one nuance** | `SPEC §5.2` lists exactly connect, authenticate, stat, list, makePath, remove, rename, freeSpace, upload, download, read, cancel, disconnect. `resetCancel` is not in v1 (code addition). C-11: `read()` "MAY be left unimplemented (Unsupported) in the first release", so "opens and closes per call" is a code fact, not a v1 requirement. |
| `Entry` | **correct** | `SPEC §5.2`: `{ name, size, modified, isDir }`. Nuance: v1 gives no sentinel for unknown size; the "v1 used 0" claim (XC-2/XC-3) is code only. |
| Names (`fromUtf8`) | **nuance** | v1 has no name-encoding rule at all. Relevant v1 text: C-15 (`/` separator, `.`/`..` rejected), SMB M-9 (forbidden characters and trailing space/dot, checked **in the UI for the backups folder** before connecting), tests SFTP S-T14 and SMB M-T18 (space, non-ASCII). |
| `rename` "always replaces (SFTP via posix-rename or stat+unlink; SMB stat+unlink)" | **nuance** | `SPEC §5.2`: "`rename` ... // replaces `to`" - correct. But SFTP §7 table says only "`sftp_unlink(to)` if it exists, then `sftp_rename` (plain SFTP rename does not replace)"; posix-rename appears in v1 only in S-22 as an advertised extension. The code comment says libssh's `sftp_rename()` replaces atomically when `posix-rename@openssh.com` exists, so the row matches the code, not the v1 table. SMB §5 row ("`smb2_unlink(to)` if it exists, then `smb2_rename`") is correct. |
| `remove` "file, or empty directory (SFTP falls back to rmdir)" | **inaccurate vs v1** | SFTP §7: `remove` = `sftp_unlink`; SMB §5: `smb2_unlink`. v1 never mentions directories (it only deletes `.part` and probe files). The rmdir fallback is code-only. |
| `read` | **nuance** | See `Backend` row (C-11 allows `Unsupported`). |
| Upload "always `.part` + rename, files created 0600 (S-20)" | **correct, nuance** | C-12 (`.part`, flush, size compare, rename, best-effort remove `.part` on failure), S-20 (**directories 0700**, files 0600, existing modes unchanged). Missing: C-13 free-space pre-check; `SPEC §8.4` step 2 deletes `*.part` older than 24 h (relevant to resume, see 2.11). |
| SMB policy "3.x only, signing required, encryption default on (M-1..M-3), one share per connection, share enumeration linked out (`noshareenum.c`, G-SMB 4)" | **correct, nuance** | M-1/M-2/M-3 right. "One share per connection" is implicit (SMB §1 "share name, typed by the user (no browsing)", M-10 `smb2_connect_share`). v1 words it as "DCE/RPC (share enumeration) compiled out" (M-6, P-3 `-DENABLE_LIBDCERPC=OFF`) and G-SMB 4 "build disables Kerberos and the separate DCE/RPC library, and the backend never calls the share-enumeration API". The `noshareenum.c` link guard is code; its header says libsmb2 still embeds a DCE/RPC client, so "compiled out" in M-6 is imprecise. |
| SFTP auth "password, public key; keyboard-interactive refused" | **inaccurate** | SFTP S-11: "If only `keyboard-interactive` is offered, `ssh_userauth_kbdint()` is used and the stored password answers a single non-echo prompt"; matrix S-T11 "server offering only keyboard-interactive: password mode works". Refused only: other prompt shapes (S-11) and `SSH_AUTH_PARTIAL` (S-13). The code implements this (`authKeyboardInteractive`). |
| Identity "SSH host key pin, single pin per account" | **correct, nuance** | S-5..S-9, key `remotefs/sftp/host_key` (+ `host_key_seen`). Nuance: SMB has deliberately no identity (SMB §3 "Server identity", L4) and `SEC-1` says "wherever the protocol has one". |
| Accounts "providers sftp, smb, one service `<p>-backup` of type `storage`" | **correct, nuance** | `SPEC §6.1`, §3.2. Missing: §6.1 "Service ids `<p>-files` are reserved for G2 and MUST NOT be shipped now" (see 2.16); §7.4 "there is only one service"; §6.2 "connection settings are account-global so that a future second service can share them" (supports XA-1). |
| Packaging "backend `.so` inside `netvfs-account-<p>` with Buteo plugins; QML module in `netvfs-core`" | **correct** | `SPEC §4.1` table. P-4 gives `jolla-settings-accounts`, `jolla-vault`, `buteo-syncfw-qt5-msyncd` as Requires of the account package, so "drags in Buteo, jolla-vault, msyncd" is right. |

### 1.2 "What stays exactly as is"

| Item | Verdict | Comment |
|---|---|---|
| "error-taxonomy approach (C-5.4)" | **inaccurate id; not "exactly as is"** | No `C-5.4`: it is C-5 (single taxonomy, no library codes above the backend) plus `SPEC §5.4` (the list). XC-21 appends ten values and re-scopes `NetworkUnreachable`; XC-24 puts protocol status text in `Result::detail()` (touches C-5 "never expose library-specific codes"). `SecurityPolicy` is defined in §5.4 as "server could not meet a mandatory security requirement"; XH-6 (password in URL) and XA-4 (config not allowed for service) reuse it for client-side refusals. |
| C-7 | **correct, nuance** | C-7 is "connect and authenticate are separate steps". For SMB, M-10 makes `connect()` only resolve/port-check, so credentials go out in `authenticate()`; fine. XC-15 prompts and `guest` profile need a sentence on how C-7 applies. |
| C-9 | **correct, nuance** | v1: "within 2 seconds **on a healthy connection**". v2 adds exceptions (L-6 kernel block) and prompter waits (XC-22). 4 MiB in flight (XS-7, XM-6) is compatible. |
| C-10 | **correct, nuance** | v1 scope is `upload()`/`download()` "no whole-file buffering". v2 extends to handles; worst case read-ahead is 4 MiB x 16 handles (XB-17) x pooled connections, not bounded per consumer. |
| C-14 | **nuance** | v1: connect 15 s, request 60 s, "no automatic retry inside the library". XC-22 says timeouts apply to "`AuthPrompter` waits": a 60 s limit on a person typing an OTP is probably not intended. |
| C-15 | **nuance** | v1 only says `/` at the API and `.`/`..` rejected. NUL rejection is code. L-1 redefines C-15 as "backend-defined" absolute paths; XM-2 changes SMB paths (see 2.9). |
| C-16/C-17 | **nuance** | C-16 fixes five category names (`remotefs.core/sftp/smb/buteo/ui`), so webdav, ftp, local, bridge, discovery need new categories. C-17 forbids secrets "at any level", paths/hosts only at debug; XSEC-5 adds TLS/FTP/WebDAV but not cookies, `Authorization` and bearer tokens explicitly. |
| SEC-5 | **nuance** | v1: "held in memory only for the duration of an operation". Bridge connection pools (XB-12) and curl's copy of Basic credentials outlive an operation; D-Bus `ay` buffers (XB-16) cannot be wiped. State "best effort" per v1 wording. |
| "vendoring approach (D-1, P-1..P-6)" | **inaccurate** | Vendoring is D-1 (submodules pinned by commit, libssh by signed tag), D-2, D-3, P-1..P-3, SEC-7. P-4 (RPM `Requires`, `ExclusiveArch`), P-5 (BuildRequires), P-6 (`%post` msyncd restart) are packaging. W-1 itself amends P-1 and XM-5 needs patches D-1 does not mention, so it does not "stay exactly". |
| "test culture (unit, interop containers, sanitizers, mutation lists, SonarCloud with zero open issues)" | **nuance** | v1 §12.2 has interop suite once normally and once with sanitizers; G-SMB 3, M-T19. Mutation lists and SonarCloud are not in v1 (repo practice only). |

---

## 2. v1 requirements changed in effect by v2 without "amends"

Format: **v1 id**: v1 text / v2 text / proposed one-line amendment.

1. **SEC-2** (also SMB M-4, SMB §1, §1 non-goals): v1 "no setting that enables legacy algorithms, SMB1, SMB 2.x or unsigned SMB"; M-4 "Guest and anonymous sessions are not offered"; SMB §1 password "must not be empty". v2 XM-1 `legacy` (2.0.2) and `guest` (signing off, no user/password), `allow_insecure`, `tls_mode=none`, W-4 peer verify off for pinned self-signed. XM-1 amends only M-1..M-3. *Amend:* "SEC-2 and M-4 (amended): weakening profiles (`legacy`, `guest`, `allow_insecure`, `tls_mode=none`) exist only for the Files service, are never chosen automatically (XSEC-2) and never for Backup; SSH algorithm lists and TLS version/cipher defaults are never changed."
2. **§1 non-goals, SMB** ("SMB1, SMB 2.x, guest or anonymous access, Kerberos, share or server discovery, DFS"): v2 adds SMB 2.x, guest, share enumeration (XM-7) and server discovery (XD-1 `_smb._tcp`, XD-4 WS-Discovery); keeps Kerberos/DFS out (XM-9). *Amend:* "Non-goals (amended): SMB 2.x and guest are allowed for the Files service only (XM-1); share and server discovery are goals (XM-7, XD); SMB1, Kerberos and DFS stay out."
3. **§1 non-goals, SFTP** ("jump hosts"): v2 XS-13 plans ProxyJump ("later, out of scope for 0.2"). SFTP S-1 sets known-hosts to `/dev/null` and S-4 says one `ssh_session` per Backend. *Amend:* "Non-goal 'jump hosts' lifted for a later release; each hop is pinned in the account (`jump_host_key`) and S-1/S-4 are amended then."
4. **§1 G2** ("the file browser is not [in scope]"; "only the shape of the library"): v2 §1.1 goal 1 makes the browser a consumer. *Amend:* "G2 (amended): the file browser is a sandboxed consumer served by netvfs-bridge (§8a)."
5. **SFTP S-3** ("never opens a shell or exec channel; only the `sftp` subsystem"): v2 XS-9 opt-in exec channel (`allow_shell`) for copy/checksum/find. *Amend:* "S-3 (amended): no exec channel unless the account sets `allow_shell=true`, and never for Backup."
6. **SFTP S-10, S-11, S-13, S-14** (exactly one auth method per `auth_mode`; kbdint answered with stored password for a single non-echo prompt; `SSH_AUTH_PARTIAL` = `AuthFailed`; denial text lists accepted methods) vs XS-11 "(amends S-14 `interactiveNotSupported`)": the cited id is wrong (see 3). XS-11 also "attempted after publickey/password methods fail", which contradicts S-10 "exactly one method", XSEC-2 (no fallback to another auth method) and XC-15 "With `prompter == nullptr`, interactive methods are not attempted (backup behaviour unchanged)", which contradicts S-11 (backup uses kbdint with the stored password, test S-T11). *Amend:* "S-10, S-11, S-13 (amended): with an `AuthPrompter` and `auth_mode=interactive`, multi-round and partial-success chains are supported; without one, S-11 and S-13 apply unchanged; no fallback between configured methods."
7. **S-20** is marked, but **directories**: S-20 "directories 0700". XC-8 `makeDir(path, exclusive)` and `WriteOptions.createMode` (files only) have no directory mode, so XC-23 "backups keep their current mode" cannot be expressed. *Amend:* "XC-8: `makeDir(path, exclusive, createMode = -1)`; `makePath` passes 0700 for backup (S-20)."
8. **S-22** is marked, but see 3 (wrong id) and XS-6: NoReplace "uses plain `SSH_FXP_RENAME`" while the code comment says libssh's `sftp_rename()` itself uses `posix-rename` when advertised (replaces). *Amend:* "XS-6: state which libssh call sends a non-replacing rename; if none, `NativeNoReplace` is not claimed for SFTP."
9. **SMB M-8** ("paths relative to the share root; a leading `/` is stripped"; Share field required) and SMB §1: XM-2 server mode with empty `share`, paths `/<share>/<rest>`; C-15/L-1 for local. *Amend:* "M-8 (amended): with `share` empty paths are `/<share>/<rest>`; `share` is mandatory for the Backup service (XA-4)."
10. **SMB §5 error mapping / SPEC §8.7** (Buteo mapping: only listed errors map; "everything else" = `INTERNAL_ERROR`): XC-21 new errors (`ConnectionLost`, `RateLimited`, `Locked`, `TooManyConnections`, ...) and the SMB "failure after TCP connect = `SecurityPolicy`" row (marked only for `connectionLost()`). *Amend:* "§8.7: `ConnectionLost` and `RateLimited` map to `CONNECTION_ERROR` without attention; `Locked`, `NotADirectory`, `IsADirectory`, `DirectoryNotEmpty`, `InvalidName` remain `INTERNAL_ERROR`."
11. **C-12** (marked by XH-1) but not the failure rule: "On any failure, best-effort remove the `.part` file" (also S-T16/M-T17 ".part removed" after cancel) vs XH-1 resume on the temp name and XB-13 "partial remote temp files are left in place". *Amend:* "C-12 (amended): the `.part` file is removed on failure unless `TransferPolicy.resume` is set; Buteo never sets it."
12. **C-13 / XC-19**: XC-19 says "(C-12's free-space check unchanged)": the check is C-13 (see 3). When `spaceInfo` is `Unsupported` v1 C-13 is silently skipped; fine, state it.
13. **SPEC §8.5 BackupQuery** ("keep regular files whose names do not end in `.part`"): `Entry::isFile()` is false for a `Symlink` whose `targetType` is unknown (default `ListOptions`), so a symlinked backup file listed before is now dropped (v1 `isDir=false` kept it). *Amend:* "§8.5: keep entries with `type != Directory`, or pass `resolveSymlinkTypes`."
14. **SPEC §8.6** (marked by XH-1 "amends ... 8.6") but XH-1 describes only upload; v2 gives no new text for restore (`<local>.part` then rename). *Amend:* "XH-1: restore keeps §8.6 unchanged (download to `<local>.part`, size check, rename)."
15. **A-3, A-6, SMB §1 "password must not be empty"**: A-3 "exactly one identity, method `password`"; A-6 "missing identity or empty secret = `AuthFailed`". XA-7 amends A-6 for `auth_mode=interactive` only; `guest` (XM-1, no secret) and WebDAV `token` (XA-3) have the same issue, and v1 §3.5/V7 restore sets `CredentialsNeedUpdate` for every restored account, so secretless accounts would show "not signed in". *Amend:* "XA-7: also `security_profile=guest`; `<p>-update.qml` auto-clears `CredentialsNeedUpdate` for secretless accounts."
16. **SPEC §6.1 reserved `<p>-files`** ("MUST NOT be shipped now"; no type given): XA-1 ships it as type `netvfs-files` in `netvfs-files-services`. Also §7.4 "enable switch ... there is only one service". *Amend:* "§6.1 (amended): `<p>-files` ships from 0.2 (XA-1); §7.4 enable switch covers both services."
17. **SPEC §6.2 `backups_path`** is the only service-scoped key; XA-3 `files_root` has no stated scope. *Amend:* "XA-3: `files_root` is service-scoped to `<p>-files`, like `backups_path`."
18. **SPEC §6.4 attention** (sets `CredentialsNeedUpdate`, `CredentialsNeedUpdateFrom=<p>-backup`; the Backup page then stops using the account): XB-14 "set attention as Buteo would" means a browser auth failure disables scheduled backups of the same account, and `CredentialsNeedUpdateFrom` has no value for Files. *Amend:* "§6.4: attention set by a Files run uses `CredentialsNeedUpdateFrom=<p>-files`; state whether it also blocks Backup."
19. **SPEC §7.2 `verify()`** (authenticate, `makePath(backupsPath)`, write/delete `.remotefs-probe-*`, free space) and §7.3 U-3 ("account created only after step 4 succeeds"): for Files accounts (read-only shares, guest, no backups folder) this creates a backups folder or fails. *Amend:* "§7.2/7.3: `verify(service)`; Files verifies `list(files_root)` only and never writes."
20. **§7.3 step 3** ("Confirm server identity. Shown only if the backend returns one (SFTP)"): TLS with `systemTrusted` returns identity but shows no dialog (XC-16). *Amend:* "§7.3 step 3: shown when `checkServerIdentity` returns `ServerIdentityUnknown`."
21. **SMB G-SMB 1, 4; M-6; P-3; D-2**: XM-7 builds a second libsmb2 without the guard and XM-5 allows `vendor/patches`; G-SMB 1 requires the pinned commit to be on upstream `master`, G-SMB 4 that the build never reaches share enumeration, M-6 "compiled out". XM-7 only says "keeps G-SMB item 4 for the plugin". *Amend:* "G-SMB 1 (amended): pinned commit plus a recorded patch set; G-SMB 2/3 and D-2 apply to `netvfs-smb-shares`; G-SMB 4 and M-6 apply to `libnetvfs-smb.so` only."
22. **C-5.1** ("MUST NOT depend on QtGui, QtQuick or Buteo, so that a sandboxed application can link it") and **SPEC §3.6 last row** (future browser links `libremotefs`, Sailjail `Accounts`+`Internet`): v2 header says Harbour apps cannot link accounts-qt5/signon/netvfs; only `netvfs-bridge` links the library (XB-2). The rule still holds in code (`core.pro`: `QT = core dbus`). *Amend:* "C-5.1: the dependency limit stays, but its purpose is linking by `netvfs-bridge` and non-Harbour consumers; sandboxed apps use the bridge (§8a)."
23. **SPEC §5.2 "API is unstable (SONAME 0) until a second consumer exists"; §4.1 `libremotefs.so.0*`** vs XC-1a `libnetvfs.so.1` (library 1.0.0, package 0.2.0). *Amend:* "§5.2: SONAME becomes 1 at API v2 (the browser is the second consumer)."
24. **SPEC §5.2 "shape is normative"** vs XC-8 (`makePath` non-virtual), XC-14 (`read` helper, `freeSpace` helper), `authenticate(…, AuthPrompter*)`, `list(…, ListSink*)`, `AccountSession::open(id, Service, parent)` (XA-4). Only some are marked. *Amend:* "§5.2: replaced by SPEC-v2 §4.10 and XA-4."
25. **SPEC §4.1 package table** vs XP-1: XP-1 says "amends P-*" but the table is §4.1; per-provider file list moves (`<p>-backup.service`, Buteo plugins and profiles to `netvfs-backup-<p>`; QML module to `netvfs-ui`). **P-6** (`%post` msyncd restart) is not assigned to a package; the bridge generator needs `daemon-reload` and unit enabling. *Amend:* "§4.1 (amended): package table of XP-1; `%post` msyncd restart (P-6) moves to `netvfs-backup-<p>`."
26. **SPEC §3.5/A-6 secret readers; XA-6**: XA-6 "exactly two kinds of processes" (Buteo, bridge). v1 also reads secrets in `jolla-settings` (§7.4 "Test connection ... against the stored settings"; §7.5 update flow). *Amend:* "XA-6: three readers (Buteo plugins, bridge, the settings UI process)."
27. **SPEC §2 baseline** lists no libcurl; W-1/F-1 claim "Sailfish ships curl 8.x with OpenSSL and nghttp2" with no tag. v1 evidence rule: untagged = design decision. *Amend:* "W-1: tag with [rpm] and record the minimum curl (`CURLOPT_PROTOCOLS_STR` needs 7.85)."
28. **SPEC §10.1 decision bar** ("build only on a modern, well-maintained foundation") for libnfs (§6.6, "vendored like libsmb2"), and **§10.2 gate** style: no gate defined. *Amend:* "§6.6: NFS ships only after a G-SMB-style gate for libnfs."
29. **SMB M-T3, M-T7, M-T9, S-T-matrix** (expected "refused" for no-encryption / SMB 2.x servers) remain true only under profile `strict`. *Amend:* "Matrices M-T3/M-T7/M-T9 are run with `strict`; XT-2 adds the `signed`/`legacy`/`guest` expectations."
30. **SFTP S-9 / S-8** (changed key never accepted by background plugin; dialog shows full fingerprint in monospace): XB-14 moves ad-hoc first-contact acceptance into the consumer UI via `Question`. *Amend:* "XB-14: the consumer must show the full fingerprint (S-8); accounts still resolve only in Settings (S-9)."
31. **C-16 / XB-18, C-2** minor: C-16 category list closed (see 1.2); C-2 "without user interaction" holds only for stored secrets, not `AuthPrompter`. *Amend:* "C-16: add `netvfs.webdav|ftp|local|bridge|discovery`."

---

## 3. v2 references with no v1 counterpart or a different meaning

| v2 reference | v1 reality | Verdict |
|---|---|---|
| "SPEC 5.4" (§0) | `SPEC §5.4` Errors | correct |
| "C-5.4" (§2) | no such id: C-5 and §5.4 | wrong id |
| "SPEC 8.6" (XH-1) | `SPEC §8.6` BackupRestore | correct id; XH-1 gives no new restore text (2.14) |
| "S-22" (XC-10 "amends S-22 and the SMB rename note") | S-22 = OpenSSH advertises `posix-rename`, `fsync`, `statvfs`, `limits`; backend must still work without them. The rename text lives in `SPEC §5.2` ("replaces `to`"), SFTP §7 rename row, SMB §5 rename row. The code cites "S-22, 7" for the same reason. | different meaning; cite §7/§5 rows |
| "S-14 `interactiveNotSupported`" (XS-11) | S-14 = denial text names the accepted methods. The kbdint refusal is S-11 (other prompt shapes) and S-13 (partial). | wrong id |
| "C-12's free-space check" (XC-19) | free-space check is C-13; C-12 is `.part` upload | wrong id |
| "A-6" (XA-7) | A-6 runtime read, missing/empty = `AuthFailed` | correct |
| "U-*" | not cited anywhere in v2. U-1 (no `OnlineSync*`/`AccountFactory`), U-2, U-3..U-6 and §7.2 `RemoteFsProbe`/`RemoteFsAccountSetup` are replaced in effect by XA-5 `ConnectionDialog`/descriptors without an amendment | unmarked (2.19, 2.20) |
| "P-1..P-6" (§2) | P-1..P-3 build/vendoring; P-4 Requires; P-5 BuildRequires; P-6 `%post` | over-broad |
| "amends P-*" (§10) | the package table is `SPEC §4.1`, not P-* | wrong target |
| "S-21 `RequestWindow`" (XS-7) | S-21 "The request window is 16"; `RequestWindow` is the code constant (`sftpsupport.h`, 16). 16 x 261120 B is about 4 MiB, so the "capped at 4 MiB" is consistent. S-21 chunk rule uses the write limit; reads use the read limit in code | correct (identifier is code) |
| "M-11 `chunkSize`" (XM-6) | M-11 = min(server max write/read size, 1 MiB); `chunkSize()` is the code function | correct |
| "M-9" (XM-4) | M-9 = forbidden characters and trailing space/dot, v1 applies it in the UI to the backups folder; v2 applies it to every name (`WindowsNames`, `Paths::checkWindowsPath`) | correct, wider scope |
| "M-5 neutralisation" (XM-7) | M-5 = explicit `smb2_set_password()`; review must confirm it beats `NTLM_USER_FILE`. "Neutralisation" is not v1 wording; the helper inherits the environment | loose |
| "M-13" (XM-2) | one `smb2_context` per thread | correct (applies to each context) |
| "D-1" (XM-5 "acceptable per D-1") | D-1 pins submodules by commit; says nothing about patches | not covered |
| "G-SMB 4" | G-SMB item 4 (no DCE/RPC, no enumeration call) | correct |
| "C-9", "C-7", "C-8", "C-14", "C-15", "C-16/17", "SEC-1", "SEC-5", "S-7", "S-19", "S-20", "M-1..M-3" | exist with the cited meaning | correct |
| "C-12" (XH-1) | exists | correct |
| "M1" (§13) | v1 milestone M1 = `libremotefs`, SFTP backend, CLI, interop CI; v2 means the file browser's M1 | ambiguous |
| prefix `L-1..L-8` (§6.5) | v1 has limitations `L1..L4` (§13) | near collision |
| "`SPEC §6.2` key `netvfs/<provider>/...`" (XA-3) | v1 `remotefs/sftp/*`, `remotefs/smb/*` plus global `remotefs/host|port|username|attention`; `files_root` scope unstated | see 2.17 |
| "§0: prefixes not in code today" | omits `XB`, `XC-CLI`; v1 uses `S-T`, `M-T`, `G`, `R`, `V` | cosmetic |

No v2 reference was found to a v1 id that does not exist, except `C-5.4`.

---

## 4. Device checks (v1 §12.3) that v2 adds to or depends on

| v1 # | v2 dependency / addition |
|---|---|
| V1 (SDK target builds vendored libs) | add: libcurl headers in the 5.2 SDK target (W-1, F-1; `CURLOPT_PROTOCOLS_STR`, `CURLOPT_PINNEDPUBLICKEY`, `CURLOPT_CONNECT_ONLY` for FTP/TLS); the second libsmb2 build for `netvfs-smb-shares`; libnetvfs soname 1. |
| V2 (provider without `user-group` shows) | applies to new providers `webdav`, `ftp` and to the extra service `<p>-files`; add: custom service type `netvfs-files` is accepted by the Accounts framework and does not appear on the Backup page. |
| V3 (account appears in Settings -> Backup with `SFTP (user@host)`) | add the negative: an account with only a Files service never appears; one with both services still shows once. |
| V4 | unchanged (Buteo path). |
| V5 (account delete removes identity) | depends on XA-6: with extra ACL entries for msyncd and the bridge, deletion must still remove the identity; bridge must drop pooled connections and consent when an account disappears. |
| V6 (secret up to 5 kB round trip) | add: empty secret identity (interactive, guest, XA-7) can be created and read; bearer tokens (W-5). |
| V7 (restore shows not signed in) | add: secretless accounts are not left permanently "not signed in" after restore (2.15). |
| V8 (`msyncd` loads plugins after `%post`) | add: package split moves plugins to `netvfs-backup-<p>` (XP-2 Obsoletes path, already in §13 step 8); bridge `systemd --user` generator and socket units need a `daemon-reload` after install. |
| V9, V10 | unchanged. |
| new (v2 open questions 3, 4) | XA-6: can `netvfs-bridge` read signond identities created by `createSignInCredentials("netvfs","default")` (ACL). XB-15: which settings D-Bus entry points open an account page or the creation flow. |
| new (XB-3..XB-5) | sailjail creates and whitelists `~/.local/share/<Org>/<App>`; the app can connect to a socket there; `/proc/<pid>/exe` of a Harbour app equals `Executable` (apps started through mapplauncherd boosters may report the booster binary: verify); `pidfd` support on the 5.2 kernel; user-generator support on the shipped systemd. |
| new (XD-1) | binding UDP 5353 with multicast on the 5.2 network stack (connman) works without an mDNS daemon; v1 L2 (`.local` depends on the platform resolver) shows this was never confirmed. |
| new (XM-1) | libsmb2 at the pinned commit signs SMB 2.x (HMAC-SHA256), supports guest sessions and exposes `SMB2_SESSION_FLAG_IS_GUEST`; v1 §6 evidence covers SMB 3 only (M-T9 and M-T11 are still "to do"). |
| new (XS-4, XS-6) | OpenSSH symlink argument order and which libssh call performs a non-replacing rename (code comment: `sftp_rename` uses `posix-rename`). |
| acceptance tests (§12.4) | 5 (stale `.part` removed after 24 h) and 9 (restore) must be re-run after XH-1 resume and the package split (XT-6). |
