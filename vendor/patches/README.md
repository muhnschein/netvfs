# Local patches on vendored libraries

`vendor/build-vendor.sh` applies `vendor/patches/<library>/*.patch` (in name
order) to a copy of the pinned submodule before building, so the submodule
checkout itself stays at the pinned commit (SPEC D-1).

## libsmb2 (pin `e80c1a48`)

Fixes for undefined behaviour that UndefinedBehaviorSanitizer reports in the
SMB interop suite (gate G-SMB item 3). None of them reads or writes out of
bounds. All three still apply to upstream `master` as of `b82d570`
(2026-10-01) and are meant to be submitted upstream; drop each patch once a
pin bump contains it.

| Patch | Report |
|---|---|
| `0001-ntlmssp-do-not-memcpy-from-a-NULL-buffer.patch` | `nonnull-attribute` in `encoder()` |
| `0002-smb3-seal-store-the-session-id-with-memcpy.patch` | `alignment` in `smb3_encrypt_pdu()` |
| `0003-unicode-count-leading-1-bits-on-an-unsigned-char.patch` | `shift-base` in `l1()` |

Additions for SPEC-v2 §6.2 (accepted per D-1 as amended by the v2 review,
item 21; to be proposed upstream):

| Patch | Why |
|---|---|
| `0004-session-setup-record-the-session-flags.patch` | XM-1: `smb2_get_session_flags()`. A session the server mapped to guest (`SMB2_SESSION_FLAG_IS_GUEST`, or anonymous `_IS_NULL`) is refused for every profile but `guest`. The flags are recorded before the signing checks, so the backend can name the reason also when the (unsignable) guest session made the sign-in fail. |
| `0005-rename-add-smb2_rename_replace_async.patch` | XM-5, open question 1: `smb2_rename_replace_async()` sends FileRenameInformation with `ReplaceIfExists`, so `rename(Replace)` is one atomic request (`AtomicReplace`) instead of stat + unlink + rename. |
| `0006-unicode-keep-unpaired-surrogates-as-WTF-8.patch` | XC-4 for SMB: Windows names may hold unpaired UTF-16 surrogates; libsmb2 turned them into U+FFFD, so such files could be listed but not opened, renamed or deleted. They now travel as WTF-8 (the 3-byte form of the surrogate) in both directions; the backend maps that form to the lone `QChar` and back (`decodeName`, `encodeName`). |

`vendor/build-vendor.sh` builds libsmb2 twice from the same pin and patches:
the plugin's copy without libdcerpc (`<prefix>`, G-SMB item 4 together with
`src/backends/smb/noshareenum.c`) and, for the share enumeration helper
`netvfs-smb-shares` only (XM-7), a copy with DCE/RPC (`<prefix>/dcerpc`).

## libssh (pin `07430deb`, 0.12.2)

| Patch | Why |
|---|---|
| `0001-sftp-add-sftp_rename_noreplace.patch` | `sftp_rename()` always prefers `posix-rename@openssh.com`, which replaces the target; SPEC-v2 XS-6 needs a plain `SSH_FXP_RENAME` for `RenameMode::NoReplace` (OpenSSH fails it on an existing target). To be proposed upstream. |
| `0002-sftp-interruptible-blocking-waits.patch` | Blocking sftp calls wait for the whole session timeout and cannot be stopped; C-9 needs `cancel()` to end every wait within 2 s. Adds `sftp_set_interrupt_callback()` (asked every 100 ms while no data of the response has arrived; the abandoned response is dropped when it comes) and `sftp_aio_discard()` (drop the late response of an abandoned asynchronous request instead of keeping it queued until `sftp_free()`, which bounds memory after cancels, C-10). Used by the SFTP backend for every request. To be proposed upstream. |
| `0003-sftp-free-the-attributes-of-the-mkdir-eexist-check.patch` | `sftp_mkdir()` releases the attributes of its EEXIST check with `SAFE_FREE()`, leaking the strings they own (LeakSanitizer in the SFTP conformance run against ProFTPD, which sends extended attributes). To be proposed upstream. |
