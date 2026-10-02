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

## libssh (pin `07430deb`, 0.12.2)

| Patch | Why |
|---|---|
| `0001-sftp-add-sftp_rename_noreplace.patch` | `sftp_rename()` always prefers `posix-rename@openssh.com`, which replaces the target; SPEC-v2 XS-6 needs a plain `SSH_FXP_RENAME` for `RenameMode::NoReplace` (OpenSSH fails it on an existing target). To be proposed upstream. |
