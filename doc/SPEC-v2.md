# netvfs — SPEC, API v2 (file-browser extensions)

Status: draft 2, against branch `foundations` at `f49242b` (PR #1), libssh pin
`07430deb` (0.12.2), libsmb2 pin `e80c1a48`.

Changes since draft 1: the file browser (`lautta/SPEC.md`) is now a sandboxed Harbour app
that cannot link libnetvfs (Harbour does not allow accounts-qt5, libsignon-qt5 or netvfs
itself). It reaches netvfs through a new component, `netvfs-bridge` (§8a, `XB-*`).
Consequences: the bridge is the only file-browser-side reader of secrets (XA-6), the
local backend is no longer needed by that consumer (§6.3), discovery and account UI
handoff are served through the bridge (XD-5, XB-15), and packaging gains the bridge
(XP-1).

## 0. How this document relates to the existing spec

The code cites an existing specification (`SPEC 5.4`, `C-8`, `C-15`, `SPEC-sftp S-19`,
`SPEC-smb M-3`, `SEC-5`, gate `G-SMB`, …), but those documents are not in the repository
(`.gitignore` excludes `/.claude/`, which is the likely home). This document was written
from the code and its comments, so:

- Existing IDs keep their meaning. Where this document changes one, it says
  "amends C-n" and gives the new text.
- New requirements use prefixes that do not occur in the code today: `XC` core API, `XH`
  core helpers, `XS` SFTP, `XM` SMB, `L` local, `XD` discovery, `XA` accounts, `XP`
  packaging, `XT` tests, `XSEC` security.
- First action item: commit the existing SPEC, SPEC-sftp and SPEC-smb under `doc/`, and
  merge this file next to them as `doc/SPEC-v2.md`. The interpretations in §2 should be
  checked against the originals.

## 1. Goals and non-goals

### 1.1 Goals

1. Serve two consumers: the existing Buteo backup integration (in-process) and an
   interactive file browser (`lautta/SPEC.md`), which is a sandboxed Harbour app served
   through `netvfs-bridge` (§8a), without weakening any backup guarantee.
2. Give backends the operations and metadata a file manager needs: full entry metadata,
   lossless names, streaming listings, rename/remove semantics a user can reason about,
   attributes, symlinks, random-access handles, resume, server-side copy, space info.
3. Add a local backend; prepare S3 and NFS.
4. Make SMB usable for browsing: server mode (shares as top-level folders), share
   enumeration, and explicit security profiles beyond "SMB 3 with encryption".
5. Split packaging so installing the bridge does not pull in Buteo, and installing backups
   does not pull in browser-only pieces.
6. Let sandboxed apps use netvfs locations without ever giving them secrets, pins or
   access to local paths outside their sandbox (§8a).

### 1.2 Non-goals

- A sync engine, transfer queue, cache or UI inside netvfs. Those belong to consumers.
- FUSE. A FUSE front end, if built, is a consumer.
- Asynchronous backend API. The blocking, thread-confined model (C-8) stays; consumers
  pool backends on threads. This keeps backends simple and the C-9 cancel guarantee
  testable.

## 2. Current state (summary of `foundations`)

| Area | Today | Gap for a file browser |
|---|---|---|
| `Backend` | blocking, thread-confined; connect/authenticate; stat, list, makePath, remove, rename, freeSpace, upload, download, read; cancel/resetCancel/disconnect | no handles, no attributes, no symlinks, no copy, no exclusive create, list is all-at-once |
| `Entry` | name, size, modified, isDir | no type (symlink/special), mode, owner, created, hidden/readonly, etag |
| Names | `QString::fromUtf8` on SFTP bytes | non-UTF-8 names are lossy; such files cannot be renamed or deleted |
| `rename` | always replaces (SFTP via posix-rename or stat+unlink; SMB stat+unlink) | browser needs no-replace by default; SMB replace is non-atomic |
| `remove` | file, or empty directory (SFTP falls back to rmdir) | fine as primitive; no tree removal helper; no distinction for UX |
| `read` | opens and closes the file per call (SMB, SFTP) | too slow for streaming, previews and archives |
| Upload | always `.part` + rename, files created 0600 (S-20) | browser needs resume, normal modes, atomic-put awareness, mtime |
| SMB policy | SMB 3.x only, signing required, encryption default on (M-1..M-3), one share per connection, share enumeration linked out (`noshareenum.c`, G-SMB 4) | no share browsing; many home NAS need SMB 2.1 or guest |
| SFTP auth | password, public key; keyboard-interactive refused | 2FA/OTP servers unusable |
| Accounts | providers `sftp`, `smb`, one service `<p>-backup` of type `storage` | no "files" service; account UI hard-codes SFTP/SMB fields |
| Packaging | backend `.so` shipped inside `netvfs-account-<p>` together with Buteo plugins; QML module in `netvfs-core` | browser would drag in Buteo, jolla-vault, msyncd |

What stays exactly as is: error-taxonomy approach (C-5.4), C-7 (no credentials before
identity check), C-9 (cancel within 2 s), C-10 (bounded memory), C-14 timeouts, C-15 path
normalisation, C-16/C-17 logging rules, SEC-5 secret wiping, the vendoring approach
(D-1, P-1..P-6), the test culture (unit, interop containers, sanitizers, mutation lists,
SonarCloud with zero open issues).

## 3. Versions

- XC-1: Plugin IID `org.netvfs.BackendFactory`; the extension interfaces are
  `org.netvfs.SshKeyTools` and `org.netvfs.ShellExec`. libnetvfs, its backends and every
  caller are built from one source tree and ship together.
- XC-1a: Library version `1.0.0` (qmake derives soname `libnetvfs.so.1`); package
  version `0.5.0`. All netvfs subpackages require the exact same `%{version}-%{release}`
  of `netvfs` so mixed installs cannot happen.
- XC-1c: Qt 5.6 and C++17 remain the baseline. No exceptions cross the API; `Result` is
  the only error channel. No `std::optional` in exported structs (ABI and QVariant
  friction); sentinels are documented per field.

## 4. Core API v2

### 4.1 Entries

- XC-2: `Entry` becomes:

```cpp
enum class EntryType : quint8 { Unknown, File, Directory, Symlink, Special };

enum class EntryFlag : quint16 {
    Hidden        = 0x0001,  // SMB hidden attribute; dot-names are NOT flagged here
    ReadOnly      = 0x0002,  // SMB read-only attribute
    System        = 0x0004,  // SMB system attribute
    NameNotUtf8   = 0x0008,  // XC-4: name contains escaped bytes
    TargetUnknown = 0x0010   // symlink whose target type could not be determined
};
Q_DECLARE_FLAGS(EntryFlags, EntryFlag)

struct NETVFS_EXPORT Entry {
    QString name;                    // XC-4 lossless
    EntryType type = EntryType::Unknown;
    EntryType targetType = EntryType::Unknown;  // for Symlink, when resolved (XC-6)
    qint64 size = -1;                // -1 unknown (v1 used 0)
    QDateTime modified;              // UTC; invalid if unknown
    QDateTime created;               // SMB, local (statx btime)
    QDateTime accessed;
    qint32 mode = -1;                // permission bits & 07777; -1 unknown
    qint64 uid = -1, gid = -1;
    QString owner, group;            // names when the server provides them
    EntryFlags flags;
    QByteArray etag;                 // opaque change token; empty if none
    QString contentType;             // server-declared; advisory only, never trusted
    QVariantMap extra;               // backend-specific (SMB "remark"), documented per backend

    bool isDir() const;              // Directory, or Symlink whose targetType is Directory
    bool isFile() const;             // File, or Symlink whose targetType is File
};
```

- XC-3: Callers that need "is this a folder" use `isDir()`. Backup code that relied on
  `size == 0` for unknown sizes is updated to check `size < 0`.

### 4.2 Lossless names

- XC-4: Names are decoded from server bytes with a reversible "surrogate escape" codec:
  well-formed UTF-8 decodes normally; every byte of an ill-formed sequence `b` (0x80–0xFF)
  becomes the lone surrogate `U+DC00 + b`. Encoding reverses this exactly. Entries with
  escaped bytes carry `NameNotUtf8`. `Paths::normalize` accepts lone surrogates; it still
  rejects NUL, `.` and `..` (C-15 unchanged otherwise). Applies to SFTP and local. SMB
  names arrive as UTF-16; unpaired UTF-16
  surrogates (possible on Windows servers) are passed through as-is if libsmb2 preserves
  them, otherwise the entry is flagged and operations on it return `InvalidName`.
- XC-4a: New helpers `Names::decode(QByteArray) -> QString`, `Names::encode(QString) ->
  QByteArray`, `Names::display(QString) -> QString` (escapes rendered as U+FFFD) in
  `names.h`. No backend calls `QString::fromUtf8` on remote names any more.
- XC-4b: Normalisation forms are not touched (no NFC/NFD conversion). Consumers compare
  names byte-exact unless the location reports `CaseInsensitive` (XC-5).

### 4.3 Capabilities

- XC-5: `virtual Capabilities capabilities() const` — valid after `authenticate()`;
  stable for the life of the connection.

```cpp
enum class Capability : quint32 {
    Symlinks, Hardlinks, PosixModes, Ownership, SetModified, SetModifiedOnUpload,
    ReadHandles, EfficientRanges,        // ranged reads without reopening per call
    WriteResume,                         // openWrite(Resume)
    AtomicPut,                           // a PUT/write is atomic: no temp name needed
    AtomicReplace,                       // rename(Replace) is atomic
    NativeNoReplace,                     // rename(NoReplace) is enforced by the server
    ServerCopy, ServerCopyRecursive,
    RecursiveDelete,                     // native tree delete exists (see XC-9)
    SpaceInfo, Checksums,
    CaseInsensitive, WindowsNames,       // name rules of Paths::checkWindowsPath apply
    ShareEnumeration,                    // SMB server mode can list shares
    ShellExec,                           // XS-9
    ETags
};
struct Capabilities {
    QSet<Capability> flags;                // QSet keeps the enum open for growth
    QStringList checksumAlgorithms;        // "sha256", "md5", ...
    qint64 maxNameBytes = -1;              // -1 unknown
    qint64 maxReadChunk = 0, maxWriteChunk = 0;
    bool has(Capability c) const { return flags.contains(c); }
};
```

### 4.4 Listing, stat

- XC-6: Streaming list:

```cpp
class ListSink {
public:
    virtual ~ListSink() = default;
    // Called on the backend thread. Return false to stop (result: Canceled).
    virtual bool entries(const QVector<Entry> &batch) = 0;
};
struct ListOptions {
    int batchSize = 256;
    bool resolveSymlinkTypes = false;  // stat each symlink target to fill targetType
};
virtual Result list(const QString &dir, ListSink *sink, const ListOptions &options) = 0;
// Non-virtual convenience, collects into a vector (used by Buteo and CLI):
Result list(const QString &dir, QVector<Entry> *out);
```

  Batches are delivered as the protocol produces them (SFTP READDIR replies, SMB
  QUERY_DIRECTORY responses). `.` and `..` never appear.
  `cancel()` is honoured between batches and within the protocol wait (C-9).
- XC-7: `stat(path, Entry*)` keeps following symlinks; new `lstat(path, Entry*)`
  returns the link itself. Backends without symlinks implement `lstat` as `stat`.

### 4.5 Namespace operations

- XC-8: `makeDir(path, bool exclusive)`: creates one folder; with `exclusive`, an
  existing entry is `AlreadyExists`; without, an existing folder is success.
  `makePath` (mkdir -p) remains a core helper built on `makeDir` (no longer virtual).
- XC-9: `removeFile(path)` removes a non-directory (a symlink is removed, not its
  target); on a directory it returns `IsADirectory`. `removeDir(path)` removes an empty
  folder; non-empty is `DirectoryNotEmpty`. `remove(path)` stays as a non-virtual
  helper with today's semantics (file, else empty dir) for Buteo. Native recursive
  deletes are reachable only through
  `removeTreeNative(path)` and only when `RecursiveDelete` is reported; the core helper
  `removeTree` (XH-2) is what consumers normally use.
- XC-10: `rename(from, to, RenameMode mode)` with `enum class RenameMode { NoReplace,
  Replace }`. NoReplace returns `AlreadyExists` if `to` exists — atomically when
  `NativeNoReplace`, otherwise via a stat check (documented race). Replace keeps today's
  behaviour (amends S-22 and the SMB rename note: still "replaces `to`" when Replace is
  requested; atomic only with `AtomicReplace`). Replacing a folder with anything is
  `AlreadyExists` in both modes. `Transfer::upload` and Buteo pass `Replace`.
- XC-11: `setAttributes(path, const AttributeChanges &)`:
  `struct AttributeChanges { qint32 mode = -1; QDateTime modified; QDateTime accessed; }`.
  Unsupported fields return `Unsupported` without changing anything else (the backend
  checks first). No chown.
- XC-12: Links: `readLink(path, QString *target)`, `makeSymlink(target, linkPath)`,
  `makeHardlink(existing, newPath)`; each `Unsupported` unless the capability is set.
  Targets are returned and accepted verbatim (not normalised, may be relative).

### 4.6 Handles and streaming I/O

- XC-13: Handles for random access and resumable writes:

```cpp
class NETVFS_EXPORT ReadHandle {
public:
    virtual ~ReadHandle();
    virtual qint64 size() const = 0;                    // at open time; -1 unknown
    virtual Result read(qint64 offset, qint64 maxBytes, QByteArray *out) = 0;  // short read only at EOF
    virtual void readAhead(qint64 offset, qint64 bytes) = 0;  // hint; may be a no-op
    virtual Result close() = 0;
};
struct WriteOptions {
    enum Disposition { CreateNew, Truncate, Resume } disposition = CreateNew;
    qint64 resumeOffset = 0;          // Resume: must equal current remote size
    qint32 createMode = -1;           // -1: backend default (XC-23)
    qint64 expectedSize = -1;         // allows preallocation / Content-Length
    QDateTime modified;               // applied on commit when SetModified/OnUpload
};
class NETVFS_EXPORT WriteHandle {
public:
    virtual ~WriteHandle();
    virtual Result write(const char *data, qint64 length) = 0;  // sequential
    virtual qint64 position() const = 0;
    virtual Result commit() = 0;      // flush (fsync where available), close, apply mtime
    virtual void abort() = 0;         // close without commit; partial data may remain
};
virtual Result openRead(const QString &path, ReadHandle **out);                 // default: Unsupported
virtual Result openWrite(const QString &path, const WriteOptions &, WriteHandle **out);
```

  Handles belong to their backend and its thread; the backend invalidates open handles on
  `disconnect()` (later calls return `ConnectionLost`). A backend may limit open handles
  (documented per backend, at least 4). `cancel()` interrupts handle calls with the same
  C-9 guarantee. Memory stays bounded (C-10): `read()` never buffers more than `maxBytes`
  plus one protocol chunk; read-ahead is capped per backend.
- XC-14: Streaming `upload`/`download` gain options and keep their tuned
  implementations:

```cpp
struct UploadOptions  { WriteOptions write; };
struct DownloadOptions { qint64 offset = 0; qint64 length = -1; };
virtual Result upload(QIODevice *source, const QString &path, const UploadOptions &, Progress *);
virtual Result download(const QString &path, QIODevice *sink, const DownloadOptions &, Progress *);
```

  `read(path, offset, length, out)` becomes a non-virtual helper over `openRead`.
  `Progress::update(done, total)` additionally gets `bool Progress::canceled() const`
  (default false) so sinks can stop without a cross-thread `cancel()`.
- XC-23: Create modes (amends S-20): the backend default for new files is `0644 & ~umask`
  semantics as the server applies them (SFTP sends no mode → server umask; local uses
  the process umask). Backup code passes `createMode = 0600` explicitly, preserving S-20
  for backups. Folders: default server/umask behaviour; backups keep their current mode.

### 4.7 Server-side work

- XC-17: `copy(from, to, const CopyOptions &)` with
  `struct CopyOptions { bool recursive = false; RenameMode mode = RenameMode::NoReplace; }`.
  `Unsupported` unless `ServerCopy` (and `ServerCopyRecursive` for folders).
- XC-18: `checksum(path, const QString &algorithm, QByteArray *digest)` — `Unsupported`
  unless listed in `checksumAlgorithms`. Digests are raw bytes.
- XC-19: `spaceInfo(dir, SpaceInfo *)` with `struct SpaceInfo { qint64 free = -1, total
  = -1, used = -1; }`. `freeSpace` becomes a helper over it (C-12's free-space check
  unchanged).
- XC-20: `keepAlive()` — one cheap round trip that proves the connection is alive
  (SFTP `keepalive@openssh.com` or SSH_MSG_IGNORE + reply wait, SMB ECHO, local:
  success). Returns `ConnectionLost` on a dead transport.

### 4.8 Authentication and identity

- XC-15: Interactive authentication:

```cpp
struct AuthPrompt { QString text; bool echo = false; };
class AuthPrompter {
public:
    virtual ~AuthPrompter() = default;
    // Called on the backend thread; may block until the user answers.
    // Returns false if the user declined (result: AuthFailed) or on cancel().
    virtual bool answer(const QString &name, const QString &instruction,
                        const QVector<AuthPrompt> &prompts, QVector<QByteArray> *answers) = 0;
};
virtual Result authenticate(const Credentials &credentials, AuthPrompter *prompter) = 0;
```

  Answers are wiped after use (SEC-5). A backend may call the prompter several times
  (multi-round keyboard-interactive). With `prompter == nullptr`, interactive methods are
  not attempted (backup behaviour unchanged).
- XC-16: `ServerIdentity` v2 (amends the struct in `types.h`):

```cpp
struct NETVFS_EXPORT ServerIdentity {
    enum class Kind { None, SshHostKey } kind = Kind::None;
    QString algorithm;        // "ssh-ed25519"
    QByteArray publicKey;     // key blob
    QString fingerprint;      // "SHA256:..."
    QString toPin() const;    // "<algorithm> <base64 publicKey>"
    static ServerIdentity fromPin(const QString &pin);
};
```

  `checkServerIdentity` (amends S-7): no pin → `ServerIdentityUnknown`; pin present →
  the key must match, else `ServerIdentityChanged`. Pins stay in the existing `host_key`
  account key.

### 4.9 Errors

- XC-21: New `Error` values (`errorName()` strings documented): `ConnectionLost`,
  `NotADirectory`, `IsADirectory`, `DirectoryNotEmpty`, `InvalidName`,
  `ReadOnlyFilesystem`, `Locked` (SMB sharing violation), `TooManyConnections` (SFTP
  channel open refused by MaxSessions, SMB limits), `RateLimited` (the server asks to
  wait, Retry-After). `NetworkUnreachable` keeps meaning "could not reach"; dropping an
  established connection becomes `ConnectionLost` (amends the SMB `connectionLost()`
  mapping after session setup; Buteo maps both to the same attention-free retryable
  failure).
- XC-24: `Result` gains `qint64 retryAfterMs() const` (−1 none) and `QString detail()
  const` (protocol status for logs and the "Details" view, never secrets, debug-level
  rules of C-17 apply to paths in it).
- XC-22: Cancellation (C-9) and timeouts (C-14) apply to every new method, including
  `AuthPrompter` waits (cancel ends the wait) and handle calls.

### 4.10 Full v2 `Backend`

```cpp
class NETVFS_EXPORT Backend {
public:
    virtual ~Backend();
    virtual Result connect(const ConnectionParams &, ServerIdentity *seen) = 0;
    virtual Result authenticate(const Credentials &, AuthPrompter *prompter) = 0;
    virtual Capabilities capabilities() const = 0;

    virtual Result stat(const QString &path, Entry *out) = 0;
    virtual Result lstat(const QString &path, Entry *out);
    virtual Result list(const QString &dir, ListSink *sink, const ListOptions &) = 0;

    virtual Result makeDir(const QString &path, bool exclusive) = 0;
    virtual Result removeFile(const QString &path) = 0;
    virtual Result removeDir(const QString &path) = 0;
    virtual Result removeTreeNative(const QString &path);                       // Unsupported
    virtual Result rename(const QString &from, const QString &to, RenameMode) = 0;
    virtual Result setAttributes(const QString &path, const AttributeChanges &); // Unsupported
    virtual Result readLink(const QString &path, QString *target);               // Unsupported
    virtual Result makeSymlink(const QString &target, const QString &linkPath);  // Unsupported
    virtual Result makeHardlink(const QString &existing, const QString &newPath);// Unsupported

    virtual Result openRead(const QString &path, ReadHandle **out);              // Unsupported
    virtual Result openWrite(const QString &path, const WriteOptions &, WriteHandle **out); // Unsupported
    virtual Result upload(QIODevice *, const QString &path, const UploadOptions &, Progress *) = 0;
    virtual Result download(const QString &path, QIODevice *, const DownloadOptions &, Progress *) = 0;

    virtual Result copy(const QString &from, const QString &to, const CopyOptions &); // Unsupported
    virtual Result checksum(const QString &path, const QString &algorithm, QByteArray *); // Unsupported
    virtual Result spaceInfo(const QString &dir, SpaceInfo *out);                // Unsupported
    virtual Result keepAlive() = 0;

    virtual void cancel() = 0;          // thread-safe (C-9)
    virtual void resetCancel() = 0;
    virtual void disconnect() = 0;

    // Non-virtual helpers (Buteo, CLI):
    Result list(const QString &dir, QVector<Entry> *out);
    Result remove(const QString &path);
    Result read(const QString &path, qint64 offset, qint64 length, QByteArray *out);
    Result freeSpace(const QString &dir, qint64 *bytes);
};
```

## 5. Core helpers

- XH-1: `Transfer` (amends C-12, C-13, 8.6): `upload` takes a `TransferPolicy`:
  `{ QString tempName (default "<name>.part" — backup), bool useTempName (default true;
  consumers pass false when AtomicPut), bool verifySize (true), RenameMode commitMode
  (Replace for backup), qint32 createMode, QDateTime modified, bool resume }`. Resume
  uses `openWrite(Resume)` on the temporary name and checks `resumeOffset` equals the
  remote temp size before writing. `removeStaleParts` gets the temp-name pattern as a
  parameter.
- XH-2: `Ops::removeTree(Backend*, path, TreeProgress*, bool useNative=false)`: depth-
  first, lists then deletes, never follows symlinks, reports counts, honours cancel
  between entries, stops at the first error unless `continueOnError`.
- XH-3: `Ops::walk(Backend*, root, WalkVisitor*, WalkOptions)`: streaming recursive
  traversal (pre/post order), symlink policy (never/follow with loop detection by path
  set), depth limit, used by planners, search, size calculation.
- XH-4: `BoundedPipe`: a pair of `QIODevice`s (writer/reader) over a ring buffer of a given
  capacity with blocking read/write, EOF, error propagation (`fail(Result)` on either side
  makes both sides return it) and cancel. Used for backend-to-backend streaming copies
  (two threads, two backends, constant memory).
- XH-5: `Ops::copyAcross(Backend *src, Backend *dst, ...)` reference implementation on
  `BoundedPipe` for the CLI and tests (consumers may schedule their own).
- XH-6: `Url`: parse and format `sftp://`, `ssh://`, `smb://host[/share[/path]]`,
  `file://` into/from
  `ConnectionParams` + path. User info may contain a user name; a password in a URL is
  rejected with `Result(Error::SecurityPolicy, "passwords in URLs are not accepted")`
  and never stored. IDN hosts are kept in Unicode for display, punycode
  on the wire. IPv6 literals in brackets.
- XH-7: `Names` (XC-4a) and `Paths::sanitizeFor(const Capabilities &, name) -> QString`
  proposing a safe name for a destination (Windows rules, max length in bytes).

## 6. Backends

### 6.1 SFTP (amends SPEC-sftp)

- XS-1: Lossless names via `Names` in list, stat, readLink and path translation.
- XS-2: Entry mapping: `type` from attribute type (symlink, special for socket/fifo/
  device), `mode`, `uid`/`gid`, `accessed`, `owner`/`group` from
  `users-groups-by-id@openssh.com` (libssh `sftp_get_users_groups_by_id`, batched per
  listing, cached per connection) when supported, else empty. Hidden flag is never set
  (dot-names are a consumer convention).
- XS-3: `list` uses `lstat` semantics (as READDIR does); with `resolveSymlinkTypes`,
  targets are `stat`ed with a per-listing cap of 512 resolutions (beyond that
  `TargetUnknown`).
- XS-4: Links: `sftp_readlink`, `sftp_symlink`, `sftp_hardlink` (when
  `hardlink@openssh.com` is offered). OpenSSH's server swaps the SSH_FXP_SYMLINK
  arguments relative to the draft; verify libssh's argument order against the OpenSSH
  container in the interop suite and against at least one non-OpenSSH server (e.g. the
  `sftpproxy.py` path through to Dropbear or ProFTPD mod_sftp) before enabling
  `Symlinks` for unknown servers.
- XS-5: `setAttributes` via `sftp_setstat` (mode, atime/mtime). `SetModified`,
  `PosixModes` reported.
- XS-6: Rename: NoReplace uses plain `SSH_FXP_RENAME` (OpenSSH implements it with
  link+unlink, failing on an existing target → `NativeNoReplace` for OpenSSH servers,
  identified by the version banner; others get the stat-check path). Replace uses
  `posix-rename@openssh.com` when offered (`AtomicReplace`), else stat+unlink+rename as
  today.
- XS-7: Handles: `ReadHandle` over an open `sftp_file` with `sftp_aio` read-ahead
  (window `RequestWindow` from S-21, capped at 4 MiB in flight); `WriteHandle` with
  pipelined `sftp_aio` writes; Resume opens without `O_TRUNC` and checks the size equals
  `resumeOffset`. `commit()` sends `fsync@openssh.com` when offered (unchanged from
  today's upload).
- XS-8: `spaceInfo` from `statvfs@openssh.com` (free = f_bavail × f_frsize, total =
  f_blocks × f_frsize).
- XS-9: Shell exec (capability `ShellExec`), only when the account option
  `allow_shell=true` and the server grants an exec channel. API:
  `Result exec(const QStringList &argv, const ExecOptions &, ExecResult *)` on the SFTP
  backend's extension interface `org.netvfs.ShellExec` (not part of `Backend`).
  argv is quoted with POSIX single-quote rules by netvfs; stdout/stderr capped (default
  1 MiB), timeout, cancel (channel close + `Canceled`). Never invoked by netvfs itself
  except through documented helpers: `serverCopy` (`cp -pR -- src dst` /
  `cp -p -- src dst`), `serverChecksum` (`sha256sum -- path`, then `shasum -a 256`
  fallback), `serverFind` (fixed template). Results are parsed defensively; any parse
  failure is `Unsupported`, not a guess. With these helpers the backend reports
  `ServerCopy`, `ServerCopyRecursive` and `Checksums: sha256`.
- XS-10: `copy-data` (OpenSSH) is not exposed by libssh 0.12.2; track upstream and
  switch `ServerCopy` to it when available, keeping shell as fallback.
- XS-11: Keyboard-interactive (amends S-14 `interactiveNotSupported`): attempted after
  publickey/password methods fail or when the account's `auth_mode=interactive`, only
  with an `AuthPrompter`. Partial success chains (publickey then OTP) are supported.
  New account `auth_mode` value `interactive` with optional stored secret.
- XS-12: `keepAlive` sends `keepalive@openssh.com` global request with want-reply and
  waits for any reply (failure reply counts as alive).
- XS-13: ProxyJump (later): account option `jump_host` (`user@host:port`) using libssh
  `SSH_OPTIONS_PROXYJUMP` with its own pinned identity (`jump_host_key`) — identity checks
  apply to every hop (C-7 per hop). Out of scope for 0.2.

### 6.2 SMB (amends SPEC-smb)

- XM-1: Security profiles (amends M-1, M-2, M-3; option `security_profile`, default
  `strict`):

  | Profile | Dialects | Signing | Encryption | Allowed for service |
  |---|---|---|---|---|
  | `strict` | 3.0–3.1.1 | required | required | backup, files |
  | `signed` | 3.0–3.1.1 | required | if server offers | backup, files |
  | `legacy` | 2.0.2–3.1.1 | required | if offered | files |
  | `guest` | 2.0.2–3.1.1 | off | off | files (explicit consent) |

  The account UI and
  `AccountSession` enforce the "allowed for service" column (XA-4); the backend enforces
  the profile it is given and still refuses any dialect it did not offer (M-1 defence in
  depth). `guest` uses an empty user name and no password; servers that map guest are
  detected (`SMB2_SESSION_FLAG_IS_GUEST`) and, for any other profile, a guest mapping is a
  `SecurityPolicy` failure (a server silently downgrading credentials to guest is never
  accepted).
- XM-2: Server mode: when the `share` option is empty, the backend's root lists shares
  (directories, `type = Directory`, flag `ReadOnly` absent); paths are `/<share>/<rest>`.
  Each share gets its own libsmb2 context, created lazily on first use, authenticated with
  the same credentials, at most 4 concurrently (LRU close). Operations on `/` other than
  `list`/`stat` return `PermissionDenied`; on `/<share>` itself, `removeDir`/`rename`
  return `PermissionDenied`. M-13 thread confinement applies to all contexts.
- XM-3: Share list sources, merged and de-duplicated: the account option `shares`
  (string list the user saved), and, when enabled, share enumeration (XM-7). Without
  either, root lists nothing and the UI asks for a share name.
- XM-4: Entry mapping: `created` from birth time, `Hidden`/`ReadOnly`/`System` from file
  attributes, `type` Symlink for reparse points reported as such (target `Unsupported`
  to read), `CaseInsensitive` and `WindowsNames` capabilities (M-9 rules already in
  `Paths`).
- XM-5: Rename NoReplace is native (libsmb2 renames without ReplaceIfExists:
  `NativeNoReplace`); Replace keeps stat+unlink+rename (non-atomic, no `AtomicReplace`)
  until libsmb2 exposes `ReplaceIfExists` (track; a local patch under `vendor/patches`
  is acceptable per D-1).
- XM-6: Handles: `ReadHandle` keeps one `smb2fh` open with pipelined reads of
  `chunkSize` (M-11) up to 4 MiB in flight; `WriteHandle` likewise; Resume opens without
  truncate. `setAttributes` supports `modified`/`accessed` via SET_INFO
  (FileBasicInformation); `PosixModes` not reported.
- XM-7: Share enumeration runs out of process (keeps G-SMB item 4 for the plugin): helper
  `/usr/libexec/netvfs/netvfs-smb-shares`, linked against the same vendored libsmb2
  without `noshareenum.c`, applies the same profile settings, reads a request (params,
  secret) as length-prefixed data on stdin (never argv or environment; M-5 neutralisation
  applies), writes JSON lines `{"name","type","remark"}` on stdout, exits. The backend
  spawns it with `posix_spawn`, enforces the connect/request timeouts, kills it on
  cancel, accepts only `STYPE_DISKTREE` shares, and hides `$`-suffixed admin shares
  unless `show_admin_shares=true`. Any helper crash or malformed output is
  `ProtocolError` and leaves the backend usable. Shipped with the backend in `netvfs`
  (XP-3); `ShareEnumeration` is still reported only when the helper is present.
- XM-8: `keepAlive` sends SMB2 ECHO. `spaceInfo` from FileFsFullSizeInformation.
- XM-9: DFS referrals and Kerberos stay out of scope; DFS paths return `Unsupported`
  with detail "DFS referral".

### 6.3 Local (new plugin `libnetvfs-local.so`)

Priority note (draft 2): the Harbour file browser handles local files itself inside its
sandbox, and the bridge never touches local paths (XB-11). The local backend remains
useful for the conformance suite (a fast, container-free target), the CLI, and future
in-process consumers, but it is no longer on the file browser's critical path.

- L-1: POSIX implementation for the local file system; `connect` succeeds immediately,
  identity `Kind::None`, credentials ignored. Option `root` (default `/`); relative paths
  are relative to `root`, absolute paths allowed (C-15 meaning "backend-defined" =
  filesystem absolute).
- L-2: Names: raw bytes via `Names` (XC-4). Entry from `statx` (birth time where the
  filesystem has it), `lstat` semantics in listings, `targetType` via `stat` when asked.
- L-3: All namespace operations; `renameat2(RENAME_NOREPLACE)` for NoReplace where the
  kernel and filesystem support it (fallback `link`+`unlink` for files, stat check for
  folders); `rename` for Replace (`AtomicReplace`).
- L-4: Copy: `ioctl(FICLONE)` then `copy_file_range` then read/write loop
  (`ServerCopy`); recursive copy left to `Ops::walk`-based consumers.
- L-5: Checksums computed locally (sha256, sha1, md5) in streaming fashion with cancel.
- L-6: `spaceInfo` via `statvfs`; `keepAlive` success; `cancel` flag checked between
  1 MiB chunks and between directory entries (C-9 holds unless the kernel blocks in a
  single syscall on a dead device — documented exception).
- L-7: Writes: Resume opens with `O_WRONLY` without truncation and checks size;
  `commit()` does `fsync` (file) and `fsync` on the parent folder after rename by
  `Transfer`.
- L-8: No privilege escalation. A future root helper is a separate component.

### 6.4 Later backends (sketch only)

- S3-compatible (`libnetvfs-s3.so`): AWS SigV4; buckets as server-mode
  top-level folders; folders as prefixes; multipart upload for resume; `AtomicPut`;
  `ServerCopy` (CopyObject ≤ 5 GB, UploadPartCopy above); no symlinks/modes; ETag as
  change token. Credentials: access key id as user name, secret key as secret.
- NFSv3/v4 (`libnetvfs-nfs.so`): libnfs (same author and model as libsmb2), vendored like
  libsmb2; AUTH_SYS only, clearly labelled as unauthenticated-by-design.

## 7. Discovery

- XD-1: `NetVfs::Discovery` (QObject, main thread, `QUdpSocket` multicast) implements a
  minimal DNS-SD browser on 224.0.0.251/ff02::fb port 5353: PTR queries for
  `_sftp-ssh._tcp`, `_ssh._tcp`, `_smb._tcp`; SRV/A/AAAA resolution. No dependency on
  avahi.
- XD-2: Results: `{instanceName, provider, host, port, addresses, lastSeen}`;
  expiry by TTL; signals `found/updated/lost`. Queries follow RFC 6762 backoff (1 s, 2 s,
  4 s … max 60 s) and stop when no consumer listens.
- XD-3: Discovery never connects to anything; it only produces connection templates.
- XD-4: Later: WS-Discovery probe for Windows SMB hosts (UDP 3702), behind an option.
- XD-5: Sandboxed consumers have no network access; they receive discovery results only
  through the bridge (`Discover`, `NearbyChanged`, XB-10). Discovery runs only while a
  consumer has asked for it.

## 8. Accounts and credentials

- XA-1: A second service per provider, `<provider>-files`, of type `netvfs-files`
  (distinct from `storage` so Backup does not list it), name "Files", shipped by the
  `netvfs` package (XP-1). Consumers list accounts whose files service is
  enabled.
- XA-3: New per-provider keys (`netvfs/<provider>/...`): `files_root` (start path for
  browsing), `security_profile` (smb), `shares` (smb, string list), `show_admin_shares`
  (smb), `allow_insecure` (smb guest/legacy), `allow_shell` (sftp); `auth_mode` gains
  `interactive` (sftp). `host_key` holds the SSH host key pin (XC-16).
- XA-4: `AccountSession::open(accountId, Service, QObject *parent)` with
  `enum class Service { Backup, Files }`. It refuses (`SecurityPolicy`) to hand out a
  configuration whose profile is not allowed for that service (XM-1 table;
  `allow_insecure` is never allowed for Backup). `AccountConfig` gains `filesRoot`,
  `service`, `securityProfile`, `insecureAllowed`.
- XA-5: Provider descriptors replace the SFTP/SMB branches in the account QML:
  `/usr/share/netvfs/providers/<provider>.json` lists fields (key, type, label id,
  default, validation rule from `NetVfsInput`, visibility conditions), auth modes, and the
  services the provider offers. `ConnectionDialog` renders from the descriptor;
  `ServerIdentityDialog` renders SSH host keys.
- XA-6 (amended in draft 2): Secrets are read by exactly two kinds of processes: the Buteo
  plugins (inside msyncd) and `netvfs-bridge`. Consumers of the bridge never receive
  secrets. Confirm whether identities created with
  `createSignInCredentials("netvfs", "default", ...)` are readable by the bridge binary on
  5.2; if an ACL is needed, the account setup adds exactly msyncd's and the bridge's
  tokens, never `*`.
- XA-7: Interactive accounts (`auth_mode=interactive`) may have no stored secret;
  `SignonSecretSource` returns an empty `Credentials` for them instead of `AuthFailed`
  (amends A-6 for that mode only).
- XA-8: Attention states gain no new values. Clearing attention still requires the
  explicit review flow.

## 8a. Bridge for sandboxed consumers (`netvfs-bridge`)

A sandboxed app may only use the D-Bus names and files its Sailjail profile allows. It
always has a private, writable folder `~/.local/share/<OrganizationName>/<ApplicationName>`
(created and whitelisted by sailjail). The bridge places a unix socket in that folder
for each registered consumer and serves netvfs over it. The consumer needs no extra
permission, links nothing from netvfs, and never sees secrets or pins.

### 8a.1 Process, registration, rendezvous

- XB-1: Trust model. The bridge acts on netvfs accounts on behalf of a consumer that the
  user has approved (XB-6). It never acts on local paths (XB-11), never discloses secrets
  or pins, and never changes accounts; account changes are handed off to Settings
  (XB-15).
- XB-2: `/usr/libexec/netvfs/netvfs-bridge`, one process per consumer, started by systemd
  user socket activation (`Accept=no`). It exits 30 s after its last client disconnected
  and no job runs.
  It runs with the user's own groups: everything that parses server data (the backends,
  libssh, libsmb2) stays outside the group `privileged`.
  Since 0.5.0 it is written in Rust (`rust/netvfs-bridge`, doc/RUST.md; up to 0.4 C++/Qt).
  It reaches the C++ backends through `%{_libdir}/netvfs/libnetvfs-bridge-ffi.so`, a C ABI
  over libnetvfs (`src/bridge/ffi/netvfs_bridge_ffi.h`) that it loads with `dlopen`
  (`RTLD_NOW | RTLD_LOCAL`) from that fixed path and that exports one symbol,
  `nvb_ffi_get`; the library sits next to the backend folder that libnetvfs's
  `BackendLoader` searches, outside the linker path. The Qt event loop of the backends
  runs on the main thread, the bridge on threads of its own; the binary itself links no
  Qt.
- XB-2a: The Sailfish OS accounts database (`~/.local/share/system/privileged/Accounts/`)
  is readable by the group `privileged` only. The bridge reads it through
  `/usr/libexec/netvfs/netvfs-accounts`, installed setgid `privileged`
  (`%attr(2755,root,privileged)`, `Requires(pre): sailfish-setup` for the group, as
  mapplauncherd's boosters), started once per request. Since 0.4.0 it is
  written in Rust (`rust/netvfs-accounts`, doc/RUST.md) and links no Qt, GLib or
  libaccounts: it reads the database with SQLite as libaccounts-glib stores it and sends
  libaccounts' change signal itself, with the same requests and answers as before:
  - `list`: the accounts of XA-1 (enabled, Files service enabled) with what `ListLocations`
    shows; `files <id>`: the connection parameters of a listed account for the Files
    service, after XA-4, with its credentials id and whether its secret is optional
    (XA-7); `attention <id> <state> [pin]`: records `auth-failed` or
    `server-identity-changed` (XB-14) on a listed account. Nothing else: it never reads or
    returns a secret (the bridge asks signond itself, XA-6), never clears attention (the
    update flow does), never touches an account the bridge would not list, and links no
    backend. Its answer is a `QDataStream` on stdout; a malformed one is
    `ProtocolError`.
  - Any process can start it, so it trusts nothing of its caller's environment: first
    thing in `main()` it keeps only `LANG`, `LANGUAGE`, `LC_*`, `TZ`, `XDG_RUNTIME_DIR` and
    `DBUS_SESSION_BUS_ADDRESS`, and sets `HOME` from the password database of its real uid.
    A missing `XDG_RUNTIME_DIR` becomes `/run/user/<uid>` when that is the uid's folder.
    A set-id helper sends its signal on the bus of `/run/user/<uid>` only, as GLib does,
    never to the caller's `DBUS_SESSION_BUS_ADDRESS`.
    Anything else could point it at another database (`HOME`, `XDG_*_HOME`, `ACCOUNTS`)
    or change what SQLite does (`SQLITE_TMPDIR`, `TMPDIR`). These
    variables (and `NETVFS_ACCOUNTS_HELPER` in the bridge, which names the build tree's
    helper) apply to tests only, where the helper is not set-id. glibc itself drops `LD_*`
    and similar. Its soft core limit is 0, so that a crash writes no user-readable core.
  - It confines itself (`rust/netvfs-accounts/src/sandbox.rs`), set-id or not, first
    thing in `main()`, while it has one thread: fds 0 to 2 open (Rust's runtime opens
    `/dev/null` on a closed one before `main()`) and no other inherited fd, umask 077,
    default signal handlers and an empty mask, the file size soft limit at the hard one.
    Then, best-effort, Landlock (ABI 1 to 7, whatever the kernel offers): read-only
    system folders (`/usr`, `/etc`, `/lib*`, `/proc`, `/dev/random`, `/dev/urandom`) and
    the uid's `/run/user/<uid>`, read-write only `/dev/null` and the database folder
    (`ACCOUNTS`, else `$XDG_DATA_HOME/system/privileged/Accounts` and
    `$XDG_CONFIG_HOME/libaccounts-glib`), no exec, no TCP (ABI 4), no device ioctls
    (ABI 5), no signals or abstract sockets beyond itself (ABI 6). Then `no_new_privs`
    and a seccomp filter failing with EPERM: exec, ptrace, non-`AF_UNIX` sockets, new
    namespaces, mounts, modules, kexec, BPF, io_uring, userfaultfd, perf, keyrings, file
    handles, and any chmod, open, mkdir or mknod with a setuid or setgid bit (`clone3` and
    `openat2`, whose arguments the filter cannot see, fail with ENOSYS so that glibc falls
    back). After the database work it gives up
    the group for good (`setresgid` to the real gid) before writing its answer. The Jolla
    Phone 2026 kernel (6.12) has seccomp but no Landlock.
  - The generated bridge service has no `NoNewPrivileges=` (it would ignore the helper's
    setgid bit). invoker and its `privileges.d` files cannot be used instead, because they
    do not pass on the socket-activated descriptor.
  - Changes: libaccounts' writers announce every change with the `AccountChanged` signal
    of `com.google.code.AccountsSSO.Accounts` on the session bus (one object path per
    service type). The bridge subscribes to it on any path and lists again 200 ms after
    the last one. After its own attention write it lists again without waiting for the
    signal, which the set-id helper may not be able to send.
  - When the helper cannot open the database, or fails, the bridge logs a warning with
    the reason and lists no account.
- XB-3: Consumers are registered by files in `/usr/share/netvfs/consumers/<id>.conf`,
  shipped by netvfs packages (never by the consumer, which in Harbour cannot install
  outside its own paths):

  ```ini
  [Consumer]
  Id=lautta
  DisplayName=Lautta
  Executable=/usr/bin/harbour-lautta
  DataDir=.local/share/org.netvfs/lautta
  ```

  A systemd user generator (`/usr/lib/systemd/user-generators/netvfs-bridge-generator`)
  turns each file into `netvfs-bridge@<id>.socket` + `.service` + `.path` units.
- XB-4: Rendezvous: `ListenStream=%h/<DataDir>/netvfs/bridge.sock`, `SocketMode=0600`,
  `DirectoryMode=0700`. The `.path` unit watches `%h/<DataDir>` and restarts the socket
  unit when the folder is recreated (the user cleared the app's data, or the app was
  reinstalled). The bridge never writes anything else into the consumer's folder.
- XB-5: Peer check on every connection: `SO_PEERCRED` uid equals the bridge's uid, and the
  peer's executable (`/proc/<pid>/exe`, read through a pidfd to avoid pid reuse races where
  the kernel supports it) equals the registered `Executable`. Anything else is closed
  without a reply and logged at warning level. "Equals" means the same file (device and
  inode) or, failing that, a file of the same size with byte-identical content: Sailjail
  starts apps with `firejail --private-bin=<binary>`, which copies the binary into a tmpfs
  and bind-mounts that over `/usr/bin`, so a sandboxed peer always runs a copy at another
  inode. The bridge opens `/proc/<pid>/exe` (the link opens the file the peer runs, across
  mount namespaces) between the two start time reads that detect pid reuse, and compares
  from that descriptor in bounded chunks.

### 8a.2 Consent and scope

- XB-6: Consent per consumer, states `unknown`, `granted`, `denied`, stored in
  `~/.config/netvfs/bridge.conf`. On the first `Hello` with `unknown`, the bridge posts a
  notification "*Lautta* wants to use your network locations" with *Allow* and *Don't
  allow* actions, handled by the bridge. Until `granted`, `ListLocations` returns nothing
  and every location call fails with `PermissionDenied`. The account UI module gains a page *Apps
  using network locations* (Settings → Accounts → netvfs) to revoke or grant; revocation
  closes open connections of that consumer immediately.
- XB-7: Scope: accounts whose *Files* service is enabled (XA-1); ad-hoc locations created
  by this consumer; discovery results. Nothing else of netvfs is visible.

### 8a.3 Protocol

- XB-8: Peer-to-peer D-Bus over the socket (no bus daemon, no proxy), object
  `/org/netvfs/Bridge`, interface `org.netvfs.Bridge1`.
  `Hello(s client) → (s bridgeVersion)` must be the first call.
  The bridge is the server of the peer-to-peer connection (zbus since 0.5.0, libdbus
  before): EXTERNAL authentication of its own uid, and unix fd passing when the client
  negotiates it. Every answer is the bridge's own, none comes from the D-Bus library:
  `org.freedesktop.DBus.Peer` (`Ping`, `GetMachineId`) on any path, `Introspect` on
  `/org/netvfs/Bridge` with the interface XML verbatim
  (`tests/bridge/contract/org.netvfs.Bridge1.xml`), and
  `org.freedesktop.DBus.Error.UnknownMethod` for any other path, interface or member.
  Consumers may use any D-Bus implementation; XT-7 checks a libdbus client against the
  binary.
- XB-9: Types. Paths and names are `ay` (raw protocol bytes, XC-4), never `s`, because
  D-Bus strings must be valid UTF-8. Entry is the struct
  `(ay name, y type, y targetType, x size, x mtimeMs, x ctimeMs, x atimeMs, i mode,
  x uid, x gid, s owner, s group, q flags, ay etag, s contentType)` with −1/empty for
  unknown. Capabilities are `(as flags, as checksumAlgorithms, x maxNameBytes)`. Errors are
  D-Bus errors named `org.netvfs.Error.<ErrorName>` (XC-21 names) with the human message;
  jobs report `detail` and `retryAfterMs` in `JobFinished`.
- XB-10: Methods (all asynchronous on the bridge side; `lane` is `interactive`, `bulk` or
  `stream`):

  | Group | Methods / signals |
  |---|---|
  | Session | `Hello`, `GetConsent → s`, `RequestConsent`, signal `ConsentChanged(s)` |
  | Locations | `ListLocations → a(s id, s provider, s name, a{sv} info)`, signal `LocationsChanged`, `Capabilities(s loc)`, `Disconnect(s loc)` |
  | Ad-hoc | `ConnectAdHoc(s url, ay secret, a{sv} opts) → s loc`, `ForgetAdHoc(s loc)` |
  | Discovery | `Discover(b on)`, signal `NearbyChanged(a(s name, s provider, s host, q port))` |
  | Listing | `List(s loc, ay dir, s lane, u batch) → u req`, signals `ListBatch(u req, a(entry))`, `ListDone(u req, s error, s message)` |
  | Metadata | `Stat(s loc, ay path, b follow, s lane) → entry`, `ReadLink`, `SpaceInfo`, `Checksum(s loc, ay path, s algo) → ay` |
  | Namespace | `MakeDir(…, b exclusive)`, `RemoveFile`, `RemoveDir`, `Rename(s loc, ay from, ay to, b replace)`, `SetAttributes(s loc, ay path, a{sv})`, `MakeSymlink`, `MakeHardlink`, `ServerCopy(s loc, ay from, ay to, a{sv})` |
  | Handles | `OpenRead(s loc, ay path, s lane) → (u h, x size)`, `Read(u h, x offset, u max) → ay` (max 1 MiB), `ReadAhead(u h, x offset, x bytes)`, `Close(u h)` |
  | Jobs | `Upload(s loc, ay path, h fd, a{sv} opts) → u job`, `Download(s loc, ay path, h fd, a{sv} opts) → u job`, `CopyAcross(s srcLoc, ay src, s dstLoc, ay dst, a{sv} opts) → u job`, `RemoveTree(s loc, ay path) → u job`, `Walk(s loc, ay root, a{sv} opts) → u job`, `Cancel(u id)`, signals `JobProgress(u job, x done, x total)` (≤ 4 Hz), `WalkBatch(u job, a(ay path, entry))`, `JobFinished(u job, s error, s message, a{sv} extra)` |
  | Questions | signal `Question(s id, s kind, a{sv})`, `Answer(s id, a{sv})`; kinds: `identity-unknown` (ad-hoc only), `keyboard-interactive`, `insecure-consent` (ad-hoc only) |
  | Handoff | `OpenAccountSettings(s loc)`, `AddAccount(s provider)` |

  `Walk` options: `maxDepth` (−1 for no limit), `followSymlinks` and `postOrder`.
  `postOrder` is accepted and has no effect: `WalkBatch` reports every folder before its
  children (its second visit after the children, `Ops::walk`'s `leave()`, is not sent).

- XB-11: File descriptors. `Upload`/`Download` take an fd the consumer opened. The bridge
  checks the fd (`fstat`: regular file or FIFO; `fcntl(F_GETFL)`: the access mode the
  operation needs) and otherwise fails with `PermissionDenied` before any network work.
  Regular files are accessed only with `pread`/`pwrite` at explicit offsets
  (`opts.offset`, resume offsets), so the consumer's file offset is irrelevant. FIFOs are
  sequential. The bridge never `fsync`s, renames or deletes local files; it closes the
  fd when the job ends. It never receives or opens a local path.
- XB-12: Connection pools per location live in the bridge, with lanes as the consumer
  hints them (defaults interactive 1, bulk 2, stream ≤ 1; total per host ≤ 4). netvfs
  rules apply unchanged (C-7, C-9, C-14, establish before credentials). Since 0.5.0 the
  bridge asks signond for an account's secret (XA-6) only after the server's identity
  was accepted, in the same step that connects and authenticates: a server that is not
  verified costs a connect, but no secret of the account is in the bridge's memory while
  it talks to it. A signond failure is therefore reported after the connect, and sets no
  attention (as before).
- XB-13: Disconnects. When a consumer connection closes, the bridge cancels all of its
  requests and jobs; partial remote temp files are left in place so the consumer can
  resume. Handles are closed.
- XB-14: Identity. For accounts, `ServerIdentityUnknown`/`ServerIdentityChanged` are
  returned as errors and set attention as Buteo would; resolution happens only in
  Settings (XB-15). For ad-hoc locations the bridge asks via `Question(identity-unknown)`
  with the full `ServerIdentity` details; accepted pins are stored per consumer in
  `~/.local/share/netvfs/bridge/<id>/known_hosts`; a changed ad-hoc identity is an error,
  and re-pinning requires `ForgetAdHoc` and a new first contact.
- XB-15: Handoff. `OpenAccountSettings(loc)` opens the account's page in Settings →
  Accounts; `AddAccount(provider)` opens the netvfs account creation flow. The bridge is
  unsandboxed and launches these through the platform's settings D-Bus interface.
- XB-16: Ad-hoc secrets arrive as `ay`, are moved into `Credentials` and wiped (SEC-5);
  `ConnectAdHoc` never persists them. A URL with a password is rejected (XH-6).
  Keyboard-interactive prompts are relayed through `Question`.
- XB-17: Limits per consumer: 64 concurrent requests, 16 open handles, 8 running jobs,
  `ListBatch` ≤ 512 entries or 1 MiB, `Read` ≤ 1 MiB. Over-limit calls fail with
  `TooManyConnections` and a `retryAfterMs`.
  Per connection, a message whose header declares more than 2 MiB, or that carries more
  than 2 file descriptors, closes the connection before its body is read (the largest
  valid call is `ConnectAdHoc`: a 64 KiB secret and a 4 KiB URL); at most 16 received
  messages wait to be handled. Outgoing (C-10): replies and signals leave in order
  through one queue, written only as fast as the consumer reads; `ListBatch` and
  `WalkBatch` wait while 4 MiB of them are not yet written, and the bridge reads no
  further calls while 64 messages wait, so a consumer that does not read cannot make the
  bridge buffer without bound.
- XB-18: Logging follows C-16/C-17 and prefixes the consumer id.

## 9. Security additions

- XSEC-1: C-7 holds for every new protocol: no credential before the identity check
  passed.
- XSEC-2: Downgrades are never automatic. A backend never retries with a weaker
  profile, dialect or auth method than configured.
- XSEC-3: The share enumeration helper (XM-7) and the shell exec channel (XS-9) are the
  only new parsers of complex untrusted data outside the existing ones; both are
  isolated (process, or fixed templates + capped defensive parsing).
- XSEC-6: SEC-5 wiping extends to `AuthPrompter` answers, the helper
  request buffer in XM-7 and ad-hoc secrets received by the bridge (XB-16). The bridge
  wipes its own copies; the received message that carried the secret (`ConnectAdHoc`'s
  `ay`, the answers of `Answer`) stays unwiped in the D-Bus library's buffer (zbus since
  0.5.0) until the call is handled and the message dropped, as it did in libdbus's
  buffer before.
- XSEC-7: The bridge is the only netvfs component reachable from a sandbox. Its attack
  surface is the D-Bus message parser (zbus and zvariant, in Rust, since 0.5.0) and its
  own argument validation: every path is checked with the rules of `Paths::normalize`
  before use, every numeric argument is range-checked, and every fd is validated
  (XB-11). The parser only sees messages within the inbound limits of XB-17.

## 10. Packaging (amends P-*)

- XP-1: Packages:

  | Package | Contents | Requires |
  |---|---|---|
  | `netvfs` | `libnetvfs.so.1`, backend dir, the `sftp`, `smb` and `local` backends, `netvfs-smb-shares` helper, QML module `org.netvfs.accounts`, provider descriptors, account providers with their UI QML and icons, `<p>-files` services and their service type, `netvfs-cli`, translations | Qt5Core, Qt5DBus, Qt5Network, accounts-qt5, libsignon-qt5, Silica, jolla-settings-accounts; Recommends `netvfs-backup` |
  | `netvfs-backup` | `sftp-backup` and `smb-backup` services, Buteo plugins and profiles | netvfs, buteo, jolla-vault |
  | `netvfs-bridge` | `netvfs-bridge` (XB-2), its C ABI `libnetvfs-bridge-ffi.so`, `netvfs-accounts` (setgid `privileged`, XB-2a), systemd generator and template units, `consumers/lautta.conf` | netvfs, systemd, sailfish-setup (pre) |
  | `netvfs-devel` | headers, pkg-config | netvfs |

- XP-3: The SMB share helper runs out of process (XM-7) but ships with the backend.
  `tools/ci/check-rpm.sh` asserts that `libnetvfs-smb.so` still contains no share
  enumeration code (the existing link-time guard stays) and that the helper does.
- XP-4: The RPM check script also asserts that only `netvfs-backup` depends on Buteo.
- XP-5: `netvfs-bridge` stays a package of its own and no package requires it, so only
  devices with a sandboxed consumer carry the setgid accounts helper. The bridge still
  reports providers whose backend it cannot load as `Unsupported`.
- XP-6: Parts nobody installs on their own share one package; separate packages stay
  only for what pulls in something the rest does not need (Buteo and jolla-vault for
  backups, a setgid binary for the bridge) or is only for development.

## 11. CLI

- XC-CLI: `netvfs-cli` gains: `stat`, `lstat`, `ls -l` (full v2 entry, `--json`),
  `mkdir [-p] [--exclusive]`, `rm [-r]`, `rmdir`, `mv [--replace]`, `cp` (server copy if
  available, else across via `copyAcross`), `cat [--offset N --length N]`, `chmod`,
  `touch --mtime`, `ln -s`, `readlink`, `df`, `sum --algo`, `caps`, `shares` (SMB),
  `discover [--seconds N]`, `--url URL` as an alternative to `--provider/--host`,
  `--prompt` (keyboard-interactive on the terminal), `--profile` (SMB). Secrets still only
  via `--secret-env` or prompt.

## 12. Tests

- XT-1: Backend conformance suite: one parameterised Qt Test (`tests/conformance`) run
  against every backend × server container, covering every `Backend` method and capability
  claim. A capability that is reported must pass its tests; an unreported one must return
  `Unsupported` without side effects. Cases include: names (UTF-8, NFC vs NFD kept
  distinct, non-UTF-8 bytes on SFTP/local, leading dots, spaces, 255-byte names,
  Windows-invalid on SMB), case-only rename, rename modes with existing file/folder
  targets, symlink to file/folder/dangling/loop, listing 10 000 entries in batches, ranged
  reads at EOF boundaries, resume with correct and wrong offsets, files > 4 GiB (sparse on
  servers that allow it), cancel within 2 s for every blocking method under a stalling
  proxy (`sftpproxy.py`, `flipproxy.py`), `keepAlive` after server restart →
  `ConnectionLost`.
- XT-2: New containers: Samba multi-share + `map to guest` + SMB 2.1-only configuration,
  OpenSSH with keyboard-interactive (PAM OTP stub) and `MaxSessions 2`.
- XT-3: Fuzzing on the host (clang, libFuzzer, ASan/UBSan): `Url` parser, `Names` codec,
  share-helper output parser. Corpora in `tests/fuzz/corpus`, runs in CI for a fixed time
  budget.
- XT-4: Mutation lists (`tests/mutations/*.json`) for: rename-mode logic,
  `checkServerIdentity`, XM-1 profile enforcement, XA-4 service gating, resume offset
  checks, `Names` codec.
- XT-5: Identity tests: no request before identity check for every backend (proxy asserts
  no NTLMSSP_AUTH before acceptance), pin mismatch behaviour.
- XT-6: Buteo regression: the existing Buteo unit and interop tests run unchanged in
  behaviour (files 0600, `.part` naming, Replace semantics) after every API step.
- XT-7: Bridge tests: a contract suite (D-Bus introspection XML and golden message
  sequences in `tests/bridge/contract`) shared with the consumer's fake bridge; peer check
  (wrong uid, wrong executable, pid reuse); consent states and revocation mid-job; fd
  validation (directory, read-only fd for download, FIFO without size); disconnect
  cancels jobs within C-9's 2 s; folder deletion and recreation (XB-4); limits (XB-17);
  fuzzing of argument validation through a libFuzzer harness that feeds decoded
  messages to the adaptor. Since 0.5.0 the contract suite also runs as a black box
  against the built binary from a libdbus client (`tests/bridge/contract`: introspection,
  peer interface, fd passing, error details, every golden sequence), next to the Rust
  tests of `rust/netvfs-bridge`; the argument fuzzing is a cargo-fuzz target.

## 13. Migration plan (PR sequence)

Each step keeps `make check` green, SonarCloud clean, and Buteo behaviour identical.

1. Merge `foundations` (PR #1). Commit the existing SPEC documents under `doc/`.
2. Introduce `Error` additions, `Result::detail/retryAfterMs`, `Entry` v2 and `isDir()`;
   adapt backends, Buteo, CLI, QML, tests. Soname bump.
3. `Names` codec and lossless names in SFTP; conformance suite skeleton with local
   test doubles.
4. Streaming `list` + `ListSink`, `lstat`, `makeDir(exclusive)`, `removeFile/removeDir`,
   `rename(mode)`; helpers `list(vector)`, `remove`, `makePath`.
5. Local backend (L-*) — gives the conformance suite a fast, container-free target
   (not needed by the file browser itself, §6.3).
6. Handles (XC-13), upload/download options (XC-14), create modes (XC-23), Transfer
   policy (XH-1), resume.
7. `setAttributes`, links, `spaceInfo`, `keepAlive`, `capabilities()` everywhere.
8. Packaging split (XP-*).
9. `ServerIdentity` v2.
10. SMB profiles, server mode, share helper.
11. Accounts: files service, new providers, descriptors, generalised account UI, XA-4/6/7.
12. Discovery.
13. Bridge (§8a): protocol types and fake consumer, generator and units, peer check,
    consent, listing/metadata/namespace, handles, jobs with fd passing, questions,
    handoff. Contract tests shared with the consumer (XT-7).
14. Keyboard-interactive (`AuthPrompter`) + interactive accounts.
15. SFTP shell exec helpers, server copy/checksum; `Ops::walk`, `removeTree`,
    `BoundedPipe`, `copyAcross`, CLI expansion (some of these can move earlier if the
    file browser's M1 needs them; `BoundedPipe` and `walk` are needed by M1).

## 14. Open questions

1. libsmb2 `ReplaceIfExists` and server-side copy (`FSCTL_SRV_COPYCHUNK`): upstream
   them, or carry patches under `vendor/patches/libsmb2` per D-1?
2. libssh `copy-data`: upstream contribution vs. waiting.
3. signond ACL behaviour on 5.2 (XA-6) — decides whether the bridge needs an ACL entry.
4. Which settings D-Bus entry points open a specific account page and the account
   creation flow for a provider on 5.2 (XB-15)? Needs a device test.
5. Keep qmake? It works on the Qt 5.6 SDK target and matches the existing tree; switching
   to CMake buys nothing until the platform moves past Qt 5.6.
6. Bridge rendezvous alternative: instead of a socket in the consumer's folder, the bridge
   could call into the consumer's own D-Bus name (which sailjail lets the app own) and hand
   over a socketpair end. Kept as fallback if the folder socket proves fragile (XB-4).
