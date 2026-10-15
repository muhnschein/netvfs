# netvfs — SPEC, API v2 (file-browser extensions)

This document extends [SPEC.md](SPEC.md), [SPEC-sftp.md](SPEC-sftp.md) and
[SPEC-smb.md](SPEC-smb.md) for consumers other than backups: an interactive file
browser, which is a sandboxed Harbour app (`lautta/SPEC.md`) and reaches netvfs through
`netvfs-bridge` (§8a, `XB-*`), and the command line tool.

## 0. How this document relates to the other specs

- IDs of SPEC, SPEC-sftp and SPEC-smb keep their meaning. Where a requirement here
  says "amends X", its text replaces X for the case it names.
- The prefixes of this document are `XC` core API, `XH` core helpers, `XS` SFTP, `XM`
  SMB, `L` local, `XD` discovery, `XA` accounts, `XB` bridge, `XP` packaging, `XT`
  tests, `XSEC` security.
- [SPEC-v2-review.md](SPEC-v2-review.md) records review points this document resolved;
  code cites some of them.

## 1. Goals and non-goals

### 1.1 Goals

1. Serve two consumers: the existing Buteo backup integration (in-process) and an
   interactive file browser (`lautta/SPEC.md`), which is a sandboxed Harbour app served
   through `netvfs-bridge` (§8a), without weakening any backup guarantee.
2. Give backends the operations and metadata a file manager needs: full entry metadata,
   lossless names, streaming listings, rename/remove semantics a user can reason about,
   attributes, symlinks, random-access handles, resume, server-side copy, space info.
3. Add a local backend.
4. Make SMB usable for browsing: server mode (shares as top-level folders), share
   enumeration, and explicit security profiles.
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

## 2. Rules of SPEC that apply unchanged

The error taxonomy (SPEC 5.4), C-7 (no credentials before the identity check), C-9
(cancel within 2 s), C-10 (bounded memory), C-14 timeouts, C-15 path normalisation,
C-16/C-17 logging rules, SEC-5 secret wiping, and the test culture (unit tests, interop
containers, sanitizers, mutation lists, SonarQube with no open issues).

## 3. Versions

- XC-1: Plugin IID `org.netvfs.BackendFactory`; the one extension interface is
  `org.netvfs.SshKeyTools`. libnetvfs, its backends and every caller are built from one
  source tree and ship together.
- XC-1a: Library version `1.0.0` (qmake derives soname `libnetvfs.so.1`); package
  version `0.6.0`, which is also the version of the Rust workspace (the bridge's `Hello`
  answer, the SSH client id `SSH-2.0-netvfs_0.6.0`). All netvfs subpackages require the exact same `%{version}-%{release}`
  of `netvfs` so mixed installs cannot happen.
- XC-1c: Qt 5.6 and C++17 are the baseline. No exceptions cross the API; `Result` is
  the only error channel. No `std::optional` in exported structs (ABI and QVariant
  friction); sentinels are documented per field.

## 4. Core API v2

### 4.1 Entries

- XC-2: `Entry`:

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
    qint64 size = -1;                // -1 unknown
    QDateTime modified;              // UTC; invalid if unknown
    QDateTime created;               // SMB, local (statx btime)
    QDateTime accessed;
    qint32 mode = -1;                // permission bits & 07777; -1 unknown
    qint64 uid = -1, gid = -1;
    QString owner, group;            // names when the server provides them
    EntryFlags flags;
    QByteArray etag;                 // opaque change token; empty if none
    QString contentType;             // server-declared; advisory only, never trusted
    QVariantMap extra;               // backend-specific; no backend fills it

    bool isDir() const;              // Directory, or Symlink whose targetType is Directory
    bool isFile() const;             // File, or Symlink whose targetType is File
};
```

- XC-3: Callers that need "is this a folder" use `isDir()`. A size below 0 is unknown.

### 4.2 Lossless names

- XC-4: Names are decoded from server bytes with a reversible "surrogate escape" codec:
  well-formed UTF-8 decodes normally; every byte of an ill-formed sequence `b` (0x80–0xFF)
  becomes the lone surrogate `U+DC00 + b`. Encoding reverses this exactly. Entries with
  escaped bytes carry `NameNotUtf8`. `Paths::normalize` accepts lone surrogates; it still
  rejects NUL, `.` and `..` (C-15 unchanged otherwise). SFTP and local names are the
  file system's bytes. SMB names arrive as UTF-16; netvfs-smb turns them into WTF-8, so
  an unpaired surrogate (possible on Windows servers) becomes its three-byte form, which
  `Names::decode` escapes and flags, and which maps back to the same UTF-16 unit.
- XC-4a: New helpers `Names::decode(QByteArray) -> QString`, `Names::encode(QString) ->
  QByteArray`, `Names::display(QString) -> QString` (escapes rendered as U+FFFD) in
  `names.h`. No backend decodes remote names with `QString::fromUtf8`.
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
    ETags
};
struct Capabilities {
    QSet<Capability> flags;                // QSet keeps the enum open for growth
    QStringList checksumAlgorithms;        // "sha256", "md5", ...
    qint64 maxNameBytes = -1;              // -1 unknown
    qint64 maxReadChunk = 0, maxWriteChunk = 0;  // 0 unknown
    bool has(Capability c) const { return flags.contains(c); }
};
```

  The SFTP and SMB backends leave `maxReadChunk` and `maxWriteChunk` at 0; their chunk
  sizes are in S-21 and M-11.

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
  QUERY_DIRECTORY responses). An entry named `.`, `..` or the empty name, or whose name
  contains `/` or NUL, is left out; the rest of the listing is delivered.
  `cancel()` is honoured between batches and within the protocol wait (C-9).
- XC-7: `stat(path, Entry*)` keeps following symlinks; new `lstat(path, Entry*)`
  returns the link itself. Backends without symlinks implement `lstat` as `stat`.

### 4.5 Namespace operations

- XC-8: `makeDir(path, bool exclusive)`: creates one folder; with `exclusive`, an
  existing entry is `AlreadyExists`; without, an existing folder is success.
  `makePath` (mkdir -p) is a non-virtual core helper built on `makeDir`.
- XC-9: `removeFile(path)` removes a non-directory (a symlink is removed, not its
  target); on a directory it returns `IsADirectory`. `removeDir(path)` removes an empty
  folder; non-empty is `DirectoryNotEmpty`. `remove(path)` stays as a non-virtual
  helper (file, else empty dir) for Buteo. Native recursive
  deletes are reachable only through
  `removeTreeNative(path)` and only when `RecursiveDelete` is reported; the core helper
  `removeTree` (XH-2) is what consumers normally use.
- XC-10: `rename(from, to, RenameMode mode)` with `enum class RenameMode { NoReplace,
  Replace }`. NoReplace returns `AlreadyExists` if `to` exists — atomically when
  `NativeNoReplace`, otherwise via a stat check (documented race). Replace replaces
  `to`, atomically only with `AtomicReplace`. Replacing a folder with anything is
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
- XC-14: Streaming `upload`/`download` with options:

```cpp
struct UploadOptions  { WriteOptions write; };
struct DownloadOptions { qint64 offset = 0; qint64 length = -1; };
virtual Result upload(QIODevice *source, const QString &path, const UploadOptions &, Progress *);
virtual Result download(const QString &path, QIODevice *sink, const DownloadOptions &, Progress *);
```

  `read(path, offset, length, out)` is a non-virtual helper over `openRead`.
  Besides `Progress::update(done, total)`, `bool Progress::canceled() const` (default
  false) lets sinks stop without a cross-thread `cancel()`.
- XC-23: Create modes: the backend default is 0666 for new files and 0777 for new
  folders, less the umask (SFTP sends these modes and the server applies its umask;
  local uses the process umask). Backups pass `createMode = 0600` and the account option
  `dir_mode` 0700 (S-20).

### 4.7 Server-side work

- XC-17: `copy(from, to, const CopyOptions &)` with
  `struct CopyOptions { bool recursive = false; RenameMode mode = RenameMode::NoReplace; }`.
  `Unsupported` unless `ServerCopy` (and `ServerCopyRecursive` for folders).
- XC-18: `checksum(path, const QString &algorithm, QByteArray *digest)` — `Unsupported`
  unless listed in `checksumAlgorithms`. Digests are raw bytes.
- XC-19: `spaceInfo(dir, SpaceInfo *)` with `struct SpaceInfo { qint64 free = -1, total
  = -1, used = -1; }`. `freeSpace` is a helper over it (C-13).
- XC-20: `keepAlive()` — one cheap round trip that proves the connection is alive
  (SFTP `keepalive@openssh.com`, XS-12; SMB ECHO; local: success). Returns
  `ConnectionLost` on a dead transport.

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
  not attempted (backups).
- XC-16: `ServerIdentity`:

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
  the key must match, else `ServerIdentityChanged`. Pins are in the account key
  `host_key`.

### 4.9 Errors

- XC-21: `Error` values besides those of SPEC 5.4 (`errorName()` strings documented): `ConnectionLost`,
  `NotADirectory`, `IsADirectory`, `DirectoryNotEmpty`, `InvalidName`,
  `ReadOnlyFilesystem`, `Locked` (SMB sharing violation), `TooManyConnections` (SFTP
  channel open refused by MaxSessions, SMB limits), `RateLimited` (the server asks to
  wait, Retry-After). `NetworkUnreachable` means "could not reach"; dropping an
  established connection is `ConnectionLost`. Buteo maps both to the same
  attention-free, retryable failure.
- XC-24: `Result` has `qint64 retryAfterMs() const` (−1 none) and `QString detail()
  const` (protocol status for logs and the "Details" view, never secrets, debug-level
  rules of C-17 apply to paths in it).
- XC-22: Cancellation (C-9) and timeouts (C-14) apply to every new method, including
  `AuthPrompter` waits (cancel ends the wait) and handle calls.

### 4.10 The `Backend` class

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

- XH-1: `Transfer` (amends C-12, C-13, SPEC 8.6): `upload` takes a `TransferPolicy`:
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

### 6.1 SFTP

The SFTP backend is `netvfs-sftp` in `libnetvfs-rs.so` (SPEC-sftp).

- XS-1: Names are the server's bytes; the shim decodes them with `Names` (XC-4) in
  list, stat, readLink and path translation.
- XS-2: Entry mapping: `type` from the attribute type (symlink; special for socket,
  fifo and device), `mode`, `uid`/`gid`, `accessed`, and `owner`/`group` from
  `users-groups-by-id@openssh.com` when the server offers it (one request per listing
  batch for the ids not yet known, cached per connection), else empty. The hidden flag
  is never set (dot-names are a consumer convention).
- XS-3: `list` uses `lstat` semantics (as READDIR does); with `resolveSymlinkTypes`,
  targets are `stat`ed with a per-listing cap of 512 resolutions (beyond that
  `TargetUnknown`).
- XS-4: Links: READLINK, SYMLINK, and `hardlink@openssh.com` when the server offers it.
  OpenSSH's server takes the SSH_FXP_SYMLINK arguments in the reverse order of the
  draft; the backend sends the target first, as OpenSSH expects, and the interop suite
  checks it against the OpenSSH containers.
- XS-5: `setAttributes` via SETSTAT (mode, atime/mtime). `SetModified` and `PosixModes`
  are reported.
- XS-6: Rename: NoReplace uses plain RENAME, which OpenSSH fails on an existing target
  (`NativeNoReplace`). Replace uses `posix-rename@openssh.com` when the server offers it
  (`AtomicReplace`), else stat, REMOVE and RENAME.
- XS-7: Handles: `ReadHandle` over one open file with pipelined READs (S-21), at most
  4 MiB in flight; `WriteHandle` with pipelined WRITEs; Resume opens without truncating
  and checks that the size equals `resumeOffset`. `commit()` sends `fsync@openssh.com`
  when the server offers it.
- XS-8: `spaceInfo` from `statvfs@openssh.com` (free = f_bavail × f_frsize, total =
  f_blocks × f_frsize).
- XS-9: The backend runs no command on the server: it opens no exec channel, and
  reports neither `Checksums` nor `ServerCopyRecursive`.
- XS-10: `copy` (XC-17) uses `copy-data` when the server offers it, for files only
  (`ServerCopy`).
- XS-11: Keyboard-interactive: with an `AuthPrompter`, it is tried after the configured
  method fails, and it is the method of `auth_mode=interactive`, whose stored secret is
  optional. A partial success continues with keyboard-interactive, or with a password
  asked through the prompter, so publickey or password followed by a one-time password
  works.
- XS-12: `keepAlive` sends the `keepalive@openssh.com` global request with want-reply and
  waits for any reply (a failure reply counts as alive).

### 6.2 SMB

The SMB backend is `netvfs-smb` in `libnetvfs-rs.so` (SPEC-smb). SPEC-smb section 8
records how it implements XM-1 to XM-9.

- XM-1: Security profiles (amends M-1, M-2, M-3; option `security_profile`, default
  `strict`):

  | Profile | Dialect | Signing | Encryption | Allowed for service |
  |---|---|---|---|---|
  | `strict` | 3.1.1 | required | required | backup, files |
  | `signed` | 3.1.1 | required | where the server marks the session or share | backup, files |
  | `guest` | 3.1.1 | off | off | files, with the account's consent (`allow_insecure`) |

  The account UI and `AccountSession` enforce the "allowed for service" column (XA-4);
  the backend enforces the profile it is given. Any other profile value is
  `SecurityPolicy`. `guest` signs in anonymously and ignores the account's credentials;
  for `strict` and `signed`, a session the server marks as guest or null is a
  `SecurityPolicy` failure (a server silently downgrading credentials to guest is never
  accepted).
- XM-2: Server mode: when the `share` option is empty, the backend's root lists shares
  (directories, `type = Directory`); paths are `/<share>/<rest>`. One session serves all
  shares: `IPC$` is its main tree, and each share is a tree of the same session,
  connected on first use, at most 4 at a time (the least recently used one without open
  files is disconnected). Operations on `/` other than `list`/`stat` return
  `PermissionDenied`; on `/<share>` itself, `removeDir`/`rename` return
  `PermissionDenied`. M-13 thread confinement applies.
- XM-3: Share list sources, merged and de-duplicated: the account option `shares`
  (string list the user saved), and share enumeration (XM-7) when it is on. Without
  either, root lists nothing and the UI asks for a share name.
- XM-4: Entry mapping: `created` from the birth time, `Hidden`/`ReadOnly`/`System` from
  the file attributes, `type` Symlink for reparse points (no `Symlinks` capability; the
  target is not read), and the `CaseInsensitive` and `WindowsNames` capabilities (M-9
  rules in `Paths`).
- XM-5: Rename NoReplace is native (FileRenameInformation without `ReplaceIfExists`:
  `NativeNoReplace`); Replace sets `ReplaceIfExists` (`AtomicReplace`).
- XM-6: Handles: `ReadHandle` keeps one file open with pipelined reads of the chunk size
  of M-11, up to 4 MiB in flight; `WriteHandle` likewise; Resume opens without
  truncating. `setAttributes` supports `modified`/`accessed` via SET_INFO
  (FileBasicInformation); `PosixModes` is not reported.
- XM-7: Share enumeration (option `share_enumeration`, default true, server mode only)
  runs in the backend: srvsvc NetrShareEnum over a pipe of the `IPC$` tree. Every count
  and string of the reply is capped before anything is allocated. Only disk shares
  (`STYPE_DISKTREE`) are listed, and names ending in `$` only when
  `show_admin_shares=true`. A malformed reply is `ProtocolError` and leaves the backend
  usable. `ShareEnumeration` is reported while enumeration is on.
- XM-8: `keepAlive` sends SMB2 ECHO. `spaceInfo` from FileFsFullSizeInformation.
- XM-9: DFS referrals and Kerberos are out of scope; DFS paths return `Unsupported`
  with detail "DFS referral".

### 6.3 Local (plugin `libnetvfs-local.so`)

The Harbour file browser handles local files itself inside its sandbox, and the bridge
never touches local paths (XB-11). The local backend serves the conformance suite (a
fast, container-free target), the CLI and in-process consumers.

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
- L-8: No privilege escalation.

## 7. Discovery

- XD-1: `NetVfs::Discovery` (QObject, main thread, `QUdpSocket` multicast) implements a
  minimal DNS-SD browser on 224.0.0.251/ff02::fb port 5353: PTR queries for
  `_sftp-ssh._tcp`, `_ssh._tcp`, `_smb._tcp`; SRV/A/AAAA resolution. No dependency on
  avahi.
- XD-2: Results: `{instanceName, provider, host, port, addresses, lastSeen}`;
  expiry by TTL; signals `found/updated/lost`. Queries follow RFC 6762 backoff (1 s, 2 s,
  4 s … max 60 s) and stop when no consumer listens.
- XD-3: Discovery never connects to anything; it only produces connection templates.
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
  (smb), `share_enumeration` (smb, default true), `allow_insecure` (consent for the SMB
  profile `guest`); `auth_mode` has the value `interactive` (sftp). `host_key` holds the
  SSH host key pin (XC-16).
- XA-4: `AccountSession::open(accountId, Service, QObject *parent)` with
  `enum class Service { Backup, Files }`. It refuses (`SecurityPolicy`) to hand out a
  configuration that is not allowed for that service:

  | Configuration | Backup | Files |
  |---|---|---|
  | smb `strict`, `signed` | yes | yes |
  | smb `guest` | no | with `allow_insecure` |
  | smb unknown profile | no | no |
  | smb without a share (server mode) | no | yes |
  | `allow_insecure=true` (any provider) | no | yes |
  | `auth_mode=interactive` | no | yes |
  | anything else | yes | yes |

  `AccountConfig` has `filesRoot`, `service`, `securityProfile` and `insecureAllowed`.
- XA-5: Provider descriptors drive the account QML:
  `/usr/share/netvfs/providers/<provider>.json` lists fields (key, type, label id,
  default, validation rule from `NetVfsInput`, visibility conditions), auth modes, and the
  services the provider offers. `ConnectionDialog` renders from the descriptor;
  `ServerIdentityDialog` renders SSH host keys.
- XA-6: Secrets are read by exactly two kinds of processes: the Buteo
  plugins (inside msyncd) and `netvfs-bridge`. Consumers of the bridge never receive
  secrets. Confirm whether identities created with
  `createSignInCredentials("netvfs", "default", ...)` are readable by the bridge binary on
  5.2; if an ACL is needed, the account setup adds exactly msyncd's and the bridge's
  tokens, never `*`.
- XA-7: Interactive accounts (`auth_mode=interactive`) and SMB `guest` accounts may
  have no stored secret; `SignonSecretSource` returns an empty `Credentials` for them
  instead of `AuthFailed` (amends A-6 for these accounts only).
- XA-8: The attention states are those of SPEC 6.4. Clearing attention requires the
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
  It runs with the user's own groups: everything that parses server data (the backends
  and `libnetvfs-rs.so`) stays outside the group `privileged`.
  It is written in Rust (`rust/netvfs-bridge`, doc/RUST.md).
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
  mapplauncherd's boosters), started once per request. It is written in Rust
  (`rust/netvfs-accounts`, doc/RUST.md) and links no Qt, GLib or libaccounts: it reads
  the database with SQLite as libaccounts-glib stores it and sends libaccounts' change
  signal itself. Its requests:
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
  and every location call fails with `PermissionDenied`. The account UI module has a page *Apps
  using network locations* (Settings → Accounts → netvfs) to revoke or grant; revocation
  closes open connections of that consumer immediately.
- XB-7: Scope: accounts whose *Files* service is enabled (XA-1); ad-hoc locations created
  by this consumer; discovery results. Nothing else of netvfs is visible.

### 8a.3 Protocol

- XB-8: Peer-to-peer D-Bus over the socket (no bus daemon, no proxy), object
  `/org/netvfs/Bridge`, interface `org.netvfs.Bridge1`.
  `Hello(s client) → (s bridgeVersion)` must be the first call.
  The bridge is the server of the peer-to-peer connection (zbus): EXTERNAL authentication of its own uid, and unix fd passing when the client
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
  rules apply unchanged (C-7, C-9, C-14, establish before credentials). The
  bridge asks signond for an account's secret (XA-6) only after the server's identity
  was accepted, in the same step that connects and authenticates: a server that is not
  verified costs a connect, but no secret of the account is in the bridge's memory while
  it talks to it. A signond failure is therefore reported after the connect, and sets no
  attention.
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

- XSEC-1: C-7 holds for every protocol: no credential before the identity check
  passed.
- XSEC-2: Downgrades are never automatic. A backend never retries with a weaker
  profile, dialect or auth method than configured.
- XSEC-3: Every parser of server data is Rust code in `libnetvfs-rs.so`: SSH (russh),
  SFTP packets and attributes, SMB messages and transform headers, SPNEGO and NTLM
  (sspi), and the srvsvc share list. Each caps counts and lengths before allocating, and
  each has a cargo-fuzz target (XT-3).
- XSEC-6: SEC-5 wiping extends to `AuthPrompter` answers and ad-hoc secrets received
  by the bridge (XB-16). The bridge wipes its own copies; the received message that
  carried the secret (`ConnectAdHoc`'s `ay`, the answers of `Answer`) stays unwiped in
  zbus's buffer until the call is handled and the message dropped.
- XSEC-7: The bridge is the only netvfs component reachable from a sandbox. Its attack
  surface is the D-Bus message parser (zbus and zvariant, in Rust) and its
  own argument validation: every path is checked with the rules of `Paths::normalize`
  before use, every numeric argument is range-checked, and every fd is validated
  (XB-11). The parser only sees messages within the inbound limits of XB-17.

## 10. Packaging (amends SPEC 4.1)

- XP-1: Packages:

  | Package | Contents | Requires |
  |---|---|---|
  | `netvfs` | `libnetvfs.so.1`, backend dir, the `sftp`, `smb` and `local` backends, `libnetvfs-rs.so`, QML module `org.netvfs.accounts`, provider descriptors, account providers with their UI QML and icons, `<p>-files` services and their service type, `netvfs-cli`, the Engineering English texts (`netvfs*.qm`, generated at build time; there are no translations) | Qt5Core, Qt5DBus, Qt5Network, accounts-qt5, libsignon-qt5, Silica, jolla-settings-accounts; Recommends `netvfs-backup` |
  | `netvfs-backup` | `sftp-backup` and `smb-backup` services, Buteo plugins and profiles | netvfs, buteo, jolla-vault |
  | `netvfs-bridge` | `netvfs-bridge` (XB-2), its C ABI `libnetvfs-bridge-ffi.so`, `netvfs-accounts` (setgid `privileged`, XB-2a), systemd generator and template units, `consumers/lautta.conf` | netvfs, systemd, sailfish-setup (pre) |
  | `netvfs-devel` | headers, pkg-config | netvfs |

- XP-3: `tools/ci/check-rpm.sh` asserts that `libnetvfs-rs.so` is in the `netvfs`
  package, exports only `nvr_get`, links only the C runtime, and sits where its
  plugins, `libnetvfs-smb.so` among them, look for it; and that no file of the `netvfs`
  package links libssh or libcrypto. `make check-packaging` checks the install tree
  against the `%files` lists.
- XP-4: The RPM check script also asserts that only `netvfs-backup` depends on Buteo.
- XP-5: `netvfs-bridge` stays a package of its own and no package requires it, so only
  devices with a sandboxed consumer carry the setgid accounts helper. The bridge
  reports providers whose backend it cannot load as `Unsupported`.
- XP-6: Parts nobody installs on their own share one package; separate packages stay
  only for what pulls in something the rest does not need (Buteo and jolla-vault for
  backups, a setgid binary for the bridge) or is only for development.

## 11. CLI

- XC-CLI: `netvfs-cli` has, besides `identify`, `verify`, `put`, `get` and `ls`: `stat`, `lstat`, `ls -l` (full v2 entry, `--json`),
  `mkdir [-p] [--exclusive]`, `rm [-r]`, `rmdir`, `mv [--replace]`, `cp` (server copy if
  available, else across via `copyAcross`), `cat [--offset N --length N]`, `chmod`,
  `touch --mtime`, `ln -s`, `readlink`, `df`, `sum --algo`, `caps`, `shares` (SMB),
  `discover [--seconds N]`, `--url URL` as an alternative to `--provider/--host`,
  `--prompt` (keyboard-interactive on the terminal), `--profile strict|signed|guest`
  (SMB). Secrets come only from `--secret-env` or a prompt.

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
- XT-2: Containers: Samba servers with several disk shares for server mode and a guest
  server (`map to guest = Bad User`), besides those of SPEC-smb section 7; OpenSSH with
  keyboard-interactive (a PAM one-time-password stub) and a user limited to
  `MaxSessions 0`, besides those of SPEC-sftp section 9.
- XT-3: Fuzzing on the host. libFuzzer harnesses in `tests/fuzz` (clang, ASan/UBSan):
  the `Url` parser, the `Names` codec and the DNS message parser. cargo-fuzz targets in
  `rust/fuzz`: SFTP packets and attributes, SMB responses and transform headers,
  SPNEGO, the NTLM challenge, the srvsvc share list, SSH key import, and the bridge's
  arguments, bus replies, C ABI marshalling, paths and stored values. Corpora in
  `tests/fuzz/corpus` and `rust/fuzz/seeds`; CI runs each target for 60 s.
- XT-4: Mutation lists (`tests/mutations/*.json`) for: rename-mode logic,
  `checkServerIdentity`, XM-1 profile enforcement, XA-4 service gating, resume offset
  checks, `Names` codec.
- XT-5: Identity tests: no credential before the identity check, and pin mismatch
  behaviour, for SFTP. SMB has no server identity (SPEC-smb section 8, XT-5).
- XT-6: Buteo regression: the Buteo unit and interop tests check the backup behaviour
  (files 0600, `.part` naming, Replace semantics).
- XT-7: Bridge tests: a contract suite (D-Bus introspection XML and golden message
  sequences in `tests/bridge/contract`) shared with the consumer's fake bridge; peer check
  (wrong uid, wrong executable, pid reuse); consent states and revocation mid-job; fd
  validation (directory, read-only fd for download, FIFO without size); disconnect
  cancels jobs within C-9's 2 s; folder deletion and recreation (XB-4); limits (XB-17);
  fuzzing of argument validation through a libFuzzer harness that feeds decoded
  messages to the adaptor. The contract suite also runs as a black box
  against the built binary from a libdbus client (`tests/bridge/contract`: introspection,
  peer interface, fd passing, error details, every golden sequence), next to the Rust
  tests of `rust/netvfs-bridge`; the argument fuzzing is a cargo-fuzz target.

## 14. Open questions

3. signond ACL behaviour on 5.2 (XA-6) — decides whether the bridge needs an ACL entry.
4. Which settings D-Bus entry points open a specific account page and the account
   creation flow for a provider on 5.2 (XB-15)? Needs a device test.
5. Keep qmake? It works on the Qt 5.6 SDK target and matches the existing tree; switching
   to CMake buys nothing until the platform moves past Qt 5.6.
6. Bridge rendezvous alternative: instead of a socket in the consumer's folder, the bridge
   could call into the consumer's own D-Bus name (which sailjail lets the app own) and hand
   over a socketpair end. Kept as fallback if the folder socket proves fragile (XB-4).
