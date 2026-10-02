// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TYPES_H
#define NETVFS_TYPES_H

#include "netvfs_global.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QFlags>
#include <QtCore/QSet>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>
#include <QtCore/QVector>

namespace NetVfs {

// ---------------------------------------------------------------- entries (XC-2)

enum class EntryType : quint8 { Unknown, File, Directory, Symlink, Special };

enum class EntryFlag : quint16 {
    Hidden        = 0x0001,  // SMB/WebDAV hidden attribute; dot-names are NOT flagged here
    ReadOnly      = 0x0002,  // SMB read-only attribute, WebDAV permissions lacking write
    System        = 0x0004,  // SMB system attribute
    NameNotUtf8   = 0x0008,  // XC-4: name contains escaped bytes
    TargetUnknown = 0x0010   // symlink whose target type could not be determined
};
Q_DECLARE_FLAGS(EntryFlags, EntryFlag)

// Sentinels for unknown values: -1 for numbers, invalid QDateTime, empty
// strings (XC-1c: no std::optional in exported structs).
struct NETVFS_EXPORT Entry {
    QString name;                    // XC-4 lossless (Names::decode)
    EntryType type = EntryType::Unknown;
    EntryType targetType = EntryType::Unknown;  // for Symlink, when resolved (XC-6)
    qint64 size = -1;                // -1 unknown (v1 used 0)
    QDateTime modified;              // UTC; invalid if unknown
    QDateTime created;               // SMB, local (statx btime), WebDAV creationdate
    QDateTime accessed;
    qint32 mode = -1;                // permission bits & 07777; -1 unknown
    qint64 uid = -1;
    qint64 gid = -1;
    QString owner;                   // names when the server provides them
    QString group;
    EntryFlags flags;
    QByteArray etag;                 // opaque change token (WebDAV ETag); empty if none
    QString contentType;             // server-declared; advisory only, never trusted
    QVariantMap extra;               // backend-specific (e.g. "oc:fileid"), documented per backend

    bool isDir() const;              // Directory, or Symlink whose targetType is Directory
    bool isFile() const;             // File, or Symlink whose targetType is File
};

// ---------------------------------------------------------- capabilities (XC-5)

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

inline uint qHash(Capability c, uint seed = 0) noexcept
{
    return ::qHash(static_cast<quint32>(c), seed);
}

// Stable names ("Symlinks", "AtomicPut", ...) for the CLI and the bridge (XB-9).
NETVFS_EXPORT QString capabilityName(Capability c);
NETVFS_EXPORT bool capabilityFromName(const QString &name, Capability *out);
NETVFS_EXPORT QVector<Capability> allCapabilities();

struct NETVFS_EXPORT Capabilities {
    QSet<Capability> flags;                // QSet keeps the enum open for growth
    QStringList checksumAlgorithms;        // "sha256", "md5", ...
    qint64 maxNameBytes = -1;              // -1 unknown
    qint64 maxReadChunk = 0;               // 0 unknown
    qint64 maxWriteChunk = 0;
    bool has(Capability c) const { return flags.contains(c); }
    QStringList names() const;             // sorted capabilityName()s
};

// -------------------------------------------------------- identity (XC-16)

// Server identity as seen during connect(). Kind::None for protocols without one.
struct NETVFS_EXPORT ServerIdentity {
    enum class Kind { None, SshHostKey, TlsCertificate };
    Kind kind = Kind::None;
    QString algorithm;        // "ssh-ed25519" | "tls-spki-sha256"
    QByteArray publicKey;     // SSH: key blob; TLS: DER SubjectPublicKeyInfo
    QString fingerprint;      // SSH: "SHA256:..."; TLS: SHA-256 of SPKI, base64 (curl pin form)
    bool systemTrusted = false;          // TLS chain + hostname verified against system CAs
    enum Problem { SelfSigned = 1, UntrustedRoot = 2, Expired = 4, NotYetValid = 8, HostnameMismatch = 16 };
    int problems = 0;
    QVariantMap details;      // TLS: subject, issuer, notBefore, notAfter, sans, certSha256

    static constexpr const char *TlsAlgorithm = "tls-spki-sha256";

    bool isEmpty() const { return publicKey.isEmpty(); }

    // Pin format stored in the account: "<algorithm> <base64 publicKey>"
    // (unchanged for SSH; the algorithm prefix distinguishes kinds).
    QString toPin() const;
    static ServerIdentity fromPin(const QString &pin);
    // TLS: identity for a DER SubjectPublicKeyInfo (fills fingerprint).
    static ServerIdentity fromTlsSpki(const QByteArray &spkiDer);

    friend bool operator==(const ServerIdentity &a, const ServerIdentity &b)
    {
        return a.algorithm == b.algorithm && a.publicKey == b.publicKey;
    }
    friend bool operator!=(const ServerIdentity &a, const ServerIdentity &b) { return !(a == b); }
};

// ------------------------------------------------------------- connection

// Connection parameters. Provider-specific values live in `options`, keyed
// without the "netvfs/<provider>/" prefix (for example "host_key", "share").
struct ConnectionParams {
    QString provider;       // "sftp", "smb", "webdav", "ftp", "local", ...
    QString host;
    int port = 0;           // 0: protocol default
    QString username;
    QVariantMap options;
    int connectTimeoutMs = 15000;   // SPEC C-14
    int requestTimeoutMs = 60000;   // SPEC C-14

    QString option(const QString &key, const QString &fallback = QString()) const
    {
        return options.value(key, fallback).toString();
    }
    bool flag(const QString &key, bool fallback = false) const
    {
        const QVariant v = options.value(key);
        if (!v.isValid())
            return fallback;
        const QString s = v.toString();
        return s == QLatin1String("true") || s == QLatin1String("1");
    }
};

// Credentials; the secret is wiped on destruction (SEC-5).
class NETVFS_EXPORT Credentials
{
public:
    Credentials() = default;
    Credentials(const QString &userName, const QByteArray &secret);
    Credentials(const Credentials &other);
    Credentials &operator=(const Credentials &other);
    ~Credentials();

    QString userName;
    QByteArray secret;

    void wipe();
};

// ------------------------------------------------------- interactive auth (XC-15)

struct AuthPrompt {
    QString text;
    bool echo = false;
};

class NETVFS_EXPORT AuthPrompter
{
public:
    virtual ~AuthPrompter();
    // Called on the backend thread; may block until the user answers.
    // Returns false if the user declined (result: AuthFailed) or on cancel().
    // The backend wipes `answers` after use (SEC-5).
    virtual bool answer(const QString &name, const QString &instruction,
                        const QVector<AuthPrompt> &prompts, QVector<QByteArray> *answers) = 0;
};

// ---------------------------------------------------------------- progress

// Progress sink for streamed transfers. Called on the transferring thread.
class Progress
{
public:
    virtual ~Progress() = default;
    virtual void update(qint64 done, qint64 total) = 0;
    // XC-14: a sink may stop the transfer without a cross-thread cancel();
    // the transfer then ends with Canceled.
    virtual bool canceled() const { return false; }
};

// ------------------------------------------------------------- listing (XC-6)

class ListSink
{
public:
    virtual ~ListSink() = default;
    // Called on the backend thread. Return false to stop (result: Canceled).
    virtual bool entries(const QVector<Entry> &batch) = 0;
};

struct ListOptions {
    int batchSize = 256;
    bool resolveSymlinkTypes = false;  // stat each symlink target to fill targetType
};

// --------------------------------------------------- namespace options (XC-10..)

enum class RenameMode { NoReplace, Replace };

struct AttributeChanges {
    qint32 mode = -1;        // -1: unchanged
    QDateTime modified;      // invalid: unchanged
    QDateTime accessed;      // invalid: unchanged
    bool isEmpty() const { return mode < 0 && !modified.isValid() && !accessed.isValid(); }
};

struct CopyOptions {
    bool recursive = false;
    RenameMode mode = RenameMode::NoReplace;
};

struct SpaceInfo {
    qint64 free = -1;
    qint64 total = -1;
    qint64 used = -1;
};

// ------------------------------------------------------------ I/O (XC-13/14)

struct WriteOptions {
    enum Disposition { CreateNew, Truncate, Resume };
    Disposition disposition = CreateNew;
    qint64 resumeOffset = 0;          // Resume: must equal current remote size
    qint32 createMode = -1;           // -1: backend default (XC-23)
    qint64 expectedSize = -1;         // allows preallocation / Content-Length
    QDateTime modified;               // applied on commit when SetModified/OnUpload
};

struct UploadOptions {
    WriteOptions write;
};

struct DownloadOptions {
    qint64 offset = 0;
    qint64 length = -1;               // -1: to EOF
};

} // namespace NetVfs

Q_DECLARE_OPERATORS_FOR_FLAGS(NetVfs::EntryFlags)

#endif
