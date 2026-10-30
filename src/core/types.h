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

enum class EntryType : quint8 { Unknown, File, Directory, Symlink, Special };

enum class EntryFlag : quint16 {
    Hidden        = 0x0001,  // SMB hidden attribute; dot-names NOT flagged
    ReadOnly      = 0x0002,
    System        = 0x0004,
    NameNotUtf8   = 0x0008,
    TargetUnknown = 0x0010
};
Q_DECLARE_FLAGS(EntryFlags, EntryFlag)

// Sentinels for unknown: -1 for numbers, invalid QDateTime, empty strings.
struct NETVFS_EXPORT Entry {
    QString name;
    EntryType type = EntryType::Unknown;
    EntryType targetType = EntryType::Unknown;
    qint64 size = -1;  // -1 unknown
    QDateTime modified;
    QDateTime created;
    QDateTime accessed;
    qint32 mode = -1;  // permission bits & 07777; -1 unknown
    qint64 uid = -1;
    qint64 gid = -1;
    QString owner;
    QString group;
    EntryFlags flags;
    QByteArray etag;
    QString contentType;
    QVariantMap extra;
    bool isDir() const;
    bool isFile() const;
};

enum class Capability : quint32 {
    Symlinks, Hardlinks, PosixModes, Ownership, SetModified, SetModifiedOnUpload,
    ReadHandles, EfficientRanges,
    WriteResume,
    AtomicPut,
    AtomicReplace,
    NativeNoReplace,
    ServerCopy, ServerCopyRecursive,
    RecursiveDelete,
    SpaceInfo, Checksums,
    CaseInsensitive, WindowsNames,
    ShareEnumeration,
    ETags
};

inline uint qHash(Capability c, uint seed = 0) noexcept
{
    return ::qHash(static_cast<quint32>(c), seed);
}

NETVFS_EXPORT QString capabilityName(Capability c);
NETVFS_EXPORT bool capabilityFromName(const QString &name, Capability *out);
NETVFS_EXPORT QVector<Capability> allCapabilities();

struct NETVFS_EXPORT Capabilities {
    QSet<Capability> flags;
    QStringList checksumAlgorithms;
    qint64 maxNameBytes = -1;
    qint64 maxReadChunk = 0;
    qint64 maxWriteChunk = 0;
    bool has(Capability c) const { return flags.contains(c); }
    QStringList names() const;
};

struct NETVFS_EXPORT ServerIdentity {
    enum class Kind { None, SshHostKey };
    Kind kind = Kind::None;
    QString algorithm;
    QByteArray publicKey;
    QString fingerprint;

    bool isEmpty() const { return publicKey.isEmpty(); }

    // Pin format stored in the account: "<algorithm> <base64 publicKey>".
    QString toPin() const;
    static ServerIdentity fromPin(const QString &pin);

    friend bool operator==(const ServerIdentity &a, const ServerIdentity &b)
    {
        return a.algorithm == b.algorithm && a.publicKey == b.publicKey;
    }
    friend bool operator!=(const ServerIdentity &a, const ServerIdentity &b) { return !(a == b); }
};

// Provider-specific values live in `options`, keyed without the "netvfs/<provider>/" prefix (e.g.
// "host_key", "share").
struct ConnectionParams {
    QString provider;
    QString host;
    int port = 0;
    QString username;
    QVariantMap options;
    int connectTimeoutMs = 15000;
    int requestTimeoutMs = 60000;

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

struct AuthPrompt {
    QString text;
    bool echo = false;
};

class NETVFS_EXPORT AuthPrompter
{
public:
    virtual ~AuthPrompter();
    // Called on the backend thread; may block until the user answers. false if declined
    // (AuthFailed) or on cancel(). Backend wipes `answers` after use.
    virtual bool answer(const QString &name, const QString &instruction,
                        const QVector<AuthPrompt> &prompts, QVector<QByteArray> *answers) = 0;
    // Backend::cancel() calls this from any thread while answer() runs. An answer() that waits for
    // a person must end that wait soon and return false (BlockingPrompter does). Default
    // fits prompters that never block.
    virtual void cancel()
    {
        // Nothing to wake: this prompter never blocks.
    }
};

// Called on the transferring thread.
class Progress
{
public:
    virtual ~Progress() = default;
    virtual void update(qint64 done, qint64 total) = 0;
    // A sink may stop the transfer without cross-thread cancel(); transfer ends with Canceled.
    virtual bool canceled() const { return false; }
};

class ListSink
{
public:
    virtual ~ListSink() = default;
    // Called on the backend thread. false stops (Canceled).
    virtual bool entries(const QVector<Entry> &batch) = 0;
};

struct ListOptions {
    int batchSize = 256;
    bool resolveSymlinkTypes = false;
};

enum class RenameMode { NoReplace, Replace };

struct AttributeChanges {
    qint32 mode = -1;
    QDateTime modified;
    QDateTime accessed;
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

struct WriteOptions {
    enum class Disposition { CreateNew, Truncate, Resume };
    Disposition disposition = Disposition::CreateNew;
    qint64 resumeOffset = 0;
    qint32 createMode = -1;  // -1: backend default
    qint64 expectedSize = -1;
    QDateTime modified;
};

struct UploadOptions {
    WriteOptions write;
};

struct DownloadOptions {
    qint64 offset = 0;
    qint64 length = -1;
};

}
Q_DECLARE_OPERATORS_FOR_FLAGS(NetVfs::EntryFlags)

#endif
