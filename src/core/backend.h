// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BACKEND_H
#define NETVFS_BACKEND_H

#include "error.h"
#include "types.h"

#include <QtCore/QObject>
#include <QtCore/QVector>
#include <QtCore/QtPlugin>

QT_BEGIN_NAMESPACE
class QIODevice;
QT_END_NAMESPACE

namespace NetVfs {

// Random access to one remote file. Belongs to the opening backend and its thread. After
// disconnect() every call returns ConnectionLost; delete the handle before its backend.
class NETVFS_EXPORT ReadHandle
{
public:
    virtual ~ReadHandle();
    virtual qint64 size() const = 0;
    // Replaces `*out`. Short read only at EOF; read at or past EOF succeeds with empty `*out`.
    virtual Result read(qint64 offset, qint64 maxBytes, QByteArray *out) = 0;
    virtual void readAhead(qint64 offset, qint64 bytes) = 0;
    virtual Result close() = 0;
};

class NETVFS_EXPORT WriteHandle
{
public:
    virtual ~WriteHandle();
    virtual Result write(const char *data, qint64 length) = 0;
    virtual qint64 position() const = 0;
    virtual Result commit() = 0;
    virtual void abort() = 0;
};

// One instance = one connection. Thread-confined: every call except cancel() from one thread. All
// calls block.
// Paths use '/'; callers pass Paths::normalize()d paths. Names lossless (Names::encode/decode).
// Defaulted methods return Unsupported unless the capability is reported.
class NonCopyable
{
protected:
    NonCopyable() = default;
    ~NonCopyable() = default;

public:
    NonCopyable(const NonCopyable &) = delete;
    NonCopyable &operator=(const NonCopyable &) = delete;
};

class NETVFS_EXPORT Backend : private NonCopyable
{
public:
    virtual ~Backend();

    // Sends no credentials.
    virtual Result connect(const ConnectionParams &params, ServerIdentity *seen) = 0;
    // `prompter` may be null: interactive methods are then not attempted.
    virtual Result authenticate(const Credentials &credentials, AuthPrompter *prompter) = 0;
    virtual Capabilities capabilities() const = 0;

    virtual Result stat(const QString &path, Entry *out) = 0;
    virtual Result lstat(const QString &path, Entry *out);
    virtual Result list(const QString &dir, ListSink *sink, const ListOptions &options) = 0;

    // With `exclusive` an existing entry is AlreadyExists, without it an existing folder is
    // success.
    virtual Result makeDir(const QString &path, bool exclusive) = 0;
    virtual Result removeFile(const QString &path) = 0;
    virtual Result removeDir(const QString &path) = 0;
    virtual Result removeTreeNative(const QString &path);
    // NoReplace fails with AlreadyExists if `to` exists; replacing a folder is AlreadyExists in
    // both modes.
    virtual Result rename(const QString &from, const QString &to, RenameMode mode) = 0;
    // Checks every field first; an unsupported one changes nothing.
    virtual Result setAttributes(const QString &path, const AttributeChanges &changes);
    // Targets verbatim (not normalised, may be relative).
    virtual Result readLink(const QString &path, QString *target);
    virtual Result makeSymlink(const QString &target, const QString &linkPath);
    virtual Result makeHardlink(const QString &existing, const QString &newPath);

    // Caller owns the returned handle.
    virtual Result openRead(const QString &path, ReadHandle **out);
    virtual Result openWrite(const QString &path, const WriteOptions &options, WriteHandle **out);
    virtual Result upload(QIODevice *source, const QString &path, const UploadOptions &options,
                          Progress *progress) = 0;
    virtual Result download(const QString &path, QIODevice *sink, const DownloadOptions &options,
                            Progress *progress) = 0;

    virtual Result copy(const QString &from, const QString &to, const CopyOptions &options);
    virtual Result checksum(const QString &path, const QString &algorithm, QByteArray *digest);
    virtual Result spaceInfo(const QString &dir, SpaceInfo *out);
    virtual Result keepAlive() = 0;

    // Thread-safe. In-flight call returns Canceled within 2 s.
    virtual void cancel() = 0;
    // Clears a previous cancel() so cleanup (removing a .part) can run on the same connection.
    virtual void resetCancel() = 0;
    virtual void disconnect() = 0;

    Result list(const QString &dir, QVector<Entry> *out);
    Result remove(const QString &path);
    // `length` -1: to EOF.
    Result read(const QString &path, qint64 offset, qint64 length, QByteArray *out);
    Result freeSpace(const QString &dir, qint64 *bytes);
    Result makePath(const QString &dir);
    Result authenticate(const Credentials &credentials) { return authenticate(credentials, nullptr); }
};

class NETVFS_EXPORT BackendFactory
{
public:
    virtual ~BackendFactory();
    virtual QString provider() const = 0;
    virtual Result create(Backend **out) = 0;
};

}
Q_DECLARE_INTERFACE(NetVfs::BackendFactory, "org.netvfs.BackendFactory")

#endif
