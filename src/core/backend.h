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

// XC-13: random access to one remote file. Belongs to the backend that opened
// it and to that backend's thread. After the backend's disconnect() every call
// returns ConnectionLost; a handle must be deleted before its backend.
class NETVFS_EXPORT ReadHandle
{
public:
    virtual ~ReadHandle();
    virtual qint64 size() const = 0;                    // at open time; -1 unknown
    // Appends nothing and replaces `*out`. A short read happens only at EOF;
    // reading at or past EOF succeeds with an empty `*out`.
    virtual Result read(qint64 offset, qint64 maxBytes, QByteArray *out) = 0;
    virtual void readAhead(qint64 offset, qint64 bytes) = 0;  // hint; may be a no-op
    virtual Result close() = 0;
};

// XC-13: sequential writes with an explicit commit.
class NETVFS_EXPORT WriteHandle
{
public:
    virtual ~WriteHandle();
    virtual Result write(const char *data, qint64 length) = 0;  // sequential
    virtual qint64 position() const = 0;
    virtual Result commit() = 0;      // flush (fsync where available), close, apply mtime
    virtual void abort() = 0;         // close without commit; partial data may remain
};

// One instance = one connection. Thread-confined: every call except cancel()
// must come from the same thread. All calls block (SPEC C-8). API v2.
//
// Paths use '/' as separator (SPEC C-15). Callers pass paths that went
// through Paths::normalize(); backends translate them. Names are lossless
// (XC-4, Names::encode/decode).
//
// Methods with a default implementation return Unsupported unless the
// matching capability is reported (XC-5).
class NETVFS_EXPORT Backend
{
public:
    virtual ~Backend();

    // Opens the transport and reports the server identity, if the protocol has
    // one. Sends no credentials (SPEC C-7).
    virtual Result connect(const ConnectionParams &params, ServerIdentity *seen) = 0;
    // `prompter` may be null: interactive methods are then not attempted (XC-15).
    virtual Result authenticate(const Credentials &credentials, AuthPrompter *prompter) = 0;
    // Valid after authenticate(); stable for the life of the connection (XC-5).
    virtual Capabilities capabilities() const = 0;

    virtual Result stat(const QString &path, Entry *out) = 0;      // follows symlinks
    virtual Result lstat(const QString &path, Entry *out);         // default: stat()
    // XC-6: streams batches into `sink`; "." and ".." never appear.
    virtual Result list(const QString &dir, ListSink *sink, const ListOptions &options) = 0;

    // XC-8: one folder; with `exclusive` an existing entry is AlreadyExists,
    // without it an existing folder is success.
    virtual Result makeDir(const QString &path, bool exclusive) = 0;
    // XC-9
    virtual Result removeFile(const QString &path) = 0;            // directory: IsADirectory
    virtual Result removeDir(const QString &path) = 0;             // non-empty: DirectoryNotEmpty
    virtual Result removeTreeNative(const QString &path);          // RecursiveDelete
    // XC-10: NoReplace fails with AlreadyExists if `to` exists; replacing a
    // folder is AlreadyExists in both modes.
    virtual Result rename(const QString &from, const QString &to, RenameMode mode) = 0;
    // XC-11: checks every field first; an unsupported one changes nothing.
    virtual Result setAttributes(const QString &path, const AttributeChanges &changes);
    // XC-12: targets verbatim (not normalised, may be relative).
    virtual Result readLink(const QString &path, QString *target);
    virtual Result makeSymlink(const QString &target, const QString &linkPath);
    virtual Result makeHardlink(const QString &existing, const QString &newPath);

    // XC-13: the caller owns the returned handle.
    virtual Result openRead(const QString &path, ReadHandle **out);
    virtual Result openWrite(const QString &path, const WriteOptions &options, WriteHandle **out);
    // XC-14: streams in bounded memory (SPEC C-10).
    virtual Result upload(QIODevice *source, const QString &path, const UploadOptions &options,
                          Progress *progress) = 0;
    virtual Result download(const QString &path, QIODevice *sink, const DownloadOptions &options,
                            Progress *progress) = 0;

    // XC-17..20
    virtual Result copy(const QString &from, const QString &to, const CopyOptions &options);
    virtual Result checksum(const QString &path, const QString &algorithm, QByteArray *digest);
    virtual Result spaceInfo(const QString &dir, SpaceInfo *out);
    virtual Result keepAlive() = 0;

    // Thread-safe. The in-flight call returns Canceled within 2 s (SPEC C-9).
    virtual void cancel() = 0;
    // Clears a previous cancel() so that cleanup requests (removing a .part
    // file after a canceled upload) can run on the same connection.
    virtual void resetCancel() = 0;
    virtual void disconnect() = 0;

    // ---- Non-virtual helpers kept for v1 callers (Buteo, CLI) ----
    // Collects a streamed listing.
    Result list(const QString &dir, QVector<Entry> *out);
    // A file, else an empty folder (v1 semantics).
    Result remove(const QString &path);
    // One ranged read through openRead(). `length` -1: to EOF.
    Result read(const QString &path, qint64 offset, qint64 length, QByteArray *out);
    // spaceInfo().free; Unsupported when unknown.
    Result freeSpace(const QString &dir, qint64 *bytes);
    // mkdir -p over makeDir(); the empty path and "/" exist.
    Result makePath(const QString &dir);
    // establish() helper for callers without a prompter.
    Result authenticate(const Credentials &credentials) { return authenticate(credentials, nullptr); }
};

// Interface implemented by each backend plugin (libnetvfs-<provider>.so),
// IID "org.netvfs.BackendFactory/2.0" (XC-1).
class NETVFS_EXPORT BackendFactory
{
public:
    virtual ~BackendFactory();
    virtual QString provider() const = 0;
    virtual Backend *create() = 0;
};

} // namespace NetVfs

#define NETVFS_BACKEND_FACTORY_IID "org.netvfs.BackendFactory/2.0"
// Plugins use the same IID string in Q_PLUGIN_METADATA (moc needs a literal).
Q_DECLARE_INTERFACE(NetVfs::BackendFactory, "org.netvfs.BackendFactory/2.0")

#endif
