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

// One instance = one connection. Thread-confined: every call except cancel()
// must come from the same thread. All calls block (SPEC C-8).
//
// Paths use '/' as separator (SPEC C-15). Callers pass paths that went
// through Paths::normalize(); backends translate them.
class NETVFS_EXPORT Backend
{
public:
    virtual ~Backend();

    // Opens the transport and reports the server identity, if the protocol has
    // one. Sends no credentials (SPEC C-7).
    virtual Result connect(const ConnectionParams &params, ServerIdentity *seen) = 0;
    virtual Result authenticate(const Credentials &credentials) = 0;

    virtual Result stat(const QString &path, Entry *out) = 0;
    virtual Result list(const QString &dir, QVector<Entry> *out) = 0;
    virtual Result makePath(const QString &dir) = 0;                     // mkdir -p
    virtual Result remove(const QString &path) = 0;
    virtual Result rename(const QString &from, const QString &to) = 0;   // replaces `to`
    virtual Result freeSpace(const QString &dir, qint64 *bytes) = 0;     // Unsupported allowed
    // Streams in bounded memory (SPEC C-10).
    virtual Result upload(QIODevice *source, const QString &path, Progress *progress) = 0;
    virtual Result download(const QString &path, QIODevice *sink, Progress *progress) = 0;
    virtual Result read(const QString &path, qint64 offset, qint64 length, QByteArray *out) = 0;

    // Thread-safe. The in-flight call returns Canceled within 2 s (SPEC C-9).
    virtual void cancel() = 0;
    // Clears a previous cancel() so that cleanup requests (removing a .part
    // file after a canceled upload) can run on the same connection.
    virtual void resetCancel() = 0;
    virtual void disconnect() = 0;
};

// Interface implemented by each backend plugin (libnetvfs-<provider>.so),
// IID "org.netvfs.BackendFactory/1.0".
class NETVFS_EXPORT BackendFactory
{
public:
    virtual ~BackendFactory();
    virtual QString provider() const = 0;
    virtual Backend *create() = 0;
};

} // namespace NetVfs

// Plugins use the same IID string in Q_PLUGIN_METADATA (moc needs a literal).
Q_DECLARE_INTERFACE(NetVfs::BackendFactory, "org.netvfs.BackendFactory/1.0")

#endif
