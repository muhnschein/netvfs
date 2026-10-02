// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_FAKEBACKEND_H
#define NETVFS_TEST_FAKEBACKEND_H

#include "backend.h"

#include <QtCore/QHash>
#include <QtCore/QMutex>
#include <QtCore/QStringList>

#include <atomic>

namespace NetVfs {
namespace Test {

// In-memory server shared by all FakeBackend instances, with fault injection.
// Paths are stored normalized without a leading '/'.
class Q_DECL_EXPORT FakeServer
{
public:
    struct Node {
        bool isDir = false;
        QByteArray data;
        QDateTime modified;
    };

    static FakeServer *instance();
    void reset();

    // Configuration
    ServerIdentity identity;            // reported by connect()
    QString userName = QStringLiteral("user");
    QByteArray secret = "secret";
    qint64 freeBytes = 1LL << 40;      // -1: freeSpace() is Unsupported
    Result connectResult;               // returned by connect()
    QHash<QString, Result> failOps;     // op name -> result to return (once)
    qint64 failUploadAfterBytes = -1;   // simulate a dropped connection
    int chunkDelayMs = 0;               // per 64 KiB chunk, for cancel tests
    bool reportSizeMismatch = false;    // stat() of .part lies about the size

    // State
    QHash<QString, Node> nodes;
    QStringList log;                    // "connect", "authenticate", "upload:<path>", ...
    int liveBackends = 0;

    void addFile(const QString &path, const QByteArray &data, const QDateTime &modified = QDateTime::currentDateTimeUtc());
    void addDir(const QString &path);
    bool exists(const QString &path) const;
    QByteArray fileData(const QString &path) const;

    QMutex mutex;

private:
    FakeServer() { reset(); }
};

class Q_DECL_EXPORT FakeBackend : public Backend
{
public:
    explicit FakeBackend(FakeServer *server = FakeServer::instance());
    ~FakeBackend() override;

    Result connect(const ConnectionParams &params, ServerIdentity *seen) override;
    Result authenticate(const Credentials &credentials) override;
    Result stat(const QString &path, Entry *out) override;
    Result list(const QString &dir, QVector<Entry> *out) override;
    Result makePath(const QString &dir) override;
    Result remove(const QString &path) override;
    Result rename(const QString &from, const QString &to) override;
    Result freeSpace(const QString &dir, qint64 *bytes) override;
    Result upload(QIODevice *source, const QString &path, Progress *progress) override;
    Result download(const QString &path, QIODevice *sink, Progress *progress) override;
    Result read(const QString &path, qint64 offset, qint64 length, QByteArray *out) override;
    void cancel() override;
    void resetCancel() override;
    void disconnect() override;

private:
    Result begin(const QString &op, bool needAuth = true);
    static QString key(const QString &path);

    FakeServer *m_server;
    bool m_connected = false;
    bool m_authenticated = false;
    std::atomic<bool> m_canceled { false };
};

} // namespace Test
} // namespace NetVfs

#endif
