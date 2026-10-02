// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakebackend.h"
#include "paths.h"

#include <QtCore/QIODevice>
#include <QtCore/QMutexLocker>
#include <QtCore/QThread>

namespace NetVfs {
namespace Test {

FakeServer *FakeServer::instance()
{
    static FakeServer server;
    return &server;
}

void FakeServer::reset()
{
    identity = ServerIdentity();
    userName = QStringLiteral("user");
    secret = "secret";
    freeBytes = 1LL << 40;
    connectResult = Result();
    failOps.clear();
    failUploadAfterBytes = -1;
    chunkDelayMs = 0;
    reportSizeMismatch = false;
    nodes.clear();
    log.clear();
}

void FakeServer::addFile(const QString &path, const QByteArray &data, const QDateTime &modified)
{
    Node node;
    node.data = data;
    node.modified = modified;
    nodes.insert(path, node);
}

void FakeServer::addDir(const QString &path)
{
    QString current;
    for (const QString &part : path.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS)) {
        current = Paths::join(current, part);
        Node node;
        node.isDir = true;
        nodes.insert(current, node);
    }
}

bool FakeServer::exists(const QString &path) const
{
    return nodes.contains(path);
}

QByteArray FakeServer::fileData(const QString &path) const
{
    return nodes.value(path).data;
}

FakeBackend::FakeBackend(FakeServer *server)
    : m_server(server)
{
    QMutexLocker lock(&m_server->mutex);
    ++m_server->liveBackends;
}

FakeBackend::~FakeBackend()
{
    QMutexLocker lock(&m_server->mutex);
    --m_server->liveBackends;
}

QString FakeBackend::key(const QString &path)
{
    QString normalized;
    Paths::normalize(path, &normalized);
    while (normalized.startsWith(QLatin1Char('/')))
        normalized.remove(0, 1);
    return normalized;
}

Result FakeBackend::begin(const QString &op, bool needAuth)
{
    m_server->log << op;
    if (m_canceled)
        return Result(Error::Canceled);
    const QString name = op.section(QLatin1Char(':'), 0, 0);
    if (m_server->failOps.contains(name))
        return m_server->failOps.take(name);
    if (needAuth && !m_authenticated)
        return Result(Error::Internal, QStringLiteral("not authenticated"));
    return Result();
}

Result FakeBackend::connect(const ConnectionParams &, ServerIdentity *seen)
{
    QMutexLocker lock(&m_server->mutex);
    Result r = begin(QStringLiteral("connect"), false);
    if (r.ok())
        r = m_server->connectResult;
    if (!r.ok())
        return r;
    m_connected = true;
    if (seen)
        *seen = m_server->identity;
    return r;
}

Result FakeBackend::authenticate(const Credentials &credentials)
{
    QMutexLocker lock(&m_server->mutex);
    Result r = begin(QStringLiteral("authenticate"), false);
    if (!r.ok())
        return r;
    if (!m_connected)
        return Result(Error::Internal, QStringLiteral("not connected"));
    if (credentials.userName != m_server->userName || credentials.secret != m_server->secret)
        return Result(Error::AuthFailed, QStringLiteral("wrong user name or secret"));
    m_authenticated = true;
    return r;
}

Result FakeBackend::stat(const QString &path, Entry *out)
{
    QMutexLocker lock(&m_server->mutex);
    const QString k = key(path);
    Result r = begin(QStringLiteral("stat:") + k);
    if (!r.ok())
        return r;
    if (!k.isEmpty() && !m_server->nodes.contains(k))
        return Result(Error::NotFound, k);
    const FakeServer::Node node = m_server->nodes.value(k);
    out->name = Paths::fileName(k);
    out->isDir = k.isEmpty() || node.isDir;
    out->size = node.data.size();
    if (m_server->reportSizeMismatch && k.endsWith(QLatin1String(".part")))
        out->size += 1;
    out->modified = node.modified;
    return r;
}

Result FakeBackend::list(const QString &dir, QVector<Entry> *out)
{
    QMutexLocker lock(&m_server->mutex);
    const QString k = key(dir);
    Result r = begin(QStringLiteral("list:") + k);
    if (!r.ok())
        return r;
    if (!k.isEmpty() && (!m_server->nodes.contains(k) || !m_server->nodes.value(k).isDir))
        return Result(Error::NotFound, k);
    out->clear();
    for (auto it = m_server->nodes.constBegin(); it != m_server->nodes.constEnd(); ++it) {
        if (Paths::parent(it.key()) != k)
            continue;
        Entry e;
        e.name = Paths::fileName(it.key());
        e.isDir = it->isDir;
        e.size = it->data.size();
        e.modified = it->modified;
        out->append(e);
    }
    return r;
}

Result FakeBackend::makePath(const QString &dir)
{
    QMutexLocker lock(&m_server->mutex);
    const QString k = key(dir);
    Result r = begin(QStringLiteral("makePath:") + k);
    if (!r.ok())
        return r;
    QString current;
    for (const QString &part : k.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS)) {
        current = Paths::join(current, part);
        if (m_server->nodes.contains(current) && !m_server->nodes.value(current).isDir)
            return Result(Error::AlreadyExists, current);
    }
    m_server->addDir(k);
    return r;
}

Result FakeBackend::remove(const QString &path)
{
    QMutexLocker lock(&m_server->mutex);
    const QString k = key(path);
    Result r = begin(QStringLiteral("remove:") + k);
    if (!r.ok())
        return r;
    if (!m_server->nodes.contains(k))
        return Result(Error::NotFound, k);
    m_server->nodes.remove(k);
    return r;
}

Result FakeBackend::rename(const QString &from, const QString &to)
{
    QMutexLocker lock(&m_server->mutex);
    const QString f = key(from);
    const QString t = key(to);
    Result r = begin(QStringLiteral("rename:") + f + QStringLiteral("->") + t);
    if (!r.ok())
        return r;
    if (!m_server->nodes.contains(f))
        return Result(Error::NotFound, f);
    m_server->nodes.insert(t, m_server->nodes.take(f));
    return r;
}

Result FakeBackend::freeSpace(const QString &dir, qint64 *bytes)
{
    QMutexLocker lock(&m_server->mutex);
    Result r = begin(QStringLiteral("freeSpace:") + key(dir));
    if (!r.ok())
        return r;
    if (m_server->freeBytes < 0)
        return Result(Error::Unsupported);
    *bytes = m_server->freeBytes;
    return r;
}

Result FakeBackend::upload(QIODevice *source, const QString &path, Progress *progress)
{
    const QString k = key(path);
    int delay = 0;
    qint64 failAfter = -1;
    {
        QMutexLocker lock(&m_server->mutex);
        Result r = begin(QStringLiteral("upload:") + k);
        if (!r.ok())
            return r;
        FakeServer::Node node;
        node.modified = QDateTime::currentDateTimeUtc();
        m_server->nodes.insert(k, node);
        delay = m_server->chunkDelayMs;
        failAfter = m_server->failUploadAfterBytes;
    }
    qint64 done = 0;
    for (;;) {
        if (m_canceled)
            return Result(Error::Canceled);
        const QByteArray chunk = source->read(64 * 1024);
        if (chunk.isEmpty())
            break;
        if (delay > 0)
            QThread::msleep(static_cast<unsigned long>(delay));
        QMutexLocker lock(&m_server->mutex);
        m_server->nodes[k].data.append(chunk);
        done += chunk.size();
        if (failAfter >= 0 && done >= failAfter)
            return Result(Error::NetworkUnreachable, QStringLiteral("connection dropped"));
        if (progress)
            progress->update(done, source->size());
    }
    return Result();
}

Result FakeBackend::download(const QString &path, QIODevice *sink, Progress *progress)
{
    QByteArray data;
    int delay = 0;
    {
        QMutexLocker lock(&m_server->mutex);
        const QString k = key(path);
        Result r = begin(QStringLiteral("download:") + k);
        if (!r.ok())
            return r;
        if (!m_server->nodes.contains(k) || m_server->nodes.value(k).isDir)
            return Result(Error::NotFound, k);
        data = m_server->nodes.value(k).data;
        delay = m_server->chunkDelayMs;
    }
    qint64 done = 0;
    while (done < data.size()) {
        if (m_canceled)
            return Result(Error::Canceled);
        if (delay > 0)
            QThread::msleep(static_cast<unsigned long>(delay));
        const qint64 n = qMin<qint64>(64 * 1024, data.size() - done);
        if (sink->write(data.constData() + done, n) != n)
            return Result(Error::NoSpace, sink->errorString());
        done += n;
        if (progress)
            progress->update(done, data.size());
    }
    return Result();
}

Result FakeBackend::read(const QString &path, qint64 offset, qint64 length, QByteArray *out)
{
    QMutexLocker lock(&m_server->mutex);
    const QString k = key(path);
    Result r = begin(QStringLiteral("read:") + k);
    if (!r.ok())
        return r;
    if (!m_server->nodes.contains(k))
        return Result(Error::NotFound, k);
    *out = m_server->nodes.value(k).data.mid(static_cast<int>(offset), static_cast<int>(length));
    return r;
}

void FakeBackend::cancel()
{
    m_canceled = true;
}

void FakeBackend::resetCancel()
{
    m_canceled = false;
}

void FakeBackend::disconnect()
{
    QMutexLocker lock(&m_server->mutex);
    m_server->log << QStringLiteral("disconnect");
    m_connected = false;
    m_authenticated = false;
}

} // namespace Test
} // namespace NetVfs
