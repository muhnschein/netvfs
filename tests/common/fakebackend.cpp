// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakebackend.h"
#include "names.h"
#include "paths.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QIODevice>
#include <QtCore/QMutexLocker>
#include <QtCore/QThread>

#include <algorithm>
#include <memory>

namespace NetVfs {
namespace Test {

namespace {

constexpr int ChunkSize = 64 * 1024;
constexpr int MaxSymlinkHops = 40;

Result notFound(const QString &key)
{
    return Result(Error::NotFound, QStringLiteral("%1: not found").arg(key));
}

Result unsupported(const char *what)
{
    return Result(Error::Unsupported, QStringLiteral("%1 is switched off").arg(QLatin1String(what)));
}

bool isBelow(const QString &key, const QString &dir)
{
    return dir.isEmpty() ? !key.isEmpty() : key.startsWith(dir + QLatin1Char('/'));
}

void sleepChunk(int delayMs)
{
    if (delayMs > 0)
        QThread::msleep(static_cast<unsigned long>(delayMs));
}

} // namespace

// --- FakeServer --------------------------------------------------------------

FakeServer *FakeServer::instance()
{
    static FakeServer server;
    return &server;
}

Capabilities FakeServer::fullCapabilities()
{
    Capabilities caps;
    caps.flags = { Capability::Symlinks, Capability::Hardlinks, Capability::PosixModes,
                   Capability::SetModified, Capability::SetModifiedOnUpload, Capability::ReadHandles,
                   Capability::EfficientRanges, Capability::WriteResume, Capability::AtomicReplace,
                   Capability::NativeNoReplace, Capability::ServerCopy, Capability::ServerCopyRecursive,
                   Capability::RecursiveDelete, Capability::SpaceInfo, Capability::Checksums };
    caps.checksumAlgorithms = QStringList({ QStringLiteral("sha256"), QStringLiteral("md5") });
    caps.maxNameBytes = 255;
    caps.maxReadChunk = ChunkSize;
    caps.maxWriteChunk = ChunkSize;
    return caps;
}

void FakeServer::reset()
{
    identity = ServerIdentity();
    userName = QStringLiteral("user");
    secret = "secret";
    otp.clear();
    capabilities = fullCapabilities();
    freeBytes = 1LL << 40;
    totalBytes = 1LL << 41;
    connectResult = Result();
    failOps.clear();
    failUploadAfterBytes = -1;
    chunkDelayMs = 0;
    reportSizeMismatch = false;
    nodes.clear();
    log.clear();
    lastParams = ConnectionParams();
    m_nextLinkGroup = 1;
}

void FakeServer::addFile(const QString &path, const QByteArray &data, const QDateTime &modified, qint32 mode)
{
    addDir(Paths::parent(path));
    Node node;
    node.data = data;
    node.modified = modified;
    node.accessed = modified;
    node.mode = mode;
    nodes.insert(path, node);
}

void FakeServer::addDir(const QString &path, qint32 mode)
{
    QString current;
    for (const QString &part : path.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS)) {
        current = Paths::join(current, part);
        if (nodes.value(current).isDir())
            continue;
        Node node;
        node.type = EntryType::Directory;
        node.mode = mode;
        node.modified = QDateTime::currentDateTimeUtc();
        nodes.insert(current, node);
    }
}

void FakeServer::addSymlink(const QString &path, const QString &target)
{
    addDir(Paths::parent(path));
    Node node;
    node.type = EntryType::Symlink;
    node.target = target;
    node.mode = 0777;
    node.modified = QDateTime::currentDateTimeUtc();
    nodes.insert(path, node);
}

void FakeServer::addSpecial(const QString &path)
{
    addDir(Paths::parent(path));
    Node node;
    node.type = EntryType::Special;
    node.modified = QDateTime::currentDateTimeUtc();
    nodes.insert(path, node);
}

bool FakeServer::exists(const QString &path) const
{
    return nodes.contains(path);
}

QByteArray FakeServer::fileData(const QString &path) const
{
    return nodes.value(path).data;
}

FakeServer::Node FakeServer::node(const QString &path) const
{
    return nodes.value(path);
}

QStringList FakeServer::children(const QString &dir) const
{
    QStringList names;
    for (auto it = nodes.constBegin(); it != nodes.constEnd(); ++it) {
        if (!it.key().isEmpty() && Paths::parent(it.key()) == dir)
            names << Paths::fileName(it.key());
    }
    std::sort(names.begin(), names.end());
    return names;
}

void FakeServer::setData(const QString &path, const QByteArray &data)
{
    Node &target = nodes[path];
    target.data = data;
    if (target.linkGroup == 0)
        return;
    for (auto it = nodes.begin(); it != nodes.end(); ++it) {
        if (it->linkGroup == target.linkGroup)
            it->data = data;
    }
}

Result FakeServer::resolve(const QString &path, bool followLast, QString *resolved) const
{
    QStringList pending = path.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS);
    QString current;
    int hops = 0;
    while (!pending.isEmpty()) {
        const QString candidate = Paths::join(current, pending.takeFirst());
        const auto it = nodes.constFind(candidate);
        if (it == nodes.constEnd() || it->type != EntryType::Symlink || (pending.isEmpty() && !followLast)) {
            if (it == nodes.constEnd() && !pending.isEmpty())
                return notFound(candidate);
            current = candidate;
            continue;
        }
        if (++hops > MaxSymlinkHops)
            return Result(Error::ProtocolError, QStringLiteral("%1: too many levels of symbolic links").arg(path));
        const QStringList target = it->target.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS);
        if (!it->target.startsWith(QLatin1Char('/')) && !current.isEmpty()) {
            pending = current.split(QLatin1Char('/')) + target + pending;
        } else {
            pending = target + pending;
        }
        current.clear();
        // ".." in targets: collapse against what was walked so far.
        QStringList collapsed;
        for (const QString &part : pending) {
            if (part != QLatin1String("..") && part != QLatin1String("."))
                collapsed << part;
            else if (part == QLatin1String("..") && !collapsed.isEmpty())
                collapsed.removeLast();
        }
        pending = collapsed;
    }
    if (!current.isEmpty() && followLast) {
        const auto it = nodes.constFind(current);
        if (it == nodes.constEnd())
            return notFound(current);
    }
    *resolved = current;
    return Result::success();
}

// --- handles -----------------------------------------------------------------

class FakeBackend::Reader : public ReadHandle
{
public:
    Reader(FakeBackend *backend, const QString &key, const QByteArray &data)
        : m_backend(backend), m_key(key), m_data(data), m_generation(backend->m_generation) {}

    qint64 size() const override { return m_data.size(); }

    Result read(qint64 offset, qint64 maxBytes, QByteArray *out) override
    {
        int delay = 0;
        {
            QMutexLocker lock(&m_backend->m_server->mutex);
            if (const Result r = check(QStringLiteral("read:") + m_key); !r.ok())
                return r;
            delay = m_backend->m_server->chunkDelayMs;
        }
        if (offset < 0 || maxBytes < 0)
            return Result(Error::Internal, QStringLiteral("Invalid range"));
        sleepChunk(delay);
        if (m_backend->m_canceled)
            return Result(Error::Canceled);
        if (out)
            *out = offset >= m_data.size() ? QByteArray()
                                            : m_data.mid(static_cast<int>(offset), static_cast<int>(qMin<qint64>(maxBytes, m_data.size())));
        return Result::success();
    }

    void readAhead(qint64, qint64) override {}

    Result close() override
    {
        QMutexLocker lock(&m_backend->m_server->mutex);
        m_backend->m_server->log << QStringLiteral("close:") + m_key;
        if (m_closed)
            return Result(Error::Internal, QStringLiteral("Handle already closed"));
        m_closed = true;
        return m_backend->checkHandle(m_generation);
    }

private:
    Result check(const QString &op)
    {
        if (m_closed)
            return Result(Error::Internal, QStringLiteral("Handle is closed"));
        if (const Result r = m_backend->checkHandle(m_generation); !r.ok())
            return r;
        return m_backend->begin(op);
    }

    FakeBackend *m_backend;
    const QString m_key;
    const QByteArray m_data;
    const quint64 m_generation;
    bool m_closed = false;
};

class FakeBackend::Writer : public WriteHandle
{
public:
    Writer(FakeBackend *backend, const QString &key, const WriteOptions &options, qint64 start)
        : m_backend(backend), m_key(key), m_options(options), m_position(start),
          m_generation(backend->m_generation) {}

    Result write(const char *data, qint64 length) override
    {
        int delay = 0;
        {
            QMutexLocker lock(&m_backend->m_server->mutex);
            if (const Result r = check(QStringLiteral("write:") + m_key); !r.ok())
                return r;
            delay = m_backend->m_server->chunkDelayMs;
        }
        sleepChunk(delay);
        if (m_backend->m_canceled)
            return Result(Error::Canceled);
        QMutexLocker lock(&m_backend->m_server->mutex);
        FakeServer *server = m_backend->m_server;
        if (!server->nodes.contains(m_key))
            return notFound(m_key);
        server->setData(m_key, server->nodes.value(m_key).data + QByteArray(data, static_cast<int>(length)));
        m_position += length;
        m_written += length;
        if (server->failUploadAfterBytes >= 0 && m_written >= server->failUploadAfterBytes)
            return Result(Error::ConnectionLost, QStringLiteral("connection dropped"));
        return Result::success();
    }

    qint64 position() const override { return m_position; }

    Result commit() override
    {
        QMutexLocker lock(&m_backend->m_server->mutex);
        if (const Result r = check(QStringLiteral("commit:") + m_key); !r.ok())
            return r;
        m_done = true;
        m_backend->finishWrite(m_key, m_options);
        return Result::success();
    }

    void abort() override
    {
        QMutexLocker lock(&m_backend->m_server->mutex);
        m_backend->m_server->log << QStringLiteral("abort:") + m_key;
        m_done = true;
    }

private:
    Result check(const QString &op)
    {
        if (m_done)
            return Result(Error::Internal, QStringLiteral("Handle is closed"));
        if (const Result r = m_backend->checkHandle(m_generation); !r.ok())
            return r;
        return m_backend->begin(op);
    }

    FakeBackend *m_backend;
    const QString m_key;
    const WriteOptions m_options;
    qint64 m_position;
    qint64 m_written = 0;
    const quint64 m_generation;
    bool m_done = false;
};

// --- FakeBackend -------------------------------------------------------------

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

Result FakeBackend::key(const QString &path, QString *out)
{
    QString normalized;
    const Result r = Paths::normalize(path, &normalized);
    if (!r.ok())
        return Result(Error::InvalidName, r.message());
    while (normalized.startsWith(QLatin1Char('/')))
        normalized.remove(0, 1);
    *out = normalized;
    return r;
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

bool FakeBackend::has(Capability c) const
{
    return m_server->capabilities.has(c);
}

Result FakeBackend::checkHandle(quint64 generation) const
{
    if (generation != m_generation || !m_connected)
        return Result(Error::ConnectionLost, QStringLiteral("The connection was closed"));
    return Result::success();
}

Entry FakeBackend::entryFor(const QString &key, const FakeServer::Node &node, bool resolveTarget) const
{
    Entry e;
    e.name = Paths::fileName(key);
    e.type = key.isEmpty() ? EntryType::Directory : node.type;
    e.mode = key.isEmpty() ? FakeServer::DefaultDirMode : node.mode;
    e.modified = node.modified;
    e.accessed = node.accessed;
    switch (e.type) {
    case EntryType::File:
        e.size = node.data.size();
        break;
    case EntryType::Symlink:
        e.size = node.target.toUtf8().size();
        break;
    case EntryType::Special:
        e.size = 0;
        break;
    default:
        break;
    }
    if (e.type == EntryType::Symlink && resolveTarget) {
        QString resolved;
        if (m_server->resolve(key, true, &resolved).ok())
            e.targetType = resolved.isEmpty() ? EntryType::Directory : m_server->nodes.value(resolved).type;
        else
            e.flags |= EntryFlag::TargetUnknown;
    }
    if (Names::hasEscapes(e.name))
        e.flags |= EntryFlag::NameNotUtf8;
    return e;
}

Result FakeBackend::connect(const ConnectionParams &params, ServerIdentity *seen)
{
    QMutexLocker lock(&m_server->mutex);
    m_server->lastParams = params;
    m_params = params;
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

Result FakeBackend::authenticate(const Credentials &credentials, AuthPrompter *prompter)
{
    QByteArray otp;
    {
        QMutexLocker lock(&m_server->mutex);
        const Result r = begin(QStringLiteral("authenticate"), false);
        if (!r.ok())
            return r;
        if (!m_connected)
            return Result(Error::Internal, QStringLiteral("not connected"));
        if (credentials.userName != m_server->userName || credentials.secret != m_server->secret)
            return Result(Error::AuthFailed, QStringLiteral("wrong user name or secret"));
        otp = m_server->otp;
    }
    if (!otp.isEmpty()) {
        // XC-15: a second factor, only with a prompter.
        QVector<QByteArray> answers;
        AuthPrompt prompt;
        prompt.text = QStringLiteral("Verification code: ");
        const bool answered = prompter
            && prompter->answer(QStringLiteral("fake"), QString(), QVector<AuthPrompt>({ prompt }), &answers);
        const bool accepted = answered && answers.size() == 1 && answers.first() == otp;
        for (QByteArray &answer : answers)
            answer.fill('\0');
        if (m_canceled)
            return Result(Error::Canceled);
        if (!accepted)
            return Result(Error::AuthFailed, QStringLiteral("wrong verification code"));
    }
    m_authenticated = true;
    return Result::success();
}

Capabilities FakeBackend::capabilities() const
{
    QMutexLocker lock(&m_server->mutex);
    return m_server->capabilities;
}

Result FakeBackend::stat(const QString &path, Entry *out)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("stat:") + k);
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, true, &resolved);
    if (!r.ok())
        return r;
    if (!resolved.isEmpty() && !m_server->nodes.contains(resolved))
        return notFound(k);
    Entry e = entryFor(resolved, m_server->nodes.value(resolved), false);
    e.name = Paths::fileName(k);
    if (m_server->reportSizeMismatch && k.endsWith(QLatin1String(".part")))
        e.size += 1;
    if (out)
        *out = e;
    return r;
}

Result FakeBackend::lstat(const QString &path, Entry *out)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("lstat:") + k);
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, false, &resolved);
    if (!r.ok())
        return r;
    if (!resolved.isEmpty() && !m_server->nodes.contains(resolved))
        return notFound(k);
    if (out)
        *out = entryFor(resolved, m_server->nodes.value(resolved), true);
    return r;
}

Result FakeBackend::list(const QString &dir, ListSink *sink, const ListOptions &options)
{
    QVector<Entry> entries;
    int delay = 0;
    {
        QMutexLocker lock(&m_server->mutex);
        QString k;
        Result r = key(dir, &k);
        if (r.ok())
            r = begin(QStringLiteral("list:") + k);
        QString resolved;
        if (r.ok())
            r = m_server->resolve(k, true, &resolved);
        if (!r.ok())
            return r;
        if (!resolved.isEmpty() && !m_server->nodes.contains(resolved))
            return notFound(k);
        if (!resolved.isEmpty() && !m_server->nodes.value(resolved).isDir())
            return Result(Error::NotADirectory, QStringLiteral("%1 is not a folder").arg(k));
        for (const QString &name : m_server->children(resolved)) {
            const QString child = Paths::join(resolved, name);
            entries << entryFor(child, m_server->nodes.value(child), options.resolveSymlinkTypes);
        }
        delay = m_server->chunkDelayMs;
    }
    const int batchSize = qMax(1, options.batchSize);
    for (int start = 0; start < entries.size(); start += batchSize) {
        sleepChunk(delay);
        if (m_canceled)
            return Result(Error::Canceled);
        if (!sink->entries(entries.mid(start, batchSize)))
            return Result(Error::Canceled, QStringLiteral("The listing was stopped"));
    }
    return Result::success();
}

Result FakeBackend::makeDir(const QString &path, bool exclusive)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("makeDir:") + k);
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, false, &resolved);
    if (!r.ok())
        return r;
    if (resolved.isEmpty() || m_server->nodes.contains(resolved)) {
        if (exclusive)
            return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(k));
        QString target;
        if (m_server->resolve(resolved, true, &target).ok()
                && (target.isEmpty() || m_server->nodes.value(target).isDir()))
            return Result::success();
        return Result(Error::AlreadyExists, QStringLiteral("%1 exists and is not a folder").arg(k));
    }
    const QString parent = Paths::parent(resolved);
    if (!parent.isEmpty() && !m_server->nodes.contains(parent))
        return notFound(parent);
    if (!parent.isEmpty() && !m_server->nodes.value(parent).isDir())
        return Result(Error::NotADirectory, QStringLiteral("%1 is not a folder").arg(parent));
    // Like SFTP: the "dir_mode" option (octal), else the server default.
    bool octal = false;
    const int mode = m_params.option(QStringLiteral("dir_mode")).toInt(&octal, 8);
    m_server->addDir(resolved, octal ? (mode & 07777) : FakeServer::DefaultDirMode);
    return r;
}

Result FakeBackend::removeFile(const QString &path)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("removeFile:") + k);
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, false, &resolved);
    if (!r.ok())
        return r;
    if (resolved.isEmpty() || m_server->nodes.value(resolved).isDir())
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(k));
    if (!m_server->nodes.contains(resolved))
        return notFound(k);
    m_server->nodes.remove(resolved);
    return r;
}

Result FakeBackend::removeDir(const QString &path)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("removeDir:") + k);
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, false, &resolved);
    if (!r.ok())
        return r;
    if (resolved.isEmpty())
        return Result(Error::PermissionDenied, QStringLiteral("The root folder cannot be removed"));
    if (!m_server->nodes.contains(resolved))
        return notFound(k);
    if (!m_server->nodes.value(resolved).isDir())
        return Result(Error::NotADirectory, QStringLiteral("%1 is not a folder").arg(k));
    if (!m_server->children(resolved).isEmpty())
        return Result(Error::DirectoryNotEmpty, QStringLiteral("%1 is not empty").arg(k));
    m_server->nodes.remove(resolved);
    return r;
}

Result FakeBackend::removeTreeNative(const QString &path)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("removeTreeNative:") + k);
    if (r.ok() && !has(Capability::RecursiveDelete))
        r = unsupported("Recursive delete");
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, false, &resolved);
    if (!r.ok())
        return r;
    if (resolved.isEmpty())
        return Result(Error::PermissionDenied, QStringLiteral("The root folder cannot be removed"));
    if (!m_server->nodes.contains(resolved))
        return notFound(k);
    for (const QString &existing : m_server->nodes.keys()) {
        if (existing == resolved || isBelow(existing, resolved))
            m_server->nodes.remove(existing);
    }
    return r;
}

Result FakeBackend::rename(const QString &from, const QString &to, RenameMode mode)
{
    QMutexLocker lock(&m_server->mutex);
    QString f;
    QString t;
    Result r = key(from, &f);
    if (r.ok())
        r = key(to, &t);
    if (r.ok()) {
        const QString suffix = mode == RenameMode::Replace ? QStringLiteral(":replace") : QString();
        r = begin(QStringLiteral("rename:") + f + QStringLiteral("->") + t + suffix);
    }
    QString source;
    QString target;
    if (r.ok())
        r = m_server->resolve(f, false, &source);
    if (r.ok())
        r = m_server->resolve(t, false, &target);
    if (!r.ok())
        return r;
    if (source.isEmpty() || !m_server->nodes.contains(source))
        return source.isEmpty() ? Result(Error::PermissionDenied, QStringLiteral("Cannot move the root")) : notFound(f);
    if (source == target)
        return r;
    if (isBelow(target, source))
        return Result(Error::InvalidName, QStringLiteral("Cannot move %1 into itself").arg(f));
    const QString parent = Paths::parent(target);
    if (!parent.isEmpty() && !m_server->nodes.value(parent).isDir())
        return m_server->nodes.contains(parent) ? Result(Error::NotADirectory, parent) : notFound(parent);
    if (target.isEmpty() || m_server->nodes.contains(target)) {
        // XC-10: replacing a folder is AlreadyExists in both modes.
        if (target.isEmpty() || m_server->nodes.value(target).isDir() || mode == RenameMode::NoReplace)
            return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(t));
        if (m_server->nodes.value(source).isDir())
            return Result(Error::NotADirectory, QStringLiteral("%1 is not a folder").arg(t));
        m_server->nodes.remove(target);
    }
    for (const QString &existing : m_server->nodes.keys()) {
        if (isBelow(existing, source))
            m_server->nodes.insert(target + existing.mid(source.size()), m_server->nodes.take(existing));
    }
    m_server->nodes.insert(target, m_server->nodes.take(source));
    return r;
}

Result FakeBackend::setAttributes(const QString &path, const AttributeChanges &changes)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("setAttributes:") + k);
    // XC-11: every field is checked before anything changes.
    if (r.ok() && changes.mode >= 0 && !has(Capability::PosixModes))
        r = unsupported("Changing modes");
    if (r.ok() && (changes.modified.isValid() || changes.accessed.isValid()) && !has(Capability::SetModified))
        r = unsupported("Changing times");
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, true, &resolved);
    if (!r.ok())
        return r;
    if (resolved.isEmpty())
        return Result(Error::PermissionDenied, QStringLiteral("The root folder cannot be changed"));
    if (!m_server->nodes.contains(resolved))
        return notFound(k);
    FakeServer::Node &node = m_server->nodes[resolved];
    if (changes.mode >= 0)
        node.mode = changes.mode & 07777;
    if (changes.modified.isValid())
        node.modified = changes.modified.toUTC();
    if (changes.accessed.isValid())
        node.accessed = changes.accessed.toUTC();
    return r;
}

Result FakeBackend::readLink(const QString &path, QString *target)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("readLink:") + k);
    if (r.ok() && !has(Capability::Symlinks))
        r = unsupported("Reading links");
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, false, &resolved);
    if (!r.ok())
        return r;
    if (!m_server->nodes.contains(resolved))
        return notFound(k);
    if (m_server->nodes.value(resolved).type != EntryType::Symlink)
        return Result(Error::ProtocolError, QStringLiteral("%1 is not a symbolic link").arg(k));
    if (target)
        *target = m_server->nodes.value(resolved).target;
    return r;
}

Result FakeBackend::makeSymlink(const QString &target, const QString &linkPath)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(linkPath, &k);
    if (r.ok())
        r = begin(QStringLiteral("makeSymlink:") + k + QStringLiteral("->") + target);
    if (r.ok() && !has(Capability::Symlinks))
        r = unsupported("Creating symbolic links");
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, false, &resolved);
    if (!r.ok())
        return r;
    if (resolved.isEmpty() || m_server->nodes.contains(resolved))
        return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(k));
    const QString parent = Paths::parent(resolved);
    if (!parent.isEmpty() && !m_server->nodes.value(parent).isDir())
        return notFound(parent);
    m_server->addSymlink(resolved, target);
    return r;
}

Result FakeBackend::makeHardlink(const QString &existing, const QString &newPath)
{
    QMutexLocker lock(&m_server->mutex);
    QString e;
    QString n;
    Result r = key(existing, &e);
    if (r.ok())
        r = key(newPath, &n);
    if (r.ok())
        r = begin(QStringLiteral("makeHardlink:") + e + QStringLiteral("->") + n);
    if (r.ok() && !has(Capability::Hardlinks))
        r = unsupported("Creating hard links");
    QString source;
    QString target;
    if (r.ok())
        r = m_server->resolve(e, false, &source);
    if (r.ok())
        r = m_server->resolve(n, false, &target);
    if (!r.ok())
        return r;
    if (!m_server->nodes.contains(source))
        return notFound(e);
    if (m_server->nodes.value(source).isDir())
        return Result(Error::PermissionDenied, QStringLiteral("Folders cannot be hard linked"));
    if (target.isEmpty() || m_server->nodes.contains(target))
        return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(n));
    const QString parent = Paths::parent(target);
    if (!parent.isEmpty() && !m_server->nodes.value(parent).isDir())
        return notFound(parent);
    FakeServer::Node &node = m_server->nodes[source];
    if (node.linkGroup == 0)
        node.linkGroup = m_server->m_nextLinkGroup++;
    m_server->nodes.insert(target, node);
    return r;
}

Result FakeBackend::openRead(const QString &path, ReadHandle **out)
{
    *out = nullptr;
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("openRead:") + k);
    if (r.ok() && !has(Capability::ReadHandles))
        r = unsupported("Random access reading");
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, true, &resolved);
    if (!r.ok())
        return r;
    if (!resolved.isEmpty() && !m_server->nodes.contains(resolved))
        return notFound(k);
    if (resolved.isEmpty() || m_server->nodes.value(resolved).isDir())
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(k));
    *out = new Reader(this, k, m_server->nodes.value(resolved).data);
    return r;
}

Result FakeBackend::prepareWrite(const QString &key, const WriteOptions &options, QString *resolved)
{
    Result r = m_server->resolve(key, true, resolved);
    if (r.error() == Error::NotFound)
        r = m_server->resolve(key, false, resolved);   // a new file
    if (!r.ok())
        return r;
    if (m_server->nodes.value(*resolved).type == EntryType::Symlink)
        return notFound(key);                           // a dangling link
    const QString parent = Paths::parent(*resolved);
    if (!parent.isEmpty() && !m_server->nodes.value(parent).isDir())
        return m_server->nodes.contains(parent) ? Result(Error::NotADirectory, parent) : notFound(parent);
    const bool exists = resolved->isEmpty() || m_server->nodes.contains(*resolved);
    if (exists && (resolved->isEmpty() || m_server->nodes.value(*resolved).isDir()))
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(key));
    switch (options.disposition) {
    case WriteOptions::CreateNew:
        if (exists)
            return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(key));
        break;
    case WriteOptions::Resume:
        if (!has(Capability::WriteResume))
            return unsupported("Resuming writes");
        if (!exists)
            return notFound(key);
        if (m_server->nodes.value(*resolved).data.size() != options.resumeOffset) {
            return Result(Error::ProtocolError, QStringLiteral("Cannot resume at %1: the file has %2 bytes")
                                                    .arg(options.resumeOffset)
                                                    .arg(m_server->nodes.value(*resolved).data.size()));
        }
        return Result::success();
    case WriteOptions::Truncate:
        break;
    }
    if (exists) {
        m_server->setData(*resolved, QByteArray());
    } else {
        FakeServer::Node node;
        node.mode = options.createMode >= 0 ? (options.createMode & 07777) : FakeServer::DefaultFileMode;
        m_server->nodes.insert(*resolved, node);
    }
    m_server->nodes[*resolved].modified = QDateTime::currentDateTimeUtc();
    return Result::success();
}

void FakeBackend::finishWrite(const QString &resolved, const WriteOptions &options)
{
    if (!m_server->nodes.contains(resolved))
        return;
    FakeServer::Node &node = m_server->nodes[resolved];
    const bool applyTime = options.modified.isValid()
        && (has(Capability::SetModified) || has(Capability::SetModifiedOnUpload));
    node.modified = applyTime ? options.modified.toUTC() : QDateTime::currentDateTimeUtc();
}

Result FakeBackend::openWrite(const QString &path, const WriteOptions &options, WriteHandle **out)
{
    *out = nullptr;
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("openWrite:") + k);
    QString resolved;
    if (r.ok())
        r = prepareWrite(k, options, &resolved);
    if (!r.ok())
        return r;
    const qint64 start = options.disposition == WriteOptions::Resume ? options.resumeOffset : 0;
    *out = new Writer(this, resolved, options, start);
    return r;
}

Result FakeBackend::upload(QIODevice *source, const QString &path, const UploadOptions &options, Progress *progress)
{
    QString resolved;
    int delay = 0;
    qint64 failAfter = -1;
    {
        QMutexLocker lock(&m_server->mutex);
        QString k;
        Result r = key(path, &k);
        if (r.ok())
            r = begin(QStringLiteral("upload:") + k);
        if (r.ok())
            r = prepareWrite(k, options.write, &resolved);
        if (!r.ok())
            return r;
        delay = m_server->chunkDelayMs;
        failAfter = m_server->failUploadAfterBytes;
    }
    const qint64 base = options.write.disposition == WriteOptions::Resume ? options.write.resumeOffset : 0;
    const qint64 total = base + source->size();
    qint64 done = 0;
    for (;;) {
        if (m_canceled || (progress && progress->canceled()))
            return Result(Error::Canceled);
        const QByteArray chunk = source->read(ChunkSize);
        if (chunk.isEmpty())
            break;
        sleepChunk(delay);
        QMutexLocker lock(&m_server->mutex);
        if (!m_server->nodes.contains(resolved))
            return notFound(resolved);
        m_server->setData(resolved, m_server->nodes.value(resolved).data + chunk);
        done += chunk.size();
        if (failAfter >= 0 && done >= failAfter)
            return Result(Error::ConnectionLost, QStringLiteral("connection dropped"));
        if (progress)
            progress->update(base + done, total);
    }
    QMutexLocker lock(&m_server->mutex);
    finishWrite(resolved, options.write);
    return Result();
}

Result FakeBackend::download(const QString &path, QIODevice *sink, const DownloadOptions &options, Progress *progress)
{
    QByteArray data;
    int delay = 0;
    {
        QMutexLocker lock(&m_server->mutex);
        QString k;
        Result r = key(path, &k);
        if (r.ok())
            r = begin(QStringLiteral("download:") + k);
        QString resolved;
        if (r.ok())
            r = m_server->resolve(k, true, &resolved);
        if (!r.ok())
            return r;
        if (!resolved.isEmpty() && !m_server->nodes.contains(resolved))
            return notFound(k);
        if (resolved.isEmpty() || m_server->nodes.value(resolved).isDir())
            return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(k));
        if (options.offset < 0 || options.length < -1)
            return Result(Error::Internal, QStringLiteral("Invalid range"));
        data = m_server->nodes.value(resolved).data;
        delay = m_server->chunkDelayMs;
    }
    const qint64 start = qMin<qint64>(options.offset, data.size());
    const qint64 end = options.length < 0 ? data.size() : qMin<qint64>(data.size(), start + options.length);
    qint64 done = start;
    while (done < end) {
        if (m_canceled || (progress && progress->canceled()))
            return Result(Error::Canceled);
        sleepChunk(delay);
        const qint64 n = qMin<qint64>(ChunkSize, end - done);
        if (sink->write(data.constData() + done, n) != n)
            return Result(Error::NoSpace, sink->errorString());
        done += n;
        if (progress)
            progress->update(done - start, end - start);
    }
    return Result();
}

Result FakeBackend::copy(const QString &from, const QString &to, const CopyOptions &options)
{
    QMutexLocker lock(&m_server->mutex);
    QString f;
    QString t;
    Result r = key(from, &f);
    if (r.ok())
        r = key(to, &t);
    if (r.ok())
        r = begin(QStringLiteral("copy:") + f + QStringLiteral("->") + t);
    if (r.ok() && !has(Capability::ServerCopy))
        r = unsupported("Server-side copy");
    QString source;
    QString target;
    if (r.ok())
        r = m_server->resolve(f, true, &source);
    if (r.ok())
        r = m_server->resolve(t, false, &target);
    if (!r.ok())
        return r;
    if (!source.isEmpty() && !m_server->nodes.contains(source))
        return notFound(f);
    const bool folder = source.isEmpty() || m_server->nodes.value(source).isDir();
    if (folder && !options.recursive)
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(f));
    if (folder && !has(Capability::ServerCopyRecursive))
        return unsupported("Recursive server-side copy");
    if (folder && isBelow(target, source))
        return Result(Error::InvalidName, QStringLiteral("Cannot copy %1 into itself").arg(f));
    const QString parent = Paths::parent(target);
    if (!parent.isEmpty() && !m_server->nodes.value(parent).isDir())
        return notFound(parent);
    if (target.isEmpty() || m_server->nodes.contains(target)) {
        if (target.isEmpty() || m_server->nodes.value(target).isDir() || options.mode == RenameMode::NoReplace)
            return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(t));
        m_server->nodes.remove(target);
    }
    QHash<QString, FakeServer::Node> copies;
    for (auto it = m_server->nodes.constBegin(); it != m_server->nodes.constEnd(); ++it) {
        if (it.key() == source || (folder && isBelow(it.key(), source))) {
            FakeServer::Node node = it.value();
            node.linkGroup = 0;
            copies.insert(target + it.key().mid(source.size()), node);
        }
    }
    for (auto it = copies.constBegin(); it != copies.constEnd(); ++it)
        m_server->nodes.insert(it.key(), it.value());
    return r;
}

Result FakeBackend::checksum(const QString &path, const QString &algorithm, QByteArray *digest)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(path, &k);
    if (r.ok())
        r = begin(QStringLiteral("checksum:") + k);
    if (r.ok() && (!has(Capability::Checksums) || !m_server->capabilities.checksumAlgorithms.contains(algorithm)))
        r = unsupported("This checksum");
    QString resolved;
    if (r.ok())
        r = m_server->resolve(k, true, &resolved);
    if (!r.ok())
        return r;
    if (!resolved.isEmpty() && !m_server->nodes.contains(resolved))
        return notFound(k);
    if (resolved.isEmpty() || m_server->nodes.value(resolved).isDir())
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(k));
    QCryptographicHash::Algorithm method = QCryptographicHash::Sha256;
    if (algorithm == QLatin1String("md5"))
        method = QCryptographicHash::Md5;
    else if (algorithm == QLatin1String("sha1"))
        method = QCryptographicHash::Sha1;
    if (digest)
        *digest = QCryptographicHash::hash(m_server->nodes.value(resolved).data, method);
    return r;
}

Result FakeBackend::spaceInfo(const QString &dir, SpaceInfo *out)
{
    QMutexLocker lock(&m_server->mutex);
    QString k;
    Result r = key(dir, &k);
    if (r.ok())
        r = begin(QStringLiteral("spaceInfo:") + k);
    if (r.ok() && !has(Capability::SpaceInfo))
        r = unsupported("Free space information");
    if (!r.ok())
        return r;
    if (out) {
        out->free = m_server->freeBytes;
        out->total = m_server->totalBytes;
        out->used = (out->free >= 0 && out->total >= 0) ? out->total - out->free : -1;
    }
    return r;
}

Result FakeBackend::keepAlive()
{
    QMutexLocker lock(&m_server->mutex);
    const Result r = begin(QStringLiteral("keepAlive"));
    if (!r.ok())
        return r;
    if (!m_connected)
        return Result(Error::ConnectionLost, QStringLiteral("Not connected"));
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
    ++m_generation;
}

} // namespace Test
} // namespace NetVfs
