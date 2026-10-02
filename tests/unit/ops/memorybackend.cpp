// SPDX-License-Identifier: LGPL-2.1-or-later
#include "memorybackend.h"
#include "paths.h"

#include <QtCore/QIODevice>
#include <QtCore/QThread>

using namespace NetVfs;

namespace {

constexpr int MaxLinkHops = 40;
constexpr quint64 FnvOffset = 1469598103934665603ULL;
constexpr quint64 FnvPrime = 1099511628211ULL;

QString keyOf(const QString &normalized)
{
    QString key = normalized;
    while (key.startsWith(QLatin1Char('/')))
        key.remove(0, 1);
    return key;
}

QString joinKey(const QString &dir, const QString &name)
{
    return dir.isEmpty() ? name : dir + QLatin1Char('/') + name;
}

QString parentKey(const QString &key)
{
    const int slash = key.lastIndexOf(QLatin1Char('/'));
    return slash < 0 ? QString() : key.left(slash);
}

QString nameOf(const QString &key)
{
    return key.mid(key.lastIndexOf(QLatin1Char('/')) + 1);
}

// Applies `target` (absolute or relative to `base`) to `base`; ".." above the root is clamped.
QString applyTarget(const QString &base, const QString &target)
{
    QStringList parts = target.startsWith(QLatin1Char('/')) ? QStringList()
                                                             : base.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS);
    for (const QString &part : target.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS)) {
        if (part == QLatin1String("..")) {
            if (!parts.isEmpty())
                parts.removeLast();
        } else if (part != QLatin1String(".")) {
            parts.append(part);
        }
    }
    return parts.join(QLatin1Char('/'));
}

} // namespace

MemoryBackend::MemoryBackend()
{
    Node root;
    root.type = EntryType::Directory;
    m_nodes[QString()] = root;
}

quint64 MemoryBackend::hashOf(const QByteArray &data)
{
    quint64 hash = FnvOffset;
    for (const char c : data)
        hash = (hash ^ uchar(c)) * FnvPrime;
    return hash;
}

char MemoryBackend::patternByte(qint64 offset)
{
    return char((offset * 31 + 7) & 0xFF);
}

quint64 MemoryBackend::patternHash(qint64 size)
{
    quint64 hash = FnvOffset;
    for (qint64 i = 0; i < size; ++i)
        hash = (hash ^ uchar(patternByte(i))) * FnvPrime;
    return hash;
}

void MemoryBackend::addDir(const QString &path)
{
    Node node;
    node.type = EntryType::Directory;
    m_nodes[keyOf(path)] = node;
}

void MemoryBackend::addFile(const QString &path, const QByteArray &data)
{
    Node node;
    node.data = data;
    node.size = data.size();
    node.hash = hashOf(data);
    node.modified = QDateTime(QDate(2020, 1, 2), QTime(3, 4, 5), Qt::UTC);
    m_nodes[keyOf(path)] = node;
}

void MemoryBackend::addGenerated(const QString &path, qint64 size)
{
    Node node;
    node.size = size;
    node.generated = size;
    node.modified = QDateTime(QDate(2020, 1, 2), QTime(3, 4, 5), Qt::UTC);
    m_nodes[keyOf(path)] = node;
}

void MemoryBackend::addSymlink(const QString &path, const QString &target)
{
    Node node;
    node.type = EntryType::Symlink;
    node.target = target;
    m_nodes[keyOf(path)] = node;
}

bool MemoryBackend::exists(const QString &path) const
{
    return m_nodes.count(keyOf(path)) > 0;
}

MemoryBackend::Node MemoryBackend::node(const QString &path) const
{
    const auto it = m_nodes.find(keyOf(path));
    return it == m_nodes.end() ? Node() : it->second;
}

QByteArray MemoryBackend::fileData(const QString &path) const
{
    return node(path).data;
}

QStringList MemoryBackend::paths() const
{
    QStringList keys;
    for (const auto &item : m_nodes) {
        if (!item.first.isEmpty())
            keys.append(item.first);
    }
    return keys;
}

Result MemoryBackend::begin(const char *op, const QString &path, QString *key)
{
    QString normalized;
    Result r = Paths::normalize(path, &normalized);
    if (!r.ok())
        return r;
    *key = keyOf(normalized);
    log << QLatin1String(op) + QLatin1Char(' ') + *key;
    if (m_canceled)
        return Result(Error::Canceled);
    if (intercept)
        return intercept(QLatin1String(op), *key);
    return Result::success();
}

// Resolves symbolic links in every component, and in the last one when
// `followLast`. The result may name a missing last component.
Result MemoryBackend::resolve(const QString &key, bool followLast, QString *out, int hops) const
{
    const QStringList parts = key.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS);
    QString current;
    for (int i = 0; i < parts.size(); ++i) {
        const bool last = i == parts.size() - 1;
        const QString candidate = joinKey(current, parts.at(i));
        const auto it = m_nodes.find(candidate);
        if (it == m_nodes.end()) {
            if (!last)
                return Result(Error::NotFound, candidate);
            current = candidate;
            break;
        }
        const Node &found = it->second;
        if (found.type == EntryType::Symlink && (!last || followLast)) {
            if (hops >= MaxLinkHops)
                return Result(Error::ProtocolError, QStringLiteral("too many levels of symbolic links"));
            const QString rest = parts.mid(i + 1).join(QLatin1Char('/'));
            return resolve(joinKey(applyTarget(current, found.target), rest), followLast, out, hops + 1);
        }
        if (!last && found.type != EntryType::Directory)
            return Result(Error::NotADirectory, candidate);
        current = candidate;
    }
    *out = current;
    return Result::success();
}

Result MemoryBackend::find(const char *op, const QString &path, bool followLast, QString *key, Node **node)
{
    QString raw;
    Result r = begin(op, path, &raw);
    if (!r.ok())
        return r;
    r = resolve(raw, followLast, key);
    if (!r.ok())
        return r;
    const auto it = m_nodes.find(*key);
    if (it == m_nodes.end())
        return Result(Error::NotFound, *key);
    *node = &it->second;
    return Result::success();
}

Entry MemoryBackend::entryFor(const QString &name, const Node &node) const
{
    Entry entry;
    entry.name = name;
    entry.type = node.type;
    entry.size = node.type == EntryType::File ? node.size : -1;
    entry.modified = node.modified;
    return entry;
}

Result MemoryBackend::connect(const ConnectionParams &, ServerIdentity *)
{
    return Result::success();
}

Result MemoryBackend::authenticate(const Credentials &, AuthPrompter *)
{
    return Result::success();
}

Result MemoryBackend::stat(const QString &path, Entry *out)
{
    QString key;
    Node *found = nullptr;
    const Result r = find("stat", path, true, &key, &found);
    if (r.ok())
        *out = entryFor(nameOf(key), *found);
    return r;
}

Result MemoryBackend::lstat(const QString &path, Entry *out)
{
    QString key;
    Node *found = nullptr;
    const Result r = find("lstat", path, false, &key, &found);
    if (!r.ok())
        return r;
    *out = entryFor(nameOf(key), *found);
    QString targetKey;
    if (found->type == EntryType::Symlink && resolve(key, true, &targetKey).ok()) {
        const auto target = m_nodes.find(targetKey);
        if (target != m_nodes.end())
            out->targetType = target->second.type;
    }
    return r;
}

Result MemoryBackend::list(const QString &dir, ListSink *sink, const ListOptions &options)
{
    QString raw;
    Result r = begin("list", dir, &raw);
    if (!r.ok())
        return r;
    QString key;
    r = resolve(raw, true, &key);
    if (!r.ok())
        return r;
    const auto self = m_nodes.find(key);
    if (self == m_nodes.end())
        return Result(Error::NotFound, key);
    if (self->second.type != EntryType::Directory)
        return Result(Error::NotADirectory, key);

    const QString prefix = key.isEmpty() ? QString() : key + QLatin1Char('/');
    QVector<Entry> batch;
    for (auto it = m_nodes.lower_bound(prefix); it != m_nodes.end() && it->first.startsWith(prefix); ++it) {
        if (it->first.isEmpty() || it->first.indexOf(QLatin1Char('/'), prefix.size()) >= 0)
            continue;
        Entry entry = entryFor(it->first.mid(prefix.size()), it->second);
        if (it->second.type == EntryType::Symlink) {
            QString targetKey;
            const bool resolved = resolve(it->first, true, &targetKey).ok() && m_nodes.count(targetKey) > 0;
            if (resolved && (options.resolveSymlinkTypes || listSymlinksAsTargets))
                entry.targetType = m_nodes.at(targetKey).type;
            if (resolved && listSymlinksAsTargets)
                entry.type = entry.targetType;
        }
        batch.append(entry);
        if (batch.size() >= options.batchSize) {
            if (m_canceled)
                return Result(Error::Canceled);
            if (!sink->entries(batch))
                return Result(Error::Canceled);
            batch.clear();
        }
    }
    if (!batch.isEmpty() && !sink->entries(batch))
        return Result(Error::Canceled);
    return Result::success();
}

Result MemoryBackend::makeDir(const QString &path, bool exclusive)
{
    QString raw;
    Result r = begin("makeDir", path, &raw);
    if (!r.ok())
        return r;
    QString key;
    r = resolve(raw, false, &key);
    if (!r.ok())
        return r;
    const auto existing = m_nodes.find(key);
    if (existing != m_nodes.end()) {
        if (exclusive || existing->second.type != EntryType::Directory)
            return Result(Error::AlreadyExists, key);
        return Result::success();
    }
    const auto parent = m_nodes.find(parentKey(key));
    if (parent == m_nodes.end() || parent->second.type != EntryType::Directory)
        return Result(Error::NotFound, parentKey(key));
    addDir(key);
    return Result::success();
}

Result MemoryBackend::removeFile(const QString &path)
{
    QString raw;
    Result r = begin("removeFile", path, &raw);
    if (!r.ok())
        return r;
    QString key;
    r = resolve(raw, false, &key);
    if (!r.ok())
        return r;
    const auto it = m_nodes.find(key);
    if (it == m_nodes.end() || key.isEmpty())
        return Result(Error::NotFound, key);
    if (it->second.type == EntryType::Directory)
        return Result(Error::IsADirectory, key);
    m_nodes.erase(it);
    return Result::success();
}

bool MemoryBackend::isEmptyDir(const QString &key) const
{
    const QString prefix = key + QLatin1Char('/');
    const auto it = m_nodes.lower_bound(prefix);
    return it == m_nodes.end() || !it->first.startsWith(prefix);
}

Result MemoryBackend::removeDir(const QString &path)
{
    QString raw;
    Result r = begin("removeDir", path, &raw);
    if (!r.ok())
        return r;
    QString key;
    r = resolve(raw, false, &key);
    if (!r.ok())
        return r;
    const auto it = m_nodes.find(key);
    if (it == m_nodes.end() || key.isEmpty())
        return Result(Error::NotFound, key);
    if (it->second.type != EntryType::Directory)
        return Result(Error::NotADirectory, key);
    if (!isEmptyDir(key))
        return Result(Error::DirectoryNotEmpty, key);
    m_nodes.erase(it);
    return Result::success();
}

Result MemoryBackend::removeTreeNative(const QString &path)
{
    if (!caps.has(Capability::RecursiveDelete))
        return Backend::removeTreeNative(path);
    QString raw;
    Result r = begin("removeTreeNative", path, &raw);
    if (!r.ok())
        return r;
    QString key;
    r = resolve(raw, false, &key);
    if (!r.ok())
        return r;
    const QString prefix = key + QLatin1Char('/');
    for (auto it = m_nodes.lower_bound(prefix); it != m_nodes.end() && it->first.startsWith(prefix);)
        it = m_nodes.erase(it);
    m_nodes.erase(key);
    return Result::success();
}

Result MemoryBackend::rename(const QString &from, const QString &to, RenameMode mode)
{
    QString rawFrom;
    QString rawTo;
    Result r = begin("rename", from, &rawFrom);
    if (r.ok())
        r = Paths::normalize(to, &rawTo);
    if (!r.ok())
        return r;
    rawTo = keyOf(rawTo);
    const auto source = m_nodes.find(rawFrom);
    if (source == m_nodes.end())
        return Result(Error::NotFound, rawFrom);
    const auto existing = m_nodes.find(rawTo);
    if (existing != m_nodes.end()
        && (mode == RenameMode::NoReplace || existing->second.type == EntryType::Directory)) {
        return Result(Error::AlreadyExists, rawTo);
    }
    m_nodes[rawTo] = source->second;
    m_nodes.erase(rawFrom);
    return Result::success();
}

Result MemoryBackend::readLink(const QString &path, QString *target)
{
    QString key;
    Node *found = nullptr;
    const Result r = find("readLink", path, false, &key, &found);
    if (!r.ok())
        return r;
    if (found->type != EntryType::Symlink)
        return Result(Error::InvalidName, QStringLiteral("not a link"));
    *target = found->target;
    return r;
}

Result MemoryBackend::checkWritable(const QString &key, const WriteOptions &options)
{
    const auto parent = m_nodes.find(parentKey(key));
    if (parent == m_nodes.end() || parent->second.type != EntryType::Directory)
        return Result(Error::NotFound, parentKey(key));
    const auto existing = m_nodes.find(key);
    if (existing == m_nodes.end())
        return Result::success();
    if (existing->second.type == EntryType::Directory)
        return Result(Error::IsADirectory, key);
    if (options.disposition == WriteOptions::CreateNew)
        return Result(Error::AlreadyExists, key);
    return Result::success();
}

Result MemoryBackend::upload(QIODevice *source, const QString &path, const UploadOptions &options,
                             Progress *progress)
{
    QString raw;
    Result r = begin("upload", path, &raw);
    if (!r.ok())
        return r;
    QString key;
    r = resolve(raw, false, &key);
    if (r.ok())
        r = checkWritable(key, options.write);
    if (!r.ok())
        return r;

    Node &node = m_nodes[key];
    node = Node();
    node.hash = FnvOffset;
    if (options.write.modified.isValid() && caps.has(Capability::SetModifiedOnUpload))
        node.modified = options.write.modified;
    QByteArray buffer(int(chunkSize), Qt::Uninitialized);
    for (;;) {
        if (m_canceled || (progress && progress->canceled()))
            return Result(Error::Canceled);
        const qint64 n = source->read(buffer.data(), buffer.size());
        if (n < 0)
            return Result(Error::ConnectionLost, QStringLiteral("the source failed"));
        if (n == 0)
            break;
        bytesRead += n;
        if (failUploadAfter >= 0 && node.size + n > failUploadAfter)
            return Result(Error::NoSpace, QStringLiteral("injected"));
        for (qint64 i = 0; i < n; ++i)
            node.hash = (node.hash ^ uchar(buffer.at(int(i)))) * FnvPrime;
        if (!discardData)
            node.data.append(buffer.constData(), int(n));
        node.size += n;
        if (progress)
            progress->update(node.size, options.write.expectedSize);
        if (chunkDelayUs > 0)
            QThread::usleep(ulong(chunkDelayUs));
    }
    return Result::success();
}

Result MemoryBackend::download(const QString &path, QIODevice *sink, const DownloadOptions &options,
                               Progress *progress)
{
    QString key;
    Node *found = nullptr;
    const Result r = find("download", path, true, &key, &found);
    if (!r.ok())
        return r;
    if (found->type == EntryType::Directory)
        return Result(Error::IsADirectory, key);
    const qint64 end = options.length < 0 ? found->size : qMin(found->size, options.offset + options.length);
    qint64 position = options.offset;
    QByteArray chunk;
    while (position < end) {
        if (m_canceled || (progress && progress->canceled()))
            return Result(Error::Canceled);
        const qint64 n = qMin(chunkSize, end - position);
        if (failDownloadAfter >= 0 && position + n > failDownloadAfter)
            return Result(Error::ConnectionLost, QStringLiteral("injected"));
        if (found->generated >= 0) {
            chunk.resize(int(n));
            for (qint64 i = 0; i < n; ++i)
                chunk[int(i)] = patternByte(position + i);
        } else {
            chunk = found->data.mid(int(position), int(n));
        }
        if (sink->write(chunk) != n)
            return Result(Error::Internal, QStringLiteral("the sink failed: %1").arg(sink->errorString()));
        position += n;
        bytesWritten += n;
        if (progress)
            progress->update(position - options.offset, end - options.offset);
    }
    return Result::success();
}
