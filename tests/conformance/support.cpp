// SPDX-License-Identifier: LGPL-2.1-or-later
#include "support.h"
#include "paths.h"

#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QElapsedTimer>
#include <QtCore/QProcess>

#include <QtCore/QFile>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace NetVfs;

namespace Conformance {

namespace {
constexpr qint64 SnapshotContentLimit = 64 * 1024;
constexpr int ShellTimeoutMs = 120000;
constexpr quint32 PatternMultiplier = 1103515245U;
constexpr quint32 PatternIncrement = 12345U;
constexpr int PatternShift = 16;
} // namespace

QByteArray pattern(qint64 size, int seed)
{
    QByteArray data(static_cast<int>(size), Qt::Uninitialized);
    auto state = static_cast<quint32>(seed) + 1U;
    for (int i = 0; i < data.size(); ++i) {
        state = state * PatternMultiplier + PatternIncrement;
        data[i] = static_cast<char>(state >> PatternShift);
    }
    return data;
}

Result putFile(Backend *backend, const QString &path, const QByteArray &data, WriteOptions::Disposition disposition)
{
    QBuffer buffer;
    buffer.setData(data);
    buffer.open(QIODevice::ReadOnly);
    UploadOptions options;
    options.write.disposition = disposition;
    options.write.expectedSize = data.size();
    return backend->upload(&buffer, path, options, nullptr);
}

Result download(Backend *backend, const QString &path, qint64 offset, qint64 length, QByteArray *data)
{
    QBuffer buffer;
    buffer.open(QIODevice::WriteOnly);
    DownloadOptions options;
    options.offset = offset;
    options.length = length;
    const Result r = backend->download(path, &buffer, options, nullptr);
    *data = buffer.data();
    return r;
}

Result getFile(Backend *backend, const QString &path, QByteArray *data)
{
    return download(backend, path, 0, -1, data);
}

bool exists(Backend *backend, const QString &path)
{
    Entry entry;
    return backend->lstat(path, &entry).ok();
}

QStringList names(Backend *backend, const QString &dir, Result *result)
{
    QVector<Entry> entries;
    const Result r = backend->list(dir, &entries);
    if (result)
        *result = r;
    QStringList out;
    for (const Entry &e : entries)
        out.append(e.name);
    out.sort();
    return out;
}

const Entry *find(const QVector<Entry> &entries, const QString &name)
{
    for (const Entry &e : entries) {
        if (e.name == name)
            return &e;
    }
    return nullptr;
}

Result removeRecursive(Backend *backend, const QString &path)
{
    Entry entry;
    Result r = backend->lstat(path, &entry);
    if (!r.ok())
        return r.error() == Error::NotFound ? Result::success() : r;
    if (entry.type != EntryType::Directory)
        return backend->removeFile(path);
    QVector<Entry> children;
    r = backend->list(path, &children);
    for (const Entry &child : children) {
        if (r.ok())
            r = removeRecursive(backend, Paths::join(path, child.name));
    }
    return r.ok() ? backend->removeDir(path) : r;
}

namespace {
void snapshotInto(Backend *backend, const QString &dir, const QString &prefix, QMap<QString, QString> *out)
{
    QVector<Entry> entries;
    if (const Result r = backend->list(dir, &entries); !r.ok()) {
        out->insert(prefix, r.toString());
        return;
    }
    for (const Entry &e : entries) {
        const QString key = prefix + QLatin1Char('/') + e.name;
        QString value = QStringLiteral("%1 %2 %3 %4")
                            .arg(static_cast<int>(e.type))
                            .arg(e.type == EntryType::Directory ? -1 : e.size)
                            .arg(e.mode)
                            .arg(e.modified.toMSecsSinceEpoch());
        const QString path = Paths::join(dir, e.name);
        if (e.type == EntryType::File && e.size >= 0 && e.size <= SnapshotContentLimit) {
            QByteArray data;
            if (getFile(backend, path, &data).ok())
                value += QLatin1Char(' ') + QString::fromLatin1(QCryptographicHash::hash(data, QCryptographicHash::Sha1).toHex());
        }
        out->insert(key, value);
        if (e.type == EntryType::Directory)
            snapshotInto(backend, path, key, out);
    }
}

} // namespace

QMap<QString, QString> snapshot(Backend *backend, const QString &dir)
{
    QMap<QString, QString> out;
    snapshotInto(backend, dir, QString(), &out);
    return out;
}

bool RecordingSink::entries(const QVector<Entry> &batch)
{
    batchSizes.append(batch.size());
    all += batch;
    if (cancelBackend)
        cancelBackend->cancel();
    return stopAfterBatches < 0 || batchSizes.size() < stopAfterBatches;
}

void RecordingProgress::update(qint64 done, qint64 total)
{
    if (!updates.isEmpty() && done < updates.last().first)
        monotonic = false;
    updates.append(qMakePair(done, total));
    if (cancelBackend)
        cancelBackend->cancel();
}

ZeroDevice::ZeroDevice(qint64 size, qint64 markerOffset, const QByteArray &marker)
    : m_size(size)
    , m_markerOffset(markerOffset)
    , m_marker(marker)
{
    open(QIODevice::ReadOnly);
}

qint64 ZeroDevice::readData(char *data, qint64 maxSize)
{
    const qint64 n = qMin(maxSize, m_size - m_position);
    if (n <= 0)
        return 0;
    std::memset(data, 0, static_cast<size_t>(n));
    for (int i = 0; i < m_marker.size(); ++i) {
        const qint64 at = m_markerOffset + i - m_position;
        if (at >= 0 && at < n)
            data[at] = m_marker.at(i);
    }
    m_position += n;
    return n;
}

qint64 ZeroDevice::writeData(const char *data, qint64 maxSize)
{
    Q_UNUSED(data)
    Q_UNUSED(maxSize)
    return -1;
}

FifoStall::FifoStall(const QString &hostPath)
{
    const QByteArray path = QFile::encodeName(hostPath);
    if (::mkfifo(path.constData(), 0600) == 0)
        m_fd = ::open(path.constData(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
}

FifoStall::~FifoStall()
{
    if (m_fd >= 0)
        ::close(m_fd);
}

Result runCanceled(Backend *backend, int delayMs, const std::function<Result()> &call, qint64 *cancelToReturnMs)
{
    QElapsedTimer clock;
    clock.start();
    std::atomic<qint64> canceledAt { -1 };
    std::thread canceler([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        canceledAt = clock.elapsed();
        backend->cancel();
    });
    const Result r = call();
    const qint64 returnedAt = clock.elapsed();
    canceler.join();
    *cancelToReturnMs = canceledAt < 0 ? -1 : returnedAt - canceledAt;
    return r;
}

bool runShell(const QString &command, QString *output)
{
    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start(QStringLiteral("/bin/sh"), QStringList { QStringLiteral("-c"), command });
    const bool finished = process.waitForFinished(ShellTimeoutMs);
    if (output)
        *output = QString::fromLocal8Bit(process.readAll());
    return finished && process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
}

} // namespace Conformance
