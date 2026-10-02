// SPDX-License-Identifier: LGPL-2.1-or-later
#include "transfer.h"
#include "logging.h"
#include "paths.h"

#include <QtCore/QFile>
#include <QtCore/QFileInfo>

#include <unistd.h>

namespace NetVfs {
namespace Transfer {

namespace {

// Pass-through reader that counts the bytes handed to the backend.
class CountingReader : public QIODevice
{
public:
    explicit CountingReader(QIODevice *source) : m_source(source) {}

    bool isSequential() const override { return true; }
    qint64 size() const override { return m_source->size(); }
    qint64 count() const { return m_count; }

protected:
    qint64 readData(char *data, qint64 maxSize) override
    {
        const qint64 n = m_source->read(data, maxSize);
        if (n > 0)
            m_count += n;
        return n;
    }
    qint64 writeData(const char *, qint64) override { return -1; }

private:
    QIODevice *m_source;
    qint64 m_count = 0;
};

void removeQuietly(Backend *backend, const QString &path, const Result &cause)
{
    if (cause.error() == Error::Canceled)
        backend->resetCancel();
    const Result r = backend->remove(path);
    if (!r.ok() && r.error() != Error::NotFound)
        qCWarning(lcNetVfsCore) << "Could not remove partial file:" << r.toString();
}

} // namespace

QString partName(const QString &path)
{
    return path + QStringLiteral(".part");
}

Result upload(Backend *backend, QIODevice *source, qint64 size, const QString &finalPath,
              Progress *progress)
{
    QString target;
    Result r = Paths::normalize(finalPath, &target);
    if (!r.ok())
        return r;
    if (Paths::fileName(target).isEmpty())
        return Result(Error::Internal, QStringLiteral("Upload target has no file name"));

    if (size >= 0) {
        qint64 available = -1;
        r = backend->freeSpace(Paths::parent(target), &available);
        if (r.error() == Error::Canceled)
            return r;
        if (r.ok() && available >= 0 && available < size) {
            return Result(Error::NoSpace,
                          QStringLiteral("The server has %1 bytes free, %2 needed").arg(available).arg(size));
        }
        if (!r.ok() && r.error() != Error::Unsupported)
            qCDebug(lcNetVfsCore) << "Free space unknown:" << r.toString();
    }

    const QString part = partName(target);
    CountingReader reader(source);
    reader.open(QIODevice::ReadOnly);
    r = backend->upload(&reader, part, progress);
    if (!r.ok()) {
        removeQuietly(backend, part, r);
        return r;
    }
    if (size >= 0 && reader.count() != size) {
        removeQuietly(backend, part, r);
        return Result(Error::Internal,
                      QStringLiteral("Local file changed during upload (%1 of %2 bytes read)")
                          .arg(reader.count()).arg(size));
    }

    Entry entry;
    r = backend->stat(part, &entry);
    if (r.ok() && entry.size != reader.count()) {
        r = Result(Error::ProtocolError,
                   QStringLiteral("Remote size %1 does not match %2 bytes sent")
                       .arg(entry.size).arg(reader.count()));
    }
    if (r.ok())
        r = backend->rename(part, target);
    if (!r.ok())
        removeQuietly(backend, part, r);
    return r;
}

Result uploadFile(Backend *backend, const QString &localPath, const QString &finalPath,
                  Progress *progress)
{
    QFile file(localPath);
    if (!file.open(QIODevice::ReadOnly))
        return Result(Error::NotFound, QStringLiteral("Cannot open %1: %2").arg(localPath, file.errorString()));
    return upload(backend, &file, file.size(), finalPath, progress);
}

Result downloadFile(Backend *backend, const QString &remotePath, const QString &localPath,
                    Progress *progress)
{
    QString source;
    Result r = Paths::normalize(remotePath, &source);
    if (!r.ok())
        return r;

    Entry entry;
    r = backend->stat(source, &entry);
    if (!r.ok())
        return r;
    if (entry.isDir)
        return Result(Error::NotFound, QStringLiteral("%1 is a directory").arg(source));

    const QString part = partName(localPath);
    QFile file(part);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return Result(Error::PermissionDenied, QStringLiteral("Cannot write %1: %2").arg(part, file.errorString()));

    r = backend->download(source, &file, progress);
    if (r.ok() && (!file.flush() || ::fsync(file.handle()) != 0))
        r = Result(Error::NoSpace, QStringLiteral("Cannot write %1: %2").arg(part, file.errorString()));
    if (r.ok() && file.size() != entry.size) {
        r = Result(Error::ProtocolError, QStringLiteral("Received %1 bytes, the server reported %2")
                                             .arg(file.size()).arg(entry.size));
    }
    file.close();

    if (r.ok()) {
        QFile::remove(localPath);
        if (!QFile::rename(part, localPath))
            r = Result(Error::PermissionDenied, QStringLiteral("Cannot rename %1 to %2").arg(part, localPath));
    }
    if (!r.ok())
        QFile::remove(part);
    return r;
}

Result removeStaleParts(Backend *backend, const QString &dir, const QDateTime &now, qint64 maxAgeSecs)
{
    QVector<Entry> entries;
    Result r = backend->list(dir, &entries);
    if (r.error() == Error::NotFound)
        return Result::success();
    if (!r.ok())
        return r;

    const QDateTime cutoff = now.addSecs(-maxAgeSecs);
    for (const Entry &entry : entries) {
        if (entry.isDir || !entry.name.endsWith(QLatin1String(".part")))
            continue;
        if (!entry.modified.isValid() || entry.modified >= cutoff)
            continue;
        r = backend->remove(Paths::join(dir, entry.name));
        if (r.error() == Error::Canceled)
            return r;
        if (!r.ok())
            qCWarning(lcNetVfsCore) << "Could not remove stale partial file:" << r.toString();
    }
    return Result::success();
}

} // namespace Transfer
} // namespace NetVfs
