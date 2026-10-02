// SPDX-License-Identifier: LGPL-2.1-or-later
#include "transfer.h"
#include "logging.h"
#include "paths.h"

#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QRegExp>

#include <memory>

#include <unistd.h>

namespace NetVfs::Transfer {

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

// C-17: the message may name a remote path, so it is logged at debug level only.
void logRemovalFailure(const char *what, const Result &r)
{
    qCWarning(lcNetVfsCore) << "Could not remove" << what << errorName(r.error());
    qCDebug(lcNetVfsCore) << r.message();
}

void removeQuietly(Backend *backend, const QString &path, const Result &cause)
{
    if (cause.error() == Error::Canceled)
        backend->resetCancel();
    const Result r = backend->removeFile(path);
    if (!r.ok() && r.error() != Error::NotFound)
        logRemovalFailure("partial file", r);
}

} // namespace

QString partName(const QString &path)
{
    return path + QStringLiteral(".part");
}

namespace {

QString temporaryPath(const QString &target, const TransferPolicy &policy)
{
    if (!policy.useTempName)
        return target;
    if (policy.tempName.isEmpty())
        return partName(target);
    return Paths::join(Paths::parent(target), policy.tempName);
}

Result checkFreeSpace(Backend *backend, const QString &target, qint64 needed)
{
    if (needed < 0)
        return Result::success();
    qint64 available = -1;
    const Result r = backend->freeSpace(Paths::parent(target), &available);
    if (r.error() == Error::Canceled)
        return r;
    if (r.ok() && available >= 0 && available < needed) {
        return Result(Error::NoSpace,
                      QStringLiteral("The server has %1 bytes free, %2 needed").arg(available).arg(needed));
    }
    if (!r.ok() && r.error() != Error::Unsupported)
        qCDebug(lcNetVfsCore) << "Free space unknown:" << r.toString();
    return Result::success();
}

// Positions `source` at `offset` (seek, else read and discard).
bool skipSource(QIODevice *source, qint64 offset)
{
    if (!source->isSequential())
        return source->seek(offset);
    QByteArray scratch;
    qint64 left = offset;
    while (left > 0) {
        scratch = source->read(qMin<qint64>(left, 256 * 1024));
        if (scratch.isEmpty())
            return false;
        left -= scratch.size();
    }
    return true;
}

Result writeResumed(Backend *backend, CountingReader *reader, const QString &path, qint64 size,
                    const TransferPolicy &policy, Progress *progress)
{
    WriteOptions options;
    options.disposition = WriteOptions::Resume;
    options.resumeOffset = policy.resumeOffset;
    options.createMode = policy.createMode;
    options.expectedSize = size;
    options.modified = policy.modified;
    WriteHandle *raw = nullptr;
    Result r = backend->openWrite(path, options, &raw);
    std::unique_ptr<WriteHandle> handle(raw);
    if (!r.ok())
        return r;
    QByteArray buffer(256 * 1024, Qt::Uninitialized);
    for (;;) {
        if (progress && progress->canceled()) {
            handle->abort();
            return Result(Error::Canceled);
        }
        const qint64 n = reader->read(buffer.data(), buffer.size());
        if (n < 0) {
            handle->abort();
            return Result(Error::Internal, QStringLiteral("Cannot read the local file"));
        }
        if (n == 0)
            break;
        r = handle->write(buffer.constData(), n);
        if (!r.ok()) {
            handle->abort();
            return r;
        }
        if (progress)
            progress->update(policy.resumeOffset + reader->count(), size);
    }
    return handle->commit();
}

} // namespace

Result upload(Backend *backend, QIODevice *source, qint64 size, const QString &finalPath,
              Progress *progress, const TransferPolicy &policy)
{
    QString target;
    Result r = Paths::normalize(finalPath, &target);
    if (!r.ok())
        return r;
    if (Paths::fileName(target).isEmpty())
        return Result(Error::Internal, QStringLiteral("Upload target has no file name"));
    if (policy.resume && (!policy.useTempName || policy.resumeOffset < 0))
        return Result(Error::Internal, QStringLiteral("Resuming needs a temporary name and an offset"));

    const qint64 base = policy.resume ? policy.resumeOffset : 0;
    r = checkFreeSpace(backend, target, size < 0 ? -1 : size - base);
    if (!r.ok())
        return r;

    const QString part = temporaryPath(target, policy);
    // Keeps a resumable temporary file; removes anything else.
    const auto cleanup = [&](const Result &cause) {
        if (policy.useTempName && !policy.resume)
            removeQuietly(backend, part, cause);
    };

    if (policy.resume) {
        Entry existing;
        r = backend->stat(part, &existing);
        if (!r.ok())
            return r;
        if (existing.size != policy.resumeOffset) {
            return Result(Error::ProtocolError,
                          QStringLiteral("Cannot resume at %1: the partial file has %2 bytes")
                              .arg(policy.resumeOffset).arg(existing.size));
        }
        if (!skipSource(source, policy.resumeOffset))
            return Result(Error::Internal, QStringLiteral("Cannot position the local file for resuming"));
    }

    CountingReader reader(source);
    reader.open(QIODevice::ReadOnly);
    if (policy.resume) {
        r = writeResumed(backend, &reader, part, size, policy, progress);
    } else {
        UploadOptions options;
        options.write.disposition = !policy.useTempName && policy.commitMode == RenameMode::NoReplace
            ? WriteOptions::CreateNew : WriteOptions::Truncate;
        options.write.createMode = policy.createMode;
        options.write.expectedSize = size;
        options.write.modified = policy.modified;
        r = backend->upload(&reader, part, options, progress);
    }
    if (!r.ok()) {
        cleanup(r);
        return r;
    }
    const qint64 sent = base + reader.count();
    if (size >= 0 && sent != size) {
        cleanup(r);
        return Result(Error::Internal,
                      QStringLiteral("Local file changed during upload (%1 of %2 bytes read)")
                          .arg(sent).arg(size));
    }

    if (policy.verifySize) {
        Entry entry;
        r = backend->stat(part, &entry);
        if (r.ok() && entry.size != sent) {
            r = Result(Error::ProtocolError,
                       QStringLiteral("Remote size %1 does not match %2 bytes sent")
                           .arg(entry.size).arg(sent));
        }
    }
    if (r.ok() && part != target)
        r = backend->rename(part, target, policy.commitMode);
    if (!r.ok())
        cleanup(r);
    return r;
}

Result uploadFile(Backend *backend, const QString &localPath, const QString &finalPath,
                  Progress *progress, const TransferPolicy &policy)
{
    QFile file(localPath);
    if (!file.open(QIODevice::ReadOnly))
        return Result(Error::NotFound, QStringLiteral("Cannot open %1: %2").arg(localPath, file.errorString()));
    return upload(backend, &file, file.size(), finalPath, progress, policy);
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
    if (entry.isDir())
        return Result(Error::IsADirectory, QStringLiteral("%1 is a directory").arg(source));

    const QString part = partName(localPath);
    QFile file(part);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return Result(Error::PermissionDenied, QStringLiteral("Cannot write %1: %2").arg(part, file.errorString()));

    r = backend->download(source, &file, DownloadOptions(), progress);
    if (r.ok() && (!file.flush() || ::fsync(file.handle()) != 0))
        r = Result(Error::NoSpace, QStringLiteral("Cannot write %1: %2").arg(part, file.errorString()));
    if (r.ok() && entry.size >= 0 && file.size() != entry.size) {
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

Result removeStaleParts(Backend *backend, const QString &dir, const QDateTime &now, qint64 maxAgeSecs,
                        const QString &pattern)
{
    QVector<Entry> entries;
    Result r = backend->list(dir, &entries);
    if (r.error() == Error::NotFound)
        return Result::success();
    if (!r.ok())
        return r;

    // QRegExp: Qt 5.6 (the target) has no QRegularExpression wildcard support.
    const QRegExp matcher(pattern, Qt::CaseSensitive, QRegExp::WildcardUnix);
    const QDateTime cutoff = now.addSecs(-maxAgeSecs);
    for (const Entry &entry : entries) {
        if (entry.type != EntryType::File || !matcher.exactMatch(entry.name))
            continue;
        if (!entry.modified.isValid() || entry.modified >= cutoff)
            continue;
        r = backend->removeFile(Paths::join(dir, entry.name));
        if (r.error() == Error::Canceled)
            return r;
        if (!r.ok())
            logRemovalFailure("stale partial file", r);
    }
    return Result::success();
}

} // namespace NetVfs::Transfer
