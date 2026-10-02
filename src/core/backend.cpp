// SPDX-License-Identifier: LGPL-2.1-or-later
#include "backend.h"
#include "paths.h"

#include <memory>

namespace NetVfs {

ReadHandle::~ReadHandle() = default;
WriteHandle::~WriteHandle() = default;
Backend::~Backend() = default;
BackendFactory::~BackendFactory() = default;

namespace {
Result unsupported(const char *what)
{
    return Result(Error::Unsupported, QStringLiteral("%1 is not supported by this backend").arg(QLatin1String(what)));
}

class CollectingSink : public ListSink
{
public:
    explicit CollectingSink(QVector<Entry> *out) : m_out(out) {}
    bool entries(const QVector<Entry> &batch) override
    {
        *m_out += batch;
        return true;
    }

private:
    QVector<Entry> *m_out;
};
} // namespace

Result Backend::lstat(const QString &path, Entry *out)
{
    return stat(path, out);
}

Result Backend::removeTreeNative(const QString &)
{
    return unsupported("Recursive delete");
}

Result Backend::setAttributes(const QString &, const AttributeChanges &)
{
    return unsupported("Changing attributes");
}

Result Backend::readLink(const QString &, QString *)
{
    return unsupported("Reading links");
}

Result Backend::makeSymlink(const QString &, const QString &)
{
    return unsupported("Creating symbolic links");
}

Result Backend::makeHardlink(const QString &, const QString &)
{
    return unsupported("Creating hard links");
}

Result Backend::openRead(const QString &, ReadHandle **out)
{
    if (out)
        *out = nullptr;
    return unsupported("Random access reading");
}

Result Backend::openWrite(const QString &, const WriteOptions &, WriteHandle **out)
{
    if (out)
        *out = nullptr;
    return unsupported("Handle based writing");
}

Result Backend::copy(const QString &, const QString &, const CopyOptions &)
{
    return unsupported("Server-side copy");
}

Result Backend::checksum(const QString &, const QString &, QByteArray *)
{
    return unsupported("Server-side checksums");
}

Result Backend::spaceInfo(const QString &, SpaceInfo *)
{
    return unsupported("Free space information");
}

Result Backend::list(const QString &dir, QVector<Entry> *out)
{
    QVector<Entry> collected;
    CollectingSink sink(&collected);
    const Result r = list(dir, &sink, ListOptions());
    if (out)
        *out = r.ok() ? collected : QVector<Entry>();
    return r;
}

Result Backend::remove(const QString &path)
{
    const Result r = removeFile(path);
    if (r.error() == Error::IsADirectory)
        return removeDir(path);
    return r;
}

Result Backend::read(const QString &path, qint64 offset, qint64 length, QByteArray *out)
{
    if (offset < 0 || length < -1)
        return Result(Error::Internal, QStringLiteral("Invalid range"));
    ReadHandle *raw = nullptr;
    Result r = openRead(path, &raw);
    std::unique_ptr<ReadHandle> handle(raw);
    if (!r.ok())
        return r;
    QByteArray data;
    qint64 position = offset;
    const auto wanted = [length, &data]() { return length < 0 ? qint64(1) << 20 : length - data.size(); };
    while (wanted() > 0) {
        QByteArray chunk;
        r = handle->read(position, wanted(), &chunk);
        if (!r.ok() || chunk.isEmpty())
            break;
        data += chunk;
        position += chunk.size();
    }
    const Result closed = handle->close();
    if (r.ok())
        r = closed;
    if (out)
        *out = r.ok() ? data : QByteArray();
    return r;
}

Result Backend::freeSpace(const QString &dir, qint64 *bytes)
{
    SpaceInfo info;
    const Result r = spaceInfo(dir, &info);
    if (!r.ok())
        return r;
    if (info.free < 0)
        return Result(Error::Unsupported, QStringLiteral("The server does not report free space"));
    if (bytes)
        *bytes = info.free;
    return r;
}

Result Backend::makePath(const QString &dir)
{
    QString normalized;
    Result r = Paths::normalize(dir, &normalized);
    if (!r.ok())
        return r;
    QString current = Paths::isAbsolute(normalized) ? QStringLiteral("/") : QString();
    for (const QString &component : Paths::components(normalized)) {
        current = Paths::join(current, component);
        r = makeDir(current, false);
        if (!r.ok())
            return r;
    }
    return Result::success();
}

} // namespace NetVfs
