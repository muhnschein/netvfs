// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbops.h"
#include "smbfiles.h"

#include "paths.h"

#include <QtCore/QIODevice>

#include <limits>

#include <fcntl.h>

namespace NetVfs::Smb::Ops {

namespace {

qint64 scaled(uint64_t units, uint64_t unit)
{
    constexpr auto limit = static_cast<uint64_t>(std::numeric_limits<qint64>::max());
    return static_cast<qint64>((unit && units > limit / unit) ? limit : units * unit);
}

Result stopped()
{
    return Result(Error::Canceled, QStringLiteral("The listing was stopped"));
}

// Delivers `batch` when it is full (or `last`), honouring cancel.
Result deliver(const Session &session, ListSink *sink, QVector<Entry> *batch, int batchSize, bool last)
{
    if (batch->isEmpty() || (!last && batch->size() < batchSize))
        return Result::success();
    if (!last && session.canceled())
        return Result(Error::Canceled);
    const bool more = sink->entries(*batch);
    batch->clear();
    return more ? Result::success() : stopped();
}

} // namespace

Result statPath(Session &session, const QByteArray &path, Entry *out)
{
    auto call = std::make_unique<Call>();
    const Result r = session.request(call, [&path](smb2_context *ctx, Call *c) {
        return smb2_stat_async(ctx, path.constData(), &c->st, netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("stat"));
    if (r.ok() && out)
        *out = entryFrom(Paths::fileName(decodeName(path.constData())), call->st);
    return r;
}

Result unlinkPath(Session &session, const QByteArray &path, const QString &context)
{
    auto call = std::make_unique<Call>();
    return session.request(call, [&path](smb2_context *ctx, Call *c) {
        return smb2_unlink_async(ctx, path.constData(), netvfs_smb_complete_plain, c->completion());
    }, context);
}

Result listPath(Session &session, const QByteArray &path, ListSink *sink, const ListOptions &options)
{
    auto call = std::make_unique<Call>();
    Result r = session.request(call, [&path](smb2_context *ctx, Call *c) {
        return smb2_opendir_async(ctx, path.constData(), netvfs_smb_complete_opendir, c->completion());
    }, QStringLiteral("list"));
    if (!r.ok()) {
        // Samba answers a file with "not found" for some paths; say what it is.
        Entry entry;
        if (r.error() != Error::ConnectionLost && statPath(session, path, &entry).ok() && !entry.isDir())
            return Result(Error::NotADirectory, QStringLiteral("list: not a folder"));
        return r;
    }
    // XC-6: libsmb2 collects the QUERY_DIRECTORY responses while opening;
    // the entries are delivered in batches of batchSize.
    const int batchSize = qMax(1, options.batchSize);
    smb2_context *ctx = session.context();
    QVector<Entry> batch;
    for (const smb2dirent *ent = smb2_readdir(ctx, call->dir); ent && r.ok(); ent = smb2_readdir(ctx, call->dir)) {
        const QByteArray name(ent->name);
        if (name != "." && name != "..")
            batch.append(entryFrom(decodeName(ent->name), ent->st));
        r = deliver(session, sink, &batch, batchSize, false);
    }
    smb2_closedir(ctx, call->dir);
    if (r.ok())
        r = deliver(session, sink, &batch, batchSize, true);
    return r;
}

Result makeDirectory(Session &session, const QByteArray &path, bool exclusive)
{
    auto call = std::make_unique<Call>();
    Result r = session.request(call, [&path](smb2_context *ctx, Call *c) {
        return smb2_mkdir_async(ctx, path.constData(), netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("create folder"));
    if (r.error() != Error::AlreadyExists || exclusive)
        return r;
    // XC-8: an existing folder is success (also one created concurrently).
    Entry entry;
    r = statPath(session, path, &entry);
    if (r.ok() && !entry.isDir())
        return Result(Error::AlreadyExists, QStringLiteral("create folder: a file has the folder's name"));
    return r;
}

// XC-9: libsmb2 deletes files and folders alike (delete-on-close without
// FILE_NON_DIRECTORY_FILE or FILE_DIRECTORY_FILE), so the type is checked
// first; a concurrent replacement in between is a documented race.
Result removeFile(Session &session, const QByteArray &path)
{
    Entry entry;
    Result r = path.isEmpty() ? Result::success() : statPath(session, path, &entry);
    if (r.ok() && (path.isEmpty() || entry.isDir()))
        return Result(Error::IsADirectory, QStringLiteral("remove: a folder"));
    if (r.ok())
        r = unlinkPath(session, path, QStringLiteral("remove"));
    return r;
}

Result removeDirectory(Session &session, const QByteArray &path)
{
    Entry entry;
    Result r = statPath(session, path, &entry);
    if (r.ok() && !entry.isDir())
        return Result(Error::NotADirectory, QStringLiteral("remove folder: not a folder"));
    if (!r.ok())
        return r;
    auto call = std::make_unique<Call>();
    r = session.request(call, [&path](smb2_context *ctx, Call *c) {
        return smb2_rmdir_async(ctx, path.constData(), netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("remove folder"));
    if (!r.ok())
        return r;
    // Samba accepts delete-on-close for a folder that is not empty and then
    // keeps it, with a successful close: the folder must be gone afterwards.
    r = statPath(session, path, nullptr);
    if (r.ok())
        return Result(Error::DirectoryNotEmpty, QStringLiteral("remove folder: the folder is not empty"));
    return r.error() == Error::NotFound ? Result::success() : r;
}

Result renamePath(Session &session, const QByteArray &from, const QByteArray &to)
{
    auto call = std::make_unique<Call>();
    return session.request(call, [&from, &to](smb2_context *ctx, Call *c) {
        return smb2_rename_async(ctx, from.constData(), to.constData(), netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("rename"));
}

Result renameReplacing(Session &session, const QByteArray &from, const QByteArray &to)
{
    // XC-10: a folder is never replaced.
    Entry target;
    const Result r = statPath(session, to, &target);
    if (r.ok() && target.isDir())
        return Result(Error::AlreadyExists, QStringLiteral("rename: the target is a folder"));
    if (!r.ok() && r.error() != Error::NotFound)
        return r;
    // XM-5: ReplaceIfExists in the same request (vendor/patches/libsmb2/0005),
    // so the target never goes missing (AtomicReplace).
    auto call = std::make_unique<Call>();
    return session.request(call, [&from, &to](smb2_context *ctx, Call *c) {
        return smb2_rename_replace_async(ctx, from.constData(), to.constData(), netvfs_smb_complete_plain,
                                         c->completion());
    }, QStringLiteral("rename"));
}

Result spaceInfo(Session &session, const QByteArray &path, SpaceInfo *out)
{
    auto call = std::make_unique<Call>();
    const Result r = session.request(call, [&path](smb2_context *ctx, Call *c) {
        return smb2_statvfs_async(ctx, path.constData(), &c->vfs, netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("free space"));
    // XM-8: FileFsFullSizeInformation (libsmb2 fills statvfs from it).
    if (r.ok() && out) {
        const quint64 unit = call->vfs.f_bsize;
        out->free = scaled(call->vfs.f_bavail, unit);
        out->total = scaled(call->vfs.f_blocks, unit);
        out->used = call->vfs.f_blocks >= call->vfs.f_bavail ? scaled(call->vfs.f_blocks - call->vfs.f_bavail, unit)
                                                              : -1;
    }
    return r;
}

Result echo(Session &session)
{
    // XM-8: one SMB2 ECHO round trip.
    auto call = std::make_unique<Call>();
    return session.request(call, [](smb2_context *ctx, Call *c) {
        return smb2_echo_async(ctx, netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("keep-alive"));
}

Result openForWrite(Session &session, const QByteArray &path, const WriteOptions &options, smb2fh **fh)
{
    // XC-14; SMB has no POSIX modes, createMode does not apply.
    int flags = O_WRONLY;
    if (options.disposition == WriteOptions::Disposition::CreateNew)
        flags |= O_CREAT | O_EXCL;
    else if (options.disposition == WriteOptions::Disposition::Truncate)
        flags |= O_CREAT | O_TRUNC;
    else
        flags = O_RDWR;     // Resume: the size check needs FILE_READ_ATTRIBUTES
    Result r = openFile(session, path, flags, fh);
    if (!r.ok()) {
        Entry entry;
        if (r.error() != Error::ConnectionLost && statPath(session, path, &entry).ok() && entry.isDir())
            return Result(Error::IsADirectory, QStringLiteral("open: a folder"));
        return r;
    }
    if (options.disposition != WriteOptions::Disposition::Resume)
        return r;
    // Resume: the remote size must be the offset the caller continues at.
    Entry entry;
    r = fileStat(session, *fh, &entry);
    if (r.ok() && entry.size != options.resumeOffset) {
        r = Result(Error::ProtocolError, QStringLiteral("Cannot resume at %1: the file has %2 bytes")
                                             .arg(options.resumeOffset).arg(entry.size));
    }
    if (!r.ok()) {
        closeFile(session, *fh, r);
        *fh = nullptr;
    }
    return r;
}

Result openForRead(Session &session, const QByteArray &path, smb2fh **fh, qint64 *size)
{
    Result r = openFile(session, path, O_RDONLY, fh);
    if (!r.ok())
        return r;
    Entry entry;
    r = fileStat(session, *fh, &entry);
    if (r.ok() && entry.isDir())
        r = Result(Error::IsADirectory, QStringLiteral("open: a folder"));
    if (!r.ok()) {
        closeFile(session, *fh, r);
        *fh = nullptr;
        return r;
    }
    *size = entry.size;
    return r;
}

Result writeAll(const Session &session, QIODevice *source, WriteHandle *writer, Progress *progress, qint64 base)
{
    const quint32 chunk = session.writeChunk();     // M-11
    QByteArray buffer(static_cast<int>(chunk), Qt::Uninitialized);
    const qint64 total = base + source->size();
    for (;;) {
        if (session.canceled() || (progress && progress->canceled()))
            return Result(Error::Canceled);
        const qint64 n = source->read(buffer.data(), chunk);
        if (n < 0)
            return Result(Error::Internal, QStringLiteral("Cannot read the data to upload"));
        if (n == 0)
            return Result::success();
        if (Result r = writer->write(buffer.constData(), n); !r.ok())
            return r;
        if (progress)
            progress->update(writer->position(), total);
    }
}

Result copyToSink(const Session &session, ReadHandle *reader, qint64 offset, qint64 end, QIODevice *sink,
                  Progress *progress)
{
    const qint64 chunk = session.readChunk();      // M-11
    const qint64 start = offset;
    while (offset < end) {
        if (progress && progress->canceled())
            return Result(Error::Canceled);
        // XM-6: up to MaxInFlight bytes on the way while this chunk is stored.
        reader->readAhead(offset, end - offset);
        QByteArray data;
        if (Result r = reader->read(offset, qMin(chunk, end - offset), &data); !r.ok())
            return r;
        if (data.isEmpty())
            break;      // the file shrank; the caller compares sizes
        if (sink->write(data) != data.size())
            return Result(Error::Internal, QStringLiteral("Cannot store the downloaded data"));
        offset += data.size();
        if (progress)
            progress->update(offset - start, end - start);
    }
    return Result::success();
}

} // namespace NetVfs::Smb::Ops
