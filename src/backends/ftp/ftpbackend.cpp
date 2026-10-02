// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ftpbackend.h"
#include "curlglobal.h"
#include "ftphandles.h"
#include "names.h"

#include <QtCore/QIODevice>
#include <QtCore/QThread>

#include <array>

#include <mutex>

namespace NetVfs::Ftp {

namespace {

constexpr int DefaultConnectTimeoutMs = 15000;   // C-14
constexpr int DefaultRequestTimeoutMs = 60000;   // C-14
constexpr qint64 UploadChunk = 256 * 1024;
constexpr int MinBatchSize = 1;
// F-2: a 421 greeting on the login connection right after connect()'s own
// probe connection: the server may not have retired the probe session yet
// (vsftpd max_clients counts it until the session process is reaped).
constexpr std::array<int, 5> BusyGreetingDelaysMs = { 100, 200, 400, 800, 1600 };
constexpr int CancelSliceMs = 50;

// The wiping initialisation shared with the WebDAV plugin (SEC-5): libcurl
// takes the memory callbacks of the first initialisation in the process.
bool curlReady()
{
    static std::once_flag once;
    static bool initialized = false;
    std::call_once(once, [] { initialized = netvfs_curl_global_init() != 0; });
    return initialized;
}

QByteArray baseName(const QByteArray &remote)
{
    if (remote == "/")
        return QByteArray();
    return remote.mid(remote.lastIndexOf('/') + 1);
}

void nameEntry(Entry *entry, const QByteArray &remote)
{
    entry->name = Names::decode(baseName(remote));
    entry->flags &= ~EntryFlags(EntryFlag::NameNotUtf8);
    if (Names::hasEscapes(entry->name))
        entry->flags |= EntryFlag::NameNotUtf8;
}

bool positive(const Reply &reply)
{
    return reply.code >= 200 && reply.code < 400;
}

// Delivers parsed listing lines in batches as the data arrives (XC-6).
class ListingSink : public TransferSink
{
public:
    ListingSink(ListSink *sink, int batchSize, bool mlsd)
        : m_sink(sink), m_batchSize(std::max(batchSize, MinBatchSize)),
          m_parser(mlsd, QDateTime::currentDateTimeUtc())
    {
    }

    size_t received(const char *data, size_t size) override
    {
        m_parser.feed(data, size, &m_pending);
        return deliver(false) ? size : 0;
    }

    bool finish()
    {
        m_parser.finish(&m_pending);
        return deliver(true);
    }

    bool stopped() const { return m_stopped; }
    int invalidLines() const { return m_parser.invalidLines(); }

private:
    bool deliver(bool all)
    {
        while (!m_stopped && (m_pending.size() >= m_batchSize || (all && !m_pending.isEmpty()))) {
            const int count = std::min(m_batchSize, m_pending.size());
            const QVector<Entry> batch = m_pending.mid(0, count);
            m_pending.remove(0, count);
            if (m_sink && !m_sink->entries(batch))
                m_stopped = true;
        }
        return !m_stopped;
    }

    ListSink *m_sink;
    int m_batchSize;
    ListingParser m_parser;
    QVector<Entry> m_pending;
    bool m_stopped = false;
};

// Collects one listing (stat fallback, emptiness check).
class CollectSink : public ListSink
{
public:
    bool entries(const QVector<Entry> &batch) override
    {
        collected += batch;
        return true;
    }
    QVector<Entry> collected;
};

class DownloadSink : public TransferSink
{
public:
    DownloadSink(QIODevice *device, Progress *progress) : m_device(device), m_progress(progress) {}

    size_t received(const char *data, size_t size) override
    {
        qint64 done = 0;
        while (done < qint64(size)) {
            const qint64 n = m_device->write(data + done, qint64(size) - done);
            if (n <= 0) {
                m_writeFailed = true;
                return 0;
            }
            done += n;
        }
        return size;
    }

    bool progress(qint64 receiveTotal, qint64 received, qint64, qint64) override
    {
        if (!m_progress)
            return true;
        m_progress->update(received, receiveTotal > 0 ? receiveTotal : -1);
        return !m_progress->canceled();
    }

    bool writeFailed() const { return m_writeFailed; }

private:
    QIODevice *m_device;
    Progress *m_progress;
    bool m_writeFailed = false;
};

// An upload of zero bytes (creates or truncates a file).
class EmptySource : public TransferSink
{
public:
    size_t send(char *, size_t) override { return 0; }
};

} // namespace

Backend *createFtpBackend()
{
    return new FtpBackend();
}

FtpBackend::FtpBackend() = default;

FtpBackend::~FtpBackend()
{
    disconnect();
}

// --- connection -------------------------------------------------------------

Result FtpBackend::connect(const ConnectionParams &params, ServerIdentity *seen)
{
    disconnect();
    if (seen)
        *seen = ServerIdentity();
    if (m_canceled)
        return Result(Error::Canceled);
    if (!curlReady())
        return Result(Error::Internal, QStringLiteral("libcurl could not be initialised"));
    Result r = settingsFrom(params, &m_settings);
    if (!r.ok())
        return r;
    m_params = params;
    if (m_params.connectTimeoutMs <= 0)
        m_params.connectTimeoutMs = DefaultConnectTimeoutMs;
    if (m_params.requestTimeoutMs <= 0)
        m_params.requestTimeoutMs = DefaultRequestTimeoutMs;
    r = Connection::probe(m_settings, m_params, &m_canceled, &m_seen);
    if (!r.ok())
        return r;
    m_connected = true;
    if (seen)
        *seen = m_seen;
    return r;
}

Result FtpBackend::authenticate(const Credentials &credentials, AuthPrompter *prompter)
{
    Q_UNUSED(prompter)   // FTP has no interactive methods (XC-15)
    if (!m_connected)
        return Result(Error::Internal, QStringLiteral("connect() must succeed before authenticate()"));
    if (m_canceled)
        return Result(Error::Canceled);
    const QString userName = credentials.userName.isEmpty() ? m_params.username : credentials.userName;
    if (userName.isEmpty())
        return Result(Error::AuthFailed, QStringLiteral("No user name"));
    if (userName.contains(QLatin1Char('\r')) || userName.contains(QLatin1Char('\n'))
        || credentials.secret.contains('\r') || credentials.secret.contains('\n'))
        return Result(Error::AuthFailed, QStringLiteral("The user name or password contains a line break"));

    m_connection.reset(new Connection(&m_canceled));
    Result r = m_connection->configure(m_settings, m_params, userName, credentials.secret, m_seen);
    QVector<Reply> replies;
    if (r.ok())
        r = signIn(&replies);
    if (!r.ok()) {
        m_connection.reset();
        return r;
    }
    m_features = parseFeatures(replies.value(0));
    const QByteArray entry = m_connection->entryPath();
    m_home = entry.startsWith('/') ? entry : QByteArrayLiteral("/");
    m_utf8 = m_features.has("UTF8");
    m_utf8Pending = m_utf8;

    m_capabilities = Capabilities();
    m_capabilities.flags << Capability::ReadHandles << Capability::PosixModes;
    if (m_features.restStream())
        m_capabilities.flags << Capability::EfficientRanges << Capability::WriteResume;
    if (m_features.has("MFMT"))
        m_capabilities.flags << Capability::SetModified;
    qCDebug(lcNetVfsFtp) << "Signed in; home" << m_home << "features" << m_features.names.values();
    return Result::success();
}

// The first request opens the control connection and signs in, then reads
// FEAT. A server that refuses the connection at the greeting with 421 (and
// so before any credential was sent) gets a few more tries, BusyGreetingDelaysMs
// apart: connect() closed its probe connection just before, and a server
// with a connection limit may still count it. cancel() ends the wait (C-9).
Result FtpBackend::signIn(QVector<Reply> *replies)
{
    Result r = command({ QByteArrayLiteral("FEAT") }, replies, QStringLiteral("Signing in"));
    for (const int delayMs : BusyGreetingDelaysMs) {
        const QVector<Reply> &seen = m_connection->replies();
        if (r.ok() || seen.size() != 1 || seen.first().code != 421)
            break;
        qCDebug(lcNetVfsFtp) << "Busy greeting; signing in again in" << delayMs << "ms";
        for (int waited = 0; waited < delayMs && !m_canceled; waited += CancelSliceMs)
            QThread::msleep(CancelSliceMs);
        r = command({ QByteArrayLiteral("FEAT") }, replies, QStringLiteral("Signing in"));
    }
    return r;
}

Capabilities FtpBackend::capabilities() const
{
    return m_capabilities;
}

void FtpBackend::cancel()
{
    m_canceled = true;
}

void FtpBackend::resetCancel()
{
    m_canceled = false;
}

void FtpBackend::disconnect()
{
    for (StreamOwner *handle : m_handles)
        handle->invalidate();
    m_handles.clear();
    m_owner = nullptr;
    m_connection.reset();
    m_connected = false;
    m_features = Features();
    m_capabilities = Capabilities();
    m_home = QByteArrayLiteral("/");
    m_utf8 = false;
    m_utf8Pending = false;
}

// --- plumbing ---------------------------------------------------------------

Result FtpBackend::ready() const
{
    if (!m_connection)
        return Result(Error::ConnectionLost, QStringLiteral("Not connected"));
    if (m_canceled)
        return Result(Error::Canceled);
    return Result::success();
}

Result FtpBackend::claim(StreamOwner *owner)
{
    const Result r = ready();
    if (!r.ok())
        return r;
    if (m_owner && m_owner != owner) {
        m_connection->stop();
        m_owner->streamStopped();
    }
    m_owner = owner;
    return r;
}

void FtpBackend::release(StreamOwner *owner)
{
    if (m_owner == owner)
        m_owner = nullptr;
}

void FtpBackend::registerHandle(StreamOwner *handle)
{
    m_handles.insert(handle);
}

void FtpBackend::unregisterHandle(StreamOwner *handle)
{
    release(handle);
    m_handles.remove(handle);
}

QList<QByteArray> FtpBackend::prefixed(const QList<QByteArray> &commands)
{
    // OPTS UTF8 ON belongs to a connection: send it on the first request and
    // whenever libcurl may have opened a new one. Tolerated if refused
    // (pure-ftpd lists UTF8 but answers 504).
    m_lastPrefixed = m_utf8 && (m_utf8Pending || m_connection->mayReconnect());
    if (!m_lastPrefixed)
        return commands;
    m_utf8Pending = false;
    return QList<QByteArray>() << QByteArrayLiteral("*OPTS UTF8 ON") << commands;
}

void FtpBackend::requestDone()
{
    if (m_connection && !m_lastPrefixed && m_connection->unexpectedReconnect())
        m_utf8Pending = m_utf8;
}

Result FtpBackend::resolve(const QString &path, QByteArray *remote) const
{
    return remotePath(path, m_home, remote);
}

Result FtpBackend::command(const QList<QByteArray> &commands, QVector<Reply> *replies, const QString &context)
{
    Result r = claim(nullptr);
    if (!r.ok())
        return r;
    Request request;
    request.kind = Request::Kind::Command;
    for (const QByteArray &c : commands)
        request.commands.append('*' + c);   // every command gets its reply; callers judge them
    request.commands = prefixed(request.commands);
    r = m_connection->run(request, nullptr, context);
    requestDone();
    if (replies)
        *replies = m_connection->lastReplies(commands.size());
    return r;
}

// --- stat -------------------------------------------------------------------

Result FtpBackend::stat(const QString &path, Entry *out)
{
    QByteArray remote;
    Result r = resolve(path, &remote);
    if (!r.ok())
        return r;
    Entry entry;
    r = statRemote(remote, &entry);
    if (r.ok() && out)
        *out = entry;
    return r;
}

Result FtpBackend::statRemote(const QByteArray &remote, Entry *out)
{
    const Result r = m_features.has("MLST") ? statMlst(remote, out) : statBasic(remote, out);
    if (r.ok())
        nameEntry(out, remote);
    return r;
}

Result FtpBackend::statMlst(const QByteArray &remote, Entry *out)
{
    QVector<Reply> replies;
    Result r = command({ "MLST " + remote }, &replies, QStringLiteral("Reading file information"));
    if (!r.ok())
        return r;
    const Reply &reply = replies.at(0);
    if (!positive(reply)) {
        bool ambiguous = false;
        r = replyError(reply, QStringLiteral("Reading file information"), &ambiguous);
        return ambiguous ? Result(Error::NotFound, QStringLiteral("Reading file information: not found"), r.detail()) : r;
    }
    if (parseMlstReply(reply, out) != LineResult::Entry)
        return Result(Error::ProtocolError, QStringLiteral("Unexpected MLST reply"), replyForLog(reply));
    return Result::success();
}

// Without MLST (F-4): SIZE and MDTM for files, CWD tells folders apart.
Result FtpBackend::statBasic(const QByteArray &remote, Entry *out)
{
    QVector<Reply> replies;
    Result r = command({ QByteArrayLiteral("TYPE I"), "SIZE " + remote, "MDTM " + remote, "CWD " + remote },
                       &replies, QStringLiteral("Reading file information"));
    if (!r.ok())
        return r;
    *out = Entry();
    const qint64 size = parseSizeReply(replies.at(1));
    if (size >= 0) {
        out->type = EntryType::File;
        out->size = size;
        out->modified = parseMdtmReply(replies.at(2));
        return Result::success();
    }
    if (positive(replies.at(3))) {
        out->type = EntryType::Directory;
        return Result::success();
    }
    if (replies.at(1).code != 550 && replies.at(1).code >= 500)
        return statViaParent(remote, out);   // no SIZE command
    bool ambiguous = false;
    r = replyError(replies.at(3), QStringLiteral("Reading file information"), &ambiguous);
    return ambiguous ? Result(Error::NotFound, QStringLiteral("Reading file information: not found"), r.detail()) : r;
}

Result FtpBackend::statViaParent(const QByteArray &remote, Entry *out)
{
    if (remote == "/") {
        *out = Entry();
        out->type = EntryType::Directory;
        return Result::success();
    }
    CollectSink sink;
    const Result r = listRemote(remoteParent(remote), &sink, ListOptions().batchSize);
    if (!r.ok())
        return r;
    const QString name = Names::decode(baseName(remote));
    for (const Entry &entry : sink.collected) {
        if (entry.name == name) {
            *out = entry;
            return Result::success();
        }
    }
    return Result(Error::NotFound, QStringLiteral("Reading file information: not found"));
}

// --- listing ----------------------------------------------------------------

Result FtpBackend::list(const QString &dir, ListSink *sink, const ListOptions &options)
{
    QByteArray remote;
    Result r = resolve(dir, &remote);
    if (!r.ok())
        return r;
    return listRemote(remote, sink, options.batchSize);
}

// F-3: CWD into the folder (so LIST gets no argument a server could take
// for options or a glob), then MLSD when MLST is offered, else LIST -a.
Result FtpBackend::listRemote(const QByteArray &remote, ListSink *sink, int batchSize)
{
    Result r = claim(nullptr);
    if (!r.ok())
        return r;
    const bool mlsd = m_features.has("MLST");
    ListingSink listing(sink, batchSize, mlsd);
    Request request;
    request.kind = Request::Kind::Listing;
    request.commands = prefixed({ "CWD " + remote });
    request.listCommand = mlsd ? QByteArrayLiteral("MLSD") : QByteArrayLiteral("LIST -a");
    r = m_connection->run(request, &listing, QStringLiteral("Listing"));
    requestDone();
    if (listing.stopped())
        return Result(Error::Canceled);
    if (!r.ok()) {
        if (r.error() != Error::NotFound && r.error() != Error::PermissionDenied)
            return r;
        Entry entry;
        const Result s = statRemote(remote, &entry);
        if (s.error() == Error::NotFound)
            return s;
        if (s.ok() && !entry.isDir())
            return Result(Error::NotADirectory, QStringLiteral("Listing: not a folder"), r.detail());
        return r;
    }
    if (!listing.finish())
        return Result(Error::Canceled);
    if (listing.invalidLines() > 0) {
        qCDebug(lcNetVfsFtp) << "Skipped" << listing.invalidLines() << "unparseable listing lines";
        r.setDetail(QStringLiteral("%1 unparseable listing lines skipped").arg(listing.invalidLines()));
    }
    return r;
}

// --- namespace operations ---------------------------------------------------

Result FtpBackend::makeDir(const QString &path, bool exclusive)
{
    QByteArray remote;
    Result r = resolve(path, &remote);
    if (!r.ok())
        return r;
    QVector<Reply> replies;
    r = command({ "MKD " + remote }, &replies, QStringLiteral("Creating a folder"));
    if (!r.ok() || positive(replies.at(0)))
        return r;
    const Result failure = replyError(replies.at(0), QStringLiteral("Creating a folder"));
    Entry existing;
    r = statRemote(remote, &existing);
    if (r.ok()) {
        if (existing.isDir() && !exclusive)
            return Result::success();
        return Result(Error::AlreadyExists, QStringLiteral("Creating a folder: already exists"), failure.detail());
    }
    Entry parent;
    r = statRemote(remoteParent(remote), &parent);
    if (r.error() == Error::NotFound)
        return Result(Error::NotFound, QStringLiteral("Creating a folder: the parent folder does not exist"), failure.detail());
    if (r.ok() && !parent.isDir())
        return Result(Error::NotADirectory, QStringLiteral("Creating a folder: the parent is not a folder"), failure.detail());
    return failure;
}

Result FtpBackend::removeFile(const QString &path)
{
    QByteArray remote;
    Result r = resolve(path, &remote);
    if (!r.ok())
        return r;
    QVector<Reply> replies;
    r = command({ "DELE " + remote }, &replies, QStringLiteral("Removing a file"));
    if (!r.ok() || positive(replies.at(0)))
        return r;
    const Result failure = replyError(replies.at(0), QStringLiteral("Removing a file"));
    Entry existing;
    r = statRemote(remote, &existing);
    if (r.error() == Error::NotFound)
        return r;
    if (r.ok() && existing.type == EntryType::Directory)
        return Result(Error::IsADirectory, QStringLiteral("Removing a file: is a folder"), failure.detail());
    return failure;
}

Result FtpBackend::removeDir(const QString &path)
{
    QByteArray remote;
    Result r = resolve(path, &remote);
    if (!r.ok())
        return r;
    QVector<Reply> replies;
    r = command({ "RMD " + remote }, &replies, QStringLiteral("Removing a folder"));
    if (!r.ok() || positive(replies.at(0)))
        return r;
    const Result failure = replyError(replies.at(0), QStringLiteral("Removing a folder"));
    Entry existing;
    r = statRemote(remote, &existing);
    if (r.error() == Error::NotFound)
        return r;
    if (r.ok() && !existing.isDir())
        return Result(Error::NotADirectory, QStringLiteral("Removing a folder: not a folder"), failure.detail());
    CollectSink contents;
    if (r.ok() && listRemote(remote, &contents, ListOptions().batchSize).ok() && !contents.collected.isEmpty())
        return Result(Error::DirectoryNotEmpty, QStringLiteral("Removing a folder: not empty"), failure.detail());
    return failure;
}

// F-4 / XC-10: NoReplace through a stat check (racy, documented: no
// NativeNoReplace); Replace deletes the target first (no AtomicReplace).
Result FtpBackend::rename(const QString &from, const QString &to, RenameMode mode)
{
    QByteArray source;
    QByteArray target;
    Result r = resolve(from, &source);
    if (r.ok())
        r = resolve(to, &target);
    if (!r.ok())
        return r;
    Entry sourceEntry;
    r = statRemote(source, &sourceEntry);
    if (!r.ok() || source == target)
        return r;
    Entry targetEntry;
    r = statRemote(target, &targetEntry);
    if (r.ok()) {
        if (targetEntry.isDir())
            return Result(Error::AlreadyExists, QStringLiteral("Renaming: a folder of that name exists"));
        if (mode == RenameMode::NoReplace)
            return Result(Error::AlreadyExists, QStringLiteral("Renaming: the target exists"));
        QVector<Reply> deleted;
        r = command({ "DELE " + target }, &deleted, QStringLiteral("Replacing"));
        if (r.ok() && !positive(deleted.at(0)))
            r = replyError(deleted.at(0), QStringLiteral("Replacing"));
    } else if (r.error() == Error::NotFound) {
        r = Result::success();
    }
    if (!r.ok())
        return r;
    QVector<Reply> replies;
    r = command({ "RNFR " + source, "RNTO " + target }, &replies, QStringLiteral("Renaming"));
    if (!r.ok())
        return r;
    if (!positive(replies.at(0)))
        return replyError(replies.at(0), QStringLiteral("Renaming"));
    if (!positive(replies.at(1)))
        return uploadFailure(replyError(replies.at(1), QStringLiteral("Renaming")), target);
    return Result::success();
}

Result FtpBackend::chmod(const QByteArray &remote, qint32 mode)
{
    QVector<Reply> replies;
    Result r = command({ "SITE CHMOD " + QByteArray::number(mode & 07777, 8) + ' ' + remote }, &replies,
                       QStringLiteral("Changing permissions"));
    if (!r.ok() || positive(replies.at(0)))
        return r;
    r = replyError(replies.at(0), QStringLiteral("Changing permissions"));
    if (r.error() == Error::Unsupported) {
        // F-4: probed on first use; the capability may only go away.
        m_capabilities.flags.remove(Capability::PosixModes);
    }
    return r;
}

Result FtpBackend::applyModified(const QByteArray &remote, const QDateTime &modified)
{
    if (!m_capabilities.has(Capability::SetModified))
        return Result::success();
    QVector<Reply> replies;
    Result r = command({ "MFMT " + formatTimeVal(modified) + ' ' + remote }, &replies,
                       QStringLiteral("Setting the modification time"));
    if (r.ok() && !positive(replies.at(0)))
        r = replyError(replies.at(0), QStringLiteral("Setting the modification time"));
    return r;
}

Result FtpBackend::setAttributes(const QString &path, const AttributeChanges &changes)
{
    QByteArray remote;
    Result r = resolve(path, &remote);
    if (!r.ok())
        return r;
    // XC-11: check every field before changing anything.
    if (changes.accessed.isValid())
        return Result(Error::Unsupported, QStringLiteral("FTP cannot set access times"));
    if (changes.modified.isValid() && !m_capabilities.has(Capability::SetModified))
        return Result(Error::Unsupported, QStringLiteral("The server cannot set modification times (no MFMT)"));
    if (changes.mode >= 0 && !m_capabilities.has(Capability::PosixModes))
        return Result(Error::Unsupported, QStringLiteral("The server cannot change permissions"));
    if (changes.mode >= 0)
        r = chmod(remote, changes.mode);
    if (r.ok() && changes.modified.isValid())
        r = applyModified(remote, changes.modified);
    if (r.error() == Error::PermissionDenied || r.error() == Error::NotFound) {
        Entry existing;
        const Result s = statRemote(remote, &existing);
        if (s.error() == Error::NotFound)
            return s;
    }
    return r;
}

// --- transfers --------------------------------------------------------------

Result FtpBackend::readFailure(const Result &failure, const QByteArray &remote)
{
    if (failure.error() != Error::NotFound && failure.error() != Error::PermissionDenied)
        return failure;
    Entry existing;
    const Result s = statRemote(remote, &existing);
    if (s.error() == Error::NotFound)
        return s;
    if (s.ok() && existing.type == EntryType::Directory)
        return Result(Error::IsADirectory, QStringLiteral("Reading: is a folder"), failure.detail());
    return failure;
}

Result FtpBackend::uploadFailure(const Result &failure, const QByteArray &remote)
{
    if (failure.error() != Error::NotFound && failure.error() != Error::PermissionDenied
        && failure.error() != Error::InvalidName)
        return failure;
    Entry parent;
    Result s = statRemote(remoteParent(remote), &parent);
    if (s.error() == Error::NotFound)
        return Result(Error::NotFound, QStringLiteral("Writing: the folder does not exist"), failure.detail());
    if (s.ok() && !parent.isDir())
        return Result(Error::NotADirectory, QStringLiteral("Writing: the parent is not a folder"), failure.detail());
    Entry existing;
    s = statRemote(remote, &existing);
    if (s.ok() && existing.type == EntryType::Directory)
        return Result(Error::IsADirectory, QStringLiteral("Writing: is a folder"), failure.detail());
    return failure;
}

Result FtpBackend::openRead(const QString &path, ReadHandle **out)
{
    if (out)
        *out = nullptr;
    QByteArray remote;
    Result r = resolve(path, &remote);
    if (!r.ok())
        return r;
    Entry entry;
    r = statRemote(remote, &entry);
    if (!r.ok())
        return r;
    if (entry.type == EntryType::Directory)
        return Result(Error::IsADirectory, QStringLiteral("Reading: is a folder"));
    if (out)
        *out = new FtpReadHandle(this, remote, entry.size);
    return r;
}

// Checks and preparations shared by openWrite() and upload().
Result FtpBackend::prepareWrite(const QByteArray &remote, const WriteOptions &options)
{
    Entry existing;
    Result r = statRemote(remote, &existing);
    if (!r.ok() && r.error() != Error::NotFound)
        return r;
    const bool exists = r.ok();
    if ((exists && existing.type == EntryType::Directory) || remote.endsWith('/'))
        return Result(Error::IsADirectory, QStringLiteral("Writing: is a folder"));
    if (!exists) {
        Entry parent;
        r = statRemote(remoteParent(remote), &parent);
        if (r.error() == Error::NotFound)
            return Result(Error::NotFound, QStringLiteral("Writing: the folder does not exist"));
        if (!r.ok())
            return r;
        if (!parent.isDir())
            return Result(Error::NotADirectory, QStringLiteral("Writing: the parent is not a folder"));
    }
    switch (options.disposition) {
    case WriteOptions::CreateNew:
        if (exists)
            return Result(Error::AlreadyExists, QStringLiteral("Writing: the file exists"));
        break;
    case WriteOptions::Resume:
        if (!m_capabilities.has(Capability::WriteResume))
            return Result(Error::Unsupported, QStringLiteral("The server cannot resume uploads (no REST STREAM)"));
        if (!exists || existing.size != options.resumeOffset) {
            return Result(Error::ProtocolError, QStringLiteral("Cannot resume at %1: the partial file has %2 bytes")
                                                    .arg(options.resumeOffset).arg(exists ? existing.size : 0));
        }
        return Result::success();
    case WriteOptions::Truncate:
        break;
    }
    if (options.createMode < 0 || !m_capabilities.has(Capability::PosixModes))
        return Result::success();
    // XC-23: FTP has no mode at creation; create the file empty, set the mode,
    // then the data upload truncates it and keeps the mode.
    r = claim(nullptr);
    if (!r.ok())
        return r;
    EmptySource empty;
    Request request;
    request.kind = Request::Kind::Upload;
    request.path = remote;
    request.commands = prefixed({});
    r = m_connection->run(request, &empty, QStringLiteral("Creating the file"));
    requestDone();
    if (!r.ok())
        return uploadFailure(r, remote);
    r = chmod(remote, options.createMode);
    return r.error() == Error::Unsupported ? Result::success() : r;
}

Result FtpBackend::openWrite(const QString &path, const WriteOptions &options, WriteHandle **out)
{
    if (out)
        *out = nullptr;
    QByteArray remote;
    Result r = resolve(path, &remote);
    if (r.ok())
        r = ready();
    if (r.ok())
        r = prepareWrite(remote, options);
    if (!r.ok())
        return r;
    if (out)
        *out = new FtpWriteHandle(this, remote, options);
    return r;
}

Result FtpBackend::upload(QIODevice *source, const QString &path, const UploadOptions &options, Progress *progress)
{
    if (!source)
        return Result(Error::Internal, QStringLiteral("No source"));
    WriteHandle *raw = nullptr;
    Result r = openWrite(path, options.write, &raw);
    const std::unique_ptr<WriteHandle> handle(raw);
    if (!r.ok())
        return r;
    QByteArray buffer(int(UploadChunk), Qt::Uninitialized);
    const qint64 base = options.write.disposition == WriteOptions::Resume ? options.write.resumeOffset : 0;
    for (;;) {
        if (m_canceled || (progress && progress->canceled())) {
            handle->abort();
            return Result(Error::Canceled);
        }
        const qint64 n = source->read(buffer.data(), buffer.size());
        if (n < 0) {
            handle->abort();
            return Result(Error::Internal, QStringLiteral("Cannot read the local data"));
        }
        if (n == 0)
            break;
        r = handle->write(buffer.constData(), n);
        if (!r.ok()) {
            handle->abort();
            return r;
        }
        if (progress)
            progress->update(handle->position() - base, options.write.expectedSize);
    }
    return handle->commit();
}

Result FtpBackend::download(const QString &path, QIODevice *sink, const DownloadOptions &options, Progress *progress)
{
    if (!sink || options.offset < 0 || options.length < -1)
        return Result(Error::Internal, QStringLiteral("Invalid download"));
    QByteArray remote;
    Result r = resolve(path, &remote);
    if (r.ok())
        r = claim(nullptr);
    if (!r.ok() || options.length == 0)
        return r;
    if (remote.endsWith('/'))   // the root; a URL ending in '/' would be a listing
        return Result(Error::IsADirectory, QStringLiteral("Downloading: is a folder"));
    DownloadSink data(sink, progress);
    Request request;
    request.kind = Request::Kind::Download;
    request.path = remote;
    request.offset = options.offset;
    request.length = options.length;
    request.commands = prefixed({});
    r = m_connection->run(request, &data, QStringLiteral("Downloading"));
    requestDone();
    if (data.writeFailed())
        return Result(Error::Internal, QStringLiteral("Cannot write the local data"));
    if (!r.ok())
        return readFailure(r, remote);
    return r;
}

// XC-20 / F-6: NOOP; a control connection libcurl had to reopen means the
// previous one was dead.
Result FtpBackend::keepAlive()
{
    QVector<Reply> replies;
    Result r = command({ QByteArrayLiteral("NOOP") }, &replies, QStringLiteral("Keep-alive"));
    if (!r.ok())
        return r;
    if (m_connection->unexpectedReconnect())
        return Result(Error::ConnectionLost, QStringLiteral("The connection to the server was lost"));
    if (!positive(replies.at(0)))
        return replyError(replies.at(0), QStringLiteral("Keep-alive"));
    return r;
}

} // namespace NetVfs::Ftp
