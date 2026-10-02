// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbbackend.h"
#include "smb2api.h"

#include "logging.h"
#include "paths.h"

#include <QtCore/QElapsedTimer>
#include <QtCore/QIODevice>

#include <algorithm>
#include <limits>

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>

namespace NetVfs::Smb {

enum class CallKind { Plain, Open, OpenDir };

// One asynchronous libsmb2 request. Heap-allocated so that a request
// abandoned on cancel or timeout can complete later without touching freed
// memory: it then moves to SmbBackend::m_orphans and keeps its buffers.
struct Call {
    Call() = default;
    explicit Call(CallKind callKind) : kind(callKind) {}

    CallKind kind = CallKind::Plain;
    bool done = false;
    bool orphaned = false;
    int status = 0;
    quint32 ntStatus = 0;
    smb2fh *fh = nullptr;           // result of an Open
    smb2dir *dir = nullptr;         // result of an OpenDir
    smb2_stat_64 st = {};
    struct smb2_statvfs vfs = {};   // "struct": a function has the same name
    QByteArray buffer;
};

namespace {

const int DefaultPort = 445;
const int PollSliceMs = 100;
const char *const UserFileVariable = "NTLM_USER_FILE";

// libsmb2 completion callbacks have the C signature smb2_command_cb.
void ignoreCompletion(smb2_context *, int, void *, void *) // NOSONAR(cpp:S5008) C callback signature
{
}

void storeResult(Call *call, int status, void *commandData) // NOSONAR(cpp:S5008) libsmb2 result pointer
{
    if (status < 0 || !commandData)
        return;
    if (call->kind == CallKind::Open)
        call->fh = static_cast<smb2fh *>(commandData);
    else if (call->kind == CallKind::OpenDir)
        call->dir = static_cast<smb2dir *>(commandData);
}

void onComplete(smb2_context *ctx, int status, void *commandData, void *privateData) // NOSONAR(cpp:S5008)
{
    auto *call = static_cast<Call *>(privateData);
    storeResult(call, status, commandData);
    // A handle opened by a request that was abandoned is closed again.
    if (call->orphaned && call->fh)
        smb2_close_async(ctx, call->fh, ignoreCompletion, nullptr);
    if (call->orphaned && call->dir)
        smb2_closedir(ctx, call->dir);
    call->done = true;
    call->status = status;
    // SPEC-smb 5: the NT status is the only input to classification.
    call->ntStatus = static_cast<quint32>(smb2_get_nterror(ctx));
}

// libsmb2 writes with writev(); a peer that closed the connection would
// otherwise kill the whole process with SIGPIPE. The signal is blocked on
// this thread while libsmb2 runs and one raised meanwhile is discarded.
class SigPipeGuard
{
public:
    SigPipeGuard()
    {
        sigemptyset(&m_set);
        sigaddset(&m_set, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &m_set, &m_old);
    }
    ~SigPipeGuard()
    {
        const timespec zero = { 0, 0 };
        while (sigtimedwait(&m_set, nullptr, &zero) > 0) {
            // drain
        }
        pthread_sigmask(SIG_SETMASK, &m_old, nullptr);
    }
    SigPipeGuard(const SigPipeGuard &) = delete;
    SigPipeGuard &operator=(const SigPipeGuard &) = delete;

private:
    sigset_t m_set = {};
    sigset_t m_old = {};
};

Entry entryFrom(const QString &name, const smb2_stat_64 &st)
{
    Entry entry;
    entry.name = name;
    entry.size = static_cast<qint64>(st.smb2_size);
    entry.isDir = st.smb2_type == SMB2_TYPE_DIRECTORY;
    entry.modified = QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(st.smb2_mtime) * 1000
                                                        + static_cast<qint64>(st.smb2_mtime_nsec / 1000000),
                                                    Qt::UTC);
    return entry;
}

} // namespace

void neutraliseUserFile()
{
    if (!qEnvironmentVariableIsSet(UserFileVariable))
        return;
    qCWarning(lcNetVfsSmb) << "Ignoring NTLM_USER_FILE: the account's own password is used (SPEC-smb M-5)";
    qunsetenv(UserFileVariable);
}

SmbBackend::SmbBackend() = default;

SmbBackend::~SmbBackend()
{
    disconnect();
}

Result SmbBackend::connect(const ConnectionParams &params, ServerIdentity *seen)
{
    disconnect();
    // SMB has no server identity (SPEC-smb 3); signing keyed by the password
    // authenticates the server instead.
    if (seen)
        *seen = ServerIdentity();
    m_params = params;
    m_owner = std::this_thread::get_id();
    const int port = params.port > 0 ? params.port : DefaultPort;
    qCDebug(lcNetVfsSmb) << "Connecting to" << params.host << "port" << port;
    // M-10: only resolve and check that the port answers; the library call
    // needs the credentials and happens in authenticate().
    Result r = probeTcp(params.host, port, params.connectTimeoutMs, m_cancel, &m_address);
    m_probed = r.ok();
    return r;
}

Result SmbBackend::authenticate(const Credentials &credentials)
{
    if (!m_probed || m_ctx || std::this_thread::get_id() != m_owner)
        return Result(Error::Internal, QStringLiteral("authenticate() needs a successful connect() on this thread"));
    const QString share = m_params.option(QStringLiteral("share"));
    if (share.isEmpty())
        return Result(Error::NotFound, QStringLiteral("share not found: no share name is set"));
    const QString user = credentials.userName.isEmpty() ? m_params.username : credentials.userName;
    if (user.isEmpty() || credentials.secret.isEmpty())
        return Result(Error::AuthFailed, QStringLiteral("A user name and a password are required"));

    m_ctx = smb2_init_context();
    if (!m_ctx)
        return Result(Error::Internal, QStringLiteral("Cannot create an SMB context"));
    m_stage = Stage::SessionSetup;
    applyPolicy(user, credentials);

    const QByteArray server = serverString(m_address, m_params.port);
    const QByteArray shareName = share.toUtf8();
    qCDebug(lcNetVfsSmb) << "Signing in to share" << share << "as" << user;
    auto call = std::make_unique<Call>();
    Result r = request(call, [&server, &shareName](smb2_context *ctx, Call *c) {
        // The user is already set (applyPolicy); passing it again here would
        // make libsmb2 consult NTLM_USER_FILE once more.
        return smb2_connect_share_async(ctx, server.constData(), shareName.constData(), nullptr, onComplete, c);
    }, QStringLiteral("Sign-in failed"));
    // SEC-5: drop libsmb2's copy of the password as soon as it is not needed.
    smb2_set_password(m_ctx, nullptr);

    if (r.ok() && !isSmb3Dialect(smb2_get_dialect(m_ctx))) {
        // M-1, defence in depth: never accept a dialect that was not offered.
        r = Result(Error::SecurityPolicy, QStringLiteral("The server negotiated SMB %1; SMB 3 is required")
                                              .arg(dialectName(smb2_get_dialect(m_ctx))));
    }
    if (!r.ok()) {
        destroyContext();
        return r;
    }
    m_stage = Stage::Established;
    qCDebug(lcNetVfsSmb) << "Signed in, dialect" << dialectName(smb2_get_dialect(m_ctx));
    return r;
}

void SmbBackend::applyPolicy(const QString &user, const Credentials &credentials)
{
    // SPEC-smb section 3. Nothing here is configurable except M-3.
    smb2_set_version(m_ctx, SMB2_VERSION_ANY3);                                  // M-1
    smb2_set_security_mode(m_ctx, SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED); // M-2
    smb2_set_sign(m_ctx, 1);
    if (requireEncryption(m_params.options))                                    // M-3; off: not called
        smb2_set_seal(m_ctx, 1);
    smb2_set_authentication(m_ctx, SMB2_SEC_NTLMSSP);                            // M-4
    smb2_set_timeout(m_ctx, qMax(1, m_params.requestTimeoutMs / 1000));          // M-7

    // M-5: smb2_set_user() and smb2_set_domain() read NTLM_USER_FILE and may
    // replace the password, so the variable goes first and the password last.
    neutraliseUserFile();
    smb2_set_user(m_ctx, user.toUtf8().constData());
    if (const QString domain = m_params.option(QStringLiteral("domain")); !domain.isEmpty())
        smb2_set_domain(m_ctx, domain.toUtf8().constData());
    smb2_set_password(m_ctx, credentials.secret.constData());
}

Result SmbBackend::checkUsable() const
{
    if (!m_ctx)
        return Result(Error::Internal, QStringLiteral("Not signed in"));
    if (std::this_thread::get_id() != m_owner)          // M-13
        return Result(Error::Internal, QStringLiteral("An SMB connection is used from one thread only"));
    if (m_broken)
        return connectionLost(Stage::Established);
    return Result::success();
}

Result SmbBackend::request(std::unique_ptr<Call> &call, const Starter &start, const QString &context, Wait wait)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    if (wait == Wait::Cancellable && m_cancel)
        return Result(Error::Canceled);
    purgeOrphans();
    smb2_set_error(m_ctx, "");      // clears the NT status of an earlier request
    if (start(m_ctx, call.get()) < 0)
        return Result(Error::Internal, context + QStringLiteral(": ") + QString::fromUtf8(smb2_get_error(m_ctx)));
    const Result r = await(call, wait);
    if (r.error() == Error::Canceled)
        return r;
    if (!r.ok())
        return Result(r.error(), context + QStringLiteral(": ") + r.message());
    if (call->status < 0)
        return errorForStatus(call->ntStatus, -call->status, m_stage, context);
    return r;
}

Result SmbBackend::await(std::unique_ptr<Call> &call, Wait wait)
{
    const qint64 limitMs = wait == Wait::Drain ? DrainMs : qint64(m_params.requestTimeoutMs) + BackstopMs;
    const SigPipeGuard guard;
    QElapsedTimer clock;
    clock.start();
    while (!call->done) {
        // M-12, C-9: a cancel abandons the request at once.
        if (wait == Wait::Cancellable && m_cancel) {
            abandon(call);
            return Result(Error::Canceled);
        }
        if (clock.elapsed() > limitMs) {
            abandon(call);
            m_broken = m_broken || wait == Wait::Cancellable;
            return Result(Error::Timeout, QStringLiteral("the server did not answer in time"));
        }
        pollfd pfd = {};
        pfd.fd = smb2_get_fd(m_ctx);
        pfd.events = static_cast<short>(smb2_which_events(m_ctx));
        const int rc = ::poll(&pfd, 1, PollSliceMs);
        // Also called without events: libsmb2 expires timed-out requests there (M-7).
        if (smb2_service(m_ctx, rc > 0 ? pfd.revents : 0) >= 0)
            continue;
        m_broken = true;
        if (!call->done) {
            abandon(call);
            return connectionLost(m_stage);
        }
    }
    return Result::success();
}

void SmbBackend::abandon(std::unique_ptr<Call> &call)
{
    call->orphaned = true;
    m_orphans.push_back(std::move(call));
}

void SmbBackend::purgeOrphans()
{
    auto finished = [](const std::unique_ptr<Call> &call) { return call->done; };
    m_orphans.erase(std::remove_if(m_orphans.begin(), m_orphans.end(), finished), m_orphans.end());
}

void SmbBackend::destroyContext()
{
    if (m_ctx) {
        // Pending requests complete with a shutdown status here, so the
        // orphans they refer to must still exist.
        smb2_destroy_context(m_ctx);
        m_ctx = nullptr;
    }
    m_orphans.clear();
    m_broken = false;
    m_stage = Stage::SessionSetup;
}

Result SmbBackend::statPath(const QByteArray &path, Entry *out)
{
    auto call = std::make_unique<Call>();
    const Result r = request(call, [&path](smb2_context *ctx, Call *c) {
        return smb2_stat_async(ctx, path.constData(), &c->st, onComplete, c);
    }, QStringLiteral("stat"));
    if (r.ok() && out)
        *out = entryFrom(Paths::fileName(QString::fromUtf8(path)), call->st);
    return r;
}

Result SmbBackend::unlinkPath(const QByteArray &path, const QString &context)
{
    auto call = std::make_unique<Call>();
    return request(call, [&path](smb2_context *ctx, Call *c) {
        return smb2_unlink_async(ctx, path.constData(), onComplete, c);
    }, context);
}

Result SmbBackend::stat(const QString &path, Entry *out)
{
    QByteArray p;
    if (Result r = translatePath(path, &p); !r.ok())
        return r;
    return statPath(p, out);
}

Result SmbBackend::list(const QString &dir, QVector<Entry> *out)
{
    QByteArray p;
    if (Result r = translatePath(dir, &p); !r.ok())
        return r;
    auto call = std::make_unique<Call>(CallKind::OpenDir);
    const Result r = request(call, [&p](smb2_context *ctx, Call *c) {
        return smb2_opendir_async(ctx, p.constData(), onComplete, c);
    }, QStringLiteral("list"));
    if (!r.ok())
        return r;
    QVector<Entry> entries;
    while (const smb2dirent *ent = smb2_readdir(m_ctx, call->dir)) {
        const QString name = QString::fromUtf8(ent->name);
        if (name != QLatin1String(".") && name != QLatin1String(".."))
            entries.append(entryFrom(name, ent->st));
    }
    smb2_closedir(m_ctx, call->dir);
    if (out)
        *out = entries;
    return r;
}

Result SmbBackend::makeDir(const QByteArray &path)
{
    Entry entry;
    Result r = statPath(path, &entry);
    if (r.error() == Error::NotFound) {
        auto call = std::make_unique<Call>();
        r = request(call, [&path](smb2_context *ctx, Call *c) {
            return smb2_mkdir_async(ctx, path.constData(), onComplete, c);
        }, QStringLiteral("create folder"));
        if (r.error() != Error::AlreadyExists)
            return r;
        r = statPath(path, &entry);     // created concurrently by someone else
    }
    if (r.ok() && !entry.isDir)
        return Result(Error::AlreadyExists, QStringLiteral("create folder: a file has the folder's name"));
    return r;
}

Result SmbBackend::makePath(const QString &dir)
{
    QByteArray p;
    Result r = translatePath(dir, &p);
    QByteArray prefix;
    for (const QByteArray &component : p.split('/')) {
        if (!r.ok())
            break;
        if (component.isEmpty())
            continue;
        prefix = prefix.isEmpty() ? component : prefix + '/' + component;
        r = makeDir(prefix);
    }
    return r;
}

Result SmbBackend::remove(const QString &path)
{
    QByteArray p;
    if (Result r = translatePath(path, &p); !r.ok())
        return r;
    return unlinkPath(p, QStringLiteral("remove"));
}

Result SmbBackend::rename(const QString &from, const QString &to)
{
    QByteArray f;
    QByteArray t;
    Result r = translatePath(from, &f);
    if (r.ok())
        r = translatePath(to, &t);
    if (r.ok())
        r = statPath(f, nullptr);
    if (!r.ok())
        return r;

    // libsmb2 renames without ReplaceIfExists: remove the target first.
    Entry target;
    r = statPath(t, &target);
    if (r.ok() && target.isDir)
        return Result(Error::AlreadyExists, QStringLiteral("rename: the target is a folder"));
    if (r.ok())
        r = unlinkPath(t, QStringLiteral("replace"));
    if (r.error() == Error::NotFound)
        r = Result::success();
    if (!r.ok())
        return r;

    auto call = std::make_unique<Call>();
    return request(call, [&f, &t](smb2_context *ctx, Call *c) {
        return smb2_rename_async(ctx, f.constData(), t.constData(), onComplete, c);
    }, QStringLiteral("rename"));
}

Result SmbBackend::freeSpace(const QString &dir, qint64 *bytes)
{
    QByteArray p;
    if (Result r = translatePath(dir, &p); !r.ok())
        return r;
    auto call = std::make_unique<Call>();
    const Result r = request(call, [&p](smb2_context *ctx, Call *c) {
        return smb2_statvfs_async(ctx, p.constData(), &c->vfs, onComplete, c);
    }, QStringLiteral("free space"));
    if (r.ok() && bytes) {
        const quint64 unit = call->vfs.f_bsize;
        const quint64 units = call->vfs.f_bavail;
        constexpr quint64 limit = quint64(std::numeric_limits<qint64>::max());
        *bytes = (unit && units > limit / unit) ? std::numeric_limits<qint64>::max()
                                                : static_cast<qint64>(units * unit);
    }
    return r;
}

Result SmbBackend::openFile(const QByteArray &path, int flags, smb2fh **fh)
{
    auto call = std::make_unique<Call>(CallKind::Open);
    const Result r = request(call, [&path, flags](smb2_context *ctx, Call *c) {
        return smb2_open_async(ctx, path.constData(), flags, onComplete, c);
    }, QStringLiteral("open"));
    if (r.ok())
        *fh = call->fh;
    return r;
}

Result SmbBackend::closeFile(smb2fh *fh, const Result &outcome)
{
    // After a failure or a cancel the handle is still closed, but within a
    // bounded time (C-9), and the first error is what the caller sees.
    auto call = std::make_unique<Call>();
    const Result r = request(call, [fh](smb2_context *ctx, Call *c) {
        return smb2_close_async(ctx, fh, onComplete, c);
    }, QStringLiteral("close"), outcome.ok() ? Wait::Cancellable : Wait::Drain);
    return outcome.ok() ? r : outcome;
}

Result SmbBackend::writeChunk(smb2fh *fh, const QByteArray &buffer, qint64 length, quint64 offset)
{
    qint64 written = 0;
    while (written < length) {
        auto call = std::make_unique<Call>();
        call->buffer = buffer;      // shared: stays valid if the request is abandoned
        const auto *data = reinterpret_cast<const uint8_t *>(call->buffer.constData()) + written;
        const auto count = static_cast<quint32>(length - written);
        const quint64 at = offset + quint64(written);
        const Result r = request(call, [fh, data, count, at](smb2_context *ctx, Call *c) {
            return smb2_pwrite_async(ctx, fh, data, count, at, onComplete, c);
        }, QStringLiteral("write"));
        if (!r.ok())
            return r;
        if (call->status == 0)
            return Result(Error::ProtocolError, QStringLiteral("write: the server accepted no data"));
        written += call->status;
    }
    return Result::success();
}

Result SmbBackend::writeAll(smb2fh *fh, QIODevice *source, Progress *progress)
{
    const quint32 chunk = chunkSize(smb2_get_max_write_size(m_ctx));     // M-11
    QByteArray buffer(static_cast<int>(chunk), Qt::Uninitialized);
    const qint64 total = source->size();
    quint64 offset = 0;
    for (;;) {
        if (m_cancel)
            return Result(Error::Canceled);
        const qint64 n = source->read(buffer.data(), chunk);
        if (n < 0)
            return Result(Error::Internal, QStringLiteral("Cannot read the data to upload"));
        if (n == 0)
            return Result::success();
        if (Result r = writeChunk(fh, buffer, n, offset); !r.ok())
            return r;
        offset += quint64(n);
        if (progress)
            progress->update(qint64(offset), total);
    }
}

Result SmbBackend::upload(QIODevice *source, const QString &path, Progress *progress)
{
    QByteArray p;
    Result r = translatePath(path, &p);
    smb2fh *fh = nullptr;
    if (r.ok())
        r = openFile(p, O_WRONLY | O_CREAT | O_TRUNC, &fh);
    if (!r.ok())
        return r;
    r = writeAll(fh, source, progress);
    if (r.ok()) {
        // C-12: flush to stable storage before the size check and rename.
        auto call = std::make_unique<Call>();
        r = request(call, [fh](smb2_context *ctx, Call *c) {
            return smb2_fsync_async(ctx, fh, onComplete, c);
        }, QStringLiteral("flush"));
    }
    return closeFile(fh, r);
}

Result SmbBackend::readChunk(smb2fh *fh, quint64 offset, quint32 count, QByteArray *buffer, quint32 *got)
{
    auto call = std::make_unique<Call>();
    call->buffer.swap(*buffer);     // owned by the request while it runs
    if (call->buffer.size() < static_cast<int>(count))
        call->buffer.resize(static_cast<int>(count));
    auto *data = reinterpret_cast<uint8_t *>(call->buffer.data());
    const Result r = request(call, [fh, data, count, offset](smb2_context *ctx, Call *c) {
        return smb2_pread_async(ctx, fh, data, count, offset, onComplete, c);
    }, QStringLiteral("read"));
    if (!r.ok())
        return r;
    buffer->swap(call->buffer);
    *got = qMin(static_cast<quint32>(call->status), count);
    return r;
}

Result SmbBackend::fileSize(smb2fh *fh, qint64 *size)
{
    auto call = std::make_unique<Call>();
    const Result r = request(call, [fh](smb2_context *ctx, Call *c) {
        return smb2_fstat_async(ctx, fh, &c->st, onComplete, c);
    }, QStringLiteral("stat"));
    if (r.ok())
        *size = static_cast<qint64>(call->st.smb2_size);
    return r;
}

Result SmbBackend::copyToSink(smb2fh *fh, qint64 size, QIODevice *sink, Progress *progress)
{
    const quint32 chunk = chunkSize(smb2_get_max_read_size(m_ctx));      // M-11
    QByteArray buffer;
    qint64 offset = 0;
    while (offset < size) {
        quint32 got = 0;
        const auto want = static_cast<quint32>(qMin<qint64>(chunk, size - offset));
        if (Result r = readChunk(fh, quint64(offset), want, &buffer, &got); !r.ok())
            return r;
        if (got == 0)
            break;      // the file shrank; the caller compares sizes
        if (sink->write(buffer.constData(), got) != qint64(got))
            return Result(Error::Internal, QStringLiteral("Cannot store the downloaded data"));
        offset += got;
        if (progress)
            progress->update(offset, size);
    }
    return Result::success();
}

Result SmbBackend::download(const QString &path, QIODevice *sink, Progress *progress)
{
    QByteArray p;
    Result r = translatePath(path, &p);
    smb2fh *fh = nullptr;
    if (r.ok())
        r = openFile(p, O_RDONLY, &fh);
    if (!r.ok())
        return r;
    qint64 size = 0;
    r = fileSize(fh, &size);
    if (r.ok())
        r = copyToSink(fh, size, sink, progress);
    return closeFile(fh, r);
}

Result SmbBackend::readRange(smb2fh *fh, qint64 offset, qint64 length, QByteArray *out)
{
    const quint32 chunk = chunkSize(smb2_get_max_read_size(m_ctx));
    QByteArray buffer;
    QByteArray result;
    while (result.size() < length) {
        quint32 got = 0;
        const auto want = static_cast<quint32>(qMin<qint64>(chunk, length - result.size()));
        if (Result r = readChunk(fh, quint64(offset + result.size()), want, &buffer, &got); !r.ok())
            return r;
        if (got == 0)
            break;
        result.append(buffer.constData(), static_cast<int>(got));
    }
    *out = result;
    return Result::success();
}

Result SmbBackend::read(const QString &path, qint64 offset, qint64 length, QByteArray *out)
{
    if (offset < 0 || length < 0 || length > std::numeric_limits<int>::max())
        return Result(Error::Internal, QStringLiteral("read: invalid range"));
    QByteArray p;
    Result r = translatePath(path, &p);
    smb2fh *fh = nullptr;
    if (r.ok())
        r = openFile(p, O_RDONLY, &fh);
    if (!r.ok())
        return r;
    QByteArray data;
    r = closeFile(fh, readRange(fh, offset, length, &data));
    if (r.ok() && out)
        *out = data;
    return r;
}

void SmbBackend::cancel()
{
    m_cancel = true;
}

void SmbBackend::resetCancel()
{
    m_cancel = false;
}

void SmbBackend::disconnect()
{
    if (m_ctx && !m_broken && m_stage == Stage::Established && std::this_thread::get_id() == m_owner) {
        auto call = std::make_unique<Call>();
        request(call, [](smb2_context *ctx, Call *c) {
            return smb2_disconnect_share_async(ctx, onComplete, c);
        }, QStringLiteral("disconnect"), Wait::Drain);
    }
    destroyContext();
    m_probed = false;
}

} // namespace NetVfs::Smb
