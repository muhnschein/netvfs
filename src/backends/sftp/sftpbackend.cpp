// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sftpbackend.h"
#include "logging.h"
#include "paths.h"
#include "secure.h"
#include "sftpsupport.h"
#include "sshkeys.h"
#include "sshutil.h"

#include <QtCore/QIODevice>

#include <deque>
#include <fcntl.h>
#include <limits>

namespace NetVfs::Sftp {

namespace {

constexpr const char *HostKeyOption = "host_key";
constexpr const char *AuthModeOption = "auth_mode";
constexpr const char *NullDevice = "/dev/null";
constexpr int DefaultPort = 22;
constexpr int DefaultConnectTimeoutMs = 15000;   // C-14
constexpr int DefaultRequestTimeoutMs = 60000;   // C-14
constexpr int PollIntervalMs = 100;
// Closing a handle after a cancel or timeout must not undo C-9's 2 s bound.
constexpr int CleanupTimeoutMs = 1000;
constexpr int MaxKeyboardInteractiveRounds = 8;
constexpr mode_t DirectoryMode = 0700;   // S-20
constexpr mode_t FileMode = 0600;        // S-20

QString text(const char *value)
{
    return value ? QString::fromUtf8(value) : QString();
}

QString display(const QByteArray &remote)
{
    return QString::fromUtf8(remote);
}

Entry entryFrom(const sftp_attributes_struct &attributes, const QString &name)
{
    Entry entry;
    entry.name = name;
    entry.size = static_cast<qint64>(attributes.size);
    entry.isDir = attributes.type == SSH_FILEXFER_TYPE_DIRECTORY;
    if (attributes.flags & SSH_FILEXFER_ATTR_ACMODTIME)
        entry.modified = QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(attributes.mtime) * 1000, Qt::UTC);
    return entry;
}

// Reads up to `size` bytes; fewer only at the end of the source. -1 on error.
qint64 readFully(QIODevice *source, char *data, qint64 size)
{
    qint64 done = 0;
    while (done < size) {
        const qint64 n = source->read(data + done, size - done);
        if (n < 0)
            return -1;
        if (n == 0)
            break;
        done += n;
    }
    return done;
}

bool supported(sftp_session sftp, const char *extension, const char *version)
{
    return sftp_extension_supported(sftp, extension, version) != 0;
}

} // namespace

// Outstanding asynchronous requests, oldest first. Requests still queued when
// a transfer ends early are released with sftp_aio_free() (SPEC-sftp 7).
class SftpBackend::PendingQueue
{
public:
    PendingQueue() = default;
    PendingQueue(const PendingQueue &) = delete;
    PendingQueue &operator=(const PendingQueue &) = delete;
    ~PendingQueue()
    {
        for (const Pending &pending : m_queue)
            sftp_aio_free(pending.aio);
    }

    bool full() const { return m_queue.size() >= RequestWindow; }
    bool empty() const { return m_queue.empty(); }
    void push(const Pending &pending) { m_queue.push_back(pending); }
    Pending take()
    {
        const Pending pending = m_queue.front();
        m_queue.pop_front();
        return pending;
    }

private:
    std::deque<Pending> m_queue;
};

SftpBackend::~SftpBackend()
{
    disconnect();
}

void SftpBackend::configureSession(ssh_session session)
{
    Q_UNUSED(session)
}

// --- connection -------------------------------------------------------------

Result SftpBackend::connect(const ConnectionParams &params, ServerIdentity *seen)
{
    disconnect();
    if (m_canceled)
        return Result(Error::Canceled);
    if (params.host.isEmpty() || params.host.contains(QLatin1Char('@')))
        return Result(Error::Internal, QStringLiteral("Invalid server name"));
    ensureLibraryInitialized();

    m_params = params;
    if (m_params.connectTimeoutMs <= 0)
        m_params.connectTimeoutMs = DefaultConnectTimeoutMs;
    if (m_params.requestTimeoutMs <= 0)
        m_params.requestTimeoutMs = DefaultRequestTimeoutMs;

    const bool pinned = !params.option(QLatin1String(HostKeyOption)).isEmpty();
    Result r = openTransport(pinned, seen);
    if (!r.ok() && pinned && m_session && isHostKeyMismatch(text(ssh_get_error(m_session)))) {
        // The server no longer offers the pinned key type (S-5). Connect once
        // more without the restriction, so that the caller sees the key the
        // server presents now and reports ServerIdentityChanged (S-7).
        disconnect();
        r = openTransport(false, seen);
    }
    if (r.ok() && m_canceled)
        r = Result(Error::Canceled);
    if (!r.ok())
        disconnect();
    return r;
}

Result SftpBackend::openTransport(bool restrictHostKey, ServerIdentity *seen)
{
    m_session = ssh_new();
    if (!m_session)
        return Result(Error::Internal, QStringLiteral("Out of memory"));
    if (const Result r = applyOptions(restrictHostKey); !r.ok())
        return r;
    configureSession(m_session);

    qCDebug(lcNetVfsSftp) << "Connecting to" << m_params.host << "port" << m_params.port;
    // S-3: no ssh_session_is_known_server(); the caller compares the pin.
    if (ssh_connect(m_session) != SSH_OK)
        return sessionFailure();

    ssh_key key = nullptr;
    if (ssh_get_server_publickey(m_session, &key) != SSH_OK)
        return sessionFailure();
    const KeyPtr serverKey(key);
    const ServerIdentity identity = identityOf(serverKey.get());
    if (seen)
        *seen = identity;
    // SEC-1: even a caller that skips the identity check cannot sign in to a
    // server whose key differs from the pin.
    const QString pin = m_params.option(QLatin1String(HostKeyOption));
    m_identityMismatch = !pin.isEmpty() && ServerIdentity::fromPin(pin) != identity;

    qCDebug(lcNetVfsSftp) << "Key exchange" << ssh_get_kex_algo(m_session)
                          << "cipher" << ssh_get_cipher_out(m_session)
                          << "host key" << identity.algorithm << identity.fingerprint;
    return Result::success();
}

Result SftpBackend::applyOptions(bool restrictHostKey) const
{
    // S-1. Algorithm lists stay at libssh defaults (S-2); S-5 only narrows
    // the host key algorithms to the pinned type.
    const bool processConfig = false;
    const int port = m_params.port > 0 ? m_params.port : DefaultPort;
    const QByteArray host = m_params.host.toUtf8();
    const QByteArray user = m_params.username.toUtf8();
    bool ok = ssh_options_set(m_session, SSH_OPTIONS_PROCESS_CONFIG, &processConfig) == SSH_OK
            && ssh_options_set(m_session, SSH_OPTIONS_HOST, host.constData()) == SSH_OK
            && ssh_options_set(m_session, SSH_OPTIONS_PORT, &port) == SSH_OK
            && ssh_options_set(m_session, SSH_OPTIONS_KNOWNHOSTS, NullDevice) == SSH_OK
            && ssh_options_set(m_session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, NullDevice) == SSH_OK
            && ssh_options_set(m_session, SSH_OPTIONS_COMPRESSION, "no") == SSH_OK
            && setTimeout(m_params.connectTimeoutMs);
    if (ok && !user.isEmpty())
        ok = ssh_options_set(m_session, SSH_OPTIONS_USER, user.constData()) == SSH_OK;
    if (ok && restrictHostKey) {
        const ServerIdentity pinned = ServerIdentity::fromPin(m_params.option(QLatin1String(HostKeyOption)));
        if (const QByteArray algorithms = hostKeyAlgorithmsFor(pinned.algorithm); !algorithms.isEmpty())
            ok = ssh_options_set(m_session, SSH_OPTIONS_HOSTKEYS, algorithms.constData()) == SSH_OK;
    }
    if (!ok)
        return Result(Error::Internal, QStringLiteral("Cannot apply connection settings: %1")
                                           .arg(text(ssh_get_error(m_session))));
    return Result::success();
}

bool SftpBackend::setTimeout(int milliseconds) const
{
    const long seconds = milliseconds / 1000;
    const long microseconds = static_cast<long>(milliseconds % 1000) * 1000;
    return ssh_options_set(m_session, SSH_OPTIONS_TIMEOUT, &seconds) == SSH_OK
            && ssh_options_set(m_session, SSH_OPTIONS_TIMEOUT_USEC, &microseconds) == SSH_OK;
}

Result SftpBackend::sessionFailure() const
{
    return connectFailure(text(ssh_get_error(m_session)));
}

void SftpBackend::disconnect()
{
    if (m_sftp) {
        sftp_free(m_sftp);
        m_sftp = nullptr;
    }
    if (m_session) {
        if (ssh_is_connected(m_session))
            ssh_disconnect(m_session);
        ssh_free(m_session);
        m_session = nullptr;
    }
    m_home.clear();
    m_identityMismatch = false;
    m_hasFsync = false;
    m_hasStatvfs = false;
    m_hasPosixRename = false;
}

void SftpBackend::cancel()
{
    m_canceled = true;
}

void SftpBackend::resetCancel()
{
    m_canceled = false;
}

// --- authentication ---------------------------------------------------------

Result SftpBackend::authenticate(const Credentials &credentials)
{
    if (!m_session || m_sftp)
        return Result(Error::Internal, QStringLiteral("authenticate() needs a fresh connection"));
    if (m_identityMismatch)
        return Result(Error::ServerIdentityChanged,
                      QStringLiteral("The server key does not match the saved key; not signing in"));
    if (m_canceled)
        return Result(Error::Canceled);

    const QString mode = m_params.option(QLatin1String(AuthModeOption), QLatin1String(AuthModePassword));
    Result r = checkSecretForMode(mode, credentials.secret);
    if (!r.ok())
        return r;
    if (const QByteArray user = credentials.userName.toUtf8(); !user.isEmpty())
        ssh_options_set(m_session, SSH_OPTIONS_USER, user.constData());

    // S-10: learn the offered methods, then use exactly one.
    const int rc = ssh_userauth_none(m_session, nullptr);
    if (rc == SSH_AUTH_ERROR)
        return sessionFailure();
    if (rc != SSH_AUTH_SUCCESS)
        r = authenticateWith(ssh_userauth_list(m_session, nullptr), credentials.secret);
    if (r.ok())
        r = openSftp();
    if (r.ok() && !setTimeout(m_params.requestTimeoutMs))
        r = Result(Error::Internal, QStringLiteral("Cannot set the timeout"));
    return r;
}

Result SftpBackend::authenticateWith(int methods, const QByteArray &secret) const
{
    if (m_params.option(QLatin1String(AuthModeOption)) == QLatin1String(AuthModePublicKey))
        return authPublicKey(methods, secret);
    return authPassword(methods, secret);
}

Result SftpBackend::authPassword(int methods, const QByteArray &secret) const
{
    // S-11. QByteArray data is NUL terminated.
    const auto mask = static_cast<unsigned>(methods);
    if (mask & SSH_AUTH_METHOD_PASSWORD)
        return authOutcome(ssh_userauth_password(m_session, nullptr, secret.constData()));
    if (mask & SSH_AUTH_METHOD_INTERACTIVE)
        return authKeyboardInteractive(secret);
    return authDenied(methods);
}

Result SftpBackend::authKeyboardInteractive(const QByteArray &secret) const
{
    // S-11: the password answers a single non-echo prompt; rounds without
    // prompts (OpenSSH sends one after PAM succeeds) are acknowledged.
    bool answered = false;
    int rc = ssh_userauth_kbdint(m_session, nullptr, nullptr);
    for (int round = 0; rc == SSH_AUTH_INFO && round < MaxKeyboardInteractiveRounds; ++round) {
        if (const int prompts = ssh_userauth_kbdint_getnprompts(m_session); prompts > 0) {
            char echo = 1;
            ssh_userauth_kbdint_getprompt(m_session, 0, &echo);
            if (prompts != 1 || echo || answered)
                return interactiveNotSupported();
            if (ssh_userauth_kbdint_setanswer(m_session, 0, secret.constData()) < 0)
                return sessionFailure();
            answered = true;
        }
        rc = ssh_userauth_kbdint(m_session, nullptr, nullptr);
    }
    if (rc == SSH_AUTH_INFO)
        return interactiveNotSupported();
    return authOutcome(rc);
}

Result SftpBackend::authPublicKey(int methods, const QByteArray &secret) const
{
    // S-12: the key comes from memory only; never from ~/.ssh or an agent (S-3).
    if (!(static_cast<unsigned>(methods) & SSH_AUTH_METHOD_PUBLICKEY))
        return authDenied(methods);
    QByteArray privateKey;
    decodeKeySecret(secret, &privateKey);
    KeyPtr key;
    const Result r = importPrivateKey(privateKey, QByteArray(), &key);
    secureWipe(privateKey);
    if (!r.ok())
        return Result(Error::AuthFailed, QStringLiteral("The stored SSH key cannot be used"));
    return authOutcome(ssh_userauth_publickey(m_session, nullptr, key.get()));
}

Result SftpBackend::authOutcome(int rc) const
{
    switch (rc) {
    case SSH_AUTH_SUCCESS:
        return Result::success();
    case SSH_AUTH_PARTIAL:
        return authPartial();                                       // S-13
    case SSH_AUTH_DENIED:
        return authDenied(ssh_userauth_list(m_session, nullptr));   // S-14
    default:
        return sessionFailure();
    }
}

Result SftpBackend::openSftp()
{
    // S-3: only the sftp subsystem; never a shell or exec channel.
    m_sftp = sftp_new(m_session);
    if (!m_sftp)
        return subsystemFailure(ssh_get_error_code(m_session) == SSH_REQUEST_DENIED, SSH_FX_OK,
                                text(ssh_get_error(m_session)));
    if (sftp_init(m_sftp) != SSH_OK) {
        const Result r = subsystemFailure(false, sftp_get_error(m_sftp), text(ssh_get_error(m_session)));
        sftp_free(m_sftp);
        m_sftp = nullptr;
        return r;
    }

    m_hasFsync = supported(m_sftp, "fsync@openssh.com", "1");
    m_hasStatvfs = supported(m_sftp, "statvfs@openssh.com", "2");
    m_hasPosixRename = supported(m_sftp, "posix-rename@openssh.com", "1");
    const bool hasLimits = supported(m_sftp, "limits@openssh.com", "1");
    uint64_t writeLimit = 0;
    uint64_t readLimit = 0;
    if (sftp_limits_t limits = hasLimits ? sftp_limits(m_sftp) : nullptr) {
        writeLimit = limits->max_write_length;
        readLimit = limits->max_read_length;
        sftp_limits_free(limits);
    }
    m_writeChunk = chunkSize(hasLimits, writeLimit);   // S-21
    m_readChunk = chunkSize(hasLimits, readLimit);

    // S-19: relative paths are relative to the start directory, resolved once.
    char *home = sftp_canonicalize_path(m_sftp, ".");
    m_home = home ? QByteArray(home) : QByteArray();
    ssh_string_free_char(home);

    qCDebug(lcNetVfsSftp) << "SFTP version" << sftp_server_version(m_sftp) << "fsync" << m_hasFsync
                          << "statvfs" << m_hasStatvfs << "posix-rename" << m_hasPosixRename
                          << "chunk" << m_writeChunk << m_readChunk << "start" << m_home;
    return Result::success();
}

// --- helpers ----------------------------------------------------------------

Result SftpBackend::checkReady() const
{
    if (!m_sftp)
        return Result(Error::Internal, QStringLiteral("Not signed in"));
    if (m_canceled)
        return Result(Error::Canceled);
    return Result::success();
}

Result SftpBackend::resolve(const QString &path, QByteArray *remote) const
{
    QString normalized;
    if (const Result r = Paths::normalize(path, &normalized); !r.ok())   // C-15
        return r;
    if (Paths::isAbsolute(normalized))
        *remote = normalized.toUtf8();
    else if (normalized.isEmpty())
        *remote = m_home.isEmpty() ? QByteArray(".") : m_home;
    else if (m_home.isEmpty())
        *remote = normalized.toUtf8();
    else
        *remote = Paths::join(display(m_home), normalized).toUtf8();
    return Result::success();
}

Result SftpBackend::sftpFailure(const QString &context) const
{
    return sftpStatusFailure(sftp_get_error(m_sftp), text(ssh_get_error(m_session)), context);
}

Result SftpBackend::writeFailure(const QByteArray &remote, qint64 attempted) const
{
    const int status = sftp_get_error(m_sftp);
    const Result failure = sftpFailure(display(remote));
    if (status != SSH_FX_FAILURE || !m_hasStatvfs || m_canceled)
        return failure;
    qint64 available = -1;
    if (!freeBytes(remote, &available).ok() || !looksLikeFullDisk(status, available, attempted))
        return failure;
    return Result(Error::NoSpace, QStringLiteral("The server has no space left for %1").arg(display(remote)));
}

// --- metadata ---------------------------------------------------------------

Result SftpBackend::statRemote(const QByteArray &remote, Entry *out) const
{
    sftp_attributes attributes = sftp_stat(m_sftp, remote.constData());
    if (!attributes)
        return sftpFailure(display(remote));
    if (out)
        *out = entryFrom(*attributes, Paths::fileName(display(remote)));
    sftp_attributes_free(attributes);
    return Result::success();
}

Result SftpBackend::stat(const QString &path, Entry *out)
{
    QByteArray remote;
    Result r = checkReady();
    if (r.ok())
        r = resolve(path, &remote);
    if (r.ok())
        r = statRemote(remote, out);
    return r;
}

Result SftpBackend::list(const QString &dir, QVector<Entry> *out)
{
    QByteArray remote;
    Result r = checkReady();
    if (r.ok())
        r = resolve(dir, &remote);
    if (!r.ok())
        return r;
    sftp_dir handle = sftp_opendir(m_sftp, remote.constData());
    if (!handle)
        return sftpFailure(display(remote));
    out->clear();
    while (sftp_attributes attributes = sftp_readdir(m_sftp, handle)) {
        if (const QString name = text(attributes->name); name != QLatin1String(".") && name != QLatin1String(".."))
            out->append(entryFrom(*attributes, name));
        sftp_attributes_free(attributes);
    }
    if (!sftp_dir_eof(handle))
        r = sftpFailure(display(remote));
    sftp_closedir(handle);
    return r;
}

Result SftpBackend::makeDirectory(const QByteArray &remote) const
{
    Entry entry;
    Result r = statRemote(remote, &entry);
    if (r.ok()) {
        return entry.isDir ? r : Result(Error::AlreadyExists,
                                        QStringLiteral("%1 exists and is not a folder").arg(display(remote)));
    }
    if (r.error() != Error::NotFound)
        return r;
    if (sftp_mkdir(m_sftp, remote.constData(), DirectoryMode) == 0)   // S-20
        return Result::success();
    r = sftpFailure(display(remote));
    // OpenSSH reports EEXIST as a plain failure; a concurrent creator is fine.
    if (statRemote(remote, &entry).ok() && entry.isDir)
        return Result::success();
    return r;
}

Result SftpBackend::makePath(const QString &dir)
{
    QByteArray remote;
    Result r = checkReady();
    if (r.ok())
        r = resolve(dir, &remote);
    if (!r.ok())
        return r;
    if (Entry entry; statRemote(remote, &entry).ok() && entry.isDir)
        return Result::success();

    const QString full = display(remote);
    QString prefix = Paths::isAbsolute(full) ? QStringLiteral("/") : QString();
    for (const QString &component : Paths::components(full)) {
        prefix = Paths::join(prefix, component);
        r = makeDirectory(prefix.toUtf8());
        if (!r.ok())
            return r;
    }
    return r;
}

Result SftpBackend::removeRemote(const QByteArray &remote) const
{
    if (sftp_unlink(m_sftp, remote.constData()) == 0)
        return Result::success();
    const Result failure = sftpFailure(display(remote));
    if (Entry entry; failure.error() == Error::NotFound || !statRemote(remote, &entry).ok() || !entry.isDir)
        return failure;
    if (sftp_rmdir(m_sftp, remote.constData()) == 0)
        return Result::success();
    return sftpFailure(display(remote));
}

Result SftpBackend::remove(const QString &path)
{
    QByteArray remote;
    Result r = checkReady();
    if (r.ok())
        r = resolve(path, &remote);
    if (r.ok())
        r = removeRemote(remote);
    return r;
}

Result SftpBackend::rename(const QString &from, const QString &to)
{
    QByteArray source;
    QByteArray target;
    Result r = checkReady();
    if (r.ok())
        r = resolve(from, &source);
    if (r.ok())
        r = resolve(to, &target);
    if (!r.ok())
        return r;
    // With posix-rename@openssh.com, libssh's sftp_rename() replaces the
    // target atomically. Plain SFTP rename does not replace (S-22, 7).
    if (!m_hasPosixRename) {
        r = statRemote(target, nullptr);
        if (r.ok() && sftp_unlink(m_sftp, target.constData()) != 0)
            return sftpFailure(display(target));
        if (!r.ok() && r.error() != Error::NotFound)
            return r;
    }
    if (sftp_rename(m_sftp, source.constData(), target.constData()) != 0)
        return sftpFailure(display(source));
    return Result::success();
}

Result SftpBackend::freeBytes(const QByteArray &remote, qint64 *bytes) const
{
    sftp_statvfs_t info = sftp_statvfs(m_sftp, remote.constData());
    if (!info)
        return sftpFailure(display(remote));
    const uint64_t unit = info->f_frsize ? info->f_frsize : info->f_bsize;
    const auto limit = static_cast<uint64_t>(std::numeric_limits<qint64>::max());
    const uint64_t available = (unit && info->f_bavail > limit / unit) ? limit : info->f_bavail * unit;
    sftp_statvfs_free(info);
    *bytes = static_cast<qint64>(available);
    return Result::success();
}

Result SftpBackend::freeSpace(const QString &dir, qint64 *bytes)
{
    Result r = checkReady();
    if (!r.ok())
        return r;
    if (!m_hasStatvfs)
        return Result(Error::Unsupported, QStringLiteral("The server cannot report free space"));
    QByteArray remote;
    r = resolve(dir, &remote);
    if (r.ok())
        r = freeBytes(remote, bytes);
    return r;
}

// --- transfers --------------------------------------------------------------

Result SftpBackend::waitForData(const QElapsedTimer &started) const
{
    if (m_canceled)
        return Result(Error::Canceled);   // C-9
    if (started.elapsed() > m_params.requestTimeoutMs) {   // C-14
        return Result(Error::Timeout, QStringLiteral("The server did not answer within %1 s")
                                          .arg(m_params.requestTimeoutMs / 1000));
    }
    if (ssh_channel_poll_timeout(m_sftp->channel, PollIntervalMs, 0) == SSH_ERROR)
        return sessionFailure();
    return Result::success();
}

Result SftpBackend::waitWrite(Pending *pending, const QByteArray &remote) const
{
    QElapsedTimer started;
    started.start();
    for (;;) {
        const ssize_t rc = sftp_aio_wait_write(&pending->aio);
        if (rc == SSH_AGAIN) {
            const Result r = waitForData(started);
            if (r.ok())
                continue;
            SFTP_AIO_FREE(pending->aio);
            return r;
        }
        if (rc < 0)
            return writeFailure(remote, static_cast<qint64>(pending->length));
        if (static_cast<size_t>(rc) != pending->length)
            return Result(Error::ProtocolError, QStringLiteral("The server stored only part of a block"));
        return Result::success();
    }
}

Result SftpBackend::waitRead(Pending *pending, char *buffer, qint64 *received) const
{
    QElapsedTimer started;
    started.start();
    for (;;) {
        const ssize_t rc = sftp_aio_wait_read(&pending->aio, buffer, pending->length);
        if (rc == SSH_AGAIN) {
            const Result r = waitForData(started);
            if (r.ok())
                continue;
            SFTP_AIO_FREE(pending->aio);
            return r;
        }
        if (rc < 0)
            return sftpFailure(QStringLiteral("read"));
        *received = static_cast<qint64>(rc);
        return Result::success();
    }
}

int SftpBackend::closeFile(sftp_file file, bool healthy) const
{
    if (!healthy)
        setTimeout(CleanupTimeoutMs);
    const int rc = sftp_close(file);
    if (!healthy)
        setTimeout(m_params.requestTimeoutMs);
    return rc;
}

Result SftpBackend::fillWriteWindow(sftp_file file, QIODevice *source, QByteArray *buffer, PendingQueue *queue,
                                    bool *eof, const QByteArray &remote) const
{
    while (!*eof && !queue->full()) {
        const qint64 n = readFully(source, buffer->data(), buffer->size());
        if (n < 0)
            return Result(Error::Internal, QStringLiteral("Cannot read the local file"));
        *eof = n < buffer->size();
        for (qint64 sent = 0; sent < n;) {
            Pending pending;
            const ssize_t rc = sftp_aio_begin_write(file, buffer->constData() + sent,
                                                    static_cast<size_t>(n - sent), &pending.aio);
            if (rc <= 0)
                return writeFailure(remote, n - sent);
            pending.length = static_cast<size_t>(rc);
            queue->push(pending);
            sent += rc;
        }
    }
    return Result::success();
}

Result SftpBackend::writeChunks(sftp_file file, QIODevice *source, const QByteArray &remote,
                                Progress *progress) const
{
    PendingQueue queue;
    QByteArray buffer(static_cast<int>(m_writeChunk), Qt::Uninitialized);
    const qint64 total = source->size();
    qint64 done = 0;
    bool eof = false;
    for (;;) {
        if (m_canceled)
            return Result(Error::Canceled);
        Result r = fillWriteWindow(file, source, &buffer, &queue, &eof, remote);
        if (!r.ok() || queue.empty())
            return r;
        Pending pending = queue.take();
        r = waitWrite(&pending, remote);
        if (!r.ok())
            return r;
        done += static_cast<qint64>(pending.length);
        if (progress)
            progress->update(done, total);
    }
}

Result SftpBackend::upload(QIODevice *source, const QString &path, Progress *progress)
{
    QByteArray remote;
    Result r = checkReady();
    if (r.ok())
        r = resolve(path, &remote);
    if (!r.ok())
        return r;
    sftp_file file = sftp_open(m_sftp, remote.constData(), O_WRONLY | O_CREAT | O_TRUNC, FileMode);
    if (!file)
        return sftpFailure(display(remote));
    sftp_file_set_nonblocking(file);
    r = writeChunks(file, source, remote, progress);
    if (r.ok() && m_hasFsync && sftp_fsync(file) != 0)   // C-12: flush to stable storage
        r = writeFailure(remote, 1);
    const int closed = closeFile(file, r.ok());
    if (r.ok() && closed != 0)
        r = writeFailure(remote, 1);
    return r;
}

Result SftpBackend::refillReadWindow(sftp_file file, PendingQueue *queue, quint64 *offset) const
{
    while (!queue->full()) {
        Pending pending;
        const ssize_t rc = sftp_aio_begin_read(file, m_readChunk, &pending.aio);
        if (rc <= 0)
            return sftpFailure(QStringLiteral("read"));
        pending.length = static_cast<size_t>(rc);
        pending.offset = *offset;
        queue->push(pending);
        *offset += static_cast<quint64>(rc);
    }
    return Result::success();
}

Result SftpBackend::drain(PendingQueue *queue, char *buffer) const
{
    // Collects and drops the answers to requests whose data is not wanted.
    Result r;
    while (r.ok() && !queue->empty()) {
        Pending pending = queue->take();
        qint64 ignored = 0;
        r = waitRead(&pending, buffer, &ignored);
    }
    return r;
}

Result SftpBackend::readChunks(sftp_file file, QIODevice *sink, qint64 total, Progress *progress) const
{
    PendingQueue queue;
    QByteArray buffer(static_cast<int>(m_readChunk), Qt::Uninitialized);
    quint64 offset = 0;
    qint64 done = 0;
    for (;;) {
        if (m_canceled)
            return Result(Error::Canceled);
        Result r = refillReadWindow(file, &queue, &offset);
        if (!r.ok())
            return r;
        Pending pending = queue.take();
        qint64 n = 0;
        r = waitRead(&pending, buffer.data(), &n);
        if (!r.ok())
            return r;
        if (n == 0)
            return drain(&queue, buffer.data());   // end of file
        if (sink->write(buffer.constData(), n) != n)
            return Result(Error::NoSpace, QStringLiteral("Cannot write the local file: %1").arg(sink->errorString()));
        done += n;
        if (progress)
            progress->update(done, total);
        if (static_cast<size_t>(n) < pending.length) {
            // A short read: the requests already sent ask for the wrong
            // offsets. Drop their answers and continue after the data.
            offset = pending.offset + static_cast<quint64>(n);
            r = drain(&queue, buffer.data());
            if (r.ok() && sftp_seek64(file, offset) < 0)
                r = sftpFailure(QStringLiteral("seek"));
            if (!r.ok())
                return r;
        }
    }
}

Result SftpBackend::download(const QString &path, QIODevice *sink, Progress *progress)
{
    QByteArray remote;
    Result r = checkReady();
    if (r.ok())
        r = resolve(path, &remote);
    if (!r.ok())
        return r;
    sftp_file file = sftp_open(m_sftp, remote.constData(), O_RDONLY, 0);
    if (!file)
        return sftpFailure(display(remote));
    qint64 total = -1;
    if (sftp_attributes attributes = sftp_fstat(file)) {
        total = static_cast<qint64>(attributes->size);
        sftp_attributes_free(attributes);
    }
    sftp_file_set_nonblocking(file);
    r = readChunks(file, sink, total, progress);
    closeFile(file, r.ok());
    return r;
}

Result SftpBackend::read(const QString &path, qint64 offset, qint64 length, QByteArray *out)
{
    QByteArray remote;
    Result r = checkReady();
    if (r.ok() && (offset < 0 || length < 0 || length > std::numeric_limits<int>::max()))
        r = Result(Error::Internal, QStringLiteral("Invalid range"));
    if (r.ok())
        r = resolve(path, &remote);
    if (!r.ok())
        return r;
    sftp_file file = sftp_open(m_sftp, remote.constData(), O_RDONLY, 0);
    if (!file)
        return sftpFailure(display(remote));
    out->clear();
    QByteArray buffer(static_cast<int>(m_readChunk), Qt::Uninitialized);
    if (sftp_seek64(file, static_cast<quint64>(offset)) < 0)
        r = sftpFailure(display(remote));
    while (r.ok() && out->size() < length) {
        const auto wanted = static_cast<size_t>(qMin<qint64>(buffer.size(), length - out->size()));
        const ssize_t n = sftp_read(file, buffer.data(), wanted);
        if (n < 0)
            r = sftpFailure(display(remote));
        else if (n == 0)
            break;
        else
            out->append(buffer.constData(), static_cast<int>(n));
    }
    closeFile(file, r.ok());
    return r;
}

} // namespace NetVfs::Sftp
