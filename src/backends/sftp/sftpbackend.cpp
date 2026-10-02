// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sftpbackend.h"
#include "logging.h"
#include "names.h"
#include "paths.h"
#include "secure.h"
#include "sftpsupport.h"
#include "sshkeys.h"
#include "sshutil.h"

#include <QtCore/QBuffer>
#include <QtCore/QIODevice>

#include <algorithm>
#include <deque>
#include <fcntl.h>
#include <limits>

// libssh's global request (channels.c). It is not in the installed headers,
// but it is the one way to send keepalive@openssh.com with want-reply and
// see the answer (SPEC-v2 XS-12); ssh_send_keepalive() discards it. Linked
// statically from the pinned libssh.
extern "C" int ssh_global_request(ssh_session session, const char *request, ssh_buffer buffer, int reply);

namespace NetVfs::Sftp {

namespace {

constexpr const char *HostKeyOption = "host_key";
constexpr const char *AuthModeOption = "auth_mode";
constexpr const char *DirModeOption = "dir_mode";
constexpr const char *KeepAliveRequest = "keepalive@openssh.com";
constexpr const char *NullDevice = "/dev/null";
constexpr int DefaultPort = 22;
constexpr int DefaultConnectTimeoutMs = 15000;   // C-14
constexpr int DefaultRequestTimeoutMs = 60000;   // C-14
constexpr int PollIntervalMs = 100;
// Closing a handle after a cancel or timeout must not undo C-9's 2 s bound.
constexpr int CleanupTimeoutMs = 1000;
constexpr int MaxKeyboardInteractiveRounds = 8;
// XC-23: without a requested mode the server's umask decides. libssh always
// sends a mode; these are what OpenSSH's sftp-server and mkdir(1) use when
// none is given.
constexpr mode_t DefaultDirectoryMode = 0777;
constexpr mode_t DefaultFileMode = 0666;
constexpr mode_t PermissionBits = 07777;
constexpr int MaxSymlinkResolutions = 512;       // XS-3, per listing
constexpr qint64 MaxHandleRead = std::numeric_limits<int>::max();

QString text(const char *value)
{
    return value ? QString::fromUtf8(value) : QString();
}

// Remote names in messages: lossless decode, escapes shown as U+FFFD (XS-1).
QString display(const QByteArray &remote)
{
    return Names::display(Names::decode(remote));
}

QByteArray lastComponent(const QByteArray &remote)
{
    const int slash = remote.lastIndexOf('/');
    return slash < 0 ? remote : remote.mid(slash + 1);
}

QByteArray joinRemote(const QByteArray &dir, const QByteArray &name)
{
    if (dir.isEmpty())
        return name;
    return dir.endsWith('/') ? dir + name : dir + '/' + name;
}

EntryType typeOf(const sftp_attributes_struct &attributes)
{
    // libssh derives the type from the permission bits for SFTP v3 servers.
    switch (attributes.type) {
    case SSH_FILEXFER_TYPE_REGULAR:
        return EntryType::File;
    case SSH_FILEXFER_TYPE_DIRECTORY:
        return EntryType::Directory;
    case SSH_FILEXFER_TYPE_SYMLINK:
        return EntryType::Symlink;
    case SSH_FILEXFER_TYPE_SPECIAL:
        return EntryType::Special;
    default:
        return EntryType::Unknown;
    }
}

QDateTime timeOf(uint32_t seconds)
{
    return QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(seconds) * 1000, Qt::UTC);
}

// XS-2 (the part that needs no extension).
Entry entryFrom(const sftp_attributes_struct &attributes, const QString &name)
{
    Entry entry;
    entry.name = name;
    entry.type = typeOf(attributes);
    if (attributes.flags & SSH_FILEXFER_ATTR_SIZE)
        entry.size = static_cast<qint64>(std::min<uint64_t>(attributes.size, std::numeric_limits<qint64>::max()));
    if (attributes.flags & SSH_FILEXFER_ATTR_ACMODTIME) {
        entry.modified = timeOf(attributes.mtime);
        entry.accessed = timeOf(attributes.atime);
    }
    if (attributes.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        entry.mode = static_cast<qint32>(attributes.permissions & PermissionBits);
    if (attributes.flags & SSH_FILEXFER_ATTR_UIDGID) {
        entry.uid = attributes.uid;
        entry.gid = attributes.gid;
    }
    if (attributes.owner)
        entry.owner = Names::decode(QByteArray(attributes.owner));
    if (attributes.group)
        entry.group = Names::decode(QByteArray(attributes.group));
    if (Names::hasEscapes(name))
        entry.flags |= EntryFlag::NameNotUtf8;
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

bool stopped(const std::atomic<bool> &canceled, const Progress *progress)
{
    return canceled || (progress && progress->canceled());
}

qint64 scaled(uint64_t blocks, uint64_t unit)
{
    const auto limit = static_cast<uint64_t>(std::numeric_limits<qint64>::max());
    return static_cast<qint64>((unit && blocks > limit / unit) ? limit : blocks * unit);
}

Result invalidRange()
{
    return Result(Error::Internal, QStringLiteral("Invalid range"));
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

// Pipelined transfers over one open file (S-21, C-9, C-14).
class SftpBackend::Io
{
public:
    explicit Io(const SftpBackend &backend) : m_b(backend) {}

    Result timedOut() const;
    bool overdue(const QElapsedTimer &started) const;
    Result waitForData(const QElapsedTimer &started) const;
    Result waitWrite(Pending *pending, const QByteArray &remote) const;
    Result waitRead(Pending *pending, char *buffer, qint64 *received) const;
    Result fillWriteWindow(sftp_file file, QIODevice *source, QByteArray *buffer, PendingQueue *queue, bool *eof, const QByteArray &remote) const;
    Result writeChunks(sftp_file file, QIODevice *source, const QByteArray &remote, Progress *progress, qint64 base) const;
    Result refillReadWindow(sftp_file file, PendingQueue *queue, quint64 *offset, quint64 end) const;
    Result drain(PendingQueue *queue, char *buffer) const;
    Result readStep(sftp_file file, PendingQueue *queue, QByteArray *buffer, Sink *sink, quint64 *offset, bool *finished) const;
    Result readChunks(sftp_file file, Sink *sink, quint64 start) const;

private:
    const SftpBackend &m_b;
};

// Sign-in with exactly one method (S-10 to S-14).
class SftpBackend::Login
{
public:
    explicit Login(const SftpBackend &backend) : m_b(backend) {}

    Result authenticateWith(int methods, const QByteArray &secret) const;
    Result authPassword(int methods, const QByteArray &secret) const;
    Result authKeyboardInteractive(const QByteArray &secret) const;
    Result authPublicKey(int methods, const QByteArray &secret) const;
    Result authOutcome(int rc) const;

private:
    const SftpBackend &m_b;
};

// XC-13: one open file; every read is pipelined like a download (S-21) and
// honours cancel() (C-9). Read-ahead across calls is not done (XS-7 later).
class SftpBackend::Reader : public ReadHandle
{
public:
    Reader(SftpBackend *backend, sftp_file file, qint64 size, const QByteArray &remote)
        : m_b(backend), m_file(file), m_size(size), m_remote(remote) {}
    Reader(const Reader &) = delete;
    Reader &operator=(const Reader &) = delete;
    ~Reader() override { close(); }

    qint64 size() const override { return m_size; }
    Result read(qint64 offset, qint64 maxBytes, QByteArray *out) override;
    void readAhead(qint64, qint64) override {}
    Result close() override;

    // The backend closed the file because its connection ends.
    void invalidate()
    {
        m_file = nullptr;
        m_lost = true;
    }
    sftp_file file() const { return m_file; }

private:
    SftpBackend *m_b;
    sftp_file m_file;
    const qint64 m_size;
    const QByteArray m_remote;
    bool m_lost = false;
};

SftpBackend::~SftpBackend()
{
    closeSession();
}

void SftpBackend::configureSession(ssh_session session)
{
    Q_UNUSED(session)
}

// --- connection -------------------------------------------------------------

Result SftpBackend::connect(const ConnectionParams &params, ServerIdentity *seen)
{
    closeSession();
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
    if (!r.ok() && pinned && isHostKeyMismatch(r.message())) {
        // The server no longer offers the pinned key type (S-5). Connect once
        // more without the restriction, so that the caller sees the key the
        // server presents now and reports ServerIdentityChanged (S-7).
        closeSession();
        r = openTransport(false, seen);
    }
    if (r.ok() && m_canceled)
        r = Result(Error::Canceled);
    if (!r.ok())
        closeSession();
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
    if (ErrorTrail trail; ssh_connect(m_session) != SSH_OK)
        return connectFailure(trail.explain(text(ssh_get_error(m_session))));

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

void SftpBackend::closeSession()
{
    // XC-13: open handles end with the connection.
    for (Reader *reader : m_readers) {
        if (m_sftp && reader->file())
            closeFile(reader->file(), false);
        reader->invalidate();
    }
    m_readers.clear();
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
    m_nativeNoReplace = false;
    m_capabilities = Capabilities();
}

void SftpBackend::disconnect()
{
    closeSession();
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

Result SftpBackend::authenticate(const Credentials &credentials, AuthPrompter *prompter)
{
    // Keyboard-interactive with a prompter (XS-11) is not implemented yet;
    // without one the v1 rules apply unchanged (S-11).
    Q_UNUSED(prompter)
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
        r = Login(*this).authenticateWith(ssh_userauth_list(m_session, nullptr), credentials.secret);
    if (r.ok())
        r = openSftp();
    if (r.ok() && !setTimeout(m_params.requestTimeoutMs))
        r = Result(Error::Internal, QStringLiteral("Cannot set the timeout"));
    return r;
}

Result SftpBackend::Login::authenticateWith(int methods, const QByteArray &secret) const
{
    if (m_b.m_params.option(QLatin1String(AuthModeOption)) == QLatin1String(AuthModePublicKey))
        return authPublicKey(methods, secret);
    return authPassword(methods, secret);
}

Result SftpBackend::Login::authPassword(int methods, const QByteArray &secret) const
{
    // S-11. QByteArray data is NUL terminated.
    const auto mask = static_cast<unsigned>(methods);
    if (mask & SSH_AUTH_METHOD_PASSWORD)
        return authOutcome(ssh_userauth_password(m_b.m_session, nullptr, secret.constData()));
    if (mask & SSH_AUTH_METHOD_INTERACTIVE)
        return authKeyboardInteractive(secret);
    return authDenied(methods);
}

Result SftpBackend::Login::authKeyboardInteractive(const QByteArray &secret) const
{
    // S-11: the password answers a single non-echo prompt; rounds without
    // prompts (OpenSSH sends one after PAM succeeds) are acknowledged.
    bool answered = false;
    int rc = ssh_userauth_kbdint(m_b.m_session, nullptr, nullptr);
    int round = 0;
    while (rc == SSH_AUTH_INFO && round < MaxKeyboardInteractiveRounds) {
        ++round;
        if (const int prompts = ssh_userauth_kbdint_getnprompts(m_b.m_session); prompts > 0) {
            char echo = 1;
            ssh_userauth_kbdint_getprompt(m_b.m_session, 0, &echo);
            if (prompts != 1 || echo || answered)
                return interactiveNotSupported();
            if (ssh_userauth_kbdint_setanswer(m_b.m_session, 0, secret.constData()) < 0)
                return m_b.sessionFailure();
            answered = true;
        }
        rc = ssh_userauth_kbdint(m_b.m_session, nullptr, nullptr);
    }
    if (rc == SSH_AUTH_INFO)
        return interactiveNotSupported();
    return authOutcome(rc);
}

Result SftpBackend::Login::authPublicKey(int methods, const QByteArray &secret) const
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
    return authOutcome(ssh_userauth_publickey(m_b.m_session, nullptr, key.get()));
}

Result SftpBackend::Login::authOutcome(int rc) const
{
    switch (rc) {
    case SSH_AUTH_SUCCESS:
        return Result::success();
    case SSH_AUTH_PARTIAL:
        return authPartial();                                       // S-13
    case SSH_AUTH_DENIED:
        return authDenied(ssh_userauth_list(m_b.m_session, nullptr));   // S-14
    default:
        return m_b.sessionFailure();
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
    detectCapabilities();

    qCDebug(lcNetVfsSftp) << "SFTP version" << sftp_server_version(m_sftp) << "fsync" << m_hasFsync
                          << "statvfs" << m_hasStatvfs << "posix-rename" << m_hasPosixRename
                          << "OpenSSH rename" << m_nativeNoReplace
                          << "chunk" << m_writeChunk << m_readChunk << "start" << m_home;
    return Result::success();
}


void SftpBackend::detectCapabilities()
{
    // XC-5: only what this backend implements and the interop suite tests.
    m_nativeNoReplace = ssh_get_openssh_version(m_session) > 0;   // XS-6, by banner
    m_capabilities = Capabilities();
    m_capabilities.flags << Capability::ReadHandles << Capability::EfficientRanges;
    if (m_hasStatvfs)
        m_capabilities.flags << Capability::SpaceInfo;
    if (m_hasPosixRename)
        m_capabilities.flags << Capability::AtomicReplace;
    if (m_nativeNoReplace)
        m_capabilities.flags << Capability::NativeNoReplace;
    m_capabilities.maxReadChunk = static_cast<qint64>(m_readChunk);
    m_capabilities.maxWriteChunk = static_cast<qint64>(m_writeChunk);
}

Capabilities SftpBackend::capabilities() const
{
    return m_capabilities;
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
    if (!Names::isEncodable(normalized))   // XC-4
        return Result(Error::InvalidName, QStringLiteral("The name cannot be sent to an SFTP server"));
    const QByteArray bytes = Names::encode(normalized);
    if (Paths::isAbsolute(normalized))
        *remote = bytes;
    else if (normalized.isEmpty())
        *remote = m_home.isEmpty() ? QByteArray(".") : m_home;
    else
        *remote = joinRemote(m_home, bytes);
    return Result::success();
}

Result SftpBackend::ready(const QString &path, QByteArray *remote) const
{
    Result r = checkReady();
    if (r.ok())
        r = resolve(path, remote);
    return r;
}

bool SftpBackend::transportLost() const
{
    return !m_session || !ssh_is_connected(m_session) || (m_sftp && ssh_channel_is_closed(m_sftp->channel));
}

// XC-21: once signed in, a transport that went away is ConnectionLost.
Result SftpBackend::established(const Result &failure) const
{
    if (m_sftp && !failure.ok() && failure.error() != Error::Canceled && transportLost())
        return Result(Error::ConnectionLost, failure.message());
    return failure;
}

Result SftpBackend::sftpFailure(const QString &context) const
{
    return established(sftpStatusFailure(sftp_get_error(m_sftp), text(ssh_get_error(m_session)), context));
}

Result SftpBackend::writeFailure(const QByteArray &remote, qint64 attempted) const
{
    const int status = sftp_get_error(m_sftp);
    const Result failure = sftpFailure(display(remote));
    if (status != SSH_FX_FAILURE || !m_hasStatvfs || m_canceled)
        return failure;
    if (qint64 available = -1;
            !freeBytes(remote, &available).ok() || !looksLikeFullDisk(status, available, attempted))
        return failure;
    return Result(Error::NoSpace, QStringLiteral("The server has no space left for %1").arg(display(remote)));
}

mode_t SftpBackend::directoryMode() const
{
    bool ok = false;
    const uint mode = m_params.option(QLatin1String(DirModeOption)).toUInt(&ok, 8);
    return ok && mode <= PermissionBits ? static_cast<mode_t>(mode) : DefaultDirectoryMode;
}

// --- metadata ---------------------------------------------------------------

Result SftpBackend::statRemote(const QByteArray &remote, Entry *out, bool follow) const
{
    sftp_attributes attributes = follow ? sftp_stat(m_sftp, remote.constData()) : sftp_lstat(m_sftp, remote.constData());
    if (!attributes)
        return sftpFailure(display(remote));
    if (out)
        *out = entryFrom(*attributes, Names::decode(lastComponent(remote)));
    sftp_attributes_free(attributes);
    return Result::success();
}

Result SftpBackend::stat(const QString &path, Entry *out)
{
    QByteArray remote;
    Result r = ready(path, &remote);
    if (r.ok())
        r = statRemote(remote, out);
    return r;
}

Result SftpBackend::lstat(const QString &path, Entry *out)
{
    QByteArray remote;
    Result r = ready(path, &remote);
    if (r.ok())
        r = statRemote(remote, out, false);
    return r;
}

void SftpBackend::resolveTarget(const QByteArray &dir, Entry *entry, int *budget) const
{
    // XS-3: at most MaxSymlinkResolutions per listing.
    Entry target;
    if (*budget > 0 && statRemote(joinRemote(dir, Names::encode(entry->name)), &target).ok())
        entry->targetType = target.type;
    else
        entry->flags |= EntryFlag::TargetUnknown;
    --*budget;
}

Result SftpBackend::readEntries(sftp_dir handle, const QByteArray &remote, ListSink *sink,
                                const ListOptions &options) const
{
    const int batchSize = qMax(1, options.batchSize);
    int budget = MaxSymlinkResolutions;
    QVector<Entry> batch;
    for (;;) {
        if (m_canceled)
            return Result(Error::Canceled);   // C-9, between READDIR replies
        sftp_attributes attributes = sftp_readdir(m_sftp, handle);
        if (!attributes)
            break;
        // XC-6: READDIR is lstat-like; "." and ".." never appear.
        if (const QByteArray name(attributes->name); name != "." && name != "..") {
            Entry entry = entryFrom(*attributes, Names::decode(name));
            if (options.resolveSymlinkTypes && entry.type == EntryType::Symlink)
                resolveTarget(remote, &entry, &budget);
            batch.append(entry);
        }
        sftp_attributes_free(attributes);
        // A batch per READDIR reply: libssh drops its buffer after the last name.
        const bool replyDone = handle->buffer == nullptr;
        if (!batch.isEmpty() && (replyDone || batch.size() >= batchSize)) {
            if (!sink->entries(batch))
                return Result(Error::Canceled, QStringLiteral("The listing was stopped"));
            batch.clear();
        }
    }
    if (!sftp_dir_eof(handle))
        return sftpFailure(display(remote));
    if (!batch.isEmpty() && !sink->entries(batch))
        return Result(Error::Canceled, QStringLiteral("The listing was stopped"));
    return Result::success();
}

Result SftpBackend::list(const QString &dir, ListSink *sink, const ListOptions &options)
{
    QByteArray remote;
    Result r = ready(dir, &remote);
    if (!r.ok())
        return r;
    sftp_dir handle = sftp_opendir(m_sftp, remote.constData());
    if (!handle) {
        r = sftpFailure(display(remote));
        // OpenSSH reports ENOTDIR as "no such file".
        if (Entry entry; r.error() != Error::ConnectionLost && statRemote(remote, &entry).ok() && !entry.isDir())
            return Result(Error::NotADirectory, QStringLiteral("%1 is not a folder").arg(display(remote)));
        return r;
    }
    r = readEntries(handle, remote, sink, options);
    sftp_closedir(handle);
    return r;
}

// --- namespace --------------------------------------------------------------

Result SftpBackend::makeDir(const QString &path, bool exclusive)
{
    QByteArray remote;
    Result r = ready(path, &remote);
    if (!r.ok())
        return r;
    if (sftp_mkdir(m_sftp, remote.constData(), directoryMode()) == 0)   // XC-8, XC-23, S-20
        return Result::success();
    r = sftpFailure(display(remote));
    // OpenSSH reports EEXIST as a plain failure; a concurrent creator is fine.
    if (Entry existing; r.error() != Error::ConnectionLost && statRemote(remote, &existing).ok()) {
        if (exclusive)
            return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(display(remote)));
        if (existing.isDir())
            return Result::success();
        return Result(Error::AlreadyExists, QStringLiteral("%1 exists and is not a folder").arg(display(remote)));
    }
    return r;
}

Result SftpBackend::removeFile(const QString &path)
{
    QByteArray remote;
    Result r = ready(path, &remote);
    if (!r.ok())
        return r;
    if (sftp_unlink(m_sftp, remote.constData()) == 0)
        return Result::success();
    r = sftpFailure(display(remote));
    // XC-9: OpenSSH reports EISDIR as a plain failure.
    if (Entry entry; r.error() != Error::ConnectionLost && statRemote(remote, &entry, false).ok()
            && entry.type == EntryType::Directory)
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(display(remote)));
    return r;
}

bool SftpBackend::hasChildren(const QByteArray &remote) const
{
    sftp_dir handle = sftp_opendir(m_sftp, remote.constData());
    if (!handle)
        return false;
    bool found = false;
    while (sftp_attributes attributes = found ? nullptr : sftp_readdir(m_sftp, handle)) {
        const QByteArray name(attributes->name);
        found = name != "." && name != "..";
        sftp_attributes_free(attributes);
    }
    sftp_closedir(handle);
    return found;
}

Result SftpBackend::removeDir(const QString &path)
{
    QByteArray remote;
    Result r = ready(path, &remote);
    if (!r.ok())
        return r;
    if (sftp_rmdir(m_sftp, remote.constData()) == 0)
        return Result::success();
    r = sftpFailure(display(remote));
    Entry entry;
    if (r.error() == Error::ConnectionLost || !statRemote(remote, &entry, false).ok())
        return r;
    // XC-9: OpenSSH reports ENOTDIR as "no such file" and ENOTEMPTY as a
    // plain failure.
    if (entry.type != EntryType::Directory)
        return Result(Error::NotADirectory, QStringLiteral("%1 is not a folder").arg(display(remote)));
    if (r.error() != Error::PermissionDenied && hasChildren(remote))
        return Result(Error::DirectoryNotEmpty, QStringLiteral("%1 is not empty").arg(display(remote)));
    return r;
}

Result SftpBackend::renameNoReplace(const QByteArray &source, const QByteArray &target)
{
    // XC-10, XS-6: OpenSSH fails a plain SSH_FXP_RENAME (never posix-rename)
    // on an existing target, atomically for files (NativeNoReplace). Other
    // servers get a stat check first (a documented race).
    if (!m_nativeNoReplace) {
        const Result r = statRemote(target, nullptr, false);
        if (r.ok())
            return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(display(target)));
        if (r.error() != Error::NotFound)
            return r;
    }
    if (sftp_rename_noreplace(m_sftp, source.constData(), target.constData()) == 0)
        return Result::success();
    const Result failure = sftpFailure(display(source));
    // OpenSSH reports the existing target as a plain failure.
    if (failure.error() != Error::NotFound && failure.error() != Error::ConnectionLost
            && statRemote(target, nullptr, false).ok())
        return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(display(target)));
    return failure;
}

Result SftpBackend::renameReplacing(const QByteArray &source, const QByteArray &target, bool targetExists)
{
    // With posix-rename@openssh.com, libssh's sftp_rename() replaces the
    // target atomically (AtomicReplace). Plain SFTP rename does not replace
    // (S-22, 7): stat, unlink and rename as in API v1.
    if (!m_hasPosixRename && targetExists && sftp_unlink(m_sftp, target.constData()) != 0)
        return sftpFailure(display(target));
    if (sftp_rename(m_sftp, source.constData(), target.constData()) != 0)
        return sftpFailure(display(source));
    return Result::success();
}

Result SftpBackend::rename(const QString &from, const QString &to, RenameMode mode)
{
    QByteArray source;
    QByteArray target;
    Result r = ready(from, &source);
    if (r.ok())
        r = resolve(to, &target);
    if (!r.ok())
        return r;
    if (mode == RenameMode::NoReplace)
        return renameNoReplace(source, target);
    Entry existing;
    r = statRemote(target, &existing, false);
    if (!r.ok() && r.error() != Error::NotFound)
        return r;
    const bool targetExists = r.ok();
    if (targetExists && source == target)
        return Result::success();
    // XC-10: a folder is never replaced.
    if (targetExists && existing.type == EntryType::Directory)
        return Result(Error::AlreadyExists, QStringLiteral("%1 is a folder").arg(display(target)));
    return renameReplacing(source, target, targetExists);
}

Result SftpBackend::freeBytes(const QByteArray &remote, qint64 *bytes) const
{
    sftp_statvfs_t info = sftp_statvfs(m_sftp, remote.constData());
    if (!info)
        return sftpFailure(display(remote));
    const uint64_t unit = info->f_frsize ? info->f_frsize : info->f_bsize;
    *bytes = scaled(info->f_bavail, unit);
    sftp_statvfs_free(info);
    return Result::success();
}

Result SftpBackend::spaceInfo(const QString &dir, SpaceInfo *out)
{
    Result r = checkReady();
    if (!r.ok())
        return r;
    if (!m_hasStatvfs)
        return Result(Error::Unsupported, QStringLiteral("The server cannot report free space"));
    QByteArray remote;
    r = resolve(dir, &remote);
    if (!r.ok())
        return r;
    // XS-8: free = f_bavail x f_frsize, total = f_blocks x f_frsize.
    sftp_statvfs_t info = sftp_statvfs(m_sftp, remote.constData());
    if (!info)
        return sftpFailure(display(remote));
    const uint64_t unit = info->f_frsize ? info->f_frsize : info->f_bsize;
    if (out) {
        out->free = scaled(info->f_bavail, unit);
        out->total = scaled(info->f_blocks, unit);
        out->used = info->f_blocks >= info->f_bfree ? scaled(info->f_blocks - info->f_bfree, unit) : -1;
    }
    sftp_statvfs_free(info);
    return Result::success();
}

// --- keepAlive --------------------------------------------------------------

Result SftpBackend::waitGlobalReply(const QElapsedTimer &started) const
{
    if (m_canceled)
        return Result(Error::Canceled);   // C-9
    if (started.elapsed() >= m_params.requestTimeoutMs)
        return Result(Error::Timeout, QStringLiteral("The server did not answer the keep-alive request"));
    if (ssh_channel_poll_timeout(m_sftp->channel, PollIntervalMs, 0) == SSH_ERROR || transportLost())
        return Result(Error::ConnectionLost, text(ssh_get_error(m_session)));
    return Result::success();
}

Result SftpBackend::keepAlive()
{
    Result r = checkReady();
    if (!r.ok())
        return r;
    if (transportLost())
        return Result(Error::ConnectionLost, QStringLiteral("The connection to the server was lost"));
    // XS-12: keepalive@openssh.com with want-reply; any reply proves the
    // connection (OpenSSH answers with a failure).
    ssh_set_blocking(m_session, 0);
    QElapsedTimer started;
    started.start();
    int rc = ssh_global_request(m_session, KeepAliveRequest, nullptr, 1);
    while (rc == SSH_AGAIN && r.ok()) {
        r = waitGlobalReply(started);
        if (r.ok())
            rc = ssh_global_request(m_session, KeepAliveRequest, nullptr, 1);
    }
    ssh_set_blocking(m_session, 1);
    if (!r.ok())
        return r;
    if (rc == SSH_OK || ssh_get_error_code(m_session) == SSH_REQUEST_DENIED)
        return Result::success();
    return Result(Error::ConnectionLost, text(ssh_get_error(m_session)));
}

// --- transfers --------------------------------------------------------------

Result SftpBackend::Io::timedOut() const
{
    return Result(Error::Timeout,
                  QStringLiteral("The server did not answer within %1 s").arg(m_b.m_params.requestTimeoutMs / 1000));
}

// A blocking read inside libssh that runs into the session timeout (the
// request timeout) fails without an error message. By then the request is
// overdue, and that is what the caller needs to know (C-14).
bool SftpBackend::Io::overdue(const QElapsedTimer &started) const
{
    return started.elapsed() >= m_b.m_params.requestTimeoutMs;
}

Result SftpBackend::Io::waitForData(const QElapsedTimer &started) const
{
    if (m_b.m_canceled)
        return Result(Error::Canceled);   // C-9
    if (overdue(started))
        return timedOut();
    if (ssh_channel_poll_timeout(m_b.m_sftp->channel, PollIntervalMs, 0) == SSH_ERROR)
        return m_b.established(m_b.sessionFailure());
    return Result::success();
}

Result SftpBackend::Io::waitWrite(Pending *pending, const QByteArray &remote) const
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
            return overdue(started) ? timedOut() : m_b.writeFailure(remote, static_cast<qint64>(pending->length));
        if (static_cast<size_t>(rc) != pending->length)
            return Result(Error::ProtocolError, QStringLiteral("The server stored only part of a block"));
        return Result::success();
    }
}

Result SftpBackend::Io::waitRead(Pending *pending, char *buffer, qint64 *received) const
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
            return overdue(started) ? timedOut() : m_b.sftpFailure(QStringLiteral("read"));
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

Result SftpBackend::Io::fillWriteWindow(sftp_file file, QIODevice *source, QByteArray *buffer, PendingQueue *queue,
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
                return m_b.writeFailure(remote, n - sent);
            pending.length = static_cast<size_t>(rc);
            queue->push(pending);
            sent += rc;
        }
    }
    return Result::success();
}

Result SftpBackend::Io::writeChunks(sftp_file file, QIODevice *source, const QByteArray &remote,
                                Progress *progress, qint64 base) const
{
    PendingQueue queue;
    QByteArray buffer(static_cast<int>(m_b.m_writeChunk), Qt::Uninitialized);
    const qint64 total = base + source->size();
    qint64 done = base;
    bool eof = false;
    for (;;) {
        if (stopped(m_b.m_canceled, progress))
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

Result SftpBackend::openForUpload(const QByteArray &remote, const WriteOptions &options, sftp_file *file) const
{
    int flags = O_WRONLY;
    if (options.disposition == WriteOptions::Disposition::CreateNew)
        flags |= O_CREAT | O_EXCL;
    else if (options.disposition == WriteOptions::Disposition::Truncate)
        flags |= O_CREAT | O_TRUNC;
    // XC-23: the requested mode, else the server's default (S-20 for backups
    // comes through TransferPolicy::createMode).
    const mode_t mode = options.createMode >= 0 ? (static_cast<mode_t>(options.createMode) & PermissionBits)
                                                : DefaultFileMode;
    *file = sftp_open(m_sftp, remote.constData(), flags, mode);
    if (!*file) {
        const Result failure = sftpFailure(display(remote));
        Entry existing;
        if (failure.error() == Error::ConnectionLost || !statRemote(remote, &existing).ok())
            return failure;
        if (existing.isDir())
            return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(display(remote)));
        if (options.disposition == WriteOptions::Disposition::CreateNew)
            return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(display(remote)));
        return failure;
    }
    if (options.disposition != WriteOptions::Disposition::Resume)
        return Result::success();
    // Resume: the remote size must be the offset the caller continues at.
    Result r;
    if (sftp_attributes attributes = sftp_fstat(*file)) {
        if (static_cast<qint64>(attributes->size) != options.resumeOffset) {
            r = Result(Error::ProtocolError, QStringLiteral("Cannot resume at %1: the file has %2 bytes")
                                                 .arg(options.resumeOffset).arg(attributes->size));
        }
        sftp_attributes_free(attributes);
    } else {
        r = sftpFailure(display(remote));
    }
    if (r.ok() && options.resumeOffset < 0)
        r = invalidRange();
    if (r.ok() && sftp_seek64(*file, static_cast<quint64>(options.resumeOffset)) < 0)
        r = sftpFailure(display(remote));
    if (!r.ok()) {
        closeFile(*file, true);
        *file = nullptr;
    }
    return r;
}

Result SftpBackend::upload(QIODevice *source, const QString &path, const UploadOptions &options, Progress *progress)
{
    QByteArray remote;
    Result r = ready(path, &remote);
    sftp_file file = nullptr;
    if (r.ok())
        r = openForUpload(remote, options.write, &file);
    if (!r.ok())
        return r;
    sftp_file_set_nonblocking(file);
    const qint64 base = options.write.disposition == WriteOptions::Disposition::Resume ? options.write.resumeOffset : 0;
    r = Io(*this).writeChunks(file, source, remote, progress, base);
    if (r.ok() && m_hasFsync && sftp_fsync(file) != 0)   // C-12: flush to stable storage
        r = writeFailure(remote, 1);
    if (const int closed = closeFile(file, r.ok()); r.ok() && closed != 0)
        r = writeFailure(remote, 1);
    return r;
}

Result SftpBackend::Io::refillReadWindow(sftp_file file, PendingQueue *queue, quint64 *offset, quint64 end) const
{
    while (!queue->full() && *offset < end) {
        Pending pending;
        const auto wanted = static_cast<size_t>(std::min<quint64>(m_b.m_readChunk, end - *offset));
        const ssize_t rc = sftp_aio_begin_read(file, wanted, &pending.aio);
        if (rc <= 0)
            return m_b.sftpFailure(QStringLiteral("read"));
        pending.length = static_cast<size_t>(rc);
        pending.offset = *offset;
        queue->push(pending);
        *offset += static_cast<quint64>(rc);
    }
    return Result::success();
}

Result SftpBackend::Io::drain(PendingQueue *queue, char *buffer) const
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

Result SftpBackend::Io::readStep(sftp_file file, PendingQueue *queue, QByteArray *buffer, Sink *sink,
                             quint64 *offset, bool *finished) const
{
    Pending pending = queue->take();
    qint64 n = 0;
    if (const Result r = waitRead(&pending, buffer->data(), &n); !r.ok())
        return r;
    if (n == 0) {
        *finished = true;
        return drain(queue, buffer->data());   // end of file
    }
    if (sink->device->write(buffer->constData(), n) != n) {
        return Result(Error::NoSpace,
                      QStringLiteral("Cannot write the local file: %1").arg(sink->device->errorString()));
    }
    sink->done += n;
    if (sink->progress)
        sink->progress->update(sink->done, sink->total);
    if (static_cast<size_t>(n) == pending.length)
        return Result::success();
    // A short read: the requests already sent ask for the wrong offsets.
    // Drop their answers and continue after the data.
    *offset = pending.offset + static_cast<quint64>(n);
    Result r = drain(queue, buffer->data());
    if (r.ok() && sftp_seek64(file, *offset) < 0)
        r = m_b.sftpFailure(QStringLiteral("seek"));
    return r;
}

// Reads from `start` to the end of the file, or sink->limit bytes.
Result SftpBackend::Io::readChunks(sftp_file file, Sink *sink, quint64 start) const
{
    PendingQueue queue;
    QByteArray buffer(static_cast<int>(m_b.m_readChunk), Qt::Uninitialized);
    quint64 offset = start;
    const quint64 end = sink->limit < 0 ? std::numeric_limits<quint64>::max()
                                        : start + static_cast<quint64>(sink->limit);
    bool finished = false;
    while (!finished) {
        if (stopped(m_b.m_canceled, sink->progress))
            return Result(Error::Canceled);   // C-9, between requests
        Result r = refillReadWindow(file, &queue, &offset, end);
        if (r.ok() && queue.empty())
            break;                            // everything wanted has arrived
        if (r.ok())
            r = readStep(file, &queue, &buffer, sink, &offset, &finished);
        if (!r.ok())
            return r;
    }
    return Result::success();
}

Result SftpBackend::openForDownload(const QByteArray &remote, const DownloadOptions &options, sftp_file *file,
                                   Sink *sink) const
{
    if (options.offset < 0 || options.length < -1)
        return invalidRange();
    *file = sftp_open(m_sftp, remote.constData(), O_RDONLY, 0);
    if (!*file)
        return sftpFailure(display(remote));
    Result r;
    if (sftp_attributes attributes = sftp_fstat(*file)) {
        const Entry entry = entryFrom(*attributes, QString());
        sftp_attributes_free(attributes);
        if (entry.type == EntryType::Directory)
            r = Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(display(remote)));
        sink->total = entry.size < 0 ? -1 : qMax<qint64>(0, entry.size - options.offset);
    }
    if (options.length >= 0)
        sink->total = sink->total < 0 ? options.length : qMin(sink->total, options.length);
    sink->limit = options.length;
    if (r.ok() && options.offset > 0 && sftp_seek64(*file, static_cast<quint64>(options.offset)) < 0)
        r = sftpFailure(display(remote));
    if (!r.ok()) {
        closeFile(*file, true);
        *file = nullptr;
    }
    return r;
}

Result SftpBackend::download(const QString &path, QIODevice *sink, const DownloadOptions &options, Progress *progress)
{
    QByteArray remote;
    Result r = ready(path, &remote);
    sftp_file file = nullptr;
    Sink target { sink, progress, -1, 0, -1 };
    if (r.ok())
        r = openForDownload(remote, options, &file, &target);
    if (!r.ok())
        return r;
    sftp_file_set_nonblocking(file);
    r = Io(*this).readChunks(file, &target, static_cast<quint64>(options.offset));
    closeFile(file, r.ok());
    return r;
}

// --- handles ----------------------------------------------------------------

Result SftpBackend::openRead(const QString &path, ReadHandle **out)
{
    *out = nullptr;
    QByteArray remote;
    Result r = ready(path, &remote);
    sftp_file file = nullptr;
    Sink probe;
    if (r.ok())
        r = openForDownload(remote, DownloadOptions(), &file, &probe);
    if (!r.ok())
        return r;
    sftp_file_set_nonblocking(file);
    auto *reader = new Reader(this, file, probe.total, remote);
    m_readers.insert(reader);
    *out = reader;
    return r;
}

Result SftpBackend::Reader::read(qint64 offset, qint64 maxBytes, QByteArray *out)
{
    if (out)
        out->clear();
    if (m_lost)
        return Result(Error::ConnectionLost, QStringLiteral("The connection was closed"));
    if (!m_file)
        return Result(Error::Internal, QStringLiteral("The file is closed"));
    if (offset < 0 || maxBytes < 0 || maxBytes > MaxHandleRead)
        return invalidRange();
    if (Result r = m_b->checkReady(); !r.ok() || maxBytes == 0)
        return r;
    if (sftp_seek64(m_file, static_cast<quint64>(offset)) < 0)
        return m_b->sftpFailure(display(m_remote));
    QByteArray data;
    QBuffer buffer(&data);
    buffer.open(QIODevice::WriteOnly);
    Sink sink { &buffer, nullptr, -1, 0, maxBytes };
    const Result r = Io(*m_b).readChunks(m_file, &sink, static_cast<quint64>(offset));
    buffer.close();
    if (r.ok() && out)
        *out = data;
    return r;
}

Result SftpBackend::Reader::close()
{
    if (!m_file)
        return m_lost ? Result(Error::ConnectionLost, QStringLiteral("The connection was closed")) : Result();
    const int rc = m_b->closeFile(m_file, !m_b->m_canceled);
    m_file = nullptr;
    m_b->m_readers.remove(this);
    return rc == 0 ? Result::success() : m_b->sftpFailure(display(m_remote));
}

} // namespace NetVfs::Sftp
