// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbutil.h"
#include "smb2api.h"

#include "paths.h"

#include <QtCore/QElapsedTimer>

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace NetVfs::Smb {

namespace {

const int PollSliceMs = 100;

struct StatusEntry {
    quint32 status;
    Error error;
    const char *message;
};

// SPEC-smb 5, error mapping. Only AuthFailed leads to an attention state,
// which callers derive with attentionForError().
const std::array<StatusEntry, 18> statusTable = { {
    { SMB2_STATUS_LOGON_FAILURE, Error::AuthFailed, "the server rejected the user name or password" },
    { SMB2_STATUS_WRONG_PASSWORD, Error::AuthFailed, "the server rejected the password" },
    { SMB2_STATUS_NO_SUCH_USER, Error::AuthFailed, "the server does not know this user" },
    { SMB2_STATUS_ACCOUNT_DISABLED, Error::AuthFailed, "the account is disabled" },
    { SMB2_STATUS_ACCOUNT_LOCKED_OUT, Error::AuthFailed, "the account is locked" },
    { SMB2_STATUS_ACCOUNT_EXPIRED, Error::AuthFailed, "the account has expired" },
    { SMB2_STATUS_ACCOUNT_RESTRICTION, Error::AuthFailed, "the account may not sign in" },
    { SMB2_STATUS_INVALID_LOGON_HOURS, Error::AuthFailed, "the account may not sign in at this time" },
    { SMB2_STATUS_PASSWORD_EXPIRED, Error::AuthFailed, "the password has expired" },
    { SMB2_STATUS_PASSWORD_MUST_CHANGE, Error::AuthFailed, "the password must be changed" },
    { SMB2_STATUS_BAD_NETWORK_NAME, Error::NotFound, "share not found" },
    { SMB2_STATUS_ACCESS_DENIED, Error::PermissionDenied, "access denied" },
    { SMB2_STATUS_OBJECT_NAME_NOT_FOUND, Error::NotFound, "no such file or folder" },
    { SMB2_STATUS_OBJECT_PATH_NOT_FOUND, Error::NotFound, "no such folder" },
    { SMB2_STATUS_OBJECT_NAME_COLLISION, Error::AlreadyExists, "the name already exists" },
    { SMB2_STATUS_DISK_FULL, Error::NoSpace, "the share is full" },
    { SMB2_STATUS_QUOTA_EXCEEDED, Error::NoSpace, "the quota is exceeded" },
    { SMB2_STATUS_IO_TIMEOUT, Error::Timeout, "the server did not answer in time" },
} };

struct ErrnoEntry {
    int errnoValue;
    Error error;
    const char *message;
};

// The errno values libsmb2's nterror_to_errno() produces for the NT statuses
// of the table above.
const std::array<ErrnoEntry, 6> errnoTable = { {
    { ENOENT, Error::NotFound, "no such file or folder" },
    { EACCES, Error::PermissionDenied, "access denied" },
    { EPERM, Error::PermissionDenied, "operation not permitted" },
    { EEXIST, Error::AlreadyExists, "the name already exists" },
    { ENOSPC, Error::NoSpace, "the share is full" },
    { ENETRESET, Error::NetworkUnreachable, ConnectionLostMessage },
} };

QString withContext(const QString &context, const QString &message)
{
    return context.isEmpty() ? message : context + QStringLiteral(": ") + message;
}

QString hexStatus(quint32 ntStatus)
{
    return QStringLiteral("0x%1").arg(ntStatus, 8, 16, QLatin1Char('0'));
}

Result errorForNtStatus(quint32 ntStatus, const QString &context)
{
    for (const StatusEntry &entry : statusTable) {
        if (entry.status == ntStatus) {
            return Result(entry.error, withContext(context, QStringLiteral("%1 (NT status %2)")
                                                                .arg(QLatin1String(entry.message), hexStatus(ntStatus))));
        }
    }
    return Result(Error::ProtocolError,
                  withContext(context, QStringLiteral("NT status %1 (%2)")
                                           .arg(hexStatus(ntStatus), QLatin1String(nterror_to_str(ntStatus)))));
}

bool keepsMeaningInSetup(Error error)
{
    return error == Error::AuthFailed || error == Error::NotFound || error == Error::Timeout;
}

bool isTransportErrno(int errnoValue)
{
    return errnoValue == ECONNREFUSED || errnoValue == ENETUNREACH || errnoValue == EHOSTUNREACH;
}

struct AddrInfoDeleter {
    void operator()(addrinfo *info) const { freeaddrinfo(info); }
};

class FdCloser
{
public:
    explicit FdCloser(int fd) : m_fd(fd) {}
    ~FdCloser() { ::close(m_fd); }
    FdCloser(const FdCloser &) = delete;
    FdCloser &operator=(const FdCloser &) = delete;

private:
    int m_fd;
};

// Waits for a non-blocking connect to finish. Returns 0 or an errno value.
int awaitConnect(int fd, const QElapsedTimer &clock, int timeoutMs, const std::atomic<bool> &cancel)
{
    pollfd pfd = {};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    for (;;) {
        if (cancel)
            return ECANCELED;
        const qint64 left = timeoutMs - clock.elapsed();
        if (left <= 0)
            return ETIMEDOUT;
        pfd.revents = 0;
        const int rc = ::poll(&pfd, 1, static_cast<int>(qMin<qint64>(left, PollSliceMs)));
        if (rc > 0)
            break;
        if (rc < 0 && errno != EINTR)
            return errno;
    }
    int err = 0;
    if (socklen_t len = sizeof(err); ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0)
        return errno;
    return err;
}

int connectOne(const addrinfo *ai, const QElapsedTimer &clock, int timeoutMs, const std::atomic<bool> &cancel)
{
    const int fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0)
        return errno;
    const FdCloser closer(fd);
    if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
        return 0;
    if (errno != EINPROGRESS)
        return errno;
    return awaitConnect(fd, clock, timeoutMs, cancel);
}

} // namespace

quint32 chunkSize(quint32 serverMaximum)
{
    if (serverMaximum == 0)
        return FallbackChunkSize;
    return qMin(serverMaximum, MaxChunkSize);
}

Result translatePath(const QString &path, QByteArray *out)
{
    QString normalized;
    if (Result r = Paths::normalize(path, &normalized); !r.ok())
        return r;
    // M-8: relative to the share root.
    if (normalized.startsWith(QLatin1Char('/')))
        normalized.remove(0, 1);
    // M-9: names Windows servers cannot store are rejected before any request.
    if (Result r = Paths::checkWindowsPath(normalized); !r.ok())
        return r;
    *out = normalized.toUtf8();
    return Result::success();
}

Result errorForStatus(quint32 ntStatus, int errnoValue, Stage stage, const QString &context)
{
    if (ntStatus != 0) {
        Result r = errorForNtStatus(ntStatus, context);
        // During negotiate, session setup and tree connect, a refusal that is
        // about neither the credentials nor the share name means the server
        // wants something this client does not offer: Samba answers SMB 2-only
        // with NOT_SUPPORTED (M-T9), signing algorithms it lacks with
        // INVALID_PARAMETER and required encryption without a common cipher
        // with ACCESS_DENIED at tree connect (M-T14).
        if (stage == Stage::SessionSetup && !keepsMeaningInSetup(r.error())) {
            // Samba gives the same ACCESS_DENIED for an account that may not
            // use the share and for a missing common cipher, so name both.
            const char *reason = ntStatus == SMB2_STATUS_ACCESS_DENIED ? ShareRefusedMessage
                                                                       : SessionRefusedMessage;
            r = Result(Error::SecurityPolicy, withContext(context, QStringLiteral("%1 (NT status %2)")
                                                                       .arg(QLatin1String(reason),
                                                                            hexStatus(ntStatus))));
        }
        return r;
    }
    if (errnoValue == ETIMEDOUT)
        return Result(Error::Timeout, withContext(context, QStringLiteral("the server did not answer in time")));
    if (stage == Stage::SessionSetup) {
        if (isTransportErrno(errnoValue))
            return errorForSocket(errnoValue, context);
        return Result(Error::SecurityPolicy, withContext(context, QLatin1String(ServerClosedMessage)));
    }
    // Compound requests (stat, mkdir, unlink, rename, free space) report the
    // server's NT status only as -nterror_to_errno(status) and leave
    // smb2_get_nterror() at 0 (vendor/libsmb2 lib/libsmb2.c). That errno is a
    // function of the NT status (lib/errors.c), so it is mapped the same way.
    for (const ErrnoEntry &entry : errnoTable) {
        if (entry.errnoValue == errnoValue)
            return Result(entry.error, withContext(context, QLatin1String(entry.message)));
    }
    return Result(Error::ProtocolError,
                  withContext(context, QStringLiteral("request failed (%1)")
                                           .arg(QString::fromLocal8Bit(std::strerror(errnoValue)))));
}

Result connectionLost(Stage stage)
{
    if (stage == Stage::SessionSetup)
        return Result(Error::SecurityPolicy, QLatin1String(ServerClosedMessage));
    return Result(Error::NetworkUnreachable, QLatin1String(ConnectionLostMessage));
}

Result errorForSocket(int errnoValue, const QString &context)
{
    if (errnoValue == ECANCELED)
        return Result(Error::Canceled);
    const QString reason = QString::fromLocal8Bit(std::strerror(errnoValue));
    if (errnoValue == ETIMEDOUT)
        return Result(Error::Timeout, withContext(context, reason));
    return Result(Error::NetworkUnreachable, withContext(context, reason));
}

bool requireEncryption(const QVariantMap &options)
{
    return options.value(QStringLiteral("require_encryption"), true).toBool();
}

bool isSmb3Dialect(quint16 dialect)
{
    return dialect == SMB2_VERSION_0300 || dialect == SMB2_VERSION_0302 || dialect == SMB2_VERSION_0311;
}

QString dialectName(quint16 dialect)
{
    return QStringLiteral("%1.%2.%3").arg(dialect >> 8).arg((dialect >> 4) & 0xf).arg(dialect & 0xf);
}

QByteArray serverString(const QString &numericHost, int port)
{
    QByteArray server = numericHost.toUtf8();
    if (port <= 0 || port == 445)
        return server;
    if (numericHost.contains(QLatin1Char(':')))
        server = '[' + server + ']';
    return server + ':' + QByteArray::number(port);
}

Result probeTcp(const QString &host, int port, int timeoutMs, const std::atomic<bool> &cancel,
                QString *numericHost)
{
    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *found = nullptr;
    if (const int rc = ::getaddrinfo(host.toUtf8().constData(), QByteArray::number(port).constData(), &hints, &found);
        rc != 0) {
        // C-17: no host names in results, which may be logged at warning level.
        return Result(Error::NetworkUnreachable, QStringLiteral("Cannot resolve the server name: %1")
                                                     .arg(QString::fromLocal8Bit(gai_strerror(rc))));
    }
    const std::unique_ptr<addrinfo, AddrInfoDeleter> list(found);

    QElapsedTimer clock;
    clock.start();
    int err = ETIMEDOUT;
    for (const addrinfo *ai = list.get(); ai; ai = ai->ai_next) {
        err = connectOne(ai, clock, timeoutMs, cancel);
        if (err == 0) {
            std::array<char, NI_MAXHOST> name = {};
            if (::getnameinfo(ai->ai_addr, ai->ai_addrlen, name.data(), name.size(), nullptr, 0, NI_NUMERICHOST) != 0)
                return Result(Error::Internal, QStringLiteral("Cannot format the server address"));
            *numericHost = QString::fromLatin1(name.data());
            return Result::success();
        }
        if (err == ECANCELED || err == ETIMEDOUT)
            break;
    }
    return errorForSocket(err, QStringLiteral("Cannot connect to the server"));
}

} // namespace NetVfs::Smb
