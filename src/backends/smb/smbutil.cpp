// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbutil.h"
#include "smb2api.h"
#include "smbshares.h"

#include "logging.h"
#include "paths.h"

#include <QtCore/QElapsedTimer>

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>

#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

namespace NetVfs::Smb {

namespace {

const int PollSliceMs = 100;
const char *const UserFileVariable = "NTLM_USER_FILE";
// MS-ERREF; libsmb2 names only STATUS_PATH_NOT_COVERED.
const quint32 StatusDfsUnavailable = 0xC000026D;

struct StatusEntry {
    quint32 status;
    Error error;
    const char *message;
};

// SPEC-smb 5, error mapping. Only AuthFailed leads to an attention state,
// which callers derive with attentionForError().
const std::array<StatusEntry, 22> statusTable = { {
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
    // SPEC-v2 XC-9, XC-21
    { SMB2_STATUS_FILE_IS_A_DIRECTORY, Error::IsADirectory, "this is a folder" },
    { SMB2_STATUS_NOT_A_DIRECTORY, Error::NotADirectory, "this is not a folder" },
    { SMB2_STATUS_DIRECTORY_NOT_EMPTY, Error::DirectoryNotEmpty, "the folder is not empty" },
    { SMB2_STATUS_SHARING_VIOLATION, Error::Locked, "the file is in use" },
} };

struct ErrnoEntry {
    int errnoValue;
    Error error;
    const char *message;
};

// The errno values libsmb2's nterror_to_errno() produces for the NT statuses
// of the table above.
const std::array<ErrnoEntry, 9> errnoTable = { {
    { ENOENT, Error::NotFound, "no such file or folder" },
    { EACCES, Error::PermissionDenied, "access denied" },
    { EPERM, Error::PermissionDenied, "operation not permitted" },
    { EEXIST, Error::AlreadyExists, "the name already exists" },
    { ENOSPC, Error::NoSpace, "the share is full" },
    { ENETRESET, Error::ConnectionLost, ConnectionLostMessage },
    { ENOTDIR, Error::NotADirectory, "this is not a folder" },
    { ENOTEMPTY, Error::DirectoryNotEmpty, "the folder is not empty" },
    { ETXTBSY, Error::Locked, "the file is in use" },
} };

QString withContext(const QString &context, const QString &message)
{
    return context.isEmpty() ? message : context + QStringLiteral(": ") + message;
}

QString hexStatus(quint32 ntStatus)
{
    return QStringLiteral("0x%1").arg(ntStatus, 8, 16, QLatin1Char('0'));
}

// XM-9: DFS referrals are out of scope; the path is on another server.
Result dfsReferral(const QString &context)
{
    return Result(Error::Unsupported,
                  withContext(context, QStringLiteral("the path is a DFS link to another server, which is not supported")),
                  QLatin1String(DfsDetail));
}

Result errorForNtStatus(quint32 ntStatus, const QString &context)
{
    if (ntStatus == SMB2_STATUS_PATH_NOT_COVERED || ntStatus == StatusDfsUnavailable)
        return dfsReferral(context);
    // XC-24: the status for a "Details" view.
    const QString detail = QStringLiteral("NT status %1 (%2)").arg(hexStatus(ntStatus), QLatin1String(nterror_to_str(ntStatus)));
    for (const StatusEntry &entry : statusTable) {
        if (entry.status == ntStatus) {
            return Result(entry.error,
                          withContext(context, QStringLiteral("%1 (NT status %2)")
                                                   .arg(QLatin1String(entry.message), hexStatus(ntStatus))),
                          detail);
        }
    }
    return Result(Error::ProtocolError, withContext(context, detail), detail);
}

bool keepsMeaningInSetup(Error error)
{
    return error == Error::AuthFailed || error == Error::NotFound || error == Error::Timeout
        || error == Error::Unsupported;
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

namespace {

// M-8: relative to the share root (or, in server mode, to the server).
QString relativePath(const QString &normalized)
{
    return normalized.startsWith(QLatin1Char('/')) ? normalized.mid(1) : normalized;
}

void appendUtf8(QByteArray *out, uint u)
{
    if (u < 0x80) {
        out->append(static_cast<char>(u));
    } else if (u < 0x800) {
        out->append(static_cast<char>(0xc0 | (u >> 6)));
        out->append(static_cast<char>(0x80 | (u & 0x3f)));
    } else if (u < 0x10000) {
        // Also an unpaired surrogate: its 3-byte form (WTF-8).
        out->append(static_cast<char>(0xe0 | (u >> 12)));
        out->append(static_cast<char>(0x80 | ((u >> 6) & 0x3f)));
        out->append(static_cast<char>(0x80 | (u & 0x3f)));
    } else {
        out->append(static_cast<char>(0xf0 | (u >> 18)));
        out->append(static_cast<char>(0x80 | ((u >> 12) & 0x3f)));
        out->append(static_cast<char>(0x80 | ((u >> 6) & 0x3f)));
        out->append(static_cast<char>(0x80 | (u & 0x3f)));
    }
}

int sequenceLength(uchar lead)
{
    if (lead < 0x80)
        return 1;
    if ((lead & 0xe0) == 0xc0)
        return 2;
    if ((lead & 0xf0) == 0xe0)
        return 3;
    if ((lead & 0xf8) == 0xf0)
        return 4;
    return 0;
}

// One code point (surrogates included) of a WTF-8 string, or U+FFFD for a
// malformed sequence (libsmb2 never produces one); advances `*at`.
uint nextCodePoint(const uchar *bytes, int size, int *at)
{
    constexpr uint Replacement = 0xfffd;
    constexpr std::array<uint, 5> minimum = { 0, 0, 0x80, 0x800, 0x10000 };
    const int length = sequenceLength(bytes[*at]);
    if (length == 0 || *at + length > size) {
        ++*at;
        return Replacement;
    }
    uint u = bytes[*at] & (0x7fu >> length);
    if (length == 1)
        u = bytes[*at];
    for (int i = 1; i < length; ++i) {
        const uchar c = bytes[*at + i];
        if ((c & 0xc0) != 0x80) {
            ++*at;
            return Replacement;
        }
        u = (u << 6) | (c & 0x3f);
    }
    *at += length;
    return (u < minimum[static_cast<size_t>(length)] || u > 0x10ffff) ? Replacement : u;
}

} // namespace

QString decodeName(const char *utf8)
{
    const auto *bytes = reinterpret_cast<const uchar *>(utf8);
    const int size = static_cast<int>(std::strlen(utf8));
    QString name;
    name.reserve(size);
    int at = 0;
    while (at < size) {
        const uint u = nextCodePoint(bytes, size, &at);
        if (QChar::requiresSurrogates(u)) {
            name.append(QChar(QChar::highSurrogate(u)));
            name.append(QChar(QChar::lowSurrogate(u)));
        } else {
            name.append(QChar(static_cast<ushort>(u)));
        }
    }
    return name;
}

QByteArray encodeName(const QString &name)
{
    QByteArray out;
    out.reserve(name.size() * 3);
    int i = 0;
    while (i < name.size()) {
        const QChar c = name.at(i++);
        if (c.isHighSurrogate() && i < name.size() && name.at(i).isLowSurrogate())
            appendUtf8(&out, QChar::surrogateToUcs4(c, name.at(i++)));
        else
            appendUtf8(&out, c.unicode());   // a lone surrogate included (WTF-8)
    }
    return out;
}

Result translatePath(const QString &path, QByteArray *out)
{
    QString normalized;
    if (Result r = Paths::normalize(path, &normalized); !r.ok())
        return r;
    normalized = relativePath(normalized);
    // M-9: names Windows servers cannot store are rejected before any request.
    if (Result r = Paths::checkWindowsPath(normalized); !r.ok())
        return r;
    *out = encodeName(normalized);
    return Result::success();
}

Result splitServerPath(const QString &path, QString *share, QByteArray *rest)
{
    QString normalized;
    if (Result r = Paths::normalize(path, &normalized); !r.ok())
        return r;
    normalized = relativePath(normalized);
    const int slash = normalized.indexOf(QLatin1Char('/'));
    *share = slash < 0 ? normalized : normalized.left(slash);
    if (!share->isEmpty() && !validShareName(*share))
        return Result(Error::InvalidName, QStringLiteral("not a valid share name"));
    const QString inside = slash < 0 ? QString() : normalized.mid(slash + 1);
    if (Result r = Paths::checkWindowsPath(inside); !r.ok())
        return r;
    *rest = encodeName(inside);
    return Result::success();
}

void mergeShareNames(QStringList *list, const QStringList &more)
{
    for (const QString &name : more) {
        if (!list->contains(name, Qt::CaseInsensitive))
            list->append(name);
    }
}

QStringList configuredShares(const QVariantMap &options)
{
    const QVariant value = options.value(QStringLiteral("shares"));
    QStringList raw;
    if (value.type() == QVariant::StringList || value.type() == QVariant::List)
        raw = value.toStringList();
    else
        raw = value.toString().split(QLatin1Char(','));
    QStringList candidates;
    for (const QString &item : raw) {
        const QString name = item.trimmed();
        if (validShareName(name))
            candidates.append(name);
        else if (!name.isEmpty())
            qCDebug(lcNetVfsSmb) << "Ignoring an invalid share name in the account options:" << name;
    }
    QStringList shares;
    mergeShareNames(&shares, candidates);
    return shares;
}

Result profileFromOptions(const QVariantMap &options, Profile *out)
{
    const QString name = options.value(QStringLiteral("security_profile")).toString().trimmed();
    if (name.isEmpty()) {
        // XM-1: the v1 option keeps its meaning (M-3: default on).
        const bool encrypt = options.value(QStringLiteral("require_encryption"), true).toBool();
        *out = encrypt ? Profile::Strict : Profile::Signed;
        return Result::success();
    }
    for (const Profile profile : { Profile::Strict, Profile::Signed, Profile::Legacy, Profile::Guest }) {
        if (name == profileName(profile)) {
            *out = profile;
            return Result::success();
        }
    }
    return Result(Error::SecurityPolicy, QStringLiteral("unknown SMB security profile \"%1\"").arg(name));
}

ProfileSettings settingsFor(Profile profile)
{
    // SPEC-v2 XM-1 table.
    ProfileSettings s;
    s.version = SMB2_VERSION_ANY3;
    switch (profile) {
    case Profile::Strict:
        break;
    case Profile::Signed:
        s.encryption = Encryption::IfServerAsks;
        break;
    case Profile::Legacy:
        s.version = SMB2_VERSION_ANY;
        s.encryption = Encryption::IfServerAsks;
        break;
    case Profile::Guest:
        s.version = SMB2_VERSION_ANY;
        s.signing = false;
        s.encryption = Encryption::Off;
        s.guest = true;
        break;
    }
    return s;
}

QString profileName(Profile profile)
{
    switch (profile) {
    case Profile::Strict:
        return QStringLiteral("strict");
    case Profile::Signed:
        return QStringLiteral("signed");
    case Profile::Legacy:
        return QStringLiteral("legacy");
    case Profile::Guest:
        return QStringLiteral("guest");
    }
    return QString();
}

bool dialectAllowed(Profile profile, quint16 dialect)
{
    if (isSmb3Dialect(dialect))
        return true;
    // SMB 2.0.2 and 2.1 only where the profile offered them (SMB2_VERSION_ANY).
    return settingsFor(profile).version == SMB2_VERSION_ANY
        && (dialect == SMB2_VERSION_0202 || dialect == SMB2_VERSION_0210);
}

Result checkSessionFlags(Profile profile, quint16 sessionFlags)
{
    if (profile == Profile::Guest)
        return Result::success();
    if (sessionFlags & (SMB2_SESSION_FLAG_IS_GUEST | SMB2_SESSION_FLAG_IS_NULL))
        return Result(Error::SecurityPolicy, QLatin1String(GuestMappedMessage));
    return Result::success();
}

void applyProfile(smb2_context *ctx, Profile profile, const QString &user, const QString &domain,
                  const QByteArray &secret, int requestTimeoutMs)
{
    // SPEC-smb section 3, amended by SPEC-v2 XM-1. Nothing is negotiated
    // down from what the profile says (XSEC-2).
    const ProfileSettings s = settingsFor(profile);
    smb2_set_version(ctx, static_cast<smb2_negotiate_version>(s.version));             // M-1
    if (s.signing) {                                                                  // M-2
        smb2_set_security_mode(ctx, SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED);
        smb2_set_sign(ctx, 1);
    } else {
        smb2_set_security_mode(ctx, SMB2_NEGOTIATE_SIGNING_ENABLED);
        smb2_set_sign(ctx, 0);
    }
    if (s.encryption == Encryption::Required)                                         // M-3
        smb2_set_seal(ctx, 1);
    else if (s.encryption == Encryption::Off)
        smb2_set_seal(ctx, 0);
    smb2_set_authentication(ctx, SMB2_SEC_NTLMSSP);                                    // M-4
    smb2_set_timeout(ctx, qMax(1, requestTimeoutMs / 1000));                           // M-7

    // M-5: smb2_set_user() and smb2_set_domain() read NTLM_USER_FILE and may
    // replace the password, so the variable goes first and the password last.
    neutraliseUserFile();
    smb2_set_user(ctx, s.guest ? "" : user.toUtf8().constData());
    if (!s.guest && !domain.isEmpty())
        smb2_set_domain(ctx, domain.toUtf8().constData());
    // Guest: no password, which makes libsmb2's NTLMSSP anonymous.
    smb2_set_password(ctx, s.guest ? nullptr : secret.constData());
}

Result checkSession(smb2_context *ctx, Profile profile, const Result &signIn)
{
    // XM-1: a session the server mapped to guest is never accepted in place
    // of the account's own, and is named as such also when it made the
    // sign-in fail (a guest session cannot sign its replies).
    if (Result r = checkSessionFlags(profile, smb2_get_session_flags(ctx)); !r.ok())
        return r;
    if (!signIn.ok())
        return signIn;
    const quint16 dialect = smb2_get_dialect(ctx);
    if (!dialectAllowed(profile, dialect)) {
        // M-1, defence in depth: never accept a dialect that was not offered.
        return Result(Error::SecurityPolicy, QStringLiteral("The server negotiated SMB %1, which the %2 profile does not allow")
                                                 .arg(dialectName(dialect), profileName(profile)));
    }
    return Result::success();
}

void neutraliseUserFile()
{
    if (!qEnvironmentVariableIsSet(UserFileVariable))
        return;
    qCWarning(lcNetVfsSmb) << "Ignoring NTLM_USER_FILE: the account's own password is used (SPEC-smb M-5)";
    qunsetenv(UserFileVariable);
}

SigPipeGuard::SigPipeGuard()
{
    sigemptyset(&m_set);
    sigaddset(&m_set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &m_set, &m_old);
}

SigPipeGuard::~SigPipeGuard()
{
    const timespec zero = { 0, 0 };
    while (sigtimedwait(&m_set, nullptr, &zero) > 0) {
        // drain
    }
    pthread_sigmask(SIG_SETMASK, &m_old, nullptr);
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
    // ENOEXEC stands for STATUS_PATH_NOT_COVERED there (XM-9).
    if (errnoValue == ENOEXEC)
        return dfsReferral(context);
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
    return Result(Error::ConnectionLost, QLatin1String(ConnectionLostMessage));   // XC-21
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
