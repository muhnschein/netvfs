// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ftpsupport.h"
#include "names.h"
#include "paths.h"

#include <array>

Q_LOGGING_CATEGORY(lcNetVfsFtp, "netvfs.ftp", QtWarningMsg)

namespace NetVfs::Ftp {

namespace {

constexpr const char *TlsModeOption = "tls_mode";
constexpr const char *InsecureOption = "allow_insecure";
constexpr const char *HostKeyOption = "host_key";
constexpr const char *VerifyPeerOption = "tls_verify_peer";
constexpr int MaxPort = 65535;

bool unreserved(uchar c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
        || c == '-' || c == '.' || c == '_' || c == '~';
}

QString serverText(const Reply &reply)
{
    // Server text is untrusted and may be long; it goes into detail() only.
    return QString::fromUtf8(reply.text()).left(512);
}

QString detailOf(const Reply &reply)
{
    if (!reply.isValid())
        return QString();
    return QStringLiteral("FTP %1 %2").arg(reply.code).arg(serverText(reply));
}

bool mentions(const QByteArray &lower, std::initializer_list<const char *> needles)
{
    for (const char *needle : needles) {
        if (lower.contains(needle))
            return true;
    }
    return false;
}

// F-7: 550 "requested action not taken" covers missing files, missing
// permissions and more; the server's message decides, PermissionDenied is
// the fallback.
Error classify550(const QByteArray &text, bool *ambiguous)
{
    const QByteArray lower = text.toLower();
    if (mentions(lower, { "already exists", "file exists", "directory exists" }))
        return Error::AlreadyExists;
    if (mentions(lower, { "not empty" }))
        return Error::DirectoryNotEmpty;
    if (mentions(lower, { "not a directory", "not a folder" }))
        return Error::NotADirectory;
    if (mentions(lower, { "is a directory", "is a folder" }))
        return Error::IsADirectory;
    if (mentions(lower, { "permission denied", "access denied", "access is denied", "not allowed", "forbidden",
                          "not permitted", "insufficient privileges" }))
        return Error::PermissionDenied;
    if (mentions(lower, { "no such file", "no such directory", "not found", "does not exist", "doesn't exist",
                          "not exist", "cannot find", "can't find", "can not find", "no files found" }))
        return Error::NotFound;
    if (ambiguous)
        *ambiguous = true;
    return Error::PermissionDenied;
}

Error classify421(const QByteArray &text)
{
    if (const QByteArray lower = text.toLower();
            mentions(lower, { "too many", "connection limit", "maximum number", "max number", "limit reached",
                          "try again later", "max clients", "users", "connections from your" }))
        return Error::TooManyConnections;
    return Error::ConnectionLost;
}

Error errorForCode(const Reply &reply, bool *ambiguous)
{
    switch (reply.code) {
    case 530:
    case 532:
        return Error::AuthFailed;
    case 550:
        return classify550(reply.text(), ambiguous);
    case 452:
    case 552:
        return Error::NoSpace;
    case 553:
        return Error::InvalidName;
    case 421:
        return classify421(reply.text());
    case 425:
    case 426:
        return Error::ConnectionLost;
    case 450:
        return Error::Locked;
    case 500:
    case 502:
    case 504:
        return Error::Unsupported;
    default:
        return Error::ProtocolError;
    }
}

QString describe(Error error)
{
    switch (error) {
    case Error::AuthFailed: return QStringLiteral("sign-in refused");
    case Error::NotFound: return QStringLiteral("not found");
    case Error::PermissionDenied: return QStringLiteral("permission denied");
    case Error::AlreadyExists: return QStringLiteral("already exists");
    case Error::DirectoryNotEmpty: return QStringLiteral("folder not empty");
    case Error::NotADirectory: return QStringLiteral("not a folder");
    case Error::IsADirectory: return QStringLiteral("is a folder");
    case Error::NoSpace: return QStringLiteral("no space left on the server");
    case Error::InvalidName: return QStringLiteral("name not allowed by the server");
    case Error::TooManyConnections: return QStringLiteral("too many connections");
    case Error::ConnectionLost: return QStringLiteral("connection lost");
    case Error::Locked: return QStringLiteral("file busy");
    case Error::Unsupported: return QStringLiteral("not supported by the server");
    default: return QStringLiteral("refused by the server");
    }
}

// Results that do not depend on a server reply.
bool transportError(CURLcode code, Result *out, const QString &d)
{
    switch (code) {
    case CURLE_OPERATION_TIMEDOUT:
        *out = Result(Error::Timeout, QStringLiteral("The server did not answer in time"), d);
        return true;
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_CONNECT:
        *out = Result(Error::NetworkUnreachable, QStringLiteral("Could not reach the server"), d);
        return true;
    case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
    case CURLE_PEER_FAILED_VERIFICATION:
        *out = Result(Error::ServerIdentityChanged, QStringLiteral("The server certificate does not match the accepted one"), d);
        return true;
    case CURLE_USE_SSL_FAILED:
        *out = Result(Error::SecurityPolicy, QStringLiteral("The server does not offer TLS"), d);
        return true;
    case CURLE_SSL_CONNECT_ERROR:
        *out = Result(Error::SecurityPolicy, QStringLiteral("The TLS handshake failed"), d);
        return true;
    case CURLE_RECV_ERROR:
    case CURLE_SEND_ERROR:
    case CURLE_GOT_NOTHING:
    case CURLE_PARTIAL_FILE:
        *out = Result(Error::ConnectionLost, QStringLiteral("The connection to the server was lost"), d);
        return true;
    case CURLE_WRITE_ERROR:
    case CURLE_READ_ERROR:
        *out = Result(Error::Internal, QStringLiteral("Local data transfer failed"), d);
        return true;
    case CURLE_OUT_OF_MEMORY:
        *out = Result(Error::Internal, QStringLiteral("Out of memory"), d);
        return true;
    default:
        return false;
    }
}

Error fallbackFor(CURLcode code)
{
    switch (code) {
    case CURLE_LOGIN_DENIED:
        return Error::AuthFailed;
    case CURLE_REMOTE_FILE_NOT_FOUND:
        return Error::NotFound;
    case CURLE_REMOTE_ACCESS_DENIED:
    case CURLE_UPLOAD_FAILED:
        return Error::PermissionDenied;
    case CURLE_REMOTE_DISK_FULL:
        return Error::NoSpace;
    case CURLE_FTP_COULDNT_USE_REST:
        return Error::Unsupported;
    default:
        return Error::ProtocolError;
    }
}

} // namespace

Result settingsFrom(const ConnectionParams &params, Settings *out)
{
    Settings settings;
    if (params.host.isEmpty() || params.host.contains(QLatin1Char('@')) || params.host.contains(QLatin1Char('/')))
        return Result(Error::Internal, QStringLiteral("Invalid server name"));
    if (const QString mode = params.option(QLatin1String(TlsModeOption), QStringLiteral("explicit")).toLower();
            mode == QLatin1String("explicit")) {
        settings.tlsMode = TlsMode::Explicit;
    } else if (mode == QLatin1String("implicit")) {
        settings.tlsMode = TlsMode::Implicit;
    } else if (mode == QLatin1String("none")) {
        if (!params.flag(QLatin1String(InsecureOption)))
            return Result(Error::SecurityPolicy, QStringLiteral("Unencrypted FTP needs the insecure connection consent"));
        settings.tlsMode = TlsMode::None;
    } else {
        return Result(Error::SecurityPolicy, QStringLiteral("Unknown TLS mode %1").arg(mode));
    }
    if (params.port < 0 || params.port > MaxPort)
        return Result(Error::Internal, QStringLiteral("Invalid port"));
    settings.host = params.host;
    settings.port = params.port;
    if (settings.port == 0)
        settings.port = settings.tlsMode == TlsMode::Implicit ? ImplicitPort : ExplicitPort;
    settings.pin = params.option(QLatin1String(HostKeyOption)).trimmed();
    settings.verifyPeer = params.flag(QLatin1String(VerifyPeerOption));
#ifdef NETVFS_TLS_TEST_HOOKS
    settings.testCaFile = params.option(QStringLiteral("test_ca_file")).toLocal8Bit();
#endif
    *out = settings;
    return Result::success();
}

QByteArray baseUrl(const Settings &settings)
{
    QByteArray host = settings.host.toUtf8();
    if (host.contains(':') && !host.startsWith('['))
        host = '[' + host + ']';
    const QByteArray scheme = settings.tlsMode == TlsMode::Implicit ? "ftps" : "ftp";
    return scheme + "://" + host + ':' + QByteArray::number(settings.port) + '/';
}

QByteArray urlPath(const QByteArray &remotePath)
{
    QByteArray out;
    int from = 0;
    if (remotePath.startsWith('/')) {
        out += "%2F";
        from = 1;
    }
    for (int i = from; i < remotePath.size(); ++i) {
        if (const auto c = uchar(remotePath.at(i)); c == '/' || unreserved(c))
            out += char(c);
        else
            out += '%' + QByteArray(1, char(c)).toHex().toUpper();
    }
    return out;
}

Result remotePath(const QString &path, const QByteArray &home, QByteArray *out)
{
    QString normalized;
    Result r = Paths::normalize(path, &normalized);
    if (!r.ok())
        return r;
    if (!Names::isEncodable(normalized))
        return Result(Error::InvalidName, QStringLiteral("The name cannot be represented on the server"));
    const QByteArray bytes = Names::encode(normalized);
    if (bytes.contains('\r') || bytes.contains('\n') || bytes.contains('\0'))
        return Result(Error::InvalidName, QStringLiteral("Names with line breaks are not supported over FTP"));
    if (Paths::isAbsolute(normalized)) {
        *out = bytes;
    } else if (bytes.isEmpty()) {
        *out = home;
    } else {
        *out = home.endsWith('/') ? home + bytes : home + '/' + bytes;
    }
    return Result::success();
}

QByteArray remoteParent(const QByteArray &remote)
{
    const int slash = remote.lastIndexOf('/');
    if (slash <= 0)
        return QByteArrayLiteral("/");
    return remote.left(slash);
}

Result replyError(const Reply &reply, const QString &context, bool *ambiguous)
{
    if (ambiguous)
        *ambiguous = false;
    const Error error = errorForCode(reply, ambiguous);
    return Result(error, QStringLiteral("%1: %2").arg(context, describe(error)), detailOf(reply));
}

Result curlError(CURLcode code, const Reply &reply, bool canceled, const QString &context)
{
    if (canceled || code == CURLE_ABORTED_BY_CALLBACK)
        return Result(Error::Canceled);
    const QString detail = detailOf(reply).isEmpty()
        ? QStringLiteral("curl %1: %2").arg(int(code)).arg(QString::fromUtf8(curl_easy_strerror(code)))
        : detailOf(reply);
    // libcurl reports any 421 ("service not available, closing control
    // connection") as CURLE_OPERATION_TIMEDOUT; the reply says why (F-7).
    if (reply.isValid() && reply.code == 421)
        return replyError(reply, context);
    Result result;
    if (transportError(code, &result, detail))
        return result;
    if (reply.isValid() && reply.code >= 400)
        return replyError(reply, context);
    const Error error = fallbackFor(code);
    return Result(error, QStringLiteral("%1: %2").arg(context, describe(error)), detail);
}

namespace {

constexpr int CodeDigits = 3;
constexpr int ReplyCodeRadix = 10;

bool isAsciiDigit(char c)
{
    return c >= '0' && c <= '9';
}

// libcurl's ftp_endofresp(): a line of more than three bytes that starts with
// three digits and a space ends a reply; its digits are the reply code.
// -1 for any other line.
int endOfReplyCode(const QByteArray &line)
{
    if (line.size() <= CodeDigits || line.at(CodeDigits) != ' ')
        return -1;
    int code = 0;
    for (int i = 0; i < CodeDigits; ++i) {
        if (!isAsciiDigit(line.at(i)))
            return -1;
        code = code * ReplyCodeRadix + (line.at(i) - '0');
    }
    return code;
}

} // namespace

void TlsGuard::reset()
{
    m_state = State::Idle;
    m_line.clear();
}

TlsGuard::Verdict TlsGuard::feed(const char *data, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        if (m_line.size() < MaxLineBytes)
            m_line.append(data[i]);
        if (data[i] != '\n')
            continue;
        const int code = endOfReplyCode(m_line);
        if (code >= 0)
            m_lastLine = m_line;
        m_line.clear();
        if (code < 0)
            continue;
        const Verdict verdict = reply(code);
        if (verdict != Verdict::Continue)
            return verdict;
    }
    return Verdict::Continue;
}

TlsGuard::Verdict TlsGuard::reply(int code)
{
    switch (m_state) {
    case State::Idle:
        // The greeting of a new connection (we never send REIN); 230 is a
        // server that claims we are logged in already, which libcurl takes
        // for the greeting in "try" mode and then skips AUTH TLS and USER.
        if (code == 220) {
            m_state = State::AwaitAuth;
            return Verdict::Continue;
        }
        return code == 230 ? Verdict::Unexpected : Verdict::Continue;
    case State::AwaitAuth:
        // Anything but 234 (also 220, 334 and 5xx) is an AUTH TLS refusal,
        // after which libcurl would try "AUTH SSL" and then USER.
        if (code != 234)
            return Verdict::AuthRefused;
        m_state = State::AwaitLogin;
        return Verdict::Continue;
    case State::AwaitLogin:
        if (code == 220)   // a greeting in the middle of a sign-in
            return Verdict::Unexpected;
        if (code / 100 == 2)
            m_state = State::AwaitPbsz;
        return Verdict::Continue;
    case State::AwaitPbsz:
        if (code == 220)
            return Verdict::Unexpected;
        m_state = State::AwaitProt;
        return Verdict::Continue;
    case State::AwaitProt:
        if (code / 100 != 2)
            return Verdict::ProtectionRefused;
        m_state = State::Idle;
        return Verdict::Continue;
    }
    return Verdict::Continue;
}

QString lineForLog(const QByteArray &line)
{
    return Names::display(Names::decode(line.trimmed()));
}

QString replyForLog(const Reply &reply)
{
    QStringList lines;
    for (const QByteArray &line : reply.lines)
        lines.append(Names::display(Names::decode(line)));
    return lines.join(QLatin1String(" | "));
}

} // namespace NetVfs::Ftp
