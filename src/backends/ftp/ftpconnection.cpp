// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ftpconnection.h"
#include "curltls.h"
#include "secure.h"

#include <QtCore/QDebug>

namespace NetVfs::Ftp {

namespace {

constexpr int PollIntervalMs = 100;          // C-9: cancel is seen within this
constexpr long LowSpeedLimit = 1;            // bytes/s; below it for requestTimeout → Timeout
constexpr int MillisecondsPerSecond = 1000;
constexpr long QuitTimeoutSeconds = 1;
constexpr const char *Protocols = "ftp,ftps";

long seconds(int milliseconds)
{
    return std::max(1L, long((milliseconds + MillisecondsPerSecond - 1) / MillisecondsPerSecond));
}

// Options shared by the probe and the control connection (XSEC-4, XSEC-2,
// C-14, F-1).
CURLcode applyCommon(CURL *easy, const QByteArray &url, const Settings &settings, const ConnectionParams &params,
                     long useSsl)
{
    const std::initializer_list<std::function<CURLcode()>> steps = {
        [&] { return curl_easy_setopt(easy, CURLOPT_URL, url.constData()); },
        [&] { return curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, Protocols); },
        [&] { return curl_easy_setopt(easy, CURLOPT_NETRC, long(CURL_NETRC_IGNORED)); },
        // An empty proxy disables the proxy environment variables (XSEC-4).
        [&] { return curl_easy_setopt(easy, CURLOPT_PROXY, ""); },
        [&] { return curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L); },
        [&] { return curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L); },
        [&] { return curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, long(params.connectTimeoutMs)); },
        [&] { return curl_easy_setopt(easy, CURLOPT_SERVER_RESPONSE_TIMEOUT, seconds(params.requestTimeoutMs)); },
        [&] { return curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, LowSpeedLimit); },
        [&] { return curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, seconds(params.requestTimeoutMs)); },
        [&] { return curl_easy_setopt(easy, CURLOPT_USE_SSL, settings.tlsMode == TlsMode::None ? long(CURLUSESSL_NONE) : useSsl); },
        [&] { return curl_easy_setopt(easy, CURLOPT_FTPSSLAUTH, long(CURLFTPAUTH_TLS)); },
        [&] { return curl_easy_setopt(easy, CURLOPT_SSLVERSION, long(CURL_SSLVERSION_TLSv1_2)); },
        // Passive only (F-1): EPSV, then PASV; the address in a PASV reply is
        // ignored in favour of the control connection's (no bounce).
        [&] { return curl_easy_setopt(easy, CURLOPT_FTP_USE_EPSV, 1L); },
        [&] { return curl_easy_setopt(easy, CURLOPT_FTP_USE_EPRT, 0L); },
        [&] { return curl_easy_setopt(easy, CURLOPT_FTPPORT, nullptr); },
        [&] { return curl_easy_setopt(easy, CURLOPT_FTP_SKIP_PASV_IP, 1L); },
        [&] { return curl_easy_setopt(easy, CURLOPT_FTP_FILEMETHOD, long(CURLFTPMETHOD_NOCWD)); },
        [&] { return curl_easy_setopt(easy, CURLOPT_FTP_CREATE_MISSING_DIRS, long(CURLFTP_CREATE_DIR_NONE)); },
        [&] { return curl_easy_setopt(easy, CURLOPT_TRANSFERTEXT, 0L); },
    };
    for (const auto &step : steps) {
        const CURLcode code = step();
        if (code != CURLE_OK)
            return code;
    }
    return CURLE_OK;
}

// Runs `easy` in `multi` until it is done or canceled. Returns false on
// cancel (the handle is removed either way).
bool drive(CURLM *multi, CURL *easy, const std::atomic<bool> *canceled, CURLcode *result)
{
    curl_multi_add_handle(multi, easy);
    bool done = false;
    while (!done) {
        int running = 0;
        if (curl_multi_perform(multi, &running) != CURLM_OK) {
            *result = CURLE_FAILED_INIT;
            break;
        }
        int left = 0;
        while (CURLMsg *message = curl_multi_info_read(multi, &left)) {
            if (message->msg == CURLMSG_DONE && message->easy_handle == easy) {
                *result = message->data.result;
                done = true;
            }
        }
        if (!done && canceled && canceled->load()) {
            curl_multi_remove_handle(multi, easy);
            return false;
        }
        if (!done)
            curl_multi_poll(multi, nullptr, 0, PollIntervalMs, nullptr);
    }
    curl_multi_remove_handle(multi, easy);
    return true;
}

struct ProbeState {
    ReplyReader reader;
    bool stopAfterGreeting = false;
};

size_t probeHeader(char *data, size_t size, size_t count, void *self)
{
    auto *state = static_cast<ProbeState *>(self);
    const size_t length = size * count;
    state->reader.feed(data, length);
    if (state->reader.last().isValid())
        qCDebug(lcNetVfsFtp) << "probe reply:" << replyForLog(state->reader.last());
    // Plain FTP: the greeting is all the probe needs; aborting here means the
    // client never sends anything.
    if (state->stopAfterGreeting && state->reader.last().isValid())
        return 0;
    return length;
}

int probeProgress(void *self, curl_off_t, curl_off_t, curl_off_t, curl_off_t)
{
    const auto *canceled = static_cast<const std::atomic<bool> *>(self);
    return canceled && canceled->load() ? 1 : 0;
}

struct EasyDeleter { void operator()(CURL *easy) const { curl_easy_cleanup(easy); } };
struct MultiDeleter { void operator()(CURLM *multi) const { curl_multi_cleanup(multi); } };

} // namespace

size_t TransferSink::received(const char *, size_t)
{
    return 0;
}

size_t TransferSink::send(char *, size_t)
{
    return 0;
}

bool TransferSink::progress(qint64, qint64, qint64, qint64)
{
    return true;
}

Connection::Connection(const std::atomic<bool> *canceled)
    : m_canceled(canceled)
{
}

Connection::~Connection()
{
    close();
}

Result Connection::probe(const Settings &settings, const ConnectionParams &params,
                         const std::atomic<bool> *canceled, ServerIdentity *seen)
{
    *seen = ServerIdentity();
    const std::unique_ptr<CURL, EasyDeleter> easy(curl_easy_init());
    const std::unique_ptr<CURLM, MultiDeleter> multi(curl_multi_init());
    if (!easy || !multi)
        return Result(Error::Internal, QStringLiteral("Out of memory"));
    const bool tls = settings.tlsMode != TlsMode::None;
    if (tls && !CurlTls::isOpenSsl())
        return Result(Error::Unsupported, QStringLiteral("FTPS needs libcurl with OpenSSL"));
    ProbeState state;
    state.stopAfterGreeting = !tls;
    CurlTls::IdentityProbe identity(settings.host, CurlTls::trustAnchors(easy.get()));
    CURLcode code = applyCommon(easy.get(), baseUrl(settings), settings, params, long(CURLUSESSL_ALL));
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy.get(), CURLOPT_NOBODY, 1L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy.get(), CURLOPT_HEADERFUNCTION, &probeHeader);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy.get(), CURLOPT_HEADERDATA, &state);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy.get(), CURLOPT_NOPROGRESS, 0L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy.get(), CURLOPT_XFERINFOFUNCTION, &probeProgress);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy.get(), CURLOPT_XFERINFODATA, canceled);
    // The probe must never get past the handshake: refuse to run without the
    // OpenSSL hook rather than risk a USER command (C-7).
    if (code == CURLE_OK && tls)
        code = identity.install(easy.get());
    if (code != CURLE_OK)
        return Result(Error::Internal, QStringLiteral("libcurl rejected the connection settings"),
                      QString::fromUtf8(curl_easy_strerror(code)));

    qCDebug(lcNetVfsFtp) << "Connecting to" << settings.host << "port" << settings.port;
    CURLcode result = CURLE_OK;
    if (!drive(multi.get(), easy.get(), canceled, &result))
        return Result(Error::Canceled);
    if (tls && identity.captured()) {
        *seen = identity.identity();
        return Result::success();
    }
    const Reply &greeting = state.reader.last();
    if (!tls && greeting.code == 220)
        return Result::success();
    if (result == CURLE_USE_SSL_FAILED)   // AUTH TLS refused: no fallback (XSEC-2)
        return Result(Error::SecurityPolicy, QStringLiteral("The server does not offer TLS"), replyForLog(greeting));
    if (greeting.isValid() && greeting.code >= 400)
        return replyError(greeting, QStringLiteral("Connecting"));
    if (result == CURLE_OK || result == CURLE_WRITE_ERROR)
        return Result(Error::ProtocolError, QStringLiteral("The server did not greet as an FTP server"));
    return curlError(result, greeting, canceled && canceled->load(), QStringLiteral("Connecting"));
}

Result Connection::configure(const Settings &settings, const ConnectionParams &params, const QString &userName,
                             const QByteArray &secret, const ServerIdentity &seen)
{
    close();
    m_easy = curl_easy_init();
    m_multi = curl_multi_init();
    if (!m_easy || !m_multi)
        return Result(Error::Internal, QStringLiteral("Out of memory"));
    m_settings = settings;
    m_params = params;
    m_userName = userName.toUtf8();
    m_secret = QByteArray(secret.constData(), secret.size());
    m_seen = seen;
    m_expectReconnect = true;
    return applyBase(baseUrl(settings));
}

Result Connection::applyBase(const QByteArray &url)
{
    curl_easy_reset(m_easy);
    // Explicit TLS: libcurl's try mode plus TlsGuard (see there); implicit
    // TLS cannot fall back.
    const long useSsl = m_settings.tlsMode == TlsMode::Explicit ? long(CURLUSESSL_TRY) : long(CURLUSESSL_ALL);
    CURLcode code = applyCommon(m_easy, url, m_settings, m_params, useSsl);
    const std::initializer_list<std::function<CURLcode()>> steps = {
        [&] { return curl_easy_setopt(m_easy, CURLOPT_USERNAME, m_userName.constData()); },
        [&] { return curl_easy_setopt(m_easy, CURLOPT_PASSWORD, m_secret.constData()); },
        [&] { return curl_easy_setopt(m_easy, CURLOPT_HEADERFUNCTION, &Connection::onHeader); },
        [&] { return curl_easy_setopt(m_easy, CURLOPT_HEADERDATA, this); },
        [&] { return curl_easy_setopt(m_easy, CURLOPT_WRITEFUNCTION, &Connection::onWrite); },
        [&] { return curl_easy_setopt(m_easy, CURLOPT_WRITEDATA, this); },
        [&] { return curl_easy_setopt(m_easy, CURLOPT_READFUNCTION, &Connection::onRead); },
        [&] { return curl_easy_setopt(m_easy, CURLOPT_READDATA, this); },
        [&] { return curl_easy_setopt(m_easy, CURLOPT_NOPROGRESS, 0L); },
        [&] { return curl_easy_setopt(m_easy, CURLOPT_XFERINFOFUNCTION, &Connection::onProgress); },
        [&] { return curl_easy_setopt(m_easy, CURLOPT_XFERINFODATA, this); },
    };
    for (const auto &step : steps) {
        if (code == CURLE_OK)
            code = step();
    }
    if (code == CURLE_OK && m_settings.tlsMode != TlsMode::None)
        code = CurlTls::applyTrustAnchors(m_easy, CurlTls::trustAnchors(m_easy));
    if (code != CURLE_OK)
        return Result(Error::Internal, QStringLiteral("libcurl rejected the connection settings"),
                      QString::fromUtf8(curl_easy_strerror(code)));
    if (m_settings.tlsMode != TlsMode::None)
        return CurlTls::applyIdentityPolicy(m_easy, m_settings.pin, m_settings.pinTrusted, m_seen);
    return Result::success();
}

Result Connection::applyRequest(const Request &request)
{
    QByteArray url = baseUrl(m_settings);
    if (request.kind == Request::Kind::Download || request.kind == Request::Kind::Upload)
        url += urlPath(request.path);
    Result r = applyBase(url);
    if (!r.ok())
        return r;
    curl_slist *list = nullptr;
    for (const QByteArray &command : request.commands) {
        curl_slist *next = curl_slist_append(list, command.constData());
        if (!next) {
            curl_slist_free_all(list);
            return Result(Error::Internal, QStringLiteral("Out of memory"));
        }
        list = next;
    }
    m_quote.reset(list);
    CURLcode code = curl_easy_setopt(m_easy, CURLOPT_QUOTE, list);
    switch (request.kind) {
    case Request::Kind::Command:
        if (code == CURLE_OK)
            code = curl_easy_setopt(m_easy, CURLOPT_NOBODY, 1L);
        break;
    case Request::Kind::Listing:
        if (code == CURLE_OK)
            code = curl_easy_setopt(m_easy, CURLOPT_CUSTOMREQUEST, request.listCommand.constData());
        break;
    case Request::Kind::Download:
        // REST <offset>; with a length libcurl stops after it (ABOR) and
        // closes the control connection. (A resume offset would override
        // the range, so the range carries both.)
        if (code == CURLE_OK && (request.offset > 0 || request.length >= 0)) {
            QByteArray range = QByteArray::number(request.offset) + '-';
            if (request.length >= 0)
                range += QByteArray::number(request.offset + request.length - 1);
            code = curl_easy_setopt(m_easy, CURLOPT_RANGE, range.constData());
        }
        break;
    case Request::Kind::Upload:
        if (code == CURLE_OK)
            code = curl_easy_setopt(m_easy, CURLOPT_UPLOAD, 1L);
        // TLS 1.3 tickets of servers that insist on session reuse for data
        // connections (vsftpd require_ssl_reuse) are single-use, and an
        // upload's data connection never reads the replacement ticket. The
        // next data connection would offer the spent one and be refused
        // (522), so a TLS control connection ends with its upload; the next
        // request signs in again and gets fresh tickets.
        if (code == CURLE_OK && m_settings.tlsMode != TlsMode::None)
            code = curl_easy_setopt(m_easy, CURLOPT_FORBID_REUSE, 1L);
        if (code == CURLE_OK && request.append)
            code = curl_easy_setopt(m_easy, CURLOPT_APPEND, 1L);
        break;
    }
    if (code != CURLE_OK)
        return Result(Error::Internal, QStringLiteral("libcurl rejected the request"),
                      QString::fromUtf8(curl_easy_strerror(code)));
    return Result::success();
}

Result Connection::run(const Request &request, TransferSink *sink, const QString &context)
{
    Result r = start(request, sink);
    if (!r.ok())
        return r;
    return pump(nullptr, context);
}

Result Connection::start(const Request &request, TransferSink *sink)
{
    if (!m_easy)
        return Result(Error::ConnectionLost, QStringLiteral("Not connected"));
    stop();
    m_reader.reset();
    m_replies.clear();
    m_guardFailure = Result();
    for (const QByteArray &command : request.commands) {
        // XSEC-5: commands at debug level only (they carry paths, never PASS).
        qCDebug(lcNetVfsFtp) << "command:" << command;
    }
    const Result r = applyRequest(request);
    if (!r.ok())
        return r;
    m_sink = sink;
    m_paused = false;
    if (curl_multi_add_handle(m_multi, m_easy) != CURLM_OK)
        return Result(Error::Internal, QStringLiteral("libcurl could not start the request"));
    m_started = true;
    // A partial download makes libcurl close the control connection, as
    // does an upload over TLS (see applyRequest()).
    m_closesConnection = (request.kind == Request::Kind::Download && request.length >= 0)
        || (request.kind == Request::Kind::Upload && m_settings.tlsMode != TlsMode::None);
    return Result::success();
}

void Connection::resume()
{
    if (m_started && m_paused) {
        m_paused = false;
        curl_easy_pause(m_easy, CURLPAUSE_CONT);
    }
}

Result Connection::pump(const std::function<bool()> &enough, const QString &context)
{
    if (!m_started)
        return Result(Error::Internal, QStringLiteral("No transfer in progress"));
    resume();
    for (;;) {
        int running = 0;
        if (curl_multi_perform(m_multi, &running) != CURLM_OK) {
            stop();
            return Result(Error::Internal, QStringLiteral("libcurl failed"));
        }
        int left = 0;
        while (CURLMsg *message = curl_multi_info_read(m_multi, &left)) {
            if (message->msg == CURLMSG_DONE && message->easy_handle == m_easy) {
                const CURLcode code = message->data.result;
                curl_multi_remove_handle(m_multi, m_easy);
                m_started = false;
                m_sink = nullptr;
                return complete(code, context);
            }
        }
        if (canceled()) {
            stop();
            return Result(Error::Canceled);
        }
        if (m_paused || (enough && enough()))
            return Result::success();
        curl_multi_poll(m_multi, nullptr, 0, PollIntervalMs, nullptr);
    }
}

Result Connection::complete(CURLcode code, const QString &context)
{
    long connects = 0;
    curl_easy_getinfo(m_easy, CURLINFO_NUM_CONNECTS, &connects);
    m_unexpectedReconnect = connects > 0 && !m_expectReconnect;
    m_replies = m_reader.replies();
    // libcurl may have closed the connection after an error.
    m_expectReconnect = code != CURLE_OK || m_closesConnection;
    if (!m_guardFailure.ok()) {
        m_guard.reset();
        return m_guardFailure;
    }
    if (code == CURLE_OK)
        return Result::success();
    return curlError(code, m_reader.last(), canceled(), context);
}

void Connection::stop()
{
    if (!m_started)
        return;
    // Premature end: libcurl closes the control connection (a later request
    // connects and signs in again).
    curl_multi_remove_handle(m_multi, m_easy);
    m_started = false;
    m_paused = false;
    m_sink = nullptr;
    m_expectReconnect = true;
}

QVector<Reply> Connection::lastReplies(int count) const
{
    QVector<Reply> result(count);
    const int available = m_replies.size();
    for (int i = 0; i < count && i < available; ++i)
        result[count - 1 - i] = m_replies.at(available - 1 - i);
    return result;
}

QByteArray Connection::entryPath() const
{
    char *path = nullptr;
    if (!m_easy || curl_easy_getinfo(m_easy, CURLINFO_FTP_ENTRY_PATH, &path) != CURLE_OK || !path)
        return QByteArray();
    return QByteArray(path);
}

void Connection::close()
{
    stop();
    if (m_multi && m_easy) {
        // libcurl sends QUIT on a connection it still considers usable and
        // waits for the reply with the timeouts of the handle added last.
        // A short wait keeps disconnect() from hanging on a stalled server.
        curl_easy_setopt(m_easy, CURLOPT_SERVER_RESPONSE_TIMEOUT, QuitTimeoutSeconds);
        curl_easy_setopt(m_easy, CURLOPT_TIMEOUT_MS, QuitTimeoutSeconds * MillisecondsPerSecond);
        if (curl_multi_add_handle(m_multi, m_easy) == CURLM_OK)
            curl_multi_remove_handle(m_multi, m_easy);
    }
    if (m_multi)
        curl_multi_cleanup(m_multi);
    if (m_easy)
        curl_easy_cleanup(m_easy);
    m_multi = nullptr;
    m_easy = nullptr;
    m_quote.reset();
    secureWipe(m_secret);
    m_replies.clear();
    m_reader.reset();
}

size_t Connection::onWrite(char *data, size_t size, size_t count, void *self)
{
    auto *connection = static_cast<Connection *>(self);
    if (!connection->m_sink)
        return 0;
    const size_t result = connection->m_sink->received(data, size * count);
    if (result == CURL_WRITEFUNC_PAUSE)
        connection->m_paused = true;
    return result;
}

size_t Connection::onRead(char *buffer, size_t size, size_t count, void *self)
{
    auto *connection = static_cast<Connection *>(self);
    if (!connection->m_sink)
        return CURL_READFUNC_ABORT;
    const size_t result = connection->m_sink->send(buffer, size * count);
    if (result == CURL_READFUNC_PAUSE)
        connection->m_paused = true;
    return result;
}

size_t Connection::onHeader(char *data, size_t size, size_t count, void *self)
{
    auto *connection = static_cast<Connection *>(self);
    const size_t length = size * count;
    const int before = connection->m_reader.count();
    connection->m_reader.feed(data, length);
    if (connection->m_reader.count() == before)
        return length;
    const Reply &reply = connection->m_reader.last();
    // XSEC-5: server replies at debug level only.
    qCDebug(lcNetVfsFtp) << "reply:" << replyForLog(reply);
    if (connection->m_settings.tlsMode != TlsMode::Explicit)
        return length;
    switch (connection->m_guard.reply(reply.code)) {
    case TlsGuard::Verdict::Continue:
        return length;
    case TlsGuard::Verdict::AuthRefused:
        connection->m_guardFailure = Result(Error::SecurityPolicy, QStringLiteral("The server does not offer TLS"),
                                            replyForLog(reply));
        break;
    case TlsGuard::Verdict::ProtectionRefused:
        connection->m_guardFailure = Result(Error::SecurityPolicy,
                                            QStringLiteral("The server refuses to encrypt data connections"),
                                            replyForLog(reply));
        break;
    case TlsGuard::Verdict::Unexpected:
        connection->m_guardFailure = Result(Error::SecurityPolicy,
                                            QStringLiteral("The server skipped the TLS sign-in"), replyForLog(reply));
        break;
    }
    return 0;   // libcurl ends the request before it sends anything else
}

int Connection::onProgress(void *self, curl_off_t dlTotal, curl_off_t dlNow, curl_off_t ulTotal, curl_off_t ulNow)
{
    auto *connection = static_cast<Connection *>(self);
    if (connection->canceled())
        return 1;
    if (connection->m_sink
        && !connection->m_sink->progress(qint64(dlTotal), qint64(dlNow), qint64(ulTotal), qint64(ulNow)))
        return 1;
    return 0;
}

} // namespace NetVfs::Ftp
