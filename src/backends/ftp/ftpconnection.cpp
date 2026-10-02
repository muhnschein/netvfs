// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ftpconnection.h"
#include "ftpcallbacks.h"
#include "tlsprobe.h"
#include "secure.h"

#include <QtCore/QDebug>

// The state of the identity probe, the user data of its callbacks.
struct NetVfsFtpProbeState {
    NetVfs::Ftp::ReplyReader reader;
    bool stopAfterGreeting = false;
    const std::atomic<bool> *canceled = nullptr;

    size_t header(const char *data, size_t length);
    bool cancelRequested() const { return canceled && canceled->load(); }
};

namespace NetVfs::Ftp {

namespace {

constexpr int PollIntervalMs = 100;          // C-9: cancel is seen within this
constexpr long LowSpeedLimit = 1;            // bytes/s; below it for requestTimeout → Timeout
constexpr int MillisecondsPerSecond = 1000;
constexpr long QuitTimeoutSeconds = 1;
constexpr const char *Protocols = "ftp,ftps";
constexpr int MaxSentCommands = 256;
// The first libcurl release measured to reuse an explicit-TLS FTP control
// connection in "TLS required" mode (8.20.0); builds before it may not (see
// TlsGuard).
constexpr unsigned int MinVersionForRequiredTls = 0x081400;

// CURLOPT_USE_SSL for explicit FTPS (XSEC-2): libcurl's own "TLS required"
// mode where the running libcurl can reuse the connection (the guard still
// checks the replies), else "try" mode where the guard alone enforces TLS.
long explicitUseSsl()
{
    const curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
    return info && info->version_num >= MinVersionForRequiredTls ? long(CURLUSESSL_ALL) : long(CURLUSESSL_TRY);
}

long seconds(int milliseconds)
{
    return std::max(1L, long((milliseconds + MillisecondsPerSecond - 1) / MillisecondsPerSecond));
}

// Options shared by the probe and the control connection (XSEC-4, XSEC-2,
// C-14, F-1).
CURLcode applyCommon(const Curl::EasyHandle &easy, const QByteArray &url, const Settings &settings,
                     const ConnectionParams &params, long useSsl)
{
    const long timeout = seconds(params.requestTimeoutMs);
    Curl::OptionChain chain(easy);
    chain.set(CURLOPT_URL, url.constData())
        .set(CURLOPT_PROTOCOLS_STR, Protocols)
        .set(CURLOPT_NETRC, long(CURL_NETRC_IGNORED))
        // An empty proxy disables the proxy environment variables (XSEC-4).
        .set(CURLOPT_PROXY, "")
        .set(CURLOPT_NOSIGNAL, 1L)
        .set(CURLOPT_TCP_KEEPALIVE, 1L)
        .set(CURLOPT_CONNECTTIMEOUT_MS, long(params.connectTimeoutMs))
        .set(CURLOPT_SERVER_RESPONSE_TIMEOUT, timeout)
        .set(CURLOPT_LOW_SPEED_LIMIT, LowSpeedLimit)
        .set(CURLOPT_LOW_SPEED_TIME, timeout)
        .set(CURLOPT_USE_SSL, settings.tlsMode == TlsMode::None ? long(CURLUSESSL_NONE) : useSsl)
        .set(CURLOPT_FTPSSLAUTH, long(CURLFTPAUTH_TLS))
        // TLS 1.2 exactly. With TLS 1.3 the server sends session tickets
        // after the handshake of every data connection; an upload never
        // reads them, so closing the data connection resets it (RST over
        // unread data) and the server may lose the end of the file ("426
        // Failure reading network stream"); and servers that require session
        // reuse for data connections (vsftpd's default require_ssl_reuse)
        // issue single-use TLS 1.3 tickets that an upload cannot renew (522
        // on the next transfer). A fixed policy, never a fallback (XSEC-2).
        .set(CURLOPT_SSLVERSION, long(CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_2))
        // Passive only (F-1): EPSV, then PASV; the address in a PASV reply is
        // ignored in favour of the control connection's (no bounce).
        .set(CURLOPT_FTP_USE_EPSV, 1L)
        .set(CURLOPT_FTP_USE_EPRT, 0L)
        .set(CURLOPT_FTPPORT, static_cast<const char *>(nullptr))
        .set(CURLOPT_FTP_SKIP_PASV_IP, 1L)
        .set(CURLOPT_FTP_FILEMETHOD, long(CURLFTPMETHOD_NOCWD))
        .set(CURLOPT_FTP_CREATE_MISSING_DIRS, long(CURLFTP_CREATE_DIR_NONE))
        .set(CURLOPT_TRANSFERTEXT, 0L);
    return chain.code();
}

// Runs `easy` in `multi` until it is done or canceled. Returns false on
// cancel (the handle is removed either way).
bool drive(const Curl::MultiHandle &multi, const Curl::EasyHandle &easy, const std::atomic<bool> *canceled,
           CURLcode *result)
{
    curl_multi_add_handle(multi.get(), easy.get());
    bool done = false;
    while (!done) {
        if (int running = 0; curl_multi_perform(multi.get(), &running) != CURLM_OK) {
            *result = CURLE_FAILED_INIT;
            break;
        }
        int left = 0;
        while (CURLMsg *message = curl_multi_info_read(multi.get(), &left)) {
            if (message->msg == CURLMSG_DONE && message->easy_handle == easy.get()) {
                *result = message->data.result;
                done = true;
            }
        }
        if (!done && canceled && canceled->load()) {
            curl_multi_remove_handle(multi.get(), easy.get());
            return false;
        }
        if (!done)
            curl_multi_poll(multi.get(), nullptr, 0, PollIntervalMs, nullptr);
    }
    curl_multi_remove_handle(multi.get(), easy.get());
    return true;
}

QString guardMessage(TlsGuard::Verdict verdict)
{
    switch (verdict) {
    case TlsGuard::Verdict::AuthRefused:
        return QStringLiteral("The server does not offer TLS");
    case TlsGuard::Verdict::ProtectionRefused:
        return QStringLiteral("The server refuses to encrypt data connections");
    case TlsGuard::Verdict::Unexpected:
        return QStringLiteral("The server skipped the TLS sign-in");
    case TlsGuard::Verdict::Continue:
        break;
    }
    return QString();
}

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
    const Curl::EasyHandle easy = Curl::newEasyHandle();
    const Curl::MultiHandle multi = Curl::newMultiHandle();
    if (!easy || !multi)
        return Result(Error::Internal, QStringLiteral("Out of memory"));
    const bool tls = settings.tlsMode != TlsMode::None;
    if (tls && !CurlTls::isOpenSsl())
        return Result(Error::Unsupported, QStringLiteral("FTPS needs libcurl with OpenSSL"));
    NetVfsFtpProbeState state;
    state.stopAfterGreeting = !tls;
    state.canceled = canceled;
    CurlTls::IdentityProbe identity(settings.host, CurlTls::trustStore(easy, settings.testCaFile));
    CURLcode code = applyCommon(easy, baseUrl(settings), settings, params, long(CURLUSESSL_ALL));
    if (code == CURLE_OK) {
        code = Curl::OptionChain(easy)
                   .set(CURLOPT_NOBODY, 1L)
                   .set(CURLOPT_HEADERFUNCTION, netvfs_ftp_probe_header_callback)
                   .set(CURLOPT_HEADERDATA, &state)
                   .set(CURLOPT_NOPROGRESS, 0L)
                   .set(CURLOPT_XFERINFOFUNCTION, netvfs_ftp_probe_progress_callback)
                   .set(CURLOPT_XFERINFODATA, &state)
                   .code();
    }
    // The probe must never get past the handshake: refuse to run without the
    // OpenSSL hook rather than risk a USER command (C-7).
    if (code == CURLE_OK && tls)
        code = identity.install(easy);
    if (code != CURLE_OK)
        return Result(Error::Internal, QStringLiteral("libcurl rejected the connection settings"),
                      QString::fromUtf8(curl_easy_strerror(code)));

    qCDebug(lcNetVfsFtp) << "Connecting to" << settings.host << "port" << settings.port;
    CURLcode result = CURLE_OK;
    if (!drive(multi, easy, canceled, &result))
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
    m_easy = Curl::newEasyHandle();
    m_multi = Curl::newMultiHandle();
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
    curl_easy_reset(m_easy.get());
    // Explicit TLS: libcurl's required or try mode plus TlsGuard (see
    // explicitUseSsl); implicit TLS cannot fall back.
    const long useSsl = m_settings.tlsMode == TlsMode::Explicit ? explicitUseSsl() : long(CURLUSESSL_ALL);
    CURLcode code = applyCommon(m_easy, url, m_settings, m_params, useSsl);
    if (code == CURLE_OK) {
        code = Curl::OptionChain(m_easy)
                   .set(CURLOPT_USERNAME, m_userName.constData())
                   .set(CURLOPT_PASSWORD, m_secret.constData())
                   .set(CURLOPT_HEADERFUNCTION, netvfs_ftp_header_callback)
                   .set(CURLOPT_HEADERDATA, &m_hooks)
                   .set(CURLOPT_WRITEFUNCTION, netvfs_ftp_write_callback)
                   .set(CURLOPT_WRITEDATA, &m_hooks)
                   .set(CURLOPT_READFUNCTION, netvfs_ftp_read_callback)
                   .set(CURLOPT_READDATA, &m_hooks)
                   .set(CURLOPT_NOPROGRESS, 0L)
                   .set(CURLOPT_XFERINFOFUNCTION, netvfs_ftp_progress_callback)
                   .set(CURLOPT_XFERINFODATA, &m_hooks)
                   // Only to see the commands libcurl sends (debug); with a
                   // debug function set, verbose mode prints nothing.
                   .set(CURLOPT_DEBUGFUNCTION, netvfs_ftp_debug_callback)
                   .set(CURLOPT_DEBUGDATA, &m_hooks)
                   .set(CURLOPT_VERBOSE, 1L)
                   .code();
    }
    if (code == CURLE_OK && m_settings.tlsMode != TlsMode::None)
        code = CurlTls::applyTestCaFile(m_easy, m_settings.testCaFile);
    if (code != CURLE_OK)
        return Result(Error::Internal, QStringLiteral("libcurl rejected the connection settings"),
                      QString::fromUtf8(curl_easy_strerror(code)));
    if (m_settings.tlsMode != TlsMode::None)
        return CurlTls::applyIdentityPolicy(m_easy, m_settings.pin, m_settings.verifyPeer, m_seen);
    return Result::success();
}

Result Connection::applyRequest(const Request &request)
{
    QByteArray url = baseUrl(m_settings);
    if (request.kind == Request::Kind::Download || request.kind == Request::Kind::Upload)
        url += urlPath(request.path);
    if (const Result r = applyBase(url); !r.ok())
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
    CURLcode code = curl_easy_setopt(m_easy.get(), CURLOPT_QUOTE, list);
    switch (request.kind) {
    case Request::Kind::Command:
        if (code == CURLE_OK)
            code = curl_easy_setopt(m_easy.get(), CURLOPT_NOBODY, 1L);
        break;
    case Request::Kind::Listing:
        if (code == CURLE_OK)
            code = curl_easy_setopt(m_easy.get(), CURLOPT_CUSTOMREQUEST, request.listCommand.constData());
        break;
    case Request::Kind::Download:
        // REST <offset>; with a length libcurl stops after it (ABOR) and
        // closes the control connection. (A resume offset would override
        // the range, so the range carries both.)
        if (code == CURLE_OK && (request.offset > 0 || request.length >= 0)) {
            QByteArray range = QByteArray::number(request.offset) + '-';
            if (request.length >= 0)
                range += QByteArray::number(request.offset + request.length - 1);
            code = curl_easy_setopt(m_easy.get(), CURLOPT_RANGE, range.constData());
        }
        break;
    case Request::Kind::Upload:
        if (code == CURLE_OK)
            code = curl_easy_setopt(m_easy.get(), CURLOPT_UPLOAD, 1L);
        if (code == CURLE_OK && request.append)
            code = curl_easy_setopt(m_easy.get(), CURLOPT_APPEND, 1L);
        break;
    }
    if (code != CURLE_OK)
        return Result(Error::Internal, QStringLiteral("libcurl rejected the request"),
                      QString::fromUtf8(curl_easy_strerror(code)));
    return Result::success();
}

Result Connection::run(const Request &request, TransferSink *sink, const QString &context)
{
    if (const Result r = start(request, sink); !r.ok())
        return r;
    return pump([] { return false; }, context);
}

Result Connection::start(const Request &request, TransferSink *sink)
{
    if (!m_easy)
        return Result(Error::ConnectionLost, QStringLiteral("Not connected"));
    stop();
    m_reader.reset();
    m_replies.clear();
    m_guardFailure = Result();
    m_sent.clear();
    m_quoted.clear();
    for (const QByteArray &command : request.commands)
        m_quoted.append(command.startsWith('*') ? command.mid(1) : command);
    // XSEC-2: every request starts in the guard's initial state, whatever
    // became of the previous one (a connection that died half way through a
    // sign-in must not colour the greeting of the next one).
    m_guard.reset();
    for (const QByteArray &command : request.commands) {
        // XSEC-5: commands at debug level only (they carry paths, never PASS).
        qCDebug(lcNetVfsFtp) << "command:" << command;
    }
    if (const Result r = applyRequest(request); !r.ok())
        return r;
    m_sink = sink;
    m_paused = false;
    if (curl_multi_add_handle(m_multi.get(), m_easy.get()) != CURLM_OK)
        return Result(Error::Internal, QStringLiteral("libcurl could not start the request"));
    m_started = true;
    // A partial download makes libcurl close the control connection.
    m_closesConnection = request.kind == Request::Kind::Download && request.length >= 0;
    return Result::success();
}

void Connection::resume()
{
    if (m_started && m_paused) {
        m_paused = false;
        curl_easy_pause(m_easy.get(), CURLPAUSE_CONT);
    }
}

bool Connection::beginPump(Result *result)
{
    if (!m_started) {
        *result = Result(Error::Internal, QStringLiteral("No transfer in progress"));
        return false;
    }
    resume();
    return true;
}

// True when pump() is over; *result is then its outcome.
bool Connection::pumpRound(Result *result, const QString &context)
{
    if (int running = 0; curl_multi_perform(m_multi.get(), &running) != CURLM_OK) {
        stop();
        *result = Result(Error::Internal, QStringLiteral("libcurl failed"));
        return true;
    }
    int left = 0;
    while (CURLMsg *message = curl_multi_info_read(m_multi.get(), &left)) {
        if (message->msg == CURLMSG_DONE && message->easy_handle == m_easy.get()) {
            const CURLcode code = message->data.result;
            curl_multi_remove_handle(m_multi.get(), m_easy.get());
            m_started = false;
            m_sink = nullptr;
            *result = complete(code, context);
            return true;
        }
    }
    if (canceled()) {
        stop();
        *result = Result(Error::Canceled);
        return true;
    }
    if (m_paused) {
        *result = Result::success();
        return true;
    }
    return false;
}

void Connection::waitForData()
{
    curl_multi_poll(m_multi.get(), nullptr, 0, PollIntervalMs, nullptr);
}

Result Connection::complete(CURLcode code, const QString &context)
{
    long connects = 0;
    curl_easy_getinfo(m_easy.get(), CURLINFO_NUM_CONNECTS, &connects);
    m_unexpectedReconnect = connects > 0 && !m_expectReconnect;
    m_replies = m_reader.replies();
    m_replyBase = m_reader.count() - m_replies.size();
    // libcurl may have closed the connection after an error.
    m_expectReconnect = code != CURLE_OK || m_closesConnection;
    if (!m_guardFailure.ok())
        return m_guardFailure;
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
    curl_multi_remove_handle(m_multi.get(), m_easy.get());
    m_started = false;
    m_paused = false;
    m_sink = nullptr;
    m_expectReconnect = true;
}

QVector<Reply> Connection::lastReplies(int count) const
{
    QVector<Reply> result(count);
    const int quoted = m_quoted.size();
    if (count > quoted)
        return result;
    // The quoted commands run back to back; find that run among the commands
    // libcurl sent (its own sign-in commands come before, its own CWD or
    // transfer commands after).
    for (int start = 0; start + quoted <= m_sent.size(); ++start) {
        int i = 0;
        while (i < quoted && m_sent.at(start + i).line == m_quoted.at(i))
            ++i;
        if (i < quoted)
            continue;
        for (int j = 0; j < count; ++j) {
            const int index = m_sent.at(start + quoted - count + j).replyIndex - m_replyBase;
            if (index >= 0 && index < m_replies.size())
                result[j] = m_replies.at(index);
        }
        break;
    }
    return result;
}

QByteArray Connection::entryPath() const
{
    char *path = nullptr;
    if (!m_easy || curl_easy_getinfo(m_easy.get(), CURLINFO_FTP_ENTRY_PATH, &path) != CURLE_OK || !path)
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
        curl_easy_setopt(m_easy.get(), CURLOPT_SERVER_RESPONSE_TIMEOUT, QuitTimeoutSeconds);
        curl_easy_setopt(m_easy.get(), CURLOPT_TIMEOUT_MS, QuitTimeoutSeconds * MillisecondsPerSecond);
        if (curl_multi_add_handle(m_multi.get(), m_easy.get()) == CURLM_OK)
            curl_multi_remove_handle(m_multi.get(), m_easy.get());
    }
    m_multi.reset();
    m_easy.reset();
    m_quote.reset();
    secureWipe(m_secret);
    m_replies.clear();
    m_reader.reset();
}

// XSEC-2: false (with m_guardFailure set) when the replies in `data` show
// that TLS would not protect what libcurl sends next.
bool Connection::guard(const char *data, size_t size)
{
    const TlsGuard::Verdict verdict = m_guard.feed(data, size);
    if (verdict == TlsGuard::Verdict::Continue)
        return true;
    m_guardFailure = Result(Error::SecurityPolicy, guardMessage(verdict), lineForLog(m_guard.lastLine()));
    return false;
}

// Remembers a command libcurl sent, to match it with its reply (the debug
// function of libcurl, see NetVfsFtpHooks::debug).
void Connection::recordSent(curl_infotype type, const char *data, size_t size)
{
    if (type != CURLINFO_HEADER_OUT || m_sent.size() >= MaxSentCommands)
        return;
    SentCommand sent;
    sent.line = QByteArray(data, static_cast<int>(size)).trimmed();
    if (sent.line.startsWith("PASS "))   // never keep the secret (SEC-5)
        sent.line.clear();
    sent.replyIndex = m_reader.count();
    m_sent.append(sent);
}

} // namespace NetVfs::Ftp

// ------------------------------------------------------------- callbacks

// The callbacks of libcurl (ftpcallbacks.c) end up here with typed state.
void NetVfsFtpHooks::debug(curl_infotype type, const char *data, size_t length) const
{
    connection->recordSent(type, data, length);
}

size_t NetVfsFtpHooks::write(const char *data, size_t length) const
{
    if (!connection->m_sink)
        return 0;
    const size_t result = connection->m_sink->received(data, length);
    if (result == CURL_WRITEFUNC_PAUSE)
        connection->m_paused = true;
    return result;
}

size_t NetVfsFtpHooks::read(char *buffer, size_t capacity) const
{
    if (!connection->m_sink)
        return CURL_READFUNC_ABORT;
    const size_t result = connection->m_sink->send(buffer, capacity);
    if (result == CURL_READFUNC_PAUSE)
        connection->m_paused = true;
    return result;
}

size_t NetVfsFtpHooks::header(const char *data, size_t length) const
{
    // The guard judges the raw lines the way libcurl does (TlsGuard), before
    // anything else is done with them.
    if (connection->m_settings.tlsMode == NetVfs::Ftp::TlsMode::Explicit && !connection->guard(data, length))
        return 0;   // libcurl ends the request before it sends anything else
    const int before = connection->m_reader.count();
    connection->m_reader.feed(data, length);
    if (connection->m_reader.count() != before) {
        // XSEC-5: server replies at debug level only.
        qCDebug(lcNetVfsFtp) << "reply:" << NetVfs::Ftp::replyForLog(connection->m_reader.last());
    }
    return length;
}

// True ends the transfer (Canceled).
bool NetVfsFtpHooks::progress(curl_off_t downloadTotal, curl_off_t downloaded, curl_off_t uploadTotal,
                              curl_off_t uploaded) const
{
    if (connection->canceled())
        return true;
    return connection->m_sink
        && !connection->m_sink->progress(static_cast<qint64>(downloadTotal), static_cast<qint64>(downloaded),
                                         static_cast<qint64>(uploadTotal), static_cast<qint64>(uploaded));
}

size_t NetVfsFtpProbeState::header(const char *data, size_t length)
{
    reader.feed(data, length);
    if (reader.last().isValid())
        qCDebug(lcNetVfsFtp) << "probe reply:" << NetVfs::Ftp::replyForLog(reader.last());
    // Plain FTP: the greeting is all the probe needs; aborting here means the
    // client never sends anything.
    if (stopAfterGreeting && reader.last().isValid())
        return 0;
    return length;
}

extern "C" {

size_t netvfs_ftp_on_write(NetVfsFtpHooks *hooks, const char *data, size_t length)
{
    return hooks->write(data, length);
}

size_t netvfs_ftp_on_read(NetVfsFtpHooks *hooks, char *buffer, size_t capacity)
{
    return hooks->read(buffer, capacity);
}

size_t netvfs_ftp_on_header(NetVfsFtpHooks *hooks, const char *data, size_t length)
{
    return hooks->header(data, length);
}

void netvfs_ftp_on_debug(NetVfsFtpHooks *hooks, curl_infotype type, const char *data, size_t length)
{
    hooks->debug(type, data, length);
}

int netvfs_ftp_on_progress(NetVfsFtpHooks *hooks, curl_off_t downloadTotal, curl_off_t downloaded,
                           curl_off_t uploadTotal, curl_off_t uploaded)
{
    return hooks->progress(downloadTotal, downloaded, uploadTotal, uploaded) ? 1 : 0;
}

size_t netvfs_ftp_probe_header(NetVfsFtpProbeState *state, const char *data, size_t length)
{
    return state->header(data, length);
}

int netvfs_ftp_probe_progress(const NetVfsFtpProbeState *state)
{
    return state->cancelRequested() ? 1 : 0;
}

}
