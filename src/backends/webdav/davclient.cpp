// SPDX-License-Identifier: LGPL-2.1-or-later
#include "davclient.h"
#include "curlglobal.h"
#include "davlog.h"
#include "secure.h"
#include "types.h"

#include <array>
#include <cstring>

namespace NetVfs::WebDav {

namespace {

constexpr int PollMs = 100;
constexpr long MsPerSecond = 1000;
constexpr const char *UserAgent = "netvfs-webdav/0.2";

struct CurlRule {
    CURLcode code;
    Error error;
    const char *message;
};

const std::array<CurlRule, 22> curlRules = { {
    { CURLE_ABORTED_BY_CALLBACK, Error::Canceled, "Canceled" },
    { CURLE_OPERATION_TIMEDOUT, Error::Timeout, "The server did not answer in time" },
    { CURLE_COULDNT_RESOLVE_HOST, Error::NetworkUnreachable, "The server name could not be resolved" },
    { CURLE_COULDNT_RESOLVE_PROXY, Error::NetworkUnreachable, "The proxy name could not be resolved" },
    { CURLE_COULDNT_CONNECT, Error::NetworkUnreachable, "Could not connect to the server" },
    { CURLE_SEND_ERROR, Error::ConnectionLost, "The connection to the server was lost" },
    { CURLE_RECV_ERROR, Error::ConnectionLost, "The connection to the server was lost" },
    { CURLE_PARTIAL_FILE, Error::ConnectionLost, "The connection to the server was lost during a transfer" },
    { CURLE_GOT_NOTHING, Error::ConnectionLost, "The server closed the connection without an answer" },
    { CURLE_HTTP2, Error::ConnectionLost, "The HTTP/2 connection failed" },
    { CURLE_HTTP2_STREAM, Error::ConnectionLost, "The HTTP/2 stream failed" },
    { CURLE_SSL_PINNEDPUBKEYNOTMATCH, Error::ServerIdentityChanged, "The server certificate key changed" },
    { CURLE_PEER_FAILED_VERIFICATION, Error::ServerIdentityChanged,
      "The server certificate is no longer trusted" },
    { CURLE_SSL_CONNECT_ERROR, Error::ProtocolError, "The TLS handshake failed" },
    { CURLE_UNSUPPORTED_PROTOCOL, Error::SecurityPolicy, "The protocol is not allowed" },
    { CURLE_LOGIN_DENIED, Error::AuthFailed, "The server did not accept the credentials" },
    { CURLE_TOO_MANY_REDIRECTS, Error::ProtocolError, "Too many redirects" },
    { CURLE_OUT_OF_MEMORY, Error::Internal, "Out of memory" },
    { CURLE_URL_MALFORMAT, Error::Internal, "Malformed URL" },
    { CURLE_SEND_FAIL_REWIND, Error::ProtocolError, "The request could not be repeated" },
    { CURLE_WEIRD_SERVER_REPLY, Error::ProtocolError, "The server sent an invalid answer" },
    { CURLE_FAILED_INIT, Error::Internal, "libcurl could not be initialised" },
} };

std::once_flag curlInitOnce;
bool curlInitialized = false;

bool isRedirect(int status)
{
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

// A copy with a terminating NUL that the caller wipes.
struct CString {
    explicit CString(const QByteArray &bytes) : data(bytes.constData(), bytes.size()) {}
    ~CString() { secureWipe(data); }
    CString(const CString &) = delete;
    CString &operator=(const CString &) = delete;
    const char *get() const { return data.constData(); }
    QByteArray data;
};

void setProtocols(CURL *easy, bool allowHttp)
{
#if LIBCURL_VERSION_NUM >= 0x075500
    const char *protocols = allowHttp ? "http,https" : "https";
    curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, protocols);
    curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, protocols);
#else
    const long protocols = allowHttp ? (CURLPROTO_HTTP | CURLPROTO_HTTPS) : CURLPROTO_HTTPS;
    curl_easy_setopt(easy, CURLOPT_PROTOCOLS, protocols);
    curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS, protocols);
#endif
}

} // namespace

Result curlResult(int code, const QString &message)
{
    if (code == CURLE_OK)
        return Result::success();
    const QString detail = message.isEmpty() ? QString::fromLatin1(curl_easy_strerror(static_cast<CURLcode>(code)))
                                             : message;
    for (const CurlRule &rule : curlRules) {
        if (rule.code == code)
            return Result(rule.error, QLatin1String(rule.message), detail);
    }
    return Result(Error::ProtocolError, QStringLiteral("Transfer failed"), detail);
}

BodySource::~BodySource() = default;
BodySink::~BodySink() = default;

qint64 BytesSource::read(char *buffer, qint64 maxSize)
{
    const qint64 count = qMin(maxSize, m_data.size() - m_position);
    if (count > 0) {
        std::memcpy(buffer, m_data.constData() + m_position, size_t(count));
        m_position += count;
    }
    return count;
}

bool BytesSource::rewind()
{
    m_position = 0;
    return true;
}

// State of one easy handle while it is attached to the multi handle; the
// libcurl callbacks receive it as their user pointer.
struct Transfer {
    Client *client = nullptr;
    CURL *easy = nullptr;
    const Request *request = nullptr;
    Response *response = nullptr;
    curl_slist *headers = nullptr;
    std::array<char, CURL_ERROR_SIZE> error {};
    bool attached = false;
    bool done = false;
    CURLcode code = CURLE_OK;
    bool sinkStopped = false;
    bool sourceFailed = false;
    bool paused = false;

    Transfer() = default;
    ~Transfer() { curl_slist_free_all(headers); }
    Transfer(const Transfer &) = delete;
    Transfer &operator=(const Transfer &) = delete;

    static size_t onHeader(char *data, size_t size, size_t count, void *user);
    static size_t onWrite(char *data, size_t size, size_t count, void *user);
    static size_t onRead(char *data, size_t size, size_t count, void *user);
    static int onSeek(void *user, curl_off_t offset, int origin);
    static int onProgress(void *user, curl_off_t, curl_off_t, curl_off_t, curl_off_t);
};

size_t Transfer::onHeader(char *data, size_t size, size_t count, void *user)
{
    auto *t = static_cast<Transfer *>(user);
    const size_t total = size * count;
    const QByteArray line = QByteArray(data, int(total)).trimmed();
    if (!t->response)
        return total;
    if (line.startsWith("HTTP/")) {
        // A new response (100 Continue, a 401 before the retry, the final one).
        const QList<QByteArray> parts = line.split(' ');
        t->response->headers.clear();
        t->response->status = parts.size() > 1 ? parts.at(1).toInt() : 0;
        const int reason = line.indexOf(' ', line.indexOf(' ') + 1);
        t->response->reason = reason > 0 ? line.mid(reason + 1) : QByteArray();
        return total;
    }
    const int colon = line.indexOf(':');
    if (colon > 0) {
        const QByteArray name = line.left(colon).trimmed().toLower();
        const QByteArray value = line.mid(colon + 1).trimmed();
        QByteArray &slot = t->response->headers[name];
        slot = slot.isEmpty() ? value : slot + ", " + value;
    }
    return total;
}

size_t Transfer::onWrite(char *data, size_t size, size_t count, void *user)
{
    auto *t = static_cast<Transfer *>(user);
    const size_t total = size * count;
    const int status = t->response ? t->response->status : 0;
    BodySink *sink = t->request ? t->request->sink : nullptr;
    if (sink && status >= 200 && status < 300) {
        if (!sink->write(data, qint64(total))) {
            t->sinkStopped = true;
            return 0;
        }
        return total;
    }
    if (t->response) {
        const qint64 room = Client::MaxErrorBody - t->response->body.size();
        if (room > 0)
            t->response->body.append(data, int(qMin<qint64>(room, qint64(total))));
    }
    return total;
}

size_t Transfer::onRead(char *data, size_t size, size_t count, void *user)
{
    auto *t = static_cast<Transfer *>(user);
    BodySource *source = t->request ? t->request->body : nullptr;
    if (!source)
        return 0;
    const qint64 got = source->read(data, qint64(size * count));
    if (got == BodySource::Pause) {
        t->paused = true;
        return CURL_READFUNC_PAUSE;
    }
    if (got < 0) {
        t->sourceFailed = true;
        return CURL_READFUNC_ABORT;
    }
    return size_t(got);
}

int Transfer::onSeek(void *user, curl_off_t offset, int origin)
{
    auto *t = static_cast<Transfer *>(user);
    BodySource *source = t->request ? t->request->body : nullptr;
    if (!source || offset != 0 || origin != SEEK_SET)
        return CURL_SEEKFUNC_CANTSEEK;
    return source->rewind() ? CURL_SEEKFUNC_OK : CURL_SEEKFUNC_CANTSEEK;
}

int Transfer::onProgress(void *user, curl_off_t, curl_off_t, curl_off_t, curl_off_t)
{
    // W-15: called at least once per second; ends the transfer with
    // CURLE_ABORTED_BY_CALLBACK (Canceled).
    const auto *t = static_cast<Transfer *>(user);
    if (t->client->canceled())
        return 1;
    const Progress *progress = t->request ? t->request->progress : nullptr;
    return progress && progress->canceled() ? 1 : 0;
}

Client::Client()
{
    std::call_once(curlInitOnce, [] { curlInitialized = netvfs_curl_global_init() != 0; });
}

Client::~Client()
{
    close();
}

Result Client::open(const Origin &origin, int connectTimeoutMs, int requestTimeoutMs)
{
    close();
    if (!curlInitialized)
        return Result(Error::Internal, QStringLiteral("libcurl could not be initialised"));
    m_origin = origin;
    m_connectTimeoutMs = connectTimeoutMs;
    m_requestTimeoutMs = requestTimeoutMs;
    CURLM *multi = curl_multi_init();
    m_share = curl_share_init();
    if (!multi || !m_share) {
        curl_multi_cleanup(multi);
        close();
        return Result(Error::Internal, QStringLiteral("libcurl could not be initialised"));
    }
    // W-16: cookies live in memory only and are shared by this backend's
    // handles; so are DNS answers and TLS sessions.
    curl_share_setopt(m_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
    curl_share_setopt(m_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
    curl_share_setopt(m_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    {
        std::lock_guard<std::mutex> lock(m_wakeLock);
        m_multi = multi;
    }
    m_easy = newEasy();
    if (!m_easy) {
        close();
        return Result(Error::Internal, QStringLiteral("libcurl could not be initialised"));
    }
    return Result::success();
}

void Client::close()
{
    for (Stream *stream : std::set<Stream *>(m_streams))
        stream->abort();
    m_streams.clear();
    if (m_easy) {
        curl_easy_cleanup(m_easy);
        m_easy = nullptr;
    }
    CURLM *multi = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_wakeLock);
        multi = m_multi;
        m_multi = nullptr;
    }
    if (multi)
        curl_multi_cleanup(multi);
    if (m_share) {
        curl_share_cleanup(m_share);
        m_share = nullptr;
    }
    secureWipe(m_secret);
    m_user.clear();
    m_authMode = AuthMode::None;
    m_authMask = 0;
}

CURL *Client::newEasy()
{
    CURL *easy = curl_easy_init();
    if (!easy)
        return nullptr;
    curl_easy_setopt(easy, CURLOPT_SHARE, m_share);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    // XSEC-4: explicit protocol allow-lists, no .netrc, no proxy from the
    // environment.
    setProtocols(easy, m_origin.scheme == "http");
    curl_easy_setopt(easy, CURLOPT_NETRC, long(CURL_NETRC_IGNORED));
    curl_easy_setopt(easy, CURLOPT_PROXY, "");
    // W-6: redirects are followed by perform() after an origin check;
    // credentials never go to another host.
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(easy, CURLOPT_UNRESTRICTED_AUTH, 0L);
    // W-16
    curl_easy_setopt(easy, CURLOPT_COOKIEFILE, "");
    // C-14, W-15: stalls end as Timeout.
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, long(m_connectTimeoutMs));
    curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, qMax(1L, long(m_requestTimeoutMs) / MsPerSecond));
    curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(easy, CURLOPT_USERAGENT, UserAgent);
    curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, &Transfer::onHeader);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &Transfer::onWrite);
    curl_easy_setopt(easy, CURLOPT_READFUNCTION, &Transfer::onRead);
    curl_easy_setopt(easy, CURLOPT_SEEKFUNCTION, &Transfer::onSeek);
    curl_easy_setopt(easy, CURLOPT_XFERINFOFUNCTION, &Transfer::onProgress);
    curl_easy_setopt(easy, CURLOPT_NOPROGRESS, 0L);
    applyAuth(easy);
    return easy;
}

void Client::setPasswordAuth(const QByteArray &user, QByteArray *password)
{
    m_authMode = AuthMode::Password;
    m_user = user;
    secureWipe(m_secret);
    m_secret = QByteArray(password->constData(), password->size());
    secureWipe(*password);
    m_authMask = 0;
    if (m_easy)
        applyAuth(m_easy);
}

void Client::setTokenAuth(QByteArray *token)
{
    m_authMode = AuthMode::Token;
    m_user.clear();
    secureWipe(m_secret);
    m_secret = QByteArray(token->constData(), token->size());
    secureWipe(*token);
    m_authMask = 0;
    if (m_easy)
        applyAuth(m_easy);
}

void Client::pinAuthMethod()
{
    if (m_authMode != AuthMode::Password || !m_easy)
        return;
    long available = 0;
    curl_easy_getinfo(m_easy, CURLINFO_HTTPAUTH_AVAIL, &available);
    if (available & CURLAUTH_DIGEST)
        m_authMask = CURLAUTH_DIGEST;
    else if (available & CURLAUTH_BASIC)
        m_authMask = CURLAUTH_BASIC;
}

void Client::applyAuth(CURL *easy) const
{
    // W-5: Basic and Digest only, never NTLM or Negotiate; Bearer tokens.
    switch (m_authMode) {
    case AuthMode::None:
        curl_easy_setopt(easy, CURLOPT_HTTPAUTH, long(CURLAUTH_NONE));
        curl_easy_setopt(easy, CURLOPT_USERNAME, static_cast<const char *>(nullptr));
        curl_easy_setopt(easy, CURLOPT_PASSWORD, static_cast<const char *>(nullptr));
        curl_easy_setopt(easy, CURLOPT_XOAUTH2_BEARER, static_cast<const char *>(nullptr));
        break;
    case AuthMode::Password: {
        const CString user(m_user);
        const CString password(m_secret);
        const long mask = m_authMask ? m_authMask : long(CURLAUTH_BASIC | CURLAUTH_DIGEST);
        curl_easy_setopt(easy, CURLOPT_HTTPAUTH, mask);
        curl_easy_setopt(easy, CURLOPT_USERNAME, user.get());
        curl_easy_setopt(easy, CURLOPT_PASSWORD, password.get());
        break;
    }
    case AuthMode::Token: {
        const CString token(m_secret);
        curl_easy_setopt(easy, CURLOPT_HTTPAUTH, long(CURLAUTH_BEARER));
        curl_easy_setopt(easy, CURLOPT_XOAUTH2_BEARER, token.get());
        break;
    }
    }
}

void Client::applyRequest(Transfer *transfer, const Request &request, const QByteArray &url)
{
    CURL *easy = transfer->easy;
    curl_easy_setopt(easy, CURLOPT_URL, url.constData());
    curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);            // resets upload/nobody state
    curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, static_cast<const char *>(nullptr));
    curl_easy_setopt(easy, CURLOPT_INFILESIZE_LARGE, curl_off_t(-1));
    if (request.body) {
        curl_easy_setopt(easy, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(easy, CURLOPT_INFILESIZE_LARGE, curl_off_t(request.body->size()));
    }
    if (request.method != Method::Get && request.method != Method::Put) {
        const QByteArray method = methodName(request.method);
        curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method.constData());
    }
    // W-4: verification and pin; host name checks follow peer checks.
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, m_tls.verifyPeer ? 1L : 0L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, m_tls.verifyPeer ? 2L : 0L);
    curl_easy_setopt(easy, CURLOPT_PINNEDPUBLICKEY,
                     m_tls.pinnedKey.isEmpty() ? static_cast<const char *>(nullptr) : m_tls.pinnedKey.constData());
    if (!m_tls.caFile.isEmpty())
        curl_easy_setopt(easy, CURLOPT_CAINFO, m_tls.caFile.constData());
    curl_easy_setopt(easy, CURLOPT_CERTINFO, request.certificateInfo ? 1L : 0L);

    curl_slist_free_all(transfer->headers);
    transfer->headers = nullptr;
    const bool upload = request.body && (request.method == Method::Put || request.method == Method::Patch);
    // W-5: a 401 must not cost the upload body.
    transfer->headers = curl_slist_append(transfer->headers, upload ? "Expect: 100-continue" : "Expect:");
    for (const QByteArray &header : request.headers)
        transfer->headers = curl_slist_append(transfer->headers, header.constData());
    curl_easy_setopt(easy, CURLOPT_HTTPHEADER, transfer->headers);

    transfer->error.fill(0);
    curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, transfer->error.data());
    curl_easy_setopt(easy, CURLOPT_PRIVATE, transfer);
    curl_easy_setopt(easy, CURLOPT_HEADERDATA, transfer);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, transfer);
    curl_easy_setopt(easy, CURLOPT_READDATA, transfer);
    curl_easy_setopt(easy, CURLOPT_SEEKDATA, transfer);
    curl_easy_setopt(easy, CURLOPT_XFERINFODATA, transfer);
    transfer->request = &request;
    transfer->done = false;
    transfer->code = CURLE_OK;
    transfer->sinkStopped = false;
    transfer->sourceFailed = false;
    transfer->paused = false;
}

void Client::drainMessages()
{
    int left = 0;
    while (CURLMsg *message = curl_multi_info_read(m_multi, &left)) {
        if (message->msg != CURLMSG_DONE)
            continue;
        Transfer *transfer = nullptr;
        curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &transfer);
        if (transfer) {
            transfer->done = true;
            transfer->code = message->data.result;
        }
    }
}

Result Client::run(Transfer *transfer, bool (*until)(const Transfer *))
{
    for (;;) {
        int running = 0;
        const CURLMcode code = curl_multi_perform(m_multi, &running);
        drainMessages();
        if (transfer->done || (until && until(transfer)))
            return Result::success();
        if (m_cancel)
            return Result(Error::Canceled, QStringLiteral("Canceled"));
        if (code != CURLM_OK)
            return Result(Error::Internal, QString::fromLatin1(curl_multi_strerror(code)));
        curl_multi_poll(m_multi, nullptr, 0, PollMs, nullptr);
    }
}

void Client::detach(Transfer *transfer)
{
    if (transfer->attached) {
        curl_multi_remove_handle(m_multi, transfer->easy);
        transfer->attached = false;
    }
}

Result Client::outcome(const Transfer *transfer) const
{
    if (transfer->sinkStopped && transfer->request && transfer->request->sink) {
        const Result stop = transfer->request->sink->stopResult();
        if (!stop.ok() || transfer->code == CURLE_WRITE_ERROR)
            return stop;
    }
    if (transfer->sourceFailed && transfer->request && transfer->request->body) {
        const Result failed = transfer->request->body->error();
        return failed.ok() ? Result(Error::Internal, QStringLiteral("Reading the upload data failed")) : failed;
    }
    if (transfer->code == CURLE_ABORTED_BY_CALLBACK || (m_cancel && transfer->code != CURLE_OK))
        return Result(Error::Canceled, QStringLiteral("Canceled"));
    return curlResult(transfer->code, QString::fromLatin1(transfer->error.data()));
}

Result Client::once(const Request &request, const QByteArray &url, Response *response)
{
    if (!m_easy)
        return Result(Error::ConnectionLost, QStringLiteral("Not connected"));
    if (m_cancel)
        return Result(Error::Canceled, QStringLiteral("Canceled"));
    Transfer transfer;
    transfer.client = this;
    transfer.easy = m_easy;
    transfer.response = response;
    applyRequest(&transfer, request, url);
    curl_multi_add_handle(m_multi, m_easy);
    transfer.attached = true;
    Result r = run(&transfer, nullptr);
    detach(&transfer);
    curl_easy_setopt(m_easy, CURLOPT_HTTPHEADER, static_cast<curl_slist *>(nullptr));
    curl_easy_setopt(m_easy, CURLOPT_ERRORBUFFER, static_cast<char *>(nullptr));
    if (r.ok())
        r = outcome(&transfer);
    response->curlCode = int(transfer.code);
    long status = 0;
    curl_easy_getinfo(m_easy, CURLINFO_RESPONSE_CODE, &status);
    if (status > 0)
        response->status = int(status);
    if (request.certificateInfo) {
        curl_certinfo *info = nullptr;
        if (curl_easy_getinfo(m_easy, CURLINFO_CERTINFO, &info) == CURLE_OK && info) {
            for (int i = 0; i < info->num_of_certs; ++i) {
                for (const curl_slist *field = info->certinfo[i]; field; field = field->next) {
                    if (std::strncmp(field->data, "Cert:", 5) == 0)
                        response->certificates << QByteArray(field->data + 5);
                }
            }
        }
    }
    return r;
}

Result Client::perform(const Request &request, Response *response)
{
    QByteArray url = request.url;
    for (int hop = 0;; ++hop) {
        *response = Response();
        response->url = url;
        const Result r = once(request, url, response);
        if (!r.ok() || !isRedirect(response->status))
            return r;
        const QByteArray location = response->header("location");
        if (location.isEmpty())
            return r;
        if (hop == MaxRedirects)
            return Result(Error::ProtocolError, QStringLiteral("The server redirected more than %1 times").arg(MaxRedirects));
        QByteArray target;
        const Result allowed = redirectTarget(m_origin, url, location, &target);
        if (!allowed.ok())
            return allowed;
        qCDebug(lcNetVfsWebdav) << "Following redirect to" << target;
        if (request.body && !request.body->rewind())
            return Result(Error::ProtocolError, QStringLiteral("The server redirected an upload that cannot be repeated"));
        url = target;
    }
}

Result Client::probeCertificates(QVector<QByteArray> *chain)
{
    if (!m_multi)
        return Result(Error::ConnectionLost, QStringLiteral("Not connected"));
    CURL *easy = curl_easy_init();
    if (!easy)
        return Result(Error::Internal, QStringLiteral("libcurl could not be initialised"));
    Transfer transfer;
    transfer.client = this;
    transfer.easy = easy;
    const QByteArray url = m_origin.toUrl() + '/';
    curl_easy_setopt(easy, CURLOPT_URL, url.constData());
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    setProtocols(easy, false);
    curl_easy_setopt(easy, CURLOPT_PROXY, "");
    curl_easy_setopt(easy, CURLOPT_CONNECT_ONLY, 1L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(easy, CURLOPT_CERTINFO, 1L);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, long(m_connectTimeoutMs));
    curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, transfer.error.data());
    curl_easy_setopt(easy, CURLOPT_PRIVATE, &transfer);
    curl_multi_add_handle(m_multi, easy);
    transfer.attached = true;
    Result r = run(&transfer, nullptr);
    detach(&transfer);
    if (r.ok())
        r = outcome(&transfer);
    curl_certinfo *info = nullptr;
    if (r.ok() && curl_easy_getinfo(easy, CURLINFO_CERTINFO, &info) == CURLE_OK && info) {
        for (int i = 0; i < info->num_of_certs; ++i) {
            for (const curl_slist *field = info->certinfo[i]; field; field = field->next) {
                if (std::strncmp(field->data, "Cert:", 5) == 0)
                    *chain << QByteArray(field->data + 5);
            }
        }
    }
    curl_easy_cleanup(easy);
    return r;
}

CurlTls::TrustStore Client::trustStore() const
{
    CurlTls::TrustStore store;
    if (!m_tls.caFile.isEmpty()) {
        store.caFile = m_tls.caFile;
        return store;
    }
#if LIBCURL_VERSION_NUM >= 0x075400
    if (m_easy) {
        const char *file = nullptr;
        const char *path = nullptr;
        curl_easy_getinfo(m_easy, CURLINFO_CAINFO, &file);
        curl_easy_getinfo(m_easy, CURLINFO_CAPATH, &path);
        store.caFile = QByteArray(file);
        store.caPath = QByteArray(path);
    }
#endif
    return store;
}

void Client::cancel()
{
    m_cancel = true;
    std::lock_guard<std::mutex> lock(m_wakeLock);
    if (m_multi)
        curl_multi_wakeup(m_multi);
}

// ------------------------------------------------------------- streams

// Hands the bytes of the current write() to libcurl without copying them.
class Client::Stream::Source final : public BodySource
{
public:
    explicit Source(qint64 size) : m_size(size) {}
    qint64 size() const override { return m_size; }
    qint64 read(char *buffer, qint64 maxSize) override
    {
        if (m_remaining == 0)
            return m_finished ? 0 : Pause;
        const qint64 count = qMin(maxSize, m_remaining);
        std::memcpy(buffer, m_data, size_t(count));
        m_data += count;
        m_remaining -= count;
        m_written += count;
        return count;
    }
    bool rewind() override { return m_written == 0; }
    void offer(const char *data, qint64 size)
    {
        m_data = data;
        m_remaining = size;
    }
    void forget()
    {
        m_data = nullptr;
        m_remaining = 0;
    }
    void finish() { m_finished = true; }
    bool drained() const { return m_remaining == 0; }
    qint64 written() const { return m_written; }

private:
    qint64 m_size;
    const char *m_data = nullptr;
    qint64 m_remaining = 0;
    qint64 m_written = 0;
    bool m_finished = false;
};

Client::Stream::Stream(Client *client, const Request &request)
    : m_client(client)
    , m_source(std::make_unique<Source>(request.body ? request.body->size() : -1))
    , m_request(request)
    , m_transfer(std::make_unique<Transfer>())
{
    m_request.body = m_source.get();
    m_request.sink = nullptr;
}

Client::Stream::~Stream()
{
    abort();
}

Result Client::openStream(const Request &request, std::unique_ptr<Stream> *out)
{
    out->reset();
    if (!m_multi)
        return Result(Error::ConnectionLost, QStringLiteral("Not connected"));
    if (m_cancel)
        return Result(Error::Canceled, QStringLiteral("Canceled"));
    auto stream = std::make_unique<Stream>(this, request);
    Transfer *transfer = stream->m_transfer.get();
    transfer->client = this;
    transfer->easy = newEasy();
    if (!transfer->easy)
        return Result(Error::Internal, QStringLiteral("libcurl could not be initialised"));
    transfer->response = &stream->m_response;
    applyRequest(transfer, stream->m_request, request.url);
    stream->m_response.url = request.url;
    curl_multi_add_handle(m_multi, transfer->easy);
    transfer->attached = true;
    m_streams.insert(stream.get());
    // Sends the request head; returns once libcurl asks for body bytes or
    // the server already answered (412 for CreateNew, 401, ...).
    const Result r = run(transfer, [](const Transfer *t) { return t->paused; });
    if (!r.ok())
        return r;     // `stream` aborts itself
    *out = std::move(stream);
    return Result::success();
}

bool Client::Stream::answered() const
{
    return m_transfer->done;
}

qint64 Client::Stream::written() const
{
    return m_source->written();
}

Result Client::Stream::write(const char *data, qint64 size)
{
    if (m_dead)
        return Result(Error::ConnectionLost, QStringLiteral("The upload is no longer active"));
    if (m_transfer->done)
        return Result(Error::ProtocolError, QStringLiteral("The server ended the upload early"));
    if (size <= 0)
        return Result::success();
    m_source->offer(data, size);
    m_transfer->paused = false;
    curl_easy_pause(m_transfer->easy, CURLPAUSE_CONT);
    const Result r = m_client->run(m_transfer.get(), [](const Transfer *t) { return t->paused; });
    const bool consumed = m_source->drained();
    m_source->forget();
    if (!r.ok()) {
        abort();
        return r;
    }
    // Done with every byte taken: the announced length is complete and the
    // answer waits for finish(). Done before that: the server cut it short.
    if (m_transfer->done && !consumed)
        return Result(Error::ProtocolError, QStringLiteral("The server ended the upload early"));
    return Result::success();
}

Result Client::Stream::finish(Response *response)
{
    if (m_dead)
        return Result(Error::ConnectionLost, QStringLiteral("The upload is no longer active"));
    m_source->finish();
    Result r;
    if (!m_transfer->done) {
        m_transfer->paused = false;
        curl_easy_pause(m_transfer->easy, CURLPAUSE_CONT);
        r = m_client->run(m_transfer.get(), nullptr);
    }
    if (r.ok())
        r = m_client->outcome(m_transfer.get());
    long status = 0;
    curl_easy_getinfo(m_transfer->easy, CURLINFO_RESPONSE_CODE, &status);
    if (status > 0)
        m_response.status = int(status);
    *response = m_response;
    abort();
    return r;
}

void Client::Stream::abort()
{
    if (m_dead)
        return;
    m_dead = true;
    if (m_transfer->easy) {
        m_client->detach(m_transfer.get());
        curl_easy_cleanup(m_transfer->easy);
        m_transfer->easy = nullptr;
    }
    m_client->m_streams.erase(this);
}

} // namespace NetVfs::WebDav
