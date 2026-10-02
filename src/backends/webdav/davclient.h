// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DAVCLIENT_H
#define NETVFS_DAVCLIENT_H

#include "davstatus.h"
#include "davtls.h"
#include "davurl.h"

#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>

#include <curl/curl.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <set>

namespace NetVfs {
class Progress;
}

namespace NetVfs::WebDav {

// W-13: a libcurl CURLcode as a Result. `message` is curl's error buffer.
Result curlResult(int code, const QString &message = QString());

// Request body. read() returns the number of bytes, 0 at the end, Failed
// (see error()) or Pause when no data is available yet (streamed writes).
class BodySource
{
public:
    static constexpr qint64 Failed = -1;
    static constexpr qint64 Pause = -2;
    virtual ~BodySource();
    virtual qint64 size() const = 0;                  // -1: unknown (chunked)
    virtual qint64 read(char *buffer, qint64 maxSize) = 0;
    virtual bool rewind() = 0;                        // for a repeated request
    virtual Result error() const { return Result::success(); }
};

// Response body of a 2xx answer. write() returns false to stop the
// transfer: with stopResult() ok the stop was intended (the request still
// succeeds), otherwise the request fails with stopResult().
class BodySink
{
public:
    virtual ~BodySink();
    virtual bool write(const char *data, qint64 size) = 0;
    virtual Result stopResult() const { return Result::success(); }
};

class BytesSource final : public BodySource
{
public:
    explicit BytesSource(const QByteArray &data) : m_data(data) {}
    qint64 size() const override { return m_data.size(); }
    qint64 read(char *buffer, qint64 maxSize) override;
    bool rewind() override;

private:
    QByteArray m_data;
    qint64 m_position = 0;
};

struct Request {
    Method method = Method::Get;
    QByteArray url;                  // absolute
    QList<QByteArray> headers;       // "Name: value"
    BodySource *body = nullptr;
    BodySink *sink = nullptr;        // 2xx bodies; others are kept in Response::body
    Progress *progress = nullptr;    // only for Progress::canceled()
    bool certificateInfo = false;    // fill Response::certificates
};

struct Response {
    int status = 0;
    int curlCode = 0;                        // CURLcode of the transfer
    QByteArray reason;
    QByteArray url;                          // after redirects
    QMap<QByteArray, QByteArray> headers;    // lower-case names, repeats joined by ", "
    QByteArray body;                         // non-2xx bodies, capped
    QVector<QByteArray> certificates;        // PEM, leaf first
    QByteArray header(const char *name) const { return headers.value(QByteArray(name)); }
};

struct TlsSettings {
    bool verifyPeer = true;          // W-4: host name verification follows it
    QByteArray pinnedKey;            // "sha256//<base64>"; empty: no pin
    QByteArray caFile;               // test hook only (see webdavbackend.h)
};

struct Transfer;

// One libcurl easy handle in a private multi handle (SPEC-v2 W-1), driven by a
// poll loop so that cancel() ends any wait within C-9's 2 s. Not thread-safe
// except cancel(). Security settings (XSEC-4, W-5, W-6, W-16) are applied to
// every easy handle it creates.
class Client
{
public:
    Client();
    ~Client();
    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;

    static constexpr int MaxRedirects = 3;          // W-6
    static constexpr qint64 MaxErrorBody = 1 << 20;

    Result open(const Origin &origin, int connectTimeoutMs, int requestTimeoutMs);
    void close();
    bool isOpen() const { return m_easy != nullptr; }
    const Origin &origin() const { return m_origin; }

    void setTls(const TlsSettings &tls) { m_tls = tls; }
    // W-5. The arguments are wiped (SEC-5, XSEC-6); the client keeps its own
    // copy for new easy handles and wipes it in close().
    void setPasswordAuth(const QByteArray &user, QByteArray *password);
    void setTokenAuth(QByteArray *token);
    // After the first authenticated answer: the method libcurl negotiated,
    // so that later handles authenticate without a first 401 round trip.
    void pinAuthMethod();

    // Sends `request`, following same-origin redirects (W-6).
    Result perform(const Request &request, Response *response);
    // W-3: a TLS handshake without verification and without any HTTP
    // request, only to collect the certificate chain.
    Result probeCertificates(QVector<QByteArray> *chain);
    TrustStore trustStore() const;

    // Streamed request body (openWrite) on a separate easy handle.
    class Stream;
    // Sends the request head and returns once libcurl wants body bytes or
    // the server already answered (Stream::answered()).
    Result openStream(const Request &request, std::unique_ptr<Stream> *out);

    void cancel();
    void resetCancel() { m_cancel = false; }
    bool canceled() const { return m_cancel; }

private:
    friend struct Transfer;
    CURL *newEasy();
    void applyRequest(Transfer *transfer, const Request &request, const QByteArray &url);
    void applyAuth(CURL *easy) const;
    Result once(const Request &request, const QByteArray &url, Response *response);
    // Runs the multi handle until `transfer` is done or `until` returns true.
    Result run(Transfer *transfer, bool (*until)(const Transfer *));
    void drainMessages();
    void detach(Transfer *transfer);
    Result outcome(const Transfer *transfer) const;

    Origin m_origin;
    TlsSettings m_tls;
    int m_connectTimeoutMs = 0;
    int m_requestTimeoutMs = 0;
    CURLM *m_multi = nullptr;
    CURLSH *m_share = nullptr;
    CURL *m_easy = nullptr;
    enum class AuthMode { None, Password, Token } m_authMode = AuthMode::None;
    long m_authMask = 0;
    QByteArray m_user;
    QByteArray m_secret;
    std::set<Stream *> m_streams;
    std::atomic<bool> m_cancel { false };
    std::mutex m_wakeLock;           // guards m_multi for cancel()
};

// A request whose body is written piece by piece (W-10 openWrite). Memory
// stays bounded (C-10): write() returns once libcurl has taken the bytes.
class Client::Stream
{
public:
    Stream(Client *client, const Request &request);   // see Client::openStream()
    ~Stream();
    Stream(const Stream &) = delete;
    Stream &operator=(const Stream &) = delete;

    // The server answered before the body was complete; finish() has it.
    bool answered() const;
    Result write(const char *data, qint64 size);
    // Ends the body and waits for the answer. The stream is closed after.
    Result finish(Response *response);
    // Closes the request without completing it (the server sees a broken
    // upload); idempotent.
    void abort();
    qint64 written() const;

private:
    friend class Client;
    class Source;
    Client *m_client;
    std::unique_ptr<Source> m_source;
    Request m_request;
    std::unique_ptr<Transfer> m_transfer;
    Response m_response;
    bool m_dead = false;
};

} // namespace NetVfs::WebDav

#endif
