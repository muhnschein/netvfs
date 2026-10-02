// SPDX-License-Identifier: LGPL-2.1-or-later
#include "httptestserver.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <array>
#include <cerrno>

namespace {

constexpr int PollMs = 50;
constexpr int ReadChunk = 64 * 1024;
constexpr qint64 StallExtra = 1 << 20;

QByteArray reasonFor(int status)
{
    switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 207: return "Multi-Status";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 412: return "Precondition Failed";
    case 416: return "Range Not Satisfiable";
    case 423: return "Locked";
    case 429: return "Too Many Requests";
    case 503: return "Service Unavailable";
    case 507: return "Insufficient Storage";
    default: return "Status";
    }
}

QByteArray head(const HttpReply &reply, qint64 contentLength)
{
    QByteArray text = "HTTP/1.1 " + QByteArray::number(reply.status) + ' ' + reasonFor(reply.status) + "\r\n";
    bool hasLength = false;
    for (const auto &header : reply.headers) {
        text += header.first + ": " + header.second + "\r\n";
        hasLength = hasLength || header.first.toLower() == "content-length";
    }
    if (!hasLength)
        text += "Content-Length: " + QByteArray::number(contentLength) + "\r\n";
    if (reply.close)
        text += "Connection: close\r\n";
    return text + "\r\n";
}

} // namespace

// A plain or TLS connection.
struct HttpTestServer::Connection {
    int fd = -1;
    SSL *ssl = nullptr;

    ~Connection()
    {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        ::close(fd);
    }
    bool pending() const { return ssl && SSL_pending(ssl) > 0; }
    qint64 receive(char *data, int size, bool peek)
    {
        if (ssl)
            return peek ? SSL_peek(ssl, data, size) : SSL_read(ssl, data, size);
        return ::recv(fd, data, size_t(size), peek ? MSG_PEEK : 0);
    }
    bool sendAll(const QByteArray &data)
    {
        qint64 sent = 0;
        while (sent < data.size()) {
            const qint64 n = ssl ? SSL_write(ssl, data.constData() + sent, int(data.size() - sent))
                                 : ::send(fd, data.constData() + sent, size_t(data.size() - sent), MSG_NOSIGNAL);
            if (n <= 0)
                return false;
            sent += n;
        }
        return true;
    }
};

HttpReply HttpReply::make(int status, const QByteArray &body)
{
    HttpReply reply;
    reply.status = status;
    reply.body = body;
    return reply;
}

HttpReply &HttpReply::with(const QByteArray &name, const QByteArray &value)
{
    headers << qMakePair(name, value);
    return *this;
}

HttpTestServer::HttpTestServer()
{
    start();
}

HttpTestServer::HttpTestServer(const QByteArray &certificateChain, const QByteArray &key)
{
    m_tls = SSL_CTX_new(TLS_server_method());
    BIO *chain = BIO_new_mem_buf(certificateChain.constData(), certificateChain.size());
    X509 *leaf = PEM_read_bio_X509(chain, nullptr, nullptr, nullptr);
    SSL_CTX_use_certificate(m_tls, leaf);
    X509_free(leaf);
    while (X509 *extra = PEM_read_bio_X509(chain, nullptr, nullptr, nullptr))
        SSL_CTX_add_extra_chain_cert(m_tls, extra);    // takes ownership
    BIO_free(chain);
    ERR_clear_error();
    BIO *keyBio = BIO_new_mem_buf(key.constData(), key.size());
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    SSL_CTX_use_PrivateKey(m_tls, pkey);
    EVP_PKEY_free(pkey);
    BIO_free(keyBio);
    start();
}

void HttpTestServer::start()
{
    m_listen = ::socket(AF_INET, SOCK_STREAM, 0);
    const int one = 1;
    ::setsockopt(m_listen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(m_listen, reinterpret_cast<sockaddr *>(&address), sizeof address);
    ::listen(m_listen, 16);
    socklen_t length = sizeof address;
    ::getsockname(m_listen, reinterpret_cast<sockaddr *>(&address), &length);
    m_port = ntohs(address.sin_port);
    m_handler = [](const HttpRequestRecord &) { return HttpReply::make(404); };
    m_acceptor = std::thread([this] { acceptLoop(); });
}

HttpTestServer::~HttpTestServer()
{
    m_stop = true;
    m_acceptor.join();
    std::vector<std::thread> workers;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        workers.swap(m_workers);
    }
    for (std::thread &worker : workers)
        worker.join();
    ::close(m_listen);
    if (m_tls)
        SSL_CTX_free(m_tls);
}

QByteArray HttpTestServer::origin() const
{
    return QByteArray(m_tls ? "https" : "http") + "://127.0.0.1:" + QByteArray::number(m_port);
}

void HttpTestServer::setHandler(Handler handler)
{
    std::lock_guard<std::mutex> lock(m_lock);
    m_handler = std::move(handler);
}

void HttpTestServer::setExpectHandler(Handler handler)
{
    std::lock_guard<std::mutex> lock(m_lock);
    m_expectHandler = std::move(handler);
}

HttpTestServer::Handler HttpTestServer::handler() const
{
    std::lock_guard<std::mutex> lock(m_lock);
    return m_handler;
}

HttpTestServer::Handler HttpTestServer::expectHandler() const
{
    std::lock_guard<std::mutex> lock(m_lock);
    return m_expectHandler;
}

QVector<HttpRequestRecord> HttpTestServer::requests() const
{
    std::lock_guard<std::mutex> lock(m_lock);
    return m_requests;
}

void HttpTestServer::clearRequests()
{
    std::lock_guard<std::mutex> lock(m_lock);
    m_requests.clear();
}

void HttpTestServer::record(const HttpRequestRecord &request)
{
    std::lock_guard<std::mutex> lock(m_lock);
    m_requests << request;
}

void HttpTestServer::acceptLoop()
{
    while (!m_stop) {
        pollfd p { m_listen, POLLIN, 0 };
        if (::poll(&p, 1, PollMs) <= 0)
            continue;
        const int fd = ::accept(m_listen, nullptr, nullptr);
        if (fd < 0)
            continue;
        const int number = ++m_connections;
        std::lock_guard<std::mutex> lock(m_lock);
        m_workers.emplace_back([this, fd, number] { serve(fd, number); });
    }
}

bool HttpTestServer::readMore(Connection *connection, QByteArray *buffer)
{
    std::array<char, ReadChunk> chunk {};
    while (!m_stop) {
        if (m_pauseReads) {
            std::this_thread::sleep_for(std::chrono::milliseconds(PollMs));
            continue;
        }
        if (!connection->pending()) {
            pollfd p { connection->fd, POLLIN, 0 };
            const int ready = ::poll(&p, 1, PollMs);
            if (ready < 0 && errno != EINTR)
                return false;
            if (ready <= 0)
                continue;
        }
        const qint64 n = connection->receive(chunk.data(), ReadChunk, false);
        if (n <= 0)
            return false;
        buffer->append(chunk.data(), int(n));
        return true;
    }
    return false;
}

bool HttpTestServer::readRequest(Connection *connection, QByteArray *buffer, HttpRequestRecord *record)
{
    int end = -1;
    while ((end = buffer->indexOf("\r\n\r\n")) < 0) {
        if (!readMore(connection, buffer))
            return false;
    }
    const QList<QByteArray> lines = buffer->left(end).split('\n');
    buffer->remove(0, end + 4);
    const QList<QByteArray> start = lines.value(0).trimmed().split(' ');
    record->method = start.value(0);
    record->target = start.value(1);
    for (int i = 1; i < lines.size(); ++i) {
        const QByteArray line = lines.at(i).trimmed();
        const int colon = line.indexOf(':');
        if (colon > 0)
            record->headers.insert(line.left(colon).trimmed().toLower(), line.mid(colon + 1).trimmed());
    }
    return true;
}

bool HttpTestServer::readBody(Connection *connection, QByteArray *buffer, HttpRequestRecord *record)
{
    if (record->header("transfer-encoding").toLower() == "chunked") {
        for (;;) {
            int line = -1;
            while ((line = buffer->indexOf("\r\n")) < 0) {
                if (!readMore(connection, buffer))
                    return false;
            }
            bool ok = false;
            const int size = buffer->left(line).split(';').value(0).trimmed().toInt(&ok, 16);
            if (!ok)
                return false;
            while (buffer->size() < line + 2 + size + 2) {
                if (!readMore(connection, buffer))
                    return false;
            }
            record->body += buffer->mid(line + 2, size);
            buffer->remove(0, line + 2 + size + 2);
            if (size == 0)
                return true;
        }
    }
    const int length = record->header("content-length").toInt();
    while (buffer->size() < length) {
        if (!readMore(connection, buffer))
            return false;
    }
    record->body = buffer->left(length);
    buffer->remove(0, length);
    return true;
}

// Holds the connection without reading until the client leaves or the
// server stops.
void HttpTestServer::hold(Connection *connection)
{
    std::array<char, 1> scratch {};
    while (!m_stop) {
        pollfd p { connection->fd, POLLIN, 0 };
        if (::poll(&p, 1, PollMs) > 0) {
            if (::recv(connection->fd, scratch.data(), 1, MSG_PEEK) == 0)
                return;
            std::this_thread::sleep_for(std::chrono::milliseconds(PollMs));
        }
    }
}

void HttpTestServer::serve(int fd, int number)
{
    Connection connection;
    connection.fd = fd;
    if (m_tls) {
        // A client that gives up mid-handshake must not block the server.
        timeval timeout { 2, 0 };
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        connection.ssl = SSL_new(m_tls);
        SSL_set_fd(connection.ssl, fd);
        if (SSL_accept(connection.ssl) != 1)
            return;
        ++m_handshakes;
    }
    serveRequests(&connection, number);
}

void HttpTestServer::serveRequests(Connection *connection, int number)
{
    QByteArray buffer;
    while (!m_stop) {
        HttpRequestRecord request;
        request.connection = number;
        if (!readRequest(connection, &buffer, &request))
            return;
        if (request.header("expect").toLower() == "100-continue") {
            HttpReply early;
            early.proceed = true;
            if (const Handler expect = expectHandler()) {
                request.bodyPending = true;
                early = expect(request);
                request.bodyPending = false;
            }
            if (early.stall) {
                hold(connection);
                return;
            }
            if (!early.proceed) {
                record(request);
                early.close = true;
                connection->sendAll(head(early, early.body.size()) + early.body);
                return;
            }
            connection->sendAll("HTTP/1.1 100 Continue\r\n\r\n");
        }
        if (!readBody(connection, &buffer, &request))
            return;
        record(request);
        const HttpReply reply = handler()(request);
        if (reply.stall) {
            hold(connection);
            return;
        }
        const qint64 announced = reply.body.size() + (reply.stallAfterBody ? StallExtra : 0);
        const QByteArray body = request.method == "HEAD" ? QByteArray() : reply.body;
        if (!connection->sendAll(head(reply, announced) + body))
            return;
        if (reply.stallAfterBody && !reply.close)
            hold(connection);
        if (reply.stallAfterBody || reply.close)
            return;
    }
}
