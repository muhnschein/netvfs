// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_HTTPTESTSERVER_H
#define NETVFS_HTTPTESTSERVER_H

#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QPair>
#include <QtCore/QVector>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

// A scripted HTTP/1.1 server on 127.0.0.1 for the WebDAV backend's unit
// tests: every request is recorded and answered by a handler. Runs one
// thread per connection; keep-alive, Content-Length and chunked request
// bodies, Expect: 100-continue.
struct HttpRequestRecord {
    QByteArray method;
    QByteArray target;                       // as sent ("/dav/a%20b")
    QMap<QByteArray, QByteArray> headers;    // lower-case names
    QByteArray body;
    int connection = 0;                      // per-server connection number
    bool bodyPending = false;                // Expect handler: body not read yet

    QByteArray header(const char *name) const { return headers.value(QByteArray(name)); }
};

struct HttpReply {
    int status = 200;
    QList<QPair<QByteArray, QByteArray>> headers;
    QByteArray body;
    bool stall = false;          // never answer (until the server is stopped)
    bool stallAfterBody = false; // send headers and `body`, announce more, then stall
    bool close = false;          // close the connection after the reply
    bool proceed = false;        // Expect handler: send 100 Continue and read the body

    static HttpReply make(int status, const QByteArray &body = QByteArray());
    HttpReply &with(const QByteArray &name, const QByteArray &value);
};

struct ssl_ctx_st;

class HttpTestServer
{
public:
    using Handler = std::function<HttpReply(const HttpRequestRecord &)>;

    HttpTestServer();
    // HTTPS with this certificate chain (PEM, leaf first) and key (PEM).
    HttpTestServer(const QByteArray &certificateChain, const QByteArray &key);
    ~HttpTestServer();
    HttpTestServer(const HttpTestServer &) = delete;
    HttpTestServer &operator=(const HttpTestServer &) = delete;

    int port() const { return m_port; }
    QByteArray origin() const;
    int handshakes() const { return m_handshakes; }

    void setHandler(Handler handler);
    // Called for requests with "Expect: 100-continue" before their body is
    // read; reply.proceed (the default when unset) continues.
    void setExpectHandler(Handler handler);
    QVector<HttpRequestRecord> requests() const;
    void clearRequests();
    int connections() const { return m_connections; }
    // Stops reading request bodies (the client's send buffers fill up).
    void pauseReading(bool paused) { m_pauseReads = paused; }

    struct Connection;

private:
    void start();
    void acceptLoop();
    void serve(int fd, int number);
    void serveRequests(Connection *connection, int number);
    bool readRequest(Connection *connection, QByteArray *buffer, HttpRequestRecord *record);
    bool readBody(Connection *connection, QByteArray *buffer, HttpRequestRecord *record);
    bool readMore(Connection *connection, QByteArray *buffer);
    void hold(Connection *connection);
    void record(const HttpRequestRecord &request);
    Handler handler() const;
    Handler expectHandler() const;

    ssl_ctx_st *m_tls = nullptr;
    std::atomic<int> m_handshakes { 0 };
    int m_listen = -1;
    int m_port = 0;
    std::atomic<bool> m_stop { false };
    std::atomic<bool> m_pauseReads { false };
    std::atomic<int> m_connections { 0 };
    mutable std::mutex m_lock;
    Handler m_handler;
    Handler m_expectHandler;
    QVector<HttpRequestRecord> m_requests;
    std::thread m_acceptor;
    std::vector<std::thread> m_workers;
};

#endif
