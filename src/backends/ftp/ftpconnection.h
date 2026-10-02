// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_FTPCONNECTION_H
#define NETVFS_FTPCONNECTION_H

#include "curlhandles.h"
#include "ftpparse.h"
#include "ftpsupport.h"

#include <curl/curl.h>

#include <atomic>
#include <memory>

namespace NetVfs::Ftp {
class Connection;
}

// The user data of libcurl's callbacks of a Connection (ftpcallbacks.h).
struct NetVfsFtpHooks {
    NetVfs::Ftp::Connection *connection;

    size_t write(const char *data, size_t length) const;
    size_t read(char *buffer, size_t capacity) const;
    size_t header(const char *data, size_t length) const;
    void debug(curl_infotype type, const char *data, size_t length) const;
    bool progress(curl_off_t downloadTotal, curl_off_t downloaded, curl_off_t uploadTotal, curl_off_t uploaded) const;
};

namespace NetVfs::Ftp {

// One request on the control connection.
struct Request {
    enum class Kind { Command, Listing, Download, Upload };
    Kind kind = Kind::Command;
    QByteArray path;                 // remote file (Download, Upload); empty otherwise
    QList<QByteArray> commands;      // quoted first, in order (CURLOPT_QUOTE)
    QByteArray listCommand;          // Listing: "MLSD" or "LIST -a" on the current folder
    qint64 offset = 0;               // Download: REST
    qint64 length = -1;              // Download: bytes from `offset`, -1 to EOF
    bool append = false;             // Upload: APPE instead of STOR
};

// Data callbacks of a transfer. Called on the backend thread from inside
// libcurl.
class TransferSink
{
public:
    virtual ~TransferSink() = default;
    // Data from the server: return `size`, 0 to fail the transfer, or
    // CURL_WRITEFUNC_PAUSE to get the same data again after resume.
    virtual size_t received(const char *data, size_t size);
    // Data for the server: bytes copied, 0 at the end, CURL_READFUNC_PAUSE
    // or CURL_READFUNC_ABORT.
    virtual size_t send(char *buffer, size_t size);
    // Byte counts so far (totals 0 when unknown); false stops the transfer
    // (Canceled).
    virtual bool progress(qint64 receiveTotal, qint64 received, qint64 sendTotal, qint64 sent);
};

// The control connection (F-1): one libcurl easy handle in a private multi
// handle, so that every wait polls the cancel flag (C-9, at most
// PollIntervalMs apart) and transfers can be paused between handle calls
// (XC-13). libcurl keeps the control connection open between requests and,
// should it have been closed (a transfer ended early, the server dropped
// it), opens a new one with the same credentials and the same identity
// checks (CurlTls::applyIdentityPolicy).
class Connection
{
public:
    explicit Connection(const std::atomic<bool> *canceled);
    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;
    ~Connection();

    // C-7 probe (F-2): greeting, AUTH TLS (explicit) and a TLS handshake that
    // records the certificate and is then failed by the client, so no USER
    // or other command ever follows. For tls_mode none the probe stops
    // after the greeting. `seen` stays empty without TLS.
    static Result probe(const Settings &settings, const ConnectionParams &params,
                        const std::atomic<bool> *canceled, ServerIdentity *seen);

    // Base options for every request. `seen` is the identity reported by
    // probe(); the policy of CurlTls::applyIdentityPolicy() applies.
    Result configure(const Settings &settings, const ConnectionParams &params, const QString &userName,
                     const QByteArray &secret, const ServerIdentity &seen);

    // Runs a request to its end.
    Result run(const Request &request, TransferSink *sink, const QString &context);

    // Streaming (handles): start() prepares the transfer, pump() drives it
    // until `enough()` holds (then the transfer stays paused or idle in the
    // multi handle) or it ends (the result is returned and finished() is
    // true). stop() ends a started transfer early; libcurl then closes the
    // control connection.
    Result start(const Request &request, TransferSink *sink);
    template<typename Enough>
    Result pump(Enough enough, const QString &context)
    {
        Result r;
        if (!beginPump(&r))
            return r;
        while (!pumpRound(&r, context)) {
            if (enough())
                return Result::success();
            waitForData();
        }
        return r;
    }
    // Wakes a paused transfer (a pump() call does this as well).
    void resume();
    bool started() const { return m_started; }
    bool finished() const { return !m_started; }
    void stop();

    // Replies of the last request, oldest first.
    const QVector<Reply> &replies() const { return m_replies; }
    // The replies to the last `count` quoted commands (all prefixed with
    // '*', so each got exactly one reply); invalid entries if missing. Each
    // reply is found through the command that libcurl sent (the debug
    // callback), not by its place among the replies: libcurl adds commands of
    // its own around the quoted ones (sign-in, a CWD after them in 8.20).
    QVector<Reply> lastReplies(int count) const;
    // The login folder libcurl found with PWD (raw bytes), empty if unknown.
    QByteArray entryPath() const;
    // True when the last request had to open a new control connection
    // although the previous one was expected to be open (XC-20).
    bool unexpectedReconnect() const { return m_unexpectedReconnect; }
    // True while the next request may find the control connection closed
    // (before the first request, after an error or an early end).
    bool mayReconnect() const { return m_expectReconnect; }

    void close();

private:
    friend struct ::NetVfsFtpHooks;

    struct SlistDeleter { void operator()(curl_slist *list) const { curl_slist_free_all(list); } };

    // The three steps of pump(): the checks before it starts; one round of
    // work (true when pump() is over: *result is its outcome); the wait
    // between two rounds.
    bool beginPump(Result *result);
    bool pumpRound(Result *result, const QString &context);
    void waitForData();

    Result applyBase(const QByteArray &url);
    Result applyRequest(const Request &request);
    Result complete(CURLcode code, const QString &context);
    bool guard(const char *data, size_t size);
    void recordSent(curl_infotype type, const char *data, size_t size);
    bool canceled() const { return m_canceled && m_canceled->load(); }

    const std::atomic<bool> *m_canceled;
    Curl::EasyHandle m_easy = Curl::noEasyHandle();
    Curl::MultiHandle m_multi = Curl::noMultiHandle();
    NetVfsFtpHooks m_hooks { this };
    Settings m_settings;
    ConnectionParams m_params;
    QByteArray m_userName;
    QByteArray m_secret;
    ServerIdentity m_seen;
    std::unique_ptr<curl_slist, SlistDeleter> m_quote;
    TransferSink *m_sink = nullptr;
    ReplyReader m_reader;
    TlsGuard m_guard;
    Result m_guardFailure;
    QVector<Reply> m_replies;
    // The commands libcurl sent during the request (never PASS), each with
    // the number of replies received before it: its reply is the next one.
    struct SentCommand {
        QByteArray line;
        int replyIndex = 0;
    };
    QVector<SentCommand> m_sent;
    QList<QByteArray> m_quoted;         // the request's quoted commands, without '*'
    int m_replyBase = 0;                // number of replies before m_replies.first()
    bool m_started = false;
    bool m_paused = false;
    bool m_expectReconnect = true;      // the first request connects
    bool m_closesConnection = false;    // the running request ends the connection
    bool m_unexpectedReconnect = false;
};

} // namespace NetVfs::Ftp

#endif
