// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_FTPBACKEND_H
#define NETVFS_FTPBACKEND_H

#include "backend.h"
#include "ftpconnection.h"

#include <QtCore/QSet>

#include <atomic>
#include <memory>

namespace NetVfs::Ftp {

// A handle that may own the transfer slot of the single control connection.
class StreamOwner
{
public:
    virtual ~StreamOwner() = default;
    // The backend needed the connection for something else and ended the
    // owner's transfer.
    virtual void streamStopped() = 0;
    // disconnect(): every later call returns ConnectionLost.
    virtual void invalidate() = 0;
};

// FTP/FTPS over libcurl (SPEC-v2 F-1..F-7). One control connection per
// instance, used from one thread; only cancel() may be called from another
// thread. Handles share the control connection: a paused handle transfer
// is ended (and the connection reopened by the next request) when another
// call needs the connection.
//
// Account options: "tls_mode" explicit (default, port 21) | implicit (990) |
// none (needs "allow_insecure"=true); "host_key" (TLS pin
// "tls-spki-sha256 <base64 SPKI>"); "tls_verify_peer" (W-4, as WebDAV);
// test builds with NETVFS_TLS_TEST_HOOKS only: "test_ca_file".
//
// connect() (F-2, C-7) does not keep a connection: libcurl sends USER right
// after AUTH TLS, so the identity comes from a probe connection whose TLS
// handshake the client ends (CurlTls::IdentityProbe). authenticate() then
// opens the control connection with that identity enforced by libcurl (the
// pin, or verification when the certificate was system trusted).
// Relative paths are relative to the login folder (PWD); every command
// carries an absolute path. FTPS uses TLS 1.2 (see ftpconnection.cpp).
//
// Capabilities: ReadHandles, PosixModes (SITE CHMOD; removed when the
// server refuses it, the documented F-4 exception), EfficientRanges and
// WriteResume with "REST STREAM", SetModified with MFMT. No SpaceInfo
// (F-6), no atomic rename or put, no links.
class FtpBackend : public Backend
{
public:
    FtpBackend();
    FtpBackend(const FtpBackend &) = delete;
    FtpBackend &operator=(const FtpBackend &) = delete;
    ~FtpBackend() override;

    Result connect(const ConnectionParams &params, ServerIdentity *seen) override;
    Result authenticate(const Credentials &credentials, AuthPrompter *prompter) override;
    Capabilities capabilities() const override;

    Result stat(const QString &path, Entry *out) override;
    Result list(const QString &dir, ListSink *sink, const ListOptions &options) override;

    Result makeDir(const QString &path, bool exclusive) override;
    Result removeFile(const QString &path) override;
    Result removeDir(const QString &path) override;
    Result rename(const QString &from, const QString &to, RenameMode mode) override;
    Result setAttributes(const QString &path, const AttributeChanges &changes) override;

    Result openRead(const QString &path, ReadHandle **out) override;
    Result openWrite(const QString &path, const WriteOptions &options, WriteHandle **out) override;
    Result upload(QIODevice *source, const QString &path, const UploadOptions &options,
                  Progress *progress) override;
    Result download(const QString &path, QIODevice *sink, const DownloadOptions &options,
                    Progress *progress) override;

    Result keepAlive() override;

    void cancel() override;
    void resetCancel() override;
    void disconnect() override;

    // ---- for the handles (ftphandles.cpp) ----
    // Makes `owner` the user of the connection, ending another owner's
    // transfer first. Fails when not connected or canceled.
    Result claim(StreamOwner *owner);
    void release(StreamOwner *owner);
    void registerHandle(StreamOwner *handle);
    void unregisterHandle(StreamOwner *handle);
    Connection *connection() const { return m_connection.get(); }
    QList<QByteArray> prefixed(const QList<QByteArray> &commands);
    void requestDone();
    bool canceled() const { return m_canceled.load(); }
    Result applyModified(const QByteArray &remote, const QDateTime &modified);
    // Maps a failed upload of `remote` to the most precise error (missing
    // parent, target is a folder).
    Result explainUpload(const Result &failure, const QByteArray &remote) { return uploadFailure(failure, remote); }
    Result explainRead(const Result &failure, const QByteArray &remote) { return readFailure(failure, remote); }

private:
    Result ready() const;
    Result resolve(const QString &path, QByteArray *remote) const;
    Result command(const QList<QByteArray> &commands, QVector<Reply> *replies, const QString &context);
    Result statRemote(const QByteArray &remote, Entry *out);
    Result statMlst(const QByteArray &remote, Entry *out);
    Result statBasic(const QByteArray &remote, Entry *out);
    Result statViaParent(const QByteArray &remote, Entry *out);
    Result listRemote(const QByteArray &remote, ListSink *sink, int batchSize);
    Result uploadFailure(const Result &failure, const QByteArray &remote);
    Result readFailure(const Result &failure, const QByteArray &remote);
    Result prepareWrite(const QByteArray &remote, const WriteOptions &options);
    Result chmod(const QByteArray &remote, qint32 mode);

    std::unique_ptr<Connection> m_connection;
    ConnectionParams m_params;
    Settings m_settings;
    ServerIdentity m_seen;
    bool m_connected = false;        // connect() succeeded
    Features m_features;
    QByteArray m_home = QByteArrayLiteral("/");
    Capabilities m_capabilities;
    bool m_utf8 = false;             // UTF8 in FEAT: OPTS UTF8 ON per new connection
    bool m_utf8Pending = false;
    bool m_lastPrefixed = false;
    StreamOwner *m_owner = nullptr;
    QSet<StreamOwner *> m_handles;
    std::atomic<bool> m_canceled { false };
};

Backend *createFtpBackend();

} // namespace NetVfs::Ftp

#endif
