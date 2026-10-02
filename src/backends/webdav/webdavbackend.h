// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_WEBDAVBACKEND_H
#define NETVFS_WEBDAVBACKEND_H

#include "backend.h"
#include "davclient.h"
#include "davconfig.h"
#include "davxml.h"

#include <memory>

namespace NetVfs::WebDav {

struct HandleLink;

// SPEC-v2 6.3. One instance = one libcurl easy handle (plus one per open
// write handle), used only from the thread that called connect().
//
// TLS identity (XC-16, W-3, W-4):
//  - no pin: the chain and host name are verified against the system CAs;
//    a trusted server needs no prompt. Otherwise a second handshake that the
//    client ends once it has the certificate (no HTTP request, nothing is
//    sent) reports the certificate and its problems and authenticate()
//    refuses (ServerIdentityUnknown).
//  - pin ("host_key" = "tls-spki-sha256 <base64 SPKI>"): every connection
//    enforces the pin (CURLOPT_PINNEDPUBLICKEY). The account option
//    "tls_verify_peer" records whether the pinned certificate was system
//    trusted when it was pinned (the consumer writes it next to the pin,
//    from ServerIdentity::systemTrusted); "true" keeps chain and host name
//    verification on as well, absent or "false" turns both off and relies
//    on the pin alone. A pinned key that no longer verifies with
//    tls_verify_peer=true is ServerIdentityChanged.
//
// Test hook: built with NETVFS_TLS_TEST_HOOKS (interop driver only, never
// the plugin), the option "test_ca_file" replaces the system CA bundle.
//
// Handles: any number of read handles (each read() is one ranged GET on the
// shared connection), at most MaxWriteHandles write handles (each streams one
// PUT/PATCH on its own connection).
//
// Entry::extra (nextcloud flavor): "oc:fileid", "oc:permissions".
// keepAlive(): HTTP has no session to lose; a server restart is invisible
// unless the transport fails (then ConnectionLost).
class WebDavBackend final : public Backend
{
public:
    WebDavBackend();
    ~WebDavBackend() override;

    static constexpr int MaxWriteHandles = 8;
    // W-9: after a server ignored a Range header, reads further in than this
    // are Unsupported (each would download and discard everything before).
    static constexpr qint64 MaxDiscardForRange = qint64(1) << 20;

    using Backend::authenticate;
    using Backend::list;

    Result connect(const ConnectionParams &params, ServerIdentity *seen) override;
    Result authenticate(const Credentials &credentials, AuthPrompter *prompter) override;
    Capabilities capabilities() const override;

    Result stat(const QString &path, Entry *out) override;
    Result list(const QString &dir, ListSink *sink, const ListOptions &options) override;

    Result makeDir(const QString &path, bool exclusive) override;
    Result removeFile(const QString &path) override;
    Result removeDir(const QString &path) override;
    Result removeTreeNative(const QString &path) override;
    Result rename(const QString &from, const QString &to, RenameMode mode) override;
    Result setAttributes(const QString &path, const AttributeChanges &changes) override;

    Result openRead(const QString &path, ReadHandle **out) override;
    Result openWrite(const QString &path, const WriteOptions &options, WriteHandle **out) override;
    Result upload(QIODevice *source, const QString &path, const UploadOptions &options, Progress *progress) override;
    Result download(const QString &path, QIODevice *sink, const DownloadOptions &options, Progress *progress) override;

    Result copy(const QString &from, const QString &to, const CopyOptions &options) override;
    Result checksum(const QString &path, const QString &algorithm, QByteArray *digest) override;
    Result spaceInfo(const QString &dir, SpaceInfo *out) override;
    Result keepAlive() override;

    void cancel() override;
    void resetCancel() override;
    void disconnect() override;

    // For the handles.
    Result readRange(const QByteArray &url, qint64 offset, qint64 length, QByteArray *out);
    Result finishWrite(Client::Stream *stream, const QString &path, const WriteOptions &options);
    Client &client() { return m_client; }
    void writeHandleClosed() { --m_openWrites; }

private:
    class Handshake;    // connect: TLS identity, OPTIONS, server features (webdavbackend.cpp)
    class Writes;       // PUT/PATCH preparation and outcome
    class Transfers;    // COPY and MOVE

    Result checkUsable() const;
    Result urlFor(const QString &path, bool collection, QByteArray *url) const;
    Result send(Request &request, Response *response);
    // Calls callback(resource, resolver) for every resource of the answer; false from it stops.
    template<typename Callback>
    Result propfind(const QByteArray &url, int depth, Callback &&callback, Response *response);
    bool nextcloud() const;

    Client m_client;
    Config m_config;
    QByteArray m_baseUrl;
    ServerFeatures m_features;
    bool m_featuresKnown = false;
    bool m_connected = false;
    bool m_authenticated = false;
    Result m_identityCheck;
    bool m_quotaSeen = false;
    bool m_efficientRanges = false;
    bool m_rangesIgnored = false;
    int m_openWrites = 0;
    std::shared_ptr<HandleLink> m_link;
};

} // namespace NetVfs::WebDav

#endif
