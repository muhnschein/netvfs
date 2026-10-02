// SPDX-License-Identifier: LGPL-2.1-or-later
#include "webdavbackend.h"
#include "davhandles.h"
#include "davio.h"
#include "davlog.h"
#include "davstatus.h"
#include "tlsidentity.h"
#include "identity.h"
#include "names.h"
#include "paths.h"
#include "secure.h"

#include <QtCore/QIODevice>

namespace NetVfs::WebDav {

using CurlTls::ChainCheck;
using CurlTls::identityFromChain;

namespace {

constexpr int StatusMultiStatus = 207;
constexpr int StatusBadRequest = 400;
constexpr int StatusRangeNotSatisfiable = 416;
constexpr int StatusUnauthorized = 401;
constexpr int StatusForbidden = 403;
constexpr int StatusNotFound = 404;
constexpr int StatusMethodNotAllowed = 405;
constexpr int StatusConflict = 409;
constexpr qint64 MsPerSecond = 1000;
constexpr const char *ContentTypeXml = "Content-Type: application/xml; charset=utf-8";

// The announced length of a streamed body (Client::openStream).
class SizeOnly final : public BodySource
{
public:
    explicit SizeOnly(qint64 size) : m_size(size) {}
    qint64 size() const override { return m_size; }
    qint64 read(char *, qint64) override { return 0; }
    bool rewind() override { return true; }

private:
    qint64 m_size;
};

bool is2xx(int status)
{
    return status >= 200 && status < 300;
}

Result notSignedIn()
{
    return Result(Error::Internal, QStringLiteral("Not signed in"));
}

QString nameOf(const QString &path)
{
    QString normalized;
    Paths::normalize(path, &normalized);
    return Paths::fileName(normalized);
}

bool isRoot(const QString &path)
{
    QString normalized;
    return Paths::normalize(path, &normalized).ok() && Paths::components(normalized).isEmpty();
}

// "<file>/" is 404 on most servers, 400 on Apache, 405 or 409 on others.
bool mayBeFile(const Response &response)
{
    return response.status == StatusBadRequest || response.status == StatusNotFound || response.status == StatusMethodNotAllowed
        || response.status == StatusConflict;
}

QByteArray depthHeader(int depth)
{
    return "Depth: " + QByteArray::number(depth);
}

} // namespace

WebDavBackend::WebDavBackend() = default;

WebDavBackend::~WebDavBackend()
{
    if (m_link)
        m_link->backend = nullptr;
}

// ------------------------------------------------------------- plumbing

Result WebDavBackend::checkUsable() const
{
    if (!m_connected || !m_authenticated)
        return notSignedIn();
    return Result::success();
}

Result WebDavBackend::urlFor(const QString &path, bool collection, QByteArray *url) const
{
    QByteArray relative;
    const Result r = encodeRelativePath(path, &relative);
    if (!r.ok())
        return r;
    *url = m_baseUrl + relative;
    if (collection && !relative.isEmpty())
        *url += '/';
    return Result::success();
}

Result WebDavBackend::send(Request &request, Response *response)
{
    qCDebug(lcNetVfsWebdav) << methodName(request.method).constData() << request.url;
    const Result r = m_client.perform(request, response);
    if (!r.ok())
        qCDebug(lcNetVfsWebdav) << "Request failed:" << r.toString() << r.detail();
    return r;
}

Result WebDavBackend::statusResult(const Response &response, Method method) const
{
    const qint64 retryAfter = parseRetryAfter(response.header("retry-after"), QDateTime::currentDateTimeUtc());
    return httpResult(response.status, method, response.reason, retryAfter);
}

bool WebDavBackend::nextcloud() const
{
    if (m_config.flavor == Flavor::Auto)
        return m_features.nextcloudHints;
    return m_config.flavor == Flavor::Nextcloud;
}

Result WebDavBackend::propfind(const QByteArray &url, int depth, const ResourceCallback &callback,
                               Response *response)
{
    std::unique_ptr<HrefResolver> resolver;
    MultistatusParser parser([&](const DavResource &resource) {
        if (!resolver)
            resolver = std::make_unique<HrefResolver>(response->url);
        return callback(resource, *resolver);
    });
    ParserSink sink(&parser);
    BytesSource body(propfindBody(m_config.flavor != Flavor::Generic));
    Request request;
    request.method = Method::Propfind;
    request.url = url;
    // W-7: Depth 0 or 1 only, never infinity.
    request.headers << depthHeader(depth) << ContentTypeXml;
    request.body = &body;
    request.sink = &sink;
    Result r = send(request, response);
    if (!r.ok())
        return r;
    if (response->status != StatusMultiStatus) {
        if (is2xx(response->status))
            return Result(Error::ProtocolError, QStringLiteral("The server answered PROPFIND without a multistatus"));
        return statusResult(*response, Method::Propfind);
    }
    return parser.stopped() ? Result::success() : parser.finish();
}

Result WebDavBackend::statUrl(const QByteArray &url, const QString &name, Entry *out)
{
    bool found = false;
    DavResource self;
    Response response;
    Result r = propfind(url, 0, [&](const DavResource &resource, const HrefResolver &) {
        if (!found) {
            self = resource;
            found = true;
        }
        return true;
    }, &response);
    if (!r.ok())
        return r;
    if (!found)
        return Result(Error::ProtocolError, QStringLiteral("The server described no resource"));
    if (self.status != 0 && !is2xx(self.status))
        return httpResult(self.status, Method::Propfind);
    if (out)
        *out = toEntry(self, name, nextcloud());
    return Result::success();
}

// ------------------------------------------------------------- connection

Result WebDavBackend::fetchOptions(Response *response)
{
    Request request;
    request.method = Method::Options;
    request.url = m_baseUrl;
    return send(request, response);
}

void WebDavBackend::takeFeatures(const Response &options)
{
    m_features = detectFeatures(options.headers, m_config.basePath);
    m_featuresKnown = is2xx(options.status);
    qCDebug(lcNetVfsWebdav) << "DAV classes" << m_features.davClasses << "nextcloud" << nextcloud();
}

Result WebDavBackend::connectTls(ServerIdentity *identity, Response *options)
{
    const ServerIdentity pinned = ServerIdentity::fromPin(m_config.pin);
    TlsSettings tls;
    if (pinned.kind == ServerIdentity::Kind::TlsCertificate) {
        tls.pinnedKey = "sha256//" + pinned.fingerprint.toLatin1();
        tls.verifyPeer = m_config.pinVerifyPeer;
    }
    tls.caFile = m_config.testCaFile;
    m_client.setTls(tls);

    // W-3: handshake and an unauthenticated OPTIONS; the chain comes from
    // CURLOPT_CERTINFO.
    Request request;
    request.method = Method::Options;
    request.url = m_baseUrl;
    request.certificateInfo = true;
    Result r = send(request, options);
    const QByteArray host = m_config.origin.host;
    if (r.ok() && !options->certificates.isEmpty()) {
        *identity = identityFromChain(options->certificates, host,
                                      tls.verifyPeer ? ChainCheck::Verified : ChainCheck::NotChecked,
                                      m_client.trustStore());
        return Result::success();
    }
    if (!r.ok() && r.error() != Error::ServerIdentityChanged)
        return r;
    // Verification or the pin failed (or the chain is missing): a second
    // handshake without verification collects the chain; no HTTP request
    // is sent on it.
    const bool verificationFailed = !r.ok() && options->curlCode == CURLE_PEER_FAILED_VERIFICATION;
    *options = Response();
    QVector<QByteArray> chain;
    const Result probe = m_client.probeCertificates(&chain);
    if (!probe.ok())
        return probe;
    *identity = identityFromChain(chain, host, verificationFailed ? ChainCheck::Failed : ChainCheck::NotChecked,
                                  m_client.trustStore());
    qCDebug(lcNetVfsWebdav) << "Certificate" << identity->details.value(QStringLiteral("subject")).toString()
                            << "issued by" << identity->details.value(QStringLiteral("issuer")).toString()
                            << "problems" << identity->problems;
    if (verificationFailed && !identity->isEmpty() && *identity == pinned) {
        return Result(Error::ServerIdentityChanged,
                      QStringLiteral("The pinned server certificate is no longer trusted by the system"),
                      r.detail());
    }
    return Result::success();
}

Result WebDavBackend::connect(const ConnectionParams &params, ServerIdentity *seen)
{
    disconnect();
    Result r = parseConfig(params, &m_config);
    if (!r.ok())
        return r;
#ifdef NETVFS_TLS_TEST_HOOKS
    m_config.testCaFile = params.option(QStringLiteral("test_ca_file")).toLocal8Bit();
#endif
    r = m_client.open(m_config.origin, params.connectTimeoutMs, params.requestTimeoutMs);
    if (!r.ok())
        return r;
    m_baseUrl = m_config.baseUrl();
    qCDebug(lcNetVfsWebdav) << "Connecting to" << m_baseUrl;

    ServerIdentity identity;
    Response options;
    if (m_config.origin.scheme == "https") {
        r = connectTls(&identity, &options);
    } else {
        m_client.setTls(TlsSettings());
        r = fetchOptions(&options);
    }
    if (seen)
        *seen = identity;
    if (!r.ok()) {
        m_client.close();
        return r;
    }
    // C-7: authenticate() refuses unless this passes (establish() checks
    // the same before it calls authenticate()).
    m_identityCheck = checkServerIdentity(identity, m_config.pin);
    m_connected = true;
    m_link = std::make_shared<HandleLink>();
    m_link->backend = this;
    if (options.status > 0)
        takeFeatures(options);
    return Result::success();
}

Result WebDavBackend::authenticate(const Credentials &credentials, AuthPrompter *prompter)
{
    Q_UNUSED(prompter)      // no interactive methods over HTTP
    if (!m_connected)
        return Result(Error::Internal, QStringLiteral("Not connected"));
    if (!m_identityCheck.ok())
        return m_identityCheck;
    QByteArray secret(credentials.secret.constData(), credentials.secret.size());
    if (m_config.tokenAuth) {
        m_client.setTokenAuth(&secret);
    } else {
        const QString user = credentials.userName.isEmpty() ? m_config.username : credentials.userName;
        m_client.setPasswordAuth(user.toUtf8(), &secret);
    }
    secureWipe(secret);

    // W-5: PROPFIND Depth 0 on the base.
    DavResource base;
    Response response;
    Result r = propfind(m_baseUrl, 0, [&](const DavResource &resource, const HrefResolver &) {
        if (base.href.isEmpty())
            base = resource;
        return true;
    }, &response);
    if (response.status == StatusUnauthorized || response.status == StatusForbidden)
        return Result(Error::AuthFailed, QStringLiteral("The server did not accept the credentials"),
                      QStringLiteral("HTTP %1").arg(response.status));
    if (response.status == StatusNotFound)
        return Result(Error::NotFound, QStringLiteral("The base path does not exist"));
    if (!r.ok())
        return r;
    m_client.pinAuthMethod();
    m_quotaSeen = base.quotaAvailable >= 0 || base.quotaUsed >= 0;
    if (!m_featuresKnown) {
        Response options;
        r = fetchOptions(&options);
        if (!r.ok())
            return r;
        takeFeatures(options);
    }
    m_authenticated = true;
    return Result::success();
}

Capabilities WebDavBackend::capabilities() const
{
    Capabilities caps;
    if (!m_authenticated)
        return caps;
    // W-8, W-9, W-10
    caps.flags << Capability::ReadHandles << Capability::AtomicPut << Capability::AtomicReplace
               << Capability::NativeNoReplace << Capability::ServerCopy << Capability::ServerCopyRecursive
               << Capability::RecursiveDelete << Capability::ETags;
    if (m_efficientRanges && !m_rangesIgnored)
        caps.flags << Capability::EfficientRanges;
    if (m_quotaSeen)
        caps.flags << Capability::SpaceInfo;
    if (m_features.partialUpdate)
        caps.flags << Capability::WriteResume;
    if (nextcloud()) {
        // W-11
        caps.flags << Capability::SetModifiedOnUpload << Capability::Checksums;
        caps.checksumAlgorithms << QStringLiteral("sha1") << QStringLiteral("md5") << QStringLiteral("adler32");
    }
    return caps;
}

Result WebDavBackend::keepAlive()
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    Response response;
    const Result r = fetchOptions(&response);
    if (r.error() == Error::NetworkUnreachable)
        return Result(Error::ConnectionLost, r.message(), r.detail());
    return r;
}

void WebDavBackend::cancel()
{
    m_client.cancel();
}

void WebDavBackend::resetCancel()
{
    m_client.resetCancel();
}

void WebDavBackend::disconnect()
{
    if (m_link) {
        m_link->backend = nullptr;
        m_link.reset();
    }
    m_client.close();
    m_connected = false;
    m_authenticated = false;
    m_featuresKnown = false;
    m_features = ServerFeatures();
    m_identityCheck = Result();
    m_quotaSeen = false;
    m_efficientRanges = false;
    m_rangesIgnored = false;
    m_openWrites = 0;
}

// ------------------------------------------------------------- metadata

Result WebDavBackend::stat(const QString &path, Entry *out)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    QByteArray url;
    if (Result r = urlFor(path, false, &url); !r.ok())
        return r;
    return statUrl(url, nameOf(path), out);
}

Result WebDavBackend::list(const QString &dir, ListSink *sink, const ListOptions &options)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    QByteArray url;
    if (Result r = urlFor(dir, true, &url); !r.ok())
        return r;
    const int batchSize = options.batchSize > 0 ? options.batchSize : ListOptions().batchSize;
    const bool flavorNextcloud = nextcloud();
    QVector<Entry> batch;
    bool sinkStopped = false;
    bool selfIsFile = false;
    Response response;
    Result r = propfind(url, 1, [&](const DavResource &resource, const HrefResolver &resolver) {
        QByteArray name;
        switch (resolver.classify(resource.href, &name)) {
        case HrefResolver::Kind::Self:
            selfIsFile = resource.typeKnown && !resource.collection;
            return true;
        case HrefResolver::Kind::Other:
            qCDebug(lcNetVfsWebdav) << "Ignoring href" << resource.href;
            return true;
        case HrefResolver::Kind::Child:
            break;
        }
        if (resource.status != 0 && !is2xx(resource.status))
            return true;
        batch << toEntry(resource, Names::decode(name), flavorNextcloud);
        if (batch.size() < batchSize)
            return true;
        // XC-6: delivered while the response is still streaming.
        sinkStopped = !sink->entries(batch);
        batch.clear();
        return !sinkStopped;
    }, &response);
    if (r.ok() && response.status == StatusMultiStatus && selfIsFile)
        return Result(Error::NotADirectory, QStringLiteral("Not a folder"));
    if (r.ok() && !sinkStopped && !batch.isEmpty())
        sinkStopped = !sink->entries(batch);
    if (sinkStopped)
        return Result(Error::Canceled, QStringLiteral("Canceled"));
    if (!r.ok() && mayBeFile(response)) {
        Entry entry;
        if (stat(dir, &entry).ok() && !entry.isDir())
            return Result(Error::NotADirectory, QStringLiteral("Not a folder"));
    }
    return r;
}

// ------------------------------------------------------------- namespace

Result WebDavBackend::makeDir(const QString &path, bool exclusive)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    if (isRoot(path))
        return exclusive ? Result(Error::AlreadyExists, QStringLiteral("The folder already exists")) : Result::success();
    if (exclusive) {
        // MKCOL on an existing collection is 405 (RFC 4918 9.3.1), but some
        // servers (rclone) answer 201.
        Entry existing;
        if (stat(path, &existing).ok())
            return Result(Error::AlreadyExists, QStringLiteral("The folder already exists"));
    }
    Request request;
    request.method = Method::Mkcol;
    if (Result r = urlFor(path, true, &request.url); !r.ok())
        return r;
    Response response;
    if (Result r = send(request, &response); !r.ok())
        return r;
    const Result r = statusResult(response, Method::Mkcol);
    if (r.error() != Error::AlreadyExists || exclusive)
        return r;
    // XC-8: an existing folder is fine without `exclusive`.
    Entry entry;
    if (stat(path, &entry).ok() && entry.isDir())
        return Result::success();
    return r;
}

Result WebDavBackend::removeFile(const QString &path)
{
    Entry entry;
    if (Result r = stat(path, &entry); !r.ok())
        return r;
    if (entry.isDir())
        return Result(Error::IsADirectory, QStringLiteral("Is a folder"));
    Request request;
    request.method = Method::Delete;
    if (Result r = urlFor(path, false, &request.url); !r.ok())
        return r;
    Response response;
    if (Result r = send(request, &response); !r.ok())
        return r;
    return statusResult(response, Method::Delete);
}

Result WebDavBackend::removeDir(const QString &path)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    QByteArray url;
    if (Result r = urlFor(path, true, &url); !r.ok())
        return r;
    // XC-9: emptiness check, then DELETE (a member created in between is
    // deleted with the folder; WebDAV has no "delete if empty").
    bool hasMember = false;
    bool selfIsFile = false;
    Response response;
    Result r = propfind(url, 1, [&](const DavResource &resource, const HrefResolver &resolver) {
        switch (resolver.classify(resource.href, nullptr)) {
        case HrefResolver::Kind::Self:
            selfIsFile = resource.typeKnown && !resource.collection;
            return true;
        case HrefResolver::Kind::Child:
            hasMember = true;
            return false;
        case HrefResolver::Kind::Other:
            break;
        }
        return true;
    }, &response);
    if (!r.ok() && mayBeFile(response)) {
        Entry entry;
        if (stat(path, &entry).ok() && !entry.isDir())
            return Result(Error::NotADirectory, QStringLiteral("Not a folder"));
    }
    if (!r.ok())
        return r;
    if (selfIsFile)
        return Result(Error::NotADirectory, QStringLiteral("Not a folder"));
    if (hasMember)
        return Result(Error::DirectoryNotEmpty, QStringLiteral("The folder is not empty"));
    Request request;
    request.method = Method::Delete;
    request.url = url;
    if (r = send(request, &response); !r.ok())
        return r;
    if (response.status == StatusMultiStatus)
        return multistatusFailure(response, Method::Delete);
    return statusResult(response, Method::Delete);
}

Result WebDavBackend::removeTreeNative(const QString &path)
{
    Entry entry;
    if (Result r = stat(path, &entry); !r.ok())
        return r;
    Request request;
    request.method = Method::Delete;
    if (Result r = urlFor(path, entry.isDir(), &request.url); !r.ok())
        return r;
    Response response;
    if (Result r = send(request, &response); !r.ok())
        return r;
    if (response.status == StatusMultiStatus)
        return multistatusFailure(response, Method::Delete);
    return statusResult(response, Method::Delete);
}

// A 207 answer to DELETE/COPY/MOVE lists the members that failed.
Result WebDavBackend::multistatusFailure(const Response &response, Method method) const
{
    int failed = 0;
    MultistatusParser parser([&](const DavResource &resource) {
        if (resource.status != 0 && !is2xx(resource.status)) {
            failed = resource.status;
            return false;
        }
        return true;
    });
    parser.feed(response.body.constData(), response.body.size());
    if (failed != 0)
        return httpResult(failed, method);
    if (!parser.stopped()) {
        const Result r = parser.finish();
        if (!r.ok())
            return r;
    }
    return Result::success();
}

Result WebDavBackend::checkReplaceTarget(const QString &to)
{
    // XC-10: a folder is never replaced (with NoReplace the server refuses
    // any existing target itself).
    Entry target;
    const Result r = stat(to, &target);
    if (r.ok() && target.isDir())
        return Result(Error::AlreadyExists, QStringLiteral("Cannot replace a folder"));
    if (!r.ok() && r.error() != Error::NotFound)
        return r;
    return Result::success();
}

Result WebDavBackend::transferTo(Method method, const QString &from, const QString &to, RenameMode mode,
                                 const QByteArray &depth)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    Request request;
    request.method = method;
    QByteArray destination;
    if (Result r = urlFor(from, false, &request.url); !r.ok())
        return r;
    if (Result r = urlFor(to, false, &destination); !r.ok())
        return r;
    if (mode == RenameMode::Replace) {
        if (Result r = checkReplaceTarget(to); !r.ok())
            return r;
    }
    // W-8: the server enforces NoReplace (412) and replaces atomically.
    request.headers << "Destination: " + destination
                    << QByteArray(mode == RenameMode::Replace ? "Overwrite: T" : "Overwrite: F");
    if (!depth.isEmpty())
        request.headers << "Depth: " + depth;
    Response response;
    if (Result r = send(request, &response); !r.ok())
        return r;
    if (response.status == StatusMultiStatus)
        return multistatusFailure(response, method);
    const Result r = statusResult(response, method);
    if (r.error() == Error::PermissionDenied) {
        // A missing source is 403 on some servers (rclone).
        Entry source;
        if (stat(from, &source).error() == Error::NotFound)
            return Result(Error::NotFound, QStringLiteral("No such file or folder"), r.detail());
    }
    return r;
}

Result WebDavBackend::rename(const QString &from, const QString &to, RenameMode mode)
{
    return transferTo(Method::Move, from, to, mode, QByteArray());
}

Result WebDavBackend::copy(const QString &from, const QString &to, const CopyOptions &options)
{
    Entry source;
    if (Result r = stat(from, &source); !r.ok())
        return r;
    const QByteArray depth = source.isDir() && options.recursive ? QByteArray("infinity") : QByteArray("0");
    return transferTo(Method::Copy, from, to, options.mode, depth);
}

Result WebDavBackend::setAttributes(const QString &path, const AttributeChanges &changes)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    Q_UNUSED(path)
    if (changes.isEmpty())
        return Result::success();
    // W-11: no generic way to set modes or times; Nextcloud only at upload.
    return Result(Error::Unsupported, QStringLiteral("The server does not support changing attributes"));
}

// ------------------------------------------------------------- reading

Result WebDavBackend::readRange(const QByteArray &url, qint64 offset, qint64 length, QByteArray *out)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    if (m_rangesIgnored && offset > MaxDiscardForRange) {
        return Result(Error::Unsupported,
                      QStringLiteral("The server ignores ranged reads; read the file from the start instead"));
    }
    Request request;
    request.method = Method::Get;
    request.url = url;
    request.headers << "Range: bytes=" + QByteArray::number(offset) + '-' + QByteArray::number(offset + length - 1);
    Response response;
    RangeSink sink(&response, offset, length, [out](const char *data, qint64 size) {
        out->append(data, int(size));
        return true;
    });
    request.sink = &sink;
    if (Result r = send(request, &response); !r.ok()) {
        out->clear();
        return r;
    }
    if (response.status == StatusRangeNotSatisfiable)
        return Result::success();   // at or past EOF
    if (!is2xx(response.status))
        return statusResult(response, Method::Get);
    if (sink.partial()) {
        m_efficientRanges = true;
    } else {
        // W-9: the server sent the whole file.
        m_efficientRanges = false;
        m_rangesIgnored = true;
    }
    return Result::success();
}

Result WebDavBackend::openRead(const QString &path, ReadHandle **out)
{
    *out = nullptr;
    Entry entry;
    if (Result r = stat(path, &entry); !r.ok())
        return r;
    if (entry.isDir())
        return Result(Error::IsADirectory, QStringLiteral("Is a folder"));
    QByteArray url;
    if (Result r = urlFor(path, false, &url); !r.ok())
        return r;
    *out = std::make_unique<DavReadHandle>(m_link, url, entry.size).release();   // the caller owns it
    return Result::success();
}

Result WebDavBackend::download(const QString &path, QIODevice *sink, const DownloadOptions &options,
                               Progress *progress)
{
    if (options.offset < 0 || options.length < -1)
        return Result(Error::Internal, QStringLiteral("Invalid range"));
    Entry entry;
    if (Result r = stat(path, &entry); !r.ok())
        return r;
    if (entry.isDir())
        return Result(Error::IsADirectory, QStringLiteral("Is a folder"));
    if (options.length == 0)
        return Result::success();
    Request request;
    request.method = Method::Get;
    request.progress = progress;
    if (Result r = urlFor(path, false, &request.url); !r.ok())
        return r;
    if (options.offset > 0 || options.length > 0) {
        QByteArray range = "Range: bytes=" + QByteArray::number(options.offset) + '-';
        if (options.length > 0)
            range += QByteArray::number(options.offset + options.length - 1);
        request.headers << range;
    }
    qint64 total = options.length;
    if (total < 0 && entry.size >= 0)
        total = qMax<qint64>(0, entry.size - options.offset);
    Response response;
    RangeSink body(&response, options.offset, options.length, [sink](const char *data, qint64 size) {
        return sink->write(data, size) == size;
    }, progress, total);
    request.sink = &body;
    if (Result r = send(request, &response); !r.ok())
        return r;
    if (response.status == StatusRangeNotSatisfiable && entry.size >= 0 && options.offset >= entry.size)
        return Result::success();
    return statusResult(response, Method::Get);
}

// ------------------------------------------------------------- writing

QList<QByteArray> WebDavBackend::uploadHeaders(const WriteOptions &options) const
{
    QList<QByteArray> headers;
    if (options.disposition == WriteOptions::Resume) {
        // W-10: sabre/dav partial update.
        headers << "Content-Type: application/x-sabredav-partialupdate" << "X-Update-Range: append";
    } else {
        headers << "Content-Type: application/octet-stream";
    }
    // W-10: the server refuses to replace (412) instead of us checking first.
    if (options.disposition == WriteOptions::CreateNew)
        headers << "If-None-Match: *";
    // W-11
    if (nextcloud() && options.modified.isValid())
        headers << "X-OC-MTime: " + QByteArray::number(options.modified.toMSecsSinceEpoch() / MsPerSecond);
    return headers;
}

Result WebDavBackend::prepareWrite(const QString &path, const WriteOptions &options)
{
    if (options.disposition == WriteOptions::Resume)
        return prepareResume(path, options);
    if (options.disposition != WriteOptions::CreateNew)
        return Result::success();
    // W-10: If-None-Match: * makes the server refuse to replace; some
    // servers (rclone) ignore it, so an existing file is caught here, too.
    Entry existing;
    const Result r = stat(path, &existing);
    if (r.ok())
        return Result(Error::AlreadyExists, QStringLiteral("The file already exists"));
    return r.error() == Error::NotFound ? Result::success() : r;
}

Result WebDavBackend::prepareResume(const QString &path, const WriteOptions &options)
{
    if (!m_features.partialUpdate)
        return Result(Error::Unsupported, QStringLiteral("The server cannot resume uploads"));
    Entry existing;
    if (Result r = stat(path, &existing); !r.ok())
        return r;
    if (existing.size != options.resumeOffset) {
        return Result(Error::ProtocolError, QStringLiteral("Cannot resume at %1: the partial file has %2 bytes")
                                                .arg(options.resumeOffset)
                                                .arg(existing.size));
    }
    return Result::success();
}

Result WebDavBackend::writeTargetResult(const Response &response, Method method, const QString &path)
{
    const Result r = statusResult(response, method);
    if (response.status == StatusMethodNotAllowed || response.status == StatusConflict) {
        Entry entry;
        if (stat(path, &entry).ok() && entry.isDir())
            return Result(Error::IsADirectory, QStringLiteral("Is a folder"));
    }
    return r;
}

Result WebDavBackend::upload(QIODevice *source, const QString &path, const UploadOptions &options,
                             Progress *progress)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    const WriteOptions &write = options.write;
    const bool resume = write.disposition == WriteOptions::Resume;
    if (Result r = prepareWrite(path, write); !r.ok())
        return r;
    qint64 size = write.expectedSize;
    if (size >= 0 && resume)
        size -= write.resumeOffset;
    if (size < 0 && !source->isSequential())
        size = source->size() - source->pos();
    Request request;
    request.method = resume ? Method::Patch : Method::Put;
    request.headers = uploadHeaders(write);
    request.progress = progress;
    if (Result r = urlFor(path, false, &request.url); !r.ok())
        return r;
    const qint64 base = resume ? write.resumeOffset : 0;
    DeviceSource body(source, size, progress, base, size >= 0 ? base + size : -1);
    request.body = &body;
    Response response;
    if (Result r = send(request, &response); !r.ok())
        return r;
    return writeTargetResult(response, request.method, path);
}

Result WebDavBackend::openWrite(const QString &path, const WriteOptions &options, WriteHandle **out)
{
    *out = nullptr;
    if (Result r = checkUsable(); !r.ok())
        return r;
    if (m_openWrites >= MaxWriteHandles)
        return Result(Error::TooManyConnections, QStringLiteral("Too many files open for writing"));
    const bool resume = options.disposition == WriteOptions::Resume;
    if (Result r = prepareWrite(path, options); !r.ok())
        return r;
    qint64 size = options.expectedSize;
    if (size >= 0 && resume)
        size -= options.resumeOffset;
    Request request;
    request.method = resume ? Method::Patch : Method::Put;
    request.headers = uploadHeaders(options);
    if (Result r = urlFor(path, false, &request.url); !r.ok())
        return r;
    // Only the announced size matters here; the stream supplies the bytes.
    SizeOnly announced(size);
    request.body = &announced;
    std::unique_ptr<Client::Stream> stream;
    if (Result r = m_client.openStream(request, &stream); !r.ok())
        return r;
    if (stream->answered()) {
        // Answered before any body byte: an error, or an empty file is done.
        const Result r = finishWrite(stream.get(), path, options);
        if (!r.ok())
            return r;
        stream.reset();
    }
    ++m_openWrites;
    *out = std::make_unique<DavWriteHandle>(m_link, std::move(stream), path, options).release();   // the caller owns it
    return Result::success();
}

Result WebDavBackend::finishWrite(Client::Stream *stream, const QString &path, const WriteOptions &options)
{
    Response response;
    if (Result r = stream->finish(&response); !r.ok())
        return r;
    const Method method = options.disposition == WriteOptions::Resume ? Method::Patch : Method::Put;
    return writeTargetResult(response, method, path);
}

// ------------------------------------------------------------- server-side

Result WebDavBackend::checksum(const QString &path, const QString &algorithm, QByteArray *digest)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    if (!nextcloud())
        return Result(Error::Unsupported, QStringLiteral("The server does not provide checksums"));
    QByteArray url;
    if (Result r = urlFor(path, false, &url); !r.ok())
        return r;
    QString checksums;
    Response response;
    if (Result r = propfind(url, 0, [&](const DavResource &resource, const HrefResolver &) {
            checksums = resource.checksums;
            return false;
        }, &response); !r.ok()) {
        return r;
    }
    const QByteArray value = parseChecksums(checksums).value(algorithm.toLower());
    if (value.isEmpty()) {
        return Result(Error::Unsupported,
                      QStringLiteral("The server has no %1 checksum for this file").arg(algorithm));
    }
    *digest = value;
    return Result::success();
}

Result WebDavBackend::spaceInfo(const QString &dir, SpaceInfo *out)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    QByteArray url;
    if (Result r = urlFor(dir, true, &url); !r.ok())
        return r;
    DavResource self;
    bool found = false;
    Response response;
    if (Result r = propfind(url, 0, [&](const DavResource &resource, const HrefResolver &) {
            self = resource;
            found = true;
            return false;
        }, &response); !r.ok()) {
        return r;
    }
    // W-12: RFC 4331.
    if (!found || !toSpaceInfo(self, out))
        return Result(Error::Unsupported, QStringLiteral("The server does not report free space"));
    return Result::success();
}

} // namespace NetVfs::WebDav
