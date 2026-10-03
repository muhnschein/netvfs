// SPDX-License-Identifier: LGPL-2.1-or-later
// WebDAV backend (SPEC-v2 6.3): the pure parts (URLs, status mapping,
// multistatus parsing, options, certificates) and the backend's behaviour
// against an in-process HTTP(S) server.
#include "davclient.h"
#include "davconfig.h"
#include "davstatus.h"
#include "tlsidentity.h"
#include "davurl.h"
#include "davxml.h"
#include "fakedav.h"
#include "httptestserver.h"
#include "identity.h"
#include "names.h"
#include "testcerts.h"
#include "webdavbackend.h"

#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QElapsedTimer>
#include <QtCore/QTemporaryFile>
#include <QtTest/QtTest>

#include <curl/curl.h>

#include <chrono>
#include <csignal>
#include <functional>
#include <memory>
#include <thread>

using namespace NetVfs;
using namespace NetVfs::WebDav;
using namespace NetVfs::CurlTls;

Q_DECLARE_METATYPE(NetVfs::Error)

namespace QTest {
template <>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest

namespace {

constexpr int CancelDelayMs = 300;
constexpr int CancelLimitMs = 2000;    // SPEC C-9
const QByteArray Credential = "Basic " + QByteArray("alice:secret").toBase64();

QByteArray multistatus(const QByteArray &inner)
{
    return "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">" + inner
        + "</d:multistatus>";
}

QByteArray fileResponse(const QByteArray &href, qint64 size)
{
    return "<d:response><d:href>" + href + "</d:href><d:propstat><d:prop><d:resourcetype/>"
           "<d:getcontentlength>" + QByteArray::number(size) + "</d:getcontentlength></d:prop>"
           "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>";
}

QByteArray folderResponse(const QByteArray &href)
{
    return "<d:response><d:href>" + href + "</d:href><d:propstat><d:prop><d:resourcetype><d:collection/>"
           "</d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>";
}

QVector<DavResource> parseAll(const QByteArray &body, Result *result = nullptr)
{
    QVector<DavResource> resources;
    MultistatusParser parser([&](const DavResource &r) {
        resources << r;
        return true;
    });
    parser.feed(body.constData(), body.size());
    const Result r = parser.finish();
    if (result)
        *result = r;
    return resources;
}

class RecordingSink : public ListSink
{
public:
    bool entries(const QVector<Entry> &batch) override
    {
        batches << batch.size();
        all += batch;
        return stopAfter < 0 || batches.size() < stopAfter;
    }
    QVector<int> batches;
    QVector<Entry> all;
    int stopAfter = -1;
};

// Runs `call` and cancels `backend` from another thread after a moment.
qint64 cancelAfterDelay(Backend *backend, const std::function<Result()> &call, Result *result)
{
    std::thread canceller([backend] {
        std::this_thread::sleep_for(std::chrono::milliseconds(CancelDelayMs));
        backend->cancel();
    });
    QElapsedTimer timer;
    timer.start();
    *result = call();
    const qint64 elapsed = timer.elapsed();
    canceller.join();
    return elapsed - CancelDelayMs;
}

class WriteBuffer : public QBuffer
{
public:
    explicit WriteBuffer(QByteArray *data) : QBuffer(data) { open(QIODevice::WriteOnly); }
};

// A sequential source of `size` bytes, for chunked uploads.
class SequentialSource : public QIODevice
{
public:
    explicit SequentialSource(const QByteArray &data) : m_data(data) { open(QIODevice::ReadOnly); }
    bool isSequential() const override { return true; }

protected:
    qint64 readData(char *data, qint64 maxSize) override
    {
        const qint64 n = qMin(maxSize, qint64(m_data.size() - m_position));
        memcpy(data, m_data.constData() + m_position, size_t(n));
        m_position += int(n);
        return n;
    }
    qint64 writeData(const char *, qint64) override { return -1; }

private:
    QByteArray m_data;
    int m_position = 0;
};

} // namespace

class TestWebDav : public QObject
{
    Q_OBJECT

private:
    // A FakeDav behind an HttpTestServer, with a backend signed in as alice.
    struct Fixture {
        Fixture()
        {
            dav.authorization = Credential;
            server.setHandler([this](const HttpRequestRecord &r) { return dav.handle(r); });
            server.setExpectHandler([this](const HttpRequestRecord &r) { return dav.expect(r); });
            params.provider = QStringLiteral("webdav");
            params.host = QStringLiteral("127.0.0.1");
            params.port = server.port();
            params.username = QStringLiteral("alice");
            params.options.insert(QStringLiteral("tls"), QStringLiteral("http"));
            params.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
            params.options.insert(QStringLiteral("base_path"), QStringLiteral("/dav"));
            params.requestTimeoutMs = 10000;
        }
        Result signIn() { return establish(&backend, params, Credentials(QStringLiteral("alice"), "secret")); }
        FakeDav dav;
        HttpTestServer server;
        ConnectionParams params;
        WebDavBackend backend;
    };

private slots:
    void initTestCase();

    // URLs (W-2, W-6, W-7)
    void segmentEncoding();
    void pathEncoding();
    void hostNames();
    void urlSplitting();
    void referenceResolution();
    void redirectOrigin();
    void hrefClassification();

    // status mapping (W-13)
    void httpStatus_data();
    void httpStatus();
    void curlCodes_data();
    void curlCodes();
    void httpDates();
    void retryAfter();
    void contentRange();

    // multistatus (W-7, XSEC-3)
    void propfindBody();
    void multistatusProperties();
    void multistatusIncremental();
    void multistatusPropstat404();
    void multistatusRejectsDoctype();
    void multistatusDepthCap();
    void multistatusSizeCap();
    void multistatusMalformed();
    void multistatusStops();
    void checksums();
    void entries();
    void spaceFromQuota();

    // options and features (W-2, W-3)
    void configOptions();
    void featureDetection();

    // certificates (XC-16)
    void certificateSelfSigned();
    void certificateFromAuthority();
    void certificateValidity();
    void certificateDetails();

    // backend over HTTP
    void connectSendsNoCredentials();
    void plainHttpNeedsConsent();
    void authenticateWithBasic();
    void authenticateFailures_data();
    void authenticateFailures();
    void neverNtlm();
    void bearerToken();
    void capabilitiesFromServer();
    void listInBatches();
    void listStreamsWhileReceiving();
    void listNamesAndOrigins();
    void listNotAFolder();
    void listRejectsDoctype();
    void redirectsSameOrigin();
    void redirectLimit();
    void redirectCrossOrigin();
    void renameModes();
    void copyDepth();
    void makeDirCases();
    void removeCases();
    void serverQuirks();
    void uploadHeaders();
    void uploadChunked();
    void uploadCreateNewConflictBeforeBody();
    void errorStatuses();
    void writeHandle();
    void writeHandleConflict();
    void writeHandleSizeMismatch();
    void resumeWithPartialUpdate();
    void readHandleRanges();
    void readHandleIgnoredRanges();
    void downloadRanges();
    void cancelWithinTwoSeconds_data();
    void cancelWithinTwoSeconds();
    void stallTimesOut();
    void connectionDrop();
    void keepAliveDeadServer();
    void cookiesInMemory();
    void spaceInfoAndChecksum();
    void handlesAfterDisconnect();
    void invalidNames();
    void unreachable();
    void ignoresProxyEnvironment();

    // backend over HTTPS (XC-16, W-3, W-4, XT-5)
    void tlsUntrustedSendsNothing();
    void tlsPinned();
    void tlsPinnedOtherName();
    void tlsPinMismatch();
    void tlsPinnedVerifyPeer();
    void tlsSystemTrusted();
};

void TestWebDav::initTestCase()
{
    qRegisterMetaType<NetVfs::Error>();
    // The TLS test server writes with OpenSSL's socket BIO.
    std::signal(SIGPIPE, SIG_IGN);
}

// ------------------------------------------------------------------ URLs

void TestWebDav::segmentEncoding()
{
    QCOMPARE(encodeSegment("a b"), QByteArray("a%20b"));
    QCOMPARE(encodeSegment("Az09-._~"), QByteArray("Az09-._~"));
    QCOMPARE(encodeSegment("a/b?c#d%"), QByteArray("a%2Fb%3Fc%23d%25"));
    QCOMPARE(encodeSegment("\xff\xc3\xa4"), QByteArray("%FF%C3%A4"));
}

void TestWebDav::pathEncoding()
{
    QByteArray out;
    QVERIFY(encodeRelativePath(QStringLiteral("/a b//c/"), &out).ok());
    QCOMPARE(out, QByteArray("a%20b/c"));
    QVERIFY(encodeRelativePath(QString(), &out).ok());
    QCOMPARE(out, QByteArray());
    // XC-4: escaped bytes go back to the original bytes.
    QVERIFY(encodeRelativePath(Names::decode("x\xff"), &out).ok());
    QCOMPARE(out, QByteArray("x%FF"));
    // A lone UTF-16 surrogate that is not an escape cannot be stored.
    QCOMPARE(encodeRelativePath(QString(QChar(0xD800)), &out).error(), Error::InvalidName);
    QCOMPARE(encodeRelativePath(QStringLiteral("a/../b"), &out).error(), Error::InvalidName);

    QVERIFY(encodeBasePath(QStringLiteral("/remote.php/dav/files/al ice"), &out).ok());
    QCOMPARE(out, QByteArray("/remote.php/dav/files/al%20ice/"));
    QVERIFY(encodeBasePath(QStringLiteral("/"), &out).ok());
    QCOMPARE(out, QByteArray("/"));
    QCOMPARE(encodeBasePath(QStringLiteral("/a/../b"), &out).error(), Error::SecurityPolicy);
}

void TestWebDav::hostNames()
{
    QCOMPARE(hostForUrl(QStringLiteral("Example.COM")), QByteArray("example.com"));
    QCOMPARE(hostForUrl(QStringLiteral("bücher.example")), QByteArray("xn--bcher-kva.example"));
    QCOMPARE(hostForUrl(QStringLiteral("::1")), QByteArray("[::1]"));
    QCOMPARE(hostForUrl(QStringLiteral("[fe80::1]")), QByteArray("[fe80::1]"));
    QCOMPARE(hostForUrl(QStringLiteral("evil.com/x")), QByteArray());
    QCOMPARE(hostForUrl(QStringLiteral("user@evil.com")), QByteArray());
    QCOMPARE(hostForUrl(QStringLiteral("fe80::1%eth0")), QByteArray());
    QCOMPARE(hostForUrl(QString()), QByteArray());
}

void TestWebDav::urlSplitting()
{
    Origin origin;
    QByteArray path;
    QVERIFY(splitUrl("HTTPS://Example.com/a%20b/?q=1#f", &origin, &path));
    QCOMPARE(origin.scheme, QByteArray("https"));
    QCOMPARE(origin.host, QByteArray("example.com"));
    QCOMPARE(origin.port, 443);
    QCOMPARE(path, QByteArray("/a%20b/"));
    QCOMPARE(origin.toUrl(), QByteArray("https://example.com"));
    QVERIFY(splitUrl("http://[::1]:8080", &origin, &path));
    QCOMPARE(origin.host, QByteArray("[::1]"));
    QCOMPARE(origin.port, 8080);
    QCOMPARE(path, QByteArray("/"));
    QCOMPARE(origin.toUrl(), QByteArray("http://[::1]:8080"));
    QVERIFY(!splitUrl("ftp://example.com/", &origin, &path));
    QVERIFY(!splitUrl("https://user@example.com/", &origin, &path));
    QVERIFY(!splitUrl("https://example.com:0/", &origin, &path));
    QVERIFY(!splitUrl("https://example.com:99999/", &origin, &path));
    QVERIFY(!splitUrl("/relative", &origin, &path));
}

void TestWebDav::referenceResolution()
{
    const QByteArray base = "https://h.example/dav/a/b";
    QCOMPARE(resolveReference(base, "c"), QByteArray("https://h.example/dav/a/c"));
    QCOMPARE(resolveReference(base, "/x/y/"), QByteArray("https://h.example/x/y/"));
    QCOMPARE(resolveReference(base, "../c"), QByteArray("https://h.example/dav/c"));
    QCOMPARE(resolveReference(base, "./"), QByteArray("https://h.example/dav/a/"));
    QCOMPARE(resolveReference(base, "//other.example/z"), QByteArray("https://other.example/z"));
    QCOMPARE(resolveReference(base, "http://h.example:80/q?x#y"), QByteArray("http://h.example/q"));
    QCOMPARE(resolveReference(base, "/a/../../b"), QByteArray("https://h.example/b"));
    QCOMPARE(resolveReference(base, ""), QByteArray("https://h.example/dav/a/b"));
    QCOMPARE(resolveReference("not a url", "x"), QByteArray());
}

void TestWebDav::redirectOrigin()
{
    Origin origin;
    QVERIFY(splitUrl("https://h.example/", &origin, nullptr));
    QByteArray target;
    QVERIFY(redirectTarget(origin, "https://h.example/dav", "/dav/", &target).ok());
    QCOMPARE(target, QByteArray("https://h.example/dav/"));
    QVERIFY(redirectTarget(origin, "https://h.example/dav", "https://H.EXAMPLE:443/x", &target).ok());
    QCOMPARE(target, QByteArray("https://h.example/x"));

    // W-6: another host, port or scheme ends with a ProtocolError naming it.
    const Result host = redirectTarget(origin, "https://h.example/dav", "https://evil.example/dav", &target);
    QCOMPARE(host.error(), Error::ProtocolError);
    QVERIFY(host.message().contains(QLatin1String("https://evil.example/dav")));
    QCOMPARE(redirectTarget(origin, "https://h.example/", "https://h.example:8443/", &target).error(),
             Error::ProtocolError);
    QCOMPARE(redirectTarget(origin, "https://h.example/", "http://h.example/", &target).error(), Error::ProtocolError);
    QCOMPARE(redirectTarget(origin, "https://h.example/", "https://u@h.example/", &target).error(),
             Error::ProtocolError);
}

void TestWebDav::hrefClassification()
{
    const HrefResolver resolver("https://h.example/dav/my%20dir/");
    QByteArray name;
    QCOMPARE(resolver.classify("/dav/my%20dir/", &name), HrefResolver::Kind::Self);
    QCOMPARE(resolver.classify("/dav/my dir", &name), HrefResolver::Kind::Self);
    QCOMPARE(resolver.classify("https://h.example/dav/my%20dir", &name), HrefResolver::Kind::Self);
    QCOMPARE(resolver.classify("/dav/my%20dir/a%20b.txt", &name), HrefResolver::Kind::Child);
    QCOMPARE(name, QByteArray("a b.txt"));
    QCOMPARE(resolver.classify("/dav/my%20dir/sub/", &name), HrefResolver::Kind::Child);
    QCOMPARE(name, QByteArray("sub"));
    QCOMPARE(resolver.classify("/dav/my%20dir/%FF%c3%a4", &name), HrefResolver::Kind::Child);
    QCOMPARE(name, QByteArray("\xff\xc3\xa4"));
    QCOMPARE(resolver.classify("https://h.example/dav/my%20dir/abs", &name), HrefResolver::Kind::Child);
    QCOMPARE(name, QByteArray("abs"));
    QCOMPARE(resolver.classify("relative", &name), HrefResolver::Kind::Child);
    QCOMPARE(name, QByteArray("relative"));
    // W-7: another origin, deeper members, slashes or NUL in names
    QCOMPARE(resolver.classify("https://evil.example/dav/my%20dir/x", &name), HrefResolver::Kind::Other);
    QCOMPARE(resolver.classify("http://h.example/dav/my%20dir/x", &name), HrefResolver::Kind::Other);
    QCOMPARE(resolver.classify("/dav/my%20dir/a/b", &name), HrefResolver::Kind::Other);
    QCOMPARE(resolver.classify("/dav/other/x", &name), HrefResolver::Kind::Other);
    QCOMPARE(resolver.classify("/dav/my%20dir/a%2Fb", &name), HrefResolver::Kind::Other);
    QCOMPARE(resolver.classify("/dav/my%20dir/a%00b", &name), HrefResolver::Kind::Other);
    QCOMPARE(resolver.classify("/dav/my%20dir/%2E%2E", &name), HrefResolver::Kind::Other);
}

// ------------------------------------------------------------- statuses

void TestWebDav::httpStatus_data()
{
    QTest::addColumn<int>("status");
    QTest::addColumn<int>("method");
    QTest::addColumn<qint64>("retryAfter");
    QTest::addColumn<NetVfs::Error>("error");
    const int propfind = int(Method::Propfind);
    QTest::newRow("200") << 200 << propfind << qint64(-1) << Error::None;
    QTest::newRow("207") << 207 << propfind << qint64(-1) << Error::None;
    QTest::newRow("304") << 304 << int(Method::Get) << qint64(-1) << Error::NotModified;
    QTest::newRow("302") << 302 << propfind << qint64(-1) << Error::ProtocolError;
    QTest::newRow("400") << 400 << propfind << qint64(-1) << Error::ProtocolError;
    QTest::newRow("401") << 401 << propfind << qint64(-1) << Error::AuthFailed;
    QTest::newRow("403") << 403 << propfind << qint64(-1) << Error::PermissionDenied;
    QTest::newRow("404") << 404 << propfind << qint64(-1) << Error::NotFound;
    QTest::newRow("405 mkcol") << 405 << int(Method::Mkcol) << qint64(-1) << Error::AlreadyExists;
    QTest::newRow("405 put") << 405 << int(Method::Put) << qint64(-1) << Error::Unsupported;
    QTest::newRow("409") << 409 << int(Method::Put) << qint64(-1) << Error::NotFound;
    QTest::newRow("412") << 412 << int(Method::Move) << qint64(-1) << Error::AlreadyExists;
    QTest::newRow("414") << 414 << int(Method::Get) << qint64(-1) << Error::InvalidName;
    QTest::newRow("415") << 415 << int(Method::Get) << qint64(-1) << Error::Unsupported;
    QTest::newRow("423") << 423 << int(Method::Delete) << qint64(-1) << Error::Locked;
    QTest::newRow("429") << 429 << int(Method::Get) << qint64(5000) << Error::RateLimited;
    QTest::newRow("429 bare") << 429 << int(Method::Get) << qint64(-1) << Error::RateLimited;
    QTest::newRow("503 retry") << 503 << int(Method::Get) << qint64(1000) << Error::RateLimited;
    QTest::newRow("503") << 503 << int(Method::Get) << qint64(-1) << Error::ProtocolError;
    QTest::newRow("500") << 500 << int(Method::Get) << qint64(-1) << Error::ProtocolError;
    QTest::newRow("507") << 507 << int(Method::Put) << qint64(-1) << Error::NoSpace;
    QTest::newRow("418") << 418 << int(Method::Get) << qint64(-1) << Error::ProtocolError;
}

void TestWebDav::httpStatus()
{
    QFETCH(int, status);
    QFETCH(int, method);
    QFETCH(qint64, retryAfter);
    QFETCH(NetVfs::Error, error);
    const Result r = httpResult(status, Method(method), "Reason", retryAfter);
    QCOMPARE(r.error(), error);
    if (error == Error::RateLimited)
        QCOMPARE(r.retryAfterMs(), retryAfter);
    if (error != Error::None) {
        // XC-24: the protocol status for the Details view.
        QVERIFY2(r.detail().contains(QString::number(status)), qPrintable(r.detail()));
        QVERIFY(r.detail().contains(QLatin1String("Reason")));
    }
}

void TestWebDav::curlCodes_data()
{
    QTest::addColumn<int>("code");
    QTest::addColumn<NetVfs::Error>("error");
    QTest::newRow("ok") << int(CURLE_OK) << Error::None;
    QTest::newRow("callback") << int(CURLE_ABORTED_BY_CALLBACK) << Error::Canceled;
    QTest::newRow("timeout") << int(CURLE_OPERATION_TIMEDOUT) << Error::Timeout;
    QTest::newRow("resolve") << int(CURLE_COULDNT_RESOLVE_HOST) << Error::NetworkUnreachable;
    QTest::newRow("connect") << int(CURLE_COULDNT_CONNECT) << Error::NetworkUnreachable;
    QTest::newRow("recv") << int(CURLE_RECV_ERROR) << Error::ConnectionLost;
    QTest::newRow("send") << int(CURLE_SEND_ERROR) << Error::ConnectionLost;
    QTest::newRow("partial") << int(CURLE_PARTIAL_FILE) << Error::ConnectionLost;
    QTest::newRow("nothing") << int(CURLE_GOT_NOTHING) << Error::ConnectionLost;
    QTest::newRow("pin") << int(CURLE_SSL_PINNEDPUBKEYNOTMATCH) << Error::ServerIdentityChanged;
    QTest::newRow("verify") << int(CURLE_PEER_FAILED_VERIFICATION) << Error::ServerIdentityChanged;
    QTest::newRow("protocol") << int(CURLE_UNSUPPORTED_PROTOCOL) << Error::SecurityPolicy;
    QTest::newRow("handshake") << int(CURLE_SSL_CONNECT_ERROR) << Error::ProtocolError;
    QTest::newRow("other") << int(CURLE_BAD_CONTENT_ENCODING) << Error::ProtocolError;
}

void TestWebDav::curlCodes()
{
    QFETCH(int, code);
    QFETCH(NetVfs::Error, error);
    const Result r = curlResult(code, QStringLiteral("curl says"));
    QCOMPARE(r.error(), error);
    if (error != Error::None)
        QCOMPARE(r.detail(), QStringLiteral("curl says"));
}

void TestWebDav::httpDates()
{
    const QDateTime expected(QDate(1994, 11, 6), QTime(8, 49, 37), Qt::UTC);
    QCOMPARE(parseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT"), expected);
    QCOMPARE(parseHttpDate("Sunday, 06-Nov-94 08:49:37 GMT"), expected);
    QCOMPARE(parseHttpDate("Sun Nov  6 08:49:37 1994"), expected);
    QCOMPARE(parseHttpDate("Thu, 01 Jan 2032 00:00:00 GMT"), QDateTime(QDate(2032, 1, 1), QTime(0, 0), Qt::UTC));
    QVERIFY(!parseHttpDate("yesterday").isValid());
    QVERIFY(!parseHttpDate("Sun, 32 Nov 1994 08:49:37 GMT").isValid());
    QVERIFY(!parseHttpDate("").isValid());
}

void TestWebDav::retryAfter()
{
    const QDateTime now(QDate(2026, 1, 1), QTime(12, 0), Qt::UTC);
    QCOMPARE(parseRetryAfter("120", now), qint64(120000));
    QCOMPARE(parseRetryAfter(" 0 ", now), qint64(0));
    QCOMPARE(parseRetryAfter("Thu, 01 Jan 2026 12:00:30 GMT", now), qint64(30000));
    QCOMPARE(parseRetryAfter("Thu, 01 Jan 2026 11:00:00 GMT", now), qint64(0));
    QCOMPARE(parseRetryAfter("soon", now), qint64(-1));
    QCOMPARE(parseRetryAfter("", now), qint64(-1));
    QCOMPARE(parseRetryAfter("-5", now), qint64(-1));
}

void TestWebDav::contentRange()
{
    QCOMPARE(contentRangeStart("bytes 100-199/1000"), qint64(100));
    QCOMPARE(contentRangeStart("bytes 0-0/*"), qint64(0));
    QCOMPARE(contentRangeStart("bytes */1000"), qint64(-1));
    QCOMPARE(contentRangeStart("items 1-2/3"), qint64(-1));
    QCOMPARE(contentRangeStart(""), qint64(-1));
}

// ----------------------------------------------------------- multistatus

void TestWebDav::propfindBody()
{
    const QByteArray generic = WebDav::propfindBody(false);
    for (const char *prop : { "resourcetype", "getcontentlength", "getlastmodified", "creationdate", "getetag",
                              "getcontenttype", "quota-available-bytes", "quota-used-bytes" })
        QVERIFY2(generic.contains(QByteArray("<d:") + prop + "/>"), prop);
    QVERIFY(!generic.contains("oc:permissions"));
    const QByteArray nextcloud = WebDav::propfindBody(true);
    QVERIFY(nextcloud.contains("<oc:permissions/>"));
    QVERIFY(nextcloud.contains("<oc:fileid/>"));
    QVERIFY(nextcloud.contains("<oc:checksums/>"));
    QVERIFY(parseAll(multistatus(QByteArray())).isEmpty());
}

void TestWebDav::multistatusProperties()
{
    const QByteArray body = multistatus(
        "<d:response><d:href>/dav/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype>"
        "<d:quota-available-bytes>1000</d:quota-available-bytes><d:quota-used-bytes>24</d:quota-used-bytes>"
        "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        "<d:response><d:href>/dav/a.txt</d:href><d:propstat><d:prop><d:resourcetype/>"
        "<d:getcontentlength>12</d:getcontentlength>"
        "<d:getlastmodified>Mon, 01 Jan 2024 10:00:00 GMT</d:getlastmodified>"
        "<d:creationdate>2023-12-31T22:00:00+01:00</d:creationdate>"
        "<d:getetag>\"abc\"</d:getetag><d:getcontenttype>text/plain</d:getcontenttype>"
        "<d:ishidden>1</d:ishidden>"
        "<oc:permissions>RGDNVW</oc:permissions><oc:fileid>42</oc:fileid>"
        "<oc:checksums><oc:checksum>SHA1:aabb MD5:ccdd</oc:checksum></oc:checksums>"
        "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        "<d:response><d:href>/dav/gone</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>");
    Result r;
    const QVector<DavResource> resources = parseAll(body, &r);
    QVERIFY(r.ok());
    QCOMPARE(resources.size(), 3);
    QCOMPARE(resources[0].href, QByteArray("/dav/"));
    QVERIFY(resources[0].typeKnown);
    QVERIFY(resources[0].collection);
    QCOMPARE(resources[0].quotaAvailable, qint64(1000));
    QCOMPARE(resources[0].quotaUsed, qint64(24));
    const DavResource &file = resources[1];
    QVERIFY(file.typeKnown);
    QVERIFY(!file.collection);
    QCOMPARE(file.contentLength, qint64(12));
    QCOMPARE(file.modified, QDateTime(QDate(2024, 1, 1), QTime(10, 0), Qt::UTC));
    QCOMPARE(file.created, QDateTime(QDate(2023, 12, 31), QTime(21, 0), Qt::UTC));
    QCOMPARE(file.etag, QByteArray("\"abc\""));
    QCOMPARE(file.contentType, QStringLiteral("text/plain"));
    QVERIFY(file.hidden);
    QVERIFY(file.hasPermissions);
    QCOMPARE(file.permissions, QStringLiteral("RGDNVW"));
    QCOMPARE(file.fileId, QStringLiteral("42"));
    QCOMPARE(file.checksums, QStringLiteral("SHA1:aabb MD5:ccdd"));
    QCOMPARE(resources[2].status, 404);
}

void TestWebDav::multistatusIncremental()
{
    QByteArray inner;
    for (int i = 0; i < 50; ++i)
        inner += fileResponse("/dav/f%C3%A4" + QByteArray::number(i), i);
    const QByteArray body = multistatus(inner);
    const QVector<DavResource> whole = parseAll(body);
    QCOMPARE(whole.size(), 50);
    // Byte by byte, as a slow network would deliver it: same result, and
    // each resource is reported as soon as its element is complete.
    QVector<DavResource> pieces;
    int reportedBeforeEnd = 0;
    MultistatusParser parser([&](const DavResource &r) {
        pieces << r;
        return true;
    });
    for (int i = 0; i < body.size(); ++i) {
        QVERIFY(parser.feed(body.constData() + i, 1));
        if (i == body.size() / 2)
            reportedBeforeEnd = pieces.size();
    }
    QVERIFY(parser.finish().ok());
    QCOMPARE(pieces.size(), whole.size());
    QVERIFY(reportedBeforeEnd > 20);
    for (int i = 0; i < whole.size(); ++i) {
        QCOMPARE(pieces[i].href, whole[i].href);
        QCOMPARE(pieces[i].contentLength, whole[i].contentLength);
    }
}

void TestWebDav::multistatusPropstat404()
{
    const QByteArray body = multistatus(
        "<d:response><d:href>/x</d:href>"
        "<d:propstat><d:prop><d:getcontentlength>5</d:getcontentlength></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
        "<d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>\"e\"</d:getetag></d:prop>"
        "<d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response>");
    const QVector<DavResource> resources = parseAll(body);
    QCOMPARE(resources.size(), 1);
    QCOMPARE(resources[0].contentLength, qint64(5));
    QVERIFY(!resources[0].typeKnown);
    QVERIFY(!resources[0].collection);
    QVERIFY(resources[0].etag.isEmpty());
    const Entry entry = toEntry(resources[0], QStringLiteral("x"), false);
    QCOMPARE(entry.type, EntryType::Unknown);
    QCOMPARE(entry.size, qint64(5));
}

void TestWebDav::multistatusRejectsDoctype()
{
    // XSEC-3: no DTDs, no entity declarations, no undeclared entities.
    Result r;
    parseAll("<?xml version=\"1.0\"?><!DOCTYPE d:multistatus [<!ENTITY x \"y\">]>"
             "<d:multistatus xmlns:d=\"DAV:\"></d:multistatus>", &r);
    QCOMPARE(r.error(), Error::ProtocolError);
    parseAll("<!DOCTYPE html><d:multistatus xmlns:d=\"DAV:\"></d:multistatus>", &r);
    QCOMPARE(r.error(), Error::ProtocolError);
    QVERIFY(r.message().contains(QLatin1String("document type")));
    parseAll(multistatus("<d:response><d:href>&ext;</d:href></d:response>"), &r);
    QCOMPARE(r.error(), Error::ProtocolError);
}

void TestWebDav::multistatusDepthCap()
{
    const auto nested = [](int depth) {
        QByteArray open;
        QByteArray close;
        for (int i = 1; i < depth; ++i) {
            open += "<d:x>";
            close.prepend("</d:x>");
        }
        return "<d:multistatus xmlns:d=\"DAV:\">" + open + close + "</d:multistatus>";
    };
    Result r;
    parseAll(nested(64), &r);
    QVERIFY2(r.ok(), qPrintable(r.toString()));
    parseAll(nested(65), &r);
    QCOMPARE(r.error(), Error::ProtocolError);
    QVERIFY(r.message().contains(QLatin1String("64")));
}

void TestWebDav::multistatusSizeCap()
{
    QCOMPARE(MultistatusParser::DefaultMaxBytes, qint64(64) << 20);
    const QByteArray body = multistatus(fileResponse("/a", 1) + fileResponse("/b", 2));
    MultistatusParser exact([](const DavResource &) { return true; }, body.size());
    QVERIFY(exact.feed(body.constData(), body.size()));
    QVERIFY(exact.finish().ok());
    MultistatusParser small([](const DavResource &) { return true; }, body.size() - 1);
    QVERIFY(small.feed(body.constData(), body.size() - 1));
    QVERIFY(!small.feed(body.constData() + body.size() - 1, 1));
    QCOMPARE(small.result().error(), Error::ProtocolError);
}

void TestWebDav::multistatusMalformed()
{
    Result r;
    parseAll("<html><body>login</body></html>", &r);
    QCOMPARE(r.error(), Error::ProtocolError);
    parseAll("<d:multistatus xmlns:d=\"DAV:\"><d:response>", &r);
    QCOMPARE(r.error(), Error::ProtocolError);
    parseAll("", &r);
    QCOMPARE(r.error(), Error::ProtocolError);
    parseAll("<d:multistatus xmlns:d=\"DAV:\"></d:wrong>", &r);
    QCOMPARE(r.error(), Error::ProtocolError);
    QCOMPARE(parseStatusLine(QStringLiteral(" HTTP/1.1  423 Locked")), 423);
    QCOMPARE(parseStatusLine(QStringLiteral("garbage")), 0);
}

void TestWebDav::multistatusStops()
{
    const QByteArray body = multistatus(fileResponse("/a", 1) + fileResponse("/b", 2) + fileResponse("/c", 3));
    int seen = 0;
    MultistatusParser parser([&](const DavResource &) { return ++seen < 2; });
    QVERIFY(!parser.feed(body.constData(), body.size()));
    QVERIFY(parser.stopped());
    QVERIFY(parser.result().ok());
    QCOMPARE(seen, 2);
}

void TestWebDav::checksums()
{
    const QMap<QString, QByteArray> sums = parseChecksums(QStringLiteral("SHA1:0a0B  MD5:ff ADLER32:zz bad sha256:"));
    QCOMPARE(sums.value(QStringLiteral("sha1")), QByteArray("\x0a\x0b"));
    QCOMPARE(sums.value(QStringLiteral("md5")), QByteArray("\xff"));
    QVERIFY(!sums.contains(QStringLiteral("adler32")));
    QVERIFY(!sums.contains(QStringLiteral("sha256")));
    QCOMPARE(sums.size(), 2);
}

void TestWebDav::entries()
{
    DavResource folder;
    folder.typeKnown = true;
    folder.collection = true;
    folder.contentLength = 4096;
    folder.hasPermissions = true;
    folder.permissions = QStringLiteral("RGDNV");
    folder.fileId = QStringLiteral("7");
    Entry entry = toEntry(folder, QStringLiteral("dir"), true);
    QCOMPARE(entry.type, EntryType::Directory);
    QCOMPARE(entry.size, qint64(-1));
    QVERIFY(entry.flags.testFlag(EntryFlag::ReadOnly));
    QCOMPARE(entry.extra.value(QStringLiteral("oc:fileid")).toString(), QStringLiteral("7"));
    QCOMPARE(entry.extra.value(QStringLiteral("oc:permissions")).toString(), QStringLiteral("RGDNV"));
    folder.permissions = QStringLiteral("RGDNVCK");
    QVERIFY(!toEntry(folder, QStringLiteral("dir"), true).flags.testFlag(EntryFlag::ReadOnly));
    // generic flavor: no oc:* interpretation
    folder.permissions = QStringLiteral("R");
    entry = toEntry(folder, QStringLiteral("dir"), false);
    QVERIFY(!entry.flags.testFlag(EntryFlag::ReadOnly));
    QVERIFY(entry.extra.isEmpty());

    DavResource file;
    file.typeKnown = true;
    file.contentLength = 3;
    file.hidden = true;
    file.hasPermissions = true;
    file.permissions = QStringLiteral("RGDNVW");
    entry = toEntry(file, Names::decode("n\xff"), true);
    QCOMPARE(entry.type, EntryType::File);
    QCOMPARE(entry.size, qint64(3));
    QVERIFY(entry.flags.testFlag(EntryFlag::Hidden));
    QVERIFY(entry.flags.testFlag(EntryFlag::NameNotUtf8));
    QVERIFY(!entry.flags.testFlag(EntryFlag::ReadOnly));
    file.permissions = QStringLiteral("RGDNV");
    QVERIFY(toEntry(file, QStringLiteral("f"), true).flags.testFlag(EntryFlag::ReadOnly));
    QVERIFY(!toEntry(file, QStringLiteral("f"), true).flags.testFlag(EntryFlag::NameNotUtf8));
}

void TestWebDav::spaceFromQuota()
{
    DavResource resource;
    SpaceInfo info;
    QVERIFY(!toSpaceInfo(resource, &info));
    resource.quotaAvailable = 100;
    QVERIFY(toSpaceInfo(resource, &info));
    QCOMPARE(info.free, qint64(100));
    QCOMPARE(info.used, qint64(-1));
    QCOMPARE(info.total, qint64(-1));
    resource.quotaUsed = 50;
    QVERIFY(toSpaceInfo(resource, &info));
    QCOMPARE(info.total, qint64(150));
    QCOMPARE(info.used, qint64(50));
    // Nextcloud reports -3 for "unlimited": unknown
    const QVector<DavResource> parsed = parseAll(multistatus(
        "<d:response><d:href>/</d:href><d:propstat><d:prop><d:quota-available-bytes>-3</d:quota-available-bytes>"
        "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"));
    QCOMPARE(parsed.value(0).quotaAvailable, qint64(-1));
}

// ------------------------------------------------------------- options

void TestWebDav::configOptions()
{
    ConnectionParams params;
    params.host = QStringLiteral("Cloud.Example");
    Config config;
    QVERIFY(parseConfig(params, &config).ok());
    QCOMPARE(config.baseUrl(), QByteArray("https://cloud.example/"));
    QCOMPARE(config.flavor, Flavor::Auto);
    QVERIFY(!config.tokenAuth);

    params.port = 8443;
    params.options.insert(QStringLiteral("base_path"), QStringLiteral("remote.php/dav/files/bob"));
    params.options.insert(QStringLiteral("auth_mode"), QStringLiteral("token"));
    params.options.insert(QStringLiteral("flavor"), QStringLiteral("nextcloud"));
    params.options.insert(QStringLiteral("host_key"), QStringLiteral(" tls-spki-sha256 AAAA "));
    params.options.insert(QStringLiteral("tls_verify_peer"), QStringLiteral("true"));
    QVERIFY(parseConfig(params, &config).ok());
    QCOMPARE(config.baseUrl(), QByteArray("https://cloud.example:8443/remote.php/dav/files/bob/"));
    QVERIFY(config.tokenAuth);
    QCOMPARE(config.flavor, Flavor::Nextcloud);
    QCOMPARE(config.pin, QStringLiteral("tls-spki-sha256 AAAA"));
    QVERIFY(config.pinVerifyPeer);

    // W-2: plain HTTP only with consent
    params.options.insert(QStringLiteral("tls"), QStringLiteral("http"));
    QCOMPARE(parseConfig(params, &config).error(), Error::SecurityPolicy);
    params.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
    QVERIFY(parseConfig(params, &config).ok());
    QCOMPARE(config.origin.scheme, QByteArray("http"));
    params.port = 0;
    QVERIFY(parseConfig(params, &config).ok());
    QCOMPARE(config.origin.port, 80);

    params.options.insert(QStringLiteral("tls"), QStringLiteral("starttls"));
    QCOMPARE(parseConfig(params, &config).error(), Error::Internal);
    params.options.remove(QStringLiteral("tls"));
    params.options.insert(QStringLiteral("auth_mode"), QStringLiteral("ntlm"));
    QCOMPARE(parseConfig(params, &config).error(), Error::Internal);
    params.options.remove(QStringLiteral("auth_mode"));
    params.options.insert(QStringLiteral("flavor"), QStringLiteral("owncloud"));
    QCOMPARE(parseConfig(params, &config).error(), Error::Internal);
    params.options.remove(QStringLiteral("flavor"));
    params.host = QStringLiteral("bad/host");
    QCOMPARE(parseConfig(params, &config).error(), Error::NetworkUnreachable);
}

void TestWebDav::featureDetection()
{
    QMap<QByteArray, QByteArray> headers;
    headers.insert("dav", "1, 2, 3, sabredav-partialupdate, extended-mkcol");
    ServerFeatures features = detectFeatures(headers, "/dav/");
    QCOMPARE(features.davClasses, QStringList({ "1", "2", "3", "sabredav-partialupdate", "extended-mkcol" }));
    QVERIFY(features.partialUpdate);
    QVERIFY(!features.nextcloudHints);

    headers.insert("dav", "1, 3, nextcloud-checksum-update, nc-calendar-search");
    features = detectFeatures(headers, "/dav/");
    QVERIFY(features.nextcloudHints);
    QVERIFY(!features.partialUpdate);

    headers.insert("dav", "1, 2");
    QVERIFY(!detectFeatures(headers, "/webdav/").nextcloudHints);
    QVERIFY(detectFeatures(headers, "/remote.php/dav/files/x/").nextcloudHints);
    headers.insert("set-cookie", "ocabc123def4=xyz; path=/; secure");
    QVERIFY(detectFeatures(headers, "/").nextcloudHints);
    headers.insert("set-cookie", "nc_sameSiteCookielax=true; path=/");
    QVERIFY(detectFeatures(headers, "/").nextcloudHints);
    headers.insert("set-cookie", "session=1, rocket=2");
    QVERIFY(!detectFeatures(headers, "/").nextcloudHints);
}

// ---------------------------------------------------------- certificates

void TestWebDav::certificateSelfSigned()
{
    const TestCertificate cert = makeCertificate(CertificateOptions());
    ServerIdentity identity = identityFromChain({ cert.certificatePem }, "localhost", ChainCheck::Failed, TrustStore());
    QCOMPARE(identity.kind, ServerIdentity::Kind::TlsCertificate);
    QCOMPARE(identity.algorithm, QStringLiteral("tls-spki-sha256"));
    QCOMPARE(identity.publicKey, cert.spkiDer);
    QVERIFY(!identity.systemTrusted);
    QCOMPARE(identity.problems, int(ServerIdentity::SelfSigned));

    identity = identityFromChain({ cert.certificatePem }, "other.example", ChainCheck::NotChecked, TrustStore());
    QCOMPARE(identity.problems, int(ServerIdentity::SelfSigned | ServerIdentity::HostnameMismatch));
    identity = identityFromChain({ cert.certificatePem }, "127.0.0.1", ChainCheck::NotChecked, TrustStore());
    QCOMPARE(identity.problems, int(ServerIdentity::SelfSigned));
    identity = identityFromChain({ cert.certificatePem }, "127.0.0.2", ChainCheck::NotChecked, TrustStore());
    QVERIFY(identity.problems & ServerIdentity::HostnameMismatch);
    QVERIFY(identityFromChain({ "garbage" }, "localhost", ChainCheck::Failed, TrustStore()).isEmpty());
    QVERIFY(identityFromChain({}, "localhost", ChainCheck::Failed, TrustStore()).isEmpty());
}

void TestWebDav::certificateFromAuthority()
{
    CertificateOptions caOptions;
    caOptions.commonName = "netvfs test CA";
    caOptions.subjectAltNames.clear();
    caOptions.authority = true;
    const TestCertificate ca = makeCertificate(caOptions);
    CertificateOptions leafOptions;
    leafOptions.issuer = &ca;
    const TestCertificate leaf = makeCertificate(leafOptions);
    QTemporaryFile caFile;
    QVERIFY(caFile.open());
    caFile.write(ca.certificatePem);
    caFile.flush();
    TrustStore store;
    store.caFile = caFile.fileName().toLocal8Bit();

    ServerIdentity identity = identityFromChain({ leaf.certificatePem, ca.certificatePem }, "localhost",
                                                ChainCheck::NotChecked, store);
    QCOMPARE(identity.problems, 0);
    QVERIFY(identity.systemTrusted);
    // Without the CA in the store: untrusted root, not self-signed.
    QTemporaryFile empty;
    QVERIFY(empty.open());
    empty.write(makeCertificate(caOptions).certificatePem);
    empty.flush();
    store.caFile = empty.fileName().toLocal8Bit();
    identity = identityFromChain({ leaf.certificatePem }, "localhost", ChainCheck::NotChecked, store);
    QCOMPARE(identity.problems, int(ServerIdentity::UntrustedRoot));
    QVERIFY(!identity.systemTrusted);
    // libcurl failed although our store agrees: still not trusted.
    store.caFile = caFile.fileName().toLocal8Bit();
    identity = identityFromChain({ leaf.certificatePem }, "localhost", ChainCheck::Failed, store);
    QCOMPARE(identity.problems, int(ServerIdentity::UntrustedRoot));
    QVERIFY(!identity.systemTrusted);
    // Verified by libcurl: trusted without further checks.
    identity = identityFromChain({ leaf.certificatePem }, "localhost", ChainCheck::Verified, TrustStore());
    QVERIFY(identity.systemTrusted);
    QCOMPARE(identity.problems, 0);
}

void TestWebDav::certificateValidity()
{
    CertificateOptions options;
    options.notBeforeDays = -30;
    options.notAfterDays = -1;
    const TestCertificate expired = makeCertificate(options);
    ServerIdentity identity = identityFromChain({ expired.certificatePem }, "localhost", ChainCheck::NotChecked, TrustStore());
    QVERIFY(identity.problems & ServerIdentity::Expired);
    QVERIFY(!(identity.problems & ServerIdentity::NotYetValid));
    options.notBeforeDays = 2;
    options.notAfterDays = 30;
    const TestCertificate future = makeCertificate(options);
    identity = identityFromChain({ future.certificatePem }, "localhost", ChainCheck::NotChecked, TrustStore());
    QVERIFY(identity.problems & ServerIdentity::NotYetValid);
    QVERIFY(!(identity.problems & ServerIdentity::Expired));
    // ... and fine at a time inside its validity
    identity = identityFromChain({ future.certificatePem }, "localhost", ChainCheck::NotChecked, TrustStore(),
                                 QDateTime::currentDateTimeUtc().addDays(10));
    QVERIFY(!(identity.problems & (ServerIdentity::NotYetValid | ServerIdentity::Expired)));
}

void TestWebDav::certificateDetails()
{
    CertificateOptions options;
    options.commonName = "dav.example";
    options.subjectAltNames = "DNS:dav.example,DNS:*.dav.example,IP:10.0.0.1,IP:::1";
    const TestCertificate cert = makeCertificate(options);
    const ServerIdentity identity = identityFromChain({ cert.certificatePem }, "x.dav.example", ChainCheck::NotChecked,
                                                      TrustStore());
    QVERIFY(!(identity.problems & ServerIdentity::HostnameMismatch));
    QCOMPARE(identity.fingerprint,
             QString::fromLatin1(QCryptographicHash::hash(cert.spkiDer, QCryptographicHash::Sha256).toBase64()));
    QCOMPARE(identity.toPin(), QStringLiteral("tls-spki-sha256 ") + QString::fromLatin1(cert.spkiDer.toBase64()));
    QCOMPARE(identity.details.value(QStringLiteral("subject")).toString(), QStringLiteral("CN=dav.example,O=netvfs tests"));
    QCOMPARE(identity.details.value(QStringLiteral("issuer")).toString(), QStringLiteral("CN=dav.example,O=netvfs tests"));
    QCOMPARE(identity.details.value(QStringLiteral("sans")).toStringList(),
             QStringList({ "DNS:dav.example", "DNS:*.dav.example", "IP:10.0.0.1", "IP:0:0:0:0:0:0:0:1" }));
    const QDateTime notAfter = identity.details.value(QStringLiteral("notAfter")).toDateTime();
    QVERIFY(qAbs(notAfter.secsTo(QDateTime::currentDateTimeUtc().addDays(30))) < 3600);
    QVERIFY(identity.details.value(QStringLiteral("notBefore")).toDateTime() < QDateTime::currentDateTimeUtc());
    QCOMPARE(identity.details.value(QStringLiteral("certSha256")).toString().size(), 64);
}

// ------------------------------------------------------- backend (HTTP)

void TestWebDav::connectSendsNoCredentials()
{
    Fixture f;
    ServerIdentity seen;
    QVERIFY(f.backend.connect(f.params, &seen).ok());
    QVERIFY(seen.isEmpty());
    QVector<HttpRequestRecord> requests = f.server.requests();
    QCOMPARE(requests.size(), 1);
    QCOMPARE(requests[0].method, QByteArray("OPTIONS"));
    QCOMPARE(requests[0].target, QByteArray("/dav/"));
    // C-7, XSEC-1: nothing secret before the identity check
    QVERIFY(requests[0].header("authorization").isEmpty());
    QVERIFY(requests[0].header("cookie").isEmpty());
    // Nothing works before authenticate().
    Entry entry;
    QCOMPARE(f.backend.stat(QStringLiteral("x"), &entry).error(), Error::Internal);
    QVERIFY(f.backend.capabilities().flags.isEmpty());
}

void TestWebDav::plainHttpNeedsConsent()
{
    Fixture f;
    f.params.options.remove(QStringLiteral("allow_insecure"));
    ServerIdentity seen;
    QCOMPARE(f.backend.connect(f.params, &seen).error(), Error::SecurityPolicy);
    QCOMPARE(f.server.connections(), 0);
    QCOMPARE(f.backend.authenticate(Credentials(QStringLiteral("alice"), "secret")).error(), Error::Internal);
    QCOMPARE(f.server.connections(), 0);
}

void TestWebDav::authenticateWithBasic()
{
    Fixture f;
    QVERIFY(f.signIn().ok());
    const QVector<HttpRequestRecord> requests = f.server.requests();
    // OPTIONS, PROPFIND without credentials -> 401, PROPFIND with Basic
    QCOMPARE(requests.size(), 3);
    QCOMPARE(requests[1].method, QByteArray("PROPFIND"));
    QCOMPARE(requests[1].header("depth"), QByteArray("0"));
    QCOMPARE(requests[2].header("authorization"), Credential);
    QCOMPARE(requests[2].target, QByteArray("/dav/"));
    // Later requests authenticate right away.
    f.server.clearRequests();
    Entry entry;
    f.dav.addFile("/a", "x");
    QVERIFY(f.backend.stat(QStringLiteral("a"), &entry).ok());
    QCOMPARE(f.server.requests().size(), 1);
    QCOMPARE(f.server.requests()[0].header("authorization"), Credential);
}

void TestWebDav::authenticateFailures_data()
{
    QTest::addColumn<int>("status");
    QTest::addColumn<NetVfs::Error>("error");
    QTest::newRow("401") << 401 << Error::AuthFailed;
    QTest::newRow("403") << 403 << Error::AuthFailed;
    QTest::newRow("404") << 404 << Error::NotFound;
    QTest::newRow("500") << 500 << Error::ProtocolError;
}

void TestWebDav::authenticateFailures()
{
    QFETCH(int, status);
    QFETCH(NetVfs::Error, error);
    Fixture f;
    f.server.setHandler([status](const HttpRequestRecord &r) {
        if (r.method == "OPTIONS")
            return HttpReply::make(200);
        return HttpReply::make(status);
    });
    const Result r = f.signIn();
    QCOMPARE(r.error(), error);
    if (status == 404)
        QVERIFY(r.message().contains(QLatin1String("base path")));
}

void TestWebDav::neverNtlm()
{
    // W-5: a server that offers only NTLM or Negotiate gets no credentials.
    for (const QByteArray &scheme : { QByteArray("NTLM"), QByteArray("Negotiate") }) {
        Fixture f;
        f.server.setHandler([scheme](const HttpRequestRecord &r) {
            if (r.method == "OPTIONS")
                return HttpReply::make(200);
            return HttpReply::make(401).with("WWW-Authenticate", scheme);
        });
        QCOMPARE(f.signIn().error(), Error::AuthFailed);
        for (const HttpRequestRecord &r : f.server.requests())
            QVERIFY2(r.header("authorization").isEmpty(), r.header("authorization").constData());
    }
}

void TestWebDav::bearerToken()
{
    Fixture f;
    f.dav.authorization = "Bearer t0ken";
    f.params.options.insert(QStringLiteral("auth_mode"), QStringLiteral("token"));
    QVERIFY(establish(&f.backend, f.params, Credentials(QString(), "t0ken")).ok());
    Entry entry;
    QVERIFY(f.backend.stat(QString(), &entry).ok());
    QVERIFY(entry.isDir());
}

void TestWebDav::capabilitiesFromServer()
{
    Fixture f;
    f.dav.davHeader = "1, 2, sabredav-partialupdate";
    f.dav.quotaAvailable = 1000;
    QVERIFY(f.signIn().ok());
    Capabilities caps = f.backend.capabilities();
    for (const Capability c : { Capability::ReadHandles, Capability::AtomicPut, Capability::AtomicReplace,
                                Capability::NativeNoReplace, Capability::ServerCopy, Capability::ServerCopyRecursive,
                                Capability::RecursiveDelete, Capability::SpaceInfo, Capability::WriteResume,
                                Capability::ETags })
        QVERIFY2(caps.has(c), qPrintable(capabilityName(c)));
    QVERIFY(!caps.has(Capability::EfficientRanges));    // not before a 206 (W-9)
    QVERIFY(!caps.has(Capability::SetModifiedOnUpload));
    QVERIFY(!caps.has(Capability::Checksums));
    QVERIFY(!caps.has(Capability::Symlinks));

    Fixture g;
    g.dav.davHeader = "1, 3, nextcloud-checksum-update";
    QVERIFY(g.signIn().ok());
    caps = g.backend.capabilities();
    QVERIFY(caps.has(Capability::SetModifiedOnUpload));
    QVERIFY(caps.has(Capability::Checksums));
    QCOMPARE(caps.checksumAlgorithms, QStringList({ "sha1", "md5", "adler32" }));
    QVERIFY(!caps.has(Capability::SpaceInfo));
    QVERIFY(!caps.has(Capability::WriteResume));

    // flavor=generic overrides the detection
    Fixture h;
    h.dav.davHeader = "1, 3, nextcloud-checksum-update";
    h.params.options.insert(QStringLiteral("flavor"), QStringLiteral("generic"));
    QVERIFY(h.signIn().ok());
    QVERIFY(!h.backend.capabilities().has(Capability::Checksums));
}

void TestWebDav::listInBatches()
{
    Fixture f;
    f.dav.addFolder("/d");
    for (int i = 0; i < 5; ++i)
        f.dav.addFile("/d/f" + QByteArray::number(i), QByteArray(i, 'x'));
    f.dav.addFolder("/d/sub");
    f.dav.addFile("/d/sub/deep", "x");
    QVERIFY(f.signIn().ok());
    f.server.clearRequests();
    RecordingSink sink;
    ListOptions options;
    options.batchSize = 2;
    QVERIFY(f.backend.list(QStringLiteral("d"), &sink, options).ok());
    QCOMPARE(sink.batches, QVector<int>({ 2, 2, 2 }));
    QStringList names;
    for (const Entry &e : sink.all)
        names << e.name;
    names.sort();
    QCOMPARE(names, QStringList({ "f0", "f1", "f2", "f3", "f4", "sub" }));
    for (const Entry &e : sink.all) {
        if (e.name == QLatin1String("sub")) {
            QCOMPARE(e.type, EntryType::Directory);
        } else {
            QCOMPARE(e.type, EntryType::File);
            QCOMPARE(e.size, qint64(e.name.mid(1).toInt()));
            QCOMPARE(e.modified, QDateTime(QDate(2024, 1, 1), QTime(10, 0), Qt::UTC));
            QVERIFY(!e.etag.isEmpty());
            QVERIFY(!e.created.isValid());      // 404 propstat
        }
    }
    const QVector<HttpRequestRecord> requests = f.server.requests();
    QCOMPARE(requests.size(), 1);
    QCOMPARE(requests[0].method, QByteArray("PROPFIND"));
    QCOMPARE(requests[0].header("depth"), QByteArray("1"));
    QCOMPARE(requests[0].target, QByteArray("/dav/d/"));

    // A sink that stops ends the listing with Canceled.
    RecordingSink stopper;
    stopper.stopAfter = 1;
    QCOMPARE(f.backend.list(QStringLiteral("d"), &stopper, options).error(), Error::Canceled);
    QCOMPARE(stopper.batches.size(), 1);
    // The v1 helper still collects everything.
    QVector<Entry> all;
    QVERIFY(f.backend.list(QStringLiteral("d"), &all).ok());
    QCOMPARE(all.size(), 6);
}

void TestWebDav::listStreamsWhileReceiving()
{
    // XC-6: batches arrive while the response is still streaming: the
    // server sends two members and then stalls; the sink sees them anyway.
    Fixture f;
    QVERIFY(f.signIn().ok());
    f.server.setHandler([](const HttpRequestRecord &) {
        HttpReply reply = HttpReply::make(207, multistatus(folderResponse("/dav/d/") + fileResponse("/dav/d/a", 1)
                                                           + fileResponse("/dav/d/b", 2) + fileResponse("/dav/d/c", 3)));
        reply.body.replace("</d:multistatus>", "");
        reply.stallAfterBody = true;
        return reply;
    });
    RecordingSink sink;
    sink.stopAfter = 1;
    ListOptions options;
    options.batchSize = 2;
    QElapsedTimer timer;
    timer.start();
    QCOMPARE(f.backend.list(QStringLiteral("d"), &sink, options).error(), Error::Canceled);
    QVERIFY(timer.elapsed() < 5000);
    QCOMPARE(sink.batches, QVector<int>({ 2 }));
}

void TestWebDav::listNamesAndOrigins()
{
    Fixture f;
    QVERIFY(f.signIn().ok());
    const QByteArray origin = f.server.origin();
    f.server.setHandler([origin](const HttpRequestRecord &) {
        return HttpReply::make(
            207, multistatus(folderResponse(origin + "/dav/d%20x")      // the folder itself, absolute
                             + fileResponse("/dav/d%20x/a%20b", 1)
                             + fileResponse("/dav/d%20x/%FF", 2)        // not UTF-8
                             + fileResponse(origin + "/dav/d%20x/abs", 3)
                             + fileResponse("https://evil.example/dav/d%20x/foreign", 4)
                             + fileResponse("/dav/d%20x/deep/er", 5)
                             + fileResponse("/dav/d%20x/sl%2Fash", 6)
                             + "<d:response><d:href>/dav/d%20x/gone</d:href><d:status>HTTP/1.1 404 Not Found"
                               "</d:status></d:response>"));
    });
    QVector<Entry> entries;
    QVERIFY(f.backend.list(QStringLiteral("d x"), &entries).ok());
    QStringList names;
    for (const Entry &e : entries)
        names << e.name;
    QCOMPARE(names, QStringList({ "a b", Names::decode("\xff"), "abs" }));
    QVERIFY(entries[1].flags.testFlag(EntryFlag::NameNotUtf8));
    QVERIFY(!entries[0].flags.testFlag(EntryFlag::NameNotUtf8));
    QCOMPARE(Names::encode(entries[1].name), QByteArray("\xff"));
}

void TestWebDav::listNotAFolder()
{
    Fixture f;
    f.dav.addFile("/file", "abc");
    QVERIFY(f.signIn().ok());
    QVector<Entry> entries;
    QCOMPARE(f.backend.list(QStringLiteral("file"), &entries).error(), Error::NotADirectory);
    QCOMPARE(f.backend.list(QStringLiteral("missing"), &entries).error(), Error::NotFound);
    // A server that answers with the file itself
    f.server.setHandler([](const HttpRequestRecord &) {
        return HttpReply::make(207, multistatus(fileResponse("/dav/file", 3)));
    });
    QCOMPARE(f.backend.list(QStringLiteral("file"), &entries).error(), Error::NotADirectory);
}

void TestWebDav::listRejectsDoctype()
{
    Fixture f;
    QVERIFY(f.signIn().ok());
    f.server.setHandler([](const HttpRequestRecord &) {
        return HttpReply::make(207, "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\">]>"
                                    "<d:multistatus xmlns:d=\"DAV:\"></d:multistatus>");
    });
    QVector<Entry> entries;
    QCOMPARE(f.backend.list(QString(), &entries).error(), Error::ProtocolError);
    Entry entry;
    QCOMPARE(f.backend.stat(QString(), &entry).error(), Error::ProtocolError);
    // A 200 with HTML (a login page) is not a listing either.
    f.server.setHandler([](const HttpRequestRecord &) { return HttpReply::make(200, "<html></html>"); });
    QCOMPARE(f.backend.list(QString(), &entries).error(), Error::ProtocolError);
}

void TestWebDav::redirectsSameOrigin()
{
    Fixture f;
    f.dav.addFile("/new/a", "data");
    f.dav.addFolder("/new");
    QVERIFY(f.signIn().ok());
    f.server.setHandler([&f](const HttpRequestRecord &r) {
        if (r.target.startsWith("/dav/old"))
            return HttpReply::make(301).with("Location", "/dav/new" + r.target.mid(8));
        return f.dav.handle(r);
    });
    f.server.clearRequests();
    QVector<Entry> entries;
    QVERIFY(f.backend.list(QStringLiteral("old"), &entries).ok());
    QCOMPARE(entries.size(), 1);
    QCOMPARE(entries[0].name, QStringLiteral("a"));
    const QVector<HttpRequestRecord> requests = f.server.requests();
    QCOMPARE(requests.size(), 2);
    QCOMPARE(requests[1].method, QByteArray("PROPFIND"));     // the method is kept
    QCOMPARE(requests[1].target, QByteArray("/dav/new/"));
    QCOMPARE(requests[1].body, requests[0].body);
    QCOMPARE(requests[1].header("authorization"), Credential);
}

void TestWebDav::redirectLimit()
{
    Fixture f;
    QVERIFY(f.signIn().ok());
    f.server.setHandler([](const HttpRequestRecord &r) {
        const int hop = r.target.mid(r.target.lastIndexOf('/') + 2).toInt();
        return HttpReply::make(302).with("Location", "/dav/r" + QByteArray::number(hop + 1));
    });
    f.server.clearRequests();
    Entry entry;
    const Result r = f.backend.stat(QStringLiteral("r0"), &entry);
    QCOMPARE(r.error(), Error::ProtocolError);
    QCOMPARE(f.server.requests().size(), 4);    // W-6: three redirects followed
    // Three are fine.
    f.server.setHandler([&f](const HttpRequestRecord &r) {
        const int hop = r.target.mid(r.target.lastIndexOf('/') + 2).toInt();
        if (hop < 3)
            return HttpReply::make(307).with("Location", "/dav/r" + QByteArray::number(hop + 1));
        return f.dav.handle(r);
    });
    f.dav.addFile("/r3", "x");
    QVERIFY(f.backend.stat(QStringLiteral("r0"), &entry).ok());
}

void TestWebDav::redirectCrossOrigin()
{
    Fixture f;
    HttpTestServer other;
    other.setHandler([](const HttpRequestRecord &) { return HttpReply::make(207, multistatus(QByteArray())); });
    QVERIFY(f.signIn().ok());
    const QByteArray target = other.origin() + "/dav/x";
    f.server.setHandler([target](const HttpRequestRecord &) { return HttpReply::make(301).with("Location", target); });
    Entry entry;
    const Result r = f.backend.stat(QStringLiteral("x"), &entry);
    QCOMPARE(r.error(), Error::ProtocolError);
    QVERIFY2(r.message().contains(QString::fromLatin1(target)), qPrintable(r.message()));
    // W-6: credentials never go to another origin; nothing goes there at all.
    QCOMPARE(other.connections(), 0);
    // Same host, other port is another origin too; so is a scheme change.
    f.server.setHandler([](const HttpRequestRecord &) {
        return HttpReply::make(301).with("Location", "https://127.0.0.1/dav/x");
    });
    QCOMPARE(f.backend.stat(QStringLiteral("x"), &entry).error(), Error::ProtocolError);
}

void TestWebDav::renameModes()
{
    Fixture f;
    f.dav.addFile("/a", "1");
    f.dav.addFile("/b", "2");
    f.dav.addFolder("/dir");
    QVERIFY(f.signIn().ok());
    f.server.clearRequests();
    // NoReplace: Overwrite F, the server refuses with 412.
    QCOMPARE(f.backend.rename(QStringLiteral("a"), QStringLiteral("b"), RenameMode::NoReplace).error(),
             Error::AlreadyExists);
    HttpRequestRecord move = f.server.requests().last();
    QCOMPARE(move.method, QByteArray("MOVE"));
    QCOMPARE(move.header("overwrite"), QByteArray("F"));
    QCOMPARE(move.header("destination"), f.server.origin() + "/dav/b");
    QCOMPARE(f.dav.node("/b").data, QByteArray("2"));
    // Replace: Overwrite T
    QVERIFY(f.backend.rename(QStringLiteral("a"), QStringLiteral("b"), RenameMode::Replace).ok());
    move = f.server.requests().last();
    QCOMPARE(move.header("overwrite"), QByteArray("T"));
    QCOMPARE(f.dav.node("/b").data, QByteArray("1"));
    QVERIFY(!f.dav.exists("/a"));
    // XC-10: a folder is never replaced, and no MOVE is sent.
    f.server.clearRequests();
    QCOMPARE(f.backend.rename(QStringLiteral("b"), QStringLiteral("dir"), RenameMode::Replace).error(),
             Error::AlreadyExists);
    for (const HttpRequestRecord &r : f.server.requests())
        QVERIFY(r.method != "MOVE");
    QVERIFY(f.dav.exists("/b"));
    // Names are encoded in the Destination header.
    QVERIFY(f.backend.rename(QStringLiteral("b"), QStringLiteral("dir/n ä"), RenameMode::NoReplace).ok());
    QCOMPARE(f.server.requests().last().header("destination"), f.server.origin() + "/dav/dir/n%20%C3%A4");
    QCOMPARE(f.backend.rename(QStringLiteral("nothing"), QStringLiteral("x"), RenameMode::NoReplace).error(),
             Error::NotFound);
    QCOMPARE(f.backend.rename(QStringLiteral("dir"), QStringLiteral("no/parent"), RenameMode::NoReplace).error(),
             Error::NotFound);
}

void TestWebDav::copyDepth()
{
    Fixture f;
    f.dav.addFolder("/d");
    f.dav.addFile("/d/x", "1");
    f.dav.addFile("/f", "2");
    QVERIFY(f.signIn().ok());
    QVERIFY(f.backend.copy(QStringLiteral("f"), QStringLiteral("g"), CopyOptions()).ok());
    QCOMPARE(f.server.requests().last().header("depth"), QByteArray("0"));
    QCOMPARE(f.server.requests().last().header("overwrite"), QByteArray("F"));
    QCOMPARE(f.dav.node("/g").data, QByteArray("2"));
    CopyOptions recursive;
    recursive.recursive = true;
    QVERIFY(f.backend.copy(QStringLiteral("d"), QStringLiteral("e"), recursive).ok());
    QCOMPARE(f.server.requests().last().header("depth"), QByteArray("infinity"));
    QVERIFY(f.dav.exists("/e/x"));
    QVERIFY(f.backend.copy(QStringLiteral("d"), QStringLiteral("shallow"), CopyOptions()).ok());
    QCOMPARE(f.server.requests().last().header("depth"), QByteArray("0"));
    QVERIFY(f.dav.exists("/shallow"));
    QVERIFY(!f.dav.exists("/shallow/x"));
    QCOMPARE(f.backend.copy(QStringLiteral("f"), QStringLiteral("g"), CopyOptions()).error(), Error::AlreadyExists);
    CopyOptions replace;
    replace.mode = RenameMode::Replace;
    QVERIFY(f.backend.copy(QStringLiteral("f"), QStringLiteral("g"), replace).ok());
    QCOMPARE(f.server.requests().last().header("overwrite"), QByteArray("T"));
    QCOMPARE(f.backend.copy(QStringLiteral("f"), QStringLiteral("d"), replace).error(), Error::AlreadyExists);
}

void TestWebDav::makeDirCases()
{
    Fixture f;
    f.dav.addFile("/file", "x");
    QVERIFY(f.signIn().ok());
    QVERIFY(f.backend.makeDir(QStringLiteral("n"), true).ok());
    QCOMPARE(f.server.requests().last().method, QByteArray("MKCOL"));
    QCOMPARE(f.server.requests().last().target, QByteArray("/dav/n/"));
    QVERIFY(f.dav.node("/n").collection);
    QCOMPARE(f.backend.makeDir(QStringLiteral("n"), true).error(), Error::AlreadyExists);
    QVERIFY(f.backend.makeDir(QStringLiteral("n"), false).ok());
    QCOMPARE(f.backend.makeDir(QStringLiteral("file"), false).error(), Error::AlreadyExists);
    QCOMPARE(f.backend.makeDir(QStringLiteral("no/parent"), false).error(), Error::NotFound);
    QVERIFY(f.backend.makeDir(QStringLiteral("/"), false).ok());
    QCOMPARE(f.backend.makeDir(QString(), true).error(), Error::AlreadyExists);
    QVERIFY(f.backend.makePath(QStringLiteral("p/q/r")).ok());
    QVERIFY(f.dav.node("/p/q/r").collection);
}

void TestWebDav::removeCases()
{
    Fixture f;
    f.dav.addFolder("/full");
    f.dav.addFile("/full/x", "1");
    f.dav.addFolder("/empty");
    f.dav.addFile("/file", "1");
    QVERIFY(f.signIn().ok());
    f.server.clearRequests();
    QCOMPARE(f.backend.removeFile(QStringLiteral("full")).error(), Error::IsADirectory);
    QCOMPARE(f.backend.removeDir(QStringLiteral("full")).error(), Error::DirectoryNotEmpty);
    QCOMPARE(f.backend.removeDir(QStringLiteral("file")).error(), Error::NotADirectory);
    for (const HttpRequestRecord &r : f.server.requests())
        QVERIFY(r.method != "DELETE");
    QVERIFY(f.dav.exists("/full/x"));
    QVERIFY(f.backend.removeDir(QStringLiteral("empty")).ok());
    QCOMPARE(f.server.requests().last().method, QByteArray("DELETE"));
    QCOMPARE(f.server.requests().last().target, QByteArray("/dav/empty/"));
    QVERIFY(f.backend.removeFile(QStringLiteral("file")).ok());
    QCOMPARE(f.server.requests().last().target, QByteArray("/dav/file"));
    QCOMPARE(f.backend.removeFile(QStringLiteral("file")).error(), Error::NotFound);
    QVERIFY(f.backend.removeTreeNative(QStringLiteral("full")).ok());
    QVERIFY(!f.dav.exists("/full/x"));
    QVERIFY(f.backend.remove(QStringLiteral("nothing")).error() == Error::NotFound);

    // A 207 to DELETE names the member that could not be removed.
    f.dav.addFolder("/locked");
    f.server.setHandler([&f](const HttpRequestRecord &r) {
        if (r.method == "DELETE") {
            return HttpReply::make(207, multistatus("<d:response><d:href>/dav/locked/x</d:href>"
                                                    "<d:status>HTTP/1.1 423 Locked</d:status></d:response>"));
        }
        return f.dav.handle(r);
    });
    QCOMPARE(f.backend.removeTreeNative(QStringLiteral("locked")).error(), Error::Locked);
}

void TestWebDav::serverQuirks()
{
    // rclone: MKCOL on an existing folder is 201, If-None-Match is ignored,
    // MOVE of a missing source is 403.
    Fixture f;
    f.dav.addFolder("/dir");
    f.dav.addFile("/file", "keep");
    QVERIFY(f.signIn().ok());
    f.server.setHandler([&f](const HttpRequestRecord &r) {
        if (r.method == "MKCOL")
            return HttpReply::make(201);
        if (r.method == "MOVE" && !f.dav.exists("/missing") && r.target.endsWith("/missing"))
            return HttpReply::make(403);
        HttpRequestRecord plain = r;
        plain.headers.remove("if-none-match");
        return f.dav.handle(plain);
    });
    f.server.setExpectHandler(HttpTestServer::Handler());
    QCOMPARE(f.backend.makeDir(QStringLiteral("dir"), true).error(), Error::AlreadyExists);
    QVERIFY(f.backend.makeDir(QStringLiteral("dir"), false).ok());
    QByteArray data("new");
    QBuffer source(&data);
    source.open(QIODevice::ReadOnly);
    QCOMPARE(f.backend.upload(&source, QStringLiteral("file"), UploadOptions(), nullptr).error(), Error::AlreadyExists);
    WriteHandle *raw = nullptr;
    QCOMPARE(f.backend.openWrite(QStringLiteral("file"), WriteOptions(), &raw).error(), Error::AlreadyExists);
    QCOMPARE(f.dav.node("/file").data, QByteArray("keep"));
    QCOMPARE(f.backend.rename(QStringLiteral("missing"), QStringLiteral("x"), RenameMode::NoReplace).error(),
             Error::NotFound);
    // A real 403 stays PermissionDenied.
    f.server.setHandler([](const HttpRequestRecord &r) {
        if (r.method == "PROPFIND")
            return HttpReply::make(207, multistatus(fileResponse("/dav/file", 4)));
        return HttpReply::make(403);
    });
    QCOMPARE(f.backend.rename(QStringLiteral("file"), QStringLiteral("x"), RenameMode::NoReplace).error(),
             Error::PermissionDenied);
}

void TestWebDav::uploadHeaders()
{
    Fixture f;
    f.dav.davHeader = "1, 3, nextcloud-checksum-update";
    QVERIFY(f.signIn().ok());
    QByteArray data(100000, 'u');
    QBuffer source(&data);
    source.open(QIODevice::ReadOnly);
    UploadOptions options;
    options.write.modified = QDateTime(QDate(2020, 5, 6), QTime(7, 8, 9), Qt::UTC);
    QVERIFY(f.backend.upload(&source, QStringLiteral("u.bin"), options, nullptr).ok());
    const HttpRequestRecord put = f.server.requests().last();
    QCOMPARE(put.method, QByteArray("PUT"));
    QCOMPARE(put.header("if-none-match"), QByteArray("*"));    // CreateNew (W-10)
    QCOMPARE(put.header("content-length"), QByteArray("100000"));
    QCOMPARE(put.header("expect"), QByteArray("100-continue"));
    QCOMPARE(put.header("x-oc-mtime"), QByteArray::number(options.write.modified.toMSecsSinceEpoch() / 1000));
    QCOMPARE(put.body, data);
    QCOMPARE(f.dav.node("/u.bin").data, data);

    // CreateNew on an existing file: 412 -> AlreadyExists
    source.seek(0);
    QCOMPARE(f.backend.upload(&source, QStringLiteral("u.bin"), options, nullptr).error(), Error::AlreadyExists);
    // Truncate replaces without the condition.
    QByteArray other("short");
    QBuffer second(&other);
    second.open(QIODevice::ReadOnly);
    options.write.disposition = WriteOptions::Disposition::Truncate;
    options.write.modified = QDateTime();
    QVERIFY(f.backend.upload(&second, QStringLiteral("u.bin"), options, nullptr).ok());
    QVERIFY(f.server.requests().last().header("if-none-match").isEmpty());
    QVERIFY(f.server.requests().last().header("x-oc-mtime").isEmpty());
    QCOMPARE(f.dav.node("/u.bin").data, other);
    // Uploading onto a folder
    f.dav.addFolder("/folder");
    second.seek(0);
    QCOMPARE(f.backend.upload(&second, QStringLiteral("folder"), options, nullptr).error(), Error::IsADirectory);
    second.seek(0);
    QCOMPARE(f.backend.upload(&second, QStringLiteral("no/parent"), options, nullptr).error(), Error::NotFound);
}

void TestWebDav::uploadChunked()
{
    Fixture f;
    QVERIFY(f.signIn().ok());
    const QByteArray data(300000, 'c');
    SequentialSource source(data);
    class Counter : public Progress
    {
    public:
        void update(qint64 done, qint64 total) override
        {
            last = done;
            lastTotal = total;
        }
        qint64 last = 0;
        qint64 lastTotal = 0;
    } progress;
    QVERIFY(f.backend.upload(&source, QStringLiteral("seq"), UploadOptions(), &progress).ok());
    const HttpRequestRecord put = f.server.requests().last();
    QCOMPARE(put.header("transfer-encoding"), QByteArray("chunked"));
    QVERIFY(put.header("content-length").isEmpty());
    QCOMPARE(f.dav.node("/seq").data, data);
    QCOMPARE(progress.last, qint64(data.size()));
    QCOMPARE(progress.lastTotal, qint64(-1));
    // expectedSize gives a Content-Length even for a sequential source.
    SequentialSource again(data);
    UploadOptions options;
    options.write.disposition = WriteOptions::Disposition::Truncate;
    options.write.expectedSize = data.size();
    QVERIFY(f.backend.upload(&again, QStringLiteral("seq"), options, nullptr).ok());
    QCOMPARE(f.server.requests().last().header("content-length"), QByteArray::number(data.size()));
    // ... and a source shorter than announced fails instead of hanging.
    SequentialSource shorter(data.left(10));
    options.write.expectedSize = 20;
    QCOMPARE(f.backend.upload(&shorter, QStringLiteral("seq"), options, nullptr).error(), Error::Internal);
}

void TestWebDav::uploadCreateNewConflictBeforeBody()
{
    // W-5/W-10: with Expect: 100-continue, a 412 arrives before the body.
    Fixture f;
    QVERIFY(f.signIn().ok());
    f.server.setExpectHandler([](const HttpRequestRecord &r) {
        HttpReply reply = HttpReply::make(412);
        reply.proceed = r.header("if-none-match") != "*";
        return reply;
    });
    const QByteArray data(5 << 20, 'x');
    QBuffer source;
    source.setData(data);
    source.open(QIODevice::ReadOnly);
    QCOMPARE(f.backend.upload(&source, QStringLiteral("big"), UploadOptions(), nullptr).error(), Error::AlreadyExists);
    QVERIFY(source.pos() < data.size());
    QVERIFY(f.server.requests().last().body.isEmpty());
}

void TestWebDav::errorStatuses()
{
    Fixture f;
    QVERIFY(f.signIn().ok());
    int status = 423;
    f.server.setHandler([&status](const HttpRequestRecord &) {
        HttpReply reply = HttpReply::make(status);
        if (status == 429 || status == 503)
            reply.with("Retry-After", "7");
        return reply;
    });
    Entry entry;
    QCOMPARE(f.backend.stat(QStringLiteral("x"), &entry).error(), Error::Locked);
    status = 507;
    QByteArray data("abc");
    QBuffer source(&data);
    source.open(QIODevice::ReadOnly);
    UploadOptions truncate;
    truncate.write.disposition = WriteOptions::Disposition::Truncate;
    QCOMPARE(f.backend.upload(&source, QStringLiteral("x"), truncate, nullptr).error(), Error::NoSpace);
    status = 429;
    Result r = f.backend.stat(QStringLiteral("x"), &entry);
    QCOMPARE(r.error(), Error::RateLimited);
    QCOMPARE(r.retryAfterMs(), qint64(7000));
    status = 503;
    r = f.backend.stat(QStringLiteral("x"), &entry);
    QCOMPARE(r.error(), Error::RateLimited);
    status = 500;
    r = f.backend.stat(QStringLiteral("x"), &entry);
    QCOMPARE(r.error(), Error::ProtocolError);
    QVERIFY(r.detail().contains(QLatin1String("500")));
    status = 403;
    QCOMPARE(f.backend.makeDir(QStringLiteral("x"), true).error(), Error::PermissionDenied);
}

void TestWebDav::writeHandle()
{
    Fixture f;
    QVERIFY(f.signIn().ok());
    WriteOptions options;
    WriteHandle *raw = nullptr;
    QVERIFY(f.backend.openWrite(QStringLiteral("w.bin"), options, &raw).ok());
    std::unique_ptr<WriteHandle> handle(raw);
    QByteArray expected;
    for (int i = 0; i < 40; ++i) {
        const QByteArray piece(10000 + i, char('a' + i % 26));
        QVERIFY(handle->write(piece.constData(), piece.size()).ok());
        expected += piece;
    }
    QCOMPARE(handle->position(), qint64(expected.size()));
    QVERIFY(handle->commit().ok());
    QCOMPARE(f.dav.node("/w.bin").data, expected);
    const HttpRequestRecord put = f.server.requests().last();
    QCOMPARE(put.header("transfer-encoding"), QByteArray("chunked"));
    QCOMPARE(put.header("if-none-match"), QByteArray("*"));

    // With a known size: Content-Length; several handles at once.
    options.disposition = WriteOptions::Disposition::Truncate;
    options.expectedSize = 6;
    QVERIFY(f.backend.openWrite(QStringLiteral("one"), options, &raw).ok());
    std::unique_ptr<WriteHandle> one(raw);
    QVERIFY(f.backend.openWrite(QStringLiteral("two"), options, &raw).ok());
    std::unique_ptr<WriteHandle> two(raw);
    QVERIFY(one->write("abc", 3).ok());
    QVERIFY(two->write("xyz", 3).ok());
    Entry entry;
    QVERIFY(f.backend.stat(QStringLiteral("w.bin"), &entry).ok());   // the main connection is free
    QVERIFY(one->write("def", 3).ok());
    QVERIFY(two->write("uvw", 3).ok());
    QVERIFY(two->commit().ok());
    QVERIFY(one->commit().ok());
    QCOMPARE(f.dav.node("/one").data, QByteArray("abcdef"));
    QCOMPARE(f.dav.node("/two").data, QByteArray("xyzuvw"));
    // An empty file is complete at once.
    options.expectedSize = 0;
    QVERIFY(f.backend.openWrite(QStringLiteral("empty"), options, &raw).ok());
    std::unique_ptr<WriteHandle> empty(raw);
    QVERIFY(empty->commit().ok());
    QVERIFY(f.dav.exists("/empty"));
    // Aborted writes leave no file behind on this server.
    options.expectedSize = -1;
    QVERIFY(f.backend.openWrite(QStringLiteral("aborted"), options, &raw).ok());
    std::unique_ptr<WriteHandle> aborted(raw);
    QVERIFY(aborted->write("abc", 3).ok());
    aborted->abort();
    QVERIFY(!f.dav.exists("/aborted"));
    QVERIFY(f.backend.stat(QStringLiteral("one"), &entry).ok());
}

void TestWebDav::writeHandleConflict()
{
    Fixture f;
    f.dav.addFile("/exists", "x");
    QVERIFY(f.signIn().ok());
    WriteHandle *raw = nullptr;
    QCOMPARE(f.backend.openWrite(QStringLiteral("exists"), WriteOptions(), &raw).error(), Error::AlreadyExists);
    QVERIFY(!raw);
    QCOMPARE(f.backend.openWrite(QStringLiteral("no/parent"), WriteOptions(), &raw).error(), Error::NotFound);
    QCOMPARE(f.dav.node("/exists").data, QByteArray("x"));
}

void TestWebDav::writeHandleSizeMismatch()
{
    Fixture f;
    QVERIFY(f.signIn().ok());
    WriteOptions options;
    options.expectedSize = 4;
    WriteHandle *raw = nullptr;
    QVERIFY(f.backend.openWrite(QStringLiteral("m"), options, &raw).ok());
    std::unique_ptr<WriteHandle> handle(raw);
    QVERIFY(handle->write("ab", 2).ok());
    QCOMPARE(handle->commit().error(), Error::Internal);
    QVERIFY(!f.dav.exists("/m"));
    QVERIFY(f.backend.openWrite(QStringLiteral("m"), options, &raw).ok());
    std::unique_ptr<WriteHandle> second(raw);
    QCOMPARE(second->write("abcdef", 6).error(), Error::Internal);
    QCOMPARE(second->write("ab", 2).error(), Error::Internal);    // stays failed
}

void TestWebDav::resumeWithPartialUpdate()
{
    Fixture f;
    f.dav.addFile("/part", "hello ");
    QVERIFY(f.signIn().ok());
    WriteOptions options;
    options.disposition = WriteOptions::Disposition::Resume;
    options.resumeOffset = 6;
    WriteHandle *raw = nullptr;
    QCOMPARE(f.backend.openWrite(QStringLiteral("part"), options, &raw).error(), Error::Unsupported);

    Fixture g;
    g.dav.davHeader = "1, 2, sabredav-partialupdate";
    g.dav.addFile("/part", "hello ");
    QVERIFY(g.signIn().ok());
    options.resumeOffset = 5;
    QCOMPARE(g.backend.openWrite(QStringLiteral("part"), options, &raw).error(), Error::ProtocolError);
    options.resumeOffset = 6;
    options.expectedSize = 11;
    QVERIFY(g.backend.openWrite(QStringLiteral("part"), options, &raw).ok());
    std::unique_ptr<WriteHandle> handle(raw);
    QVERIFY(handle->write("world", 5).ok());
    QVERIFY(handle->commit().ok());
    QCOMPARE(g.dav.node("/part").data, QByteArray("hello world"));
    const HttpRequestRecord patch = g.server.requests().last();
    QCOMPARE(patch.method, QByteArray("PATCH"));
    QCOMPARE(patch.header("x-update-range"), QByteArray("append"));
    QCOMPARE(patch.header("content-type"), QByteArray("application/x-sabredav-partialupdate"));
    QCOMPARE(patch.header("content-length"), QByteArray("5"));
    QVERIFY(patch.header("if-none-match").isEmpty());
    // upload() resumes the same way
    QByteArray rest("!!");
    QBuffer source(&rest);
    source.open(QIODevice::ReadOnly);
    UploadOptions upload;
    upload.write = options;
    upload.write.resumeOffset = 11;
    upload.write.expectedSize = 13;
    QVERIFY(g.backend.upload(&source, QStringLiteral("part"), upload, nullptr).ok());
    QCOMPARE(g.dav.node("/part").data, QByteArray("hello world!!"));
}

void TestWebDav::readHandleRanges()
{
    Fixture f;
    QByteArray data;
    for (int i = 0; i < 100000; ++i)
        data += char(i % 251);
    f.dav.addFile("/r", data);
    f.dav.addFolder("/dir");
    QVERIFY(f.signIn().ok());
    ReadHandle *raw = nullptr;
    QCOMPARE(f.backend.openRead(QStringLiteral("dir"), &raw).error(), Error::IsADirectory);
    QCOMPARE(f.backend.openRead(QStringLiteral("none"), &raw).error(), Error::NotFound);
    QVERIFY(f.backend.openRead(QStringLiteral("r"), &raw).ok());
    std::unique_ptr<ReadHandle> handle(raw);
    QCOMPARE(handle->size(), qint64(data.size()));
    f.server.clearRequests();
    QByteArray out;
    QVERIFY(handle->read(1000, 5000, &out).ok());
    QCOMPARE(out, data.mid(1000, 5000));
    QCOMPARE(f.server.requests().last().header("range"), QByteArray("bytes=1000-5999"));
    QVERIFY(f.backend.capabilities().has(Capability::EfficientRanges));
    // Short read only at EOF; nothing past it.
    QVERIFY(handle->read(data.size() - 10, 100, &out).ok());
    QCOMPARE(out, data.right(10));
    QVERIFY(handle->read(data.size(), 100, &out).ok());
    QVERIFY(out.isEmpty());
    QVERIFY(handle->read(data.size() + 5, 100, &out).ok());
    QVERIFY(out.isEmpty());
    // Ranged reads reuse the connection.
    const int connections = f.server.connections();
    for (int i = 0; i < 5; ++i)
        QVERIFY(handle->read(i * 100, 10, &out).ok());
    QCOMPARE(f.server.connections(), connections);
    QVERIFY(handle->close().ok());
    // The v1 helper
    QVERIFY(f.backend.read(QStringLiteral("r"), 10, 20, &out).ok());
    QCOMPARE(out, data.mid(10, 20));
}

void TestWebDav::readHandleIgnoredRanges()
{
    Fixture f;
    f.dav.ranges = false;
    const QByteArray data(3 << 20, 'z');
    f.dav.addFile("/big", data);
    QVERIFY(f.signIn().ok());
    ReadHandle *raw = nullptr;
    QVERIFY(f.backend.openRead(QStringLiteral("big"), &raw).ok());
    std::unique_ptr<ReadHandle> handle(raw);
    QByteArray out;
    QVERIFY(handle->read(100, 50, &out).ok());     // 200: skipped and cut
    QCOMPARE(out, data.mid(100, 50));
    QVERIFY(!f.backend.capabilities().has(Capability::EfficientRanges));
    QVERIFY(handle->read(1 << 20, 10, &out).ok());  // up to 1 MiB in: still allowed
    QCOMPARE(out.size(), 10);
    f.server.clearRequests();
    // W-9: beyond 1 MiB the read is Unsupported, without a request.
    QCOMPARE(handle->read((1 << 20) + 1, 10, &out).error(), Error::Unsupported);
    QVERIFY(f.server.requests().isEmpty());
    // EfficientRanges stays cleared even if the server changes its mind.
    f.dav.ranges = true;
    QVERIFY(handle->read(0, 10, &out).ok());
    QVERIFY(!f.backend.capabilities().has(Capability::EfficientRanges));
}

void TestWebDav::downloadRanges()
{
    Fixture f;
    QByteArray data;
    for (int i = 0; i < 70000; ++i)
        data += char(i % 13);
    f.dav.addFile("/d", data);
    f.dav.addFolder("/dir");
    QVERIFY(f.signIn().ok());
    for (const bool ranges : { true, false }) {
        f.dav.ranges = ranges;
        QByteArray out;
        WriteBuffer sink(&out);
        QVERIFY(f.backend.download(QStringLiteral("d"), &sink, DownloadOptions(), nullptr).ok());
        QCOMPARE(out, data);
        QVERIFY(f.server.requests().last().header("range").isEmpty());
        out.clear();
        WriteBuffer part(&out);
        DownloadOptions options;
        options.offset = 1234;
        options.length = 5000;
        QVERIFY(f.backend.download(QStringLiteral("d"), &part, options, nullptr).ok());
        QCOMPARE(out, data.mid(1234, 5000));
        out.clear();
        WriteBuffer tail(&out);
        options.length = -1;
        QVERIFY(f.backend.download(QStringLiteral("d"), &tail, options, nullptr).ok());
        QCOMPARE(out, data.mid(1234));
        out.clear();
        WriteBuffer atEnd(&out);
        options.offset = data.size();
        QVERIFY(f.backend.download(QStringLiteral("d"), &atEnd, options, nullptr).ok());
        QVERIFY(out.isEmpty());
    }
    QByteArray out;
    WriteBuffer sink(&out);
    QCOMPARE(f.backend.download(QStringLiteral("dir"), &sink, DownloadOptions(), nullptr).error(), Error::IsADirectory);
    // A 206 for a different range is refused.
    f.server.setHandler([&f](const HttpRequestRecord &r) {
        if (r.method == "GET")
            return HttpReply::make(206, "abc").with("Content-Range", "bytes 0-2/70000");
        return f.dav.handle(r);
    });
    DownloadOptions options;
    options.offset = 10;
    QCOMPARE(f.backend.download(QStringLiteral("d"), &sink, options, nullptr).error(), Error::ProtocolError);
}

void TestWebDav::cancelWithinTwoSeconds_data()
{
    QTest::addColumn<QString>("operation");
    for (const char *name : { "connect", "stat", "list", "mkdir", "rename", "download", "upload", "read",
                              "openWrite", "write", "commit", "keepAlive", "spaceInfo", "copy", "removeFile" })
        QTest::newRow(name) << QString::fromLatin1(name);
}

void TestWebDav::cancelWithinTwoSeconds()
{
    // C-9 for every blocking method: the server holds its answer.
    QFETCH(QString, operation);
    Fixture f;
    f.dav.addFile("/file", QByteArray(1000, 'x'));
    if (operation != QLatin1String("connect"))
        QVERIFY(f.signIn().ok());
    std::unique_ptr<ReadHandle> reader;
    std::unique_ptr<WriteHandle> writer;
    if (operation == QLatin1String("read")) {
        ReadHandle *raw = nullptr;
        QVERIFY(f.backend.openRead(QStringLiteral("file"), &raw).ok());
        reader.reset(raw);
    }
    if (operation == QLatin1String("write") || operation == QLatin1String("commit")) {
        WriteHandle *raw = nullptr;
        QVERIFY(f.backend.openWrite(QStringLiteral("new"), WriteOptions(), &raw).ok());
        writer.reset(raw);
    }
    f.server.setHandler([](const HttpRequestRecord &) {
        HttpReply reply;
        reply.stall = true;
        return reply;
    });
    f.server.setExpectHandler([](const HttpRequestRecord &) {
        HttpReply reply;
        reply.stall = true;
        return reply;
    });
    const QByteArray big(64 << 20, 'b');
    QBuffer bigSource;
    bigSource.setData(big);
    bigSource.open(QIODevice::ReadOnly);
    QByteArray sinkData;
    WriteBuffer sink(&sinkData);
    std::function<Result()> call;
    Backend *backend = &f.backend;
    if (operation == QLatin1String("connect")) {
        call = [&] { return backend->connect(f.params, nullptr); };
    } else if (operation == QLatin1String("stat")) {
        call = [&] { Entry e; return backend->stat(QStringLiteral("file"), &e); };
    } else if (operation == QLatin1String("list")) {
        call = [&] { QVector<Entry> e; return backend->list(QString(), &e); };
    } else if (operation == QLatin1String("mkdir")) {
        call = [&] { return backend->makeDir(QStringLiteral("m"), true); };
    } else if (operation == QLatin1String("rename")) {
        call = [&] { return backend->rename(QStringLiteral("file"), QStringLiteral("x"), RenameMode::NoReplace); };
    } else if (operation == QLatin1String("download")) {
        f.server.setHandler([&f](const HttpRequestRecord &r) {
            if (r.method != "GET")
                return f.dav.handle(r);
            HttpReply reply = HttpReply::make(200, QByteArray(4096, ' '));
            reply.stallAfterBody = true;
            return reply;
        });
        call = [&] { return backend->download(QStringLiteral("file"), &sink, DownloadOptions(), nullptr); };
    } else if (operation == QLatin1String("upload")) {
        call = [&] { return backend->upload(&bigSource, QStringLiteral("up"), UploadOptions(), nullptr); };
    } else if (operation == QLatin1String("read")) {
        call = [&] { QByteArray out; return reader->read(0, 100, &out); };
    } else if (operation == QLatin1String("openWrite")) {
        call = [&] {
            WriteHandle *raw = nullptr;
            const Result r = backend->openWrite(QStringLiteral("ow"), WriteOptions(), &raw);
            delete raw;
            return r;
        };
    } else if (operation == QLatin1String("write")) {
        // The server stops reading the body: the socket buffers fill up.
        f.server.pauseReading(true);
        call = [&] {
            for (int i = 0; i < 64; ++i) {
                const Result r = writer->write(big.constData(), 1 << 20);
                if (!r.ok())
                    return r;
            }
            return Result(Error::Internal, QStringLiteral("the writes never blocked"));
        };
    } else if (operation == QLatin1String("commit")) {
        call = [&] {
            const Result r = writer->write("abc", 3);
            return r.ok() ? writer->commit() : r;
        };
    } else if (operation == QLatin1String("keepAlive")) {
        call = [&] { return backend->keepAlive(); };
    } else if (operation == QLatin1String("spaceInfo")) {
        call = [&] { SpaceInfo s; return backend->spaceInfo(QString(), &s); };
    } else if (operation == QLatin1String("copy")) {
        call = [&] { return backend->copy(QStringLiteral("file"), QStringLiteral("c"), CopyOptions()); };
    } else {
        call = [&] { return backend->removeFile(QStringLiteral("file")); };
    }
    Result r;
    const qint64 late = cancelAfterDelay(backend, call, &r);
    QCOMPARE(r.error(), Error::Canceled);
    QVERIFY2(late < CancelLimitMs, qPrintable(QString::number(late)));
    // Canceled until resetCancel(); then the backend works again.
    Entry entry;
    if (operation != QLatin1String("connect")) {
        QCOMPARE(f.backend.stat(QStringLiteral("file"), &entry).error(), Error::Canceled);
        f.backend.resetCancel();
        f.server.pauseReading(false);
        f.server.setHandler([&f](const HttpRequestRecord &req) { return f.dav.handle(req); });
        f.server.setExpectHandler([&f](const HttpRequestRecord &req) { return f.dav.expect(req); });
        QVERIFY(f.backend.stat(QStringLiteral("file"), &entry).ok());
    }
}

void TestWebDav::stallTimesOut()
{
    // W-15: a stalled transfer ends as Timeout after requestTimeoutMs.
    Fixture f;
    f.params.requestTimeoutMs = 1000;
    QVERIFY(f.signIn().ok());
    f.server.setHandler([](const HttpRequestRecord &) {
        HttpReply reply;
        reply.stall = true;
        return reply;
    });
    QElapsedTimer timer;
    timer.start();
    Entry entry;
    QCOMPARE(f.backend.stat(QStringLiteral("x"), &entry).error(), Error::Timeout);
    QVERIFY(timer.elapsed() < 5000);
}

void TestWebDav::connectionDrop()
{
    Fixture f;
    f.dav.addFile("/f", QByteArray(100, 'x'));
    QVERIFY(f.signIn().ok());
    f.server.setHandler([&f](const HttpRequestRecord &r) {
        if (r.method != "GET")
            return f.dav.handle(r);
        HttpReply reply = HttpReply::make(200, QByteArray(50, 'x'));
        reply.stallAfterBody = true;
        reply.close = true;          // announce more, send part, hang up
        return reply;
    });
    QByteArray out;
    WriteBuffer sink(&out);
    QCOMPARE(f.backend.download(QStringLiteral("f"), &sink, DownloadOptions(), nullptr).error(), Error::ConnectionLost);
}

void TestWebDav::keepAliveDeadServer()
{
    auto server = std::make_unique<HttpTestServer>();
    FakeDav dav;
    server->setHandler([&dav](const HttpRequestRecord &r) { return dav.handle(r); });
    ConnectionParams params;
    params.host = QStringLiteral("127.0.0.1");
    params.port = server->port();
    params.options.insert(QStringLiteral("tls"), QStringLiteral("http"));
    params.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
    params.options.insert(QStringLiteral("base_path"), QStringLiteral("/dav"));
    WebDavBackend backend;
    QVERIFY(establish(&backend, params, Credentials(QStringLiteral("a"), "b")).ok());
    QVERIFY(backend.keepAlive().ok());
    QCOMPARE(server->requests().last().method, QByteArray("OPTIONS"));
    server.reset();
    QCOMPARE(backend.keepAlive().error(), Error::ConnectionLost);
}

void TestWebDav::cookiesInMemory()
{
    // W-16: a session cookie set by the server comes back on later requests.
    Fixture f;
    f.server.setHandler([&f](const HttpRequestRecord &r) {
        HttpReply reply = f.dav.handle(r);
        if (r.method == "PROPFIND" && reply.status == 207)
            reply.with("Set-Cookie", "session=s3cr3t; Path=/; HttpOnly");
        return reply;
    });
    QVERIFY(f.signIn().ok());
    Entry entry;
    QVERIFY(f.backend.stat(QString(), &entry).ok());
    QCOMPARE(f.server.requests().last().header("cookie"), QByteArray("session=s3cr3t"));
    // A new connection of the same backend has a fresh cookie jar.
    QVERIFY(f.signIn().ok());
    const QVector<HttpRequestRecord> requests = f.server.requests();
    QVERIFY(requests.at(requests.size() - 2).header("cookie").isEmpty());
    QVERIFY(requests.last().header("cookie").isEmpty());
}

void TestWebDav::spaceInfoAndChecksum()
{
    Fixture f;
    f.dav.quotaAvailable = 5000;
    f.dav.quotaUsed = 1000;
    f.dav.addFile("/f", "x");
    QVERIFY(f.signIn().ok());
    SpaceInfo info;
    QVERIFY(f.backend.spaceInfo(QString(), &info).ok());
    QCOMPARE(info.free, qint64(5000));
    QCOMPARE(info.used, qint64(1000));
    QCOMPARE(info.total, qint64(6000));
    QCOMPARE(f.server.requests().last().header("depth"), QByteArray("0"));
    qint64 free = 0;
    QVERIFY(f.backend.freeSpace(QString(), &free).ok());
    QCOMPARE(free, qint64(5000));
    QByteArray digest;
    QCOMPARE(f.backend.checksum(QStringLiteral("f"), QStringLiteral("sha1"), &digest).error(), Error::Unsupported);
    QCOMPARE(f.backend.setAttributes(QStringLiteral("f"), AttributeChanges()).error(), Error::None);
    AttributeChanges changes;
    changes.modified = QDateTime::currentDateTimeUtc();
    QCOMPARE(f.backend.setAttributes(QStringLiteral("f"), changes).error(), Error::Unsupported);

    Fixture g;
    g.dav.davHeader = "1, 3, nc-calendar-search";
    g.dav.addFile("/f", "x");
    g.dav.extraPropXml = "<oc:checksums xmlns:oc=\"http://owncloud.org/ns\"><oc:checksum>SHA1:00ff MD5:abcd"
                         "</oc:checksum></oc:checksums>";
    QVERIFY(g.signIn().ok());
    QVERIFY(g.backend.checksum(QStringLiteral("f"), QStringLiteral("SHA1"), &digest).ok());
    QCOMPARE(digest, QByteArray("\x00\xff", 2));
    QVERIFY(g.backend.checksum(QStringLiteral("f"), QStringLiteral("md5"), &digest).ok());
    QCOMPARE(digest, QByteArray("\xab\xcd"));
    QCOMPARE(g.backend.checksum(QStringLiteral("f"), QStringLiteral("adler32"), &digest).error(), Error::Unsupported);
    SpaceInfo none;
    QCOMPARE(g.backend.spaceInfo(QString(), &none).error(), Error::Unsupported);
}

void TestWebDav::handlesAfterDisconnect()
{
    Fixture f;
    f.dav.addFile("/f", "data");
    QVERIFY(f.signIn().ok());
    ReadHandle *rawReader = nullptr;
    QVERIFY(f.backend.openRead(QStringLiteral("f"), &rawReader).ok());
    std::unique_ptr<ReadHandle> reader(rawReader);
    WriteHandle *rawWriter = nullptr;
    QVERIFY(f.backend.openWrite(QStringLiteral("g"), WriteOptions(), &rawWriter).ok());
    std::unique_ptr<WriteHandle> writer(rawWriter);
    QVERIFY(writer->write("ab", 2).ok());
    f.backend.disconnect();
    QByteArray out;
    QCOMPARE(reader->read(0, 4, &out).error(), Error::ConnectionLost);
    QCOMPARE(writer->write("cd", 2).error(), Error::ConnectionLost);
    QCOMPARE(writer->commit().error(), Error::ConnectionLost);
    QCOMPARE(reader->close().error(), Error::ConnectionLost);
    Entry entry;
    QCOMPARE(f.backend.stat(QStringLiteral("f"), &entry).error(), Error::Internal);
}

void TestWebDav::invalidNames()
{
    Fixture f;
    QVERIFY(f.signIn().ok());
    f.server.clearRequests();
    Entry entry;
    QCOMPARE(f.backend.stat(QString(QChar(0xD800)), &entry).error(), Error::InvalidName);
    QCOMPARE(f.backend.stat(QStringLiteral("a/../b"), &entry).error(), Error::InvalidName);
    QCOMPARE(f.backend.makeDir(QString(QChar(0xDBFF)), true).error(), Error::InvalidName);
    QVERIFY(f.server.requests().isEmpty());
    // Escaped bytes round-trip to the server.
    QVERIFY(f.backend.makeDir(Names::decode("n\xfe"), true).ok());
    QCOMPARE(f.server.requests().last().target, QByteArray("/dav/n%FE/"));
    QVERIFY(f.dav.exists("/n\xfe"));
}

void TestWebDav::unreachable()
{
    int port = 0;
    {
        HttpTestServer gone;
        port = gone.port();
    }
    WebDavBackend backend;
    ConnectionParams params;
    params.host = QStringLiteral("127.0.0.1");
    params.port = port;
    params.options.insert(QStringLiteral("tls"), QStringLiteral("http"));
    params.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
    QCOMPARE(backend.connect(params, nullptr).error(), Error::NetworkUnreachable);
}

void TestWebDav::ignoresProxyEnvironment()
{
    // XSEC-4: no proxy from the environment.
    QMap<QByteArray, QByteArray> saved;
    for (const QByteArray &name : { QByteArray("http_proxy"), QByteArray("HTTP_PROXY"), QByteArray("all_proxy"),
                                    QByteArray("ALL_PROXY"), QByteArray("no_proxy"), QByteArray("NO_PROXY") }) {
        if (qEnvironmentVariableIsSet(name.constData()))
            saved.insert(name, qgetenv(name.constData()));
        qunsetenv(name.constData());
    }
    qputenv("http_proxy", "http://127.0.0.1:1");
    qputenv("ALL_PROXY", "http://127.0.0.1:1");
    Fixture f;
    f.dav.addFile("/f", "x");
    const Result r = f.signIn();
    Entry entry;
    const Result s = f.backend.stat(QStringLiteral("f"), &entry);
    qunsetenv("http_proxy");
    qunsetenv("ALL_PROXY");
    for (auto it = saved.constBegin(); it != saved.constEnd(); ++it)
        qputenv(it.key().constData(), it.value());
    QVERIFY2(r.ok(), qPrintable(r.toString()));
    QVERIFY(s.ok());
}

// ------------------------------------------------------ backend (HTTPS)

namespace {

struct TlsFixture {
    explicit TlsFixture(const TestCertificate &leaf, const QByteArray &chain = QByteArray())
        : server(leaf.certificatePem + chain, leaf.keyPem)
    {
        dav.authorization = Credential;
        server.setHandler([this](const HttpRequestRecord &r) { return dav.handle(r); });
        params.host = QStringLiteral("127.0.0.1");
        params.port = server.port();
        params.options.insert(QStringLiteral("base_path"), QStringLiteral("/dav"));
    }
    FakeDav dav;
    HttpTestServer server;
    ConnectionParams params;
    WebDavBackend backend;
};

constexpr int HandshakeSettleMs = 300;   // time for the server to see a failed handshake

} // namespace

void TestWebDav::tlsUntrustedSendsNothing()
{
    // XT-5: an unknown certificate: the identity comes back, nothing is sent.
    const TestCertificate cert = makeCertificate(CertificateOptions());
    TlsFixture f(cert);
    ServerIdentity seen;
    const Result r = establish(&f.backend, f.params, Credentials(QStringLiteral("alice"), "secret"), &seen);
    QCOMPARE(r.error(), Error::ServerIdentityUnknown);
    QCOMPARE(seen.kind, ServerIdentity::Kind::TlsCertificate);
    QCOMPARE(seen.publicKey, cert.spkiDer);
    QVERIFY(!seen.systemTrusted);
    QVERIFY(seen.problems & ServerIdentity::SelfSigned);
    // The client ended the handshake once it had the certificate (W-3): none
    // completed, so nothing could have been sent.
    QTest::qWait(HandshakeSettleMs);
    QCOMPARE(f.server.handshakes(), 0);
    QVERIFY(f.server.requests().isEmpty());
    // Calling authenticate() anyway is refused before any request.
    QVERIFY(f.backend.connect(f.params, &seen).ok());
    QCOMPARE(f.backend.authenticate(Credentials(QStringLiteral("alice"), "secret")).error(),
             Error::ServerIdentityUnknown);
    QVERIFY(f.server.requests().isEmpty());
}

void TestWebDav::tlsPinned()
{
    // W-4: pinned self-signed certificate: verification off, pin enforced.
    const TestCertificate cert = makeCertificate(CertificateOptions());
    TlsFixture f(cert);
    f.params.options.insert(QStringLiteral("host_key"), ServerIdentity::fromTlsSpki(cert.spkiDer).toPin());
    ServerIdentity seen;
    QVERIFY(establish(&f.backend, f.params, Credentials(QStringLiteral("alice"), "secret"), &seen).ok());
    QCOMPARE(seen.publicKey, cert.spkiDer);
    QVERIFY(!seen.systemTrusted);
    const QVector<HttpRequestRecord> requests = f.server.requests();
    QCOMPARE(requests.first().method, QByteArray("OPTIONS"));
    QVERIFY(requests.first().header("authorization").isEmpty());
    Entry entry;
    QVERIFY(f.backend.stat(QString(), &entry).ok());
    QVERIFY(entry.isDir());
}

void TestWebDav::tlsPinnedOtherName()
{
    // W-4: without peer verification the host name is not checked either;
    // the pin alone identifies the server.
    CertificateOptions options;
    options.commonName = "nas.example";
    options.subjectAltNames = "DNS:nas.example";
    const TestCertificate cert = makeCertificate(options);
    TlsFixture f(cert);
    f.params.options.insert(QStringLiteral("host_key"), ServerIdentity::fromTlsSpki(cert.spkiDer).toPin());
    ServerIdentity seen;
    const Result r = establish(&f.backend, f.params, Credentials(QStringLiteral("alice"), "secret"), &seen);
    QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
    QVERIFY(seen.problems & ServerIdentity::HostnameMismatch);
    QVERIFY(seen.problems & ServerIdentity::SelfSigned);
}

void TestWebDav::tlsPinMismatch()
{
    const TestCertificate cert = makeCertificate(CertificateOptions());
    const TestCertificate other = makeCertificate(CertificateOptions());
    TlsFixture f(cert);
    f.params.options.insert(QStringLiteral("host_key"), ServerIdentity::fromTlsSpki(other.spkiDer).toPin());
    ServerIdentity seen;
    const Result r = establish(&f.backend, f.params, Credentials(QStringLiteral("alice"), "secret"), &seen);
    QCOMPARE(r.error(), Error::ServerIdentityChanged);
    QCOMPARE(seen.publicKey, cert.spkiDer);     // the new key, for the dialog
    QVERIFY(f.server.requests().isEmpty());
    QVERIFY(f.backend.connect(f.params, &seen).ok());
    QCOMPARE(f.backend.authenticate(Credentials(QStringLiteral("alice"), "secret")).error(),
             Error::ServerIdentityChanged);
    QVERIFY(f.server.requests().isEmpty());
    // An SSH pin on a TLS location is a mismatch, too.
    f.params.options.insert(QStringLiteral("host_key"),
                            QStringLiteral("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"));
    QCOMPARE(establish(&f.backend, f.params, Credentials(QStringLiteral("alice"), "secret")).error(),
             Error::ServerIdentityChanged);
    QVERIFY(f.server.requests().isEmpty());
}

void TestWebDav::tlsPinnedVerifyPeer()
{
    // W-4: tls_verify_peer=true keeps chain and host name verification on.
    const TestCertificate cert = makeCertificate(CertificateOptions());
    TlsFixture f(cert);
    f.params.options.insert(QStringLiteral("host_key"), ServerIdentity::fromTlsSpki(cert.spkiDer).toPin());
    f.params.options.insert(QStringLiteral("tls_verify_peer"), QStringLiteral("true"));
    ServerIdentity seen;
    const Result r = establish(&f.backend, f.params, Credentials(QStringLiteral("alice"), "secret"), &seen);
    QCOMPARE(r.error(), Error::ServerIdentityChanged);
    QVERIFY2(r.message().contains(QLatin1String("pinned")), qPrintable(r.message()));
    QCOMPARE(seen.publicKey, cert.spkiDer);
    QVERIFY(f.server.requests().isEmpty());
}

void TestWebDav::tlsSystemTrusted()
{
    // XC-16: a certificate the system trusts needs no prompt and no pin.
    CertificateOptions caOptions;
    caOptions.commonName = "netvfs test CA";
    caOptions.subjectAltNames.clear();
    caOptions.authority = true;
    const TestCertificate ca = makeCertificate(caOptions);
    CertificateOptions leafOptions;
    leafOptions.issuer = &ca;
    const TestCertificate leaf = makeCertificate(leafOptions);
    QTemporaryFile caFile;
    QVERIFY(caFile.open());
    caFile.write(ca.certificatePem);
    caFile.flush();

    TlsFixture f(leaf, ca.certificatePem);
    f.params.options.insert(QStringLiteral("test_ca_file"), caFile.fileName());
    ServerIdentity seen;
    QVERIFY(establish(&f.backend, f.params, Credentials(QStringLiteral("alice"), "secret"), &seen).ok());
    QVERIFY(seen.systemTrusted);
    QCOMPARE(seen.problems, 0);
    QCOMPARE(seen.publicKey, leaf.spkiDer);
    QCOMPARE(seen.details.value(QStringLiteral("issuer")).toString(), QStringLiteral("CN=netvfs test CA,O=netvfs tests"));
    Entry entry;
    QVERIFY(f.backend.stat(QString(), &entry).ok());

    // The wrong host name is not trusted, even with the right CA.
    TlsFixture g(leaf, ca.certificatePem);
    g.params.host = QStringLiteral("localhost.localdomain");
    g.params.options.insert(QStringLiteral("test_ca_file"), caFile.fileName());
    // (resolve may fail on some hosts; only check when it connects)
    const Result r = establish(&g.backend, g.params, Credentials(QStringLiteral("alice"), "secret"), &seen);
    if (r.error() != Error::NetworkUnreachable) {
        QCOMPARE(r.error(), Error::ServerIdentityUnknown);
        QVERIFY(seen.problems & ServerIdentity::HostnameMismatch);
        QVERIFY(g.server.requests().isEmpty());
    }
}

QTEST_GUILESS_MAIN(TestWebDav)
#include "tst_webdav.moc"
