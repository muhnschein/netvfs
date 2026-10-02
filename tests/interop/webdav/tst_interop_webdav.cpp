// SPDX-License-Identifier: LGPL-2.1-or-later
// WebDAV interoperability (SPEC-v2 6.3, XT-2, XT-5) against the servers that
// run.sh starts: Apache httpd + mod_dav (plain HTTP, TLS self-signed, TLS
// from a test CA with HTTP/2, Basic and Digest) and rclone "serve webdav".
// Ports, the password and the CA file come from the JSON file named by
// NETVFS_WEBDAV_INTEROP_CONFIG. The backend sources are compiled in with
// NETVFS_WEBDAV_TEST_HOOKS so that the test CA can stand in for the system
// CAs; pluginLoads() checks the real plugin.
#include "backendloader.h"
#include "identity.h"
#include "names.h"
#include "transfer.h"
#include "webdavbackend.h"

#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QElapsedTimer>
#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QProcess>
#include <QtCore/QUuid>
#include <QtNetwork/QTcpSocket>
#include <QtTest/QtTest>

#include <chrono>
#include <functional>
#include <memory>
#include <thread>

using namespace NetVfs;
using WebDav::WebDavBackend;

Q_DECLARE_METATYPE(NetVfs::Error)

namespace QTest {
template <>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest

// Shows the result when a call that must succeed fails.
#define QVERIFY_OK(expression)                                                                         \
    do {                                                                                               \
        const NetVfs::Result result_ = (expression);                                                   \
        QVERIFY2(result_.ok(), qPrintable(result_.toString() + QLatin1Char(' ') + result_.detail()));  \
    } while (false)

namespace {

constexpr int CancelDelayMs = 500;
constexpr int CancelLimitMs = 2000;     // SPEC C-9
constexpr qint64 BigSize = 32 << 20;

QByteArray pseudoRandom(qint64 size, quint32 seed)
{
    QByteArray data(int(size), Qt::Uninitialized);
    quint32 state = seed;
    for (int i = 0; i < data.size(); ++i) {
        state = state * 1664525u + 1013904223u;
        data[i] = char(state >> 24);
    }
    return data;
}

class BufferSink : public QBuffer
{
public:
    BufferSink() { open(QIODevice::WriteOnly); }
};

class Recorder : public ListSink
{
public:
    bool entries(const QVector<Entry> &batch) override
    {
        ++batches;
        all += batch;
        return true;
    }
    int batches = 0;
    QVector<Entry> all;
};

// The stalling proxy (httpstall.py) in front of a server.
class StallProxy
{
public:
    bool start(int targetPort)
    {
        m_process.setProgram(QStringLiteral("python3"));
        m_process.setArguments({ QStringLiteral(NETVFS_SOURCE_DIR "/tests/interop/webdav/httpstall.py"),
                                 QStringLiteral("127.0.0.1"), QString::number(targetPort) });
        m_process.start();
        if (!m_process.waitForReadyRead(10000))
            return false;
        const QList<QByteArray> parts = m_process.readLine().trimmed().split(' ');
        if (parts.size() != 3 || parts.at(0) != "PORTS")
            return false;
        port = parts.at(1).toInt();
        m_control.connectToHost(QStringLiteral("127.0.0.1"), quint16(parts.at(2).toInt()));
        return m_control.waitForConnected(5000);
    }
    ~StallProxy()
    {
        m_control.abort();
        m_process.kill();
        m_process.waitForFinished(5000);
    }
    bool command(const char *text)
    {
        m_control.write(QByteArray(text) + '\n');
        if (!m_control.waitForBytesWritten(5000))
            return false;
        while (!m_control.canReadLine()) {
            if (!m_control.waitForReadyRead(5000))
                return false;
        }
        return m_control.readLine().trimmed() == "ok";
    }
    int port = 0;

private:
    QProcess m_process;
    QTcpSocket m_control;
};

} // namespace

class TestInteropWebDav : public QObject
{
    Q_OBJECT

private:
    ConnectionParams params(const QString &server) const;
    std::unique_ptr<WebDavBackend> signedIn(const QString &server, Result *result = nullptr) const;
    Credentials credentials() const { return Credentials(QStringLiteral("alice"), m_password); }
    QString fresh(const QString &stem) const;
    bool configured(const QString &server) const;
    QStringList apacheLog() const;
    static void addServers();

    QJsonObject m_config;
    QByteArray m_password;
    QString m_selfPin;

private slots:
    void initTestCase();
    void pluginLoads();

    // XT-5 / XC-16
    void untrustedCertificateSendsNothing();
    void credentialsOnlyAfterIdentity();
    void pinMismatch();
    void systemTrustedNoPrompt();
    void testCaNotTrustedWithoutHook();
    void redirects();
    void authFailures();

    // operations on every server
    void roundTrip_data();
    void roundTrip();
    void names_data();
    void names();
    void renameAndCopy_data();
    void renameAndCopy();
    void handles_data();
    void handles();
    void errors_data();
    void errors();
    void bigTransfer_data();
    void bigTransfer();
    void streamingListing();
    void nextcloudFlavor();
    void noSpace();

    // C-9, W-15, XC-21
    void cancel_data();
    void cancel();
    void stallTimesOut();
    void connectionDrop();
};

void TestInteropWebDav::initTestCase()
{
    qRegisterMetaType<NetVfs::Error>();
    const QByteArray path = qgetenv("NETVFS_WEBDAV_INTEROP_CONFIG");
    if (path.isEmpty())
        QSKIP("Run through tests/interop/webdav/run.sh");
    QFile file(QString::fromLocal8Bit(path));
    QVERIFY(file.open(QIODevice::ReadOnly));
    m_config = QJsonDocument::fromJson(file.readAll()).object();
    m_password = m_config.value(QStringLiteral("password")).toString().toLatin1();
    QVERIFY(!m_password.isEmpty());
    if (!m_config.contains(QStringLiteral("apache")))
        return;     // nextcloud.sh: Nextcloud only
    // The self-signed server's pin, as the identity dialog would store it.
    WebDavBackend probe;
    ConnectionParams self = params(QStringLiteral("apache-self"));
    self.options.remove(QStringLiteral("host_key"));
    ServerIdentity seen;
    QVERIFY_OK(probe.connect(self, &seen));
    QCOMPARE(seen.kind, ServerIdentity::Kind::TlsCertificate);
    m_selfPin = seen.toPin();
}

ConnectionParams TestInteropWebDav::params(const QString &server) const
{
    const QJsonObject apache = m_config.value(QStringLiteral("apache")).toObject();
    ConnectionParams p;
    p.provider = QStringLiteral("webdav");
    p.host = QStringLiteral("127.0.0.1");
    p.username = QStringLiteral("alice");
    p.requestTimeoutMs = 20000;
    p.options.insert(QStringLiteral("base_path"), QStringLiteral("/dav"));
    const auto plain = [&p](int port) {
        p.port = port;
        p.options.insert(QStringLiteral("tls"), QStringLiteral("http"));
        p.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
    };
    if (server == QLatin1String("apache-http")) {
        plain(apache.value(QStringLiteral("http")).toInt());
    } else if (server == QLatin1String("apache-digest")) {
        plain(apache.value(QStringLiteral("http")).toInt());
        p.options.insert(QStringLiteral("base_path"), QStringLiteral("/digest"));
    } else if (server == QLatin1String("apache-self")) {
        p.port = apache.value(QStringLiteral("https_self")).toInt();
        p.options.insert(QStringLiteral("host_key"), m_selfPin);
    } else if (server == QLatin1String("apache-ca")) {
        p.port = apache.value(QStringLiteral("https_ca")).toInt();
        p.options.insert(QStringLiteral("test_ca_file"), m_config.value(QStringLiteral("ca_file")).toString());
    } else if (server == QLatin1String("rclone")) {
        plain(m_config.value(QStringLiteral("rclone")).toObject().value(QStringLiteral("http")).toInt());
        p.options.insert(QStringLiteral("base_path"), QStringLiteral("/"));
    } else if (server == QLatin1String("nextcloud")) {
        // flavor=auto detects Nextcloud from the base path and DAV header.
        plain(m_config.value(QStringLiteral("nextcloud")).toObject().value(QStringLiteral("http")).toInt());
        p.options.insert(QStringLiteral("base_path"), QStringLiteral("/remote.php/dav/files/alice"));
    }
    return p;
}

bool TestInteropWebDav::configured(const QString &server) const
{
    return m_config.contains(server.section(QLatin1Char('-'), 0, 0));
}

std::unique_ptr<WebDavBackend> TestInteropWebDav::signedIn(const QString &server, Result *result) const
{
    auto backend = std::make_unique<WebDavBackend>();
    const Result r = establish(backend.get(), params(server), credentials());
    if (result)
        *result = r;
    return r.ok() ? std::move(backend) : nullptr;
}

QString TestInteropWebDav::fresh(const QString &stem) const
{
    return stem + QLatin1Char('-') + QUuid::createUuid().toString().mid(1, 8);
}

QStringList TestInteropWebDav::apacheLog() const
{
    QProcess docker;
    docker.start(QStringLiteral("docker"),
                 { QStringLiteral("logs"), m_config.value(QStringLiteral("apache_container")).toString() });
    docker.waitForFinished(20000);
    return QString::fromLatin1(docker.readAllStandardOutput()).split(QLatin1Char('\n'), NETVFS_SKIP_EMPTY_PARTS);
}

void TestInteropWebDav::addServers()
{
    QTest::addColumn<QString>("server");
    for (const char *server : { "apache-http", "apache-digest", "apache-self", "apache-ca", "rclone", "nextcloud" })
        QTest::newRow(server) << QString::fromLatin1(server);
}

void TestInteropWebDav::pluginLoads()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    Result r;
    std::unique_ptr<Backend> backend(BackendLoader::create(QStringLiteral("webdav"), &r));
    QVERIFY2(backend, qPrintable(r.toString()));
    QVERIFY_OK(establish(backend.get(), params(QStringLiteral("apache-self")), credentials()));
    QVERIFY(backend->capabilities().has(Capability::AtomicPut));
    QVector<Entry> entries;
    QVERIFY_OK(backend->list(QString(), &entries));
}

// ------------------------------------------------------------- identity

void TestInteropWebDav::untrustedCertificateSendsNothing()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    const int before = apacheLog().size();
    ConnectionParams p = params(QStringLiteral("apache-self"));
    p.options.remove(QStringLiteral("host_key"));
    WebDavBackend backend;
    ServerIdentity seen;
    const Result r = establish(&backend, p, credentials(), &seen);
    QCOMPARE(r.error(), Error::ServerIdentityUnknown);
    QVERIFY(seen.problems & ServerIdentity::SelfSigned);
    QVERIFY(!seen.systemTrusted);
    QCOMPARE(seen.details.value(QStringLiteral("subject")).toString(), QStringLiteral("CN=localhost,O=netvfs interop"));
    QVERIFY(seen.details.value(QStringLiteral("sans")).toStringList().contains(QStringLiteral("IP:127.0.0.1")));
    QCOMPARE(seen.toPin(), m_selfPin);
    // XT-5: not a single HTTP request reached the server.
    QCOMPARE(apacheLog().size(), before);
}

void TestInteropWebDav::credentialsOnlyAfterIdentity()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    for (const QString &server : { QStringLiteral("apache-self"), QStringLiteral("apache-ca") }) {
        const int before = apacheLog().size();
        QVERIFY(signedIn(server));
        const QStringList lines = apacheLog().mid(before);
        QVERIFY2(lines.size() >= 3, qPrintable(lines.join(QLatin1Char('\n'))));
        // The OPTIONS of connect() carries nothing; credentials follow the check.
        QVERIFY2(lines.first().startsWith(QLatin1String("OPTIONS /dav/ ")), qPrintable(lines.first()));
        QVERIFY2(lines.first().endsWith(QLatin1String("auth=-")), qPrintable(lines.first()));
        QVERIFY(lines.last().endsWith(QLatin1String("auth=yes")));
    }
}

void TestInteropWebDav::pinMismatch()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    // The CA server's key pinned on the self-signed server, and vice versa.
    ConnectionParams ca = params(QStringLiteral("apache-ca"));
    ServerIdentity caIdentity;
    {
        WebDavBackend probe;
        QVERIFY_OK(probe.connect(ca, &caIdentity));
    }
    const int before = apacheLog().size();
    ConnectionParams self = params(QStringLiteral("apache-self"));
    self.options.insert(QStringLiteral("host_key"), caIdentity.toPin());
    WebDavBackend backend;
    ServerIdentity seen;
    QCOMPARE(establish(&backend, self, credentials(), &seen).error(), Error::ServerIdentityChanged);
    QCOMPARE(seen.toPin(), m_selfPin);
    ca.options.insert(QStringLiteral("host_key"), m_selfPin);
    QCOMPARE(establish(&backend, ca, credentials(), &seen).error(), Error::ServerIdentityChanged);
    QCOMPARE(seen.toPin(), caIdentity.toPin());
    QCOMPARE(apacheLog().size(), before);
    // Pinned with tls_verify_peer on a self-signed certificate: refused too.
    self.options.insert(QStringLiteral("host_key"), m_selfPin);
    self.options.insert(QStringLiteral("tls_verify_peer"), QStringLiteral("true"));
    QCOMPARE(establish(&backend, self, credentials(), &seen).error(), Error::ServerIdentityChanged);
    QCOMPARE(apacheLog().size(), before);
}

void TestInteropWebDav::systemTrustedNoPrompt()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    WebDavBackend backend;
    ServerIdentity seen;
    QVERIFY_OK(establish(&backend, params(QStringLiteral("apache-ca")), credentials(), &seen));
    QVERIFY(seen.systemTrusted);
    QCOMPARE(seen.problems, 0);
    QCOMPARE(seen.details.value(QStringLiteral("issuer")).toString(),
             QStringLiteral("CN=netvfs interop CA,O=netvfs interop"));
    // Opting in to pin a trusted certificate (pin_trusted): verify on + pin.
    ConnectionParams pinned = params(QStringLiteral("apache-ca"));
    pinned.options.insert(QStringLiteral("host_key"), seen.toPin());
    pinned.options.insert(QStringLiteral("tls_verify_peer"), QStringLiteral("true"));
    QVERIFY_OK(establish(&backend, pinned, credentials()));
    Entry entry;
    QVERIFY_OK(backend.stat(QString(), &entry));
}

void TestInteropWebDav::testCaNotTrustedWithoutHook()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    ConnectionParams p = params(QStringLiteral("apache-ca"));
    p.options.remove(QStringLiteral("test_ca_file"));
    WebDavBackend backend;
    ServerIdentity seen;
    QCOMPARE(establish(&backend, p, credentials(), &seen).error(), Error::ServerIdentityUnknown);
    QVERIFY(seen.problems & ServerIdentity::UntrustedRoot);
    QVERIFY(!(seen.problems & ServerIdentity::SelfSigned));
    // A host name the certificate does not name.
    p = params(QStringLiteral("apache-ca"));
    p.host = QStringLiteral("::1");
    const Result r = establish(&backend, p, credentials(), &seen);
    if (r.error() != Error::NetworkUnreachable) {      // docker may publish IPv4 only
        QCOMPARE(r.error(), Error::ServerIdentityUnknown);
        QVERIFY(seen.problems & ServerIdentity::HostnameMismatch);
    }
}

void TestInteropWebDav::redirects()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    // W-6: Apache redirects /moved -> /dav (same origin) ...
    ConnectionParams moved = params(QStringLiteral("apache-self"));
    moved.options.insert(QStringLiteral("base_path"), QStringLiteral("/moved"));
    WebDavBackend backend;
    QVERIFY_OK(establish(&backend, moved, credentials()));
    QVector<Entry> entries;
    QVERIFY_OK(backend.list(QString(), &entries));
    // ... and /elsewhere to another origin, which is refused by name.
    ConnectionParams elsewhere = params(QStringLiteral("apache-self"));
    elsewhere.options.insert(QStringLiteral("base_path"), QStringLiteral("/elsewhere"));
    const Result r = establish(&backend, elsewhere, credentials());
    QCOMPARE(r.error(), Error::ProtocolError);
    QVERIFY2(r.message().contains(QLatin1String("https://elsewhere.invalid/dav")), qPrintable(r.message()));
}

void TestInteropWebDav::authFailures()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    for (const QString &server : { QStringLiteral("apache-http"), QStringLiteral("apache-digest"),
                                   QStringLiteral("apache-ca"), QStringLiteral("rclone") }) {
        WebDavBackend backend;
        QCOMPARE(establish(&backend, params(server), Credentials(QStringLiteral("alice"), "wrong")).error(),
                 Error::AuthFailed);
        QCOMPARE(establish(&backend, params(server), Credentials(QStringLiteral("mallory"), m_password)).error(),
                 Error::AuthFailed);
    }
    ConnectionParams missing = params(QStringLiteral("apache-ca"));
    missing.options.insert(QStringLiteral("base_path"), QStringLiteral("/dav/does-not-exist"));
    WebDavBackend backend;
    const Result r = establish(&backend, missing, credentials());
    QCOMPARE(r.error(), Error::NotFound);
    QVERIFY(r.message().contains(QLatin1String("base path")));
    // W-2: no plain HTTP without consent.
    ConnectionParams insecure = params(QStringLiteral("apache-http"));
    insecure.options.remove(QStringLiteral("allow_insecure"));
    QCOMPARE(establish(&backend, insecure, credentials()).error(), Error::SecurityPolicy);
}

// ------------------------------------------------------------ operations

void TestInteropWebDav::roundTrip_data()
{
    addServers();
}

void TestInteropWebDav::roundTrip()
{
    QFETCH(QString, server);
    if (!configured(server))
        QSKIP("server not started by this run");
    Result r;
    const auto backend = signedIn(server, &r);
    QVERIFY2(backend, qPrintable(r.toString()));
    const Capabilities caps = backend->capabilities();
    QVERIFY(caps.has(Capability::AtomicPut));
    QVERIFY(caps.has(Capability::NativeNoReplace));
    QVERIFY(caps.has(Capability::ReadHandles));

    const QString dir = fresh(QStringLiteral("round"));
    QVERIFY_OK(backend->makeDir(dir, true));
    QCOMPARE(backend->makeDir(dir, true).error(), Error::AlreadyExists);
    QVERIFY_OK(backend->makeDir(dir, false));
    QVERIFY_OK(backend->makePath(dir + QStringLiteral("/a/b/c")));

    const QByteArray data = pseudoRandom(300000, 7);
    QBuffer source;
    source.setData(data);
    source.open(QIODevice::ReadOnly);
    UploadOptions options;
    options.write.expectedSize = data.size();
    const QString file = dir + QStringLiteral("/file.bin");
    QVERIFY_OK(backend->upload(&source, file, options, nullptr));
    Entry entry;
    QVERIFY_OK(backend->stat(file, &entry));
    QCOMPARE(entry.type, EntryType::File);
    QCOMPARE(entry.size, qint64(data.size()));
    QCOMPARE(entry.name, QStringLiteral("file.bin"));
    QVERIFY(entry.modified.isValid());
    QVERIFY(qAbs(entry.modified.secsTo(QDateTime::currentDateTimeUtc())) < 600);
    QVERIFY(!entry.etag.isEmpty());

    BufferSink sink;
    QVERIFY_OK(backend->download(file, &sink, DownloadOptions(), nullptr));
    QCOMPARE(sink.data(), data);

    QVector<Entry> entries;
    QVERIFY_OK(backend->list(dir, &entries));
    QCOMPARE(entries.size(), 2);
    for (const Entry &e : entries) {
        if (e.name == QLatin1String("a"))
            QVERIFY(e.isDir());
        else
            QCOMPARE(e.name, QStringLiteral("file.bin"));
    }
    QCOMPARE(backend->list(file, &entries).error(), Error::NotADirectory);
    QVERIFY_OK(backend->keepAlive());

    // Transfer::upload with the browser policy (AtomicPut: no temp name).
    Transfer::TransferPolicy policy;
    policy.useTempName = !caps.has(Capability::AtomicPut);
    policy.createMode = -1;
    source.seek(0);
    QVERIFY(Transfer::upload(backend.get(), &source, data.size(), dir + QStringLiteral("/via-transfer"), nullptr,
                             policy).ok());
    // ... and the backup policy (.part + Replace). Nextcloud refuses names
    // ending in ".part" (its own upload temporaries) with 400.
    source.seek(0);
    policy = Transfer::TransferPolicy();
    if (server == QLatin1String("nextcloud"))
        policy.tempName = QStringLiteral("backup.tar.upload");
    QVERIFY_OK(Transfer::upload(backend.get(), &source, data.size(), dir + QStringLiteral("/backup.tar"), nullptr,
                                policy));
    const QString temporary = policy.tempName.isEmpty() ? QStringLiteral("backup.tar.part") : policy.tempName;
    QCOMPARE(backend->stat(dir + QLatin1Char('/') + temporary, &entry).error(), Error::NotFound);

    // Clean up through the native tree delete.
    QVERIFY(caps.has(Capability::RecursiveDelete));
    QVERIFY_OK(backend->removeTreeNative(dir));
    QCOMPARE(backend->stat(dir, &entry).error(), Error::NotFound);
}

void TestInteropWebDav::names_data()
{
    addServers();
}

void TestInteropWebDav::names()
{
    QFETCH(QString, server);
    if (!configured(server))
        QSKIP("server not started by this run");
    const auto backend = signedIn(server);
    QVERIFY(backend);
    const QString dir = fresh(QStringLiteral("names"));
    QVERIFY_OK(backend->makeDir(dir, true));
    QStringList names = { QStringLiteral("with space"), QStringLiteral("percent%25 hash# question?"),
                          QStringLiteral(".hidden"), QStringLiteral("ümlaut-ß-漢字"),
                          QStringLiteral("é-nfd"), QStringLiteral("é-nfc"),
                          QStringLiteral("plus+amp&semi;eq=") };
    // XC-4b: NFD stays NFD, next to its NFC twin; Nextcloud itself
    // normalises names to NFC, and refuses some characters.
    if (server == QLatin1String("nextcloud"))
        names.removeAll(QString::fromUtf8("e\xcc\x81-nfd"));
    else
        names << QStringLiteral("quote'\"<>");
    // Non-UTF-8 bytes survive on a POSIX file system (rclone normalises them).
    if (server.startsWith(QLatin1String("apache")))
        names << Names::decode("latin1-\xe9");
    for (const QString &name : names) {
        QByteArray content = Names::encode(name);
        QBuffer source(&content);
        source.open(QIODevice::ReadOnly);
        const Result r = backend->upload(&source, dir + QLatin1Char('/') + name, UploadOptions(), nullptr);
        QVERIFY2(r.ok(), qPrintable(name + QStringLiteral(": ") + r.toString()));
    }
    QVector<Entry> entries;
    QVERIFY_OK(backend->list(dir, &entries));
    QStringList listed;
    for (const Entry &e : entries) {
        listed << e.name;
        QCOMPARE(e.flags.testFlag(EntryFlag::NameNotUtf8), Names::hasEscapes(e.name));
        // Each listed name works for stat and read.
        QByteArray out;
        QVERIFY2(backend->read(dir + QLatin1Char('/') + e.name, 0, -1, &out).ok(), qPrintable(e.name));
        QCOMPARE(out, Names::encode(e.name));
    }
    listed.sort();
    names.sort();
    QCOMPARE(listed, names);
    QVERIFY_OK(backend->removeTreeNative(dir));
}

void TestInteropWebDav::renameAndCopy_data()
{
    addServers();
}

void TestInteropWebDav::renameAndCopy()
{
    QFETCH(QString, server);
    if (!configured(server))
        QSKIP("server not started by this run");
    const auto backend = signedIn(server);
    QVERIFY(backend);
    const QString dir = fresh(QStringLiteral("move"));
    QVERIFY_OK(backend->makeDir(dir, true));
    const auto put = [&](const QString &name, const QByteArray &data) {
        QByteArray copy = data;
        QBuffer source(&copy);
        source.open(QIODevice::ReadOnly);
        UploadOptions options;
        options.write.disposition = WriteOptions::Truncate;
        return backend->upload(&source, dir + QLatin1Char('/') + name, options, nullptr);
    };
    const auto content = [&](const QString &name) {
        QByteArray out;
        backend->read(dir + QLatin1Char('/') + name, 0, -1, &out);
        return out;
    };
    QVERIFY_OK(put(QStringLiteral("a"), "A"));
    QVERIFY_OK(put(QStringLiteral("b"), "B"));
    QVERIFY_OK(backend->makeDir(dir + QStringLiteral("/sub"), true));
    const QString a = dir + QStringLiteral("/a");
    const QString b = dir + QStringLiteral("/b");
    // XC-10
    QCOMPARE(backend->rename(a, b, RenameMode::NoReplace).error(), Error::AlreadyExists);
    QCOMPARE(content(QStringLiteral("b")), QByteArray("B"));
    QVERIFY_OK(backend->rename(a, b, RenameMode::Replace));
    QCOMPARE(content(QStringLiteral("b")), QByteArray("A"));
    Entry entry;
    QCOMPARE(backend->stat(a, &entry).error(), Error::NotFound);
    QCOMPARE(backend->rename(b, dir + QStringLiteral("/sub"), RenameMode::Replace).error(), Error::AlreadyExists);
    QVERIFY_OK(backend->rename(b, dir + QStringLiteral("/sub/moved"), RenameMode::NoReplace));
    QVERIFY_OK(backend->rename(dir + QStringLiteral("/sub"), dir + QStringLiteral("/renamed"), RenameMode::NoReplace));
    QVERIFY_OK(backend->stat(dir + QStringLiteral("/renamed/moved"), &entry));
    QCOMPARE(backend->rename(dir + QStringLiteral("/nothing"), a, RenameMode::NoReplace).error(), Error::NotFound);
    // XC-17
    CopyOptions recursive;
    recursive.recursive = true;
    QVERIFY_OK(backend->copy(dir + QStringLiteral("/renamed"), dir + QStringLiteral("/copy"), recursive));
    QVERIFY_OK(backend->stat(dir + QStringLiteral("/copy/moved"), &entry));
    QCOMPARE(backend->copy(dir + QStringLiteral("/renamed/moved"), dir + QStringLiteral("/copy/moved"), CopyOptions()).error(),
             Error::AlreadyExists);
    CopyOptions replace;
    replace.mode = RenameMode::Replace;
    QVERIFY_OK(put(QStringLiteral("c"), "C"));
    QVERIFY_OK(backend->copy(dir + QStringLiteral("/c"), dir + QStringLiteral("/copy/moved"), replace));
    QCOMPARE(content(QStringLiteral("copy/moved")), QByteArray("C"));
    QVERIFY_OK(backend->removeTreeNative(dir));
}

void TestInteropWebDav::handles_data()
{
    addServers();
}

void TestInteropWebDav::handles()
{
    QFETCH(QString, server);
    if (!configured(server))
        QSKIP("server not started by this run");
    const auto backend = signedIn(server);
    QVERIFY(backend);
    const QString dir = fresh(QStringLiteral("handles"));
    QVERIFY_OK(backend->makeDir(dir, true));
    const QString file = dir + QStringLiteral("/h.bin");
    const QByteArray data = pseudoRandom(5 << 20, 11);

    // Streamed write, chunked (no size known).
    WriteHandle *rawWriter = nullptr;
    QVERIFY_OK(backend->openWrite(file, WriteOptions(), &rawWriter));
    std::unique_ptr<WriteHandle> writer(rawWriter);
    for (int offset = 0; offset < data.size(); offset += 100000) {
        const int n = qMin(100000, data.size() - offset);
        QVERIFY_OK(writer->write(data.constData() + offset, n));
    }
    QVERIFY_OK(writer->commit());
    // CreateNew on the existing file (If-None-Match: *): refused at open
    // when the server checks before 100 Continue, else at commit.
    const Result conflict = backend->openWrite(file, WriteOptions(), &rawWriter);
    std::unique_ptr<WriteHandle> second(rawWriter);
    if (conflict.ok())
        QCOMPARE(second->commit().error(), Error::AlreadyExists);
    else
        QCOMPARE(conflict.error(), Error::AlreadyExists);

    // Ranged reads (W-9)
    ReadHandle *rawReader = nullptr;
    QVERIFY_OK(backend->openRead(file, &rawReader));
    std::unique_ptr<ReadHandle> reader(rawReader);
    QCOMPARE(reader->size(), qint64(data.size()));
    QByteArray out;
    for (const qint64 offset : { qint64(0), qint64(12345), qint64(data.size() - 100), qint64(3 << 20) }) {
        QVERIFY_OK(reader->read(offset, 65536, &out));
        QCOMPARE(out, data.mid(int(offset), 65536));
    }
    QVERIFY_OK(reader->read(data.size(), 10, &out));
    QVERIFY(out.isEmpty());
    QVERIFY(backend->capabilities().has(Capability::EfficientRanges));
    QVERIFY_OK(reader->close());

    // Ranged download
    BufferSink sink;
    DownloadOptions range;
    range.offset = 1000;
    range.length = 2000;
    QVERIFY_OK(backend->download(file, &sink, range, nullptr));
    QCOMPARE(sink.data(), data.mid(1000, 2000));

    // Resume where the server offers it (sabre/dav), Unsupported elsewhere.
    WriteOptions resume;
    resume.disposition = WriteOptions::Resume;
    resume.resumeOffset = data.size();
    const Result r = backend->openWrite(file, resume, &rawWriter);
    std::unique_ptr<WriteHandle> resumed(rawWriter);
    if (backend->capabilities().has(Capability::WriteResume))
        QVERIFY_OK(r);
    else
        QCOMPARE(r.error(), Error::Unsupported);
    QVERIFY_OK(backend->removeTreeNative(dir));
}

void TestInteropWebDav::errors_data()
{
    addServers();
}

void TestInteropWebDav::errors()
{
    QFETCH(QString, server);
    if (!configured(server))
        QSKIP("server not started by this run");
    const auto backend = signedIn(server);
    QVERIFY(backend);
    const QString dir = fresh(QStringLiteral("errors"));
    QVERIFY_OK(backend->makeDir(dir, true));
    QVERIFY_OK(backend->makeDir(dir + QStringLiteral("/full"), true));
    QByteArray data("x");
    QBuffer source(&data);
    source.open(QIODevice::ReadOnly);
    QVERIFY_OK(backend->upload(&source, dir + QStringLiteral("/full/f"), UploadOptions(), nullptr));
    source.seek(0);
    QCOMPARE(backend->upload(&source, dir + QStringLiteral("/full/f"), UploadOptions(), nullptr).error(),
             Error::AlreadyExists);
    source.seek(0);
    QCOMPARE(backend->upload(&source, dir + QStringLiteral("/missing/f"), UploadOptions(), nullptr).error(),
             Error::NotFound);

    Entry entry;
    QCOMPARE(backend->stat(dir + QStringLiteral("/none"), &entry).error(), Error::NotFound);
    QCOMPARE(backend->makeDir(dir + QStringLiteral("/none/sub"), true).error(), Error::NotFound);
    QCOMPARE(backend->removeFile(dir + QStringLiteral("/full")).error(), Error::IsADirectory);
    QCOMPARE(backend->removeDir(dir + QStringLiteral("/full")).error(), Error::DirectoryNotEmpty);
    QCOMPARE(backend->removeDir(dir + QStringLiteral("/full/f")).error(), Error::NotADirectory);
    QCOMPARE(backend->removeFile(dir + QStringLiteral("/none")).error(), Error::NotFound);
    ReadHandle *raw = nullptr;
    QCOMPARE(backend->openRead(dir + QStringLiteral("/full"), &raw).error(), Error::IsADirectory);
    BufferSink sink;
    QCOMPARE(backend->download(dir + QStringLiteral("/none"), &sink, DownloadOptions(), nullptr).error(),
             Error::NotFound);
    QVERIFY_OK(backend->removeFile(dir + QStringLiteral("/full/f")));
    QVERIFY_OK(backend->removeDir(dir + QStringLiteral("/full")));
    QVERIFY_OK(backend->removeDir(dir));
    AttributeChanges changes;
    changes.mode = 0644;
    QCOMPARE(backend->setAttributes(QString(), changes).error(), Error::Unsupported);
}

void TestInteropWebDav::bigTransfer_data()
{
    QTest::addColumn<QString>("server");
    QTest::newRow("apache-ca (HTTP/2)") << QStringLiteral("apache-ca");
    QTest::newRow("apache-http") << QStringLiteral("apache-http");
    QTest::newRow("rclone") << QStringLiteral("rclone");
}

void TestInteropWebDav::bigTransfer()
{
    QFETCH(QString, server);
    if (!configured(server))
        QSKIP("server not started by this run");
    const auto backend = signedIn(server);
    QVERIFY(backend);
    const QByteArray data = pseudoRandom(BigSize, 3);
    QBuffer source;
    source.setData(data);
    source.open(QIODevice::ReadOnly);
    const QString file = fresh(QStringLiteral("big"));
    class Last : public Progress
    {
    public:
        void update(qint64 done, qint64) override { last = done; }
        qint64 last = 0;
    } progress;
    QVERIFY_OK(backend->upload(&source, file, UploadOptions(), &progress));
    QCOMPARE(progress.last, BigSize);
    BufferSink sink;
    QVERIFY_OK(backend->download(file, &sink, DownloadOptions(), &progress));
    QCOMPARE(QCryptographicHash::hash(sink.data(), QCryptographicHash::Sha256),
             QCryptographicHash::hash(data, QCryptographicHash::Sha256));
    QVERIFY_OK(backend->removeFile(file));
}

void TestInteropWebDav::streamingListing()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    // XC-6: 600 members arrive in batches.
    const auto backend = signedIn(QStringLiteral("apache-http"));
    QVERIFY(backend);
    const QString dir = fresh(QStringLiteral("many"));
    QVERIFY_OK(backend->makeDir(dir, true));
    for (int i = 0; i < 600; ++i)
        QVERIFY_OK(backend->makeDir(dir + QStringLiteral("/d%1").arg(i), true));
    Recorder recorder;
    ListOptions options;
    options.batchSize = 100;
    QVERIFY_OK(backend->list(dir, &recorder, options));
    QCOMPARE(recorder.all.size(), 600);
    QCOMPARE(recorder.batches, 6);
    QVERIFY_OK(backend->removeTreeNative(dir));
}

void TestInteropWebDav::nextcloudFlavor()
{
    // W-11: X-OC-MTime at upload, oc:* properties.
    if (!configured(QStringLiteral("nextcloud")))
        QSKIP("Nextcloud runs in the nightly job (nextcloud.sh)");
    const auto backend = signedIn(QStringLiteral("nextcloud"));
    QVERIFY(backend);
    const Capabilities caps = backend->capabilities();
    QVERIFY(caps.has(Capability::SetModifiedOnUpload));
    QVERIFY(caps.has(Capability::Checksums));
    QByteArray data("nextcloud");
    QBuffer source(&data);
    source.open(QIODevice::ReadOnly);
    UploadOptions options;
    options.write.modified = QDateTime(QDate(2021, 3, 4), QTime(5, 6, 7), Qt::UTC);
    const QString file = fresh(QStringLiteral("mtime"));
    QVERIFY_OK(backend->upload(&source, file, options, nullptr));
    Entry entry;
    QVERIFY_OK(backend->stat(file, &entry));
    QCOMPARE(entry.modified, options.write.modified);
    QVERIFY(!entry.extra.value(QStringLiteral("oc:fileid")).toString().isEmpty());
    QVERIFY(entry.extra.value(QStringLiteral("oc:permissions")).toString().contains(QLatin1Char('W')));
    QVERIFY(!entry.flags.testFlag(EntryFlag::ReadOnly));
    QVERIFY_OK(backend->removeFile(file));
}

void TestInteropWebDav::noSpace()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    ConnectionParams p = params(QStringLiteral("apache-http"));
    p.options.insert(QStringLiteral("base_path"), QStringLiteral("/small"));
    WebDavBackend backend;
    QVERIFY_OK(establish(&backend, p, credentials()));
    QBuffer source;
    source.setData(pseudoRandom(3 << 20, 5));
    source.open(QIODevice::ReadOnly);
    const Result r = backend.upload(&source, QStringLiteral("too-big"), UploadOptions(), nullptr);
    QCOMPARE(r.error(), Error::NoSpace);
}

// --------------------------------------------------------------- cancel

void TestInteropWebDav::cancel_data()
{
    QTest::addColumn<QString>("operation");
    for (const char *name : { "connect", "authenticate", "stat", "list", "mkdir", "rename", "download", "upload",
                              "read", "write", "keepAlive", "copy" })
        QTest::newRow(name) << QString::fromLatin1(name);
}

void TestInteropWebDav::cancel()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    // C-9 under a stalling proxy (XT-1): every blocking call returns
    // Canceled within 2 s of cancel().
    QFETCH(QString, operation);
    StallProxy proxy;
    QVERIFY(proxy.start(m_config.value(QStringLiteral("apache")).toObject().value(QStringLiteral("http")).toInt()));
    ConnectionParams p = params(QStringLiteral("apache-http"));
    p.port = proxy.port;
    WebDavBackend backend;
    const QString dir = fresh(QStringLiteral("cancel"));
    std::unique_ptr<ReadHandle> reader;
    std::unique_ptr<WriteHandle> writer;
    if (operation != QLatin1String("connect")) {
        QVERIFY_OK(backend.connect(p, nullptr));
        if (operation != QLatin1String("authenticate")) {
            QVERIFY_OK(backend.authenticate(credentials()));
            QVERIFY_OK(backend.makeDir(dir, true));
            QByteArray data(100000, 'r');
            QBuffer source(&data);
            source.open(QIODevice::ReadOnly);
            QVERIFY_OK(backend.upload(&source, dir + QStringLiteral("/f"), UploadOptions(), nullptr));
        }
    }
    if (operation == QLatin1String("read")) {
        ReadHandle *raw = nullptr;
        QVERIFY_OK(backend.openRead(dir + QStringLiteral("/f"), &raw));
        reader.reset(raw);
    }
    if (operation == QLatin1String("write")) {
        WriteHandle *raw = nullptr;
        QVERIFY_OK(backend.openWrite(dir + QStringLiteral("/w"), WriteOptions(), &raw));
        writer.reset(raw);
    }
    const QByteArray big = pseudoRandom(64 << 20, 1);
    QBuffer bigSource;
    bigSource.setData(big);
    bigSource.open(QIODevice::ReadOnly);
    BufferSink sink;
    std::function<Result()> call;
    if (operation == QLatin1String("connect"))
        call = [&] { return backend.connect(p, nullptr); };
    else if (operation == QLatin1String("authenticate"))
        call = [&] { return backend.authenticate(credentials()); };
    else if (operation == QLatin1String("stat"))
        call = [&] { Entry e; return backend.stat(dir + QStringLiteral("/f"), &e); };
    else if (operation == QLatin1String("list"))
        call = [&] { QVector<Entry> e; return backend.list(dir, &e); };
    else if (operation == QLatin1String("mkdir"))
        call = [&] { return backend.makeDir(dir + QStringLiteral("/m"), true); };
    else if (operation == QLatin1String("rename"))
        call = [&] { return backend.rename(dir + QStringLiteral("/f"), dir + QStringLiteral("/g"), RenameMode::NoReplace); };
    else if (operation == QLatin1String("download"))
        call = [&] { return backend.download(dir + QStringLiteral("/f"), &sink, DownloadOptions(), nullptr); };
    else if (operation == QLatin1String("upload"))
        call = [&] { return backend.upload(&bigSource, dir + QStringLiteral("/u"), UploadOptions(), nullptr); };
    else if (operation == QLatin1String("read"))
        call = [&] { QByteArray out; return reader->read(0, 1000, &out); };
    else if (operation == QLatin1String("write"))
        call = [&] {
            for (int i = 0; i < 64; ++i) {
                const Result r = writer->write(big.constData() + (i << 20), 1 << 20);
                if (!r.ok())
                    return r;
            }
            return writer->commit();
        };
    else if (operation == QLatin1String("keepAlive"))
        call = [&] { return backend.keepAlive(); };
    else
        call = [&] { return backend.copy(dir + QStringLiteral("/f"), dir + QStringLiteral("/c"), CopyOptions()); };

    QVERIFY(proxy.command("stall"));
    std::thread canceller([&backend] {
        std::this_thread::sleep_for(std::chrono::milliseconds(CancelDelayMs));
        backend.cancel();
    });
    QElapsedTimer timer;
    timer.start();
    const Result r = call();
    const qint64 late = timer.elapsed() - CancelDelayMs;
    canceller.join();
    QCOMPARE(r.error(), Error::Canceled);
    QVERIFY2(late < CancelLimitMs, qPrintable(QString::number(late)));
    QVERIFY(proxy.command("flow"));
    backend.resetCancel();
    reader.reset();
    writer.reset();
    if (operation != QLatin1String("connect") && operation != QLatin1String("authenticate")) {
        // The backend is usable again after resetCancel(). (The proxy still
        // delivers the held request, so a canceled MOVE may happen.)
        Entry entry;
        QVERIFY_OK(backend.stat(dir, &entry));
        QVERIFY_OK(backend.removeTreeNative(dir));
    }
}

void TestInteropWebDav::stallTimesOut()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    StallProxy proxy;
    QVERIFY(proxy.start(m_config.value(QStringLiteral("apache")).toObject().value(QStringLiteral("http")).toInt()));
    ConnectionParams p = params(QStringLiteral("apache-http"));
    p.port = proxy.port;
    p.requestTimeoutMs = 2000;
    WebDavBackend backend;
    QVERIFY_OK(establish(&backend, p, credentials()));
    QVERIFY(proxy.command("stall"));
    QElapsedTimer timer;
    timer.start();
    Entry entry;
    QCOMPARE(backend.stat(QString(), &entry).error(), Error::Timeout);
    QVERIFY(timer.elapsed() < 10000);
    QVERIFY(proxy.command("flow"));
}

void TestInteropWebDav::connectionDrop()
{
    if (!configured(QStringLiteral("apache")))
        QSKIP("Apache not started by this run");
    StallProxy proxy;
    QVERIFY(proxy.start(m_config.value(QStringLiteral("apache")).toObject().value(QStringLiteral("http")).toInt()));
    ConnectionParams p = params(QStringLiteral("apache-http"));
    p.port = proxy.port;
    WebDavBackend backend;
    QVERIFY_OK(establish(&backend, p, credentials()));
    const QString file = fresh(QStringLiteral("drop"));
    QBuffer source;
    source.setData(pseudoRandom(8 << 20, 9));
    source.open(QIODevice::ReadOnly);
    QVERIFY_OK(backend.upload(&source, file, UploadOptions(), nullptr));
    // Drop the connection in the middle of a download.
    class Dropper : public Progress
    {
    public:
        explicit Dropper(StallProxy *proxy) : m_proxy(proxy) {}
        void update(qint64 done, qint64) override
        {
            if (!m_dropped && done > (1 << 20)) {
                m_dropped = true;
                m_proxy->command("drop");
            }
        }

    private:
        StallProxy *m_proxy;
        bool m_dropped = false;
    } dropper(&proxy);
    BufferSink sink;
    QCOMPARE(backend.download(file, &sink, DownloadOptions(), &dropper).error(), Error::ConnectionLost);
    // HTTP reconnects by itself for the next request.
    QVERIFY_OK(backend.removeFile(file));
}

QTEST_GUILESS_MAIN(TestInteropWebDav)
#include "tst_interop_webdav.moc"
