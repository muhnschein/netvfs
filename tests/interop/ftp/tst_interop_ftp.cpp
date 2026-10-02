// SPDX-License-Identifier: LGPL-2.1-or-later
// FTP/FTPS interoperability (SPEC-v2 6.4, XT-1, XT-2, XT-5) against the
// vsftpd and pure-ftpd containers started by run.sh, which passes their
// ports and the test password in the JSON file named by
// NETVFS_FTP_INTEROP_CONFIG. ftpstall.py provides the recording fake server
// (identity tests) and the stalling proxy (cancel and timeout tests).
#include "backendloader.h"
#include "ftpbackend.h"
#include "identity.h"
#include "names.h"
#include "paths.h"
#include "transfer.h"

#include <QtConcurrent/QtConcurrent>
#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QElapsedTimer>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QProcess>
#include <QtCore/QTemporaryDir>
#include <QtCore/QUuid>
#include <QtTest/QtTest>

#include <csignal>
#include <functional>
#include <memory>

using namespace NetVfs;

namespace QTest {
template<>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest

namespace {

constexpr qint64 FileSize = 3 * 1024 * 1024 + 4321;
constexpr qint64 CancelBoundMs = 2000;   // C-9
constexpr int CancelDelayMs = 700;
const char *const Provider = "ftp";

QString unique(const QString &prefix)
{
    return prefix + QUuid::createUuid().toString().mid(1, 8);
}

QByteArray sha256(const QByteArray &data)
{
    return QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex();
}

// A helper process from ftpstall.py; the first line it prints is its port.
class Helper
{
public:
    Helper(const QString &script, const QStringList &arguments)
    {
        m_process.setProcessChannelMode(QProcess::ForwardedErrorChannel);
        m_process.start(QStringLiteral("python3"), QStringList() << script << arguments);
        if (m_process.waitForStarted(10000) && m_process.waitForReadyRead(10000))
            m_port = m_process.readLine().trimmed().toInt();
    }
    ~Helper()
    {
        m_process.kill();
        m_process.waitForFinished(5000);
    }
    Helper(const Helper &) = delete;
    Helper &operator=(const Helper &) = delete;

    int port() const { return m_port; }
    void signal(int number) const { ::kill(pid_t(m_process.processId()), number); }

private:
    QProcess m_process;
    int m_port = 0;
};

class Collector : public ListSink
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

const Entry *findEntry(const QVector<Entry> &entries, const QString &name)
{
    for (const Entry &entry : entries) {
        if (entry.name == name)
            return &entry;
    }
    return nullptr;
}

} // namespace

class TestInteropFtp : public QObject
{
    Q_OBJECT

private:
    QJsonObject m_servers;
    QByteArray m_password;
    QString m_certs;
    QString m_proxy;
    QTemporaryDir m_tmp;
    QByteArray m_data;

    QJsonObject server(const QString &name) const { return m_servers.value(name).toObject(); }

    ConnectionParams params(const QString &name) const
    {
        const QJsonObject s = server(name);
        ConnectionParams p;
        p.provider = QLatin1String(Provider);
        p.host = QStringLiteral("127.0.0.1");
        p.port = s.value(QStringLiteral("port")).toInt();
        p.username = QStringLiteral("alice");
        p.options.insert(QStringLiteral("tls_mode"), s.value(QStringLiteral("tls")).toString());
        if (s.value(QStringLiteral("tls")).toString() == QLatin1String("none"))
            p.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
        p.options.insert(QStringLiteral("test_ca_file"), m_certs + QStringLiteral("/ca.crt"));
        p.connectTimeoutMs = 10000;
        p.requestTimeoutMs = 20000;
        return p;
    }

    // The backend compiled in with the test CA hook (see ftp.pro).
    static std::unique_ptr<Backend> create()
    {
        return std::unique_ptr<Backend>(Ftp::createFtpBackend());
    }

    // The identity a first connection reports (account creation).
    ServerIdentity identify(const ConnectionParams &p) const
    {
        const std::unique_ptr<Backend> b = create();
        ServerIdentity seen;
        const Result r = b->connect(p, &seen);
        if (!r.ok())
            qWarning() << "identify failed:" << r.toString();
        return seen;
    }

    // Pins the certificate unless the system trusts it, then signs in.
    std::unique_ptr<Backend> signedIn(const QString &name, ConnectionParams *used = nullptr) const
    {
        ConnectionParams p = params(name);
        const ServerIdentity seen = identify(p);
        if (!seen.isEmpty() && !seen.systemTrusted)
            p.options.insert(QStringLiteral("host_key"), seen.toPin());
        std::unique_ptr<Backend> b = create();
        const Result r = establish(b.get(), p, Credentials(p.username, m_password));
        if (!r.ok()) {
            qWarning() << "sign-in failed:" << r.toString();
            return nullptr;
        }
        if (used)
            *used = p;
        return b;
    }

    QByteArray exec(const QString &name, const QString &script, const QStringList &env = QStringList()) const
    {
        QStringList arguments { QStringLiteral("exec") };
        for (const QString &variable : env)
            arguments << QStringLiteral("-e") << variable;
        arguments << server(name).value(QStringLiteral("container")).toString() << QStringLiteral("sh")
                  << QStringLiteral("-c") << script;
        QProcess process;
        process.start(QStringLiteral("docker"), arguments);
        process.waitForFinished(120000);
        if (process.exitCode() != 0)
            qWarning() << "docker exec failed:" << script << process.readAllStandardError();
        return process.readAllStandardOutput();
    }

    QString home(const QString &name) const { return server(name).value(QStringLiteral("home")).toString(); }

    QString serverMode(const QString &name, const QString &relative) const
    {
        return QString::fromLatin1(exec(name, QStringLiteral("stat -c %a \"$P\""),
                                        { QStringLiteral("P=") + home(name) + QLatin1Char('/') + relative }))
            .trimmed();
    }

    QByteArray serverSha(const QString &name, const QString &relative) const
    {
        return exec(name, QStringLiteral("sha256sum \"$P\""),
                    { QStringLiteral("P=") + home(name) + QLatin1Char('/') + relative })
            .split(' ')
            .value(0);
    }

    // Owner of the files the FTP user creates (vsftpd: alice, pure-ftpd: the
    // virtual user's system account).
    static QString owner(const QString &name)
    {
        return name.startsWith(QLatin1String("pureftpd")) ? QStringLiteral("ftpuser") : QStringLiteral("alice");
    }

    Result put(Backend *b, const QString &path, const QByteArray &data, const WriteOptions &write = WriteOptions())
    {
        QBuffer source;
        source.setData(data);
        source.open(QIODevice::ReadOnly);
        UploadOptions options;
        options.write = write;
        if (options.write.disposition == WriteOptions::CreateNew)
            options.write.disposition = WriteOptions::Truncate;
        return b->upload(&source, path, options, nullptr);
    }

    QByteArray get(Backend *b, const QString &path, Result *result = nullptr,
                   const DownloadOptions &options = DownloadOptions())
    {
        QBuffer sink;
        sink.open(QIODevice::WriteOnly);
        const Result r = b->download(path, &sink, options, nullptr);
        if (result)
            *result = r;
        return sink.data();
    }

    // Runs `work` on another thread, cancels after CancelDelayMs, returns the
    // milliseconds between cancel() and the end of `work`.
    qint64 cancelDuring(Backend *b, const std::function<Result()> &work, Result *out)
    {
        QFuture<Result> future = QtConcurrent::run([work]() { return work(); });
        QThread::msleep(CancelDelayMs);
        QElapsedTimer timer;
        timer.start();
        b->cancel();
        future.waitForFinished();
        const qint64 ms = timer.elapsed();
        *out = future.result();
        b->resetCancel();
        return ms;
    }

    void tlsServers()
    {
        QTest::addColumn<QString>("name");
        QTest::newRow("vsftpd explicit (LIST, trusted)") << QStringLiteral("vsftpd");
        QTest::newRow("vsftpd implicit (LIST, pinned)") << QStringLiteral("vsftpd-implicit");
        QTest::newRow("pure-ftpd explicit (MLSD, pinned)") << QStringLiteral("pureftpd");
    }

    void allServers()
    {
        tlsServers();
        QTest::newRow("vsftpd plain") << QStringLiteral("vsftpd-plain");
    }

    // ftpstall.py fake: a recording FTP server with `cert`.
    std::unique_ptr<Helper> fakeServer(const QString &tls, const QString &cert, const QString &log,
                                       const QStringList &extra = QStringList()) const
    {
        QStringList arguments { QStringLiteral("fake"), QStringLiteral("--tls"), tls, QStringLiteral("--log"), log };
        arguments << extra;
        if (!cert.isEmpty()) {
            arguments << QStringLiteral("--cert") << m_certs + QLatin1Char('/') + cert + QStringLiteral(".crt")
                      << QStringLiteral("--key") << m_certs + QLatin1Char('/') + cert + QStringLiteral(".key");
        }
        return std::unique_ptr<Helper>(new Helper(m_proxy, arguments));
    }

    static QStringList recorded(const QString &log)
    {
        QFile file(log);
        if (!file.open(QIODevice::ReadOnly))
            return QStringList();
        return QString::fromUtf8(file.readAll()).split(QLatin1Char('\n'), NETVFS_SKIP_EMPTY_PARTS);
    }

    static bool sentUser(const QStringList &lines)
    {
        for (const QString &line : lines) {
            if (line.startsWith(QLatin1String("C: USER")) || line.startsWith(QLatin1String("C: PASS")))
                return true;
        }
        return false;
    }

    ConnectionParams fakeParams(int port, const QString &tls) const
    {
        ConnectionParams p;
        p.provider = QLatin1String(Provider);
        p.host = QStringLiteral("127.0.0.1");
        p.port = port;
        p.username = QStringLiteral("alice");
        p.options.insert(QStringLiteral("tls_mode"), tls);
        p.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
        p.options.insert(QStringLiteral("test_ca_file"), m_certs + QStringLiteral("/ca.crt"));
        p.connectTimeoutMs = 5000;
        p.requestTimeoutMs = 5000;
        return p;
    }

    // Sessions of the vsftpd instance with `config` that the server has not
    // retired yet (children of its listener process).
    int serverSessions(const QString &name, const QString &config) const
    {
        const QByteArray out = exec(name,
                                    QStringLiteral("l=$(ps -eo pid=,ppid=,args= | awk -v c=\"$C\" '$2 == 1 && index($0, c) "
                                                   "{print $1}'); ps -eo ppid= | awk -v l=\"$l\" '$1 == l' | wc -l"),
                                    { QStringLiteral("C=") + config })
                                   .trimmed();
        return out.isEmpty() ? -1 : out.toInt();
    }

    // Waits until the server has no session left (polling, no fixed sleep).
    bool waitIdle(const QString &name, const QString &config) const
    {
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < 30000) {
            if (serverSessions(name, config) == 0)
                return true;
            QThread::msleep(100);
        }
        return false;
    }

private slots:
    void initTestCase()
    {
        QFile config(QString::fromLocal8Bit(qgetenv("NETVFS_FTP_INTEROP_CONFIG")));
        QVERIFY2(config.open(QIODevice::ReadOnly), "run this test through tests/interop/ftp/run.sh");
        const QJsonObject root = QJsonDocument::fromJson(config.readAll()).object();
        m_servers = root.value(QStringLiteral("servers")).toObject();
        m_password = root.value(QStringLiteral("password")).toString().toUtf8();
        m_certs = root.value(QStringLiteral("certs")).toString();
        m_proxy = root.value(QStringLiteral("proxy")).toString();
        QVERIFY(!m_servers.isEmpty());
        QVERIFY(m_tmp.isValid());
        m_data.resize(int(FileSize));
        for (int i = 0; i < m_data.size(); ++i)
            m_data[i] = char((uint(i) * 7919u + (uint(i) >> 9)) & 0xFFu);
        QVERIFY(BackendLoader::isAvailable(QLatin1String(Provider)));
    }

    // ---------------------------------------------------------------- XT-5

    void identityBeforeUser_data()
    {
        QTest::addColumn<QString>("tls");
        QTest::newRow("explicit") << QStringLiteral("explicit");
        QTest::newRow("implicit") << QStringLiteral("implicit");
    }

    // C-7 / F-2 / XSEC-1: the recording server proves that no USER (or any
    // command but AUTH TLS) is sent before the identity is accepted.
    void identityBeforeUser()
    {
        QFETCH(QString, tls);
        const QString log = m_tmp.filePath(unique(QStringLiteral("fake-")));
        const auto fake = fakeServer(tls, QStringLiteral("selfsigned"), log);
        QVERIFY(fake->port() > 0);
        const ConnectionParams p = fakeParams(fake->port(), tls);

        // connect(): the certificate, and nothing after the handshake.
        std::unique_ptr<Backend> b = create();
        ServerIdentity seen;
        Result r = b->connect(p, &seen);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(seen.kind, ServerIdentity::Kind::TlsCertificate);
        QCOMPARE(seen.algorithm, QStringLiteral("tls-spki-sha256"));
        QVERIFY(!seen.systemTrusted);
        QVERIFY(seen.problems & ServerIdentity::SelfSigned);
        QCOMPARE(seen.details.value(QStringLiteral("subject")).toString(), QStringLiteral("CN=selfsigned.test"));
        b->disconnect();
        QTRY_VERIFY(recorded(log).contains(QStringLiteral("CLOSED")) || recorded(log).join(QString()).contains(QLatin1String("TLS-FAIL")));
        QStringList lines = recorded(log);
        QVERIFY2(!sentUser(lines), qPrintable(lines.join(QLatin1Char('|'))));
        const QStringList commands = lines.filter(QRegularExpression(QStringLiteral("^C: ")));
        QCOMPARE(commands, tls == QLatin1String("explicit") ? QStringList { QStringLiteral("C: AUTH TLS") } : QStringList());
        QVERIFY(lines.contains(QStringLiteral("TLS-START")));
        QVERIFY(!lines.contains(QStringLiteral("TLS-OK")));   // the client ended the handshake

        // establish() without a pin and with a wrong pin: refused, no USER.
        b = create();
        r = establish(b.get(), p, Credentials(p.username, m_password));
        QCOMPARE(r.error(), Error::ServerIdentityUnknown);
        ConnectionParams wrong = p;
        wrong.options.insert(QStringLiteral("host_key"),
                             ServerIdentity::fromTlsSpki(QByteArray("not the server's key")).toPin());
        r = establish(b.get(), wrong, Credentials(p.username, m_password));
        QCOMPARE(r.error(), Error::ServerIdentityChanged);
        lines = recorded(log);
        QVERIFY2(!sentUser(lines), qPrintable(lines.join(QLatin1Char('|'))));

        // Positive control: with the right pin the credentials follow.
        ConnectionParams pinned = p;
        pinned.options.insert(QStringLiteral("host_key"), seen.toPin());
        r = establish(b.get(), pinned, Credentials(p.username, m_password));
        QCOMPARE(r.error(), Error::AuthFailed);   // the fake server answers 530
        QTRY_VERIFY(sentUser(recorded(log)));
        lines = recorded(log);
        const int user = lines.indexOf(QStringLiteral("C: USER alice"));
        QVERIFY(user > 0);
        QCOMPARE(lines.at(user - 1), QStringLiteral("TLS-OK"));
    }

    // Plain FTP (allow_insecure): connect() reads the greeting and sends nothing.
    void plainConnectSendsNothing()
    {
        const QString log = m_tmp.filePath(unique(QStringLiteral("fake-")));
        const auto fake = fakeServer(QStringLiteral("none"), QString(), log);
        QVERIFY(fake->port() > 0);
        const ConnectionParams p = fakeParams(fake->port(), QStringLiteral("none"));
        std::unique_ptr<Backend> b = create();
        ServerIdentity seen;
        const Result r = b->connect(p, &seen);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QVERIFY(seen.isEmpty());
        b->disconnect();
        QTRY_VERIFY(recorded(log).contains(QStringLiteral("CLOSED")));
        QCOMPARE(recorded(log), QStringList { QStringLiteral("CLOSED") });
    }

    // XC-16: a chain to a trusted anchor needs no pin and no prompt.
    void systemTrustedNeedsNoPin()
    {
        const QString log = m_tmp.filePath(unique(QStringLiteral("fake-")));
        const auto fake = fakeServer(QStringLiteral("explicit"), QStringLiteral("trusted"), log);
        const ConnectionParams p = fakeParams(fake->port(), QStringLiteral("explicit"));
        const ServerIdentity seen = identify(p);
        QVERIFY(seen.systemTrusted);
        QCOMPARE(seen.problems, 0);
        QVERIFY(seen.details.value(QStringLiteral("sans")).toStringList().contains(QStringLiteral("IP:127.0.0.1")));
        std::unique_ptr<Backend> b = create();
        const Result r = establish(b.get(), p, Credentials(p.username, m_password));
        QCOMPARE(r.error(), Error::AuthFailed);   // reached USER/PASS without a pin
        QTRY_VERIFY(sentUser(recorded(log)));

        // The real server with the CA-signed certificate.
        const ServerIdentity real = identify(params(QStringLiteral("vsftpd")));
        QVERIFY(real.systemTrusted);
        QVERIFY(signedIn(QStringLiteral("vsftpd")) != nullptr);
    }

    // W-4: pins against the real servers.
    void pins()
    {
        // A wrong pin on a real server: refused before sign-in.
        ConnectionParams p = params(QStringLiteral("pureftpd"));
        p.options.insert(QStringLiteral("host_key"), ServerIdentity::fromTlsSpki(QByteArray("other")).toPin());
        std::unique_ptr<Backend> b = create();
        QCOMPARE(establish(b.get(), p, Credentials(p.username, m_password)).error(), Error::ServerIdentityChanged);

        // authenticate() itself enforces the pin (libcurl PINNEDPUBLICKEY),
        // also when a caller skips the identity check.
        b = create();
        QVERIFY(b->connect(p, nullptr).ok());
        QCOMPARE(b->authenticate(Credentials(p.username, m_password)).error(), Error::ServerIdentityChanged);

        // tls_verify_peer on a self-signed certificate: no longer trusted.
        p = params(QStringLiteral("pureftpd"));
        p.options.insert(QStringLiteral("host_key"), identify(p).toPin());
        p.options.insert(QStringLiteral("tls_verify_peer"), QStringLiteral("true"));
        b = create();
        QCOMPARE(establish(b.get(), p, Credentials(p.username, m_password)).error(), Error::ServerIdentityChanged);

        // A pinned trusted certificate (verification and pin).
        p = params(QStringLiteral("vsftpd"));
        p.options.insert(QStringLiteral("host_key"), identify(p).toPin());
        p.options.insert(QStringLiteral("tls_verify_peer"), QStringLiteral("true"));
        b = create();
        Result r = establish(b.get(), p, Credentials(p.username, m_password));
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QVERIFY(b->keepAlive().ok());
    }

    // The shipped plugin: loads, signs in with a pin, ignores test_ca_file.
    void pluginLoads()
    {
        Result r;
        const std::unique_ptr<Backend> plugin(BackendLoader::create(QLatin1String(Provider), &r));
        QVERIFY2(plugin, qPrintable(r.toString()));
        ConnectionParams p = params(QStringLiteral("pureftpd"));
        p.options.insert(QStringLiteral("host_key"), identify(p).toPin());
        r = establish(plugin.get(), p, Credentials(p.username, m_password));
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QVector<Entry> entries;
        QVERIFY(plugin->list(QString(), &entries).ok());
        // Without the hook the test CA means nothing: the CA-signed
        // certificate is not trusted.
        ServerIdentity seen;
        const std::unique_ptr<Backend> other(BackendLoader::create(QLatin1String(Provider), &r));
        QVERIFY(other->connect(params(QStringLiteral("vsftpd")), &seen).ok());
        QVERIFY(!seen.systemTrusted);
        QVERIFY(seen.problems & ServerIdentity::UntrustedRoot);
    }

    // F-1 / XSEC-2: no plain FTP without consent, no downgrade.
    void insecureRefused()
    {
        ConnectionParams p = params(QStringLiteral("vsftpd-plain"));
        p.options.remove(QStringLiteral("allow_insecure"));
        std::unique_ptr<Backend> b = create();
        QCOMPARE(b->connect(p, nullptr).error(), Error::SecurityPolicy);
        p.options.insert(QStringLiteral("tls_mode"), QStringLiteral("whatever"));
        QCOMPARE(b->connect(p, nullptr).error(), Error::SecurityPolicy);
        // Explicit TLS against a server without AUTH TLS: no fallback.
        p.options.insert(QStringLiteral("tls_mode"), QStringLiteral("explicit"));
        QCOMPARE(b->connect(p, nullptr).error(), Error::SecurityPolicy);
    }

    void wrongPassword()
    {
        ConnectionParams p = params(QStringLiteral("vsftpd"));
        std::unique_ptr<Backend> b = create();
        const Result r = establish(b.get(), p, Credentials(p.username, "wrong"));
        QCOMPARE(r.error(), Error::AuthFailed);
    }

    // ----------------------------------------------------------- operations

    void capabilities_data() { tlsServers(); }
    void capabilities()
    {
        QFETCH(QString, name);
        const auto b = signedIn(name);
        QVERIFY(b);
        const Capabilities caps = b->capabilities();
        QVERIFY(caps.has(Capability::ReadHandles));
        QVERIFY(caps.has(Capability::EfficientRanges));
        QVERIFY(caps.has(Capability::WriteResume));
        QVERIFY(caps.has(Capability::PosixModes));
        QCOMPARE(caps.has(Capability::SetModified), name == QLatin1String("pureftpd"));
        QVERIFY(!caps.has(Capability::AtomicPut));
        QVERIFY(!caps.has(Capability::AtomicReplace));
        QVERIFY(!caps.has(Capability::NativeNoReplace));
        QVERIFY(!caps.has(Capability::SpaceInfo));
        SpaceInfo space;
        QCOMPARE(b->spaceInfo(QString(), &space).error(), Error::Unsupported);   // F-6
        QVERIFY(b->keepAlive().ok());
    }

    void roundTrip_data() { allServers(); }
    void roundTrip()
    {
        QFETCH(QString, name);
        const auto b = signedIn(name);
        QVERIFY(b);
        const QString dir = unique(QStringLiteral("rt-"));
        QVERIFY(b->makeDir(dir, true).ok());
        const QString target = Paths::join(dir, QStringLiteral("data.bin"));
        const QString local = m_tmp.filePath(unique(QStringLiteral("up-")));
        {
            QFile file(local);
            QVERIFY(file.open(QIODevice::WriteOnly));
            file.write(m_data);
        }
        Result r = Transfer::uploadFile(b.get(), local, target);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(serverSha(name, target), sha256(m_data));
        QCOMPARE(serverMode(name, target), QStringLiteral("600"));   // XC-23 createMode 0600 (backups)
        Entry entry;
        r = b->stat(target, &entry);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(entry.type, EntryType::File);
        QCOMPARE(entry.size, FileSize);
        QCOMPARE(entry.name, QStringLiteral("data.bin"));
        QVERIFY(entry.modified.isValid());
        QVERIFY(qAbs(entry.modified.secsTo(QDateTime::currentDateTimeUtc())) < 600);
        const QString back = m_tmp.filePath(unique(QStringLiteral("down-")));
        r = Transfer::downloadFile(b.get(), target, back);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QFile file(back);
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(sha256(file.readAll()), sha256(m_data));
        QVERIFY(b->stat(dir, &entry).ok());
        QCOMPARE(entry.type, EntryType::Directory);
        QVERIFY(b->stat(QString(), &entry).ok());
        QVERIFY(entry.isDir());
        QVERIFY(b->stat(QStringLiteral("/"), &entry).ok());
        QVERIFY(entry.isDir());
        QVERIFY(b->remove(target).ok());
        QVERIFY(b->removeDir(dir).ok());
        QCOMPARE(b->stat(dir, &entry).error(), Error::NotFound);
    }

    void listing_data() { tlsServers(); }
    // F-3 / XC-4 / XC-6: MLSD or LIST, odd and non-UTF-8 names, batches.
    void listing()
    {
        QFETCH(QString, name);
        const auto b = signedIn(name);
        QVERIFY(b);
        const QString dir = unique(QStringLiteral("ls-"));
        QVERIFY(b->makeDir(dir, true).ok());
        const QStringList names { QStringLiteral("plain.txt"), QStringLiteral("with space"),
                                  QStringLiteral(" leading space"), QStringLiteral(".hidden"),
                                  QStringLiteral("-dash"), QStringLiteral("semi;type=a"), QStringLiteral("glob*[x]"),
                                  QStringLiteral("100%"), QStringLiteral("Grüße ünd ½"),
                                  QStringLiteral("quote\"d") };
        for (const QString &n : names)
            QVERIFY2(put(b.get(), Paths::join(dir, n), n.toUtf8()).ok(), qPrintable(n));
        QVERIFY(b->makeDir(Paths::join(dir, QStringLiteral("sub dir")), true).ok());
        // Non-UTF-8 bytes (Latin-1 "é" and a lone 0xFF) and a symbolic link,
        // made on the server's disk.
        const QString disk = home(name) + QLatin1Char('/') + dir;
        exec(name, QStringLiteral("cd \"$D\" && printf x > \"$(printf 'caf\\351')\" && printf yy > \"$(printf 'b\\377d')\""
                                  " && ln -s plain.txt link && chown -h -- %1 ./* link").arg(owner(name)),
             { QStringLiteral("D=") + disk });

        Collector collector;
        ListOptions options;
        options.batchSize = 3;
        Result r = b->list(dir, &collector, options);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QVERIFY(collector.batches >= 4);
        QCOMPARE(collector.all.size(), names.size() + 4);
        for (const QString &n : names) {
            const Entry *e = findEntry(collector.all, n);
            QVERIFY2(e, qPrintable(n));
            QCOMPARE(e->type, EntryType::File);
            QCOMPARE(e->size, qint64(n.toUtf8().size()));
            QVERIFY(!(e->flags & EntryFlag::NameNotUtf8));
            QVERIFY(e->modified.isValid());
            QVERIFY(qAbs(e->modified.secsTo(QDateTime::currentDateTimeUtc())) < 24 * 3600);
        }
        const Entry *sub = findEntry(collector.all, QStringLiteral("sub dir"));
        QVERIFY(sub && sub->type == EntryType::Directory);
        const QString latin = Names::decode(QByteArray("caf\xe9"));
        const Entry *cafe = findEntry(collector.all, latin);
        QVERIFY(cafe);
        QVERIFY(cafe->flags & EntryFlag::NameNotUtf8);
        QCOMPARE(cafe->size, qint64(1));
        const QString ff = Names::decode(QByteArray("b\xff" "d"));
        QVERIFY(findEntry(collector.all, ff));
        const Entry *link = findEntry(collector.all, QStringLiteral("link"));
        QVERIFY(link);
        if (name == QLatin1String("pureftpd"))
            QVERIFY(link->type == EntryType::File || link->type == EntryType::Symlink);   // MLSD follows
        else
            QCOMPARE(link->type, EntryType::Symlink);
        // LIST timestamps are server-local and flagged (F-3).
        QCOMPARE(collector.all.first().extra.value(QStringLiteral("timeApproximate")).toBool(),
                 name != QLatin1String("pureftpd"));
        if (name == QLatin1String("pureftpd"))
            QCOMPARE(findEntry(collector.all, QStringLiteral("plain.txt"))->mode, 0644);

        // Lossless names: the non-UTF-8 entries can be read, renamed, removed.
        Entry entry;
        QVERIFY(b->stat(Paths::join(dir, latin), &entry).ok());
        QCOMPARE(entry.name, latin);
        QVERIFY(entry.flags & EntryFlag::NameNotUtf8);
        QCOMPARE(get(b.get(), Paths::join(dir, latin)), QByteArray("x"));
        const QString renamed = Names::decode(QByteArray("ren\xe9"));
        r = b->rename(Paths::join(dir, latin), Paths::join(dir, renamed), RenameMode::NoReplace);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(exec(name, QStringLiteral("ls \"$D\" | grep -c \"$(printf 'ren\\351')\""), { QStringLiteral("D=") + disk }).trimmed(),
                 QByteArray("1"));
        QVERIFY(b->removeFile(Paths::join(dir, renamed)).ok());
        QVERIFY(b->removeFile(Paths::join(dir, ff)).ok());
        // Other names round-trip through stat and download.
        for (const QString &n : names) {
            QVERIFY2(b->stat(Paths::join(dir, n), &entry).ok(), qPrintable(n));
            QCOMPARE(get(b.get(), Paths::join(dir, n)), n.toUtf8());
        }
        exec(name, QStringLiteral("rm -rf \"$D\""), { QStringLiteral("D=") + disk });
    }

    // XC-6: 2000 entries in batches, and a sink that stops early.
    void largeListing()
    {
        const auto b = signedIn(QStringLiteral("vsftpd"));
        QVERIFY(b);
        const QString dir = unique(QStringLiteral("many-"));
        QVERIFY(b->makeDir(dir, true).ok());
        exec(QStringLiteral("vsftpd"), QStringLiteral("cd \"$D\" && for i in $(seq 1 2000); do : > f$i; done && chown alice *"),
             { QStringLiteral("D=") + home(QStringLiteral("vsftpd")) + QLatin1Char('/') + dir });
        Collector collector;
        ListOptions options;
        options.batchSize = 256;
        QVERIFY(b->list(dir, &collector, options).ok());
        QCOMPARE(collector.all.size(), 2000);
        QVERIFY(collector.batches >= 8);

        struct Stopper : ListSink {
            bool entries(const QVector<Entry> &) override { return false; }
        } stopper;
        QCOMPARE(b->list(dir, &stopper, options).error(), Error::Canceled);
        Entry entry;
        QVERIFY(b->stat(dir, &entry).ok());   // the connection recovers
    }

    void namespaceOps_data() { tlsServers(); }
    // XC-8..XC-10 and the F-7 mapping through real replies.
    void namespaceOps()
    {
        QFETCH(QString, name);
        const auto b = signedIn(name);
        QVERIFY(b);
        const QString dir = unique(QStringLiteral("ns-"));
        QVERIFY(b->makeDir(dir, true).ok());
        QCOMPARE(b->makeDir(dir, true).error(), Error::AlreadyExists);
        QVERIFY(b->makeDir(dir, false).ok());
        QCOMPARE(b->makeDir(Paths::join(dir, QStringLiteral("missing/child")), false).error(), Error::NotFound);
        const QString file = Paths::join(dir, QStringLiteral("file"));
        QVERIFY(put(b.get(), file, "one").ok());
        QCOMPARE(b->makeDir(file, false).error(), Error::AlreadyExists);
        QCOMPARE(b->makeDir(Paths::join(file, QStringLiteral("x")), false).error(), Error::NotADirectory);
        QCOMPARE(b->removeFile(dir).error(), Error::IsADirectory);
        QCOMPARE(b->removeDir(file).error(), Error::NotADirectory);
        QCOMPARE(b->removeDir(dir).error(), Error::DirectoryNotEmpty);
        QCOMPARE(b->removeFile(Paths::join(dir, QStringLiteral("nope"))).error(), Error::NotFound);
        QCOMPARE(b->removeDir(Paths::join(dir, QStringLiteral("nope"))).error(), Error::NotFound);
        QVector<Entry> entries;
        QCOMPARE(b->list(file, &entries).error(), Error::NotADirectory);
        QCOMPARE(b->list(Paths::join(dir, QStringLiteral("nope")), &entries).error(), Error::NotFound);

        // Rename modes.
        const QString other = Paths::join(dir, QStringLiteral("other"));
        QVERIFY(put(b.get(), other, "two").ok());
        QCOMPARE(b->rename(file, other, RenameMode::NoReplace).error(), Error::AlreadyExists);
        QCOMPARE(get(b.get(), other), QByteArray("two"));
        Result r = b->rename(file, other, RenameMode::Replace);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(get(b.get(), other), QByteArray("one"));
        Entry entry;
        QCOMPARE(b->stat(file, &entry).error(), Error::NotFound);
        const QString sub = Paths::join(dir, QStringLiteral("sub"));
        QVERIFY(b->makeDir(sub, true).ok());
        QCOMPARE(b->rename(other, sub, RenameMode::Replace).error(), Error::AlreadyExists);
        QCOMPARE(b->rename(Paths::join(dir, QStringLiteral("nope")), file, RenameMode::NoReplace).error(), Error::NotFound);
        r = b->rename(other, Paths::join(sub, QStringLiteral("moved")), RenameMode::NoReplace);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        r = b->rename(sub, Paths::join(dir, QStringLiteral("sub2")), RenameMode::NoReplace);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(get(b.get(), Paths::join(dir, QStringLiteral("sub2/moved"))), QByteArray("one"));

        // Absolute paths address the same files.
        const QString absolute = home(name) + QLatin1Char('/') + dir + QStringLiteral("/sub2/moved");
        if (name != QLatin1String("pureftpd")) {   // pure-ftpd shows the home as "/"
            QVERIFY(b->stat(absolute, &entry).ok());
            QCOMPARE(entry.size, qint64(3));
        }
        exec(name, QStringLiteral("rm -rf \"$D\""), { QStringLiteral("D=") + home(name) + QLatin1Char('/') + dir });
    }

    void attributes_data() { tlsServers(); }
    void attributes()
    {
        QFETCH(QString, name);
        const auto b = signedIn(name);
        QVERIFY(b);
        const QString file = unique(QStringLiteral("attr-"));
        QVERIFY(put(b.get(), file, "data").ok());
        AttributeChanges mode;
        mode.mode = 0640;
        Result r = b->setAttributes(file, mode);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(serverMode(name, file), QStringLiteral("640"));
        AttributeChanges time;
        time.modified = QDateTime(QDate(2021, 3, 4), QTime(5, 6, 7), Qt::UTC);
        r = b->setAttributes(file, time);
        Entry entry;
        if (b->capabilities().has(Capability::SetModified)) {
            QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
            QVERIFY(b->stat(file, &entry).ok());
            QCOMPARE(entry.modified, time.modified);
        } else {
            QCOMPARE(r.error(), Error::Unsupported);
        }
        AttributeChanges accessed;
        accessed.accessed = QDateTime::currentDateTimeUtc();
        accessed.mode = 0600;
        QCOMPARE(b->setAttributes(file, accessed).error(), Error::Unsupported);
        QCOMPARE(serverMode(name, file), QStringLiteral("640"));   // nothing changed (XC-11)
        QCOMPARE(b->setAttributes(file + QStringLiteral("-missing"), mode).error(), Error::NotFound);
        QVERIFY(b->removeFile(file).ok());
    }

    void handles_data() { tlsServers(); }
    // XC-13 / F-5: sequential and random reads, interleaved requests, writes.
    void handles()
    {
        QFETCH(QString, name);
        const auto b = signedIn(name);
        QVERIFY(b);
        const QString file = unique(QStringLiteral("h-"));
        QVERIFY(put(b.get(), file, m_data).ok());
        ReadHandle *raw = nullptr;
        Result r = b->openRead(file, &raw);
        std::unique_ptr<ReadHandle> reader(raw);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(reader->size(), FileSize);
        QByteArray out;
        // Sequential reads of odd sizes.
        QByteArray collected;
        qint64 offset = 0;
        while (offset < FileSize) {
            r = reader->read(offset, 100000, &out);
            QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
            QVERIFY(!out.isEmpty());
            collected += out;
            offset += out.size();
        }
        QCOMPARE(collected, m_data);
        QVERIFY(reader->read(FileSize, 10, &out).ok());
        QVERIFY(out.isEmpty());
        // Random access, also across another request on the connection.
        for (const qint64 at : { qint64(2000000), qint64(17), qint64(FileSize - 5), qint64(1048576) }) {
            r = reader->read(at, 4096, &out);
            QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
            QCOMPARE(out, m_data.mid(int(at), 4096));
            Entry entry;
            QVERIFY(b->stat(file, &entry).ok());
            QVERIFY(reader->read(at + 4096, 10, &out).ok());
            QCOMPARE(out, m_data.mid(int(at + 4096), 10));
        }
        QVERIFY(reader->close().ok());
        QByteArray range;
        QVERIFY(b->read(file, 1000, 50, &range).ok());   // core helper over openRead
        QCOMPARE(range, m_data.mid(1000, 50));
        ReadHandle *dirHandle = nullptr;
        QCOMPARE(b->openRead(QString(), &dirHandle).error(), Error::IsADirectory);
        QCOMPARE(b->openRead(file + QStringLiteral("-missing"), &dirHandle).error(), Error::NotFound);

        // Writes: CreateNew, Resume with the right and a wrong offset.
        WriteOptions create;
        WriteHandle *w = nullptr;
        QCOMPARE(b->openWrite(file, create, &w).error(), Error::AlreadyExists);
        const QString part = unique(QStringLiteral("w-"));
        r = b->openWrite(part, create, &w);
        std::unique_ptr<WriteHandle> writer(w);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        r = writer->write(m_data.constData(), 1000000);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        r = writer->write(m_data.constData() + 1000000, 1);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(writer->position(), qint64(1000001));
        r = writer->commit();
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        writer.reset();
        WriteOptions resume;
        resume.disposition = WriteOptions::Resume;
        resume.resumeOffset = 999;
        QCOMPARE(b->openWrite(part, resume, &w).error(), Error::ProtocolError);
        resume.resumeOffset = 1000001;
        r = b->openWrite(part, resume, &w);
        writer.reset(w);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(writer->position(), qint64(1000001));
        r = writer->write(m_data.constData() + 1000001, FileSize - 1000001);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        r = writer->commit();
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        writer.reset();
        QCOMPARE(serverSha(name, part), sha256(m_data));
        // An empty file.
        const QString empty = unique(QStringLiteral("e-"));
        QVERIFY(b->openWrite(empty, create, &w).ok());
        writer.reset(w);
        QVERIFY(writer->commit().ok());
        writer.reset();
        Entry entry;
        QVERIFY(b->stat(empty, &entry).ok());
        QCOMPARE(entry.size, qint64(0));
        // Into a missing folder.
        QCOMPARE(b->openWrite(QStringLiteral("no-such-dir/x"), create, &w).error(), Error::NotFound);
        QCOMPARE(put(b.get(), QStringLiteral("no-such-dir/x"), "x").error(), Error::NotFound);
        for (const QString &f : { file, part, empty })
            QVERIFY(b->removeFile(f).ok());
    }

    void ranges_data() { tlsServers(); }
    void ranges()
    {
        QFETCH(QString, name);
        const auto b = signedIn(name);
        QVERIFY(b);
        const QString file = unique(QStringLiteral("r-"));
        QVERIFY(put(b.get(), file, m_data).ok());
        DownloadOptions options;
        options.offset = 123456;
        Result r;
        QByteArray data = get(b.get(), file, &r, options);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(data, m_data.mid(123456));
        options.length = 1000;
        data = get(b.get(), file, &r, options);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(data, m_data.mid(123456, 1000));
        options.offset = FileSize - 10;
        options.length = 10;
        data = get(b.get(), file, &r, options);
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QCOMPARE(data, m_data.right(10));
        QVERIFY(b->keepAlive().ok());   // the reconnect after a partial download is expected
        get(b.get(), QStringLiteral("missing-file"), &r);
        QCOMPARE(r.error(), Error::NotFound);
        get(b.get(), QString(), &r);
        QCOMPARE(r.error(), Error::IsADirectory);
        QVERIFY(b->removeFile(file).ok());
    }

    // F-2: the login connection follows connect()'s probe at once; a server
    // that still counts the probe greets it with 421 (before any credential).
    // The backend signs in again a few times, with a growing delay.
    void busyGreeting()
    {
        const QString log = m_tmp.filePath(unique(QStringLiteral("fake-")));
        auto fake = fakeServer(QStringLiteral("none"), QString(), log, { QStringLiteral("--busy"), QStringLiteral("2") });
        const ConnectionParams p = fakeParams(fake->port(), QStringLiteral("none"));
        std::unique_ptr<Backend> b = create();
        Result r = establish(b.get(), p, Credentials(p.username, m_password));
        QCOMPARE(r.error(), Error::AuthFailed);   // USER/PASS reached on the third login connection
        QCOMPARE(recorded(log).count(QStringLiteral("BUSY")), 2);
        QVERIFY(sentUser(recorded(log)));

        // A server that stays busy: TooManyConnections, the 421 in the detail.
        const QString busyLog = m_tmp.filePath(unique(QStringLiteral("fake-")));
        fake = fakeServer(QStringLiteral("none"), QString(), busyLog,
                          { QStringLiteral("--busy"), QStringLiteral("100") });
        const ConnectionParams busy = fakeParams(fake->port(), QStringLiteral("none"));
        QElapsedTimer timer;
        timer.start();
        r = establish(b.get(), busy, Credentials(busy.username, m_password));
        QCOMPARE(r.error(), Error::TooManyConnections);
        QVERIFY2(r.detail().startsWith(QLatin1String("FTP 421")), qPrintable(r.detail()));
        QCOMPARE(recorded(busyLog).count(QStringLiteral("BUSY")), 6);   // the first try and five more
        QVERIFY(!sentUser(recorded(busyLog)));
        QVERIFY(timer.elapsed() >= 3000);

        // cancel() ends the wait between the tries (C-9).
        const QString cancelLog = m_tmp.filePath(unique(QStringLiteral("fake-")));
        fake = fakeServer(QStringLiteral("none"), QString(), cancelLog,
                          { QStringLiteral("--busy"), QStringLiteral("100") });
        const ConnectionParams stuck = fakeParams(fake->port(), QStringLiteral("none"));
        Backend *raw = b.get();
        const qint64 ms = cancelDuring(
            raw, [&]() { return establish(raw, stuck, Credentials(stuck.username, m_password)); }, &r);
        QCOMPARE(r.error(), Error::Canceled);
        QVERIFY2(ms <= CancelBoundMs, qPrintable(QString::number(ms)));
    }

    // 421 at the greeting from a real server: vsftpd's max_clients=1.
    void tooManyConnections()
    {
        const QString name = QStringLiteral("vsftpd-limited");
        const QString config = QStringLiteral("/etc/vsftpd-limited.conf");
        QVERIFY2(waitIdle(name, config), "the server kept an old session");
        const ConnectionParams p = params(name);
        std::unique_ptr<Backend> first = create();
        Result r = establish(first.get(), p, Credentials(p.username, m_password));
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
        QVERIFY(first->keepAlive().ok());
        QCOMPARE(serverSessions(name, config), 1);
        std::unique_ptr<Backend> second = create();
        r = second->connect(p, nullptr);
        QCOMPARE(r.error(), Error::TooManyConnections);
        QVERIFY2(r.detail().startsWith(QLatin1String("FTP 421")), qPrintable(r.detail()));
        // Once the first session is gone, the second backend gets in.
        first->disconnect();
        QVERIFY2(waitIdle(name, config), "the server kept the first session");
        r = establish(second.get(), p, Credentials(p.username, m_password));
        QVERIFY2(r.ok(), qPrintable(r.toString() + QLatin1Char(' ') + r.detail()));
    }

    // ------------------------------------------------------------ C-9, C-14

    void cancel_data()
    {
        QTest::addColumn<QString>("hold");
        QTest::addColumn<QString>("operation");
        QTest::newRow("list") << QStringLiteral("^LIST") << QStringLiteral("list");
        QTest::newRow("download") << QStringLiteral("^RETR") << QStringLiteral("download");
        QTest::newRow("upload") << QStringLiteral("^STOR") << QStringLiteral("upload");
        QTest::newRow("stat") << QStringLiteral("^SIZE") << QStringLiteral("stat");
        QTest::newRow("keepAlive") << QStringLiteral("^NOOP") << QStringLiteral("keepAlive");
        QTest::newRow("read handle") << QStringLiteral("^RETR") << QStringLiteral("read");
    }

    void cancel()
    {
        QFETCH(QString, hold);
        QFETCH(QString, operation);
        const ConnectionParams direct = params(QStringLiteral("vsftpd-plain"));
        const auto setup = signedIn(QStringLiteral("vsftpd-plain"));
        QVERIFY(setup);
        QVERIFY(put(setup.get(), QStringLiteral("cancel.bin"), m_data).ok());
        Helper proxy(m_proxy, { QStringLiteral("forward"), QStringLiteral("--target"),
                                QStringLiteral("127.0.0.1:%1").arg(direct.port), QStringLiteral("--hold"), hold });
        QVERIFY(proxy.port() > 0);
        ConnectionParams p = direct;
        p.port = proxy.port();
        std::unique_ptr<Backend> b = create();
        QVERIFY(establish(b.get(), p, Credentials(p.username, m_password)).ok());
        Backend *raw = b.get();
        ReadHandle *handle = nullptr;
        if (operation == QLatin1String("read"))
            QVERIFY(raw->openRead(QStringLiteral("cancel.bin"), &handle).ok());
        std::unique_ptr<ReadHandle> reader(handle);
        Result r;
        const qint64 ms = cancelDuring(raw, [&]() {
            QBuffer buffer;
            buffer.open(QIODevice::ReadWrite);
            QVector<Entry> entries;
            Entry entry;
            QByteArray out;
            if (operation == QLatin1String("list"))
                return raw->list(QString(), &entries);
            if (operation == QLatin1String("download"))
                return raw->download(QStringLiteral("cancel.bin"), &buffer, DownloadOptions(), nullptr);
            if (operation == QLatin1String("upload")) {
                buffer.setData(m_data);
                return raw->upload(&buffer, QStringLiteral("cancel-up.bin"), UploadOptions(), nullptr);
            }
            if (operation == QLatin1String("stat"))
                return raw->stat(QStringLiteral("cancel.bin"), &entry);
            if (operation == QLatin1String("read"))
                return reader->read(0, 1000, &out);
            return raw->keepAlive();
        }, &r);
        QCOMPARE(r.error(), Error::Canceled);
        QVERIFY2(ms <= CancelBoundMs, qPrintable(QString::number(ms)));
        reader.reset();
        QElapsedTimer timer;
        timer.start();
        b->disconnect();   // QUIT waits at most a second on a stalled server
        QVERIFY2(timer.elapsed() < CancelBoundMs, qPrintable(QString::number(timer.elapsed())));
    }

    // C-9 before the greeting, C-14 timeouts.
    void stalledServer()
    {
        Helper silent(m_proxy, { QStringLiteral("silent") });
        ConnectionParams p = params(QStringLiteral("vsftpd-plain"));
        p.port = silent.port();
        std::unique_ptr<Backend> b = create();
        Backend *raw = b.get();
        Result r;
        const qint64 ms = cancelDuring(raw, [&]() { return raw->connect(p, nullptr); }, &r);
        QCOMPARE(r.error(), Error::Canceled);
        QVERIFY2(ms <= CancelBoundMs, qPrintable(QString::number(ms)));

        // No greeting within the request timeout.
        p.requestTimeoutMs = 2000;
        QElapsedTimer timer;
        timer.start();
        r = raw->connect(p, nullptr);
        QCOMPARE(r.error(), Error::Timeout);
        QVERIFY(timer.elapsed() < 6000);

        // A server that stops answering after sign-in.
        const ConnectionParams direct = params(QStringLiteral("vsftpd-plain"));
        Helper proxy(m_proxy, { QStringLiteral("forward"), QStringLiteral("--target"),
                                QStringLiteral("127.0.0.1:%1").arg(direct.port), QStringLiteral("--hold"),
                                QStringLiteral("^NOOP") });
        p = direct;
        p.port = proxy.port();
        p.requestTimeoutMs = 2000;
        QVERIFY(establish(raw, p, Credentials(p.username, m_password)).ok());
        timer.restart();
        QCOMPARE(raw->keepAlive().error(), Error::Timeout);
        QVERIFY(timer.elapsed() < 6000);
    }

    // XC-20: keepAlive notices a dropped control connection.
    void keepAliveAfterDrop()
    {
        const ConnectionParams direct = params(QStringLiteral("vsftpd-plain"));
        Helper proxy(m_proxy, { QStringLiteral("forward"), QStringLiteral("--target"),
                                QStringLiteral("127.0.0.1:%1").arg(direct.port) });
        ConnectionParams p = direct;
        p.port = proxy.port();
        std::unique_ptr<Backend> b = create();
        QVERIFY(establish(b.get(), p, Credentials(p.username, m_password)).ok());
        QVERIFY(b->keepAlive().ok());
        QVERIFY(b->keepAlive().ok());
        proxy.signal(SIGUSR1);
        QThread::msleep(300);
        QCOMPARE(b->keepAlive().error(), Error::ConnectionLost);
    }

    // A canceled backend refuses work until resetCancel().
    void cancelFlag()
    {
        const auto b = signedIn(QStringLiteral("vsftpd"));
        QVERIFY(b);
        b->cancel();
        Entry entry;
        QCOMPARE(b->stat(QString(), &entry).error(), Error::Canceled);
        b->resetCancel();
        QVERIFY(b->stat(QString(), &entry).ok());
    }
};

QTEST_GUILESS_MAIN(TestInteropFtp)
#include "tst_interop_ftp.moc"
