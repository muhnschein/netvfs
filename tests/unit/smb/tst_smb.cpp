// SPDX-License-Identifier: LGPL-2.1-or-later
// SMB backend pieces that need no SMB server: error mapping, paths, chunk
// size, the TCP probe of connect(), and the plugin's behaviour against local
// TCP peers that accept and then close or never answer.
#include "backendloader.h"
#include "smbutil.h"

#include <QtCore/QBuffer>
#include <QtCore/QElapsedTimer>
#include <QtCore/QProcess>
#include <QtCore/QStandardPaths>
#include <QtCore/QUuid>
#include <QtConcurrent/QtConcurrentRun>
#include <QtTest/QtTest>

#include "smb2api.h"

#include <smb2/libsmb2-share-enum.h>

#include <atomic>
#include <chrono>
#include <cerrno>
#include <memory>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace NetVfs;
using namespace NetVfs::Smb;

namespace {

// A TCP listener on 127.0.0.1 that either closes every connection at once or
// keeps it open without ever sending anything.
class LocalPeer
{
public:
    enum class Mode { CloseAtOnce, Silent };

    explicit LocalPeer(Mode mode) : m_mode(mode)
    {
        m_listener = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t len = sizeof(addr);
        ::bind(m_listener, reinterpret_cast<sockaddr *>(&addr), len);
        ::listen(m_listener, 8);
        ::getsockname(m_listener, reinterpret_cast<sockaddr *>(&addr), &len);
        m_port = ntohs(addr.sin_port);
        m_thread = std::thread([this] { run(); });
    }
    ~LocalPeer()
    {
        m_stop = true;
        m_thread.join();
        for (const int fd : m_open)
            ::close(fd);
        ::close(m_listener);
    }
    LocalPeer(const LocalPeer &) = delete;
    LocalPeer &operator=(const LocalPeer &) = delete;

    int port() const { return m_port; }
    int accepted() const { return m_accepted; }

private:
    void run()
    {
        pollfd pfd = {};
        pfd.fd = m_listener;
        pfd.events = POLLIN;
        while (!m_stop) {
            if (::poll(&pfd, 1, 20) <= 0)
                continue;
            const int fd = ::accept(m_listener, nullptr, nullptr);
            if (fd < 0)
                continue;
            ++m_accepted;
            if (m_mode == Mode::CloseAtOnce)
                ::close(fd);
            else
                m_open.push_back(fd);
        }
    }

    Mode m_mode;
    int m_listener = -1;
    int m_port = 0;
    std::atomic<bool> m_stop { false };
    std::atomic<int> m_accepted { 0 };
    std::vector<int> m_open;
    std::thread m_thread;
};

// A listener that never accepts, with its accept queue filled: a further
// connect() neither completes nor fails (Linux drops the SYNs), which is a
// local stand-in for an unreachable server.
class FullListener
{
public:
    FullListener()
    {
        m_listener = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t len = sizeof(addr);
        ::bind(m_listener, reinterpret_cast<sockaddr *>(&addr), len);
        ::listen(m_listener, 0);
        ::getsockname(m_listener, reinterpret_cast<sockaddr *>(&addr), &len);
        m_port = ntohs(addr.sin_port);
        for (int i = 0; i < 8 && !m_full; ++i) {
            const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            m_fillers.push_back(fd);
            ::connect(fd, reinterpret_cast<sockaddr *>(&addr), len);
            pollfd pfd = {};
            pfd.fd = fd;
            pfd.events = POLLOUT;
            m_full = ::poll(&pfd, 1, 200) == 0;
        }
    }
    ~FullListener()
    {
        for (const int fd : m_fillers)
            ::close(fd);
        ::close(m_listener);
    }
    FullListener(const FullListener &) = delete;
    FullListener &operator=(const FullListener &) = delete;

    int port() const { return m_port; }
    bool full() const { return m_full; }

private:
    int m_listener = -1;
    int m_port = 0;
    bool m_full = false;
    std::vector<int> m_fillers;
};

int closedPort()
{
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(addr);
    ::bind(fd, reinterpret_cast<sockaddr *>(&addr), len);
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
    ::close(fd);
    return ntohs(addr.sin_port);
}

ConnectionParams localParams(int port)
{
    ConnectionParams params;
    params.provider = QStringLiteral("smb");
    params.host = QStringLiteral("127.0.0.1");
    params.port = port;
    params.username = QStringLiteral("backup");
    params.options.insert(QStringLiteral("share"), QStringLiteral("backup"));
    return params;
}

std::unique_ptr<Backend> smbBackend()
{
    qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_BACKEND_DIR);
    return std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("smb")));
}

// Nothing here reaches a real server; any non-empty secret will do.
Credentials testCredentials()
{
    return Credentials(QStringLiteral("backup"), QUuid::createUuid().toByteArray());
}

} // namespace

class TestSmb : public QObject
{
    Q_OBJECT

private slots:
    // M-11
    void chunkSizes_data()
    {
        QTest::addColumn<quint32>("server");
        QTest::addColumn<quint32>("chunk");
        QTest::newRow("samba 8 MiB") << quint32(8 * 1024 * 1024) << quint32(1024 * 1024);
        QTest::newRow("exactly 1 MiB") << quint32(1024 * 1024) << quint32(1024 * 1024);
        QTest::newRow("just above") << quint32(1024 * 1024 + 1) << quint32(1024 * 1024);
        QTest::newRow("small server") << quint32(65536) << quint32(65536);
        QTest::newRow("unknown") << quint32(0) << FallbackChunkSize;
    }
    void chunkSizes()
    {
        QFETCH(quint32, server);
        QFETCH(quint32, chunk);
        QCOMPARE(chunkSize(server), chunk);
    }

    // M-8, M-9, C-15
    void paths_data()
    {
        QTest::addColumn<QString>("input");
        QTest::addColumn<bool>("ok");
        QTest::addColumn<QByteArray>("expected");
        QTest::newRow("share root") << QString() << true << QByteArray();
        QTest::newRow("slash is root") << "/" << true << QByteArray();
        QTest::newRow("leading slash stripped") << "/Sailfish OS/Backups" << true << QByteArray("Sailfish OS/Backups");
        QTest::newRow("relative") << "Sailfish OS/Backups" << true << QByteArray("Sailfish OS/Backups");
        QTest::newRow("collapsed") << "a//b/" << true << QByteArray("a/b");
        QTest::newRow("utf-8") << QString::fromUtf8("Backups \xc3\xa4") << true << QByteArray("Backups \xc3\xa4");
        QTest::newRow("dotdot") << "a/../b" << false << QByteArray();
        QTest::newRow("colon") << "a:b" << false << QByteArray();
        QTest::newRow("backslash") << "a\\b" << false << QByteArray();
        QTest::newRow("star") << "x/*" << false << QByteArray();
        QTest::newRow("trailing dot") << "x/name." << false << QByteArray();
        QTest::newRow("trailing space") << "x /y" << false << QByteArray();
    }
    void paths()
    {
        QFETCH(QString, input);
        QFETCH(bool, ok);
        QFETCH(QByteArray, expected);
        QByteArray out("unchanged");
        const Result r = translatePath(input, &out);
        QCOMPARE(r.ok(), ok);
        QCOMPARE(out, ok ? expected : QByteArray("unchanged"));
    }

    // SPEC-smb 5, error mapping table. `setup` is the result during sign-in,
    // where any refusal that is not about the credentials or the share name
    // means the server wants something this client does not offer.
    void ntStatus_data()
    {
        QTest::addColumn<quint32>("status");
        QTest::addColumn<int>("error");
        QTest::addColumn<int>("setup");
        const auto row = [](const char *name, quint32 status, Error error, Error setup) {
            QTest::newRow(name) << status << static_cast<int>(error) << static_cast<int>(setup);
        };
        const Error policy = Error::SecurityPolicy;
        row("logon failure", SMB2_STATUS_LOGON_FAILURE, Error::AuthFailed, Error::AuthFailed);
        row("wrong password", SMB2_STATUS_WRONG_PASSWORD, Error::AuthFailed, Error::AuthFailed);
        row("no such user", SMB2_STATUS_NO_SUCH_USER, Error::AuthFailed, Error::AuthFailed);
        row("account disabled", SMB2_STATUS_ACCOUNT_DISABLED, Error::AuthFailed, Error::AuthFailed);
        row("account locked", SMB2_STATUS_ACCOUNT_LOCKED_OUT, Error::AuthFailed, Error::AuthFailed);
        row("account expired", SMB2_STATUS_ACCOUNT_EXPIRED, Error::AuthFailed, Error::AuthFailed);
        row("account restriction", SMB2_STATUS_ACCOUNT_RESTRICTION, Error::AuthFailed, Error::AuthFailed);
        row("logon hours", SMB2_STATUS_INVALID_LOGON_HOURS, Error::AuthFailed, Error::AuthFailed);
        row("password expired", SMB2_STATUS_PASSWORD_EXPIRED, Error::AuthFailed, Error::AuthFailed);
        row("password must change", SMB2_STATUS_PASSWORD_MUST_CHANGE, Error::AuthFailed, Error::AuthFailed);
        row("bad network name", SMB2_STATUS_BAD_NETWORK_NAME, Error::NotFound, Error::NotFound);
        row("io timeout", SMB2_STATUS_IO_TIMEOUT, Error::Timeout, Error::Timeout);
        row("access denied", SMB2_STATUS_ACCESS_DENIED, Error::PermissionDenied, policy);
        row("name not found", SMB2_STATUS_OBJECT_NAME_NOT_FOUND, Error::NotFound, Error::NotFound);
        row("path not found", SMB2_STATUS_OBJECT_PATH_NOT_FOUND, Error::NotFound, Error::NotFound);
        row("collision", SMB2_STATUS_OBJECT_NAME_COLLISION, Error::AlreadyExists, policy);
        row("disk full", SMB2_STATUS_DISK_FULL, Error::NoSpace, policy);
        row("quota", SMB2_STATUS_QUOTA_EXCEEDED, Error::NoSpace, policy);
        row("not supported", SMB2_STATUS_NOT_SUPPORTED, Error::ProtocolError, policy);
        row("invalid parameter", SMB2_STATUS_INVALID_PARAMETER, Error::ProtocolError, policy);
        row("sharing violation", SMB2_STATUS_SHARING_VIOLATION, Error::ProtocolError, policy);
    }
    void ntStatus()
    {
        QFETCH(quint32, status);
        QFETCH(int, error);
        QFETCH(int, setup);
        const QString hex = QStringLiteral("0x%1").arg(status, 8, 16, QLatin1Char('0'));
        // The NT status wins over the errno.
        const Result established = errorForStatus(status, ECONNRESET, Stage::Established, QStringLiteral("ctx"));
        QCOMPARE(static_cast<int>(established.error()), error);
        QVERIFY2(established.message().startsWith(QLatin1String("ctx: ")), qPrintable(established.message()));
        QVERIFY2(established.message().contains(hex), qPrintable(established.message()));
        const Result signIn = errorForStatus(status, ECONNRESET, Stage::SessionSetup, QStringLiteral("ctx"));
        QCOMPARE(static_cast<int>(signIn.error()), setup);
        QVERIFY2(signIn.message().contains(hex), qPrintable(signIn.message()));
    }

    void specMessages()
    {
        QVERIFY(errorForStatus(SMB2_STATUS_BAD_NETWORK_NAME, 0, Stage::SessionSetup, QString())
                    .message().startsWith(QLatin1String("share not found")));
        // SPEC-smb 5: the SecurityPolicy text.
        const Result closed = errorForStatus(0, ECONNRESET, Stage::SessionSetup, QString());
        QCOMPARE(closed.error(), Error::SecurityPolicy);
        QCOMPARE(closed.message(), QStringLiteral("the server closed the connection; it may not support SMB 3, "
                                                  "signing or encryption"));
        QCOMPARE(connectionLost(Stage::SessionSetup).toString(), closed.toString());
        QCOMPARE(connectionLost(Stage::Established).error(), Error::NetworkUnreachable);
        QVERIFY(errorForStatus(SMB2_STATUS_NOT_SUPPORTED, 0, Stage::SessionSetup, QString())
                    .message().startsWith(QLatin1String(SessionRefusedMessage)));
    }

    // No NT status: TCP failures, the server dropping the session, and the
    // errno that libsmb2's compound requests report instead of the status.
    void withoutStatus_data()
    {
        QTest::addColumn<int>("errnoValue");
        QTest::addColumn<bool>("sessionSetup");
        QTest::addColumn<int>("error");
        const auto row = [](const char *name, int err, bool setup, Error error) {
            QTest::newRow(name) << err << setup << static_cast<int>(error);
        };
        row("setup: reset", ECONNRESET, true, Error::SecurityPolicy);
        row("setup: eio", EIO, true, Error::SecurityPolicy);
        row("setup: refused", ECONNREFUSED, true, Error::NetworkUnreachable);
        row("setup: net unreachable", ENETUNREACH, true, Error::NetworkUnreachable);
        row("setup: host unreachable", EHOSTUNREACH, true, Error::NetworkUnreachable);
        row("setup: timeout", ETIMEDOUT, true, Error::Timeout);
        row("session: timeout", ETIMEDOUT, false, Error::Timeout);
        row("session: enoent", ENOENT, false, Error::NotFound);
        row("session: eacces", EACCES, false, Error::PermissionDenied);
        row("session: eperm", EPERM, false, Error::PermissionDenied);
        row("session: eexist", EEXIST, false, Error::AlreadyExists);
        row("session: enospc", ENOSPC, false, Error::NoSpace);
        row("session: enetreset", ENETRESET, false, Error::NetworkUnreachable);
        row("session: other", EIO, false, Error::ProtocolError);
    }
    void withoutStatus()
    {
        QFETCH(int, errnoValue);
        QFETCH(bool, sessionSetup);
        QFETCH(int, error);
        const Result r = errorForStatus(0, errnoValue, sessionSetup ? Stage::SessionSetup : Stage::Established,
                                        QStringLiteral("ctx"));
        QCOMPARE(static_cast<int>(r.error()), error);
        QVERIFY(r.message().startsWith(QLatin1String("ctx: ")));
    }

    void socketErrors()
    {
        QCOMPARE(errorForSocket(ECANCELED, QString()).error(), Error::Canceled);
        QCOMPARE(errorForSocket(ETIMEDOUT, QString()).error(), Error::Timeout);
        QCOMPARE(errorForSocket(ECONNREFUSED, QString()).error(), Error::NetworkUnreachable);
    }

    // M-3
    void encryptionOption()
    {
        QVariantMap options;
        QVERIFY(requireEncryption(options));
        options.insert(QStringLiteral("require_encryption"), false);
        QVERIFY(!requireEncryption(options));
        options.insert(QStringLiteral("require_encryption"), QStringLiteral("false"));
        QVERIFY(!requireEncryption(options));
        options.insert(QStringLiteral("require_encryption"), QStringLiteral("true"));
        QVERIFY(requireEncryption(options));
    }

    // M-1
    void dialects()
    {
        QVERIFY(!isSmb3Dialect(0x0202));
        QVERIFY(!isSmb3Dialect(0x0210));
        QVERIFY(!isSmb3Dialect(0x02ff));
        QVERIFY(!isSmb3Dialect(0));
        QVERIFY(isSmb3Dialect(0x0300));
        QVERIFY(isSmb3Dialect(0x0302));
        QVERIFY(isSmb3Dialect(0x0311));
        QCOMPARE(dialectName(0x0311), QStringLiteral("3.1.1"));
        QCOMPARE(dialectName(0x0210), QStringLiteral("2.1.0"));
    }

    void serverStrings()
    {
        QCOMPARE(serverString(QStringLiteral("10.0.0.1"), 445), QByteArray("10.0.0.1"));
        QCOMPARE(serverString(QStringLiteral("10.0.0.1"), 0), QByteArray("10.0.0.1"));
        QCOMPARE(serverString(QStringLiteral("10.0.0.1"), 4450), QByteArray("10.0.0.1:4450"));
        QCOMPARE(serverString(QStringLiteral("fd00::1"), 4450), QByteArray("[fd00::1]:4450"));
        QCOMPARE(serverString(QStringLiteral("fd00::1"), 445), QByteArray("fd00::1"));
    }

    // M-10: the TCP probe.
    void probe()
    {
        const LocalPeer peer(LocalPeer::Mode::Silent);
        const std::atomic<bool> cancel { false };
        QString address;
        QVERIFY(probeTcp(QStringLiteral("localhost"), peer.port(), 2000, cancel, &address).ok());
        QVERIFY2(address == QLatin1String("127.0.0.1") || address == QLatin1String("::1"), qPrintable(address));

        const Result refused = probeTcp(QStringLiteral("127.0.0.1"), closedPort(), 2000, cancel, &address);
        QCOMPARE(refused.error(), Error::NetworkUnreachable);
        QVERIFY(!refused.message().contains(QLatin1String("127.0.0.1")));   // C-17

        const Result unresolvable = probeTcp(QStringLiteral("no-such-host.invalid"), 445, 2000, cancel, &address);
        QCOMPARE(unresolvable.error(), Error::NetworkUnreachable);
    }

    void probeCanceledAndTimeout()
    {
        // TEST-NET-1 is not routed: the connect either hangs or fails at once.
        const std::atomic<bool> canceled { true };
        const std::atomic<bool> running { false };
        QString address;
        QElapsedTimer clock;
        clock.start();
        const Result c = probeTcp(QStringLiteral("192.0.2.1"), 445, 5000, canceled, &address);
        QVERIFY2(c.error() == Error::Canceled || c.error() == Error::NetworkUnreachable, qPrintable(c.toString()));
        const Result t = probeTcp(QStringLiteral("192.0.2.1"), 445, 300, running, &address);
        QVERIFY2(t.error() == Error::Timeout || t.error() == Error::NetworkUnreachable, qPrintable(t.toString()));
        QVERIFY(clock.elapsed() < 3000);
    }

    // M-10, C-9, C-14: a connect that hangs ends at the connect timeout, or
    // within 2 s of a cancel.
    void probeHanging()
    {
        const FullListener listener;
        if (!listener.full())
            QSKIP("the accept queue could not be filled here");
        std::atomic<bool> cancel { false };
        QString address;
        QElapsedTimer clock;
        clock.start();
        const Result timedOut = probeTcp(QStringLiteral("127.0.0.1"), listener.port(), 500, cancel, &address);
        QCOMPARE(timedOut.error(), Error::Timeout);
        QVERIFY2(clock.elapsed() >= 450 && clock.elapsed() < 2000, qPrintable(QString::number(clock.elapsed())));

        std::thread canceller([&cancel]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            cancel = true;
        });
        clock.restart();
        const Result canceled = probeTcp(QStringLiteral("127.0.0.1"), listener.port(), 15000, cancel, &address);
        canceller.join();
        QCOMPARE(canceled.error(), Error::Canceled);
        QVERIFY2(clock.elapsed() < 2000, qPrintable(QString::number(clock.elapsed())));
    }

    void plugin()
    {
        const auto backend = smbBackend();
        QVERIFY(backend);
        QVERIFY(BackendLoader::isAvailable(QStringLiteral("smb")));
    }

    // G-SMB item 4, M-6: neither Kerberos nor DCE/RPC (share enumeration) code
    // is linked into the plugin.
    void noDceRpcOrKerberos()
    {
        const QString nm = QStandardPaths::findExecutable(QStringLiteral("nm"));
        if (nm.isEmpty())
            QSKIP("nm is not installed");
        QProcess process;
        process.start(nm, { QStringLiteral(NETVFS_TEST_BACKEND_DIR "/libnetvfs-smb.so") });
        QVERIFY(process.waitForFinished(30000));
        const QList<QByteArray> lines = process.readAllStandardOutput().split('\n');
        QVERIFY(lines.size() > 100);
        int libsmb2Symbols = 0;
        for (const QByteArray &line : lines) {
            const QByteArray symbol = line.mid(line.lastIndexOf(' ') + 1);
            if (symbol.startsWith("smb2_"))
                ++libsmb2Symbols;
            QVERIFY2(!symbol.contains("dcerpc") && !symbol.contains("srvsvc") && !symbol.startsWith("krb5_")
                         && !symbol.startsWith("gss_"),
                     symbol.constData());
        }
        QVERIFY(libsmb2Symbols > 50);   // libsmb2 is linked statically (SEC-7)
    }

    // The plugin's definition, linked here the same way: share enumeration is
    // not available and does not reach the network.
    void shareEnumerationStub()
    {
        smb2_context *ctx = smb2_init_context();
        QVERIFY(ctx);
        QCOMPARE(smb2_share_enum_async(ctx, SHARE_INFO_1, nullptr, nullptr), -ENOTSUP);
        QCOMPARE(QByteArray(smb2_get_error(ctx)), QByteArray("Share enumeration is not available"));
        smb2_destroy_context(ctx);
    }

    void callsBeforeSignIn()
    {
        const auto backend = smbBackend();
        Entry entry;
        QVector<Entry> entries;
        qint64 bytes = 0;
        QByteArray data;
        QBuffer buffer(&data);
        QCOMPARE(backend->authenticate(testCredentials()).error(), Error::Internal);
        QCOMPARE(backend->stat(QString(), &entry).error(), Error::Internal);
        QCOMPARE(backend->list(QString(), &entries).error(), Error::Internal);
        QCOMPARE(backend->makePath(QStringLiteral("a/b")).error(), Error::Internal);
        QCOMPARE(backend->remove(QStringLiteral("a")).error(), Error::Internal);
        QCOMPARE(backend->rename(QStringLiteral("a"), QStringLiteral("b")).error(), Error::Internal);
        QCOMPARE(backend->freeSpace(QString(), &bytes).error(), Error::Internal);
        QCOMPARE(backend->upload(&buffer, QStringLiteral("a"), nullptr).error(), Error::Internal);
        QCOMPARE(backend->download(QStringLiteral("a"), &buffer, nullptr).error(), Error::Internal);
        QCOMPARE(backend->read(QStringLiteral("a"), 0, 1, &data).error(), Error::Internal);
        QCOMPARE(backend->read(QStringLiteral("a"), -1, 1, &data).error(), Error::Internal);
        // M-9: rejected before anything is sent.
        QCOMPARE(backend->stat(QStringLiteral("bad:name"), &entry).error(), Error::Internal);
        QVERIFY(backend->stat(QStringLiteral("bad:name"), &entry).message().contains(QLatin1Char(':')));
        backend->disconnect();
    }

    // M-10: connect() only checks the port; there is no server identity.
    void connectOnly()
    {
        const LocalPeer peer(LocalPeer::Mode::Silent);
        const auto backend = smbBackend();
        ServerIdentity seen;
        seen.publicKey = "stale";
        QVERIFY(backend->connect(localParams(peer.port()), &seen).ok());
        QVERIFY(seen.isEmpty());
        QTRY_COMPARE(peer.accepted(), 1);

        QCOMPARE(backend->connect(localParams(closedPort()), &seen).error(), Error::NetworkUnreachable);
        // A failed connect() leaves nothing to authenticate.
        QCOMPARE(backend->authenticate(testCredentials()).error(), Error::Internal);
    }

    void authenticateChecksInput()
    {
        const LocalPeer peer(LocalPeer::Mode::Silent);
        const auto backend = smbBackend();
        ConnectionParams params = localParams(peer.port());
        params.options.remove(QStringLiteral("share"));
        QVERIFY(backend->connect(params, nullptr).ok());
        QCOMPARE(backend->authenticate(testCredentials()).error(), Error::NotFound);

        QVERIFY(backend->connect(localParams(peer.port()), nullptr).ok());
        QCOMPARE(backend->authenticate(Credentials(QStringLiteral("backup"), QByteArray())).error(),
                 Error::AuthFailed);
        QTRY_COMPARE(peer.accepted(), 2);   // nothing beyond the two probes
    }

    // SPEC-smb 5: no NT status, failure after TCP connect.
    void serverClosesDuringSetup()
    {
        const LocalPeer peer(LocalPeer::Mode::CloseAtOnce);
        const auto backend = smbBackend();
        qputenv("NTLM_USER_FILE", "/nonexistent");
        QVERIFY(backend->connect(localParams(peer.port()), nullptr).ok());
        const Result r = backend->authenticate(testCredentials());
        QCOMPARE(r.error(), Error::SecurityPolicy);
        QVERIFY2(r.message().endsWith(QLatin1String(ServerClosedMessage)), qPrintable(r.message()));
        // M-5: the variable is gone before the session setup.
        QVERIFY(!qEnvironmentVariableIsSet("NTLM_USER_FILE"));
        // The failed sign-in leaves the backend unusable, not half open.
        Entry entry;
        QCOMPARE(backend->stat(QString(), &entry).error(), Error::Internal);
    }

    // M-12, C-9: a stalled sign-in is abandoned within 2 s of cancel().
    void cancelStalledSignIn()
    {
        const LocalPeer peer(LocalPeer::Mode::Silent);
        const auto backend = smbBackend();
        QFuture<Result> future = QtConcurrent::run([&backend, &peer]() {
            Result r = backend->connect(localParams(peer.port()), nullptr);
            if (r.ok())
                r = backend->authenticate(testCredentials());
            return r;
        });
        QTest::qWait(500);
        QVERIFY(future.isRunning());
        QElapsedTimer clock;
        clock.start();
        backend->cancel();
        future.waitForFinished();
        QVERIFY2(clock.elapsed() < 2000, qPrintable(QString::number(clock.elapsed())));
        QCOMPARE(future.result().error(), Error::Canceled);

        // Still canceled until resetCancel().
        QCOMPARE(backend->connect(localParams(peer.port()), nullptr).error(), Error::Canceled);
        backend->resetCancel();
        QVERIFY(backend->connect(localParams(peer.port()), nullptr).ok());
    }

    // M-7, C-14: the request timeout applies to the sign-in.
    void signInTimeout()
    {
        const LocalPeer peer(LocalPeer::Mode::Silent);
        const auto backend = smbBackend();
        ConnectionParams params = localParams(peer.port());
        params.requestTimeoutMs = 1000;
        QVERIFY(backend->connect(params, nullptr).ok());
        QElapsedTimer clock;
        clock.start();
        const Result r = backend->authenticate(testCredentials());
        QCOMPARE(r.error(), Error::Timeout);
        QVERIFY2(clock.elapsed() < 1000 + 5000, qPrintable(QString::number(clock.elapsed())));
    }

    // M-13: one context per thread.
    void otherThread()
    {
        const LocalPeer peer(LocalPeer::Mode::Silent);
        const auto backend = smbBackend();
        QVERIFY(backend->connect(localParams(peer.port()), nullptr).ok());
        // A real second thread: QFuture::result() may run a task that has not
        // started yet on the waiting thread itself.
        Result r;
        std::thread other([&backend, &r]() { r = backend->authenticate(testCredentials()); });
        other.join();
        QVERIFY2(r.error() == Error::Internal, qPrintable(r.toString()));
    }
};

QTEST_GUILESS_MAIN(TestSmb)
#include "tst_smb.moc"
