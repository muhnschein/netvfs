// SPDX-License-Identifier: LGPL-2.1-or-later
// SMB backend pieces that need no SMB server: error mapping, paths, chunk
// size, the TCP probe of connect(), and the plugin's behaviour against local
// TCP peers that accept and then close or never answer.
#include "backendloader.h"
#include "smbhelper.h"
#include "smbshares.h"
#include "smbutil.h"

#include <QtCore/QBuffer>
#include <QtCore/QElapsedTimer>
#include <QtCore/QFile>
#include <QtCore/QProcess>
#include <QtCore/QStandardPaths>
#include <QtCore/QTemporaryDir>
#include <QtCore/QUuid>
#include <QtConcurrent/QtConcurrentRun>
#include <QtTest/QtTest>

#include "smb2api.h"

#include <smb2/libsmb2-share-enum.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstring>
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

// A stand-in for netvfs-smb-shares: a shell script in `dir`.
QString writeScript(const QTemporaryDir &dir, const QByteArray &body)
{
    const QString path = dir.filePath(QStringLiteral("helper.sh"));
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write("#!/bin/sh\n" + body) < 0)
        return QString();
    file.close();
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    return path;
}

QByteArray testRequest()
{
    ShareRequest request;
    request.server = "127.0.0.1";
    request.user = "backup";
    request.profile = "strict";
    request.requestTimeoutMs = 1000;
    request.secret = "hunter2";
    return encodeShareRequest(request);
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
        // SPEC-v2 XC-9, XC-21
        row("sharing violation", SMB2_STATUS_SHARING_VIOLATION, Error::Locked, policy);
        row("file is a directory", SMB2_STATUS_FILE_IS_A_DIRECTORY, Error::IsADirectory, policy);
        row("not a directory", SMB2_STATUS_NOT_A_DIRECTORY, Error::NotADirectory, policy);
        row("directory not empty", SMB2_STATUS_DIRECTORY_NOT_EMPTY, Error::DirectoryNotEmpty, policy);
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
        QCOMPARE(connectionLost(Stage::Established).error(), Error::ConnectionLost);   // XC-21
        QVERIFY(errorForStatus(SMB2_STATUS_NOT_SUPPORTED, 0, Stage::SessionSetup, QString())
                    .message().startsWith(QLatin1String(SessionRefusedMessage)));
        // ACCESS_DENIED at tree connect: no share access or no common cipher (M-T14).
        QVERIFY(errorForStatus(SMB2_STATUS_ACCESS_DENIED, 0, Stage::SessionSetup, QString())
                    .message().startsWith(QLatin1String(ShareRefusedMessage)));
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
        row("session: enetreset", ENETRESET, false, Error::ConnectionLost);
        row("session: enotdir", ENOTDIR, false, Error::NotADirectory);
        row("session: enotempty", ENOTEMPTY, false, Error::DirectoryNotEmpty);
        row("session: etxtbsy", ETXTBSY, false, Error::Locked);
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

    // M-3, XM-1: the v1 option maps to strict or signed.
    void encryptionOption()
    {
        QVariantMap options;
        Profile profile = Profile::Guest;
        QVERIFY(profileFromOptions(options, &profile).ok());
        QCOMPARE(profile, Profile::Strict);
        options.insert(QStringLiteral("require_encryption"), false);
        QVERIFY(profileFromOptions(options, &profile).ok());
        QCOMPARE(profile, Profile::Signed);
        options.insert(QStringLiteral("require_encryption"), QStringLiteral("false"));
        QVERIFY(profileFromOptions(options, &profile).ok());
        QCOMPARE(profile, Profile::Signed);
        options.insert(QStringLiteral("require_encryption"), QStringLiteral("true"));
        QVERIFY(profileFromOptions(options, &profile).ok());
        QCOMPARE(profile, Profile::Strict);
    }

    // XM-1: the profile option wins; unknown names fail closed.
    void profiles_data()
    {
        QTest::addColumn<QString>("name");
        QTest::addColumn<bool>("valid");
        QTest::addColumn<int>("profile");
        QTest::newRow("strict") << "strict" << true << int(Profile::Strict);
        QTest::newRow("signed") << "signed" << true << int(Profile::Signed);
        QTest::newRow("legacy") << "legacy" << true << int(Profile::Legacy);
        QTest::newRow("guest") << "guest" << true << int(Profile::Guest);
        QTest::newRow("padded") << " legacy " << true << int(Profile::Legacy);
        QTest::newRow("case") << "Strict" << false << 0;
        QTest::newRow("unknown") << "smb1" << false << 0;
        QTest::newRow("none") << "none" << false << 0;
    }

    void profiles()
    {
        QFETCH(QString, name);
        QFETCH(bool, valid);
        QFETCH(int, profile);
        QVariantMap options;
        options.insert(QStringLiteral("security_profile"), name);
        options.insert(QStringLiteral("require_encryption"), false);   // ignored next to a profile
        Profile out = Profile::Signed;
        const Result r = profileFromOptions(options, &out);
        QCOMPARE(r.ok(), valid);
        if (valid) {
            QCOMPARE(int(out), profile);
            QCOMPARE(profileName(out), name.trimmed());
        } else {
            QCOMPARE(r.error(), Error::SecurityPolicy);
        }
    }

    // XM-1 table.
    void profileSettings()
    {
        const ProfileSettings strict = settingsFor(Profile::Strict);
        QCOMPARE(strict.version, quint16(SMB2_VERSION_ANY3));
        QVERIFY(strict.signing);
        QCOMPARE(strict.encryption, Encryption::Required);
        QVERIFY(!strict.guest);
        const ProfileSettings signedOnly = settingsFor(Profile::Signed);
        QCOMPARE(signedOnly.version, quint16(SMB2_VERSION_ANY3));
        QVERIFY(signedOnly.signing);
        QCOMPARE(signedOnly.encryption, Encryption::IfServerAsks);
        QVERIFY(!signedOnly.guest);
        const ProfileSettings legacy = settingsFor(Profile::Legacy);
        QCOMPARE(legacy.version, quint16(SMB2_VERSION_ANY));
        QVERIFY(legacy.signing);
        QCOMPARE(legacy.encryption, Encryption::IfServerAsks);
        QVERIFY(!legacy.guest);
        const ProfileSettings guest = settingsFor(Profile::Guest);
        QCOMPARE(guest.version, quint16(SMB2_VERSION_ANY));
        QVERIFY(!guest.signing);
        QCOMPARE(guest.encryption, Encryption::Off);
        QVERIFY(guest.guest);
    }

    // M-1, XM-1: what applyProfile() puts into a libsmb2 context.
    void appliedProfile()
    {
        for (const Profile profile : { Profile::Strict, Profile::Signed, Profile::Legacy, Profile::Guest }) {
            smb2_context *ctx = smb2_init_context();
            QVERIFY(ctx);
            applyProfile(ctx, profile, QStringLiteral("user"), QStringLiteral("DOM"), "secret", 30000);
            const bool guest = profile == Profile::Guest;
            QCOMPARE(QByteArray(smb2_get_user(ctx)), guest ? QByteArray() : QByteArray("user"));
            QCOMPARE(smb2_get_domain(ctx) != nullptr, !guest);
            smb2_destroy_context(ctx);
        }
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
        // XM-1: SMB 2.x only where the profile offered it.
        for (const Profile profile : { Profile::Strict, Profile::Signed }) {
            QVERIFY(!dialectAllowed(profile, 0x0202));
            QVERIFY(!dialectAllowed(profile, 0x0210));
            QVERIFY(dialectAllowed(profile, 0x0300));
            QVERIFY(dialectAllowed(profile, 0x0311));
            QVERIFY(!dialectAllowed(profile, 0));
        }
        for (const Profile profile : { Profile::Legacy, Profile::Guest }) {
            QVERIFY(dialectAllowed(profile, 0x0202));
            QVERIFY(dialectAllowed(profile, 0x0210));
            QVERIFY(dialectAllowed(profile, 0x0302));
            QVERIFY(!dialectAllowed(profile, 0x02ff));     // the SMB 2 wildcard is no dialect
            QVERIFY(!dialectAllowed(profile, 0x0100));
        }
    }

    // XM-1: a guest mapping is never accepted for an account.
    void sessionFlags()
    {
        for (const Profile profile : { Profile::Strict, Profile::Signed, Profile::Legacy }) {
            QVERIFY(checkSessionFlags(profile, 0).ok());
            QVERIFY(checkSessionFlags(profile, SMB2_SESSION_FLAG_IS_ENCRYPT_DATA).ok());
            const Result guest = checkSessionFlags(profile, SMB2_SESSION_FLAG_IS_GUEST);
            QCOMPARE(guest.error(), Error::SecurityPolicy);
            QCOMPARE(guest.message(), QLatin1String(GuestMappedMessage));
            QCOMPARE(checkSessionFlags(profile, SMB2_SESSION_FLAG_IS_NULL).error(), Error::SecurityPolicy);
            QCOMPARE(checkSessionFlags(profile, SMB2_SESSION_FLAG_IS_GUEST | SMB2_SESSION_FLAG_IS_ENCRYPT_DATA).error(),
                     Error::SecurityPolicy);
        }
        QVERIFY(checkSessionFlags(Profile::Guest, SMB2_SESSION_FLAG_IS_GUEST).ok());
        QVERIFY(checkSessionFlags(Profile::Guest, SMB2_SESSION_FLAG_IS_NULL).ok());
        QVERIFY(checkSessionFlags(Profile::Guest, 0).ok());
    }

    // XM-9
    void dfsReferrals()
    {
        for (const Stage stage : { Stage::SessionSetup, Stage::Established }) {
            const Result r = errorForStatus(SMB2_STATUS_PATH_NOT_COVERED, 0, stage, QStringLiteral("open"));
            QCOMPARE(r.error(), Error::Unsupported);
            QCOMPARE(r.detail(), QStringLiteral("DFS referral"));
            QCOMPARE(errorForStatus(0xC000026D, 0, stage, QString()).detail(), QStringLiteral("DFS referral"));
        }
        // Compound requests: -nterror_to_errno(STATUS_PATH_NOT_COVERED).
        const Result compound = errorForStatus(0, ENOEXEC, Stage::Established, QStringLiteral("stat"));
        QCOMPARE(compound.error(), Error::Unsupported);
        QCOMPARE(compound.detail(), QStringLiteral("DFS referral"));
        QCOMPARE(nterror_to_errno(SMB2_STATUS_PATH_NOT_COVERED), ENOEXEC);
        // XC-24: other statuses carry their code as the detail.
        QVERIFY(errorForStatus(SMB2_STATUS_ACCESS_DENIED, 0, Stage::Established, QString())
                    .detail().contains(QLatin1String("0xc0000022")));
    }

    // XC-4 for SMB: unpaired UTF-16 surrogates survive (WTF-8).
    void names()
    {
        const QString plain = QStringLiteral("ünïcödé €.txt");
        QCOMPARE(encodeName(plain), plain.toUtf8());
        QCOMPARE(decodeName(plain.toUtf8().constData()), plain);
        const QString emoji = QString::fromUtf8("a\xf0\x9f\x98\x80z");
        QCOMPARE(encodeName(emoji), emoji.toUtf8());
        QCOMPARE(decodeName(emoji.toUtf8().constData()), emoji);

        QString lone = QStringLiteral("x");
        lone.append(QChar(0xd800));
        lone.append(QStringLiteral("y"));
        lone.append(QChar(0xdc80));
        QCOMPARE(encodeName(lone), QByteArray("x\xed\xa0\x80y\xed\xb2\x80"));
        QCOMPARE(decodeName(encodeName(lone).constData()), lone);
        QString trailing = QStringLiteral("end");
        trailing.append(QChar(0xdbff));
        QCOMPARE(decodeName(encodeName(trailing).constData()), trailing);
        // Malformed input (libsmb2 never sends it) becomes U+FFFD, not a crash.
        QCOMPARE(decodeName("a\xff" "b"), QString::fromUtf8("a\xef\xbf\xbd" "b"));
        QCOMPARE(decodeName("\xc0\x80"), QString(QChar(0xfffd)));
        QCOMPARE(decodeName("\xe2\x82"), QString(2, QChar(0xfffd)));

        // libsmb2 with vendor/patches/libsmb2/0006: UTF-16 -> WTF-8 -> UTF-16.
        const std::array<uint16_t, 4> units = { 'a', 0xd800, 'b', 0xdc01 };
        const char *utf8 = smb2_utf16_to_utf8(units.data(), units.size());
        QVERIFY(utf8);
        QCOMPARE(QByteArray(utf8), QByteArray("a\xed\xa0\x80" "b\xed\xb0\x81"));
        QCOMPARE(decodeName(utf8).size(), 4);
        QCOMPARE(decodeName(utf8).at(1).unicode(), ushort(0xd800));
        smb2_utf16 *back = smb2_utf8_to_utf16(utf8);
        QVERIFY(back);
        QCOMPARE(back->len, 4);
        QCOMPARE(std::memcmp(back->val, units.data(), sizeof(units)), 0);
        free(back);
        free(const_cast<char *>(utf8));
        // A pair written as two 3-byte surrogates (CESU-8) is still refused.
        QVERIFY(!smb2_utf8_to_utf16("\xed\xa0\x80\xed\xb0\x80"));
        QVERIFY(smb2_utf8_to_utf16("\xed\xb0\x80\xed\xa0\x80"));   // trail then lead: two lone units
    }

    // XM-2
    void serverPaths()
    {
        QString share;
        QByteArray rest;
        QVERIFY(splitServerPath(QStringLiteral("/"), &share, &rest).ok());
        QVERIFY(share.isEmpty() && rest.isEmpty());
        QVERIFY(splitServerPath(QString(), &share, &rest).ok());
        QVERIFY(share.isEmpty() && rest.isEmpty());
        QVERIFY(splitServerPath(QStringLiteral("/data"), &share, &rest).ok());
        QCOMPARE(share, QStringLiteral("data"));
        QVERIFY(rest.isEmpty());
        QVERIFY(splitServerPath(QStringLiteral("/data//a/b/"), &share, &rest).ok());
        QCOMPARE(share, QStringLiteral("data"));
        QCOMPARE(rest, QByteArray("a/b"));
        QVERIFY(splitServerPath(QStringLiteral("C$/x"), &share, &rest).ok());
        QCOMPARE(share, QStringLiteral("C$"));
        QCOMPARE(splitServerPath(QStringLiteral("/da:ta/x"), &share, &rest).error(), Error::InvalidName);
        QVERIFY(!splitServerPath(QStringLiteral("/data/a:b"), &share, &rest).ok());
        QVERIFY(!splitServerPath(QStringLiteral("/data/../x"), &share, &rest).ok());
        QCOMPARE(splitServerPath(QStringLiteral("/") + QString(81, QLatin1Char('s')), &share, &rest).error(),
                 Error::InvalidName);
    }

    // XM-3
    void configuredShareList()
    {
        QVariantMap options;
        QVERIFY(configuredShares(options).isEmpty());
        options.insert(QStringLiteral("shares"), QStringLiteral(" media, backup ,,Media,bad:name, docs"));
        QCOMPARE(configuredShares(options), QStringList({ QStringLiteral("media"), QStringLiteral("backup"),
                                                         QStringLiteral("docs") }));
        options.insert(QStringLiteral("shares"),
                       QStringList({ QStringLiteral("a,b"), QStringLiteral("x"), QStringLiteral("X"), QString() }));
        QCOMPARE(configuredShares(options), QStringList({ QStringLiteral("x") }));
        options.insert(QStringLiteral("shares"), QVariantList({ QStringLiteral("one"), QStringLiteral("two") }));
        QCOMPARE(configuredShares(options), QStringList({ QStringLiteral("one"), QStringLiteral("two") }));
        QStringList merged { QStringLiteral("Media") };
        mergeShareNames(&merged, { QStringLiteral("media"), QStringLiteral("public") });
        QCOMPARE(merged, QStringList({ QStringLiteral("Media"), QStringLiteral("public") }));

        QVERIFY(validShareName(QStringLiteral("public")));
        QVERIFY(validShareName(QStringLiteral("C$")));
        QVERIFY(validShareName(QString(80, QLatin1Char('n'))));
        QVERIFY(!validShareName(QString(81, QLatin1Char('n'))));
        QVERIFY(!validShareName(QString()));
        QVERIFY(!validShareName(QStringLiteral("..")));
        QVERIFY(!validShareName(QStringLiteral("a/b")));
        QVERIFY(!validShareName(QStringLiteral("a\\b")));
        QVERIFY(!validShareName(QStringLiteral("a\tb")));
        QVERIFY(!validShareName(QString(QChar(0xd800))));
    }

    // XM-7: the request goes through stdin in this form only.
    void shareRequests()
    {
        ShareRequest request;
        request.server = "10.0.0.1:4450";
        request.user = "backup";
        request.domain = "WORK";
        request.profile = "legacy";
        request.requestTimeoutMs = 60000;
        request.secret = QByteArray("p\0ss:\nword", 10);
        const QByteArray encoded = encodeShareRequest(request);
        ShareRequest decoded;
        QVERIFY(decodeShareRequest(encoded, &decoded));
        QCOMPARE(decoded.server, request.server);
        QCOMPARE(decoded.user, request.user);
        QCOMPARE(decoded.domain, request.domain);
        QCOMPARE(decoded.profile, request.profile);
        QCOMPARE(decoded.requestTimeoutMs, 60000);
        QCOMPARE(decoded.secret, request.secret);
        QVERIFY(!decodeShareRequest(encoded + 'x', &decoded));
        QVERIFY(!decodeShareRequest(encoded.left(encoded.size() - 1), &decoded));
        QVERIFY(!decodeShareRequest(QByteArray(), &decoded));
        QByteArray wrongMagic = encoded;
        wrongMagic[5] = 'X';
        QVERIFY(!decodeShareRequest(wrongMagic, &decoded));
        request.server.clear();
        QVERIFY(!decodeShareRequest(encodeShareRequest(request), &decoded));
        request.server = "h";
        request.secret = QByteArray(MaxShareRequestBytes, 's');
        QVERIFY(!decodeShareRequest(encodeShareRequest(request), &decoded));
        QByteArray huge = encoded;
        huge[4 + 19] = '\x7f';          // the server field's length, high byte
        QVERIFY(!decodeShareRequest(huge, &decoded));
    }

    void shareOutput_data()
    {
        QTest::addColumn<QByteArray>("output");
        QTest::addColumn<int>("error");
        QTest::addColumn<int>("count");
        const QByteArray a = "{\"name\":\"media\",\"type\":0,\"remark\":\"Films\"}\n";
        const QByteArray ipc = "{\"name\":\"IPC$\",\"type\":2147483651,\"remark\":\"IPC\"}\n";
        QTest::newRow("empty list") << QByteArray("{\"end\":0}\n") << int(Error::None) << 0;
        QTest::newRow("two") << (a + ipc + "{\"end\":2}\n") << int(Error::None) << 2;
        QTest::newRow("duplicate kept once") << (a + a + "{\"end\":2}\n") << int(Error::None) << 1;
        QTest::newRow("no end") << a << int(Error::ProtocolError) << 0;
        QTest::newRow("no newline") << (a + "{\"end\":1}") << int(Error::ProtocolError) << 0;
        QTest::newRow("count mismatch") << (a + "{\"end\":2}\n") << int(Error::ProtocolError) << 0;
        QTest::newRow("end with more") << (a + "{\"end\":1,\"x\":1}\n") << int(Error::ProtocolError) << 0;
        QTest::newRow("after end") << ("{\"end\":0}\n" + a) << int(Error::ProtocolError) << 0;
        QTest::newRow("empty") << QByteArray() << int(Error::ProtocolError) << 0;
        QTest::newRow("blank line") << (a + "\n{\"end\":1}\n") << int(Error::ProtocolError) << 0;
        QTest::newRow("not json") << QByteArray("hello\n") << int(Error::ProtocolError) << 0;
        QTest::newRow("array") << QByteArray("[1]\n{\"end\":0}\n") << int(Error::ProtocolError) << 0;
        QTest::newRow("extra field") << QByteArray("{\"name\":\"a\",\"type\":0,\"remark\":\"\",\"path\":\"/\"}\n{\"end\":1}\n")
                                     << int(Error::ProtocolError) << 0;
        QTest::newRow("missing remark") << QByteArray("{\"name\":\"a\",\"type\":0}\n{\"end\":1}\n") << int(Error::ProtocolError) << 0;
        QTest::newRow("type string") << QByteArray("{\"name\":\"a\",\"type\":\"0\",\"remark\":\"\"}\n{\"end\":1}\n")
                                     << int(Error::ProtocolError) << 0;
        QTest::newRow("type negative") << QByteArray("{\"name\":\"a\",\"type\":-1,\"remark\":\"\"}\n{\"end\":1}\n")
                                       << int(Error::ProtocolError) << 0;
        QTest::newRow("type fraction") << QByteArray("{\"name\":\"a\",\"type\":0.5,\"remark\":\"\"}\n{\"end\":1}\n")
                                       << int(Error::ProtocolError) << 0;
        QTest::newRow("type too big") << QByteArray("{\"name\":\"a\",\"type\":4294967296,\"remark\":\"\"}\n{\"end\":1}\n")
                                      << int(Error::ProtocolError) << 0;
        QTest::newRow("name with slash") << QByteArray("{\"name\":\"a/b\",\"type\":0,\"remark\":\"\"}\n{\"end\":1}\n")
                                         << int(Error::ProtocolError) << 0;
        QTest::newRow("name dotdot") << QByteArray("{\"name\":\"..\",\"type\":0,\"remark\":\"\"}\n{\"end\":1}\n")
                                     << int(Error::ProtocolError) << 0;
        QTest::newRow("name empty") << QByteArray("{\"name\":\"\",\"type\":0,\"remark\":\"\"}\n{\"end\":1}\n")
                                    << int(Error::ProtocolError) << 0;
        QTest::newRow("error") << QByteArray("{\"error\":\"AuthFailed\",\"message\":\"wrong password\"}\n")
                               << int(Error::AuthFailed) << 0;
        QTest::newRow("error after shares") << (a + "{\"error\":\"Timeout\",\"message\":\"slow\"}\n") << int(Error::Timeout) << 0;
        QTest::newRow("error not last") << QByteArray("{\"error\":\"Timeout\",\"message\":\"\"}\n{\"end\":0}\n")
                                        << int(Error::ProtocolError) << 0;
        QTest::newRow("error unknown") << QByteArray("{\"error\":\"Bogus\",\"message\":\"\"}\n") << int(Error::ProtocolError) << 0;
        QTest::newRow("error internal") << QByteArray("{\"error\":\"Canceled\",\"message\":\"\"}\n") << int(Error::ProtocolError) << 0;
        QTest::newRow("error none") << QByteArray("{\"error\":\"None\",\"message\":\"\"}\n") << int(Error::ProtocolError) << 0;
        QTest::newRow("long line") << (QByteArray("{\"name\":\"a\",\"type\":0,\"remark\":\"") + QByteArray(MaxShareLineBytes, 'r')
                                       + "\"}\n{\"end\":1}\n")
                                   << int(Error::ProtocolError) << 0;
        QByteArray many;
        for (int i = 0; i <= MaxShares; ++i)
            many += "{\"name\":\"s" + QByteArray::number(i) + "\",\"type\":0,\"remark\":\"\"}\n";
        QTest::newRow("too many") << (many + "{\"end\":" + QByteArray::number(MaxShares + 1) + "}\n")
                                  << int(Error::ProtocolError) << 0;
        QTest::newRow("too much") << QByteArray(MaxShareOutputBytes + 1, '\n') << int(Error::ProtocolError) << 0;
        // Well-formed but over 1 MiB: long remarks (each capped, each line short enough).
        QByteArray large;
        for (int i = 0; i < 200; ++i)
            large += "{\"name\":\"s" + QByteArray::number(i) + "\",\"type\":0,\"remark\":\"" + QByteArray(6000, 'r') + "\"}\n";
        QTest::newRow("too much, well-formed") << (large + "{\"end\":200}\n") << int(Error::ProtocolError) << 0;
    }

    // XM-7: the helper's output is parsed defensively.
    void shareOutput()
    {
        QFETCH(QByteArray, output);
        QFETCH(int, error);
        QFETCH(int, count);
        QVector<ShareInfo> shares;
        shares.append(ShareInfo());   // replaced, also on failure
        const Result r = parseShareOutput(output, &shares);
        QCOMPARE(int(r.error()), error);
        QCOMPARE(shares.size(), count);
    }

    void shareOutputFields()
    {
        QVector<ShareInfo> shares;
        QByteArray remark = "{\"name\":\"media\",\"type\":0,\"remark\":\"a\\u0007b";
        remark += QByteArray(300, 'r') + "\"}\n{\"end\":1}\n";
        QVERIFY(parseShareOutput(remark, &shares).ok());
        QCOMPARE(shares.size(), 1);
        QCOMPARE(shares.first().name, QStringLiteral("media"));
        QCOMPARE(shares.first().type, quint32(0));
        QCOMPARE(shares.first().remark.size(), MaxRemarkLength - 1);   // capped, BEL removed
        QVERIFY(shares.first().remark.startsWith(QLatin1String("abr")));
        const Result error = parseShareOutput("{\"error\":\"SecurityPolicy\",\"message\":\"guest\"}\n", &shares);
        QCOMPARE(error.message(), QStringLiteral("guest"));
        // Round trip through the helper's own writers.
        ShareInfo info;
        info.name = QStringLiteral("Fotos 2026 ü ©");
        info.type = 0x80000000;
        info.remark = QStringLiteral("ünï");
        QVERIFY(parseShareOutput(shareLine(info) + '\n' + endLine(1) + '\n', &shares).ok());
        QCOMPARE(shares.first().name, info.name);
        QCOMPARE(shares.first().type, info.type);
        QCOMPARE(shares.first().remark, info.remark);
        QCOMPARE(parseShareOutput(errorLine(Result(Error::AuthFailed, QStringLiteral("no"))) + '\n', &shares).error(),
                 Error::AuthFailed);
    }

    // XM-7: disk shares only; '$' shares on request.
    void shareFilter()
    {
        ShareInfo share;
        share.name = QStringLiteral("media");
        QVERIFY(shareVisible(share, false));
        share.type = 0x80000000;            // STYPE_SPECIAL disk share
        QVERIFY(shareVisible(share, false));
        share.type = 1;                     // print queue
        QVERIFY(!shareVisible(share, true));
        share.type = 2;                     // device
        QVERIFY(!shareVisible(share, true));
        share.type = 0x80000003;            // IPC$
        share.name = QStringLiteral("IPC$");
        QVERIFY(!shareVisible(share, true));
        share.type = 0x80000000;
        share.name = QStringLiteral("C$");
        QVERIFY(!shareVisible(share, false));
        QVERIFY(shareVisible(share, true));
        share.name = QStringLiteral("a$b");
        QVERIFY(shareVisible(share, false));
        share.type = 0x02000000;            // cluster file system share: a disk share
        QVERIFY(shareVisible(share, false));
    }

    // XM-7: runShareHelper() against stand-in helpers.
    void helperProcess_data()
    {
        QTest::addColumn<QByteArray>("script");
        QTest::addColumn<int>("error");
        QTest::addColumn<int>("count");
        const QByteArray ok = "printf '{\"name\":\"a\",\"type\":0,\"remark\":\"r\"}\\n{\"end\":1}\\n'";
        QTest::newRow("ok") << ok << int(Error::None) << 1;
        QTest::newRow("ok but exit 3") << (ok + "; exit 3") << int(Error::ProtocolError) << 0;
        QTest::newRow("crash") << QByteArray("kill -SEGV $$") << int(Error::ProtocolError) << 0;
        QTest::newRow("crash after output") << (ok + "; kill -KILL $$") << int(Error::ProtocolError) << 0;
        QTest::newRow("garbage") << QByteArray("echo hello") << int(Error::ProtocolError) << 0;
        QTest::newRow("silent") << QByteArray("true") << int(Error::ProtocolError) << 0;
        QTest::newRow("error line") << QByteArray("printf '{\"error\":\"AuthFailed\",\"message\":\"no\"}\\n'; exit 1")
                                    << int(Error::AuthFailed) << 0;
        QTest::newRow("error line, exit 0") << QByteArray("printf '{\"error\":\"AuthFailed\",\"message\":\"no\"}\\n'")
                                            << int(Error::ProtocolError) << 0;
        QTest::newRow("flood") << QByteArray("yes '{\"end\":0}'") << int(Error::ProtocolError) << 0;
    }

    void helperProcess()
    {
        QFETCH(QByteArray, script);
        QFETCH(int, error);
        QFETCH(int, count);
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString program = writeScript(dir, "cat > \"$(dirname \"$0\")/stdin\"\n" + script + '\n');
        QByteArray request = testRequest();
        const QByteArray sent = request;
        const std::atomic<bool> cancel { false };
        QVector<ShareInfo> shares;
        const Result r = runShareHelper(program, &request, 10000, cancel, &shares);
        QVERIFY2(int(r.error()) == error, qPrintable(r.toString()));
        if (QByteArray(QTest::currentDataTag()).startsWith("crash"))
            QVERIFY2(r.message().contains(QLatin1String("crashed")), qPrintable(r.message()));
        QCOMPARE(shares.size(), count);
        // XSEC-6: the caller's copy of the request is wiped.
        QVERIFY(!request.contains("hunter2"));
        // The request arrived on stdin, whole.
        QFile in(dir.filePath(QStringLiteral("stdin")));
        QVERIFY(in.open(QIODevice::ReadOnly));
        QCOMPARE(in.readAll(), sent);
    }

    // XM-7: the secret is never in argv or the environment; M-5 applies.
    void helperEnvironment()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString program = writeScript(dir, "d=$(dirname \"$0\"); cat > /dev/null; echo \"$@\" > \"$d/argv\"; "
                                                 "env > \"$d/env\"; printf '{\"end\":0}\\n'\n");
        qputenv("NTLM_USER_FILE", "/nonexistent");
        QByteArray request = testRequest();
        const std::atomic<bool> cancel { false };
        QVector<ShareInfo> shares;
        QVERIFY(runShareHelper(program, &request, 10000, cancel, &shares).ok());
        QFile argv(dir.filePath(QStringLiteral("argv")));
        QFile env(dir.filePath(QStringLiteral("env")));
        QVERIFY(argv.open(QIODevice::ReadOnly) && env.open(QIODevice::ReadOnly));
        const QByteArray environment = env.readAll();
        QVERIFY(!argv.readAll().contains("hunter2"));
        QVERIFY(!environment.contains("hunter2"));
        QVERIFY(!environment.contains("NTLM_USER_FILE"));
    }

    // C-9, C-14: a stalled helper is killed on cancel and at the timeout.
    void helperStalls()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString program = writeScript(dir, "exec sleep 30\n");
        QVector<ShareInfo> shares;
        QElapsedTimer clock;
        clock.start();
        QByteArray request = testRequest();
        std::atomic<bool> cancel { false };
        QCOMPARE(runShareHelper(program, &request, 500, cancel, &shares).error(), Error::Timeout);
        QVERIFY2(clock.elapsed() < 2000, qPrintable(QString::number(clock.elapsed())));
        std::thread canceller([&cancel]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            cancel = true;
        });
        clock.restart();
        request = testRequest();
        QCOMPARE(runShareHelper(program, &request, 30000, cancel, &shares).error(), Error::Canceled);
        canceller.join();
        QVERIFY2(clock.elapsed() < 2000, qPrintable(QString::number(clock.elapsed())));
        QVERIFY(!request.contains("hunter2"));
        request = testRequest();
        QCOMPARE(runShareHelper(dir.filePath(QStringLiteral("missing")), &request, 1000, cancel, &shares).error(),
                 Error::ProtocolError);
        QVERIFY(!request.contains("hunter2"));
    }

    // XM-7: the real helper rejects a bad request and reports a server it
    // cannot reach as an error line.
    void helperBinary()
    {
        const QString program = QStringLiteral(NETVFS_TEST_SHARES_HELPER);
        if (!QFile::exists(program))
            QSKIP("netvfs-smb-shares is not built");
        QByteArray garbage = "not a request";
        const std::atomic<bool> cancel { false };
        QVector<ShareInfo> shares;
        const Result bad = runShareHelper(program, &garbage, 10000, cancel, &shares);
        QCOMPARE(bad.error(), Error::ProtocolError);
        ShareRequest request;
        request.server = "127.0.0.1:" + QByteArray::number(closedPort());
        request.user = "backup";
        request.profile = "strict";
        request.requestTimeoutMs = 5000;
        request.secret = "hunter2";
        QByteArray encoded = encodeShareRequest(request);
        const Result unreachable = runShareHelper(program, &encoded, 10000, cancel, &shares);
        QVERIFY2(unreachable.error() == Error::NetworkUnreachable || unreachable.error() == Error::SecurityPolicy,
                 qPrintable(unreachable.toString()));
        request.profile = "weak";
        encoded = encodeShareRequest(request);
        QCOMPARE(runShareHelper(program, &encoded, 10000, cancel, &shares).error(), Error::ProtocolError);
        QVERIFY(shares.isEmpty());
    }

    // SPEC-v2 XM-7: ShareEnumeration only with an installed helper.
    void helperInstalled()
    {
        qputenv("NETVFS_SMB_SHARES_HELPER", "/nonexistent/netvfs-smb-shares");
        QVERIFY(!shareHelperInstalled());
        QCOMPARE(shareHelperPath(), QStringLiteral("/nonexistent/netvfs-smb-shares"));
        qputenv("NETVFS_SMB_SHARES_HELPER", QFile::encodeName(QStandardPaths::findExecutable(QStringLiteral("true"))));
        QVERIFY(shareHelperInstalled());
        qunsetenv("NETVFS_SMB_SHARES_HELPER");
        QCOMPARE(shareHelperPath(), QStringLiteral("/usr/libexec/netvfs/netvfs-smb-shares"));
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
        QCOMPARE(backend->makeDir(QStringLiteral("a"), true).error(), Error::Internal);
        QCOMPARE(backend->remove(QStringLiteral("a")).error(), Error::Internal);
        QCOMPARE(backend->removeDir(QStringLiteral("a")).error(), Error::Internal);
        QCOMPARE(backend->rename(QStringLiteral("a"), QStringLiteral("b"), RenameMode::Replace).error(), Error::Internal);
        QCOMPARE(backend->rename(QStringLiteral("a"), QStringLiteral("b"), RenameMode::NoReplace).error(), Error::Internal);
        QCOMPARE(backend->freeSpace(QString(), &bytes).error(), Error::Internal);
        QCOMPARE(backend->upload(&buffer, QStringLiteral("a"), UploadOptions(), nullptr).error(), Error::Internal);
        QCOMPARE(backend->download(QStringLiteral("a"), &buffer, DownloadOptions(), nullptr).error(), Error::Internal);
        QCOMPARE(backend->read(QStringLiteral("a"), 0, 1, &data).error(), Error::Internal);
        QCOMPARE(backend->read(QStringLiteral("a"), -1, 1, &data).error(), Error::Internal);
        QCOMPARE(backend->keepAlive().error(), Error::Internal);
        AttributeChanges times;
        times.modified = QDateTime::currentDateTimeUtc();
        QCOMPARE(backend->setAttributes(QStringLiteral("a"), times).error(), Error::Internal);
        WriteHandle *writer = nullptr;
        QCOMPARE(backend->openWrite(QStringLiteral("a"), WriteOptions(), &writer).error(), Error::Internal);
        QVERIFY(!writer);
        ReadHandle *reader = nullptr;
        QCOMPARE(backend->openRead(QStringLiteral("a"), &reader).error(), Error::Internal);
        QVERIFY(!reader);
        SpaceInfo space;
        QCOMPARE(backend->spaceInfo(QString(), &space).error(), Error::Internal);
        // XC-11: what SMB cannot store is refused before anything else.
        AttributeChanges mode;
        mode.mode = 0644;
        QCOMPARE(backend->setAttributes(QStringLiteral("a"), mode).error(), Error::Unsupported);
        QVERIFY(backend->capabilities().flags.isEmpty());   // XC-5: valid after authenticate()
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
        const LocalPeer peer(LocalPeer::Mode::CloseAtOnce);
        const auto backend = smbBackend();
        ConnectionParams params = localParams(peer.port());
        QVERIFY(backend->connect(params, nullptr).ok());
        QCOMPARE(backend->authenticate(Credentials(QStringLiteral("backup"), QByteArray())).error(),
                 Error::AuthFailed);
        // XM-1, XSEC-2: an unknown profile is refused, nothing weaker tried.
        params.options.insert(QStringLiteral("security_profile"), QStringLiteral("smb1"));
        QVERIFY(backend->connect(params, nullptr).ok());
        const Result unknown = backend->authenticate(testCredentials());
        QCOMPARE(unknown.error(), Error::SecurityPolicy);
        QVERIFY2(unknown.message().contains(QLatin1String("smb1")), qPrintable(unknown.message()));
        QTRY_COMPARE(peer.accepted(), 2);   // nothing beyond the two probes

        // XM-1: guest needs no credentials; XM-2: no share is server mode
        // (IPC$). Both go on to the session setup, which this peer ends.
        params.options.insert(QStringLiteral("security_profile"), QStringLiteral("guest"));
        params.options.remove(QStringLiteral("share"));
        QVERIFY(backend->connect(params, nullptr).ok());
        QCOMPARE(backend->authenticate(Credentials()).error(), Error::SecurityPolicy);
        QTRY_COMPARE(peer.accepted(), 4);
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

    // M-13 (C-8 hand-over): an idle connection may move to another thread.
    void otherThread()
    {
        const LocalPeer peer(LocalPeer::Mode::CloseAtOnce);
        const auto backend = smbBackend();
        QVERIFY(backend->connect(localParams(peer.port()), nullptr).ok());
        // A real second thread: QFuture::result() may run a task that has not
        // started yet on the waiting thread itself.
        Result r;
        std::thread other([&backend, &r]() { r = backend->authenticate(testCredentials()); });
        other.join();
        // It got as far as the session setup, which this peer ends.
        QVERIFY2(r.error() == Error::SecurityPolicy, qPrintable(r.toString()));
    }

    // M-13: but never two threads at once.
    void concurrentThreads()
    {
        const LocalPeer peer(LocalPeer::Mode::Silent);
        const auto backend = smbBackend();
        QVERIFY(backend->connect(localParams(peer.port()), nullptr).ok());
        std::atomic<bool> inside { false };
        Result signIn;
        std::thread other([&backend, &signIn, &inside]() {
            inside = true;
            signIn = backend->authenticate(testCredentials());   // stalls: the peer never answers
        });
        QTRY_VERIFY(inside);
        QTest::qWait(300);
        Entry entry;
        const Result busy = backend->stat(QStringLiteral("x"), &entry);
        QCOMPARE(busy.error(), Error::Internal);
        QVERIFY2(busy.message().contains(QLatin1String("one thread at a time")), qPrintable(busy.message()));
        QCOMPARE(backend->keepAlive().error(), Error::Internal);
        backend->cancel();                          // thread-safe (C-9)
        other.join();
        QCOMPARE(signIn.error(), Error::Canceled);
        backend->resetCancel();
        // Idle again: this thread may use it.
        QCOMPARE(backend->stat(QStringLiteral("x"), &entry).message(), QStringLiteral("Not signed in"));
    }
};

QTEST_GUILESS_MAIN(TestSmb)
#include "tst_smb.moc"
