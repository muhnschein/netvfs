// SPDX-License-Identifier: LGPL-2.1-or-later
#include "accountsession.h"
#include "accountsfixture.h"
#include "backendjobs.h"
#include "fakebackend.h"
#include "netvfshelpers.h"
#include "netvfsprobe.h"
#include "secretsource.h"
#include "../qmltestutil.h"

#include <Accounts/Manager>

#include <QtCore/QMutexLocker>
#include <QtCore/QTimer>
#include <QtTest/QtTest>

#include <memory>

using namespace NetVfs;
using NetVfs::Test::AccountsFixture;
using NetVfs::Test::FakeBackend;
using NetVfs::Test::FakeServer;
using NetVfsUi::NetVfsProbe;

namespace {
const QByteArray KeyBlob("\x00\x00\x00\x0bssh-ed25519 server-key", 26);
const QByteArray OtherBlob("\x00\x00\x00\x0bssh-ed25519 other-key!", 26);

ServerIdentity identityOf(const QByteArray &blob)
{
    ServerIdentity identity;
    identity.algorithm = QStringLiteral("ssh-ed25519");
    identity.publicKey = blob;
    identity.fingerprint = NetVfsUi::sha256Fingerprint(blob);
    return identity;
}

QString pinOf(const QByteArray &blob)
{
    return identityOf(blob).toPin();
}

QVariantMap params(const QString &pin = QString(), const QString &provider = QStringLiteral("fake"))
{
    QVariantMap options;
    if (!pin.isEmpty())
        options.insert(QStringLiteral("host_key"), pin);
    QVariantMap map;
    map.insert(QStringLiteral("provider"), provider);
    map.insert(QStringLiteral("host"), QStringLiteral("server.example"));
    map.insert(QStringLiteral("username"), QStringLiteral("user"));
    map.insert(QStringLiteral("options"), options);
    return map;
}

QVariantMap credentials(const QString &secret)
{
    QVariantMap map;
    map.insert(QStringLiteral("secret"), secret);
    return map;
}

QStringList serverLog()
{
    FakeServer *server = FakeServer::instance();
    QMutexLocker lock(&server->mutex);
    return server->log;
}

bool logHas(const QString &prefix)
{
    for (const QString &entry : serverLog()) {
        if (entry.startsWith(prefix))
            return true;
    }
    return false;
}

// Delivers a fixed outcome asynchronously, as signond would.
class StaticSecretSource : public SecretSource
{
public:
    explicit StaticSecretSource(const Result &result, const Credentials &credentials = Credentials())
        : m_result(result), m_credentials(credentials) {}

    void fetch(quint32 id) override
    {
        Q_UNUSED(id)
        QTimer::singleShot(0, this, [this]() {
            if (m_result.ok())
                emit fetched(m_credentials);
            else
                emit failed(m_result);
        });
    }

private:
    Result m_result;
    Credentials m_credentials;
};
} // namespace

class TestQmlProbe : public QObject
{
    Q_OBJECT

private:
    std::unique_ptr<AccountsFixture> fixture;

    NetVfsProbe::SessionFactory sessionFactory(const Result &secretResult)
    {
        Accounts::Manager *manager = fixture->manager();
        return [manager, secretResult](int accountId, Service service, QObject *parent) {
            auto secrets = std::make_unique<StaticSecretSource>(secretResult, Credentials(QString(), "secret"));
            auto session = std::make_unique<AccountSession>(manager, secrets.release(), parent);
            AccountSession *raw = session.release();
            QTimer::singleShot(0, raw, [raw, accountId, service]() { raw->start(accountId, service); });
            return raw;
        };
    }

    int createAccount(const QString &pin, const QString &backupsPath = QString(),
                      const QVariantMap &options = QVariantMap())
    {
        QVariantMap globals;
        globals.insert(QStringLiteral("netvfs/host"), QStringLiteral("server.example"));
        globals.insert(QStringLiteral("netvfs/username"), QStringLiteral("user"));
        globals.insert(QStringLiteral("netvfs/fake/host_key"), pin);
        for (auto it = options.constBegin(); it != options.constEnd(); ++it)
            globals.insert(QStringLiteral("netvfs/fake/") + it.key(), it.value());
        return fixture->createAccount(QStringLiteral("fake"), globals, backupsPath, 7);
    }

    static QVariantMap pinOptions(const QString &pin)
    {
        QVariantMap options;
        options.insert(QStringLiteral("host_key"), pin);
        return options;
    }

    static ServerIdentity tlsIdentity(bool trusted)
    {
        ServerIdentity identity = ServerIdentity::fromTlsSpki(QByteArray("server-spki"));
        identity.systemTrusted = trusted;
        if (!trusted)
            identity.problems = ServerIdentity::SelfSigned;
        return identity;
    }

private slots:
    void initTestCase()
    {
        fixture = std::make_unique<AccountsFixture>(QStringList { QStringLiteral("fake") });
        QVERIFY(fixture->isValid());
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
        QVERIFY(Test::installEngineeringEnglish(this));
    }

    void init()
    {
        FakeServer::instance()->reset();
    }

    void identifySendsNoCredentials()
    {
        // SPEC C-7, S-7: identify on creation reports the key as unknown.
        FakeServer::instance()->identity = identityOf(KeyBlob);
        NetVfsProbe probe;
        QSignalSpy identified(&probe, &NetVfsProbe::identified);
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.identify(params());
        QCOMPARE(probe.state(), NetVfsProbe::State::Identifying);
        QVERIFY(probe.busy());
        QTRY_COMPARE(identified.count(), 1);
        QCOMPARE(failed.count(), 0);
        QCOMPARE(probe.state(), NetVfsProbe::State::Identified);
        QVERIFY(!probe.busy());
        QCOMPARE(probe.identityStatus(), NetVfsProbe::IdentityStatus::IdentityUnknown);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::NoError);
        const QVariantMap identity = probe.serverIdentity();
        QCOMPARE(identity.value(QStringLiteral("algorithm")).toString(), QStringLiteral("ssh-ed25519"));
        QCOMPARE(identity.value(QStringLiteral("fingerprint")).toString(), NetVfsUi::sha256Fingerprint(KeyBlob));
        QCOMPARE(identity.value(QStringLiteral("pin")).toString(), pinOf(KeyBlob));
        QCOMPARE(serverLog(), QStringList({ QStringLiteral("connect"), QStringLiteral("disconnect") }));
    }

    void identifyComparesPin_data()
    {
        QTest::addColumn<QByteArray>("serverKey");
        QTest::addColumn<QString>("pin");
        QTest::addColumn<int>("status");
        QTest::newRow("matches") << KeyBlob << pinOf(KeyBlob) << int(NetVfsProbe::IdentityStatus::IdentityMatches);
        QTest::newRow("changed") << OtherBlob << pinOf(KeyBlob) << int(NetVfsProbe::IdentityStatus::IdentityChanged);
        QTest::newRow("no identity") << QByteArray() << QString() << int(NetVfsProbe::IdentityStatus::NoIdentity);
        QTest::newRow("identity vanished") << QByteArray() << pinOf(KeyBlob) << int(NetVfsProbe::IdentityStatus::IdentityChanged);
    }

    void identifyComparesPin()
    {
        QFETCH(QByteArray, serverKey);
        QFETCH(QString, pin);
        QFETCH(int, status);
        if (!serverKey.isEmpty())
            FakeServer::instance()->identity = identityOf(serverKey);
        NetVfsProbe probe;
        QSignalSpy identified(&probe, &NetVfsProbe::identified);
        probe.identify(params(pin));
        QTRY_COMPARE(identified.count(), 1);
        QCOMPARE(int(probe.identityStatus()), status);
        QVERIFY(!logHas(QStringLiteral("authenticate")));
        QCOMPARE(probe.serverIdentity().isEmpty(), serverKey.isEmpty());
    }

    void identifyFailure()
    {
        FakeServer::instance()->connectResult = Result(Error::NetworkUnreachable, QStringLiteral("no route to host"));
        NetVfsProbe probe;
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        QSignalSpy identified(&probe, &NetVfsProbe::identified);
        probe.identify(params());
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(identified.count(), 0);
        QCOMPARE(probe.state(), NetVfsProbe::State::Failed);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::NetworkUnreachable);
        QCOMPARE(probe.errorText(),
                 QStringLiteral("Cannot reach the server. Check the server name, the port and the network connection."));
        QCOMPARE(probe.errorDetail(), QStringLiteral("no route to host"));
        QCOMPARE(probe.identityStatus(), NetVfsProbe::IdentityStatus::IdentityNotChecked);
    }

    void missingBackend()
    {
        NetVfsProbe probe;
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.identify(params(QString(), QStringLiteral("nope")));
        QCOMPARE(failed.count(), 1);
        QCOMPARE(probe.state(), NetVfsProbe::State::Failed);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::Unsupported);
        QCOMPARE(probe.errorText(), QStringLiteral("Support for this kind of server is not installed on this device."));
        probe.verify(params(QString(), QStringLiteral("nope")), credentials(QStringLiteral("secret")), QString());
        QCOMPARE(failed.count(), 2);
    }

    void verifyWritesProbeFile()
    {
        // SPEC 7.2: authenticate, makePath, probe file written and removed, free space.
        FakeServer *server = FakeServer::instance();
        server->identity = identityOf(KeyBlob);
        server->freeBytes = 123456789;
        NetVfsProbe probe;
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        probe.verify(params(pinOf(KeyBlob)), credentials(QStringLiteral("secret")), QStringLiteral("Sailfish OS/Backups"));
        QCOMPARE(probe.state(), NetVfsProbe::State::Verifying);
        QTRY_COMPARE(verified.count(), 1);
        QCOMPARE(probe.state(), NetVfsProbe::State::Verified);
        QCOMPARE(probe.freeBytes(), Q_INT64_C(123456789));
        QCOMPARE(probe.identityStatus(), NetVfsProbe::IdentityStatus::IdentityMatches);
        QVERIFY(server->exists(QStringLiteral("Sailfish OS/Backups")));
        const QStringList log = serverLog();
        QCOMPARE(log.value(0), QStringLiteral("connect"));
        QCOMPARE(log.value(1), QStringLiteral("authenticate"));
        QVERIFY(logHas(QStringLiteral("upload:Sailfish OS/Backups/.netvfs-probe-")));
        QVERIFY(logHas(QStringLiteral("removeFile:Sailfish OS/Backups/.netvfs-probe-")));
        // S-20 via XC-23: the backups folder is created the way backups create it.
        QCOMPARE(server->lastParams.option(QStringLiteral("dir_mode")), QStringLiteral("0700"));
        QCOMPARE(server->node(QStringLiteral("Sailfish OS")).mode, 0700);
        QCOMPARE(server->node(QStringLiteral("Sailfish OS/Backups")).mode, 0700);
        QCOMPARE(log.last(), QStringLiteral("disconnect"));
    }

    void verifyWithoutFreeSpace()
    {
        FakeServer::instance()->freeBytes = -1;
        NetVfsProbe probe;
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        probe.verify(params(), credentials(QStringLiteral("secret")), QStringLiteral("b"));
        QTRY_COMPARE(verified.count(), 1);
        QCOMPARE(probe.freeBytes(), Q_INT64_C(-1));
        QCOMPARE(probe.identityStatus(), NetVfsProbe::IdentityStatus::NoIdentity);
    }

    void verifyChecksPinBeforeCredentials_data()
    {
        QTest::addColumn<QString>("pin");
        QTest::addColumn<int>("error");
        QTest::addColumn<int>("status");
        QTest::newRow("no pin") << QString() << int(NetVfsProbe::ErrorCode::ServerIdentityUnknown) << int(NetVfsProbe::IdentityStatus::IdentityUnknown);
        QTest::newRow("other pin") << pinOf(OtherBlob) << int(NetVfsProbe::ErrorCode::ServerIdentityChanged)
                                   << int(NetVfsProbe::IdentityStatus::IdentityChanged);
    }

    void verifyChecksPinBeforeCredentials()
    {
        // SEC-1: no credential leaves the device unless the identity matches.
        QFETCH(QString, pin);
        QFETCH(int, error);
        QFETCH(int, status);
        FakeServer::instance()->identity = identityOf(KeyBlob);
        NetVfsProbe probe;
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.verify(params(pin), credentials(QStringLiteral("secret")), QStringLiteral("b"));
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(int(probe.error()), error);
        QCOMPARE(int(probe.identityStatus()), status);
        QCOMPARE(probe.serverIdentity().value(QStringLiteral("pin")).toString(), pinOf(KeyBlob));
        QVERIFY(!logHas(QStringLiteral("authenticate")));
    }

    void verifyErrors_data()
    {
        QTest::addColumn<QString>("secret");
        QTest::addColumn<QString>("failOp");
        QTest::addColumn<int>("error");
        QTest::addColumn<QString>("text");
        QTest::newRow("wrong secret") << "wrong" << QString() << int(NetVfsProbe::ErrorCode::AuthFailed)
                                      << "The server refused the sign-in. Check the user name and the password or key.";
        QTest::newRow("no permission") << "secret" << "makeDir" << int(NetVfsProbe::ErrorCode::PermissionDenied)
                                       << "The server does not allow writing to the backups folder.";
        QTest::newRow("upload fails") << "secret" << "upload" << int(NetVfsProbe::ErrorCode::PermissionDenied)
                                      << "The server does not allow writing to the backups folder.";
    }

    void verifyErrors()
    {
        QFETCH(QString, secret);
        QFETCH(QString, failOp);
        QFETCH(int, error);
        QFETCH(QString, text);
        if (!failOp.isEmpty())
            FakeServer::instance()->failOps.insert(failOp, Result(static_cast<Error>(error), QStringLiteral("detail")));
        NetVfsProbe probe;
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.verify(params(), credentials(secret), QStringLiteral("b"));
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(int(probe.error()), error);
        QCOMPARE(probe.errorText(), text);
        QVERIFY(!probe.errorDetail().isEmpty());
    }

    void verifyUsesGivenUserName()
    {
        QVariantMap creds = credentials(QStringLiteral("secret"));
        creds.insert(QStringLiteral("username"), QStringLiteral("someone-else"));
        NetVfsProbe probe;
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.verify(params(), creds, QStringLiteral("b"));
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::AuthFailed);
    }

    void cancelReachesBackend()
    {
        // SPEC C-9 through the UI: cancel() stops the call in flight and
        // discards its result.
        FakeServer::instance()->chunkDelayMs = 600;
        NetVfsProbe probe;
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.verify(params(), credentials(QStringLiteral("secret")), QStringLiteral("b"));
        QTRY_VERIFY(logHas(QStringLiteral("upload:")));
        probe.cancel();
        QCOMPARE(probe.state(), NetVfsProbe::State::Idle);
        QVERIFY(!probe.busy());
        QTest::qWait(900);
        QCOMPARE(verified.count(), 0);
        QCOMPARE(failed.count(), 0);
        QCOMPARE(probe.state(), NetVfsProbe::State::Idle);
        QVERIFY(!logHas(QStringLiteral("spaceInfo:")));

        // The probe is usable again afterwards.
        FakeServer::instance()->chunkDelayMs = 0;
        probe.identify(params());
        QSignalSpy identified(&probe, &NetVfsProbe::identified);
        QTRY_COMPARE(identified.count(), 1);
    }

    void newOperationDiscardsOld()
    {
        FakeServer::instance()->chunkDelayMs = 300;
        NetVfsProbe probe;
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        QSignalSpy identified(&probe, &NetVfsProbe::identified);
        probe.verify(params(), credentials(QStringLiteral("secret")), QStringLiteral("b"));
        probe.identify(params());
        QTRY_COMPARE(identified.count(), 1);
        QTest::qWait(500);
        QCOMPARE(verified.count(), 0);
        QCOMPARE(probe.state(), NetVfsProbe::State::Identified);
    }

    void destroyWhileRunning()
    {
        FakeServer::instance()->chunkDelayMs = 300;
        {
            NetVfsProbe probe;
            probe.verify(params(), credentials(QStringLiteral("secret")), QStringLiteral("b"));
            QTRY_VERIFY(logHas(QStringLiteral("upload:")));
        }
        // The worker was joined and its backend released.
        QCOMPARE(FakeServer::instance()->liveBackends, 0);
    }

    void cancelTokenBeforeAttach()
    {
        NetVfsUi::CancelToken token;
        QVERIFY(!token.isCanceled());
        token.cancel();
        QVERIFY(token.isCanceled());
        FakeBackend backend;
        token.attach(&backend);
        ServerIdentity seen;
        QCOMPARE(backend.connect(ConnectionParams(), &seen).error(), Error::Canceled);
        token.detach();
        token.cancel();   // no backend attached any more
    }

    void resetClearsState()
    {
        NetVfsProbe probe;
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.identify(params(QString(), QStringLiteral("nope")));
        QCOMPARE(probe.state(), NetVfsProbe::State::Failed);
        probe.reset();
        QCOMPARE(probe.state(), NetVfsProbe::State::Idle);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::NoError);
        QVERIFY(probe.errorText().isEmpty());
        QVERIFY(probe.errorDetail().isEmpty());
        QVERIFY(probe.serverIdentity().isEmpty());
        QCOMPARE(probe.freeBytes(), Q_INT64_C(-1));
        probe.cancel();   // nothing running: stays idle
        QCOMPARE(probe.state(), NetVfsProbe::State::Idle);
    }

    void verifyAccountWithStoredSecret()
    {
        // Settings page "Test connection": stored settings and secret.
        FakeServer::instance()->identity = identityOf(KeyBlob);
        const int accountId = createAccount(pinOf(KeyBlob), QStringLiteral("Phone backups"));
        QVERIFY(accountId > 0);
        NetVfsProbe probe;
        probe.setSessionFactory(sessionFactory(Result()));
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        probe.verifyAccount(accountId);
        QCOMPARE(probe.state(), NetVfsProbe::State::Verifying);
        QTRY_COMPARE(verified.count(), 1);
        QVERIFY(FakeServer::instance()->exists(QStringLiteral("Phone backups")));
        QCOMPARE(probe.identityStatus(), NetVfsProbe::IdentityStatus::IdentityMatches);
    }

    void verifyAccountPinOverride()
    {
        // SPEC 7.5: the accepted new key replaces the stored pin for the check.
        FakeServer::instance()->identity = identityOf(OtherBlob);
        const int accountId = createAccount(pinOf(KeyBlob));
        NetVfsProbe probe;
        probe.setSessionFactory(sessionFactory(Result()));
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.verifyAccount(accountId);
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::ServerIdentityChanged);
        QVERIFY(!logHas(QStringLiteral("authenticate")));
        probe.verifyAccount(accountId, pinOptions(pinOf(OtherBlob)));
        QTRY_COMPARE(verified.count(), 1);
        QVERIFY(FakeServer::instance()->exists(QStringLiteral("Sailfish OS/Backups")));
    }

    void verifyAccountSecretMissing()
    {
        const int accountId = createAccount(QString());
        NetVfsProbe probe;
        probe.setSessionFactory(sessionFactory(Result(Error::AuthFailed, QStringLiteral("no identity"))));
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.verifyAccount(accountId);
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::AuthFailed);
        QCOMPARE(probe.errorText(),
                 QStringLiteral("The stored password or key for this account could not be read. Update the sign-in details."));
        QCOMPARE(probe.errorDetail(), QStringLiteral("no identity"));
        QVERIFY(serverLog().isEmpty());
    }

    void verifyAccountCanceled()
    {
        const int accountId = createAccount(QString());
        NetVfsProbe probe;
        probe.setSessionFactory(sessionFactory(Result()));
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        probe.verifyAccount(accountId);
        probe.cancel();
        QTest::qWait(100);
        QCOMPARE(verified.count(), 0);
        QCOMPARE(probe.state(), NetVfsProbe::State::Idle);
        QVERIFY(serverLog().isEmpty());
    }

    // SPEC-v2-review 2.19: a Files verify authenticates and stats the start folder, nothing more.
    void verifyFilesWritesNothing()
    {
        FakeServer *server = FakeServer::instance();
        server->identity = identityOf(KeyBlob);
        server->addDir(QStringLiteral("media/photos"));
        server->freeBytes = 4242;
        NetVfsProbe probe;
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        probe.verify(params(pinOf(KeyBlob)), credentials(QStringLiteral("secret")), QStringLiteral("media/photos"),
                     QStringLiteral("files"));
        QTRY_COMPARE(verified.count(), 1);
        QCOMPARE(probe.freeBytes(), Q_INT64_C(4242));
        const QStringList log = serverLog();
        QCOMPARE(log.value(0), QStringLiteral("connect"));
        QCOMPARE(log.value(1), QStringLiteral("authenticate"));
        QVERIFY(log.contains(QStringLiteral("stat:media/photos")));
        for (const QString &entry : log) {
            QVERIFY2(!entry.startsWith(QStringLiteral("upload")) && !entry.startsWith(QStringLiteral("makeDir"))
                     && !entry.startsWith(QStringLiteral("removeFile")) && !entry.startsWith(QStringLiteral("openWrite")),
                     qPrintable(entry));
        }
        QVERIFY(!server->lastParams.options.contains(QStringLiteral("dir_mode")));
        QCOMPARE(log.last(), QStringLiteral("disconnect"));

        // The backend's base folder by default.
        probe.verify(params(pinOf(KeyBlob)), credentials(QStringLiteral("secret")), QString(), QStringLiteral("files"));
        QTRY_COMPARE(verified.count(), 2);
    }

    void verifyFilesErrors_data()
    {
        QTest::addColumn<QString>("folder");
        QTest::addColumn<int>("error");
        QTest::addColumn<QString>("text");
        QTest::newRow("missing") << "nope" << int(NetVfsProbe::ErrorCode::NotFound)
                                 << "The start folder was not found on the server.";
        QTest::newRow("file") << "file.txt" << int(Error::NotADirectory)
                              << "The start folder on the server is not a folder.";
        QTest::newRow("dots") << "a/../b" << -1 << QString();
    }

    void verifyFilesErrors()
    {
        QFETCH(QString, folder);
        QFETCH(int, error);
        QFETCH(QString, text);
        FakeServer::instance()->addFile(QStringLiteral("file.txt"), "x");
        NetVfsProbe probe;
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.verify(params(), credentials(QStringLiteral("secret")), folder, QStringLiteral("files"));
        QTRY_COMPARE(failed.count(), 1);
        if (error >= 0)
            QCOMPARE(int(probe.error()), error);
        if (!text.isEmpty())
            QCOMPARE(probe.errorText(), text);
        QVERIFY(!logHas(QStringLiteral("upload")));
    }

    // SPEC-v2 XA-4: refused before anything is sent.
    void verifyRefusedByPolicy()
    {
        QVariantMap guest = params();
        QVariantMap options;
        options.insert(QStringLiteral("allow_insecure"), true);
        guest.insert(QStringLiteral("options"), options);
        NetVfsProbe probe;
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        probe.verify(guest, credentials(QStringLiteral("secret")), QStringLiteral("b"), QStringLiteral("backup"));
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::SecurityPolicy);
        QVERIFY(probe.errorText().startsWith(QStringLiteral("These settings cannot be used for backups.")));
        QVERIFY(serverLog().isEmpty());

        // The same configuration is fine for files.
        probe.verify(guest, credentials(QStringLiteral("secret")), QString(), QStringLiteral("files"));
        QTRY_COMPARE(verified.count(), 1);

        probe.verify(guest, credentials(QStringLiteral("secret")), QString(), QStringLiteral("storage"));
        QCOMPARE(probe.state(), NetVfsProbe::State::Failed);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::Internal);
    }

    void verifyInteractiveChecksIdentityOnly()
    {
        // Interactive sign-in needs a person: connect and identity only.
        FakeServer::instance()->identity = identityOf(KeyBlob);
        QVariantMap interactive = params(pinOf(KeyBlob));
        QVariantMap options = interactive.value(QStringLiteral("options")).toMap();
        options.insert(QStringLiteral("auth_mode"), QStringLiteral("interactive"));
        interactive.insert(QStringLiteral("options"), options);
        NetVfsProbe probe;
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.verify(interactive, credentials(QString()), QString(), QStringLiteral("files"));
        QTRY_COMPARE(verified.count(), 1);
        QCOMPARE(serverLog(), QStringList({ QStringLiteral("connect"), QStringLiteral("disconnect") }));
        QCOMPARE(probe.identityStatus(), NetVfsProbe::IdentityStatus::IdentityMatches);

        // An unconfirmed identity still fails, before any credential.
        options.remove(QStringLiteral("host_key"));
        interactive.insert(QStringLiteral("options"), options);
        probe.verify(interactive, credentials(QString()), QString(), QStringLiteral("files"));
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::ServerIdentityUnknown);

        // Never for backups.
        probe.verify(interactive, credentials(QString()),
                     QStringLiteral("b"), QStringLiteral("backup"));
        QTRY_COMPARE(failed.count(), 2);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::SecurityPolicy);
    }

    // XC-16: TLS identities in the account flow.
    void tlsIdentityStatus_data()
    {
        QTest::addColumn<bool>("trusted");
        QTest::addColumn<bool>("pinTrusted");
        QTest::addColumn<bool>("pinned");
        QTest::addColumn<int>("status");
        QTest::newRow("trusted") << true << false << false << int(NetVfsProbe::IdentityStatus::IdentityTrusted);
        QTest::newRow("trusted, pin wanted") << true << true << false << int(NetVfsProbe::IdentityStatus::IdentityUnknown);
        QTest::newRow("untrusted") << false << false << false << int(NetVfsProbe::IdentityStatus::IdentityUnknown);
        QTest::newRow("untrusted, pin wanted") << false << true << false << int(NetVfsProbe::IdentityStatus::IdentityUnknown);
        QTest::newRow("pinned") << false << false << true << int(NetVfsProbe::IdentityStatus::IdentityMatches);
        QTest::newRow("pinned trusted") << true << true << true << int(NetVfsProbe::IdentityStatus::IdentityMatches);
    }

    void tlsIdentityStatus()
    {
        QFETCH(bool, trusted);
        QFETCH(bool, pinTrusted);
        QFETCH(bool, pinned);
        QFETCH(int, status);
        const ServerIdentity identity = tlsIdentity(trusted);
        FakeServer::instance()->identity = identity;
        QVariantMap map = params(pinned ? identity.toPin() : QString());
        QVariantMap options = map.value(QStringLiteral("options")).toMap();
        options.insert(QStringLiteral("pin_trusted"), pinTrusted);
        map.insert(QStringLiteral("options"), options);
        NetVfsProbe probe;
        QSignalSpy identified(&probe, &NetVfsProbe::identified);
        probe.identify(map);
        QTRY_COMPARE(identified.count(), 1);
        QCOMPARE(int(probe.identityStatus()), status);
        const QVariantMap seen = probe.serverIdentity();
        QCOMPARE(seen.value(QStringLiteral("kind")).toString(), QStringLiteral("tls"));
        // W-4: the accepted pin records whether the certificate was system trusted.
        const QVariantMap accepted = seen.value(QStringLiteral("pinOptions")).toMap();
        QCOMPARE(accepted.value(QStringLiteral("host_key")).toString(), identity.toPin());
        QCOMPARE(accepted.value(QStringLiteral("tls_verify_peer")), QVariant(trusted));
    }

    void identityCheckForPinTrusted()
    {
        ConnectionParams params;
        ServerIdentity trusted = tlsIdentity(true);
        QVERIFY(NetVfsUi::identityCheckFor(trusted, params).ok());
        params.options.insert(QStringLiteral("pin_trusted"), true);
        QCOMPARE(NetVfsUi::identityCheckFor(trusted, params).error(), Error::ServerIdentityUnknown);
        params.options.insert(QStringLiteral("host_key"), trusted.toPin());
        QVERIFY(NetVfsUi::identityCheckFor(trusted, params).ok());
        // SSH is unaffected by pin_trusted.
        params.options.remove(QStringLiteral("host_key"));
        QCOMPARE(NetVfsUi::identityCheckFor(identityOf(KeyBlob), params).error(), Error::ServerIdentityUnknown);
        params.options.insert(QStringLiteral("host_key"), pinOf(KeyBlob));
        QVERIFY(NetVfsUi::identityCheckFor(identityOf(KeyBlob), params).ok());
    }

    void verifyAccountFiles()
    {
        // The stored start folder of the files service; nothing written.
        FakeServer *server = FakeServer::instance();
        server->identity = identityOf(KeyBlob);
        server->addDir(QStringLiteral("shared"));
        const int accountId = createAccount(pinOf(KeyBlob));
        QVERIFY(fixture->setService(accountId, QStringLiteral("fake-files"), true,
                                    { { QStringLiteral("files_root"), QStringLiteral("shared") } }));
        NetVfsProbe probe;
        probe.setSessionFactory(sessionFactory(Result()));
        QSignalSpy verified(&probe, &NetVfsProbe::verified);
        probe.verifyAccount(accountId, QVariantMap(), QStringLiteral("files"));
        QTRY_COMPARE(verified.count(), 1);
        QVERIFY(logHas(QStringLiteral("stat:shared")));
        QVERIFY(!logHas(QStringLiteral("upload")));
        QVERIFY(!server->exists(QStringLiteral("Sailfish OS/Backups")));

        probe.verifyAccount(accountId, QVariantMap(), QStringLiteral("nope"));
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::Internal);
    }

    void verifyAccountRefusedForBackup()
    {
        QVariantMap options;
        options.insert(QStringLiteral("allow_insecure"), true);
        const int accountId = createAccount(QString(), QString(), options);
        NetVfsProbe probe;
        probe.setSessionFactory(sessionFactory(Result()));
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.verifyAccount(accountId);
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::SecurityPolicy);
        QVERIFY(probe.errorText().startsWith(QStringLiteral("These settings cannot be used for backups.")));
        QVERIFY(serverLog().isEmpty());
    }

    void verifyAccountDefaultSession()
    {
        // The production factory (AccountSession::open) on an unknown account
        // fails while loading, before signond is involved.
        NetVfsProbe probe;
        QSignalSpy failed(&probe, &NetVfsProbe::failed);
        probe.verifyAccount(424242);
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(probe.error(), NetVfsProbe::ErrorCode::NotFound);
    }
};

QTEST_GUILESS_MAIN(TestQmlProbe)
#include "tst_qmlprobe.moc"
