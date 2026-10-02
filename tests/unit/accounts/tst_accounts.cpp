// SPDX-License-Identifier: LGPL-2.1-or-later
#include "accountsession.h"
#include "accountsfixture.h"
#include "accountstore.h"
#include "fakebackend.h"
#include "secretsource.h"

#include <Accounts/Manager>
#include <SignOn/Error>
#include <SignOn/Identity>
#include <SignOn/IdentityInfo>

#include <QtTest/QtTest>

using namespace NetVfs;
using NetVfs::Test::AccountsFixture;
using NetVfs::Test::FakeServer;

namespace {
class StaticSecretSource : public SecretSource
{
public:
    explicit StaticSecretSource(const Result &result, const Credentials &credentials = Credentials())
        : m_result(result), m_credentials(credentials) {}
    void fetch(quint32 id) override
    {
        requested = id;
        if (m_result.ok())
            emit fetched(m_credentials);
        else
            emit failed(m_result);
    }
    quint32 requested = 0;

private:
    Result m_result;
    Credentials m_credentials;
};

QVariantMap sftpGlobals()
{
    QVariantMap globals;
    globals.insert(QStringLiteral("netvfs/host"), QStringLiteral("nas.example"));
    globals.insert(QStringLiteral("netvfs/port"), 2222);
    globals.insert(QStringLiteral("netvfs/username"), QStringLiteral("alice"));
    globals.insert(QStringLiteral("netvfs/sftp/auth_mode"), QStringLiteral("password"));
    globals.insert(QStringLiteral("netvfs/sftp/host_key"), QStringLiteral("ssh-ed25519 AAAA"));
    globals.insert(QStringLiteral("netvfs/smb/share"), QStringLiteral("not mine"));
    return globals;
}
} // namespace

class TestAccounts : public QObject
{
    Q_OBJECT

private:
    AccountsFixture *fixture = nullptr;

private slots:
    void initTestCase()
    {
        fixture = new AccountsFixture({ QStringLiteral("sftp"), QStringLiteral("fake"), QStringLiteral("nosvc") });
        QVERIFY(fixture->isValid());
        QFile::remove(fixture->path() + QStringLiteral("/services/nosvc-backup.service"));
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
    }

    void cleanupTestCase() { delete fixture; }

    void attentionStrings()
    {
        QCOMPARE(attentionToString(Attention::AuthFailed), QStringLiteral("auth-failed"));
        QCOMPARE(attentionToString(Attention::ServerIdentityChanged), QStringLiteral("server-identity-changed"));
        QCOMPARE(attentionToString(Attention::None), QString());
        QCOMPARE(attentionFromString(QStringLiteral("auth-failed")), Attention::AuthFailed);
        QCOMPARE(attentionFromString(QStringLiteral("server-identity-changed")), Attention::ServerIdentityChanged);
        QCOMPARE(attentionFromString(QStringLiteral("other")), Attention::None);
        QCOMPARE(attentionForError(Error::AuthFailed), Attention::AuthFailed);
        QCOMPARE(attentionForError(Error::ServerIdentityChanged), Attention::ServerIdentityChanged);
        QCOMPARE(attentionForError(Error::ServerIdentityUnknown), Attention::ServerIdentityChanged);
        QCOMPARE(attentionForError(Error::SecurityPolicy), Attention::None);
        QCOMPARE(backupServiceName(QStringLiteral("smb")), QStringLiteral("smb-backup"));
        QCOMPARE(Keys::providerKey(QStringLiteral("sftp"), QStringLiteral("host_key")),
                 QStringLiteral("netvfs/sftp/host_key"));
    }

    void load()
    {
        const int id = fixture->createAccount(QStringLiteral("sftp"), sftpGlobals(), QStringLiteral("/srv/backups"), 42);
        QVERIFY(id > 0);
        AccountConfig config;
        QVERIFY(AccountStore(fixture->manager()).load(id, &config).ok());
        QCOMPARE(config.accountId, id);
        QCOMPARE(config.provider, QStringLiteral("sftp"));
        QCOMPARE(config.displayName, QStringLiteral("alice@nas.example"));
        QVERIFY(config.enabled);
        QCOMPARE(config.credentialsId, 42u);
        QCOMPARE(config.backupsPath, QStringLiteral("/srv/backups"));
        QCOMPARE(config.params.provider, QStringLiteral("sftp"));
        QCOMPARE(config.params.host, QStringLiteral("nas.example"));
        QCOMPARE(config.params.port, 2222);
        QCOMPARE(config.params.username, QStringLiteral("alice"));
        QCOMPARE(config.params.option(QStringLiteral("auth_mode")), QStringLiteral("password"));
        QCOMPARE(config.params.option(QStringLiteral("host_key")), QStringLiteral("ssh-ed25519 AAAA"));
        QVERIFY(!config.params.options.contains(QStringLiteral("share")));
        QCOMPARE(config.attention, Attention::None);
        QVERIFY(!config.credentialsNeedUpdate);
    }

    void loadDefaultsAndErrors()
    {
        const int id = fixture->createAccount(QStringLiteral("sftp"), sftpGlobals());
        AccountConfig config;
        QVERIFY(AccountStore(fixture->manager()).load(id, &config).ok());
        QCOMPARE(config.backupsPath, QStringLiteral("Sailfish OS/Backups"));

        const int noService = fixture->createAccount(QStringLiteral("nosvc"), sftpGlobals());
        QVERIFY(AccountStore(fixture->manager()).load(noService, &config).ok());
        QCOMPARE(config.backupsPath, QStringLiteral("Sailfish OS/Backups"));

        QCOMPARE(AccountStore(fixture->manager()).load(99999, &config).error(), Error::NotFound);

        QVariantMap noHost = sftpGlobals();
        noHost.remove(QStringLiteral("netvfs/host"));
        const int bad = fixture->createAccount(QStringLiteral("sftp"), noHost);
        QCOMPARE(AccountStore(fixture->manager()).load(bad, &config).error(), Error::Internal);
        QVERIFY(AccountStore(fixture->manager()).load(id, nullptr).ok());
    }

    // SPEC 6.4.
    void attentionStates()
    {
        const int id = fixture->createAccount(QStringLiteral("sftp"), sftpGlobals());
        AccountStore store(fixture->manager());
        QVERIFY(store.setAttention(id, Attention::ServerIdentityChanged, QStringLiteral("ssh-ed25519 BBBB")).ok());
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("server-identity-changed"));
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdate")).toBool(), true);
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdateFrom")).toString(), QStringLiteral("sftp-backup"));
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/sftp/host_key_seen")).toString(), QStringLiteral("ssh-ed25519 BBBB"));

        AccountConfig config;
        QVERIFY(store.load(id, &config).ok());
        QCOMPARE(config.attention, Attention::ServerIdentityChanged);
        QVERIFY(config.credentialsNeedUpdate);

        QVERIFY(store.clearAttention(id).ok());
        QVERIFY(fixture->value(id, QStringLiteral("netvfs/attention")).toString().isEmpty());
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdate")).toBool(), false);
        QVERIFY(fixture->value(id, QStringLiteral("CredentialsNeedUpdateFrom")).toString().isEmpty());
        QVERIFY(fixture->value(id, QStringLiteral("netvfs/sftp/host_key_seen")).toString().isEmpty());

        QVERIFY(store.setAttention(id, Attention::AuthFailed).ok());
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));
        QVERIFY(fixture->value(id, QStringLiteral("netvfs/sftp/host_key_seen")).toString().isEmpty());
        QVERIFY(store.setAttention(id, Attention::None).ok());
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdate")).toBool(), false);

        QCOMPARE(store.setAttention(99999, Attention::AuthFailed).error(), Error::NotFound);
        QCOMPARE(store.clearAttention(99999).error(), Error::NotFound);
    }

    // A-6 / 6.4: only an unusable identity or secret flags the account.
    void signonErrorMapping_data()
    {
        QTest::addColumn<int>("type");
        QTest::addColumn<int>("expected");
        const int auth = int(Error::AuthFailed);
        const int internal = int(Error::Internal);
        QTest::newRow("permission denied") << int(SignOn::Error::PermissionDenied) << auth;
        QTest::newRow("identity not found") << int(SignOn::Error::IdentityNotFound) << auth;
        QTest::newRow("credentials not available") << int(SignOn::Error::CredentialsNotAvailable) << auth;
        QTest::newRow("missing data") << int(SignOn::Error::MissingData) << auth;
        QTest::newRow("invalid credentials") << int(SignOn::Error::InvalidCredentials) << auth;
        QTest::newRow("not authorized") << int(SignOn::Error::NotAuthorized) << auth;
        QTest::newRow("user interaction") << int(SignOn::Error::UserInteraction) << auth;
        QTest::newRow("internal server") << int(SignOn::Error::InternalServer) << internal;
        QTest::newRow("communication") << int(SignOn::Error::InternalCommunication) << internal;
        QTest::newRow("service not available") << int(SignOn::Error::ServiceNotAvailable) << internal;
        QTest::newRow("timed out") << int(SignOn::Error::TimedOut) << internal;
        QTest::newRow("unknown") << int(SignOn::Error::Unknown) << internal;
    }

    void signonErrorMapping()
    {
        QFETCH(int, type);
        QFETCH(int, expected);
        const Result r = secretErrorFromSignon(type);
        QCOMPARE(int(r.error()), expected);
        QCOMPARE(attentionForError(r.error()) == Attention::AuthFailed, expected == int(Error::AuthFailed));
    }

    void sessionReady()
    {
        const int id = fixture->createAccount(QStringLiteral("fake"), sftpGlobals(), QString(), 7);
        StaticSecretSource *secrets = new StaticSecretSource(Result(), Credentials(QString(), "pw"));
        AccountSession session(fixture->manager(), secrets);
        QSignalSpy ready(&session, &AccountSession::ready);
        QSignalSpy failed(&session, &AccountSession::failed);
        session.start(id);
        QCOMPARE(ready.count(), 1);
        QCOMPARE(failed.count(), 0);
        QCOMPARE(secrets->requested, 7u);
        QCOMPARE(session.credentials().userName, QStringLiteral("alice"));   // falls back to settings
        QCOMPARE(session.credentials().secret, QByteArray("pw"));
        QCOMPARE(session.params().host, QStringLiteral("nas.example"));
        QCOMPARE(session.backupsPath(), QStringLiteral("Sailfish OS/Backups"));
        QCOMPARE(session.config().accountId, id);
        QVERIFY(session.backend());
        QCOMPARE(session.backend(), session.backend());
        QScopedPointer<Backend> fresh(session.createBackend());
        QVERIFY(fresh);
        QVERIFY(fresh.data() != session.backend());
        session.releaseCredentials();
        QVERIFY(session.credentials().secret.isEmpty());
    }

    void sessionFailures()
    {
        StaticSecretSource *unused = new StaticSecretSource(Result());
        AccountSession missing(fixture->manager(), unused);
        QSignalSpy failedMissing(&missing, &AccountSession::failed);
        missing.start(99999);
        QCOMPARE(failedMissing.count(), 1);
        QCOMPARE(failedMissing.at(0).at(0).value<Result>().error(), Error::NotFound);
        QCOMPARE(unused->requested, 0u);

        const int id = fixture->createAccount(QStringLiteral("fake"), sftpGlobals());
        AccountSession session(fixture->manager(), new StaticSecretSource(Result(Error::AuthFailed)));
        QSignalSpy failed(&session, &AccountSession::failed);
        session.start(id);
        QCOMPARE(failed.count(), 1);
        QCOMPARE(failed.at(0).at(0).value<Result>().error(), Error::AuthFailed);
    }

    void openUsesDefaults()
    {
        // The production entry point: default manager, signond. Credentials id
        // 0 fails fast with AuthFailed without talking to signond.
        const int id = fixture->createAccount(QStringLiteral("fake"), sftpGlobals());
        AccountSession *session = AccountSession::open(id, this);
        QSignalSpy failed(session, &AccountSession::failed);
        QVERIFY(failed.wait(5000));
        QCOMPARE(failed.at(0).at(0).value<Result>().error(), Error::AuthFailed);
        delete session;
    }

    // A-6 against a real signond on the test's private session bus, when available.
    void signonSecretSource()
    {
        if (QStandardPaths::findExecutable(QStringLiteral("signond")).isEmpty()
                && !QFile::exists(QStringLiteral("/usr/bin/signond")))
            QSKIP("signond is not installed");
        if (qEnvironmentVariableIsEmpty("DBUS_SESSION_BUS_ADDRESS"))
            QSKIP("no session bus");

        SignOn::IdentityInfo info;
        info.setCaption(QStringLiteral("netvfs test"));
        info.setUserName(QStringLiteral("alice"));
        info.setSecret(QStringLiteral("s3cret pass"), true);
        info.setMethod(QStringLiteral("password"), QStringList() << QStringLiteral("password"));
        info.setAccessControlList(QStringList() << QStringLiteral("*"));
        SignOn::Identity *identity = SignOn::Identity::newIdentity(info, this);
        QSignalSpy stored(identity, &SignOn::Identity::credentialsStored);
        QSignalSpy storeError(identity, &SignOn::Identity::error);
        identity->storeCredentials();
        QVERIFY(stored.wait(15000) || !storeError.isEmpty());
        if (stored.isEmpty())
            QSKIP("signond is not usable in this environment");
        const quint32 credentialsId = stored.at(0).at(0).toUInt();

        SignonSecretSource source;
        QSignalSpy fetched(&source, &SecretSource::fetched);
        QSignalSpy failed(&source, &SecretSource::failed);
        source.fetch(credentialsId);
        QVERIFY(fetched.wait(15000));
        const Credentials credentials = fetched.at(0).at(0).value<Credentials>();
        QCOMPARE(credentials.userName, QStringLiteral("alice"));
        QCOMPARE(credentials.secret, QByteArray("s3cret pass"));

        // Missing identity: AuthFailed.
        source.fetch(credentialsId + 1000);
        QVERIFY(failed.wait(15000));
        QCOMPARE(failed.at(0).at(0).value<Result>().error(), Error::AuthFailed);

        // No identity at all: immediate AuthFailed.
        source.fetch(0);
        QCOMPARE(failed.count(), 2);
        QCOMPARE(failed.at(1).at(0).value<Result>().error(), Error::AuthFailed);

        // Stored identity with an empty secret: AuthFailed (A-6).
        SignOn::IdentityInfo emptyInfo = info;
        emptyInfo.setSecret(QString(), true);
        SignOn::Identity *empty = SignOn::Identity::newIdentity(emptyInfo, this);
        QSignalSpy emptyStored(empty, &SignOn::Identity::credentialsStored);
        empty->storeCredentials();
        QVERIFY(emptyStored.wait(15000));
        source.fetch(emptyStored.at(0).at(0).toUInt());
        QVERIFY(failed.wait(15000));
        QCOMPARE(failed.count(), 3);
        QCOMPARE(failed.at(2).at(0).value<Result>().error(), Error::AuthFailed);
        QCOMPARE(fetched.count(), 1);

        empty->remove();
        identity->remove();
    }
};

QTEST_GUILESS_MAIN(TestAccounts)
#include "tst_accounts.moc"
