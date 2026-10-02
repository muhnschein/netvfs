// SPDX-License-Identifier: LGPL-2.1-or-later
#include "accountsession.h"
#include "accountsfixture.h"
#include "accountstore.h"
#include "fakebackend.h"
#include "secretsource.h"
#include "servicepolicy.h"

#include <Accounts/Manager>
#include <SignOn/Error>
#include <SignOn/Identity>
#include <SignOn/IdentityInfo>

#include <QtTest/QtTest>

#include <algorithm>

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
        fixture = new AccountsFixture({ QStringLiteral("sftp"), QStringLiteral("smb"), QStringLiteral("fake"), QStringLiteral("nosvc") });
        QVERIFY(fixture->isValid());
        QFile::remove(fixture->path() + QStringLiteral("/services/nosvc-backup.service"));
        QFile::remove(fixture->path() + QStringLiteral("/services/nosvc-files.service"));
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
        QVERIFY(AccountStore(fixture->manager()).load(id, Service::Backup, &config).ok());
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
        QVERIFY(AccountStore(fixture->manager()).load(id, Service::Backup, &config).ok());
        QCOMPARE(config.backupsPath, QStringLiteral("Sailfish OS/Backups"));

        const int noService = fixture->createAccount(QStringLiteral("nosvc"), sftpGlobals());
        QVERIFY(AccountStore(fixture->manager()).load(noService, Service::Backup, &config).ok());
        QCOMPARE(config.backupsPath, QStringLiteral("Sailfish OS/Backups"));

        QCOMPARE(AccountStore(fixture->manager()).load(99999, Service::Backup, &config).error(), Error::NotFound);

        QVariantMap noHost = sftpGlobals();
        noHost.remove(QStringLiteral("netvfs/host"));
        const int bad = fixture->createAccount(QStringLiteral("sftp"), noHost);
        QCOMPARE(AccountStore(fixture->manager()).load(bad, Service::Backup, &config).error(), Error::Internal);
        QVERIFY(AccountStore(fixture->manager()).load(id, Service::Backup, nullptr).ok());
    }

    // SPEC 6.4.
    void attentionStates()
    {
        const int id = fixture->createAccount(QStringLiteral("sftp"), sftpGlobals());
        AccountStore store(fixture->manager());
        QVERIFY(store.setAttention(id, Service::Backup, Attention::ServerIdentityChanged, QStringLiteral("ssh-ed25519 BBBB")).ok());
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("server-identity-changed"));
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdate")).toBool(), true);
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdateFrom")).toString(), QStringLiteral("sftp-backup"));
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/sftp/host_key_seen")).toString(), QStringLiteral("ssh-ed25519 BBBB"));

        AccountConfig config;
        QVERIFY(store.load(id, Service::Backup, &config).ok());
        QCOMPARE(config.attention, Attention::ServerIdentityChanged);
        QVERIFY(config.credentialsNeedUpdate);

        QVERIFY(store.clearAttention(id).ok());
        QVERIFY(fixture->value(id, QStringLiteral("netvfs/attention")).toString().isEmpty());
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdate")).toBool(), false);
        QVERIFY(fixture->value(id, QStringLiteral("CredentialsNeedUpdateFrom")).toString().isEmpty());
        QVERIFY(fixture->value(id, QStringLiteral("netvfs/sftp/host_key_seen")).toString().isEmpty());

        QVERIFY(store.setAttention(id, Service::Backup, Attention::AuthFailed).ok());
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));
        QVERIFY(fixture->value(id, QStringLiteral("netvfs/sftp/host_key_seen")).toString().isEmpty());
        QVERIFY(store.setAttention(id, Service::Backup, Attention::None).ok());
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdate")).toBool(), false);

        QCOMPARE(store.setAttention(99999, Service::Backup, Attention::AuthFailed).error(), Error::NotFound);
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
        session.start(id, Service::Backup);
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
        missing.start(99999, Service::Backup);
        QCOMPARE(failedMissing.count(), 1);
        QCOMPARE(failedMissing.at(0).at(0).value<Result>().error(), Error::NotFound);
        QCOMPARE(unused->requested, 0u);

        const int id = fixture->createAccount(QStringLiteral("fake"), sftpGlobals());
        AccountSession session(fixture->manager(), new StaticSecretSource(Result(Error::AuthFailed)));
        QSignalSpy failed(&session, &AccountSession::failed);
        session.start(id, Service::Backup);
        QCOMPARE(failed.count(), 1);
        QCOMPARE(failed.at(0).at(0).value<Result>().error(), Error::AuthFailed);
    }

    void openUsesDefaults()
    {
        // The production entry point: default manager, signond. Credentials id
        // 0 fails fast with AuthFailed without talking to signond.
        const int id = fixture->createAccount(QStringLiteral("fake"), sftpGlobals());
        AccountSession *session = AccountSession::open(id, Service::Backup, this);
        QSignalSpy failed(session, &AccountSession::failed);
        QVERIFY(failed.wait(5000));
        QCOMPARE(failed.at(0).at(0).value<Result>().error(), Error::AuthFailed);
        delete session;
    }

    // SPEC-v2 XA-1, XA-3: new keys come back as options, files_root from the files service.
    void loadV2Keys()
    {
        QVariantMap globals = sftpGlobals();
        globals.insert(QStringLiteral("netvfs/smb/security_profile"), QStringLiteral("legacy"));
        globals.insert(QStringLiteral("netvfs/smb/shares"), QStringList({ QStringLiteral("photos"), QStringLiteral("music") }));
        globals.insert(QStringLiteral("netvfs/smb/show_admin_shares"), true);
        globals.insert(QStringLiteral("netvfs/smb/allow_insecure"), true);
        const int id = fixture->createAccount(QStringLiteral("smb"), globals, QStringLiteral("Phone"), 3);
        QVERIFY(id > 0);
        QVERIFY(fixture->setService(id, QStringLiteral("smb-files"), true,
                                    { { QStringLiteral("files_root"), QStringLiteral(" Media ") } }));
        AccountStore store(fixture->manager());
        AccountConfig config;
        QVERIFY(store.load(id, Service::Files, &config).ok());
        QCOMPARE(config.service, Service::Files);
        QVERIFY(config.serviceEnabled);
        QCOMPARE(config.filesRoot, QStringLiteral("Media"));
        QCOMPARE(config.backupsPath, QStringLiteral("Phone"));
        QCOMPARE(config.securityProfile, QStringLiteral("legacy"));
        QVERIFY(config.insecureAllowed);
        QCOMPARE(config.params.options.value(QStringLiteral("shares")).toStringList(),
                 QStringList({ QStringLiteral("photos"), QStringLiteral("music") }));
        QVERIFY(config.params.flag(QStringLiteral("show_admin_shares")));
        QVERIFY(!config.params.options.contains(QStringLiteral("auth_mode")));   // sftp keys stay out

        QVERIFY(store.load(id, Service::Backup, &config).ok());
        QCOMPARE(config.service, Service::Backup);
        QVERIFY(config.serviceEnabled);

        // Disabled service, then disabled account.
        QVERIFY(fixture->setService(id, QStringLiteral("smb-backup"), false));
        QVERIFY(store.load(id, Service::Backup, &config).ok());
        QVERIFY(!config.serviceEnabled);
        QVERIFY(fixture->setService(id, QString(), false));
        QVERIFY(store.load(id, Service::Files, &config).ok());
        QVERIFY(!config.serviceEnabled);
        QVERIFY(!config.enabled);

        // Defaults: no files service value, provider without services.
        const int plain = fixture->createAccount(QStringLiteral("sftp"), sftpGlobals());
        QVERIFY(store.load(plain, Service::Files, &config).ok());
        QVERIFY(config.filesRoot.isEmpty());
        QVERIFY(!config.serviceEnabled);
        QVERIFY(config.securityProfile.isEmpty());
        QVERIFY(!config.insecureAllowed);
        const int noService = fixture->createAccount(QStringLiteral("nosvc"), sftpGlobals());
        QVERIFY(store.load(noService, Service::Files, &config).ok());
        QVERIFY(!config.serviceEnabled);
        QVERIFY(config.filesRoot.isEmpty());
    }

    // SPEC-v2 XA-1: consumers list enabled accounts whose files service is enabled.
    void filesAccounts()
    {
        const int listed = fixture->createAccount(QStringLiteral("sftp"), sftpGlobals());
        QVERIFY(fixture->setService(listed, QStringLiteral("sftp-files"), true));
        const int backupOnly = fixture->createAccount(QStringLiteral("sftp"), sftpGlobals());
        const int filesOff = fixture->createAccount(QStringLiteral("sftp"), sftpGlobals());
        QVERIFY(fixture->setService(filesOff, QStringLiteral("sftp-files"), false));
        const int accountOff = fixture->createAccount(QStringLiteral("smb"), sftpGlobals());
        QVERIFY(fixture->setService(accountOff, QStringLiteral("smb-files"), true));
        QVERIFY(fixture->setService(accountOff, QString(), false));
        const int second = fixture->createAccount(QStringLiteral("smb"), sftpGlobals());
        QVERIFY(fixture->setService(second, QStringLiteral("smb-files"), true));
        const int noService = fixture->createAccount(QStringLiteral("nosvc"), sftpGlobals());

        const QList<int> ids = AccountStore(fixture->manager()).filesAccounts();
        QVERIFY(ids.contains(listed));
        QVERIFY(ids.contains(second));
        QVERIFY(!ids.contains(backupOnly));
        QVERIFY(!ids.contains(filesOff));
        QVERIFY(!ids.contains(accountOff));
        QVERIFY(!ids.contains(noService));
        QList<int> sorted = ids;
        std::sort(sorted.begin(), sorted.end());
        QCOMPARE(ids, sorted);
    }

    void serviceNames()
    {
        QCOMPARE(serviceName(QStringLiteral("webdav"), Service::Files), QStringLiteral("webdav-files"));
        QCOMPARE(serviceName(QStringLiteral("smb"), Service::Backup), QStringLiteral("smb-backup"));
        QCOMPARE(filesServiceName(QStringLiteral("ftp")), QStringLiteral("ftp-files"));
        QCOMPARE(serviceId(Service::Backup), QStringLiteral("backup"));
        QCOMPARE(serviceId(Service::Files), QStringLiteral("files"));
        Service service = Service::Backup;
        QVERIFY(serviceFromId(QStringLiteral("files"), &service));
        QCOMPARE(service, Service::Files);
        QVERIFY(serviceFromId(QStringLiteral("backup"), &service));
        QCOMPARE(service, Service::Backup);
        QVERIFY(!serviceFromId(QStringLiteral("storage"), &service));
        QCOMPARE(service, Service::Backup);
    }

    // SPEC-v2 XA-4 and the "allowed for service" column of XM-1.
    void servicePolicy_data()
    {
        QTest::addColumn<QString>("provider");
        QTest::addColumn<QVariantMap>("options");
        QTest::addColumn<bool>("backup");
        QTest::addColumn<bool>("files");
        QTest::addColumn<QString>("profile");
        QTest::addColumn<bool>("insecure");
        const QString share = QStringLiteral("share");
        const QString profile = QStringLiteral("security_profile");
        const QString consent = QStringLiteral("allow_insecure");
        const QVariantMap withShare { { share, QStringLiteral("backups") } };
        auto with = [](QVariantMap map, const QString &key, const QVariant &value) {
            map.insert(key, value);
            return map;
        };
        QTest::newRow("smb default") << "smb" << withShare << true << true << "strict" << false;
        QTest::newRow("smb strict") << "smb" << with(withShare, profile, "strict") << true << true << "strict" << false;
        QTest::newRow("smb signed") << "smb" << with(withShare, profile, "signed") << true << true << "signed" << false;
        QTest::newRow("smb v1 no encryption") << "smb" << with(withShare, "require_encryption", false)
                                              << true << true << "signed" << false;
        QTest::newRow("smb v1 encryption") << "smb" << with(withShare, "require_encryption", true)
                                           << true << true << "strict" << false;
        QTest::newRow("smb profile wins") << "smb" << with(with(withShare, "require_encryption", false), profile, "strict")
                                          << true << true << "strict" << false;
        QTest::newRow("smb legacy") << "smb" << with(withShare, profile, "legacy") << false << false << "legacy" << true;
        QTest::newRow("smb legacy consent") << "smb" << with(with(withShare, profile, "legacy"), consent, true)
                                            << false << true << "legacy" << true;
        QTest::newRow("smb guest") << "smb" << with(withShare, profile, "guest") << false << false << "guest" << true;
        QTest::newRow("smb guest consent") << "smb" << with(with(withShare, profile, "guest"), consent, "true")
                                           << false << true << "guest" << true;
        QTest::newRow("smb unknown profile") << "smb" << with(with(withShare, profile, "none"), consent, true)
                                             << false << false << "none" << false;
        QTest::newRow("smb server mode") << "smb" << QVariantMap() << false << true << "strict" << false;
        QTest::newRow("smb blank share") << "smb" << with(QVariantMap(), share, "  ") << false << true << "strict" << false;
        QTest::newRow("smb strict consent") << "smb" << with(withShare, consent, true) << false << true << "strict" << false;
        QTest::newRow("webdav https") << "webdav" << QVariantMap() << true << true << "" << false;
        QTest::newRow("webdav http") << "webdav" << with(QVariantMap(), "tls", "http") << false << false << "" << true;
        QTest::newRow("webdav http consent") << "webdav" << with(with(QVariantMap(), "tls", "http"), consent, true)
                                             << false << true << "" << true;
        QTest::newRow("webdav token") << "webdav" << with(QVariantMap(), "auth_mode", "token") << true << true << "" << false;
        QTest::newRow("ftp explicit") << "ftp" << with(QVariantMap(), "tls_mode", "explicit") << true << true << "" << false;
        QTest::newRow("ftp implicit") << "ftp" << with(QVariantMap(), "tls_mode", "implicit") << true << true << "" << false;
        QTest::newRow("ftp none") << "ftp" << with(QVariantMap(), "tls_mode", "none") << false << false << "" << true;
        QTest::newRow("ftp none consent") << "ftp" << with(with(QVariantMap(), "tls_mode", "none"), consent, true)
                                          << false << true << "" << true;
        QTest::newRow("sftp") << "sftp" << QVariantMap() << true << true << "" << false;
        QTest::newRow("sftp consent false") << "sftp" << with(QVariantMap(), consent, false) << true << true << "" << false;
        QTest::newRow("sftp interactive") << "sftp" << with(QVariantMap(), "auth_mode", "interactive")
                                          << false << true << "" << false;
        QTest::newRow("sftp shell") << "sftp" << with(QVariantMap(), "allow_shell", true) << true << true << "" << false;
        QTest::newRow("sftp profile ignored") << "sftp" << with(QVariantMap(), profile, "guest") << true << true << "" << false;
        QTest::newRow("sftp consent") << "sftp" << with(QVariantMap(), consent, true) << false << true << "" << false;
    }

    void servicePolicy()
    {
        QFETCH(QString, provider);
        QFETCH(QVariantMap, options);
        QFETCH(bool, backup);
        QFETCH(bool, files);
        QFETCH(QString, profile);
        QFETCH(bool, insecure);
        ConnectionParams params;
        params.provider = provider;
        params.host = QStringLiteral("nas");
        params.options = options;
        const Result forBackup = checkServicePolicy(params, Service::Backup);
        const Result forFiles = checkServicePolicy(params, Service::Files);
        QCOMPARE(forBackup.ok(), backup);
        QCOMPARE(forFiles.ok(), files);
        if (!backup) {
            QCOMPARE(forBackup.error(), Error::SecurityPolicy);
            QVERIFY(!forBackup.message().isEmpty());
        }
        if (!files)
            QCOMPARE(forFiles.error(), Error::SecurityPolicy);
        QCOMPARE(securityProfile(params), profile);
        QCOMPARE(isInsecureConfiguration(params), insecure);
    }

    void paramsPerService()
    {
        // S-3 as amended: the exec channel is never used for backups.
        ConnectionParams params;
        params.provider = QStringLiteral("sftp");
        params.options.insert(QStringLiteral("allow_shell"), true);
        params.options.insert(QStringLiteral("host_key"), QStringLiteral("ssh-ed25519 AAAA"));
        const ConnectionParams backup = paramsForService(params, Service::Backup);
        QVERIFY(!backup.options.contains(QStringLiteral("allow_shell")));
        QCOMPARE(backup.option(QStringLiteral("host_key")), QStringLiteral("ssh-ed25519 AAAA"));
        const ConnectionParams files = paramsForService(params, Service::Files);
        QVERIFY(files.flag(QStringLiteral("allow_shell")));
    }

    // SPEC-v2 XA-7 and SPEC-v2-review 2.15.
    void secretOptionality_data()
    {
        QTest::addColumn<QString>("provider");
        QTest::addColumn<QString>("key");
        QTest::addColumn<QString>("value");
        QTest::addColumn<bool>("optional");
        QTest::newRow("sftp password") << "sftp" << "auth_mode" << "password" << false;
        QTest::newRow("sftp key") << "sftp" << "auth_mode" << "publickey" << false;
        QTest::newRow("sftp interactive") << "sftp" << "auth_mode" << "interactive" << true;
        QTest::newRow("webdav token") << "webdav" << "auth_mode" << "token" << false;
        QTest::newRow("webdav password") << "webdav" << "auth_mode" << "password" << false;
        QTest::newRow("smb guest") << "smb" << "security_profile" << "guest" << true;
        QTest::newRow("smb legacy") << "smb" << "security_profile" << "legacy" << false;
        QTest::newRow("smb strict") << "smb" << "security_profile" << "strict" << false;
        QTest::newRow("ftp guest is no smb profile") << "ftp" << "security_profile" << "guest" << false;
    }

    void secretOptionality()
    {
        QFETCH(QString, provider);
        QFETCH(QString, key);
        QFETCH(QString, value);
        QFETCH(bool, optional);
        ConnectionParams params;
        params.provider = provider;
        params.options.insert(key, value);
        QCOMPARE(secretOptional(params), optional);
    }

    void missingSecretDecision()
    {
        // XA-7 keeps A-6 for everything else, and never hides an outage.
        const Result noSecret(Error::AuthFailed, QStringLiteral("empty"));
        const Result outage(Error::Internal, QStringLiteral("signond down"));
        QVERIFY(acceptsMissingSecret(noSecret, true));
        QVERIFY(!acceptsMissingSecret(noSecret, false));
        QVERIFY(!acceptsMissingSecret(outage, true));
        QVERIFY(!acceptsMissingSecret(outage, false));
    }

    void secretSourceWithoutIdentity()
    {
        // Credentials id 0 is decided without signond.
        SignonSecretSource source;
        QVERIFY(!source.secretOptional());
        QSignalSpy fetched(&source, &SecretSource::fetched);
        QSignalSpy failed(&source, &SecretSource::failed);
        source.fetch(0);
        QCOMPARE(failed.count(), 1);
        QCOMPARE(failed.at(0).at(0).value<Result>().error(), Error::AuthFailed);
        QCOMPARE(fetched.count(), 0);

        source.setSecretOptional(true);
        QVERIFY(source.secretOptional());
        source.fetch(0);
        QCOMPARE(fetched.count(), 1);
        QCOMPARE(failed.count(), 1);
        const Credentials credentials = fetched.at(0).at(0).value<Credentials>();
        QVERIFY(credentials.secret.isEmpty());
        QVERIFY(credentials.userName.isEmpty());
    }

    void pinOptionsForIdentities()
    {
        QVERIFY(pinOptions(ServerIdentity()).isEmpty());

        ServerIdentity ssh;
        ssh.kind = ServerIdentity::Kind::SshHostKey;
        ssh.algorithm = QStringLiteral("ssh-ed25519");
        ssh.publicKey = QByteArray("key");
        QVariantMap options = pinOptions(ssh);
        QCOMPARE(options.value(QStringLiteral("host_key")).toString(), ssh.toPin());
        QVERIFY(!options.contains(QStringLiteral("tls_verify_peer")));

        // W-4: the backend verifies the chain only for a pin of a trusted certificate.
        ServerIdentity tls = ServerIdentity::fromTlsSpki(QByteArray("spki-der"));
        tls.systemTrusted = false;
        options = pinOptions(tls);
        QCOMPARE(options.value(QStringLiteral("host_key")).toString(), tls.toPin());
        QVERIFY(options.value(QStringLiteral("tls_verify_peer")).isValid());
        QCOMPARE(options.value(QStringLiteral("tls_verify_peer")).toBool(), false);
        tls.systemTrusted = true;
        options = pinOptions(tls);
        QCOMPARE(options.value(QStringLiteral("tls_verify_peer")).toBool(), true);
        ConnectionParams params;
        params.options = options;
        QVERIFY(params.flag(QStringLiteral("tls_verify_peer")));
    }

    // XA-4: the session refuses a configuration before reading the secret.
    void sessionServiceGating()
    {
        QVariantMap globals = sftpGlobals();
        globals.insert(QStringLiteral("netvfs/fake/allow_insecure"), true);
        globals.insert(QStringLiteral("netvfs/fake/allow_shell"), true);
        const int id = fixture->createAccount(QStringLiteral("fake"), globals, QString(), 9);

        auto *refusedSecrets = new StaticSecretSource(Result(), Credentials(QString(), "pw"));
        AccountSession refused(fixture->manager(), refusedSecrets);
        QSignalSpy refusedFailed(&refused, &AccountSession::failed);
        QSignalSpy refusedReady(&refused, &AccountSession::ready);
        refused.start(id, Service::Backup);
        QCOMPARE(refusedFailed.count(), 1);
        QCOMPARE(refusedFailed.at(0).at(0).value<Result>().error(), Error::SecurityPolicy);
        QCOMPARE(refusedReady.count(), 0);
        QCOMPARE(refusedSecrets->requested, 0u);

        auto *secrets = new StaticSecretSource(Result(), Credentials(QString(), "pw"));
        AccountSession files(fixture->manager(), secrets);
        QSignalSpy ready(&files, &AccountSession::ready);
        files.start(id, Service::Files);
        QCOMPARE(ready.count(), 1);
        QCOMPARE(secrets->requested, 9u);
        QVERIFY(!secrets->secretOptional());
        QCOMPARE(files.service(), Service::Files);
        QVERIFY(files.config().insecureAllowed);
        QVERIFY(files.params().flag(QStringLiteral("allow_shell")));
        QVERIFY(files.filesRoot().isEmpty());

        // Backup on an allowed account: allow_shell is not handed out.
        QVariantMap shell = sftpGlobals();
        shell.insert(QStringLiteral("netvfs/fake/allow_shell"), true);
        const int shellId = fixture->createAccount(QStringLiteral("fake"), shell);
        AccountSession backup(fixture->manager(), new StaticSecretSource(Result(), Credentials(QString(), "pw")));
        QSignalSpy backupReady(&backup, &AccountSession::ready);
        backup.start(shellId, Service::Backup);
        QCOMPARE(backupReady.count(), 1);
        QVERIFY(!backup.params().options.contains(QStringLiteral("allow_shell")));
        QCOMPARE(backup.service(), Service::Backup);
    }

    void sessionSecretOptional()
    {
        // XA-7: an interactive account reads its (absent) secret as optional.
        QVariantMap globals = sftpGlobals();
        globals.insert(QStringLiteral("netvfs/fake/auth_mode"), QStringLiteral("interactive"));
        const int id = fixture->createAccount(QStringLiteral("fake"), globals);
        auto *secrets = new StaticSecretSource(Result(), Credentials());
        AccountSession session(fixture->manager(), secrets);
        QSignalSpy ready(&session, &AccountSession::ready);
        session.start(id, Service::Files);
        QCOMPARE(ready.count(), 1);
        QVERIFY(secrets->secretOptional());
        QVERIFY(session.credentials().secret.isEmpty());
        QCOMPARE(session.credentials().userName, QStringLiteral("alice"));

        AccountSession refused(fixture->manager(), new StaticSecretSource(Result()));
        QSignalSpy failed(&refused, &AccountSession::failed);
        refused.start(id, Service::Backup);
        QCOMPARE(failed.count(), 1);
        QCOMPARE(failed.at(0).at(0).value<Result>().error(), Error::SecurityPolicy);
    }

    // XA-8: a Files run records the same attention; CredentialsNeedUpdateFrom names the service.
    void attentionFromFiles()
    {
        const int id = fixture->createAccount(QStringLiteral("sftp"), sftpGlobals());
        AccountStore store(fixture->manager());
        QVERIFY(store.setAttention(id, Service::Files, Attention::AuthFailed).ok());
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdate")).toBool(), true);
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdateFrom")).toString(), QStringLiteral("sftp-files"));
        QVERIFY(store.clearAttention(id).ok());
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

        // XA-7: the same lookups for an account without a secret by design.
        source.setSecretOptional(true);
        source.fetch(emptyStored.at(0).at(0).toUInt());
        QVERIFY(fetched.wait(15000));
        QCOMPARE(fetched.count(), 2);
        QVERIFY(fetched.at(1).at(0).value<Credentials>().secret.isEmpty());
        // signond reports the empty secret as an error: no user name (the session uses the settings one).
        source.fetch(credentialsId + 1000);
        QVERIFY(fetched.wait(15000));
        QCOMPARE(fetched.count(), 3);
        source.fetch(credentialsId);   // a stored secret is still returned
        QVERIFY(fetched.wait(15000));
        QCOMPARE(fetched.at(3).at(0).value<Credentials>().secret, QByteArray("s3cret pass"));
        QCOMPARE(failed.count(), 3);

        empty->remove();
        identity->remove();
    }
};

QTEST_GUILESS_MAIN(TestAccounts)
#include "tst_accounts.moc"
