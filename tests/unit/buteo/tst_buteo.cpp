// SPDX-License-Identifier: LGPL-2.1-or-later
// Buteo backup plugins (SPEC 8) driven through the Buteo::ClientPlugin API
// against a fake org.sailfishos.backup service and the in-memory FakeServer.
#include "accountsession.h"
#include "accountsfixture.h"
#include "backupclient.h"
#include "backupservice.h"
#include "backupsteps.h"
#include "fakebackend.h"
#include "fakebackupservice.h"
#include "networkjob.h"
#include "secretsource.h"

#include <Accounts/Manager>
#include <SignOn/Identity>
#include <SignOn/IdentityInfo>
#include <Profile.h>
#include <SyncPluginLoader.h>
#include <SyncProfile.h>

#include <QtCore/QPluginLoader>
#include <QtDBus/QDBusConnectionInterface>
#include <QtTest/QtTest>
#include <QtXml/QDomDocument>

#include <array>
#include <memory>

using namespace NetVfs;
using NetVfs::Test::AccountsFixture;
using NetVfs::Test::FakeServer;
using Op = NetVfs::BackupClient::Operation;
using Minor = Buteo::SyncResults::MinorCode;

namespace {

// Secret source that answers asynchronously, like signond.
class QueuedSecretSource : public SecretSource
{
public:
    QueuedSecretSource(const Result &result, const Credentials &credentials)
        : m_result(result), m_credentials(credentials) {}

    void fetch(quint32 credentialsId) override
    {
        Q_UNUSED(credentialsId)
        QTimer::singleShot(0, this, [this]() {
            if (m_result.ok())
                emit fetched(m_credentials);
            else
                emit failed(m_result);
        });
    }

private:
    const Result m_result;
    const Credentials m_credentials;
};

// Opens sessions like AccountSession::open(), with a secret chosen by the test.
struct SessionSource
{
    Result secretResult;
    QByteArray secret = "secret";
    QPointer<AccountSession> last;

    AccountSession *open(int accountId, QObject *parent)
    {
        auto manager = std::make_unique<Accounts::Manager>();
        auto secrets = std::make_unique<QueuedSecretSource>(secretResult, Credentials(QStringLiteral("user"), secret));
        auto session = std::make_unique<AccountSession>(manager.get(), secrets.release(), parent);
        manager.release()->setParent(session.get());
        AccountSession *raw = session.release();   // owned by `parent`
        QTimer::singleShot(0, raw, [raw, accountId]() { raw->start(accountId); });
        last = raw;
        return raw;
    }
};

// Records what a plugin reports (B-7: exactly one of success/error). Copies
// share the record, so the connections never outlive it.
struct Outcome
{
    struct Record
    {
        int successes = 0;
        int errors = 0;
        int code = -1;
        QString message;
        QString profile;
    };
    std::shared_ptr<Record> d = std::make_shared<Record>();

    int total() const { return d->successes + d->errors; }

    void watch(Buteo::SyncPluginBase *plugin) const
    {
        const std::shared_ptr<Record> record = d;
        QObject::connect(plugin, &Buteo::SyncPluginBase::success, plugin, [record](const QString &p, const QString &m) {
            ++record->successes;
            record->code = Buteo::SyncResults::NO_ERROR;
            record->profile = p;
            record->message = m;
        });
        QObject::connect(plugin, &Buteo::SyncPluginBase::error, plugin,
                         [record](const QString &p, const QString &m, Buteo::SyncResults::MinorCode c) {
            ++record->errors;
            record->code = c;
            record->profile = p;
            record->message = m;
        });
    }

    bool wait(int ms = 15000) const
    {
        QElapsedTimer timer;
        timer.start();
        while (total() == 0 && timer.elapsed() < ms)
            QTest::qWait(5);
        return total() > 0;
    }
};

QStringList serverLog()
{
    FakeServer *server = FakeServer::instance();
    QMutexLocker lock(&server->mutex);
    return server->log;
}

bool serverHas(const QString &path)
{
    FakeServer *server = FakeServer::instance();
    QMutexLocker lock(&server->mutex);
    return server->exists(path);
}

bool waitForLog(const QString &prefix, int ms = 10000)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < ms) {
        for (const QString &entry : serverLog()) {
            if (entry.startsWith(prefix))
                return true;
        }
        QTest::qWait(2);
    }
    return false;
}

QString pinOf(char fill)
{
    ServerIdentity identity;
    identity.algorithm = QStringLiteral("ssh-ed25519");
    identity.publicKey = QByteArray(32, fill);
    return identity.toPin();
}

QString expectedClientProfile(const QString &name)
{
    return QStringLiteral("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                          "<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->\n"
                          "<profile name=\"%1\" type=\"client\">\n"
                          "    <field name=\"Sync Transport\"/>\n"
                          "    <field name=\"Sync Direction\"/>\n"
                          "    <field name=\"Sync Protocol\"/>\n"
                          "    <field name=\"conflictpolicy\"/>\n"
                          "</profile>\n").arg(name);
}

QString expectedSyncProfile(const QString &name, const QString &client, const QString &protocol)
{
    return QStringLiteral("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                          "<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->\n"
                          "<profile name=\"%1\" type=\"sync\">\n"
                          "    <key name=\"destinationtype\" value=\"online\"/>\n"
                          "    <key name=\"enabled\" value=\"false\"/>\n"
                          "    <key name=\"hidden\" value=\"true\"/>\n"
                          "    <key name=\"use_accounts\" value=\"true\"/>\n"
                          "    <profile type=\"client\" name=\"%2\">\n"
                          "        <key name=\"Sync Direction\" value=\"one-way\"/>\n"
                          "        <key name=\"Sync Protocol\" value=\"%3\"/>\n"
                          "        <key name=\"Sync Transport\" value=\"HTTP\"/>\n"
                          "        <key name=\"conflictpolicy\" value=\"prefer remote\"/>\n"
                          "    </profile>\n"
                          "    <schedule enabled=\"false\" interval=\"\" days=\"1,2,3,4,5,6,7\" "
                          "syncconfiguredtime=\"\" time=\"02:00:00\"/>\n"
                          "</profile>\n").arg(name, client, protocol);
}

QByteArray readFile(const QString &path)
{
    QFile file(path);
    return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

QStringList &capturedMessages()
{
    static QStringList messages;
    return messages;
}

void captureMessage(QtMsgType type, const QMessageLogContext &context, const QString &message)
{
    Q_UNUSED(type)
    Q_UNUSED(context)
    capturedMessages() << message;
}

const std::array<const char *, 3> OperationNames = { { "Backup", "BackupQuery", "BackupRestore" } };
const std::array<const char *, 2> Providers = { { "sftp", "smb" } };

} // namespace

class TestButeo : public QObject
{
    Q_OBJECT

private:
    std::unique_ptr<AccountsFixture> fixture;
    std::unique_ptr<FakeBackupService> service;
    std::unique_ptr<QTemporaryDir> local;
    SessionSource sessions;

    QVariantMap globals(const QString &pin = QString())
    {
        QVariantMap values;
        values.insert(QStringLiteral("netvfs/host"), QStringLiteral("fake.example"));
        values.insert(QStringLiteral("netvfs/username"), QStringLiteral("user"));
        if (!pin.isEmpty())
            values.insert(QStringLiteral("netvfs/fake/host_key"), pin);
        return values;
    }

    int createAccount(const QString &backupsPath = QStringLiteral("Backups"), const QString &pin = QString(),
                      const QString &provider = QStringLiteral("fake"), quint32 credentialsId = 0)
    {
        return fixture->createAccount(provider, globals(pin), backupsPath, credentialsId);
    }

    static QString profileName(Op op, int accountId)
    {
        return QStringLiteral("fake.%1-%2").arg(QLatin1String(OperationNames.at(static_cast<size_t>(op)))).arg(accountId);
    }

    BackupClient *makeClient(Op op, int accountId, const QString &restoreFile = QString())
    {
        Buteo::SyncProfile profile(profileName(op, accountId));
        profile.setKey(QStringLiteral("accountid"), QString::number(accountId));
        if (!restoreFile.isEmpty())
            profile.setKey(QStringLiteral("sfos-backuprestore-file"), restoreFile);
        auto client = std::make_unique<BackupClient>(
            QStringLiteral("fake"), op, QStringLiteral("fake-backup"), profile, nullptr,
            [this](int accountId, QObject *parent) { return sessions.open(accountId, parent); });
        client->setParent(this);
        return client.release();
    }

    // init() + startSync() + wait for the outcome, for runs that need no
    // interaction with the backup service on the way.
    Outcome run(BackupClient *client)
    {
        Outcome outcome;
        outcome.watch(client);
        if (!client->init() || !client->startSync())
            return outcome;
        outcome.wait();
        return outcome;
    }

    // Starts a backup and waits until the archive was requested.
    bool startBackup(BackupClient *client, Outcome *outcome)
    {
        outcome->watch(client);
        if (!client->init() || !client->startSync())
            return false;
        QElapsedTimer timer;
        timer.start();
        while (service->createCalls.isEmpty() && outcome->total() == 0 && timer.elapsed() < 10000)
            QTest::qWait(2);
        return !service->createCalls.isEmpty();
    }

    void addBackupFiles(const QString &dir)
    {
        FakeServer *server = FakeServer::instance();
        QMutexLocker lock(&server->mutex);
        server->addDir(dir + QStringLiteral("/subdir"));
        server->addFile(dir + QStringLiteral("/b.tar"), "bee");
        server->addFile(dir + QStringLiteral("/a.tar"), "ay");
        server->addFile(dir + QStringLiteral("/c.tar.part"), "partial");
    }

private slots:
    void initTestCase()
    {
        QVERIFY2(QDBusConnection::sessionBus().isConnected(), "the tests need a session bus (make check-unit)");
        fixture = std::make_unique<AccountsFixture>(
            QStringList { QStringLiteral("fake"), QStringLiteral("sftp"), QStringLiteral("smb") });
        QVERIFY(fixture->isValid());
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
        service = std::make_unique<FakeBackupService>();
        QVERIFY(service->registerOnBus());
        local = std::make_unique<QTemporaryDir>();
    }

    void cleanupTestCase()
    {
        local.reset();
        service.reset();
        fixture.reset();
    }

    void cleanup()
    {
        // Clients of a finished test must not report into the next one.
        qDeleteAll(findChildren<BackupClient *>(QString(), Qt::FindDirectChildrenOnly));
    }

    void init()
    {
        FakeServer::instance()->reset();
        service->reset();
        sessions.secretResult = Result();
        sessions.secret = "secret";
    }

    // SPEC 8.2: generated from one template per kind; only the names and the
    // sync protocol differ.
    void profiles_data()
    {
        QTest::addColumn<QString>("provider");
        QTest::addColumn<QString>("operation");
        for (const char *provider : Providers) {
            for (const char *operation : OperationNames)
                QTest::newRow(QByteArray(provider).append('.').append(operation).constData())
                        << QString::fromLatin1(provider) << QString::fromLatin1(operation);
        }
    }

    void profiles()
    {
        QFETCH(QString, provider);
        QFETCH(QString, operation);
        const QString client = provider + QLatin1Char('-') + operation.toLower();
        const QString sync = provider + QLatin1Char('.') + operation;
        const QString dir = QStringLiteral(NETVFS_TEST_BUTEO_BUILD_DIR "/%1/%2/").arg(provider, operation.toLower());

        const QByteArray clientXml = readFile(dir + client + QStringLiteral(".xml"));
        QCOMPARE(QString::fromUtf8(clientXml), expectedClientProfile(client));
        const QByteArray syncXml = readFile(dir + sync + QStringLiteral(".xml"));
        QCOMPARE(QString::fromUtf8(syncXml), expectedSyncProfile(sync, client, provider));

        // And Buteo reads them as intended.
        QDomDocument doc;
        QVERIFY(doc.setContent(syncXml));
        Buteo::SyncProfile profile(doc.documentElement());
        QCOMPARE(profile.name(), sync);
        QCOMPARE(profile.key(QStringLiteral("use_accounts")), QStringLiteral("true"));
        QCOMPARE(profile.destinationType(), Buteo::SyncProfile::DESTINATION_TYPE_ONLINE);
        const Buteo::Profile *sub = profile.subProfile(client, QStringLiteral("client"));
        QVERIFY(sub);
        QCOMPARE(sub->key(QStringLiteral("Sync Protocol")), provider);
        QDomDocument clientDoc;
        QVERIFY(clientDoc.setContent(clientXml));
        const Buteo::Profile clientProfile(clientDoc.documentElement());
        QCOMPARE(clientProfile.name(), client);
        QCOMPARE(clientProfile.type(), QStringLiteral("client"));
    }

    // SPEC 3.3 / 8.1: six plugins from one loader source, unique IIDs, each
    // creating the shared client for its provider and operation.
    void loaders()
    {
        QSet<QString> iids;
        for (const char *provider : Providers) {
            for (const char *operation : OperationNames) {
                const QString client = QString::fromLatin1(provider) + QLatin1Char('-')
                        + QString::fromLatin1(operation).toLower();
                QPluginLoader loader(QStringLiteral(NETVFS_TEST_BUTEO_PLUGIN_DIR "/lib%1-client.so").arg(client));
                const QString iid = loader.metaData().value(QStringLiteral("IID")).toString();
                QCOMPARE(iid, QStringLiteral("org.netvfs.buteo.%1-client").arg(client));
                iids.insert(iid);

                Buteo::SyncPluginLoader *factory = qobject_cast<Buteo::SyncPluginLoader *>(loader.instance());
                QVERIFY2(factory, qPrintable(loader.errorString()));
                Buteo::SyncProfile profile(client);
                QScopedPointer<Buteo::ClientPlugin> plugin(factory->createClientPlugin(client, profile, nullptr));
                QVERIFY(plugin);
                QVERIFY(plugin->inherits("NetVfs::BackupClient"));
                QCOMPARE(plugin->property("provider").toString(), QString::fromLatin1(provider));
                QCOMPARE(plugin->property("operationName").toString(), QString::fromLatin1(operation));
                QCOMPARE(plugin->getPluginName(), client);
                QVERIFY(!plugin->init());   // B-1: no account id
            }
        }
        QCOMPARE(iids.size(), 6);
    }

    // The loaded plugins run on the production path (AccountSession::open,
    // signond): an account without stored credentials fails as AuthFailed.
    void loadedPluginRealSession()
    {
        const int id = createAccount(QStringLiteral("Backups"), QString(), QStringLiteral("sftp"));
        QPluginLoader loader(QStringLiteral(NETVFS_TEST_BUTEO_PLUGIN_DIR "/libsftp-backupquery-client.so"));
        Buteo::SyncPluginLoader *factory = qobject_cast<Buteo::SyncPluginLoader *>(loader.instance());
        QVERIFY(factory);
        Buteo::SyncProfile profile(QStringLiteral("sftp.BackupQuery-%1").arg(id));
        profile.setKey(QStringLiteral("accountid"), QString::number(id));
        QScopedPointer<Buteo::ClientPlugin> plugin(factory->createClientPlugin(QStringLiteral("sftp-backupquery"),
                                                                              profile, nullptr));
        Outcome outcome;
        outcome.watch(plugin.data());
        QVERIFY(plugin->init());
        QVERIFY(plugin->startSync());
        QVERIFY(outcome.wait());
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::AUTHENTICATION_FAILURE));
        QCOMPARE(outcome.d->profile, profile.name());
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));
        QVERIFY(plugin->uninit());
    }

    // SPEC 8.7.
    void minorCodes()
    {
        QCOMPARE(BackupClient::minorCodeFor(Error::None), Buteo::SyncResults::NO_ERROR);
        QCOMPARE(BackupClient::minorCodeFor(Error::Canceled), Buteo::SyncResults::ABORTED);
        QCOMPARE(BackupClient::minorCodeFor(Error::NetworkUnreachable), Buteo::SyncResults::CONNECTION_ERROR);
        QCOMPARE(BackupClient::minorCodeFor(Error::Timeout), Buteo::SyncResults::CONNECTION_ERROR);
        QCOMPARE(BackupClient::minorCodeFor(Error::AuthFailed), Buteo::SyncResults::AUTHENTICATION_FAILURE);
        QCOMPARE(BackupClient::minorCodeFor(Error::ServerIdentityChanged), Buteo::SyncResults::AUTHENTICATION_FAILURE);
        QCOMPARE(BackupClient::minorCodeFor(Error::ServerIdentityUnknown), Buteo::SyncResults::AUTHENTICATION_FAILURE);
        for (Error e : { Error::SecurityPolicy, Error::PermissionDenied, Error::NotFound, Error::AlreadyExists,
                         Error::NoSpace, Error::Unsupported, Error::ProtocolError, Error::Internal })
            QCOMPARE(BackupClient::minorCodeFor(e), Buteo::SyncResults::INTERNAL_ERROR);

        QCOMPARE(BackupClient::minorCodeForAbort(Sync::SYNC_ABORTED), Buteo::SyncResults::ABORTED);
        QCOMPARE(BackupClient::minorCodeForAbort(Sync::SYNC_CANCELLED), Buteo::SyncResults::ABORTED);
        QCOMPARE(BackupClient::minorCodeForAbort(Sync::SYNC_ERROR), Buteo::SyncResults::CONNECTION_ERROR);
        QCOMPARE(BackupClient::minorCodeForAbort(Sync::SYNC_CONNECTION_ERROR), Buteo::SyncResults::CONNECTION_ERROR);
        QCOMPARE(BackupClient::minorCodeForAbort(Sync::SYNC_AUTHENTICATION_FAILURE),
                 Buteo::SyncResults::AUTHENTICATION_FAILURE);
        QCOMPARE(BackupClient::minorCodeForAbort(Sync::SYNC_DATABASE_FAILURE), Buteo::SyncResults::DATABASE_FAILURE);
        QCOMPARE(BackupClient::minorCodeForAbort(Sync::SYNC_PLUGIN_ERROR), Buteo::SyncResults::PLUGIN_ERROR);
        QCOMPARE(BackupClient::minorCodeForAbort(Sync::SYNC_PLUGIN_TIMEOUT), Buteo::SyncResults::PLUGIN_TIMEOUT);
    }

    // B-1
    void initNeedsAccountId_data()
    {
        QTest::addColumn<QString>("value");
        QTest::newRow("missing") << QString();
        QTest::newRow("zero") << QStringLiteral("0");
        QTest::newRow("negative") << QStringLiteral("-3");
        QTest::newRow("garbage") << QStringLiteral("abc");
    }

    void initNeedsAccountId()
    {
        QFETCH(QString, value);
        Buteo::SyncProfile profile(QStringLiteral("fake.Backup-x"));
        if (!value.isNull())
            profile.setKey(QStringLiteral("accountid"), value);
        BackupClient client(QStringLiteral("fake"), Op::Backup, QStringLiteral("fake-backup"), profile, nullptr);
        Outcome outcome;
        outcome.watch(&client);
        QVERIFY(!client.init());
        QVERIFY(!client.startSync());
        QTest::qWait(50);
        QCOMPARE(outcome.total(), 0);
        QVERIFY(serverLog().isEmpty());
    }

    void startNeedsInit()
    {
        BackupClient *client = makeClient(Op::Backup, createAccount());
        QVERIFY(!client->startSync());
        QCOMPARE(client->provider(), QStringLiteral("fake"));
        QCOMPARE(client->operation(), Op::Backup);
    }

    // SPEC 8.4, B-2, C-12: the full backup flow.
    void backupSuccess()
    {
        const int id = createAccount();
        const QString dir = QStringLiteral("Backups/device-1");
        {
            FakeServer *server = FakeServer::instance();
            server->addFile(dir + QStringLiteral("/old.tar.part"), "x",
                            QDateTime::currentDateTimeUtc().addSecs(-25 * 3600));
            server->addFile(dir + QStringLiteral("/recent.tar.part"), "y",
                            QDateTime::currentDateTimeUtc().addSecs(-3600));
        }
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        QVERIFY(startBackup(client, &outcome));
        QCOMPARE(service->createCalls, QStringList() << profileName(Op::Backup, id));

        // Pre-flight finished (and disconnected) before the archive was requested.
        const QStringList before = service->serverLogAtCreate;
        QCOMPARE(before.value(0), QStringLiteral("connect"));
        QCOMPARE(before.value(1), QStringLiteral("authenticate"));
        QVERIFY(before.contains(QStringLiteral("makePath:") + dir));
        QVERIFY(before.contains(QStringLiteral("remove:") + dir + QStringLiteral("/old.tar.part")));
        QVERIFY(!before.contains(QStringLiteral("remove:") + dir + QStringLiteral("/recent.tar.part")));
        QCOMPARE(before.last(), QStringLiteral("disconnect"));

        QTest::qWait(50);
        QCOMPARE(outcome.total(), 0);   // no timeout on this wait
        const QString archive = service->lastArchivePath;
        QVERIFY(QFile::exists(archive));
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        QVERIFY(outcome.wait());
        QCOMPARE(outcome.d->successes, 1);
        QCOMPARE(outcome.d->errors, 0);
        QCOMPARE(outcome.d->profile, profileName(Op::Backup, id));

        const QString remote = dir + QLatin1Char('/') + QFileInfo(archive).fileName();
        QCOMPARE(FakeServer::instance()->fileData(remote), service->archiveContent);
        QVERIFY(!serverHas(remote + QStringLiteral(".part")));
        QVERIFY(serverHas(dir + QStringLiteral("/recent.tar.part")));
        QVERIFY(!serverHas(dir + QStringLiteral("/old.tar.part")));
        // A fresh connection for the upload.
        QCOMPARE(serverLog().count(QStringLiteral("connect")), 2);
        QCOMPARE(serverLog().count(QStringLiteral("disconnect")), 2);
        QVERIFY(serverLog().contains(QStringLiteral("upload:") + remote + QStringLiteral(".part")));
        QCOMPARE(FakeServer::instance()->liveBackends, 0);

        // The local archive and its directory are gone.
        QVERIFY(!QFile::exists(archive));
        QVERIFY(!QFileInfo::exists(QFileInfo(archive).absolutePath()));
        QCOMPARE(client->getSyncResults().majorCode(), Buteo::SyncResults::SYNC_RESULT_SUCCESS);
        QCOMPARE(client->getSyncResults().minorCode(), Buteo::SyncResults::NO_ERROR);
        // SEC-5: the session no longer holds the secret.
        QVERIFY(sessions.last);
        QVERIFY(sessions.last->credentials().secret.isEmpty());
        QVERIFY(fixture->value(id, QStringLiteral("netvfs/attention")).toString().isEmpty());

        QTest::qWait(50);
        QCOMPARE(outcome.total(), 1);
    }

    // The status signal may arrive before the reply carrying the path.
    void backupStatusBeforeReply()
    {
        const int id = createAccount();
        service->statusBeforeReplyAccount = id;
        Outcome outcome = run(makeClient(Op::Backup, id));
        QCOMPARE(outcome.d->successes, 1);
        QVERIFY(serverHas(QStringLiteral("Backups/device-1/") + QFileInfo(service->lastArchivePath).fileName()));
    }

    // Signals for other accounts are ignored; a parent directory that still
    // holds other files is kept.
    void backupIgnoresOtherAccounts()
    {
        const int id = createAccount();
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        QVERIFY(startBackup(client, &outcome));
        const QString archive = service->lastArchivePath;
        const QString sibling = QFileInfo(archive).absolutePath() + QStringLiteral("/keep");
        QFile keep(sibling);
        QVERIFY(keep.open(QIODevice::WriteOnly));
        keep.close();

        service->emitBackupStatus(id + 1000, QStringLiteral("UploadingBackup"));
        service->emitBackupStatus(id + 1000, QStringLiteral("Canceled"));
        service->emitBackupError(id + 1000, QStringLiteral("Failed"), QStringLiteral("other"));
        service->emitRestoreStatus(id, QStringLiteral("Canceled"));   // not a restore
        QTest::qWait(100);
        QCOMPARE(outcome.total(), 0);
        QVERIFY(!serverLog().join(QLatin1Char(' ')).contains(QStringLiteral("upload:")));

        service->emitBackupStatus(id, QStringLiteral("SomethingElse"));
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        QVERIFY(outcome.wait());
        QCOMPARE(outcome.d->successes, 1);
        QVERIFY(!QFile::exists(archive));
        QVERIFY(QFile::exists(sibling));
    }

    void backupServiceFailures_data()
    {
        QTest::addColumn<QString>("kind");
        QTest::addColumn<int>("code");
        QTest::addColumn<QString>("text");
        QTest::newRow("canceled") << QStringLiteral("Canceled") << int(Buteo::SyncResults::ABORTED)
                                  << QStringLiteral("canceled the backup");
        QTest::newRow("error") << QStringLiteral("Error") << int(Buteo::SyncResults::INTERNAL_ERROR)
                               << QStringLiteral("could not create");
        QTest::newRow("cloudBackupError") << QStringLiteral("cloudBackupError")
                                          << int(Buteo::SyncResults::INTERNAL_ERROR)
                                          << QStringLiteral("DiskFull no room");
    }

    // SPEC 8.4 step 4, step 6 on failure.
    void backupServiceFailures()
    {
        QFETCH(QString, kind);
        QFETCH(int, code);
        QFETCH(QString, text);
        const int id = createAccount();
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        QVERIFY(startBackup(client, &outcome));
        const QString archive = service->lastArchivePath;
        if (kind == QLatin1String("cloudBackupError"))
            service->emitBackupError(id, QStringLiteral("DiskFull"), QStringLiteral("no room"));
        else
            service->emitBackupStatus(id, kind);
        QVERIFY(outcome.wait());
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, code);
        QVERIFY2(outcome.d->message.contains(text), qPrintable(outcome.d->message));
        QVERIFY(!QFile::exists(archive));
        QVERIFY(!QFileInfo::exists(QFileInfo(archive).absolutePath()));
        QCOMPARE(serverLog().count(QStringLiteral("connect")), 1);
        QCOMPARE(client->getSyncResults().majorCode(), Buteo::SyncResults::SYNC_RESULT_FAILED);
        QCOMPARE(int(client->getSyncResults().minorCode()), code);

        // Late signals change nothing (B-7).
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        QTest::qWait(50);
        QCOMPARE(outcome.total(), 1);
    }

    void backupArchiveRequestFails_data()
    {
        QTest::addColumn<bool>("dbusError");
        QTest::newRow("D-Bus error") << true;
        QTest::newRow("empty path") << false;
    }

    void backupArchiveRequestFails()
    {
        QFETCH(bool, dbusError);
        service->failCreate = dbusError;
        service->returnEmptyPath = !dbusError;
        Outcome outcome = run(makeClient(Op::Backup, createAccount()));
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::INTERNAL_ERROR));
        QVERIFY(outcome.d->message.contains(QStringLiteral("createBackupForSyncProfile")));
    }

    // SPEC 8.4 step 2: a failing pre-flight ends the run before any archive is built.
    void backupPreflightFailures_data()
    {
        QTest::addColumn<QString>("op");
        QTest::addColumn<int>("error");
        QTest::addColumn<int>("code");
        QTest::newRow("unreachable") << QStringLiteral("connect") << int(Error::NetworkUnreachable)
                                     << int(Buteo::SyncResults::CONNECTION_ERROR);
        QTest::newRow("timeout") << QStringLiteral("connect") << int(Error::Timeout)
                                 << int(Buteo::SyncResults::CONNECTION_ERROR);
        QTest::newRow("makePath") << QStringLiteral("makePath") << int(Error::PermissionDenied)
                                  << int(Buteo::SyncResults::INTERNAL_ERROR);
        QTest::newRow("stale parts") << QStringLiteral("list") << int(Error::ProtocolError)
                                     << int(Buteo::SyncResults::INTERNAL_ERROR);
        QTest::newRow("policy") << QStringLiteral("connect") << int(Error::SecurityPolicy)
                                << int(Buteo::SyncResults::INTERNAL_ERROR);
    }

    void backupPreflightFailures()
    {
        QFETCH(QString, op);
        QFETCH(int, error);
        QFETCH(int, code);
        FakeServer::instance()->failOps.insert(op, Result(static_cast<Error>(error), QStringLiteral("injected cause")));
        const int id = createAccount();
        Outcome outcome = run(makeClient(Op::Backup, id));
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, code);
        QVERIFY2(outcome.d->message.contains(QStringLiteral("injected cause")), qPrintable(outcome.d->message));
        QVERIFY(outcome.d->message.contains(errorName(static_cast<Error>(error))));
        QVERIFY(service->createCalls.isEmpty());
        QVERIFY(fixture->value(id, QStringLiteral("netvfs/attention")).toString().isEmpty());
        QVERIFY(!fixture->value(id, QStringLiteral("CredentialsNeedUpdate")).toBool());
    }

    // SPEC 8.7 / 6.4: authentication failures flag the account.
    void backupAuthFailed()
    {
        FakeServer::instance()->secret = "other";
        FakeServer::instance()->identity = ServerIdentity::fromPin(pinOf('a'));
        const int id = createAccount(QStringLiteral("Backups"), pinOf('a'));
        Outcome outcome = run(makeClient(Op::Backup, id));
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::AUTHENTICATION_FAILURE));
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdate")).toBool(), true);
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdateFrom")).toString(),
                 QStringLiteral("fake-backup"));
        QVERIFY(fixture->value(id, QStringLiteral("netvfs/fake/host_key_seen")).toString().isEmpty());
        QVERIFY(service->createCalls.isEmpty());
    }

    // The secret cannot be fetched: the AuthFailed path, without connecting.
    void backupSecretUnavailable()
    {
        sessions.secretResult = Result(Error::AuthFailed, QStringLiteral("no identity"));
        const int id = createAccount();
        Outcome outcome = run(makeClient(Op::Backup, id));
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::AUTHENTICATION_FAILURE));
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));
        QVERIFY(serverLog().isEmpty());
    }

    void backupIdentity_data()
    {
        QTest::addColumn<QString>("pin");
        QTest::newRow("changed") << pinOf('a');
        QTest::newRow("unknown") << QString();
    }

    // SEC-1, SPEC-sftp S-7: no authentication; seen key recorded.
    void backupIdentity()
    {
        QFETCH(QString, pin);
        FakeServer::instance()->identity = ServerIdentity::fromPin(pinOf('b'));
        const int id = createAccount(QStringLiteral("Backups"), pin);
        Outcome outcome = run(makeClient(Op::Backup, id));
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::AUTHENTICATION_FAILURE));
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/attention")).toString(),
                 QStringLiteral("server-identity-changed"));
        QCOMPARE(fixture->value(id, QStringLiteral("netvfs/fake/host_key_seen")).toString(), pinOf('b'));
        QCOMPARE(fixture->value(id, QStringLiteral("CredentialsNeedUpdate")).toBool(), true);
        QVERIFY(!serverLog().contains(QStringLiteral("authenticate")));
        QVERIFY(service->createCalls.isEmpty());
    }

    void backupUploadFailures_data()
    {
        QTest::addColumn<bool>("noSpace");
        QTest::newRow("dropped") << false;
        QTest::newRow("no space") << true;
    }

    // C-12, C-13 through the plugin; local archive removed on failure.
    void backupUploadFailures()
    {
        QFETCH(bool, noSpace);
        const int id = createAccount();
        if (noSpace)
            FakeServer::instance()->freeBytes = 1000;
        else
            FakeServer::instance()->failUploadAfterBytes = 100 * 1024;
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        QVERIFY(startBackup(client, &outcome));
        const QString archive = service->lastArchivePath;
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        QVERIFY(outcome.wait());
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, int(noSpace ? Buteo::SyncResults::INTERNAL_ERROR : Buteo::SyncResults::CONNECTION_ERROR));
        if (noSpace)
            QVERIFY(outcome.d->message.contains(QStringLiteral("NoSpace")));
        const QString remote = QStringLiteral("Backups/device-1/") + QFileInfo(archive).fileName();
        QVERIFY(!serverHas(remote));
        QVERIFY(!serverHas(remote + QStringLiteral(".part")));
        QCOMPARE(serverLog().join(QLatin1Char(' ')).contains(QStringLiteral("upload:")), !noSpace);
        QVERIFY(!QFile::exists(archive));
    }

    // B-4: abort cancels the in-flight upload and reports Buteo's code;
    // B-3: the plugin thread keeps running its event loop meanwhile.
    void abortDuringUpload()
    {
        const int id = createAccount();
        service->archiveContent = QByteArray(64 * 1024 * 40, 'z');
        FakeServer::instance()->chunkDelayMs = 50;
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        QVERIFY(startBackup(client, &outcome));
        const QString archive = service->lastArchivePath;
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        QVERIFY(waitForLog(QStringLiteral("upload:")));

        int ticks = 0;
        QTimer ticker;
        connect(&ticker, &QTimer::timeout, [&ticks]() { ++ticks; });
        ticker.start(10);
        QTest::qWait(150);
        QVERIFY2(ticks >= 3, "the plugin thread was blocked by the upload");
        QCOMPARE(outcome.total(), 0);

        QElapsedTimer timer;
        timer.start();
        client->abortSync(Sync::SYNC_CONNECTION_ERROR);
        QVERIFY(outcome.wait());
        QVERIFY(timer.elapsed() < 1000);
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::CONNECTION_ERROR));
        const QString remote = QStringLiteral("Backups/device-1/") + QFileInfo(archive).fileName();
        QVERIFY(!serverHas(remote));
        QVERIFY(!serverHas(remote + QStringLiteral(".part")));
        QVERIFY(!QFile::exists(archive));
        QCOMPARE(FakeServer::instance()->liveBackends, 0);
        QVERIFY(fixture->value(id, QStringLiteral("netvfs/attention")).toString().isEmpty());

        client->abortSync(Sync::SYNC_ABORTED);
        QTest::qWait(100);
        QCOMPARE(outcome.total(), 1);
    }

    // Abort while waiting for the archive: immediate result, archive removed.
    void abortWhileWaitingForArchive()
    {
        const int id = createAccount();
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        QVERIFY(startBackup(client, &outcome));
        const QString archive = service->lastArchivePath;
        QTest::qWait(100);   // the reply with the path has arrived
        client->abortSync();
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::ABORTED));
        QVERIFY(!QFile::exists(archive));
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        QTest::qWait(100);
        QCOMPARE(outcome.total(), 1);
        QVERIFY(!serverLog().join(QLatin1Char(' ')).contains(QStringLiteral("upload:")));
    }

    // Abort before the reply carrying the archive path: the archive is still removed.
    void abortBeforeArchiveReply()
    {
        const int id = createAccount();
        BackupClient *client = makeClient(Op::Backup, id);
        service->onCreate = [client]() { client->abortSync(); };
        Outcome outcome;
        QVERIFY(startBackup(client, &outcome));
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::ABORTED));
        const QString archive = service->lastArchivePath;
        QTRY_VERIFY(!QFile::exists(archive));
        QVERIFY(!QFileInfo::exists(QFileInfo(archive).absolutePath()));
        QCOMPARE(outcome.total(), 1);
    }

    // B-7: abort racing a completed upload whose result is not yet delivered.
    void abortRacesCompletion()
    {
        const int id = createAccount();
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        QVERIFY(startBackup(client, &outcome));
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        // Spin only until the upload starts, then block this thread until the
        // worker is done so its result is still queued when abort arrives.
        QVERIFY(waitForLog(QStringLiteral("upload:")));
        QElapsedTimer timer;
        timer.start();
        while (!serverLog().contains(QStringLiteral("disconnect"), Qt::CaseSensitive)
               || serverLog().count(QStringLiteral("disconnect")) < 2) {
            QVERIFY(timer.elapsed() < 10000);
            QThread::msleep(2);
        }
        QThread::msleep(20);
        client->abortSync();
        client->abortSync(Sync::SYNC_ERROR);
        QVERIFY(outcome.wait());
        QTest::qWait(100);
        QCOMPARE(outcome.total(), 1);
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::ABORTED));
    }

    // Abort racing a successful pre-flight: no archive is requested.
    void abortRacesPreflight()
    {
        const int id = createAccount();
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        outcome.watch(client);
        QVERIFY(client->init());
        // Hold the server so the pre-flight cannot finish while the run gets there.
        FakeServer::instance()->mutex.lock();
        const bool started = client->startSync();
        QTest::qWait(300);
        FakeServer::instance()->mutex.unlock();
        QVERIFY(started);
        // Without spinning the event loop, until the worker has disconnected.
        QElapsedTimer timer;
        timer.start();
        while (!serverLog().contains(QStringLiteral("disconnect"))) {
            QVERIFY(timer.elapsed() < 10000);
            QThread::msleep(2);
        }
        QThread::msleep(20);
        client->abortSync();
        QVERIFY(outcome.wait());
        QTest::qWait(100);
        QCOMPARE(outcome.total(), 1);
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::ABORTED));
        QVERIFY(service->createCalls.isEmpty());
    }

    void abortBeforeStartAndAfterFinish()
    {
        const int id = createAccount();
        BackupClient *client = makeClient(Op::BackupQuery, id);
        Outcome outcome;
        outcome.watch(client);
        client->abortSync();
        QVERIFY(client->init());
        QCOMPARE(outcome.total(), 0);
        QVERIFY(client->startSync());
        QVERIFY(!client->startSync());   // one run at a time
        QVERIFY(outcome.wait());
        QCOMPARE(outcome.d->successes, 1);
        client->abortSync();
        QTest::qWait(50);
        QCOMPARE(outcome.total(), 1);

        // A second run on the same instance works.
        QVERIFY(client->startSync());
        QElapsedTimer timer;
        timer.start();
        while (outcome.total() < 2 && timer.elapsed() < 10000)
            QTest::qWait(5);
        QCOMPARE(outcome.d->successes, 2);
    }

    // uninit() during an upload stops the worker and removes the archive.
    void uninitWhileUploading()
    {
        const int id = createAccount();
        service->archiveContent = QByteArray(64 * 1024 * 40, 'u');
        FakeServer::instance()->chunkDelayMs = 50;
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        QVERIFY(startBackup(client, &outcome));
        const QString archive = service->lastArchivePath;
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        QVERIFY(waitForLog(QStringLiteral("upload:")));
        QElapsedTimer timer;
        timer.start();
        QVERIFY(client->uninit());
        QVERIFY(timer.elapsed() < 1000);
        QCOMPARE(FakeServer::instance()->liveBackends, 0);
        QVERIFY(!QFile::exists(archive));
        QTest::qWait(50);
        QCOMPARE(outcome.total(), 0);
        QVERIFY(client->uninit());
    }

    // Abort while the session is still opening.
    void abortWhileOpening()
    {
        BackupClient *client = makeClient(Op::BackupQuery, createAccount());
        Outcome outcome;
        outcome.watch(client);
        QVERIFY(client->init());
        QVERIFY(client->startSync());
        client->abortSync(Sync::SYNC_PLUGIN_TIMEOUT);
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::PLUGIN_TIMEOUT));
        QTest::qWait(100);
        QCOMPARE(outcome.total(), 1);
        QVERIFY(serverLog().isEmpty());
        QVERIFY(service->cloudBackups.isEmpty());
    }

    // B-5
    void connectivityIgnored()
    {
        const int id = createAccount();
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        QVERIFY(startBackup(client, &outcome));
        client->connectivityStateChanged(Sync::CONNECTIVITY_INTERNET, false);
        client->connectivityStateChanged(Sync::CONNECTIVITY_BT, false);
        QTest::qWait(50);
        QCOMPARE(outcome.total(), 0);
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        QVERIFY(outcome.wait());
        QCOMPARE(outcome.d->successes, 1);
    }

    // B-6
    void cleanUpKeepsServerFiles()
    {
        const int id = createAccount();
        FakeServer::instance()->addFile(QStringLiteral("Backups/device-1/a.tar"), "keep");
        BackupClient *client = makeClient(Op::Backup, id);
        Outcome outcome;
        outcome.watch(client);
        QVERIFY(client->cleanUp());
        QTest::qWait(50);
        QVERIFY(serverLog().isEmpty());
        QVERIFY(serverHas(QStringLiteral("Backups/device-1/a.tar")));
        QCOMPARE(outcome.total(), 0);
        QVERIFY(client->uninit());
    }

    // SPEC 8.5
    void query()
    {
        const int id = createAccount();
        addBackupFiles(QStringLiteral("Backups/device-1"));
        Outcome outcome = run(makeClient(Op::BackupQuery, id));
        QCOMPARE(outcome.d->successes, 1);
        QCOMPARE(service->cloudBackups.size(), 1);
        QCOMPARE(service->cloudBackups.at(0).first, profileName(Op::BackupQuery, id));
        QCOMPARE(service->cloudBackups.at(0).second,
                 QStringList() << QStringLiteral("Backups/device-1/a.tar") << QStringLiteral("Backups/device-1/b.tar"));
        QVERIFY(service->createCalls.isEmpty());
        QCOMPARE(serverLog().count(QStringLiteral("disconnect")), 1);
    }

    // B-2 with an absolute, untidy backups_path.
    void queryRemoteDirectory()
    {
        const int id = createAccount(QStringLiteral("/srv//backups/"));
        service->deviceId = QStringLiteral("phone-2");
        addBackupFiles(QStringLiteral("srv/backups/phone-2"));
        Outcome outcome = run(makeClient(Op::BackupQuery, id));
        QCOMPARE(outcome.d->successes, 1);
        QCOMPARE(service->cloudBackups.at(0).second,
                 QStringList() << QStringLiteral("/srv/backups/phone-2/a.tar")
                               << QStringLiteral("/srv/backups/phone-2/b.tar"));
    }

    void queryMissingDirectory()
    {
        const int id = createAccount();
        Outcome outcome = run(makeClient(Op::BackupQuery, id));
        QCOMPARE(outcome.d->successes, 1);
        QCOMPARE(service->cloudBackups.size(), 1);
        QVERIFY(service->cloudBackups.at(0).second.isEmpty());
        QVERIFY(!serverHas(QStringLiteral("Backups")));   // nothing created
    }

    void queryFailures()
    {
        const int id = createAccount();
        FakeServer::instance()->failOps.insert(QStringLiteral("list"), Result(Error::PermissionDenied, QStringLiteral("no")));
        Outcome outcome = run(makeClient(Op::BackupQuery, id));
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::INTERNAL_ERROR));
        QVERIFY(service->cloudBackups.isEmpty());

        service->failSetCloudBackups = true;
        outcome = run(makeClient(Op::BackupQuery, id));
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::INTERNAL_ERROR));
        QVERIFY(outcome.d->message.contains(QStringLiteral("setCloudBackups")));
    }

    void deviceIdFailures_data()
    {
        QTest::addColumn<bool>("dbusError");
        QTest::addColumn<QString>("deviceId");
        QTest::newRow("D-Bus error") << true << QStringLiteral("device-1");
        QTest::newRow("empty") << false << QString();
        QTest::newRow("dot dot") << false << QStringLiteral("..");
        QTest::newRow("dot") << false << QStringLiteral(".");
        QTest::newRow("slash") << false << QStringLiteral("a/b");
    }

    void deviceIdFailures()
    {
        QFETCH(bool, dbusError);
        QFETCH(QString, deviceId);
        service->failDeviceId = dbusError;
        service->deviceId = deviceId;
        Outcome outcome = run(makeClient(Op::BackupQuery, createAccount()));
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::INTERNAL_ERROR));
        QVERIFY(serverLog().isEmpty());
    }

    void accountProblems()
    {
        // No such account.
        Outcome outcome = run(makeClient(Op::BackupQuery, 99999));
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::INTERNAL_ERROR));
        // An account of another provider.
        const int sftp = createAccount(QStringLiteral("Backups"), QString(), QStringLiteral("sftp"));
        outcome = run(makeClient(Op::BackupQuery, sftp));
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::INTERNAL_ERROR));
        QVERIFY2(outcome.d->message.contains(QStringLiteral("not fake")), qPrintable(outcome.d->message));
        QVERIFY(serverLog().isEmpty());
    }

    // SPEC 8.6
    void restore()
    {
        const int id = createAccount();
        FakeServer::instance()->addFile(QStringLiteral("Backups/device-1/b.tar"), QByteArray(200 * 1024, 'r'));
        const QString target = local->path() + QStringLiteral("/restore/b.tar");
        QDir().mkpath(local->path() + QStringLiteral("/restore"));
        Outcome outcome = run(makeClient(Op::BackupRestore, id, target));
        QCOMPARE(outcome.d->successes, 1);
        QCOMPARE(readFile(target), QByteArray(200 * 1024, 'r'));
        QVERIFY(!QFile::exists(target + QStringLiteral(".part")));
        QVERIFY(serverLog().contains(QStringLiteral("download:Backups/device-1/b.tar")));
        QVERIFY(service->createCalls.isEmpty());
        QVERIFY(service->cloudBackups.isEmpty());
    }

    void restoreMissing()
    {
        const int id = createAccount();
        const QString target = local->path() + QStringLiteral("/missing.tar");
        Outcome outcome = run(makeClient(Op::BackupRestore, id, target));
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::INTERNAL_ERROR));
        QVERIFY2(outcome.d->message.contains(QStringLiteral("The backup missing.tar does not exist in Backups/device-1")),
                 qPrintable(outcome.d->message));
        QVERIFY(!QFile::exists(target));
        QVERIFY(!QFile::exists(target + QStringLiteral(".part")));

        outcome = run(makeClient(Op::BackupRestore, id));
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::INTERNAL_ERROR));
        QVERIFY(outcome.d->message.contains(QStringLiteral("No backup file to restore")));
    }

    void restoreCanceledByService_data()
    {
        QTest::addColumn<QString>("status");
        QTest::addColumn<int>("code");
        QTest::newRow("canceled") << QStringLiteral("Canceled") << int(Buteo::SyncResults::ABORTED);
        QTest::newRow("error") << QStringLiteral("Error") << int(Buteo::SyncResults::INTERNAL_ERROR);
    }

    void restoreCanceledByService()
    {
        QFETCH(QString, status);
        QFETCH(int, code);
        const int id = createAccount();
        FakeServer::instance()->addFile(QStringLiteral("Backups/device-1/big.tar"), QByteArray(64 * 1024 * 40, 'r'));
        FakeServer::instance()->chunkDelayMs = 50;
        const QString target = local->path() + QStringLiteral("/big.tar");
        BackupClient *client = makeClient(Op::BackupRestore, id, target);
        Outcome outcome;
        outcome.watch(client);
        QVERIFY(client->init());
        QVERIFY(client->startSync());
        QVERIFY(waitForLog(QStringLiteral("download:")));
        service->emitRestoreError(id, QStringLiteral("Failed"), QStringLiteral("informational"));
        service->emitRestoreStatus(id + 1000, status);
        service->emitBackupStatus(id, QStringLiteral("Canceled"));   // not a backup
        QTest::qWait(100);
        QCOMPARE(outcome.total(), 0);
        QElapsedTimer timer;
        timer.start();
        service->emitRestoreStatus(id, status);
        QVERIFY(outcome.wait());
        QVERIFY(timer.elapsed() < 1000);
        QCOMPARE(outcome.d->errors, 1);
        QCOMPARE(outcome.d->code, code);
        QVERIFY(!QFile::exists(target));
        QVERIFY(!QFile::exists(target + QStringLiteral(".part")));
    }

    // Restore status before the transfer started: no job to cancel.
    void restoreCanceledEarly()
    {
        const int id = createAccount();
        BackupClient *client = makeClient(Op::BackupRestore, id, local->path() + QStringLiteral("/x.tar"));
        Outcome outcome;
        outcome.watch(client);
        QVERIFY(client->init());
        QVERIFY(client->startSync());
        service->emitRestoreStatus(id, QStringLiteral("Canceled"));
        QVERIFY(outcome.wait());
        QCOMPARE(outcome.d->code, int(Buteo::SyncResults::ABORTED));
        QTest::qWait(100);
        QCOMPARE(outcome.total(), 1);
    }

    // C-17: the secret never reaches a log, even at debug level.
    void noSecretsLogged()
    {
        sessions.secret = "s3cr3t-Value";
        FakeServer::instance()->secret = sessions.secret;
        QLoggingCategory::setFilterRules(QStringLiteral("netvfs.*=true"));
        capturedMessages().clear();
        const QtMessageHandler previous = qInstallMessageHandler(captureMessage);
        const int id = createAccount();
        Outcome outcome;
        BackupClient *client = makeClient(Op::Backup, id);
        const bool started = startBackup(client, &outcome);
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        outcome.wait();
        FakeServer::instance()->secret = "wrong";
        run(makeClient(Op::BackupQuery, id));
        qInstallMessageHandler(previous);
        QLoggingCategory::setFilterRules(QString());
        QVERIFY(started);
        QCOMPARE(outcome.d->successes, 1);
        QVERIFY(!capturedMessages().isEmpty());
        for (const QString &message : capturedMessages())
            QVERIFY2(!message.contains(QStringLiteral("s3cr3t")), qPrintable(message));
    }

    // The production session path with a real signond identity, when signond works here.
    void realSignondBackup()
    {
        if (QStandardPaths::findExecutable(QStringLiteral("signond")).isEmpty())
            QSKIP("signond is not installed");
        SignOn::IdentityInfo info;
        info.setCaption(QStringLiteral("netvfs buteo test"));
        info.setUserName(QStringLiteral("user"));
        info.setSecret(QStringLiteral("secret"), true);
        info.setMethod(QStringLiteral("password"), QStringList() << QStringLiteral("password"));
        info.setAccessControlList(QStringList() << QStringLiteral("*"));
        SignOn::Identity *identity = SignOn::Identity::newIdentity(info, this);
        QSignalSpy stored(identity, &SignOn::Identity::credentialsStored);
        identity->storeCredentials();
        if (!stored.wait(15000))
            QSKIP("signond is not usable in this environment");
        const quint32 credentialsId = stored.at(0).at(0).toUInt();

        const int id = createAccount(QStringLiteral("Backups"), QString(), QStringLiteral("fake"), credentialsId);
        Buteo::SyncProfile profile(profileName(Op::Backup, id));
        profile.setKey(QStringLiteral("accountid"), QString::number(id));
        BackupClient client(QStringLiteral("fake"), Op::Backup, QStringLiteral("fake-backup"), profile, nullptr);
        Outcome outcome;
        const bool started = startBackup(&client, &outcome);
        service->emitBackupStatus(id, QStringLiteral("UploadingBackup"));
        outcome.wait();
        identity->remove();
        QVERIFY(started);
        QCOMPARE(outcome.d->successes, 1);
    }

    // The worker in isolation.
    void networkJob()
    {
        ConnectionParams params;
        params.host = QStringLiteral("fake.example");
        const Credentials credentials(QStringLiteral("user"), "secret");

        NetworkJob missing(QStringLiteral("nosuchprovider"), params, credentials,
                           [](Backend *) { return Result(); });
        missing.start();
        QVERIFY(missing.wait(5000));
        QVERIFY(!missing.result().ok());

        bool ranBody = false;
        NetworkJob canceled(QStringLiteral("fake"), params, credentials, [&ranBody](Backend *) {
            ranBody = true;
            return Result();
        });
        canceled.cancel();
        canceled.start();
        QVERIFY(canceled.wait(5000));
        QCOMPARE(canceled.result().error(), Error::Canceled);
        QVERIFY(!ranBody);

        FakeServer::instance()->identity = ServerIdentity::fromPin(pinOf('c'));
        params.options.insert(QStringLiteral("host_key"), pinOf('c'));
        QThread *bodyThread = nullptr;
        NetworkJob ok(QStringLiteral("fake"), params, credentials, [&bodyThread](Backend *backend) {
            bodyThread = QThread::currentThread();
            return backend->makePath(QStringLiteral("x/y"));
        });
        ok.start();
        QVERIFY(ok.wait(5000));
        QVERIFY(ok.result().ok());
        QCOMPARE(ok.seenIdentity().toPin(), pinOf('c'));
        QVERIFY(bodyThread && bodyThread != QThread::currentThread());
        QVERIFY(serverHas(QStringLiteral("x/y")));
        QCOMPARE(serverLog().last(), QStringLiteral("disconnect"));
    }

    void steps()
    {
        QString dir;
        QVERIFY(BackupSteps::remoteDirectory(QStringLiteral("a/b/"), QStringLiteral(" dev "), &dir).ok());
        QCOMPARE(dir, QStringLiteral("a/b/dev"));
        QVERIFY(!BackupSteps::remoteDirectory(QStringLiteral("a/../b"), QStringLiteral("dev"), &dir).ok());

        Test::FakeBackend backend;
        ServerIdentity seen;
        QVERIFY(backend.connect(ConnectionParams(), &seen).ok());
        QVERIFY(backend.authenticate(Credentials(QStringLiteral("user"), "secret")).ok());
        QCOMPARE(BackupSteps::restoreBackup(&backend, QStringLiteral("d"), local->path() + QStringLiteral("/")).error(),
                 Error::Internal);
        QStringList paths;
        FakeServer::instance()->failOps.insert(QStringLiteral("list"), Result(Error::Timeout));
        QCOMPARE(BackupSteps::listBackups(&backend, QStringLiteral("d"), &paths).error(), Error::Timeout);
        QVERIFY(paths.isEmpty());
        FakeServer::instance()->failOps.insert(QStringLiteral("makePath"), Result(Error::NoSpace));
        QCOMPARE(BackupSteps::preflight(&backend, QStringLiteral("d")).error(), Error::NoSpace);
        QCOMPARE(serverLog().count(QStringLiteral("list:d")), 1);   // only the listBackups() above
    }

    void backupServiceDirect()
    {
        BackupService direct;
        QString id;
        Result result(Error::Internal);
        direct.backupFileDeviceId([&](const Result &r, const QString &value) {
            result = r;
            id = value;
        });
        QTRY_VERIFY(result.ok());
        QCOMPARE(id, QStringLiteral("device-1"));
    }
};

QTEST_GUILESS_MAIN(TestButeo)
#include "tst_buteo.moc"
