// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs-accounts (SPEC-v2 XB-2a): the setgid helper that is the bridge's
// only access to the accounts database, its answers, its environment when
// set-id, and the bridge's side that runs it.
#include "accountsfixture.h"
#include "accountshelper.h"
#include "privileges.h"

#include <Accounts/Manager>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>
#include <QtTest/QtTest>

#include <memory>

#include <pwd.h>
#include <sys/resource.h>
#include <unistd.h>

using namespace NetVfs;
using namespace NetVfs::Bridge;
using NetVfs::Test::AccountsFixture;

namespace QTest {
template<>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest

namespace {

const QString Helper = QStringLiteral(NETVFS_TEST_LIBEXEC_DIR "/netvfs-accounts");

QVariantMap globals(const QString &host, const QVariantMap &extra = QVariantMap())
{
    QVariantMap map { { QStringLiteral("netvfs/host"), host },
                      { QStringLiteral("netvfs/port"), 2222 },
                      { QStringLiteral("netvfs/username"), QStringLiteral("alice") } };
    for (auto it = extra.constBegin(); it != extra.constEnd(); ++it)
        map.insert(it.key(), it.value());
    return map;
}

QByteArray serve(AccountsFixture *fixture, const QStringList &arguments)
{
    return AccountsHelper::serve(fixture->manager(), arguments);
}

// Restores the environment after prepareSetIdProcess().
class SavedEnvironment
{
public:
    SavedEnvironment()
    {
        for (char **entry = environ; *entry; ++entry) {
            const QByteArray variable(*entry);
            const int eq = variable.indexOf('=');
            m_saved.append({ variable.left(eq), variable.mid(eq + 1) });
        }
    }
    ~SavedEnvironment()
    {
        QList<QByteArray> names;
        for (char **entry = environ; *entry; ++entry)
            names << QByteArray(*entry).left(QByteArray(*entry).indexOf('='));
        for (const QByteArray &name : names)
            qunsetenv(name.constData());
        for (const auto &[name, value] : m_saved)
            qputenv(name.constData(), value);
    }

private:
    QList<QPair<QByteArray, QByteArray>> m_saved;
};

} // namespace

class tst_BridgeAccounts : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();
    void list();
    void files();
    void filesPolicy();
    void attention();
    void usage();
    void databaseUnusable();
    void malformedAnswers();
    void setIdEnvironment();
    void directoryLists();
    void directoryFailures();
    void directoryFetch();
    void directoryAttention();
    void directoryChangeSignal();

private:
    // A session bus of this test's own: other tests that write accounts at
    // the same time would announce their changes here too.
    QProcess busDaemon;
    std::unique_ptr<AccountsFixture> fixture;
    int listed = 0;      // fake, Files enabled
    int unlisted = 0;    // fake, Files service disabled
};

void tst_BridgeAccounts::initTestCase()
{
    busDaemon.start(QStringLiteral("dbus-daemon"), { QStringLiteral("--session"), QStringLiteral("--nofork"),
                                                     QStringLiteral("--print-address") });
    QVERIFY2(busDaemon.waitForStarted(), "dbus-daemon is needed");
    QVERIFY(busDaemon.waitForReadyRead(10000));
    const QByteArray address = busDaemon.readLine().trimmed();
    QVERIFY(!address.isEmpty());
    // Before the first use of the session bus in this process; the helpers
    // and libaccounts inherit it.
    qputenv("DBUS_SESSION_BUS_ADDRESS", address);
}

void tst_BridgeAccounts::cleanupTestCase()
{
    busDaemon.kill();
    busDaemon.waitForFinished();
}

void tst_BridgeAccounts::init()
{
    fixture = std::make_unique<AccountsFixture>(
        QStringList { QStringLiteral("fake"), QStringLiteral("smb") });
    listed = fixture->createAccount(QStringLiteral("fake"), globals(QStringLiteral("files.example")), QString(), 7);
    QVERIFY(listed > 0);
    QVERIFY(fixture->setService(listed, QStringLiteral("fake-files"), true,
                                { { QStringLiteral("files_root"), QStringLiteral("photos//2026/") } }));
    unlisted = fixture->createAccount(QStringLiteral("fake"), globals(QStringLiteral("backup.example")));
    QVERIFY(unlisted > 0);
}

void tst_BridgeAccounts::cleanup()
{
    fixture.reset();
}

void tst_BridgeAccounts::list()
{
    // XA-1: only enabled accounts with the Files service enabled.
    QVector<AccountLocation> accounts;
    QVERIFY(AccountsHelper::decodeList(serve(fixture.get(), { QStringLiteral("list") }), &accounts).ok());
    QCOMPARE(accounts.size(), 1);
    const AccountLocation &a = accounts.at(0);
    QCOMPARE(a.accountId, listed);
    QCOMPARE(a.provider, QStringLiteral("fake"));
    QCOMPARE(a.displayName, QStringLiteral("alice@files.example"));
    QCOMPARE(a.params.host, QStringLiteral("files.example"));
    QCOMPARE(a.params.port, 2222);
    QCOMPARE(a.params.username, QStringLiteral("alice"));
    QCOMPARE(a.filesRoot, QStringLiteral("photos/2026"));
    QCOMPARE(a.attention, Attention::None);

    QVERIFY(fixture->setService(listed, QString(), false));
    QVERIFY(AccountsHelper::decodeList(serve(fixture.get(), { QStringLiteral("list") }), &accounts).ok());
    QVERIFY(accounts.isEmpty());
}

void tst_BridgeAccounts::files()
{
    FilesAccess access;
    QVERIFY(AccountsHelper::decodeFiles(serve(fixture.get(), { QStringLiteral("files"), QString::number(listed) }),
                                        &access).ok());
    QCOMPARE(access.params.host, QStringLiteral("files.example"));
    QCOMPARE(access.params.provider, QStringLiteral("fake"));
    QCOMPARE(access.credentialsId, 7u);
    QVERIFY(!access.secretOptional);
    // Only listed accounts: not one whose Files service is off, nor ids that
    // are not ids.
    for (const QString &id : { QString::number(unlisted), QStringLiteral("999"), QStringLiteral("0"),
                               QStringLiteral("-1"), QStringLiteral("x"), QString() }) {
        QCOMPARE(AccountsHelper::decodeFiles(serve(fixture.get(), { QStringLiteral("files"), id }), &access).error(),
                 Error::NotFound);
    }
}

void tst_BridgeAccounts::filesPolicy()
{
    // XA-4 is applied by the helper, before the bridge looks up a secret.
    const int bogus = fixture->createAccount(
        QStringLiteral("smb"), globals(QStringLiteral("nas.example"),
                                       { { QStringLiteral("netvfs/smb/security_profile"), QStringLiteral("bogus") } }));
    QVERIFY(fixture->setService(bogus, QStringLiteral("smb-files"), true));
    FilesAccess access;
    QCOMPARE(AccountsHelper::decodeFiles(serve(fixture.get(), { QStringLiteral("files"), QString::number(bogus) }),
                                         &access).error(),
             Error::SecurityPolicy);
    // XA-7: a guest profile with consent needs no secret.
    const int guest = fixture->createAccount(
        QStringLiteral("smb"), globals(QStringLiteral("guest.example"),
                                       { { QStringLiteral("netvfs/smb/security_profile"), QStringLiteral("guest") },
                                         { QStringLiteral("netvfs/smb/allow_insecure"), true } }));
    QVERIFY(fixture->setService(guest, QStringLiteral("smb-files"), true));
    QVERIFY(AccountsHelper::decodeFiles(serve(fixture.get(), { QStringLiteral("files"), QString::number(guest) }),
                                        &access).ok());
    QVERIFY(access.secretOptional);
}

void tst_BridgeAccounts::attention()
{
    // XB-14: recorded for a listed account, as a Files run.
    QVERIFY(AccountsHelper::decodeStatus(serve(fixture.get(), { QStringLiteral("attention"), QString::number(listed),
                                                                QStringLiteral("server-identity-changed"),
                                                                QStringLiteral("SHA256:pin") }))
                .ok());
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(),
             QStringLiteral("server-identity-changed"));
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/fake/host_key_seen")).toString(), QStringLiteral("SHA256:pin"));
    QCOMPARE(fixture->value(listed, QStringLiteral("CredentialsNeedUpdateFrom")).toString(),
             QStringLiteral("fake-files"));
    QVERIFY(AccountsHelper::decodeStatus(serve(fixture.get(), { QStringLiteral("attention"), QString::number(listed),
                                                                QStringLiteral("auth-failed") }))
                .ok());
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));

    // Clearing it is not the bridge's, and anyone can run the helper.
    for (const QString &state : { QStringLiteral("none"), QString(), QStringLiteral("whatever") }) {
        QCOMPARE(AccountsHelper::decodeStatus(serve(fixture.get(), { QStringLiteral("attention"),
                                                                     QString::number(listed), state }))
                     .error(),
                 Error::Unsupported);
    }
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));
    // Nor on an account the bridge does not list.
    QCOMPARE(AccountsHelper::decodeStatus(serve(fixture.get(), { QStringLiteral("attention"), QString::number(unlisted),
                                                                 QStringLiteral("auth-failed") }))
                 .error(),
             Error::NotFound);
    QVERIFY(fixture->value(unlisted, QStringLiteral("netvfs/attention")).toString().isEmpty());
}

void tst_BridgeAccounts::usage()
{
    const QList<QStringList> invalid {
        {},
        { QStringLiteral("list"), QStringLiteral("extra") },
        { QStringLiteral("files") },
        { QStringLiteral("files"), QString::number(listed), QStringLiteral("extra") },
        { QStringLiteral("attention"), QString::number(listed) },
        { QStringLiteral("attention"), QString::number(listed), QStringLiteral("auth-failed"), QStringLiteral("p"),
          QStringLiteral("extra") },
        { QStringLiteral("secret"), QString::number(listed) },
    };
    for (const QStringList &arguments : invalid)
        QCOMPARE(AccountsHelper::decodeStatus(serve(fixture.get(), arguments)).error(), Error::Unsupported);
}

void tst_BridgeAccounts::databaseUnusable()
{
    // What a helper without the group sees on Sailfish OS: an error naming
    // the setgid bit, not an empty list.
    fixture.reset();
    QTemporaryDir dir;
    QFile file(dir.path() + QStringLiteral("/file"));
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.close();
    const QByteArray saved = qgetenv("ACCOUNTS");
    qputenv("ACCOUNTS", QFile::encodeName(dir.path() + QStringLiteral("/file/accounts")));
    QByteArray answer;
    {
        Accounts::Manager manager;
        answer = AccountsHelper::serve(&manager, { QStringLiteral("list") });
    }
    if (saved.isNull())
        qunsetenv("ACCOUNTS");
    else
        qputenv("ACCOUNTS", saved);
    QVector<AccountLocation> accounts;
    const Result r = AccountsHelper::decodeList(answer, &accounts);
    QCOMPARE(r.error(), Error::PermissionDenied);
    QVERIFY2(r.message().contains(QLatin1String("setgid privileged")), qPrintable(r.message()));
}

void tst_BridgeAccounts::malformedAnswers()
{
    const QByteArray good = serve(fixture.get(), { QStringLiteral("list") });
    QVector<AccountLocation> accounts;
    QVERIFY(AccountsHelper::decodeList(good, &accounts).ok());
    QCOMPARE(AccountsHelper::decodeList(QByteArray(), &accounts).error(), Error::ProtocolError);
    QCOMPARE(AccountsHelper::decodeList("garbage", &accounts).error(), Error::ProtocolError);
    QCOMPARE(AccountsHelper::decodeList(good.left(good.size() - 1), &accounts).error(), Error::ProtocolError);
    QCOMPARE(AccountsHelper::decodeList(good + 'x', &accounts).error(), Error::ProtocolError);
    QCOMPARE(accounts.size(), 1);   // untouched by the failures
    FilesAccess access;
    QCOMPARE(AccountsHelper::decodeFiles(good, &access).error(), Error::ProtocolError);
    QCOMPARE(AccountsHelper::decodeStatus(good).error(), Error::ProtocolError);
    // Another kind of answer is no list either.
    const QByteArray files = serve(fixture.get(), { QStringLiteral("files"), QString::number(listed) });
    QCOMPARE(AccountsHelper::decodeList(files, &accounts).error(), Error::ProtocolError);
}

void tst_BridgeAccounts::setIdEnvironment()
{
    // XB-2a: what a setgid helper keeps from its caller's environment.
    for (const char *name : { "LANG", "LANGUAGE", "LC_ALL", "LC_TIME", "TZ", "XDG_RUNTIME_DIR",
                              "DBUS_SESSION_BUS_ADDRESS" })
        QVERIFY2(keptInSetIdProcess(name), name);
    for (const char *name : { "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "ACCOUNTS", "AG_PROVIDERS", "AG_SERVICES",
                              "AG_APPLICATIONS", "NETVFS_ACCOUNTS_HELPER", "QT_PLUGIN_PATH", "QT_LOGGING_RULES",
                              "LD_PRELOAD", "GIO_EXTRA_MODULES", "PATH", "LANGX", "XLANG", "" })
        QVERIFY2(!keptInSetIdProcess(name), name);

    QList<QByteArray> removed;
    bool prepared = false;
    QByteArray home;
    QByteArray accounts;
    QByteArray lang;
    struct rlimit coreBefore {};
    struct rlimit coreAfter {};
    ::getrlimit(RLIMIT_CORE, &coreBefore);
    {
        const SavedEnvironment saved;
        qputenv("HOME", "/tmp/someone-else");
        qputenv("ACCOUNTS", "/tmp/evil");
        qputenv("LANG", "fi_FI.UTF-8");
        // A core limit of its own to drop (the soft limit may start at 0).
        const struct rlimit coreOpen { coreBefore.rlim_max, coreBefore.rlim_max };
        QVERIFY(coreOpen.rlim_cur != 0);
        ::setrlimit(RLIMIT_CORE, &coreOpen);
        prepared = prepareSetIdProcess(&removed);
        ::getrlimit(RLIMIT_CORE, &coreAfter);
        ::setrlimit(RLIMIT_CORE, &coreBefore);
        home = qgetenv("HOME");
        accounts = qgetenv("ACCOUNTS");
        lang = qgetenv("LANG");
    }
    const struct passwd *user = ::getpwuid(::getuid());
    QVERIFY(user && user->pw_dir);
    QVERIFY(prepared);
    QCOMPARE(home, QByteArray(user->pw_dir));   // the real uid's, not the caller's
    QVERIFY(accounts.isNull());
    QCOMPARE(lang, QByteArray("fi_FI.UTF-8"));
    QVERIFY(removed.contains("ACCOUNTS"));
    QVERIFY(!removed.contains("LANG"));
    QCOMPARE(coreAfter.rlim_cur, rlim_t(0));
    QCOMPARE(coreAfter.rlim_max, coreBefore.rlim_max);
    QCOMPARE(qgetenv("ACCOUNTS"), QFile::encodeName(fixture->path()));   // restored
}

void tst_BridgeAccounts::directoryLists()
{
    // The built helper, through the bridge's side (it inherits the private
    // database's environment and is not set-id here).
    HelperAccountsDirectory directory(Helper);
    const QVector<AccountLocation> accounts = directory.filesAccounts();
    QCOMPARE(accounts.size(), 1);
    QCOMPARE(accounts.at(0).accountId, listed);
    QCOMPARE(accounts.at(0).params.host, QStringLiteral("files.example"));
}

void tst_BridgeAccounts::directoryFailures()
{
    // A missing or failing helper lists nothing, and says why.
    QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("^Cannot list the accounts")));
    QVERIFY(HelperAccountsDirectory(QStringLiteral("/nonexistent/netvfs-accounts")).filesAccounts().isEmpty());
    QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("^Cannot list the accounts.*/bin/false")));
    QVERIFY(HelperAccountsDirectory(QStringLiteral("/bin/false")).filesAccounts().isEmpty());
    QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("^Cannot list the accounts.*malformed")));
    QVERIFY(HelperAccountsDirectory(QStringLiteral("/bin/true")).filesAccounts().isEmpty());
}

void tst_BridgeAccounts::directoryFetch()
{
    // An account the helper does not hand out fails before signond is asked.
    HelperAccountsDirectory directory(Helper);
    Result result(Error::Internal);
    bool called = false;
    directory.fetch(unlisted, [&](const Result &r, const ConnectionParams &params, const Credentials &) {
        result = r;
        called = true;
        QVERIFY(params.host.isEmpty());
    });
    QTRY_VERIFY_WITH_TIMEOUT(called, 10000);
    QCOMPARE(result.error(), Error::NotFound);

    called = false;
    HelperAccountsDirectory missing(QStringLiteral("/nonexistent/netvfs-accounts"));
    missing.fetch(listed, [&](const Result &r, const ConnectionParams &, const Credentials &) {
        result = r;
        called = true;
    });
    QTRY_VERIFY_WITH_TIMEOUT(called, 10000);
    QCOMPARE(result.error(), Error::Unsupported);
}

void tst_BridgeAccounts::directoryAttention()
{
    HelperAccountsDirectory directory(Helper);
    QSignalSpy changed(&directory, &AccountDirectory::changed);
    directory.setAttention(listed, Attention::AuthFailed, QString());
    QTRY_VERIFY_WITH_TIMEOUT(changed.count() >= 1, 10000);
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));

    // A refused write is logged, and nothing changed.
    QTest::qWait(500);   // the refresh for the write's own AccountChanged
    changed.clear();
    QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("^Cannot record the attention state")));
    directory.setAttention(unlisted, Attention::AuthFailed, QString());
    QTRY_VERIFY_WITH_TIMEOUT(directory.findChildren<QProcess *>().isEmpty(), 10000);
    QTest::qWait(500);
    QCOMPARE(changed.count(), 0);

    // A helper whose own AccountChanged never reaches the bus (as a set-id
    // one may not): the bridge lists again all the same.
    QTemporaryDir dir;
    QFile answer(dir.path() + QStringLiteral("/answer"));
    QVERIFY(answer.open(QIODevice::WriteOnly));
    answer.write(serve(fixture.get(), { QStringLiteral("attention"), QString::number(listed),
                                        QStringLiteral("auth-failed") }));
    answer.close();
    QFile script(dir.path() + QStringLiteral("/helper"));
    QVERIFY(script.open(QIODevice::WriteOnly));
    script.write("#!/bin/sh\nexec cat '" + QFile::encodeName(answer.fileName()) + "'\n");
    script.close();
    QVERIFY(script.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    QTest::qWait(500);   // the signals of the write above
    HelperAccountsDirectory quiet(script.fileName());
    QSignalSpy quietChanged(&quiet, &AccountDirectory::changed);
    quiet.setAttention(listed, Attention::AuthFailed, QString());
    QTRY_COMPARE_WITH_TIMEOUT(quietChanged.count(), 1, 10000);
}

void tst_BridgeAccounts::directoryChangeSignal()
{
    // libaccounts' writers announce changes on the session bus, on a path
    // per service type; the several signals of one write make one refresh.
    HelperAccountsDirectory directory(Helper);
    QSignalSpy changed(&directory, &AccountDirectory::changed);
    QDBusConnection bus = QDBusConnection::sessionBus();
    QVERIFY(bus.isConnected());
    QVERIFY(bus.send(QDBusMessage::createSignal(QStringLiteral("/org/example/other"),
                                                QStringLiteral("com.google.code.AccountsSSO.Accounts"),
                                                QStringLiteral("Unrelated"))));
    QVERIFY(bus.send(QDBusMessage::createSignal(QStringLiteral("/org/example/other"), QStringLiteral("org.example.Other"),
                                                QStringLiteral("AccountChanged"))));
    QTest::qWait(500);
    QCOMPARE(changed.count(), 0);

    // Real writes, as Settings makes them: two in a row, one refresh.
    QVERIFY(fixture->setService(listed, QStringLiteral("fake-files"), false));
    QVERIFY(fixture->setService(listed, QStringLiteral("fake-files"), true));
    QTRY_COMPARE_WITH_TIMEOUT(changed.count(), 1, 5000);
    QTest::qWait(500);
    QCOMPARE(changed.count(), 1);
}

QTEST_GUILESS_MAIN(tst_BridgeAccounts)
#include "tst_bridgeaccounts.moc"
