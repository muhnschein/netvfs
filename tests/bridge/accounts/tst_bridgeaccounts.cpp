// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs-accounts (SPEC-v2 XB-2a): the setgid helper that is the bridge's
// only access to the accounts database. The helper is rust/netvfs-accounts,
// whose own tests cover its confinement and set-id environment; the bridge's
// side that runs it is rust/netvfs-bridge/src/accounts, tested there. These
// run the built helper: its answers must be the bytes the C++ helper it
// replaced gave (referencehelper.h) and read back as the C++ bridge read them
// (referencedecoder.h), its writes what libaccounts would store, and its
// change signal one libaccounts reads.
#include "accountsfixture.h"
#include "referencedecoder.h"
#include "referencehelper.h"

#include <Accounts/Account>
#include <Accounts/Manager>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QProcess>
#include <QtCore/QRegularExpression>
#include <QtCore/QTemporaryDir>
#include <QtDBus/QDBusConnection>
#include <QtTest/QtTest>

#include <algorithm>
#include <memory>

#include <sqlite3.h>

using namespace NetVfs;
using namespace NetVfs::Test;

namespace QTest {
template<>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest

namespace {

const QString Helper = QStringLiteral(NETVFS_TEST_LIBEXEC_DIR "/netvfs-accounts");

using Environment = QMap<QString, QString>;

QVariantMap globals(const QString &host, const QVariantMap &extra = QVariantMap())
{
    QVariantMap map { { QStringLiteral("netvfs/host"), host },
                      { QStringLiteral("netvfs/port"), 2222 },
                      { QStringLiteral("netvfs/username"), QStringLiteral("alice") } };
    for (auto it = extra.constBegin(); it != extra.constEnd(); ++it)
        map.insert(it.key(), it.value());
    return map;
}

// The built helper's answer to `arguments`, run with this process's
// environment and `extra`.
QByteArray runHelper(const QStringList &arguments, const Environment &extra = Environment(),
                     int *exitCode = nullptr, QByteArray *errors = nullptr)
{
    QProcess helper;
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    for (auto it = extra.constBegin(); it != extra.constEnd(); ++it)
        environment.insert(it.key(), it.value());
    helper.setProcessEnvironment(environment);
    helper.start(Helper, arguments);
    if (!helper.waitForFinished(10000)) {
        helper.kill();
        helper.waitForFinished();
    }
    if (exitCode)
        *exitCode = helper.exitStatus() == QProcess::NormalExit ? helper.exitCode() : -1;
    if (errors)
        *errors = helper.readAllStandardError();
    return helper.readAllStandardOutput();
}

QByteArray serve(AccountsFixture *, const QStringList &arguments)
{
    return runHelper(arguments);
}

// The C++ helper's answer, from the database ACCOUNTS names now.
QByteArray reference(const QStringList &arguments)
{
    Accounts::Manager manager;
    return Test::referenceServe(&manager, arguments);
}

bool sql(const QString &database, const QString &statement)
{
    sqlite3 *db = nullptr;
    bool ok = sqlite3_open_v2(QFile::encodeName(database).constData(), &db, SQLITE_OPEN_READWRITE, nullptr)
            == SQLITE_OK;
    if (ok) {
        sqlite3_busy_timeout(db, 5000);
        char *error = nullptr;
        ok = sqlite3_exec(db, statement.toUtf8().constData(), nullptr, nullptr, &error) == SQLITE_OK;
        if (!ok)
            qWarning("%s: %s", qPrintable(statement), error);
        sqlite3_free(error);
    }
    sqlite3_close(db);
    return ok;
}

// A consistent copy of the database at `from` (in WAL mode) at `to`.
bool copyDatabase(const QString &from, const QString &to)
{
    sqlite3 *source = nullptr;
    sqlite3 *target = nullptr;
    bool ok = sqlite3_open_v2(QFile::encodeName(from).constData(), &source, SQLITE_OPEN_READONLY, nullptr)
                    == SQLITE_OK
            && sqlite3_open(QFile::encodeName(to).constData(), &target) == SQLITE_OK;
    if (ok) {
        sqlite3_backup *backup = sqlite3_backup_init(target, "main", source, "main");
        ok = backup && sqlite3_backup_step(backup, -1) == SQLITE_DONE;
        ok = sqlite3_backup_finish(backup) == SQLITE_OK && ok;
    }
    sqlite3_close(source);
    sqlite3_close(target);
    return ok;
}

QByteArray describe(const QStringList &arguments, const QByteArray &rust, const QByteArray &cpp)
{
    return "netvfs-accounts " + arguments.join(QLatin1Char(' ')).toUtf8() + "\n   rust: " + rust.toHex()
            + "\n    c++: " + cpp.toHex();
}

// The global settings of `accountId` in the database at `accounts`, as
// libaccounts reads them.
QVariantMap globalSettings(const QString &accounts, int accountId)
{
    const QByteArray saved = qgetenv("ACCOUNTS");
    qputenv("ACCOUNTS", QFile::encodeName(accounts));
    QVariantMap settings;
    {
        Accounts::Manager manager;
        if (Accounts::Account *account = manager.account(static_cast<Accounts::AccountId>(accountId))) {
            account->selectService(Accounts::Service());
            for (const QString &key : account->allKeys())
                settings.insert(key, account->value(key));
        }
    }
    qputenv("ACCOUNTS", saved);
    return settings;
}

} // namespace

class tst_BridgeAccounts : public QObject
{
    Q_OBJECT

public Q_SLOTS:
    void onNameOwnerChanged(const QString &name, const QString &oldOwner, const QString &newOwner);

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
    void goldenAnswers();
    void goldenStoredValues();
    void goldenAttention();
    void attentionSignal();
    void attentionWithoutBus();
    void helperLinks();
    void helperWithClosedDescriptors();

private:
    QString database() const { return fixture->path() + QStringLiteral("/accounts.db"); }
    int listedAccount(const QString &provider, const QVariantMap &globals, const QVariantMap &files = QVariantMap(),
                      quint32 credentialsId = 0);
    void compareAnswers(const QList<QStringList> &requests);

    // A session bus of this test's own: other tests that write accounts at
    // the same time would announce their changes here too.
    QProcess busDaemon;
    QStringList ownedNames;
    std::unique_ptr<AccountsFixture> fixture;
    int listed = 0;      // sftp, Files enabled
    int unlisted = 0;    // sftp, Files service disabled
};

void tst_BridgeAccounts::onNameOwnerChanged(const QString &name, const QString &, const QString &newOwner)
{
    if (!newOwner.isEmpty())
        ownedNames << name;
}

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
    QVERIFY(QDBusConnection::sessionBus().connect(
        QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
        QStringLiteral("org.freedesktop.DBus"), QStringLiteral("NameOwnerChanged"), this,
        SLOT(onNameOwnerChanged(QString, QString, QString))));
}

void tst_BridgeAccounts::cleanupTestCase()
{
    busDaemon.kill();
    busDaemon.waitForFinished();
}

void tst_BridgeAccounts::init()
{
    fixture = std::make_unique<AccountsFixture>(
        QStringList { QStringLiteral("sftp"), QStringLiteral("smb") });
    listed = fixture->createAccount(QStringLiteral("sftp"), globals(QStringLiteral("files.example")), QString(), 7);
    QVERIFY(listed > 0);
    QVERIFY(fixture->setService(listed, QStringLiteral("sftp-files"), true,
                                { { QStringLiteral("files_root"), QStringLiteral("photos//2026/") } }));
    unlisted = fixture->createAccount(QStringLiteral("sftp"), globals(QStringLiteral("backup.example")));
    QVERIFY(unlisted > 0);
}

void tst_BridgeAccounts::cleanup()
{
    fixture.reset();
}

int tst_BridgeAccounts::listedAccount(const QString &provider, const QVariantMap &globals, const QVariantMap &files,
                                      quint32 credentialsId)
{
    const int id = fixture->createAccount(provider, globals, QString(), credentialsId);
    if (id <= 0 || !fixture->setService(id, provider + QStringLiteral("-files"), true, files))
        return 0;
    return id;
}

void tst_BridgeAccounts::list()
{
    // XA-1: only enabled accounts with the Files service enabled.
    QVector<AccountLocation> accounts;
    QVERIFY(decodeList(serve(fixture.get(), { QStringLiteral("list") }), &accounts).ok());
    QCOMPARE(accounts.size(), 1);
    const AccountLocation &a = accounts.at(0);
    QCOMPARE(a.accountId, listed);
    QCOMPARE(a.provider, QStringLiteral("sftp"));
    QCOMPARE(a.displayName, QStringLiteral("alice@files.example"));
    QCOMPARE(a.params.host, QStringLiteral("files.example"));
    QCOMPARE(a.params.port, 2222);
    QCOMPARE(a.params.username, QStringLiteral("alice"));
    QCOMPARE(a.filesRoot, QStringLiteral("photos/2026"));
    QCOMPARE(a.attention, Attention::None);

    QVERIFY(fixture->setService(listed, QString(), false));
    QVERIFY(decodeList(serve(fixture.get(), { QStringLiteral("list") }), &accounts).ok());
    QVERIFY(accounts.isEmpty());
}

void tst_BridgeAccounts::files()
{
    FilesAccess access;
    QVERIFY(decodeFiles(serve(fixture.get(), { QStringLiteral("files"), QString::number(listed) }),
                                        &access).ok());
    QCOMPARE(access.params.host, QStringLiteral("files.example"));
    QCOMPARE(access.params.provider, QStringLiteral("sftp"));
    QCOMPARE(access.credentialsId, 7u);
    QVERIFY(!access.secretOptional);
    // Only listed accounts: not one whose Files service is off, nor ids that
    // are not ids.
    for (const QString &id : { QString::number(unlisted), QStringLiteral("999"), QStringLiteral("0"),
                               QStringLiteral("-1"), QStringLiteral("x"), QString() }) {
        QCOMPARE(decodeFiles(serve(fixture.get(), { QStringLiteral("files"), id }), &access).error(),
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
    QCOMPARE(decodeFiles(serve(fixture.get(), { QStringLiteral("files"), QString::number(bogus) }),
                                         &access).error(),
             Error::SecurityPolicy);
    // XA-7: a guest profile with consent needs no secret.
    const int guest = fixture->createAccount(
        QStringLiteral("smb"), globals(QStringLiteral("guest.example"),
                                       { { QStringLiteral("netvfs/smb/security_profile"), QStringLiteral("guest") },
                                         { QStringLiteral("netvfs/smb/allow_insecure"), true } }));
    QVERIFY(fixture->setService(guest, QStringLiteral("smb-files"), true));
    QVERIFY(decodeFiles(serve(fixture.get(), { QStringLiteral("files"), QString::number(guest) }),
                                        &access).ok());
    QVERIFY(access.secretOptional);
}

void tst_BridgeAccounts::attention()
{
    // XB-14: recorded for a listed account, as a Files run.
    QVERIFY(decodeStatus(serve(fixture.get(), { QStringLiteral("attention"), QString::number(listed),
                                                                QStringLiteral("server-identity-changed"),
                                                                QStringLiteral("SHA256:pin") }))
                .ok());
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(),
             QStringLiteral("server-identity-changed"));
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/sftp/host_key_seen")).toString(), QStringLiteral("SHA256:pin"));
    QCOMPARE(fixture->value(listed, QStringLiteral("CredentialsNeedUpdateFrom")).toString(),
             QStringLiteral("sftp-files"));
    QVERIFY(decodeStatus(serve(fixture.get(), { QStringLiteral("attention"), QString::number(listed),
                                                                QStringLiteral("auth-failed") }))
                .ok());
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));

    // Clearing it is not the bridge's, and anyone can run the helper.
    for (const QString &state : { QStringLiteral("none"), QString(), QStringLiteral("whatever") }) {
        QCOMPARE(decodeStatus(serve(fixture.get(), { QStringLiteral("attention"),
                                                                     QString::number(listed), state }))
                     .error(),
                 Error::Unsupported);
    }
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));
    // Nor on an account the bridge does not list.
    QCOMPARE(decodeStatus(serve(fixture.get(), { QStringLiteral("attention"), QString::number(unlisted),
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
        QCOMPARE(decodeStatus(serve(fixture.get(), arguments)).error(), Error::Unsupported);
}

void tst_BridgeAccounts::databaseUnusable()
{
    // What a helper without the group sees on Sailfish OS: an error naming
    // the setgid bit, not an empty list; also before the request is read.
    QTemporaryDir dir;
    QFile file(dir.path() + QStringLiteral("/file"));
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.close();
    const Environment notAFolder { { QStringLiteral("ACCOUNTS"), dir.path() + QStringLiteral("/file/accounts") } };
    for (const QStringList &arguments : QList<QStringList> { { QStringLiteral("list") },
                                                             { QStringLiteral("files"), QString::number(listed) },
                                                             { QStringLiteral("bogus") } }) {
        const Result r = decodeStatus(runHelper(arguments, notAFolder));
        QCOMPARE(r.error(), Error::PermissionDenied);
        QVERIFY2(r.message().contains(QLatin1String("setgid privileged")), qPrintable(r.message()));
    }

    // Not a database.
    QVERIFY(QDir(dir.path()).mkdir(QStringLiteral("junk")));
    QFile junk(dir.path() + QStringLiteral("/junk/accounts.db"));
    QVERIFY(junk.open(QIODevice::WriteOnly));
    junk.write(QByteArray(4096, 'x'));
    junk.close();
    const Result r = decodeStatus(
        runHelper({ QStringLiteral("list") }, { { QStringLiteral("ACCOUNTS"), dir.path() + QStringLiteral("/junk") } }));
    QCOMPARE(r.error(), Error::PermissionDenied);

    // No database yet is no account, and the helper creates none.
    const QString missing = dir.path() + QStringLiteral("/missing");
    QVector<AccountLocation> accounts { AccountLocation() };
    QVERIFY(decodeList(runHelper({ QStringLiteral("list") }, { { QStringLiteral("ACCOUNTS"), missing } }),
                                       &accounts).ok());
    QVERIFY(accounts.isEmpty());
    QCOMPARE(decodeStatus(runHelper({ QStringLiteral("attention"), QStringLiteral("1"),
                                                      QStringLiteral("auth-failed") },
                                                    { { QStringLiteral("ACCOUNTS"), missing } }))
                 .error(),
             Error::NotFound);
    QVERIFY(!QFileInfo::exists(missing));
}

void tst_BridgeAccounts::malformedAnswers()
{
    const QByteArray good = serve(fixture.get(), { QStringLiteral("list") });
    QVector<AccountLocation> accounts;
    QVERIFY(decodeList(good, &accounts).ok());
    QCOMPARE(decodeList(QByteArray(), &accounts).error(), Error::ProtocolError);
    QCOMPARE(decodeList("garbage", &accounts).error(), Error::ProtocolError);
    QCOMPARE(decodeList(good.left(good.size() - 1), &accounts).error(), Error::ProtocolError);
    QCOMPARE(decodeList(good + 'x', &accounts).error(), Error::ProtocolError);
    QCOMPARE(accounts.size(), 1);   // untouched by the failures
    FilesAccess access;
    QCOMPARE(decodeFiles(good, &access).error(), Error::ProtocolError);
    QCOMPARE(decodeStatus(good).error(), Error::ProtocolError);
    // Another kind of answer is no list either.
    const QByteArray files = serve(fixture.get(), { QStringLiteral("files"), QString::number(listed) });
    QCOMPARE(decodeList(files, &accounts).error(), Error::ProtocolError);
}

void tst_BridgeAccounts::compareAnswers(const QList<QStringList> &requests)
{
    for (const QStringList &arguments : requests) {
        int exitCode = -1;
        const QByteArray rust = runHelper(arguments, Environment(), &exitCode);
        QCOMPARE(exitCode, 0);
        const QByteArray cpp = reference(arguments);
        QVERIFY2(rust == cpp, describe(arguments, rust, cpp).constData());
    }
}

void tst_BridgeAccounts::goldenAnswers()
{
    // The answers of the C++ helper, byte for byte, for what the accounts
    // UI writes and for what other writers of the database could.
    fixture->installProvider(QStringLiteral("sftp"));
    QVariantMap typed = globals(QStringLiteral("types.example"), {
        { QStringLiteral("netvfs/sftp/string"), QStringLiteral("ünïcødé \U0001F600 \"'\\\n\t") },
        { QStringLiteral("netvfs/sftp/empty"), QLatin1String("") },
        { QStringLiteral("netvfs/sftp/int"), -5 },
        { QStringLiteral("netvfs/sftp/uint"), 7u },
        { QStringLiteral("netvfs/sftp/int64"), qint64(1) << 40 },
        { QStringLiteral("netvfs/sftp/uint64"), quint64(1) << 63 },
        { QStringLiteral("netvfs/sftp/true"), true },
        { QStringLiteral("netvfs/sftp/false"), false },
        { QStringLiteral("netvfs/sftp/list0"), QStringList() },
        { QStringLiteral("netvfs/sftp/list1"), QStringList { QStringLiteral("one") } },
        { QStringLiteral("netvfs/sftp/list2"), QStringList { QStringLiteral("a"), QStringLiteral("b") } },
        { QStringLiteral("netvfs/sftp/ä"), QStringLiteral("a Latin-1 key") },
        { QStringLiteral("netvfs/sftp/"), QStringLiteral("an empty option name") },
        { QStringLiteral("netvfs/sftp"), QStringLiteral("no option") },
        { QStringLiteral("netvfs/sftpX/y"), QStringLiteral("another provider's") },
        { QStringLiteral("netvfs/smb/share"), QStringLiteral("another provider's") },
        { QStringLiteral("netvfs/port"), QStringLiteral(" 7 ") },
        { QStringLiteral("netvfs/attention"), QStringLiteral("auth-failed") },
    });
    typed.remove(QStringLiteral("netvfs/username"));
    const int types = listedAccount(QStringLiteral("sftp"), typed,
                                    { { QStringLiteral("files_root"), QStringLiteral("/") } }, 4294967295u);
    QVERIFY(types > 0);
    const int guest = listedAccount(
        QStringLiteral("smb"),
        globals(QStringLiteral("guest.example"), { { QStringLiteral("netvfs/smb/security_profile"), QStringLiteral(" guest ") },
                                                   { QStringLiteral("netvfs/smb/allow_insecure"), true },
                                                   { QStringLiteral("netvfs/attention"),
                                                     QStringLiteral("server-identity-changed") } }),
        { { QStringLiteral("files_root"), QStringLiteral("   ") } });
    QVERIFY(guest > 0);
    const int bogus = listedAccount(
        QStringLiteral("smb"),
        globals(QStringLiteral("bogus.example"), { { QStringLiteral("netvfs/smb/security_profile"), QStringLiteral("x") },
                                                   { QStringLiteral("netvfs/port"), QStringLiteral("99999999999") } }),
        { { QStringLiteral("files_root"), QStringLiteral("../escape") } });
    QVERIFY(bogus > 0);
    const int signedSmb = listedAccount(
        QStringLiteral("smb"),
        globals(QStringLiteral("signed.example"), { { QStringLiteral("netvfs/smb/security_profile"), QStringLiteral("signed") },
                                                    { QStringLiteral("netvfs/port"), 70000u } }));
    QVERIFY(signedSmb > 0);
    const int legacy = listedAccount(
        QStringLiteral("smb"), globals(QStringLiteral("old.example"), { { QStringLiteral("netvfs/smb/security_profile"), QStringLiteral("legacy") } }),
        { { QStringLiteral("files_root"), QStringLiteral("a/./b") } });
    QVERIFY(legacy > 0);
    const int legacyAllowed = listedAccount(
        QStringLiteral("smb"), globals(QStringLiteral("old.example"), { { QStringLiteral("netvfs/smb/security_profile"), QStringLiteral("legacy") },
                                                                     { QStringLiteral("netvfs/smb/allow_insecure"), QStringLiteral("1") } }),
        { { QStringLiteral("files_root"), QStringLiteral("//srv//smb//") } });
    QVERIFY(legacyAllowed > 0);
    const int sftp = listedAccount(
        QStringLiteral("sftp"), globals(QStringLiteral("ssh.example"), { { QStringLiteral("netvfs/sftp/auth_mode"), QStringLiteral("interactive") },
                                                                      { QStringLiteral("netvfs/sftp/allow_shell"), true },
                                                                      { QStringLiteral("netvfs/port"), qint64(22) } }),
        QVariantMap(), 12);
    QVERIFY(sftp > 0);
    QVariantMap withoutHost = globals(QString());
    withoutHost.remove(QStringLiteral("netvfs/host"));
    const int noHost = listedAccount(QStringLiteral("sftp"), withoutHost);
    QVERIFY(noHost > 0);
    const int emptyHost = listedAccount(QStringLiteral("sftp"), globals(QString()));
    QVERIFY(emptyHost > 0);
    const int off = listedAccount(QStringLiteral("sftp"), globals(QStringLiteral("off.example")));
    QVERIFY(off > 0);
    QVERIFY(fixture->setService(off, QString(), false));

    // What only other writers store.
    const QString t = QString::number(types);
    QVERIFY(sql(database(), QStringLiteral(
        "INSERT OR REPLACE INTO Settings (account, service, key, type, value) VALUES "
        "(%1, 0, 'netvfs/sftp/double', 'd', '1.5'),"
        "(%1, 0, 'netvfs/sftp/byte', 'y', '7'),"
        "(%1, 0, 'netvfs/sftp/path', 'o', '''/x'''),"
        "(%1, 0, 'netvfs/sftp/badlist', 'as', '[''a'''),"
        "(%1, 0, 'netvfs/sftp/raw', 's', 'raw ''text'''),"
        "(%1, 0, 'netvfs/sftp/escapes', 's', '''a\\nb\\u00e9\\U0001F600\\x41'''),"
        "(%1, 0, 'netvfs/sftp/hex', 'i', '0x10'),"
        "(%1, 0, 'netvfs/sftp/annotated', 'x', 'int64 5'),"
        "(%1, 0, 'netvfs/sftp/badbool', 'b', 'yes'),"
        "(%1, 0, 'netvfs/sftp/null', 's', NULL),"
        "(%1, 0, 'netvfs/sftp/dict', 'a{sv}', '{''k'': <''v''>, ''n'': <int32 3>, ''l'': <[''x'']>}'),"
        "(%1, 0, 'netvfs/sftp/tuple', '(ss)', '(''a'', ''b'')'),"
        "(%1, 0, 'netvfs/sftp/variant', 'v', '<''x''>');"
        "UPDATE Accounts SET name = NULL WHERE id = %2;").arg(t, QString::number(guest))));

    QList<QStringList> requests { { QStringLiteral("list") } };
    for (const int id : { listed, unlisted, types, guest, bogus, signedSmb, legacy, legacyAllowed, sftp, noHost, emptyHost, off })
        requests << QStringList { QStringLiteral("files"), QString::number(id) };
    for (const QString &id : { QStringLiteral("999"), QStringLiteral("0"), QStringLiteral("-1"), QStringLiteral("x"),
                               QString(), QStringLiteral(" ") + t, QStringLiteral("+") + t, QStringLiteral("0") + t,
                               t + QStringLiteral("x"), t + QStringLiteral(" "), QStringLiteral("4294967296"),
                               QStringLiteral("0x1") }) {
        requests << QStringList { QStringLiteral("files"), id };
    }
    for (const QString &state : { QStringLiteral("none"), QString(), QStringLiteral("Auth-failed") })
        requests << QStringList { QStringLiteral("attention"), QString::number(listed), state };
    for (const int id : { unlisted, noHost, off, 999 }) {
        requests << QStringList { QStringLiteral("attention"), QString::number(id), QStringLiteral("auth-failed"),
                                  QStringLiteral("pin") };
    }
    requests << QStringList() << QStringList { QStringLiteral("list"), QString() }
             << QStringList { QStringLiteral("files") } << QStringList { QStringLiteral("LIST") };
    compareAnswers(requests);
}

void tst_BridgeAccounts::goldenStoredValues()
{
    // Each value as libaccounts-glib could find it in the database, as an
    // option, the port, the credentials, the attention state, the Files
    // root and the Files service's enabled flag.
    const QList<QPair<QString, QString>> values {
        { "s", "'x'" }, { "s", "\"it's\"" }, { "s", "' 7 '" }, { "s", "'-7'" }, { "s", "'+7'" }, { "s", "'7x'" },
        { "s", "'0x10'" }, { "s", "'010'" }, { "s", "'2147483648'" }, { "s", "'-2147483649'" },
        { "s", "'4294967295'" }, { "s", "'-1'" }, { "s", "'1e3'" }, { "s", "'7.0'" }, { "s", "''" },
        { "s", "'\\u3000 7\\u00a0'" }, { "s", "'\\u0663'" }, { "s", "'auth-failed'" },
        { "s", "'server-identity-changed'" }, { "s", "'true'" }, { "s", "'1'" }, { "s", "'/'" }, { "s", "' /a//b/ '" },
        { "s", "'a/../b'" }, { "s", "raw" }, { "s", "  'x'  " }, { "s", "@s 'x'" }, { "s", "string 'x'" },
        { "s", "'\\u00e4\\U0001F600'" }, { "s", "'\\u0000'" }, { "s", "'x" }, { "s", "''x''" },
        { "i", "7" }, { "i", "-2147483648" }, { "i", "2147483648" }, { "i", "0x7fffffff" }, { "i", "010" },
        { "i", "int32 7" }, { "i", "@i 7" }, { "i", " 7 " }, { "i", "+7" }, { "i", "x" }, { "i", "'7'" }, { "i", "1" },
        { "i", "0" }, { "u", "4294967295" }, { "u", "4294967296" }, { "u", "-1" }, { "u", "uint32 7" },
        { "x", "-9223372036854775808" }, { "x", "9223372036854775807" }, { "x", "4294967303" }, { "x", "int64 -1" },
        { "t", "18446744073709551615" }, { "t", "18446744073709551616" }, { "t", "uint64 7" },
        { "b", "true" }, { "b", "false" }, { "b", "True" }, { "b", "1" }, { "b", "boolean true" }, { "b", "'true'" },
        { "as", "['a']" }, { "as", "[]" }, { "as", "@as []" }, { "as", "['a', 'b']" }, { "as", "['7']" },
        { "as", "[' 7 ']" }, { "as", "['true']" }, { "as", "['1']" }, { "as", "['auth-failed']" }, { "as", "['/x/']" },
        { "a{sv}", "{'k': <'v'>}" }, { "a{sv}", "@a{sv} {}" }, { "a{sv}", "{'n': <int32 3>, 'l': <['x']>}" },
        { "y", "7" }, { "n", "7" }, { "q", "7" }, { "d", "7.5" }, { "o", "'/x'" }, { "g", "'s'" }, { "v", "<'x'>" },
        { "(ss)", "('a', 'b')" }, { "ai", "[1]" }, { "ms", "just 'x'" }, { "h", "1" },
    };
    const QString global = QStringLiteral("0");
    const QString files = QStringLiteral("(SELECT id FROM Services WHERE name = 'sftp-files')");
    QList<int> ids;
    for (const auto &[type, text] : values) {
        // One account with the value as its settings, one with it as the
        // Files service's flag.
        const int id = listedAccount(QStringLiteral("sftp"), globals(QStringLiteral("values.example")));
        const int flag = listedAccount(QStringLiteral("sftp"), globals(QStringLiteral("flag.example")));
        QVERIFY(id > 0 && flag > 0);
        ids << id;
        QString quoted = text;
        quoted.replace(QLatin1Char('\''), QStringLiteral("''"));
        const QString row = QStringLiteral("(%1, %2, '%3', '%4', '%5')");
        QStringList rows;
        for (const char *key : { "netvfs/sftp/v", "netvfs/port", "CredentialsId", "netvfs/attention" })
            rows << row.arg(QString::number(id), global, QLatin1String(key), type, quoted);
        rows << row.arg(QString::number(id), files, QStringLiteral("files_root"), type, quoted);
        rows << row.arg(QString::number(flag), files, QStringLiteral("enabled"), type, quoted);
        QVERIFY(sql(database(),
                    QStringLiteral("INSERT OR REPLACE INTO Settings (account, service, key, type, value) VALUES %1;")
                        .arg(rows.join(QLatin1Char(',')))));
    }
    QList<QStringList> requests { { QStringLiteral("list") } };
    for (const int id : ids)
        requests << QStringList { QStringLiteral("files"), QString::number(id) };
    compareAnswers(requests);
}

void tst_BridgeAccounts::goldenAttention()
{
    // The same request on two copies of the database: the same answer, and
    // the same settings afterwards, as libaccounts reads them.
    QVERIFY(fixture->setService(unlisted, QStringLiteral("sftp-files"), false));
    const int other = listedAccount(QStringLiteral("smb"), globals(QStringLiteral("nas.example")));
    QVERIFY(other > 0);
    QTemporaryDir copy;
    QVERIFY(copyDatabase(database(), copy.path() + QStringLiteral("/accounts.db")));
    const Environment rustDatabase { { QStringLiteral("ACCOUNTS"), copy.path() } };

    const QString id = QString::number(listed);
    const QList<QStringList> requests {
        { QStringLiteral("attention"), id, QStringLiteral("auth-failed") },
        { QStringLiteral("attention"), id, QStringLiteral("server-identity-changed"), QStringLiteral("SHA256:a'b\"c") },
        { QStringLiteral("attention"), id, QStringLiteral("auth-failed"), QString() },
        { QStringLiteral("attention"), id, QStringLiteral("server-identity-changed"),
          QStringLiteral("é\U0001F600\\\n") },
        { QStringLiteral("attention"), QString::number(other), QStringLiteral("server-identity-changed"),
          QStringLiteral("SHA256:smb") },
        { QStringLiteral("attention"), QString::number(unlisted), QStringLiteral("auth-failed") },
        { QStringLiteral("attention"), id, QStringLiteral("none") },
    };
    for (const QStringList &arguments : requests) {
        int exitCode = -1;
        const QByteArray rust = runHelper(arguments, rustDatabase, &exitCode);
        QCOMPARE(exitCode, 0);
        const QByteArray cpp = reference(arguments);
        QVERIFY2(rust == cpp, describe(arguments, rust, cpp).constData());
        for (const int account : { listed, unlisted, other })
            QCOMPARE(globalSettings(copy.path(), account), globalSettings(fixture->path(), account));
    }

    // A write the database refuses.
    const QString refuse = QStringLiteral(
        "CREATE TRIGGER refuse BEFORE INSERT ON Settings BEGIN SELECT RAISE(ABORT, 'refused'); END;");
    QVERIFY(sql(database(), refuse));
    QVERIFY(sql(copy.path() + QStringLiteral("/accounts.db"), refuse));
    const QStringList arguments { QStringLiteral("attention"), id, QStringLiteral("auth-failed") };
    const QByteArray rust = runHelper(arguments, rustDatabase);
    QCOMPARE(decodeStatus(rust).error(), Error::Internal);
    const QByteArray cpp = reference(arguments);
    QVERIFY2(rust == cpp, describe(arguments, rust, cpp).constData());
}

void tst_BridgeAccounts::attentionSignal()
{
    // libaccounts' writers announce a change on the session bus, from a
    // name of their own; a process that has the account loaded reads the
    // new settings from the signal (on the path of the global service, the
    // one such a manager of Files accounts listens to).
    Accounts::Manager watcher(QStringLiteral("netvfs-files"));
    Accounts::Account *account = watcher.account(static_cast<Accounts::AccountId>(listed));
    QVERIFY(account);
    account->selectService(Accounts::Service());
    QVERIFY(account->value(QStringLiteral("netvfs/attention")).toString().isEmpty());
    ownedNames.clear();
    QVERIFY(decodeStatus(runHelper({ QStringLiteral("attention"), QString::number(listed),
                                                     QStringLiteral("server-identity-changed"),
                                                     QStringLiteral("SHA256:it's") }))
                .ok());
    QTRY_COMPARE_WITH_TIMEOUT(account->value(QStringLiteral("netvfs/attention")).toString(),
                              QStringLiteral("server-identity-changed"), 10000);
    QCOMPARE(account->value(QStringLiteral("netvfs/sftp/host_key_seen")).toString(), QStringLiteral("SHA256:it's"));
    // A boolean, not the string "true" (QVariant's == would convert it).
    const QVariant needsUpdate = account->value(QStringLiteral("CredentialsNeedUpdate"));
    QCOMPARE(needsUpdate.userType(), int(QMetaType::Bool));
    QVERIFY(needsUpdate.toBool());
    QCOMPARE(account->value(QStringLiteral("CredentialsNeedUpdateFrom")).toString(), QStringLiteral("sftp-files"));
    // Sailfish OS's libaccounts-glib owns such a name to send from.
    const QRegularExpression name(QStringLiteral("^com\\.google\\.code\\.AccountsSSO\\.Accounts\\.uuid_[0-9a-f]{32}$"));
    QTRY_VERIFY_WITH_TIMEOUT(std::any_of(ownedNames.cbegin(), ownedNames.cend(),
                                         [&](const QString &n) { return name.match(n).hasMatch(); }),
                             5000);
}

void tst_BridgeAccounts::attentionWithoutBus()
{
    // The write stands when nobody can be told.
    int exitCode = -1;
    QByteArray errors;
    const QByteArray answer = runHelper({ QStringLiteral("attention"), QString::number(listed),
                                          QStringLiteral("auth-failed") },
                                        { { QStringLiteral("DBUS_SESSION_BUS_ADDRESS"),
                                            QStringLiteral("unix:path=/nonexistent/bus") } },
                                        &exitCode, &errors);
    QCOMPARE(exitCode, 0);
    QVERIFY(decodeStatus(answer).ok());
    QVERIFY2(errors.contains("cannot announce the change"), errors.constData());
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));
}

void tst_BridgeAccounts::helperLinks()
{
    // XB-2a: no Qt, GLib or libaccounts in the setgid helper.
    QProcess readelf;
    readelf.start(QStringLiteral("readelf"), { QStringLiteral("-d"), Helper });
    QVERIFY2(readelf.waitForFinished(10000), "readelf is needed");
    QCOMPARE(readelf.exitCode(), 0);
    QStringList needed;
    const QRegularExpression library(QStringLiteral("\\(NEEDED\\)\\s+Shared library: \\[([^]]+)\\]"));
    for (auto it = library.globalMatch(QString::fromLatin1(readelf.readAllStandardOutput())); it.hasNext();)
        needed << it.next().captured(1);
    needed.sort();
    QCOMPARE(needed, QStringList({ QStringLiteral("libc.so.6"), QStringLiteral("libgcc_s.so.1"),
                                   QStringLiteral("libsqlite3.so.0") }));
}

void tst_BridgeAccounts::helperWithClosedDescriptors()
{
    // The built helper, confined, started with stdin and stderr closed.
    QProcess helper;
    helper.start(QStringLiteral("/bin/sh"), { QStringLiteral("-c"), QStringLiteral("exec \"$0\" list 0<&- 2>&-"),
                                             Helper });
    QVERIFY(helper.waitForFinished(10000));
    QCOMPARE(helper.exitCode(), 0);
    QVector<AccountLocation> accounts;
    QVERIFY(decodeList(helper.readAllStandardOutput(), &accounts).ok());
    QCOMPARE(accounts.size(), 1);
}

QTEST_GUILESS_MAIN(tst_BridgeAccounts)
#include "tst_bridgeaccounts.moc"
