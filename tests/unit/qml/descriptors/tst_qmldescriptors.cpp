// SPDX-License-Identifier: LGPL-2.1-or-later
#include "accessmodel.h"
#include "accountsfixture.h"
#include "consentmodel.h"
#include "consentstore.h"
#include "netvfshelpers.h"
#include "providerdescriptors.h"
#include "servicepolicy.h"
#include "../qmltestutil.h"

#include <QtCore/QDir>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QSet>
#include <QtCore/QSettings>
#include <QtCore/QTemporaryDir>
#include <QtTest/QtTest>

#include <functional>
#include <memory>

using namespace NetVfs;
using NetVfsUi::ProviderDescriptors;

namespace {
const QString SourceDir = QStringLiteral(NETVFS_SOURCE_DIR);
const QString DescriptorDir = SourceDir + QStringLiteral("/accounts/descriptors");

QJsonObject readJson(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return QJsonObject();
    return QJsonDocument::fromJson(file.readAll()).object();
}

QJsonObject sftpJson()
{
    return readJson(DescriptorDir + QStringLiteral("/sftp.json"));
}

QJsonObject withFirstField(QJsonObject object, const std::function<void(QJsonObject *)> &edit)
{
    QJsonArray fields = object.value(QStringLiteral("fields")).toArray();
    QJsonObject field = fields.at(0).toObject();
    edit(&field);
    fields.replace(0, field);
    object.insert(QStringLiteral("fields"), fields);
    return object;
}

QVariantMap field(const QVariantMap &descriptor, const QString &key)
{
    for (const QVariant &item : descriptor.value(QStringLiteral("fields")).toList()) {
        if (item.toMap().value(QStringLiteral("key")).toString() == key)
            return item.toMap();
    }
    return QVariantMap();
}

QStringList services(bool backup, bool files)
{
    QStringList list;
    if (backup)
        list << QStringLiteral("backup");
    if (files)
        list << QStringLiteral("files");
    return list;
}

void writeFile(const QString &path, const QByteArray &content)
{
    QFile file(path);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write(content);
}
}

class TestQmlDescriptors : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir consumersDir;
    QTemporaryDir configDir;
    std::unique_ptr<Test::AccountsFixture> accounts;
    int firstAccount = 0;
    int secondAccount = 0;

    int filesAccount(const QString &host)
    {
        const int id = accounts->createAccount(
            QStringLiteral("sftp"), { { QStringLiteral("netvfs/host"), host },
                                      { QStringLiteral("netvfs/username"), QStringLiteral("alice") } });
        return id > 0 && accounts->setService(id, QStringLiteral("sftp-files"), true) ? id : 0;
    }

private slots:
    void initTestCase()
    {
        qputenv("NETVFS_PROVIDERS_DIR", DescriptorDir.toLocal8Bit());
        QVERIFY(Test::installEngineeringEnglish(this));
        QVERIFY(consumersDir.isValid() && configDir.isValid());
        qputenv("NETVFS_CONSUMERS_DIR", consumersDir.path().toLocal8Bit());
        accounts = std::make_unique<Test::AccountsFixture>(QStringList { QStringLiteral("sftp") });
        QVERIFY(accounts->isValid());
        firstAccount = filesAccount(QStringLiteral("a.example"));
        secondAccount = filesAccount(QStringLiteral("b.example"));
        QVERIFY(accounts->createAccount(QStringLiteral("sftp"), { { QStringLiteral("netvfs/host"), QStringLiteral("c.example") } }) > 0);
        QVERIFY(firstAccount > 0 && secondAccount > firstAccount);
    }

    void shippedDescriptorsAreValid_data()
    {
        QTest::addColumn<QString>("provider");
        QTest::addColumn<QStringList>("offered");
        QTest::newRow("sftp") << "sftp" << QStringList({ QStringLiteral("backup"), QStringLiteral("files") });
        QTest::newRow("smb") << "smb" << QStringList({ QStringLiteral("backup"), QStringLiteral("files") });
        QTest::newRow("webdav") << "webdav" << QStringList({ QStringLiteral("backup"), QStringLiteral("files") });
        QTest::newRow("ftps") << "ftps" << QStringList({ QStringLiteral("backup"), QStringLiteral("files") });
    }

    void shippedDescriptorsAreValid()
    {
        QFETCH(QString, provider);
        QFETCH(QStringList, offered);
        QVariantMap descriptor;
        const Result r = ProviderDescriptors::load(provider, &descriptor);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(descriptor.value(QStringLiteral("services")).toStringList(), offered);
        ProviderDescriptors descriptors;
        for (const QString &service : { QStringLiteral("backup"), QStringLiteral("files") })
            QCOMPARE(descriptors.offersService(provider, service), offered.contains(service));
        QVERIFY(!field(descriptor, QStringLiteral("host")).isEmpty());
        QVERIFY(!field(descriptor, QStringLiteral("port")).isEmpty());
        QVERIFY(!field(descriptor, QStringLiteral("username")).isEmpty());
        QCOMPARE(field(descriptor, QStringLiteral("files_root")).value(QStringLiteral("service")).toString(),
                 QStringLiteral("files"));
        QCOMPARE(!field(descriptor, QStringLiteral("backups_path")).isEmpty(), offered.contains(QStringLiteral("backup")));
    }

    void providersListed()
    {
        ProviderDescriptors descriptors;
        QCOMPARE(descriptors.providers(),
                 QStringList({ QStringLiteral("ftps"), QStringLiteral("sftp"), QStringLiteral("smb"),
                               QStringLiteral("webdav") }));
        QVERIFY(descriptors.descriptor(QStringLiteral("local")).isEmpty());
        QVERIFY(descriptors.descriptor(QStringLiteral("../etc")).isEmpty());
        QCOMPARE(ProviderDescriptors::load(QStringLiteral("../sftp"), nullptr).error(), Error::InvalidName);
        QCOMPARE(ProviderDescriptors::load(QStringLiteral("nope"), nullptr).error(), Error::NotFound);
    }

    void textIdsAreUsed()
    {
        QSet<QString> used;
        for (const QString &provider :
             { QStringLiteral("sftp"), QStringLiteral("smb"), QStringLiteral("webdav"), QStringLiteral("ftps") }) {
            QFile file(DescriptorDir + QLatin1Char('/') + provider + QStringLiteral(".json"));
            QVERIFY(file.open(QIODevice::ReadOnly));
            const QString text = QString::fromUtf8(file.readAll());
            for (const QString &id : ProviderDescriptors::knownTextIds()) {
                if (text.contains(QLatin1Char('"') + id + QLatin1Char('"')))
                    used.insert(id);
            }
        }
        const QStringList known = ProviderDescriptors::knownTextIds();
        QCOMPARE(used.size(), known.size());
        ProviderDescriptors descriptors;
        for (const QString &id : known)
            QVERIFY2(descriptors.text(id) != id && !descriptors.text(id).isEmpty(), qPrintable(id));
        QCOMPARE(descriptors.text(QString()), QString());
    }

    void validatorRejects_data()
    {
        QTest::addColumn<QJsonObject>("descriptor");
        QTest::addColumn<QString>("problem");
        const QJsonObject base = sftpJson();
        QVERIFY(!base.isEmpty());
        auto with = [&base](const QString &key, const QJsonValue &value) {
            QJsonObject copy = base;
            copy.insert(key, value);
            return copy;
        };
        auto without = [&base](const QString &key) {
            QJsonObject copy = base;
            copy.remove(key);
            return copy;
        };
        auto fieldWith = [&base](const QString &key, const QJsonValue &value) {
            return withFirstField(base, [key, value](QJsonObject *f) { f->insert(key, value); });
        };
        QTest::newRow("other provider") << with(QStringLiteral("provider"), QStringLiteral("smb")) << "provider";
        QTest::newRow("no port") << without(QStringLiteral("defaultPort")) << "defaultPort";
        QTest::newRow("port too big") << with(QStringLiteral("defaultPort"), 70000) << "defaultPort";
        QTest::newRow("negative port") << with(QStringLiteral("defaultPort"), -1) << "defaultPort";
        QTest::newRow("fractional port") << with(QStringLiteral("defaultPort"), 22.5) << "defaultPort";
        QTest::newRow("no services") << with(QStringLiteral("services"), QJsonArray()) << "no services";
        QTest::newRow("bad service") << with(QStringLiteral("services"), QJsonArray({ QStringLiteral("storage") }))
                                     << "bad service";
        QTest::newRow("duplicate service")
                << with(QStringLiteral("services"), QJsonArray({ QStringLiteral("files"), QStringLiteral("files") }))
                << "bad service";
        QTest::newRow("no auth modes") << with(QStringLiteral("authModes"), QJsonArray()) << "no auth modes";
        QJsonObject kerberos;
        kerberos.insert(QStringLiteral("id"), QStringLiteral("kerberos"));
        kerberos.insert(QStringLiteral("label"), QStringLiteral("settings-accounts-netvfs-me-password"));
        kerberos.insert(QStringLiteral("secret"), QStringLiteral("password"));
        QTest::newRow("bad auth mode") << with(QStringLiteral("authModes"), QJsonArray({ kerberos })) << "bad auth mode";
        QJsonObject secretless = kerberos;
        secretless.insert(QStringLiteral("id"), QStringLiteral("password"));
        secretless.insert(QStringLiteral("secret"), QStringLiteral("file"));
        QTest::newRow("bad secret") << with(QStringLiteral("authModes"), QJsonArray({ secretless })) << "secret kind";
        QJsonObject unlabelled = secretless;
        unlabelled.insert(QStringLiteral("secret"), QStringLiteral("password"));
        unlabelled.insert(QStringLiteral("label"), QStringLiteral("Password"));
        QTest::newRow("auth label") << with(QStringLiteral("authModes"), QJsonArray({ unlabelled })) << "label";
        QJsonObject source = unlabelled;
        source.insert(QStringLiteral("label"), QStringLiteral("settings-accounts-netvfs-me-password"));
        source.insert(QStringLiteral("source"), QStringLiteral("import"));
        QTest::newRow("source on password") << with(QStringLiteral("authModes"), QJsonArray({ source })) << "key source";
        QTest::newRow("no fields") << without(QStringLiteral("fields")) << "no fields";
        QTest::newRow("bad key") << fieldWith(QStringLiteral("key"), QStringLiteral("Host")) << "key";
        QTest::newRow("auth_mode key") << fieldWith(QStringLiteral("key"), QStringLiteral("auth_mode")) << "key";
        QTest::newRow("duplicate key") << fieldWith(QStringLiteral("key"), QStringLiteral("port")) << "duplicate";
        QTest::newRow("bad type") << fieldWith(QStringLiteral("type"), QStringLiteral("slider")) << "bad type";
        QTest::newRow("unknown label") << fieldWith(QStringLiteral("label"), QStringLiteral("Server")) << "label";
        QTest::newRow("unknown description") << fieldWith(QStringLiteral("description"), QStringLiteral("x"))
                                             << "description";
        QTest::newRow("unknown placeholder") << fieldWith(QStringLiteral("placeholder"), 3) << "placeholder";
        QTest::newRow("bad validation") << fieldWith(QStringLiteral("validation"), QStringLiteral("email"))
                                        << "validation";
        QTest::newRow("bad input") << fieldWith(QStringLiteral("input"), QStringLiteral("phone")) << "input";
        QTest::newRow("bad service field") << fieldWith(QStringLiteral("service"), QStringLiteral("storage"))
                                           << "bad service";
        QTest::newRow("connection key as service")
                << fieldWith(QStringLiteral("service"), QStringLiteral("files")) << "connection key";
        QTest::newRow("default type") << fieldWith(QStringLiteral("default"), true) << "default";
        QTest::newRow("choices on text") << fieldWith(QStringLiteral("choices"), QJsonArray()) << "choices";
        QTest::newRow("condition key") << fieldWith(QStringLiteral("visibleWhen"),
                                                    QJsonObject({ { QStringLiteral("nothing"), QJsonArray({ QStringLiteral("x") }) } }))
                                       << "unknown key";
        QTest::newRow("condition values") << fieldWith(QStringLiteral("visibleWhen"),
                                                       QJsonObject({ { QStringLiteral("port"), QStringLiteral("22") } }))
                                          << "non-empty list";
        QTest::newRow("condition type") << fieldWith(QStringLiteral("visibleWhen"), QStringLiteral("port")) << "object";
        QTest::newRow("no secret condition")
                << with(QStringLiteral("noSecretWhen"), QJsonObject({ { QStringLiteral("x"), QJsonArray({ QStringLiteral("y") }) } }))
                << "noSecretWhen";
        QJsonObject choice = withFirstField(base, [](QJsonObject *f) {
            f->insert(QStringLiteral("type"), QStringLiteral("choice"));
            f->insert(QStringLiteral("choices"), QJsonArray());
        });
        QTest::newRow("no choices") << choice << "no choices";
        QJsonObject badChoice = withFirstField(base, [](QJsonObject *f) {
            f->insert(QStringLiteral("type"), QStringLiteral("choice"));
            f->insert(QStringLiteral("choices"), QJsonArray({ QJsonObject({ { QStringLiteral("value"), QStringLiteral("a") },
                                                                            { QStringLiteral("label"), QStringLiteral("A") } }) }));
        });
        QTest::newRow("bad choice") << badChoice << "bad choice";
        QJsonObject badDefault = withFirstField(base, [](QJsonObject *f) {
            f->insert(QStringLiteral("type"), QStringLiteral("choice"));
            f->insert(QStringLiteral("default"), QStringLiteral("b"));
            f->insert(QStringLiteral("choices"), QJsonArray({ QJsonObject({ { QStringLiteral("value"), QStringLiteral("a") },
                                                                            { QStringLiteral("label"), QStringLiteral("settings-accounts-netvfs-la-server") } }) }));
        });
        QTest::newRow("default not a choice") << badDefault << "not a choice";
    }

    void validatorRejects()
    {
        QFETCH(QJsonObject, descriptor);
        QFETCH(QString, problem);
        const Result r = ProviderDescriptors::validate(descriptor, QStringLiteral("sftp"));
        QVERIFY(!r.ok());
        QCOMPARE(r.error(), Error::Internal);
        QVERIFY2(r.message().contains(problem), qPrintable(r.message()));
    }

    void validatorAccepts()
    {
        QVERIFY(ProviderDescriptors::validate(sftpJson(), QStringLiteral("sftp")).ok());
        QJsonObject choice = withFirstField(sftpJson(), [](QJsonObject *f) {
            f->insert(QStringLiteral("type"), QStringLiteral("choice"));
            f->insert(QStringLiteral("default"), QStringLiteral("a"));
            f->insert(QStringLiteral("choices"), QJsonArray({ QJsonObject({ { QStringLiteral("value"), QStringLiteral("a") },
                                                                            { QStringLiteral("label"), QStringLiteral("settings-accounts-netvfs-la-server") } }) }));
        });
        QVERIFY(ProviderDescriptors::validate(choice, QStringLiteral("sftp")).ok());
    }

    void brokenFiles()
    {
        QTemporaryDir dir;
        writeFile(dir.filePath(QStringLiteral("broken.json")), "{ not json");
        writeFile(dir.filePath(QStringLiteral("array.json")), "[]");
        QFile::copy(DescriptorDir + QStringLiteral("/smb.json"), dir.filePath(QStringLiteral("smb.json")));
        qputenv("NETVFS_PROVIDERS_DIR", dir.path().toLocal8Bit());
        QCOMPARE(ProviderDescriptors::directory(), dir.path());
        QCOMPARE(ProviderDescriptors::load(QStringLiteral("broken"), nullptr).error(), Error::Internal);
        QCOMPARE(ProviderDescriptors::load(QStringLiteral("array"), nullptr).error(), Error::Internal);
        ProviderDescriptors descriptors;
        QCOMPARE(descriptors.providers(), QStringList({ QStringLiteral("smb") }));
        QVERIFY(descriptors.descriptor(QStringLiteral("broken")).isEmpty());
        QVERIFY(!descriptors.isValid(QStringLiteral("broken"), QVariantMap(), services(false, true)));
        qputenv("NETVFS_PROVIDERS_DIR", DescriptorDir.toLocal8Bit());
        qunsetenv("NETVFS_PROVIDERS_DIR");
        QCOMPARE(ProviderDescriptors::directory(), QStringLiteral("/usr/share/netvfs/providers"));
        qputenv("NETVFS_PROVIDERS_DIR", DescriptorDir.toLocal8Bit());
    }

    void sftpForm()
    {
        ProviderDescriptors d;
        const QString p = QStringLiteral("sftp");
        QVariantMap values = d.initialValues(p);
        QCOMPARE(values.value(QStringLiteral("port")).toString(), QStringLiteral("22"));
        QCOMPARE(values.value(QStringLiteral("backups_path")).toString(), QStringLiteral("Sailfish OS/Backups"));
        QCOMPARE(values.value(QStringLiteral("auth_mode")).toString(), QStringLiteral("password"));
        QVERIFY(!values.contains(QStringLiteral("key_mode_hint")));
        QCOMPARE(d.secretKind(p, values), QStringLiteral("password"));
        QVERIFY(!d.isValid(p, values, services(true, true)));

        values.insert(QStringLiteral("host"), QStringLiteral("[fe80::1]"));
        values.insert(QStringLiteral("username"), QStringLiteral(" alice "));
        QVERIFY(d.isValid(p, values, services(true, true)));
        values.insert(QStringLiteral("backups_path"), QStringLiteral("a/../b"));
        QVERIFY(!d.isValid(p, values, services(true, true)));
        QVERIFY(d.isValid(p, values, services(false, true)));
        QVERIFY(!d.problem(p, field(d.descriptor(p), QStringLiteral("backups_path")), values,
                           services(true, false)).isEmpty());
        QVERIFY(d.problem(p, field(d.descriptor(p), QStringLiteral("backups_path")), values,
                          services(false, true)).isEmpty());
        values.insert(QStringLiteral("backups_path"), QStringLiteral("Backups"));
        values.insert(QStringLiteral("port"), QString());
        QVERIFY(d.isValid(p, values, services(true, true)));
        values.insert(QStringLiteral("port"), QStringLiteral("99999"));
        QVERIFY(!d.isValid(p, values, services(true, true)));
        values.insert(QStringLiteral("port"), QStringLiteral("2222"));

        values.insert(QStringLiteral("auth_mode"), QStringLiteral("publickey"));
        values.insert(QStringLiteral("key_source"), QStringLiteral("import"));
        QCOMPARE(d.authMode(p, values).value(QStringLiteral("source")).toString(), QStringLiteral("import"));
        QCOMPARE(d.secretKind(p, values), QStringLiteral("key"));
        QVERIFY(d.isVisible(field(d.descriptor(p), QStringLiteral("key_mode_hint")), values, QStringList()));
        values.insert(QStringLiteral("auth_mode"), QStringLiteral("password"));
        values.insert(QStringLiteral("key_source"), QString());
        QCOMPARE(d.secretKind(p, values), QStringLiteral("password"));
        QVERIFY(!d.isVisible(field(d.descriptor(p), QStringLiteral("key_mode_hint")), values, QStringList()));

        QVariantMap pin;
        pin.insert(QStringLiteral("host_key"), QStringLiteral("ssh-ed25519 AAAA"));
        const NetVfs::ConnectionParams params = NetVfsUi::paramsFromVariant(d.makeParams(p, values, pin));
        QCOMPARE(params.provider, p);
        QCOMPARE(params.host, QStringLiteral("fe80::1"));
        QCOMPARE(params.port, 2222);
        QCOMPARE(params.username, QStringLiteral("alice"));
        QCOMPARE(params.option(QStringLiteral("auth_mode")), QStringLiteral("password"));
        QCOMPARE(params.option(QStringLiteral("host_key")), QStringLiteral("ssh-ed25519 AAAA"));
        QCOMPARE(params.options.keys(), QStringList({ QStringLiteral("auth_mode"), QStringLiteral("host_key") }));
        for (const QString &key : { QStringLiteral("host"), QStringLiteral("port"), QStringLiteral("username"),
                                    QStringLiteral("key_mode_hint"), QStringLiteral("backups_path"),
                                    QStringLiteral("files_root"), QStringLiteral("key_source") })
            QVERIFY2(!params.options.contains(key), qPrintable(key));
        QCOMPARE(d.serviceValue(p, values, QStringLiteral("backups_path")), QStringLiteral("Backups"));
    }

    void smbForm()
    {
        ProviderDescriptors d;
        const QString p = QStringLiteral("smb");
        QVariantMap values = d.initialValues(p);
        QCOMPARE(values.value(QStringLiteral("security_profile")).toString(), QStringLiteral("strict"));
        values.insert(QStringLiteral("host"), QStringLiteral("nas"));
        values.insert(QStringLiteral("username"), QStringLiteral("bob"));
        QVERIFY(d.isValid(p, values, services(true, true)));
        QVERIFY(d.isVisible(field(d.descriptor(p), QStringLiteral("show_admin_shares")), values, QStringList()));
        values.insert(QStringLiteral("share"), QStringLiteral("a/b"));
        QVERIFY(!d.isValid(p, values, services(false, true)));
        values.insert(QStringLiteral("share"), QStringLiteral("backup"));
        QVERIFY(!d.isVisible(field(d.descriptor(p), QStringLiteral("show_admin_shares")), values, QStringList()));
        QVERIFY(NetVfsUi::paramsFromVariant(d.makeParams(p, values, QVariantMap()))
                .options.value(QStringLiteral("show_admin_shares")).isNull());
        QCOMPARE(d.secretKind(p, values), QStringLiteral("password"));

        values.insert(QStringLiteral("security_profile"), QStringLiteral("guest"));
        QCOMPARE(d.secretKind(p, values), QStringLiteral("none"));
        QVERIFY(!d.isValid(p, values, services(false, true)));
        QCOMPARE(d.problem(p, field(d.descriptor(p), QStringLiteral("allow_insecure")), values, QStringList()),
                 QStringLiteral("Confirm that you accept the risk to continue."));
        values.insert(QStringLiteral("allow_insecure"), true);
        QVERIFY(d.isValid(p, values, services(false, true)));
        const QVariantMap params = d.makeParams(p, values, QVariantMap());
        const NetVfs::ConnectionParams guest = NetVfsUi::paramsFromVariant(params);
        QVERIFY(guest.username.isEmpty());
        QVERIFY(!guest.options.contains(QStringLiteral("domain")));
        QVERIFY(!guest.options.contains(QStringLiteral("auth_mode")));
        QCOMPARE(guest.option(QStringLiteral("security_profile")), QStringLiteral("guest"));
        QVERIFY(guest.flag(QStringLiteral("allow_insecure")));
        QVERIFY(!checkServicePolicy(guest, Service::Backup).ok());
        QVERIFY(checkServicePolicy(guest, Service::Files).ok());
        QVERIFY(secretOptional(guest));

        const QVariantList details = d.details(p, params);
        QStringList labels;
        QStringList shown;
        for (const QVariant &row : details) {
            labels << row.toMap().value(QStringLiteral("label")).toString();
            shown << row.toMap().value(QStringLiteral("value")).toString();
        }
        QVERIFY(labels.contains(QStringLiteral("Connection security")));
        QVERIFY(shown.contains(QStringLiteral("Guest, without signing in")));
        QVERIFY(shown.contains(QStringLiteral("Yes")));
        QVERIFY(shown.contains(QStringLiteral("nas")));
        QVERIFY(!labels.contains(QStringLiteral("User name")));
    }

    void consumers()
    {
        writeFile(consumersDir.filePath(QStringLiteral("lautta.conf")),
                  "[Consumer]\nId=lautta\nDisplayName=Lautta\nExecutable=/usr/bin/harbour-lautta\n"
                  "DataDir=.local/share/org.netvfs/lautta\nAccess=read-add\n");
        writeFile(consumersDir.filePath(QStringLiteral("aaa.conf")),
                  "[Consumer]\nId=aaa\nDisplayName=Aaa\nExecutable=/usr/bin/aaa\nDataDir=.local/share/aaa\n"
                  "Access=everything\n");
        writeFile(consumersDir.filePath(QStringLiteral("mismatch.conf")),
                  "[Consumer]\nId=other\nDisplayName=X\nExecutable=/usr/bin/x\nDataDir=x\n");
        writeFile(consumersDir.filePath(QStringLiteral("readme.txt")), "[Consumer]\nId=readme\n");
        QCOMPARE(ConsentStore::consumersDir(), consumersDir.path());
        const QVector<ConsumerInfo> list = ConsentStore::consumers();
        QCOMPARE(list.size(), 2);
        QCOMPARE(list.at(0).id, QStringLiteral("aaa"));
        QCOMPARE(list.at(0).access, QStringLiteral("read"));
        QCOMPARE(list.at(1).displayName, QStringLiteral("Lautta"));
        QCOMPARE(list.at(1).access, QStringLiteral("read-add"));
    }

    void accessLevels()
    {
        for (const char *word : { "full", "read-add", "read", "add" })
            QVERIFY2(isAccessLevel(QLatin1String(word)), word);
        for (const char *word : { "", "denied", "ask", "granted", "Read", "read-write" })
            QVERIFY2(!isAccessLevel(QLatin1String(word)), word);
    }

    void consentStore()
    {
        const QString path = configDir.filePath(QStringLiteral("store/bridge.conf"));
        const ConsentStore store(path);
        QVERIFY(!store.consent(QStringLiteral("lautta")).isDecided());
        QVERIFY(QDir().mkpath(QFileInfo(path).absolutePath()));
        writeFile(path,
                  "[Consent]\nlautta=granted\naaa=ask\nbbb=sometimes\n"
                  "[Access]\nlautta\\1=read\nlautta\\07=full\nlautta\\2=bogus\nlautta\\-3=read\nlautta\\x=read\n"
                  "lautta\\4=denied\naaa\\1=add\nlautta\\5\\6=read\n");
        AppConsent lautta = store.consent(QStringLiteral("lautta"));
        QCOMPARE(lautta.newAccounts, QStringLiteral("full"));
        QCOMPARE(lautta.accounts, (QMap<int, QString> { { 1, QStringLiteral("read") }, { 4, QStringLiteral("denied") } }));
        QCOMPARE(lautta.choice(1), QStringLiteral("read"));
        QCOMPARE(lautta.choice(4), QStringLiteral("denied"));
        QCOMPARE(lautta.choice(9), QStringLiteral("full"));
        const AppConsent aaa = store.consent(QStringLiteral("aaa"));
        QVERIFY(aaa.isDecided());
        QCOMPARE(aaa.choice(1), QStringLiteral("add"));
        QCOMPARE(aaa.choice(2), QString());
        QVERIFY(!store.consent(QStringLiteral("bbb")).isDecided());
        QVERIFY(!store.consent(QStringLiteral("../x")).isDecided());
        QVERIFY(store.consent(QStringLiteral("../x")).accounts.isEmpty());

        lautta.newAccounts = QStringLiteral("denied");
        lautta.accounts = { { 2, QStringLiteral("read-add") }, { 0, QStringLiteral("full") }, { 3, QStringLiteral("ask") } };
        QVERIFY(store.setConsent(QStringLiteral("lautta"), lautta));
        const AppConsent stored = store.consent(QStringLiteral("lautta"));
        QCOMPARE(stored.newAccounts, QStringLiteral("denied"));
        QCOMPARE(stored.accounts, (QMap<int, QString> { { 2, QStringLiteral("read-add") } }));
        QCOMPARE(stored.choice(1), QStringLiteral("denied"));
        QCOMPARE(store.consent(QStringLiteral("aaa")), aaa);
        QSettings raw(path, QSettings::IniFormat);
        QCOMPARE(raw.value(QStringLiteral("Access/lautta/2")).toString(), QStringLiteral("read-add"));
        QVERIFY(!raw.contains(QStringLiteral("Access/lautta/07")));

        QVERIFY(store.setConsent(QStringLiteral("lautta"), AppConsent()));
        QSettings after(path, QSettings::IniFormat);
        QVERIFY(!after.contains(QStringLiteral("Consent/lautta")));
        QVERIFY(after.contains(QStringLiteral("Consent/aaa")));
        QCOMPARE(store.consent(QStringLiteral("lautta")), AppConsent());
        QVERIFY(!store.setConsent(QStringLiteral("../x"), aaa));

        QTemporaryDir blocked;
        const QString dirAsFile = blocked.filePath(QStringLiteral("file"));
        writeFile(dirAsFile, "x");
        QVERIFY(!ConsentStore(dirAsFile + QStringLiteral("/bridge.conf")).setConsent(QStringLiteral("lautta"), aaa));
    }

    void pending()
    {
        const QVector<NetVfsUi::FilesAccount> accounts { { 1, QString() }, { 2, QString() } };
        AppConsent consent;
        QVERIFY(NetVfsUi::isPending(consent, {}));
        consent.newAccounts = QStringLiteral("ask");
        QVERIFY(!NetVfsUi::isPending(consent, {}));
        QVERIFY(NetVfsUi::isPending(consent, accounts));
        consent.accounts = { { 1, QStringLiteral("read") }, { 2, QStringLiteral("denied") } };
        QVERIFY(!NetVfsUi::isPending(consent, accounts));
        consent.accounts.remove(2);
        QVERIFY(NetVfsUi::isPending(consent, accounts));
        consent.newAccounts = QStringLiteral("denied");
        QVERIFY(!NetVfsUi::isPending(consent, accounts));
    }

    void filesAccounts()
    {
        const QVector<NetVfsUi::FilesAccount> accounts = NetVfsUi::filesAccounts();
        QCOMPARE(accounts.size(), 2);
        QCOMPARE(accounts.at(0).id, firstAccount);
        QCOMPARE(accounts.at(0).name, QStringLiteral("alice@a.example"));
        QCOMPARE(accounts.at(1).id, secondAccount);
    }

    void icons()
    {
        QTemporaryDir icons;
        QVERIFY(QDir(icons.path()).mkpath(QStringLiteral("86x86/apps")));
        QVERIFY(QDir(icons.path()).mkpath(QStringLiteral("128x128/apps")));
        writeFile(icons.filePath(QStringLiteral("86x86/apps/harbour-lautta.png")), "png");
        QCOMPARE(NetVfsUi::ConsentModel::iconOf(QStringLiteral("/usr/bin/harbour-lautta"), icons.path()),
                 icons.filePath(QStringLiteral("86x86/apps/harbour-lautta.png")));
        writeFile(icons.filePath(QStringLiteral("128x128/apps/harbour-lautta.png")), "png");
        QCOMPARE(NetVfsUi::ConsentModel::iconOf(QStringLiteral("/usr/bin/harbour-lautta"), icons.path()),
                 icons.filePath(QStringLiteral("128x128/apps/harbour-lautta.png")));
        QCOMPARE(NetVfsUi::ConsentModel::iconOf(QStringLiteral("/usr/bin/other"), icons.path()), QString());
        QVERIFY(QDir(icons.path()).mkpath(QStringLiteral("86x86/apps/.png")));
        QCOMPARE(NetVfsUi::ConsentModel::iconOf(QStringLiteral("/usr/bin/"), icons.path()), QString());
    }

    void consentModel()
    {
        const QString path = configDir.filePath(QStringLiteral("model/bridge.conf"));
        AppConsent decided;
        decided.newAccounts = QStringLiteral("ask");
        decided.accounts = { { firstAccount, QStringLiteral("read") }, { secondAccount, QStringLiteral("denied") } };
        QVERIFY(ConsentStore(path).setConsent(QStringLiteral("aaa"), decided));
        NetVfsUi::ConsentModel defaults;
        QVERIFY(defaults.storePath().isEmpty());
        QCOMPARE(defaults.count(), 2);
        NetVfsUi::ConsentModel model;
        QSignalSpy pathChanged(&model, &NetVfsUi::ConsentModel::storePathChanged);
        model.setStorePath(path);
        model.setStorePath(path);
        QCOMPARE(pathChanged.count(), 1);
        QCOMPARE(model.storePath(), path);
        QCOMPARE(model.rowCount(), 2);
        QCOMPARE(model.count(), 2);
        QCOMPARE(model.rowCount(model.index(0)), 0);
        using Role = NetVfsUi::ConsentModel::Role;
        const auto role = [](Role r) { return NetVfsUi::ConsentModel::roleId(r); };
        const QHash<int, QByteArray> roles = model.roleNames();
        QCOMPARE(roles.value(role(Role::ConsumerId)), QByteArray("consumerId"));
        QCOMPARE(roles.value(role(Role::DisplayName)), QByteArray("displayName"));
        QCOMPARE(roles.value(role(Role::Icon)), QByteArray("icon"));
        QCOMPARE(roles.value(role(Role::Pending)), QByteArray("pending"));
        QCOMPARE(model.data(model.index(1), role(Role::ConsumerId)).toString(), QStringLiteral("lautta"));
        QCOMPARE(model.data(model.index(1), Qt::DisplayRole).toString(), QStringLiteral("Lautta"));
        QCOMPARE(model.data(model.index(0), role(Role::DisplayName)).toString(), QStringLiteral("Aaa"));
        QCOMPARE(model.data(model.index(0), role(Role::Icon)).toString(), QString());
        QCOMPARE(model.data(model.index(0), role(Role::Pending)).toBool(), false);
        QCOMPARE(model.data(model.index(1), role(Role::Pending)).toBool(), true);
        QVERIFY(!model.data(model.index(5), role(Role::Pending)).isValid());
        QVERIFY(!model.data(model.index(0), Qt::DecorationRole).isValid());
        QCOMPARE(model.firstPending(), QStringLiteral("lautta"));

        QVERIFY(ConsentStore(path).setConsent(QStringLiteral("lautta"), decided));
        model.reload();
        QCOMPARE(model.firstPending(), QString());
        decided.accounts.remove(secondAccount);
        QVERIFY(ConsentStore(path).setConsent(QStringLiteral("aaa"), decided));
        model.reload();
        QCOMPARE(model.firstPending(), QStringLiteral("aaa"));
        QSignalSpy countChanged(&model, &NetVfsUi::ConsentModel::countChanged);
        QFile::rename(consumersDir.filePath(QStringLiteral("aaa.conf")), consumersDir.filePath(QStringLiteral("aaa.off")));
        model.reload();
        QCOMPARE(model.count(), 1);
        QCOMPARE(countChanged.count(), 1);
        QCOMPARE(model.firstPending(), QString());
        model.reload();
        QCOMPARE(countChanged.count(), 1);
        QFile::rename(consumersDir.filePath(QStringLiteral("aaa.off")), consumersDir.filePath(QStringLiteral("aaa.conf")));
    }

    void accessModel()
    {
        const QString path = configDir.filePath(QStringLiteral("access/bridge.conf"));
        using Role = NetVfsUi::AccessModel::Role;
        const auto role = [](Role r) { return NetVfsUi::AccessModel::roleId(r); };
        NetVfsUi::AccessModel model;
        QVERIFY(model.autoSave());
        QSignalSpy changed(&model, &NetVfsUi::AccessModel::changed);
        model.setStorePath(path);
        model.setConsumerId(QStringLiteral("lautta"));
        QCOMPARE(model.consumerId(), QStringLiteral("lautta"));
        QCOMPARE(model.storePath(), path);
        QCOMPARE(model.displayName(), QStringLiteral("Lautta"));
        QCOMPARE(model.asked(), QStringLiteral("read-add"));
        QVERIFY(!model.decided());
        QCOMPARE(model.newAccounts(), QStringLiteral("ask"));
        QVERIFY(changed.count() > 0);
        const QHash<int, QByteArray> roles = model.roleNames();
        QCOMPARE(roles.value(role(Role::AccountId)), QByteArray("accountId"));
        QCOMPARE(roles.value(role(Role::Name)), QByteArray("name"));
        QCOMPARE(roles.value(role(Role::Choice)), QByteArray("choice"));
        QCOMPARE(model.count(), 2);
        QCOMPARE(model.rowCount(model.index(0)), 0);
        QCOMPARE(model.data(model.index(0), role(Role::AccountId)).toInt(), firstAccount);
        QCOMPARE(model.data(model.index(0), role(Role::Name)).toString(), QStringLiteral("alice@a.example"));
        QCOMPARE(model.data(model.index(1), Qt::DisplayRole).toString(), QStringLiteral("alice@b.example"));
        QCOMPARE(model.data(model.index(0), role(Role::Choice)).toString(), QStringLiteral("denied"));
        QCOMPARE(model.data(model.index(1), role(Role::Choice)).toString(), QStringLiteral("denied"));
        QVERIFY(!model.data(model.index(2), role(Role::Choice)).isValid());
        QVERIFY(!model.data(model.index(0), Qt::DecorationRole).isValid());
        QVERIFY(!QFile::exists(path));

        QSignalSpy dataChanged(&model, &QAbstractItemModel::dataChanged);
        QVERIFY(model.setChoice(secondAccount, QStringLiteral("add")));
        QCOMPARE(dataChanged.count(), 1);
        QCOMPARE(dataChanged.at(0).at(0).value<QModelIndex>().row(), 1);
        QCOMPARE(model.data(model.index(1), role(Role::Choice)).toString(), QStringLiteral("add"));
        QVERIFY(model.decided());
        AppConsent stored = ConsentStore(path).consent(QStringLiteral("lautta"));
        QCOMPARE(stored.newAccounts, QStringLiteral("ask"));
        QCOMPARE(stored.accounts, (QMap<int, QString> { { firstAccount, QStringLiteral("denied") },
                                                        { secondAccount, QStringLiteral("add") } }));
        QVERIFY(!model.setChoice(secondAccount, QStringLiteral("ask")));
        QVERIFY(!model.setChoice(secondAccount, QStringLiteral("granted")));
        QVERIFY(!model.setChoice(99, QStringLiteral("read")));
        QCOMPARE(dataChanged.count(), 1);
        QVERIFY(model.setNewAccounts(QStringLiteral("read")));
        QCOMPARE(model.newAccounts(), QStringLiteral("read"));
        QCOMPARE(ConsentStore(path).consent(QStringLiteral("lautta")).newAccounts, QStringLiteral("read"));
        QVERIFY(!model.setNewAccounts(QStringLiteral("granted")));
        QCOMPARE(model.newAccounts(), QStringLiteral("read"));
        model.reload();
        QVERIFY(model.decided());
        QCOMPARE(model.count(), 2);
        QCOMPARE(model.data(model.index(1), role(Role::Choice)).toString(), QStringLiteral("add"));

        NetVfsUi::AccessModel request;
        request.setAutoSave(false);
        request.setStorePath(path);
        request.setRequest(true);
        QVERIFY(request.request());
        request.setConsumerId(QStringLiteral("lautta"));
        QVERIFY(request.decided());
        QCOMPARE(request.count(), 0);
        QVERIFY(ConsentStore(path).setConsent(QStringLiteral("aaa"), AppConsent()));
        request.setConsumerId(QStringLiteral("aaa"));
        QVERIFY(!request.decided());
        QCOMPARE(request.count(), 2);
        QCOMPARE(request.asked(), QStringLiteral("read"));
        QVERIFY(request.setChoice(firstAccount, QStringLiteral("full")));
        QVERIFY(request.setNewAccounts(QStringLiteral("denied")));
        QVERIFY(!ConsentStore(path).consent(QStringLiteral("aaa")).isDecided());
        QVERIFY(request.save());
        QVERIFY(request.decided());
        stored = ConsentStore(path).consent(QStringLiteral("aaa"));
        QCOMPARE(stored.newAccounts, QStringLiteral("denied"));
        QCOMPARE(stored.accounts, (QMap<int, QString> { { firstAccount, QStringLiteral("full") },
                                                        { secondAccount, QStringLiteral("denied") } }));

        stored.newAccounts = QStringLiteral("ask");
        stored.accounts = { { firstAccount, QStringLiteral("full") }, { 77, QStringLiteral("read") } };
        QVERIFY(ConsentStore(path).setConsent(QStringLiteral("aaa"), stored));
        request.reload();
        QVERIFY(request.decided());
        QCOMPARE(request.count(), 1);
        QCOMPARE(request.data(request.index(0), role(Role::AccountId)).toInt(), secondAccount);
        QCOMPARE(request.data(request.index(0), role(Role::Choice)).toString(), QStringLiteral("denied"));
        QVERIFY(!request.setChoice(firstAccount, QStringLiteral("read")));
        QVERIFY(request.setChoice(secondAccount, QStringLiteral("read-add")));
        QVERIFY(request.save());
        stored = ConsentStore(path).consent(QStringLiteral("aaa"));
        QCOMPARE(stored.newAccounts, QStringLiteral("ask"));
        QCOMPARE(stored.accounts, (QMap<int, QString> { { firstAccount, QStringLiteral("full") },
                                                        { secondAccount, QStringLiteral("read-add") },
                                                        { 77, QStringLiteral("read") } }));

        NetVfsUi::AccessModel unknown;
        unknown.setStorePath(path);
        unknown.setConsumerId(QStringLiteral("stranger"));
        QCOMPARE(unknown.displayName(), QString());
        QCOMPARE(unknown.asked(), QStringLiteral("read"));
        unknown.setConsumerId(QStringLiteral("../x"));
        QVERIFY(!unknown.setChoice(firstAccount, QStringLiteral("read")));
        QVERIFY(!unknown.save());

        QTemporaryDir blocked;
        const QString dirAsFile = blocked.filePath(QStringLiteral("file"));
        writeFile(dirAsFile, "x");
        NetVfsUi::AccessModel failing;
        failing.setStorePath(dirAsFile + QStringLiteral("/bridge.conf"));
        failing.setConsumerId(QStringLiteral("lautta"));
        QVERIFY(!failing.setChoice(firstAccount, QStringLiteral("read")));
        QVERIFY(!failing.decided());
        QVERIFY(!failing.setNewAccounts(QStringLiteral("read")));
    }
};

QTEST_GUILESS_MAIN(TestQmlDescriptors)
#include "tst_qmldescriptors.moc"
