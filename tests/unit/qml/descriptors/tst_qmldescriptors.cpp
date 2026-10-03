// SPDX-License-Identifier: LGPL-2.1-or-later
// SPEC-v2 XA-5 provider descriptors (the shipped ones and the validator) and
// the XB-6 consent model behind "Apps using network locations".
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
#include <QtCore/QTemporaryDir>
#include <QtTest/QtTest>

#include <functional>

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

// A copy of `object` with `edit` applied to its first field.
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
} // namespace

class TestQmlDescriptors : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir consumersDir;
    QTemporaryDir configDir;

private slots:
    void initTestCase()
    {
        qputenv("NETVFS_PROVIDERS_DIR", DescriptorDir.toLocal8Bit());
        QVERIFY(Test::installEngineeringEnglish(this));
        QVERIFY(consumersDir.isValid() && configDir.isValid());
        qputenv("NETVFS_CONSUMERS_DIR", consumersDir.path().toLocal8Bit());
    }

    void shippedDescriptorsAreValid_data()
    {
        QTest::addColumn<QString>("provider");
        QTest::addColumn<QStringList>("offered");
        QTest::newRow("sftp") << "sftp" << QStringList({ QStringLiteral("backup"), QStringLiteral("files") });
        QTest::newRow("smb") << "smb" << QStringList({ QStringLiteral("backup"), QStringLiteral("files") });
        QTest::newRow("webdav") << "webdav" << QStringList({ QStringLiteral("files") });
        QTest::newRow("ftp") << "ftp" << QStringList({ QStringLiteral("files") });
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
        // The connection and the service settings every account UI relies on.
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
        QCOMPARE(descriptors.providers(), QStringList({ QStringLiteral("ftp"), QStringLiteral("sftp"),
                                                        QStringLiteral("smb"), QStringLiteral("webdav") }));
        QVERIFY(descriptors.descriptor(QStringLiteral("local")).isEmpty());   // not an account provider
        QVERIFY(descriptors.descriptor(QStringLiteral("../etc")).isEmpty());
        QCOMPARE(ProviderDescriptors::load(QStringLiteral("../sftp"), nullptr).error(), Error::InvalidName);
        QCOMPARE(ProviderDescriptors::load(QStringLiteral("nope"), nullptr).error(), Error::NotFound);
    }

    void textIdsAreUsed()
    {
        // Every known id is used by a shipped descriptor, and translated.
        QSet<QString> used;
        for (const QString &provider : { QStringLiteral("sftp"), QStringLiteral("smb"), QStringLiteral("webdav"),
                                         QStringLiteral("ftp") }) {
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
        // A switch with a bool default and a choice with a listed default are fine.
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
        QCOMPARE(values.value(QStringLiteral("allow_shell")), QVariant(false));
        QCOMPARE(values.value(QStringLiteral("auth_mode")).toString(), QStringLiteral("password"));
        QVERIFY(!values.contains(QStringLiteral("key_mode_hint")));   // notes carry no value
        QCOMPARE(d.secretKind(p, values), QStringLiteral("password"));
        QVERIFY(!d.isValid(p, values, services(true, true)));   // host and user missing

        values.insert(QStringLiteral("host"), QStringLiteral("[fe80::1]"));
        values.insert(QStringLiteral("username"), QStringLiteral(" alice "));
        QVERIFY(d.isValid(p, values, services(true, true)));
        values.insert(QStringLiteral("backups_path"), QStringLiteral("a/../b"));
        QVERIFY(!d.isValid(p, values, services(true, true)));
        QVERIFY(d.isValid(p, values, services(false, true)));   // not shown without backups
        QVERIFY(!d.problem(p, field(d.descriptor(p), QStringLiteral("backups_path")), values,
                           services(true, false)).isEmpty());
        QVERIFY(d.problem(p, field(d.descriptor(p), QStringLiteral("backups_path")), values,
                          services(false, true)).isEmpty());
        values.insert(QStringLiteral("backups_path"), QStringLiteral("Backups"));
        values.insert(QStringLiteral("port"), QString());   // optional
        QVERIFY(d.isValid(p, values, services(true, true)));
        values.insert(QStringLiteral("port"), QStringLiteral("99999"));
        QVERIFY(!d.isValid(p, values, services(true, true)));
        values.insert(QStringLiteral("port"), QStringLiteral("2222"));

        // Key modes and interactive sign-in.
        values.insert(QStringLiteral("auth_mode"), QStringLiteral("publickey"));
        values.insert(QStringLiteral("key_source"), QStringLiteral("import"));
        QCOMPARE(d.authMode(p, values).value(QStringLiteral("source")).toString(), QStringLiteral("import"));
        QCOMPARE(d.secretKind(p, values), QStringLiteral("key"));
        QVERIFY(d.isVisible(field(d.descriptor(p), QStringLiteral("key_mode_hint")), values, QStringList()));
        values.insert(QStringLiteral("auth_mode"), QStringLiteral("interactive"));
        values.insert(QStringLiteral("key_source"), QString());
        QCOMPARE(d.secretKind(p, values), QStringLiteral("none"));
        QVERIFY(!d.isVisible(field(d.descriptor(p), QStringLiteral("key_mode_hint")), values, QStringList()));

        QVariantMap pin;
        pin.insert(QStringLiteral("host_key"), QStringLiteral("ssh-ed25519 AAAA"));
        const NetVfs::ConnectionParams params = NetVfsUi::paramsFromVariant(d.makeParams(p, values, pin));
        QCOMPARE(params.provider, p);
        QCOMPARE(params.host, QStringLiteral("fe80::1"));
        QCOMPARE(params.port, 2222);
        QCOMPARE(params.username, QStringLiteral("alice"));
        QCOMPARE(params.option(QStringLiteral("auth_mode")), QStringLiteral("interactive"));
        QCOMPARE(params.option(QStringLiteral("host_key")), QStringLiteral("ssh-ed25519 AAAA"));
        QCOMPARE(params.options.value(QStringLiteral("allow_shell")), QVariant(false));
        // Connection keys, notes and service settings are not options.
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
        // Server mode: admin shares switch only without a share.
        QVERIFY(d.isVisible(field(d.descriptor(p), QStringLiteral("show_admin_shares")), values, QStringList()));
        values.insert(QStringLiteral("share"), QStringLiteral("a/b"));
        QVERIFY(!d.isValid(p, values, services(false, true)));
        values.insert(QStringLiteral("share"), QStringLiteral("backup"));
        QVERIFY(!d.isVisible(field(d.descriptor(p), QStringLiteral("show_admin_shares")), values, QStringList()));
        QVERIFY(NetVfsUi::paramsFromVariant(d.makeParams(p, values, QVariantMap()))
                .options.value(QStringLiteral("show_admin_shares")).isNull());
        QCOMPARE(d.secretKind(p, values), QStringLiteral("password"));

        // Guest: no user, no secret, explicit consent (XM-1, XA-7).
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
        QVERIFY(!guest.options.contains(QStringLiteral("auth_mode")));   // one auth mode only
        QCOMPARE(guest.option(QStringLiteral("security_profile")), QStringLiteral("guest"));
        QVERIFY(guest.flag(QStringLiteral("allow_insecure")));
        QVERIFY(!checkServicePolicy(guest, Service::Backup).ok());
        QVERIFY(checkServicePolicy(guest, Service::Files).ok());
        QVERIFY(secretOptional(guest));

        // Settings page view.
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

    void webdavForm()
    {
        ProviderDescriptors d;
        const QString p = QStringLiteral("webdav");
        QVariantMap values = d.initialValues(p);
        QCOMPARE(values.value(QStringLiteral("port")).toString(), QString());   // protocol default
        QCOMPARE(values.value(QStringLiteral("tls")).toString(), QStringLiteral("https"));
        QCOMPARE(values.value(QStringLiteral("base_path")).toString(), QStringLiteral("/"));
        values.insert(QStringLiteral("host"), QStringLiteral("cloud.example"));
        values.insert(QStringLiteral("username"), QStringLiteral("me"));
        QVERIFY(d.isValid(p, values, services(false, true)));
        values.insert(QStringLiteral("base_path"), QStringLiteral("dav"));
        QVERIFY(!d.isValid(p, values, services(false, true)));
        values.insert(QStringLiteral("base_path"), QStringLiteral("/remote.php/dav/files/me/"));
        values.insert(QStringLiteral("auth_mode"), QStringLiteral("token"));
        QCOMPARE(d.secretKind(p, values), QStringLiteral("token"));
        values.insert(QStringLiteral("tls"), QStringLiteral("http"));
        QVERIFY(!d.isValid(p, values, services(false, true)));   // consent needed
        values.insert(QStringLiteral("allow_insecure"), true);
        QVERIFY(d.isValid(p, values, services(false, true)));
        const NetVfs::ConnectionParams params = NetVfsUi::paramsFromVariant(d.makeParams(p, values, QVariantMap()));
        QCOMPARE(params.option(QStringLiteral("auth_mode")), QStringLiteral("token"));
        QCOMPARE(params.option(QStringLiteral("tls")), QStringLiteral("http"));
        QCOMPARE(params.option(QStringLiteral("base_path")), QStringLiteral("/remote.php/dav/files/me/"));
        QVERIFY(!params.options.contains(QStringLiteral("pin_trusted")));   // https only
        QCOMPARE(params.port, 0);
        QVERIFY(checkServicePolicy(params, Service::Files).ok());
    }

    void ftpForm()
    {
        ProviderDescriptors d;
        const QString p = QStringLiteral("ftp");
        QVariantMap values = d.initialValues(p);
        QCOMPARE(values.value(QStringLiteral("tls_mode")).toString(), QStringLiteral("explicit"));
        values.insert(QStringLiteral("host"), QStringLiteral("ftp.example"));
        values.insert(QStringLiteral("username"), QStringLiteral("me"));
        values.insert(QStringLiteral("pin_trusted"), true);
        QVERIFY(d.isValid(p, values, services(false, true)));
        NetVfs::ConnectionParams params = NetVfsUi::paramsFromVariant(d.makeParams(p, values, QVariantMap()));
        QVERIFY(params.flag(QStringLiteral("pin_trusted")));
        QVERIFY(!params.options.contains(QStringLiteral("allow_insecure")));
        values.insert(QStringLiteral("tls_mode"), QStringLiteral("none"));
        QVERIFY(!d.isValid(p, values, services(false, true)));
        values.insert(QStringLiteral("allow_insecure"), true);
        QVERIFY(d.isValid(p, values, services(false, true)));
        params = NetVfsUi::paramsFromVariant(d.makeParams(p, values, QVariantMap()));
        QVERIFY(!params.options.contains(QStringLiteral("pin_trusted")));
        QVERIFY(isInsecureConfiguration(params));
    }

    // XB-3 registrations as the page lists them (the store itself is tested with the bridge).
    void consumers()
    {
        writeFile(consumersDir.filePath(QStringLiteral("lautta.conf")),
                  "[Consumer]\nId=lautta\nDisplayName=Lautta\nExecutable=/usr/bin/harbour-lautta\n"
                  "DataDir=.local/share/org.netvfs/lautta\n");
        writeFile(consumersDir.filePath(QStringLiteral("aaa.conf")),
                  "[Consumer]\nId=aaa\nDisplayName=Aaa\nExecutable=/usr/bin/aaa\nDataDir=.local/share/aaa\n");
        writeFile(consumersDir.filePath(QStringLiteral("mismatch.conf")),
                  "[Consumer]\nId=other\nDisplayName=X\nExecutable=/usr/bin/x\nDataDir=x\n");
        writeFile(consumersDir.filePath(QStringLiteral("readme.txt")), "[Consumer]\nId=readme\n");
        QCOMPARE(ConsentStore::consumersDir(), consumersDir.path());
        const QVector<ConsumerInfo> list = ConsentStore::consumers();
        QCOMPARE(list.size(), 2);
        QCOMPARE(list.at(0).id, QStringLiteral("aaa"));
        QCOMPARE(list.at(1).displayName, QStringLiteral("Lautta"));
    }

    // ... and the model of the page "Apps using network locations".
    void consentModel()
    {
        const QString path = configDir.filePath(QStringLiteral("model/bridge.conf"));
        ConsentStore(path).setConsent(QStringLiteral("aaa"), Consent::Denied);
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
        const QHash<int, QByteArray> roles = model.roleNames();
        QCOMPARE(roles.value(NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::ConsumerId)), QByteArray("consumerId"));
        QCOMPARE(roles.value(NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::DisplayName)), QByteArray("displayName"));
        QCOMPARE(roles.value(NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::Consent)), QByteArray("consent"));
        QCOMPARE(model.data(model.index(1), NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::ConsumerId)).toString(), QStringLiteral("lautta"));
        QCOMPARE(model.data(model.index(1), Qt::DisplayRole).toString(), QStringLiteral("Lautta"));
        QCOMPARE(model.data(model.index(0), NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::DisplayName)).toString(), QStringLiteral("Aaa"));
        QCOMPARE(model.data(model.index(1), NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::Consent)).toString(), QStringLiteral("unknown"));
        QCOMPARE(model.data(model.index(0), NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::Consent)).toString(), QStringLiteral("denied"));
        QVERIFY(!model.data(model.index(5), NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::Consent)).isValid());
        QVERIFY(!model.data(model.index(0), Qt::DecorationRole).isValid());

        QSignalSpy changed(&model, &QAbstractItemModel::dataChanged);
        QVERIFY(model.grant(QStringLiteral("lautta")));
        QCOMPARE(changed.count(), 1);
        QCOMPARE(model.data(model.index(1), NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::Consent)).toString(), QStringLiteral("granted"));
        QCOMPARE(ConsentStore(path).consent(QStringLiteral("lautta")), Consent::Granted);   // the bridge's view
        QCOMPARE(model.consent(QStringLiteral("lautta")), QStringLiteral("granted"));
        QVERIFY(model.revoke(QStringLiteral("lautta")));
        QCOMPARE(ConsentStore(path).consent(QStringLiteral("lautta")), Consent::Denied);
        QCOMPARE(model.data(model.index(1), NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::Consent)).toString(), QStringLiteral("denied"));
        // Only registered consumers.
        QVERIFY(!model.grant(QStringLiteral("stranger")));
        QCOMPARE(ConsentStore(path).consent(QStringLiteral("stranger")), Consent::Unknown);
        QCOMPARE(changed.count(), 2);

        // Changes made elsewhere (the bridge's notification) show after reload().
        ConsentStore(path).setConsent(QStringLiteral("aaa"), Consent::Granted);
        model.reload();
        QCOMPARE(model.data(model.index(0), NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::Consent)).toString(), QStringLiteral("granted"));
        QSignalSpy countChanged(&model, &NetVfsUi::ConsentModel::countChanged);
        QFile::remove(consumersDir.filePath(QStringLiteral("aaa.conf")));
        model.reload();
        QCOMPARE(model.count(), 1);
        QCOMPARE(countChanged.count(), 1);

        // A consent file that cannot be written is reported.
        QTemporaryDir blocked;
        const QString dirAsFile = blocked.filePath(QStringLiteral("file"));
        writeFile(dirAsFile, "x");
        model.setStorePath(dirAsFile + QStringLiteral("/bridge.conf"));
        QVERIFY(!model.grant(QStringLiteral("lautta")));
        QCOMPARE(model.data(model.index(0), NetVfsUi::ConsentModel::roleId(NetVfsUi::ConsentModel::Role::Consent)).toString(), QStringLiteral("unknown"));
    }
};

QTEST_GUILESS_MAIN(TestQmlDescriptors)
#include "tst_qmldescriptors.moc"
