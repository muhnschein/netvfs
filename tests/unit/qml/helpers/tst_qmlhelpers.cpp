// SPDX-License-Identifier: LGPL-2.1-or-later
#include "errortexts.h"
#include "netvfshelpers.h"
#include "../qmltestutil.h"

#include <QtCore/QSet>
#include <QtTest/QtTest>

using namespace NetVfs;
using NetVfsUi::Helpers;

namespace {
QVariantMap sftpParams()
{
    QVariantMap options;
    options.insert(QStringLiteral("auth_mode"), QStringLiteral("publickey"));
    options.insert(QStringLiteral("host_key"), QStringLiteral("ssh-ed25519 AAAA"));
    options.insert(QStringLiteral("public_key"), QStringLiteral("ssh-ed25519 BBBB sailfish-backup"));
    options.insert(QStringLiteral("host_key_seen"), QStringLiteral("ssh-ed25519 CCCC"));
    QVariantMap params;
    params.insert(QStringLiteral("provider"), QStringLiteral("sftp"));
    params.insert(QStringLiteral("host"), QStringLiteral(" nas.example "));
    params.insert(QStringLiteral("port"), 2222);
    params.insert(QStringLiteral("username"), QStringLiteral("alice "));
    params.insert(QStringLiteral("options"), options);
    return params;
}

QVariantMap smbParams(const QVariant &requireEncryption)
{
    QVariantMap options;
    options.insert(QStringLiteral("share"), QStringLiteral("backup"));
    if (requireEncryption.isValid())
        options.insert(QStringLiteral("require_encryption"), requireEncryption);
    QVariantMap params;
    params.insert(QStringLiteral("provider"), QStringLiteral("smb"));
    params.insert(QStringLiteral("host"), QStringLiteral("nas"));
    params.insert(QStringLiteral("username"), QStringLiteral("bob"));
    params.insert(QStringLiteral("options"), options);
    return params;
}
} // namespace

class TestQmlHelpers : public QObject
{
    Q_OBJECT

private:
    Helpers helpers;
    NetVfsUi::InputRules input;

private slots:
    void initTestCase()
    {
        QVERIFY2(Test::installEngineeringEnglish(this), "netvfs_eng_en.qm missing from the build tree");
    }

    void constants()
    {
        QCOMPARE(helpers.defaultBackupsPath(), QStringLiteral("Sailfish OS/Backups"));
        QCOMPARE(helpers.credentialsApplication(), QStringLiteral("netvfs"));
        QCOMPARE(helpers.credentialsName(), QStringLiteral("default"));
        QCOMPARE(helpers.backupsPathKey(), QStringLiteral("backups_path"));
        QCOMPARE(input.defaultPort(QStringLiteral("sftp")), 22);
        QCOMPARE(input.defaultPort(QStringLiteral("smb")), 445);
        QCOMPARE(input.defaultPort(QStringLiteral("fake")), 0);
        QCOMPARE(helpers.backupServiceName(QStringLiteral("smb")), QStringLiteral("smb-backup"));
    }

    void providerInstalled()
    {
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
        QVERIFY(helpers.isProviderInstalled(QStringLiteral("fake")));
        QVERIFY(!helpers.isProviderInstalled(QStringLiteral("nope")));
    }

    void host_data()
    {
        QTest::addColumn<QString>("host");
        QTest::addColumn<QString>("problem");
        const QString invalid = QStringLiteral("This is not a valid server name or IP address.");
        QTest::newRow("empty") << "  " << "Enter the server name or IP address.";
        QTest::newRow("url") << "sftp://nas" << "Enter only the server name, without a prefix such as sftp:// or smb://.";
        QTest::newRow("user") << "bob@nas" << "Enter the user name in its own field.";
        QTest::newRow("name") << "nas.example.org" << "";
        QTest::newRow("trailing dot") << "nas.example.org." << "";
        QTest::newRow("short") << "nas" << "";
        QTest::newRow("mdns") << "nas.local" << "";
        QTest::newRow("underscore") << "my_nas" << "";
        QTest::newRow("ipv4") << "192.168.1.10" << "";
        QTest::newRow("ipv6") << "fe80::1" << "";
        QTest::newRow("ipv6 brackets") << "[2001:db8::2]" << "";
        QTest::newRow("ipv6 zone") << "fe80::1%wlan0" << "";
        QTest::newRow("idn") << QStringLiteral("bücher.example") << "";
        QTest::newRow("space") << "my nas" << invalid;
        QTest::newRow("leading hyphen") << "-nas.example" << invalid;
        QTest::newRow("trailing hyphen") << "nas-.example" << invalid;
        QTest::newRow("empty label") << "nas..example" << invalid;
        QTest::newRow("label 63") << QString(63, QLatin1Char('a')) + QStringLiteral(".example") << "";
        QTest::newRow("label 64") << QString(64, QLatin1Char('a')) + QStringLiteral(".example") << invalid;
        QTest::newRow("path") << "nas/share" << invalid;
        QTest::newRow("one colon") << "nas:22" << invalid;
        QTest::newRow("hex with port") << "ab:12" << invalid;
    }

    void host()
    {
        QFETCH(QString, host);
        QFETCH(QString, problem);
        QCOMPARE(input.hostProblem(host), problem);
    }

    void port_data()
    {
        QTest::addColumn<QString>("port");
        QTest::addColumn<bool>("ok");
        QTest::addColumn<int>("value");
        QTest::newRow("empty") << "" << true << 0;
        QTest::newRow("default") << "22" << true << 22;
        QTest::newRow("spaces") << " 2222 " << true << 2222;
        QTest::newRow("min") << "1" << true << 1;
        QTest::newRow("max") << "65535" << true << 65535;
        QTest::newRow("zero") << "0" << false << 0;
        QTest::newRow("too big") << "65536" << false << 0;
        QTest::newRow("letters") << "22a" << false << 0;
        QTest::newRow("negative") << "-1" << false << 0;
        QTest::newRow("six digits") << "000022" << false << 0;
    }

    void port()
    {
        QFETCH(QString, port);
        QFETCH(bool, ok);
        QFETCH(int, value);
        QCOMPARE(input.portProblem(port).isEmpty(), ok);
        if (!ok)
            QCOMPARE(input.portProblem(port), QStringLiteral("The port must be a number from 1 to 65535."));
        QCOMPARE(input.portValue(port), value);
    }

    void userName()
    {
        QCOMPARE(input.userNameProblem(QStringLiteral(" ")), QStringLiteral("Enter the user name."));
        QCOMPARE(input.userNameProblem(QStringLiteral("alice")), QString());
        QCOMPARE(input.userNameProblem(QStringLiteral("WORKGROUP\\alice")), QString());
        QCOMPARE(input.userNameProblem(QStringLiteral("ali\tce")),
                 QStringLiteral("The user name contains characters that are not allowed."));
    }

    void share_data()
    {
        QTest::addColumn<QString>("share");
        QTest::addColumn<QString>("problem");
        const QString invalid = QStringLiteral("This is not a valid share name.");
        const QString path = QStringLiteral("Enter only the share name. Put folders inside the share into the backups folder.");
        QTest::newRow("empty") << "" << "Enter the name of the share.";
        QTest::newRow("ok") << "backup" << "";
        QTest::newRow("dollar") << "backup$" << "";
        QTest::newRow("slash") << "backup/sub" << path;
        QTest::newRow("backslash") << "\\\\nas\\backup" << path;
        QTest::newRow("colon") << "back:up" << invalid;
        QTest::newRow("dot") << "backup." << invalid;
        QTest::newRow("80") << QString(80, QLatin1Char('s')) << "";
        QTest::newRow("81") << QString(81, QLatin1Char('s')) << invalid;
    }

    void share()
    {
        QFETCH(QString, share);
        QFETCH(QString, problem);
        QCOMPARE(input.shareProblem(share), problem);
    }

    void backupsPath_data()
    {
        QTest::addColumn<QString>("provider");
        QTest::addColumn<QString>("path");
        QTest::addColumn<QString>("problem");
        QTest::addColumn<QString>("clean");
        const QString dots = QStringLiteral("Folder names \".\" and \"..\" are not allowed.");
        QTest::newRow("empty") << "sftp" << " " << "Enter the folder for backups." << "";
        QTest::newRow("default") << "sftp" << "Sailfish OS/Backups" << "" << "Sailfish OS/Backups";
        QTest::newRow("absolute sftp") << "sftp" << "/srv//backup/" << "" << "/srv/backup";
        QTest::newRow("absolute smb") << "smb" << "/srv//backup/" << "" << "srv/backup";
        QTest::newRow("trimmed") << "smb" << "  a/b  " << "" << "a/b";
        QTest::newRow("dotdot") << "sftp" << "a/../b" << dots << "";
        QTest::newRow("dot") << "smb" << "./b" << dots << "";
        // SPEC-smb M-9 applies to SMB only.
        QTest::newRow("colon sftp") << "sftp" << "a:b" << "" << "a:b";
        QTest::newRow("colon smb") << "smb" << "x/a:b"
                                   << "\"a:b\" cannot be used as a folder name on an SMB server: names must not "
                                      "contain \\ : * ? \" < > | or end in a space or a dot." << "x/a:b";
        QTest::newRow("trailing space smb") << "smb" << "a /b"
                                            << "\"a \" cannot be used as a folder name on an SMB server: names must not "
                                               "contain \\ : * ? \" < > | or end in a space or a dot." << "a /b";
        QTest::newRow("trailing dot smb") << "smb" << "a./b"
                                          << "\"a.\" cannot be used as a folder name on an SMB server: names must not "
                                             "contain \\ : * ? \" < > | or end in a space or a dot." << "a./b";
        QTest::newRow("question smb") << "smb" << "why?" << "\"why?\" cannot be used as a folder name on an SMB "
                                                            "server: names must not contain \\ : * ? \" < > | or end "
                                                            "in a space or a dot." << "why?";
    }

    void backupsPath()
    {
        QFETCH(QString, provider);
        QFETCH(QString, path);
        QFETCH(QString, problem);
        QFETCH(QString, clean);
        QCOMPARE(input.backupsPathProblem(provider, path), problem);
        QCOMPARE(input.cleanBackupsPath(provider, path), clean);
    }

    void accountLabel()
    {
        // SPEC A-1, A-2
        QCOMPARE(helpers.accountLabel(QStringLiteral(" alice "), QStringLiteral(" nas.example ")),
                 QStringLiteral("alice@nas.example"));
        QCOMPARE(helpers.accountLabel(QStringLiteral("bob"), QStringLiteral("[2001:db8::2]")),
                 QStringLiteral("bob@2001:db8::2"));
    }

    void makeParams()
    {
        QVariantMap options;
        options.insert(QStringLiteral("share"), QStringLiteral("backup"));
        const QVariantMap params = helpers.makeParams(QStringLiteral("smb"), QStringLiteral(" [fe80::1] "),
                                                      QStringLiteral("4445"), QStringLiteral(" bob "), options);
        QCOMPARE(params.value(QStringLiteral("provider")).toString(), QStringLiteral("smb"));
        QCOMPARE(params.value(QStringLiteral("host")).toString(), QStringLiteral("fe80::1"));
        QCOMPARE(params.value(QStringLiteral("port")).toInt(), 4445);
        QCOMPARE(params.value(QStringLiteral("username")).toString(), QStringLiteral("bob"));
        QCOMPARE(params.value(QStringLiteral("options")).toMap(), options);

        const ConnectionParams converted = NetVfsUi::paramsFromVariant(params);
        QCOMPARE(converted.host, QStringLiteral("fe80::1"));
        QCOMPARE(converted.option(QStringLiteral("share")), QStringLiteral("backup"));
        QCOMPARE(NetVfsUi::paramsToVariant(converted), params);
        QCOMPARE(helpers.makeParams(QStringLiteral("sftp"), QStringLiteral("h"), QString(), QStringLiteral("u"),
                                    QVariantMap()).value(QStringLiteral("port")).toInt(), 0);
    }

    void paramsFromConfiguration()
    {
        QVariantMap configuration;
        configuration.insert(QStringLiteral("netvfs/host"), QStringLiteral("nas"));
        configuration.insert(QStringLiteral("netvfs/port"), 2222);
        configuration.insert(QStringLiteral("netvfs/username"), QStringLiteral("alice"));
        configuration.insert(QStringLiteral("netvfs/sftp/host_key"), QStringLiteral("ssh-ed25519 AAAA"));
        configuration.insert(QStringLiteral("netvfs/smb/share"), QStringLiteral("other provider"));
        configuration.insert(QStringLiteral("default_credentials_username"), QStringLiteral("alice@nas"));
        const QVariantMap params = helpers.paramsFromConfiguration(QStringLiteral("sftp"), configuration);
        QCOMPARE(params.value(QStringLiteral("provider")).toString(), QStringLiteral("sftp"));
        QCOMPARE(params.value(QStringLiteral("host")).toString(), QStringLiteral("nas"));
        QCOMPARE(params.value(QStringLiteral("port")).toInt(), 2222);
        QCOMPARE(params.value(QStringLiteral("username")).toString(), QStringLiteral("alice"));
        QVariantMap expected;
        expected.insert(QStringLiteral("host_key"), QStringLiteral("ssh-ed25519 AAAA"));
        QCOMPARE(params.value(QStringLiteral("options")).toMap(), expected);
    }

    void withOptions()
    {
        QVariantMap change;
        change.insert(QStringLiteral("host_key"), QStringLiteral("ssh-ed25519 NEW"));
        change.insert(QStringLiteral("public_key"), QString());
        change.insert(QStringLiteral("require_encryption"), false);
        const QVariantMap merged = helpers.withOptions(sftpParams(), change);
        const QVariantMap options = merged.value(QStringLiteral("options")).toMap();
        QCOMPARE(options.value(QStringLiteral("host_key")).toString(), QStringLiteral("ssh-ed25519 NEW"));
        QVERIFY(!options.contains(QStringLiteral("public_key")));
        QCOMPARE(options.value(QStringLiteral("require_encryption")), QVariant(false));
        QCOMPARE(options.value(QStringLiteral("auth_mode")).toString(), QStringLiteral("publickey"));
        QCOMPARE(merged.value(QStringLiteral("host")).toString(), QStringLiteral("nas.example"));
    }

    void creationSettings()
    {
        // SPEC 6.2, SPEC-sftp 2
        const QVariantMap settings = helpers.creationSettings(sftpParams(), QStringLiteral("/srv//backups/"));
        const QVariantMap global = settings.value(QStringLiteral("global")).toMap();
        QVariantMap expected;
        expected.insert(QStringLiteral("netvfs/host"), QStringLiteral("nas.example"));
        expected.insert(QStringLiteral("netvfs/port"), 2222);
        expected.insert(QStringLiteral("netvfs/username"), QStringLiteral("alice"));
        expected.insert(QStringLiteral("netvfs/sftp/auth_mode"), QStringLiteral("publickey"));
        expected.insert(QStringLiteral("netvfs/sftp/host_key"), QStringLiteral("ssh-ed25519 AAAA"));
        expected.insert(QStringLiteral("netvfs/sftp/public_key"), QStringLiteral("ssh-ed25519 BBBB sailfish-backup"));
        QCOMPARE(global, expected);   // no host_key_seen, no default_credentials_username yet (A-2)
        QVariantMap service;
        service.insert(QStringLiteral("backups_path"), QStringLiteral("/srv/backups"));
        QCOMPARE(settings.value(QStringLiteral("service")).toMap(), service);
        QCOMPARE(settings.value(QStringLiteral("serviceName")).toString(), QStringLiteral("sftp-backup"));
    }

    void creationSettingsSmb()
    {
        const QVariantMap settings = helpers.creationSettings(smbParams(false), QStringLiteral("/Backups"));
        const QVariantMap global = settings.value(QStringLiteral("global")).toMap();
        QCOMPARE(global.value(QStringLiteral("netvfs/smb/share")).toString(), QStringLiteral("backup"));
        QCOMPARE(global.value(QStringLiteral("netvfs/smb/require_encryption")), QVariant(false));
        QCOMPARE(global.value(QStringLiteral("netvfs/port")).toInt(), 0);
        QVERIFY(!global.contains(QStringLiteral("netvfs/smb/host_key")));
        QCOMPARE(settings.value(QStringLiteral("service")).toMap().value(QStringLiteral("backups_path")).toString(),
                 QStringLiteral("Backups"));
        QCOMPARE(settings.value(QStringLiteral("serviceName")).toString(), QStringLiteral("smb-backup"));
    }

    void credentialsLabel()
    {
        const QVariantMap global = helpers.credentialsLabelSettings(sftpParams()).value(QStringLiteral("global")).toMap();
        QCOMPARE(global.size(), 1);
        QCOMPARE(global.value(QStringLiteral("default_credentials_username")).toString(),
                 QStringLiteral("alice@nas.example"));
    }

    void updateSettings()
    {
        // SPEC 6.4, 7.5: attention keys cleared, pin and key stored
        const QVariantMap settings = helpers.updateSettings(sftpParams());
        const QVariantMap global = settings.value(QStringLiteral("global")).toMap();
        QCOMPARE(global.value(QStringLiteral("CredentialsNeedUpdate")), QVariant(false));
        QCOMPARE(global.value(QStringLiteral("default_credentials_username")).toString(),
                 QStringLiteral("alice@nas.example"));
        QCOMPARE(global.value(QStringLiteral("netvfs/sftp/host_key")).toString(), QStringLiteral("ssh-ed25519 AAAA"));
        QCOMPARE(global.value(QStringLiteral("netvfs/sftp/public_key")).toString(),
                 QStringLiteral("ssh-ed25519 BBBB sailfish-backup"));
        QVERIFY(!global.contains(QStringLiteral("netvfs/sftp/host_key_seen")));
        const QStringList remove = settings.value(QStringLiteral("remove")).toStringList();
        QVERIFY(remove.contains(QStringLiteral("netvfs/attention")));
        QVERIFY(remove.contains(QStringLiteral("CredentialsNeedUpdateFrom")));
        QVERIFY(remove.contains(QStringLiteral("netvfs/sftp/host_key_seen")));
        QVERIFY(!remove.contains(QStringLiteral("netvfs/sftp/public_key")));

        // S-18: switching to a password drops the stored public key
        QVariantMap password;
        password.insert(QStringLiteral("auth_mode"), QStringLiteral("password"));
        password.insert(QStringLiteral("public_key"), QString());
        const QVariantMap switched = helpers.updateSettings(helpers.withOptions(sftpParams(), password));
        QVERIFY(switched.value(QStringLiteral("remove")).toStringList().contains(QStringLiteral("netvfs/sftp/public_key")));
        QCOMPARE(switched.value(QStringLiteral("global")).toMap().value(QStringLiteral("netvfs/sftp/auth_mode")).toString(),
                 QStringLiteral("password"));
    }

    void attention()
    {
        QVariantMap configuration;
        QCOMPARE(helpers.attentionState(configuration), QString());
        QCOMPARE(helpers.attentionText(QString()), QString());
        configuration.insert(QStringLiteral("CredentialsNeedUpdate"), true);
        QCOMPARE(helpers.attentionState(configuration), QStringLiteral("credentials-missing"));
        QCOMPARE(helpers.attentionText(QStringLiteral("credentials-missing")),
                 QStringLiteral("The sign-in details for this account are missing, for example after restoring the "
                                "device. Enter them again to continue backing up."));
        configuration.insert(QStringLiteral("netvfs/attention"), QStringLiteral("auth-failed"));
        QCOMPARE(helpers.attentionState(configuration), QStringLiteral("auth-failed"));
        QVERIFY(helpers.attentionText(QStringLiteral("auth-failed")).startsWith(QStringLiteral("The server refused")));
        configuration.insert(QStringLiteral("netvfs/attention"), QStringLiteral("server-identity-changed"));
        QCOMPARE(helpers.attentionState(configuration), QStringLiteral("server-identity-changed"));
        QVERIFY(helpers.attentionText(QStringLiteral("server-identity-changed")).contains(QStringLiteral("identity")));
        configuration.insert(QStringLiteral("CredentialsNeedUpdate"), false);
        configuration.insert(QStringLiteral("netvfs/attention"), QStringLiteral("unknown"));
        QCOMPARE(helpers.attentionState(configuration), QString());
    }

    void identity()
    {
        // ssh-keygen -lf prints "SHA256:" + unpadded base64 of SHA-256 over the key blob.
        QCOMPARE(NetVfsUi::sha256Fingerprint(QByteArray()), QStringLiteral("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"));
        const QByteArray blob("\x00\x00\x00\x0bssh-ed25519 key", 19);
        const QString pin = QStringLiteral("ssh-ed25519 ") + QString::fromLatin1(blob.toBase64());
        const QVariantMap identity = helpers.identityFromPin(pin);
        QCOMPARE(identity.value(QStringLiteral("algorithm")).toString(), QStringLiteral("ssh-ed25519"));
        QCOMPARE(identity.value(QStringLiteral("fingerprint")).toString(), NetVfsUi::sha256Fingerprint(blob));
        QCOMPARE(identity.value(QStringLiteral("pin")).toString(), pin);
        QVERIFY(helpers.identityFromPin(QStringLiteral("garbage")).isEmpty());
        QVERIFY(helpers.identityFromPin(QString()).isEmpty());

        ServerIdentity seen;
        seen.algorithm = QStringLiteral("ssh-rsa");
        seen.publicKey = blob;
        seen.fingerprint = QStringLiteral("SHA256:given");
        QCOMPARE(NetVfsUi::identityToVariant(seen).value(QStringLiteral("fingerprint")).toString(),
                 QStringLiteral("SHA256:given"));
        QVERIFY(NetVfsUi::identityToVariant(ServerIdentity()).isEmpty());

        QVariantMap configuration;
        configuration.insert(QStringLiteral("netvfs/sftp/host_key_seen"), pin);
        QCOMPARE(helpers.seenPin(QStringLiteral("sftp"), configuration), pin);
        QCOMPARE(helpers.seenPin(QStringLiteral("smb"), configuration), QString());
    }

    void hostKeyHint_data()
    {
        QTest::addColumn<QString>("algorithm");
        QTest::addColumn<QString>("file");
        QTest::newRow("ed25519") << "ssh-ed25519" << "ssh_host_ed25519_key.pub";
        QTest::newRow("ecdsa") << "ecdsa-sha2-nistp256" << "ssh_host_ecdsa_key.pub";
        QTest::newRow("rsa") << "ssh-rsa" << "ssh_host_rsa_key.pub";
        QTest::newRow("rsa-sha2") << "rsa-sha2-512" << "ssh_host_rsa_key.pub";
        QTest::newRow("unknown") << "" << "ssh_host_ed25519_key.pub";
    }

    void hostKeyHint()
    {
        // SPEC-sftp S-8
        QFETCH(QString, algorithm);
        QFETCH(QString, file);
        QCOMPARE(helpers.hostKeyHint(algorithm),
                 QStringLiteral("To compare, run this command on the server: ssh-keygen -lf /etc/ssh/") + file);
    }

    void labels()
    {
        // SPEC-smb M-3
        QCOMPARE(helpers.transportSecurityText(sftpParams()), QStringLiteral("Encrypted (SSH)"));
        QCOMPARE(helpers.transportSecurityText(smbParams(true)), QStringLiteral("Signed and encrypted"));
        QCOMPARE(helpers.transportSecurityText(smbParams(QVariant())), QStringLiteral("Signed and encrypted"));
        QCOMPARE(helpers.transportSecurityText(smbParams(false)), QStringLiteral("Signed, not encrypted"));
        QCOMPARE(helpers.transportSecurityText(smbParams(QStringLiteral("false"))), QStringLiteral("Signed, not encrypted"));
        QCOMPARE(helpers.authModeText(QStringLiteral("publickey")), QStringLiteral("SSH key"));
        QCOMPARE(helpers.authModeText(QStringLiteral("password")), QStringLiteral("Password"));
        QCOMPARE(helpers.authModeText(QString()), QStringLiteral("Password"));
    }

    void errorTexts()
    {
        // U-4: a specific text for every error.
        QSet<QString> texts;
        const int last = static_cast<int>(Error::NotModified);
        for (int i = static_cast<int>(Error::Canceled); i <= last; ++i) {
            const QString text = NetVfsUi::userErrorText(static_cast<Error>(i));
            QVERIFY2(!text.isEmpty() && !text.startsWith(QStringLiteral("settings-accounts-")),
                     qPrintable(errorName(static_cast<Error>(i))));
            texts.insert(text);
        }
        QCOMPARE(texts.size(), last);
        QCOMPARE(NetVfsUi::userErrorText(Error::None), QString());
        QCOMPARE(NetVfsUi::userErrorText(Error::AuthFailed),
                 QStringLiteral("The server refused the sign-in. Check the user name and the password or key."));
        QCOMPARE(NetVfsUi::userErrorText(Error::NetworkUnreachable),
                 QStringLiteral("Cannot reach the server. Check the server name, the port and the network connection."));
        QCOMPARE(NetVfsUi::backendMissingText(), QStringLiteral("Support for this kind of server is not installed on this device."));
    }

    void activityTexts()
    {
        using NetVfsUi::Activity;
        QCOMPARE(NetVfsUi::userErrorText(Error::AuthFailed, Activity::StoredSecret),
                 QStringLiteral("The stored password or key for this account could not be read. Update the sign-in details."));
        QCOMPARE(NetVfsUi::userErrorText(Error::AuthFailed, Activity::InstallKey),
                 QStringLiteral("The server did not accept the password, so the key could not be installed."));
        QCOMPARE(NetVfsUi::userErrorText(Error::Unsupported, Activity::KeyFile),
                 QStringLiteral("This key type is not supported. Use an Ed25519, ECDSA or RSA (2048 bits or more) key "
                                "without a certificate."));
        QCOMPARE(NetVfsUi::userErrorText(Error::AuthFailed, Activity::KeyFile), QStringLiteral("The passphrase is not correct."));
        QCOMPARE(NetVfsUi::userErrorText(Error::NotFound, Activity::KeyFile),
                 QStringLiteral("The file could not be read as a private key."));
        // Activities only change the errors they are about.
        QCOMPARE(NetVfsUi::userErrorText(Error::Timeout, Activity::StoredSecret), NetVfsUi::userErrorText(Error::Timeout));
        QCOMPARE(NetVfsUi::userErrorText(Error::NotFound, Activity::InstallKey), NetVfsUi::userErrorText(Error::NotFound));
        QCOMPARE(NetVfsUi::userErrorText(Error::None, Activity::KeyFile), QString());
    }
};

QTEST_GUILESS_MAIN(TestQmlHelpers)
#include "tst_qmlhelpers.moc"
