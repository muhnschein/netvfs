// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakebackend.h"
#include "netvfshelpers.h"
#include "sshkeys.h"
#include "sshkeytool.h"
#include "../qmltestutil.h"

#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QMutexLocker>
#include <QtCore/QSemaphore>
#include <QtCore/QTemporaryDir>
#include <QtCore/QUrl>
#include <QtTest/QtTest>

using namespace NetVfs;
using NetVfs::Test::FakeServer;
using NetVfsUi::SshKeyTool;

namespace {
const QByteArray PrivateKey("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfake\n-----END OPENSSH PRIVATE KEY-----\n");
const QString PublicLine = QStringLiteral("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake sailfish-backup");

// Test double for the SFTP plugin's key operations (SPEC-sftp 5.1).
class FakeKeyTools : public SshKeyTools
{
public:
    QSemaphore *gate = nullptr;   // when set, generate() waits for it

    Result generate(SshKeyMaterial *out) override
    {
        if (gate)
            gate->acquire();
        fill(out, QStringLiteral("ssh-ed25519"));
        return Result();
    }

    Result importKey(const QByteArray &contents, const QByteArray &passphrase, SshKeyMaterial *out) override
    {
        if (contents.contains("DSA"))
            return Result(Error::Unsupported, QStringLiteral("DSA keys are not supported"));
        if (contents.contains("ENCRYPTED") && passphrase != "open sesame")
            return Result(Error::AuthFailed);
        if (!contents.contains("PRIVATE KEY"))
            return Result(Error::Internal, QStringLiteral("not a key"));
        fill(out, QStringLiteral("ecdsa-sha2-nistp256"));
        return Result();
    }

    Result describe(const QByteArray &privateKey, SshKeyMaterial *out) override
    {
        Q_UNUSED(privateKey)
        Q_UNUSED(out)
        return Result(Error::Unsupported);
    }

private:
    static void fill(SshKeyMaterial *out, const QString &algorithm)
    {
        out->privateKey = PrivateKey;
        out->algorithm = algorithm;
        out->publicLine = PublicLine;
        out->fingerprint = QStringLiteral("SHA256:fake");
    }
};

QVariantMap sftpParams(const QString &pin, const QString &provider = QStringLiteral("fake"))
{
    QVariantMap options;
    options.insert(QStringLiteral("auth_mode"), QStringLiteral("publickey"));
    if (!pin.isEmpty())
        options.insert(QStringLiteral("host_key"), pin);
    QVariantMap params;
    params.insert(QStringLiteral("provider"), provider);
    params.insert(QStringLiteral("host"), QStringLiteral("server.example"));
    params.insert(QStringLiteral("username"), QStringLiteral("user"));
    params.insert(QStringLiteral("options"), options);
    return params;
}

ServerIdentity serverIdentity()
{
    ServerIdentity identity;
    identity.algorithm = QStringLiteral("ssh-ed25519");
    identity.publicKey = QByteArray("\x00\x00\x00\x0bssh-ed25519 host", 20);
    return identity;
}

bool logHas(const QString &entry)
{
    FakeServer *server = FakeServer::instance();
    QMutexLocker lock(&server->mutex);
    return server->log.contains(entry);
}
} // namespace

class TestQmlKeyTool : public QObject
{
    Q_OBJECT

private:
    FakeKeyTools tools;
    QTemporaryDir dir;

    QString writeFile(const QString &name, const QByteArray &contents)
    {
        QFile file(dir.filePath(name));
        if (!file.open(QIODevice::WriteOnly))
            return QString();
        file.write(contents);
        return file.fileName();
    }

    void makeReady(SshKeyTool *tool)
    {
        QSignalSpy changed(tool, &SshKeyTool::stateChanged);
        tool->generate();
        QTRY_COMPARE(tool->state(), SshKeyTool::State::Ready);
    }

private slots:
    void initTestCase()
    {
        QVERIFY(dir.isValid());
        QVERIFY(Test::installEngineeringEnglish(this));
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
    }

    void init()
    {
        FakeServer::instance()->reset();
        tools.gate = nullptr;
    }

    void generate()
    {
        SshKeyTool tool(&tools, nullptr);
        QVERIFY(tool.available());
        QCOMPARE(tool.state(), SshKeyTool::State::Empty);
        QVERIFY(tool.secret().isEmpty());
        tool.generate();
        QCOMPARE(tool.state(), SshKeyTool::State::Working);
        QTRY_COMPARE(tool.state(), SshKeyTool::State::Ready);
        QVERIFY(tool.hasKey());
        QCOMPARE(tool.algorithm(), QStringLiteral("ssh-ed25519"));
        QCOMPARE(tool.publicKey(), PublicLine);
        QCOMPARE(tool.fingerprint(), QStringLiteral("SHA256:fake"));
        QVERIFY(tool.errorText().isEmpty());

        // SPEC-sftp 2: "netvfs-key-v1:" + base64 of the private key.
        const QString secret = tool.secret();
        QCOMPARE(secret, QStringLiteral("netvfs-key-v1:") + QString::fromLatin1(PrivateKey.toBase64()));
        QByteArray decoded;
        QVERIFY(decodeKeySecret(secret.toLatin1(), &decoded));
        QCOMPARE(decoded, PrivateKey);

        tool.clear();
        QCOMPARE(tool.state(), SshKeyTool::State::Empty);
        QVERIFY(!tool.hasKey());
        QVERIFY(tool.secret().isEmpty());
        QVERIFY(tool.publicKey().isEmpty());
    }

    void importPlain()
    {
        SshKeyTool tool(&tools, nullptr);
        tool.importFile(writeFile(QStringLiteral("id_ecdsa"), PrivateKey));
        QTRY_COMPARE(tool.state(), SshKeyTool::State::Ready);
        QCOMPARE(tool.algorithm(), QStringLiteral("ecdsa-sha2-nistp256"));
        QVERIFY(!tool.secret().isEmpty());
    }

    void importFileUrl()
    {
        SshKeyTool tool(&tools, nullptr);
        const QString path = writeFile(QStringLiteral("id url"), PrivateKey);
        tool.importFile(QUrl::fromLocalFile(path).toString());
        QTRY_COMPARE(tool.state(), SshKeyTool::State::Ready);
    }

    void importEncrypted()
    {
        // SPEC-sftp 5.1: asks for the passphrase when the file is encrypted.
        const QString path = writeFile(QStringLiteral("id_encrypted"), "ENCRYPTED " + PrivateKey);
        SshKeyTool tool(&tools, nullptr);
        tool.importFile(path);
        QTRY_COMPARE(tool.state(), SshKeyTool::State::NeedsPassphrase);
        QVERIFY(tool.errorText().isEmpty());
        QVERIFY(!tool.hasKey());
        tool.importFile(path, QStringLiteral("wrong"));
        QTRY_VERIFY(tool.state() != SshKeyTool::State::Working);
        QCOMPARE(tool.state(), SshKeyTool::State::NeedsPassphrase);
        QCOMPARE(tool.errorText(), QStringLiteral("The passphrase is not correct."));
        tool.importFile(path, QStringLiteral("open sesame"));
        QTRY_COMPARE(tool.state(), SshKeyTool::State::Ready);
        QVERIFY(tool.errorText().isEmpty());
    }

    void importRejected_data()
    {
        QTest::addColumn<QString>("name");
        QTest::addColumn<QByteArray>("contents");
        QTest::addColumn<QString>("text");
        QTest::addColumn<QString>("detail");
        QTest::newRow("dsa") << "id_dsa" << QByteArray("DSA PRIVATE KEY")
                             << "This key type is not supported. Use an Ed25519, ECDSA or RSA (2048 bits or more) key "
                                "without a certificate." << "DSA keys are not supported";
        QTest::newRow("not a key") << "notes.txt" << QByteArray("hello")
                                   << "The file could not be read as a private key." << "not a key";
        QTest::newRow("too large") << "huge" << QByteArray(70 * 1024, 'x')
                                   << "The file could not be read as a private key."
                                   << "The file is too large to be a private key";
    }

    void importRejected()
    {
        // S-15
        QFETCH(QString, name);
        QFETCH(QByteArray, contents);
        QFETCH(QString, text);
        QFETCH(QString, detail);
        SshKeyTool tool(&tools, nullptr);
        tool.importFile(writeFile(name, contents));
        QTRY_COMPARE(tool.state(), SshKeyTool::State::Failed);
        QCOMPARE(tool.errorText(), text);
        QCOMPARE(tool.errorDetail(), detail);
        QVERIFY(tool.secret().isEmpty());
    }

    void importMissingFile()
    {
        SshKeyTool tool(&tools, nullptr);
        tool.importFile(dir.filePath(QStringLiteral("does-not-exist")));
        QTRY_COMPARE(tool.state(), SshKeyTool::State::Failed);
        QCOMPARE(tool.errorText(), QStringLiteral("The file could not be read as a private key."));
    }

    void failedImportForgetsOldKey()
    {
        SshKeyTool tool(&tools, nullptr);
        makeReady(&tool);
        tool.importFile(writeFile(QStringLiteral("bad"), "hello"));
        QTRY_COMPARE(tool.state(), SshKeyTool::State::Failed);
        QVERIFY(tool.secret().isEmpty());
        QVERIFY(tool.publicKey().isEmpty());
    }

    void unavailable()
    {
        SshKeyTool tool(nullptr, nullptr);
        QVERIFY(!tool.available());
        tool.generate();
        QCOMPARE(tool.state(), SshKeyTool::State::Failed);
        QCOMPARE(tool.errorText(), QStringLiteral("Support for this kind of server is not installed on this device."));
        tool.importFile(writeFile(QStringLiteral("k"), PrivateKey));
        QCOMPARE(tool.state(), SshKeyTool::State::Failed);
    }

    void defaultToolsWithoutPlugin()
    {
        // No SFTP plugin in the search path: reported, not crashed.
        const QByteArray saved = qgetenv("NETVFS_BACKEND_PATH");
        qputenv("NETVFS_BACKEND_PATH", dir.path().toLocal8Bit());
        SshKeyTool tool;
        qputenv("NETVFS_BACKEND_PATH", saved);
        if (tool.available())
            QSKIP("An SFTP backend is installed on this host");
        tool.generate();
        QCOMPARE(tool.state(), SshKeyTool::State::Failed);
    }

    void realSftpPlugin()
    {
        // Against the real SFTP plugin when it is built in this tree.
        if (!QFileInfo::exists(QStringLiteral(NETVFS_TEST_BACKEND_DIR "/libnetvfs-sftp.so")))
            QSKIP("SFTP backend not built");
        const QByteArray saved = qgetenv("NETVFS_BACKEND_PATH");
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_BACKEND_DIR);
        SshKeyTool tool;
        qputenv("NETVFS_BACKEND_PATH", saved);
        QVERIFY(tool.available());
        tool.generate();
        QTRY_COMPARE(tool.state(), SshKeyTool::State::Ready);
        QVERIFY(tool.publicKey().startsWith(QStringLiteral("ssh-ed25519 ")));
        QVERIFY(tool.fingerprint().startsWith(QStringLiteral("SHA256:")));
        QVERIFY(tool.secret().startsWith(QStringLiteral("netvfs-key-v1:")));
    }

    void cancelGeneration()
    {
        QSemaphore gate;
        tools.gate = &gate;
        SshKeyTool tool(&tools, nullptr);
        tool.generate();
        QCOMPARE(tool.state(), SshKeyTool::State::Working);
        tool.cancel();
        QCOMPARE(tool.state(), SshKeyTool::State::Empty);
        gate.release();
        QTest::qWait(100);
        QCOMPARE(tool.state(), SshKeyTool::State::Empty);
        QVERIFY(tool.secret().isEmpty());
        tool.cancel();   // nothing running
        QCOMPARE(tool.state(), SshKeyTool::State::Empty);
    }

    void installWithPassword()
    {
        // S-16, S-17
        FakeServer *server = FakeServer::instance();
        server->identity = serverIdentity();
        SshKeyTool tool(&tools, nullptr);
        makeReady(&tool);
        QSignalSpy changed(&tool, &SshKeyTool::installStateChanged);
        tool.installWithPassword(sftpParams(serverIdentity().toPin()), QStringLiteral("secret"));
        QCOMPARE(tool.installState(), SshKeyTool::InstallState::Installing);
        QTRY_COMPARE(tool.installState(), SshKeyTool::InstallState::Installed);
        QVERIFY(tool.installErrorText().isEmpty());
        QCOMPARE(server->fileData(QStringLiteral(".ssh/authorized_keys")), PublicLine.toUtf8() + '\n');
        QVERIFY(logHas(QStringLiteral("authenticate")));
        QVERIFY(changed.count() >= 2);
        QCOMPARE(tool.state(), SshKeyTool::State::Ready);   // the key itself is unchanged
    }

    void installWrongPassword()
    {
        SshKeyTool tool(&tools, nullptr);
        makeReady(&tool);
        tool.installWithPassword(sftpParams(QString()), QStringLiteral("wrong"));
        QTRY_COMPARE(tool.installState(), SshKeyTool::InstallState::InstallFailed);
        QCOMPARE(tool.installErrorText(),
                 QStringLiteral("The server did not accept the password, so the key could not be installed."));
        QVERIFY(!tool.installErrorDetail().isEmpty());
        QVERIFY(!FakeServer::instance()->exists(QStringLiteral(".ssh/authorized_keys")));
    }

    void installChecksPin()
    {
        // SEC-1: the password is not sent to a server with another key.
        FakeServer::instance()->identity = serverIdentity();
        SshKeyTool tool(&tools, nullptr);
        makeReady(&tool);
        tool.installWithPassword(sftpParams(QStringLiteral("ssh-ed25519 AAAAother")), QStringLiteral("secret"));
        QTRY_COMPARE(tool.installState(), SshKeyTool::InstallState::InstallFailed);
        QVERIFY(!logHas(QStringLiteral("authenticate")));
    }

    void installPreconditions()
    {
        SshKeyTool tool(&tools, nullptr);
        tool.installWithPassword(sftpParams(QString()), QStringLiteral("secret"));
        QCOMPARE(tool.installState(), SshKeyTool::InstallState::InstallFailed);
        QCOMPARE(tool.installErrorText(), QStringLiteral("Something went wrong on this device."));

        makeReady(&tool);
        tool.installWithPassword(sftpParams(QString(), QStringLiteral("nope")), QStringLiteral("secret"));
        QCOMPARE(tool.installState(), SshKeyTool::InstallState::InstallFailed);
        QCOMPARE(tool.installErrorText(), QStringLiteral("Support for this kind of server is not installed on this device."));
    }

    void cancelInstall()
    {
        FakeServer::instance()->chunkDelayMs = 400;
        SshKeyTool tool(&tools, nullptr);
        makeReady(&tool);
        tool.installWithPassword(sftpParams(QString()), QStringLiteral("secret"));
        QTRY_VERIFY(logHas(QStringLiteral("authenticate")));
        tool.cancel();
        QCOMPARE(tool.installState(), SshKeyTool::InstallState::InstallIdle);
        QTest::qWait(600);
        QCOMPARE(tool.installState(), SshKeyTool::InstallState::InstallIdle);
        tool.clear();
        QCOMPARE(tool.installState(), SshKeyTool::InstallState::InstallIdle);
    }
};

QTEST_GUILESS_MAIN(TestQmlKeyTool)
#include "tst_qmlkeytool.moc"
