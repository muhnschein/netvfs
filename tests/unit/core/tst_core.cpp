// SPDX-License-Identifier: LGPL-2.1-or-later
#include "backendloader.h"
#include "error.h"
#include "fakebackend.h"
#include "identity.h"
#include "paths.h"
#include "probe.h"
#include "secure.h"
#include "sshkeys.h"
#include "types.h"

#include <QtCore/QScopedPointer>
#include <QtTest/QtTest>

using namespace NetVfs;
using NetVfs::Test::FakeBackend;
using NetVfs::Test::FakeServer;

class TestCore : public QObject
{
    Q_OBJECT

private:
    static ServerIdentity ed25519(char fill)
    {
        ServerIdentity id;
        id.algorithm = QStringLiteral("ssh-ed25519");
        id.publicKey = QByteArray(51, fill);
        id.fingerprint = QStringLiteral("SHA256:abc");
        return id;
    }

private slots:
    void init() { FakeServer::instance()->reset(); }

    void errorNames()
    {
        for (int i = 0; i <= static_cast<int>(Error::Internal); ++i) {
            const Error e = static_cast<Error>(i);
            QCOMPARE(errorFromName(errorName(e)), e);
        }
        QCOMPARE(errorName(Error::ServerIdentityChanged), QStringLiteral("ServerIdentityChanged"));
        QCOMPARE(errorFromName(QStringLiteral("bogus")), Error::Internal);
        QCOMPARE(Result(Error::NotFound, QStringLiteral("x")).toString(), QStringLiteral("NotFound: x"));
        QCOMPARE(Result(Error::Timeout).toString(), QStringLiteral("Timeout"));
        QVERIFY(Result::success().ok());
        QVERIFY(!Result(Error::Canceled).ok());
    }

    void normalize_data()
    {
        QTest::addColumn<QString>("input");
        QTest::addColumn<bool>("ok");
        QTest::addColumn<QString>("expected");
        QTest::newRow("empty") << QString() << true << QString();
        QTest::newRow("relative") << "Sailfish OS/Backups" << true << "Sailfish OS/Backups";
        QTest::newRow("slashes") << "a//b///c/" << true << "a/b/c";
        QTest::newRow("absolute") << "/srv/backup/" << true << "/srv/backup";
        QTest::newRow("root") << "/" << true << "/";
        QTest::newRow("dot") << "a/./b" << false << QString();
        QTest::newRow("dotdot") << "../etc" << false << QString();
        QTest::newRow("trailing dotdot") << "a/.." << false << QString();
        QTest::newRow("dots in name") << "a/..b/c." << true << "a/..b/c.";
        QTest::newRow("nul") << QString(QStringLiteral("a") + QChar(0) + QStringLiteral("b")) << false << QString();
    }

    void normalize()
    {
        QFETCH(QString, input);
        QFETCH(bool, ok);
        QFETCH(QString, expected);
        QString out = QStringLiteral("unchanged");
        const Result r = Paths::normalize(input, &out);
        QCOMPARE(r.ok(), ok);
        if (ok)
            QCOMPARE(out, expected);
        else
            QCOMPARE(out, QStringLiteral("unchanged"));
    }

    void pathHelpers()
    {
        QVERIFY(Paths::isAbsolute(QStringLiteral("/a")));
        QVERIFY(!Paths::isAbsolute(QStringLiteral("a")));
        QCOMPARE(Paths::components(QStringLiteral("/a/b")), QStringList({ QStringLiteral("a"), QStringLiteral("b") }));
        QCOMPARE(Paths::join(QString(), QStringLiteral("f")), QStringLiteral("f"));
        QCOMPARE(Paths::join(QStringLiteral("/"), QStringLiteral("f")), QStringLiteral("/f"));
        QCOMPARE(Paths::join(QStringLiteral("d"), QStringLiteral("f")), QStringLiteral("d/f"));
        QCOMPARE(Paths::parent(QStringLiteral("d/e/f")), QStringLiteral("d/e"));
        QCOMPARE(Paths::parent(QStringLiteral("/f")), QStringLiteral("/"));
        QCOMPARE(Paths::parent(QStringLiteral("f")), QString());
        QCOMPARE(Paths::fileName(QStringLiteral("d/e/f.tar")), QStringLiteral("f.tar"));
        QCOMPARE(Paths::fileName(QStringLiteral("f")), QStringLiteral("f"));
    }

    void windowsComponents_data()
    {
        QTest::addColumn<QString>("path");
        QTest::addColumn<bool>("ok");
        QTest::newRow("plain") << "Sailfish OS/Backups" << true;
        QTest::newRow("unicode") << QString::fromUtf8("Sicherung/Gerät") << true;
        for (const char c : QByteArray("\\:*?\"<>|"))
            QTest::newRow(QByteArray("char ") .append(c).constData()) << QString(QStringLiteral("a") + QLatin1Char(c)) << false;
        QTest::newRow("trailing space") << "dir /x" << false;
        QTest::newRow("trailing dot") << "dir./x" << false;
        QTest::newRow("control") << QString(QStringLiteral("a") + QChar(1)) << false;
    }

    void windowsComponents()
    {
        QFETCH(QString, path);
        QFETCH(bool, ok);
        QCOMPARE(Paths::checkWindowsPath(path).ok(), ok);
    }

    void pins()
    {
        const ServerIdentity id = ed25519('k');
        const QString pin = id.toPin();
        QVERIFY(pin.startsWith(QStringLiteral("ssh-ed25519 ")));
        QCOMPARE(ServerIdentity::fromPin(pin), id);
        QVERIFY(ServerIdentity::fromPin(QStringLiteral("ssh-ed25519")).isEmpty());
        QVERIFY(ServerIdentity::fromPin(QStringLiteral("ssh-ed25519 !!!notbase64")).isEmpty());
        QVERIFY(ServerIdentity::fromPin(QStringLiteral("a b c")).isEmpty());
        QVERIFY(ServerIdentity().toPin().isEmpty());
        QVERIFY(ed25519('a') != ed25519('b'));
    }

    void identityPolicy()
    {
        const ServerIdentity seen = ed25519('k');
        QVERIFY(checkServerIdentity(ServerIdentity(), QString()).ok());
        QCOMPARE(checkServerIdentity(ServerIdentity(), seen.toPin()).error(), Error::ServerIdentityChanged);
        QCOMPARE(checkServerIdentity(seen, QString()).error(), Error::ServerIdentityUnknown);
        QVERIFY(checkServerIdentity(seen, seen.toPin()).ok());
        QCOMPARE(checkServerIdentity(seen, ed25519('x').toPin()).error(), Error::ServerIdentityChanged);
        ServerIdentity otherAlgorithm = seen;
        otherAlgorithm.algorithm = QStringLiteral("ssh-rsa");
        QCOMPARE(checkServerIdentity(seen, otherAlgorithm.toPin()).error(), Error::ServerIdentityChanged);
    }

    // SEC-1 / C-7: no authentication request before the identity matches.
    void establishChecksIdentityBeforeAuth()
    {
        FakeServer *server = FakeServer::instance();
        server->identity = ed25519('k');
        FakeBackend backend;
        ConnectionParams params;
        params.options.insert(QStringLiteral("host_key"), ed25519('z').toPin());
        ServerIdentity seen;
        const Result r = establish(&backend, params, Credentials(QStringLiteral("user"), "secret"), &seen);
        QCOMPARE(r.error(), Error::ServerIdentityChanged);
        QCOMPARE(seen, server->identity);
        QVERIFY(!server->log.contains(QStringLiteral("authenticate")));
        QCOMPARE(server->log.last(), QStringLiteral("disconnect"));

        server->log.clear();
        QCOMPARE(establish(&backend, ConnectionParams(), Credentials(QStringLiteral("user"), "secret")).error(),
                 Error::ServerIdentityUnknown);
        QVERIFY(!server->log.contains(QStringLiteral("authenticate")));
    }

    void establishSuccessAndFailures()
    {
        FakeServer *server = FakeServer::instance();
        server->identity = ed25519('k');
        ConnectionParams params;
        params.options.insert(QStringLiteral("host_key"), server->identity.toPin());
        FakeBackend backend;
        QVERIFY(establish(&backend, params, Credentials(QStringLiteral("user"), "secret")).ok());
        QCOMPARE(server->log, QStringList({ QStringLiteral("connect"), QStringLiteral("authenticate") }));

        FakeBackend wrong;
        QCOMPARE(establish(&wrong, params, Credentials(QStringLiteral("user"), "nope")).error(), Error::AuthFailed);
        QCOMPARE(server->log.last(), QStringLiteral("disconnect"));

        server->connectResult = Result(Error::NetworkUnreachable);
        FakeBackend unreachable;
        QCOMPARE(establish(&unreachable, params, Credentials()).error(), Error::NetworkUnreachable);
    }

    void credentialsWipe()
    {
        QByteArray secret("hunter2");
        Credentials c(QStringLiteral("u"), secret);
        secureWipe(secret);
        QVERIFY(secret.isEmpty());
        QCOMPARE(c.secret, QByteArray("hunter2"));   // deep copy
        Credentials copy(c);
        Credentials assigned;
        assigned = c;
        assigned = assigned;
        c.wipe();
        QVERIFY(c.secret.isEmpty());
        QCOMPARE(copy.secret, QByteArray("hunter2"));
        QCOMPARE(assigned.secret, QByteArray("hunter2"));
        QString text = QStringLiteral("pw");
        secureWipe(text);
        QVERIFY(text.isEmpty());
        QByteArray empty;
        secureWipe(empty);
        QVERIFY(empty.isEmpty());
    }

    void verifyAccessWritesAndRemovesProbe()
    {
        FakeServer *server = FakeServer::instance();
        FakeBackend backend;
        ConnectionParams params;
        QVERIFY(establish(&backend, params, Credentials(QStringLiteral("user"), "secret")).ok());
        qint64 freeBytes = 0;
        QVERIFY(verifyAccess(&backend, QStringLiteral("Sailfish OS/Backups"), &freeBytes).ok());
        QCOMPARE(freeBytes, server->freeBytes);
        QVERIFY(server->exists(QStringLiteral("Sailfish OS/Backups")));
        QCOMPARE(server->nodes.size(), 2);   // two directories, no probe left
        bool sawProbe = false;
        for (const QString &entry : server->log)
            sawProbe |= entry.startsWith(QStringLiteral("upload:Sailfish OS/Backups/.netvfs-probe-"));
        QVERIFY(sawProbe);

        server->freeBytes = -1;
        QVERIFY(verifyAccess(&backend, QStringLiteral("x"), &freeBytes).ok());
        QCOMPARE(freeBytes, qint64(-1));

        server->failOps.insert(QStringLiteral("upload"), Result(Error::PermissionDenied));
        QCOMPARE(verifyAccess(&backend, QStringLiteral("x")).error(), Error::PermissionDenied);
        server->failOps.insert(QStringLiteral("makePath"), Result(Error::PermissionDenied));
        QCOMPARE(verifyAccess(&backend, QStringLiteral("y")).error(), Error::PermissionDenied);
        QCOMPARE(verifyAccess(&backend, QStringLiteral("../y")).ok(), false);
        server->failOps.insert(QStringLiteral("remove"), Result(Error::PermissionDenied));
        QCOMPARE(verifyAccess(&backend, QStringLiteral("x")).error(), Error::PermissionDenied);
        server->freeBytes = 10;
        server->failOps.insert(QStringLiteral("freeSpace"), Result(Error::Timeout));
        QCOMPARE(verifyAccess(&backend, QStringLiteral("x")).error(), Error::Timeout);
    }

    void loader()
    {
        qputenv("NETVFS_BACKEND_PATH", QByteArray("/nonexistent:") + NETVFS_TEST_FAKE_BACKEND_DIR);
        QVERIFY(BackendLoader::searchPaths().contains(QStringLiteral(NETVFS_TEST_FAKE_BACKEND_DIR)));
        QVERIFY(BackendLoader::isAvailable(QStringLiteral("fake")));
        QVERIFY(!BackendLoader::isAvailable(QStringLiteral("nosuch")));
        QVERIFY(!BackendLoader::isAvailable(QStringLiteral("../evil")));
        Result r;
        QScopedPointer<Backend> backend(BackendLoader::create(QStringLiteral("fake"), &r));
        QVERIFY(r.ok());
        QVERIFY(backend);
        QVERIFY(!BackendLoader::create(QStringLiteral("nosuch"), &r));
        QCOMPARE(r.error(), Error::Unsupported);
        QVERIFY(!BackendLoader::create(QStringLiteral("nosuch")));
    }

    void keySecrets()
    {
        const QByteArray key("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n");
        const QByteArray secret = encodeKeySecret(key);
        QVERIFY(secret.startsWith("netvfs-key-v1:"));
        QVERIFY(!secret.contains('\n'));   // A-4: single line
        QVERIFY(isKeySecret(secret));
        QVERIFY(!isKeySecret("hunter2"));
        QByteArray decoded;
        QVERIFY(decodeKeySecret(secret, &decoded));
        QCOMPARE(decoded, key);
        QVERIFY(decodeKeySecret(secret, nullptr));
        QVERIFY(!decodeKeySecret("hunter2", &decoded));
        QVERIFY(!decodeKeySecret("netvfs-key-v1:", &decoded));
        QVERIFY(!decodeKeySecret("netvfs-key-v1:%%%", &decoded));
        SshKeyMaterial material;
        material.privateKey = key;
        SshKeyMaterial copy = material;
        material.wipe();
        QVERIFY(material.privateKey.isEmpty());
        QCOMPARE(copy.privateKey, key);
    }

    void installAuthorizedKey()
    {
        FakeServer *server = FakeServer::instance();
        FakeBackend backend;
        QVERIFY(establish(&backend, ConnectionParams(), Credentials(QStringLiteral("user"), "secret")).ok());
        const QString line = QStringLiteral("ssh-ed25519 AAAAC3Nza sailfish-backup");

        QVERIFY(NetVfs::installAuthorizedKey(&backend, line).ok());
        QVERIFY(server->nodes.value(QStringLiteral(".ssh")).isDir);
        QCOMPARE(server->fileData(QStringLiteral(".ssh/authorized_keys")), QByteArray("ssh-ed25519 AAAAC3Nza sailfish-backup\n"));
        QVERIFY(server->log.contains(QStringLiteral("rename:.ssh/authorized_keys.part->.ssh/authorized_keys")));

        // Already present (other comment, with options): unchanged.
        server->addFile(QStringLiteral(".ssh/authorized_keys"), "no-pty ssh-ed25519 AAAAC3Nza old comment");
        QVERIFY(NetVfs::installAuthorizedKey(&backend, line).ok());
        QCOMPARE(server->fileData(QStringLiteral(".ssh/authorized_keys")), QByteArray("no-pty ssh-ed25519 AAAAC3Nza old comment"));

        // Appended after existing keys; missing final newline repaired.
        server->addFile(QStringLiteral(".ssh/authorized_keys"), "ssh-rsa AAAAB3 other");
        QVERIFY(NetVfs::installAuthorizedKey(&backend, line).ok());
        QCOMPARE(server->fileData(QStringLiteral(".ssh/authorized_keys")),
                 QByteArray("ssh-rsa AAAAB3 other\nssh-ed25519 AAAAC3Nza sailfish-backup\n"));

        QCOMPARE(NetVfs::installAuthorizedKey(&backend, QStringLiteral("garbage")).error(), Error::Internal);
        QCOMPARE(NetVfs::installAuthorizedKey(&backend, line + QStringLiteral("\nssh-rsa X")).error(), Error::Internal);
        server->failOps.insert(QStringLiteral("makePath"), Result(Error::PermissionDenied));
        QCOMPARE(NetVfs::installAuthorizedKey(&backend, line).error(), Error::PermissionDenied);
        server->failOps.insert(QStringLiteral("stat"), Result(Error::Timeout));
        QCOMPARE(NetVfs::installAuthorizedKey(&backend, line).error(), Error::Timeout);
        server->failOps.insert(QStringLiteral("download"), Result(Error::PermissionDenied));
        QCOMPARE(NetVfs::installAuthorizedKey(&backend, line).error(), Error::PermissionDenied);
    }

    void loaderHasNoKeyToolsWithoutSftp()
    {
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
        if (BackendLoader::isAvailable(QStringLiteral("sftp")))
            QSKIP("an SFTP backend is installed system-wide");
        QVERIFY(!BackendLoader::sshKeyTools());
    }

    void loaderRejectsWrongProviderAndNonPlugins()
    {
        QTemporaryDir dir;
        // A file with the right name that is not a plugin.
        QFile bogus(dir.filePath(QStringLiteral("libnetvfs-bogus.so")));
        QVERIFY(bogus.open(QIODevice::WriteOnly));
        bogus.write("not an ELF file");
        bogus.close();
        // The fake plugin under another provider's name.
        QVERIFY(QFile::copy(QStringLiteral(NETVFS_TEST_FAKE_BACKEND_DIR "/libnetvfs-fake.so"),
                            dir.filePath(QStringLiteral("libnetvfs-other.so"))));
        qputenv("NETVFS_BACKEND_PATH", dir.path().toLocal8Bit());
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("Not a netvfs backend")));
        QVERIFY(!BackendLoader::isAvailable(QStringLiteral("bogus")));
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("reports provider")));
        QVERIFY(!BackendLoader::isAvailable(QStringLiteral("other")));
        qunsetenv("NETVFS_BACKEND_PATH");
        QCOMPARE(BackendLoader::searchPaths().size(), 1);
    }
};

QTEST_GUILESS_MAIN(TestCore)
#include "tst_core.moc"
