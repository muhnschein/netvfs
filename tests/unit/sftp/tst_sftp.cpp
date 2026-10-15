// SPDX-License-Identifier: LGPL-2.1-or-later
// The SFTP plugin of the build tree, through BackendLoader as every consumer
// reaches it: the SSH key tools of its root object (S-6, S-15) and the
// connection failures that need no SSH server (SPEC-sftp 7, C-14, S-2).
#include "backendloader.h"
#include "sshkeys.h"

#include <QtCore/QElapsedTimer>
#include <QtCore/QProcess>
#include <QtCore/QSemaphore>
#include <QtCore/QStandardPaths>
#include <QtCore/QTemporaryDir>
#include <QtCore/QThread>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>
#include <QtTest/QtTest>

#include <atomic>
#include <memory>

using namespace NetVfs;

namespace QTest {
template<>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest

namespace {

const char RsaRefused[] = "RSA keys are not supported; generate a new key, or use an Ed25519 or ECDSA key";
const char LegacyRefused[] = "Keys encrypted in the legacy PEM format are not supported; generate a new key";
const char DsaRefused[] = "DSA keys are not supported; generate a new key, or use an Ed25519 or ECDSA key";
const char NotAKey[] = "The file is not a private key in OpenSSH or PEM format";
const char TooCostly[] = "Opening this key would take too long; protect it with fewer rounds, or generate a new key";

QByteArray wireUint32(quint32 n)
{
    QByteArray out;
    for (int shift = 24; shift >= 0; shift -= 8)
        out.append(static_cast<char>((n >> shift) & 0xff));
    return out;
}

QByteArray wireString(const QByteArray &data)
{
    return wireUint32(static_cast<quint32>(data.size())) + data;
}

// An OpenSSH private key container (PROTOCOL.key) whose first public key
// has the given type; the private section is filler.
QByteArray openSshKeyText(const QByteArray &type)
{
    QByteArray binary("openssh-key-v1", 15);
    binary += wireString("none") + wireString("none") + wireString(QByteArray());
    binary += wireUint32(1) + wireString(wireString(type) + wireString(QByteArray(32, 'k')));
    binary += wireString(QByteArray(64, 'p'));
    QByteArray text("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    const QByteArray base64 = binary.toBase64();
    for (int i = 0; i < base64.size(); i += 70)
        text += base64.mid(i, 70) + '\n';
    return text + "-----END OPENSSH PRIVATE KEY-----\n";
}

// A TCP peer on 127.0.0.1, in its own thread, that accepts one connection,
// sends `greeting` and then reads until the client goes away.
class ScriptedPeer : public QThread
{
public:
    explicit ScriptedPeer(const QByteArray &greeting) : m_greeting(greeting)
    {
        start();
        m_ready.acquire();
    }
    ScriptedPeer(const ScriptedPeer &) = delete;
    ScriptedPeer &operator=(const ScriptedPeer &) = delete;
    ~ScriptedPeer() override
    {
        m_stop = true;
        wait();
    }

    int port() const { return m_port; }

protected:
    void run() override
    {
        QTcpServer server;
        server.listen(QHostAddress::LocalHost);
        m_port = server.serverPort();
        m_ready.release();
        while (!m_stop && !server.waitForNewConnection(100)) {
        }
        const std::unique_ptr<QTcpSocket> connection(server.nextPendingConnection());
        if (!connection)
            return;
        connection->write(m_greeting);
        connection->waitForBytesWritten(1000);
        while (!m_stop && connection->state() == QAbstractSocket::ConnectedState) {
            if (connection->waitForReadyRead(100))
                connection->readAll();
        }
    }

private:
    QByteArray m_greeting;
    QSemaphore m_ready;
    std::atomic<int> m_port { 0 };
    std::atomic<bool> m_stop { false };
};

// Banner plus a KEXINIT whose key exchange no client supports.
QByteArray unsupportedKexGreeting()
{
    QByteArray payload(1, '\x14');   // SSH_MSG_KEXINIT
    payload += QByteArray(16, '\x2a');
    const QList<QByteArray> lists = { "frobnicate-kex@example.org", "ssh-ed25519", "aes128-ctr", "aes128-ctr",
                                      "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", "" };
    for (const QByteArray &list : lists)
        payload += wireString(list);
    payload += QByteArray(1, '\0') + wireUint32(0);
    int padding = 8 - ((5 + payload.size()) % 8);
    if (padding < 4)
        padding += 8;
    QByteArray packet = wireUint32(static_cast<quint32>(1 + payload.size() + padding));
    packet += static_cast<char>(padding);
    packet += payload + QByteArray(padding, '\0');
    return QByteArray("SSH-2.0-ScriptedPeer\r\n") + packet;
}

ConnectionParams localParams(int port)
{
    ConnectionParams params;
    params.provider = QStringLiteral("sftp");
    params.host = QStringLiteral("127.0.0.1");
    params.port = port;
    params.username = QStringLiteral("nobody");
    params.connectTimeoutMs = 3000;
    return params;
}

} // namespace

class TestSftp : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;
    SshKeyTools *m_tools = nullptr;

    // Runs a tool from the host (ssh-keygen, openssl); false if it is absent or fails.
    bool tool(const QString &program, const QStringList &arguments, QByteArray *output = nullptr)
    {
        if (QStandardPaths::findExecutable(program).isEmpty())
            return false;
        QProcess process;
        process.setWorkingDirectory(m_dir.path());
        process.start(program, arguments);
        if (!process.waitForFinished(60000) || process.exitCode() != 0) {
            qWarning() << program << arguments << process.readAllStandardError();
            return false;
        }
        if (output)
            *output = process.readAllStandardOutput();
        return true;
    }

    static bool installed(const char *program)
    {
        return !QStandardPaths::findExecutable(QString::fromLatin1(program)).isEmpty();
    }

    // A new key file of ssh-keygen (and its .pub); false when ssh-keygen
    // fails (callers skip only when it is not installed).
    bool keygen(const QString &name, const QStringList &arguments, const QByteArray &passphrase)
    {
        QFile::remove(m_dir.filePath(name));
        QFile::remove(m_dir.filePath(name + QStringLiteral(".pub")));
        return tool(QStringLiteral("ssh-keygen"),
                    arguments + QStringList { QStringLiteral("-q"), QStringLiteral("-N"), QString::fromLatin1(passphrase),
                                              QStringLiteral("-C"), QStringLiteral("test"), QStringLiteral("-f"),
                                              m_dir.filePath(name) });
    }

    QByteArray file(const QString &name) const
    {
        QFile f(m_dir.filePath(name));
        return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
    }

    void writeFile(const QString &name, const QByteArray &data) const
    {
        QFile f(m_dir.filePath(name));
        QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
        f.write(data);
    }

    // "SHA256:..." of a key file as printed by ssh-keygen -lf.
    QString keygenFingerprint(const QString &name)
    {
        QByteArray out;
        if (!tool(QStringLiteral("ssh-keygen"), { QStringLiteral("-l"), QStringLiteral("-E"), QStringLiteral("sha256"),
                                                 QStringLiteral("-f"), m_dir.filePath(name) }, &out))
            return QString();
        return QString::fromLatin1(out.split(' ').value(1));
    }

    // The public key ssh-keygen derives from a private key file.
    QByteArray keygenPublic(const QString &name)
    {
        QByteArray out;
        QFile::setPermissions(m_dir.filePath(name), QFile::ReadOwner | QFile::WriteOwner);
        if (!tool(QStringLiteral("ssh-keygen"), { QStringLiteral("-y"), QStringLiteral("-f"), m_dir.filePath(name) }, &out))
            return QByteArray();
        return out.trimmed().split(' ').mid(0, 2).join(' ');
    }

    std::unique_ptr<Backend> backend() const
    {
        return std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
    }

private slots:
    void initTestCase()
    {
        QVERIFY(m_dir.isValid());
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_BACKEND_DIR);
        qputenv("NETVFS_RS_LIB", NETVFS_TEST_RS_RELEASE_LIB);
        m_tools = BackendLoader::sshKeyTools();
        QVERIFY(m_tools);
    }

    // --- SSH key tools (plugin root object) --------------------------------

    void generate()
    {
        SshKeyMaterial first;
        QVERIFY(m_tools->generate(&first).ok());
        QCOMPARE(first.algorithm, QStringLiteral("ssh-ed25519"));
        QVERIFY(first.privateKey.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        QVERIFY(first.publicLine.startsWith(QLatin1String("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")));
        QVERIFY(first.publicLine.endsWith(QLatin1String(" sailfish-backup")));
        QCOMPARE(first.publicLine.split(QLatin1Char(' ')).size(), 3);
        QVERIFY(first.fingerprint.startsWith(QLatin1String("SHA256:")));
        QCOMPARE(first.fingerprint.size(), 50);

        SshKeyMaterial second;
        QVERIFY(m_tools->generate(&second).ok());
        QVERIFY(first.publicLine != second.publicLine);
        QVERIFY(first.privateKey != second.privateKey);

        SshKeyMaterial described;
        QVERIFY(m_tools->describe(first.privateKey, &described).ok());
        QCOMPARE(described.privateKey, first.privateKey);
        QCOMPARE(described.publicLine, first.publicLine);
        QCOMPARE(described.fingerprint, first.fingerprint);
        QCOMPARE(described.algorithm, first.algorithm);
        QVERIFY(m_tools->generate(nullptr).ok());

        // S-6: the fingerprint is the one ssh-keygen prints; ssh-keygen reads
        // the exported private key, which is not encrypted (stored in signond).
        writeFile(QStringLiteral("generated.pub"), first.publicLine.toLatin1() + '\n');
        writeFile(QStringLiteral("generated"), first.privateKey);
        if (!installed("ssh-keygen"))
            QSKIP("ssh-keygen is not installed");
        QCOMPARE(first.fingerprint, keygenFingerprint(QStringLiteral("generated.pub")));
        QCOMPARE(keygenPublic(QStringLiteral("generated")), first.publicLine.toLatin1().split(' ').mid(0, 2).join(' '));
    }

    void importKeys_data()
    {
        QTest::addColumn<QStringList>("keygen");
        QTest::addColumn<QString>("algorithm");
        QTest::addColumn<QByteArray>("passphrase");
        QTest::newRow("ed25519") << QStringList { "-t", "ed25519" } << "ssh-ed25519" << QByteArray();
        QTest::newRow("ed25519 passphrase") << QStringList { "-t", "ed25519" } << "ssh-ed25519"
                                            << QByteArray("correct horse");
        QTest::newRow("ecdsa p256") << QStringList { "-t", "ecdsa", "-b", "256" } << "ecdsa-sha2-nistp256"
                                    << QByteArray();
        QTest::newRow("ecdsa p384 pem") << QStringList { "-t", "ecdsa", "-b", "384", "-m", "PEM" }
                                        << "ecdsa-sha2-nistp384" << QByteArray();
        QTest::newRow("ecdsa p521 pkcs8") << QStringList { "-t", "ecdsa", "-b", "521", "-m", "PKCS8" }
                                          << "ecdsa-sha2-nistp521" << QByteArray();
        QTest::newRow("ecdsa p256 pkcs8 passphrase") << QStringList { "-t", "ecdsa", "-b", "256", "-m", "PKCS8" }
                                                     << "ecdsa-sha2-nistp256" << QByteArray("battery staple");
    }

    void importKeys()
    {
        QFETCH(QStringList, keygen);
        QFETCH(QString, algorithm);
        QFETCH(QByteArray, passphrase);
        const QString name = QStringLiteral("key-%1").arg(QString::fromLatin1(QTest::currentDataTag()).replace(' ', '-'));
        if (!installed("ssh-keygen"))
            QSKIP("ssh-keygen is not installed");
        QVERIFY(this->keygen(name, keygen, passphrase));
        const QByteArray contents = file(name);

        SshKeyMaterial key;
        Result r = m_tools->importKey(contents, passphrase, &key);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(key.algorithm, algorithm);
        QCOMPARE(key.fingerprint, keygenFingerprint(name + QStringLiteral(".pub")));
        QVERIFY(key.publicLine.endsWith(QLatin1String(" sailfish-backup")));
        QCOMPARE(key.publicLine.split(QLatin1Char(' ')).value(1).toLatin1(),
                 file(name + QStringLiteral(".pub")).split(' ').value(1));
        // Re-exported unencrypted in OpenSSH format, which ssh-keygen reads.
        QVERIFY(key.privateKey.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        writeFile(name + QStringLiteral(".exported"), key.privateKey);
        QCOMPARE(keygenPublic(name + QStringLiteral(".exported")), key.publicLine.toLatin1().split(' ').mid(0, 2).join(' '));
        SshKeyMaterial again;
        QVERIFY(m_tools->describe(key.privateKey, &again).ok());
        QCOMPARE(again.publicLine, key.publicLine);
        QCOMPARE(again.fingerprint, key.fingerprint);

        if (!passphrase.isEmpty()) {
            r = m_tools->importKey(contents, QByteArray(), &again);
            QCOMPARE(r.error(), Error::AuthFailed);
            QCOMPARE(r.message(), QStringLiteral("The key is protected by a passphrase"));
            r = m_tools->importKey(contents, "wrong", &again);
            QCOMPARE(r.error(), Error::AuthFailed);
            QCOMPARE(r.message(), QStringLiteral("The passphrase is not correct"));
            QCOMPARE(m_tools->describe(contents, &again).error(), Error::AuthFailed);
        }
    }

    // S-15: what the hardened subset refuses, with the fix in the message.
    void refusedKeyFiles_data()
    {
        QTest::addColumn<QStringList>("keygen");
        QTest::addColumn<QByteArray>("passphrase");
        QTest::addColumn<QString>("message");
        QTest::newRow("rsa 3072 pem") << QStringList { "-t", "rsa", "-b", "3072", "-m", "PEM" } << QByteArray()
                                      << RsaRefused;
        QTest::newRow("rsa 2048 openssh") << QStringList { "-t", "rsa", "-b", "2048" } << QByteArray() << RsaRefused;
        QTest::newRow("rsa pkcs8") << QStringList { "-t", "rsa", "-b", "2048", "-m", "PKCS8" } << QByteArray()
                                   << RsaRefused;
        // ssh-keygen wants five characters at least.
        QTest::newRow("rsa openssh passphrase") << QStringList { "-t", "rsa", "-b", "2048" } << QByteArray("passphrase")
                                                << RsaRefused;
        QTest::newRow("ecdsa legacy pem passphrase") << QStringList { "-t", "ecdsa", "-b", "256", "-m", "PEM" }
                                                     << QByteArray("passphrase") << LegacyRefused;
    }

    void refusedKeyFiles()
    {
        QFETCH(QStringList, keygen);
        QFETCH(QByteArray, passphrase);
        QFETCH(QString, message);
        const QString name = QStringLiteral("refused-%1").arg(QString::fromLatin1(QTest::currentDataTag()).replace(' ', '-'));
        if (!installed("ssh-keygen"))
            QSKIP("ssh-keygen is not installed");
        QVERIFY(this->keygen(name, keygen, passphrase));
        const QByteArray contents = file(name);
        // Refused before (and without) the passphrase, and with it.
        for (const QByteArray &given : { QByteArray(), passphrase, QByteArray("wrong") }) {
            SshKeyMaterial key;
            const Result r = m_tools->importKey(contents, given, &key);
            QCOMPARE(r.error(), Error::Unsupported);
            QCOMPARE(r.message(), message);
            QVERIFY(key.privateKey.isEmpty());
            QVERIFY(key.algorithm.isEmpty());
        }
        QCOMPARE(m_tools->describe(contents, nullptr).message(), message);
    }

    // A key whose passphrase protection would take too long to open is
    // refused before any key derivation runs, whatever the passphrase (the
    // right one is correct-horse).
    void costlyKeys_data()
    {
        QTest::addColumn<QString>("fixture");
        QTest::newRow("bcrypt 1025 rounds") << "ed25519-openssh-rounds1025";
        QTest::newRow("pbkdf2 1000001 iterations") << "ecdsa256-pkcs8-iter1000001";
        QTest::newRow("scrypt p 5") << "ecdsa256-pkcs8-scrypt-p5";
    }

    void costlyKeys()
    {
        QFETCH(QString, fixture);
        QFile f(QStringLiteral(NETVFS_TEST_KEY_FIXTURES "/") + fixture);
        QVERIFY(f.open(QIODevice::ReadOnly));
        const QByteArray contents = f.readAll();
        for (const QByteArray &given : { QByteArray("correct-horse"), QByteArray(), QByteArray("wrong") }) {
            SshKeyMaterial key;
            const Result r = m_tools->importKey(contents, given, &key);
            QCOMPARE(r.error(), Error::Unsupported);
            QCOMPARE(r.message(), QString::fromLatin1(TooCostly));
            QVERIFY(key.privateKey.isEmpty());
        }
    }

    void rejectedKeys()
    {
        SshKeyMaterial key;
        if (!tool(QStringLiteral("openssl"), { QStringLiteral("dsaparam"), QStringLiteral("-genkey"),
                                              QStringLiteral("-noout"), QStringLiteral("-out"),
                                              QStringLiteral("dsa.pem"), QStringLiteral("1024") }))
            QSKIP("openssl is not installed");
        Result r = m_tools->importKey(file(QStringLiteral("dsa.pem")), QByteArray(), &key);   // PKCS#8
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.message(), QString::fromLatin1(DsaRefused));
        QVERIFY(tool(QStringLiteral("openssl"), { QStringLiteral("dsa"),
                                                 QStringLiteral("-in"), QStringLiteral("dsa.pem"),
                                                 QStringLiteral("-out"), QStringLiteral("dsa-traditional.pem") }));
        r = m_tools->importKey(file(QStringLiteral("dsa-traditional.pem")), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.message(), QString::fromLatin1(DsaRefused));
        QVERIFY(tool(QStringLiteral("openssl"), { QStringLiteral("genrsa"), QStringLiteral("-traditional"),
                                                 QStringLiteral("-out"), QStringLiteral("small.pem"), QStringLiteral("768") }));
        r = m_tools->importKey(file(QStringLiteral("small.pem")), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.message(), QString::fromLatin1(RsaRefused));
        // A PKCS#8 key of another type: named by its OID.
        QVERIFY(tool(QStringLiteral("openssl"), { QStringLiteral("genpkey"), QStringLiteral("-algorithm"),
                                                 QStringLiteral("ed448"), QStringLiteral("-out"),
                                                 QStringLiteral("ed448.pem") }));
        r = m_tools->importKey(file(QStringLiteral("ed448.pem")), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.message(), QStringLiteral("Key type 1.3.101.113 is not supported; generate a new key, or use an "
                                             "Ed25519 or ECDSA key"));

        QFile::remove(m_dir.filePath(QStringLiteral("ca")));
        QFile::remove(m_dir.filePath(QStringLiteral("user")));
        QVERIFY(keygen(QStringLiteral("ca"), { QStringLiteral("-t"), QStringLiteral("ed25519") }, QByteArray()));
        QVERIFY(keygen(QStringLiteral("user"), { QStringLiteral("-t"), QStringLiteral("ed25519") }, QByteArray()));
        QVERIFY(tool(QStringLiteral("ssh-keygen"), { QStringLiteral("-q"), QStringLiteral("-s"),
                                                    m_dir.filePath(QStringLiteral("ca")), QStringLiteral("-I"),
                                                    QStringLiteral("id"), m_dir.filePath(QStringLiteral("user.pub")) }));
        r = m_tools->importKey(file(QStringLiteral("user-cert.pub")), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.message(), QStringLiteral("SSH certificates are not supported; choose a private key file"));
        r = m_tools->importKey(file(QStringLiteral("user.pub")), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.message(), QStringLiteral("This is a public key; choose the private key file"));

        // Looks like a key, but is none.
        r = m_tools->importKey(openSshKeyText("ssh-ed25519"), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        r = m_tools->describe("not a key", &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.message(), QString::fromLatin1(NotAKey));
        QCOMPARE(m_tools->importKey(QByteArray(), QByteArray(), &key).message(), QString::fromLatin1(NotAKey));
        QVERIFY(key.privateKey.isEmpty());
    }

    // --- backend failures without a server ---------------------------------

    void plugin()
    {
        QVERIFY(BackendLoader::isAvailable(QStringLiteral("sftp")));
        QVERIFY(backend());
    }

    void notSignedIn()
    {
        auto b = backend();
        Entry entry;
        QVector<Entry> entries;
        qint64 bytes = 0;
        QByteArray data;
        QCOMPARE(b->stat(QStringLiteral("x"), &entry).error(), Error::Internal);
        QCOMPARE(b->lstat(QStringLiteral("x"), &entry).error(), Error::Internal);
        QCOMPARE(b->list(QStringLiteral("x"), &entries).error(), Error::Internal);
        QCOMPARE(b->makePath(QStringLiteral("x")).error(), Error::Internal);
        QCOMPARE(b->makeDir(QStringLiteral("x"), true).error(), Error::Internal);
        QCOMPARE(b->remove(QStringLiteral("x")).error(), Error::Internal);
        QCOMPARE(b->removeDir(QStringLiteral("x")).error(), Error::Internal);
        QCOMPARE(b->rename(QStringLiteral("x"), QStringLiteral("y"), RenameMode::Replace).error(), Error::Internal);
        QCOMPARE(b->rename(QStringLiteral("x"), QStringLiteral("y"), RenameMode::NoReplace).error(), Error::Internal);
        QCOMPARE(b->freeSpace(QStringLiteral("x"), &bytes).error(), Error::Internal);
        QCOMPARE(b->read(QStringLiteral("x"), 0, 1, &data).error(), Error::Internal);
        QCOMPARE(b->keepAlive().error(), Error::Internal);
        QVERIFY(b->capabilities().flags.isEmpty());   // XC-5: valid after authenticate()
        QCOMPARE(b->setAttributes(QStringLiteral("x"), AttributeChanges()).error(), Error::Internal);
        QString target;
        QCOMPARE(b->readLink(QStringLiteral("x"), &target).error(), Error::Internal);
        QCOMPARE(b->makeSymlink(QStringLiteral("x"), QStringLiteral("y")).error(), Error::Internal);
        QCOMPARE(b->makeHardlink(QStringLiteral("x"), QStringLiteral("y")).error(), Error::Internal);
        WriteHandle *writer = nullptr;
        QCOMPARE(b->openWrite(QStringLiteral("x"), WriteOptions(), &writer).error(), Error::Internal);
        QVERIFY(!writer);
        ReadHandle *reader = nullptr;
        QCOMPARE(b->openRead(QStringLiteral("x"), &reader).error(), Error::Internal);
        QVERIFY(!reader);
        QCOMPARE(b->copy(QStringLiteral("x"), QStringLiteral("y"), CopyOptions()).error(), Error::Internal);
        // Checksums are computed locally (SFTP reports no Checksums).
        QCOMPARE(b->checksum(QStringLiteral("x"), QStringLiteral("sha256"), &data).error(), Error::Unsupported);
        SpaceInfo space;
        QCOMPARE(b->spaceInfo(QStringLiteral("x"), &space).error(), Error::Internal);
        QCOMPARE(b->authenticate(Credentials(QStringLiteral("u"), "p")).error(), Error::Internal);
        b->disconnect();
    }

    void invalidHost()
    {
        auto b = backend();
        ServerIdentity seen;
        ConnectionParams params = localParams(22);
        params.host = QStringLiteral("root@example.org");
        Result r = b->connect(params, &seen);
        QCOMPARE(r.error(), Error::Internal);
        QCOMPARE(r.message(), QStringLiteral("Invalid server name"));
        params.host.clear();
        QCOMPARE(b->connect(params, &seen).error(), Error::Internal);
        params = localParams(65536);
        r = b->connect(params, &seen);
        QCOMPARE(r.error(), Error::Internal);
        QCOMPARE(r.message(), QStringLiteral("Invalid port 65536"));
    }

    void refused()
    {
        int port = 0;
        {
            QTcpServer closed;
            QVERIFY(closed.listen(QHostAddress::LocalHost));
            port = closed.serverPort();
        }
        auto b = backend();
        ServerIdentity seen;
        const Result r = b->connect(localParams(port), &seen);
        QCOMPARE(r.error(), Error::NetworkUnreachable);
        QCOMPARE(r.message(), QStringLiteral("Cannot connect to 127.0.0.1 port %1").arg(port));
        QVERIFY(seen.isEmpty());
    }

    void unresolvable()
    {
        auto b = backend();
        ConnectionParams params = localParams(22);
        params.host = QStringLiteral("no-such-host.invalid");
        const Result r = b->connect(params, nullptr);
        QCOMPARE(r.error(), Error::NetworkUnreachable);
        QCOMPARE(r.message(), QStringLiteral("Cannot find the server no-such-host.invalid"));
    }

    void timeout()
    {
        // C-14: the connect timeout applies while waiting for the banner.
        QTcpServer silent;   // listens, never accepts or answers
        QVERIFY(silent.listen(QHostAddress::LocalHost));
        auto b = backend();
        ConnectionParams params = localParams(silent.serverPort());
        params.connectTimeoutMs = 1000;
        QElapsedTimer timer;
        timer.start();
        const Result r = b->connect(params, nullptr);
        QCOMPARE(r.error(), Error::Timeout);
        QVERIFY2(timer.elapsed() >= 900 && timer.elapsed() < 5000, qPrintable(QString::number(timer.elapsed())));
    }

    void noCommonAlgorithm()
    {
        // S-2: no common algorithm is SecurityPolicy, naming the list and
        // what the server offers.
        const ScriptedPeer peer(unsupportedKexGreeting());
        auto b = backend();
        const Result r = b->connect(localParams(peer.port()), nullptr);
        QVERIFY2(r.error() == Error::SecurityPolicy, qPrintable(r.toString()));
        QCOMPARE(r.message(), QStringLiteral("The server offers no key exchange algorithm this app accepts "
                                             "(it offers frobnicate-kex@example.org)"));
    }

    void peerHangsUp()
    {
        const ScriptedPeer peer(QByteArray("SSH-2.0-ScriptedPeer\r\n"));
        auto b = backend();
        ConnectionParams params = localParams(peer.port());
        params.connectTimeoutMs = 2000;
        const Result r = b->connect(params, nullptr);
        QVERIFY(!r.ok());
        QVERIFY2(r.error() == Error::NetworkUnreachable || r.error() == Error::Timeout, qPrintable(r.toString()));
    }

    void canceledBeforeConnect()
    {
        auto b = backend();
        b->cancel();
        QCOMPARE(b->connect(localParams(1), nullptr).error(), Error::Canceled);
        b->resetCancel();
        QVERIFY(b->connect(localParams(1), nullptr).error() != Error::Canceled);
    }
};

QTEST_GUILESS_MAIN(TestSftp)

#include "tst_sftp.moc"
