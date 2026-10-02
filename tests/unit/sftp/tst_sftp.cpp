// SPDX-License-Identifier: LGPL-2.1-or-later
// SFTP backend behaviour that needs no SSH server (SPEC-sftp 2, 3, 5.1, 7).
#include "backendloader.h"
#include "sftpsupport.h"
#include "sshkeys.h"

#include <libssh/libssh.h>
#include <libssh/sftp.h>

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
using namespace NetVfs::Sftp;

Q_DECLARE_METATYPE(NetVfs::Error)

namespace {

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
QByteArray openSshKeyText(const QByteArray &cipher, const QByteArray &type)
{
    QByteArray binary("openssh-key-v1", 15);
    binary += wireString(cipher) + wireString(cipher == "none" ? "none" : "bcrypt") + wireString(QByteArray());
    binary += wireUint32(1) + wireString(wireString(type) + wireString(QByteArray(32, 'k')));
    binary += wireString(QByteArray(64, 'p'));
    QByteArray text("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    const QByteArray base64 = binary.toBase64();
    for (int i = 0; i < base64.size(); i += 70)
        text += base64.mid(i, 70) + '\n';
    return text + "-----END OPENSSH PRIVATE KEY-----\n";
}

QByteArray rsaBlob(const QByteArray &modulus)
{
    return wireString("ssh-rsa") + wireString(QByteArray("\x01\x00\x01", 3)) + wireString(modulus);
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

    // Runs a tool from the host (ssh-keygen, openssl); skips the test if absent.
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

    std::unique_ptr<Backend> backend() const
    {
        return std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
    }

private slots:
    void initTestCase()
    {
        QVERIFY(m_dir.isValid());
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_BACKEND_DIR);
        m_tools = BackendLoader::sshKeyTools();
        QVERIFY(m_tools);
    }

    // --- policy helpers ----------------------------------------------------

    void hostKeyAlgorithms_data()
    {
        QTest::addColumn<QString>("pinned");
        QTest::addColumn<QByteArray>("requested");
        QTest::newRow("ed25519") << "ssh-ed25519" << QByteArray("ssh-ed25519");
        QTest::newRow("p256") << "ecdsa-sha2-nistp256" << QByteArray("ecdsa-sha2-nistp256");
        QTest::newRow("p384") << "ecdsa-sha2-nistp384" << QByteArray("ecdsa-sha2-nistp384");
        QTest::newRow("p521") << "ecdsa-sha2-nistp521" << QByteArray("ecdsa-sha2-nistp521");
        QTest::newRow("rsa") << "ssh-rsa" << QByteArray("rsa-sha2-512,rsa-sha2-256");
        QTest::newRow("unknown") << "ssh-dss" << QByteArray();
        QTest::newRow("empty") << "" << QByteArray();
    }

    void hostKeyAlgorithms()
    {
        QFETCH(QString, pinned);
        QFETCH(QByteArray, requested);
        QCOMPARE(hostKeyAlgorithmsFor(pinned), requested);   // S-5
    }

    void chunkSizes()
    {
        // S-21
        QCOMPARE(chunkSize(true, 261120), size_t(261120));
        QCOMPARE(chunkSize(true, 262144), size_t(262144));
        QCOMPARE(chunkSize(true, 1024 * 1024), size_t(256 * 1024));
        QCOMPARE(chunkSize(false, 1024 * 1024), size_t(32 * 1024));
        QCOMPARE(chunkSize(true, 0), size_t(32 * 1024));
        QCOMPARE(RequestWindow, size_t(16));
    }

    void connectFailures_data()
    {
        QTest::addColumn<QString>("message");
        QTest::addColumn<NetVfs::Error>("error");
        QTest::newRow("kex") << "kex error : no match for method kex algos: server [x], client [y]"
                             << Error::SecurityPolicy;
        QTest::newRow("hostkey") << "kex error : no match for method server host key algo: server [a], client [b]"
                                 << Error::SecurityPolicy;
        QTest::newRow("timeout") << "Timeout connecting to example.org" << Error::Timeout;
        QTest::newRow("timed out") << "Socket error: connection timed out" << Error::Timeout;
        QTest::newRow("refused") << "Connection refused" << Error::NetworkUnreachable;
        QTest::newRow("unreachable") << "Network is unreachable" << Error::NetworkUnreachable;
        QTest::newRow("no route") << "No route to host" << Error::NetworkUnreachable;
        QTest::newRow("resolve") << "Failed to resolve hostname x (y): z" << Error::NetworkUnreachable;
        QTest::newRow("socket") << "Socket error: disconnected" << Error::NetworkUnreachable;
        QTest::newRow("reset") << "Connection reset by peer" << Error::NetworkUnreachable;
        QTest::newRow("eof") << "Received EOF while reading sftp packet size" << Error::NetworkUnreachable;
        QTest::newRow("other") << "Protocol mismatch: HTTP/1.1" << Error::ProtocolError;
    }

    void connectFailures()
    {
        QFETCH(QString, message);
        QFETCH(NetVfs::Error, error);
        const Result r = connectFailure(message);
        QCOMPARE(r.error(), error);
        QVERIFY(r.message().contains(message));
    }

    void hostKeyMismatch()
    {
        QVERIFY(isHostKeyMismatch(QStringLiteral("kex error : no match for method server host key algo: server [a]")));
        QVERIFY(!isHostKeyMismatch(QStringLiteral("kex error : no match for method kex algos: server [a]")));
    }

    void sftpStatuses_data()
    {
        QTest::addColumn<int>("status");
        QTest::addColumn<QString>("message");
        QTest::addColumn<NetVfs::Error>("error");
        QTest::newRow("no such file") << SSH_FX_NO_SUCH_FILE << "" << Error::NotFound;
        QTest::newRow("no such path") << SSH_FX_NO_SUCH_PATH << "" << Error::NotFound;
        QTest::newRow("permission") << SSH_FX_PERMISSION_DENIED << "" << Error::PermissionDenied;
        QTest::newRow("write protect") << SSH_FX_WRITE_PROTECT << "" << Error::PermissionDenied;
        QTest::newRow("exists") << SSH_FX_FILE_ALREADY_EXISTS << "" << Error::AlreadyExists;
        QTest::newRow("unsupported") << SSH_FX_OP_UNSUPPORTED << "" << Error::Unsupported;
        QTest::newRow("lost") << SSH_FX_CONNECTION_LOST << "gone" << Error::NetworkUnreachable;
        QTest::newRow("no connection") << SSH_FX_NO_CONNECTION << "gone" << Error::NetworkUnreachable;
        QTest::newRow("timeout") << SSH_FX_FAILURE << "Timeout while reading sftp packet size" << Error::Timeout;
        QTest::newRow("failure") << SSH_FX_FAILURE << "SFTP server: Failure" << Error::ProtocolError;
        QTest::newRow("bad message") << SSH_FX_BAD_MESSAGE << "SFTP server: Bad message" << Error::ProtocolError;
    }

    void sftpStatuses()
    {
        QFETCH(int, status);
        QFETCH(QString, message);
        QFETCH(NetVfs::Error, error);
        const Result r = sftpStatusFailure(status, message, QStringLiteral("dir/file"));
        QCOMPARE(r.error(), error);
        QVERIFY(r.message().startsWith(QLatin1String("dir/file")));
        if (error == Error::ProtocolError)
            QVERIFY(r.message().contains(message));   // "with the server's message"
    }

    void subsystem()
    {
        Result r = subsystemFailure(true, SSH_FX_OK, QStringLiteral("Channel request subsystem failed"));
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.message(), QStringLiteral("SFTP is not enabled for this user"));
        QCOMPARE(subsystemFailure(false, SSH_FX_EOF, QString()).error(), Error::Unsupported);
        r = subsystemFailure(false, SSH_FX_FAILURE, QStringLiteral("Socket error: disconnected"));
        QCOMPARE(r.error(), Error::NetworkUnreachable);
    }

    void fullDisk()
    {
        QVERIFY(looksLikeFullDisk(SSH_FX_FAILURE, 0, 1));
        QVERIFY(looksLikeFullDisk(SSH_FX_FAILURE, 4095, 4096));
        QVERIFY(!looksLikeFullDisk(SSH_FX_FAILURE, 4096, 4096));
        QVERIFY(!looksLikeFullDisk(SSH_FX_FAILURE, -1, 4096));
        QVERIFY(!looksLikeFullDisk(SSH_FX_PERMISSION_DENIED, 0, 4096));
    }

    void acceptedMethods()
    {
        // S-14
        Result r = authDenied(SSH_AUTH_METHOD_PUBLICKEY);
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY(r.message().contains(QLatin1String("only accepts SSH keys")));
        QVERIFY(r.message().contains(QLatin1String("publickey")));
        r = authDenied(SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE
                       | SSH_AUTH_METHOD_HOSTBASED | SSH_AUTH_METHOD_GSSAPI_MIC);
        QVERIFY(r.message().contains(
            QLatin1String("publickey, password, keyboard-interactive, hostbased, gssapi-with-mic.")));
        QVERIFY(authDenied(SSH_AUTH_METHOD_PASSWORD).message().endsWith(QLatin1String("accepts: password.")));
        QVERIFY(authDenied(0).message().contains(QLatin1String("no sign-in method")));
        QCOMPARE(authPartial().error(), Error::AuthFailed);   // S-13
        QVERIFY(authPartial().message().contains(QLatin1String("second sign-in step")));
        QCOMPARE(interactiveNotSupported().error(), Error::AuthFailed);   // S-11
        QVERIFY(interactiveNotSupported().message().contains(QLatin1String("interactive sign-in")));
    }

    void secretForMode()
    {
        const QByteArray key = encodeKeySecret("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        QVERIFY(checkSecretForMode(QStringLiteral("password"), "hunter2").ok());
        QVERIFY(checkSecretForMode(QStringLiteral("password"), QByteArray()).ok());
        // Never send a private key as a password.
        QCOMPARE(checkSecretForMode(QStringLiteral("password"), key).error(), Error::AuthFailed);
        QVERIFY(checkSecretForMode(QStringLiteral("publickey"), key).ok());
        QCOMPARE(checkSecretForMode(QStringLiteral("publickey"), "hunter2").error(), Error::AuthFailed);
        QCOMPARE(checkSecretForMode(QStringLiteral("publickey"), "netvfs-key-v1:%%%").error(), Error::AuthFailed);
        QCOMPARE(checkSecretForMode(QStringLiteral("kerberos"), "x").error(), Error::Internal);
    }

    void keyFiles_data()
    {
        QTest::addColumn<QByteArray>("contents");
        QTest::addColumn<int>("format");
        QTest::addColumn<bool>("encrypted");
        QTest::addColumn<QString>("type");
        QTest::addColumn<QString>("rejection");   // empty: accepted by checkKeyFile
        QTest::newRow("openssh ed25519") << openSshKeyText("none", "ssh-ed25519") << int(KeyFileInfo::OpenSsh)
                                         << false << "ssh-ed25519" << "";
        QTest::newRow("openssh encrypted") << openSshKeyText("aes256-ctr", "ssh-rsa") << int(KeyFileInfo::OpenSsh)
                                           << true << "ssh-rsa" << "";
        QTest::newRow("openssh dsa") << openSshKeyText("none", "ssh-dss") << int(KeyFileInfo::OpenSsh) << false
                                     << "ssh-dss" << "DSA keys";
        QTest::newRow("openssh sk") << openSshKeyText("none", "sk-ssh-ed25519@openssh.com")
                                    << int(KeyFileInfo::OpenSsh) << false << "sk-ssh-ed25519@openssh.com"
                                    << "Security-key";
        QTest::newRow("openssh sk ecdsa") << openSshKeyText("none", "sk-ecdsa-sha2-nistp256@openssh.com")
                                          << int(KeyFileInfo::OpenSsh) << false
                                          << "sk-ecdsa-sha2-nistp256@openssh.com" << "Security-key";
        QTest::newRow("openssh cert") << openSshKeyText("none", "ssh-ed25519-cert-v01@openssh.com")
                                      << int(KeyFileInfo::OpenSsh) << false << "ssh-ed25519-cert-v01@openssh.com"
                                      << "certificates";
        QTest::newRow("openssh truncated")
            << QByteArray("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n")
            << int(KeyFileInfo::Unknown) << false << "" << "not a private key";
        QTest::newRow("pem rsa") << QByteArray("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
                                 << int(KeyFileInfo::Pem) << false << "ssh-rsa" << "";
        QTest::newRow("pem rsa encrypted")
            << QByteArray("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n")
            << int(KeyFileInfo::Pem) << true << "ssh-rsa" << "";
        QTest::newRow("pem ec") << QByteArray("-----BEGIN EC PRIVATE KEY-----\nAAAA\n") << int(KeyFileInfo::Pem)
                                << false << "ecdsa" << "";
        QTest::newRow("pem dsa") << QByteArray("-----BEGIN DSA PRIVATE KEY-----\nAAAA\n") << int(KeyFileInfo::Pem)
                                 << false << "ssh-dss" << "DSA keys";
        QTest::newRow("pkcs8") << QByteArray("-----BEGIN PRIVATE KEY-----\nAAAA\n") << int(KeyFileInfo::Pem) << false
                               << "" << "";
        QTest::newRow("pkcs8 encrypted") << QByteArray("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n")
                                         << int(KeyFileInfo::Pem) << true << "" << "";
        QTest::newRow("public key") << QByteArray("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== me@host\n")
                                    << int(KeyFileInfo::PublicKey) << false << "ssh-ed25519" << "public key";
        QTest::newRow("certificate") << QByteArray("ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5 me\n")
                                     << int(KeyFileInfo::PublicKey) << false << "ssh-ed25519-cert-v01@openssh.com"
                                     << "certificates";
        QTest::newRow("garbage") << QByteArray("hello world") << int(KeyFileInfo::Unknown) << false << ""
                                 << "not a private key";
        QTest::newRow("empty") << QByteArray() << int(KeyFileInfo::Unknown) << false << "" << "not a private key";
    }

    void keyFiles()
    {
        QFETCH(QByteArray, contents);
        QFETCH(int, format);
        QFETCH(bool, encrypted);
        QFETCH(QString, type);
        QFETCH(QString, rejection);
        const KeyFileInfo info = inspectKeyFile(contents);
        QCOMPARE(int(info.format), format);
        QCOMPARE(info.encrypted, encrypted);
        QCOMPARE(info.keyType, type);
        const Result r = checkKeyFile(info);
        if (rejection.isEmpty()) {
            QVERIFY2(r.ok(), qPrintable(r.toString()));
        } else {
            QCOMPARE(r.error(), Error::Unsupported);   // S-15
            QVERIFY2(r.message().contains(rejection), qPrintable(r.message()));
        }
    }

    void keyTypes()
    {
        QVERIFY(checkKeyType(QStringLiteral("ssh-ed25519"), 0).ok());
        QVERIFY(checkKeyType(QStringLiteral("ecdsa-sha2-nistp256"), 0).ok());
        QVERIFY(checkKeyType(QStringLiteral("ecdsa-sha2-nistp384"), 0).ok());
        QVERIFY(checkKeyType(QStringLiteral("ecdsa-sha2-nistp521"), 0).ok());
        QVERIFY(checkKeyType(QStringLiteral("ssh-rsa"), 1024).ok());
        QVERIFY(checkKeyType(QStringLiteral("ssh-rsa"), 3072).ok());
        Result r = checkKeyType(QStringLiteral("ssh-rsa"), 1023);
        QCOMPARE(r.error(), Error::Unsupported);
        QVERIFY(r.message().contains(QLatin1String("at least 1024 bits")));
        QVERIFY(r.message().contains(QLatin1String("1023")));
        QVERIFY(checkKeyType(QStringLiteral("ssh-dss"), 0).message().contains(QLatin1String("ssh-dss")));
        QVERIFY(checkKeyType(QStringLiteral("sk-ssh-ed25519@openssh.com"), 0).message().contains(QLatin1String("Security-key")));
        QVERIFY(checkKeyType(QStringLiteral("ssh-rsa-cert-v01@openssh.com"), 0).message().contains(QLatin1String("certificates")));
        r = checkKeyType(QString(), 0);
        QCOMPARE(r.error(), Error::Unsupported);
        QVERIFY(r.message().contains(QLatin1String("(unknown)")));
    }

    void rsaBits()
    {
        QCOMPARE(rsaBitsFromBlob(rsaBlob(QByteArray(1, '\0') + QByteArray(1, '\x80') + QByteArray(127, '\x11'))), 1024);
        QCOMPARE(rsaBitsFromBlob(rsaBlob(QByteArray(1, '\x7f') + QByteArray(127, '\x11'))), 1023);
        QCOMPARE(rsaBitsFromBlob(rsaBlob(QByteArray(1, '\x01') + QByteArray(383, '\x11'))), 3065);
        QCOMPARE(rsaBitsFromBlob(rsaBlob(QByteArray(3, '\0'))), 0);
        QCOMPARE(rsaBitsFromBlob(rsaBlob(QByteArray())), 0);
        QCOMPARE(rsaBitsFromBlob(wireString("ssh-ed25519") + wireString("x") + wireString("y")), 0);
        QCOMPARE(rsaBitsFromBlob(rsaBlob(QByteArray(4, '\x11')).left(20)), 0);
        QCOMPARE(rsaBitsFromBlob(QByteArray()), 0);
    }

    // --- SSH key tools (plugin root object) --------------------------------

    void generate()
    {
        SshKeyMaterial first;
        QVERIFY(m_tools->generate(&first).ok());
        QCOMPARE(first.algorithm, QStringLiteral("ssh-ed25519"));
        QVERIFY(first.privateKey.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----"));
        const KeyFileInfo info = inspectKeyFile(first.privateKey);
        QCOMPARE(int(info.format), int(KeyFileInfo::OpenSsh));
        QVERIFY(!info.encrypted);   // stored unencrypted in signond
        QVERIFY(first.publicLine.startsWith(QLatin1String("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")));
        QVERIFY(first.publicLine.endsWith(QLatin1String(" sailfish-backup")));
        QCOMPARE(first.publicLine.split(QLatin1Char(' ')).size(), 3);
        QVERIFY(first.fingerprint.startsWith(QLatin1String("SHA256:")));
        QCOMPARE(first.fingerprint.size(), 50);

        SshKeyMaterial second;
        QVERIFY(m_tools->generate(&second).ok());
        QVERIFY(first.publicLine != second.publicLine);

        SshKeyMaterial described;
        QVERIFY(m_tools->describe(first.privateKey, &described).ok());
        QCOMPARE(described.publicLine, first.publicLine);
        QCOMPARE(described.fingerprint, first.fingerprint);
        QCOMPARE(described.algorithm, first.algorithm);
        QVERIFY(m_tools->generate(nullptr).ok());

        // S-6: the fingerprint is the one ssh-keygen prints; and ssh-keygen
        // reads the exported private key.
        writeFile(QStringLiteral("generated.pub"), first.publicLine.toLatin1() + '\n');
        writeFile(QStringLiteral("generated"), first.privateKey);
        QFile::setPermissions(m_dir.filePath(QStringLiteral("generated")), QFile::ReadOwner | QFile::WriteOwner);
        const QString expected = keygenFingerprint(QStringLiteral("generated.pub"));
        if (expected.isEmpty())
            QSKIP("ssh-keygen is not installed");
        QCOMPARE(first.fingerprint, expected);
        QByteArray derived;
        QVERIFY(tool(QStringLiteral("ssh-keygen"), { QStringLiteral("-y"), QStringLiteral("-f"),
                                                    m_dir.filePath(QStringLiteral("generated")) }, &derived));
        QCOMPARE(derived.trimmed().split(' ').mid(0, 2), first.publicLine.toLatin1().split(' ').mid(0, 2));
    }

    void importKeys_data()
    {
        QTest::addColumn<QStringList>("keygen");
        QTest::addColumn<QString>("algorithm");
        QTest::addColumn<QByteArray>("passphrase");
        QTest::newRow("rsa 3072 pem") << QStringList { "-t", "rsa", "-b", "3072", "-m", "PEM" } << "ssh-rsa"
                                      << QByteArray();
        QTest::newRow("rsa 2048 openssh") << QStringList { "-t", "rsa", "-b", "2048" } << "ssh-rsa" << QByteArray();
        QTest::newRow("ecdsa p256") << QStringList { "-t", "ecdsa", "-b", "256" } << "ecdsa-sha2-nistp256"
                                    << QByteArray();
        QTest::newRow("ecdsa p384 pem") << QStringList { "-t", "ecdsa", "-b", "384", "-m", "PEM" }
                                        << "ecdsa-sha2-nistp384" << QByteArray();
        QTest::newRow("ecdsa p521 pkcs8") << QStringList { "-t", "ecdsa", "-b", "521", "-m", "PKCS8" }
                                          << "ecdsa-sha2-nistp521" << QByteArray();
        QTest::newRow("ed25519 passphrase") << QStringList { "-t", "ed25519" } << "ssh-ed25519"
                                            << QByteArray("correct horse");
        QTest::newRow("rsa pem passphrase") << QStringList { "-t", "rsa", "-b", "2048", "-m", "PEM" } << "ssh-rsa"
                                            << QByteArray("battery staple");
    }

    void importKeys()
    {
        QFETCH(QStringList, keygen);
        QFETCH(QString, algorithm);
        QFETCH(QByteArray, passphrase);
        const QString name = QStringLiteral("key-%1").arg(QString::fromLatin1(QTest::currentDataTag()).replace(' ', '-'));
        QFile::remove(m_dir.filePath(name));
        if (!tool(QStringLiteral("ssh-keygen"), keygen + QStringList { QStringLiteral("-q"), QStringLiteral("-N"),
                                                                       QString::fromLatin1(passphrase),
                                                                       QStringLiteral("-C"), QStringLiteral("test"),
                                                                       QStringLiteral("-f"), m_dir.filePath(name) }))
            QSKIP("ssh-keygen is not installed");
        const QByteArray contents = file(name);

        SshKeyMaterial key;
        Result r = m_tools->importKey(contents, passphrase, &key);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(key.algorithm, algorithm);
        QCOMPARE(key.fingerprint, keygenFingerprint(name + QStringLiteral(".pub")));
        QVERIFY(key.publicLine.endsWith(QLatin1String(" sailfish-backup")));
        QCOMPARE(key.publicLine.split(QLatin1Char(' ')).value(1).toLatin1(),
                 file(name + QStringLiteral(".pub")).split(' ').value(1));
        // Re-exported unencrypted in OpenSSH format.
        const KeyFileInfo info = inspectKeyFile(key.privateKey);
        QCOMPARE(int(info.format), int(KeyFileInfo::OpenSsh));
        QVERIFY(!info.encrypted);
        SshKeyMaterial again;
        QVERIFY(m_tools->describe(key.privateKey, &again).ok());
        QCOMPARE(again.publicLine, key.publicLine);

        if (!passphrase.isEmpty()) {
            r = m_tools->importKey(contents, QByteArray(), &again);
            QCOMPARE(r.error(), Error::AuthFailed);
            QVERIFY(r.message().contains(QLatin1String("passphrase")));
            r = m_tools->importKey(contents, "wrong", &again);
            QCOMPARE(r.error(), Error::AuthFailed);
            QVERIFY(r.message().contains(QLatin1String("not correct")));
            QCOMPARE(m_tools->describe(contents, &again).error(), Error::AuthFailed);
        }
    }

    void rejectedKeys()
    {
        // S-15 with real files.
        SshKeyMaterial key;
        if (!tool(QStringLiteral("openssl"), { QStringLiteral("genrsa"), QStringLiteral("-traditional"),
                                              QStringLiteral("-out"), QStringLiteral("small.pem"), QStringLiteral("768") }))
            QSKIP("openssl is not installed");
        Result r = m_tools->importKey(file(QStringLiteral("small.pem")), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QVERIFY2(r.message().contains(QLatin1String("1024")), qPrintable(r.message()));
        QVERIFY(key.privateKey.isEmpty());

        QVERIFY(tool(QStringLiteral("openssl"), { QStringLiteral("dsaparam"), QStringLiteral("-genkey"),
                                                 QStringLiteral("-noout"), QStringLiteral("-out"),
                                                 QStringLiteral("dsa.pem"), QStringLiteral("1024") }));
        r = m_tools->importKey(file(QStringLiteral("dsa.pem")), QByteArray(), &key);   // PKCS#8
        QCOMPARE(r.error(), Error::Unsupported);
        QVERIFY2(r.message().contains(QLatin1String("DSA")), qPrintable(r.message()));
        QVERIFY(tool(QStringLiteral("openssl"), { QStringLiteral("dsa"),
                                                 QStringLiteral("-in"), QStringLiteral("dsa.pem"),
                                                 QStringLiteral("-out"), QStringLiteral("dsa-traditional.pem") }));
        r = m_tools->importKey(file(QStringLiteral("dsa-traditional.pem")), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QVERIFY2(r.message().contains(QLatin1String("DSA")), qPrintable(r.message()));
        // A PKCS#8 key of a type libssh does not know.
        QVERIFY(tool(QStringLiteral("openssl"), { QStringLiteral("genpkey"), QStringLiteral("-algorithm"),
                                                 QStringLiteral("ed448"), QStringLiteral("-out"),
                                                 QStringLiteral("ed448.pem") }));
        r = m_tools->importKey(file(QStringLiteral("ed448.pem")), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QVERIFY2(r.message().contains(QLatin1String("Ed25519, ECDSA or RSA")), qPrintable(r.message()));

        QFile::remove(m_dir.filePath(QStringLiteral("ca")));
        QFile::remove(m_dir.filePath(QStringLiteral("user")));
        QVERIFY(tool(QStringLiteral("ssh-keygen"), { QStringLiteral("-q"), QStringLiteral("-t"), QStringLiteral("ed25519"),
                                                    QStringLiteral("-N"), QString(), QStringLiteral("-f"),
                                                    m_dir.filePath(QStringLiteral("ca")) }));
        QVERIFY(tool(QStringLiteral("ssh-keygen"), { QStringLiteral("-q"), QStringLiteral("-t"), QStringLiteral("ed25519"),
                                                    QStringLiteral("-N"), QString(), QStringLiteral("-f"),
                                                    m_dir.filePath(QStringLiteral("user")) }));
        QVERIFY(tool(QStringLiteral("ssh-keygen"), { QStringLiteral("-q"), QStringLiteral("-s"),
                                                    m_dir.filePath(QStringLiteral("ca")), QStringLiteral("-I"),
                                                    QStringLiteral("id"), m_dir.filePath(QStringLiteral("user.pub")) }));
        r = m_tools->importKey(file(QStringLiteral("user-cert.pub")), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QVERIFY2(r.message().contains(QLatin1String("certificates")), qPrintable(r.message()));
        r = m_tools->importKey(file(QStringLiteral("user.pub")), QByteArray(), &key);
        QVERIFY2(r.message().contains(QLatin1String("public key")), qPrintable(r.message()));

        // Looks like a key, but libssh cannot parse it.
        r = m_tools->importKey(openSshKeyText("none", "ssh-ed25519"), QByteArray(), &key);
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(m_tools->describe("not a key", &key).error(), Error::Unsupported);
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
        QCOMPARE(b->list(QStringLiteral("x"), &entries).error(), Error::Internal);
        QCOMPARE(b->makePath(QStringLiteral("x")).error(), Error::Internal);
        QCOMPARE(b->remove(QStringLiteral("x")).error(), Error::Internal);
        QCOMPARE(b->rename(QStringLiteral("x"), QStringLiteral("y")).error(), Error::Internal);
        QCOMPARE(b->freeSpace(QStringLiteral("x"), &bytes).error(), Error::Internal);
        QCOMPARE(b->upload(nullptr, QStringLiteral("x"), nullptr).error(), Error::Internal);
        QCOMPARE(b->download(QStringLiteral("x"), nullptr, nullptr).error(), Error::Internal);
        QCOMPARE(b->read(QStringLiteral("x"), 0, 1, &data).error(), Error::Internal);
        QCOMPARE(b->authenticate(Credentials(QStringLiteral("u"), "p")).error(), Error::Internal);
        b->disconnect();
    }

    void invalidHost()
    {
        auto b = backend();
        ServerIdentity seen;
        ConnectionParams params = localParams(22);
        params.host = QStringLiteral("root@example.org");
        QCOMPARE(b->connect(params, &seen).error(), Error::Internal);
        params.host.clear();
        QCOMPARE(b->connect(params, &seen).error(), Error::Internal);
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
        QVERIFY(seen.isEmpty());
    }

    void unresolvable()
    {
        auto b = backend();
        ConnectionParams params = localParams(22);
        params.host = QStringLiteral("no-such-host.invalid");
        QCOMPARE(b->connect(params, nullptr).error(), Error::NetworkUnreachable);
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
        QVERIFY2(timer.elapsed() < 5000, qPrintable(QString::number(timer.elapsed())));
    }

    void noCommonAlgorithm()
    {
        // S-2: no common algorithm is SecurityPolicy.
        const ScriptedPeer peer(unsupportedKexGreeting());
        auto b = backend();
        const Result r = b->connect(localParams(peer.port()), nullptr);
        QCOMPARE(r.error(), Error::SecurityPolicy);
        QVERIFY(r.message().contains(QLatin1String("frobnicate-kex@example.org")));
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
