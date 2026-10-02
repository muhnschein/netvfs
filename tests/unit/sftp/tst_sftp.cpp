// SPDX-License-Identifier: LGPL-2.1-or-later
// SFTP backend behaviour that needs no SSH server (SPEC-sftp 2, 3, 5.1, 7).
#include "backendloader.h"
#include "sftpshell.h"
#include "sftpsupport.h"
#include "shellexec.h"
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

namespace QTest {
template<>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest
using namespace NetVfs::Sftp;

Q_DECLARE_METATYPE(NetVfs::Error)

namespace {

// A prompter that answers from a script and records what it was asked.
class ScriptedPrompter : public AuthPrompter
{
public:
    bool answer(const QString &n, const QString &i, const QVector<AuthPrompt> &p, QVector<QByteArray> *answers) override
    {
        name = n;
        instruction = i;
        prompts = p;
        *answers = reply;
        for (QByteArray &a : *answers)
            a.detach();
        return !decline;
    }
    QVector<QByteArray> reply;
    bool decline = false;
    QString name;
    QString instruction;
    QVector<AuthPrompt> prompts;
};

void writeLocal(const QString &path, const QByteArray &data)
{
    QFile file(path);
    if (file.open(QIODevice::WriteOnly))
        file.write(data);
}

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
        QTest::newRow("lost") << SSH_FX_CONNECTION_LOST << "gone" << Error::ConnectionLost;   // XC-21
        QTest::newRow("no connection") << SSH_FX_NO_CONNECTION << "gone" << Error::ConnectionLost;
        QTest::newRow("timeout") << SSH_FX_FAILURE << "Timeout while reading sftp packet size" << Error::Timeout;
        QTest::newRow("failure") << SSH_FX_FAILURE << "SFTP server: Failure" << Error::ProtocolError;
        QTest::newRow("bad message") << SSH_FX_BAD_MESSAGE << "SFTP server: Bad message" << Error::ProtocolError;
        // strerror() texts with SSH_FX_FAILURE (ProFTPD)
        QTest::newRow("not a directory") << SSH_FX_FAILURE << "SFTP server: Not a directory" << Error::NotADirectory;
        QTest::newRow("is a directory") << SSH_FX_FAILURE << "SFTP server: Is a directory" << Error::IsADirectory;
        QTest::newRow("not empty") << SSH_FX_FAILURE << "SFTP server: Directory not empty" << Error::DirectoryNotEmpty;
        QTest::newRow("text with another code") << SSH_FX_BAD_MESSAGE << "SFTP server: Not a directory"
                                                << Error::ProtocolError;
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

    void secretForInteractive()
    {
        // XS-11: auth_mode=interactive, the stored secret is optional.
        const QByteArray key = encodeKeySecret("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        QVERIFY(checkSecretForMode(QStringLiteral("interactive"), QByteArray()).ok());
        QVERIFY(checkSecretForMode(QStringLiteral("interactive"), "hunter2").ok());
        QCOMPARE(checkSecretForMode(QStringLiteral("interactive"), key).error(), Error::AuthFailed);
        QCOMPARE(interactiveDeclined().error(), Error::AuthFailed);
    }

    // --- keyboard-interactive (S-11, XS-11) --------------------------------

    void roundActions_data()
    {
        QTest::addColumn<int>("prompts");
        QTest::addColumn<bool>("echo");
        QTest::addColumn<bool>("password");
        QTest::addColumn<bool>("secretUsable");
        QTest::addColumn<bool>("prompter");
        QTest::addColumn<int>("action");
        const int ack = int(RoundAction::Acknowledge);
        const int secret = int(RoundAction::AnswerWithSecret);
        const int ask = int(RoundAction::AskPrompter);
        const int refuse = int(RoundAction::Refuse);
        // S-11 exactly, without a prompter; the prompt's text does not matter.
        QTest::newRow("no prompts") << 0 << false << false << true << false << ack;
        QTest::newRow("one hidden prompt") << 1 << false << true << true << false << secret;
        QTest::newRow("one hidden prompt, any text") << 1 << false << false << true << false << secret;
        QTest::newRow("one echoed prompt") << 1 << true << true << true << false << refuse;
        QTest::newRow("two prompts") << 2 << false << true << true << false << refuse;
        QTest::newRow("password used already") << 1 << false << true << false << false << refuse;
        // XS-11, with a prompter: the password answers only a password prompt.
        QTest::newRow("prompter, no prompts") << 0 << true << false << false << true << ack;
        QTest::newRow("prompter, password round") << 1 << false << true << true << true << secret;
        QTest::newRow("prompter, code round") << 1 << false << false << true << true << ask;
        QTest::newRow("prompter, second round") << 1 << false << true << false << true << ask;
        QTest::newRow("prompter, echoed prompt") << 1 << true << true << true << true << ask;
        QTest::newRow("prompter, two prompts") << 2 << false << true << true << true << ask;
    }

    void roundActions()
    {
        QFETCH(int, prompts);
        QFETCH(bool, echo);
        QFETCH(bool, password);
        QFETCH(bool, secretUsable);
        QFETCH(bool, prompter);
        QFETCH(int, action);
        QCOMPARE(int(keyboardInteractiveAction(prompts, echo, password, secretUsable, prompter)), action);
    }

    void passwordPrompts()
    {
        QVERIFY(isPasswordPrompt(QStringLiteral("Password: ")));
        QVERIFY(isPasswordPrompt(QStringLiteral("alice@host's password:")));
        QVERIFY(isPasswordPrompt(QStringLiteral("PASSWORD")));
        QVERIFY(!isPasswordPrompt(QStringLiteral("Verification code: ")));
        QVERIFY(!isPasswordPrompt(QStringLiteral("Token label: ")));
        QVERIFY(!isPasswordPrompt(QString()));
    }

    void promptRounds()
    {
        QVector<AuthPrompt> prompts(2);
        prompts[0].text = QStringLiteral("Token label: ");
        prompts[0].echo = true;
        prompts[1].text = QStringLiteral("Verification code: ");
        ScriptedPrompter prompter;
        prompter.reply = { QByteArray("label"), QByteArray("123456") };
        QVector<QByteArray> answers;
        QList<QPair<int, QByteArray>> set;
        const auto record = [&set](int index, const QByteArray &answer) {
            set.append(qMakePair(index, answer));
            return true;
        };
        QCOMPARE(promptRound(&prompter, QStringLiteral("name"), QStringLiteral("instruction"), prompts, &answers, record),
                 PromptOutcome::Answered);
        QCOMPARE(prompter.name, QStringLiteral("name"));
        QCOMPARE(prompter.instruction, QStringLiteral("instruction"));
        QCOMPARE(prompter.prompts.size(), 2);
        QVERIFY(prompter.prompts.at(0).echo);
        QCOMPARE(prompter.prompts.at(1).text, QStringLiteral("Verification code: "));
        QCOMPARE(set.size(), 2);
        QCOMPARE(set.at(0), qMakePair(0, QByteArray("label")));
        QCOMPARE(set.at(1), qMakePair(1, QByteArray("123456")));
        // XSEC-6: the answers are overwritten, in place, before the call returns.
        QCOMPARE(answers.size(), 2);
        QCOMPARE(answers.at(0), QByteArray(5, '\0'));
        QCOMPARE(answers.at(1), QByteArray(6, '\0'));

        // One answer for two prompts: nothing is handed on; still wiped.
        set.clear();
        prompter.reply = { QByteArray("123456") };
        QCOMPARE(promptRound(&prompter, QString(), QString(), prompts, &answers, record), PromptOutcome::BadAnswers);
        QVERIFY(set.isEmpty());
        QCOMPARE(answers, QVector<QByteArray>({ QByteArray(6, '\0') }));
        // libssh refused an answer.
        prompter.reply = { QByteArray("label"), QByteArray("123456") };
        const auto refuse = [](int, const QByteArray &) { return false; };
        QCOMPARE(promptRound(&prompter, QString(), QString(), prompts, &answers, refuse), PromptOutcome::Rejected);
        QCOMPARE(answers.at(1), QByteArray(6, '\0'));
        // Declined (or canceled): whatever the prompter left is wiped too.
        prompter.decline = true;
        QCOMPARE(promptRound(&prompter, QString(), QString(), prompts, &answers, record), PromptOutcome::Declined);
        QVERIFY(set.isEmpty());
        QCOMPARE(answers.at(0), QByteArray(5, '\0'));
    }

    // --- channels, links, attributes, resume -------------------------------

    void channelOpenFailures()
    {
        // XC-21: OpenSSH beyond MaxSessions (libssh's wording).
        Result r = channelOpenFailure(QStringLiteral("Channel opening failure: channel 2 error (1) open failed"));
        QCOMPARE(r.error(), Error::TooManyConnections);
        QVERIFY(r.detail().contains(QLatin1String("open failed")));
        QCOMPARE(channelOpenFailure(QStringLiteral("Channel opening failure: channel 45 error (2) open failed")).error(),
                 Error::TooManyConnections);   // what OpenSSH sends
        QCOMPARE(channelOpenFailure(QStringLiteral("Channel opening failure: channel 2 error (4) no memory")).error(),
                 Error::TooManyConnections);
        QCOMPARE(channelOpenFailure(QStringLiteral("Channel opening failure: channel 2 error (2) connect failed")).error(),
                 Error::ProtocolError);
        QCOMPARE(channelOpenFailure(QStringLiteral("Channel opening failure: channel 2 error (3) open failed")).error(),
                 Error::ProtocolError);
        QCOMPARE(channelOpenFailure(QStringLiteral("Socket error: error (1)")).error(), Error::ProtocolError);
    }

    void symlinkOrders()
    {
        // XS-4: libssh's order for OpenSSH (by banner) and verified families.
        QCOMPARE(symlinkOrderFor(QStringLiteral("SSH-2.0-OpenSSH_10.3"), true), SymlinkOrder::AsLibssh);
        QCOMPARE(symlinkOrderFor(QStringLiteral("SSH-2.0-mod_sftp"), false), SymlinkOrder::Swapped);
        QCOMPARE(symlinkOrderFor(QStringLiteral("SSH-2.0-mod_sftp/1.3.8"), false), SymlinkOrder::Swapped);
        QCOMPARE(symlinkOrderFor(QStringLiteral("SSH-2.0-SFTPGo_2.6.0"), false), SymlinkOrder::Unverified);
        QCOMPARE(symlinkOrderFor(QStringLiteral("SSH-2.0-dropbear_2024.86"), false), SymlinkOrder::Unverified);
        QCOMPARE(symlinkOrderFor(QStringLiteral("SSH-2.0-OpenSSH_10.3"), false), SymlinkOrder::Unverified);
        QCOMPARE(symlinkOrderFor(QString(), false), SymlinkOrder::Unverified);
    }

    void lstatQuirks()
    {
        QVERIFY(lstatFollowsLinks(QStringLiteral("SSH-2.0-mod_sftp")));
        QVERIFY(!lstatFollowsLinks(QStringLiteral("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")));
        QVERIFY(!lstatFollowsLinks(QString()));
    }

    void resumeOffsets()
    {
        // XC-13: only at the current remote size; ProtocolError like Transfer.
        QVERIFY(checkResumeOffset(100, 100).ok());
        QVERIFY(checkResumeOffset(0, 0).ok());
        QCOMPARE(checkResumeOffset(100, 99).error(), Error::ProtocolError);
        QCOMPARE(checkResumeOffset(100, 101).error(), Error::ProtocolError);
        QCOMPARE(checkResumeOffset(100, 0).error(), Error::ProtocolError);
        QVERIFY(checkResumeOffset(100, 0).message().contains(QLatin1String("100 bytes")));
    }

    void attributeChanges()
    {
        // XC-11, XS-5: checked before anything is sent.
        AttributeChanges changes;
        QVERIFY(checkAttributeChanges(changes).ok());
        changes.mode = 07777;
        QVERIFY(checkAttributeChanges(changes).ok());
        changes.mode = 0;
        QVERIFY(checkAttributeChanges(changes).ok());
        changes.mode = 0170644;
        QCOMPARE(checkAttributeChanges(changes).error(), Error::Internal);
        changes.mode = 010000;
        QCOMPARE(checkAttributeChanges(changes).error(), Error::Internal);
        changes.mode = -2;
        QCOMPARE(checkAttributeChanges(changes).error(), Error::Internal);
        changes.mode = -1;
        changes.modified = QDateTime::fromMSecsSinceEpoch(0, Qt::UTC);
        QVERIFY(checkAttributeChanges(changes).ok());
        changes.modified = QDateTime::fromMSecsSinceEpoch(qint64(0xffffffffLL) * 1000, Qt::UTC);
        QVERIFY(checkAttributeChanges(changes).ok());
        changes.modified = QDateTime::fromMSecsSinceEpoch((qint64(0xffffffffLL) + 1) * 1000, Qt::UTC);
        QCOMPARE(checkAttributeChanges(changes).error(), Error::Internal);
        changes.modified = QDateTime();
        changes.accessed = QDateTime(QDate(1969, 12, 31), QTime(23, 59, 59), Qt::UTC);
        QCOMPARE(checkAttributeChanges(changes).error(), Error::Internal);
    }

    // --- shell exec helpers (XS-9) -----------------------------------------

    void shellQuoting()
    {
        QCOMPARE(shellQuote("abc"), QByteArray("'abc'"));
        QCOMPARE(shellQuote(""), QByteArray("''"));
        QCOMPARE(shellQuote("it's"), QByteArray("'it'\\''s'"));
        QCOMPARE(shellQuote("''"), QByteArray("''\\'''\\'''"));
        QCOMPARE(shellCommand({ "cp", "-p", "--", "a b", "c" }), QByteArray("'cp' '-p' '--' 'a b' 'c'"));
        QCOMPARE(sha256sumCommand("/x"), QList<QByteArray>({ "sha256sum", "--", "/x" }));
        QCOMPARE(shasumCommand("/x"), QList<QByteArray>({ "shasum", "-a", "256", "--", "/x" }));
        QCOMPARE(copyCommand("/a", "/b", false), QList<QByteArray>({ "cp", "-p", "--", "/a", "/b" }));
        QCOMPARE(copyCommand("/a", "/b", true), QList<QByteArray>({ "cp", "-pR", "--", "/a", "/b" }));
        QCOMPARE(findCommand("/d", "*.txt"), QList<QByteArray>({ "find", "/d", "-name", "*.txt", "-print0" }));
    }

    void shellQuotingRoundTrip()
    {
        // Whatever the bytes, a POSIX shell sees exactly these words.
        const QList<QByteArray> words = {
            "printf", "%s\\0", "-n", "--", "a b", "it's", "\"q\"", "$HOME", "`id`", "$(id)", "\\", "*", "~",
            "line\nbreak", "tab\there", ";|&<>", "caf\xe9 \xff", "''", "",
        };
        // Through a script file: command line arguments would be recoded.
        QTemporaryDir dir;
        const QString script = dir.filePath(QStringLiteral("command.sh"));
        writeLocal(script, shellCommand(words) + '\n');
        QProcess shell;
        shell.start(QStringLiteral("/bin/sh"), { script });
        QVERIFY(shell.waitForFinished(10000));
        QCOMPARE(shell.exitCode(), 0);
        QList<QByteArray> printed = shell.readAllStandardOutput().split('\0');
        QCOMPARE(printed.takeLast(), QByteArray());
        QCOMPARE(printed, words.mid(2));
    }

    void probe()
    {
        // The probe runs through a real POSIX shell and is understood.
        QProcess shell;
        shell.start(QStringLiteral("/bin/sh"), { QStringLiteral("-c"), QString::fromLatin1(probeCommand()) });
        QVERIFY(shell.waitForFinished(10000));
        ShellTools tools;
        QVERIFY(parseProbe(shell.readAllStandardOutput(), &tools));
        QVERIFY(tools.cp);
        QVERIFY(tools.find);

        const QByteArray head = "netvfs-probe\nit's \"q\" $HOME \\ * `x` ;|&\n";
        QVERIFY(parseProbe(head + "cp\nsha256sum\n", &tools));
        QVERIFY(tools.cp && tools.sha256sum && !tools.shasum && !tools.find);
        QVERIFY(parseProbe(head + "shasum\nfind\n", &tools));
        QVERIFY(!tools.cp && !tools.sha256sum && tools.shasum && tools.find);
        QVERIFY(parseProbe(head, &tools));
        QVERIFY(!tools.cp);
        tools.cp = true;
        QVERIFY(!parseProbe(head + "rm\n", &tools));                               // unknown line
        QVERIFY(tools.cp);                                                          // untouched on failure
        QVERIFY(!parseProbe(head + "cp", &tools));                                 // not terminated
        QVERIFY(!parseProbe("netvfs-probe\nit's q $HOME \\ * `x` ;|&\ncp\n", &tools));   // quoting lost
        QVERIFY(!parseProbe("This account is currently not available.\n", &tools));
        QVERIFY(!parseProbe(QByteArray(), &tools));
    }

    void sha256Output()
    {
        const QByteArray hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        QByteArray digest;
        QVERIFY(parseSha256Output(hex + "  /home/a/file\n", &digest));
        QCOMPARE(digest, QByteArray::fromHex(hex));
        QCOMPARE(digest.size(), 32);
        digest.clear();
        QVERIFY(parseSha256Output("\\" + hex + "  /home/a/new\\nline\n", &digest));   // escaped name
        QCOMPARE(digest, QByteArray::fromHex(hex));
        QVERIFY(parseSha256Output(hex.toUpper() + " */x\n", &digest));
        QCOMPARE(digest, QByteArray::fromHex(hex));
        digest = "unchanged";
        QVERIFY(!parseSha256Output(hex.left(63) + "  x\n", &digest));
        QVERIFY(!parseSha256Output(hex + "0  x\n", &digest));                 // 65 digits
        QVERIFY(!parseSha256Output(hex, &digest));                           // nothing after
        QVERIFY(!parseSha256Output(hex.left(63) + "g  x\n", &digest));        // not hex
        QVERIFY(!parseSha256Output("sha256sum: x: No such file or directory\n", &digest));
        QVERIFY(!parseSha256Output(QByteArray(), &digest));
        QVERIFY(!parseSha256Output("\\", &digest));
        QCOMPARE(digest, QByteArray("unchanged"));

        // The real tool, where the host has it.
        QTemporaryDir dir;
        const QString path = dir.filePath(QStringLiteral("data"));
        writeLocal(path, "abc");
        QProcess shell;
        shell.start(QStringLiteral("/bin/sh"),
                    { QStringLiteral("-c"), QString::fromLatin1(shellCommand(sha256sumCommand(path.toLocal8Bit()))) });
        QVERIFY(shell.waitForFinished(10000));
        if (shell.exitCode() != 0)
            QSKIP("no sha256sum on this host");
        QVERIFY(parseSha256Output(shell.readAllStandardOutput(), &digest));
        QCOMPARE(digest.toHex(), QByteArray("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    }

    void findOutput()
    {
        QList<QByteArray> paths;
        const QByteArray out = QByteArray("/d/a.txt\0/d/sub/b.txt\0/d\0", 25);
        QVERIFY(parseFindOutput(out, "/d", false, 10, &paths));
        QCOMPARE(paths, QList<QByteArray>({ "/d/a.txt", "/d/sub/b.txt", "/d" }));
        QVERIFY(parseFindOutput(out, "/d", false, 2, &paths));
        QCOMPARE(paths, QList<QByteArray>({ "/d/a.txt", "/d/sub/b.txt" }));
        QVERIFY(parseFindOutput(QByteArray(), "/d", false, 10, &paths));
        QVERIFY(paths.isEmpty());
        // A cut-off output loses its last, unterminated piece.
        QVERIFY(parseFindOutput(QByteArray("/d/a\0/d/b", 9), "/d", true, 10, &paths));
        QCOMPARE(paths, QList<QByteArray>({ "/d/a" }));
        QVERIFY(!parseFindOutput(QByteArray("/d/a\0/d/b", 9), "/d", false, 10, &paths));
        // Anything outside the folder is not understood.
        QVERIFY(!parseFindOutput(QByteArray("/d/a\0/etc/passwd\0", 17), "/d", false, 10, &paths));
        QVERIFY(!parseFindOutput(QByteArray("/dx/a\0", 6), "/d", false, 10, &paths));
        QVERIFY(!parseFindOutput(QByteArray("/d/\0", 4), "/d", false, 10, &paths));
        QVERIFY(!parseFindOutput("find: '/d': Permission denied\n", "/d", false, 10, &paths));
        // Below the root and relative starts.
        QVERIFY(parseFindOutput(QByteArray("/\0/etc\0", 7), "/", false, 10, &paths));
        QCOMPARE(paths, QList<QByteArray>({ "/", "/etc" }));
        QVERIFY(parseFindOutput(QByteArray("./x/y\0", 6), "./x", false, 10, &paths));
        QCOMPARE(paths, QList<QByteArray>({ "./x/y" }));
    }

    void keyFiles_data()
    {
        QTest::addColumn<QByteArray>("contents");
        QTest::addColumn<int>("format");
        QTest::addColumn<bool>("encrypted");
        QTest::addColumn<QString>("type");
        QTest::addColumn<QString>("rejection");   // empty: accepted by checkKeyFile
        QTest::newRow("openssh ed25519") << openSshKeyText("none", "ssh-ed25519") << int(KeyFileInfo::Format::OpenSsh)
                                         << false << "ssh-ed25519" << "";
        QTest::newRow("openssh encrypted") << openSshKeyText("aes256-ctr", "ssh-rsa") << int(KeyFileInfo::Format::OpenSsh)
                                           << true << "ssh-rsa" << "";
        QTest::newRow("openssh dsa") << openSshKeyText("none", "ssh-dss") << int(KeyFileInfo::Format::OpenSsh) << false
                                     << "ssh-dss" << "DSA keys";
        QTest::newRow("openssh sk") << openSshKeyText("none", "sk-ssh-ed25519@openssh.com")
                                    << int(KeyFileInfo::Format::OpenSsh) << false << "sk-ssh-ed25519@openssh.com"
                                    << "Security-key";
        QTest::newRow("openssh sk ecdsa") << openSshKeyText("none", "sk-ecdsa-sha2-nistp256@openssh.com")
                                          << int(KeyFileInfo::Format::OpenSsh) << false
                                          << "sk-ecdsa-sha2-nistp256@openssh.com" << "Security-key";
        QTest::newRow("openssh cert") << openSshKeyText("none", "ssh-ed25519-cert-v01@openssh.com")
                                      << int(KeyFileInfo::Format::OpenSsh) << false << "ssh-ed25519-cert-v01@openssh.com"
                                      << "certificates";
        QTest::newRow("openssh truncated")
            << QByteArray("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n")
            << int(KeyFileInfo::Format::Unknown) << false << "" << "not a private key";
        QTest::newRow("pem rsa") << QByteArray("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
                                 << int(KeyFileInfo::Format::Pem) << false << "ssh-rsa" << "";
        QTest::newRow("pem rsa encrypted")
            << QByteArray("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n")
            << int(KeyFileInfo::Format::Pem) << true << "ssh-rsa" << "";
        QTest::newRow("pem ec") << QByteArray("-----BEGIN EC PRIVATE KEY-----\nAAAA\n") << int(KeyFileInfo::Format::Pem)
                                << false << "ecdsa" << "";
        QTest::newRow("pem dsa") << QByteArray("-----BEGIN DSA PRIVATE KEY-----\nAAAA\n") << int(KeyFileInfo::Format::Pem)
                                 << false << "ssh-dss" << "DSA keys";
        QTest::newRow("pkcs8") << QByteArray("-----BEGIN PRIVATE KEY-----\nAAAA\n") << int(KeyFileInfo::Format::Pem) << false
                               << "" << "";
        QTest::newRow("pkcs8 encrypted") << QByteArray("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n")
                                         << int(KeyFileInfo::Format::Pem) << true << "" << "";
        QTest::newRow("public key") << QByteArray("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== me@host\n")
                                    << int(KeyFileInfo::Format::PublicKey) << false << "ssh-ed25519" << "public key";
        QTest::newRow("certificate") << QByteArray("ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5 me\n")
                                     << int(KeyFileInfo::Format::PublicKey) << false << "ssh-ed25519-cert-v01@openssh.com"
                                     << "certificates";
        QTest::newRow("garbage") << QByteArray("hello world") << int(KeyFileInfo::Format::Unknown) << false << ""
                                 << "not a private key";
        QTest::newRow("empty") << QByteArray() << int(KeyFileInfo::Format::Unknown) << false << "" << "not a private key";
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
        QCOMPARE(int(info.format), int(KeyFileInfo::Format::OpenSsh));
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
        QCOMPARE(int(info.format), int(KeyFileInfo::Format::OpenSsh));
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
        QCOMPARE(b->lstat(QStringLiteral("x"), &entry).error(), Error::Internal);
        QCOMPARE(b->list(QStringLiteral("x"), &entries).error(), Error::Internal);
        QCOMPARE(b->makePath(QStringLiteral("x")).error(), Error::Internal);
        QCOMPARE(b->makeDir(QStringLiteral("x"), true).error(), Error::Internal);
        QCOMPARE(b->remove(QStringLiteral("x")).error(), Error::Internal);
        QCOMPARE(b->removeDir(QStringLiteral("x")).error(), Error::Internal);
        QCOMPARE(b->rename(QStringLiteral("x"), QStringLiteral("y"), RenameMode::Replace).error(), Error::Internal);
        QCOMPARE(b->rename(QStringLiteral("x"), QStringLiteral("y"), RenameMode::NoReplace).error(), Error::Internal);
        QCOMPARE(b->freeSpace(QStringLiteral("x"), &bytes).error(), Error::Internal);
        QCOMPARE(b->upload(nullptr, QStringLiteral("x"), UploadOptions(), nullptr).error(), Error::Internal);
        QCOMPARE(b->download(QStringLiteral("x"), nullptr, DownloadOptions(), nullptr).error(), Error::Internal);
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
        QCOMPARE(b->copy(QStringLiteral("x"), QStringLiteral("y"), CopyOptions()).error(), Error::Internal);
        QCOMPARE(b->checksum(QStringLiteral("x"), QStringLiteral("sha256"), &data).error(), Error::Internal);
        SpaceInfo space;
        QCOMPARE(b->spaceInfo(QStringLiteral("x"), &space).error(), Error::Internal);
        // XS-9: the interface is there, the capability is not.
        auto *shell = dynamic_cast<ShellExec *>(b.get());
        QVERIFY(shell);
        QVERIFY(!ShellExec::of(b.get()));
        ExecResult result;
        QCOMPARE(shell->exec({ QStringLiteral("true") }, ExecOptions(), &result).error(), Error::Internal);
        QStringList found;
        QCOMPARE(shell->find(QStringLiteral("x"), QStringLiteral("*"), 1, &found).error(), Error::Internal);
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
        QVERIFY2(r.error() == Error::SecurityPolicy, qPrintable(r.toString()));
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
