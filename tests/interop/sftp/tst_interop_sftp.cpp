// SPDX-License-Identifier: LGPL-2.1-or-later
// SFTP interoperability matrix (SPEC-sftp section 8) against the OpenSSH
// containers started by run.sh, which passes their ports and the test
// password in the JSON file named by NETVFS_SFTP_INTEROP_CONFIG.
#include "backendloader.h"
#include "identity.h"
#include "paths.h"
#include "sftpbackend.h"
#include "sshkeys.h"
#include "transfer.h"

#include <QtConcurrent/QtConcurrent>
#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QElapsedTimer>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QMutex>
#include <QtCore/QProcess>
#include <QtCore/QSemaphore>
#include <QtCore/QTemporaryDir>
#include <QtCore/QUuid>
#include <QtTest/QtTest>

#include <atomic>
#include <functional>
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

constexpr qint64 BigFileSize = 64 * 1024 * 1024;   // SPEC-sftp 8
constexpr qint64 CancelBoundMs = 2000;              // C-9

// S-T4: emulates a server without the hybrid post-quantum key exchanges by
// narrowing the client's list through the test-only extension point.
class Curve25519OnlyBackend : public Sftp::SftpBackend
{
protected:
    void configureSession(ssh_session session) override
    {
        ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, "curve25519-sha256");
    }
};

// Debug output of the backend (category netvfs.sftp), for the negotiated
// key exchange.
struct LogCapture {
    QMutex mutex;
    QStringList lines;
    QtMessageHandler previous = nullptr;
};

LogCapture &logCapture()
{
    static LogCapture capture;
    return capture;
}

void captureLog(QtMsgType type, const QMessageLogContext &context, const QString &message)
{
    LogCapture &capture = logCapture();
    if (context.category && qstrcmp(context.category, "netvfs.sftp") == 0) {
        const QMutexLocker lock(&capture.mutex);
        capture.lines << message;
        if (type == QtDebugMsg)
            return;
    }
    capture.previous(type, context, message);
}

QString capturedLog()
{
    LogCapture &capture = logCapture();
    const QMutexLocker lock(&capture.mutex);
    return capture.lines.join(QLatin1Char('\n'));
}

void clearLog()
{
    LogCapture &capture = logCapture();
    const QMutexLocker lock(&capture.mutex);
    capture.lines.clear();
}

QByteArray sha256(QIODevice *device)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(device);
    return hash.result().toHex();
}

QByteArray fileSha256(const QString &path)
{
    QFile file(path);
    return file.open(QIODevice::ReadOnly) ? sha256(&file) : QByteArray();
}

// Blocks the transferring thread in its first progress report after
// `threshold` bytes until the test lets it go on.
class GateProgress : public Progress
{
public:
    explicit GateProgress(qint64 threshold) : m_threshold(threshold) {}

    void update(qint64 done, qint64 total) override
    {
        Q_UNUSED(total)
        if (m_passed || done < m_threshold)
            return;
        m_passed = true;
        m_reached.release();
        m_proceed.tryAcquire(1, 60000);
    }

    bool waitReached(int ms) { return m_reached.tryAcquire(1, ms); }
    void proceed() { m_proceed.release(); }

private:
    QSemaphore m_reached;
    QSemaphore m_proceed;
    qint64 m_threshold;
    bool m_passed = false;
};

// A source whose reads fail.
class FailingSource : public QIODevice
{
protected:
    qint64 readData(char *, qint64) override { return -1; }
    qint64 writeData(const char *, qint64) override { return -1; }
};

QString unique(const QString &prefix)
{
    return prefix + QUuid::createUuid().toString().mid(1, 8);
}

} // namespace

class TestInteropSftp : public QObject
{
    Q_OBJECT

private:
    QJsonObject m_servers;
    QByteArray m_password;
    QTemporaryDir m_tmp;
    QString m_bigFile;
    QByteArray m_bigSha;
    SshKeyTools *m_tools = nullptr;

    QString container(const QString &server) const
    {
        return m_servers.value(server).toObject().value(QStringLiteral("container")).toString();
    }

    ConnectionParams params(const QString &server, const QString &instance, const QString &user,
                            const QString &authMode = QStringLiteral("password")) const
    {
        ConnectionParams p;
        p.provider = QStringLiteral("sftp");
        p.host = QStringLiteral("127.0.0.1");
        p.port = m_servers.value(server).toObject().value(QStringLiteral("ports")).toObject().value(instance).toInt();
        p.username = user;
        p.options.insert(QStringLiteral("auth_mode"), authMode);
        return p;
    }

    // docker exec <container> sh -c <script>, with optional environment and stdin.
    QByteArray exec(const QString &server, const QString &script, const QStringList &env = QStringList(),
                    const QByteArray &input = QByteArray(), int *exitCode = nullptr) const
    {
        QStringList arguments { QStringLiteral("exec"), QStringLiteral("-i") };
        for (const QString &variable : env)
            arguments << QStringLiteral("-e") << variable;
        arguments << container(server) << QStringLiteral("sh") << QStringLiteral("-c") << script;
        QProcess process;
        process.start(QStringLiteral("docker"), arguments);
        process.write(input);
        process.closeWriteChannel();
        process.waitForFinished(300000);
        if (exitCode)
            *exitCode = process.exitCode();
        else if (process.exitCode() != 0)
            qWarning() << "docker exec failed:" << script << process.readAllStandardError();
        return process.readAllStandardOutput();
    }

    void docker(const QStringList &arguments) const
    {
        QProcess process;
        process.start(QStringLiteral("docker"), arguments);
        process.waitForFinished(60000);
    }

    QByteArray serverSha(const QString &server, const QString &path) const
    {
        return exec(server, QStringLiteral("sha256sum \"$P\""), { QStringLiteral("P=") + path }).split(' ').value(0);
    }

    QString serverMode(const QString &server, const QString &path) const
    {
        return QString::fromLatin1(exec(server, QStringLiteral("stat -c %a \"$P\""), { QStringLiteral("P=") + path }))
            .trimmed();
    }

    QString serverLog(const QString &server, const QString &instance) const
    {
        return QString::fromUtf8(exec(server, QStringLiteral("cat /var/log/sshd-%1.log").arg(instance)));
    }

    // "SHA256:..." of the server's host key of `algorithm`, by ssh-keygen -lf (S-6).
    QString serverFingerprint(const QString &server, const QString &algorithm) const
    {
        return QString::fromLatin1(exec(server, QStringLiteral("ssh-keygen -lf /etc/ssh/ssh_host_%1_key.pub")
                                                    .arg(keyFileType(algorithm)))
                                       .split(' ')
                                       .value(1));
    }

    static QString keyFileType(const QString &algorithm)
    {
        if (algorithm.startsWith(QLatin1String("ecdsa")))
            return QStringLiteral("ecdsa");
        return algorithm == QLatin1String("ssh-rsa") ? QStringLiteral("rsa") : QStringLiteral("ed25519");
    }

    void authorizeKey(const QString &server, const QString &user, const QString &publicLine) const
    {
        exec(server, QStringLiteral("cat >> /etc/ssh/authorized_keys/%1 && chmod 644 /etc/ssh/authorized_keys/%1")
                         .arg(user),
             QStringList(), publicLine.toLatin1() + '\n');
    }

    // The identity the server presents, without a pin (account creation).
    QString pinOf(const ConnectionParams &p) const
    {
        const std::unique_ptr<Backend> b(BackendLoader::create(QStringLiteral("sftp")));
        ServerIdentity seen;
        const Result r = b->connect(p, &seen);
        if (!r.ok())
            qWarning() << "identify failed:" << r.toString();
        return seen.toPin();
    }

    // Pins the server key, then connects and signs in (SEC-1 order).
    Result signIn(Backend *b, ConnectionParams p, const QByteArray &secret) const
    {
        p.options.insert(QStringLiteral("host_key"), pinOf(p));
        return establish(b, p, Credentials(p.username, secret));
    }

    std::unique_ptr<Backend> signedIn(const ConnectionParams &p, const QByteArray &secret) const
    {
        std::unique_ptr<Backend> b(BackendLoader::create(QStringLiteral("sftp")));
        const Result r = signIn(b.get(), p, secret);
        if (!r.ok()) {
            qWarning() << "sign-in failed:" << r.toString();
            return nullptr;
        }
        return b;
    }

    // SPEC-sftp 8: makePath, 64 MiB upload, list, free space, download and
    // SHA-256 comparison on the client and on the server's disk; S-20 modes.
    void fullFlow(Backend *b, const QString &server, const QString &dir, const QString &diskDir,
                  bool statvfs = true)
    {
        QVERIFY(b);
        Result r = b->makePath(dir);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        const QString target = Paths::join(dir, QStringLiteral("backup.tar"));
        QElapsedTimer timer;
        timer.start();
        r = Transfer::uploadFile(b, m_bigFile, target);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        const qint64 uploadMs = timer.restart();

        QVector<Entry> entries;
        r = b->list(dir, &entries);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(entries.size(), 1);   // no .part left behind (C-12)
        QCOMPARE(entries.at(0).name, QStringLiteral("backup.tar"));
        QCOMPARE(entries.at(0).size, BigFileSize);
        QVERIFY(!entries.at(0).isDir);
        QVERIFY(entries.at(0).modified.isValid());

        qint64 available = -1;
        r = b->freeSpace(dir, &available);
        if (statvfs) {
            QVERIFY2(r.ok(), qPrintable(r.toString()));
            QVERIFY(available > 0);
        } else {
            QCOMPARE(r.error(), Error::Unsupported);
        }

        const QString local = m_tmp.filePath(unique(QStringLiteral("download-")));
        timer.restart();
        r = Transfer::downloadFile(b, target, local);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        const qint64 downloadMs = timer.elapsed();
        QCOMPARE(fileSha256(local), m_bigSha);
        QFile::remove(local);
        QCOMPARE(serverSha(server, Paths::join(diskDir, QStringLiteral("backup.tar"))), m_bigSha);
        QCOMPARE(serverMode(server, diskDir), QStringLiteral("700"));   // S-20
        QCOMPARE(serverMode(server, Paths::join(diskDir, QStringLiteral("backup.tar"))), QStringLiteral("600"));
        qInfo("64 MiB: upload %lld ms, download %lld ms", uploadMs, downloadMs);

        r = b->remove(target);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
    }

    // S-T8: the reference OpenSSH client inside the container fetches a file.
    QByteArray clientFetch(const QString &server, int internalPort, const QString &user, const QString &remote) const
    {
        const QString batch = QStringLiteral("get \"%1\" /tmp/fetched.bin\n").arg(remote);
        int code = -1;
        exec(server, QStringLiteral("rm -f /tmp/fetched.bin && sftp -q -b - -i /setup/client_key "
                                    "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P %1 %2@127.0.0.1")
                         .arg(internalPort).arg(user),
             QStringList(), batch.toUtf8(), &code);
        if (code != 0)
            return QByteArray();
        return serverSha(server, QStringLiteral("/tmp/fetched.bin"));
    }

    // Runs `work` on a worker thread (the backend's thread), pauses it at the
    // gate, applies `atGate` on this thread and returns the milliseconds from
    // `atGate` to the end of `work`.
    qint64 interrupt(GateProgress *gate, const std::function<Result()> &work,
                     const std::function<void()> &atGate, Result *result) const
    {
        QFuture<Result> future = QtConcurrent::run(work);
        if (!gate->waitReached(120000)) {
            gate->proceed();
            *result = future.result();
            return -1;
        }
        QElapsedTimer timer;
        timer.start();
        atGate();
        gate->proceed();
        *result = future.result();
        return timer.elapsed();
    }

private slots:
    void initTestCase()
    {
        const QByteArray configPath = qgetenv("NETVFS_SFTP_INTEROP_CONFIG");
        if (configPath.isEmpty())
            QSKIP("Run through tests/interop/sftp/run.sh");
        QFile config(QString::fromLocal8Bit(configPath));
        QVERIFY(config.open(QIODevice::ReadOnly));
        const QJsonObject root = QJsonDocument::fromJson(config.readAll()).object();
        m_servers = root.value(QStringLiteral("servers")).toObject();
        m_password = root.value(QStringLiteral("password")).toString().toLatin1();
        QVERIFY(!m_password.isEmpty());
        QVERIFY(m_tmp.isValid());
        m_tools = BackendLoader::sshKeyTools();
        QVERIFY(m_tools);

        // Pseudo-random, incompressible content.
        m_bigFile = m_tmp.filePath(QStringLiteral("big.bin"));
        QFile big(m_bigFile);
        QVERIFY(big.open(QIODevice::WriteOnly));
        QByteArray block(1024 * 1024, Qt::Uninitialized);
        quint64 state = 0x9e3779b97f4a7c15ULL;
        for (qint64 written = 0; written < BigFileSize; written += block.size()) {
            for (int i = 0; i < block.size(); i += 8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                memcpy(block.data() + i, &state, 8);
            }
            QCOMPARE(big.write(block), qint64(block.size()));
        }
        big.close();
        m_bigSha = fileSha256(m_bigFile);

        logCapture().previous = qInstallMessageHandler(captureLog);
        QLoggingCategory::setFilterRules(QStringLiteral("netvfs.sftp.debug=true"));
    }

    void cleanupTestCase()
    {
        if (logCapture().previous)
            qInstallMessageHandler(logCapture().previous);
        if (!m_servers.isEmpty())
            docker({ QStringLiteral("unpause"), container(QStringLiteral("o89")) });
    }

    // S-T1, S-6, S-7
    void openssh103Password()
    {
        const ConnectionParams p = params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice"));
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        ServerIdentity seen;
        Result r = b->connect(p, &seen);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(seen.algorithm, QStringLiteral("ssh-ed25519"));
        QCOMPARE(seen.fingerprint, serverFingerprint(QStringLiteral("o103"), seen.algorithm));
        b->disconnect();

        // No pin (account creation): the identity is reported, nothing is sent.
        r = establish(b.get(), p, Credentials(p.username, m_password));
        QCOMPARE(r.error(), Error::ServerIdentityUnknown);
        QVERIFY(r.message().contains(seen.fingerprint));

        clearLog();
        r = signIn(b.get(), p, m_password);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QVERIFY2(capturedLog().contains(QLatin1String("mlkem768x25519-sha256")), qPrintable(capturedLog()));
        QVERIFY(serverLog(QStringLiteral("o103"), QStringLiteral("default"))
                    .contains(QLatin1String("kex: algorithm: mlkem768x25519-sha256")));
        fullFlow(b.get(), QStringLiteral("o103"), QStringLiteral("netvfs-it/st01"),
                         QStringLiteral("/home/alice/netvfs-it/st01"));
    }

    // S-T2, S-19 (absolute and relative paths in a chroot), section 9
    void openssh103Hardened()
    {
        SshKeyMaterial key;
        QVERIFY(m_tools->generate(&key).ok());
        authorizeKey(QStringLiteral("o103"), QStringLiteral("backup"), key.publicLine);
        const ConnectionParams p = params(QStringLiteral("o103"), QStringLiteral("hardened"), QStringLiteral("backup"),
                                          QStringLiteral("publickey"));
        clearLog();
        auto b = signedIn(p, encodeKeySecret(key.privateKey));
        QVERIFY(b);
        QVERIFY(capturedLog().contains(QLatin1String("mlkem768x25519-sha256")));
        fullFlow(b.get(), QStringLiteral("o103"), QStringLiteral("/data/Sailfish OS/Backups"),
                         QStringLiteral("/srv/sftpjail/data/Sailfish OS/Backups"));
        if (QTest::currentTestFailed())
            return;

        // Relative to the start directory, which is /data inside the jail.
        const Result made = b->makePath(QStringLiteral("relative/dir"));
        QVERIFY2(made.ok(), qPrintable(made.toString()));
        QCOMPARE(serverMode(QStringLiteral("o103"), QStringLiteral("/srv/sftpjail/data/relative/dir")),
                 QStringLiteral("700"));
        Entry entry;
        QVERIFY(b->stat(QStringLiteral("/"), &entry).ok());
        QVERIFY(entry.isDir);

        // The 10.3p1 sftp client reads what we uploaded.
        QByteArray data(300000, 'h');
        QBuffer buffer(&data);
        QVERIFY(buffer.open(QIODevice::ReadOnly));
        QVERIFY(Transfer::upload(b.get(), &buffer, data.size(), QStringLiteral("relative/h.bin")).ok());
        QCOMPARE(clientFetch(QStringLiteral("o103"), 2202, QStringLiteral("backup"), QStringLiteral("/data/relative/h.bin")),
                 QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
    }

    // S-T3
    void openssh96PasswordAndKey()
    {
        clearLog();
        auto b = signedIn(params(QStringLiteral("o96"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        QVERIFY2(capturedLog().contains(QLatin1String("sntrup761x25519-sha512")), qPrintable(capturedLog()));
        fullFlow(b.get(), QStringLiteral("o96"), QStringLiteral("netvfs-it/st03-password"),
                         QStringLiteral("/home/alice/netvfs-it/st03-password"));
        if (QTest::currentTestFailed())
            return;
        b.reset();

        SshKeyMaterial key;
        QVERIFY(m_tools->generate(&key).ok());
        authorizeKey(QStringLiteral("o96"), QStringLiteral("alice"), key.publicLine);
        b = signedIn(params(QStringLiteral("o96"), QStringLiteral("default"), QStringLiteral("alice"),
                            QStringLiteral("publickey")),
                     encodeKeySecret(key.privateKey));
        fullFlow(b.get(), QStringLiteral("o96"), QStringLiteral("netvfs-it/st03-key"),
                         QStringLiteral("/home/alice/netvfs-it/st03-key"));
    }

    // S-T4
    void curve25519Only()
    {
        Curve25519OnlyBackend b;
        clearLog();
        const Result r = signIn(&b, params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")),
                                m_password);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QVERIFY2(capturedLog().contains(QLatin1String("Key exchange curve25519-sha256")), qPrintable(capturedLog()));
        QVERIFY(serverLog(QStringLiteral("o103"), QStringLiteral("default"))
                    .contains(QLatin1String("kex: algorithm: curve25519-sha256")));
        fullFlow(&b, QStringLiteral("o103"), QStringLiteral("netvfs-it/st04"),
                         QStringLiteral("/home/alice/netvfs-it/st04"));
    }

    // S-T5, S-7, SEC-1: refused before authentication.
    void pinnedKeyDiffers()
    {
        const QString probe = unique(QStringLiteral("pinprobe"));
        ConnectionParams p = params(QStringLiteral("o103"), QStringLiteral("default"), probe);
        const QString actual = pinOf(p);
        // A key of the same type from another server.
        p.options.insert(QStringLiteral("host_key"),
                         pinOf(params(QStringLiteral("o96"), QStringLiteral("default"), probe)));
        QVERIFY(p.option(QStringLiteral("host_key")) != actual);

        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        ServerIdentity seen;
        Result r = establish(b.get(), p, Credentials(probe, m_password), &seen);
        QCOMPARE(r.error(), Error::ServerIdentityChanged);
        QCOMPARE(seen.toPin(), actual);   // recorded as host_key_seen by the caller

        // Even without the caller's check, authenticate() refuses.
        r = b->connect(p, &seen);
        QVERIFY(r.ok());
        r = b->authenticate(Credentials(probe, m_password));
        QCOMPARE(r.error(), Error::ServerIdentityChanged);
        b->disconnect();

        // The pinned type is not offered at all (S-5): the backend reports the
        // key the server has now instead of a key exchange failure.
        ConnectionParams hardened = params(QStringLiteral("o103"), QStringLiteral("hardened"), probe);
        const QString hardenedKey = pinOf(hardened);
        const QString ecdsa = QString::fromLatin1(exec(QStringLiteral("o96"),
                                                       QStringLiteral("cat /etc/ssh/ssh_host_ecdsa_key.pub")))
                                  .section(QLatin1Char(' '), 0, 1);
        hardened.options.insert(QStringLiteral("host_key"), ecdsa);
        r = establish(b.get(), hardened, Credentials(probe, m_password), &seen);
        QCOMPARE(r.error(), Error::ServerIdentityChanged);
        QCOMPARE(seen.toPin(), hardenedKey);

        // The server never saw an authentication request from the probe user.
        QVERIFY(!serverLog(QStringLiteral("o103"), QStringLiteral("default")).contains(probe));
        QVERIFY(!serverLog(QStringLiteral("o103"), QStringLiteral("hardened")).contains(probe));
        // Positive control: with the right pin the request is logged.
        p.options.insert(QStringLiteral("host_key"), actual);
        r = establish(b.get(), p, Credentials(probe, m_password));
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY(serverLog(QStringLiteral("o103"), QStringLiteral("default")).contains(probe));
    }

    // S-T6; SPEC-sftp 2: a key secret is never sent as a password.
    void wrongPassword()
    {
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        const ConnectionParams p = params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice"));
        Result r = signIn(b.get(), p, m_password + "-wrong");
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY(r.message().contains(QLatin1String("password")));

        SshKeyMaterial key;
        QVERIFY(m_tools->generate(&key).ok());
        const QString probe = unique(QStringLiteral("keyprobe"));
        r = signIn(b.get(), params(QStringLiteral("o103"), QStringLiteral("default"), probe),
                   encodeKeySecret(key.privateKey));
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY(!serverLog(QStringLiteral("o103"), QStringLiteral("default")).contains(probe));
        // ... and a password is never treated as a key.
        r = signIn(b.get(), params(QStringLiteral("o103"), QStringLiteral("default"), probe, QStringLiteral("publickey")),
                   m_password);
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY(!serverLog(QStringLiteral("o103"), QStringLiteral("default")).contains(probe));
    }

    // S-T7, S-14
    void passwordOnKeyOnlyServer()
    {
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        const Result r = signIn(b.get(), params(QStringLiteral("o103"), QStringLiteral("hardened"),
                                                QStringLiteral("backup")),
                                m_password);
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY2(r.message().contains(QLatin1String("publickey")), qPrintable(r.message()));
        QVERIFY(r.message().contains(QLatin1String("only accepts SSH keys")));
        // The password was not offered to a server that does not take one.
        QVERIFY(!serverLog(QStringLiteral("o103"), QStringLiteral("hardened")).contains(QLatin1String("method password")));
    }

    // S-T8
    void referenceClient_data()
    {
        QTest::addColumn<QString>("server");
        QTest::newRow("10.3p1") << "o103";
        QTest::newRow("9.6p1") << "o96";
    }

    void referenceClient()
    {
        QFETCH(QString, server);
        auto b = signedIn(params(server, QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        QVERIFY(b->makePath(QStringLiteral("netvfs-it/st08")).ok());
        Result r = Transfer::uploadFile(b.get(), m_bigFile, QStringLiteral("netvfs-it/st08/ours.bin"));
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(clientFetch(server, 2201, QStringLiteral("alice"), QStringLiteral("netvfs-it/st08/ours.bin")), m_bigSha);

        int code = -1;
        exec(server, QStringLiteral("head -c 5000000 /dev/urandom > /tmp/theirs.bin && sftp -q -b - -i /setup/client_key "
                                    "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 2201 alice@127.0.0.1"),
             QStringList(), "put /tmp/theirs.bin netvfs-it/st08/theirs.bin\n", &code);
        QCOMPARE(code, 0);
        QVector<Entry> entries;
        QVERIFY(b->list(QStringLiteral("netvfs-it/st08"), &entries).ok());
        bool listed = false;
        for (const Entry &entry : entries)
            listed = listed || (entry.name == QLatin1String("theirs.bin") && entry.size == 5000000);
        QVERIFY(listed);
        const QString local = m_tmp.filePath(QStringLiteral("theirs.bin"));
        QVERIFY(Transfer::downloadFile(b.get(), QStringLiteral("netvfs-it/st08/theirs.bin"), local).ok());
        QCOMPARE(fileSha256(local), serverSha(server, QStringLiteral("/tmp/theirs.bin")));
    }

    // S-T9
    void openssh89()
    {
        auto b = signedIn(params(QStringLiteral("o89"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        fullFlow(b.get(), QStringLiteral("o89"), QStringLiteral("netvfs-it/st09"),
                         QStringLiteral("/home/alice/netvfs-it/st09"));
    }

    // S-T10, S-5, S-6
    void hostKeyTypes_data()
    {
        QTest::addColumn<QString>("server");
        QTest::addColumn<QString>("type");
        for (const char *server : { "o103", "o96" }) {
            for (const char *type : { "ed25519", "ecdsa", "rsa" })
                QTest::newRow(qPrintable(QStringLiteral("%1 %2").arg(QLatin1String(server), QLatin1String(type))))
                    << server << type;
        }
    }

    void hostKeyTypes()
    {
        QFETCH(QString, server);
        QFETCH(QString, type);
        const QString pin = QString::fromLatin1(exec(server, QStringLiteral("cat /etc/ssh/ssh_host_%1_key.pub").arg(type)))
                                .section(QLatin1Char(' '), 0, 1);
        ConnectionParams p = params(server, QStringLiteral("default"), QStringLiteral("alice"));
        p.options.insert(QStringLiteral("host_key"), pin);
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        ServerIdentity seen;
        Result r = establish(b.get(), p, Credentials(p.username, m_password), &seen);
        QVERIFY2(r.ok(), qPrintable(r.toString()));   // no false mismatch
        QCOMPARE(seen.toPin(), pin);
        QCOMPARE(seen.fingerprint, serverFingerprint(server, seen.algorithm));
        Entry entry;
        QVERIFY(b->stat(QString(), &entry).ok());
        QVERIFY(entry.isDir);
    }

    // S-T11, S-11
    void keyboardInteractive()
    {
        const ConnectionParams p = params(QStringLiteral("o96"), QStringLiteral("kbdint"), QStringLiteral("alice"));
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        Result r = signIn(b.get(), p, m_password + "-wrong");
        QCOMPARE(r.error(), Error::AuthFailed);
        r = signIn(b.get(), p, m_password);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        fullFlow(b.get(), QStringLiteral("o96"), QStringLiteral("netvfs-it/st11"),
                         QStringLiteral("/home/alice/netvfs-it/st11"));
    }

    // S-T12, S-12
    void importedKeys_data()
    {
        QTest::addColumn<QString>("keygen");
        QTest::addColumn<QByteArray>("passphrase");
        QTest::addColumn<QString>("algorithm");
        QTest::newRow("rsa 3072") << "-t rsa -b 3072 -m PEM" << QByteArray() << "ssh-rsa";
        QTest::newRow("ecdsa p256") << "-t ecdsa -b 256" << QByteArray() << "ecdsa-sha2-nistp256";
        QTest::newRow("ed25519 passphrase") << "-t ed25519" << QByteArray("open sesame") << "ssh-ed25519";
    }

    void importedKeys()
    {
        QFETCH(QString, keygen);
        QFETCH(QByteArray, passphrase);
        QFETCH(QString, algorithm);
        const QByteArray file = exec(QStringLiteral("o103"),
                                     QStringLiteral("rm -f /tmp/k /tmp/k.pub && ssh-keygen -q %1 -N \"$PASS\" -f /tmp/k "
                                                    "&& cat /tmp/k").arg(keygen),
                                     { QStringLiteral("PASS=") + QString::fromLatin1(passphrase) });
        SshKeyMaterial key;
        Result r = m_tools->importKey(file, passphrase, &key);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(key.algorithm, algorithm);
        authorizeKey(QStringLiteral("o103"), QStringLiteral("alice"), key.publicLine);
        auto b = signedIn(params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice"),
                                 QStringLiteral("publickey")),
                          encodeKeySecret(key.privateKey));
        const QString dir = QStringLiteral("netvfs-it/st12-%1").arg(algorithm);
        fullFlow(b.get(), QStringLiteral("o103"), dir, QStringLiteral("/home/alice/") + dir);
    }

    // S-T13, S-17
    void installKeyWithPassword()
    {
        SshKeyMaterial key;
        QVERIFY(m_tools->generate(&key).ok());
        const ConnectionParams p = params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("carol"));
        auto b = signedIn(p, m_password);
        QVERIFY(b);
        Result r = installAuthorizedKey(b.get(), key.publicLine);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        r = installAuthorizedKey(b.get(), key.publicLine);   // already present: unchanged
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        b.reset();
        QCOMPARE(serverMode(QStringLiteral("o103"), QStringLiteral("/home/carol/.ssh")), QStringLiteral("700"));
        QCOMPARE(serverMode(QStringLiteral("o103"), QStringLiteral("/home/carol/.ssh/authorized_keys")),
                 QStringLiteral("600"));
        QCOMPARE(exec(QStringLiteral("o103"), QStringLiteral("grep -c sailfish-backup /home/carol/.ssh/authorized_keys"))
                     .trimmed(),
                 QByteArray("1"));

        ConnectionParams keyParams = p;
        keyParams.options.insert(QStringLiteral("auth_mode"), QStringLiteral("publickey"));
        b = signedIn(keyParams, encodeKeySecret(key.privateKey));
        fullFlow(b.get(), QStringLiteral("o103"), QStringLiteral("netvfs-it/st13"),
                         QStringLiteral("/home/carol/netvfs-it/st13"));
    }

    // S-T14, S-19
    void relativeFolderWithSpace()
    {
        auto b = signedIn(params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        fullFlow(b.get(), QStringLiteral("o103"), QStringLiteral("Sailfish OS/Backups"),
                         QStringLiteral("/home/alice/Sailfish OS/Backups"));
    }

    // S-T15
    void fullDisk()
    {
        auto b = signedIn(params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const QString dir = QStringLiteral("/srv/small/alice/st15");
        QVERIFY(b->makePath(dir).ok());
        QByteArray data(16 * 1024 * 1024, 'x');
        QBuffer buffer(&data);
        QVERIFY(buffer.open(QIODevice::ReadOnly));

        // Known size: refused before transferring (C-13).
        Result r = Transfer::upload(b.get(), &buffer, data.size(), Paths::join(dir, QStringLiteral("a.tar")));
        QCOMPARE(r.error(), Error::NoSpace);
        // Unknown size: the write fails and the backend maps it (section 7).
        buffer.seek(0);
        r = Transfer::upload(b.get(), &buffer, -1, Paths::join(dir, QStringLiteral("b.tar")));
        QCOMPARE(r.error(), Error::NoSpace);
        QVERIFY(r.message().contains(QLatin1String("no space")));

        QVector<Entry> entries;
        QVERIFY(b->list(dir, &entries).ok());
        QVERIFY(entries.isEmpty());   // no partial file
        QCOMPARE(exec(QStringLiteral("o103"), QStringLiteral("ls -A /srv/small/alice/st15")), QByteArray());
    }

    // S-T16, C-9
    void cancelTransfers()
    {
        const ConnectionParams p = params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice"));
        std::unique_ptr<Backend> b;
        const QString target = QStringLiteral("netvfs-it/st16/backup.tar");
        GateProgress uploadGate(4 * 1024 * 1024);
        Result r;
        qint64 ms = interrupt(
            &uploadGate,
            [&]() {
                b = signedIn(p, m_password);
                if (!b || !b->makePath(QStringLiteral("netvfs-it/st16")).ok())
                    return Result(Error::Internal, QStringLiteral("setup failed"));
                return Transfer::uploadFile(b.get(), m_bigFile, target, &uploadGate);
            },
            [&]() { b->cancel(); }, &r);
        QCOMPARE(r.error(), Error::Canceled);
        QVERIFY2(ms >= 0 && ms <= CancelBoundMs, qPrintable(QString::number(ms)));
        Entry entry;
        QCOMPARE(b->stat(Transfer::partName(target), &entry).error(), Error::NotFound);   // .part removed
        QCOMPARE(b->stat(target, &entry).error(), Error::NotFound);

        QVERIFY(Transfer::uploadFile(b.get(), m_bigFile, target).ok());
        const QString local = m_tmp.filePath(QStringLiteral("canceled.tar"));
        GateProgress downloadGate(4 * 1024 * 1024);
        ms = interrupt(
            &downloadGate, [&]() { return Transfer::downloadFile(b.get(), target, local, &downloadGate); },
            [&]() { b->cancel(); }, &r);
        QCOMPARE(r.error(), Error::Canceled);
        QVERIFY2(ms >= 0 && ms <= CancelBoundMs, qPrintable(QString::number(ms)));
        QVERIFY(!QFile::exists(Transfer::partName(local)));
        QVERIFY(!QFile::exists(local));
        // The connection is still usable.
        b->resetCancel();
        QVERIFY(b->stat(target, &entry).ok());
        QCOMPARE(entry.size, BigFileSize);
    }

    // C-9 and C-14 while the server does not answer at all.
    void stalledServer()
    {
        ConnectionParams p = params(QStringLiteral("o89"), QStringLiteral("default"), QStringLiteral("alice"));
        p.requestTimeoutMs = 3000;
        auto b = signedIn(p, m_password);
        QVERIFY(b);
        QVERIFY(Transfer::uploadFile(b.get(), m_bigFile, QStringLiteral("stall.bin")).ok());
        const QString paused = container(QStringLiteral("o89"));

        QBuffer sink;
        QVERIFY(sink.open(QIODevice::WriteOnly));
        GateProgress cancelGate(1024 * 1024);
        Result r;
        Backend *raw = b.get();
        qint64 ms = interrupt(
            &cancelGate, [&]() { return raw->download(QStringLiteral("stall.bin"), &sink, &cancelGate); },
            [&]() {
                docker({ QStringLiteral("pause"), paused });
                raw->cancel();
            },
            &r);
        docker({ QStringLiteral("unpause"), paused });
        QCOMPARE(r.error(), Error::Canceled);
        QVERIFY2(ms >= 0 && ms <= CancelBoundMs + 1000, qPrintable(QString::number(ms)));   // + docker pause itself

        b = signedIn(p, m_password);
        QVERIFY(b);
        raw = b.get();
        sink.close();
        QVERIFY(sink.open(QIODevice::WriteOnly | QIODevice::Truncate));
        GateProgress timeoutGate(1024 * 1024);
        ms = interrupt(
            &timeoutGate, [&]() { return raw->download(QStringLiteral("stall.bin"), &sink, &timeoutGate); },
            [&]() { docker({ QStringLiteral("pause"), paused }); }, &r);
        docker({ QStringLiteral("unpause"), paused });
        QVERIFY2(r.error() == Error::Timeout, qPrintable(r.toString()));
        QVERIFY2(ms >= 2500 && ms <= 8000, qPrintable(QString::number(ms)));
    }

    // S-T17, S-22
    void withoutExtensions_data()
    {
        QTest::addColumn<QString>("server");
        QTest::newRow("10.3p1") << "o103";
        QTest::newRow("9.6p1") << "o96";
    }

    void withoutExtensions()
    {
        QFETCH(QString, server);
        auto b = signedIn(params(server, QStringLiteral("noext"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        fullFlow(b.get(), server, QStringLiteral("netvfs-it/st17"), QStringLiteral("/home/alice/netvfs-it/st17"),
                         false);
        if (QTest::currentTestFailed())
            return;
        // Upload over an existing file: the plain SFTP rename must not fail.
        for (const QByteArray &content : { QByteArray("first version"), QByteArray("second version") }) {
            QByteArray data = content;
            QBuffer buffer(&data);
            QVERIFY(buffer.open(QIODevice::ReadOnly));
            const Result r = Transfer::upload(b.get(), &buffer, data.size(), QStringLiteral("netvfs-it/st17/same.txt"));
            QVERIFY2(r.ok(), qPrintable(r.toString()));
        }
        QCOMPARE(exec(server, QStringLiteral("cat /home/alice/netvfs-it/st17/same.txt")), QByteArray("second version"));
    }

    // Section 7: "sftp subsystem refused".
    void subsystemRefused()
    {
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        const Result r = signIn(b.get(), params(QStringLiteral("o103"), QStringLiteral("nosftp"), QStringLiteral("alice")),
                                m_password);
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.message(), QStringLiteral("SFTP is not enabled for this user"));
    }

    // S-2: libssh defaults are not widened; no common algorithm is SecurityPolicy.
    void noCommonAlgorithm()
    {
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        for (int attempt = 0; attempt < 5; ++attempt) {
            ServerIdentity seen;
            const Result r = b->connect(params(QStringLiteral("o96"), QStringLiteral("legacy"), QStringLiteral("alice")),
                                        &seen);
            QVERIFY2(r.error() == Error::SecurityPolicy, qPrintable(r.toString()));
            QVERIFY(r.message().contains(QLatin1String("diffie-hellman-group14-sha1")));
            QVERIFY(seen.isEmpty());
        }
    }

    // S-13, S-14 with a server that wants a key and then a password.
    void secondFactor()
    {
        SshKeyMaterial key;
        QVERIFY(m_tools->generate(&key).ok());
        authorizeKey(QStringLiteral("o103"), QStringLiteral("twofactor"), key.publicLine);
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        Result r = signIn(b.get(), params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("twofactor"),
                                          QStringLiteral("publickey")),
                          encodeKeySecret(key.privateKey));
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY2(r.message().contains(QLatin1String("second sign-in step")), qPrintable(r.message()));
        r = signIn(b.get(), params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("twofactor")),
                   m_password);
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY2(r.message().contains(QLatin1String("publickey")), qPrintable(r.message()));
    }

    // Error mapping (section 7) and the remaining Backend operations.
    void operationsAndErrors()
    {
        auto b = signedIn(params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const QString dir = QStringLiteral("netvfs-it/ops");
        QVERIFY(b->makePath(dir).ok());
        QVERIFY(b->makePath(dir).ok());   // exists already
        Entry entry;
        QVector<Entry> entries;
        qint64 bytes = 0;
        QByteArray data;
        QCOMPARE(b->stat(dir + QStringLiteral("/nope"), &entry).error(), Error::NotFound);
        QCOMPARE(b->list(dir + QStringLiteral("/nope"), &entries).error(), Error::NotFound);
        QCOMPARE(b->remove(dir + QStringLiteral("/nope")).error(), Error::NotFound);
        QCOMPARE(b->rename(dir + QStringLiteral("/nope"), dir + QStringLiteral("/x")).error(), Error::NotFound);
        QCOMPARE(b->freeSpace(dir + QStringLiteral("/nope"), &bytes).error(), Error::NotFound);
        QCOMPARE(b->read(dir + QStringLiteral("/nope"), 0, 1, &data).error(), Error::NotFound);
        QBuffer sink;
        QVERIFY(sink.open(QIODevice::WriteOnly));
        QCOMPARE(b->download(dir + QStringLiteral("/nope"), &sink, nullptr).error(), Error::NotFound);
        QCOMPARE(b->stat(dir + QStringLiteral("/../x"), &entry).error(), Error::Internal);   // C-15
        QCOMPARE(b->makePath(QStringLiteral("/root/netvfs")).error(), Error::PermissionDenied);
        QByteArray content("0123456789abcdefghij");
        QBuffer source(&content);
        QVERIFY(source.open(QIODevice::ReadOnly));
        QCOMPARE(b->upload(&source, QStringLiteral("/root/x"), nullptr).error(), Error::PermissionDenied);

        source.seek(0);
        QVERIFY(b->upload(&source, dir + QStringLiteral("/a.txt"), nullptr).ok());
        QCOMPARE(b->makePath(dir + QStringLiteral("/a.txt/sub")).error(), Error::AlreadyExists);
        QCOMPARE(b->makePath(dir + QStringLiteral("/a.txt")).error(), Error::AlreadyExists);
        QVERIFY(b->read(dir + QStringLiteral("/a.txt"), 5, 10, &data).ok());   // C-11
        QCOMPARE(data, QByteArray("56789abcde"));
        QVERIFY(b->read(dir + QStringLiteral("/a.txt"), 15, 100, &data).ok());
        QCOMPARE(data, QByteArray("fghij"));
        QCOMPARE(b->read(dir + QStringLiteral("/a.txt"), -1, 1, &data).error(), Error::Internal);

        // rename replaces an existing target (posix-rename here).
        QByteArray other("other");
        QBuffer otherSource(&other);
        QVERIFY(otherSource.open(QIODevice::ReadOnly));
        QVERIFY(b->upload(&otherSource, dir + QStringLiteral("/b.txt"), nullptr).ok());
        QVERIFY(b->rename(dir + QStringLiteral("/b.txt"), dir + QStringLiteral("/a.txt")).ok());
        QVERIFY(b->stat(dir + QStringLiteral("/a.txt"), &entry).ok());
        QCOMPARE(entry.size, qint64(5));
        QCOMPARE(entry.name, QStringLiteral("a.txt"));

        // A local sink that cannot be written, a source that cannot be read.
        QBuffer readOnly;
        QVERIFY(readOnly.open(QIODevice::ReadOnly));
        QCOMPARE(b->download(dir + QStringLiteral("/a.txt"), &readOnly, nullptr).error(), Error::NoSpace);
        FailingSource failing;
        QVERIFY(failing.open(QIODevice::ReadOnly));
        QCOMPARE(b->upload(&failing, dir + QStringLiteral("/c.txt"), nullptr).error(), Error::Internal);

        // Directories: remove() takes empty ones too.
        QVERIFY(b->makePath(dir + QStringLiteral("/empty")).ok());
        QVERIFY(b->remove(dir + QStringLiteral("/empty")).ok());
        QCOMPARE(b->stat(dir + QStringLiteral("/empty"), &entry).error(), Error::NotFound);
        QVERIFY(b->makePath(dir + QStringLiteral("/full/sub")).ok());
        QVERIFY(!b->remove(dir + QStringLiteral("/full")).ok());

        // The start directory and the root.
        QVERIFY(b->list(QString(), &entries).ok());
        bool found = false;
        for (const Entry &e : entries)
            found = found || (e.name == QLatin1String("netvfs-it") && e.isDir);
        QVERIFY(found);
        QVERIFY(b->stat(QStringLiteral("/"), &entry).ok());
        QVERIFY(entry.isDir);

        // A canceled backend refuses work until resetCancel().
        b->cancel();
        QCOMPARE(b->stat(dir, &entry).error(), Error::Canceled);
        b->resetCancel();
        QVERIFY(b->stat(dir, &entry).ok());
        QCOMPARE(b->authenticate(Credentials(QStringLiteral("alice"), m_password)).error(), Error::Internal);

        // A second connect() replaces the first connection.
        ServerIdentity seen;
        QVERIFY(b->connect(params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), &seen).ok());
        QCOMPARE(b->stat(dir, &entry).error(), Error::Internal);
    }
};

QTEST_GUILESS_MAIN(TestInteropSftp)

#include "tst_interop_sftp.moc"
