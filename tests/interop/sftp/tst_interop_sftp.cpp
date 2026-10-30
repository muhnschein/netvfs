// SPDX-License-Identifier: LGPL-2.1-or-later
// SFTP interoperability matrix against the OpenSSH containers started by run.sh, which passes ports and
// test password in the JSON file named by NETVFS_SFTP_INTEROP_CONFIG. Goes through the SFTP plugin of the
// build tree; negotiated algorithms are read from the servers' logs.
#include "backendloader.h"
#include "identity.h"
#include "names.h"
#include "paths.h"
#include "probe.h"
#include "prompter.h"
#include "sshkeys.h"
#include "transfer.h"

#include <QtConcurrent/QtConcurrent>
#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QElapsedTimer>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
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
template<>
char *toString(const NetVfs::EntryType &type)
{
    return qstrdup(QByteArray::number(static_cast<int>(type)).constData());
}
} // namespace QTest

namespace {

constexpr qint64 BigFileSize = 64 * 1024 * 1024;
constexpr qint64 CancelBoundMs = 2000;
constexpr qint64 OwnCancelBoundMs = 500;

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

class FailingSource : public QIODevice
{
protected:
    qint64 readData(char *, qint64) override { return -1; }
    qint64 writeData(const char *, qint64) override { return -1; }
};

class AnsweringPrompter : public AuthPrompter
{
public:
    AnsweringPrompter(const QByteArray &password, const QByteArray &code) : m_password(password), m_code(code) {}

    bool answer(const QString &, const QString &, const QVector<AuthPrompt> &prompts,
                QVector<QByteArray> *answers) override
    {
        for (const AuthPrompt &prompt : prompts) {
            asked << prompt.text;
            if (prompt.echo)
                echoed << prompt.text;
            if (prompt.text.contains(QLatin1String("Password")))
                answers->append(m_password);
            else if (prompt.text.contains(QLatin1String("Verification code")))
                answers->append(m_code);
            else
                answers->append("label");
        }
        return !decline;
    }

    QStringList asked;
    QStringList echoed;
    bool decline = false;

private:
    QByteArray m_password;
    QByteArray m_code;
};

// a person who never answers. cancel() ends the wait; without it
// the prompter gives up after 10 s (so a broken cancel fails, not hangs).
class SilentPrompter : public AuthPrompter
{
public:
    bool answer(const QString &, const QString &, const QVector<AuthPrompt> &, QVector<QByteArray> *) override
    {
        m_asked.release();
        m_canceled.tryAcquire(1, 10000);
        return false;
    }
    void cancel() override { m_canceled.release(); }
    bool waitAsked(int ms) { return m_asked.tryAcquire(1, ms); }

private:
    QSemaphore m_asked;
    QSemaphore m_canceled;
};

// Runs `call` on another thread and cancel()s the backend after 300 ms;
// returns the milliseconds from cancel() to the end of the call.
qint64 runCanceled(Backend *backend, const std::function<Result()> &call, Result *result)
{
    QFuture<Result> future = QtConcurrent::run(call);
    QThread::msleep(300);
    QElapsedTimer timer;
    timer.start();
    backend->cancel();
    *result = future.result();
    return timer.elapsed();
}

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
    QByteArray m_otp;
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
        return withBackupDirMode(p);
    }

    ConnectionParams filesParams(const QString &server, const QString &instance, const QString &user) const
    {
        ConnectionParams p = params(server, instance, user);
        p.options.remove(QLatin1String(DirModeOption));
        return p;
    }

    static bool put(Backend *b, const QString &path, const QByteArray &data,
                    const UploadOptions &options = UploadOptions())
    {
        QByteArray copy = data;
        QBuffer buffer(&copy);
        buffer.open(QIODevice::ReadOnly);
        const Result r = b->upload(&buffer, path, options, nullptr);
        if (!r.ok())
            qWarning() << "upload failed:" << r.toString();
        return r.ok();
    }

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

    QString pinOf(const ConnectionParams &p) const
    {
        const std::unique_ptr<Backend> b(BackendLoader::create(QStringLiteral("sftp")));
        ServerIdentity seen;
        const Result r = b->connect(p, &seen);
        if (!r.ok())
            qWarning() << "identify failed:" << r.toString();
        return seen.toPin();
    }

    Result signIn(Backend *b, ConnectionParams p, const QByteArray &secret, AuthPrompter *prompter = nullptr) const
    {
        p.options.insert(QStringLiteral("host_key"), pinOf(p));
        return establish(b, p, Credentials(p.username, secret), nullptr, prompter);
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

    // makePath, 64 MiB upload, list, free space, download and
    // SHA-256 comparison on the client and on the server's disk; modes.
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
        QCOMPARE(entries.size(), 1);
        QCOMPARE(entries.at(0).name, QStringLiteral("backup.tar"));
        QCOMPARE(entries.at(0).size, BigFileSize);
        QCOMPARE(entries.at(0).type, EntryType::File);
        QCOMPARE(entries.at(0).mode, 0600);
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
        QCOMPARE(serverMode(server, diskDir), QStringLiteral("700"));
        QCOMPARE(serverMode(server, Paths::join(diskDir, QStringLiteral("backup.tar"))), QStringLiteral("600"));
        qInfo("64 MiB: upload %lld ms, download %lld ms", uploadMs, downloadMs);

        r = b->remove(target);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
    }

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
        return interrupt(gate, work, atGate, std::function<void()>(), result);
    }

    // As above; `afterRelease` runs once the worker goes on, and the time is
    // measured from its end.
    qint64 interrupt(GateProgress *gate, const std::function<Result()> &work, const std::function<void()> &atGate,
                     const std::function<void()> &afterRelease, Result *result) const
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
        if (afterRelease) {
            afterRelease();
            timer.restart();
        }
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
        m_otp = root.value(QStringLiteral("otp")).toString().toLatin1();
        QVERIFY(!m_password.isEmpty());
        QVERIFY(m_tmp.isValid());
        m_tools = BackendLoader::sshKeyTools();
        QVERIFY(m_tools);

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
    }

    void cleanupTestCase()
    {
        if (!m_servers.isEmpty()) {
            docker({ QStringLiteral("unpause"), container(QStringLiteral("o89")) });
            exec(QStringLiteral("o89"), QStringLiteral("rm -f /tmp/hold"));
        }
    }

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

        r = establish(b.get(), p, Credentials(p.username, m_password));
        QCOMPARE(r.error(), Error::ServerIdentityUnknown);
        QVERIFY(r.message().contains(seen.fingerprint));

        r = signIn(b.get(), p, m_password);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QVERIFY(serverLog(QStringLiteral("o103"), QStringLiteral("default"))
                    .contains(QLatin1String("kex: algorithm: mlkem768x25519-sha256")));
        fullFlow(b.get(), QStringLiteral("o103"), QStringLiteral("netvfs-it/st01"),
                         QStringLiteral("/home/alice/netvfs-it/st01"));
    }

    void openssh103Hardened()
    {
        SshKeyMaterial key;
        QVERIFY(m_tools->generate(&key).ok());
        authorizeKey(QStringLiteral("o103"), QStringLiteral("backup"), key.publicLine);
        const ConnectionParams p = params(QStringLiteral("o103"), QStringLiteral("hardened"), QStringLiteral("backup"),
                                          QStringLiteral("publickey"));
        auto b = signedIn(p, encodeKeySecret(key.privateKey));
        QVERIFY(b);
        QVERIFY(serverLog(QStringLiteral("o103"), QStringLiteral("hardened"))
                    .contains(QLatin1String("kex: algorithm: mlkem768x25519-sha256")));
        fullFlow(b.get(), QStringLiteral("o103"), QStringLiteral("/data/Sailfish OS/Backups"),
                         QStringLiteral("/srv/sftpjail/data/Sailfish OS/Backups"));
        if (QTest::currentTestFailed())
            return;

        const Result made = b->makePath(QStringLiteral("relative/dir"));
        QVERIFY2(made.ok(), qPrintable(made.toString()));
        QCOMPARE(serverMode(QStringLiteral("o103"), QStringLiteral("/srv/sftpjail/data/relative/dir")),
                 QStringLiteral("700"));
        Entry entry;
        QVERIFY(b->stat(QStringLiteral("/"), &entry).ok());
        QVERIFY(entry.isDir());

        QByteArray data(300000, 'h');
        QBuffer buffer(&data);
        QVERIFY(buffer.open(QIODevice::ReadOnly));
        QVERIFY(Transfer::upload(b.get(), &buffer, data.size(), QStringLiteral("relative/h.bin")).ok());
        QCOMPARE(clientFetch(QStringLiteral("o103"), 2202, QStringLiteral("backup"), QStringLiteral("/data/relative/h.bin")),
                 QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
    }

    // 9.6p1 has no ML-KEM; of its hybrid exchanges the hardened
    // list takes none, so curve25519 it is.
    void openssh96PasswordAndKey()
    {
        auto b = signedIn(params(QStringLiteral("o96"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const QString log = serverLog(QStringLiteral("o96"), QStringLiteral("default"));
        QVERIFY(log.contains(QLatin1String("kex: algorithm: curve25519-sha256")));
        QVERIFY(!log.contains(QLatin1String("kex: algorithm: sntrup")));
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

    // a 10.3p1 server that offers only curve25519 ("curve").
    void curve25519Only()
    {
        auto b = signedIn(params(QStringLiteral("o103"), QStringLiteral("curve"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        QVERIFY(serverLog(QStringLiteral("o103"), QStringLiteral("curve"))
                    .contains(QLatin1String("kex: algorithm: curve25519-sha256")));
        fullFlow(b.get(), QStringLiteral("o103"), QStringLiteral("netvfs-it/st04"),
                 QStringLiteral("/home/alice/netvfs-it/st04"));
    }

    // refused before authentication.
    void pinnedKeyDiffers()
    {
        const QString probe = unique(QStringLiteral("pinprobe"));
        ConnectionParams p = params(QStringLiteral("o103"), QStringLiteral("default"), probe);
        const QString actual = pinOf(p);
        p.options.insert(QStringLiteral("host_key"),
                         pinOf(params(QStringLiteral("o96"), QStringLiteral("default"), probe)));
        QVERIFY(p.option(QStringLiteral("host_key")) != actual);

        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        ServerIdentity seen;
        Result r = establish(b.get(), p, Credentials(probe, m_password), &seen);
        QCOMPARE(r.error(), Error::ServerIdentityChanged);
        QCOMPARE(seen.toPin(), actual);

        r = b->connect(p, &seen);
        QVERIFY(r.ok());
        r = b->authenticate(Credentials(probe, m_password));
        QCOMPARE(r.error(), Error::ServerIdentityChanged);
        b->disconnect();

        // The pinned type is not offered at all: the backend reports the
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

        QVERIFY(!serverLog(QStringLiteral("o103"), QStringLiteral("default")).contains(probe));
        QVERIFY(!serverLog(QStringLiteral("o103"), QStringLiteral("hardened")).contains(probe));
        p.options.insert(QStringLiteral("host_key"), actual);
        r = establish(b.get(), p, Credentials(probe, m_password));
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY(serverLog(QStringLiteral("o103"), QStringLiteral("default")).contains(probe));
    }

    // a key secret is never sent as a password.
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
        r = signIn(b.get(), params(QStringLiteral("o103"), QStringLiteral("default"), probe, QStringLiteral("publickey")),
                   m_password);
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY(!serverLog(QStringLiteral("o103"), QStringLiteral("default")).contains(probe));
    }

    void passwordOnKeyOnlyServer()
    {
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        const Result r = signIn(b.get(), params(QStringLiteral("o103"), QStringLiteral("hardened"),
                                                QStringLiteral("backup")),
                                m_password);
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY2(r.message().contains(QLatin1String("publickey")), qPrintable(r.message()));
        QVERIFY(r.message().contains(QLatin1String("only accepts SSH keys")));
        QVERIFY(!serverLog(QStringLiteral("o103"), QStringLiteral("hardened")).contains(QLatin1String("method password")));
    }

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

    void openssh89()
    {
        auto b = signedIn(params(QStringLiteral("o89"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        fullFlow(b.get(), QStringLiteral("o89"), QStringLiteral("netvfs-it/st09"),
                         QStringLiteral("/home/alice/netvfs-it/st09"));
    }

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
        QVERIFY(entry.isDir());
    }

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

    // RSA user keys are refused with what to do instead.
    void importedKeys_data()
    {
        QTest::addColumn<QString>("keygen");
        QTest::addColumn<QByteArray>("passphrase");
        QTest::addColumn<QString>("algorithm");
        QTest::addColumn<QString>("refusal");
        QTest::newRow("rsa 3072") << "-t rsa -b 3072 -m PEM" << QByteArray() << QString()
                                  << "RSA keys are not supported; generate a new key, or use an Ed25519 or ECDSA key";
        QTest::newRow("rsa 3072 openssh") << "-t rsa -b 3072" << QByteArray("open sesame") << QString()
                                          << "RSA keys are not supported; generate a new key, or use an Ed25519 or ECDSA key";
        QTest::newRow("ecdsa p256") << "-t ecdsa -b 256" << QByteArray() << "ecdsa-sha2-nistp256" << QString();
        QTest::newRow("ecdsa p384 pem") << "-t ecdsa -b 384 -m PEM" << QByteArray() << "ecdsa-sha2-nistp384"
                                        << QString();
        QTest::newRow("ed25519 passphrase") << "-t ed25519" << QByteArray("open sesame") << "ssh-ed25519" << QString();
    }

    void importedKeys()
    {
        QFETCH(QString, keygen);
        QFETCH(QByteArray, passphrase);
        QFETCH(QString, algorithm);
        QFETCH(QString, refusal);
        const QByteArray file = exec(QStringLiteral("o103"),
                                     QStringLiteral("rm -f /tmp/k /tmp/k.pub && ssh-keygen -q %1 -N \"$PASS\" -f /tmp/k "
                                                    "&& cat /tmp/k").arg(keygen),
                                     { QStringLiteral("PASS=") + QString::fromLatin1(passphrase) });
        SshKeyMaterial key;
        Result r = m_tools->importKey(file, passphrase, &key);
        if (!refusal.isEmpty()) {
            QCOMPARE(r.error(), Error::Unsupported);
            QCOMPARE(r.message(), refusal);
            QVERIFY(key.privateKey.isEmpty());
            return;
        }
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(key.algorithm, algorithm);
        authorizeKey(QStringLiteral("o103"), QStringLiteral("alice"), key.publicLine);
        auto b = signedIn(params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice"),
                                 QStringLiteral("publickey")),
                          encodeKeySecret(key.privateKey));
        const QString dir = QStringLiteral("netvfs-it/st12-%1").arg(algorithm);
        fullFlow(b.get(), QStringLiteral("o103"), dir, QStringLiteral("/home/alice/") + dir);
    }

    void installKeyWithPassword()
    {
        SshKeyMaterial key;
        QVERIFY(m_tools->generate(&key).ok());
        const ConnectionParams p = params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("carol"));
        auto b = signedIn(p, m_password);
        QVERIFY(b);
        Result r = installAuthorizedKey(b.get(), key.publicLine);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        r = installAuthorizedKey(b.get(), key.publicLine);
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

    void relativeFolderWithSpace()
    {
        auto b = signedIn(params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        fullFlow(b.get(), QStringLiteral("o103"), QStringLiteral("Sailfish OS/Backups"),
                         QStringLiteral("/home/alice/Sailfish OS/Backups"));
    }

    void fullDisk()
    {
        auto b = signedIn(params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const QString dir = QStringLiteral("/srv/small/alice/st15");
        QVERIFY(b->makePath(dir).ok());
        QByteArray data(16 * 1024 * 1024, 'x');
        QBuffer buffer(&data);
        QVERIFY(buffer.open(QIODevice::ReadOnly));

        Result r = Transfer::upload(b.get(), &buffer, data.size(), Paths::join(dir, QStringLiteral("a.tar")));
        QCOMPARE(r.error(), Error::NoSpace);
        buffer.seek(0);
        r = Transfer::upload(b.get(), &buffer, -1, Paths::join(dir, QStringLiteral("b.tar")));
        QCOMPARE(r.error(), Error::NoSpace);
        QVERIFY(r.message().contains(QLatin1String("no space")));

        QVector<Entry> entries;
        QVERIFY(b->list(dir, &entries).ok());
        QVERIFY(entries.isEmpty());
        QCOMPARE(exec(QStringLiteral("o103"), QStringLiteral("ls -A /srv/small/alice/st15")), QByteArray());
    }

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
        QCOMPARE(b->stat(Transfer::partName(target), &entry).error(), Error::NotFound);
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
        b->resetCancel();
        QVERIFY(b->stat(target, &entry).ok());
        QCOMPARE(entry.size, BigFileSize);
    }

    // and while the server does not answer at all.
    void stalledServer()
    {
        // the server holds its replies back (whole packets only); the
        // worker drains what arrived and then waits; cancel() ends the wait.
        ConnectionParams p = params(QStringLiteral("o89"), QStringLiteral("hold"), QStringLiteral("alice"));
        auto b = signedIn(p, m_password);
        QVERIFY(b);
        QVERIFY(Transfer::uploadFile(b.get(), m_bigFile, QStringLiteral("stall.bin")).ok());
        QBuffer sink;
        QVERIFY(sink.open(QIODevice::WriteOnly));
        GateProgress cancelGate(1024 * 1024);
        Result r;
        Backend *raw = b.get();
        qint64 ms = interrupt(
            &cancelGate, [&]() { return raw->download(QStringLiteral("stall.bin"), &sink, DownloadOptions(), &cancelGate); },
            [&]() { exec(QStringLiteral("o89"), QStringLiteral("touch /tmp/hold")); },
            [&]() {
                QThread::msleep(1000);
                raw->cancel();
            },
            &r);
        exec(QStringLiteral("o89"), QStringLiteral("rm -f /tmp/hold"));
        QCOMPARE(r.error(), Error::Canceled);
        // The backend answers the cancel itself, well before the Rust
        // library's cut of a call 1 s after a cancel (doc/RUST.md, GRACE).
        QVERIFY2(ms >= 0 && ms <= OwnCancelBoundMs, qPrintable(QString::number(ms)));
        QVERIFY(sink.size() < BigFileSize);

        p = params(QStringLiteral("o89"), QStringLiteral("default"), QStringLiteral("alice"));
        p.requestTimeoutMs = 3000;
        b = signedIn(p, m_password);
        QVERIFY(b);
        raw = b.get();
        sink.close();
        QVERIFY(sink.open(QIODevice::WriteOnly | QIODevice::Truncate));
        const QString paused = container(QStringLiteral("o89"));
        GateProgress timeoutGate(1024 * 1024);
        ms = interrupt(
            &timeoutGate, [&]() { return raw->download(QStringLiteral("stall.bin"), &sink, DownloadOptions(), &timeoutGate); },
            [&]() { docker({ QStringLiteral("pause"), paused }); }, &r);
        docker({ QStringLiteral("unpause"), paused });
        QVERIFY2(r.error() == Error::Timeout, qPrintable(r.toString()));
        QVERIFY2(ms >= 2500 && ms <= 8000, qPrintable(QString::number(ms)));
    }

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
        for (const QByteArray &content : { QByteArray("first version"), QByteArray("second version") }) {
            QByteArray data = content;
            QBuffer buffer(&data);
            QVERIFY(buffer.open(QIODevice::ReadOnly));
            const Result r = Transfer::upload(b.get(), &buffer, data.size(), QStringLiteral("netvfs-it/st17/same.txt"));
            QVERIFY2(r.ok(), qPrintable(r.toString()));
        }
        QCOMPARE(exec(server, QStringLiteral("cat /home/alice/netvfs-it/st17/same.txt")), QByteArray("second version"));
    }

    void subsystemRefused()
    {
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        const Result r = signIn(b.get(), params(QStringLiteral("o103"), QStringLiteral("nosftp"), QStringLiteral("alice")),
                                m_password);
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.message(), QStringLiteral("SFTP is not enabled for this user"));
    }

    // the hardened lists are never widened. A server that offers only
    // what they leave out (finite-field Diffie-Hellman, CBC, SHA-1 RSA
    // signatures) is refused with SecurityPolicy before any key is seen,
    // and the message says what the server offers.
    void noCommonAlgorithm_data()
    {
        QTest::addColumn<QString>("server");
        QTest::addColumn<QString>("instance");
        QTest::addColumn<QString>("list");
        QTest::addColumn<QString>("offered");
        QTest::newRow("9.6p1 DH SHA-1") << "o96" << "legacy" << "key exchange" << "diffie-hellman-group14-sha1";
        QTest::newRow("10.3p1 DH only") << "o103" << "dh" << "key exchange"
                                        << "diffie-hellman-group16-sha512, diffie-hellman-group14-sha256";
        QTest::newRow("10.3p1 CBC only") << "o103" << "cbc" << "cipher" << "aes256-cbc, aes128-cbc";
        QTest::newRow("10.3p1 ssh-rsa only") << "o103" << "sha1rsa" << "host key" << "ssh-rsa";
    }

    void noCommonAlgorithm()
    {
        QFETCH(QString, server);
        QFETCH(QString, instance);
        QFETCH(QString, list);
        QFETCH(QString, offered);
        const QString expected = QStringLiteral("The server offers no %1 algorithm this app accepts (it offers %2)")
                                     .arg(list, offered);
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        for (int attempt = 0; attempt < 5; ++attempt) {
            ServerIdentity seen;
            const Result r = b->connect(params(server, instance, QStringLiteral("alice")), &seen);
            QVERIFY2(r.error() == Error::SecurityPolicy, qPrintable(r.toString()));
            QCOMPARE(r.message(), expected);
            QVERIFY(seen.isEmpty());
        }
        // Pinned or not: a pin of a key the server has changes nothing.
        ConnectionParams p = params(server, instance, QStringLiteral("alice"));
        p.options.insert(QStringLiteral("host_key"),
                         QString::fromLatin1(exec(server, QStringLiteral("cat /etc/ssh/ssh_host_rsa_key.pub")))
                             .section(QLatin1Char(' '), 0, 1));
        const Result r = establish(b.get(), p, Credentials(p.username, m_password));
        QVERIFY2(r.error() == Error::SecurityPolicy, qPrintable(r.toString()));
        QVERIFY(!serverLog(server, instance).contains(QLatin1String("Accepted")));
    }

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

    void operationsAndErrors()
    {
        auto b = signedIn(params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const QString dir = QStringLiteral("netvfs-it/ops");
        QVERIFY(b->makePath(dir).ok());
        QVERIFY(b->makePath(dir).ok());
        Entry entry;
        QVector<Entry> entries;
        qint64 bytes = 0;
        QByteArray data;
        QCOMPARE(b->stat(dir + QStringLiteral("/nope"), &entry).error(), Error::NotFound);
        QCOMPARE(b->list(dir + QStringLiteral("/nope"), &entries).error(), Error::NotFound);
        QCOMPARE(b->remove(dir + QStringLiteral("/nope")).error(), Error::NotFound);
        QCOMPARE(b->rename(dir + QStringLiteral("/nope"), dir + QStringLiteral("/x"), RenameMode::Replace).error(),
                 Error::NotFound);
        QCOMPARE(b->freeSpace(dir + QStringLiteral("/nope"), &bytes).error(), Error::NotFound);
        QCOMPARE(b->read(dir + QStringLiteral("/nope"), 0, 1, &data).error(), Error::NotFound);
        QBuffer sink;
        QVERIFY(sink.open(QIODevice::WriteOnly));
        QCOMPARE(b->download(dir + QStringLiteral("/nope"), &sink, DownloadOptions(), nullptr).error(), Error::NotFound);
        QCOMPARE(b->stat(dir + QStringLiteral("/../x"), &entry).error(), Error::InvalidName);
        QCOMPARE(b->makePath(QStringLiteral("/root/netvfs")).error(), Error::PermissionDenied);
        QByteArray content("0123456789abcdefghij");
        QBuffer source(&content);
        QVERIFY(source.open(QIODevice::ReadOnly));
        QCOMPARE(b->upload(&source, QStringLiteral("/root/x"), UploadOptions(), nullptr).error(), Error::PermissionDenied);

        source.seek(0);
        QVERIFY(b->upload(&source, dir + QStringLiteral("/a.txt"), UploadOptions(), nullptr).ok());
        QCOMPARE(b->makePath(dir + QStringLiteral("/a.txt/sub")).error(), Error::AlreadyExists);
        QCOMPARE(b->makePath(dir + QStringLiteral("/a.txt")).error(), Error::AlreadyExists);
        QVERIFY(b->read(dir + QStringLiteral("/a.txt"), 5, 10, &data).ok());
        QCOMPARE(data, QByteArray("56789abcde"));
        QVERIFY(b->read(dir + QStringLiteral("/a.txt"), 15, 100, &data).ok());
        QCOMPARE(data, QByteArray("fghij"));
        QCOMPARE(b->read(dir + QStringLiteral("/a.txt"), -1, 1, &data).error(), Error::Internal);

        QByteArray other("other");
        QBuffer otherSource(&other);
        QVERIFY(otherSource.open(QIODevice::ReadOnly));
        QVERIFY(b->upload(&otherSource, dir + QStringLiteral("/b.txt"), UploadOptions(), nullptr).ok());
        QVERIFY(b->rename(dir + QStringLiteral("/b.txt"), dir + QStringLiteral("/a.txt"), RenameMode::Replace).ok());
        QVERIFY(b->stat(dir + QStringLiteral("/a.txt"), &entry).ok());
        QCOMPARE(entry.size, qint64(5));
        QCOMPARE(entry.name, QStringLiteral("a.txt"));

        QBuffer readOnly;
        QVERIFY(readOnly.open(QIODevice::ReadOnly));
        QCOMPARE(b->download(dir + QStringLiteral("/a.txt"), &readOnly, DownloadOptions(), nullptr).error(), Error::NoSpace);
        FailingSource failing;
        QVERIFY(failing.open(QIODevice::ReadOnly));
        QCOMPARE(b->upload(&failing, dir + QStringLiteral("/c.txt"), UploadOptions(), nullptr).error(), Error::Internal);

        QVERIFY(b->makePath(dir + QStringLiteral("/empty")).ok());
        QVERIFY(b->remove(dir + QStringLiteral("/empty")).ok());
        QCOMPARE(b->stat(dir + QStringLiteral("/empty"), &entry).error(), Error::NotFound);
        QVERIFY(b->makePath(dir + QStringLiteral("/full/sub")).ok());
        QCOMPARE(b->remove(dir + QStringLiteral("/full")).error(), Error::DirectoryNotEmpty);

        QVERIFY(b->list(QString(), &entries).ok());
        bool found = false;
        for (const Entry &e : entries)
            found = found || (e.name == QLatin1String("netvfs-it") && e.isDir());
        QVERIFY(found);
        QVERIFY(b->stat(QStringLiteral("/"), &entry).ok());
        QVERIFY(entry.isDir());

        b->cancel();
        QCOMPARE(b->stat(dir, &entry).error(), Error::Canceled);
        b->resetCancel();
        QVERIFY(b->stat(dir, &entry).ok());
        QCOMPARE(b->authenticate(Credentials(QStringLiteral("alice"), m_password)).error(), Error::Internal);

        ServerIdentity seen;
        QVERIFY(b->connect(params(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), &seen).ok());
        QCOMPARE(b->stat(dir, &entry).error(), Error::Internal);
    }


    void v2Namespace_data()
    {
        QTest::addColumn<QString>("server");
        QTest::addColumn<QString>("instance");
        QTest::addColumn<bool>("posixRename");
        QTest::newRow("10.3p1") << "o103" << "default" << true;
        QTest::newRow("10.3p1 noext") << "o103" << "noext" << false;
        QTest::newRow("9.6p1") << "o96" << "default" << true;
    }

    void v2Namespace()
    {
        QFETCH(QString, server);
        QFETCH(QString, instance);
        QFETCH(bool, posixRename);
        auto b = signedIn(filesParams(server, instance, QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const Capabilities caps = b->capabilities();
        QVERIFY(caps.has(Capability::NativeNoReplace));
        QCOMPARE(caps.has(Capability::AtomicReplace), posixRename);
        QCOMPARE(caps.has(Capability::SpaceInfo), posixRename);
        QVERIFY(caps.has(Capability::ReadHandles));
        QVERIFY(caps.has(Capability::WriteResume));
        QVERIFY(caps.has(Capability::Symlinks));
        QCOMPARE(caps.maxReadChunk, qint64(0));

        const QString dir = unique(QStringLiteral("netvfs-it/v2-"));
        const QString disk = QStringLiteral("/home/alice/") + dir;
        QVERIFY(b->makePath(dir).ok());
        QCOMPARE(b->makeDir(dir, true).error(), Error::AlreadyExists);
        QVERIFY(b->makeDir(dir, false).ok());
        QVERIFY(b->makeDir(dir + QStringLiteral("/new"), true).ok());
        // the server's umask decides (022 or 002 in these images), not 0700.
        const QString newMode = serverMode(server, disk + QStringLiteral("/new"));
        QVERIFY2(newMode == QLatin1String("755") || newMode == QLatin1String("775"), qPrintable(newMode));
        QVERIFY(put(b.get(), dir + QStringLiteral("/a.txt"), "aaa"));
        QVERIFY(put(b.get(), dir + QStringLiteral("/b.txt"), "bbbb"));
        QCOMPARE(b->makeDir(dir + QStringLiteral("/a.txt"), false).error(), Error::AlreadyExists);
        QCOMPARE(b->makeDir(dir + QStringLiteral("/a.txt"), true).error(), Error::AlreadyExists);

        QCOMPARE(b->rename(dir + QStringLiteral("/b.txt"), dir + QStringLiteral("/a.txt"), RenameMode::NoReplace).error(),
                 Error::AlreadyExists);
        QCOMPARE(exec(server, QStringLiteral("cat \"$P\""), { QStringLiteral("P=") + disk + QStringLiteral("/a.txt") }),
                 QByteArray("aaa"));
        QVERIFY(b->rename(dir + QStringLiteral("/b.txt"), dir + QStringLiteral("/c.txt"), RenameMode::NoReplace).ok());
        QCOMPARE(b->rename(dir + QStringLiteral("/nope"), dir + QStringLiteral("/x"), RenameMode::NoReplace).error(),
                 Error::NotFound);
        QVERIFY(b->rename(dir + QStringLiteral("/c.txt"), dir + QStringLiteral("/a.txt"), RenameMode::Replace).ok());
        QCOMPARE(exec(server, QStringLiteral("cat \"$P\""), { QStringLiteral("P=") + disk + QStringLiteral("/a.txt") }),
                 QByteArray("bbbb"));
        QCOMPARE(b->rename(dir + QStringLiteral("/a.txt"), dir + QStringLiteral("/new"), RenameMode::Replace).error(),
                 Error::AlreadyExists);
        QVERIFY(b->makeDir(dir + QStringLiteral("/empty"), true).ok());
        QCOMPARE(b->rename(dir + QStringLiteral("/empty"), dir + QStringLiteral("/new"), RenameMode::Replace).error(),
                 Error::AlreadyExists);
        QVERIFY(b->rename(dir + QStringLiteral("/empty"), dir + QStringLiteral("/moved"), RenameMode::NoReplace).ok());

        QVERIFY(put(b.get(), dir + QStringLiteral("/new/inner.txt"), "x"));
        QCOMPARE(b->removeFile(dir + QStringLiteral("/new")).error(), Error::IsADirectory);
        QCOMPARE(b->removeDir(dir + QStringLiteral("/new")).error(), Error::DirectoryNotEmpty);
        QCOMPARE(b->removeDir(dir + QStringLiteral("/a.txt")).error(), Error::NotADirectory);
        QCOMPARE(b->removeFile(dir + QStringLiteral("/nope")).error(), Error::NotFound);
        QCOMPARE(b->removeDir(dir + QStringLiteral("/nope")).error(), Error::NotFound);
        QVERIFY(b->removeFile(dir + QStringLiteral("/new/inner.txt")).ok());
        QVERIFY(b->removeDir(dir + QStringLiteral("/new")).ok());
        QVERIFY(b->removeDir(dir + QStringLiteral("/moved")).ok());
        QVERIFY(b->remove(dir + QStringLiteral("/a.txt")).ok());

        QVERIFY(b->keepAlive().ok());
    }

    void v2Listing()
    {
        auto b = signedIn(filesParams(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const QString dir = unique(QStringLiteral("netvfs-it/list-"));
        const QString disk = QStringLiteral("/home/alice/") + dir;
        QVERIFY(b->makePath(dir).ok());
        // 300 files, a symlink to a file, one to a folder, a dangling one, a
        // FIFO and a name that is not UTF-8.
        exec(QStringLiteral("o103"),
             QStringLiteral("cd \"$P\" && for i in $(seq 1 300); do echo $i > f$i; done && mkdir sub && "
                            "ln -s f1 tofile && ln -s sub todir && ln -s nowhere dangling && mkfifo fifo && "
                            "printf x > \"$(printf 'caf\\351')\" && chmod 644 f1 && chown -R alice \"$P\""),
             { QStringLiteral("P=") + disk });

        struct Batches : ListSink {
            QVector<int> sizes;
            QVector<Entry> all;
            bool entries(const QVector<Entry> &batch) override
            {
                sizes << batch.size();
                all += batch;
                return true;
            }
        } sink;
        ListOptions options;
        options.batchSize = 7;
        options.resolveSymlinkTypes = true;
        Result r = b->list(dir, &sink, options);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(sink.all.size(), 306);
        QVERIFY(sink.sizes.size() >= 306 / 7);
        for (const int size : sink.sizes)
            QVERIFY(size >= 1 && size <= 7);
        QHash<QString, Entry> byName;
        for (const Entry &e : sink.all)
            byName.insert(e.name, e);
        QVERIFY(!byName.contains(QStringLiteral(".")) && !byName.contains(QStringLiteral("..")));
        QCOMPARE(byName.value(QStringLiteral("f1")).type, EntryType::File);
        QCOMPARE(byName.value(QStringLiteral("f1")).size, qint64(2));
        QCOMPARE(byName.value(QStringLiteral("f1")).mode, 0644);
        QVERIFY(byName.value(QStringLiteral("f1")).uid > 0);
        QVERIFY(byName.value(QStringLiteral("f1")).modified.isValid());
        QCOMPARE(byName.value(QStringLiteral("sub")).type, EntryType::Directory);
        QCOMPARE(byName.value(QStringLiteral("tofile")).type, EntryType::Symlink);
        QCOMPARE(byName.value(QStringLiteral("tofile")).targetType, EntryType::File);
        QVERIFY(byName.value(QStringLiteral("todir")).isDir());
        QVERIFY(byName.value(QStringLiteral("dangling")).flags.testFlag(EntryFlag::TargetUnknown));
        QCOMPARE(byName.value(QStringLiteral("fifo")).type, EntryType::Special);

        const QString latin1 = Names::decode(QByteArray("caf\xe9"));
        QVERIFY(byName.contains(latin1));
        QVERIFY(byName.value(latin1).flags.testFlag(EntryFlag::NameNotUtf8));
        Entry entry;
        QVERIFY(b->stat(Paths::join(dir, latin1), &entry).ok());
        QCOMPARE(entry.name, latin1);
        QCOMPARE(entry.size, qint64(1));
        QVERIFY(b->rename(Paths::join(dir, latin1), Paths::join(dir, latin1 + QStringLiteral(".old")),
                          RenameMode::NoReplace).ok());
        QVERIFY(b->removeFile(Paths::join(dir, latin1 + QStringLiteral(".old"))).ok());

        // stat follows links, lstat does not; removeFile removes the link.
        QVERIFY(b->stat(dir + QStringLiteral("/todir"), &entry).ok());
        QCOMPARE(entry.type, EntryType::Directory);
        QCOMPARE(entry.name, QStringLiteral("todir"));
        QVERIFY(b->lstat(dir + QStringLiteral("/todir"), &entry).ok());
        QCOMPARE(entry.type, EntryType::Symlink);
        QCOMPARE(b->stat(dir + QStringLiteral("/dangling"), &entry).error(), Error::NotFound);
        QVERIFY(b->removeFile(dir + QStringLiteral("/todir")).ok());
        QVERIFY(b->stat(dir + QStringLiteral("/sub"), &entry).ok());

        struct StopAfterOne : ListSink {
            int calls = 0;
            bool entries(const QVector<Entry> &) override { return ++calls < 1; }
        } stop;
        QCOMPARE(b->list(dir, &stop, ListOptions()).error(), Error::Canceled);
        QCOMPARE(stop.calls, 1);
        QVector<Entry> plain;
        QVERIFY(b->list(dir, &plain).ok());
        for (const Entry &e : plain) {
            if (e.name == QLatin1String("tofile"))
                QCOMPARE(e.targetType, EntryType::Unknown);
        }
        QCOMPARE(b->list(dir + QStringLiteral("/f1"), &plain).error(), Error::NotADirectory);
        exec(QStringLiteral("o103"), QStringLiteral("rm -rf \"$P\""), { QStringLiteral("P=") + disk });
    }

    void v2Transfers()
    {
        auto b = signedIn(filesParams(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const QString dir = unique(QStringLiteral("netvfs-it/io-"));
        const QString disk = QStringLiteral("/home/alice/") + dir;
        QVERIFY(b->makePath(dir).ok());
        QByteArray content(3 * 1024 * 1024 + 17, Qt::Uninitialized);
        for (int i = 0; i < content.size(); ++i)
            content[i] = static_cast<char>((i * 131) >> 3);

        UploadOptions options;
        QVERIFY(put(b.get(), dir + QStringLiteral("/default.bin"), content, options));
        QCOMPARE(serverMode(QStringLiteral("o103"), disk + QStringLiteral("/default.bin")), QStringLiteral("644"));
        options.write.createMode = 0640;
        QVERIFY(put(b.get(), dir + QStringLiteral("/private.bin"), "p", options));
        QCOMPARE(serverMode(QStringLiteral("o103"), disk + QStringLiteral("/private.bin")), QStringLiteral("640"));
        options.write.createMode = -1;
        QByteArray small("small");
        QBuffer source(&small);
        QVERIFY(source.open(QIODevice::ReadOnly));
        QCOMPARE(b->upload(&source, dir + QStringLiteral("/private.bin"), options, nullptr).error(),
                 Error::AlreadyExists);
        QCOMPARE(b->upload(&source, dir, options, nullptr).error(), Error::IsADirectory);
        options.write.disposition = WriteOptions::Disposition::Truncate;
        QVERIFY(b->upload(&source, dir + QStringLiteral("/private.bin"), options, nullptr).ok());
        QCOMPARE(exec(QStringLiteral("o103"), QStringLiteral("cat \"$P\""),
                      { QStringLiteral("P=") + disk + QStringLiteral("/private.bin") }),
                 small);
        QCOMPARE(serverMode(QStringLiteral("o103"), disk + QStringLiteral("/private.bin")), QStringLiteral("640"));

        QByteArray received;
        QBuffer sink(&received);
        QVERIFY(sink.open(QIODevice::WriteOnly));
        DownloadOptions range;
        range.offset = 1000;
        range.length = 1024 * 1024 + 5;
        QVERIFY(b->download(dir + QStringLiteral("/default.bin"), &sink, range, nullptr).ok());
        QCOMPARE(received, content.mid(1000, 1024 * 1024 + 5));
        sink.close();
        received.clear();
        QVERIFY(sink.open(QIODevice::WriteOnly));
        range.offset = content.size() - 10;
        range.length = -1;
        QVERIFY(b->download(dir + QStringLiteral("/default.bin"), &sink, range, nullptr).ok());
        QCOMPARE(received, content.right(10));
        QCOMPARE(b->download(dir, &sink, DownloadOptions(), nullptr).error(), Error::IsADirectory);

        ReadHandle *raw = nullptr;
        QVERIFY(b->openRead(dir + QStringLiteral("/default.bin"), &raw).ok());
        std::unique_ptr<ReadHandle> handle(raw);
        QCOMPARE(handle->size(), qint64(content.size()));
        QByteArray part;
        QVERIFY(handle->read(5, 100, &part).ok());
        QCOMPARE(part, content.mid(5, 100));
        QVERIFY(handle->read(1024 * 1024 - 3, 2 * 1024 * 1024, &part).ok());
        QCOMPARE(part, content.mid(1024 * 1024 - 3, 2 * 1024 * 1024));
        QVERIFY(handle->read(content.size() - 4, 100, &part).ok());
        QCOMPARE(part, content.right(4));
        QVERIFY(handle->read(content.size(), 100, &part).ok());
        QVERIFY(part.isEmpty());
        QVERIFY(handle->read(content.size() + 100, 100, &part).ok());
        QVERIFY(part.isEmpty());
        QVERIFY(handle->read(0, 0, &part).ok());
        QVERIFY(part.isEmpty());
        // A bad offset and a closed handle are the caller's mistakes, which
        // the Rust backends' C ABI reports as ProtocolError.
        QCOMPARE(handle->read(-1, 1, &part).error(), Error::ProtocolError);
        QVERIFY(handle->close().ok());
        QCOMPARE(handle->read(0, 1, &part).error(), Error::ProtocolError);
        ReadHandle *missing = nullptr;
        QCOMPARE(b->openRead(dir + QStringLiteral("/nope"), &missing).error(), Error::NotFound);
        QVERIFY(!missing);

        // A handle outlives the connection only as a stale object.
        QVERIFY(b->openRead(dir + QStringLiteral("/default.bin"), &raw).ok());
        handle.reset(raw);
        b->disconnect();
        QCOMPARE(handle->read(0, 1, &part).error(), Error::ConnectionLost);
        handle.reset();

        b = signedIn(filesParams(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        SpaceInfo space;
        QVERIFY(b->spaceInfo(dir, &space).ok());
        QVERIFY(space.total > 0 && space.free >= 0 && space.used >= 0 && space.free <= space.total);
        exec(QStringLiteral("o103"), QStringLiteral("rm -rf \"$P\""), { QStringLiteral("P=") + disk });
    }

    // a dropped connection is ConnectionLost, not NetworkUnreachable.
    void v2ConnectionLost()
    {
        auto b = signedIn(params(QStringLiteral("o96"), QStringLiteral("default"), QStringLiteral("carol")), m_password);
        QVERIFY(b);
        QVERIFY(b->keepAlive().ok());
        Entry entry;
        QVERIFY(b->stat(QString(), &entry).ok());
        // No procps in the image: find carol's processes in /proc.
        exec(QStringLiteral("o96"), QStringLiteral("for p in /proc/[0-9]*; do [ \"$(stat -c %U $p)\" = carol ] "
                                                   "&& kill -9 ${p#/proc/}; done; true"));
        QTest::qWait(500);
        QCOMPARE(b->keepAlive().error(), Error::ConnectionLost);
        QCOMPARE(b->stat(QString(), &entry).error(), Error::ConnectionLost);
    }

    // on every server. The symlink rows verify on the
    // server's disk that SSH_FXP_SYMLINK goes in OpenSSH's argument order
    // (target first).
    void v2LinksAndAttributes_data()
    {
        QTest::addColumn<QString>("server");
        QTest::addColumn<QString>("instance");
        QTest::addColumn<bool>("ownership");
        QTest::newRow("10.3p1") << "o103" << "default" << true;
        QTest::newRow("10.3p1 noext") << "o103" << "noext" << false;
        QTest::newRow("9.6p1") << "o96" << "default" << true;
        QTest::newRow("8.9p1") << "o89" << "default" << false;   // no users-groups-by-id
    }

    void v2LinksAndAttributes()
    {
        QFETCH(QString, server);
        QFETCH(QString, instance);
        QFETCH(bool, ownership);
        auto b = signedIn(filesParams(server, instance, QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const Capabilities caps = b->capabilities();
        QVERIFY(caps.has(Capability::Symlinks));
        QVERIFY(caps.has(Capability::PosixModes) && caps.has(Capability::SetModified));
        QCOMPARE(caps.has(Capability::Ownership), ownership);
        const QString dir = unique(QStringLiteral("netvfs-it/links-"));
        const QString disk = QStringLiteral("/home/alice/") + dir;
        QVERIFY(b->makePath(dir).ok());
        QVERIFY(put(b.get(), dir + QStringLiteral("/target.txt"), "target"));

        Result r = b->makeSymlink(QStringLiteral("target.txt"), dir + QStringLiteral("/link"));
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(exec(server, QStringLiteral("readlink \"$P\""), { QStringLiteral("P=") + disk + QStringLiteral("/link") }),
                 QByteArray("target.txt\n"));
        const QString odd = QStringLiteral("../sub dir/ü'x");
        QVERIFY(b->makeSymlink(odd, dir + QStringLiteral("/odd")).ok());
        QCOMPARE(QString::fromUtf8(exec(server, QStringLiteral("readlink \"$P\""),
                                        { QStringLiteral("P=") + disk + QStringLiteral("/odd") })),
                 odd + QLatin1Char('\n'));
        QString target;
        QVERIFY(b->readLink(dir + QStringLiteral("/odd"), &target).ok());
        QCOMPARE(target, odd);
        exec(server, QStringLiteral("ln -s target.txt \"$P\" && chown -h alice:alice \"$P\""),
             { QStringLiteral("P=") + disk + QStringLiteral("/theirs") });
        QVERIFY(b->readLink(dir + QStringLiteral("/theirs"), &target).ok());
        QCOMPARE(target, QStringLiteral("target.txt"));
        Entry entry;
        QVERIFY(b->lstat(dir + QStringLiteral("/link"), &entry).ok());
        QVERIFY2(entry.type == EntryType::Symlink, qPrintable(QStringLiteral("type %1 size %2 mode %3")
                                                                  .arg(int(entry.type)).arg(entry.size).arg(entry.mode, 0, 8)));
        QVERIFY(b->stat(dir + QStringLiteral("/link"), &entry).ok());
        QCOMPARE(entry.type, EntryType::File);
        QCOMPARE(entry.size, qint64(6));
        QCOMPARE(b->makeSymlink(QStringLiteral("other"), dir + QStringLiteral("/link")).error(), Error::AlreadyExists);
        QCOMPARE(b->readLink(dir + QStringLiteral("/target.txt"), &target).error(), Error::InvalidName);
        QCOMPARE(b->readLink(dir + QStringLiteral("/missing"), &target).error(), Error::NotFound);

        if (caps.has(Capability::Hardlinks)) {
            QVERIFY(b->makeHardlink(dir + QStringLiteral("/target.txt"), dir + QStringLiteral("/hard")).ok());
            QCOMPARE(exec(server, QStringLiteral("stat -c %h \"$P\""), { QStringLiteral("P=") + disk + QStringLiteral("/hard") }),
                     QByteArray("2\n"));
            QCOMPARE(b->makeHardlink(dir + QStringLiteral("/target.txt"), dir + QStringLiteral("/hard")).error(),
                     Error::AlreadyExists);
            QCOMPARE(b->makeHardlink(dir + QStringLiteral("/missing"), dir + QStringLiteral("/hard2")).error(),
                     Error::NotFound);
            QVERIFY(b->rename(dir + QStringLiteral("/hard"), dir + QStringLiteral("/target.txt"), RenameMode::Replace).ok());
            QCOMPARE(b->stat(dir + QStringLiteral("/hard"), &entry).error(), Error::NotFound);
        } else {
            QCOMPARE(b->makeHardlink(dir + QStringLiteral("/target.txt"), dir + QStringLiteral("/hard")).error(),
                     Error::Unsupported);
        }

        const QString file = dir + QStringLiteral("/target.txt");
        const QStringList env { QStringLiteral("P=") + disk + QStringLiteral("/target.txt") };
        AttributeChanges changes;
        changes.mode = 0640;
        QVERIFY(b->setAttributes(file, changes).ok());
        QCOMPARE(exec(server, QStringLiteral("stat -c %a \"$P\""), env), QByteArray("640\n"));
        changes = AttributeChanges();
        changes.modified = QDateTime(QDate(2001, 2, 3), QTime(4, 5, 6), Qt::UTC);
        QVERIFY(b->setAttributes(file, changes).ok());
        QCOMPARE(exec(server, QStringLiteral("stat -c %Y \"$P\""), env).trimmed().toLongLong(),
                 changes.modified.toMSecsSinceEpoch() / 1000);
        const QByteArray mtime = exec(server, QStringLiteral("stat -c %Y \"$P\""), env);
        changes = AttributeChanges();
        changes.accessed = QDateTime(QDate(2002, 3, 4), QTime(5, 6, 7), Qt::UTC);
        QVERIFY(b->setAttributes(file, changes).ok());
        QCOMPARE(exec(server, QStringLiteral("stat -c %Y \"$P\""), env), mtime);
        QCOMPARE(exec(server, QStringLiteral("stat -c %X \"$P\""), env).trimmed().toLongLong(),
                 changes.accessed.toMSecsSinceEpoch() / 1000);
        QVERIFY(b->stat(file, &entry).ok());
        QCOMPARE(entry.accessed, changes.accessed);
        changes.mode = 0170644;
        changes.accessed = QDateTime();
        changes.modified = QDateTime::currentDateTimeUtc();
        QCOMPARE(b->setAttributes(file, changes).error(), Error::Internal);
        QCOMPARE(exec(server, QStringLiteral("stat -c %Y \"$P\""), env), mtime);
        QCOMPARE(b->setAttributes(dir + QStringLiteral("/missing"), changes = AttributeChanges()).error(), Error::NotFound);

        // names by users-groups-by-id@openssh.com, never Hidden; a
        // file of another user needs a lookup beyond the start directory's.
        exec(server, QStringLiteral("touch \"$P\" && chown root:root \"$P\""),
             { QStringLiteral("P=") + disk + QStringLiteral("/.rootfile") });
        QVector<Entry> entries;
        QVERIFY(b->list(dir, &entries).ok());
        for (const Entry &e : entries) {
            if (e.name == QLatin1String(".rootfile")) {
                QCOMPARE(e.uid, qint64(0));
                QCOMPARE(e.owner, ownership ? QStringLiteral("root") : QString());
                QVERIFY(!e.flags.testFlag(EntryFlag::Hidden));
                continue;
            }
            QVERIFY(e.uid > 0 && e.gid > 0);
            // Names come from the extension only, never from the "ls -l"
            // style long names of a listing.
            QCOMPARE(e.owner, ownership ? QStringLiteral("alice") : QString());
            QCOMPARE(e.group, ownership ? QStringLiteral("alice") : QString());
            QVERIFY(!e.flags.testFlag(EntryFlag::Hidden));
        }
        QVERIFY(b->stat(dir, &entry).ok());
        QCOMPARE(entry.owner, ownership ? QStringLiteral("alice") : QString());
        QVERIFY(b->stat(dir + QStringLiteral("/.rootfile"), &entry).ok());
        QCOMPARE(entry.owner, ownership ? QStringLiteral("root") : QString());
        QCOMPARE(entry.group, ownership ? QStringLiteral("root") : QString());
        exec(server, QStringLiteral("rm -rf \"$P\""), { QStringLiteral("P=") + disk });
    }

    void v2SymlinkCap()
    {
        auto b = signedIn(filesParams(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const QString dir = unique(QStringLiteral("netvfs-it/cap-"));
        const QString disk = QStringLiteral("/home/alice/") + dir;
        QVERIFY(b->makePath(dir).ok());
        exec(QStringLiteral("o103"), QStringLiteral("cd \"$P\" && touch t && for i in $(seq 1 515); do ln -s t l$i; done "
                                                    "&& chown -R alice \"$P\""),
             { QStringLiteral("P=") + disk });
        ListOptions options;
        options.resolveSymlinkTypes = true;
        QVector<Entry> all;
        struct Collect : ListSink {
            QVector<Entry> *out = nullptr;
            bool entries(const QVector<Entry> &batch) override
            {
                *out += batch;
                return true;
            }
        } sink;
        sink.out = &all;
        QVERIFY(b->list(dir, &sink, options).ok());
        int resolved = 0;
        int unknown = 0;
        for (const Entry &e : all) {
            if (e.type != EntryType::Symlink)
                continue;
            if (e.targetType == EntryType::File)
                ++resolved;
            if (e.flags.testFlag(EntryFlag::TargetUnknown))
                ++unknown;
        }
        QCOMPARE(resolved, 512);
        QCOMPARE(unknown, 3);
        exec(QStringLiteral("o103"), QStringLiteral("rm -rf \"$P\""), { QStringLiteral("P=") + disk });
    }

    // several handles at once, read-ahead, resume, commit with mtime.
    void v2Handles()
    {
        auto b = signedIn(filesParams(QStringLiteral("o103"), QStringLiteral("default"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const Capabilities caps = b->capabilities();
        QVERIFY(caps.has(Capability::ReadHandles) && caps.has(Capability::EfficientRanges));
        QVERIFY(caps.has(Capability::WriteResume) && caps.has(Capability::SetModifiedOnUpload));
        const QString dir = unique(QStringLiteral("netvfs-it/handles-"));
        const QString disk = QStringLiteral("/home/alice/") + dir;
        QVERIFY(b->makePath(dir).ok());
        QByteArray content(6 * 1024 * 1024 + 123, Qt::Uninitialized);
        for (int i = 0; i < content.size(); ++i)
            content[i] = static_cast<char>((static_cast<quint32>(i) * 7919u) >> 5);
        QVERIFY(put(b.get(), dir + QStringLiteral("/data.bin"), content));

        std::vector<std::unique_ptr<WriteHandle>> writers;
        std::vector<std::unique_ptr<ReadHandle>> readers;
        for (int i = 0; i < 4; ++i) {
            WriteHandle *w = nullptr;
            QVERIFY(b->openWrite(dir + QStringLiteral("/w%1").arg(i), WriteOptions(), &w).ok());
            writers.emplace_back(w);
            ReadHandle *rh = nullptr;
            QVERIFY(b->openRead(dir + QStringLiteral("/data.bin"), &rh).ok());
            readers.emplace_back(rh);
        }
        const int piece = 300000;
        for (int round = 0; round < 3; ++round) {
            for (int i = 0; i < 4; ++i) {
                QVERIFY(writers[i]->write(content.constData() + round * piece, piece).ok());
                QByteArray part;
                const qint64 offset = qint64(i) * 1000000 + round * piece;
                QVERIFY(readers[i]->read(offset, piece, &part).ok());
                QCOMPARE(part, content.mid(int(offset), piece));
            }
        }
        for (int i = 0; i < 4; ++i) {
            QCOMPARE(writers[i]->position(), qint64(3 * piece));
            QVERIFY(writers[i]->commit().ok());
            QVERIFY(readers[i]->close().ok());
        }
        QCOMPARE(serverSha(QStringLiteral("o103"), disk + QStringLiteral("/w3")),
                 QCryptographicHash::hash(content.left(3 * piece), QCryptographicHash::Sha256).toHex());

        ReadHandle *raw = nullptr;
        QVERIFY(b->openRead(dir + QStringLiteral("/data.bin"), &raw).ok());
        std::unique_ptr<ReadHandle> reader(raw);
        reader->readAhead(0, 4 * 1024 * 1024);
        QByteArray all;
        QByteArray part;
        for (qint64 offset = 0; offset < content.size(); offset += 65536) {
            QVERIFY(reader->read(offset, 65536, &part).ok());
            all += part;
        }
        QCOMPARE(all, content);
        for (const qint64 offset : { qint64(5000000), qint64(17), qint64(3000001), qint64(content.size() - 5) }) {
            QVERIFY(reader->read(offset, 70000, &part).ok());
            QCOMPARE(part, content.mid(int(offset), 70000));
        }
        reader->readAhead(content.size() - 100, 1000);
        QVERIFY(reader->read(content.size() - 100, 1000, &part).ok());
        QCOMPARE(part, content.right(100));
        QVERIFY(reader->close().ok());

        // Resume: only at the remote size (ProtocolError, as Transfer reports),
        // neither past it nor before it.
        WriteOptions resume;
        resume.disposition = WriteOptions::Disposition::Resume;
        WriteHandle *w = nullptr;
        for (const qint64 offset : { qint64(3 * piece + 1), qint64(3 * piece - 1) }) {
            resume.resumeOffset = offset;
            QCOMPARE(b->openWrite(dir + QStringLiteral("/w0"), resume, &w).error(), Error::ProtocolError);
            QVERIFY(!w);
        }
        resume.resumeOffset = 3 * piece;
        resume.modified = QDateTime(QDate(2010, 1, 2), QTime(3, 4, 5), Qt::UTC);
        QVERIFY(b->openWrite(dir + QStringLiteral("/w0"), resume, &w).ok());
        std::unique_ptr<WriteHandle> writer(w);
        QCOMPARE(writer->position(), qint64(3 * piece));
        QVERIFY(writer->write(content.constData() + 3 * piece, 1000).ok());
        QVERIFY(writer->commit().ok());
        QCOMPARE(serverSha(QStringLiteral("o103"), disk + QStringLiteral("/w0")),
                 QCryptographicHash::hash(content.left(3 * piece + 1000), QCryptographicHash::Sha256).toHex());
        QCOMPARE(exec(QStringLiteral("o103"), QStringLiteral("stat -c %Y \"$P\""), { QStringLiteral("P=") + disk + QStringLiteral("/w0") })
                     .trimmed().toLongLong(),
                 resume.modified.toMSecsSinceEpoch() / 1000);
        QCOMPARE(writer->write("x", 1).error(), Error::ProtocolError);

        // upload() honours WriteOptions::modified too (SetModifiedOnUpload).
        UploadOptions upload;
        upload.write.modified = resume.modified.addDays(1);
        QVERIFY(put(b.get(), dir + QStringLiteral("/stamped"), "s", upload));
        QCOMPARE(exec(QStringLiteral("o103"), QStringLiteral("stat -c %Y \"$P\""),
                      { QStringLiteral("P=") + disk + QStringLiteral("/stamped") })
                     .trimmed().toLongLong(),
                 upload.write.modified.toMSecsSinceEpoch() / 1000);

        // abort() leaves what was written; a lost connection invalidates.
        QVERIFY(b->openWrite(dir + QStringLiteral("/aborted"), WriteOptions(), &w).ok());
        writer.reset(w);
        QVERIFY(writer->write("partial", 7).ok());
        writer->abort();
        QVERIFY(b->openWrite(dir + QStringLiteral("/lost"), WriteOptions(), &w).ok());
        writer.reset(w);
        QVERIFY(b->openRead(dir + QStringLiteral("/data.bin"), &raw).ok());
        reader.reset(raw);
        b->disconnect();
        QCOMPARE(writer->write("x", 1).error(), Error::ConnectionLost);
        QCOMPARE(writer->commit().error(), Error::ConnectionLost);
        QCOMPARE(reader->read(0, 1, &part).error(), Error::ConnectionLost);
        exec(QStringLiteral("o103"), QStringLiteral("rm -rf \"$P\""), { QStringLiteral("P=") + disk });
    }

    // Server-side copy: copy-data where the server offers it (OpenSSH 9.0
    // and later), nothing else; no exec channel, so no checksums and no
    // folder copies (copying a folder is the caller's work, file by file).
    void v2ServerCopy_data()
    {
        QTest::addColumn<QString>("server");
        QTest::addColumn<QString>("instance");
        QTest::addColumn<bool>("copyData");
        QTest::newRow("10.3p1") << "o103" << "default" << true;
        QTest::newRow("10.3p1 noext") << "o103" << "noext" << false;
        QTest::newRow("9.6p1") << "o96" << "default" << true;
        QTest::newRow("8.9p1") << "o89" << "default" << false;
    }

    void v2ServerCopy()
    {
        QFETCH(QString, server);
        QFETCH(QString, instance);
        QFETCH(bool, copyData);
        auto b = signedIn(filesParams(server, instance, QStringLiteral("alice")), m_password);
        QVERIFY(b);
        const Capabilities caps = b->capabilities();
        QCOMPARE(caps.has(Capability::ServerCopy), copyData);
        QVERIFY(!caps.has(Capability::ServerCopyRecursive));
        QVERIFY(!caps.has(Capability::Checksums));
        QVERIFY(caps.checksumAlgorithms.isEmpty());

        const QString dir = unique(QStringLiteral("netvfs-it/copy-"));
        const QString disk = QStringLiteral("/home/alice/") + dir;
        QVERIFY(b->makePath(dir + QStringLiteral("/tree/sub")).ok());
        QByteArray data(1234567, 'q');
        data[100] = 'x';
        const QString source = dir + QStringLiteral("/-dash file");
        QVERIFY(put(b.get(), source, data));
        QVERIFY(put(b.get(), dir + QStringLiteral("/other"), "other"));
        QByteArray digest;
        QCOMPARE(b->checksum(source, QStringLiteral("sha256"), &digest).error(), Error::Unsupported);
        QVERIFY(digest.isEmpty());

        Entry entry;
        CopyOptions recursive;
        recursive.recursive = true;
        const Result copied = b->copy(source, dir + QStringLiteral("/copy"), CopyOptions());
        if (!copyData) {
            QCOMPARE(copied.error(), Error::Unsupported);
            QCOMPARE(b->stat(dir + QStringLiteral("/copy"), &entry).error(), Error::NotFound);
            QCOMPARE(b->copy(dir + QStringLiteral("/tree"), dir + QStringLiteral("/tree2"), recursive).error(),
                     Error::Unsupported);
            exec(server, QStringLiteral("rm -rf \"$P\""), { QStringLiteral("P=") + disk });
            return;
        }
        QVERIFY2(copied.ok(), qPrintable(copied.toString()));
        const QByteArray sha = QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex();
        QCOMPARE(serverSha(server, disk + QStringLiteral("/copy")), sha);
        QCOMPARE(b->copy(source, dir + QStringLiteral("/copy"), CopyOptions()).error(), Error::AlreadyExists);
        QCOMPARE(b->copy(dir + QStringLiteral("/other"), dir + QStringLiteral("/copy"), CopyOptions()).error(),
                 Error::AlreadyExists);
        QCOMPARE(serverSha(server, disk + QStringLiteral("/copy")), sha);
        CopyOptions replace;
        replace.mode = RenameMode::Replace;
        QVERIFY(b->copy(dir + QStringLiteral("/other"), dir + QStringLiteral("/copy"), replace).ok());
        QCOMPARE(exec(server, QStringLiteral("cat \"$P\""), { QStringLiteral("P=") + disk + QStringLiteral("/copy") }),
                 QByteArray("other"));
        // Onto another name of the same file (a hard link) the content
        // stays; onto its own name the server refuses, and nothing changes.
        exec(server, QStringLiteral("ln \"$P/-dash file\" \"$P/hard\""), { QStringLiteral("P=") + disk });
        const Result linked = b->copy(source, dir + QStringLiteral("/hard"), replace);
        QVERIFY2(linked.ok(), qPrintable(linked.toString()));
        QVERIFY(!b->copy(source, source, replace).ok());
        QCOMPARE(serverSha(server, disk + QStringLiteral("/-dash file")), sha);
        QCOMPARE(serverSha(server, disk + QStringLiteral("/hard")), sha);
        QCOMPARE(b->copy(dir + QStringLiteral("/tree"), dir + QStringLiteral("/tree2"), CopyOptions()).error(),
                 Error::IsADirectory);
        QCOMPARE(b->copy(dir + QStringLiteral("/tree"), dir + QStringLiteral("/tree2"), recursive).error(),
                 Error::Unsupported);
        QCOMPARE(b->stat(dir + QStringLiteral("/tree2"), &entry).error(), Error::NotFound);
        QCOMPARE(b->copy(source, dir + QStringLiteral("/tree"), replace).error(), Error::AlreadyExists);
        QCOMPARE(b->copy(dir + QStringLiteral("/missing"), dir + QStringLiteral("/x"), CopyOptions()).error(),
                 Error::NotFound);
        exec(server, QStringLiteral("rm -rf \"$P\""), { QStringLiteral("P=") + disk });
    }

    // a server that allows no session on the connection (OpenSSH
    // MaxSessions 0 for user "nosession") is TooManyConnections at sign-in.
    void v2MaxSessions()
    {
        const ConnectionParams p = filesParams(QStringLiteral("o96"), QStringLiteral("default"),
                                               QStringLiteral("nosession"));
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));
        const Result r = signIn(b.get(), p, m_password);
        QCOMPARE(r.error(), Error::TooManyConnections);
        QCOMPARE(r.message(), QStringLiteral("The server allows no further session on this connection"));
        QVERIFY(serverLog(QStringLiteral("o96"), QStringLiteral("default"))
                    .contains(QLatin1String("Accepted password for nosession")));
        Entry entry;
        QCOMPARE(b->stat(QString(), &entry).error(), Error::Internal);
    }

    void v2KeyboardInteractive()
    {
        const QByteArray code = m_otp;
        ConnectionParams p = params(QStringLiteral("o96"), QStringLiteral("otp"), QStringLiteral("otp"));
        auto b = std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("sftp")));

        // Without a prompter is unchanged: the password answers its
        // round, the code round is refused.
        Result r = signIn(b.get(), p, m_password);
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY2(r.message().contains(QLatin1String("interactive sign-in")), qPrintable(r.message()));

        AnsweringPrompter prompter(m_password, code);
        r = signIn(b.get(), p, m_password, &prompter);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(prompter.asked, QStringList { QStringLiteral("Verification code: ") });
        Entry entry;
        QVERIFY(b->stat(QString(), &entry).ok());

        ConnectionParams interactive = params(QStringLiteral("o96"), QStringLiteral("otp"), QStringLiteral("otp"),
                                              QStringLiteral("interactive"));
        prompter.asked.clear();
        r = signIn(b.get(), interactive, QByteArray(), &prompter);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(prompter.asked.size(), 2);
        QVERIFY(prompter.asked.first().startsWith(QLatin1String("Password")));
        QCOMPARE(signIn(b.get(), interactive, QByteArray()).error(), Error::AuthFailed);
        AnsweringPrompter wrong(m_password, "000000");
        QCOMPARE(signIn(b.get(), p, m_password, &wrong).error(), Error::AuthFailed);
        AnsweringPrompter declining(m_password, code);
        declining.decline = true;
        r = signIn(b.get(), p, m_password, &declining);
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY2(r.message().contains(QLatin1String("not completed")), qPrintable(r.message()));

        SshKeyMaterial key;
        QVERIFY(m_tools->generate(&key).ok());
        authorizeKey(QStringLiteral("o96"), QStringLiteral("keyotp"), key.publicLine);
        const ConnectionParams keyotp = params(QStringLiteral("o96"), QStringLiteral("otp"), QStringLiteral("keyotp"),
                                               QStringLiteral("publickey"));
        r = signIn(b.get(), keyotp, encodeKeySecret(key.privateKey));
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY2(r.message().contains(QLatin1String("second sign-in step")), qPrintable(r.message()));
        prompter.asked.clear();
        r = signIn(b.get(), keyotp, encodeKeySecret(key.privateKey), &prompter);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(prompter.asked, QStringList { QStringLiteral("Verification code: ") });

        const ConnectionParams pwotp = params(QStringLiteral("o96"), QStringLiteral("otp"), QStringLiteral("pwotp"));
        QCOMPARE(signIn(b.get(), pwotp, m_password).error(), Error::AuthFailed);
        prompter.asked.clear();
        r = signIn(b.get(), pwotp, m_password, &prompter);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(prompter.asked, QStringList { QStringLiteral("Verification code: ") });

        // An echoed round: refused without a prompter, asked with one.
        const ConnectionParams echo = params(QStringLiteral("o96"), QStringLiteral("otp"), QStringLiteral("twoprompt"));
        QCOMPARE(signIn(b.get(), echo, m_password).error(), Error::AuthFailed);
        prompter.asked.clear();
        r = signIn(b.get(), echo, m_password, &prompter);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(prompter.asked.size(), 2);
        QVERIFY(prompter.echoed.contains(QStringLiteral("Token label: ")));

        // cancel() ends a wait in the prompter.
        SilentPrompter nobody;
        Backend *raw = b.get();
        QFuture<Result> future = QtConcurrent::run([this, raw, &p, &nobody]() { return signIn(raw, p, m_password, &nobody); });
        QVERIFY(nobody.waitAsked(30000));
        QElapsedTimer timer;
        timer.start();
        raw->cancel();
        r = future.result();
        QCOMPARE(r.error(), Error::Canceled);
        QVERIFY2(timer.elapsed() <= CancelBoundMs, qPrintable(QString::number(timer.elapsed())));
        b->resetCancel();
    }

    // cancel() ends blocking requests while the server holds its
    // answers back, and the connection stays usable afterwards.
    void v2CancelBlocking()
    {
        auto b = signedIn(filesParams(QStringLiteral("o89"), QStringLiteral("hold"), QStringLiteral("alice")), m_password);
        QVERIFY(b);
        QVERIFY(b->makePath(QStringLiteral("netvfs-it/cancel")).ok());
        Backend *raw = b.get();
        const QVector<QPair<QString, std::function<Result()>>> calls = {
            { QStringLiteral("stat"), [raw]() { Entry e; return raw->stat(QStringLiteral("netvfs-it/cancel"), &e); } },
            { QStringLiteral("list"), [raw]() { QVector<Entry> e; return raw->list(QStringLiteral("netvfs-it/cancel"), &e); } },
            { QStringLiteral("makeDir"), [raw]() { return raw->makeDir(QStringLiteral("netvfs-it/cancel/new"), false); } },
        };
        for (const auto &call : calls) {
            exec(QStringLiteral("o89"), QStringLiteral("touch /tmp/hold"));
            Result r;
            const qint64 ms = runCanceled(raw, call.second, &r);
            exec(QStringLiteral("o89"), QStringLiteral("rm -f /tmp/hold"));
            QVERIFY2(r.error() == Error::Canceled, qPrintable(call.first + QLatin1String(": ") + r.toString()));
            QVERIFY2(ms <= CancelBoundMs, qPrintable(call.first + QLatin1String(": ") + QString::number(ms)));
            raw->resetCancel();
            Entry entry;
            const Result after = raw->stat(QStringLiteral("netvfs-it/cancel"), &entry);
            QVERIFY2(after.ok(), qPrintable(call.first + QLatin1String(" then stat: ") + after.toString()));
        }
    }
};

QTEST_GUILESS_MAIN(TestInteropSftp)

#include "tst_interop_sftp.moc"
