// SPDX-License-Identifier: LGPL-2.1-or-later
// SMB interoperability matrix (SPEC-smb section 7) against the Samba
// containers that run.sh starts. Container names are "<prefix>-<server>";
// see run.sh for the servers and server/conf/ for their configurations.
#include "backendloader.h"
#include "identity.h"
#include "paths.h"
#include "smb2api.h"
#include "transfer.h"

#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QElapsedTimer>
#include <QtCore/QFile>
#include <QtCore/QHash>
#include <QtCore/QProcess>
#include <QtCore/QStandardPaths>
#include <QtCore/QTemporaryDir>
#include <QtTest/QtTest>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>

using namespace NetVfs;

namespace {

const qint64 BigSize = 64 * 1024 * 1024;        // SPEC-smb 7: 64 MiB per positive case
constexpr const char *BigName = "backup-64MiB.tar";
constexpr const char *BackupsDir = "Sailfish OS/Backups";

class AtomicProgress : public Progress
{
public:
    void update(qint64 done, qint64) override { bytes = done; }
    std::atomic<qint64> bytes { 0 };
};

qint64 steadyMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count();
}

struct CancelProbe {
    void returned() { returnedAt = steadyMs(); }
    std::atomic<qint64> canceledAt { 0 };
    std::atomic<qint64> returnedAt { 0 };
};

QByteArray sha256Of(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return QByteArray();
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(&file);
    return hash.result().toHex();
}

// Deterministic, incompressible test data (xorshift64).
bool writePattern(const QString &path, qint64 size, quint64 seed)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    QByteArray block(1024 * 1024, Qt::Uninitialized);
    quint64 x = seed;
    for (qint64 written = 0; written < size; written += block.size()) {
        for (int i = 0; i + 8 <= block.size(); i += 8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            std::memcpy(block.data() + i, &x, 8);
        }
        const qint64 n = qMin<qint64>(block.size(), size - written);
        if (file.write(block.constData(), n) != n)
            return false;
    }
    return true;
}

QByteArray utf16(const QString &text)
{
    return QByteArray(reinterpret_cast<const char *>(text.utf16()), text.size() * 2);
}

std::unique_ptr<Backend> newBackend()
{
    return std::unique_ptr<Backend>(BackendLoader::create(QStringLiteral("smb")));
}

} // namespace

class TestInteropSmb : public QObject
{
    Q_OBJECT

private:
    QString m_prefix;
    QByteArray m_password;
    QTemporaryDir m_tmp;
    QString m_big;
    QByteArray m_bigSha;
    QHash<QString, QString> m_addresses;

    QString container(const QString &server) const { return m_prefix + QLatin1Char('-') + server; }

    QByteArray docker(const QStringList &args, int *exitCode = nullptr) const
    {
        QProcess process;
        // An absolute path: the command is not looked up in PATH at start().
        process.start(QStandardPaths::findExecutable(QStringLiteral("docker")), args);
        process.waitForFinished(120000);
        if (exitCode)
            *exitCode = process.exitCode();
        return process.readAllStandardOutput();
    }

    QByteArray exec(const QString &server, const QStringList &command, int *exitCode = nullptr) const
    {
        return docker(QStringList { QStringLiteral("exec"), container(server) } + command, exitCode);
    }

    QString address(const QString &server)
    {
        if (!m_addresses.contains(server)) {
            const QByteArray ip = docker({ QStringLiteral("inspect"), QStringLiteral("-f"),
                                           QStringLiteral("{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"),
                                           container(server) });
            m_addresses.insert(server, QString::fromLatin1(ip.trimmed()));
        }
        return m_addresses.value(server);
    }

    QByteArray serverSha(const QString &server, const QString &sharePath) const
    {
        return exec(server, { QStringLiteral("sha256sum"), QStringLiteral("/srv/smb/backup/") + sharePath })
            .left(64);
    }

    ConnectionParams params(const QString &server, bool encrypt = true, const QString &share = QStringLiteral("backup"))
    {
        ConnectionParams p;
        p.provider = QStringLiteral("smb");
        p.host = address(server);
        p.username = QStringLiteral("backup");
        p.options.insert(QStringLiteral("share"), share);
        if (!encrypt)
            p.options.insert(QStringLiteral("require_encryption"), false);
        return p;
    }

    ConnectionParams viaProxy(int port, bool encrypt)
    {
        ConnectionParams p = params(QStringLiteral("proxy"), encrypt);
        p.port = port;
        return p;
    }

    Credentials credentials(const QByteArray &secret = QByteArray()) const
    {
        return Credentials(QStringLiteral("backup"), secret.isEmpty() ? m_password : secret);
    }

    // Every positive case of SPEC-smb 7: makePath, 64 MiB upload, list, free
    // space, download, SHA-256 at the client and on the server's disk.
    void positiveFlow(Backend *backend, const QString &server, const QString &dir)
    {
        QVERIFY(backend->makePath(dir).ok());
        const QString remote = Paths::join(dir, QLatin1String(BigName));
        const Result up = Transfer::uploadFile(backend, m_big, remote);
        QVERIFY2(up.ok(), qPrintable(up.toString()));

        QVector<Entry> entries;
        QVERIFY(backend->list(dir, &entries).ok());
        bool found = false;
        for (const Entry &e : entries) {
            QVERIFY2(!e.name.endsWith(QLatin1String(".part")), qPrintable(e.name));
            if (e.name == QLatin1String(BigName)) {
                found = true;
                QCOMPARE(e.size, BigSize);
                QVERIFY(!e.isDir);
                QVERIFY(e.modified.isValid());
            }
        }
        QVERIFY(found);

        qint64 freeBytes = -1;
        QVERIFY(backend->freeSpace(dir, &freeBytes).ok());
        QVERIFY(freeBytes > 0);

        const QString local = m_tmp.filePath(QStringLiteral("download-") + server);
        const Result down = Transfer::downloadFile(backend, remote, local);
        QVERIFY2(down.ok(), qPrintable(down.toString()));
        QCOMPARE(sha256Of(local), m_bigSha);
        QCOMPARE(serverSha(server, remote), m_bigSha);
        QFile::remove(local);
    }

    // The session row of `smbstatus -b` for the one connected client.
    QByteArray sessionRow(const QString &server) const
    {
        const QList<QByteArray> lines = exec(server, { QStringLiteral("smbstatus"), QStringLiteral("-b") }).split('\n');
        for (const QByteArray &line : lines) {
            if (line.contains("backup") && line.contains("SMB"))
                return line.simplified();
        }
        return QByteArray();
    }

    Result signIn(Backend *backend, const ConnectionParams &p, const Credentials &c) const
    {
        return establish(backend, p, c);
    }

    // Runs `work` on its own thread (which signs in itself: a connection is
    // confined to the thread that connects, M-13) and calls cancel() from
    // this thread once `trigger` holds. `work` calls probe.returned() right
    // after the call that is to be canceled; the result is the time from
    // cancel() to that point.
    template <typename Work, typename Trigger>
    qint64 cancelDuring(Backend *backend, CancelProbe *probe, Work work, Trigger trigger)
    {
        std::atomic<bool> finished { false };
        std::thread worker([&work, &finished]() {
            work();
            finished = true;
        });
        QElapsedTimer waited;
        waited.start();
        while (!trigger() && !finished && waited.elapsed() < 60000)
            QTest::qWait(10);
        probe->canceledAt = steadyMs();
        backend->cancel();
        worker.join();
        return probe->returnedAt - probe->canceledAt;
    }

    void startCapture(const QString &server)
    {
        int code = -1;
        exec(server, { QStringLiteral("sh"), QStringLiteral("-c"),
                       QStringLiteral("rm -f /srv/work/capture.pcap; (tcpdump -Z root -i any -p -U --immediate-mode -w /srv/work/capture.pcap "
                                      "tcp port 445 >/srv/work/tcpdump.log 2>&1 &); for i in $(seq 100); do "
                                      "grep -q listening /srv/work/tcpdump.log && exit 0; sleep 0.1; done; exit 1") },
             &code);
        QCOMPARE(code, 0);
    }

    QByteArray stopCapture(const QString &server)
    {
        QTest::qWait(1000);
        exec(server, { QStringLiteral("pkill"), QStringLiteral("-INT"), QStringLiteral("tcpdump") });
        QTest::qWait(300);
        return exec(server, { QStringLiteral("cat"), QStringLiteral("/srv/work/capture.pcap") });
    }

    void uploadMarker(const ConnectionParams &p, const QString &dir, const QByteArray &payload)
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), p, credentials()).ok());
        QVERIFY(backend->makePath(dir).ok());
        QByteArray data = payload;
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        const Result r = Transfer::upload(backend.get(), &buffer, data.size(),
                                          Paths::join(dir, QStringLiteral("marker.txt")));
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QVector<Entry> entries;
        QVERIFY(backend->list(dir, &entries).ok());
        QCOMPARE(entries.size(), 1);
    }

private slots:
    void initTestCase()
    {
        m_prefix = QString::fromLocal8Bit(qgetenv("NETVFS_SMB_PREFIX"));
        m_password = qgetenv("NETVFS_SMB_PASSWORD");
        if (m_prefix.isEmpty() || m_password.isEmpty())
            QSKIP("Run by tests/interop/smb/run.sh, which starts the servers");
        QVERIFY(m_tmp.isValid());
        m_big = m_tmp.filePath(QStringLiteral("big.tar"));
        QVERIFY(writePattern(m_big, BigSize, 0x9e3779b97f4a7c15ULL));
        m_bigSha = sha256Of(m_big);
        QVERIFY(BackendLoader::isAvailable(QStringLiteral("smb")));
    }

    // M-T1, M-T8, M-11: strict Samba 4.19.5; dialect, cipher and signing as
    // smbstatus reports them; smbclient cross-check in both directions.
    void strictServer()
    {
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), params(QStringLiteral("strict")), credentials());
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        positiveFlow(backend.get(), QStringLiteral("strict"), QLatin1String(BackupsDir));
        if (QTest::currentTestFailed())
            return;
        const QByteArray row = sessionRow(QStringLiteral("strict"));
        qInfo("smbstatus: %s", row.constData());
        QVERIFY2(row.contains("SMB3_11"), row.constData());
        QVERIFY2(row.contains("AES-128-CCM"), row.constData());
        QVERIFY2(row.contains("AES-128-CMAC"), row.constData());
        QVERIFY2(!row.contains("partial"), row.constData());

        // M-T8: smbclient fetches our upload ...
        const QString remote = QLatin1String(BackupsDir) + QLatin1Char('/') + QLatin1String(BigName);
        int code = -1;
        exec(QStringLiteral("strict"),
             { QStringLiteral("smbclient"), QStringLiteral("//localhost/backup"), QStringLiteral("-A"),
               QStringLiteral("/etc/netvfs-auth"), QStringLiteral("-c"),
               QStringLiteral("get \"%1\" /srv/work/fetched.bin").arg(remote) }, &code);
        QCOMPARE(code, 0);
        QCOMPARE(exec(QStringLiteral("strict"), { QStringLiteral("sha256sum"), QStringLiteral("/srv/work/fetched.bin") })
                     .left(64), m_bigSha);
        // ... and we list and fetch an upload by smbclient.
        exec(QStringLiteral("strict"),
             { QStringLiteral("sh"), QStringLiteral("-c"),
               QStringLiteral("head -c 3333333 /dev/urandom > /srv/work/theirs.bin && smbclient //localhost/backup "
                              "-A /etc/netvfs-auth -c 'put /srv/work/theirs.bin \"%1/theirs.bin\"'")
                   .arg(QLatin1String(BackupsDir)) }, &code);
        QCOMPARE(code, 0);
        QVector<Entry> entries;
        QVERIFY(backend->list(QLatin1String(BackupsDir), &entries).ok());
        const auto theirs = std::find_if(entries.cbegin(), entries.cend(),
                                         [](const Entry &e) { return e.name == QLatin1String("theirs.bin"); });
        QVERIFY(theirs != entries.cend());
        QCOMPARE(theirs->size, qint64(3333333));
        const QString local = m_tmp.filePath(QStringLiteral("theirs.bin"));
        QVERIFY(Transfer::downloadFile(backend.get(), QLatin1String(BackupsDir) + QStringLiteral("/theirs.bin"),
                                       local).ok());
        QCOMPARE(sha256Of(local),
                 exec(QStringLiteral("strict"), { QStringLiteral("sha256sum"), QStringLiteral("/srv/work/theirs.bin") })
                     .left(64));
        backend->disconnect();
    }

    // M-T2: distribution defaults, encryption required by the account.
    void defaultServer()
    {
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), params(QStringLiteral("default")), credentials());
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        positiveFlow(backend.get(), QStringLiteral("default"), QLatin1String(BackupsDir));
        const QByteArray row = sessionRow(QStringLiteral("default"));
        qInfo("smbstatus: %s", row.constData());
        QVERIFY2(row.contains("SMB3_11"), row.constData());
        QVERIFY2(row.contains("AES-128-CCM"), row.constData());
    }

    // M-T3: the account requires encryption, the server has it off.
    void encryptionRequiredServerOff()
    {
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), params(QStringLiteral("encoff")), credentials());
        QCOMPARE(r.error(), Error::SecurityPolicy);
        Entry entry;
        QVERIFY(!backend->stat(QString(), &entry).ok());
    }

    // M-T4: same server, "Require encryption" off: signed, not encrypted.
    void encryptionOffSigned()
    {
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), params(QStringLiteral("encoff"), false), credentials());
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        positiveFlow(backend.get(), QStringLiteral("encoff"), QLatin1String(BackupsDir));
        const QByteArray row = sessionRow(QStringLiteral("encoff"));
        qInfo("smbstatus: %s", row.constData());
        QVERIFY2(row.contains("SMB3_11"), row.constData());
        QVERIFY2(row.contains("AES-128-CMAC"), row.constData());
        QVERIFY2(!row.contains("AES-128-CCM"), row.constData());
    }

    // M-3: with "Require encryption" off the library still encrypts where the
    // server mandates it (smb2_set_seal() is not called at all).
    void encryptionOffServerRequires()
    {
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), params(QStringLiteral("strict"), false), credentials());
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        Entry entry;
        QVERIFY(backend->stat(QString(), &entry).ok());
        const QByteArray row = sessionRow(QStringLiteral("strict"));
        QVERIFY2(row.contains("SMB3_11") && row.contains("AES-128-CCM"), row.constData());
    }

    // M-T5: wrong password, unknown user.
    void wrongCredentials_data()
    {
        QTest::addColumn<QString>("user");
        QTest::addColumn<bool>("rightPassword");
        QTest::newRow("wrong password") << QStringLiteral("backup") << false;
        QTest::newRow("unknown user") << QStringLiteral("nosuchuser") << true;
    }
    void wrongCredentials()
    {
        QFETCH(QString, user);
        QFETCH(bool, rightPassword);
        const auto backend = newBackend();
        const QByteArray secret = rightPassword ? m_password : m_password + "x";
        const Result r = signIn(backend.get(), params(QStringLiteral("strict")), Credentials(user, secret));
        QCOMPARE(r.error(), Error::AuthFailed);
        QVERIFY2(r.message().contains(QLatin1String("0xc000006d")), qPrintable(r.message()));
        QVERIFY(!r.message().contains(QString::fromLatin1(m_password)));
    }

    // M-T6
    void unknownShare()
    {
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), params(QStringLiteral("strict"), true, QStringLiteral("nosuchshare")),
                                credentials());
        QCOMPARE(r.error(), Error::NotFound);
        QVERIFY2(r.message().contains(QLatin1String("share not found")), qPrintable(r.message()));
        QVERIFY2(r.message().contains(QLatin1String("0xc00000cc")), qPrintable(r.message()));
    }

    // M-T7: there is no setting for SMB 2.x, so libsmb2 itself is pinned to
    // SMB 2.1 here (test code only) against the strict server.
    void clientPinnedToSmb21()
    {
        const QByteArray server = address(QStringLiteral("strict")).toUtf8();
        for (const bool pinned : { true, false }) {
            smb2_context *ctx = smb2_init_context();
            QVERIFY(ctx);
            smb2_set_version(ctx, pinned ? SMB2_VERSION_0210 : SMB2_VERSION_ANY3);
            smb2_set_security_mode(ctx, SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED);
            smb2_set_seal(ctx, 1);
            smb2_set_timeout(ctx, 30);
            smb2_set_user(ctx, "backup");
            smb2_set_password(ctx, m_password.constData());
            const int rc = smb2_connect_share(ctx, server.constData(), "backup", nullptr);
            if (rc == 0)
                smb2_disconnect_share(ctx);
            smb2_destroy_context(ctx);
            QVERIFY2(pinned ? rc < 0 : rc == 0, pinned ? "SMB 2.1 was accepted" : "control: SMB 3 failed");
        }
    }

    // M-T9: server limited to SMB 2.x.
    void smb2OnlyServer()
    {
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), params(QStringLiteral("smb2only")), credentials());
        QCOMPARE(r.error(), Error::SecurityPolicy);
        // M-1: refused by the server's negotiate reply (STATUS_NOT_SUPPORTED),
        // because the client offered SMB 3 dialects only.
        QVERIFY2(r.message().contains(QLatin1String("0xc00000bb")), qPrintable(r.message()));
        const Result plain = signIn(backend.get(), params(QStringLiteral("smb2only"), false), credentials());
        QCOMPARE(plain.error(), Error::SecurityPolicy);
    }

    // M-1: a reply that picks a dialect the client never offered (SMB 2.1
    // against SMB2_VERSION_ANY3) ends the sign-in.
    void dialectNeverOffered()
    {
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), viaProxy(4457, true), credentials());
        QVERIFY2(!r.ok(), "a dialect that was not offered was accepted");
        qInfo("%s", qPrintable(r.toString()));
    }

    // M-T10: a current Samba release with the strict configuration.
    void currentSamba()
    {
        qInfo("current Samba: %s", exec(QStringLiteral("current"), { QStringLiteral("smbd"), QStringLiteral("--version") })
                                       .trimmed().constData());
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), params(QStringLiteral("current")), credentials());
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        positiveFlow(backend.get(), QStringLiteral("current"), QLatin1String(BackupsDir));
        const QByteArray row = sessionRow(QStringLiteral("current"));
        qInfo("smbstatus: %s", row.constData());
        QVERIFY2(row.contains("SMB3_11") && row.contains("AES-128-CCM"), row.constData());
    }

    // M-T12: one byte of a signed (or sealed) reply after sign-in is altered.
    void tamperedResponse_data()
    {
        QTest::addColumn<int>("port");
        QTest::addColumn<bool>("encrypt");
        QTest::newRow("signed") << 4451 << false;
        QTest::newRow("encrypted") << 4452 << true;
    }
    void tamperedResponse()
    {
        QFETCH(int, port);
        QFETCH(bool, encrypt);
        Entry entry;
        // Control: the same proxy path without tampering works.
        const auto control = newBackend();
        QVERIFY(signIn(control.get(), viaProxy(4450, false), credentials()).ok());
        QVERIFY(control->stat(QString(), &entry).ok());
        control->disconnect();

        const auto backend = newBackend();
        const Result r = signIn(backend.get(), viaProxy(port, encrypt), credentials());
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        const Result first = backend->stat(QString(), &entry);
        QVERIFY2(!first.ok(), "a tampered reply was accepted");
        QCOMPARE(first.error(), Error::NetworkUnreachable);
        // The connection is aborted, not resynchronised.
        QCOMPARE(backend->stat(QString(), &entry).error(), Error::NetworkUnreachable);
    }

    // M-T13: with encryption required nothing readable crosses the wire; the
    // control run without encryption shows the method finds cleartext.
    void noCleartextOnWire()
    {
        const QByteArray marker("NETVFS-CLEARTEXT-MARKER-4f1d");
        const QString folder = QStringLiteral("M-T13 SecretFolderName");
        QByteArray payload;
        while (payload.size() < 256 * 1024)
            payload += marker;

        startCapture(QStringLiteral("default"));
        uploadMarker(params(QStringLiteral("default")), folder, payload);
        const QByteArray sealed = stopCapture(QStringLiteral("default"));
        if (QTest::currentTestFailed())
            return;
        QVERIFY2(sealed.size() > payload.size(), qPrintable(QString::number(sealed.size())));
        QVERIFY(sealed.contains("\xfdSMB"));    // SMB 3 transform (encrypted) messages
        QVERIFY(!sealed.contains(marker));
        QVERIFY(!sealed.contains(utf16(folder)));
        QVERIFY(!sealed.contains(utf16(QStringLiteral("marker.txt"))));
        QVERIFY(!sealed.contains(folder.toUtf8()));

        startCapture(QStringLiteral("encoff"));
        uploadMarker(params(QStringLiteral("encoff"), false), folder, payload);
        const QByteArray plain = stopCapture(QStringLiteral("encoff"));
        QVERIFY(plain.contains(marker));
        QVERIFY(plain.contains(utf16(folder)));
    }

    // M-T14: only ciphers or signing algorithms libsmb2 lacks.
    void unsupportedAlgorithms_data()
    {
        QTest::addColumn<QString>("server");
        QTest::addColumn<bool>("encrypt");
        QTest::newRow("AES-256/GCM ciphers only") << QStringLiteral("aes256") << true;
        QTest::newRow("AES-GMAC/HMAC signing only") << QStringLiteral("gmac") << false;
    }
    void unsupportedAlgorithms()
    {
        QFETCH(QString, server);
        QFETCH(bool, encrypt);
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), params(server, encrypt), credentials());
        QCOMPARE(r.error(), Error::SecurityPolicy);
        qInfo("%s", qPrintable(r.toString()));
    }

    // M-T16, C-13: a 16 MiB share; nothing is left behind.
    void fullShare()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict"), true, QStringLiteral("small")),
                       credentials()).ok());
        qint64 freeBytes = -1;
        QVERIFY(backend->freeSpace(QString(), &freeBytes).ok());
        QVERIFY2(freeBytes > 15 * 1024 * 1024 && freeBytes <= 16 * 1024 * 1024, qPrintable(QString::number(freeBytes)));
        // Free space known: refused before transferring.
        QCOMPARE(Transfer::uploadFile(backend.get(), m_big, QStringLiteral("full.tar")).error(), Error::NoSpace);
        // Size unknown: the server's DISK_FULL ends the upload.
        QFile file(m_big);
        QVERIFY(file.open(QIODevice::ReadOnly));
        const Result r = Transfer::upload(backend.get(), &file, -1, QStringLiteral("full.tar"));
        QCOMPARE(r.error(), Error::NoSpace);
        QVector<Entry> entries;
        QVERIFY(backend->list(QString(), &entries).ok());
        QVERIFY2(entries.isEmpty(), qPrintable(entries.value(0).name));
        QCOMPARE(exec(QStringLiteral("strict"), { QStringLiteral("ls"), QStringLiteral("-A"),
                                                  QStringLiteral("/srv/smb/small") }), QByteArray());
    }

    // M-T17, C-9: cancel from another thread during upload and download.
    void cancelUpload()
    {
        const auto backend = newBackend();
        AtomicProgress progress;
        CancelProbe probe;
        Result signedIn;
        Result upload;
        Result listed;
        QVector<Entry> entries;
        const qint64 elapsed = cancelDuring(backend.get(), &probe, [&]() {
            signedIn = signIn(backend.get(), params(QStringLiteral("strict")), credentials());
            if (!signedIn.ok() || !backend->makePath(QStringLiteral("M-T17")).ok())
                return;
            upload = Transfer::uploadFile(backend.get(), m_big, QStringLiteral("M-T17/up.tar"), &progress);
            probe.returned();
            backend->resetCancel();
            listed = backend->list(QStringLiteral("M-T17"), &entries);
            backend->disconnect();
        }, [&]() { return progress.bytes >= 4 * 1024 * 1024; });
        QVERIFY2(signedIn.ok(), qPrintable(signedIn.toString()));
        QCOMPARE(upload.error(), Error::Canceled);
        QVERIFY2(elapsed < 2000, qPrintable(QString::number(elapsed)));
        QVERIFY(progress.bytes < BigSize);
        // C-12: the .part file is gone.
        QVERIFY(listed.ok());
        QVERIFY2(entries.isEmpty(), qPrintable(entries.value(0).name));
    }

    void cancelDownload()
    {
        const auto backend = newBackend();
        const QString local = m_tmp.filePath(QStringLiteral("canceled.tar"));
        AtomicProgress progress;
        CancelProbe probe;
        Result setup;
        Result download;
        Result after;
        Entry entry;
        const qint64 elapsed = cancelDuring(backend.get(), &probe, [&]() {
            setup = signIn(backend.get(), params(QStringLiteral("strict")), credentials());
            if (setup.ok())
                setup = backend->makePath(QStringLiteral("M-T17"));
            if (setup.ok())
                setup = Transfer::uploadFile(backend.get(), m_big, QStringLiteral("M-T17/down.tar"));
            if (!setup.ok())
                return;
            download = Transfer::downloadFile(backend.get(), QStringLiteral("M-T17/down.tar"), local, &progress);
            probe.returned();
            // The connection stays usable after resetCancel().
            backend->resetCancel();
            after = backend->stat(QStringLiteral("M-T17/down.tar"), &entry);
            if (after.ok())
                after = backend->remove(QStringLiteral("M-T17/down.tar"));
            backend->disconnect();
        }, [&]() { return progress.bytes >= 4 * 1024 * 1024; });
        QVERIFY2(setup.ok(), qPrintable(setup.toString()));
        QCOMPARE(download.error(), Error::Canceled);
        QVERIFY2(elapsed < 2000, qPrintable(QString::number(elapsed)));
        QVERIFY(!QFile::exists(local));
        QVERIFY(!QFile::exists(Transfer::partName(local)));
        QVERIFY2(after.ok(), qPrintable(after.toString()));
        QCOMPARE(entry.size, BigSize);
    }

    // M-12: a request stalled on the network is abandoned within 2 s.
    void cancelStalledRequest()
    {
        const auto backend = newBackend();
        CancelProbe probe;
        Result signedIn;
        Result stalled;
        std::atomic<qint64> closingMs { -1 };
        std::atomic<qint64> stalledSince { 0 };
        const qint64 elapsed = cancelDuring(backend.get(), &probe, [&]() {
            signedIn = signIn(backend.get(), viaProxy(4453, true), credentials());
            if (!signedIn.ok())
                return;
            Entry entry;
            stalledSince = steadyMs();
            stalled = backend->stat(QString(), &entry);
            probe.returned();
            const qint64 closing = steadyMs();
            backend->disconnect();
            closingMs = steadyMs() - closing;
        }, [&]() { return stalledSince > 0 && steadyMs() - stalledSince > 500; });
        QVERIFY2(signedIn.ok(), qPrintable(signedIn.toString()));
        QCOMPARE(stalled.error(), Error::Canceled);
        QVERIFY2(elapsed < 2000, qPrintable(QString::number(elapsed)));
        QVERIFY2(closingMs >= 0 && closingMs < 2000, qPrintable(QString::number(closingMs)));
    }

    void cancelStalledSignIn()
    {
        const auto backend = newBackend();
        CancelProbe probe;
        Result r;
        const qint64 started = steadyMs();
        const qint64 elapsed = cancelDuring(backend.get(), &probe, [&]() {
            r = signIn(backend.get(), viaProxy(4454, true), credentials());
            probe.returned();
        }, [&]() { return steadyMs() - started > 500; });
        QCOMPARE(r.error(), Error::Canceled);
        QVERIFY2(elapsed < 2000, qPrintable(QString::number(elapsed)));
    }

    // M-7, C-14: the request timeout.
    void requestTimeout()
    {
        const auto backend = newBackend();
        ConnectionParams p = viaProxy(4453, true);
        p.requestTimeoutMs = 2000;
        QVERIFY(signIn(backend.get(), p, credentials()).ok());
        Entry entry;
        QElapsedTimer clock;
        clock.start();
        QCOMPARE(backend->stat(QString(), &entry).error(), Error::Timeout);
        QVERIFY2(clock.elapsed() < 2000 + 3000, qPrintable(QString::number(clock.elapsed())));
    }

    // The server goes away after sign-in, or during it.
    void connectionDropped()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), viaProxy(4455, true), credentials()).ok());
        Entry entry;
        QCOMPARE(backend->stat(QString(), &entry).error(), Error::NetworkUnreachable);
        QCOMPARE(backend->makePath(QStringLiteral("x")).error(), Error::NetworkUnreachable);
        backend->disconnect();

        const Result r = signIn(backend.get(), viaProxy(4456, true), credentials());
        QCOMPARE(r.error(), Error::SecurityPolicy);
    }

    // M-T18, M-8: a backups folder with a space and a non-ASCII character,
    // given with a leading '/' that is stripped.
    void nonAsciiFolder()
    {
        const QString dir = QString::fromUtf8("Sailfish OS/Backups f\xc3\xbcr J\xc3\xb6rg");
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict")), credentials()).ok());
        positiveFlow(backend.get(), QStringLiteral("strict"), QLatin1Char('/') + dir);
        int code = -1;
        exec(QStringLiteral("strict"), { QStringLiteral("test"), QStringLiteral("-d"),
                                         QStringLiteral("/srv/smb/backup/") + dir }, &code);
        QCOMPARE(code, 0);
    }

    // M-5: NTLM_USER_FILE never decides which password is used.
    void userFileIgnored()
    {
        QTemporaryDir dir;
        const QString file = dir.filePath(QStringLiteral("ntlm_user_file"));
        const auto writeUserFile = [&file](const QByteArray &secret) {
            QFile f(file);
            f.open(QIODevice::WriteOnly | QIODevice::Truncate);
            f.write(":backup:" + secret + "\n");     // empty domain: matches any server
        };

        // A wrong password in the file, the right one from the account.
        writeUserFile(m_password + "-wrong");
        qputenv("NTLM_USER_FILE", file.toLocal8Bit());
        const auto backend = newBackend();
        const Result right = signIn(backend.get(), params(QStringLiteral("strict")), credentials());
        QVERIFY2(right.ok(), qPrintable(right.toString()));
        QVERIFY(!qEnvironmentVariableIsSet("NTLM_USER_FILE"));
        backend->disconnect();

        // The right password in the file, a wrong one from the account.
        writeUserFile(m_password);
        qputenv("NTLM_USER_FILE", file.toLocal8Bit());
        const Result wrong = signIn(backend.get(), params(QStringLiteral("strict")), credentials(m_password + "x"));
        QCOMPARE(wrong.error(), Error::AuthFailed);
        qunsetenv("NTLM_USER_FILE");
    }

    // Documents why M-5 needs the backend's workaround: at the pinned commit
    // libsmb2 lets the file replace a password set with smb2_set_password().
    void libsmb2UserFilePrecedence()
    {
        QTemporaryDir dir;
        const QString file = dir.filePath(QStringLiteral("ntlm_user_file"));
        QFile f(file);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write(":backup:" + m_password + "-wrong\n");
        f.close();
        qputenv("NTLM_USER_FILE", file.toLocal8Bit());
        smb2_context *ctx = smb2_init_context();
        smb2_set_version(ctx, SMB2_VERSION_ANY3);
        smb2_set_seal(ctx, 1);
        smb2_set_user(ctx, "backup");
        smb2_set_password(ctx, m_password.constData());
        const QByteArray server = address(QStringLiteral("strict")).toUtf8();
        const int rc = smb2_connect_share(ctx, server.constData(), "backup", nullptr);
        const int status = smb2_get_nterror(ctx);
        smb2_destroy_context(ctx);
        qunsetenv("NTLM_USER_FILE");
        qInfo("libsmb2 with NTLM_USER_FILE and an explicit password: rc %d, NT status 0x%08x", rc, status);
        QVERIFY2(rc < 0, "libsmb2 now prefers the explicit password; M-5's workaround may be revisited");
    }

    // Operations beyond the positive flow, on the strict server.
    void operations()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict")), credentials()).ok());
        Entry entry;
        QVERIFY(backend->stat(QString(), &entry).ok());
        QVERIFY(entry.isDir);
        QVERIFY(backend->makePath(QStringLiteral("ops/sub")).ok());
        QVERIFY(backend->makePath(QStringLiteral("ops/sub")).ok());     // idempotent

        QByteArray a(10, 'a');
        QByteArray b(20, 'b');
        QBuffer bufA(&a);
        QBuffer bufB(&b);
        bufA.open(QIODevice::ReadOnly);
        bufB.open(QIODevice::ReadOnly);
        QVERIFY(backend->upload(&bufA, QStringLiteral("ops/a"), nullptr).ok());
        QVERIFY(backend->upload(&bufB, QStringLiteral("ops/b"), nullptr).ok());

        // rename replaces the target.
        QVERIFY(backend->rename(QStringLiteral("ops/a"), QStringLiteral("ops/b")).ok());
        QVERIFY(backend->stat(QStringLiteral("ops/b"), &entry).ok());
        QCOMPARE(entry.size, qint64(10));
        QCOMPARE(backend->stat(QStringLiteral("ops/a"), &entry).error(), Error::NotFound);
        QCOMPARE(backend->rename(QStringLiteral("ops/a"), QStringLiteral("ops/c")).error(), Error::NotFound);
        QCOMPARE(backend->rename(QStringLiteral("ops/b"), QStringLiteral("ops/sub")).error(), Error::AlreadyExists);
        QCOMPARE(backend->makePath(QStringLiteral("ops/b/deeper")).error(), Error::AlreadyExists);

        QByteArray part;
        QVERIFY(backend->read(QStringLiteral("ops/b"), 4, 3, &part).ok());
        QCOMPARE(part, QByteArray("aaa"));
        QVERIFY(backend->read(QStringLiteral("ops/b"), 8, 100, &part).ok());
        QCOMPARE(part, QByteArray("aa"));
        QCOMPARE(backend->read(QStringLiteral("ops/none"), 0, 1, &part).error(), Error::NotFound);

        QVERIFY(backend->remove(QStringLiteral("ops/b")).ok());
        QCOMPARE(backend->remove(QStringLiteral("ops/b")).error(), Error::NotFound);
        QVector<Entry> entries;
        QCOMPARE(backend->list(QStringLiteral("ops/none"), &entries).error(), Error::NotFound);
        QCOMPARE(backend->freeSpace(QStringLiteral("ops/none"), nullptr).error(), Error::NotFound);
        QByteArray sink;
        QBuffer sinkBuffer(&sink);
        sinkBuffer.open(QIODevice::WriteOnly);
        QCOMPARE(backend->download(QStringLiteral("ops/none"), &sinkBuffer, nullptr).error(), Error::NotFound);
        // Local I/O failures are not reported as server errors.
        QBuffer closed;
        QCOMPARE(backend->upload(&closed, QStringLiteral("ops/local"), nullptr).error(), Error::Internal);
        QVERIFY(backend->remove(QStringLiteral("ops/local")).ok());
        QByteArray small("0123456789");
        QBuffer smallBuffer(&small);
        smallBuffer.open(QIODevice::ReadOnly);
        QVERIFY(backend->upload(&smallBuffer, QStringLiteral("ops/small"), nullptr).ok());
        QBuffer readOnlySink(&small);
        readOnlySink.open(QIODevice::ReadOnly);
        QCOMPARE(backend->download(QStringLiteral("ops/small"), &readOnlySink, nullptr).error(), Error::Internal);
        // M-9 inside a session too: nothing is sent.
        QCOMPARE(backend->makePath(QStringLiteral("ops/bad|name")).error(), Error::Internal);
    }

    // The account lacks write access: PermissionDenied, not a sign-in error.
    void readOnlyShare()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict"), true, QStringLiteral("readonly")),
                       credentials()).ok());
        QByteArray data("x");
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QCOMPARE(backend->upload(&buffer, QStringLiteral("new.txt"), nullptr).error(), Error::PermissionDenied);
        QCOMPARE(backend->makePath(QStringLiteral("newdir")).error(), Error::PermissionDenied);
        QByteArray part;
        QVERIFY(backend->read(QStringLiteral("existing.txt"), 5, 4, &part).ok());
        QCOMPARE(part, QByteArray("only"));
    }

    // M-13: one context per thread; two connections in parallel.
    void parallelConnections()
    {
        const QString file = m_tmp.filePath(QStringLiteral("parallel.bin"));
        QVERIFY(writePattern(file, 8 * 1024 * 1024, 42));
        const QByteArray sha = sha256Of(file);
        std::array<Result, 2> results;
        std::array<std::thread, 2> threads;
        for (int i = 0; i < 2; ++i) {
            threads[i] = std::thread([this, i, &results, &file, &sha]() {
                const auto backend = newBackend();
                Result r = signIn(backend.get(), params(QStringLiteral("strict")), credentials());
                const QString name = QStringLiteral("parallel-%1.tar").arg(i);
                if (r.ok())
                    r = Transfer::uploadFile(backend.get(), file, name);
                const QString local = m_tmp.filePath(name);
                if (r.ok())
                    r = Transfer::downloadFile(backend.get(), name, local);
                if (r.ok() && sha256Of(local) != sha)
                    r = Result(Error::ProtocolError, QStringLiteral("content differs"));
                if (r.ok())
                    r = backend->remove(name);
                results[i] = r;
            });
        }
        for (std::thread &t : threads)
            t.join();
        for (const Result &r : results)
            QVERIFY2(r.ok(), qPrintable(r.toString()));
    }
};

QTEST_GUILESS_MAIN(TestInteropSmb)
#include "tst_interop_smb.moc"
