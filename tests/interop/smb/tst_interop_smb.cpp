// SPDX-License-Identifier: LGPL-2.1-or-later
// SMB interoperability matrix (SPEC-smb section 7) against the Samba
// containers that run.sh starts. Container names are "<prefix>-<server>";
// see run.sh for the servers and server/conf/ for their configurations.
#include "backendloader.h"
#include "identity.h"
#include "ops.h"
#include "paths.h"
#include "smb2api.h"
#include "smbshares.h"
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
using NetVfs::Smb::ShareInfo;
using NetVfs::Smb::ShareRequest;
using NetVfs::Smb::parseShareOutput;
using NetVfs::Smb::encodeShareRequest;

namespace QTest {
template<>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest

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
                QCOMPARE(e.type, EntryType::File);   // XC-2
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
        // tcpdump flushes and exits on SIGINT; on a loaded host that takes a while.
        exec(server, { QStringLiteral("sh"), QStringLiteral("-c"),
                       QStringLiteral("pkill -INT tcpdump; for i in $(seq 100); do pgrep tcpdump >/dev/null || exit 0; "
                                      "sleep 0.1; done; exit 1") });
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
        // M-2: every message is signed because the client requires it; the
        // server alone (signing not mandatory) would sign only the tree connect.
        QVERIFY2(!row.contains("partial"), row.constData());
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
        QCOMPARE(first.error(), Error::ConnectionLost);   // XC-21: after sign-in
        // The connection is aborted, not resynchronised.
        QCOMPARE(backend->stat(QString(), &entry).error(), Error::ConnectionLost);
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
        QCOMPARE(backend->stat(QString(), &entry).error(), Error::ConnectionLost);   // XC-21
        QCOMPARE(backend->makePath(QStringLiteral("x")).error(), Error::ConnectionLost);
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
        QVERIFY(entry.isDir());
        QVERIFY(backend->makePath(QStringLiteral("ops/sub")).ok());
        QVERIFY(backend->makePath(QStringLiteral("ops/sub")).ok());     // idempotent

        QByteArray a(10, 'a');
        QByteArray b(20, 'b');
        QBuffer bufA(&a);
        QBuffer bufB(&b);
        bufA.open(QIODevice::ReadOnly);
        bufB.open(QIODevice::ReadOnly);
        QVERIFY(backend->upload(&bufA, QStringLiteral("ops/a"), UploadOptions(), nullptr).ok());
        QVERIFY(backend->upload(&bufB, QStringLiteral("ops/b"), UploadOptions(), nullptr).ok());

        // rename(Replace) replaces the target.
        QVERIFY(backend->rename(QStringLiteral("ops/a"), QStringLiteral("ops/b"), RenameMode::Replace).ok());
        QVERIFY(backend->stat(QStringLiteral("ops/b"), &entry).ok());
        QCOMPARE(entry.size, qint64(10));
        QCOMPARE(backend->stat(QStringLiteral("ops/a"), &entry).error(), Error::NotFound);
        QCOMPARE(backend->rename(QStringLiteral("ops/a"), QStringLiteral("ops/c"), RenameMode::Replace).error(), Error::NotFound);
        QCOMPARE(backend->rename(QStringLiteral("ops/b"), QStringLiteral("ops/sub"), RenameMode::Replace).error(), Error::AlreadyExists);
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
        QCOMPARE(backend->download(QStringLiteral("ops/none"), &sinkBuffer, DownloadOptions(), nullptr).error(), Error::NotFound);
        // Local I/O failures are not reported as server errors.
        QBuffer closed;
        QCOMPARE(backend->upload(&closed, QStringLiteral("ops/local"), UploadOptions(), nullptr).error(), Error::Internal);
        QVERIFY(backend->remove(QStringLiteral("ops/local")).ok());
        QByteArray small("0123456789");
        QBuffer smallBuffer(&small);
        smallBuffer.open(QIODevice::ReadOnly);
        QVERIFY(backend->upload(&smallBuffer, QStringLiteral("ops/small"), UploadOptions(), nullptr).ok());
        QBuffer readOnlySink(&small);
        readOnlySink.open(QIODevice::ReadOnly);
        QCOMPARE(backend->download(QStringLiteral("ops/small"), &readOnlySink, DownloadOptions(), nullptr).error(), Error::Internal);
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
        QCOMPARE(backend->upload(&buffer, QStringLiteral("new.txt"), UploadOptions(), nullptr).error(), Error::PermissionDenied);
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

    // ---- API v2 (SPEC-v2 §4, §6.2) ---------------------------------------

private:
    static bool put(Backend *backend, const QString &path, const QByteArray &data,
                    const UploadOptions &options = UploadOptions())
    {
        QByteArray copy = data;
        QBuffer buffer(&copy);
        buffer.open(QIODevice::ReadOnly);
        const Result r = backend->upload(&buffer, path, options, nullptr);
        if (!r.ok())
            qWarning() << "upload failed:" << r.toString();
        return r.ok();
    }

    static QByteArray contentOf(Backend *backend, const QString &path)
    {
        QByteArray data;
        return backend->read(path, 0, -1, &data).ok() ? data : QByteArray("<unreadable>");
    }

private slots:
    // XC-5, XC-8, XC-9, XC-10, XM-5
    void v2Namespace()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict")), credentials()).ok());
        const Capabilities caps = backend->capabilities();
        QVERIFY(caps.has(Capability::NativeNoReplace));
        QVERIFY(caps.has(Capability::AtomicReplace));       // vendor/patches/libsmb2/0005
        QVERIFY(caps.has(Capability::ReadHandles));
        QVERIFY(caps.has(Capability::EfficientRanges));
        QVERIFY(caps.has(Capability::WriteResume));
        QVERIFY(caps.has(Capability::SetModified));
        QVERIFY(caps.has(Capability::SpaceInfo));
        QVERIFY(caps.has(Capability::WindowsNames));
        QVERIFY(caps.has(Capability::CaseInsensitive));
        QVERIFY(!caps.has(Capability::PosixModes));
        QVERIFY(!caps.has(Capability::Symlinks));
        QVERIFY(!caps.has(Capability::ShareEnumeration));   // share mode
        QCOMPARE(caps.maxNameBytes, qint64(255));
        QVERIFY(caps.maxReadChunk > 0 && caps.maxWriteChunk > 0);

        // XC-8
        QVERIFY(backend->makeDir(QStringLiteral("v2"), true).ok());
        QCOMPARE(backend->makeDir(QStringLiteral("v2"), true).error(), Error::AlreadyExists);
        QVERIFY(backend->makeDir(QStringLiteral("v2"), false).ok());
        QVERIFY(backend->makeDir(QString(), false).ok());
        QCOMPARE(backend->makeDir(QString(), true).error(), Error::AlreadyExists);
        QCOMPARE(backend->makeDir(QStringLiteral("v2/missing/deeper"), false).error(), Error::NotFound);
        QVERIFY(put(backend.get(), QStringLiteral("v2/a.txt"), "aaa"));
        QVERIFY(put(backend.get(), QStringLiteral("v2/b.txt"), "bbbb"));
        QCOMPARE(backend->makeDir(QStringLiteral("v2/a.txt"), false).error(), Error::AlreadyExists);
        QCOMPARE(backend->makeDir(QStringLiteral("v2/a.txt"), true).error(), Error::AlreadyExists);
        QVERIFY(backend->makeDir(QStringLiteral("v2/sub"), true).ok());

        // XC-10, XM-5: NoReplace is the server's; the target is untouched.
        QCOMPARE(backend->rename(QStringLiteral("v2/b.txt"), QStringLiteral("v2/a.txt"), RenameMode::NoReplace).error(),
                 Error::AlreadyExists);
        QCOMPARE(contentOf(backend.get(), QStringLiteral("v2/a.txt")), QByteArray("aaa"));
        QCOMPARE(backend->rename(QStringLiteral("v2/b.txt"), QStringLiteral("v2/sub"), RenameMode::NoReplace).error(),
                 Error::AlreadyExists);
        // XC-10: refused before the request (servers differ in what they answer).
        const Result ontoFolder = backend->rename(QStringLiteral("v2/b.txt"), QStringLiteral("v2/sub"), RenameMode::Replace);
        QCOMPARE(ontoFolder.error(), Error::AlreadyExists);
        QVERIFY2(ontoFolder.message().contains(QLatin1String("the target is a folder")), qPrintable(ontoFolder.message()));
        QVERIFY(backend->rename(QStringLiteral("v2/b.txt"), QStringLiteral("v2/c.txt"), RenameMode::NoReplace).ok());
        QCOMPARE(backend->rename(QStringLiteral("v2/nope"), QStringLiteral("v2/x"), RenameMode::NoReplace).error(),
                 Error::NotFound);
        QVERIFY(backend->rename(QStringLiteral("v2/c.txt"), QStringLiteral("v2/a.txt"), RenameMode::Replace).ok());
        QCOMPARE(contentOf(backend.get(), QStringLiteral("v2/a.txt")), QByteArray("bbbb"));
        QCOMPARE(backend->rename(QString(), QStringLiteral("v2/root"), RenameMode::NoReplace).error(),
                 Error::PermissionDenied);

        // XC-9
        QVERIFY(put(backend.get(), QStringLiteral("v2/sub/inner.txt"), "x"));
        QCOMPARE(backend->removeFile(QStringLiteral("v2/sub")).error(), Error::IsADirectory);
        QCOMPARE(backend->removeDir(QStringLiteral("v2/sub")).error(), Error::DirectoryNotEmpty);
        QCOMPARE(backend->removeDir(QStringLiteral("v2/a.txt")).error(), Error::NotADirectory);
        QCOMPARE(backend->removeDir(QStringLiteral("v2/nope")).error(), Error::NotFound);
        QCOMPARE(backend->removeFile(QStringLiteral("v2/nope")).error(), Error::NotFound);
        QCOMPARE(backend->removeDir(QString()).error(), Error::PermissionDenied);
        QVERIFY(backend->removeFile(QStringLiteral("v2/sub/inner.txt")).ok());
        QVERIFY(backend->removeDir(QStringLiteral("v2/sub")).ok());
        QVERIFY(backend->remove(QStringLiteral("v2/a.txt")).ok());

        QVERIFY(backend->keepAlive().ok());   // XM-8
        SpaceInfo space;
        QVERIFY(backend->spaceInfo(QStringLiteral("v2"), &space).ok());
        QVERIFY(space.total > 0 && space.free > 0 && space.free <= space.total && space.used >= 0);
        QVERIFY(backend->removeDir(QStringLiteral("v2")).ok());
    }

    // XC-6, XM-4
    void v2Listing()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict")), credentials()).ok());
        QVERIFY(backend->makePath(QStringLiteral("v2list/sub")).ok());
        for (int i = 0; i < 25; ++i)
            QVERIFY(put(backend.get(), QStringLiteral("v2list/f%1").arg(i), QByteArray(i, 'x')));

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
        options.batchSize = 4;
        QVERIFY(backend->list(QStringLiteral("v2list"), &sink, options).ok());
        QCOMPARE(sink.all.size(), 26);
        QCOMPARE(sink.sizes.size(), 7);
        for (const int size : sink.sizes)
            QVERIFY(size >= 1 && size <= 4);
        for (const Entry &e : sink.all) {
            QVERIFY(e.name != QLatin1String(".") && e.name != QLatin1String(".."));
            if (e.name == QLatin1String("sub")) {
                QCOMPARE(e.type, EntryType::Directory);
                QCOMPARE(e.size, qint64(-1));
            } else {
                QCOMPARE(e.type, EntryType::File);
                QCOMPARE(e.size, qint64(e.name.mid(1).toInt()));
                QVERIFY(e.modified.isValid());
                QCOMPARE(e.mode, -1);   // SMB has no POSIX modes
            }
        }

        struct StopAtFirst : ListSink {
            int calls = 0;
            bool entries(const QVector<Entry> &) override { return ++calls < 1; }
        } stop;
        QCOMPARE(backend->list(QStringLiteral("v2list"), &stop, options).error(), Error::Canceled);
        QCOMPARE(stop.calls, 1);
        QVector<Entry> plain;
        QCOMPARE(backend->list(QStringLiteral("v2list/f3"), &plain).error(), Error::NotADirectory);
    }

    // XC-13, XC-14
    void v2Transfers()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict")), credentials()).ok());
        QVERIFY(backend->makePath(QStringLiteral("v2io")).ok());
        QByteArray content(3 * 1024 * 1024 + 17, Qt::Uninitialized);
        for (int i = 0; i < content.size(); ++i)
            content[i] = static_cast<char>((i * 131) >> 3);
        QVERIFY(put(backend.get(), QStringLiteral("v2io/big.bin"), content));

        // Dispositions.
        QByteArray small("small");
        QBuffer source(&small);
        QVERIFY(source.open(QIODevice::ReadOnly));
        UploadOptions options;
        QCOMPARE(backend->upload(&source, QStringLiteral("v2io/big.bin"), options, nullptr).error(), Error::AlreadyExists);
        QCOMPARE(backend->upload(&source, QStringLiteral("v2io"), options, nullptr).error(), Error::IsADirectory);
        QVERIFY(put(backend.get(), QStringLiteral("v2io/small.bin"), "0123456789"));
        options.write.disposition = WriteOptions::Truncate;
        QVERIFY(backend->upload(&source, QStringLiteral("v2io/small.bin"), options, nullptr).ok());
        QCOMPARE(contentOf(backend.get(), QStringLiteral("v2io/small.bin")), small);

        // Ranged downloads.
        QByteArray received;
        QBuffer sink(&received);
        QVERIFY(sink.open(QIODevice::WriteOnly));
        DownloadOptions range;
        range.offset = 1000;
        range.length = 1024 * 1024 + 5;
        QVERIFY(backend->download(QStringLiteral("v2io/big.bin"), &sink, range, nullptr).ok());
        QCOMPARE(received, content.mid(1000, 1024 * 1024 + 5));
        sink.close();
        received.clear();
        QVERIFY(sink.open(QIODevice::WriteOnly));
        range.offset = content.size() - 10;
        range.length = -1;
        QVERIFY(backend->download(QStringLiteral("v2io/big.bin"), &sink, range, nullptr).ok());
        QCOMPARE(received, content.right(10));
        QCOMPARE(backend->download(QStringLiteral("v2io"), &sink, DownloadOptions(), nullptr).error(),
                 Error::IsADirectory);

        // A handle reads ranges on one open file, also at EOF.
        ReadHandle *raw = nullptr;
        QVERIFY(backend->openRead(QStringLiteral("v2io/big.bin"), &raw).ok());
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
        QCOMPARE(handle->read(-1, 1, &part).error(), Error::Internal);
        // XM-6: read-ahead, then reads elsewhere: the queued chunks are not
        // mistaken for the new position.
        handle->readAhead(0, 3 * 1024 * 1024);
        QVERIFY(handle->read(2 * 1024 * 1024 + 7, 10, &part).ok());
        QCOMPARE(part, content.mid(2 * 1024 * 1024 + 7, 10));
        QVERIFY(handle->read(100, 10, &part).ok());
        QCOMPARE(part, content.mid(100, 10));
        handle->readAhead(1000, 2 * 1024 * 1024);
        QVERIFY(handle->read(1000, 1024 * 1024 + 1, &part).ok());
        QCOMPARE(part, content.mid(1000, 1024 * 1024 + 1));
        QVERIFY(handle->close().ok());
        QCOMPARE(handle->read(0, 1, &part).error(), Error::Internal);
        ReadHandle *missing = nullptr;
        QCOMPARE(backend->openRead(QStringLiteral("v2io/nope"), &missing).error(), Error::NotFound);
        QVERIFY(!missing);
        QCOMPARE(backend->openRead(QStringLiteral("v2io"), &missing).error(), Error::IsADirectory);
        QVERIFY(!missing);

        // Handles end with the connection.
        QVERIFY(backend->openRead(QStringLiteral("v2io/big.bin"), &raw).ok());
        handle.reset(raw);
        backend->disconnect();
        QCOMPARE(handle->read(0, 1, &part).error(), Error::ConnectionLost);
        handle.reset();
    }

    // XC-20, XC-21: the proxy drops the connection after sign-in.
    void v2KeepAliveAfterDrop()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), viaProxy(4455, true), credentials()).ok());
        QCOMPARE(backend->keepAlive().error(), Error::ConnectionLost);
        QCOMPARE(backend->keepAlive().error(), Error::ConnectionLost);
    }

    // ---- SPEC-v2 §6.2: profiles, server mode, share enumeration ---------

private:
    ConnectionParams profiled(const QString &server, const QString &profile, const QString &share = QStringLiteral("backup"))
    {
        ConnectionParams p = params(server, true, share);
        p.options.insert(QStringLiteral("security_profile"), profile);
        if (share.isEmpty())
            p.options.remove(QStringLiteral("share"));
        return p;
    }

    // Processes (one per TCP connection) of `user` on `server`.
    int connections(const QString &server, const QByteArray &user = QByteArray("backup")) const
    {
        const QList<QByteArray> lines = exec(server, { QStringLiteral("smbstatus"), QStringLiteral("-p") }).split('\n');
        return static_cast<int>(std::count_if(lines.begin(), lines.end(), [&user](const QByteArray &line) {
            return line.simplified().split(' ').value(1) == user;
        }));
    }

    // Tree connects to `share` on `server`.
    int treeConnects(const QString &server, const QByteArray &share) const
    {
        const QList<QByteArray> lines = exec(server, { QStringLiteral("smbstatus"), QStringLiteral("-S") }).split('\n');
        return static_cast<int>(std::count_if(lines.begin(), lines.end(), [&share](const QByteArray &line) {
            return line.simplified().split(' ').value(0) == share;
        }));
    }

    static QStringList namesOf(const QVector<Entry> &entries)
    {
        QStringList names;
        for (const Entry &e : entries)
            names << e.name;
        return names;
    }

private slots:
    // XM-1, M-T9: SMB 2.1 only. strict and signed refuse it, legacy accepts it.
    void profilesOnSmb2Only_data()
    {
        QTest::addColumn<QString>("profile");
        QTest::addColumn<bool>("accepted");
        QTest::newRow("strict") << "strict" << false;
        QTest::newRow("signed") << "signed" << false;
        QTest::newRow("legacy") << "legacy" << true;
    }

    void profilesOnSmb2Only()
    {
        QFETCH(QString, profile);
        QFETCH(bool, accepted);
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), profiled(QStringLiteral("smb2only"), profile), credentials());
        if (!accepted) {
            QCOMPARE(r.error(), Error::SecurityPolicy);
            return;
        }
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QVERIFY(put(backend.get(), QStringLiteral("legacy.txt"), "smb 2.1"));
        QCOMPARE(contentOf(backend.get(), QStringLiteral("legacy.txt")), QByteArray("smb 2.1"));
        const QByteArray row = sessionRow(QStringLiteral("smb2only"));
        QVERIFY2(row.contains("SMB2_10"), row.constData());
        QVERIFY(backend->removeFile(QStringLiteral("legacy.txt")).ok());
    }

    // XM-1: legacy and signed against the strict server still get SMB 3.1.1
    // with the encryption the server requires.
    void weakerProfilesOnStrictServer()
    {
        for (const QString &profile : { QStringLiteral("signed"), QStringLiteral("legacy") }) {
            const auto backend = newBackend();
            const Result r = signIn(backend.get(), profiled(QStringLiteral("strict"), profile), credentials());
            QVERIFY2(r.ok(), qPrintable(profile + QLatin1String(": ") + r.toString()));
            QVERIFY(backend->keepAlive().ok());
            const QByteArray row = sessionRow(QStringLiteral("strict"));
            QVERIFY2(row.contains("SMB3_11") && row.contains("AES-128-CCM"), row.constData());
        }
    }

    // XM-1: the guest profile: no user, no password, signing off.
    void guestProfile()
    {
        const auto backend = newBackend();
        const Result r = signIn(backend.get(), profiled(QStringLiteral("guest"), QStringLiteral("guest"),
                                                        QStringLiteral("public")),
                                Credentials());
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QVERIFY(backend->makeDir(QStringLiteral("guestdir"), false).ok());
        QVERIFY(put(backend.get(), QStringLiteral("guestdir/g.txt"), "guest"));
        QCOMPARE(contentOf(backend.get(), QStringLiteral("guestdir/g.txt")), QByteArray("guest"));
        QVERIFY(backend->removeFile(QStringLiteral("guestdir/g.txt")).ok());
        QVERIFY(backend->removeDir(QStringLiteral("guestdir")).ok());
        // Guest against a server that does not map guests.
        const auto refused = newBackend();
        QVERIFY(!signIn(refused.get(), profiled(QStringLiteral("strict"), QStringLiteral("guest")), Credentials()).ok());
    }

    // XM-1: "map to guest = Bad User" turns an unknown user into a guest;
    // every profile but guest refuses that session (no silent downgrade).
    void guestMappingRefused_data()
    {
        QTest::addColumn<QString>("profile");
        QTest::newRow("strict") << "strict";
        QTest::newRow("signed") << "signed";
        QTest::newRow("legacy") << "legacy";
    }

    void guestMappingRefused()
    {
        QFETCH(QString, profile);
        const auto backend = newBackend();
        ConnectionParams p = profiled(QStringLiteral("guest"), profile, QStringLiteral("public"));
        p.username = QStringLiteral("nosuchuser");
        const Result r = signIn(backend.get(), p, Credentials(QStringLiteral("nosuchuser"), "whatever"));
        QCOMPARE(r.error(), Error::SecurityPolicy);
        QVERIFY2(r.message().contains(QLatin1String("guest")), qPrintable(r.message()));
        // The real account is not affected.
        const auto account = newBackend();
        QVERIFY(signIn(account.get(), profiled(QStringLiteral("guest"), profile), credentials()).ok());
    }

    // XM-2, XM-3, XM-7: the root of server mode lists shares.
    void serverModeRoot()
    {
        const auto backend = newBackend();
        ConnectionParams p = profiled(QStringLiteral("strict"), QStringLiteral("strict"), QString());
        p.options.insert(QStringLiteral("shares"), QStringLiteral("backup, Saved"));
        QVERIFY(signIn(backend.get(), p, credentials()).ok());
        const Capabilities caps = backend->capabilities();
        QVERIFY(caps.has(Capability::ShareEnumeration));
        QVERIFY(caps.has(Capability::ReadHandles));

        QVector<Entry> entries;
        QVERIFY(backend->list(QStringLiteral("/"), &entries).ok());
        const QStringList names = namesOf(entries);
        // Saved names first, then what the server lists (disk shares, no '$').
        QCOMPARE(names, QStringList({ QStringLiteral("backup"), QStringLiteral("Saved"), QStringLiteral("readonly"),
                                      QStringLiteral("small"), QStringLiteral("media"), QStringLiteral("dfs") }));
        for (const Entry &e : entries) {
            QCOMPARE(e.type, EntryType::Directory);
            QVERIFY(!e.flags.testFlag(EntryFlag::ReadOnly));
        }
        QCOMPARE(entries.at(4).extra.value(QStringLiteral("remark")).toString(), QStringLiteral("Films and music"));

        Entry entry;
        QVERIFY(backend->stat(QStringLiteral("/"), &entry).ok());
        QCOMPARE(entry.type, EntryType::Directory);
        QVERIFY(backend->stat(QStringLiteral("/media"), &entry).ok());
        QCOMPARE(entry.name, QStringLiteral("media"));
        QCOMPARE(entry.type, EntryType::Directory);
        QCOMPARE(backend->stat(QStringLiteral("/Saved"), &entry).error(), Error::NotFound);   // no such share

        p.options.insert(QStringLiteral("show_admin_shares"), true);
        const auto admin = newBackend();
        QVERIFY(signIn(admin.get(), p, credentials()).ok());
        QVERIFY(admin->list(QStringLiteral("/"), &entries).ok());
        QVERIFY(namesOf(entries).contains(QStringLiteral("hidden$")));
        QVERIFY(!namesOf(entries).contains(QStringLiteral("IPC$")));     // not a disk share

        p.options.insert(QStringLiteral("share_enumeration"), false);
        const auto saved = newBackend();
        QVERIFY(signIn(saved.get(), p, credentials()).ok());
        QVERIFY(!saved->capabilities().has(Capability::ShareEnumeration));
        QVERIFY(saved->list(QStringLiteral("/"), &entries).ok());
        QCOMPARE(namesOf(entries), QStringList({ QStringLiteral("backup"), QStringLiteral("Saved") }));
    }

    // XM-2: what the root and the shares themselves allow.
    void serverModeOperations()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), profiled(QStringLiteral("strict"), QStringLiteral("strict"), QString()),
                       credentials()).ok());
        QCOMPARE(backend->makeDir(QStringLiteral("/"), false).error(), Error::PermissionDenied);
        QCOMPARE(backend->makeDir(QStringLiteral("/newshare"), false).error(), Error::PermissionDenied);
        QCOMPARE(backend->removeDir(QStringLiteral("/")).error(), Error::PermissionDenied);
        QCOMPARE(backend->removeFile(QStringLiteral("/")).error(), Error::PermissionDenied);
        // Refused by the backend itself, not left to the server.
        const Result shareRemoval = backend->removeDir(QStringLiteral("/backup"));
        QCOMPARE(shareRemoval.error(), Error::PermissionDenied);
        QVERIFY2(shareRemoval.message().contains(QLatin1String("a share cannot be removed")),
                 qPrintable(shareRemoval.message()));
        QCOMPARE(backend->rename(QStringLiteral("/backup"), QStringLiteral("/b2"), RenameMode::NoReplace).error(),
                 Error::PermissionDenied);
        QVERIFY(put(backend.get(), QStringLiteral("/backup/server-mode.txt"), "server mode"));
        QCOMPARE(backend->rename(QStringLiteral("/backup/server-mode.txt"), QStringLiteral("/"), RenameMode::Replace).error(),
                 Error::PermissionDenied);
        QCOMPARE(backend->rename(QStringLiteral("/backup/server-mode.txt"), QStringLiteral("/media/x.txt"),
                                 RenameMode::NoReplace).error(),
                 Error::Unsupported);
        QByteArray data("x");
        QBuffer source(&data);
        QVERIFY(source.open(QIODevice::ReadOnly));
        QCOMPARE(backend->upload(&source, QStringLiteral("/file.txt"), UploadOptions(), nullptr).error(),
                 Error::PermissionDenied);
        WriteHandle *writer = nullptr;
        QCOMPARE(backend->openWrite(QStringLiteral("/"), WriteOptions(), &writer).error(), Error::PermissionDenied);
        ReadHandle *reader = nullptr;
        QCOMPARE(backend->openRead(QStringLiteral("/"), &reader).error(), Error::PermissionDenied);
        SpaceInfo space;
        QCOMPARE(backend->spaceInfo(QStringLiteral("/"), &space).error(), Error::PermissionDenied);
        AttributeChanges times;
        times.modified = QDateTime::currentDateTimeUtc();
        QCOMPARE(backend->setAttributes(QStringLiteral("/"), times).error(), Error::PermissionDenied);

        // Inside a share everything works as in share mode.
        QVERIFY(backend->makePath(QStringLiteral("/backup/server/a")).ok());
        QVERIFY(backend->makeDir(QStringLiteral("/backup"), false).ok());
        QCOMPARE(backend->makeDir(QStringLiteral("/backup"), true).error(), Error::AlreadyExists);
        QCOMPARE(contentOf(backend.get(), QStringLiteral("/backup/server-mode.txt")), QByteArray("server mode"));
        QVERIFY(backend->rename(QStringLiteral("/backup/server-mode.txt"), QStringLiteral("/backup/server/a/m.txt"),
                                RenameMode::NoReplace).ok());
        QVERIFY(backend->spaceInfo(QStringLiteral("/backup"), &space).ok());
        QVERIFY(space.total > 0);
        QVERIFY(backend->keepAlive().ok());
        QVERIFY(backend->removeFile(QStringLiteral("/backup/server/a/m.txt")).ok());
        QVERIFY(backend->removeDir(QStringLiteral("/backup/server/a")).ok());
        QVERIFY(backend->removeDir(QStringLiteral("/backup/server")).ok());
    }

    // XM-2: at most four share contexts; the least recently used goes,
    // never one with open handles.
    void serverModeContextLimit()
    {
        const QString server = QStringLiteral("strict");
        QTRY_COMPARE_WITH_TIMEOUT(connections(server), 0, 15000);
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), profiled(server, QStringLiteral("strict"), QString()), credentials()).ok());
        const QStringList shares { QStringLiteral("backup"), QStringLiteral("small"), QStringLiteral("media"),
                                   QStringLiteral("hidden$"), QStringLiteral("readonly") };
        Entry entry;
        QVERIFY(put(backend.get(), QStringLiteral("/backup/lru.txt"), "backup"));
        QTRY_COMPARE(connections(server), 2);        // IPC$ and backup
        // Share names are case-insensitive: no second context for BACKUP.
        QVERIFY(backend->stat(QStringLiteral("/BACKUP/lru.txt"), &entry).ok());
        QTest::qWait(500);
        QCOMPARE(connections(server), 2);
        for (const QString &share : shares.mid(1, 3))
            QVERIFY(put(backend.get(), QStringLiteral("/%1/lru.txt").arg(share), share.toUtf8()));
        QTRY_COMPARE(connections(server), 5);        // IPC$ and four shares
        // Share names are case-insensitive: the same context, and a use.
        QVERIFY(backend->stat(QStringLiteral("/BACKUP/lru.txt"), &entry).ok());
        QVERIFY(backend->stat(QStringLiteral("/readonly/existing.txt"), &entry).ok());
        QTRY_COMPARE(connections(server), 5);        // one closed for the fifth
        QTRY_COMPARE(treeConnects(server, "small"), 0);    // the least recently used
        QCOMPARE(treeConnects(server, "backup"), 1);

        // Handles keep their context: four open files, a fifth share waits.
        std::vector<std::unique_ptr<ReadHandle>> handles;
        for (const QString &share : shares.mid(0, 4)) {
            ReadHandle *raw = nullptr;
            QVERIFY(backend->openRead(QStringLiteral("/%1/lru.txt").arg(share), &raw).ok());
            handles.emplace_back(raw);
        }
        QCOMPARE(backend->stat(QStringLiteral("/readonly/existing.txt"), &entry).error(), Error::TooManyConnections);
        QVERIFY(handles.at(1)->close().ok());
        QVERIFY(backend->stat(QStringLiteral("/readonly/existing.txt"), &entry).ok());
        QByteArray data;
        for (const int i : { 0, 2, 3 }) {
            QVERIFY(handles.at(static_cast<size_t>(i))->read(0, 100, &data).ok());
            QCOMPARE(data, shares.at(i).toUtf8());
        }
        QCOMPARE(handles.at(1)->read(0, 1, &data).error(), Error::Internal);   // closed
        handles.clear();
        for (const QString &share : shares.mid(0, 4))
            QVERIFY(backend->removeFile(QStringLiteral("/%1/lru.txt").arg(share)).ok());
        // C-9, disconnect covers every context.
        backend->disconnect();
        QTRY_COMPARE_WITH_TIMEOUT(connections(server), 0, 15000);
    }

    // XM-7: a broken helper is ProtocolError and the backend stays usable;
    // without the helper there is no ShareEnumeration.
    void shareHelperFailures()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString crash = dir.filePath(QStringLiteral("crash.sh"));
        QFile script(crash);
        QVERIFY(script.open(QIODevice::WriteOnly));
        script.write("#!/bin/sh\ncat >/dev/null\nprintf '{\"name\":\"evil/../x\",\"type\":0,\"remark\":\"\"}\\n'\nkill -SEGV $$\n");
        script.close();
        script.setPermissions(QFileDevice::ReadOwner | QFileDevice::ExeOwner);
        const QByteArray original = qgetenv("NETVFS_SMB_SHARES_HELPER");
        qputenv("NETVFS_SMB_SHARES_HELPER", QFile::encodeName(crash));
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), profiled(QStringLiteral("strict"), QStringLiteral("strict"), QString()),
                       credentials()).ok());
        QVector<Entry> entries;
        QCOMPARE(backend->list(QStringLiteral("/"), &entries).error(), Error::ProtocolError);
        Entry entry;
        QVERIFY(backend->stat(QStringLiteral("/backup"), &entry).ok());
        QVERIFY(backend->keepAlive().ok());

        qputenv("NETVFS_SMB_SHARES_HELPER", QFile::encodeName(dir.filePath(QStringLiteral("missing"))));
        QVERIFY(!backend->capabilities().has(Capability::ShareEnumeration));
        QVERIFY(backend->list(QStringLiteral("/"), &entries).ok());
        QVERIFY(entries.isEmpty());          // nothing saved, nothing enumerated
        qputenv("NETVFS_SMB_SHARES_HELPER", original);
    }

    // XM-7: the helper itself, as the backend runs it: the same profile
    // checks (a guest mapping is refused), shares as JSON lines.
    void shareHelperDirect()
    {
        const auto run = [](const ShareRequest &request, QByteArray *out) {
            QProcess helper;
            helper.start(QString::fromLocal8Bit(qgetenv("NETVFS_SMB_SHARES_HELPER")), QStringList());
            if (!helper.waitForStarted(10000))
                return -1;
            helper.write(encodeShareRequest(request));
            helper.closeWriteChannel();
            helper.waitForFinished(60000);
            *out = helper.readAllStandardOutput();
            return helper.exitStatus() == QProcess::NormalExit ? helper.exitCode() : -1;
        };
        ShareRequest request;
        request.server = address(QStringLiteral("strict")).toUtf8();
        request.user = "backup";
        request.profile = "strict";
        request.requestTimeoutMs = 30000;
        request.secret = m_password;
        QByteArray out;
        QCOMPARE(run(request, &out), 0);
        QVector<ShareInfo> shares;
        QVERIFY2(parseShareOutput(out, &shares).ok(), out.constData());
        QStringList names;
        for (const ShareInfo &share : shares)
            names << share.name;
        QVERIFY2(names.contains(QStringLiteral("hidden$")) && names.contains(QStringLiteral("IPC$")),
                 qPrintable(names.join(QLatin1Char(','))));   // the filter is the backend's

        request.server = address(QStringLiteral("guest")).toUtf8();
        request.user = "nosuchuser";
        request.secret = "whatever";
        QCOMPARE(run(request, &out), 1);
        const Result mapped = parseShareOutput(out, &shares);
        QCOMPARE(mapped.error(), Error::SecurityPolicy);
        QVERIFY2(mapped.message().contains(QLatin1String("guest")), qPrintable(mapped.message()));
        request.secret = "wrong";
        request.user = "backup";
        QCOMPARE(run(request, &out), 1);
        QCOMPARE(parseShareOutput(out, &shares).error(), Error::AuthFailed);
    }

    // C-9: a cancel() from within the transfer ends it, even when the
    // rest of the file has already arrived (read-ahead).
    void downloadCancelFromProgress()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict")), credentials()).ok());
        const QByteArray data(3 * 1024 * 1024, 'd');
        QVERIFY(put(backend.get(), QStringLiteral("cancel-me.bin"), data));
        struct CancelOnFirst : Progress {
            Backend *backend = nullptr;
            void update(qint64, qint64) override { backend->cancel(); }
        } progress;
        progress.backend = backend.get();
        QByteArray received;
        QBuffer sink(&received);
        QVERIFY(sink.open(QIODevice::WriteOnly));
        QCOMPARE(backend->download(QStringLiteral("cancel-me.bin"), &sink, DownloadOptions(), &progress).error(),
                 Error::Canceled);
        QVERIFY(received.size() < data.size());
        backend->resetCancel();
        QVERIFY(backend->removeFile(QStringLiteral("cancel-me.bin")).ok());
    }

    // XM-9: a DFS link is Unsupported with the detail "DFS referral".
    void dfsReferral()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict"), true, QStringLiteral("dfs")), credentials()).ok());
        Entry entry;
        const Result r = backend->stat(QStringLiteral("away"), &entry);
        QCOMPARE(r.error(), Error::Unsupported);
        QCOMPARE(r.detail(), QStringLiteral("DFS referral"));
        QVector<Entry> entries;
        QCOMPARE(backend->list(QStringLiteral("away"), &entries).error(), Error::Unsupported);
    }

    // XC-11, XM-6: times through SET_INFO; modes are not SMB's.
    void attributes()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict")), credentials()).ok());
        QVERIFY(put(backend.get(), QStringLiteral("attr.txt"), "attributes"));
        const QDateTime when(QDate(2021, 3, 4), QTime(5, 6, 7), Qt::UTC);
        AttributeChanges changes;
        changes.modified = when;
        QVERIFY(backend->setAttributes(QStringLiteral("attr.txt"), changes).ok());
        Entry entry;
        QVERIFY(backend->stat(QStringLiteral("attr.txt"), &entry).ok());
        QCOMPARE(entry.modified, when);
        QCOMPARE(exec(QStringLiteral("strict"), { QStringLiteral("stat"), QStringLiteral("-c"), QStringLiteral("%Y"),
                                                  QStringLiteral("/srv/smb/backup/attr.txt") })
                     .trimmed(),
                 QByteArray::number(when.toMSecsSinceEpoch() / 1000));
        changes.mode = 0644;
        QCOMPARE(backend->setAttributes(QStringLiteral("attr.txt"), changes).error(), Error::Unsupported);
        changes = AttributeChanges();
        changes.accessed = when.addDays(1);
        QVERIFY(backend->setAttributes(QStringLiteral("attr.txt"), changes).ok());
        QVERIFY(backend->stat(QStringLiteral("attr.txt"), &entry).ok());
        QCOMPARE(entry.modified, when);                  // left alone
        QCOMPARE(entry.accessed, when.addDays(1));
        QCOMPARE(backend->setAttributes(QStringLiteral("nope.txt"), changes).error(), Error::NotFound);
        // A folder, too.
        QVERIFY(backend->makeDir(QStringLiteral("attrdir"), false).ok());
        changes = AttributeChanges();
        changes.modified = when;
        QVERIFY(backend->setAttributes(QStringLiteral("attrdir"), changes).ok());
        QVERIFY(backend->stat(QStringLiteral("attrdir"), &entry).ok());
        QCOMPARE(entry.modified, when);
        // XC-14: WriteOptions::modified on commit.
        UploadOptions upload;
        upload.write.disposition = WriteOptions::Truncate;
        upload.write.modified = when.addYears(1);
        QVERIFY(put(backend.get(), QStringLiteral("attr.txt"), "again", upload));
        QVERIFY(backend->stat(QStringLiteral("attr.txt"), &entry).ok());
        QCOMPARE(entry.modified, when.addYears(1));
        QVERIFY(entry.created.isValid());               // XM-4: birth time
        QVERIFY(backend->removeFile(QStringLiteral("attr.txt")).ok());
        QVERIFY(backend->removeDir(QStringLiteral("attrdir")).ok());
    }

    // XM-4: DOS attributes as entry flags.
    void entryFlags()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict")), credentials()).ok());
        QVERIFY(put(backend.get(), QStringLiteral("flags.txt"), "flags"));
        int code = -1;
        exec(QStringLiteral("strict"), { QStringLiteral("smbclient"), QStringLiteral("//localhost/backup"),
                                         QStringLiteral("-A"), QStringLiteral("/etc/netvfs-auth"), QStringLiteral("-c"),
                                         QStringLiteral("setmode flags.txt +hrs") },
             &code);
        QCOMPARE(code, 0);
        Entry entry;
        QVERIFY(backend->stat(QStringLiteral("flags.txt"), &entry).ok());
        QVERIFY(entry.flags.testFlag(EntryFlag::Hidden));
        QVERIFY(entry.flags.testFlag(EntryFlag::ReadOnly));
        QVERIFY(entry.flags.testFlag(EntryFlag::System));
        exec(QStringLiteral("strict"), { QStringLiteral("smbclient"), QStringLiteral("//localhost/backup"),
                                         QStringLiteral("-A"), QStringLiteral("/etc/netvfs-auth"), QStringLiteral("-c"),
                                         QStringLiteral("setmode flags.txt -hrs") });
        QVERIFY(backend->stat(QStringLiteral("flags.txt"), &entry).ok());
        QVERIFY(!entry.flags.testFlag(EntryFlag::Hidden));
        QVERIFY(backend->removeFile(QStringLiteral("flags.txt")).ok());
    }

    // M-13 (C-8 hand-over), XH-5: Ops::copyAcross runs the source's download
    // on a worker thread; SMB to local and SMB to SMB (server mode).
    void copyAcrossThreads()
    {
        const auto source = newBackend();
        QVERIFY(signIn(source.get(), params(QStringLiteral("strict")), credentials()).ok());
        QByteArray content(5 * 1024 * 1024 + 3, Qt::Uninitialized);
        for (int i = 0; i < content.size(); ++i)
            content[i] = static_cast<char>(i * 7 + (i >> 11));
        QVERIFY(put(source.get(), QStringLiteral("across.bin"), content));

        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const std::unique_ptr<Backend> local(BackendLoader::create(QStringLiteral("local")));
        QVERIFY(local);
        ConnectionParams localParams;
        localParams.provider = QStringLiteral("local");
        localParams.options.insert(QStringLiteral("root"), dir.path());
        QVERIFY(establish(local.get(), localParams, Credentials()).ok());
        Result r = Ops::copyAcross(source.get(), QStringLiteral("across.bin"), local.get(), QStringLiteral("copy.bin"));
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QFile copy(dir.filePath(QStringLiteral("copy.bin")));
        QVERIFY(copy.open(QIODevice::ReadOnly));
        QCOMPARE(copy.readAll(), content);

        const auto destination = newBackend();
        QVERIFY(signIn(destination.get(), profiled(QStringLiteral("strict"), QStringLiteral("strict"), QString()),
                       credentials()).ok());
        r = Ops::copyAcross(source.get(), QStringLiteral("across.bin"), destination.get(), QStringLiteral("/media/across.bin"));
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(contentOf(destination.get(), QStringLiteral("/media/across.bin")), content);
        // And back, with the server-mode backend as the source.
        r = Ops::copyAcross(destination.get(), QStringLiteral("/media/across.bin"), source.get(), QStringLiteral("back.bin"));
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(contentOf(source.get(), QStringLiteral("back.bin")), content);
        // The source is usable on this thread again.
        QVERIFY(source->keepAlive().ok());
        QVERIFY(source->removeFile(QStringLiteral("across.bin")).ok());
        QVERIFY(source->removeFile(QStringLiteral("back.bin")).ok());
        QVERIFY(destination->removeFile(QStringLiteral("/media/across.bin")).ok());
    }

    // XM-6: resume continues at the remote size, and only there.
    void writeResume()
    {
        const auto backend = newBackend();
        QVERIFY(signIn(backend.get(), params(QStringLiteral("strict")), credentials()).ok());
        QVERIFY(put(backend.get(), QStringLiteral("resume.bin"), "0123456789"));
        WriteOptions options;
        options.disposition = WriteOptions::Resume;
        options.resumeOffset = 9;
        WriteHandle *raw = nullptr;
        const Result wrong = backend->openWrite(QStringLiteral("resume.bin"), options, &raw);
        QVERIFY2(wrong.error() == Error::ProtocolError, qPrintable(wrong.toString()));
        QVERIFY(!raw);
        options.resumeOffset = 11;
        QCOMPARE(backend->openWrite(QStringLiteral("resume.bin"), options, &raw).error(), Error::ProtocolError);
        options.resumeOffset = 10;
        QVERIFY(backend->openWrite(QStringLiteral("resume.bin"), options, &raw).ok());
        std::unique_ptr<WriteHandle> writer(raw);
        QCOMPARE(writer->position(), qint64(10));
        QByteArray tail(3 * 1024 * 1024 + 5, 'z');
        QVERIFY(writer->write(tail.constData(), tail.size()).ok());
        QCOMPARE(writer->position(), qint64(10) + tail.size());
        QVERIFY(writer->commit().ok());
        QCOMPARE(contentOf(backend.get(), QStringLiteral("resume.bin")), QByteArray("0123456789") + tail);
        QCOMPARE(writer->write("x", 1).error(), Error::Internal);    // committed: closed
        options.resumeOffset = 0;
        QCOMPARE(backend->openWrite(QStringLiteral("missing.bin"), options, &raw).error(), Error::NotFound);
        QVERIFY(backend->removeFile(QStringLiteral("resume.bin")).ok());
    }
};

QTEST_GUILESS_MAIN(TestInteropSmb)
#include "tst_interop_smb.moc"
