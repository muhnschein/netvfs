// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakebackend.h"
#include "identity.h"
#include "transfer.h"

#include <QtCore/QBuffer>
#include <QtCore/QTemporaryDir>
#include <QtConcurrent/QtConcurrentRun>
#include <QtTest/QtTest>

#include <algorithm>

using namespace NetVfs;
using NetVfs::Test::FakeBackend;
using NetVfs::Test::FakeServer;

namespace {
class RecordingProgress : public Progress
{
public:
    void update(qint64 done, qint64) override { last = done; ++calls; }
    qint64 last = 0;
    int calls = 0;
};

// A source that cannot seek, so resuming has to skip by reading.
class SequentialSource : public QIODevice
{
public:
    explicit SequentialSource(const QByteArray &data) : m_data(data) { open(QIODevice::ReadOnly); }
    bool isSequential() const override { return true; }

protected:
    qint64 readData(char *data, qint64 maxSize) override
    {
        const qint64 n = qMin<qint64>(maxSize, m_data.size() - m_pos);
        std::copy_n(m_data.constData() + m_pos, n, data);
        m_pos += n;
        return n;
    }
    qint64 writeData(const char *, qint64) override { return -1; }

private:
    QByteArray m_data;
    qint64 m_pos = 0;
};

// Stops the transfer through Progress::canceled() after the first update (XC-14).
class CancelingProgress : public Progress
{
public:
    void update(qint64 done, qint64) override { stop = done > 0; }
    bool canceled() const override { return stop; }
    bool stop = false;
};

QByteArray pattern(int size)
{
    QByteArray data(size, Qt::Uninitialized);
    for (int i = 0; i < size; ++i)
        data[i] = static_cast<char>(i * 31 + 7);
    return data;
}
} // namespace

class TestTransfer : public QObject
{
    Q_OBJECT

private:
    FakeServer *server = FakeServer::instance();
    QScopedPointer<FakeBackend> backend;

    void connectBackend()
    {
        backend.reset(new FakeBackend);
        QVERIFY(establish(backend.data(), ConnectionParams(), Credentials(QStringLiteral("user"), "secret")).ok());
        server->log.clear();
    }

private slots:
    void init()
    {
        server->reset();
        connectBackend();
        server->addDir(QStringLiteral("dir"));
    }

    void partName() { QCOMPARE(Transfer::partName(QStringLiteral("a/b.tar")), QStringLiteral("a/b.tar.part")); }

    // C-12: data goes to .part, then rename; final file appears only at the end.
    void uploadViaPartAndRename()
    {
        QByteArray data = pattern(300 * 1024);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        RecordingProgress progress;
        QVERIFY(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b.tar"), &progress).ok());
        QCOMPARE(server->fileData(QStringLiteral("dir/b.tar")), data);
        QVERIFY(!server->exists(QStringLiteral("dir/b.tar.part")));
        QCOMPARE(progress.last, qint64(data.size()));
        QVERIFY(progress.calls > 1);
        const QStringList expected = {
            QStringLiteral("spaceInfo:dir"), QStringLiteral("upload:dir/b.tar.part"),
            QStringLiteral("stat:dir/b.tar.part"), QStringLiteral("rename:dir/b.tar.part->dir/b.tar:replace"),
        };
        QCOMPARE(server->log, expected);
    }

    // C-13: no transfer when the server reports too little space.
    void noSpaceBeforeTransfer()
    {
        server->freeBytes = 10;
        QByteArray data = pattern(11);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        const Result r = Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"));
        QCOMPARE(r.error(), Error::NoSpace);
        QCOMPARE(server->log, QStringList({ QStringLiteral("spaceInfo:dir") }));
    }

    void freeSpaceUnsupportedOrFailingIsNotFatal_data()
    {
        QTest::addColumn<int>("error");
        QTest::newRow("unsupported") << static_cast<int>(Error::Unsupported);
        QTest::newRow("protocol") << static_cast<int>(Error::ProtocolError);
    }

    void freeSpaceUnsupportedOrFailingIsNotFatal()
    {
        QFETCH(int, error);
        server->failOps.insert(QStringLiteral("spaceInfo"), Result(static_cast<Error>(error)));
        QByteArray data = pattern(10);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QVERIFY(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b")).ok());
        QCOMPARE(server->fileData(QStringLiteral("dir/b")), data);
    }

    void unknownSizeSkipsFreeSpace()
    {
        QByteArray data = pattern(10);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QVERIFY(Transfer::upload(backend.data(), &buffer, -1, QStringLiteral("dir/b")).ok());
        QVERIFY(!server->log.contains(QStringLiteral("spaceInfo:dir")));
    }

    void canceledFreeSpaceStops()
    {
        server->failOps.insert(QStringLiteral("spaceInfo"), Result(Error::Canceled));
        QByteArray data = pattern(10);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QCOMPARE(Transfer::upload(backend.data(), &buffer, 10, QStringLiteral("dir/b")).error(), Error::Canceled);
        QCOMPARE(server->log.size(), 1);
    }

    // Connection dropped mid-upload: .part removed (best effort), no final file.
    void failedUploadRemovesPart()
    {
        server->failUploadAfterBytes = 64 * 1024;
        QByteArray data = pattern(200 * 1024);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b")).error(),
                 Error::ConnectionLost);
        QVERIFY(!server->exists(QStringLiteral("dir/b")));
        QVERIFY(!server->exists(QStringLiteral("dir/b.part")));
        QVERIFY(server->log.contains(QStringLiteral("removeFile:dir/b.part")));
    }

    void sizeMismatchFails()
    {
        server->reportSizeMismatch = true;
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b")).error(),
                 Error::ProtocolError);
        QVERIFY(!server->exists(QStringLiteral("dir/b")));
        QVERIFY(!server->exists(QStringLiteral("dir/b.part")));
    }

    void shortSourceFails()
    {
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QCOMPARE(Transfer::upload(backend.data(), &buffer, 200, QStringLiteral("dir/b")).error(), Error::Internal);
        QVERIFY(!server->exists(QStringLiteral("dir/b.part")));
    }

    void renameFailureRemovesPart()
    {
        server->failOps.insert(QStringLiteral("rename"), Result(Error::PermissionDenied));
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b")).error(),
                 Error::PermissionDenied);
        QVERIFY(!server->exists(QStringLiteral("dir/b.part")));
    }

    void cleanupFailureIsTolerated()
    {
        server->failOps.insert(QStringLiteral("rename"), Result(Error::PermissionDenied));
        server->failOps.insert(QStringLiteral("removeFile"), Result(Error::PermissionDenied, QStringLiteral("dir/b.part")));
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        // C-17: no remote path in a warning.
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("^Could not remove partial file \"PermissionDenied\"$")));
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b")).error(),
                 Error::PermissionDenied);
    }

    void rejectsBadTargets()
    {
        QBuffer buffer;
        buffer.open(QIODevice::ReadOnly);
        QVERIFY(!Transfer::upload(backend.data(), &buffer, 0, QStringLiteral("../b")).ok());
        QCOMPARE(Transfer::upload(backend.data(), &buffer, 0, QString()).error(), Error::Internal);
        QVERIFY(server->log.isEmpty());
    }

    // C-9: cancel() from another thread ends the transfer with Canceled.
    void cancelFromOtherThread()
    {
        server->chunkDelayMs = 20;
        QByteArray data = pattern(4 * 1024 * 1024);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QElapsedTimer timer;
        timer.start();
        QFuture<Result> future = QtConcurrent::run([&]() {
            return Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"));
        });
        QTest::qWait(100);
        backend->cancel();
        future.waitForFinished();
        QCOMPARE(future.result().error(), Error::Canceled);
        QVERIFY(timer.elapsed() < 2000);
        QVERIFY(!server->exists(QStringLiteral("dir/b")));
        QVERIFY(!server->exists(QStringLiteral("dir/b.part")));   // S-T16
    }

    void uploadFile()
    {
        QTemporaryDir dir;
        const QString local = dir.filePath(QStringLiteral("x.tar"));
        QFile file(local);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write(pattern(1000));
        file.close();
        QVERIFY(Transfer::uploadFile(backend.data(), local, QStringLiteral("dir/x.tar")).ok());
        QCOMPARE(server->fileData(QStringLiteral("dir/x.tar")), pattern(1000));
        QCOMPARE(Transfer::uploadFile(backend.data(), dir.filePath(QStringLiteral("missing")), QStringLiteral("dir/y")).error(),
                 Error::NotFound);
    }

    void downloadFile()
    {
        QTemporaryDir dir;
        const QString local = dir.filePath(QStringLiteral("restore.tar"));
        QFile old(local);
        QVERIFY(old.open(QIODevice::WriteOnly));
        old.write("old content");
        old.close();
        server->addFile(QStringLiteral("dir/b.tar"), pattern(500 * 1024));
        RecordingProgress progress;
        QVERIFY(Transfer::downloadFile(backend.data(), QStringLiteral("dir/b.tar"), local, &progress).ok());
        QFile file(local);
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(file.readAll(), pattern(500 * 1024));
        QVERIFY(!QFile::exists(local + QStringLiteral(".part")));
        QCOMPARE(progress.last, qint64(500 * 1024));
    }

    void downloadFailures()
    {
        QTemporaryDir dir;
        const QString local = dir.filePath(QStringLiteral("r.tar"));
        QCOMPARE(Transfer::downloadFile(backend.data(), QStringLiteral("dir/missing"), local).error(), Error::NotFound);
        QCOMPARE(Transfer::downloadFile(backend.data(), QStringLiteral("dir"), local).error(), Error::IsADirectory);
        QVERIFY(!Transfer::downloadFile(backend.data(), QStringLiteral("../x"), local).ok());

        server->addFile(QStringLiteral("dir/b.tar"), pattern(10));
        QCOMPARE(Transfer::downloadFile(backend.data(), QStringLiteral("dir/b.tar"),
                                        dir.filePath(QStringLiteral("no/such/dir/r.tar"))).error(),
                 Error::PermissionDenied);

        server->failOps.insert(QStringLiteral("download"), Result(Error::Timeout));
        QCOMPARE(Transfer::downloadFile(backend.data(), QStringLiteral("dir/b.tar"), local).error(), Error::Timeout);
        QVERIFY(!QFile::exists(local));
        QVERIFY(!QFile::exists(local + QStringLiteral(".part")));
    }

    // SPEC 8.4 step 2.
    void removeStaleParts()
    {
        const QDateTime now = QDateTime::currentDateTimeUtc();
        server->addFile(QStringLiteral("dir/old.tar.part"), "x", now.addSecs(-25 * 3600));
        server->addFile(QStringLiteral("dir/new.tar.part"), "x", now.addSecs(-3600));
        server->addFile(QStringLiteral("dir/old.tar"), "x", now.addSecs(-48 * 3600));
        server->addFile(QStringLiteral("dir/undated.part"), "x", QDateTime());
        server->addDir(QStringLiteral("dir/sub.part"));
        QVERIFY(Transfer::removeStaleParts(backend.data(), QStringLiteral("dir"), now).ok());
        QVERIFY(!server->exists(QStringLiteral("dir/old.tar.part")));
        QVERIFY(server->exists(QStringLiteral("dir/new.tar.part")));
        QVERIFY(server->exists(QStringLiteral("dir/old.tar")));
        QVERIFY(server->exists(QStringLiteral("dir/undated.part")));
        QVERIFY(server->exists(QStringLiteral("dir/sub.part")));

        QVERIFY(Transfer::removeStaleParts(backend.data(), QStringLiteral("missing"), now).ok());
        server->failOps.insert(QStringLiteral("list"), Result(Error::PermissionDenied));
        QCOMPARE(Transfer::removeStaleParts(backend.data(), QStringLiteral("dir"), now).error(), Error::PermissionDenied);

        server->addFile(QStringLiteral("dir/a.part"), "x", now.addSecs(-30 * 3600));
        server->failOps.insert(QStringLiteral("removeFile"), Result(Error::PermissionDenied, QStringLiteral("dir/a.part")));
        QTest::ignoreMessage(QtWarningMsg,
                             QRegularExpression(QStringLiteral("^Could not remove stale partial file \"PermissionDenied\"$")));
        QVERIFY(Transfer::removeStaleParts(backend.data(), QStringLiteral("dir"), now).ok());
        server->failOps.insert(QStringLiteral("removeFile"), Result(Error::Canceled));
        QCOMPARE(Transfer::removeStaleParts(backend.data(), QStringLiteral("dir"), now).error(), Error::Canceled);
    }

    // ---- XH-1 policies --------------------------------------------------

    // Backups (the default policy) create files 0600 (S-20 through XC-23).
    void defaultPolicyCreatesPrivateFiles()
    {
        QCOMPARE(Transfer::TransferPolicy().createMode, 0600);
        QCOMPARE(Transfer::TransferPolicy().commitMode, RenameMode::Replace);
        QVERIFY(Transfer::TransferPolicy().useTempName);
        QVERIFY(Transfer::TransferPolicy().verifySize);
        QVERIFY(!Transfer::TransferPolicy().resume);
        QByteArray data = pattern(10);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QVERIFY(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b")).ok());
        QCOMPARE(server->node(QStringLiteral("dir/b")).mode, 0600);
    }

    void createModes_data()
    {
        QTest::addColumn<int>("createMode");
        QTest::addColumn<int>("expected");
        QTest::newRow("backend default") << -1 << static_cast<int>(FakeServer::DefaultFileMode);
        QTest::newRow("explicit") << 0640 << 0640;
    }

    void createModes()
    {
        QFETCH(int, createMode);
        QFETCH(int, expected);
        Transfer::TransferPolicy policy;
        policy.createMode = createMode;
        QByteArray data = pattern(10);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QVERIFY(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).ok());
        QCOMPARE(server->node(QStringLiteral("dir/b")).mode, expected);
    }

    // AtomicPut consumers write the final name directly.
    void noTempName()
    {
        server->addFile(QStringLiteral("dir/b"), "old");
        Transfer::TransferPolicy policy;
        policy.useTempName = false;
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QVERIFY(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).ok());
        QCOMPARE(server->fileData(QStringLiteral("dir/b")), data);
        QCOMPARE(server->log, QStringList({ QStringLiteral("spaceInfo:dir"), QStringLiteral("upload:dir/b"),
                                            QStringLiteral("stat:dir/b") }));
    }

    void noTempNameNoReplaceCreatesNew()
    {
        server->addFile(QStringLiteral("dir/b"), "old");
        Transfer::TransferPolicy policy;
        policy.useTempName = false;
        policy.commitMode = RenameMode::NoReplace;
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).error(),
                 Error::AlreadyExists);
        QCOMPARE(server->fileData(QStringLiteral("dir/b")), QByteArray("old"));
        buffer.seek(0);
        QVERIFY(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/c"), nullptr, policy).ok());
        QCOMPARE(server->fileData(QStringLiteral("dir/c")), data);
    }

    // XC-10: the commit mode reaches rename(); NoReplace keeps an existing file.
    void noReplaceCommit()
    {
        server->addFile(QStringLiteral("dir/b"), "old");
        Transfer::TransferPolicy policy;
        policy.commitMode = RenameMode::NoReplace;
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).error(),
                 Error::AlreadyExists);
        QCOMPARE(server->fileData(QStringLiteral("dir/b")), QByteArray("old"));
        QVERIFY(!server->exists(QStringLiteral("dir/b.part")));
        QVERIFY(server->log.contains(QStringLiteral("rename:dir/b.part->dir/b")));

        buffer.seek(0);
        server->log.clear();
        QVERIFY(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/new"), nullptr, policy).ok());
        QCOMPARE(server->fileData(QStringLiteral("dir/new")), data);
        QVERIFY(server->log.contains(QStringLiteral("rename:dir/new.part->dir/new")));
    }

    void replaceCommitReplaces()
    {
        server->addFile(QStringLiteral("dir/b"), "old");
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QVERIFY(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b")).ok());
        QCOMPARE(server->fileData(QStringLiteral("dir/b")), data);
    }

    void customTempNameAndOptions()
    {
        Transfer::TransferPolicy policy;
        policy.tempName = QStringLiteral(".b.uploading");
        policy.verifySize = false;
        policy.modified = QDateTime(QDate(2020, 5, 6), QTime(7, 8, 9), Qt::UTC);
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QVERIFY(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).ok());
        QCOMPARE(server->log, QStringList({ QStringLiteral("spaceInfo:dir"), QStringLiteral("upload:dir/.b.uploading"),
                                            QStringLiteral("rename:dir/.b.uploading->dir/b:replace") }));
        QCOMPARE(server->node(QStringLiteral("dir/b")).modified, policy.modified);
    }

    void progressCancelStopsUpload()
    {
        QByteArray data = pattern(300 * 1024);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        CancelingProgress progress;
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), &progress).error(),
                 Error::Canceled);
        QVERIFY(!server->exists(QStringLiteral("dir/b")));
        QVERIFY(!server->exists(QStringLiteral("dir/b.part")));
    }

    // XH-1 resume: the offset must match the temporary file's size.
    void resumeAtCorrectOffset_data()
    {
        QTest::addColumn<bool>("sequential");
        QTest::newRow("seekable") << false;
        QTest::newRow("sequential") << true;
    }

    void resumeAtCorrectOffset()
    {
        QFETCH(bool, sequential);
        const QByteArray data = pattern(300 * 1024);
        const int done = 100 * 1024 + 17;
        server->addFile(QStringLiteral("dir/b.part"), data.left(done));
        Transfer::TransferPolicy policy;
        policy.resume = true;
        policy.resumeOffset = done;
        QByteArray copy = data;
        QBuffer buffer(&copy);
        buffer.open(QIODevice::ReadOnly);
        SequentialSource stream(data);
        QIODevice *source = sequential ? static_cast<QIODevice *>(&stream) : &buffer;
        RecordingProgress progress;
        const Result r = Transfer::upload(backend.data(), source, data.size(), QStringLiteral("dir/b"), &progress, policy);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(server->fileData(QStringLiteral("dir/b")), data);
        QVERIFY(!server->exists(QStringLiteral("dir/b.part")));
        QCOMPARE(progress.last, qint64(data.size()));
        QVERIFY(server->log.contains(QStringLiteral("openWrite:dir/b.part")));
        QVERIFY(!server->log.contains(QStringLiteral("upload:dir/b.part")));
        QVERIFY(server->log.contains(QStringLiteral("rename:dir/b.part->dir/b:replace")));
    }

    void resumeAtWrongOffset()
    {
        const QByteArray data = pattern(1000);
        server->addFile(QStringLiteral("dir/b.part"), data.left(400));
        Transfer::TransferPolicy policy;
        policy.resume = true;
        policy.resumeOffset = 500;
        QByteArray copy = data;
        QBuffer buffer(&copy);
        buffer.open(QIODevice::ReadOnly);
        const Result r = Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy);
        QCOMPARE(r.error(), Error::ProtocolError);
        QVERIFY(r.message().contains(QStringLiteral("400")));
        QCOMPARE(server->fileData(QStringLiteral("dir/b.part")), data.left(400));   // kept, untouched
        QVERIFY(!server->exists(QStringLiteral("dir/b")));
        QVERIFY(!server->log.contains(QStringLiteral("openWrite:dir/b.part")));

        policy.resumeOffset = 300;
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).error(),
                 Error::ProtocolError);
        QCOMPARE(server->fileData(QStringLiteral("dir/b.part")), data.left(400));
    }

    void resumeKeepsTempOnFailure()
    {
        const QByteArray data = pattern(300 * 1024);
        server->addFile(QStringLiteral("dir/b.part"), data.left(1000));
        server->failOps.insert(QStringLiteral("write"), Result(Error::ConnectionLost));
        Transfer::TransferPolicy policy;
        policy.resume = true;
        policy.resumeOffset = 1000;
        QByteArray copy = data;
        QBuffer buffer(&copy);
        buffer.open(QIODevice::ReadOnly);
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).error(),
                 Error::ConnectionLost);
        QVERIFY(server->exists(QStringLiteral("dir/b.part")));
        QVERIFY(!server->exists(QStringLiteral("dir/b")));
        QVERIFY(server->log.contains(QStringLiteral("abort:dir/b.part")));
        QVERIFY(!server->log.contains(QStringLiteral("removeFile:dir/b.part")));

        // A canceled resume keeps the temporary file as well.
        buffer.seek(0);
        CancelingProgress progress;
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), &progress, policy).error(),
                 Error::Canceled);
        QVERIFY(server->exists(QStringLiteral("dir/b.part")));
        QVERIFY(server->fileData(QStringLiteral("dir/b.part")).startsWith(data.left(1000)));
    }

    void resumePreconditions()
    {
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        Transfer::TransferPolicy policy;
        policy.resume = true;
        policy.useTempName = false;
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).error(),
                 Error::Internal);
        policy.useTempName = true;
        policy.resumeOffset = -1;
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).error(),
                 Error::Internal);
        QVERIFY(server->log.isEmpty());

        policy.resumeOffset = 10;
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).error(),
                 Error::NotFound);

        server->addFile(QStringLiteral("dir/b.part"), data.left(10));
        server->capabilities.flags.remove(Capability::WriteResume);
        QCOMPARE(Transfer::upload(backend.data(), &buffer, data.size(), QStringLiteral("dir/b"), nullptr, policy).error(),
                 Error::Unsupported);
        QCOMPARE(server->fileData(QStringLiteral("dir/b.part")), data.left(10));

        // A local file shorter than the offset cannot be resumed.
        server->capabilities = FakeServer::fullCapabilities();
        policy.resumeOffset = 10;
        SequentialSource shortSource(data.left(5));
        QCOMPARE(Transfer::upload(backend.data(), &shortSource, data.size(), QStringLiteral("dir/b"), nullptr, policy).error(),
                 Error::Internal);
    }

    void removeStalePartsCustomPattern()
    {
        const QDateTime now = QDateTime::currentDateTimeUtc();
        const QDateTime old = now.addSecs(-25 * 3600);
        server->addFile(QStringLiteral("dir/.a.uploading"), "x", old);
        server->addFile(QStringLiteral("dir/b.part"), "x", old);
        server->addFile(QStringLiteral("dir/c.uploading.keep"), "x", old);
        server->addSymlink(QStringLiteral("dir/.d.uploading"), QStringLiteral("b.part"));
        QVERIFY(Transfer::removeStaleParts(backend.data(), QStringLiteral("dir"), now, 24 * 3600,
                                           QStringLiteral(".*.uploading")).ok());
        QVERIFY(!server->exists(QStringLiteral("dir/.a.uploading")));
        QVERIFY(server->exists(QStringLiteral("dir/b.part")));
        QVERIFY(server->exists(QStringLiteral("dir/c.uploading.keep")));
        QVERIFY(server->exists(QStringLiteral("dir/.d.uploading")));   // only regular files

        QVERIFY(Transfer::removeStaleParts(backend.data(), QStringLiteral("dir"), now, 10 * 24 * 3600).ok());
        QVERIFY(server->exists(QStringLiteral("dir/b.part")));        // younger than the limit
    }
};

QTEST_GUILESS_MAIN(TestTransfer)
#include "tst_transfer.moc"
