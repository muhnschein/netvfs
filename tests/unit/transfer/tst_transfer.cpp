// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakebackend.h"
#include "identity.h"
#include "transfer.h"

#include <QtCore/QBuffer>
#include <QtCore/QTemporaryDir>
#include <QtConcurrent/QtConcurrentRun>
#include <QtTest/QtTest>

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
            QStringLiteral("freeSpace:dir"), QStringLiteral("upload:dir/b.tar.part"),
            QStringLiteral("stat:dir/b.tar.part"), QStringLiteral("rename:dir/b.tar.part->dir/b.tar"),
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
        QCOMPARE(server->log, QStringList({ QStringLiteral("freeSpace:dir") }));
    }

    void freeSpaceUnsupportedOrFailingIsNotFatal_data()
    {
        QTest::addColumn<int>("error");
        QTest::newRow("unsupported") << int(Error::Unsupported);
        QTest::newRow("protocol") << int(Error::ProtocolError);
    }

    void freeSpaceUnsupportedOrFailingIsNotFatal()
    {
        QFETCH(int, error);
        server->failOps.insert(QStringLiteral("freeSpace"), Result(static_cast<Error>(error)));
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
        QVERIFY(!server->log.contains(QStringLiteral("freeSpace:dir")));
    }

    void canceledFreeSpaceStops()
    {
        server->failOps.insert(QStringLiteral("freeSpace"), Result(Error::Canceled));
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
                 Error::NetworkUnreachable);
        QVERIFY(!server->exists(QStringLiteral("dir/b")));
        QVERIFY(!server->exists(QStringLiteral("dir/b.part")));
        QVERIFY(server->log.contains(QStringLiteral("remove:dir/b.part")));
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
        server->failOps.insert(QStringLiteral("remove"), Result(Error::PermissionDenied));
        QByteArray data = pattern(100);
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("Could not remove partial file")));
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
        QCOMPARE(Transfer::downloadFile(backend.data(), QStringLiteral("dir"), local).error(), Error::NotFound);
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
        server->failOps.insert(QStringLiteral("remove"), Result(Error::PermissionDenied));
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("stale partial file")));
        QVERIFY(Transfer::removeStaleParts(backend.data(), QStringLiteral("dir"), now).ok());
        server->failOps.insert(QStringLiteral("remove"), Result(Error::Canceled));
        QCOMPARE(Transfer::removeStaleParts(backend.data(), QStringLiteral("dir"), now).error(), Error::Canceled);
    }
};

QTEST_GUILESS_MAIN(TestTransfer)
#include "tst_transfer.moc"
