// SPDX-License-Identifier: LGPL-2.1-or-later
// SPEC-v2 XH-4: BoundedPipe.
#include "boundedpipe.h"

#include <QtCore/QThread>
#include <QtTest/QtTest>

#include <atomic>
#include <random>
#include <thread>

using namespace NetVfs;

namespace {

QByteArray patternBytes(qint64 size, quint32 seed)
{
    std::mt19937 generator(seed);
    QByteArray data(int(size), Qt::Uninitialized);
    for (char &c : data)
        c = char(generator() & 0xFF);
    return data;
}

// Waits up to `ms` for a flag set by a worker thread.
bool waitFor(const std::atomic<bool> &flag, int ms)
{
    for (int waited = 0; waited < ms && !flag; waited += 2)
        QThread::msleep(2);
    return flag;
}

struct Writer {
    std::atomic<bool> done { false };
    qint64 result = 0;               // last write() result
    std::thread thread;
    ~Writer()
    {
        if (thread.joinable())
            thread.join();
    }
};

// Writes `data` in pieces of random size, closes the pipe at the end and
// stores the last write() result.
void startWriter(Writer *writer, BoundedPipe *pipe, const QByteArray &data, quint32 seed, int maxPiece)
{
    writer->thread = std::thread([writer, pipe, data, seed, maxPiece] {
        std::mt19937 generator(seed);
        qint64 offset = 0;
        writer->result = 0;
        while (offset < data.size() && writer->result >= 0) {
            const qint64 piece = qMin<qint64>(1 + generator() % maxPiece, data.size() - offset);
            writer->result = pipe->writer()->write(data.constData() + offset, piece);
            offset += piece;
        }
        pipe->writer()->close();
        writer->done = true;
    });
}

} // namespace

class TstBoundedPipe : public QObject
{
    Q_OBJECT

private slots:
    void roundTrip_data()
    {
        QTest::addColumn<int>("capacity");
        QTest::addColumn<int>("maxPiece");
        QTest::addColumn<int>("size");
        QTest::newRow("one byte ring") << 1 << 50 << 20000;
        QTest::newRow("tiny odd ring") << 7 << 100 << 100000;
        QTest::newRow("small ring") << 4096 << 10000 << 1500000;
        QTest::newRow("big pieces") << 1000 << 100000 << 1500000;
        QTest::newRow("large ring") << 65536 << 3000 << 1500000;
    }

    // Data passes unchanged through a ring much smaller than the data; the
    // ring never holds more than its capacity.
    void roundTrip()
    {
        QFETCH(int, capacity);
        QFETCH(int, maxPiece);
        QFETCH(int, size);
        const QByteArray data = patternBytes(size, 42);
        BoundedPipe pipe(capacity);
        QCOMPARE(pipe.capacity(), qint64(capacity));
        Writer writer;
        startWriter(&writer, &pipe, data, 7, maxPiece);

        QByteArray received;
        std::mt19937 generator(99);
        QByteArray buffer(maxPiece, Qt::Uninitialized);
        for (;;) {
            const qint64 want = 1 + generator() % buffer.size();
            const qint64 n = pipe.reader()->read(buffer.data(), want);
            QVERIFY(n >= 0);
            if (n == 0)
                break;
            QVERIFY(n <= want);
            received.append(buffer.constData(), int(n));
        }
        QVERIFY(waitFor(writer.done, 5000));
        QCOMPARE(received.size(), data.size());
        QVERIFY(received == data);
        QVERIFY(writer.result > 0);
        QVERIFY(pipe.result().ok());
        QVERIFY(pipe.peakBuffered() <= capacity);
        QCOMPARE(pipe.peakBuffered(), qint64(capacity));    // the ring did fill: writes blocked
        QCOMPARE(pipe.buffered(), qint64(0));
    }

    void eofAfterWriterClose()
    {
        BoundedPipe pipe(64);
        QCOMPARE(pipe.writer()->write("0123456789", 10), qint64(10));
        pipe.writer()->close();
        QVERIFY(!pipe.writer()->isOpen());
        QTest::ignoreMessage(QtWarningMsg, "QIODevice::write (QIODevice): device not open");
        QCOMPARE(pipe.writer()->write("x", 1), qint64(-1));     // closed
        QCOMPARE(pipe.reader()->bytesAvailable(), qint64(10));
        QVERIFY(!pipe.reader()->atEnd());
        QCOMPARE(pipe.reader()->readAll(), QByteArray("0123456789"));
        QVERIFY(pipe.reader()->atEnd());
        char c = 0;
        QCOMPARE(pipe.reader()->read(&c, 1), qint64(0));
        QCOMPARE(pipe.reader()->read(&c, 1), qint64(0));        // EOF is sticky
        QVERIFY(pipe.result().ok());
    }

    void wrapAroundKeepsOrder()
    {
        BoundedPipe pipe(10);
        char buffer[16];
        for (int round = 0; round < 40; ++round) {
            const QByteArray piece = QByteArray::number(round * 7919 + 1000000).left(7);
            QCOMPARE(pipe.writer()->write(piece), qint64(piece.size()));
            const qint64 n = pipe.reader()->read(buffer, sizeof buffer);
            QCOMPARE(n, qint64(piece.size()));
            QCOMPARE(QByteArray(buffer, int(n)), piece);
        }
    }

    void writeBlocksUntilRead()
    {
        BoundedPipe pipe(8);
        const QByteArray data = patternBytes(64, 1);
        Writer writer;
        startWriter(&writer, &pipe, data, 3, 64);
        QThread::msleep(150);
        QVERIFY(!writer.done);                       // blocked on the full ring
        QCOMPARE(pipe.buffered(), qint64(8));

        QByteArray received;
        while (true) {
            char buffer[5];
            const qint64 n = pipe.reader()->read(buffer, sizeof buffer);
            QVERIFY(n >= 0);
            if (n == 0)
                break;
            received.append(buffer, int(n));
        }
        QVERIFY(received == data);
        QVERIFY(pipe.peakBuffered() <= 8);
    }

    void readBlocksUntilWrite()
    {
        BoundedPipe pipe(32);
        std::atomic<bool> done { false };
        QByteArray got;
        std::thread reader([&] {
            got = pipe.reader()->read(100);      // blocks until data arrives
            done = true;
        });
        QThread::msleep(100);
        QVERIFY(!done);
        pipe.writer()->write("hello", 5);
        QVERIFY(waitFor(done, 5000));            // returns what is there, not 100 bytes
        reader.join();
        QCOMPARE(got, QByteArray("hello"));
        pipe.writer()->close();
        QVERIFY(pipe.reader()->read(100).isEmpty());
    }

    // fail() wakes a writer blocked on a full ring; both sides then return -1
    // and result() carries the failure, even for data still buffered.
    void failWakesBlockedWriter()
    {
        BoundedPipe pipe(4);
        const QByteArray data = patternBytes(100, 5);
        Writer writer;
        startWriter(&writer, &pipe, data, 1, 100);
        QThread::msleep(100);
        QVERIFY(!writer.done);
        QCOMPARE(pipe.buffered(), qint64(4));

        pipe.fail(Result(Error::Timeout, QStringLiteral("stalled")));
        QVERIFY(waitFor(writer.done, 2000));
        QCOMPARE(writer.result, qint64(-1));
        QCOMPARE(pipe.result().error(), Error::Timeout);
        QCOMPARE(pipe.result().message(), QStringLiteral("stalled"));
        char buffer[8];
        QCOMPARE(pipe.reader()->read(buffer, sizeof buffer), qint64(-1));
        QCOMPARE(pipe.reader()->bytesAvailable(), qint64(0));
        QVERIFY(pipe.reader()->atEnd());
        QVERIFY(pipe.reader()->errorString().contains(QLatin1String("stalled")));
        QTest::ignoreMessage(QtWarningMsg, "QIODevice::write (QIODevice): device not open");   // the writer thread closed it
        QCOMPARE(pipe.writer()->write("x", 1), qint64(-1));
    }

    void failWakesBlockedReader()
    {
        BoundedPipe pipe(16);
        std::atomic<bool> done { false };
        qint64 result = 0;
        std::thread reader([&] {
            char buffer[8];
            result = pipe.reader()->read(buffer, sizeof buffer);
            done = true;
        });
        QThread::msleep(100);
        QVERIFY(!done);
        pipe.fail(Result(Error::ConnectionLost, QStringLiteral("gone")));
        QVERIFY(waitFor(done, 2000));
        reader.join();
        QCOMPARE(result, qint64(-1));
        QCOMPARE(pipe.result().error(), Error::ConnectionLost);
    }

    void cancelIsFailCanceled()
    {
        BoundedPipe pipe(16);
        QVERIFY(pipe.result().ok());
        pipe.writer()->write("abc", 3);
        pipe.cancel();
        QCOMPARE(pipe.result().error(), Error::Canceled);
        char c = 0;
        QCOMPARE(pipe.reader()->read(&c, 1), qint64(-1));
        QCOMPARE(pipe.writer()->write("d", 1), qint64(-1));
    }

    void firstFailureWins()
    {
        BoundedPipe pipe(16);
        pipe.fail(Result(Error::NoSpace, QStringLiteral("first")));
        pipe.fail(Result(Error::Timeout, QStringLiteral("second")));
        pipe.cancel();
        QCOMPARE(pipe.result().error(), Error::NoSpace);
        QCOMPARE(pipe.result().message(), QStringLiteral("first"));
    }

    void failAfterEofKeepsFailure()
    {
        BoundedPipe pipe(16);
        pipe.writer()->write("abc", 3);
        pipe.writer()->close();
        pipe.fail(Result(Error::ProtocolError, QStringLiteral("late")));
        char c = 0;
        QCOMPARE(pipe.reader()->read(&c, 1), qint64(-1));
    }

    // A reader that goes away before EOF fails the next (or a blocked) write.
    void earlyReaderCloseFailsWriter()
    {
        BoundedPipe pipe(4);
        Writer writer;
        startWriter(&writer, &pipe, patternBytes(100, 9), 2, 100);
        QThread::msleep(100);
        QVERIFY(!writer.done);
        pipe.reader()->close();
        QVERIFY(waitFor(writer.done, 2000));
        QCOMPARE(writer.result, qint64(-1));
        QCOMPARE(pipe.result().error(), Error::Canceled);
    }

    void readerCloseAfterEofIsHarmless()
    {
        BoundedPipe pipe(16);
        pipe.writer()->write("abc", 3);
        pipe.writer()->close();
        QCOMPARE(pipe.reader()->readAll(), QByteArray("abc"));
        pipe.reader()->close();
        QVERIFY(pipe.result().ok());
    }

    void devicesOutliveThePipe()
    {
        QIODevice *writer = nullptr;
        {
            BoundedPipe pipe(16);
            writer = pipe.writer();
            QVERIFY(writer->isOpen());
        }
        // The pipe is gone together with its devices; nothing left to touch.
        QVERIFY(writer != nullptr);
    }

    void capacityIsClamped()
    {
        BoundedPipe pipe(0);
        QCOMPARE(pipe.capacity(), qint64(1));
        QCOMPARE(pipe.writer()->write("a", 1), qint64(1));
        QCOMPARE(pipe.buffered(), qint64(1));
    }

    // Many producer/consumer pairs with random sizes and a random failure
    // while a monitor thread watches the fill level: every thread ends, the
    // ring never exceeds its capacity, and without failure all data arrives.
    void stress()
    {
        for (int round = 0; round < 40; ++round) {
            const int capacity = 1 + round % 13 * 37;
            const bool inject = round % 3 == 0;
            const QByteArray data = patternBytes(20000 + round * 97, quint32(round));
            BoundedPipe pipe(capacity);
            std::atomic<bool> stop { false };
            std::atomic<qint64> highest { 0 };
            std::thread monitor([&] {
                while (!stop) {
                    highest = qMax(highest.load(), pipe.buffered());
                    std::this_thread::yield();
                }
            });

            Writer writer;
            startWriter(&writer, &pipe, data, quint32(round) * 3, 1 + round * 31);
            std::atomic<bool> readerDone { false };
            QByteArray received;
            std::thread reader([&] {
                QByteArray buffer(1 + round * 17, Qt::Uninitialized);
                for (;;) {
                    const qint64 n = pipe.reader()->read(buffer.data(), buffer.size());
                    if (n <= 0)
                        break;
                    received.append(buffer.constData(), int(n));
                }
                readerDone = true;
            });
            if (inject) {
                QThread::usleep(500 + (round * 131) % 3000);
                pipe.fail(Result(Error::ConnectionLost, QStringLiteral("injected")));
            }
            QVERIFY2(waitFor(writer.done, 20000), "writer stuck");
            QVERIFY2(waitFor(readerDone, 20000), "reader stuck");
            reader.join();
            stop = true;
            monitor.join();
            QVERIFY(highest <= capacity);
            QVERIFY(pipe.peakBuffered() <= capacity);
            if (!inject || pipe.result().ok()) {
                QVERIFY(pipe.result().ok());
                QVERIFY(received == data);
            } else {
                QCOMPARE(pipe.result().error(), Error::ConnectionLost);
                QVERIFY(received.size() <= data.size());
                QVERIFY(data.startsWith(received));
            }
        }
    }
};

QTEST_GUILESS_MAIN(TstBoundedPipe)
#include "tst_boundedpipe.moc"
