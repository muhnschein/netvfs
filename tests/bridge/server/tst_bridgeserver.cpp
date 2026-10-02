// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs-bridge end to end in one process (SPEC-v2 XT-7): a libdbus client
// talks to a BridgeServer over a unix socket; locations are served by the
// FakeBackend through the fake plugin (provider "fake").
#include "bridgetest.h"

#include "backendloader.h"
#include "discovery.h"
#include "fakebackend.h"
#include "names.h"
#include "protocol.h"
#include "session.h"

#include <QtCore/QElapsedTimer>
#include <QtCore/QFile>
#include <QtTest/QtTest>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace NetVfs;
using namespace NetVfs::BridgeTest;
using NetVfs::Bridge::WireWriter;
using NetVfs::Test::FakeServer;

namespace {

const QString Loc = QStringLiteral("account:1");
const char NotFound[] = "org.netvfs.Error.NotFound";
const char PermissionDenied[] = "org.netvfs.Error.PermissionDenied";
const char TooMany[] = "org.netvfs.Error.TooManyConnections";
const char InvalidArgs[] = "org.freedesktop.DBus.Error.InvalidArgs";

FakeServer *fake()
{
    return FakeServer::instance();
}

TestClient::Args locPath(const QString &loc, const QByteArray &path)
{
    return [loc, path](WireWriter &w) { w.string(loc).bytes(path); };
}

bool waitFor(const std::function<bool()> &done, int timeoutMs = 5000)
{
    QElapsedTimer timer;
    timer.start();
    while (!done()) {
        if (timer.elapsed() > timeoutMs)
            return false;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        QThread::msleep(2);
    }
    return true;
}

QString tempFile(const QTemporaryDir &dir, const char *name, const QByteArray &content)
{
    const QString path = dir.path() + QLatin1Char('/') + QLatin1String(name);
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(content);
    return path;
}

// Accounts whose secret never arrives: requests stay in flight.
class HangingAccounts : public FakeAccounts
{
public:
    QList<Fetched> pending;
    void fetch(int, const Fetched &done) override { pending << done; }
};

} // namespace

class tst_BridgeServer : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void init();
    void helloFirst();
    void helloAndLocations();
    void consentUnknownThenGranted();
    void consentDenied();
    void revocationMidJob();
    void listStreamsBatches();
    void metadataAndNamespace();
    void pathValidation();
    void handles();
    void handleLimit();
    void requestLimit();
    void jobLimit();
    void uploadAndDownloadRegular();
    void transferThroughPipes();
    void fdValidation();
    void disconnectCancelsJobs();
    void cancelJob();
    void walkRemoveTreeCopyAcross();
    void accountIdentityChangedSetsAttention();
    void adHocIdentityQuestion();
    void keyboardInteractive();
    void connectAdHocRefusals();
    void insecureConsentDeclined();
    void peerCheckRefuses();
    void idleExit();
    void discovery();
    void handoff();
    void locationsChanged();
};

void tst_BridgeServer::init()
{
    fake()->reset();
}

void tst_BridgeServer::helloFirst()
{
    Fixture f;
    auto c = f.client();
    TestClient::Message m = c->call("ListLocations");
    QVERIFY(m.isError);
    QCOMPARE(m.name, QStringLiteral("org.netvfs.Error.ProtocolError"));
    m = c->hello();
    QVERIFY(!m.isError);
    QCOMPARE(m.args.value(0).toUInt(), 1u);
    QCOMPARE(m.args.value(1).toString(), Bridge::Protocol::bridgeVersion());
    QVERIFY(m.args.value(2).toStringList().contains(QStringLiteral("error-details")));
}

void tst_BridgeServer::helloAndLocations()
{
    Fixture f;
    auto c = f.helloClient();
    QCOMPARE(c->call("GetConsent").args.value(0).toString(), QStringLiteral("granted"));
    const QVariantList locations = c->call("ListLocations").args.value(0).toList();
    QCOMPARE(locations.size(), 1);
    const QVariantList first = locations.at(0).toList();
    QCOMPARE(first.at(0).toString(), Loc);
    QCOMPARE(first.at(1).toString(), QStringLiteral("fake"));
    const QVariantMap info = first.at(3).toMap();
    QCOMPARE(info.value("kind").toString(), QStringLiteral("account"));
    QVERIFY(!info.contains("host_key"));   // never pins or secrets (XB-1)
    const TestClient::Message caps = c->call("Capabilities", [](WireWriter &w) { w.string(Loc); });
    QVERIFY2(!caps.isError, qPrintable(caps.name));
    QVERIFY(caps.args.value(0).toList().value(0).toStringList().contains(QStringLiteral("ReadHandles")));
    QCOMPARE(f.prompt->shown, 0);
}

void tst_BridgeServer::consentUnknownThenGranted()
{
    Fixture f(Consent::Unknown);
    auto c = f.helloClient();
    QCOMPARE(f.prompt->shown, 1);   // XB-6: first Hello while unknown
    QCOMPARE(c->call("GetConsent").args.value(0).toString(), QStringLiteral("unknown"));
    QCOMPARE(c->call("ListLocations").args.value(0).toList().size(), 0);
    TestClient::Message m = c->call("Stat", [](WireWriter &w) { w.string(Loc).bytes("x").boolean(true).string(QString()); });
    QCOMPARE(m.name, QLatin1String(PermissionDenied));
    m = c->call("Discover", [](WireWriter &w) { w.boolean(true); });
    QCOMPARE(m.name, QLatin1String(PermissionDenied));
    c->hello();
    QCOMPARE(f.prompt->shown, 1);   // not again while shown
    f.prompt->answer(true);
    QVERIFY(c->waitSignal(QStringLiteral("ConsentChanged")).args.value(0).toString() == QStringLiteral("granted"));
    QCOMPARE(ConsentStore(f.config.consentFile).consent(QStringLiteral("test")), Consent::Granted);
    QCOMPARE(c->call("ListLocations").args.value(0).toList().size(), 1);
}

void tst_BridgeServer::consentDenied()
{
    Fixture f(Consent::Denied);
    auto c = f.helloClient();
    QCOMPARE(f.prompt->shown, 0);
    QCOMPARE(c->call("GetConsent").args.value(0).toString(), QStringLiteral("denied"));
    QCOMPARE(c->call("ListLocations").args.value(0).toList().size(), 0);
    QCOMPARE(c->call("List", [](WireWriter &w) { w.string(Loc).bytes("").string(QString()).uint32(0); }).name,
             QLatin1String(PermissionDenied));
    QVERIFY(!c->call("RequestConsent").isError);
    QCOMPARE(f.prompt->shown, 1);
    f.prompt->answer(false);
    QCOMPARE(ConsentStore(f.config.consentFile).consent(QStringLiteral("test")), Consent::Denied);
}

void tst_BridgeServer::revocationMidJob()
{
    Fixture f;
    fake()->addFile(QStringLiteral("big"), QByteArray(4 << 20, 'x'));
    fake()->chunkDelayMs = 50;
    auto c = f.helloClient();
    int pipeFds[2];
    QCOMPARE(::pipe(pipeFds), 0);
    const TestClient::Message job = c->call("Download", [&pipeFds](WireWriter &w) {
        w.string(Loc).bytes("big").unixFd(pipeFds[1]).variantMap(QVariantMap());
    });
    ::close(pipeFds[1]);
    QVERIFY2(!job.isError, qPrintable(job.name));
    QVERIFY(waitFor([&f]() { return f.server->runningJobs() == 1; }));
    // netvfs-ui revokes: bridge.conf changes on disk.
    QElapsedTimer timer;
    timer.start();
    f.setConsent(Consent::Denied);
    QVERIFY(c->waitDisconnected(3000));
    QVERIFY(waitFor([&f]() { return f.server->runningJobs() == 0; }, 3000));
    QVERIFY2(timer.elapsed() < 3000, qPrintable(QString::number(timer.elapsed())));
    ::close(pipeFds[0]);
    // A new client is still refused location calls.
    auto again = f.helloClient();
    QCOMPARE(again->call("ListLocations").args.value(0).toList().size(), 0);
}

void tst_BridgeServer::listStreamsBatches()
{
    Fixture f;
    for (int i = 0; i < 1000; ++i)
        fake()->addFile(QStringLiteral("many/f%1").arg(i, 4, 10, QLatin1Char('0')), "x");
    auto c = f.helloClient();
    const TestClient::Message m = c->call("List", [](WireWriter &w) {
        w.string(Loc).bytes("many").string(QStringLiteral("bulk")).uint32(100);
    });
    QVERIFY2(!m.isError, qPrintable(m.name));
    const quint32 request = m.args.value(0).toUInt();
    const TestClient::Message done = c->waitSignal(QStringLiteral("ListDone"));
    QCOMPARE(done.args.value(0).toUInt(), request);
    QCOMPARE(done.args.value(1).toString(), QString());
    int total = 0;
    int batches = 0;
    for (;;) {
        const TestClient::Message b = c->waitSignal(QStringLiteral("ListBatch"), nullptr, 100);
        if (!b.valid)
            break;
        QCOMPARE(b.args.value(0).toUInt(), request);
        const int n = b.args.value(1).toList().size();
        QVERIFY(n > 0 && n <= 100);
        total += n;
        ++batches;
    }
    QCOMPARE(total, 1000);
    QVERIFY(batches >= 10);
    // A missing folder: ListDone carries the error name.
    c->call("List", [](WireWriter &w) { w.string(Loc).bytes("nope").string(QString()).uint32(0); });
    QCOMPARE(c->waitSignal(QStringLiteral("ListDone")).args.value(1).toString(), QStringLiteral("NotFound"));
}

void tst_BridgeServer::metadataAndNamespace()
{
    Fixture f;
    fake()->addFile(QStringLiteral("docs/a.txt"), "hello");
    auto c = f.helloClient();
    TestClient::Message m = c->call("Stat", [](WireWriter &w) { w.string(Loc).bytes("docs/a.txt").boolean(true).string(QString()); });
    QVERIFY2(!m.isError, qPrintable(m.name));
    const QVariantList entry = m.args.value(0).toList();
    QCOMPARE(entry.size(), 15);
    QCOMPARE(entry.at(1).toUInt(), uint(EntryType::File));
    QCOMPARE(entry.at(3).toLongLong(), 5);
    QCOMPARE(c->call("Stat", [](WireWriter &w) { w.string(Loc).bytes("docs/zz").boolean(true).string(QString()); }).name,
             QLatin1String(NotFound));
    QVERIFY(!c->call("MakeDir", [](WireWriter &w) { w.string(Loc).bytes("docs/new").boolean(true); }).isError);
    QVERIFY(fake()->exists(QStringLiteral("docs/new")));
    QCOMPARE(c->call("MakeDir", [](WireWriter &w) { w.string(Loc).bytes("docs/new").boolean(true); }).name,
             QStringLiteral("org.netvfs.Error.AlreadyExists"));
    fake()->addFile(QStringLiteral("docs/b.txt"), "b");
    QCOMPARE(c->call("Rename", [](WireWriter &w) { w.string(Loc).bytes("docs/a.txt").bytes("docs/b.txt").boolean(false); }).name,
             QStringLiteral("org.netvfs.Error.AlreadyExists"));
    QVERIFY(!c->call("Rename", [](WireWriter &w) { w.string(Loc).bytes("docs/a.txt").bytes("docs/b.txt").boolean(true); }).isError);
    QCOMPARE(fake()->fileData(QStringLiteral("docs/b.txt")), QByteArray("hello"));
    QVERIFY(!c->call("RemoveFile", locPath(Loc, "docs/b.txt")).isError);
    QVERIFY(!fake()->exists(QStringLiteral("docs/b.txt")));
    QVERIFY(!c->call("RemoveDir", locPath(Loc, "docs/new")).isError);
    QVERIFY(!c->call("SetAttributes", [](WireWriter &w) {
        w.string(Loc).bytes("docs").variantMap(QVariantMap { { "mode", 0700 } });
    }).isError);
    QCOMPARE(fake()->node(QStringLiteral("docs")).mode, 0700);
    QVERIFY(!c->call("MakeSymlink", [](WireWriter &w) { w.string(Loc).bytes("../t").bytes("docs/l"); }).isError);
    m = c->call("ReadLink", locPath(Loc, "docs/l"));
    QCOMPARE(m.args.value(0).toByteArray(), QByteArray("../t"));
    m = c->call("SpaceInfo", locPath(Loc, ""));
    QCOMPARE(m.args.size(), 3);
    fake()->addFile(QStringLiteral("docs/c"), "abc");
    QVERIFY(!c->call("ServerCopy", [](WireWriter &w) {
        w.string(Loc).bytes("docs/c").bytes("docs/d").variantMap(QVariantMap());
    }).isError);
    QCOMPARE(fake()->fileData(QStringLiteral("docs/d")), QByteArray("abc"));
    m = c->call("Checksum", [](WireWriter &w) { w.string(Loc).bytes("docs/c").string(QStringLiteral("sha256")); });
    QVERIFY2(!m.isError, qPrintable(m.name));
    QCOMPARE(m.args.value(0).toByteArray().size(), 32);
    QCOMPARE(c->call("Stat", [](WireWriter &w) { w.string(QStringLiteral("account:99")).bytes("").boolean(true).string(QString()); }).name,
             QLatin1String(NotFound));
}

void tst_BridgeServer::pathValidation()
{
    Fixture f;
    auto c = f.helloClient();
    TestClient::Message m = c->call("Stat", [](WireWriter &w) { w.string(Loc).bytes("a/../b").boolean(true).string(QString()); });
    QCOMPARE(m.name, QStringLiteral("org.netvfs.Error.InvalidName"));
    m = c->call("RemoveFile", [](WireWriter &w) { w.string(Loc).bytes(QByteArray("a\0b", 3)); });
    QCOMPARE(m.name, QStringLiteral("org.netvfs.Error.InvalidName"));
    m = c->call("RemoveFile", [](WireWriter &w) { w.string(Loc).string(QStringLiteral("a")); });   // "s" for a path
    QCOMPARE(m.name, QLatin1String(InvalidArgs));
    m = c->call("Frobnicate");
    QCOMPARE(m.name, QStringLiteral("org.freedesktop.DBus.Error.UnknownMethod"));
    QVERIFY(fake()->log.filter(QStringLiteral("remove")).isEmpty());   // nothing reached the backend
}

void tst_BridgeServer::handles()
{
    Fixture f;
    fake()->addFile(QStringLiteral("v.bin"), "0123456789");
    auto c = f.helloClient();
    TestClient::Message m = c->call("OpenRead", [](WireWriter &w) { w.string(Loc).bytes("v.bin").string(QStringLiteral("stream")); });
    QVERIFY2(!m.isError, qPrintable(m.name));
    const quint32 h = m.args.value(0).toUInt();
    QCOMPARE(m.args.value(1).toLongLong(), 10);
    QCOMPARE(f.server->openHandles(), 1);
    m = c->call("Read", [h](WireWriter &w) { w.uint32(h).int64(3).uint32(4); });
    QCOMPARE(m.args.value(0).toByteArray(), QByteArray("3456"));
    QVERIFY(!c->call("ReadAhead", [h](WireWriter &w) { w.uint32(h).int64(0).int64(100); }).isError);
    m = c->call("Read", [h](WireWriter &w) { w.uint32(h).int64(8).uint32(1 << 20); });
    QCOMPARE(m.args.value(0).toByteArray(), QByteArray("89"));
    QCOMPARE(c->call("Read", [h](WireWriter &w) { w.uint32(h).int64(0).uint32((1 << 20) + 1); }).name,
             QLatin1String(InvalidArgs));
    QVERIFY(!c->call("Close", [h](WireWriter &w) { w.uint32(h); }).isError);
    QCOMPARE(f.server->openHandles(), 0);
    QCOMPARE(c->call("Read", [h](WireWriter &w) { w.uint32(h).int64(0).uint32(1); }).name, QLatin1String(NotFound));
    // Disconnect drops the location's connections: the handle is gone.
    m = c->call("OpenRead", [](WireWriter &w) { w.string(Loc).bytes("v.bin").string(QString()); });
    const quint32 h2 = m.args.value(0).toUInt();
    QVERIFY(!c->call("Disconnect", [](WireWriter &w) { w.string(Loc); }).isError);
    QCOMPARE(c->call("Read", [h2](WireWriter &w) { w.uint32(h2).int64(0).uint32(1); }).name,
             QStringLiteral("org.netvfs.Error.ConnectionLost"));
}

void tst_BridgeServer::handleLimit()
{
    Fixture f;
    fake()->addFile(QStringLiteral("v.bin"), "x");
    auto c = f.helloClient();
    for (int i = 0; i < Bridge::ConsumerLimits::Handles; ++i) {
        const TestClient::Message m = c->call("OpenRead", [](WireWriter &w) { w.string(Loc).bytes("v.bin").string(QString()); });
        QVERIFY2(!m.isError, qPrintable(m.name));
    }
    const TestClient::Message over = c->call("OpenRead", [](WireWriter &w) { w.string(Loc).bytes("v.bin").string(QString()); });
    QCOMPARE(over.name, QLatin1String(TooMany));
    QVERIFY(over.args.value(1).toMap().value("retryAfterMs").toLongLong() > 0);
    c->close();
    QVERIFY(waitFor([&f]() { return f.server->openHandles() == 0; }));
}

void tst_BridgeServer::requestLimit()
{
    auto *accounts = new HangingAccounts;
    accounts->accounts << FakeAccounts::fakeAccount(1);
    Fixture f(Consent::Granted, false);
    delete f.accounts;
    f.accounts = accounts;
    f.config.accounts = accounts;
    f.startServer();
    auto c = f.helloClient();
    QList<quint32> serials;
    for (int i = 0; i < Bridge::ConsumerLimits::Requests; ++i)
        serials << c->send("Stat", [](WireWriter &w) { w.string(Loc).bytes("x").boolean(true).string(QString()); });
    QVERIFY(waitFor([&f]() { return f.server->activeRequests() == Bridge::ConsumerLimits::Requests; }));
    const TestClient::Message over = c->call("Stat", [](WireWriter &w) { w.string(Loc).bytes("x").boolean(true).string(QString()); });
    QCOMPARE(over.name, QLatin1String(TooMany));
    QCOMPARE(over.args.value(1).toMap().value("retryAfterMs").toLongLong(), Bridge::ConsumerLimits::RetryAfterMs);
    // Session-level calls are not limited by pending location work.
    QVERIFY(!c->call("GetConsent").isError);
    // Disconnecting cancels the waits (XB-13).
    c->close();
    QVERIFY(waitFor([&f]() { return f.server->activeRequests() == 0; }, 3000));
}

void tst_BridgeServer::jobLimit()
{
    auto *accounts = new HangingAccounts;
    accounts->accounts << FakeAccounts::fakeAccount(1);
    Fixture f(Consent::Granted, false);
    delete f.accounts;
    f.accounts = accounts;
    f.config.accounts = accounts;
    f.startServer();
    auto c = f.helloClient();
    for (int i = 0; i < Bridge::ConsumerLimits::Jobs; ++i) {
        const TestClient::Message m = c->call("RemoveTree", locPath(Loc, "x"));
        QVERIFY2(!m.isError, qPrintable(m.name));
    }
    QCOMPARE(f.server->runningJobs(), Bridge::ConsumerLimits::Jobs);
    QCOMPARE(c->call("RemoveTree", locPath(Loc, "x")).name, QLatin1String(TooMany));
    c->close();
    QVERIFY(waitFor([&f]() { return f.server->runningJobs() == 0; }, 3000));
}

void tst_BridgeServer::uploadAndDownloadRegular()
{
    Fixture f;
    QTemporaryDir dir;
    const QByteArray local = QFile::encodeName(tempFile(dir, "up.bin", "0123456789"));
    auto c = f.helloClient();
    const int rd = ::open(local.constData(), O_RDONLY);
    ::lseek(rd, 7, SEEK_SET);
    TestClient::Message m = c->call("Upload", [rd](WireWriter &w) {
        w.string(Loc).bytes("up.bin").unixFd(rd).variantMap(QVariantMap { { "offset", qlonglong(2) }, { "size", qlonglong(5) } });
    });
    QVERIFY2(!m.isError, qPrintable(m.name));
    const quint32 job = m.args.value(0).toUInt();
    TestClient::Message done = c->waitSignal(QStringLiteral("JobFinished"));
    QCOMPARE(done.args.value(0).toUInt(), job);
    QVERIFY2(done.args.value(1).toString().isEmpty(), qPrintable(done.args.value(2).toString()));
    QCOMPARE(done.args.value(3).toMap().value("bytes").toLongLong(), 5);
    QCOMPARE(fake()->fileData(QStringLiteral("up.bin")), QByteArray("23456"));
    QCOMPARE(::lseek(rd, 0, SEEK_CUR), off_t(7));   // pread: the consumer's offset is untouched
    ::close(rd);

    // CreateNew is the default: a second upload to the same name fails.
    const int rd2 = ::open(local.constData(), O_RDONLY);
    c->call("Upload", [rd2](WireWriter &w) { w.string(Loc).bytes("up.bin").unixFd(rd2).variantMap(QVariantMap()); });
    ::close(rd2);
    QCOMPARE(c->waitSignal(QStringLiteral("JobFinished")).args.value(1).toString(), QStringLiteral("AlreadyExists"));

    fake()->addFile(QStringLiteral("down.bin"), "abcdefgh");
    const QByteArray target = QFile::encodeName(tempFile(dir, "down.bin", "........"));
    const int wr = ::open(target.constData(), O_WRONLY);
    m = c->call("Download", [wr](WireWriter &w) {
        w.string(Loc).bytes("down.bin").unixFd(wr).variantMap(QVariantMap { { "offset", qlonglong(3) } });
    });
    ::close(wr);
    QVERIFY2(!m.isError, qPrintable(m.name));
    done = c->waitSignal(QStringLiteral("JobFinished"));
    QVERIFY2(done.args.value(1).toString().isEmpty(), qPrintable(done.args.value(2).toString()));
    QFile result(QString::fromLocal8Bit(target));
    QVERIFY(result.open(QIODevice::ReadOnly));
    QCOMPARE(result.readAll(), QByteArray("...defgh"));
}

void tst_BridgeServer::transferThroughPipes()
{
    Fixture f;
    auto c = f.helloClient();
    int up[2];
    QCOMPARE(::pipe(up), 0);
    QCOMPARE(::write(up[1], "streamed", 8), ssize_t(8));
    ::close(up[1]);
    TestClient::Message m = c->call("Upload", [&up](WireWriter &w) {
        w.string(Loc).bytes("fifo.bin").unixFd(up[0]).variantMap(QVariantMap());
    });
    ::close(up[0]);
    QVERIFY2(!m.isError, qPrintable(m.name));
    TestClient::Message done = c->waitSignal(QStringLiteral("JobFinished"));
    QVERIFY2(done.args.value(1).toString().isEmpty(), qPrintable(done.args.value(2).toString()));
    QCOMPARE(fake()->fileData(QStringLiteral("fifo.bin")), QByteArray("streamed"));

    int down[2];
    QCOMPARE(::pipe(down), 0);
    m = c->call("Download", [&down](WireWriter &w) {
        w.string(Loc).bytes("fifo.bin").unixFd(down[1]).variantMap(QVariantMap());
    });
    ::close(down[1]);
    QVERIFY2(!m.isError, qPrintable(m.name));
    done = c->waitSignal(QStringLiteral("JobFinished"));
    QVERIFY(done.args.value(1).toString().isEmpty());
    char buffer[16] = {};
    QCOMPARE(::read(down[0], buffer, sizeof(buffer)), ssize_t(8));
    QCOMPARE(QByteArray(buffer, 8), QByteArray("streamed"));
    // The bridge closed its copy at the end of the job: EOF.
    QCOMPARE(::read(down[0], buffer, sizeof(buffer)), ssize_t(0));
    ::close(down[0]);
}

void tst_BridgeServer::fdValidation()
{
    Fixture f;
    fake()->addFile(QStringLiteral("a"), "a");
    QTemporaryDir dir;
    const QByteArray local = QFile::encodeName(tempFile(dir, "l", "l"));
    auto c = f.helloClient();
    const int folder = ::open(QFile::encodeName(dir.path()).constData(), O_RDONLY | O_DIRECTORY);
    QCOMPARE(c->call("Upload", [folder](WireWriter &w) { w.string(Loc).bytes("x").unixFd(folder).variantMap(QVariantMap()); }).name,
             QLatin1String(PermissionDenied));
    ::close(folder);
    const int readOnly = ::open(local.constData(), O_RDONLY);
    QCOMPARE(c->call("Download", [readOnly](WireWriter &w) { w.string(Loc).bytes("a").unixFd(readOnly).variantMap(QVariantMap()); }).name,
             QLatin1String(PermissionDenied));
    ::close(readOnly);
    const int writeOnly = ::open(local.constData(), O_WRONLY);
    QCOMPARE(c->call("Upload", [writeOnly](WireWriter &w) { w.string(Loc).bytes("x").unixFd(writeOnly).variantMap(QVariantMap()); }).name,
             QLatin1String(PermissionDenied));
    ::close(writeOnly);
    QCOMPARE(f.server->runningJobs(), 0);
    QVERIFY(fake()->log.filter(QStringLiteral("connect")).isEmpty());   // refused before any network work
    QVERIFY(!fake()->exists(QStringLiteral("x")));
}

void tst_BridgeServer::disconnectCancelsJobs()
{
    Fixture f;
    fake()->addFile(QStringLiteral("big"), QByteArray(8 << 20, 'x'));
    fake()->chunkDelayMs = 100;
    auto c = f.helloClient();
    QTemporaryDir dir;
    const QByteArray target = QFile::encodeName(tempFile(dir, "t", ""));
    const int wr = ::open(target.constData(), O_WRONLY);
    QVERIFY(!c->call("Download", [wr](WireWriter &w) { w.string(Loc).bytes("big").unixFd(wr).variantMap(QVariantMap()); }).isError);
    ::close(wr);
    QVERIFY(waitFor([]() { return fake()->log.contains(QStringLiteral("download:big")); }));
    QThread::msleep(150);
    QElapsedTimer timer;
    timer.start();
    c->close();
    QVERIFY(waitFor([&f]() { return f.server->runningJobs() == 0; }, 2500));
    QVERIFY2(timer.elapsed() < 2000, qPrintable(QString::number(timer.elapsed())));   // C-9 / XB-13
    QVERIFY(QFileInfo(QString::fromLocal8Bit(target)).size() < (8 << 20));
}

void tst_BridgeServer::cancelJob()
{
    Fixture f;
    fake()->addFile(QStringLiteral("big"), QByteArray(4 << 20, 'x'));
    fake()->chunkDelayMs = 100;
    auto c = f.helloClient();
    QTemporaryDir dir;
    const int wr = ::open(QFile::encodeName(tempFile(dir, "t", "")).constData(), O_WRONLY);
    const quint32 job = c->call("Download", [wr](WireWriter &w) {
        w.string(Loc).bytes("big").unixFd(wr).variantMap(QVariantMap());
    }).args.value(0).toUInt();
    ::close(wr);
    QVERIFY(waitFor([]() { return fake()->log.contains(QStringLiteral("download:big")); }));
    QVERIFY(!c->call("Cancel", [job](WireWriter &w) { w.uint32(job); }).isError);
    const TestClient::Message done = c->waitSignal(QStringLiteral("JobFinished"), nullptr, 3000);
    QCOMPARE(done.args.value(0).toUInt(), job);
    QCOMPARE(done.args.value(1).toString(), QStringLiteral("Canceled"));
    QVERIFY(c->signalCount(QStringLiteral("JobProgress")) >= 0);
    QCOMPARE(c->call("Cancel", [](WireWriter &w) { w.uint32(4000); }).name, QLatin1String(NotFound));
}

void tst_BridgeServer::walkRemoveTreeCopyAcross()
{
    Fixture f;
    f.accounts->accounts << FakeAccounts::fakeAccount(2);
    f.accounts->notifyChanged();
    fake()->addFile(QStringLiteral("t/a/1"), "1");
    fake()->addFile(QStringLiteral("t/a/2"), "22");
    fake()->addFile(QStringLiteral("t/b"), "333");
    auto c = f.helloClient();
    TestClient::Message m = c->call("Walk", [](WireWriter &w) { w.string(Loc).bytes("t").variantMap(QVariantMap()); });
    QVERIFY2(!m.isError, qPrintable(m.name));
    TestClient::Message done = c->waitSignal(QStringLiteral("JobFinished"));
    QVERIFY(done.args.value(1).toString().isEmpty());
    QCOMPARE(done.args.value(3).toMap().value("entries").toLongLong(), 4);
    QStringList paths;
    for (;;) {
        const TestClient::Message b = c->waitSignal(QStringLiteral("WalkBatch"), nullptr, 100);
        if (!b.valid)
            break;
        for (const QVariant &item : b.args.value(1).toList())
            paths << QString::fromUtf8(item.toList().value(0).toByteArray());
    }
    paths.sort();
    QCOMPARE(paths, QStringList({ "t/a", "t/a/1", "t/a/2", "t/b" }));

    m = c->call("CopyAcross", [](WireWriter &w) {
        w.string(Loc).bytes("t").string(QStringLiteral("account:2")).bytes("copy")
            .variantMap(QVariantMap { { "recursive", true } });
    });
    QVERIFY2(!m.isError, qPrintable(m.name));
    done = c->waitSignal(QStringLiteral("JobFinished"));
    QVERIFY2(done.args.value(1).toString().isEmpty(), qPrintable(done.args.value(2).toString()));
    QCOMPARE(fake()->fileData(QStringLiteral("copy/a/2")), QByteArray("22"));

    m = c->call("RemoveTree", locPath(Loc, "t"));
    QVERIFY(!m.isError);
    done = c->waitSignal(QStringLiteral("JobFinished"));
    QVERIFY(done.args.value(1).toString().isEmpty());
    QCOMPARE(done.args.value(3).toMap().value("files").toLongLong(), 3);
    QVERIFY(!fake()->exists(QStringLiteral("t")));
}

void tst_BridgeServer::accountIdentityChangedSetsAttention()
{
    Fixture f;
    fake()->identity = ServerIdentity::fromPin(QStringLiteral("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA=="));
    f.accounts->accounts[0].params.options.insert(QStringLiteral("host_key"),
                                                  QStringLiteral("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB=="));
    f.accounts->notifyChanged();
    auto c = f.helloClient();
    const TestClient::Message m = c->call("Stat", [](WireWriter &w) { w.string(Loc).bytes("").boolean(true).string(QString()); });
    QCOMPARE(m.name, QStringLiteral("org.netvfs.Error.ServerIdentityChanged"));
    QVERIFY(waitFor([&f]() { return !f.accounts->attention.isEmpty(); }));
    QCOMPARE(f.accounts->attention.at(0).first, 1);
    QCOMPARE(f.accounts->attention.at(0).second, Attention::ServerIdentityChanged);
    QVERIFY(!fake()->log.contains(QStringLiteral("authenticate")));   // C-7
    QCOMPARE(c->signalCount(QStringLiteral("Question")), 0);           // accounts are resolved in Settings
}

namespace {
Bridge::LocationSpec fakeAdHoc(Bridge::BridgeServer *server)
{
    Bridge::LocationSpec spec;
    spec.id = server->reserveAdHocId();
    spec.kind = Bridge::LocationKind::AdHoc;
    spec.provider = QStringLiteral("fake");
    spec.name = QStringLiteral("adhoc");
    spec.params.provider = QStringLiteral("fake");
    spec.params.host = QStringLiteral("adhoc.example");
    spec.adHocCredentials = std::make_shared<Credentials>(QStringLiteral("user"), QByteArray("secret"));
    return spec;
}
} // namespace

void tst_BridgeServer::adHocIdentityQuestion()
{
    Fixture f;
    fake()->identity = ServerIdentity::fromPin(QStringLiteral("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA=="));
    const Bridge::LocationSpec spec = fakeAdHoc(f.server.get());
    f.server->addAdHoc(spec, std::make_unique<Bridge::Pool>(spec, f.server->connector(), f.server->hosts()));
    auto c = f.helloClient();
    QCOMPARE(c->call("ListLocations").args.value(0).toList().size(), 2);

    // Declined: no credentials are sent.
    const QString loc = spec.id;
    quint32 serial = c->send("Stat", [loc](WireWriter &w) { w.string(loc).bytes("").boolean(true).string(QString()); });
    TestClient::Message q = c->waitSignal(QStringLiteral("Question"));
    QCOMPARE(q.args.value(1).toString(), QStringLiteral("identity-unknown"));
    const QVariantMap details = q.args.value(2).toMap();
    QCOMPARE(details.value("algorithm").toString(), QStringLiteral("ssh-ed25519"));
    QVERIFY(!details.value("fingerprint").toString().isEmpty());
    QString id = q.args.value(0).toString();
    QVERIFY(!c->call("Answer", [id](WireWriter &w) { w.string(id).variantMap(QVariantMap { { "accept", false } }); }).isError);
    QCOMPARE(c->waitReply(serial).name, QStringLiteral("org.netvfs.Error.ServerIdentityUnknown"));
    QVERIFY(!fake()->log.contains(QStringLiteral("authenticate")));

    // Accepted: pinned in known_hosts; the next connection does not ask.
    serial = c->send("Stat", [loc](WireWriter &w) { w.string(loc).bytes("").boolean(true).string(QString()); });
    q = c->waitSignal(QStringLiteral("Question"));
    id = q.args.value(0).toString();
    QCOMPARE(c->call("Answer", [](WireWriter &w) { w.string(QStringLiteral("q999")).variantMap(QVariantMap()); }).name,
             QLatin1String(NotFound));
    QVERIFY(!c->call("Answer", [id](WireWriter &w) { w.string(id).variantMap(QVariantMap { { "accept", true } }); }).isError);
    QVERIFY(!c->waitReply(serial).isError);
    QVERIFY(Bridge::KnownHosts(f.config.knownHostsFile).pin(spec.hostKey()).startsWith(QStringLiteral("ssh-ed25519")));
    QVERIFY(!c->call("Disconnect", [loc](WireWriter &w) { w.string(loc); }).isError);
    QVERIFY(!c->call("Stat", [loc](WireWriter &w) { w.string(loc).bytes("").boolean(true).string(QString()); }).isError);
    QCOMPARE(c->signalCount(QStringLiteral("Question")), 0);

    // A changed identity is an error, not a question (XB-14).
    QVERIFY(!c->call("Disconnect", [loc](WireWriter &w) { w.string(loc); }).isError);
    fake()->identity = ServerIdentity::fromPin(QStringLiteral("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB=="));
    QCOMPARE(c->call("Stat", [loc](WireWriter &w) { w.string(loc).bytes("").boolean(true).string(QString()); }).name,
             QStringLiteral("org.netvfs.Error.ServerIdentityChanged"));
    QCOMPARE(c->signalCount(QStringLiteral("Question")), 0);
    // ForgetAdHoc drops the location and the pin.
    QVERIFY(!c->call("ForgetAdHoc", [loc](WireWriter &w) { w.string(loc); }).isError);
    QVERIFY(Bridge::KnownHosts(f.config.knownHostsFile).pin(spec.hostKey()).isEmpty());
    QCOMPARE(c->call("ForgetAdHoc", [loc](WireWriter &w) { w.string(loc); }).name, QLatin1String(NotFound));
    QCOMPARE(c->call("ListLocations").args.value(0).toList().size(), 1);
}

void tst_BridgeServer::keyboardInteractive()
{
    Fixture f;
    fake()->otp = "123456";
    auto c = f.helloClient();
    quint32 serial = c->send("Stat", [](WireWriter &w) { w.string(Loc).bytes("").boolean(true).string(QString()); });
    TestClient::Message q = c->waitSignal(QStringLiteral("Question"));
    QCOMPARE(q.args.value(1).toString(), QStringLiteral("keyboard-interactive"));
    QVERIFY(!q.args.value(2).toMap().value("prompts").toStringList().isEmpty());
    QString id = q.args.value(0).toString();
    QVERIFY(!c->call("Answer", [id](WireWriter &w) {
        w.string(id).variantMap(QVariantMap { { "accept", true }, { "answers", QVariantList { QByteArray("123456") } } });
    }).isError);
    QVERIFY(!c->waitReply(serial).isError);

    // Canceling the request ends the wait: disconnect while the question is open.
    QVERIFY(!c->call("Disconnect", [](WireWriter &w) { w.string(Loc); }).isError);
    serial = c->send("Stat", [](WireWriter &w) { w.string(Loc).bytes("").boolean(true).string(QString()); });
    q = c->waitSignal(QStringLiteral("Question"));
    QVERIFY(q.valid);
    c->close();
    QVERIFY(waitFor([&f]() { return f.server->activeRequests() == 0; }, 3000));
    QCOMPARE(f.server->questions()->pending(), 0);
}

void tst_BridgeServer::connectAdHocRefusals()
{
    Fixture f;
    auto c = f.helloClient();
    TestClient::Message m = c->call("ConnectAdHoc", [](WireWriter &w) {
        w.string(QStringLiteral("sftp://user:pw@host/")).bytes("s").variantMap(QVariantMap());
    });
    QCOMPARE(m.name, QStringLiteral("org.netvfs.Error.SecurityPolicy"));   // XH-6
    m = c->call("ConnectAdHoc", [](WireWriter &w) { w.string(QStringLiteral("file:///etc")).bytes("").variantMap(QVariantMap()); });
    QCOMPARE(m.name, QLatin1String(PermissionDenied));                      // XB-11: never local paths
    m = c->call("ConnectAdHoc", [](WireWriter &w) { w.string(QStringLiteral("sftp://host/")).bytes("").variantMap(QVariantMap()); });
    QCOMPARE(m.name, QStringLiteral("org.netvfs.Error.Unsupported"));      // no sftp backend on this path
    m = c->call("ConnectAdHoc", [](WireWriter &w) {
        w.string(QStringLiteral("sftp://host/")).bytes("").variantMap(QVariantMap { { "password", "x" } });
    });
    QCOMPARE(m.name, QLatin1String(InvalidArgs));
}

void tst_BridgeServer::insecureConsentDeclined()
{
    qputenv("NETVFS_BACKEND_PATH", QByteArray(NETVFS_TEST_FAKE_BACKEND_DIR) + ':' + NETVFS_TEST_BACKEND_DIR);
    Fixture f;
    qputenv("NETVFS_BACKEND_PATH", QByteArray(NETVFS_TEST_FAKE_BACKEND_DIR) + ':' + NETVFS_TEST_BACKEND_DIR);
    if (!BackendLoader::isAvailable(QStringLiteral("webdav")))
        QSKIP("the WebDAV backend is not built");
    auto c = f.helloClient();
    const quint32 serial = c->send("ConnectAdHoc", [](WireWriter &w) {
        w.string(QStringLiteral("dav://127.0.0.1:1/")).bytes("pw").variantMap(QVariantMap());
    });
    const TestClient::Message q = c->waitSignal(QStringLiteral("Question"));
    QCOMPARE(q.args.value(1).toString(), QStringLiteral("insecure-consent"));
    const QString id = q.args.value(0).toString();
    QVERIFY(!c->call("Answer", [id](WireWriter &w) { w.string(id).variantMap(QVariantMap { { "accept", false } }); }).isError);
    QCOMPARE(c->waitReply(serial).name, QStringLiteral("org.netvfs.Error.SecurityPolicy"));
    QCOMPARE(c->call("ListLocations").args.value(0).toList().size(), 1);
}

void tst_BridgeServer::peerCheckRefuses()
{
    Fixture f(Consent::Granted, false);
    f.config.consumer.executable = QStringLiteral("/bin/sh");   // not this test binary
    f.startServer();
    auto c = f.client();
    const quint32 serial = c->send("Hello", [](WireWriter &w) { w.uint32(1).string(QStringLiteral("x")); });
    QVERIFY(c->waitDisconnected(3000));
    QVERIFY(!c->waitReply(serial, 200).valid);   // closed without a reply
}

void tst_BridgeServer::idleExit()
{
    Fixture f;
    QSignalSpy idle(f.server.get(), &Bridge::BridgeServer::idleTimeout);
    {
        auto c = f.helloClient();
        QTest::qWait(500);
        QCOMPARE(idle.count(), 0);   // a client is connected
        c->close();
        QVERIFY(c->waitDisconnected());
    }
    QVERIFY(idle.wait(2000));
}

namespace {
class SilentTransport : public DiscoveryTransport
{
public:
    bool open() override { return m_open = true; }
    void close() override { m_open = false; }
    bool isOpen() const override { return m_open; }
    void send(const QByteArray &) override {}

private:
    bool m_open = false;
};
} // namespace

void tst_BridgeServer::discovery()
{
    Fixture f(Consent::Granted, false);
    Discovery *created = nullptr;
    f.config.discoveryFactory = [&created]() { return created = new Discovery(new SilentTransport); };
    f.startServer();
    auto c = f.helloClient();
    QVERIFY(!c->call("Discover", [](WireWriter &w) { w.boolean(true); }).isError);
    QVERIFY(created);
    QVERIFY(created->isRunning());
    QVERIFY(c->waitSignal(QStringLiteral("NearbyChanged")).valid);
    QVERIFY(!c->call("Discover", [](WireWriter &w) { w.boolean(false); }).isError);
    QVERIFY(!created->isRunning());   // XD-5
    QVERIFY(!c->call("Discover", [](WireWriter &w) { w.boolean(true); }).isError);
    c->close();
    QVERIFY(waitFor([&created]() { return !created->isRunning(); }));
}

void tst_BridgeServer::handoff()
{
    Fixture f(Consent::Granted, false);
    QList<Bridge::HandoffCall> calls;
    f.config.handoffLauncher = [&calls](const Bridge::HandoffCall &call) {
        calls << call;
        return Result::success();
    };
    QFile conf(f.config.handoffConfig);
    QVERIFY(conf.open(QIODevice::WriteOnly));
    conf.write("[OpenAccountSettings]\nService=a.b\nPath=/c\nInterface=a.b\nMethod=show\nArguments=i:{accountId}\n"
               "[AddAccount]\nService=a.b\nPath=/c\nInterface=a.b\nMethod=add\nArguments=s:{provider}\n");
    conf.close();
    f.startServer();
    auto c = f.helloClient();
    QVERIFY(!c->call("OpenAccountSettings", [](WireWriter &w) { w.string(Loc); }).isError);
    QVERIFY(!c->call("AddAccount", [](WireWriter &w) { w.string(QStringLiteral("webdav")); }).isError);
    QCOMPARE(calls.size(), 2);
    QCOMPARE(calls.at(0).arguments, QVariantList({ 1 }));
    QCOMPARE(calls.at(1).arguments, QVariantList({ QStringLiteral("webdav") }));
    QCOMPARE(c->call("OpenAccountSettings", [](WireWriter &w) { w.string(QStringLiteral("adhoc:7")); }).name,
             QLatin1String(NotFound));
}

void tst_BridgeServer::locationsChanged()
{
    Fixture f;
    auto c = f.helloClient();
    f.accounts->accounts << FakeAccounts::fakeAccount(5);
    f.accounts->notifyChanged();
    QVERIFY(c->waitSignal(QStringLiteral("LocationsChanged")).valid);
    QCOMPARE(c->call("ListLocations").args.value(0).toList().size(), 2);
}

QTEST_GUILESS_MAIN(tst_BridgeServer)
#include "tst_bridgeserver.moc"
