// SPDX-License-Identifier: LGPL-2.1-or-later
// SPEC-v2 XT-1: backend conformance suite. Every test function runs once per
// target (tests/conformance/README.md); a capability a backend reports must
// pass its tests, an unreported one must answer Unsupported and change
// nothing.
#include "backendloader.h"
#include "identity.h"
#include "names.h"
#include "paths.h"
#include "support.h"
#include "target.h"

#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>
#include <QtTest/QtTest>

#include <memory>

using namespace NetVfs;
using namespace Conformance;

namespace NetVfs {
// QCOMPARE(result, Result(Error::X)) compares the error only and prints the
// whole result on failure.
bool operator==(const Result &a, const Result &b)
{
    return a.error() == b.error();
}
} // namespace NetVfs

namespace QTest {
template<>
char *toString(const NetVfs::Result &result)
{
    return qstrdup(qPrintable(result.ok() ? QStringLiteral("success") : result.toString()));
}
} // namespace QTest

namespace {

constexpr int MiB = 1 << 20;
constexpr qint64 FourGiB = qint64(4) << 30;
constexpr qint64 CancelLimitMs = 2000;   // C-9
constexpr int CancelDelayMs = 300;
constexpr int ClockToleranceSecs = 600;
constexpr int ListTimeToleranceSecs = 60;
constexpr int TimeoutMs = 500;
constexpr int BatchSize = 100;
constexpr int StallBytes = 4 * MiB;      // more than any pipe buffer

QDateTime fixedTime()
{
    return QDateTime(QDate(2001, 2, 3), QTime(4, 5, 6), Qt::UTC);
}

qint64 seconds(const QDateTime &time)
{
    return time.toMSecsSinceEpoch() / 1000;
}

QString describe(const Result &r)
{
    return r.ok() ? QStringLiteral("success") : r.toString();
}

} // namespace

class TestConformance : public QObject
{
    Q_OBJECT

public:
    explicit TestConformance(const Target &target) : m_target(target) {}

private slots:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();

    void capabilities();
    void cancelBeforeCall();
    void keepAlive();
    void entryFields();
    void statAndLstat();
    void listing();
    void listBatches();
    void makeDir();
    void removeFile();
    void removeDir();
    void removeTreeNative();
    void renameFiles();
    void renameFolders();
    void renameCaseOnly();
    void namesUtf8();
    void namesNormalization();
    void namesNonUtf8();
    void namesLong();
    void namesWindowsInvalid();
    void setAttributes();
    void symlinks();
    void symlinkFolder();
    void symlinkDangling();
    void symlinkLoop();
    void hardlinks();
    void readHandle();
    void readHelper();
    void downloadRanges();
    void writeHandle();
    void writeResume();
    void handlesAfterDisconnect();
    void uploadDownload();
    void uploadOptions();
    void progressCancel();
    void largeSparse();
    void copy();
    void checksum();
    void spaceInfo();
    void unsupportedWithoutSideEffects();
    void cancelStalledFifo();
    void stallTimeoutFifo();
    void cancelStalledProxy();

private:
    std::unique_ptr<Backend> connectTo(const ConnectionParams &params, Result *result);
    QString p(const QString &name) const { return Paths::join(m_dir, name); }
    QString hostPath(const QString &name) const;
    bool has(Capability c) const { return m_caps.has(c); }
    void expectUnsupported(Capability c, const std::function<Result()> &call);
    void checkLink(const QString &link, EntryType targetType);
    void largeSparseChecks(const QString &path, qint64 size, qint64 markerOffset, const QByteArray &marker);
    void runFifoStall(const QString &what, const std::function<Result()> &call);

    Target m_target;
    std::unique_ptr<Backend> m_backend;
    Capabilities m_caps;
    QString m_pin;
    QString m_runName;
    QString m_runDir;
    QString m_dir;
};

// --- fixture ----------------------------------------------------------------

std::unique_ptr<Backend> TestConformance::connectTo(const ConnectionParams &params, Result *result)
{
    std::unique_ptr<Backend> backend(BackendLoader::create(params.provider, result));
    if (!backend)
        return nullptr;
    ConnectionParams effective = params;
    if (!m_pin.isEmpty() && effective.option(QStringLiteral("host_key")).isEmpty())
        effective.options.insert(QStringLiteral("host_key"), m_pin);
    const Credentials credentials(m_target.user, qgetenv(m_target.secretEnv.toLocal8Bit().constData()));
    ServerIdentity seen;
    Result r = establish(backend.get(), effective, credentials, &seen);
    if (r.error() == Error::ServerIdentityUnknown && m_target.trustOnFirstUse) {
        m_pin = seen.toPin();
        effective.options.insert(QStringLiteral("host_key"), m_pin);
        r = establish(backend.get(), effective, credentials, &seen);
    }
    *result = r;
    if (!r.ok())
        return nullptr;
    return backend;
}

QString TestConformance::hostPath(const QString &name) const
{
    return QStringLiteral("%1/%2/%3/%4")
        .arg(m_target.hostPath, m_runName, QString::fromLatin1(QTest::currentTestFunction()), name);
}

void TestConformance::initTestCase()
{
    qInfo("Target %s (provider %s)", qPrintable(m_target.name), qPrintable(m_target.params.provider));
    Result r;
    m_backend = connectTo(m_target.params, &r);
    QVERIFY2(m_backend, qPrintable(r.toString()));
    m_caps = m_backend->capabilities();
    qInfo("Capabilities: %s", qPrintable(m_caps.names().join(QLatin1Char(' '))));
    m_runName = QStringLiteral("run-%1-%2").arg(QCoreApplication::applicationPid()).arg(QDateTime::currentMSecsSinceEpoch());
    QCOMPARE(m_backend->makePath(m_target.baseDir), Result::success());
    m_runDir = Paths::join(m_target.baseDir, m_runName);
    QCOMPARE(m_backend->makeDir(m_runDir, true), Result::success());
    m_backend.reset();
}

void TestConformance::cleanupTestCase()
{
    if (m_runDir.isEmpty() || qgetenv("NETVFS_CONFORMANCE_KEEP") == "1")
        return;
    Result r;
    const std::unique_ptr<Backend> backend = connectTo(m_target.params, &r);
    QVERIFY2(backend, qPrintable(r.toString()));
    QCOMPARE(removeRecursive(backend.get(), m_runDir), Result::success());
}

void TestConformance::init()
{
    const QString function = QString::fromLatin1(QTest::currentTestFunction());
    if (m_target.skip.contains(function))
        QSKIP(qPrintable(QStringLiteral("skipped for %1: %2").arg(m_target.name, m_target.skip.value(function))));
    Result r;
    m_backend = connectTo(m_target.params, &r);
    QVERIFY2(m_backend, qPrintable(r.toString()));
    m_caps = m_backend->capabilities();
    m_dir = Paths::join(m_runDir, function);
    QCOMPARE(m_backend->makeDir(m_dir, true), Result::success());
}

void TestConformance::cleanup()
{
    if (m_backend)
        m_backend->disconnect();
    m_backend.reset();
}

// --- connection, capabilities, cancel ----------------------------------------

void TestConformance::capabilities()
{
    const Capabilities again = m_backend->capabilities();   // XC-5: stable
    QCOMPARE(again.names(), m_caps.names());
    QCOMPARE(again.checksumAlgorithms, m_caps.checksumAlgorithms);
    QCOMPARE(m_caps.checksumAlgorithms.isEmpty(), !has(Capability::Checksums));
    QVERIFY(m_caps.maxNameBytes == -1 || m_caps.maxNameBytes > 0);
    QVERIFY(m_caps.maxReadChunk >= 0);
    QVERIFY(m_caps.maxWriteChunk >= 0);
    for (const Capability c : m_caps.flags) {
        Capability parsed {};
        QVERIFY(capabilityFromName(capabilityName(c), &parsed));
        QCOMPARE(parsed, c);
    }
}

void TestConformance::cancelBeforeCall()
{
    // C-9: a cancel() stays in effect until resetCancel().
    m_backend->cancel();
    Entry entry;
    QCOMPARE(m_backend->stat(m_dir, &entry), Result(Error::Canceled));
    m_backend->resetCancel();
    QCOMPARE(m_backend->stat(m_dir, &entry), Result::success());
}

void TestConformance::keepAlive()
{
    QCOMPARE(m_backend->keepAlive(), Result::success());   // XC-20
    QCOMPARE(m_backend->keepAlive(), Result::success());
    m_backend->disconnect();
    QVERIFY(!m_backend->keepAlive().ok());
    if (m_target.restart.isEmpty())
        return;
    Result r;
    const std::unique_ptr<Backend> backend = connectTo(m_target.params, &r);
    QVERIFY2(backend, qPrintable(r.toString()));
    QString output;
    QVERIFY2(runShell(m_target.restart, &output), qPrintable(output));
    QCOMPARE(backend->keepAlive(), Result(Error::ConnectionLost));
}

// --- metadata ---------------------------------------------------------------

void TestConformance::entryFields()
{
    const QByteArray data = pattern(1234, 1);
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("fields.bin")), data), Result::success());
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("sub")), true), Result::success());

    Entry file;
    QCOMPARE(m_backend->stat(p(QStringLiteral("fields.bin")), &file), Result::success());
    QCOMPARE(file.name, QStringLiteral("fields.bin"));
    QCOMPARE(file.type, EntryType::File);
    QVERIFY(file.isFile());
    QVERIFY(!file.isDir());
    QCOMPARE(file.size, qint64(data.size()));
    QVERIFY(file.modified.isValid());
    QVERIFY2(qAbs(file.modified.secsTo(QDateTime::currentDateTimeUtc())) < ClockToleranceSecs,
             qPrintable(file.modified.toString(Qt::ISODate)));
    QVERIFY(!file.created.isValid() || file.created.secsTo(QDateTime::currentDateTimeUtc()) > -ClockToleranceSecs);
    QVERIFY(file.mode >= -1 && file.mode <= 07777);
    if (has(Capability::PosixModes))
        QVERIFY(file.mode >= 0);
    QVERIFY(file.uid >= -1 && file.gid >= -1);
    if (has(Capability::Ownership))
        QVERIFY(file.uid >= 0 || !file.owner.isEmpty());
    QVERIFY(!file.flags.testFlag(EntryFlag::NameNotUtf8));
    QVERIFY(!file.flags.testFlag(EntryFlag::TargetUnknown));
    QCOMPARE(file.targetType, EntryType::Unknown);
    if (has(Capability::ETags))
        QVERIFY(!file.etag.isEmpty());

    Entry dir;
    QCOMPARE(m_backend->stat(p(QStringLiteral("sub")), &dir), Result::success());
    QCOMPARE(dir.name, QStringLiteral("sub"));
    QCOMPARE(dir.type, EntryType::Directory);
    QVERIFY(dir.isDir());
    QVERIFY(!dir.isFile());

    QVector<Entry> entries;
    QCOMPARE(m_backend->list(m_dir, &entries), Result::success());
    QCOMPARE(entries.size(), 2);   // "." and ".." never appear (XC-6)
    const Entry *listedFile = find(entries, QStringLiteral("fields.bin"));
    const Entry *listedDir = find(entries, QStringLiteral("sub"));
    QVERIFY(listedFile && listedDir);
    QCOMPARE(listedFile->type, EntryType::File);
    QCOMPARE(listedFile->size, file.size);
    // Listings may carry coarser times than stat (FTP LIST: minutes).
    QVERIFY(qAbs(listedFile->modified.secsTo(file.modified)) <= ListTimeToleranceSecs);
    QCOMPARE(listedFile->mode, file.mode);
    QCOMPARE(listedDir->type, EntryType::Directory);
}

void TestConformance::statAndLstat()
{
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("plain")), "abc"), Result::success());
    Entry followed;
    Entry itself;
    QCOMPARE(m_backend->stat(p(QStringLiteral("plain")), &followed), Result::success());
    QCOMPARE(m_backend->lstat(p(QStringLiteral("plain")), &itself), Result::success());
    QCOMPARE(itself.type, followed.type);
    QCOMPARE(itself.size, followed.size);
    QCOMPARE(m_backend->stat(p(QStringLiteral("missing")), &followed), Result(Error::NotFound));
    QCOMPARE(m_backend->lstat(p(QStringLiteral("missing")), &itself), Result(Error::NotFound));
    const Result below = m_backend->stat(p(QStringLiteral("plain/below")), &followed);
    QVERIFY2(below.error() == Error::NotFound || below.error() == Error::NotADirectory, qPrintable(describe(below)));
}

void TestConformance::listing()
{
    QVector<Entry> entries;
    QCOMPARE(m_backend->list(m_dir, &entries), Result::success());
    QVERIFY(entries.isEmpty());
    QCOMPARE(m_backend->list(p(QStringLiteral("missing")), &entries), Result(Error::NotFound));
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("file")), "x"), Result::success());
    QCOMPARE(m_backend->list(p(QStringLiteral("file")), &entries), Result(Error::NotADirectory));
}

void TestConformance::listBatches()
{
    const int count = m_target.listCount;
    const QString dir = p(QStringLiteral("many"));
    QCOMPARE(m_backend->makeDir(dir, true), Result::success());
    QStringList expected;
    for (int i = 0; i < count; ++i) {
        const QString name = QStringLiteral("entry-%1").arg(i, 5, 10, QLatin1Char('0'));
        expected.append(name);
        if (m_target.hostPath.isEmpty()) {
            QCOMPARE(putFile(m_backend.get(), Paths::join(dir, name), QByteArray()), Result::success());
        } else {
            QFile file(hostPath(QStringLiteral("many/") + name));
            QVERIFY(file.open(QIODevice::WriteOnly));
        }
    }

    // XC-6: batches of at most batchSize, delivered as they come.
    ListOptions options;
    options.batchSize = BatchSize;
    RecordingSink sink;
    QCOMPARE(m_backend->list(dir, &sink, options), Result::success());
    QCOMPARE(sink.all.size(), count);
    QVERIFY(sink.batchSizes.size() >= (count + BatchSize - 1) / BatchSize);
    for (const int size : sink.batchSizes)
        QVERIFY2(size > 0 && size <= BatchSize, qPrintable(QString::number(size)));
    QStringList seen;
    for (const Entry &e : sink.all)
        seen.append(e.name);
    seen.sort();
    QCOMPARE(seen, expected);

    // A sink returning false stops the listing with Canceled.
    RecordingSink stopping;
    stopping.stopAfterBatches = 1;
    QCOMPARE(m_backend->list(dir, &stopping, options), Result(Error::Canceled));
    QCOMPARE(stopping.batchSizes.size(), 1);

    // cancel() during the listing (C-9, L-6) ends it early.
    RecordingSink canceling;
    canceling.cancelBackend = m_backend.get();
    QCOMPARE(m_backend->list(dir, &canceling, options), Result(Error::Canceled));
    QVERIFY(canceling.all.size() < count);
    m_backend->resetCancel();
    QVector<Entry> all;
    QCOMPARE(m_backend->list(dir, &all), Result::success());   // the convenience helper
    QCOMPARE(all.size(), count);
}

// --- namespace ----------------------------------------------------------------

void TestConformance::makeDir()
{
    const QString dir = p(QStringLiteral("folder"));
    QCOMPARE(m_backend->makeDir(dir, true), Result::success());
    QCOMPARE(m_backend->makeDir(dir, true), Result(Error::AlreadyExists));   // XC-8
    QCOMPARE(m_backend->makeDir(dir, false), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("file")), "x"), Result::success());
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("file")), false), Result(Error::AlreadyExists));
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("file")), true), Result(Error::AlreadyExists));
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("missing/child")), false), Result(Error::NotFound));
    QVERIFY(!exists(m_backend.get(), p(QStringLiteral("missing"))));
    QCOMPARE(m_backend->makePath(p(QStringLiteral("a/b/c"))), Result::success());
    QCOMPARE(m_backend->makePath(p(QStringLiteral("a/b/c"))), Result::success());
    Entry entry;
    QCOMPARE(m_backend->stat(p(QStringLiteral("a/b/c")), &entry), Result::success());
    QCOMPARE(entry.type, EntryType::Directory);
}

void TestConformance::removeFile()
{
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("file")), "x"), Result::success());
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("dir")), true), Result::success());
    QCOMPARE(m_backend->removeFile(p(QStringLiteral("file"))), Result::success());
    QVERIFY(!exists(m_backend.get(), p(QStringLiteral("file"))));
    QCOMPARE(m_backend->removeFile(p(QStringLiteral("file"))), Result(Error::NotFound));
    QCOMPARE(m_backend->removeFile(p(QStringLiteral("dir"))), Result(Error::IsADirectory));   // XC-9
    QVERIFY(exists(m_backend.get(), p(QStringLiteral("dir"))));
}

void TestConformance::removeDir()
{
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("empty")), true), Result::success());
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("full")), true), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("full/inner")), "x"), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("file")), "x"), Result::success());
    QCOMPARE(m_backend->removeDir(p(QStringLiteral("empty"))), Result::success());
    QVERIFY(!exists(m_backend.get(), p(QStringLiteral("empty"))));
    QCOMPARE(m_backend->removeDir(p(QStringLiteral("empty"))), Result(Error::NotFound));
    QCOMPARE(m_backend->removeDir(p(QStringLiteral("full"))), Result(Error::DirectoryNotEmpty));   // XC-9
    QVERIFY(exists(m_backend.get(), p(QStringLiteral("full/inner"))));
    QCOMPARE(m_backend->removeDir(p(QStringLiteral("file"))), Result(Error::NotADirectory));
    QVERIFY(exists(m_backend.get(), p(QStringLiteral("file"))));
    // The v1 helper: a file, else an empty folder.
    QCOMPARE(m_backend->remove(p(QStringLiteral("full/inner"))), Result::success());
    QCOMPARE(m_backend->remove(p(QStringLiteral("full"))), Result::success());
    QVERIFY(!exists(m_backend.get(), p(QStringLiteral("full"))));
}

void TestConformance::removeTreeNative()
{
    if (!has(Capability::RecursiveDelete))
        QSKIP("RecursiveDelete not reported");
    QCOMPARE(m_backend->makePath(p(QStringLiteral("tree/a/b"))), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("tree/a/b/f")), "x"), Result::success());
    QCOMPARE(m_backend->removeTreeNative(p(QStringLiteral("tree"))), Result::success());
    QVERIFY(!exists(m_backend.get(), p(QStringLiteral("tree"))));
}

void TestConformance::renameFiles()
{
    const QByteArray one = pattern(100, 1);
    const QByteArray two = pattern(200, 2);
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("one")), one), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("two")), two), Result::success());
    QByteArray data;

    // XC-10: NoReplace refuses an existing target and changes nothing.
    QCOMPARE(m_backend->rename(p(QStringLiteral("one")), p(QStringLiteral("two")), RenameMode::NoReplace), Result(Error::AlreadyExists));
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("one")), &data), Result::success());
    QCOMPARE(data, one);
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("two")), &data), Result::success());
    QCOMPARE(data, two);

    // Replace replaces it.
    QCOMPARE(m_backend->rename(p(QStringLiteral("one")), p(QStringLiteral("two")), RenameMode::Replace), Result::success());
    QVERIFY(!exists(m_backend.get(), p(QStringLiteral("one"))));
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("two")), &data), Result::success());
    QCOMPARE(data, one);

    // Plain moves in both modes, also into another folder.
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("dir")), true), Result::success());
    QCOMPARE(m_backend->rename(p(QStringLiteral("two")), p(QStringLiteral("three")), RenameMode::NoReplace), Result::success());
    QCOMPARE(m_backend->rename(p(QStringLiteral("three")), p(QStringLiteral("dir/four")), RenameMode::Replace), Result::success());
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("dir/four")), &data), Result::success());
    QCOMPARE(data, one);
    QCOMPARE(names(m_backend.get(), m_dir), QStringList { QStringLiteral("dir") });

    for (const RenameMode mode : { RenameMode::NoReplace, RenameMode::Replace }) {
        QCOMPARE(m_backend->rename(p(QStringLiteral("missing")), p(QStringLiteral("other")), mode), Result(Error::NotFound));
        QCOMPARE(m_backend->rename(p(QStringLiteral("dir/four")), p(QStringLiteral("nowhere/four")), mode), Result(Error::NotFound));
        QVERIFY(exists(m_backend.get(), p(QStringLiteral("dir/four"))));
    }
}

void TestConformance::renameFolders()
{
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("src")), true), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("src/inner")), "inner"), Result::success());
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("empty")), true), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("file")), "file"), Result::success());

    // XC-10: replacing a folder is AlreadyExists in both modes, even an
    // empty one, and whatever the source is.
    for (const RenameMode mode : { RenameMode::NoReplace, RenameMode::Replace }) {
        QCOMPARE(m_backend->rename(p(QStringLiteral("src")), p(QStringLiteral("empty")), mode), Result(Error::AlreadyExists));
        QCOMPARE(m_backend->rename(p(QStringLiteral("file")), p(QStringLiteral("empty")), mode), Result(Error::AlreadyExists));
        QVERIFY(exists(m_backend.get(), p(QStringLiteral("src/inner"))));
        QVERIFY(exists(m_backend.get(), p(QStringLiteral("file"))));
        QVERIFY(names(m_backend.get(), p(QStringLiteral("empty"))).isEmpty());
    }
    QCOMPARE(m_backend->rename(p(QStringLiteral("src")), p(QStringLiteral("file")), RenameMode::NoReplace), Result(Error::AlreadyExists));
    QVERIFY(exists(m_backend.get(), p(QStringLiteral("src/inner"))));

    QCOMPARE(m_backend->rename(p(QStringLiteral("src")), p(QStringLiteral("moved")), RenameMode::NoReplace), Result::success());
    QVERIFY(exists(m_backend.get(), p(QStringLiteral("moved/inner"))));
    QVERIFY(!exists(m_backend.get(), p(QStringLiteral("src"))));
    QCOMPARE(m_backend->rename(p(QStringLiteral("moved")), p(QStringLiteral("empty/moved")), RenameMode::Replace), Result::success());
    QVERIFY(exists(m_backend.get(), p(QStringLiteral("empty/moved/inner"))));
}

void TestConformance::renameCaseOnly()
{
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("CaseOnly.txt")), "case"), Result::success());
    // A case-only rename is not "replacing an existing entry", also where
    // the server compares names case-insensitively.
    QCOMPARE(m_backend->rename(p(QStringLiteral("CaseOnly.txt")), p(QStringLiteral("caseonly.txt")),
                               RenameMode::NoReplace), Result::success());
    QCOMPARE(names(m_backend.get(), m_dir), QStringList { QStringLiteral("caseonly.txt") });
    if (has(Capability::CaseInsensitive)) {
        Entry entry;
        QCOMPARE(m_backend->stat(p(QStringLiteral("CASEONLY.TXT")), &entry), Result::success());
        return;
    }
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("Upper")), "upper"), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("upper")), "lower"), Result::success());
    QCOMPARE(m_backend->rename(p(QStringLiteral("Upper")), p(QStringLiteral("upper")), RenameMode::NoReplace), Result(Error::AlreadyExists));
    QByteArray data;
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("upper")), &data), Result::success());
    QCOMPARE(data, QByteArray("lower"));
}

// --- names (XC-4) -------------------------------------------------------------

void TestConformance::namesUtf8()
{
    QStringList candidates = {
        QStringLiteral("ünïcödé €.txt"),
        QStringLiteral("日本語.txt"),
        QString::fromUtf8("emoji \xf0\x9f\x98\x80.txt"),
        QStringLiteral(".hidden"),
        QStringLiteral(" leading space"),
        QStringLiteral("trailing space "),
        QStringLiteral("a b  c"),
        QStringLiteral("#%&+;=@[]{}!$'(),~"),
        QStringLiteral("quote\"star*colon:"),
    };
    if (has(Capability::WindowsNames)) {
        QStringList allowed;
        for (const QString &name : candidates) {
            if (Paths::windowsComponentProblem(name).isEmpty())
                allowed.append(name);
        }
        candidates = allowed;
    }
    for (const QString &name : candidates) {
        const QString path = p(name);
        QCOMPARE(putFile(m_backend.get(), path, name.toUtf8()), Result::success());
        QVector<Entry> entries;
        QCOMPARE(m_backend->list(m_dir, &entries), Result::success());
        const Entry *listed = find(entries, name);
        QVERIFY2(listed, qPrintable(name));
        QVERIFY(!listed->flags.testFlag(EntryFlag::NameNotUtf8));
        QVERIFY(!listed->flags.testFlag(EntryFlag::Hidden));   // dot names are not flagged
        Entry entry;
        QCOMPARE(m_backend->stat(path, &entry), Result::success());
        QCOMPARE(entry.name, name);
        QByteArray data;
        QCOMPARE(getFile(m_backend.get(), path, &data), Result::success());
        QCOMPARE(data, name.toUtf8());
        QCOMPARE(m_backend->rename(path, path + QStringLiteral("2"), RenameMode::NoReplace), Result::success());
        QCOMPARE(m_backend->removeFile(path + QStringLiteral("2")), Result::success());
    }
    QVERIFY(names(m_backend.get(), m_dir).isEmpty());
}

void TestConformance::namesNormalization()
{
    // XC-4b: no NFC/NFD conversion; both spellings are two names.
    const QString nfc = QStringLiteral("é.txt");
    const QString nfd = QStringLiteral("é.txt");
    QCOMPARE(putFile(m_backend.get(), p(nfc), "nfc"), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(nfd), "nfd", WriteOptions::Disposition::CreateNew), Result::success());
    QStringList expected { nfc, nfd };
    expected.sort();
    QCOMPARE(names(m_backend.get(), m_dir), expected);
    QByteArray data;
    QCOMPARE(getFile(m_backend.get(), p(nfc), &data), Result::success());
    QCOMPARE(data, QByteArray("nfc"));
    QCOMPARE(getFile(m_backend.get(), p(nfd), &data), Result::success());
    QCOMPARE(data, QByteArray("nfd"));
}

void TestConformance::namesNonUtf8()
{
    if (has(Capability::WindowsNames))
        QSKIP("names are UTF-16 on this backend");
    const QString name = Names::decode(QByteArray("caf\xe9-\xff\xfe.txt"));
    const QString renamed = Names::decode(QByteArray("latin1-\xe4\xf6\xfc"));
    QVERIFY(Names::hasEscapes(name));
    const Result created = putFile(m_backend.get(), p(name), "bytes");
    if (!created.ok())
        QSKIP(qPrintable(QStringLiteral("the server refuses non-UTF-8 names: %1").arg(created.toString())));
    QVector<Entry> entries;
    QCOMPARE(m_backend->list(m_dir, &entries), Result::success());
    QCOMPARE(entries.size(), 1);
    QCOMPARE(entries.first().name, name);   // lossless round trip
    QVERIFY(entries.first().flags.testFlag(EntryFlag::NameNotUtf8));
    Entry entry;
    QCOMPARE(m_backend->stat(p(name), &entry), Result::success());
    QCOMPARE(entry.name, name);
    QVERIFY(entry.flags.testFlag(EntryFlag::NameNotUtf8));
    QByteArray data;
    QCOMPARE(getFile(m_backend.get(), p(name), &data), Result::success());
    QCOMPARE(data, QByteArray("bytes"));
    QCOMPARE(m_backend->rename(p(name), p(renamed), RenameMode::NoReplace), Result::success());
    QCOMPARE(names(m_backend.get(), m_dir), QStringList { renamed });
    QCOMPARE(m_backend->removeFile(p(renamed)), Result::success());
}

void TestConformance::namesLong()
{
    const int limit = m_caps.maxNameBytes > 0 ? static_cast<int>(qMin<qint64>(m_caps.maxNameBytes, 255)) : 255;
    const QString ascii = QString(limit - 4, QLatin1Char('a')) + QStringLiteral(".txt");
    const QString multibyte = QString(limit / 2, QChar(0x00e9));   // two bytes each
    for (const QString &name : { ascii, multibyte }) {
        QVERIFY(Names::encode(name).size() <= limit);
        QCOMPARE(putFile(m_backend.get(), p(name), "long"), Result::success());
        QVERIFY2(names(m_backend.get(), m_dir).contains(name), qPrintable(name));
        QCOMPARE(m_backend->removeFile(p(name)), Result::success());
    }
    if (m_caps.maxNameBytes > 0) {
        const QString tooLong(static_cast<int>(m_caps.maxNameBytes) + 1, QLatin1Char('b'));
        QVERIFY(!putFile(m_backend.get(), p(tooLong), "x").ok());
        QVERIFY(names(m_backend.get(), m_dir).isEmpty());
    }
}

void TestConformance::namesWindowsInvalid()
{
    if (!has(Capability::WindowsNames))
        QSKIP("no Windows name rules");
    for (const QString &name : { QStringLiteral("a:b.txt"), QStringLiteral("q?.txt"), QStringLiteral("trail."),
                                 QStringLiteral("trail "), QStringLiteral("pipe|.txt") }) {
        const Result r = putFile(m_backend.get(), p(name), "x");
        QVERIFY2(!r.ok(), qPrintable(name));
        QVERIFY(names(m_backend.get(), m_dir).isEmpty());
    }
}

// --- attributes (XC-11) -------------------------------------------------------

void TestConformance::setAttributes()
{
    const QString file = p(QStringLiteral("attr"));
    QCOMPARE(putFile(m_backend.get(), file, "attributes"), Result::success());
    Entry before;
    QCOMPARE(m_backend->stat(file, &before), Result::success());
    Entry entry;
    if (has(Capability::PosixModes)) {
        AttributeChanges mode;
        mode.mode = 0640;
        QCOMPARE(m_backend->setAttributes(file, mode), Result::success());
        QCOMPARE(m_backend->stat(file, &entry), Result::success());
        QCOMPARE(entry.mode, 0640);
        mode.mode = 0604;
        QCOMPARE(m_backend->setAttributes(file, mode), Result::success());
        QCOMPARE(m_backend->stat(file, &entry), Result::success());
        QCOMPARE(entry.mode, 0604);
    }
    if (has(Capability::SetModified)) {
        AttributeChanges times;
        times.modified = fixedTime();
        QCOMPARE(m_backend->setAttributes(file, times), Result::success());
        QCOMPARE(m_backend->stat(file, &entry), Result::success());
        QCOMPARE(seconds(entry.modified), seconds(fixedTime()));
        times.modified = QDateTime();
        times.accessed = fixedTime().addDays(1);
        if (m_backend->setAttributes(file, times).ok()) {
            QCOMPARE(m_backend->stat(file, &entry), Result::success());
            QCOMPARE(seconds(entry.modified), seconds(fixedTime()));   // left alone
            if (entry.accessed.isValid())
                QCOMPARE(seconds(entry.accessed), seconds(fixedTime().addDays(1)));
        }
    }
    QCOMPARE(m_backend->stat(file, &before), Result::success());
    // An invalid field fails the whole call before anything changes.
    AttributeChanges invalid;
    invalid.mode = 0170644;
    invalid.modified = fixedTime().addYears(5);
    QVERIFY(!m_backend->setAttributes(file, invalid).ok());
    QCOMPARE(m_backend->stat(file, &entry), Result::success());
    QCOMPARE(entry.modified, before.modified);
    QCOMPARE(entry.mode, before.mode);
    AttributeChanges any;
    any.modified = fixedTime();
    const Result missing = m_backend->setAttributes(p(QStringLiteral("missing")), any);
    QVERIFY2(missing.error() == Error::NotFound || missing.error() == Error::Unsupported, qPrintable(describe(missing)));
}

// --- links (XC-12) ------------------------------------------------------------

void TestConformance::checkLink(const QString &link, EntryType targetType)
{
    Entry itself;
    QCOMPARE(m_backend->lstat(link, &itself), Result::success());   // XC-7
    QCOMPARE(itself.type, EntryType::Symlink);
    if (itself.targetType != EntryType::Unknown)
        QCOMPARE(itself.targetType, targetType);
    Entry followed;
    QCOMPARE(m_backend->stat(link, &followed), Result::success());
    QCOMPARE(followed.type, targetType);
    ListOptions options;
    options.resolveSymlinkTypes = true;
    RecordingSink sink;
    QCOMPARE(m_backend->list(Paths::parent(link), &sink, options), Result::success());
    const Entry *listed = find(sink.all, Paths::fileName(link));
    QVERIFY(listed);
    QCOMPARE(listed->type, EntryType::Symlink);   // lstat semantics (XS-3, L-2)
    QCOMPARE(listed->targetType, targetType);
    QCOMPARE(listed->isDir(), targetType == EntryType::Directory);
    QCOMPARE(listed->isFile(), targetType == EntryType::File);
}

void TestConformance::symlinks()
{
    if (!has(Capability::Symlinks))
        QSKIP("Symlinks not reported");
    const QByteArray data = pattern(500, 3);
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("target.txt")), data), Result::success());
    QCOMPARE(m_backend->makeSymlink(QStringLiteral("target.txt"), p(QStringLiteral("link"))), Result::success());
    QString target;
    QCOMPARE(m_backend->readLink(p(QStringLiteral("link")), &target), Result::success());
    QCOMPARE(target, QStringLiteral("target.txt"));   // verbatim
    checkLink(p(QStringLiteral("link")), EntryType::File);
    Entry followed;
    QCOMPARE(m_backend->stat(p(QStringLiteral("link")), &followed), Result::success());
    QCOMPARE(followed.size, qint64(data.size()));
    QByteArray read;
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("link")), &read), Result::success());
    QCOMPARE(read, data);
    QCOMPARE(m_backend->makeSymlink(QStringLiteral("other"), p(QStringLiteral("link"))), Result(Error::AlreadyExists));
    QVERIFY(!m_backend->readLink(p(QStringLiteral("target.txt")), &target).ok());
    QCOMPARE(m_backend->removeFile(p(QStringLiteral("link"))), Result::success());   // the link, not the target
    QCOMPARE(names(m_backend.get(), m_dir), QStringList { QStringLiteral("target.txt") });
}

void TestConformance::symlinkFolder()
{
    if (!has(Capability::Symlinks))
        QSKIP("Symlinks not reported");
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("real")), true), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("real/inner")), "inner"), Result::success());
    QCOMPARE(m_backend->makeSymlink(QStringLiteral("real"), p(QStringLiteral("dirlink"))), Result::success());
    checkLink(p(QStringLiteral("dirlink")), EntryType::Directory);
    QCOMPARE(names(m_backend.get(), p(QStringLiteral("dirlink"))), QStringList { QStringLiteral("inner") });
    QVERIFY(!m_backend->removeDir(p(QStringLiteral("dirlink"))).ok());
    QVERIFY(exists(m_backend.get(), p(QStringLiteral("real/inner"))));
    QCOMPARE(m_backend->removeFile(p(QStringLiteral("dirlink"))), Result::success());
    QVERIFY(exists(m_backend.get(), p(QStringLiteral("real/inner"))));
    QVERIFY(!exists(m_backend.get(), p(QStringLiteral("dirlink"))));
}

void TestConformance::symlinkDangling()
{
    if (!has(Capability::Symlinks))
        QSKIP("Symlinks not reported");
    QCOMPARE(m_backend->makeSymlink(QStringLiteral("nowhere"), p(QStringLiteral("dangling"))), Result::success());
    Entry entry;
    QCOMPARE(m_backend->lstat(p(QStringLiteral("dangling")), &entry), Result::success());
    QCOMPARE(entry.type, EntryType::Symlink);
    QCOMPARE(m_backend->stat(p(QStringLiteral("dangling")), &entry), Result(Error::NotFound));
    ListOptions options;
    options.resolveSymlinkTypes = true;
    RecordingSink sink;
    QCOMPARE(m_backend->list(m_dir, &sink, options), Result::success());
    QCOMPARE(sink.all.size(), 1);
    QCOMPARE(sink.all.first().type, EntryType::Symlink);
    QCOMPARE(sink.all.first().targetType, EntryType::Unknown);
    QVERIFY(!sink.all.first().isDir() && !sink.all.first().isFile());
    QString target;
    QCOMPARE(m_backend->readLink(p(QStringLiteral("dangling")), &target), Result::success());
    QCOMPARE(target, QStringLiteral("nowhere"));
    QCOMPARE(m_backend->removeFile(p(QStringLiteral("dangling"))), Result::success());
}

void TestConformance::symlinkLoop()
{
    if (!has(Capability::Symlinks))
        QSKIP("Symlinks not reported");
    QCOMPARE(m_backend->makeSymlink(QStringLiteral("b"), p(QStringLiteral("a"))), Result::success());
    QCOMPARE(m_backend->makeSymlink(QStringLiteral("a"), p(QStringLiteral("b"))), Result::success());
    Entry entry;
    QCOMPARE(m_backend->lstat(p(QStringLiteral("a")), &entry), Result::success());
    QCOMPARE(entry.type, EntryType::Symlink);
    QVERIFY(!m_backend->stat(p(QStringLiteral("a")), &entry).ok());
    ListOptions options;
    options.resolveSymlinkTypes = true;
    RecordingSink sink;
    QCOMPARE(m_backend->list(m_dir, &sink, options), Result::success());
    QCOMPARE(sink.all.size(), 2);
    for (const Entry &e : sink.all) {
        QCOMPARE(e.type, EntryType::Symlink);
        QCOMPARE(e.targetType, EntryType::Unknown);
    }
    QByteArray data;
    QVERIFY(!getFile(m_backend.get(), p(QStringLiteral("a")), &data).ok());
}

void TestConformance::hardlinks()
{
    if (!has(Capability::Hardlinks))
        QSKIP("Hardlinks not reported");
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("file")), "first"), Result::success());
    QCOMPARE(m_backend->makeHardlink(p(QStringLiteral("file")), p(QStringLiteral("hard"))), Result::success());
    QCOMPARE(m_backend->makeHardlink(p(QStringLiteral("file")), p(QStringLiteral("hard"))), Result(Error::AlreadyExists));
    QByteArray data;
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("hard")), &data), Result::success());
    QCOMPARE(data, QByteArray("first"));
    // One file under two names: a write through one shows through the other.
    WriteHandle *raw = nullptr;
    WriteOptions options;
    options.disposition = WriteOptions::Disposition::Truncate;
    const Result opened = m_backend->openWrite(p(QStringLiteral("hard")), options, &raw);
    std::unique_ptr<WriteHandle> handle(raw);
    if (opened.ok()) {
        QCOMPARE(handle->write("second", 6), Result::success());
        QCOMPARE(handle->commit(), Result::success());
        QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("file")), &data), Result::success());
        QCOMPARE(data, QByteArray("second"));
    }
    // Renaming one link onto the other: NoReplace refuses, Replace leaves one name.
    QCOMPARE(m_backend->rename(p(QStringLiteral("hard")), p(QStringLiteral("file")), RenameMode::NoReplace), Result(Error::AlreadyExists));
    QCOMPARE(names(m_backend.get(), m_dir).size(), 2);
    QCOMPARE(m_backend->rename(p(QStringLiteral("hard")), p(QStringLiteral("file")), RenameMode::Replace), Result::success());
    QCOMPARE(names(m_backend.get(), m_dir), QStringList { QStringLiteral("file") });
}

// --- handles and transfers (XC-13, XC-14) -------------------------------------

void TestConformance::readHandle()
{
    if (!has(Capability::ReadHandles))
        QSKIP("ReadHandles not reported");
    const QByteArray data = pattern(3 * MiB + 17, 4);
    const qint64 n = data.size();
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("data")), data), Result::success());
    ReadHandle *raw = nullptr;
    QCOMPARE(m_backend->openRead(p(QStringLiteral("data")), &raw), Result::success());
    std::unique_ptr<ReadHandle> handle(raw);
    QVERIFY(handle);
    QCOMPARE(handle->size(), n);
    QByteArray chunk;
    QCOMPARE(handle->read(0, 1000, &chunk), Result::success());
    QCOMPARE(chunk, data.left(1000));
    QCOMPARE(handle->read(n - 10, 100, &chunk), Result::success());   // short read only at EOF
    QCOMPARE(chunk, data.right(10));
    QCOMPARE(handle->read(n, 10, &chunk), Result::success());
    QVERIFY(chunk.isEmpty());
    QCOMPARE(handle->read(n + 5, 10, &chunk), Result::success());
    QVERIFY(chunk.isEmpty());
    QCOMPARE(handle->read(5, 0, &chunk), Result::success());
    QVERIFY(chunk.isEmpty());
    handle->readAhead(MiB, MiB);
    QCOMPARE(handle->read(MiB + 3, 2 * MiB, &chunk), Result::success());   // spans protocol chunks
    QCOMPARE(chunk, data.mid(MiB + 3, 2 * MiB));
    QByteArray all;
    for (qint64 offset = 0; offset < n; offset += MiB) {
        QCOMPARE(handle->read(offset, MiB, &chunk), Result::success());
        all += chunk;
    }
    QCOMPARE(all, data);
    QCOMPARE(handle->close(), Result::success());

    QCOMPARE(m_backend->openRead(p(QStringLiteral("missing")), &raw), Result(Error::NotFound));
    QVERIFY(!raw);
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("dir")), true), Result::success());
    QVERIFY(!m_backend->openRead(p(QStringLiteral("dir")), &raw).ok());
    QVERIFY(!raw);
}

void TestConformance::readHelper()
{
    const QByteArray data = pattern(1000, 5);
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("data")), data), Result::success());
    QByteArray out;
    const Result first = m_backend->read(p(QStringLiteral("data")), 0, 10, &out);
    if (first.error() == Error::Unsupported)
        QSKIP("no read handles");
    QCOMPARE(first, Result::success());
    QCOMPARE(out, data.left(10));
    QCOMPARE(m_backend->read(p(QStringLiteral("data")), 990, 100, &out), Result::success());
    QCOMPARE(out, data.right(10));
    QCOMPARE(m_backend->read(p(QStringLiteral("data")), 1000, 10, &out), Result::success());
    QVERIFY(out.isEmpty());
    QCOMPARE(m_backend->read(p(QStringLiteral("data")), 2000, -1, &out), Result::success());
    QVERIFY(out.isEmpty());
    QCOMPARE(m_backend->read(p(QStringLiteral("data")), 100, -1, &out), Result::success());
    QCOMPARE(out, data.mid(100));
    QCOMPARE(m_backend->read(p(QStringLiteral("data")), 0, 0, &out), Result::success());
    QVERIFY(out.isEmpty());
}

void TestConformance::downloadRanges()
{
    const QByteArray data = pattern(MiB + 999, 6);
    const qint64 n = data.size();
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("data")), data), Result::success());
    QByteArray out;
    QCOMPARE(download(m_backend.get(), p(QStringLiteral("data")), 5, 10, &out), Result::success());
    QCOMPARE(out, data.mid(5, 10));
    QCOMPARE(download(m_backend.get(), p(QStringLiteral("data")), n - 10, -1, &out), Result::success());
    QCOMPARE(out, data.right(10));
    QCOMPARE(download(m_backend.get(), p(QStringLiteral("data")), n - 10, 100, &out), Result::success());
    QCOMPARE(out, data.right(10));
    QCOMPARE(download(m_backend.get(), p(QStringLiteral("data")), n, -1, &out), Result::success());
    QVERIFY(out.isEmpty());
    QCOMPARE(download(m_backend.get(), p(QStringLiteral("data")), n + 100, 10, &out), Result::success());
    QVERIFY(out.isEmpty());
    QCOMPARE(download(m_backend.get(), p(QStringLiteral("data")), 7, 0, &out), Result::success());
    QVERIFY(out.isEmpty());
    QCOMPARE(download(m_backend.get(), p(QStringLiteral("data")), MiB - 1, 2, &out), Result::success());   // across a chunk edge
    QCOMPARE(out, data.mid(MiB - 1, 2));
}

void TestConformance::writeHandle()
{
    WriteHandle *raw = nullptr;
    WriteOptions options;
    const Result opened = m_backend->openWrite(p(QStringLiteral("written")), options, &raw);
    if (opened.error() == Error::Unsupported)
        QSKIP("no write handles");
    QCOMPARE(opened, Result::success());
    std::unique_ptr<WriteHandle> handle(raw);
    const QByteArray data = pattern(2 * MiB + 3, 7);
    QCOMPARE(handle->write(data.constData(), MiB), Result::success());
    QCOMPARE(handle->position(), qint64(MiB));
    QCOMPARE(handle->write(data.constData() + MiB, data.size() - MiB), Result::success());
    QCOMPARE(handle->position(), qint64(data.size()));
    QCOMPARE(handle->commit(), Result::success());
    handle.reset();
    QByteArray read;
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("written")), &read), Result::success());
    QCOMPARE(read, data);

    // CreateNew on an existing file: AlreadyExists, content unchanged.
    QCOMPARE(m_backend->openWrite(p(QStringLiteral("written")), options, &raw), Result(Error::AlreadyExists));
    QVERIFY(!raw);
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("written")), &read), Result::success());
    QCOMPARE(read, data);

    options.disposition = WriteOptions::Disposition::Truncate;
    options.createMode = 0600;
    QCOMPARE(m_backend->openWrite(p(QStringLiteral("written")), options, &raw), Result::success());
    handle.reset(raw);
    QCOMPARE(handle->write("short", 5), Result::success());
    QCOMPARE(handle->commit(), Result::success());
    handle.reset();
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("written")), &read), Result::success());
    QCOMPARE(read, QByteArray("short"));

    // XC-23: an explicit mode for new files (backups pass 0600).
    QCOMPARE(m_backend->openWrite(p(QStringLiteral("private")), options, &raw), Result::success());
    handle.reset(raw);
    QCOMPARE(handle->commit(), Result::success());
    handle.reset();
    Entry entry;
    QCOMPARE(m_backend->stat(p(QStringLiteral("private")), &entry), Result::success());
    QCOMPARE(entry.size, qint64(0));
    if (has(Capability::PosixModes))
        QCOMPARE(entry.mode, 0600);

    // abort(): closes without commit; whatever was written may remain.
    options.disposition = WriteOptions::Disposition::CreateNew;
    QCOMPARE(m_backend->openWrite(p(QStringLiteral("aborted")), options, &raw), Result::success());
    handle.reset(raw);
    QCOMPARE(handle->write("partial", 7), Result::success());
    handle->abort();
    handle.reset();
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("dir")), true), Result::success());
    options.disposition = WriteOptions::Disposition::Truncate;
    QVERIFY(!m_backend->openWrite(p(QStringLiteral("dir")), options, &raw).ok());
    QVERIFY(!raw);
}

void TestConformance::writeResume()
{
    if (!has(Capability::WriteResume))
        QSKIP("WriteResume not reported");
    const QByteArray head = pattern(100, 8);
    const QByteArray tail = pattern(50, 9);
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("part")), head), Result::success());
    WriteHandle *raw = nullptr;
    WriteOptions options;
    options.disposition = WriteOptions::Disposition::Resume;
    QByteArray read;
    // Wrong offsets are refused before anything is written.
    for (const qint64 wrong : { qint64(99), qint64(101), qint64(0) }) {
        options.resumeOffset = wrong;
        const Result r = m_backend->openWrite(p(QStringLiteral("part")), options, &raw);
        std::unique_ptr<WriteHandle> refused(raw);
        QVERIFY2(!r.ok(), qPrintable(QString::number(wrong)));
        QVERIFY(!raw);
        QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("part")), &read), Result::success());
        QCOMPARE(read, head);
    }
    options.resumeOffset = head.size();
    QCOMPARE(m_backend->openWrite(p(QStringLiteral("part")), options, &raw), Result::success());
    std::unique_ptr<WriteHandle> handle(raw);
    QCOMPARE(handle->position(), qint64(head.size()));
    QCOMPARE(handle->write(tail.constData(), tail.size()), Result::success());
    QCOMPARE(handle->position(), qint64(head.size() + tail.size()));
    QCOMPARE(handle->commit(), Result::success());
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("part")), &read), Result::success());
    QCOMPARE(read, head + tail);

    // Through upload() as well.
    QBuffer more;
    more.setData(head);
    more.open(QIODevice::ReadOnly);
    UploadOptions upload;
    upload.write = options;
    upload.write.resumeOffset = head.size() + tail.size();
    QCOMPARE(m_backend->upload(&more, p(QStringLiteral("part")), upload, nullptr), Result::success());
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("part")), &read), Result::success());
    QCOMPARE(read, head + tail + head);

    options.resumeOffset = 0;
    QVERIFY(!m_backend->openWrite(p(QStringLiteral("missing")), options, &raw).ok());
    QVERIFY(!raw);
    QVERIFY(!exists(m_backend.get(), p(QStringLiteral("missing"))));
}

void TestConformance::handlesAfterDisconnect()
{
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("data")), "data"), Result::success());
    ReadHandle *reader = nullptr;
    const Result readable = m_backend->openRead(p(QStringLiteral("data")), &reader);
    std::unique_ptr<ReadHandle> readHandle(reader);
    WriteHandle *writer = nullptr;
    const Result writable = m_backend->openWrite(p(QStringLiteral("new")), WriteOptions(), &writer);
    std::unique_ptr<WriteHandle> writeHandle(writer);
    if (!readable.ok() && !writable.ok())
        QSKIP("no handles");
    m_backend->disconnect();   // XC-13: open handles die with the connection
    if (readHandle) {
        QByteArray out;
        QCOMPARE(readHandle->read(0, 4, &out), Result(Error::ConnectionLost));
    }
    if (writeHandle) {
        QCOMPARE(writeHandle->write("x", 1), Result(Error::ConnectionLost));
        QVERIFY(!writeHandle->commit().ok());
    }
}

void TestConformance::uploadDownload()
{
    const QByteArray data = pattern(3 * MiB + 7, 10);
    QBuffer source;
    source.setData(data);
    source.open(QIODevice::ReadOnly);
    RecordingProgress up;
    UploadOptions options;
    options.write.disposition = WriteOptions::Disposition::CreateNew;
    QCOMPARE(m_backend->upload(&source, p(QStringLiteral("big")), options, &up), Result::success());
    QVERIFY(!up.updates.isEmpty());
    QVERIFY(up.monotonic);
    QCOMPARE(up.updates.last().first, qint64(data.size()));

    QBuffer sink;
    sink.open(QIODevice::WriteOnly);
    RecordingProgress down;
    QCOMPARE(m_backend->download(p(QStringLiteral("big")), &sink, DownloadOptions(), &down), Result::success());
    QCOMPARE(sink.data(), data);
    QVERIFY(!down.updates.isEmpty());
    QVERIFY(down.monotonic);
    QCOMPARE(down.updates.last().first, qint64(data.size()));
    QVERIFY(down.updates.last().second == -1 || down.updates.last().second == data.size());

    // CreateNew refuses an existing file and leaves it alone.
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("big")), "small", WriteOptions::Disposition::CreateNew), Result(Error::AlreadyExists));
    QByteArray read;
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("big")), &read), Result::success());
    QCOMPARE(read, data);
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("big")), "small", WriteOptions::Disposition::Truncate), Result::success());
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("big")), &read), Result::success());
    QCOMPARE(read, QByteArray("small"));
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("empty")), QByteArray()), Result::success());
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("empty")), &read), Result::success());
    QVERIFY(read.isEmpty());

    QCOMPARE(m_backend->makeDir(p(QStringLiteral("dir")), true), Result::success());
    QVERIFY(!putFile(m_backend.get(), p(QStringLiteral("dir")), "x").ok());
    QVERIFY(names(m_backend.get(), p(QStringLiteral("dir"))).isEmpty());
    QVERIFY(!getFile(m_backend.get(), p(QStringLiteral("dir")), &read).ok());
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("missing")), &read), Result(Error::NotFound));
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("missing/file")), "x"), Result(Error::NotFound));
}

void TestConformance::uploadOptions()
{
    QBuffer source;
    source.setData("options");
    source.open(QIODevice::ReadOnly);
    UploadOptions options;
    options.write.createMode = 0600;
    options.write.modified = fixedTime();
    QCOMPARE(m_backend->upload(&source, p(QStringLiteral("opts")), options, nullptr), Result::success());
    Entry entry;
    QCOMPARE(m_backend->stat(p(QStringLiteral("opts")), &entry), Result::success());
    QCOMPARE(entry.size, qint64(7));
    if (has(Capability::PosixModes))
        QCOMPARE(entry.mode, 0600);
    if (has(Capability::SetModifiedOnUpload))
        QCOMPARE(seconds(entry.modified), seconds(fixedTime()));

    // XC-23: the default mode is the server's (umask applied); the owner
    // can always read and write a new file.
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("default")), "x", WriteOptions::Disposition::CreateNew), Result::success());
    QCOMPARE(m_backend->stat(p(QStringLiteral("default")), &entry), Result::success());
    if (has(Capability::PosixModes))
        QCOMPARE(entry.mode & 0600, 0600);
}

void TestConformance::progressCancel()
{
    const QByteArray data = pattern(4 * MiB, 11);
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("data")), data), Result::success());
    // XC-14: Progress::canceled() stops a transfer.
    QBuffer sink;
    sink.open(QIODevice::WriteOnly);
    RecordingProgress stop;
    stop.cancelAfterFirst = true;
    QCOMPARE(m_backend->download(p(QStringLiteral("data")), &sink, DownloadOptions(), &stop), Result(Error::Canceled));
    QVERIFY(sink.data().size() < data.size());
    QBuffer source;
    source.setData(data);
    source.open(QIODevice::ReadOnly);
    RecordingProgress stopUp;
    stopUp.cancelAfterFirst = true;
    QCOMPARE(m_backend->upload(&source, p(QStringLiteral("up")), UploadOptions(), &stopUp), Result(Error::Canceled));

    // cancel() from within the transfer (C-9).
    QBuffer sink2;
    sink2.open(QIODevice::WriteOnly);
    RecordingProgress cancelDown;
    cancelDown.cancelBackend = m_backend.get();
    QCOMPARE(m_backend->download(p(QStringLiteral("data")), &sink2, DownloadOptions(), &cancelDown), Result(Error::Canceled));
    QVERIFY(sink2.data().size() < data.size());
    m_backend->resetCancel();
    source.seek(0);
    RecordingProgress cancelUp;
    cancelUp.cancelBackend = m_backend.get();
    QCOMPARE(m_backend->upload(&source, p(QStringLiteral("up2")), UploadOptions(), &cancelUp), Result(Error::Canceled));
    m_backend->resetCancel();
    QCOMPARE(m_backend->keepAlive(), Result::success());
}

void TestConformance::largeSparseChecks(const QString &path, qint64 size, qint64 markerOffset, const QByteArray &marker)
{
    Entry entry;
    QCOMPARE(m_backend->stat(path, &entry), Result::success());
    QCOMPARE(entry.size, size);
    QVector<Entry> entries;
    QCOMPARE(m_backend->list(Paths::parent(path), &entries), Result::success());
    QVERIFY(find(entries, Paths::fileName(path)));
    QCOMPARE(find(entries, Paths::fileName(path))->size, size);
    QByteArray out;
    QCOMPARE(download(m_backend.get(), path, markerOffset, marker.size(), &out), Result::success());
    QCOMPARE(out, marker);
    QCOMPARE(download(m_backend.get(), path, size - 4, -1, &out), Result::success());
    QCOMPARE(out.size(), 4);
    if (has(Capability::ReadHandles)) {
        QCOMPARE(m_backend->read(path, markerOffset - 1, marker.size() + 2, &out), Result::success());
        QCOMPARE(out.mid(1, marker.size()), marker);
    }
    if (has(Capability::WriteResume)) {
        WriteOptions options;
        options.disposition = WriteOptions::Disposition::Resume;
        options.resumeOffset = size;
        WriteHandle *raw = nullptr;
        QCOMPARE(m_backend->openWrite(path, options, &raw), Result::success());
        std::unique_ptr<WriteHandle> handle(raw);
        QCOMPARE(handle->write("TAIL", 4), Result::success());
        QCOMPARE(handle->commit(), Result::success());
        QCOMPARE(download(m_backend.get(), path, size, -1, &out), Result::success());
        QCOMPARE(out, QByteArray("TAIL"));
    }
}

void TestConformance::largeSparse()
{
    const Heavy heavy = heavyMode();
    const qint64 size = FourGiB + 4096;
    const qint64 markerOffset = FourGiB + 100;
    const QByteArray marker("MARKER-BEYOND-4GIB");
    const QString path = p(QStringLiteral("large"));
    if (heavy == Heavy::Skip)
        QSKIP("heavy cases disabled (NETVFS_CONFORMANCE_HEAVY=0)");
    if (!m_target.hostPath.isEmpty()) {
        // Sparse where the folder is visible on this host: ftruncate().
        QFile file(hostPath(QStringLiteral("large")));
        QVERIFY(file.open(QIODevice::WriteOnly));
        QVERIFY(file.resize(size));
        QVERIFY(file.seek(markerOffset));
        QCOMPARE(file.write(marker), qint64(marker.size()));
        file.close();
    } else if (heavy == Heavy::Always) {
        ZeroDevice zeros(size, markerOffset, marker);
        UploadOptions options;
        options.write.expectedSize = size;
        QCOMPARE(m_backend->upload(&zeros, path, options, nullptr), Result::success());
    } else {
        QSKIP("a file > 4 GiB needs hostPath or NETVFS_CONFORMANCE_HEAVY=1");
    }
    largeSparseChecks(path, size, markerOffset, marker);
    QCOMPARE(m_backend->removeFile(path), Result::success());
}

// --- server-side work (XC-17..19) ---------------------------------------------

void TestConformance::copy()
{
    if (!has(Capability::ServerCopy))
        QSKIP("ServerCopy not reported");
    const QByteArray data = pattern(2 * MiB + 1, 12);
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("source")), data), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("existing")), "existing"), Result::success());
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("dir")), true), Result::success());
    CopyOptions options;
    QCOMPARE(m_backend->copy(p(QStringLiteral("source")), p(QStringLiteral("copy")), options), Result::success());
    QByteArray read;
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("copy")), &read), Result::success());
    QCOMPARE(read, data);
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("source")), &read), Result::success());
    QCOMPARE(read, data);

    QCOMPARE(m_backend->copy(p(QStringLiteral("source")), p(QStringLiteral("existing")), options), Result(Error::AlreadyExists));
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("existing")), &read), Result::success());
    QCOMPARE(read, QByteArray("existing"));
    for (const RenameMode mode : { RenameMode::NoReplace, RenameMode::Replace }) {
        options.mode = mode;
        QCOMPARE(m_backend->copy(p(QStringLiteral("source")), p(QStringLiteral("dir")), options), Result(Error::AlreadyExists));
        QVERIFY(names(m_backend.get(), p(QStringLiteral("dir"))).isEmpty());
        QCOMPARE(m_backend->copy(p(QStringLiteral("missing")), p(QStringLiteral("other")), options), Result(Error::NotFound));
        QVERIFY(!exists(m_backend.get(), p(QStringLiteral("other"))));
    }
    options.mode = RenameMode::Replace;
    QCOMPARE(m_backend->copy(p(QStringLiteral("source")), p(QStringLiteral("existing")), options), Result::success());
    QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("existing")), &read), Result::success());
    QCOMPARE(read, data);
    QStringList expected { QStringLiteral("copy"), QStringLiteral("dir"), QStringLiteral("existing"),
                           QStringLiteral("source") };
    QCOMPARE(names(m_backend.get(), m_dir), expected);   // no temporary leftovers

    if (has(Capability::ServerCopyRecursive)) {
        QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("dir/inner")), "inner"), Result::success());
        options.recursive = true;
        options.mode = RenameMode::NoReplace;
        QCOMPARE(m_backend->copy(p(QStringLiteral("dir")), p(QStringLiteral("dircopy")), options), Result::success());
        QCOMPARE(getFile(m_backend.get(), p(QStringLiteral("dircopy/inner")), &read), Result::success());
        QCOMPARE(read, QByteArray("inner"));
    }
}

void TestConformance::checksum()
{
    if (!has(Capability::Checksums))
        QSKIP("Checksums not reported");
    const QByteArray data = pattern(3 * MiB + 5, 13);
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("data")), data), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("empty")), QByteArray()), Result::success());
    const QMap<QString, QCryptographicHash::Algorithm> known = {
        { QStringLiteral("md5"), QCryptographicHash::Md5 },
        { QStringLiteral("sha1"), QCryptographicHash::Sha1 },
        { QStringLiteral("sha256"), QCryptographicHash::Sha256 },
        { QStringLiteral("sha512"), QCryptographicHash::Sha512 },
    };
    int compared = 0;
    for (const QString &algorithm : m_caps.checksumAlgorithms) {
        QByteArray digest;
        QCOMPARE(m_backend->checksum(p(QStringLiteral("data")), algorithm, &digest), Result::success());
        if (!known.contains(algorithm))
            continue;
        QCOMPARE(digest.toHex(), QCryptographicHash::hash(data, known.value(algorithm)).toHex());
        QCOMPARE(m_backend->checksum(p(QStringLiteral("empty")), algorithm, &digest), Result::success());
        QCOMPARE(digest.toHex(), QCryptographicHash::hash(QByteArray(), known.value(algorithm)).toHex());
        ++compared;
    }
    QVERIFY(compared > 0);
    const QString first = m_caps.checksumAlgorithms.first();
    QByteArray digest;
    QCOMPARE(m_backend->checksum(p(QStringLiteral("data")), QStringLiteral("no-such-digest"), &digest), Result(Error::Unsupported));
    QCOMPARE(m_backend->checksum(p(QStringLiteral("missing")), first, &digest), Result(Error::NotFound));
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("dir")), true), Result::success());
    QVERIFY(!m_backend->checksum(p(QStringLiteral("dir")), first, &digest).ok());
}

void TestConformance::spaceInfo()
{
    if (!has(Capability::SpaceInfo))
        QSKIP("SpaceInfo not reported");
    SpaceInfo info;
    QCOMPARE(m_backend->spaceInfo(m_dir, &info), Result::success());
    QVERIFY(info.free >= -1 && info.total >= -1 && info.used >= -1);
    QVERIFY(info.free >= 0 || info.total >= 0 || info.used >= 0);
    if (info.free >= 0 && info.total >= 0)
        QVERIFY(info.free <= info.total);
    if (info.used >= 0 && info.total >= 0)
        QVERIFY(info.used <= info.total);
    if (info.free >= 0) {
        qint64 free = -1;
        QCOMPARE(m_backend->freeSpace(m_dir, &free), Result::success());
        QVERIFY(free >= 0);
    }
    QCOMPARE(m_backend->spaceInfo(p(QStringLiteral("missing")), &info), Result(Error::NotFound));
}

// --- unsupported means no side effects (XT-1) ---------------------------------

void TestConformance::expectUnsupported(Capability c, const std::function<Result()> &call)
{
    if (has(c))
        return;
    const QMap<QString, QString> before = snapshot(m_backend.get(), m_dir);
    const Result r = call();
    QVERIFY2(r.error() == Error::Unsupported,
             qPrintable(QStringLiteral("%1 not reported, got %2").arg(capabilityName(c), describe(r))));
    QCOMPARE(snapshot(m_backend.get(), m_dir), before);
}

void TestConformance::unsupportedWithoutSideEffects()
{
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("file")), "content"), Result::success());
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("dir")), true), Result::success());
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("dir/inner")), "inner"), Result::success());
    AttributeChanges time;
    time.modified = fixedTime();
    AttributeChanges modeAndTime = time;
    modeAndTime.mode = 0600;

    expectUnsupported(Capability::Symlinks, [&]() {
        return m_backend->makeSymlink(QStringLiteral("file"), p(QStringLiteral("link")));
    });
    expectUnsupported(Capability::Symlinks, [&]() {
        QString target;
        return m_backend->readLink(p(QStringLiteral("file")), &target);
    });
    expectUnsupported(Capability::Hardlinks, [&]() {
        return m_backend->makeHardlink(p(QStringLiteral("file")), p(QStringLiteral("hard")));
    });
    expectUnsupported(Capability::PosixModes, [&]() {
        return m_backend->setAttributes(p(QStringLiteral("file")), modeAndTime);   // the time must not change either
    });
    expectUnsupported(Capability::SetModified, [&]() { return m_backend->setAttributes(p(QStringLiteral("file")), time); });
    expectUnsupported(Capability::ReadHandles, [&]() {
        ReadHandle *raw = nullptr;
        const Result r = m_backend->openRead(p(QStringLiteral("file")), &raw);
        std::unique_ptr<ReadHandle> handle(raw);
        return handle ? Result(Error::Internal, QStringLiteral("a handle came back")) : r;
    });
    expectUnsupported(Capability::WriteResume, [&]() {
        WriteOptions options;
        options.disposition = WriteOptions::Disposition::Resume;
        options.resumeOffset = 7;
        WriteHandle *raw = nullptr;
        const Result r = m_backend->openWrite(p(QStringLiteral("file")), options, &raw);
        std::unique_ptr<WriteHandle> handle(raw);
        return r;
    });
    CopyOptions copy;
    expectUnsupported(Capability::ServerCopy, [&]() {
        return m_backend->copy(p(QStringLiteral("file")), p(QStringLiteral("copy")), copy);
    });
    expectUnsupported(Capability::ServerCopyRecursive, [&]() {
        CopyOptions recursive;
        recursive.recursive = true;
        return m_backend->copy(p(QStringLiteral("dir")), p(QStringLiteral("dircopy")), recursive);
    });
    expectUnsupported(Capability::RecursiveDelete, [&]() { return m_backend->removeTreeNative(p(QStringLiteral("dir"))); });
    expectUnsupported(Capability::SpaceInfo, [&]() {
        SpaceInfo info;
        return m_backend->spaceInfo(m_dir, &info);
    });
    expectUnsupported(Capability::Checksums, [&]() {
        QByteArray digest;
        return m_backend->checksum(p(QStringLiteral("file")), QStringLiteral("sha256"), &digest);
    });
    // XC-18: an algorithm that is not listed is Unsupported as well.
    const QMap<QString, QString> before = snapshot(m_backend.get(), m_dir);
    QByteArray digest;
    QCOMPARE(m_backend->checksum(p(QStringLiteral("file")), QStringLiteral("crc-unlisted"), &digest), Result(Error::Unsupported));
    QCOMPARE(snapshot(m_backend.get(), m_dir), before);
}

// --- cancel under a stall (C-9, C-14) -----------------------------------------

void TestConformance::runFifoStall(const QString &what, const std::function<Result()> &call)
{
    qint64 elapsed = -1;
    const Result r = runCanceled(m_backend.get(), CancelDelayMs, call, &elapsed);
    QVERIFY2(r.error() == Error::Canceled, qPrintable(QStringLiteral("%1: %2").arg(what, describe(r))));
    QVERIFY2(elapsed >= 0 && elapsed <= CancelLimitMs, qPrintable(QStringLiteral("%1: %2 ms").arg(what).arg(elapsed)));
    m_backend->resetCancel();
}

void TestConformance::cancelStalledFifo()
{
    if (!m_target.fifoStall)
        QSKIP("no FIFO stall for this target");
    const FifoStall fifo(hostPath(QStringLiteral("stall")));
    QVERIFY(fifo.isOpen());
    const QString path = p(QStringLiteral("stall"));

    runFifoStall(QStringLiteral("download"), [&]() {
        QBuffer sink;
        sink.open(QIODevice::WriteOnly);
        return m_backend->download(path, &sink, DownloadOptions(), nullptr);
    });
    if (QTest::currentTestFailed())
        return;
    ReadHandle *reader = nullptr;
    if (m_backend->openRead(path, &reader).ok()) {
        std::unique_ptr<ReadHandle> handle(reader);
        runFifoStall(QStringLiteral("ReadHandle::read"), [&]() {
            QByteArray out;
            return handle->read(0, 100, &out);
        });
        if (QTest::currentTestFailed())
            return;
    }
    if (has(Capability::Checksums)) {
        runFifoStall(QStringLiteral("checksum"), [&]() {
            QByteArray digest;
            return m_backend->checksum(path, m_caps.checksumAlgorithms.first(), &digest);
        });
        if (QTest::currentTestFailed())
            return;
    }
    const QByteArray data(StallBytes, 'x');
    runFifoStall(QStringLiteral("upload"), [&]() { return putFile(m_backend.get(), path, data); });
    if (QTest::currentTestFailed())
        return;
    WriteOptions options;
    options.disposition = WriteOptions::Disposition::Truncate;
    WriteHandle *writer = nullptr;
    if (m_backend->openWrite(path, options, &writer).ok()) {
        std::unique_ptr<WriteHandle> handle(writer);
        runFifoStall(QStringLiteral("WriteHandle::write"), [&]() { return handle->write(data.constData(), data.size()); });
    }
}

void TestConformance::stallTimeoutFifo()
{
    if (!m_target.fifoStall)
        QSKIP("no FIFO stall for this target");
    const FifoStall fifo(hostPath(QStringLiteral("stall")));
    QVERIFY(fifo.isOpen());
    // C-14: the request timeout ends a wait nobody cancels.
    ConnectionParams params = m_target.params;
    params.requestTimeoutMs = TimeoutMs;
    Result r;
    const std::unique_ptr<Backend> backend = connectTo(params, &r);
    QVERIFY2(backend, qPrintable(r.toString()));
    QElapsedTimer timer;
    timer.start();
    QBuffer sink;
    sink.open(QIODevice::WriteOnly);
    QCOMPARE(backend->download(p(QStringLiteral("stall")), &sink, DownloadOptions(), nullptr), Result(Error::Timeout));
    QVERIFY(timer.elapsed() >= TimeoutMs);
    QVERIFY(timer.elapsed() < TimeoutMs + CancelLimitMs);
}

void TestConformance::cancelStalledProxy()
{
    const StallProxy &proxy = m_target.stallProxy;
    if (!proxy.enabled)
        QSKIP("no stall proxy configured for this target");
    QCOMPARE(putFile(m_backend.get(), p(QStringLiteral("file")), pattern(MiB, 14)), Result::success());
    QCOMPARE(m_backend->makeDir(p(QStringLiteral("dir")), true), Result::success());
    struct Case {
        const char *name;
        std::function<Result(Backend *)> call;
    };
    const QString file = p(QStringLiteral("file"));
    const QVector<Case> cases = {
        { "stat", [&](Backend *b) { Entry e; return b->stat(file, &e); } },
        { "lstat", [&](Backend *b) { Entry e; return b->lstat(file, &e); } },
        { "list", [&](Backend *b) { QVector<Entry> e; return b->list(m_dir, &e); } },
        { "makeDir", [&](Backend *b) { return b->makeDir(p(QStringLiteral("new")), true); } },
        { "removeDir", [&](Backend *b) { return b->removeDir(p(QStringLiteral("dir"))); } },
        { "rename", [&](Backend *b) { return b->rename(file, p(QStringLiteral("renamed")), RenameMode::NoReplace); } },
        { "download", [&](Backend *b) {
              QBuffer sink;
              sink.open(QIODevice::WriteOnly);
              return b->download(file, &sink, DownloadOptions(), nullptr);
          } },
        { "upload", [&](Backend *b) { return putFile(b, p(QStringLiteral("up")), pattern(MiB, 15)); } },
        { "keepAlive", [&](Backend *b) { return b->keepAlive(); } },
    };
    for (const Case &c : cases) {
        Result r;
        const std::unique_ptr<Backend> backend = connectTo(proxy.params, &r);
        QVERIFY2(backend, qPrintable(r.toString()));
        QString output;
        if (!proxy.engage.isEmpty())
            QVERIFY2(runShell(proxy.engage, &output), qPrintable(output));
        qint64 elapsed = -1;
        r = runCanceled(backend.get(), CancelDelayMs, [&]() { return c.call(backend.get()); }, &elapsed);
        if (!proxy.release.isEmpty())
            QVERIFY2(runShell(proxy.release, &output), qPrintable(output));
        QVERIFY2(r.error() == Error::Canceled, qPrintable(QStringLiteral("%1: %2").arg(QLatin1String(c.name), describe(r))));
        QVERIFY2(elapsed <= CancelLimitMs, qPrintable(QStringLiteral("%1: %2 ms").arg(QLatin1String(c.name)).arg(elapsed)));
    }
}

// --- main ---------------------------------------------------------------------

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (qEnvironmentVariableIsEmpty("NETVFS_BACKEND_PATH"))
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_BACKEND_DIR);
    QTemporaryDir scratch;
    QVector<Target> targets;
    QString error;
    if (!scratch.isValid() || !loadTargets(scratch.path(), &targets, &error)) {
        qCritical("%s", qPrintable(error));
        return 1;
    }
    int failures = 0;
    for (const Target &target : targets) {
        TestConformance test(target);
        failures += QTest::qExec(&test, app.arguments());
    }
    return failures == 0 ? 0 : 1;
}

#include "tst_conformance.moc"
