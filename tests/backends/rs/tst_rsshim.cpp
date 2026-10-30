// SPDX-License-Identifier: LGPL-2.1-or-later
// Shim of the Rust backends (src/backends/rs) against libnetvfs-rs.so with its mem backend: loading,
// BackendFactory via libnetvfs-mem.so, conversions, callbacks (sink, prompter, progress, local side of
// transfers) and what they throw, cancel, one call at a time, panics. Operations are covered by the
// conformance suite on mem.
#include "backendloader.h"
#include "names.h"
#include "rsbackend.h"
#include "rsloader.h"

#include <QtConcurrent/QtConcurrent>
#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QElapsedTimer>
#include <QtCore/QPluginLoader>
#include <QtTest/QtTest>

#include <condition_variable>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace NetVfs;

namespace NetVfs {
// QCOMPARE(result, Result(Error::X)) compares the error only and prints the whole result on failure.
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

constexpr qint64 CancelLimitMs = 2000;
constexpr int CancelDelayMs = 300;
const QString Busy = QStringLiteral("The connection is busy: one call at a time, none from a callback");
const QString CallbackFailed = QStringLiteral("A callback of the Rust backend failed");

QByteArray pattern(int size)
{
    QByteArray data(size, Qt::Uninitialized);
    for (int i = 0; i < size; ++i)
        data[i] = static_cast<char>((i * 7 + i / 251) & 0xff);
    return data;
}

QDateTime fixedTime()
{
    return QDateTime(QDate(2001, 2, 3), QTime(4, 5, 6, 789), Qt::UTC);
}

ConnectionParams memParams(QVariantMap options = {})
{
    ConnectionParams params;
    params.provider = QStringLiteral("mem");
    params.username = QStringLiteral("tester");
    if (!options.contains(QStringLiteral("store")))
        options.insert(QStringLiteral("store"), QString::fromLatin1(QTest::currentTestFunction()));
    params.options = options;
    return params;
}

std::unique_ptr<Backend> newBackend(Result *result)
{
    Backend *raw = nullptr;
    *result = Rs::createBackend(QStringLiteral("mem"), &raw);
    return std::unique_ptr<Backend>(raw);
}

std::unique_ptr<Backend> connected(const QVariantMap &options = {})
{
    Result r;
    std::unique_ptr<Backend> backend = newBackend(&r);
    if (!backend || !backend->connect(memParams(options), nullptr).ok()
        || !backend->authenticate(Credentials(QStringLiteral("tester"), QByteArray())).ok())
        return nullptr;
    return backend;
}

Result put(Backend *backend, const QString &path, const QByteArray &data)
{
    QBuffer source;
    source.setData(data);
    source.open(QIODevice::ReadOnly);
    UploadOptions options;
    options.write.disposition = WriteOptions::Disposition::Truncate;
    return backend->upload(&source, path, options, nullptr);
}

Result get(Backend *backend, const QString &path, QByteArray *data, qint64 offset = 0, qint64 length = -1)
{
    QBuffer sink;
    sink.open(QIODevice::WriteOnly);
    DownloadOptions options;
    options.offset = offset;
    options.length = length;
    const Result r = backend->download(path, &sink, options, nullptr);
    *data = sink.data();
    return r;
}

SshKeyTools *memKeyTools()
{
    QPluginLoader loader(QStringLiteral(NETVFS_TEST_FAKE_BACKEND_DIR "/libnetvfs-mem.so"));
    return qobject_cast<SshKeyTools *>(loader.instance());
}

class Sink : public ListSink
{
public:
    bool entries(const QVector<Entry> &batch) override
    {
        if (throwOnBatch)
            throw std::runtime_error("sink failed");
        sizes << batch.size();
        all += batch;
        if (backend) {
            Entry entry;
            inner = backend->stat(QStringLiteral("a"), &entry);
            innerCapabilities = backend->capabilities();
        }
        return stopAfter < 0 || sizes.size() < stopAfter;
    }

    QVector<int> sizes;
    QVector<Entry> all;
    int stopAfter = -1;
    bool throwOnBatch = false;
    Backend *backend = nullptr;
    Result inner;
    Capabilities innerCapabilities;
};

class Prompter : public AuthPrompter
{
public:
    bool answer(const QString &name, const QString &instruction, const QVector<AuthPrompt> &prompts,
                QVector<QByteArray> *answers) override
    {
        ++calls;
        seenName = name;
        seenInstruction = instruction;
        seenPrompts = prompts;
        if (throwIt)
            throw std::runtime_error("prompter failed");
        if (waitForCancel) {
            std::unique_lock<std::mutex> lock(mutex);
            waiting = true;
            woken.notify_all();
            woken.wait_for(lock, std::chrono::seconds(10), [this]() { return canceled; });
            return false;
        }
        *answers = reply;
        return give;
    }

    void cancel() override
    {
        const std::scoped_lock lock(mutex);
        canceled = true;
        woken.notify_all();
    }

    void waitUntilAsked()
    {
        std::unique_lock<std::mutex> lock(mutex);
        woken.wait_for(lock, std::chrono::seconds(10), [this]() { return waiting; });
    }

    int calls = 0;
    QString seenName;
    QString seenInstruction;
    QVector<AuthPrompt> seenPrompts;
    QVector<QByteArray> reply;
    bool give = true;
    bool throwIt = false;
    bool waitForCancel = false;
    std::mutex mutex;
    std::condition_variable woken;
    bool waiting = false;
    bool canceled = false;
};

class Watch : public Progress
{
public:
    void update(qint64 done, qint64 total) override
    {
        if (throwOnUpdate)
            throw std::runtime_error("progress failed");
        updates.append(qMakePair(done, total));
    }
    bool canceled() const override
    {
        if (throwOnCanceled)
            throw std::runtime_error("progress failed");
        return stop;
    }

    QVector<QPair<qint64, qint64>> updates;
    bool stop = false;
    bool throwOnUpdate = false;
    bool throwOnCanceled = false;
};

class Device : public QIODevice
{
public:
    enum class Mode { Works, Fails, Throws };
    explicit Device(Mode mode, const QByteArray &data = QByteArray()) : m_mode(mode), m_data(data) {}

    bool isSequential() const override { return true; }
    QByteArray written;

protected:
    qint64 readData(char *data, qint64 maxSize) override
    {
        check();
        if (m_mode == Mode::Fails)
            return -1;
        const qint64 n = qMin<qint64>(maxSize, m_data.size() - m_at);
        std::memcpy(data, m_data.constData() + m_at, static_cast<size_t>(n));
        m_at += n;
        return n;
    }
    qint64 writeData(const char *data, qint64 size) override
    {
        check();
        if (m_mode == Mode::Fails)
            return -1;
        written.append(data, static_cast<int>(size));
        return size;
    }

private:
    void check() const
    {
        if (m_mode == Mode::Throws)
            throw std::runtime_error("device failed");
    }

    Mode m_mode;
    QByteArray m_data;
    qint64 m_at = 0;
};

Result canceledAfterDelay(Backend *backend, const std::function<Result()> &call, qint64 *afterCancelMs)
{
    QElapsedTimer clock;
    clock.start();
    std::thread canceler([backend]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(CancelDelayMs));
        backend->cancel();
    });
    const Result r = call();
    *afterCancelMs = clock.elapsed() - CancelDelayMs;
    canceler.join();
    return r;
}

} // namespace

class tst_RsShim : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void missingLibrary();
    void plugin();
    void unknownProvider();
    void establish();
    void prompts();
    void cancelWakesPrompter();
    void entries();
    void names();
    void listing();
    void namespaceCalls();
    void readHandles();
    void writeHandles();
    void transfers();
    void transferFailures();
    void cancel();
    void oneCallAtATime();
    void panics();
    void otherThreads();
};

void tst_RsShim::initTestCase()
{
    qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
}

void tst_RsShim::missingLibrary()
{
    // the plugin is there, the library is not.
    qputenv("NETVFS_RS_LIB", "/nonexistent/libnetvfs-rs.so");
    QVERIFY(BackendLoader::isAvailable(QStringLiteral("mem")));
    Result r;
    std::unique_ptr<Backend> backend(BackendLoader::create(QStringLiteral("mem"), &r));
    QVERIFY(!backend);
    QCOMPARE(r, Result(Error::Internal));
    QCOMPARE(r.message(), QStringLiteral("netvfs Rust backends not installed"));
    QVERIFY2(r.detail().contains(QLatin1String("/nonexistent/libnetvfs-rs.so")), qPrintable(r.detail()));
    SshKeyTools *keys = memKeyTools();
    QVERIFY(keys);
    SshKeyMaterial key;
    r = keys->generate(&key);
    QCOMPARE(r.message(), QStringLiteral("netvfs Rust backends not installed"));
    QVERIFY(key.privateKey.isEmpty());

    // A library without nvr_get is no better.
    qputenv("NETVFS_RS_LIB", NETVFS_TEST_CORE_LIB);
    backend = newBackend(&r);
    QVERIFY(!backend);
    QCOMPARE(r.message(), QStringLiteral("netvfs Rust backends not installed"));
    QVERIFY2(r.detail().contains(QLatin1String("nvr_get")), qPrintable(r.detail()));

    // The loader looks again, finds it and keeps it (the plugin and this
    // test each have their copy of the shim).
    qputenv("NETVFS_RS_LIB", NETVFS_TEST_RS_LIB);
    backend.reset(BackendLoader::create(QStringLiteral("mem"), &r));
    QVERIFY2(backend, qPrintable(r.toString()));
    QVERIFY(newBackend(&r));
    qputenv("NETVFS_RS_LIB", "/nonexistent/libnetvfs-rs.so");
    QVERIFY(Rs::table(&r));
    QCOMPARE(r, Result::success());
    QVERIFY(newBackend(&r));
    backend.reset(BackendLoader::create(QStringLiteral("mem"), &r));
    QVERIFY(backend);
}

void tst_RsShim::plugin()
{
    Result r;
    std::unique_ptr<Backend> backend(BackendLoader::create(QStringLiteral("mem"), &r));
    QVERIFY2(backend, qPrintable(r.toString()));
    QCOMPARE(r, Result::success());
    QCOMPARE(backend->connect(memParams(), nullptr), Result::success());
    QCOMPARE(backend->authenticate(Credentials()), Result::success());
    Entry root;
    QCOMPARE(backend->stat(QString(), &root), Result::success());
    QCOMPARE(root.type, EntryType::Directory);

    SshKeyTools *keys = memKeyTools();
    QVERIFY(keys);
    SshKeyMaterial key;
    QCOMPARE(keys->generate(&key), Result::success());
    QVERIFY(key.privateKey.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    QCOMPARE(key.algorithm, QStringLiteral("ssh-ed25519"));
    QVERIFY2(key.publicLine.startsWith(QLatin1String("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI")),
             qPrintable(key.publicLine));
    QVERIFY2(key.publicLine.endsWith(QLatin1String(" sailfish-backup")), qPrintable(key.publicLine));
    QVERIFY2(key.fingerprint.startsWith(QLatin1String("SHA256:")), qPrintable(key.fingerprint));
    SshKeyMaterial described;
    QCOMPARE(keys->describe(key.privateKey, &described), Result::success());
    QCOMPARE(described.privateKey, key.privateKey);
    QCOMPARE(described.algorithm, key.algorithm);
    QCOMPARE(described.publicLine, key.publicLine);
    QCOMPARE(described.fingerprint, key.fingerprint);
    SshKeyMaterial imported;
    QCOMPARE(keys->importKey(key.privateKey, "unused", &imported), Result::success());
    QCOMPARE(imported.fingerprint, key.fingerprint);
    for (const Result &refused : { keys->importKey("file", "secret", &imported), keys->describe("key", &imported) }) {
        QCOMPARE(refused, Result(Error::Unsupported));
        QCOMPARE(refused.message(), QStringLiteral("The file is not a private key in OpenSSH or PEM format"));
    }
}

void tst_RsShim::unknownProvider()
{
    Backend *raw = reinterpret_cast<Backend *>(this);
    const Result r = Rs::createBackend(QStringLiteral("ftp"), &raw);
    QVERIFY(!raw);
    QCOMPARE(r, Result(Error::Unsupported));
    QCOMPARE(r.message(), QStringLiteral("No Rust backend for provider \"ftp\""));
}

void tst_RsShim::establish()
{
    Result r;
    std::unique_ptr<Backend> backend = newBackend(&r);
    QVERIFY(backend);
    ConnectionParams params = memParams({ { QStringLiteral("identity"), QStringLiteral("ssh-ed25519") },
                                          { QStringLiteral("secret"), QStringLiteral("s3cret") },
                                          { QStringLiteral("number"), 7 } });
    params.host = QStringLiteral("example.org");
    params.port = 2222;
    params.connectTimeoutMs = 3000;
    params.requestTimeoutMs = 4000;
    ServerIdentity seen;
    QCOMPARE(backend->connect(params, &seen), Result::success());
    QCOMPARE(seen.kind, ServerIdentity::Kind::SshHostKey);
    QCOMPARE(seen.algorithm, QStringLiteral("ssh-ed25519"));
    QCOMPARE(seen.publicKey, QByteArray("mem host key"));
    QCOMPARE(seen.fingerprint, QStringLiteral("tester@example.org:2222 3000/4000 ms"));

    QVERIFY(backend->capabilities().has(Capability::Symlinks));
    QCOMPARE(backend->authenticate(Credentials(QStringLiteral("tester"), "wrong")), Result(Error::AuthFailed));
    QCOMPARE(backend->authenticate(Credentials(QStringLiteral("tester"), "s3cret")), Result::success());
    const Capabilities caps = backend->capabilities();
    QCOMPARE(caps.names(),
             QStringList({ QStringLiteral("AtomicReplace"), QStringLiteral("Checksums"), QStringLiteral("ETags"),
                           QStringLiteral("EfficientRanges"), QStringLiteral("Hardlinks"),
                           QStringLiteral("NativeNoReplace"), QStringLiteral("Ownership"),
                           QStringLiteral("PosixModes"), QStringLiteral("ReadHandles"), QStringLiteral("ServerCopy"),
                           QStringLiteral("ServerCopyRecursive"), QStringLiteral("SetModified"),
                           QStringLiteral("SetModifiedOnUpload"), QStringLiteral("SpaceInfo"),
                           QStringLiteral("Symlinks"), QStringLiteral("WriteResume") }));
    QCOMPARE(caps.checksumAlgorithms, QStringList(QStringLiteral("sha256")));
    QCOMPARE(caps.maxNameBytes, qint64(255));

    // The whole error crosses: name, message, detail (panics()) and when
    // to retry.
    std::unique_ptr<Backend> throttled = newBackend(&r);
    QCOMPARE(throttled->connect(memParams({ { QStringLiteral("throttle"), 1500 } }), nullptr), Result::success());
    r = throttled->authenticate(Credentials(QStringLiteral("tester"), QByteArray()));
    QCOMPARE(r, Result(Error::RateLimited));
    QCOMPARE(r.message(), QStringLiteral("Too many attempts"));
    QCOMPARE(r.retryAfterMs(), qint64(1500));

    // No identity: an empty one, also where there was one before.
    std::unique_ptr<Backend> plain = newBackend(&r);
    QCOMPARE(plain->connect(memParams(), &seen), Result::success());
    QCOMPARE(seen.kind, ServerIdentity::Kind::None);
    QVERIFY(seen.isEmpty());
    QCOMPARE(plain->connect(memParams(), nullptr), Result::success());
}

void tst_RsShim::prompts()
{
    std::unique_ptr<Backend> backend;
    {
        Result r;
        backend = newBackend(&r);
    }
    QVERIFY(backend);
    QCOMPARE(backend->connect(memParams({ { QStringLiteral("interactive"), QStringLiteral("Code?") },
                                          { QStringLiteral("answer"), QStringLiteral("42") } }),
                              nullptr),
             Result::success());
    const Credentials credentials(QStringLiteral("tester"), QByteArray());

    QCOMPARE(backend->authenticate(credentials, nullptr), Result(Error::AuthFailed));

    Prompter declining;
    declining.give = false;
    QCOMPARE(backend->authenticate(credentials, &declining), Result(Error::AuthFailed));
    QCOMPARE(declining.calls, 1);
    QCOMPARE(declining.seenName, QStringLiteral("mem"));
    QCOMPARE(declining.seenInstruction, QStringLiteral("Sign in as tester"));
    QCOMPARE(declining.seenPrompts.size(), 1);
    QCOMPARE(declining.seenPrompts.first().text, QStringLiteral("Code?"));
    QVERIFY(!declining.seenPrompts.first().echo);

    Prompter wrong;
    wrong.reply = { "41" };
    QCOMPARE(backend->authenticate(credentials, &wrong), Result(Error::AuthFailed));
    Prompter tooMany;
    tooMany.reply = { "42", "42" };
    QCOMPARE(backend->authenticate(credentials, &tooMany), Result(Error::AuthFailed));
    Prompter right;
    right.reply = { "42" };
    QCOMPARE(backend->authenticate(credentials, &right), Result::success());
    QCOMPARE(right.calls, 1);

    // The domain is an option of the connection and goes with the
    // credentials.
    QCOMPARE(backend->connect(memParams({ { QStringLiteral("interactive"), QStringLiteral("Code?") },
                                          { QStringLiteral("answer"), QStringLiteral("42") },
                                          { QStringLiteral("domain"), QStringLiteral("WORKGROUP") } }),
                              nullptr),
             Result::success());
    Prompter inDomain;
    inDomain.reply = { "42" };
    QCOMPARE(backend->authenticate(credentials, &inDomain), Result::success());
    QCOMPARE(inDomain.seenInstruction, QStringLiteral("Sign in as WORKGROUP\\tester"));

    Prompter throwing;
    throwing.throwIt = true;
    const Result r = backend->authenticate(credentials, &throwing);
    QCOMPARE(r, Result(Error::Internal));
    QCOMPARE(r.message(), CallbackFailed);
    QVERIFY2(r.detail().startsWith(QLatin1String("AuthFailed")), qPrintable(r.detail()));
}

void tst_RsShim::cancelWakesPrompter()
{
    Result r;
    std::unique_ptr<Backend> backend = newBackend(&r);
    QVERIFY(backend);
    QCOMPARE(backend->connect(memParams({ { QStringLiteral("interactive"), QStringLiteral("Code?") } }), nullptr),
             Result::success());
    Prompter waiting;
    waiting.waitForCancel = true;
    QElapsedTimer clock;
    std::thread canceler([&waiting, &backend]() {
        waiting.waitUntilAsked();
        backend->cancel();
    });
    clock.start();
    r = backend->authenticate(Credentials(QStringLiteral("tester"), QByteArray()), &waiting);
    canceler.join();
    QVERIFY(!r.ok());
    QVERIFY(waiting.canceled);
    QVERIFY(clock.elapsed() < CancelLimitMs);

    // only while it is asking: afterwards cancel() leaves it alone.
    waiting.canceled = false;
    backend->resetCancel();
    backend->cancel();
    QVERIFY(!waiting.canceled);
}

void tst_RsShim::entries()
{
    std::unique_ptr<Backend> backend = connected();
    QVERIFY(backend);
    QCOMPARE(backend->makeDir(QStringLiteral("dir"), true), Result::success());
    QCOMPARE(put(backend.get(), QStringLiteral("dir/file"), "content"), Result::success());
    AttributeChanges changes;
    changes.mode = 0600;
    changes.modified = fixedTime();
    changes.accessed = fixedTime().addDays(1);
    QCOMPARE(backend->setAttributes(QStringLiteral("dir/file"), changes), Result::success());

    Entry entry;
    QCOMPARE(backend->stat(QStringLiteral("dir/file"), &entry), Result::success());
    QCOMPARE(entry.name, QStringLiteral("file"));
    QCOMPARE(entry.type, EntryType::File);
    QCOMPARE(entry.targetType, EntryType::Unknown);
    QCOMPARE(entry.size, qint64(7));
    QCOMPARE(entry.mode, 0600);
    QCOMPARE(entry.modified, fixedTime());
    QCOMPARE(entry.accessed, fixedTime().addDays(1));
    QVERIFY(entry.created.isValid());
    QCOMPARE(entry.created.timeSpec(), Qt::UTC);
    QCOMPARE(entry.uid, qint64(1000));
    QCOMPARE(entry.gid, qint64(1000));
    QCOMPARE(entry.owner, QStringLiteral("mem"));
    QCOMPARE(entry.group, QStringLiteral("mem"));
    QVERIFY(!entry.etag.isEmpty());
    QVERIFY(entry.contentType.isEmpty());
    QCOMPARE(entry.flags, EntryFlags());

    AttributeChanges onlyMode;
    onlyMode.mode = 0640;
    QCOMPARE(backend->setAttributes(QStringLiteral("dir/file"), onlyMode), Result::success());
    QCOMPARE(backend->stat(QStringLiteral("dir/file"), &entry), Result::success());
    QCOMPARE(entry.mode, 0640);
    QCOMPARE(entry.modified, fixedTime());

    // lstat does not follow, stat does; a dangling link is TargetUnknown.
    QCOMPARE(backend->makeSymlink(QStringLiteral("dir/file"), QStringLiteral("link")), Result::success());
    QCOMPARE(backend->lstat(QStringLiteral("link"), &entry), Result::success());
    QCOMPARE(entry.type, EntryType::Symlink);
    QCOMPARE(entry.size, qint64(8));
    // mem knows only a link's modification time, and no mode: the others
    // are unknown.
    QVERIFY(entry.modified.isValid());
    QVERIFY(!entry.created.isValid());
    QVERIFY(!entry.accessed.isValid());
    QCOMPARE(entry.mode, -1);
    QCOMPARE(backend->stat(QStringLiteral("link"), &entry), Result::success());
    QCOMPARE(entry.type, EntryType::File);
    QCOMPARE(entry.name, QStringLiteral("link"));
    QCOMPARE(backend->makeSymlink(QStringLiteral("nowhere"), QStringLiteral("dangling")), Result::success());
    Sink sink;
    ListOptions options;
    options.resolveSymlinkTypes = true;
    QCOMPARE(backend->list(QString(), &sink, options), Result::success());
    QCOMPARE(sink.all.size(), 3);
    for (const Entry &listed : sink.all) {
        if (listed.name == QLatin1String("dangling"))
            QCOMPARE(listed.flags, EntryFlags(EntryFlag::TargetUnknown));
        if (listed.name == QLatin1String("link"))
            QCOMPARE(listed.targetType, EntryType::File);
    }

    entry.name = QStringLiteral("stale");
    QCOMPARE(backend->stat(QStringLiteral("missing"), &entry), Result(Error::NotFound));
    QVERIFY(entry.name.isEmpty());
    QCOMPARE(backend->stat(QStringLiteral("dir"), nullptr), Result::success());
}

void tst_RsShim::names()
{
    std::unique_ptr<Backend> backend = connected();
    QVERIFY(backend);
    const QString latin1 = Names::decode(QByteArray("caf\xe9"));
    QVERIFY(Names::hasEscapes(latin1));
    QCOMPARE(put(backend.get(), latin1, "x"), Result::success());
    Entry entry;
    QCOMPARE(backend->stat(latin1, &entry), Result::success());
    QCOMPARE(entry.name, latin1);
    QCOMPARE(entry.flags, EntryFlags(EntryFlag::NameNotUtf8));
    const QString utf8 = QStringLiteral("grüße \U0001F600");
    QCOMPARE(put(backend.get(), utf8, "y"), Result::success());
    QCOMPARE(backend->stat(utf8, &entry), Result::success());
    QCOMPARE(entry.name, utf8);
    QCOMPARE(entry.flags, EntryFlags());

    // A lone surrogate that decode() cannot make has no bytes: InvalidName,
    // for either path of a call.
    const QString lone = QStringLiteral("bad") + QChar(0xd800);
    QVERIFY(!Names::isEncodable(lone));
    QCOMPARE(backend->stat(lone, &entry), Result(Error::InvalidName));
    QCOMPARE(backend->rename(lone, QStringLiteral("good"), RenameMode::NoReplace), Result(Error::InvalidName));
    QCOMPARE(backend->rename(utf8, lone, RenameMode::NoReplace), Result(Error::InvalidName));
    QCOMPARE(backend->stat(utf8, &entry), Result::success());
}

void tst_RsShim::listing()
{
    std::unique_ptr<Backend> backend = connected();
    QVERIFY(backend);
    for (const char *name : { "a", "b", "c", "d", "e" })
        QCOMPARE(put(backend.get(), QString::fromLatin1(name), name), Result::success());

    ListOptions options;
    options.batchSize = 2;
    Sink sink;
    QCOMPARE(backend->list(QString(), &sink, options), Result::success());
    QCOMPARE(sink.sizes, QVector<int>({ 2, 2, 1 }));
    QStringList names;
    for (const Entry &entry : sink.all)
        names << entry.name;
    QCOMPARE(names, QStringList({ "a", "b", "c", "d", "e" }));

    options.batchSize = 0;
    Sink single;
    QCOMPARE(backend->list(QString(), &single, options), Result::success());
    QCOMPARE(single.sizes, QVector<int>({ 1, 1, 1, 1, 1 }));

    options.batchSize = 2;
    Sink stopping;
    stopping.stopAfter = 1;
    QCOMPARE(backend->list(QString(), &stopping, options), Result(Error::Canceled));
    QCOMPARE(stopping.sizes, QVector<int>({ 2 }));

    Sink throwing;
    throwing.throwOnBatch = true;
    const Result r = backend->list(QString(), &throwing, options);
    QCOMPARE(r, Result(Error::Internal));
    QCOMPARE(r.message(), CallbackFailed);
    QVERIFY2(r.detail().startsWith(QLatin1String("Canceled")), qPrintable(r.detail()));

    QCOMPARE(backend->list(QString(), nullptr, options).message(), QStringLiteral("No listing sink"));
    QCOMPARE(backend->list(QStringLiteral("a"), &sink, options), Result(Error::NotADirectory));

    QVector<Entry> all;
    QCOMPARE(backend->list(QString(), &all), Result::success());
    QCOMPARE(all.size(), 5);
}

void tst_RsShim::namespaceCalls()
{
    std::unique_ptr<Backend> backend = connected();
    QVERIFY(backend);
    const QByteArray data = pattern(1000);
    QCOMPARE(put(backend.get(), QStringLiteral("file"), data), Result::success());
    QCOMPARE(backend->makeDir(QStringLiteral("dir"), true), Result::success());
    QCOMPARE(backend->makeDir(QStringLiteral("dir"), true), Result(Error::AlreadyExists));
    QCOMPARE(backend->makeDir(QStringLiteral("dir"), false), Result::success());

    QCOMPARE(backend->copy(QStringLiteral("file"), QStringLiteral("dir/copy"), CopyOptions()), Result::success());
    QCOMPARE(backend->copy(QStringLiteral("file"), QStringLiteral("dir/copy"), CopyOptions()),
             Result(Error::AlreadyExists));
    CopyOptions replace;
    replace.mode = RenameMode::Replace;
    QCOMPARE(backend->copy(QStringLiteral("file"), QStringLiteral("dir/copy"), replace), Result::success());
    CopyOptions flat;
    QCOMPARE(backend->copy(QStringLiteral("dir"), QStringLiteral("tree"), flat), Result(Error::IsADirectory));
    CopyOptions recursive;
    recursive.recursive = true;
    QCOMPARE(backend->copy(QStringLiteral("dir"), QStringLiteral("tree"), recursive), Result::success());
    QByteArray read;
    QCOMPARE(get(backend.get(), QStringLiteral("tree/copy"), &read), Result::success());
    QCOMPARE(read, data);

    QCOMPARE(backend->rename(QStringLiteral("tree/copy"), QStringLiteral("file"), RenameMode::NoReplace),
             Result(Error::AlreadyExists));
    QCOMPARE(backend->rename(QStringLiteral("tree/copy"), QStringLiteral("file"), RenameMode::Replace),
             Result::success());
    QCOMPARE(backend->removeFile(QStringLiteral("dir/copy")), Result::success());
    QCOMPARE(backend->removeFile(QStringLiteral("dir/copy")), Result(Error::NotFound));
    QCOMPARE(backend->removeDir(QStringLiteral("dir")), Result::success());
    QCOMPARE(backend->removeDir(QStringLiteral("dir")), Result(Error::NotFound));

    QString target = QStringLiteral("stale");
    QCOMPARE(backend->makeSymlink(QStringLiteral("../some where"), QStringLiteral("link")), Result::success());
    QCOMPARE(backend->readLink(QStringLiteral("link"), &target), Result::success());
    QCOMPARE(target, QStringLiteral("../some where"));
    QCOMPARE(backend->readLink(QStringLiteral("file"), &target), Result(Error::InvalidName));
    QVERIFY(target.isEmpty());
    QCOMPARE(backend->readLink(QStringLiteral("link"), nullptr), Result::success());

    QCOMPARE(backend->makeHardlink(QStringLiteral("file"), QStringLiteral("hard")), Result::success());
    QCOMPARE(get(backend.get(), QStringLiteral("hard"), &read), Result::success());
    QCOMPARE(read, data);

    QByteArray digest = "stale";
    QCOMPARE(backend->checksum(QStringLiteral("file"), QStringLiteral("sha256"), &digest), Result::success());
    QCOMPARE(digest, QCryptographicHash::hash(data, QCryptographicHash::Sha256));
    QCOMPARE(backend->checksum(QStringLiteral("file"), QStringLiteral("md5"), &digest), Result(Error::Unsupported));
    QVERIFY(digest.isEmpty());

    SpaceInfo space;
    QCOMPARE(backend->spaceInfo(QString(), &space), Result::success());
    QCOMPARE(space.total, qint64(1) << 40);
    QCOMPARE(space.used, qint64(data.size()));
    QCOMPARE(space.free, space.total - space.used);
    QCOMPARE(backend->spaceInfo(QStringLiteral("missing"), &space), Result(Error::NotFound));
    QCOMPARE(space.total, qint64(-1));
    QCOMPARE(backend->keepAlive(), Result::success());
}

void tst_RsShim::readHandles()
{
    std::unique_ptr<Backend> backend = connected();
    QVERIFY(backend);
    const QByteArray data = pattern(3000);
    QCOMPARE(put(backend.get(), QStringLiteral("data"), data), Result::success());
    ReadHandle *raw = nullptr;
    QCOMPARE(backend->openRead(QStringLiteral("data"), &raw), Result::success());
    std::unique_ptr<ReadHandle> handle(raw);
    QVERIFY(handle);
    QCOMPARE(handle->size(), qint64(3000));
    QByteArray chunk;
    QCOMPARE(handle->read(0, 1000, &chunk), Result::success());
    QCOMPARE(chunk, data.left(1000));
    handle->readAhead(1000, 1000);
    QCOMPARE(handle->read(2990, 100, &chunk), Result::success());
    QCOMPARE(chunk, data.right(10));
    QCOMPARE(handle->read(1, 0, &chunk), Result::success());
    QVERIFY(chunk.isEmpty());
    QCOMPARE(handle->read(5, 5, nullptr), Result::success());

    // Ranges no QByteArray holds are refused here, and `out` is emptied.
    chunk = "stale";
    QCOMPARE(handle->read(0, -1, &chunk).message(), QStringLiteral("Invalid range"));
    QVERIFY(chunk.isEmpty());
    QCOMPARE(handle->read(0, qint64(std::numeric_limits<int>::max() / 2) + 1, &chunk), Result(Error::Internal));
    chunk = "stale";
    QCOMPARE(handle->read(-1, 10, &chunk), Result(Error::ProtocolError));
    QVERIFY(chunk.isEmpty());
    QCOMPARE(handle->close(), Result::success());
    QCOMPARE(handle->read(0, 10, &chunk), Result(Error::ProtocolError));
    QCOMPARE(handle->close(), Result(Error::ProtocolError));
    handle.reset();

    QCOMPARE(backend->openRead(QStringLiteral("data"), &raw), Result::success());
    delete raw;

    raw = reinterpret_cast<ReadHandle *>(this);
    QCOMPARE(backend->openRead(QStringLiteral("missing"), &raw), Result(Error::NotFound));
    QVERIFY(!raw);
    QCOMPARE(backend->openRead(QStringLiteral("data"), nullptr), Result::success());

    QCOMPARE(backend->openRead(QStringLiteral("data"), &raw), Result::success());
    handle.reset(raw);
    backend->disconnect();
    QCOMPARE(handle->read(0, 10, &chunk), Result(Error::ConnectionLost));
    QCOMPARE(handle->close(), Result(Error::ConnectionLost));
}

void tst_RsShim::writeHandles()
{
    std::unique_ptr<Backend> backend = connected();
    QVERIFY(backend);
    WriteHandle *raw = nullptr;
    WriteOptions options;
    options.createMode = 0600;
    options.modified = fixedTime();
    QCOMPARE(backend->openWrite(QStringLiteral("new"), options, &raw), Result::success());
    std::unique_ptr<WriteHandle> handle(raw);
    QVERIFY(handle);
    QCOMPARE(handle->position(), qint64(0));
    QCOMPARE(handle->write("hello", 5), Result::success());
    QCOMPARE(handle->write(nullptr, 0), Result::success());
    QCOMPARE(handle->position(), qint64(5));
    QCOMPARE(handle->write("x", -1).message(), QStringLiteral("Invalid length"));
    QCOMPARE(handle->commit(), Result::success());
    QCOMPARE(handle->position(), qint64(-1));
    QCOMPARE(handle->write("x", 1), Result(Error::ProtocolError));
    QCOMPARE(handle->commit(), Result(Error::ProtocolError));
    handle->abort();
    handle.reset();
    Entry entry;
    QCOMPARE(backend->stat(QStringLiteral("new"), &entry), Result::success());
    QCOMPARE(entry.size, qint64(5));
    QCOMPARE(entry.mode, 0600);
    QCOMPARE(entry.modified, fixedTime());

    options = WriteOptions();
    QCOMPARE(backend->openWrite(QStringLiteral("new"), options, &raw), Result(Error::AlreadyExists));
    QVERIFY(!raw);
    options.disposition = WriteOptions::Disposition::Resume;
    options.resumeOffset = 4;
    QVERIFY(!backend->openWrite(QStringLiteral("new"), options, &raw).ok());
    options.resumeOffset = 5;
    QCOMPARE(backend->openWrite(QStringLiteral("new"), options, &raw), Result::success());
    handle.reset(raw);
    QCOMPARE(handle->position(), qint64(5));
    QCOMPARE(handle->write(" world", 6), Result::success());
    QCOMPARE(handle->commit(), Result::success());
    QByteArray read;
    QCOMPARE(get(backend.get(), QStringLiteral("new"), &read), Result::success());
    QCOMPARE(read, QByteArray("hello world"));
    options.disposition = WriteOptions::Disposition::Truncate;
    QCOMPARE(backend->openWrite(QStringLiteral("new"), options, &raw), Result::success());
    handle.reset(raw);
    QCOMPARE(handle->position(), qint64(0));
    handle->abort();
    QCOMPARE(handle->position(), qint64(-1));
    QCOMPARE(handle->write("x", 1), Result(Error::ProtocolError));

    QCOMPARE(backend->openWrite(QStringLiteral("other"), WriteOptions(), &raw), Result::success());
    delete raw;
    QCOMPARE(backend->openWrite(QStringLiteral("third"), WriteOptions(), nullptr), Result::success());

    QCOMPARE(backend->openWrite(QStringLiteral("last"), WriteOptions(), &raw), Result::success());
    handle.reset(raw);
    backend->disconnect();
    QCOMPARE(handle->write("x", 1), Result(Error::ConnectionLost));
    QCOMPARE(handle->commit(), Result(Error::ConnectionLost));
}

void tst_RsShim::transfers()
{
    std::unique_ptr<Backend> backend = connected();
    QVERIFY(backend);
    const QByteArray data = pattern(600 * 1024);

    QBuffer source;
    source.setData(data);
    source.open(QIODevice::ReadOnly);
    source.seek(100);
    Watch watch;
    QCOMPARE(backend->upload(&source, QStringLiteral("big"), UploadOptions(), &watch), Result::success());
    QCOMPARE(watch.updates.size(), 3);
    QCOMPARE(watch.updates.last(), qMakePair(qint64(data.size() - 100), qint64(data.size() - 100)));
    QByteArray read;
    Watch down;
    QBuffer sink;
    sink.open(QIODevice::WriteOnly);
    DownloadOptions range;
    range.offset = 1000;
    range.length = 300 * 1024;
    QCOMPARE(backend->download(QStringLiteral("big"), &sink, range, &down), Result::success());
    QCOMPARE(sink.data(), data.mid(1100, 300 * 1024));
    QCOMPARE(down.updates.last(), qMakePair(qint64(300 * 1024), qint64(300 * 1024)));

    Device stream(Device::Mode::Works, data.left(5000));
    stream.open(QIODevice::ReadOnly);
    Watch unknown;
    UploadOptions truncate;
    truncate.write.disposition = WriteOptions::Disposition::Truncate;
    QCOMPARE(backend->upload(&stream, QStringLiteral("big"), truncate, &unknown), Result::success());
    QCOMPARE(unknown.updates, (QVector<QPair<qint64, qint64>>({ qMakePair(qint64(5000), qint64(-1)) })));
    Device expected(Device::Mode::Works, data.left(5000));
    expected.open(QIODevice::ReadOnly);
    Watch announced;
    truncate.write.expectedSize = 5000;
    truncate.write.createMode = 0600;
    truncate.write.modified = fixedTime();
    QCOMPARE(backend->upload(&expected, QStringLiteral("small"), truncate, &announced), Result::success());
    QCOMPARE(announced.updates.last(), qMakePair(qint64(5000), qint64(5000)));
    Entry entry;
    QCOMPARE(backend->stat(QStringLiteral("small"), &entry), Result::success());
    QCOMPARE(entry.mode, 0600);
    QCOMPARE(entry.modified, fixedTime());
    Device local(Device::Mode::Works);
    local.open(QIODevice::WriteOnly);
    QCOMPARE(backend->download(QStringLiteral("small"), &local, DownloadOptions(), nullptr), Result::success());
    QCOMPARE(local.written, data.left(5000));

    // CreateNew on an existing file and resume through upload().
    QBuffer more;
    more.setData("+");
    more.open(QIODevice::ReadOnly);
    QCOMPARE(backend->upload(&more, QStringLiteral("small"), UploadOptions(), nullptr), Result(Error::AlreadyExists));
    UploadOptions resume;
    resume.write.disposition = WriteOptions::Disposition::Resume;
    resume.write.resumeOffset = 5000;
    QCOMPARE(backend->upload(&more, QStringLiteral("small"), resume, nullptr), Result::success());
    QCOMPARE(get(backend.get(), QStringLiteral("small"), &read), Result::success());
    QCOMPARE(read, data.left(5000) + "+");

    Watch stopping;
    stopping.stop = true;
    source.seek(0);
    QCOMPARE(backend->upload(&source, QStringLiteral("big"), truncate, &stopping), Result(Error::Canceled));
    sink.seek(0);
    QCOMPARE(backend->download(QStringLiteral("small"), &sink, DownloadOptions(), &stopping), Result(Error::Canceled));
}

void tst_RsShim::transferFailures()
{
    std::unique_ptr<Backend> backend = connected();
    QVERIFY(backend);
    QCOMPARE(put(backend.get(), QStringLiteral("file"), pattern(1000)), Result::success());
    UploadOptions truncate;
    truncate.write.disposition = WriteOptions::Disposition::Truncate;

    QCOMPARE(backend->upload(nullptr, QStringLiteral("file"), truncate, nullptr).message(), QStringLiteral("No source"));
    QCOMPARE(backend->download(QStringLiteral("file"), nullptr, DownloadOptions(), nullptr).message(),
             QStringLiteral("No sink"));

    Device failingSource(Device::Mode::Fails);
    failingSource.open(QIODevice::ReadOnly);
    Result r = backend->upload(&failingSource, QStringLiteral("up"), truncate, nullptr);
    QCOMPARE(r, Result(Error::Internal));
    QCOMPARE(r.message(), QStringLiteral("Cannot read the local file"));
    Device failingSink(Device::Mode::Fails);
    failingSink.open(QIODevice::WriteOnly);
    r = backend->download(QStringLiteral("file"), &failingSink, DownloadOptions(), nullptr);
    QCOMPARE(r, Result(Error::NoSpace));
    QCOMPARE(r.message(), QStringLiteral("Cannot write the local file"));

    Device throwingSource(Device::Mode::Throws);
    throwingSource.open(QIODevice::ReadOnly);
    r = backend->upload(&throwingSource, QStringLiteral("up"), truncate, nullptr);
    QCOMPARE(r.message(), CallbackFailed);
    QVERIFY2(r.detail().contains(QLatin1String("Cannot read the local file")), qPrintable(r.detail()));
    Device throwingSink(Device::Mode::Throws);
    throwingSink.open(QIODevice::WriteOnly);
    r = backend->download(QStringLiteral("file"), &throwingSink, DownloadOptions(), nullptr);
    QCOMPARE(r.message(), CallbackFailed);
    Watch throwingUpdate;
    throwingUpdate.throwOnUpdate = true;
    QBuffer sink;
    sink.open(QIODevice::WriteOnly);
    r = backend->download(QStringLiteral("file"), &sink, DownloadOptions(), &throwingUpdate);
    QCOMPARE(r.message(), CallbackFailed);
    QVERIFY2(r.detail().isEmpty(), qPrintable(r.detail()));
    Watch throwingCanceled;
    throwingCanceled.throwOnCanceled = true;
    r = backend->download(QStringLiteral("file"), &sink, DownloadOptions(), &throwingCanceled);
    QCOMPARE(r.message(), CallbackFailed);
    QVERIFY2(r.detail().startsWith(QLatin1String("Canceled")), qPrintable(r.detail()));

    QByteArray read;
    QCOMPARE(get(backend.get(), QStringLiteral("file"), &read), Result::success());
    QCOMPARE(read, pattern(1000));
}

void tst_RsShim::cancel()
{
    // until resetCancel() every call is Canceled.
    std::unique_ptr<Backend> backend = connected();
    QVERIFY(backend);
    backend->cancel();
    Entry entry;
    QCOMPARE(backend->stat(QString(), &entry), Result(Error::Canceled));
    QCOMPARE(backend->keepAlive(), Result(Error::Canceled));
    backend->resetCancel();
    QCOMPARE(backend->stat(QString(), &entry), Result::success());

    // A call that waits for the server ends within 2 s of cancel().
    std::unique_ptr<Backend> stalled = connected({ { QStringLiteral("stall"), QStringLiteral("true") } });
    QVERIFY(stalled);
    qint64 afterMs = 0;
    Result r = canceledAfterDelay(stalled.get(), [&stalled, &entry]() { return stalled->stat(QString(), &entry); },
                                  &afterMs);
    QCOMPARE(r, Result(Error::Canceled));
    QVERIFY2(afterMs < CancelLimitMs, qPrintable(QString::number(afterMs)));

    // Even when the backend does not look at the cancel (the cut).
    std::unique_ptr<Backend> deaf = connected({ { QStringLiteral("stall"), QStringLiteral("ignore") } });
    QVERIFY(deaf);
    r = canceledAfterDelay(deaf.get(), [&deaf]() { return deaf->keepAlive(); }, &afterMs);
    QCOMPARE(r, Result(Error::Canceled));
    QVERIFY2(afterMs < CancelLimitMs, qPrintable(QString::number(afterMs)));
}

void tst_RsShim::oneCallAtATime()
{
    // a call from inside a callback finds the connection busy; the
    // capabilities are kept since authenticate, so they still answer.
    std::unique_ptr<Backend> backend = connected();
    QVERIFY(backend);
    QCOMPARE(put(backend.get(), QStringLiteral("a"), "a"), Result::success());
    Sink inside;
    inside.backend = backend.get();
    QCOMPARE(backend->list(QString(), &inside, ListOptions()), Result::success());
    QCOMPARE(inside.inner, Result(Error::Internal));
    QCOMPARE(inside.inner.message(), Busy);
    QVERIFY(inside.innerCapabilities.has(Capability::ReadHandles));

    // Another thread meanwhile is refused at once, not queued.
    std::unique_ptr<Backend> stalled = connected({ { QStringLiteral("stall"), QStringLiteral("true") } });
    QVERIFY(stalled);
    QFuture<Result> waiting = QtConcurrent::run([&stalled]() { return stalled->keepAlive(); });
    Result second;
    QElapsedTimer clock;
    clock.start();
    do {
        QThread::msleep(20);
        second = stalled->keepAlive();
    } while (second.message() != Busy && clock.elapsed() < 5000);
    QCOMPARE(second.message(), Busy);
    stalled->cancel();
    QCOMPARE(waiting.result(), Result(Error::Canceled));
}

void tst_RsShim::panics()
{
    std::unique_ptr<Backend> backend = connected({ { QStringLiteral("panic"), QStringLiteral("stat") } });
    QVERIFY(backend);
    Entry entry;
    const Result r = backend->stat(QString(), &entry);
    QCOMPARE(r, Result(Error::Internal));
    QCOMPARE(r.message(), QStringLiteral("The Rust backend failed"));
    QCOMPARE(r.detail(), QStringLiteral("panic: mem: stat panics on request"));
    QCOMPARE(backend->makeDir(QStringLiteral("dir"), true), Result::success());

    std::unique_ptr<Backend> positions = connected({ { QStringLiteral("panic"), QStringLiteral("position") } });
    QVERIFY(positions);
    WriteHandle *raw = nullptr;
    QCOMPARE(positions->openWrite(QStringLiteral("file"), WriteOptions(), &raw), Result::success());
    std::unique_ptr<WriteHandle> handle(raw);
    QCOMPARE(handle->position(), qint64(-1));
    QCOMPARE(handle->commit(), Result::success());

    // Before authenticate a capabilities call that fails is empty.
    Result made;
    std::unique_ptr<Backend> caps = newBackend(&made);
    QCOMPARE(caps->connect(memParams({ { QStringLiteral("panic"), QStringLiteral("capabilities") } }), nullptr),
             Result::success());
    QVERIFY(caps->capabilities().flags.isEmpty());
}

void tst_RsShim::otherThreads()
{
    // one thread at a time, not always the one that made the backend.
    Result r;
    std::unique_ptr<Backend> backend = newBackend(&r);
    QVERIFY(backend);
    QFuture<Result> used = QtConcurrent::run([&backend]() {
        Result step = backend->connect(memParams(), nullptr);
        if (step.ok())
            step = backend->authenticate(Credentials());
        if (step.ok())
            step = backend->makeDir(QStringLiteral("made elsewhere"), true);
        return step;
    });
    QCOMPARE(used.result(), Result::success());
    Entry entry;
    QCOMPARE(backend->stat(QStringLiteral("made elsewhere"), &entry), Result::success());
    QFuture<void> freed = QtConcurrent::run([&backend]() { backend.reset(); });
    freed.waitForFinished();
    QVERIFY(!backend);
}

QTEST_GUILESS_MAIN(tst_RsShim)

#include "tst_rsshim.moc"
