// SPDX-License-Identifier: LGPL-2.1-or-later
// The C ABI of libnetvfs-bridge-ffi.so (design: phase2-design.md §1, §4.3),
// called through its table as the Rust bridge does: dlopen, nvb_ffi_get,
// init on the main thread first (T1). Connections use the fake backend
// (provider "fake"), steered through libnetvfs-bridge-ffi-fake.so (§4.1).
// Run in the normal and the sanitizer build (ASan + UBSan, LSan at exit).
// The marshalling templates (marshal.h) are also compiled in, for the cases
// no backend produces.
#include "netvfs_bridge_ffi.h"
#include "nvb_fake.h"

#include "marshal.h"

#include "fakebackend.h"

#include <QtCore/QElapsedTimer>
#include <QtCore/QProcess>
#include <QtCore/QTemporaryDir>
#include <QtTest/QtTest>

#include <atomic>
#include <cstring>
#include <functional>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

#include <dlfcn.h>
#include <malloc.h>

namespace {

const nvb_ffi *t = nullptr;     // the table under test
const nvb_fake *f = nullptr;    // the fake backend's controls
void *ffiLibrary = nullptr;

// ------------------------------------------------------------ secret scan

// SEC-5, XSEC-6: secrets given to the library carry this canary; every
// block freed while the scan is armed is searched for it. A hit is a copy
// that was released without being wiped.
namespace SecretScan {
const char Canary[] = "C4nary-0f-a-s3cret";
std::atomic<bool> armed { false };
std::atomic<int> hits { 0 };

void check(const volatile void *block, size_t size)
{
    const size_t length = sizeof(Canary) - 1;
    if (armed.load(std::memory_order_relaxed) && block && size >= length
            && memmem(const_cast<const void *>(block), size, Canary, length))
        hits.fetch_add(1);
}
} // namespace SecretScan

} // namespace

#if defined(__SANITIZE_ADDRESS__)
// ASan runs free hooks before it poisons the block.
extern "C" int __sanitizer_install_malloc_and_free_hooks(void (*mallocHook)(const volatile void *, size_t),
                                                         void (*freeHook)(const volatile void *));
extern "C" size_t __sanitizer_get_allocated_size(const volatile void *p);

namespace {
void scanFreed(const volatile void *block)
{
    SecretScan::check(block, __sanitizer_get_allocated_size(block));
}

void ignoreAllocated(const volatile void *, size_t)
{
    // Only frees are scanned; ASan installs hooks in pairs.
}

void installSecretScan()
{
    static const bool installed = __sanitizer_install_malloc_and_free_hooks(ignoreAllocated, scanFreed) != 0;
    QVERIFY(installed);
}
} // namespace
#else
// Without ASan, free() itself is interposed (the libraries' calls bind to
// this definition) and hands the block on to glibc's own.
extern "C" void __libc_free(void *p);

extern "C" void free(void *p) noexcept
{
    if (p)
        SecretScan::check(p, malloc_usable_size(p));
    __libc_free(p);
}

namespace {
void installSecretScan()
{
    // Nothing to install: the definition of free() above is the hook.
}
} // namespace
#endif

namespace {

// ------------------------------------------------------------- helpers

nvb_bytes bytes(const QByteArray &data)
{
    return nvb_bytes { reinterpret_cast<const uint8_t *>(data.constData()), static_cast<size_t>(data.size()) };
}

nvb_bytes lit(const char *text)
{
    return nvb_bytes { reinterpret_cast<const uint8_t *>(text), std::strlen(text) };
}

QByteArray toBytes(nvb_bytes b)
{
    return QByteArray(reinterpret_cast<const char *>(b.ptr), static_cast<int>(b.len));
}

struct Free {
    void operator()(void *p) const { t->free(p); }
};
template <typename T>
using Owned = std::unique_ptr<T, Free>;
using ErrorPtr = Owned<nvb_error>;

struct ConnFree {
    void operator()(nvb_conn *conn) const { t->conn_free(conn); }
};
using ConnPtr = std::unique_ptr<nvb_conn, ConnFree>;

QString nameOf(const nvb_error *error)
{
    return error ? QString::fromUtf8(toBytes(error->name)) : QString();
}

QString nameOf(const ErrorPtr &error)
{
    return nameOf(error.get());
}

// What establish needs; the default signs in to the fake as user/secret.
struct Establish {
    QByteArray provider = "fake";
    QByteArray host = "fake.example";
    QByteArray user = "user";
    QByteArray secret = "secret";
    QByteArray pin;
    nvb_secret source {};
    nvb_establish_hooks hooks {};
    bool withHooks = false;
    uint32_t phase = 0;

    Establish() { source.source = NVB_SECRET_BYTES; }

    ErrorPtr run(nvb_conn *conn)
    {
        nvb_params params {};
        params.provider = bytes(provider);
        params.host = bytes(host);
        params.username = bytes(user);
        params.connect_timeout_ms = 15000;
        params.request_timeout_ms = 60000;
        source.user = bytes(user);
        source.secret = bytes(secret);
        return ErrorPtr(t->conn_establish(conn, &params, bytes(pin), &source, withHooks ? &hooks : nullptr,
                                          &phase));
    }
};

ConnPtr newConn()
{
    nvb_conn *conn = nullptr;
    const ErrorPtr error(t->conn_new(lit("fake"), &conn));
    return ConnPtr(error ? nullptr : conn);
}

ConnPtr connected()
{
    ConnPtr conn = newConn();
    Establish e;
    if (!conn || e.run(conn.get()))
        return ConnPtr();
    return conn;
}

int logCount(const char *prefix)
{
    return f->log_count(lit(prefix));
}

QByteArray pinFor(const QByteArray &key)
{
    return "ssh-ed25519 " + key.toBase64();
}

// Runs `fn` on another thread while this one runs the Qt event loop (the
// Rust bridge's layout: workers block, the main thread serves signond).
void offQtThread(const std::function<void()> &fn)
{
    std::thread worker([fn]() {
        fn();
        t->quit(0);
    });
    t->run();
    worker.join();
}

// Collects listing batches; stops after `stopAfter` batches (-1: never).
struct ListSink {
    QVector<QStringList> batches;
    int stopAfter = -1;
    std::function<void()> onBatch;

    static int call(void *ctx, const nvb_entry *entries, size_t n)
    {
        auto *self = static_cast<ListSink *>(ctx);
        if (self->onBatch)
            self->onBatch();
        QStringList names;
        for (size_t i = 0; i < n; ++i)
            names << QString::fromUtf8(toBytes(entries[i].name));
        self->batches << names;
        return self->stopAfter < 0 || self->batches.size() < self->stopAfter ? 1 : 0;
    }
};

// The local side of a transfer: a byte array, written in short pieces.
struct Memory {
    QByteArray data;
    qint64 maxWrite = -1;      // > 0: at most this many bytes per write
    bool failWrites = false;
    int writes = 0;

    nvb_io io(bool forUpload)
    {
        nvb_io io {};
        io.ctx = this;
        io.size = forUpload ? data.size() : 0;
        io.read = read;
        io.write = write;
        return io;
    }

    static int64_t read(void *ctx, int64_t pos, uint8_t *buf, size_t cap)
    {
        const auto *self = static_cast<Memory *>(ctx);
        const qint64 n = qBound<qint64>(0, self->data.size() - pos, static_cast<qint64>(cap));
        std::memcpy(buf, self->data.constData() + pos, static_cast<size_t>(n));
        return n;
    }

    static int64_t write(void *ctx, int64_t pos, const uint8_t *buf, size_t len)
    {
        auto *self = static_cast<Memory *>(ctx);
        ++self->writes;
        if (self->failWrites)
            return -1;
        const qint64 n = self->maxWrite > 0 ? qMin<qint64>(self->maxWrite, static_cast<qint64>(len))
                                            : static_cast<qint64>(len);
        if (self->data.size() < pos + n)
            self->data.resize(static_cast<int>(pos + n));
        std::memcpy(self->data.data() + pos, buf, static_cast<size_t>(n));
        return n;
    }
};

QByteArray pattern(int size)
{
    QByteArray data(size, Qt::Uninitialized);
    for (int i = 0; i < size; ++i)
        data[i] = static_cast<char>((i * 7 + i / 251) & 0xff);
    return data;
}

bool insideBlock(const void *block, nvb_bytes b)
{
    const auto *start = static_cast<const uint8_t *>(block);
    const size_t size = malloc_usable_size(const_cast<void *>(block));
    return b.ptr >= start && b.ptr + b.len <= start + size;
}

} // namespace

class tst_BridgeFfi : public QObject
{
    Q_OBJECT

private slots:
    void init();

    // The first test that creates a backend: the seed is read on first use.
    void fakeSeed();
    void entry();
    void onlyOneSymbol();
    void freeNull();
    void connLifecycle();
    void establishIdentityHook_data();
    void establishIdentityHook();
    void establishNoAuthenticateBeforeIdentity();
    void establishPromptReplySet();
    void establishSecretsWiped();
    void establishSignonId0Optional();
    void establishSignonCancel();
    void establishPhases();
    void listBatchesAndStop();
    void walkVisitAndStop();
    void removeTreeCounts();
    void metadataAndNamespace();
    void handlesReadEof();
    void uploadDownloadViaIo();
    void cancelFromOtherThreadDuringList();
    void copyAcrossTwoConns();
    void urlParseFormat();
    void errorBlockContents();
    void mapValuesNotCarried();
    void exceptionsBecomeInternal();
    void discoveryStartStopFree();
    void postAndQuit();
};

void tst_BridgeFfi::init()
{
    f->reset();
    SecretScan::armed = false;
    SecretScan::hits = 0;
}

void tst_BridgeFfi::fakeSeed()
{
    // NETVFS_FAKE_SEED (design §4.1), read by the plugin on the first create().
    QTemporaryDir dir;
    QFile seed(dir.filePath(QStringLiteral("seed")));
    QVERIFY(seed.open(QIODevice::WriteOnly));
    seed.write("file " + QByteArray("/seeded/a\xff.txt").toHex() + " " + QByteArray("hello").toHex() + "\n");
    seed.write("dir " + QByteArray("/seeded/empty").toHex() + "\n");
    seed.write("credentials seeduser " + QByteArray("s3").toHex() + "\n");
    seed.write("identity " + pinFor("seeded-key") + "\n");
    seed.close();
    qputenv("NETVFS_FAKE_SEED", seed.fileName().toLocal8Bit());
    ConnPtr conn = newConn();
    qunsetenv("NETVFS_FAKE_SEED");
    QVERIFY(conn);
    QCOMPARE(f->exists(lit("/seeded/empty")), 1);
    const Owned<nvb_blob> data(f->file_data(lit("seeded/a\xff.txt")));
    QVERIFY(data);
    QCOMPARE(toBytes(data->data), QByteArray("hello"));
    Establish e;
    e.user = "seeduser";
    e.secret = "s3";
    e.pin = pinFor("seeded-key");
    const ErrorPtr error = e.run(conn.get());
    QVERIFY2(!error, qPrintable(nameOf(error)));
    QCOMPARE(e.phase, uint32_t(NVB_PHASE_DONE));
}

void tst_BridgeFfi::entry()
{
    const auto get = reinterpret_cast<nvb_ffi_get_fn>(dlsym(ffiLibrary, NVB_FFI_ENTRY));
    QVERIFY(get);
    QCOMPARE(get(), t);
    // T1: a second init is refused.
    QCOMPARE(t->init(lit("again")), -1);
}

void tst_BridgeFfi::onlyOneSymbol()
{
    // Design §1: -fvisibility=hidden and the version script.
    QProcess nm;
    nm.start(QStringLiteral("nm"), { QStringLiteral("-D"), QStringLiteral("--defined-only"),
                                     QStringLiteral(NETVFS_TEST_FFI_LIB) });
    if (!nm.waitForFinished() || nm.exitCode() != 0)
        QSKIP("nm is not available");
    QStringList symbols;
    for (const QByteArray &line : nm.readAllStandardOutput().split('\n')) {
        if (const QList<QByteArray> words = line.simplified().split(' '); words.size() == 3)
            symbols << QString::fromLatin1(words.at(2));
    }
    QCOMPARE(symbols, QStringList { QStringLiteral(NVB_FFI_ENTRY) });
}

void tst_BridgeFfi::freeNull()
{
    t->free(nullptr);
    f->free(nullptr);
    t->conn_free(nullptr);
    QVERIFY(!t->handle_close(nullptr));
    t->discovery_free(nullptr);
}

void tst_BridgeFfi::connLifecycle()
{
    nvb_conn *none = reinterpret_cast<nvb_conn *>(0x1);
    const ErrorPtr unknown(t->conn_new(lit("nosuchprovider"), &none));
    QCOMPARE(nameOf(unknown), QStringLiteral("Unsupported"));
    QVERIFY(!none);
    QCOMPARE(t->provider_available(lit("fake")), 1);
    QCOMPARE(t->provider_available(lit("nosuchprovider")), 0);

    ConnPtr conn = connected();
    QVERIFY(conn);
    QCOMPARE(f->live_backends(), 1);
    f->add_file(lit("/a"), lit("0123456789"));
    nvb_handle *handle = nullptr;
    int64_t size = -1;
    const ErrorPtr opened(t->conn_open_read(conn.get(), lit("/a"), &handle, &size));
    QVERIFY(!opened);
    QVERIFY(handle);
    QCOMPARE(size, int64_t(10));
    // O4: conn_free closes the open handle (LSan sees a leak otherwise).
    conn.reset();
    QCOMPARE(logCount("close:a"), 1);
    QCOMPARE(f->live_backends(), 0);
    QCOMPARE(logCount("disconnect"), 1);
}

void tst_BridgeFfi::establishIdentityHook_data()
{
    QTest::addColumn<QByteArray>("serverKey");
    QTest::addColumn<QByteArray>("pinKey");
    QTest::addColumn<uint>("verdict");
    QTest::addColumn<QString>("checkName");     // what the hook is shown; "" passed
    QTest::addColumn<QString>("error");
    QTest::addColumn<uint>("phase");

    const uint useCheck = NVB_ID_USE_CHECK;
    const uint accept = NVB_ID_ACCEPT_UNKNOWN;
    const uint cancel = NVB_ID_CANCEL;
    const QString unknown = QStringLiteral("ServerIdentityUnknown");
    const QString changed = QStringLiteral("ServerIdentityChanged");
    QTest::newRow("pinned") << QByteArray("k1") << QByteArray("k1") << useCheck << QString() << QString()
                            << uint(NVB_PHASE_DONE);
    QTest::newRow("unknown, check stands") << QByteArray("k1") << QByteArray() << useCheck << unknown << unknown
                                           << uint(NVB_PHASE_IDENTITY);
    QTest::newRow("unknown, accepted") << QByteArray("k1") << QByteArray() << accept << unknown << QString()
                                       << uint(NVB_PHASE_DONE);
    QTest::newRow("changed, accept ignored") << QByteArray("k1") << QByteArray("k2") << accept << changed
                                             << changed << uint(NVB_PHASE_IDENTITY);
    QTest::newRow("canceled") << QByteArray("k1") << QByteArray("k1") << cancel << QString()
                              << QStringLiteral("Canceled") << uint(NVB_PHASE_IDENTITY);
    QTest::newRow("unknown verdict value") << QByteArray("k1") << QByteArray() << 77u << unknown << unknown
                                           << uint(NVB_PHASE_IDENTITY);
}

namespace {

struct IdentitySeen {
    uint32_t verdict = NVB_ID_USE_CHECK;
    int calls = 0;
    int authenticatedBefore = -1;
    QString checkName;
    QByteArray pin;
    QByteArray fingerprint;
    uint32_t kind = 0;

    static uint32_t hook(void *ctx, const nvb_identity *seen, const nvb_error *check)
    {
        auto *self = static_cast<IdentitySeen *>(ctx);
        ++self->calls;
        self->authenticatedBefore = logCount("authenticate");
        self->checkName = nameOf(check);
        self->pin = toBytes(seen->pin);
        self->fingerprint = toBytes(seen->fingerprint);
        self->kind = seen->kind;
        return self->verdict;
    }
};

} // namespace

void tst_BridgeFfi::establishIdentityHook()
{
    QFETCH(QByteArray, serverKey);
    QFETCH(QByteArray, pinKey);
    QFETCH(uint, verdict);
    QFETCH(QString, checkName);
    QFETCH(QString, error);
    QFETCH(uint, phase);

    f->set_identity_pin(bytes(pinFor(serverKey)));
    IdentitySeen seen;
    seen.verdict = verdict;
    Establish e;
    e.withHooks = true;
    e.hooks.ctx = &seen;
    e.hooks.identity = IdentitySeen::hook;
    e.pin = pinKey.isEmpty() ? QByteArray() : pinFor(pinKey);
    ConnPtr conn = newConn();
    const ErrorPtr result = e.run(conn.get());

    QCOMPARE(nameOf(result), error);
    QCOMPARE(e.phase, uint32_t(phase));
    QCOMPARE(seen.calls, 1);
    QCOMPARE(seen.checkName, checkName);
    QCOMPARE(seen.pin, pinFor(serverKey));
    QCOMPARE(seen.kind, uint32_t(NVB_IDENTITY_SSH));
    // XC-16: filled when the backend gave none, as connector.cpp did.
    QCOMPARE(seen.fingerprint, "SHA256:" + QCryptographicHash::hash(serverKey, QCryptographicHash::Sha256)
                                               .toBase64(QByteArray::OmitTrailingEquals));
    // C-7: the hook runs before anything is sent; a refusal sends nothing.
    QCOMPARE(seen.authenticatedBefore, 0);
    QCOMPARE(logCount("authenticate"), error.isEmpty() ? 1 : 0);
    QCOMPARE(logCount("disconnect"), error.isEmpty() ? 0 : 1);
}

void tst_BridgeFfi::establishNoAuthenticateBeforeIdentity()
{
    // No hook: an unknown identity fails (USE_CHECK) before authenticate.
    f->set_identity_pin(bytes(pinFor("k1")));
    ConnPtr conn = newConn();
    Establish e;
    QCOMPARE(nameOf(e.run(conn.get())), QStringLiteral("ServerIdentityUnknown"));
    QCOMPARE(e.phase, uint32_t(NVB_PHASE_IDENTITY));
    QCOMPARE(logCount("connect"), 1);
    QCOMPARE(logCount("authenticate"), 0);
    QCOMPARE(logCount("disconnect"), 1);
}

namespace {

struct Prompted {
    // reply_set() calls in this order (the last one counts); split before
    // the secret scan is armed, so that the test makes no copies itself.
    std::vector<std::vector<QByteArray>> replies;
    int answer = 1;
    int calls = 0;
    QByteArray name;
    QByteArray text;
    uint8_t echo = 1;

    static int hook(void *ctx, nvb_bytes name, nvb_bytes, const nvb_prompt *prompts, size_t n, nvb_reply *reply)
    {
        auto *self = static_cast<Prompted *>(ctx);
        ++self->calls;
        self->name = toBytes(name);
        if (n > 0) {
            self->text = toBytes(prompts[0].text);
            self->echo = prompts[0].echo;
        }
        for (const std::vector<QByteArray> &set : self->replies) {
            std::vector<nvb_bytes> answers;
            for (const QByteArray &a : set)
                answers.push_back(bytes(a));
            t->reply_set(reply, answers.data(), answers.size());
        }
        return self->answer;
    }
};

} // namespace

void tst_BridgeFfi::establishPromptReplySet()
{
    // XC-15 through the prompt hook; every given answer carries the canary.
    const QByteArray otp = QByteArray(SecretScan::Canary) + "-1";
    f->set_otp(bytes(otp));
    struct Case {
        const char *name;
        std::vector<std::vector<QByteArray>> replies;
        int answer;
        const char *error;
        int delivered;              // "answers:<n>" lines: replies the backend saw
    };
    const QByteArray old = QByteArray(SecretScan::Canary) + "-old";
    const std::vector<Case> cases = {
        { "accepted", { { otp } }, 1, "", 1 },
        { "replaced, the last one counts", { { old }, { otp } }, 1, "", 1 },
        { "count mismatch declines", { { otp, otp } }, 1, "AuthFailed", 0 },
        { "hook declines", { { otp } }, 0, "AuthFailed", 0 },
        { "no answers", {}, 1, "AuthFailed", 0 },
    };
    installSecretScan();
    for (const Case &c : cases) {
        f->reset();
        f->set_otp(bytes(otp));
        Prompted prompted;
        prompted.replies = c.replies;
        prompted.answer = c.answer;
        Establish e;
        e.withHooks = true;
        e.hooks.ctx = &prompted;
        e.hooks.prompt = Prompted::hook;
        ConnPtr conn = newConn();
        SecretScan::hits = 0;
        SecretScan::armed = true;
        const ErrorPtr error = e.run(conn.get());
        SecretScan::armed = false;
        QVERIFY2(nameOf(error) == QLatin1String(c.error), c.name);
        QVERIFY2(prompted.calls == 1, c.name);
        QCOMPARE(prompted.name, QByteArray("fake"));
        QCOMPARE(prompted.text, QByteArray("Verification code: "));
        QCOMPARE(prompted.echo, uint8_t(0));
        QVERIFY2(logCount("answers:") == c.delivered, c.name);
        // XSEC-6: no copy of an answer was released unwiped.
        QVERIFY2(SecretScan::hits == 0, c.name);
    }

    // No prompt hook: no prompter, so the second factor fails.
    f->reset();
    f->set_otp(bytes(otp));
    ConnPtr conn = newConn();
    Establish e;
    QCOMPARE(nameOf(e.run(conn.get())), QStringLiteral("AuthFailed"));
    QCOMPARE(e.phase, uint32_t(NVB_PHASE_AUTHENTICATE));
    QCOMPARE(logCount("disconnect"), 1);
}

void tst_BridgeFfi::establishSecretsWiped()
{
    // O5, SEC-5: the secret is copied once into Credentials and wiped.
    const QByteArray secret = QByteArray(SecretScan::Canary) + "-pw";
    f->set_credentials(lit("user"), bytes(secret));
    installSecretScan();
    for (const char *right : { "yes", "no" }) {
        ConnPtr conn = newConn();
        Establish e;
        e.secret = qstrcmp(right, "yes") == 0 ? secret : QByteArray(SecretScan::Canary) + "-wrong";
        SecretScan::hits = 0;
        SecretScan::armed = true;
        const ErrorPtr error = e.run(conn.get());
        conn.reset();
        SecretScan::armed = false;
        QCOMPARE(nameOf(error), qstrcmp(right, "yes") == 0 ? QString() : QStringLiteral("AuthFailed"));
        QCOMPARE(SecretScan::hits.load(), 0);
    }
}

void tst_BridgeFfi::establishSignonId0Optional()
{
    // XA-7: credentials id 0 with an optional secret yields empty
    // credentials without signond; the empty fetched user name becomes the
    // given one. Waits on a worker while the Qt thread serves the lookup.
    f->set_credentials(lit("user"), lit(""));
    for (const bool optional : { true, false }) {
        f->reset();
        f->set_credentials(lit("user"), lit(""));
        ConnPtr conn = newConn();
        Establish e;
        e.source.source = NVB_SECRET_SIGNON;
        e.source.credentials_id = 0;
        e.source.secret_optional = optional ? 1 : 0;
        ErrorPtr error;
        offQtThread([&error, &e, &conn]() { error = e.run(conn.get()); });
        if (optional) {
            QVERIFY2(!error, qPrintable(nameOf(error)));
            QCOMPARE(e.phase, uint32_t(NVB_PHASE_DONE));
            QCOMPARE(logCount("authenticate"), 1);
        } else {
            // A-6: no stored secret is AuthFailed, before authenticate.
            QCOMPARE(nameOf(error), QStringLiteral("AuthFailed"));
            QCOMPARE(e.phase, uint32_t(NVB_PHASE_CREDENTIALS));
            QCOMPARE(logCount("authenticate"), 0);
            QCOMPARE(logCount("disconnect"), 1);
        }
    }

    // On the Qt thread itself the wait could never end: refused.
    ConnPtr conn = newConn();
    Establish e;
    e.source.source = NVB_SECRET_SIGNON;
    e.source.secret_optional = 1;
    QCOMPARE(nameOf(e.run(conn.get())), QStringLiteral("Internal"));
    QCOMPARE(e.phase, uint32_t(NVB_PHASE_CREDENTIALS));
}

namespace {

// Holds the Qt thread until `release` is set, so that what is posted after
// it waits in the queue.
struct Blocker {
    std::atomic<bool> release { false };

    static void fn(void *ctx)
    {
        const auto *self = static_cast<Blocker *>(ctx);
        while (!self->release.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
};

} // namespace

void tst_BridgeFfi::establishSignonCancel()
{
    // T4: conn_cancel also ends the wait for signond (the lookup is queued
    // behind a busy Qt thread here, so it never answers in time).
    Blocker blocker;
    ConnPtr conn = newConn();
    Establish e;
    e.source.source = NVB_SECRET_SIGNON;
    e.source.secret_optional = 1;
    f->set_credentials(lit("user"), lit(""));
    ErrorPtr error;
    QElapsedTimer sinceCancel;
    qint64 elapsed = -1;
    int32_t blocked = -1;
    std::atomic<bool> looping { false };
    QTimer::singleShot(0, [&looping]() { looping = true; });
    std::thread worker([&]() {
        while (!looping.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        blocked = t->post(Blocker::fn, &blocker);
        std::thread canceler([&conn, &sinceCancel]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            sinceCancel.start();
            t->conn_cancel(conn.get());
        });
        error = e.run(conn.get());
        elapsed = sinceCancel.elapsed();
        canceler.join();
        blocker.release = true;
        t->quit(0);
    });
    t->run();   // the blocker, then the abandoned lookup, then quit
    worker.join();
    QCOMPARE(blocked, 1);
    QCOMPARE(nameOf(error), QStringLiteral("Canceled"));
    QCOMPARE(e.phase, uint32_t(NVB_PHASE_CREDENTIALS));
    QVERIFY2(elapsed >= 0 && elapsed < 2000, qPrintable(QString::number(elapsed)));
    QCOMPARE(logCount("authenticate"), 0);
    QCOMPARE(logCount("disconnect"), 1);
}

void tst_BridgeFfi::establishPhases()
{
    {
        // Connect fails: nothing to disconnect.
        f->fail_op(lit("connect"), lit("NetworkUnreachable"));
        ConnPtr conn = newConn();
        Establish e;
        QCOMPARE(nameOf(e.run(conn.get())), QStringLiteral("NetworkUnreachable"));
        QCOMPARE(e.phase, uint32_t(NVB_PHASE_CONNECT));
        QCOMPARE(logCount("disconnect"), 0);   // before conn_free disconnects
    }
    f->reset();
    {
        ConnPtr conn = newConn();
        Establish e;
        e.secret = "wrong";
        QCOMPARE(nameOf(e.run(conn.get())), QStringLiteral("AuthFailed"));
        QCOMPARE(e.phase, uint32_t(NVB_PHASE_AUTHENTICATE));
        QCOMPARE(logCount("disconnect"), 1);
    }
    f->reset();
    {
        ConnPtr conn = newConn();
        Establish e;
        e.source.source = NVB_SECRET_NONE;
        f->set_credentials(lit("user"), lit(""));
        QVERIFY(!e.run(conn.get()));
        QCOMPARE(e.phase, uint32_t(NVB_PHASE_DONE));
    }
    {
        ConnPtr conn = newConn();
        Establish e;
        e.source.source = 99;
        QCOMPARE(nameOf(e.run(conn.get())), QStringLiteral("Internal"));
        QCOMPARE(e.phase, uint32_t(NVB_PHASE_CREDENTIALS));
    }
}

void tst_BridgeFfi::listBatchesAndStop()
{
    for (int i = 0; i < 10; ++i)
        f->add_file(bytes("/dir/f" + QByteArray::number(i)), lit("x"));
    f->add_file(lit("/dir/n\xff"), lit(""));
    ConnPtr conn = connected();
    QVERIFY(conn);
    ListSink sink;
    QVERIFY(!ErrorPtr(t->conn_list(conn.get(), lit("/dir"), 3, ListSink::call, &sink)));
    // One sink call per backend batch.
    QCOMPARE(sink.batches.size(), 4);
    QCOMPARE(sink.batches.at(0).size(), 3);
    QCOMPARE(sink.batches.at(3).size(), 2);
    // XC-4: names cross as protocol bytes (Names::encode).
    QCOMPARE(sink.batches.at(3).last().toUtf8(), QString::fromUtf8("n\xff").toUtf8());

    ListSink stopping;
    stopping.stopAfter = 1;
    QCOMPARE(nameOf(ErrorPtr(t->conn_list(conn.get(), lit("/dir"), 3, ListSink::call, &stopping))),
             QStringLiteral("Canceled"));
    QCOMPARE(stopping.batches.size(), 1);

    ListSink missing;
    QCOMPARE(nameOf(ErrorPtr(t->conn_list(conn.get(), lit("/nope"), 3, ListSink::call, &missing))),
             QStringLiteral("NotFound"));
}

namespace {

struct Walked {
    QStringList paths;
    int stopAfter = -1;

    static int visit(void *ctx, nvb_bytes path, const nvb_entry *entry)
    {
        auto *self = static_cast<Walked *>(ctx);
        self->paths << QString::fromLatin1(toBytes(path)) + (entry->type == 2 ? QStringLiteral("/") : QString());
        return self->stopAfter < 0 || self->paths.size() < self->stopAfter ? 1 : 0;
    }
};

} // namespace

void tst_BridgeFfi::walkVisitAndStop()
{
    f->add_file(lit("/t/a/one"), lit("1"));
    f->add_file(lit("/t/a/b/two"), lit("2"));
    f->add_file(lit("/t/three"), lit("3"));
    ConnPtr conn = connected();
    QVERIFY(conn);
    nvb_walk_opts opts { -1, 0, 0, 0 };
    Walked all;
    QVERIFY(!ErrorPtr(t->walk(conn.get(), lit("/t"), &opts, Walked::visit, &all)));
    all.paths.sort();
    QCOMPARE(all.paths, QStringList({ "/t/a/", "/t/a/b/", "/t/a/b/two", "/t/a/one", "/t/three" }));

    opts.max_depth = 0;
    Walked top;
    QVERIFY(!ErrorPtr(t->walk(conn.get(), lit("/t"), &opts, Walked::visit, &top)));
    top.paths.sort();
    QCOMPARE(top.paths, QStringList({ "/t/a/", "/t/three" }));

    opts.max_depth = -1;
    Walked stopped;
    stopped.stopAfter = 2;
    QCOMPARE(nameOf(ErrorPtr(t->walk(conn.get(), lit("/t"), &opts, Walked::visit, &stopped))),
             QStringLiteral("Canceled"));
    QCOMPARE(stopped.paths.size(), 2);
}

namespace {

struct Progressed {
    QVector<QPair<qint64, qint64>> updates;
    int cancelAfter = -1;          // updates before canceled() says yes

    nvb_progress progress()
    {
        return nvb_progress { this, update, canceled };
    }

    static void update(void *ctx, int64_t done, int64_t total)
    {
        static_cast<Progressed *>(ctx)->updates << qMakePair(qint64(done), qint64(total));
    }

    static int canceled(void *ctx)
    {
        const auto *self = static_cast<Progressed *>(ctx);
        return self->cancelAfter >= 0 && self->updates.size() >= self->cancelAfter ? 1 : 0;
    }
};

} // namespace

void tst_BridgeFfi::removeTreeCounts()
{
    f->add_file(lit("/r/a/one"), lit("1"));
    f->add_file(lit("/r/a/two"), lit("2"));
    f->add_file(lit("/r/three"), lit("3"));
    ConnPtr conn = connected();
    QVERIFY(conn);
    Progressed progressed;
    const nvb_progress progress = progressed.progress();
    int64_t files = -1;
    int64_t dirs = -1;
    QVERIFY(!ErrorPtr(t->remove_tree(conn.get(), lit("/r"), &progress, &files, &dirs)));
    QCOMPARE(files, int64_t(3));
    QCOMPARE(dirs, int64_t(2));
    QCOMPARE(f->exists(lit("/r")), 0);
    // Design §1.2: update(files + dirs, -1) per removed entry.
    QCOMPARE(progressed.updates.size(), 5);
    QCOMPARE(progressed.updates.last(), qMakePair(qint64(5), qint64(-1)));

    f->add_file(lit("/s/a"), lit("1"));
    f->add_file(lit("/s/b"), lit("2"));
    Progressed stopping;
    stopping.cancelAfter = 1;
    const nvb_progress stop = stopping.progress();
    QCOMPARE(nameOf(ErrorPtr(t->remove_tree(conn.get(), lit("/s"), &stop, &files, &dirs))),
             QStringLiteral("Canceled"));
    QCOMPARE(files, int64_t(1));
    QCOMPARE(f->exists(lit("/s")), 1);
}

void tst_BridgeFfi::metadataAndNamespace()
{
    f->add_file(lit("/m/file"), lit("abc"));
    ConnPtr conn = connected();
    QVERIFY(conn);
    nvb_conn *c = conn.get();

    nvb_entry *raw = nullptr;
    QVERIFY(!ErrorPtr(t->conn_stat(c, lit("/m/file"), 1, &raw)));
    const Owned<nvb_entry> entry(raw);
    QCOMPARE(toBytes(entry->name), QByteArray("file"));
    QCOMPARE(entry->type, uint8_t(1));
    QCOMPARE(entry->size, int64_t(3));
    QCOMPARE(entry->mode, int32_t(0644));
    QVERIFY(entry->mtime_ms > 0);
    QCOMPARE(entry->uid, int64_t(-1));

    QVERIFY(!ErrorPtr(t->conn_make_dir(c, lit("/m/d"), 1)));
    QCOMPARE(nameOf(ErrorPtr(t->conn_make_dir(c, lit("/m/d"), 1))), QStringLiteral("AlreadyExists"));
    QVERIFY(!ErrorPtr(t->conn_rename(c, lit("/m/file"), lit("/m/d/moved"), 0)));
    QCOMPARE(f->exists(lit("/m/d/moved")), 1);
    QVERIFY(!ErrorPtr(t->conn_make_symlink(c, lit("d/moved"), lit("/m/link"))));
    nvb_blob *target = nullptr;
    QVERIFY(!ErrorPtr(t->conn_read_link(c, lit("/m/link"), &target)));
    QCOMPARE(toBytes(Owned<nvb_blob>(target)->data), QByteArray("d/moved"));
    QVERIFY(!ErrorPtr(t->conn_stat(c, lit("/m/link"), 0, &raw)));
    QCOMPARE(Owned<nvb_entry>(raw)->type, uint8_t(3));
    QVERIFY(!ErrorPtr(t->conn_make_hardlink(c, lit("/m/d/moved"), lit("/m/hard"))));
    QVERIFY(!ErrorPtr(t->conn_copy(c, lit("/m/d"), lit("/m/copy"), 1, 0)));
    QCOMPARE(f->exists(lit("/m/copy/moved")), 1);
    const nvb_attributes attributes { 0600, 1, 0, 1000, 0 };
    QVERIFY(!ErrorPtr(t->conn_set_attributes(c, lit("/m/hard"), &attributes)));
    QCOMPARE(f->node_mode(lit("/m/hard")), 0600);
    QVERIFY(!ErrorPtr(t->conn_stat(c, lit("/m/hard"), 1, &raw)));
    QCOMPARE(Owned<nvb_entry>(raw)->mtime_ms, int64_t(1000));

    nvb_blob *digest = nullptr;
    QVERIFY(!ErrorPtr(t->conn_checksum(c, lit("/m/hard"), lit("sha256"), &digest)));
    QCOMPARE(toBytes(Owned<nvb_blob>(digest)->data), QCryptographicHash::hash("abc", QCryptographicHash::Sha256));
    nvb_space space {};
    QVERIFY(!ErrorPtr(t->conn_space_info(c, lit("/m"), &space)));
    QCOMPARE(space.free_bytes, int64_t(1) << 40);
    nvb_capabilities *caps = nullptr;
    QVERIFY(!ErrorPtr(t->conn_capabilities(c, &caps)));
    const Owned<nvb_capabilities> owned(caps);
    QStringList flags;
    for (size_t i = 0; i < caps->n_flags; ++i)
        flags << QString::fromUtf8(toBytes(caps->flags[i]));
    QVERIFY(flags.contains(QStringLiteral("Symlinks")));
    QCOMPARE(caps->n_checksum_algorithms, size_t(2));
    QCOMPARE(caps->max_name_bytes, int64_t(255));

    QVERIFY(!ErrorPtr(t->conn_remove_file(c, lit("/m/hard"))));
    QCOMPARE(nameOf(ErrorPtr(t->conn_remove_dir(c, lit("/m/d")))), QStringLiteral("DirectoryNotEmpty"));
    QVERIFY(!ErrorPtr(t->conn_remove_file(c, lit("/m/d/moved"))));
    QVERIFY(!ErrorPtr(t->conn_remove_dir(c, lit("/m/d"))));
    QCOMPARE(f->exists(lit("/m/d")), 0);
}

void tst_BridgeFfi::handlesReadEof()
{
    f->add_file(lit("/h"), lit("0123456789"));
    ConnPtr conn = connected();
    QVERIFY(conn);
    nvb_handle *h = nullptr;
    int64_t size = 0;
    QVERIFY(!ErrorPtr(t->conn_open_read(conn.get(), lit("/h"), &h, &size)));
    QCOMPARE(size, int64_t(10));
    uint8_t buf[8] = {};
    size_t len = 99;
    QVERIFY(!ErrorPtr(t->handle_read(h, 2, buf, 4, &len)));
    QCOMPARE(len, size_t(4));
    QCOMPARE(QByteArray(reinterpret_cast<const char *>(buf), 4), QByteArray("2345"));
    // XC-13: short only at EOF; at or past EOF nothing.
    QVERIFY(!ErrorPtr(t->handle_read(h, 7, buf, 8, &len)));
    QCOMPARE(len, size_t(3));
    QVERIFY(!ErrorPtr(t->handle_read(h, 40, buf, 8, &len)));
    QCOMPARE(len, size_t(0));
    t->handle_read_ahead(h, 0, 10);
    QVERIFY(!ErrorPtr(t->handle_close(h)));
    QCOMPARE(logCount("close:h"), 1);
    nvb_handle *missing = nullptr;
    QCOMPARE(nameOf(ErrorPtr(t->conn_open_read(conn.get(), lit("/nope"), &missing, &size))),
             QStringLiteral("NotFound"));
    QVERIFY(!missing);
}

void tst_BridgeFfi::uploadDownloadViaIo()
{
    ConnPtr conn = connected();
    QVERIFY(conn);
    const QByteArray data = pattern(200000);

    Memory source;
    source.data = data;
    const nvb_io in = source.io(true);
    nvb_upload_opts opts { NVB_DISPOSITION_CREATE_NEW, -1, 0, data.size(), 1, 5000 };
    Progressed progressed;
    const nvb_progress progress = progressed.progress();
    QVERIFY(!ErrorPtr(t->conn_upload(conn.get(), lit("/up"), &opts, &in, &progress)));
    const Owned<nvb_blob> stored(f->file_data(lit("/up")));
    QVERIFY(stored);
    QCOMPARE(toBytes(stored->data), data);
    QVERIFY(!progressed.updates.isEmpty());
    QCOMPARE(progressed.updates.last().first, qint64(data.size()));
    nvb_entry *raw = nullptr;
    QVERIFY(!ErrorPtr(t->conn_stat(conn.get(), lit("/up"), 1, &raw)));
    QCOMPARE(Owned<nvb_entry>(raw)->mtime_ms, int64_t(5000));

    // Short writes into a regular file are retried until all is written.
    Memory sink;
    sink.maxWrite = 1000;
    const nvb_io out = sink.io(false);
    QVERIFY(!ErrorPtr(t->conn_download(conn.get(), lit("/up"), 100, 70000, &out, nullptr)));
    QCOMPARE(sink.data, data.mid(100, 70000));
    QVERIFY(sink.writes >= 70);

    // -1 is an error.
    Memory failing;
    failing.failWrites = true;
    const nvb_io broken = failing.io(false);
    QVERIFY(ErrorPtr(t->conn_download(conn.get(), lit("/up"), 0, -1, &broken, nullptr)));

    // canceled() stops the transfer.
    Memory again;
    again.data = data;
    const nvb_io in2 = again.io(true);
    Progressed stopping;
    stopping.cancelAfter = 1;
    const nvb_progress stop = stopping.progress();
    opts.disposition = NVB_DISPOSITION_TRUNCATE;
    QCOMPARE(nameOf(ErrorPtr(t->conn_upload(conn.get(), lit("/up"), &opts, &in2, &stop))),
             QStringLiteral("Canceled"));
}

void tst_BridgeFfi::cancelFromOtherThreadDuringList()
{
    for (int i = 0; i < 40; ++i)
        f->add_file(bytes("/slow/f" + QByteArray::number(i)), lit("x"));
    ConnPtr conn = connected();
    QVERIFY(conn);
    f->set_chunk_delay_ms(100);
    ListSink sink;
    std::atomic<bool> started { false };
    sink.onBatch = [&started]() { started = true; };
    QElapsedTimer sinceCancel;
    std::thread canceler([&conn, &started, &sinceCancel]() {
        while (!started.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        sinceCancel.start();
        t->conn_cancel(conn.get());
    });
    const ErrorPtr error(t->conn_list(conn.get(), lit("/slow"), 1, ListSink::call, &sink));
    const qint64 elapsed = sinceCancel.elapsed();
    canceler.join();
    QCOMPARE(nameOf(error), QStringLiteral("Canceled"));
    // C-9: within 2 s of the cancel.
    QVERIFY2(elapsed < 2000, qPrintable(QString::number(elapsed)));
    QVERIFY(sink.batches.size() < 40);
    // resetCancel: the connection is usable again.
    t->conn_reset_cancel(conn.get());
    f->set_chunk_delay_ms(0);
    ListSink after;
    QVERIFY(!ErrorPtr(t->conn_list(conn.get(), lit("/slow"), 64, ListSink::call, &after)));
    QCOMPARE(after.batches.size(), 1);
}

void tst_BridgeFfi::copyAcrossTwoConns()
{
    const QByteArray data = pattern(300000);
    f->add_file(lit("/src/big"), bytes(data));
    f->add_file(lit("/src/tree/a"), lit("a"));
    f->add_dir(lit("/dst"), -1);
    ConnPtr source = connected();
    ConnPtr destination = connected();
    QVERIFY(source && destination);
    Progressed progressed;
    const nvb_progress progress = progressed.progress();
    const ErrorPtr copied(t->copy_across(source.get(), lit("/src/big"), destination.get(), lit("/dst/big"), 0, 0,
                                         &progress));
    QVERIFY2(!copied, qPrintable(nameOf(copied)));
    QCOMPARE(toBytes(Owned<nvb_blob>(f->file_data(lit("/dst/big")))->data), data);
    QVERIFY(!progressed.updates.isEmpty());
    QCOMPARE(nameOf(ErrorPtr(t->copy_across(source.get(), lit("/src/big"), destination.get(), lit("/dst/big"), 0,
                                            0, nullptr))),
             QStringLiteral("AlreadyExists"));
    QVERIFY(!ErrorPtr(t->copy_across(source.get(), lit("/src/tree"), destination.get(), lit("/dst/tree"), 1, 0,
                                     nullptr)));
    QCOMPARE(f->exists(lit("/dst/tree/a")), 1);
}

namespace {

QMap<QString, QString> optionsOf(const nvb_params &params)
{
    QMap<QString, QString> options;
    for (size_t i = 0; i < params.n_options; ++i) {
        const nvb_kv &kv = params.options[i];
        if (kv.value.kind == NVB_VALUE_STRING)
            options.insert(QString::fromUtf8(toBytes(kv.key)), QString::fromUtf8(toBytes(kv.value.bytes)));
    }
    return options;
}

} // namespace

void tst_BridgeFfi::urlParseFormat()
{
    nvb_url *raw = nullptr;
    QVERIFY(!ErrorPtr(t->url_parse(lit("sftp://alice@host.example:2222/home/a%FFb"), &raw)));
    Owned<nvb_url> url(raw);
    QCOMPARE(toBytes(url->params.provider), QByteArray("sftp"));
    QCOMPARE(toBytes(url->params.host), QByteArray("host.example"));
    QCOMPARE(url->params.port, 2222);
    QCOMPARE(toBytes(url->params.username), QByteArray("alice"));
    QCOMPARE(toBytes(url->path), QByteArray("/home/a\xff" "b"));   // XC-4 bytes
    QCOMPARE(url->params.connect_timeout_ms, 15000);

    nvb_blob *formatted = nullptr;
    QVERIFY(!ErrorPtr(t->url_format(&url->params, url->path, &formatted)));
    QCOMPARE(toBytes(Owned<nvb_blob>(formatted)->data), QByteArray("sftp://alice@host.example:2222/home/a%FFb"));

    // XH-6: a password is refused; IDN; smb share and file://.
    nvb_url *none = reinterpret_cast<nvb_url *>(0x1);
    QCOMPARE(nameOf(ErrorPtr(t->url_parse(lit("sftp://alice:pw@host/"), &none))), QStringLiteral("SecurityPolicy"));
    QVERIFY(!none);
    QVERIFY(!ErrorPtr(t->url_parse(lit("sftp://xn--bcher-kva.de/x"), &raw)));
    url.reset(raw);
    QCOMPARE(QString::fromUtf8(toBytes(url->params.host)), QString::fromUtf8("b\xC3\xBC" "cher.de"));
    QVERIFY(!ErrorPtr(t->url_parse(lit("smb://nas/share/dir"), &raw)));
    url.reset(raw);
    QCOMPARE(optionsOf(url->params).value(QStringLiteral("share")), QStringLiteral("share"));
    QCOMPARE(toBytes(url->path), QByteArray("/dir"));
    QVERIFY(!ErrorPtr(t->url_format(&url->params, url->path, &formatted)));
    QCOMPARE(toBytes(Owned<nvb_blob>(formatted)->data), QByteArray("smb://nas/share/dir"));
    QVERIFY(!ErrorPtr(t->url_parse(lit("file:///tmp/x"), &raw)));
    url.reset(raw);
    QCOMPARE(toBytes(url->params.provider), QByteArray("local"));
    QCOMPARE(nameOf(ErrorPtr(t->url_parse(lit("gopher://h/"), &raw))), QStringLiteral("Unsupported"));

    nvb_params unknown {};
    unknown.provider = lit("fake");
    QCOMPARE(nameOf(ErrorPtr(t->url_format(&unknown, lit("/"), &formatted))), QStringLiteral("Unsupported"));
    QVERIFY(!formatted);
}

void tst_BridgeFfi::errorBlockContents()
{
    NetVfs::Test::FakeServer *server = NetVfs::Test::FakeServer::instance();
    ConnPtr conn = connected();
    QVERIFY(conn);
    {
        QMutexLocker lock(&server->mutex);
        server->failOps.insert(QStringLiteral("stat"),
                               NetVfs::Result(NetVfs::Error::RateLimited, QStringLiteral("slow döwn"),
                                              QStringLiteral("HTTP 429"), 1500));
    }
    nvb_entry *entry = reinterpret_cast<nvb_entry *>(0x1);
    const ErrorPtr error(t->conn_stat(conn.get(), lit("/x"), 1, &entry));
    QVERIFY(error);
    QVERIFY(!entry);
    QCOMPARE(toBytes(error->name), QByteArray("RateLimited"));
    QCOMPARE(QString::fromUtf8(toBytes(error->message)), QStringLiteral("slow döwn"));
    QCOMPARE(toBytes(error->detail), QByteArray("HTTP 429"));
    QCOMPARE(error->retry_after_ms, int64_t(1500));
    // O3: one block holds everything it points to.
    QVERIFY(insideBlock(error.get(), error->name));
    QVERIFY(insideBlock(error.get(), error->message));
    QVERIFY(insideBlock(error.get(), error->detail));

    f->add_file(lit("/e"), lit("e"));
    nvb_capabilities *caps = nullptr;
    QVERIFY(!ErrorPtr(t->conn_capabilities(conn.get(), &caps)));
    const Owned<nvb_capabilities> owned(caps);
    QVERIFY(caps->n_flags > 0);
    for (size_t i = 0; i < caps->n_flags; ++i)
        QVERIFY(insideBlock(caps, caps->flags[i]));
    QVERIFY(insideBlock(caps, nvb_bytes { reinterpret_cast<const uint8_t *>(caps->flags),
                                          caps->n_flags * sizeof(nvb_bytes) }));
    nvb_url *url = nullptr;
    QVERIFY(!ErrorPtr(t->url_parse(lit("smb://nas/share/dir"), &url)));
    const Owned<nvb_url> ownedUrl(url);
    QCOMPARE(url->params.n_options, size_t(1));
    for (size_t i = 0; i < url->params.n_options; ++i) {
        QVERIFY(insideBlock(url, url->params.options[i].key));
        QVERIFY(insideBlock(url, url->params.options[i].value.bytes));
    }
    QVERIFY(insideBlock(url, url->path));
    QCOMPARE(optionsOf(url->params).value(QStringLiteral("share")), QStringLiteral("share"));
}

void tst_BridgeFfi::mapValuesNotCarried()
{
    // fillMap() leaves out the values the ABI cannot carry (no backend has
    // such options yet) and keeps the key order of the
    // others. With none left the array is empty: never indexed, not null,
    // and in the block (O3).
    using namespace NetVfs::Ffi;
    const auto packed = [](const QVariantMap &map) {
        return Owned<nvb_params>(pack<nvb_params>([&map](auto &arena, nvb_params *out) {
            out->options = fillMap(arena, map, &out->n_options);
        }));
    };
    QVariantMap map;
    map.insert(QStringLiteral("a"), 1.5);
    map.insert(QStringLiteral("b"), QStringLiteral("x"));
    map.insert(QStringLiteral("c"), QVariant::fromValue(QPoint(1, 2)));
    map.insert(QStringLiteral("d"), 7);
    const Owned<nvb_params> mixed = packed(map);
    QCOMPARE(mixed->n_options, size_t(2));
    QCOMPARE(toBytes(mixed->options[0].key), QByteArray("b"));
    QCOMPARE(mixed->options[0].value.kind, uint32_t(NVB_VALUE_STRING));
    QCOMPARE(toBytes(mixed->options[0].value.bytes), QByteArray("x"));
    QCOMPARE(toBytes(mixed->options[1].key), QByteArray("d"));
    QCOMPARE(mixed->options[1].value.kind, uint32_t(NVB_VALUE_INT));
    QCOMPARE(mixed->options[1].value.number, int64_t(7));
    QVERIFY(insideBlock(mixed.get(), nvb_bytes { reinterpret_cast<const uint8_t *>(mixed->options),
                                                 mixed->n_options * sizeof(nvb_kv) }));
    for (size_t i = 0; i < mixed->n_options; ++i)
        QVERIFY(insideBlock(mixed.get(), mixed->options[i].key));

    map.remove(QStringLiteral("b"));
    map.remove(QStringLiteral("d"));
    for (const QVariantMap &none : { map, QVariantMap() }) {
        const Owned<nvb_params> empty = packed(none);
        QCOMPARE(empty->n_options, size_t(0));
        QVERIFY(empty->options);
        QVERIFY(insideBlock(empty.get(), nvb_bytes { reinterpret_cast<const uint8_t *>(empty->options), 0 }));
        HoldArena arena;
        size_t count = 99;
        QVERIFY(fillMap(arena, none, &count));
        QCOMPARE(count, size_t(0));
    }
}

void tst_BridgeFfi::exceptionsBecomeInternal()
{
    // T7: a C++ exception (here from a callback) never crosses the ABI.
    f->add_file(lit("/x/a"), lit("a"));
    ConnPtr conn = connected();
    QVERIFY(conn);
    const nvb_list_sink_fn throwing = [](void *, const nvb_entry *, size_t) -> int {
        throw std::runtime_error("sink failed");
    };
    const ErrorPtr error(t->conn_list(conn.get(), lit("/x"), 8, throwing, nullptr));
    QCOMPARE(nameOf(error), QStringLiteral("Internal"));
    QVERIFY(toBytes(error->message).contains("sink failed"));
    const nvb_walk_visit_fn notStd = [](void *, nvb_bytes, const nvb_entry *) -> int { throw 42; };
    const nvb_walk_opts opts { -1, 0, 0, 0 };
    QCOMPARE(nameOf(ErrorPtr(t->walk(conn.get(), lit("/x"), &opts, notStd, nullptr))), QStringLiteral("Internal"));
    // Invalid arguments are Internal too, not a crash.
    nvb_entry *entry = nullptr;
    QCOMPARE(nameOf(ErrorPtr(t->conn_stat(nullptr, lit("/x"), 1, &entry))), QStringLiteral("Internal"));
    QCOMPARE(nameOf(ErrorPtr(t->conn_list(conn.get(), lit("/x"), 8, nullptr, nullptr))),
             QStringLiteral("Internal"));
    // The connection still works.
    ListSink sink;
    QVERIFY(!ErrorPtr(t->conn_list(conn.get(), lit("/x"), 8, ListSink::call, &sink)));
}

namespace {

struct Nearby {
    int calls = 0;

    static void changed(void *ctx, const nvb_nearby *, size_t)
    {
        ++static_cast<Nearby *>(ctx)->calls;
    }
};

} // namespace

void tst_BridgeFfi::discoveryStartStopFree()
{
    // XD-5 on the Qt thread (T3); sockets may be unavailable in a sandbox,
    // so only the bookkeeping is checked.
    Nearby nearby;
    const nvb_discovery_hooks hooks { &nearby, Nearby::changed };
    nvb_discovery *d = t->discovery_new(&hooks);
    QVERIFY(d);
    const int32_t open = t->discovery_set_running(d, 1);
    QVERIFY(open == 0 || open == 1);
    QCOMPARE(t->discovery_set_running(d, 1), open);   // idempotent
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    QCOMPARE(t->discovery_set_running(d, 0), 0);
    QCOMPARE(t->discovery_set_running(d, 0), 0);
    QCOMPARE(t->discovery_set_running(d, 1), open);
    t->discovery_free(d);
    const int calls = nearby.calls;
    QTest::qWait(100);
    QCOMPARE(nearby.calls, calls);   // no hook call after free
}

namespace {

struct Posted {
    std::atomic<int> runs { 0 };
    QThread *thread = nullptr;
    int32_t quitWith = -1;

    static void fn(void *ctx)
    {
        auto *self = static_cast<Posted *>(ctx);
        self->thread = QThread::currentThread();
        ++self->runs;
        if (self->quitWith >= 0)
            t->quit(self->quitWith);
    }
};

} // namespace

void tst_BridgeFfi::postAndQuit()
{
    QCOMPARE(t->post(nullptr, nullptr), 0);
    // From another thread while the loop runs; the functor runs on the Qt
    // thread and its quit() ends run() with the code.
    Posted posted;
    posted.quitWith = 7;
    int32_t queued = -1;
    std::thread worker([&posted, &queued]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        queued = t->post(Posted::fn, &posted);
    });
    QCOMPARE(t->run(), 7);
    worker.join();
    QCOMPARE(queued, 1);
    QCOMPARE(posted.runs.load(), 1);
    QCOMPARE(posted.thread, QThread::currentThread());

    // Quitting: not queued, and it never runs.
    Posted late;
    QCOMPARE(t->post(Posted::fn, &late), 0);

    // A quit() before run() still ends the next run(); a functor posted
    // before it runs first.
    t->quit(5);
    QCOMPARE(t->run(), 5);
    QCOMPARE(late.runs.load(), 0);
    Posted first;
    first.quitWith = 3;
    QCOMPARE(t->post(Posted::fn, &first), 0);   // still quitting until run()
}

int main(int argc, char **argv)
{
    ffiLibrary = dlopen(NETVFS_TEST_FFI_LIB, RTLD_NOW | RTLD_LOCAL);
    void *fakeLibrary = dlopen(NETVFS_TEST_FFI_FAKE_LIB, RTLD_NOW | RTLD_LOCAL);
    if (!ffiLibrary || !fakeLibrary) {
        qCritical("Cannot load the libraries: %s", dlerror());
        return 1;
    }
    const auto getTable = reinterpret_cast<nvb_ffi_get_fn>(dlsym(ffiLibrary, NVB_FFI_ENTRY));
    const auto getFake = reinterpret_cast<nvb_fake_get_fn>(dlsym(fakeLibrary, NVB_FAKE_ENTRY));
    if (!getTable || !getFake)
        return 1;
    t = getTable();
    f = getFake();
    qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
    // T1: init first, on this (the main) thread.
    if (t->init(lit("tst_bridgeffi")) != 0)
        return 1;
    int rc = 0;
    {
        tst_BridgeFfi test;
        rc = QTest::qExec(&test, argc, argv);
    }
    t->shutdown();
    // The libraries stay loaded: LeakSanitizer reports at exit.
    return rc;
}

#include "tst_bridgeffi.moc"
