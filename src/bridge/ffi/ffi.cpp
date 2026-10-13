// SPDX-License-Identifier: LGPL-2.1-or-later
// libnetvfs-bridge-ffi.so: the table of the C ABI (netvfs_bridge_ffi.h), the
// process and Qt event loop part (T1, T2) and the helpers. SPEC-v2 §8a;
// design: phase2-design.md §1.
#include "ffi_p.h"

#include "backendloader.h"
#include "url.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QEvent>
#include <QtCore/QThread>

#include <mutex>
#include <stdexcept>
#include <typeinfo>

Q_LOGGING_CATEGORY(lcNetVfsFfi, "netvfs.bridge.ffi", QtWarningMsg)

namespace NetVfs::Ffi {

namespace {

// A functor posted to the Qt thread.
class FunctorEvent : public QEvent
{
public:
    explicit FunctorEvent(std::function<void()> fn) : QEvent(eventType()), m_fn(std::move(fn)) {}

    static QEvent::Type eventType()
    {
        static const auto type = static_cast<QEvent::Type>(QEvent::registerEventType());
        return type;
    }

    void run() const
    {
        if (m_fn)
            m_fn();
    }

private:
    std::function<void()> m_fn;
};

// Runs the posted functors on the Qt thread, in order (design §1.2).
class MainQueue : public QObject
{
public:
    using QObject::QObject;

protected:
    bool event(QEvent *event) override
    {
        if (event->type() != FunctorEvent::eventType())
            return QObject::event(event);
        try {
            static_cast<FunctorEvent *>(event)->run();
        } catch (...) {
            internalResult(std::current_exception());   // T7: never into Qt's event loop
        }
        return true;
    }
};

// The application of init() (T1). `mutex` orders post() and quit() from any
// thread against shutdown().
struct App {
    std::mutex mutex;
    std::unique_ptr<QCoreApplication> app;
    MainQueue *queue = nullptr;                 // child of `app`
    bool initialized = false;
    bool quitting = false;
    std::atomic<int32_t> exitCode { 0 };
    // Design §1.2: argc = 1, argv = { app_name } for the life of the app.
    QByteArray name;
    int argc = 1;
    char *argv[2] = { nullptr, nullptr };
};

App &app()
{
    static App state;
    return state;
}

int32_t init(nvb_bytes appName) noexcept
{
    return guardedValue<int32_t>(-1, [appName]() {
        App &a = app();
        std::scoped_lock lock(a.mutex);
        if (a.initialized || QCoreApplication::instance())
            return -1;
        a.name = toByteArray(appName);
        a.argv[0] = a.name.data();
        a.app = std::make_unique<QCoreApplication>(a.argc, a.argv);
        a.queue = new MainQueue(a.app.get());   // owned by the application
        a.initialized = true;
        return 0;
    });
}

int32_t run() noexcept
{
    return guardedValue<int32_t>(-1, []() {
        App &a = app();
        {
            std::scoped_lock lock(a.mutex);
            if (!a.app)
                return -1;
            a.quitting = false;   // a quit() from before still ends the loop: its call is queued
        }
        QCoreApplication::exec();
        // The loop is over: post() accepts nothing until the next run().
        std::scoped_lock lock(a.mutex);
        a.quitting = true;
        return a.exitCode.load();
    });
}

void quit(int32_t exitCode) noexcept
{
    guardedVoid([exitCode]() {
        App &a = app();
        a.exitCode.store(exitCode);
        std::scoped_lock lock(a.mutex);
        a.quitting = true;
        if (a.app)
            QMetaObject::invokeMethod(a.app.get(), "quit", Qt::QueuedConnection);
    });
}

int32_t post(void (*fn)(void *ctx), void *ctx) noexcept
{
    if (!fn)
        return 0;
    return guardedValue<int32_t>(0, [fn, ctx]() { return postToQt([fn, ctx]() { fn(ctx); }) ? 1 : 0; });
}

void shutdown() noexcept
{
    guardedVoid([]() {
        App &a = app();
        std::unique_ptr<QCoreApplication> owned;
        MainQueue *queue = nullptr;
        {
            std::scoped_lock lock(a.mutex);
            a.quitting = true;
            queue = a.queue;
            owned = std::move(a.app);
            a.queue = nullptr;
        }
        // A functor that post() accepted runs: its context may own memory.
        if (queue)
            QCoreApplication::sendPostedEvents(queue, FunctorEvent::eventType());
        owned.reset();
    });
}

void freeBlock(void *p) noexcept
{
    std::free(p);
}

int32_t providerAvailable(nvb_bytes provider) noexcept
{
    return guardedValue<int32_t>(0, [provider]() {
        return BackendLoader::isAvailable(toUtf8String(provider)) ? 1 : 0;
    });
}

// XH-6: Url::parse stays in C++ (design §1.2, "Url ownership").
nvb_error *urlParse(nvb_bytes url, nvb_url **out) noexcept
{
    if (out)
        *out = nullptr;
    return guarded([url, out]() {
        ConnectionParams params;
        QString path;
        const Result r = Url::parse(toUtf8String(url), &params, &path);
        if (r.ok() && out)
            *out = packUrl(params, path);
        return r;
    });
}

nvb_error *urlFormat(const nvb_params *params, nvb_bytes path, nvb_blob **out) noexcept
{
    if (out)
        *out = nullptr;
    return guarded([params, path, out]() {
        if (!params)
            throw std::invalid_argument("no parameters");
        ConnectionParams p;
        if (const Result r = toParams(*params, &p); !r.ok())
            return r;
        const QString url = Url::format(p, toPath(path));
        if (url.isEmpty())
            return Result(Error::Unsupported, QStringLiteral("No URL form for provider \"%1\"").arg(p.provider));
        if (out)
            *out = packBlob(url.toUtf8());
        return Result::success();
    });
}

// Field order as in the header.
const nvb_ffi_v1 Table = {
    NVB_FFI_VERSION,
    sizeof(nvb_ffi_v1),
    init,
    run,
    quit,
    post,
    shutdown,
    freeBlock,
    providerAvailable,
    urlParse,
    urlFormat,
    connNew,
    connFree,
    connCancel,
    connResetCancel,
    connEstablish,
    replySet,
    connCapabilities,
    connStat,
    connList,
    connReadLink,
    connSpaceInfo,
    connChecksum,
    connMakeDir,
    connRemoveFile,
    connRemoveDir,
    connRename,
    connSetAttributes,
    connMakeSymlink,
    connMakeHardlink,
    connCopy,
    connOpenRead,
    handleRead,
    handleReadAhead,
    handleClose,
    connUpload,
    connDownload,
    removeTree,
    walk,
    copyAcross,
    discoveryNew,
    discoverySetRunning,
    discoveryFree,
};

} // namespace

Result internalResult(const std::exception_ptr &thrown)
{
    QString what = QStringLiteral("unknown exception");
    try {
        if (thrown)
            std::rethrow_exception(thrown);
    } catch (const std::exception &e) {
        what = QString::fromLocal8Bit(e.what());
    } catch (...) {
        // Not a std::exception: nothing more to say than "unknown".
    }
    qCWarning(lcNetVfsFfi).noquote() << "Internal error:" << what;
    return Result(Error::Internal, QStringLiteral("Internal error: %1").arg(what));
}

Backend *backendOf(const nvb_conn *conn)
{
    if (!conn || !conn->backend)
        throw std::invalid_argument("no connection");
    return conn->backend.get();
}

bool postToQt(std::function<void()> fn)
{
    App &a = app();
    std::scoped_lock lock(a.mutex);
    if (!a.queue || a.quitting)
        return false;
    // postEvent takes ownership of the event.
    QCoreApplication::postEvent(a.queue, std::make_unique<FunctorEvent>(std::move(fn)).release());
    return true;
}

bool onQtThread()
{
    const QCoreApplication *application = QCoreApplication::instance();
    return application && QThread::currentThread() == application->thread();
}

} // namespace NetVfs::Ffi

extern "C" __attribute__((visibility("default"))) const nvb_ffi_v1 *nvb_ffi_get(uint32_t version)
{
    return version == NVB_FFI_VERSION ? &NetVfs::Ffi::Table : nullptr;
}
