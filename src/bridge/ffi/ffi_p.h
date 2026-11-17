// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_FFI_P_H
#define NETVFS_BRIDGE_FFI_P_H

// Internals of libnetvfs-bridge-ffi.so. Nothing here is exported; the only symbol is nvb_ffi_get.
#include "netvfs_bridge_ffi.h"

#include "backend.h"
#include "marshal.h"
#include "ops.h"

#include <QtCore/QLoggingCategory>

#include <atomic>
#include <exception>
#include <functional>
#include <map>
#include <memory>

Q_DECLARE_LOGGING_CATEGORY(lcNetVfsFfi)

struct nvb_handle {
    nvb_conn *conn = nullptr;
    std::unique_ptr<NetVfs::ReadHandle> handle;
};

// One backend connection. Used from its owner thread only, except `canceled` and Backend::cancel(),
// which conn_cancel reaches from any thread.
struct nvb_conn {
    std::unique_ptr<NetVfs::Backend> backend;
    std::atomic<bool> canceled { false };
    std::map<const nvb_handle *, std::unique_ptr<nvb_handle>> handles;

    nvb_conn() = default;
    nvb_conn(const nvb_conn &) = delete;
    nvb_conn &operator=(const nvb_conn &) = delete;
    // Handles go before their backend; then disconnect().
    ~nvb_conn();
};

// Answers of one keyboard-interactive prompt. Wiped when replaced and on destruction.
struct nvb_reply {
    QVector<QByteArray> answers;

    nvb_reply() = default;
    nvb_reply(const nvb_reply &) = delete;
    nvb_reply &operator=(const nvb_reply &) = delete;
    ~nvb_reply() { wipe(); }
    void wipe();
};

namespace NetVfs::Ffi {

// Nothing thrown crosses the ABI. A table function runs its body through one of these; an exception
// is logged and becomes Internal (or `fallback`). If even the Internal error cannot be allocated,
// std::terminate() (the functions are noexcept).
Result internalResult(const std::exception_ptr &thrown);

template <typename Body>
nvb_error *guarded(const Body &body) noexcept
{
    try {
        return packError(body());
    } catch (...) {
        return packError(internalResult(std::current_exception()));
    }
}

template <typename T, typename Body>
T guardedValue(T fallback, const Body &body) noexcept
{
    try {
        return body();
    } catch (...) {
        internalResult(std::current_exception());
        return fallback;
    }
}

template <typename Body>
void guardedVoid(const Body &body) noexcept
{
    try {
        body();
    } catch (...) {
        internalResult(std::current_exception());
    }
}

// C side of a transfer or tree operation's progress (nvb_progress and each of its functions may be
// null).
class ProgressAdapter final : public Progress, public Ops::TreeProgress
{
public:
    explicit ProgressAdapter(const nvb_progress *progress) : m_progress(progress) {}

    void update(qint64 done, qint64 total) override;
    bool canceled() const override;
    bool removed(const QString &path, bool isDir, qint64 files, qint64 dirs) override;

private:
    const nvb_progress *m_progress;
};

Backend *backendOf(const nvb_conn *conn);

// Runs `fn` on the Qt thread (MainQueue of init()); false when there is no application or it is
// quitting: `fn` never runs then.
bool postToQt(std::function<void()> fn);
bool onQtThread();

nvb_error *connNew(nvb_bytes provider, nvb_conn **out) noexcept;
void connFree(nvb_conn *conn) noexcept;
void connCancel(nvb_conn *conn) noexcept;
void connResetCancel(nvb_conn *conn) noexcept;
nvb_error *connCapabilities(nvb_conn *conn, nvb_capabilities **out) noexcept;
nvb_error *connStat(nvb_conn *conn, nvb_bytes path, int32_t follow, nvb_entry **out) noexcept;
nvb_error *connList(nvb_conn *conn, nvb_bytes dir, uint32_t batchSize, nvb_list_sink_fn sink,
                    void *ctx) noexcept;
nvb_error *connReadLink(nvb_conn *conn, nvb_bytes path, nvb_blob **target) noexcept;
nvb_error *connSpaceInfo(nvb_conn *conn, nvb_bytes path, nvb_space *out) noexcept;
nvb_error *connChecksum(nvb_conn *conn, nvb_bytes path, nvb_bytes algorithm, nvb_blob **digest) noexcept;
nvb_error *connMakeDir(nvb_conn *conn, nvb_bytes path, int32_t exclusive) noexcept;
nvb_error *connRemoveFile(nvb_conn *conn, nvb_bytes path) noexcept;
nvb_error *connRemoveDir(nvb_conn *conn, nvb_bytes path) noexcept;
nvb_error *connRename(nvb_conn *conn, nvb_bytes from, nvb_bytes to, int32_t replace) noexcept;
nvb_error *connSetAttributes(nvb_conn *conn, nvb_bytes path, const nvb_attributes *changes) noexcept;
nvb_error *connMakeSymlink(nvb_conn *conn, nvb_bytes target, nvb_bytes linkPath) noexcept;
nvb_error *connMakeHardlink(nvb_conn *conn, nvb_bytes existing, nvb_bytes newPath) noexcept;
nvb_error *connCopy(nvb_conn *conn, nvb_bytes from, nvb_bytes to, int32_t recursive, int32_t replace) noexcept;
nvb_error *connOpenRead(nvb_conn *conn, nvb_bytes path, nvb_handle **out, int64_t *size) noexcept;
nvb_error *handleRead(nvb_handle *h, int64_t offset, uint8_t *buf, size_t cap, size_t *len) noexcept;
void handleReadAhead(nvb_handle *h, int64_t offset, int64_t bytes) noexcept;
nvb_error *handleClose(nvb_handle *h) noexcept;
nvb_error *connEstablish(nvb_conn *conn, const nvb_params *params, nvb_bytes pin, const nvb_secret *secret,
                         const nvb_establish_hooks *hooks, uint32_t *phase) noexcept;
void replySet(nvb_reply *reply, const nvb_bytes *answers, size_t count) noexcept;
nvb_error *connUpload(nvb_conn *conn, nvb_bytes path, const nvb_upload_opts *opts, const nvb_io *io,
                      const nvb_progress *progress) noexcept;
nvb_error *connDownload(nvb_conn *conn, nvb_bytes path, int64_t offset, int64_t length, const nvb_io *io,
                        const nvb_progress *progress) noexcept;
nvb_error *removeTree(nvb_conn *conn, nvb_bytes path, const nvb_progress *progress, int64_t *files,
                      int64_t *dirs) noexcept;
nvb_error *walk(nvb_conn *conn, nvb_bytes root, const nvb_walk_opts *opts, nvb_walk_visit_fn visit,
                void *ctx) noexcept;
nvb_error *copyAcross(nvb_conn *source, nvb_bytes sourcePath, nvb_conn *destination, nvb_bytes destinationPath,
                      int32_t recursive, int32_t replace, const nvb_progress *progress) noexcept;
nvb_discovery *discoveryNew(const nvb_discovery_hooks *hooks) noexcept;
int32_t discoverySetRunning(nvb_discovery *d, int32_t on) noexcept;
void discoveryFree(nvb_discovery *d) noexcept;

}
#endif
