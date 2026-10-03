// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CONFORMANCE_SUPPORT_H
#define NETVFS_CONFORMANCE_SUPPORT_H

#include "backend.h"

#include <QtCore/QIODevice>
#include <QtCore/QMap>

#include <functional>

// Helpers for tst_conformance; everything goes through the Backend API.
namespace Conformance {

// Deterministic test data.
QByteArray pattern(qint64 size, int seed);

// Writes `data` to `path` with upload() (Truncate unless given).
NetVfs::Result putFile(NetVfs::Backend *backend, const QString &path, const QByteArray &data,
                       NetVfs::WriteOptions::Disposition disposition = NetVfs::WriteOptions::Disposition::Truncate);
// The whole file through download().
NetVfs::Result getFile(NetVfs::Backend *backend, const QString &path, QByteArray *data);
NetVfs::Result download(NetVfs::Backend *backend, const QString &path, qint64 offset, qint64 length,
                        QByteArray *data);
bool exists(NetVfs::Backend *backend, const QString &path);
QStringList names(NetVfs::Backend *backend, const QString &dir, NetVfs::Result *result = nullptr);
const NetVfs::Entry *find(const QVector<NetVfs::Entry> &entries, const QString &name);
// Depth-first removal through list/removeFile/removeDir; never follows links.
NetVfs::Result removeRecursive(NetVfs::Backend *backend, const QString &path);

// Recursive listing (lstat semantics) as path -> "type size mode mtime
// [content digest]", for side-effect checks.
QMap<QString, QString> snapshot(NetVfs::Backend *backend, const QString &dir);

// Records every batch; optionally stops or cancels the backend.
class RecordingSink : public NetVfs::ListSink
{
public:
    bool entries(const QVector<NetVfs::Entry> &batch) override;

    QVector<int> batchSizes;
    QVector<NetVfs::Entry> all;
    int stopAfterBatches = -1;                 // return false after this many
    NetVfs::Backend *cancelBackend = nullptr;  // cancel() on the first batch
};

// Records updates; can ask for cancellation (Progress::canceled) or cancel
// the backend after the first update.
class RecordingProgress : public NetVfs::Progress
{
public:
    void update(qint64 done, qint64 total) override;
    bool canceled() const override { return cancelAfterFirst && !updates.isEmpty(); }

    QVector<QPair<qint64, qint64>> updates;
    bool cancelAfterFirst = false;
    NetVfs::Backend *cancelBackend = nullptr;
    bool monotonic = true;
};

// Sequential source of `size` bytes: zeros with `marker` at `markerOffset`;
// for multi-GiB uploads without the memory.
class ZeroDevice : public QIODevice
{
public:
    ZeroDevice(qint64 size, qint64 markerOffset, const QByteArray &marker);
    bool isSequential() const override { return true; }

protected:
    qint64 readData(char *data, qint64 maxSize) override;
    qint64 writeData(const char *data, qint64 maxSize) override;

private:
    qint64 m_size;
    qint64 m_position = 0;
    qint64 m_markerOffset;
    QByteArray m_marker;
};

// A FIFO at `hostPath` that this process holds open for reading and
// writing: a backend reading it finds no data and a backend writing it
// fills the pipe, so either waits until cancel() (C-9 stall for targets
// whose folder is visible on this host).
class FifoStall
{
public:
    explicit FifoStall(const QString &hostPath);
    ~FifoStall();
    FifoStall(const FifoStall &) = delete;
    FifoStall &operator=(const FifoStall &) = delete;
    bool isOpen() const { return m_fd >= 0; }

private:
    int m_fd = -1;
};

// Runs `call` on this thread while another thread calls backend->cancel()
// after `delayMs`. `*cancelToReturnMs` is the time from cancel() to the
// return of `call` (C-9: at most 2 s).
NetVfs::Result runCanceled(NetVfs::Backend *backend, int delayMs, const std::function<NetVfs::Result()> &call,
                           qint64 *cancelToReturnMs);

// Runs a shell command (stall proxy hooks); true on exit code 0.
bool runShell(const QString &command, QString *output);

} // namespace Conformance

#endif
