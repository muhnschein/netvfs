// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CONFORMANCE_SUPPORT_H
#define NETVFS_CONFORMANCE_SUPPORT_H

#include "backend.h"

#include <QtCore/QIODevice>
#include <QtCore/QMap>

#include <functional>

namespace Conformance {

QByteArray pattern(qint64 size, int seed);

NetVfs::Result putFile(NetVfs::Backend *backend, const QString &path, const QByteArray &data,
                       NetVfs::WriteOptions::Disposition disposition = NetVfs::WriteOptions::Disposition::Truncate);
NetVfs::Result getFile(NetVfs::Backend *backend, const QString &path, QByteArray *data);
NetVfs::Result download(NetVfs::Backend *backend, const QString &path, qint64 offset, qint64 length,
                        QByteArray *data);
bool exists(NetVfs::Backend *backend, const QString &path);
QStringList names(NetVfs::Backend *backend, const QString &dir, NetVfs::Result *result = nullptr);
const NetVfs::Entry *find(const QVector<NetVfs::Entry> &entries, const QString &name);
NetVfs::Result removeRecursive(NetVfs::Backend *backend, const QString &path);

QMap<QString, QString> snapshot(NetVfs::Backend *backend, const QString &dir);

class RecordingSink : public NetVfs::ListSink
{
public:
    bool entries(const QVector<NetVfs::Entry> &batch) override;

    QVector<int> batchSizes;
    QVector<NetVfs::Entry> all;
    int stopAfterBatches = -1;
    NetVfs::Backend *cancelBackend = nullptr;
};

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

NetVfs::Result runCanceled(NetVfs::Backend *backend, int delayMs, const std::function<NetVfs::Result()> &call,
                           qint64 *cancelToReturnMs);

bool runShell(const QString &command, QString *output);

}

#endif
