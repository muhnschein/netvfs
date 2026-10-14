// SPDX-License-Identifier: LGPL-2.1-or-later
// The fake backend's control table (nvb_fake.h, design §4.1).
#include "nvb_fake.h"

#include "fakebackend.h"
#include "names.h"

#include <QtCore/QMutexLocker>

#include <cstdlib>
#include <cstring>

namespace {

using NetVfs::Test::FakeServer;

FakeServer *server()
{
    return FakeServer::instance();
}

QByteArray bytesOf(nvb_bytes bytes)
{
    if (bytes.len == 0)
        return QByteArray();
    return QByteArray(reinterpret_cast<const char *>(bytes.ptr), static_cast<int>(bytes.len));
}

QString keyOf(nvb_bytes path)
{
    return FakeServer::keyFor(NetVfs::Names::decode(bytesOf(path)));
}

void reset()
{
    QMutexLocker lock(&server()->mutex);
    server()->reset();
}

void addFile(nvb_bytes path, nvb_bytes data)
{
    QMutexLocker lock(&server()->mutex);
    server()->addFile(keyOf(path), bytesOf(data));
}

void addDir(nvb_bytes path, int32_t mode)
{
    QMutexLocker lock(&server()->mutex);
    server()->addDir(keyOf(path), mode < 0 ? FakeServer::DefaultDirMode : mode);
}

void addSymlink(nvb_bytes path, nvb_bytes target)
{
    QMutexLocker lock(&server()->mutex);
    server()->addSymlink(keyOf(path), NetVfs::Names::decode(bytesOf(target)));
}

int32_t exists(nvb_bytes path)
{
    QMutexLocker lock(&server()->mutex);
    return server()->exists(keyOf(path)) ? 1 : 0;
}

// One block (O3): the nvb_blob, then its bytes.
nvb_blob *fileData(nvb_bytes path)
{
    QByteArray data;
    {
        QMutexLocker lock(&server()->mutex);
        const QString key = keyOf(path);
        if (!server()->exists(key) || server()->node(key).type != NetVfs::EntryType::File)
            return nullptr;
        data = server()->fileData(key);
    }
    const auto size = static_cast<size_t>(data.size());
    void *raw = std::malloc(sizeof(nvb_blob) + size);
    if (!raw)
        return nullptr;
    auto *blob = static_cast<nvb_blob *>(raw);
    auto *bytes = static_cast<uint8_t *>(raw) + sizeof(nvb_blob);
    if (size > 0)
        std::memcpy(bytes, data.constData(), size);
    blob->data = nvb_bytes { bytes, size };
    return blob;
}

int32_t nodeMode(nvb_bytes path)
{
    QMutexLocker lock(&server()->mutex);
    const QString key = keyOf(path);
    return server()->exists(key) ? server()->node(key).mode : -1;
}

void setIdentityPin(nvb_bytes pin)
{
    QMutexLocker lock(&server()->mutex);
    server()->identity = NetVfs::ServerIdentity::fromPin(QString::fromUtf8(bytesOf(pin)));
}

void setOtp(nvb_bytes otp)
{
    QMutexLocker lock(&server()->mutex);
    server()->otp = bytesOf(otp);
}

void setCredentials(nvb_bytes user, nvb_bytes secret)
{
    QMutexLocker lock(&server()->mutex);
    server()->userName = QString::fromUtf8(bytesOf(user));
    server()->secret = bytesOf(secret);
}

void setChunkDelayMs(int32_t ms)
{
    QMutexLocker lock(&server()->mutex);
    server()->chunkDelayMs = ms;
}

void failOp(nvb_bytes op, nvb_bytes errorName)
{
    const QString name = QString::fromUtf8(bytesOf(errorName));
    QMutexLocker lock(&server()->mutex);
    server()->failOps.insert(QString::fromUtf8(bytesOf(op)),
                             NetVfs::Result(NetVfs::errorFromName(name), QStringLiteral("Injected %1").arg(name)));
}

int32_t logCount(nvb_bytes prefix)
{
    const QString start = QString::fromUtf8(bytesOf(prefix));
    QMutexLocker lock(&server()->mutex);
    int32_t count = 0;
    for (const QString &line : server()->log)
        count += line.startsWith(start) ? 1 : 0;
    return count;
}

int32_t liveBackends()
{
    QMutexLocker lock(&server()->mutex);
    return server()->liveBackends;
}

void freeBlock(void *p)
{
    std::free(p);
}

const nvb_fake Table = {
    reset,
    addFile,
    addDir,
    addSymlink,
    exists,
    fileData,
    nodeMode,
    setIdentityPin,
    setOtp,
    setCredentials,
    setChunkDelayMs,
    failOp,
    logCount,
    liveBackends,
    freeBlock,
};

} // namespace

extern "C" __attribute__((visibility("default"))) const nvb_fake *nvb_fake_get()
{
    return &Table;
}
