// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_MEMORYBACKEND_H
#define NETVFS_TEST_MEMORYBACKEND_H

#include "backend.h"

#include <atomic>
#include <functional>
#include <map>

// A self-contained in-memory v2 Backend for the Ops tests: folders, files,
// symlinks (resolved like a file system, including through path components),
// batched listings, fault injection and an operation log. Single-threaded
// like every backend, except cancel() which is thread-safe.
class MemoryBackend : public NetVfs::Backend
{
public:
    struct Node {
        NetVfs::EntryType type = NetVfs::EntryType::File;
        QByteArray data;                 // file contents unless discarded
        qint64 size = 0;
        quint64 hash = 0;                // FNV-1a of the contents
        QString target;                  // symlink
        QDateTime modified;
        qint64 generated = -1;           // >= 0: contents are pattern(offset), nothing stored
    };

    MemoryBackend();

    // ---- building and inspecting
    void addDir(const QString &path);
    void addFile(const QString &path, const QByteArray &data);
    void addGenerated(const QString &path, qint64 size);
    void addSymlink(const QString &path, const QString &target);
    bool exists(const QString &path) const;
    Node node(const QString &path) const;
    QByteArray fileData(const QString &path) const;
    QStringList paths() const;           // every key, sorted
    static quint64 patternHash(qint64 size);
    static char patternByte(qint64 offset);
    static quint64 hashOf(const QByteArray &data);

    // ---- knobs
    NetVfs::Capabilities caps;
    QStringList log;                     // "<op> <path>" per call
    // Called at the start of every operation; a failure is returned as is.
    std::function<NetVfs::Result(const QString &op, const QString &path)> intercept;
    bool listSymlinksAsTargets = false;  // hostile: list reports a link to a folder as a folder
    bool discardData = false;            // uploads keep only size and hash
    qint64 chunkSize = 16 * 1024;
    int chunkDelayUs = 0;                // sleep per uploaded chunk
    qint64 failDownloadAfter = -1;       // ConnectionLost after this many bytes
    qint64 failUploadAfter = -1;         // NoSpace after this many bytes
    std::atomic<qint64> bytesWritten { 0 };   // handed to the download sink
    std::atomic<qint64> bytesRead { 0 };      // taken from the upload source

    // ---- Backend
    using Backend::authenticate;
    using Backend::list;
    NetVfs::Result connect(const NetVfs::ConnectionParams &params, NetVfs::ServerIdentity *seen) override;
    NetVfs::Result authenticate(const NetVfs::Credentials &credentials, NetVfs::AuthPrompter *prompter) override;
    NetVfs::Capabilities capabilities() const override { return caps; }
    NetVfs::Result stat(const QString &path, NetVfs::Entry *out) override;
    NetVfs::Result lstat(const QString &path, NetVfs::Entry *out) override;
    NetVfs::Result list(const QString &dir, NetVfs::ListSink *sink, const NetVfs::ListOptions &options) override;
    NetVfs::Result makeDir(const QString &path, bool exclusive) override;
    NetVfs::Result removeFile(const QString &path) override;
    NetVfs::Result removeDir(const QString &path) override;
    NetVfs::Result removeTreeNative(const QString &path) override;
    NetVfs::Result rename(const QString &from, const QString &to, NetVfs::RenameMode mode) override;
    NetVfs::Result readLink(const QString &path, QString *target) override;
    NetVfs::Result upload(QIODevice *source, const QString &path, const NetVfs::UploadOptions &options,
                          NetVfs::Progress *progress) override;
    NetVfs::Result download(const QString &path, QIODevice *sink, const NetVfs::DownloadOptions &options,
                            NetVfs::Progress *progress) override;
    NetVfs::Result keepAlive() override { return NetVfs::Result::success(); }
    void cancel() override { m_canceled = true; }
    void resetCancel() override { m_canceled = false; }
    void disconnect() override {}

private:
    NetVfs::Result begin(const char *op, const QString &path, QString *key);
    NetVfs::Result resolve(const QString &key, bool followLast, QString *out, int hops = 0) const;
    NetVfs::Entry entryFor(const QString &name, const Node &node) const;
    NetVfs::Result find(const char *op, const QString &path, bool followLast, QString *key, Node **node);
    bool isEmptyDir(const QString &key) const;
    NetVfs::Result checkWritable(const QString &key, const NetVfs::WriteOptions &options);

    std::map<QString, Node> m_nodes;     // key: normalized path without a leading '/'
    std::atomic<bool> m_canceled { false };
};

#endif
