// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_FAKEBACKEND_H
#define NETVFS_TEST_FAKEBACKEND_H

#include "backend.h"

#include <QtCore/QHash>
#include <QtCore/QMutex>
#include <QtCore/QStringList>

#include <atomic>

namespace NetVfs {
namespace Test {

// In-memory server shared by all FakeBackend instances, with fault injection.
// Implements the whole v2 Backend contract (SPEC-v2 §4) so that consumers and
// helpers can be tested without a container.
//
// Paths are stored normalized without a leading '/'; "" is the root folder,
// which always exists. Symlink targets are stored verbatim; relative targets
// resolve against the link's folder, absolute ones against the root.
// Hard links share their content through a link group (no inodes).
//
// Every call appends "<op>:<path>" to `log` (see FakeBackend) and first
// consults `failOps`: an entry for the op name is returned once.
class Q_DECL_EXPORT FakeServer
{
public:
    struct Node {
        EntryType type = EntryType::File;
        QByteArray data;
        QDateTime modified;
        QDateTime accessed;
        qint32 mode = 0644;
        QString target;                 // Symlink: verbatim target
        int linkGroup = 0;              // hard links: nodes with the same group share data
        bool isDir() const { return type == EntryType::Directory; }
    };

    static constexpr qint32 DefaultFileMode = 0644;
    static constexpr qint32 DefaultDirMode = 0755;

    static FakeServer *instance();
    void reset();

    // Everything the fake implements; the default of `capabilities`.
    static Capabilities fullCapabilities();

    // Configuration
    ServerIdentity identity;            // reported by connect()
    QString userName = QStringLiteral("user");
    QByteArray secret = "secret";
    QByteArray otp;                     // non-empty: asked through the AuthPrompter
    Capabilities capabilities;          // reported by capabilities(); gates the optional methods
    qint64 freeBytes = 1LL << 40;      // -1: spaceInfo() reports free space as unknown
    qint64 totalBytes = 1LL << 41;
    Result connectResult;               // returned by connect()
    QHash<QString, Result> failOps;     // op name -> result to return (once)
    qint64 failUploadAfterBytes = -1;   // simulate a dropped connection (ConnectionLost)
    int chunkDelayMs = 0;               // per 64 KiB chunk, for cancel tests
    bool reportSizeMismatch = false;    // stat() of .part lies about the size

    // State
    QHash<QString, Node> nodes;
    QStringList log;                    // "connect", "authenticate", "upload:<path>", ...
    int liveBackends = 0;
    ConnectionParams lastParams;        // given to the last connect()

    // add*() create missing parent folders.
    void addFile(const QString &path, const QByteArray &data, const QDateTime &modified = QDateTime::currentDateTimeUtc(),
                 qint32 mode = DefaultFileMode);
    void addDir(const QString &path, qint32 mode = DefaultDirMode);   // with missing parents
    void addSymlink(const QString &path, const QString &target);
    void addSpecial(const QString &path);
    bool exists(const QString &path) const;
    QByteArray fileData(const QString &path) const;
    Node node(const QString &path) const;
    QStringList children(const QString &dir) const;   // sorted names

    // Stores `data` for `path` and every hard link of it.
    void setData(const QString &path, const QByteArray &data);
    // Resolves symlinks in `path` (all components, the last one only with
    // `followLast`). NotFound for dangling links, ProtocolError for loops.
    Result resolve(const QString &path, bool followLast, QString *resolved) const;

    QMutex mutex;

private:
    FakeServer() { reset(); }
    int m_nextLinkGroup = 1;
    friend class FakeBackend;
};

class Q_DECL_EXPORT FakeBackend : public Backend
{
public:
    explicit FakeBackend(FakeServer *server = FakeServer::instance());
    ~FakeBackend() override;

    using Backend::list;
    using Backend::authenticate;

    Result connect(const ConnectionParams &params, ServerIdentity *seen) override;
    Result authenticate(const Credentials &credentials, AuthPrompter *prompter) override;
    Capabilities capabilities() const override;

    Result stat(const QString &path, Entry *out) override;
    Result lstat(const QString &path, Entry *out) override;
    Result list(const QString &dir, ListSink *sink, const ListOptions &options) override;

    Result makeDir(const QString &path, bool exclusive) override;
    Result removeFile(const QString &path) override;
    Result removeDir(const QString &path) override;
    Result removeTreeNative(const QString &path) override;
    Result rename(const QString &from, const QString &to, RenameMode mode) override;
    Result setAttributes(const QString &path, const AttributeChanges &changes) override;
    Result readLink(const QString &path, QString *target) override;
    Result makeSymlink(const QString &target, const QString &linkPath) override;
    Result makeHardlink(const QString &existing, const QString &newPath) override;

    Result openRead(const QString &path, ReadHandle **out) override;
    Result openWrite(const QString &path, const WriteOptions &options, WriteHandle **out) override;
    Result upload(QIODevice *source, const QString &path, const UploadOptions &options, Progress *progress) override;
    Result download(const QString &path, QIODevice *sink, const DownloadOptions &options, Progress *progress) override;

    Result copy(const QString &from, const QString &to, const CopyOptions &options) override;
    Result checksum(const QString &path, const QString &algorithm, QByteArray *digest) override;
    Result spaceInfo(const QString &dir, SpaceInfo *out) override;
    Result keepAlive() override;

    void cancel() override;
    void resetCancel() override;
    void disconnect() override;

private:
    class Reader;
    class Writer;

    // Logs `op`, then: Canceled, an injected failure, or "not authenticated".
    // Called with the server mutex held.
    Result begin(const QString &op, bool needAuth = true);
    bool has(Capability c) const;
    Entry entryFor(const QString &key, const FakeServer::Node &node, bool resolveTarget) const;
    // Opens `key` for writing per `options` (server mutex held).
    Result prepareWrite(const QString &key, const WriteOptions &options, QString *resolved);
    // Applies the mtime of a finished write (server mutex held).
    void finishWrite(const QString &resolved, const WriteOptions &options);
    Result checkHandle(quint64 generation) const;
    static Result key(const QString &path, QString *out);

    FakeServer *m_server;
    ConnectionParams m_params;
    bool m_connected = false;
    bool m_authenticated = false;
    quint64 m_generation = 0;           // bumped by disconnect(): handles become stale
    std::atomic<bool> m_canceled { false };
};

} // namespace Test
} // namespace NetVfs

#endif
