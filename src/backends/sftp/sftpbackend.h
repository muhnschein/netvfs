// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SFTPBACKEND_H
#define NETVFS_SFTPBACKEND_H

#include "backend.h"

#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <QtCore/QElapsedTimer>
#include <QtCore/QSet>

#include <atomic>

namespace NetVfs::Sftp {

// Backend over libssh (SPEC-sftp, SPEC-v2 §6.1). One ssh_session per
// instance, used from one thread (S-4); only cancel() may be called from
// another thread.
class SftpBackend : public Backend
{
public:
    SftpBackend() = default;
    SftpBackend(const SftpBackend &) = delete;
    SftpBackend &operator=(const SftpBackend &) = delete;
    ~SftpBackend() override;

    using Backend::authenticate;
    using Backend::list;

    Result connect(const ConnectionParams &params, ServerIdentity *seen) override;
    Result authenticate(const Credentials &credentials, AuthPrompter *prompter) override;
    Capabilities capabilities() const override;

    Result stat(const QString &path, Entry *out) override;
    Result lstat(const QString &path, Entry *out) override;
    Result list(const QString &dir, ListSink *sink, const ListOptions &options) override;

    Result makeDir(const QString &path, bool exclusive) override;
    Result removeFile(const QString &path) override;
    Result removeDir(const QString &path) override;
    Result rename(const QString &from, const QString &to, RenameMode mode) override;

    Result openRead(const QString &path, ReadHandle **out) override;
    Result upload(QIODevice *source, const QString &path, const UploadOptions &options, Progress *progress) override;
    Result download(const QString &path, QIODevice *sink, const DownloadOptions &options, Progress *progress) override;

    Result spaceInfo(const QString &dir, SpaceInfo *out) override;
    Result keepAlive() override;

    void cancel() override;
    void resetCancel() override;
    void disconnect() override;

protected:
    // Called after the connection policy (S-1, S-5) has been applied and
    // before ssh_connect(). Production code does not override it; the interop
    // tests use it to emulate an old server by narrowing the key exchange.
    virtual void configureSession(ssh_session session);

private:
    struct Pending {
        sftp_aio aio = nullptr;
        size_t length = 0;
        quint64 offset = 0;
    };
    class PendingQueue;
    class Io;      // transfers (sftpbackend.cpp)
    class Login;   // sign-in methods (sftpbackend.cpp)
    class Reader;  // ReadHandle (sftpbackend.cpp)
    struct Sink {
        QIODevice *device = nullptr;
        Progress *progress = nullptr;
        qint64 total = -1;
        qint64 done = 0;
        qint64 limit = -1;            // bytes wanted; -1: to the end of the file
    };

    void closeSession();
    Result openTransport(bool restrictHostKey, ServerIdentity *seen);
    Result applyOptions(bool restrictHostKey) const;
    bool setTimeout(int milliseconds) const;
    Result sessionFailure() const;
    Result sftpFailure(const QString &context) const;
    Result writeFailure(const QByteArray &remote, qint64 attempted) const;
    Result established(const Result &failure) const;
    bool transportLost() const;
    Result checkReady() const;
    Result resolve(const QString &path, QByteArray *remote) const;
    Result ready(const QString &path, QByteArray *remote) const;

    Result openSftp();
    void detectCapabilities();

    Result statRemote(const QByteArray &remote, Entry *out, bool follow = true) const;
    Result readEntries(sftp_dir handle, const QByteArray &remote, ListSink *sink, const ListOptions &options) const;
    void resolveTarget(const QByteArray &dir, Entry *entry, int *budget) const;
    Result freeBytes(const QByteArray &remote, qint64 *bytes) const;
    bool hasChildren(const QByteArray &remote) const;
    Result renameReplacing(const QByteArray &source, const QByteArray &target, bool targetExists);
    Result renameNoReplace(const QByteArray &source, const QByteArray &target);
    Result openForUpload(const QByteArray &remote, const WriteOptions &options, sftp_file *file) const;
    Result openForDownload(const QByteArray &remote, const DownloadOptions &options, sftp_file *file, Sink *sink) const;
    Result waitGlobalReply(const QElapsedTimer &started) const;
    mode_t directoryMode() const;

    int closeFile(sftp_file file, bool healthy) const;

    ssh_session m_session = nullptr;
    sftp_session m_sftp = nullptr;
    ConnectionParams m_params;
    QByteArray m_home;                // S-19 start directory
    bool m_identityMismatch = false;  // SEC-1 guard, see openTransport()
    bool m_hasFsync = false;
    bool m_hasStatvfs = false;
    bool m_hasPosixRename = false;
    bool m_nativeNoReplace = false;   // XS-6: OpenSSH fails SSH_FXP_RENAME on an existing target
    size_t m_writeChunk = 0;
    size_t m_readChunk = 0;
    Capabilities m_capabilities;
    QSet<Reader *> m_readers;         // open handles, closed by closeSession()
    std::atomic<bool> m_canceled { false };
};

} // namespace NetVfs::Sftp

#endif
