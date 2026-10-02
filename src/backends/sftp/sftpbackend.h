// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SFTPBACKEND_H
#define NETVFS_SFTPBACKEND_H

#include "backend.h"

#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <QtCore/QElapsedTimer>

#include <atomic>

namespace NetVfs::Sftp {

// Backend over libssh (SPEC-sftp). One ssh_session per instance, used from
// one thread (S-4); only cancel() may be called from another thread.
class SftpBackend : public Backend
{
public:
    SftpBackend() = default;
    SftpBackend(const SftpBackend &) = delete;
    SftpBackend &operator=(const SftpBackend &) = delete;
    ~SftpBackend() override;

    Result connect(const ConnectionParams &params, ServerIdentity *seen) override;
    Result authenticate(const Credentials &credentials) override;

    Result stat(const QString &path, Entry *out) override;
    Result list(const QString &dir, QVector<Entry> *out) override;
    Result makePath(const QString &dir) override;
    Result remove(const QString &path) override;
    Result rename(const QString &from, const QString &to) override;
    Result freeSpace(const QString &dir, qint64 *bytes) override;
    Result upload(QIODevice *source, const QString &path, Progress *progress) override;
    Result download(const QString &path, QIODevice *sink, Progress *progress) override;
    Result read(const QString &path, qint64 offset, qint64 length, QByteArray *out) override;

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
    struct Sink {
        QIODevice *device = nullptr;
        Progress *progress = nullptr;
        qint64 total = -1;
        qint64 done = 0;
    };

    void closeSession();
    Result openTransport(bool restrictHostKey, ServerIdentity *seen);
    Result applyOptions(bool restrictHostKey) const;
    bool setTimeout(int milliseconds) const;
    Result sessionFailure() const;
    Result sftpFailure(const QString &context) const;
    Result writeFailure(const QByteArray &remote, qint64 attempted) const;
    Result checkReady() const;
    Result resolve(const QString &path, QByteArray *remote) const;

    Result openSftp();

    Result statRemote(const QByteArray &remote, Entry *out) const;
    Result freeBytes(const QByteArray &remote, qint64 *bytes) const;
    Result makeDirectory(const QByteArray &remote) const;
    Result removeRemote(const QByteArray &remote) const;

    int closeFile(sftp_file file, bool healthy) const;

    ssh_session m_session = nullptr;
    sftp_session m_sftp = nullptr;
    ConnectionParams m_params;
    QByteArray m_home;                // S-19 start directory
    bool m_identityMismatch = false;  // SEC-1 guard, see openTransport()
    bool m_hasFsync = false;
    bool m_hasStatvfs = false;
    bool m_hasPosixRename = false;
    size_t m_writeChunk = 0;
    size_t m_readChunk = 0;
    std::atomic<bool> m_canceled { false };
};

} // namespace NetVfs::Sftp

#endif
