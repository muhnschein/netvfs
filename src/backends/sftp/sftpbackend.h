// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SFTPBACKEND_H
#define NETVFS_SFTPBACKEND_H

#include "backend.h"
#include "sftpshell.h"
#include "sftpsupport.h"
#include "shellexec.h"

#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <QtCore/QHash>
#include <QtCore/QSet>

#include <atomic>
#include <mutex>

// What libssh's interrupt callback gets (vendor/patches/libssh/0002): the
// application defines the struct, libssh only passes the pointer on.
struct sftp_interrupt_struct {
    const std::atomic<bool> *canceled = nullptr;
};

namespace NetVfs::Sftp {

// Backend over libssh (SPEC-sftp, SPEC-v2 §6.1). One ssh_session per
// instance, used from one thread (S-4); only cancel() may be called from
// another thread.
//
// Handles (XC-13): no limit of their own; the server's applies (OpenSSH:
// 512 open handles per session). Read-ahead is capped at RequestWindow
// requests of one chunk, at most 4 MiB in flight per handle.
//
// ShellExec (XS-9, amends SPEC-sftp S-3): with the account option
// allow_shell=true, and only if the server runs a probe command on an exec
// channel at sign-in, the backend reports ShellExec and serves copy() and
// checksum("sha256") through fixed command templates. Without the option it
// never opens anything but the sftp subsystem (S-3 unchanged).
//
// The work is split over nested classes, each in its own source file:
// Connection (sftpconnection.cpp), Requests (sftprequests.cpp), Login
// (sftplogin.cpp), Io, Reader, Writer (sftpio.cpp), Shell, Tools
// (sftpexec.cpp). This class holds the state and the API entry points.
class SftpBackend : public Backend, public ShellExec
{
public:
    SftpBackend();
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

    // ShellExec (XS-9)
    Result exec(const QStringList &argv, const ExecOptions &options, ExecResult *result) override;
    Result find(const QString &dir, const QString &namePattern, int maxResults, QStringList *paths) override;

protected:
    // Called after the connection policy (S-1, S-5) has been applied and
    // before ssh_connect(). Production code does not override it; the interop
    // tests use it to emulate an old server by narrowing the key exchange,
    // and to open a channel of their own (XC-21).
    virtual void configureSession(ssh_session session);

private:
    struct Pending {
        sftp_aio aio = nullptr;
        size_t length = 0;
        quint64 offset = 0;
    };
    struct Sink {
        QIODevice *device = nullptr;
        Progress *progress = nullptr;
        qint64 total = -1;
        qint64 done = 0;
        qint64 limit = -1;            // bytes wanted; -1: to the end of the file
    };
    class Connection;    // connect, sign-in setup, capabilities, teardown
    class Requests;      // paths, error mapping and the requests the API calls share
    class Login;         // sign-in methods
    class PendingQueue;
    class Io;            // pipelined transfers
    class Reader;        // ReadHandle
    class Writer;        // WriteHandle
    class Shell;         // one command on an exec channel
    class Tools;         // copy, checksum and find over Shell

    ssh_session m_session = nullptr;
    sftp_session m_sftp = nullptr;
    ConnectionParams m_params;
    QByteArray m_home;                // S-19 start directory
    bool m_identityMismatch = false;  // SEC-1 guard, see Connection::openTransport()
    bool m_hasFsync = false;
    bool m_hasStatvfs = false;
    bool m_hasPosixRename = false;
    bool m_hasHardlink = false;
    bool m_hasUsersGroups = false;    // XS-2, and it answered at sign-in
    bool m_nativeNoReplace = false;   // XS-6: OpenSSH fails SSH_FXP_RENAME on an existing target
    SymlinkOrder m_symlinkOrder = SymlinkOrder::Unverified;   // XS-4
    bool m_lstatFollows = false;      // lstatFollowsLinks(): READLINK tells links apart
    bool m_shell = false;             // XS-9: allowed and the probe passed
    ShellTools m_shellTools;
    size_t m_writeChunk = 0;
    size_t m_readChunk = 0;
    Capabilities m_capabilities;
    // XS-2: names by id, per connection.
    mutable QHash<quint32, QString> m_userNames;
    mutable QHash<quint32, QString> m_groupNames;
    QSet<Reader *> m_readers;         // open handles, closed with the connection
    QSet<Writer *> m_writers;
    std::atomic<bool> m_canceled { false };
    sftp_interrupt_struct m_interrupt;   // m_canceled for libssh's waits
    // XC-22: the prompter answer() runs in; cancel() reaches it.
    std::mutex m_prompterMutex;
    AuthPrompter *m_prompter = nullptr;
};

} // namespace NetVfs::Sftp

#endif
