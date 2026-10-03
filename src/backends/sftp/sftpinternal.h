// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SFTPINTERNAL_H
#define NETVFS_SFTPINTERNAL_H

#include "sftpbackend.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <sys/types.h>

// Declarations shared by the backend's source files. Free helpers are
// defined in sftprequests.cpp.
namespace NetVfs::Sftp {

constexpr int PollIntervalMs = 100;
// Closing a handle after a cancel or timeout must not undo C-9's 2 s bound.
constexpr int CleanupTimeoutMs = 1000;
// XC-23: without a requested mode the server's umask decides. libssh always
// sends a mode; these are what OpenSSH's sftp-server and mkdir(1) use when
// none is given.
constexpr mode_t DefaultDirectoryMode = 0777;
constexpr mode_t DefaultFileMode = 0666;
constexpr mode_t PermissionBits = 07777;

QString text(const char *value);
// Remote names in messages: lossless decode, escapes shown as U+FFFD (XS-1).
QString display(const QByteArray &remote);
QByteArray lastComponent(const QByteArray &remote);
QByteArray joinRemote(const QByteArray &dir, const QByteArray &name);
// XS-2 without names (those need users-groups-by-id@openssh.com).
Entry entryFrom(const sftp_attributes_struct &attributes, const QString &name);
Result invalidRange();
Result canceled();
Result handleLost();

// Connection set-up and teardown (sftpconnection.cpp; detectShell() in
// sftpexec.cpp).
class SftpBackend::Connection
{
public:
    explicit Connection(SftpBackend &backend) : m_b(backend) {}

    Result open(const ConnectionParams &params, ServerIdentity *seen);
    void close();
    Result openSftp();
    void setPrompter(AuthPrompter *prompter);

private:
    Result openTransport(bool restrictHostKey, ServerIdentity *seen);
    Result applyOptions(bool restrictHostKey) const;
    void invalidateHandles();
    void detectCapabilities();
    void detectOwnership();
    void detectShell();
    static int interrupted(const sftp_interrupt_struct *interrupt);

    SftpBackend &m_b;
};

// Paths, error mapping and the requests several API calls share
// (sftprequests.cpp).
class SftpBackend::Requests
{
public:
    explicit Requests(const SftpBackend &backend) : m_b(backend) {}

    Result checkReady() const;
    Result resolve(const QString &path, QByteArray *remote) const;
    Result ready(const QString &path, QByteArray *remote) const;
    bool setTimeout(int milliseconds) const;
    int closeFile(sftp_file file, bool healthy) const;

    bool transportLost() const;
    Result established(const Result &failure) const;
    Result sessionFailure() const;
    Result sftpFailure(const QString &context) const;
    Result writeFailure(const QByteArray &remote, qint64 attempted) const;
    Result existsAs(const QByteArray &remote, const Result &failure) const;

    Result statRemote(const QByteArray &remote, Entry *out, bool follow = true) const;
    Entry entryOf(const sftp_attributes_struct &attributes, const QString &name) const;
    void resolveOwners(QVector<Entry> *entries) const;
    Result readEntries(sftp_dir handle, const QByteArray &remote, ListSink *sink, const ListOptions &options) const;
    bool hasChildren(const QByteArray &remote) const;

    Result renameNoReplace(const QByteArray &source, const QByteArray &target) const;
    Result renameReplacing(const QByteArray &source, const QByteArray &target, const Entry &existing,
                           bool targetExists) const;
    Result setTimes(const QByteArray &remote, const QDateTime &modified, const QDateTime &accessed, qint32 mode) const;
    Result spaceOf(const QByteArray &remote, SpaceInfo *out) const;
    Result freeBytes(const QByteArray &remote, qint64 *bytes) const;
    mode_t directoryMode() const;

private:
    Result linkAware(const QByteArray &remote, const Result &lstat, Entry *out) const;
    Result deliver(QVector<Entry> *batch, ListSink *sink) const;
    void resolveTarget(const QByteArray &dir, Entry *entry, int *budget) const;

    const SftpBackend &m_b;
};

} // namespace NetVfs::Sftp

#endif
