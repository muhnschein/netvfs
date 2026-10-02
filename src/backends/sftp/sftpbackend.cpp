// SPDX-License-Identifier: LGPL-2.1-or-later
// API entry points of the SFTP backend; the work happens in the nested
// classes (sftpbackend.h lists them).
#include "names.h"
#include "sftpinternal.h"

#include <QtCore/QElapsedTimer>

// libssh's global request (channels.c). It is not in the installed headers,
// but it is the one way to send keepalive@openssh.com with want-reply and
// see the answer (SPEC-v2 XS-12); ssh_send_keepalive() discards it. Linked
// statically from the pinned libssh.
extern "C" int ssh_global_request(ssh_session session, const char *request, ssh_buffer buffer, int reply);

namespace NetVfs::Sftp {

namespace {

constexpr const char *KeepAliveRequest = "keepalive@openssh.com";

} // namespace

SftpBackend::SftpBackend()
{
    m_interrupt.canceled = &m_canceled;
}

SftpBackend::~SftpBackend()
{
    Connection(*this).close();
}

void SftpBackend::configureSession(ssh_session session)
{
    // Production code applies nothing beyond the connection policy.
    Q_UNUSED(session)
}

// --- connection -------------------------------------------------------------------

Result SftpBackend::connect(const ConnectionParams &params, ServerIdentity *seen)
{
    return Connection(*this).open(params, seen);
}

Capabilities SftpBackend::capabilities() const
{
    return m_capabilities;
}

void SftpBackend::disconnect()
{
    Connection(*this).close();
}

void SftpBackend::cancel()
{
    m_canceled = true;
    // XC-22: a prompter waiting for a person returns now.
    const std::lock_guard<std::mutex> lock(m_prompterMutex);
    if (m_prompter)
        m_prompter->cancel();
}

void SftpBackend::resetCancel()
{
    m_canceled = false;
}

// --- metadata ---------------------------------------------------------------------

Result SftpBackend::stat(const QString &path, Entry *out)
{
    const Requests q(*this);
    QByteArray remote;
    QVector<Entry> one(1);
    Result r = q.ready(path, &remote);
    if (r.ok())
        r = q.statRemote(remote, &one[0]);
    if (r.ok() && out) {
        q.resolveOwners(&one);
        *out = one.first();
    }
    return r;
}

Result SftpBackend::lstat(const QString &path, Entry *out)
{
    const Requests q(*this);
    QByteArray remote;
    QVector<Entry> one(1);
    Result r = q.ready(path, &remote);
    if (r.ok())
        r = q.statRemote(remote, &one[0], false);
    if (r.ok() && out) {
        q.resolveOwners(&one);
        *out = one.first();
    }
    return r;
}

Result SftpBackend::list(const QString &dir, ListSink *sink, const ListOptions &options)
{
    const Requests q(*this);
    QByteArray remote;
    Result r = q.ready(dir, &remote);
    if (!r.ok())
        return r;
    sftp_dir handle = sftp_opendir(m_sftp, remote.constData());
    if (!handle) {
        r = q.sftpFailure(display(remote));
        // OpenSSH reports ENOTDIR as "no such file".
        if (Entry entry; r.error() != Error::ConnectionLost && r.error() != Error::Canceled
                && q.statRemote(remote, &entry).ok() && !entry.isDir())
            return Result(Error::NotADirectory, QStringLiteral("%1 is not a folder").arg(display(remote)));
        return r;
    }
    r = q.readEntries(handle, remote, sink, options);
    // After cancel() the close request is sent and its answer not awaited.
    sftp_closedir(handle);
    return r;
}

// --- namespace --------------------------------------------------------------------

Result SftpBackend::makeDir(const QString &path, bool exclusive)
{
    const Requests q(*this);
    QByteArray remote;
    Result r = q.ready(path, &remote);
    if (!r.ok())
        return r;
    if (sftp_mkdir(m_sftp, remote.constData(), q.directoryMode()) == 0)   // XC-8, XC-23, S-20
        return Result::success();
    r = q.sftpFailure(display(remote));
    // OpenSSH reports EEXIST as a plain failure; a concurrent creator is fine.
    Entry existing;
    if (r.error() == Error::ConnectionLost || r.error() == Error::Canceled || !q.statRemote(remote, &existing).ok())
        return r;
    if (exclusive)
        return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(display(remote)));
    if (existing.isDir())
        return Result::success();
    return Result(Error::AlreadyExists, QStringLiteral("%1 exists and is not a folder").arg(display(remote)));
}

Result SftpBackend::removeFile(const QString &path)
{
    const Requests q(*this);
    QByteArray remote;
    Result r = q.ready(path, &remote);
    if (!r.ok())
        return r;
    if (sftp_unlink(m_sftp, remote.constData()) == 0)
        return Result::success();
    r = q.sftpFailure(display(remote));
    // XC-9: OpenSSH reports EISDIR as a plain failure.
    if (Entry entry; r.error() != Error::ConnectionLost && r.error() != Error::Canceled
            && q.statRemote(remote, &entry, false).ok() && entry.type == EntryType::Directory)
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(display(remote)));
    return r;
}

Result SftpBackend::removeDir(const QString &path)
{
    const Requests q(*this);
    QByteArray remote;
    Result r = q.ready(path, &remote);
    if (!r.ok())
        return r;
    if (sftp_rmdir(m_sftp, remote.constData()) == 0)
        return Result::success();
    r = q.sftpFailure(display(remote));
    Entry entry;
    if (r.error() == Error::ConnectionLost || r.error() == Error::Canceled || !q.statRemote(remote, &entry, false).ok())
        return r;
    // XC-9: OpenSSH reports ENOTDIR as "no such file" and ENOTEMPTY as a
    // plain failure.
    if (entry.type != EntryType::Directory)
        return Result(Error::NotADirectory, QStringLiteral("%1 is not a folder").arg(display(remote)));
    if (r.error() != Error::PermissionDenied && q.hasChildren(remote))
        return Result(Error::DirectoryNotEmpty, QStringLiteral("%1 is not empty").arg(display(remote)));
    return r;
}

Result SftpBackend::rename(const QString &from, const QString &to, RenameMode mode)
{
    const Requests q(*this);
    QByteArray source;
    QByteArray target;
    Result r = q.ready(from, &source);
    if (r.ok())
        r = q.resolve(to, &target);
    if (!r.ok())
        return r;
    if (mode == RenameMode::NoReplace)
        return q.renameNoReplace(source, target);
    Entry existing;
    r = q.statRemote(target, &existing, false);
    if (!r.ok() && r.error() != Error::NotFound)
        return r;
    const bool targetExists = r.ok();
    if (targetExists && source == target)
        return Result::success();
    // XC-10: a folder is never replaced.
    if (targetExists && existing.type == EntryType::Directory)
        return Result(Error::AlreadyExists, QStringLiteral("%1 is a folder").arg(display(target)));
    return q.renameReplacing(source, target, existing, targetExists);
}

// --- attributes and links -----------------------------------------------------------

Result SftpBackend::setAttributes(const QString &path, const AttributeChanges &changes)
{
    // XC-11, XS-5: every field is checked first; SFTP v3 stores all of them.
    const Requests q(*this);
    Result r = checkAttributeChanges(changes);
    QByteArray remote;
    if (r.ok())
        r = q.ready(path, &remote);
    if (!r.ok())
        return r;
    if (changes.isEmpty())
        return q.statRemote(remote, nullptr);
    return q.setTimes(remote, changes.modified, changes.accessed, changes.mode);
}

Result SftpBackend::readLink(const QString &path, QString *target)
{
    // XS-4: SSH_FXP_READLINK has the same arguments on every server.
    const Requests q(*this);
    QByteArray remote;
    Result r = q.ready(path, &remote);
    if (!r.ok())
        return r;
    char *link = sftp_readlink(m_sftp, remote.constData());
    if (!link) {
        r = q.sftpFailure(display(remote));
        if (Entry entry; r.error() != Error::ConnectionLost && r.error() != Error::Canceled
                && q.statRemote(remote, &entry, false).ok() && entry.type != EntryType::Symlink)
            return Result(Error::InvalidName, QStringLiteral("%1 is not a symbolic link").arg(display(remote)));
        return r;
    }
    if (target)
        *target = Names::decode(QByteArray(link));   // XC-12: verbatim
    ssh_string_free_char(link);
    return Result::success();
}

Result SftpBackend::makeSymlink(const QString &target, const QString &linkPath)
{
    const Requests q(*this);
    QByteArray link;
    Result r = q.checkReady();
    if (r.ok() && m_symlinkOrder == SymlinkOrder::Unverified)
        return Result(Error::Unsupported, QStringLiteral("Symbolic links are not verified to work with this server"));
    if (r.ok())
        r = q.resolve(linkPath, &link);
    if (!r.ok())
        return r;
    if (target.isEmpty() || target.contains(QChar(0)) || !Names::isEncodable(target))
        return Result(Error::InvalidName, QStringLiteral("Invalid link target"));
    const QByteArray destination = Names::encode(target);   // XC-12: verbatim
    // XS-4: libssh orders the arguments by the server banner; a server that
    // wants OpenSSH's order without saying OpenSSH gets them swapped.
    const bool swapped = m_symlinkOrder == SymlinkOrder::Swapped;
    const QByteArray &first = swapped ? link : destination;
    const QByteArray &second = swapped ? destination : link;
    if (sftp_symlink(m_sftp, first.constData(), second.constData()) == 0)
        return Result::success();
    return q.existsAs(link, q.sftpFailure(display(link)));
}

Result SftpBackend::makeHardlink(const QString &existing, const QString &newPath)
{
    const Requests q(*this);
    QByteArray source;
    QByteArray target;
    Result r = q.checkReady();
    if (r.ok() && !m_hasHardlink)
        return Result(Error::Unsupported, QStringLiteral("The server cannot create hard links"));
    if (r.ok())
        r = q.resolve(existing, &source);
    if (r.ok())
        r = q.resolve(newPath, &target);
    if (!r.ok())
        return r;
    if (sftp_hardlink(m_sftp, source.constData(), target.constData()) == 0)
        return Result::success();
    r = q.sftpFailure(display(target));
    if (r.error() == Error::NotFound)
        return r;
    return q.existsAs(target, r);
}

// --- space, keepAlive ---------------------------------------------------------------

Result SftpBackend::spaceInfo(const QString &dir, SpaceInfo *out)
{
    const Requests q(*this);
    Result r = q.checkReady();
    if (r.ok() && !m_hasStatvfs)
        return Result(Error::Unsupported, QStringLiteral("The server cannot report free space"));
    QByteArray remote;
    if (r.ok())
        r = q.resolve(dir, &remote);
    SpaceInfo space;
    if (r.ok())
        r = q.spaceOf(remote, &space);
    if (r.ok() && out)
        *out = space;
    return r;
}

Result SftpBackend::keepAlive()
{
    const Requests q(*this);
    Result r = q.checkReady();
    if (!r.ok())
        return r;
    if (q.transportLost())
        return Result(Error::ConnectionLost, QStringLiteral("The connection to the server was lost"));
    // XS-12: keepalive@openssh.com with want-reply; any reply proves the
    // connection (OpenSSH answers with a failure).
    ssh_set_blocking(m_session, 0);
    QElapsedTimer started;
    started.start();
    int rc = ssh_global_request(m_session, KeepAliveRequest, nullptr, 1);
    while (rc == SSH_AGAIN && r.ok()) {
        if (m_canceled)
            r = canceled();   // C-9
        else if (started.elapsed() >= m_params.requestTimeoutMs)
            r = Result(Error::Timeout, QStringLiteral("The server did not answer the keep-alive request"));
        else if (ssh_channel_poll_timeout(m_sftp->channel, PollIntervalMs, 0) == SSH_ERROR || q.transportLost())
            r = Result(Error::ConnectionLost, text(ssh_get_error(m_session)));
        else
            rc = ssh_global_request(m_session, KeepAliveRequest, nullptr, 1);
    }
    ssh_set_blocking(m_session, 1);
    if (!r.ok())
        return r;
    if (rc == SSH_OK || ssh_get_error_code(m_session) == SSH_REQUEST_DENIED)
        return Result::success();
    return Result(Error::ConnectionLost, text(ssh_get_error(m_session)));
}

} // namespace NetVfs::Sftp
