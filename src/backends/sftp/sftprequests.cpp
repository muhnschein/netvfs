// SPDX-License-Identifier: LGPL-2.1-or-later
// Paths, error mapping and shared requests (SPEC-sftp 6, 7; SPEC-v2 XS-1..XS-6).
#include "names.h"
#include "paths.h"
#include "sftpinternal.h"

#include <algorithm>
#include <limits>

namespace NetVfs::Sftp {

namespace {

constexpr const char *DirModeOption = "dir_mode";
constexpr int MaxSymlinkResolutions = 512;       // XS-3, per listing
constexpr int MaxCachedNames = 4096;             // XS-2, per connection and kind
constexpr qint32 LinkMode = 0777;                // what lstat(2) reports for a link on Linux

EntryType typeOf(const sftp_attributes_struct &attributes)
{
    // libssh derives the type from the permission bits for SFTP v3 servers.
    switch (attributes.type) {
    case SSH_FILEXFER_TYPE_REGULAR:
        return EntryType::File;
    case SSH_FILEXFER_TYPE_DIRECTORY:
        return EntryType::Directory;
    case SSH_FILEXFER_TYPE_SYMLINK:
        return EntryType::Symlink;
    case SSH_FILEXFER_TYPE_SPECIAL:
        return EntryType::Special;
    default:
        return EntryType::Unknown;
    }
}

QDateTime timeOf(uint32_t seconds)
{
    return QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(seconds) * 1000, Qt::UTC);
}

uint32_t secondsOf(const QDateTime &time)
{
    return static_cast<uint32_t>(time.toMSecsSinceEpoch() / 1000);
}

qint64 scaled(uint64_t blocks, uint64_t unit)
{
    const auto limit = static_cast<uint64_t>(std::numeric_limits<qint64>::max());
    return static_cast<qint64>((unit && blocks > limit / unit) ? limit : blocks * unit);
}

// Ids in `wanted` that `cache` does not know yet.
QVector<quint32> missing(const QSet<quint32> &wanted, const QHash<quint32, QString> &cache)
{
    QVector<quint32> ids;
    std::copy_if(wanted.cbegin(), wanted.cend(), std::back_inserter(ids),
                 [&cache](quint32 id) { return !cache.contains(id); });
    return ids;
}

sftp_name_id_map mapOf(const QVector<quint32> &ids)
{
    if (ids.isEmpty())
        return nullptr;
    sftp_name_id_map map = sftp_name_id_map_new(static_cast<uint32_t>(ids.size()));
    if (map)
        std::copy(ids.cbegin(), ids.cend(), map->ids);
    return map;
}

void remember(const sftp_name_id_map_struct *map, QHash<quint32, QString> *cache)
{
    if (!map)
        return;
    if (cache->size() + static_cast<int>(map->count) > MaxCachedNames)
        cache->clear();
    for (uint32_t i = 0; i < map->count; ++i)
        cache->insert(map->ids[i], map->names[i] ? Names::decode(QByteArray(map->names[i])) : QString());
}

void nameOwners(Entry *entry, const QHash<quint32, QString> &users, const QHash<quint32, QString> &groups)
{
    if (entry->owner.isEmpty() && entry->uid >= 0)
        entry->owner = users.value(static_cast<quint32>(entry->uid));
    if (entry->group.isEmpty() && entry->gid >= 0)
        entry->group = groups.value(static_cast<quint32>(entry->gid));
}

} // namespace

// --- free helpers (sftpinternal.h) --------------------------------------------

QString text(const char *value)
{
    return value ? QString::fromUtf8(value) : QString();
}

QString display(const QByteArray &remote)
{
    return Names::display(Names::decode(remote));
}

QByteArray lastComponent(const QByteArray &remote)
{
    const int slash = remote.lastIndexOf('/');
    return slash < 0 ? remote : remote.mid(slash + 1);
}

QByteArray joinRemote(const QByteArray &dir, const QByteArray &name)
{
    if (dir.isEmpty())
        return name;
    return dir.endsWith('/') ? dir + name : dir + '/' + name;
}

Entry entryFrom(const sftp_attributes_struct &attributes, const QString &name)
{
    Entry entry;
    entry.name = name;
    entry.type = typeOf(attributes);
    if (attributes.flags & SSH_FILEXFER_ATTR_SIZE)
        entry.size = static_cast<qint64>(std::min<uint64_t>(attributes.size, std::numeric_limits<qint64>::max()));
    if (attributes.flags & SSH_FILEXFER_ATTR_ACMODTIME) {
        entry.modified = timeOf(attributes.mtime);
        entry.accessed = timeOf(attributes.atime);
    }
    if (attributes.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        entry.mode = static_cast<qint32>(attributes.permissions & PermissionBits);
    if (attributes.flags & SSH_FILEXFER_ATTR_UIDGID) {
        entry.uid = attributes.uid;
        entry.gid = attributes.gid;
    }
    if (attributes.owner)
        entry.owner = Names::decode(QByteArray(attributes.owner));
    if (attributes.group)
        entry.group = Names::decode(QByteArray(attributes.group));
    // XS-2: Hidden is never set; dot names are a consumer convention.
    if (Names::hasEscapes(name))
        entry.flags |= EntryFlag::NameNotUtf8;
    return entry;
}

Result invalidRange()
{
    return Result(Error::Internal, QStringLiteral("Invalid range"));
}

Result canceled()
{
    return Result(Error::Canceled);
}

Result handleLost()
{
    return Result(Error::ConnectionLost, QStringLiteral("The connection was closed"));
}

// --- paths and state --------------------------------------------------------------

Result SftpBackend::Requests::checkReady() const
{
    if (!m_b.m_sftp)
        return Result(Error::Internal, QStringLiteral("Not signed in"));
    if (m_b.m_canceled)
        return canceled();
    return Result::success();
}

Result SftpBackend::Requests::resolve(const QString &path, QByteArray *remote) const
{
    QString normalized;
    if (const Result r = Paths::normalize(path, &normalized); !r.ok())   // C-15
        return r;
    if (!Names::isEncodable(normalized))   // XC-4
        return Result(Error::InvalidName, QStringLiteral("The name cannot be sent to an SFTP server"));
    const QByteArray bytes = Names::encode(normalized);
    if (Paths::isAbsolute(normalized))
        *remote = bytes;
    else if (normalized.isEmpty())
        *remote = m_b.m_home.isEmpty() ? QByteArray(".") : m_b.m_home;
    else
        *remote = joinRemote(m_b.m_home, bytes);
    return Result::success();
}

Result SftpBackend::Requests::ready(const QString &path, QByteArray *remote) const
{
    Result r = checkReady();
    if (r.ok())
        r = resolve(path, remote);
    return r;
}

bool SftpBackend::Requests::setTimeout(int milliseconds) const
{
    const long seconds = milliseconds / 1000;
    const long microseconds = static_cast<long>(milliseconds % 1000) * 1000;
    return ssh_options_set(m_b.m_session, SSH_OPTIONS_TIMEOUT, &seconds) == SSH_OK
            && ssh_options_set(m_b.m_session, SSH_OPTIONS_TIMEOUT_USEC, &microseconds) == SSH_OK;
}

int SftpBackend::Requests::closeFile(sftp_file file, bool healthy) const
{
    // After cancel() the close request is sent and its answer not awaited.
    if (!healthy)
        setTimeout(CleanupTimeoutMs);
    const int rc = sftp_close(file);
    if (!healthy)
        setTimeout(m_b.m_params.requestTimeoutMs);
    return rc;
}

mode_t SftpBackend::Requests::directoryMode() const
{
    bool ok = false;
    const uint mode = m_b.m_params.option(QLatin1String(DirModeOption)).toUInt(&ok, 8);
    return ok && mode <= PermissionBits ? static_cast<mode_t>(mode) : DefaultDirectoryMode;
}

// --- errors -------------------------------------------------------------------------

bool SftpBackend::Requests::transportLost() const
{
    return !m_b.m_session || !ssh_is_connected(m_b.m_session)
        || (m_b.m_sftp && ssh_channel_is_closed(m_b.m_sftp->channel));
}

// XC-21: once signed in, a transport that went away is ConnectionLost.
Result SftpBackend::Requests::established(const Result &failure) const
{
    if (m_b.m_sftp && !failure.ok() && failure.error() != Error::Canceled && transportLost())
        return Result(Error::ConnectionLost, failure.message());
    return failure;
}

Result SftpBackend::Requests::sessionFailure() const
{
    return connectFailure(text(ssh_get_error(m_b.m_session)));
}

Result SftpBackend::Requests::sftpFailure(const QString &context) const
{
    // An interrupted wait (Connection::interrupted()) fails the call: that
    // is cancel().
    if (m_b.m_canceled)
        return canceled();
    return established(sftpStatusFailure(sftp_get_error(m_b.m_sftp), text(ssh_get_error(m_b.m_session)), context));
}

Result SftpBackend::Requests::writeFailure(const QByteArray &remote, qint64 attempted) const
{
    const int status = sftp_get_error(m_b.m_sftp);
    const Result failure = sftpFailure(display(remote));
    if (status != SSH_FX_FAILURE || !m_b.m_hasStatvfs || m_b.m_canceled)
        return failure;
    if (qint64 available = -1;
            !freeBytes(remote, &available).ok() || !looksLikeFullDisk(status, available, attempted))
        return failure;
    return Result(Error::NoSpace, QStringLiteral("The server has no space left for %1").arg(display(remote)));
}

// The failure of creating `remote`, or AlreadyExists when something is there
// (OpenSSH reports EEXIST as a plain failure).
Result SftpBackend::Requests::existsAs(const QByteArray &remote, const Result &failure) const
{
    if (failure.error() == Error::ConnectionLost || failure.error() == Error::Canceled
            || !statRemote(remote, nullptr, false).ok())
        return failure;
    return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(display(remote)));
}

// --- metadata -----------------------------------------------------------------------

Entry SftpBackend::Requests::entryOf(const sftp_attributes_struct &attributes, const QString &name) const
{
    Entry entry = entryFrom(attributes, name);
    nameOwners(&entry, m_b.m_userNames, m_b.m_groupNames);
    return entry;
}

void SftpBackend::Requests::resolveOwners(QVector<Entry> *entries) const
{
    // XS-2: one users-groups-by-id@openssh.com request per batch for the ids
    // the connection's cache does not know yet.
    if (!m_b.m_hasUsersGroups)
        return;
    QSet<quint32> uids;
    QSet<quint32> gids;
    for (const Entry &entry : *entries) {
        if (entry.uid >= 0)
            uids.insert(static_cast<quint32>(entry.uid));
        if (entry.gid >= 0)
            gids.insert(static_cast<quint32>(entry.gid));
    }
    sftp_name_id_map users = mapOf(missing(uids, m_b.m_userNames));
    sftp_name_id_map groups = mapOf(missing(gids, m_b.m_groupNames));
    if ((users || groups) && sftp_get_users_groups_by_id(m_b.m_sftp, users, groups) == 0) {
        remember(users, &m_b.m_userNames);
        remember(groups, &m_b.m_groupNames);
    }
    sftp_name_id_map_free(users);
    sftp_name_id_map_free(groups);
    for (Entry &entry : *entries)
        nameOwners(&entry, m_b.m_userNames, m_b.m_groupNames);
}

Result SftpBackend::Requests::statRemote(const QByteArray &remote, Entry *out, bool follow) const
{
    sftp_attributes attributes = follow ? sftp_stat(m_b.m_sftp, remote.constData())
                                        : sftp_lstat(m_b.m_sftp, remote.constData());
    Result r;
    Entry entry;
    if (attributes) {
        entry = entryOf(*attributes, Names::decode(lastComponent(remote)));
        sftp_attributes_free(attributes);
    } else {
        r = sftpFailure(display(remote));
    }
    if (!follow && m_b.m_lstatFollows && entry.type != EntryType::Symlink)
        r = linkAware(remote, r, &entry);
    if (r.ok() && out)
        *out = entry;
    return r;
}

// XC-7 on servers whose LSTAT follows links (lstatFollowsLinks()): what
// READLINK accepts is a link. Its size is the target's length, as lstat(2)
// reports; the other attributes are the target's, when there is one.
Result SftpBackend::Requests::linkAware(const QByteArray &remote, const Result &lstat, Entry *out) const
{
    if (!lstat.ok() && lstat.error() != Error::NotFound && lstat.error() != Error::ProtocolError)
        return lstat;
    char *link = sftp_readlink(m_b.m_sftp, remote.constData());
    if (!link)
        return lstat;
    if (!lstat.ok())
        *out = entryFrom(sftp_attributes_struct {}, Names::decode(lastComponent(remote)));
    out->type = EntryType::Symlink;
    out->targetType = EntryType::Unknown;
    out->size = static_cast<qint64>(qstrlen(link));
    out->mode = LinkMode;
    ssh_string_free_char(link);
    return Result::success();
}

void SftpBackend::Requests::resolveTarget(const QByteArray &dir, Entry *entry, int *budget) const
{
    // XS-3: at most MaxSymlinkResolutions per listing; beyond, and for links
    // whose target cannot be stat()ed (dangling, loops), TargetUnknown.
    if (Entry target; *budget > 0 && statRemote(joinRemote(dir, Names::encode(entry->name)), &target).ok())
        entry->targetType = target.type;
    else
        entry->flags |= EntryFlag::TargetUnknown;
    --*budget;
}

Result SftpBackend::Requests::deliver(QVector<Entry> *batch, ListSink *sink) const
{
    resolveOwners(batch);
    const bool more = sink->entries(*batch);
    batch->clear();
    return more ? Result::success() : Result(Error::Canceled, QStringLiteral("The listing was stopped"));
}

Result SftpBackend::Requests::readEntries(sftp_dir handle, const QByteArray &remote, ListSink *sink,
                                          const ListOptions &options) const
{
    const int batchSize = qMax(1, options.batchSize);
    int budget = MaxSymlinkResolutions;
    QVector<Entry> batch;
    for (;;) {
        if (m_b.m_canceled)
            return canceled();   // C-9, between READDIR replies
        sftp_attributes attributes = sftp_readdir(m_b.m_sftp, handle);
        if (!attributes)
            break;
        // XC-6: READDIR is lstat-like; "." and ".." never appear.
        if (const QByteArray name(attributes->name); name != "." && name != "..") {
            Entry entry = entryOf(*attributes, Names::decode(name));
            if (options.resolveSymlinkTypes && entry.type == EntryType::Symlink)
                resolveTarget(remote, &entry, &budget);
            batch.append(entry);
        }
        sftp_attributes_free(attributes);
        // A batch per READDIR reply: libssh drops its buffer after the last name.
        const bool replyDone = handle->buffer == nullptr;
        if (batch.isEmpty() || (!replyDone && batch.size() < batchSize))
            continue;
        if (const Result r = deliver(&batch, sink); !r.ok())
            return r;
    }
    if (!sftp_dir_eof(handle))
        return sftpFailure(display(remote));
    return batch.isEmpty() ? Result::success() : deliver(&batch, sink);
}

bool SftpBackend::Requests::hasChildren(const QByteArray &remote) const
{
    sftp_dir handle = sftp_opendir(m_b.m_sftp, remote.constData());
    if (!handle)
        return false;
    bool found = false;
    while (sftp_attributes attributes = found ? nullptr : sftp_readdir(m_b.m_sftp, handle)) {
        const QByteArray name(attributes->name);
        found = name != "." && name != "..";
        sftp_attributes_free(attributes);
    }
    sftp_closedir(handle);
    return found;
}

// --- renames, attributes, space ---------------------------------------------------

Result SftpBackend::Requests::renameNoReplace(const QByteArray &source, const QByteArray &target) const
{
    // XC-10, XS-6: OpenSSH fails a plain SSH_FXP_RENAME (never posix-rename)
    // on an existing target, atomically for files (NativeNoReplace). Other
    // servers get a stat check first (a documented race).
    if (!m_b.m_nativeNoReplace) {
        const Result r = statRemote(target, nullptr, false);
        if (r.ok())
            return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(display(target)));
        if (r.error() != Error::NotFound)
            return r;
    }
    if (sftp_rename_noreplace(m_b.m_sftp, source.constData(), target.constData()) == 0)
        return Result::success();
    const Result failure = sftpFailure(display(source));
    // OpenSSH reports the existing target as a plain failure.
    if (failure.error() == Error::NotFound)
        return failure;
    return existsAs(target, failure);
}

Result SftpBackend::Requests::renameReplacing(const QByteArray &source, const QByteArray &target,
                                              const Entry &existing, bool targetExists) const
{
    // With posix-rename@openssh.com, libssh's sftp_rename() replaces the
    // target atomically (AtomicReplace). Plain SFTP rename does not replace
    // (S-22, 7): stat, unlink and rename as in API v1.
    if (!m_b.m_hasPosixRename && targetExists && sftp_unlink(m_b.m_sftp, target.constData()) != 0)
        return sftpFailure(display(target));
    if (sftp_rename(m_b.m_sftp, source.constData(), target.constData()) != 0)
        return sftpFailure(display(source));
    // rename(2) of one hard link onto another of the same file succeeds and
    // keeps both names; XC-10 leaves one.
    const bool mayRemain = m_b.m_hasPosixRename && targetExists && existing.type == EntryType::File;
    if (mayRemain && statRemote(source, nullptr, false).ok() && sftp_unlink(m_b.m_sftp, source.constData()) != 0)
        return sftpFailure(display(source));
    return Result::success();
}

Result SftpBackend::Requests::setTimes(const QByteArray &remote, const QDateTime &modified, const QDateTime &accessed,
                                       qint32 mode) const
{
    // SFTP v3 sets atime and mtime together: the one not given keeps its value.
    sftp_attributes_struct attributes {};
    if (mode >= 0) {
        attributes.flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        attributes.permissions = static_cast<uint32_t>(mode);
    }
    if (modified.isValid() || accessed.isValid()) {
        Entry current;
        if (!modified.isValid() || !accessed.isValid()) {
            if (const Result r = statRemote(remote, &current); !r.ok())
                return r;
        }
        const QDateTime mtime = modified.isValid() ? modified : current.modified;
        const QDateTime atime = accessed.isValid() ? accessed : current.accessed;
        attributes.flags |= SSH_FILEXFER_ATTR_ACMODTIME;
        attributes.mtime = secondsOf(mtime.isValid() ? mtime : atime);
        attributes.atime = secondsOf(atime.isValid() ? atime : mtime);
    }
    if (sftp_setstat(m_b.m_sftp, remote.constData(), &attributes) != 0)
        return sftpFailure(display(remote));
    return Result::success();
}

Result SftpBackend::Requests::spaceOf(const QByteArray &remote, SpaceInfo *out) const
{
    // XS-8: free = f_bavail x f_frsize, total = f_blocks x f_frsize.
    sftp_statvfs_t info = sftp_statvfs(m_b.m_sftp, remote.constData());
    if (!info)
        return sftpFailure(display(remote));
    const uint64_t unit = info->f_frsize ? info->f_frsize : info->f_bsize;
    out->free = scaled(info->f_bavail, unit);
    out->total = scaled(info->f_blocks, unit);
    out->used = info->f_blocks >= info->f_bfree ? scaled(info->f_blocks - info->f_bfree, unit) : -1;
    sftp_statvfs_free(info);
    return Result::success();
}

Result SftpBackend::Requests::freeBytes(const QByteArray &remote, qint64 *bytes) const
{
    SpaceInfo space;
    const Result r = spaceOf(remote, &space);
    *bytes = space.free;
    return r;
}

} // namespace NetVfs::Sftp
