// SPDX-License-Identifier: LGPL-2.1-or-later
#include "localbackend.h"
#include "names.h"
#include "paths.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>

namespace NetVfs::Local {

namespace {

constexpr const char *RootOption = "root";
constexpr const char *NativeNoReplaceOption = "native_noreplace";
constexpr int DefaultRequestTimeoutMs = 60000;
constexpr int MaxSymlinkResolutions = 512;     // per listing, as XS-3
constexpr int DefaultBatchSize = 256;
constexpr size_t InitialLinkBuffer = 256;
constexpr size_t MaxLinkBuffer = 1 << 20;
constexpr unsigned RenameNoReplace = 1U;      // RENAME_NOREPLACE (linux/fs.h)
constexpr unsigned RenameInvalidFlag = 1U << 30;   // rejected before any lookup
constexpr mode_t FolderMode = 0777;           // umask applies (XC-23)

// statfs f_type values (linux/magic.h) of file systems whose rename
// implementation honours RENAME_NOREPLACE.
constexpr std::array<unsigned long, 9> NoReplaceFileSystems = {
    0xEF53UL,       // ext2/3/4
    0x58465342UL,   // xfs
    0x9123683EUL,   // btrfs
    0x01021994UL,   // tmpfs
    0xF2F52010UL,   // f2fs
    0x794C7630UL,   // overlayfs
    0x24051905UL,   // ubifs
    0x4D44UL,       // vfat
    0x2011BAB0UL,   // exfat
};

long renameat2Call(const QByteArray &from, const QByteArray &to, unsigned flags)
{
#ifdef SYS_renameat2
    // Through syscall(): the C library on the target may lack the wrapper.
    return ::syscall(SYS_renameat2, AT_FDCWD, from.constData(), AT_FDCWD, to.constData(), flags);
#else
    Q_UNUSED(from)
    Q_UNUSED(to)
    Q_UNUSED(flags)
    errno = ENOSYS;
    return -1;
#endif
}

// The kernel has renameat2 when an invalid flag is refused with EINVAL
// rather than ENOSYS; the flags are checked before any lookup, so nothing
// is touched.
bool kernelHasRenameat2()
{
    return renameat2Call(QByteArrayLiteral("/"), QByteArrayLiteral("/"), RenameInvalidFlag) != 0 && errno == EINVAL;
}

bool fileSystemHasNoReplace(const QByteArray &root)
{
    struct statfs fs {};
    if (::statfs(root.constData(), &fs) != 0)
        return false;
    const auto type = static_cast<unsigned long>(fs.f_type);
    return std::find(NoReplaceFileSystems.begin(), NoReplaceFileSystems.end(), type) != NoReplaceFileSystems.end();
}

QByteArray joinNative(const QByteArray &dir, const QByteArray &name)
{
    return dir.endsWith('/') ? dir + name : dir + '/' + name;
}

QString nameOf(const QByteArray &native)
{
    return Names::decode(native.mid(native.lastIndexOf('/') + 1));
}

bool isDotOrDotDot(const char *name)
{
    return std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0;
}

Result systemFailure(const QByteArray &native)
{
    return errnoResult(errno, display(native));
}

Result plainRename(const QByteArray &from, const QByteArray &to)
{
    if (::rename(from.constData(), to.constData()) != 0)
        return systemFailure(to);
    return Result::success();
}

Result alreadyExists(const QByteArray &native)
{
    return Result(Error::AlreadyExists, QStringLiteral("%1 already exists").arg(display(native)));
}

} // namespace

// --- listing (XC-6, L-2) ----------------------------------------------------

class LocalBackend::Lister
{
public:
    Lister(LocalBackend &backend, ListSink *sink, const ListOptions &options)
        : m_backend(backend)
        , m_sink(sink)
        , m_batchSize(options.batchSize > 0 ? options.batchSize : DefaultBatchSize)
        , m_resolve(options.resolveSymlinkTypes)
    {
        m_batch.reserve(m_batchSize);
    }

    Result run(DIR *dir)
    {
        const int fd = ::dirfd(dir);
        for (;;) {
            if (m_backend.m_context->canceled)   // L-6: between entries
                return Result(Error::Canceled);
            errno = 0;
            const struct dirent *entry = ::readdir(dir);
            if (!entry)
                break;
            if (isDotOrDotDot(entry->d_name))
                continue;
            add(fd, QByteArray(entry->d_name));
            if (m_batch.size() >= m_batchSize) {
                if (const Result r = flush(); !r.ok())
                    return r;
            }
        }
        if (errno != 0)
            return errnoResult(errno, QStringLiteral("Cannot read the folder"));
        return flush();
    }

private:
    void add(int dirFd, const QByteArray &name)
    {
        Entry entry;
        entry.name = Names::decode(name);
        NativeStat st;
        const int rc = statAt(dirFd, name, false, &st);   // lstat semantics (L-2, XS-3)
        if (rc == ENOENT)
            return;   // removed while listing
        if (rc != 0) {
            if (Names::hasEscapes(entry.name))
                entry.flags |= EntryFlag::NameNotUtf8;
            m_batch.append(entry);
            return;
        }
        m_backend.fillEntry(st, &entry);
        if (st.type == EntryType::Symlink && m_resolve) {
            if (m_resolutions < MaxSymlinkResolutions) {
                ++m_resolutions;
                m_backend.resolveTarget(dirFd, name, &entry);
            } else {
                entry.flags |= EntryFlag::TargetUnknown;
            }
        }
        m_batch.append(entry);
    }

    Result flush()
    {
        if (m_batch.isEmpty())
            return Result::success();
        const bool more = m_sink->entries(m_batch);
        m_batch.clear();
        return more ? Result::success() : Result(Error::Canceled, QStringLiteral("The listing was stopped"));
    }

    LocalBackend &m_backend;
    ListSink *m_sink;
    int m_batchSize;
    bool m_resolve;
    int m_resolutions = 0;
    QVector<Entry> m_batch;
};

// --- connection (L-1) -------------------------------------------------------

LocalBackend::LocalBackend()
    : m_context(std::make_shared<Context>())
{
}

LocalBackend::~LocalBackend()
{
    close();
}

Result LocalBackend::connect(const ConnectionParams &params, ServerIdentity *seen)
{
    close();
    if (seen)
        *seen = ServerIdentity();   // Kind::None
    if (m_context->canceled)
        return Result(Error::Canceled);

    QString root;
    if (const Result r = Paths::normalize(params.option(QLatin1String(RootOption), QStringLiteral("/")), &root);
            !r.ok())
        return r;
    if (!Paths::isAbsolute(root))
        return Result(Error::Internal, QStringLiteral("The local root must be an absolute path"));
    if (!Names::isEncodable(root))
        return Result(Error::InvalidName, QStringLiteral("The local root cannot be represented as bytes"));
    m_root = Names::encode(root);

    NativeStat st;
    if (const int e = statAt(AT_FDCWD, m_root, true, &st); e != 0)
        return errnoResult(e, display(m_root));
    if (!st.isDir())
        return Result(Error::NotADirectory, QStringLiteral("%1 is not a folder").arg(display(m_root)));

    m_context->requestTimeoutMs = params.requestTimeoutMs > 0 ? params.requestTimeoutMs : DefaultRequestTimeoutMs;
    probeCapabilities(params);
    m_state = State::Connected;
    qCDebug(lcNetVfsLocal) << "Local root" << display(m_root);
    return Result::success();
}

void LocalBackend::probeCapabilities(const ConnectionParams &params)
{
    m_tryNativeNoReplace = params.flag(QLatin1String(NativeNoReplaceOption), true);
    Capabilities caps;
    for (const Capability c : { Capability::Symlinks, Capability::Hardlinks, Capability::PosixModes,
                                Capability::Ownership, Capability::SetModified, Capability::SetModifiedOnUpload,
                                Capability::ReadHandles, Capability::EfficientRanges, Capability::WriteResume,
                                Capability::AtomicReplace, Capability::ServerCopy, Capability::SpaceInfo,
                                Capability::Checksums })
        caps.flags.insert(c);
    if (m_tryNativeNoReplace && kernelHasRenameat2() && fileSystemHasNoReplace(m_root))
        caps.flags.insert(Capability::NativeNoReplace);
    caps.checksumAlgorithms = QStringList { QStringLiteral("sha256"), QStringLiteral("sha1"), QStringLiteral("md5") };
    struct statvfs vfs {};
    if (::statvfs(m_root.constData(), &vfs) == 0 && vfs.f_namemax > 0)
        caps.maxNameBytes = static_cast<qint64>(vfs.f_namemax);
    m_capabilities = caps;
}

Result LocalBackend::authenticate(const Credentials &credentials, AuthPrompter *prompter)
{
    Q_UNUSED(credentials)   // L-1: the caller's own rights apply
    Q_UNUSED(prompter)
    if (m_state != State::Connected && m_state != State::SignedIn)
        return Result(Error::Internal, QStringLiteral("authenticate() needs a connection"));
    if (m_context->canceled)
        return Result(Error::Canceled);
    m_state = State::SignedIn;
    return Result::success();
}

Capabilities LocalBackend::capabilities() const
{
    return m_capabilities;
}

Result LocalBackend::keepAlive()
{
    return checkReady();   // XC-20: nothing to reach
}

void LocalBackend::cancel()
{
    m_context->canceled = true;
}

void LocalBackend::resetCancel()
{
    m_context->canceled = false;
}

void LocalBackend::disconnect()
{
    close();
}

void LocalBackend::close()
{
    ++m_context->generation;   // XC-13: open handles report ConnectionLost
    m_names.clear();
    if (m_state != State::Idle)
        m_state = State::Closed;
}

// --- helpers ----------------------------------------------------------------

Result LocalBackend::checkReady() const
{
    if (m_state == State::Closed)
        return Result(Error::ConnectionLost, QStringLiteral("The connection was closed"));
    if (m_state != State::SignedIn)
        return Result(Error::Internal, QStringLiteral("Not signed in"));
    if (m_context->canceled)
        return Result(Error::Canceled);
    return Result::success();
}

Result LocalBackend::resolve(const QString &path, QByteArray *native) const
{
    QString normalized;
    if (const Result r = Paths::normalize(path, &normalized); !r.ok())   // C-15
        return r;
    if (!Names::isEncodable(normalized))
        return Result(Error::InvalidName, QStringLiteral("The path cannot be represented as bytes"));
    if (Paths::isAbsolute(normalized))
        *native = Names::encode(normalized);   // L-1: file system absolute
    else if (normalized.isEmpty())
        *native = m_root;
    else
        *native = joinNative(m_root, Names::encode(normalized));
    return Result::success();
}

Result LocalBackend::prepare(const QString &path, QByteArray *native) const
{
    if (const Result r = checkReady(); !r.ok())
        return r;
    return resolve(path, native);
}

void LocalBackend::fillEntry(const NativeStat &st, Entry *out)
{
    out->type = st.type;
    out->size = st.isDir() ? -1 : st.size;
    out->modified = fromMsecs(st.modifiedMs);
    out->accessed = fromMsecs(st.accessedMs);
    if (st.hasBirth)
        out->created = fromMsecs(st.birthMs);
    out->mode = st.mode;
    out->uid = st.uid;
    out->gid = st.gid;
    out->owner = m_names.user(st.uid);
    out->group = m_names.group(st.gid);
    if (Names::hasEscapes(out->name))
        out->flags |= EntryFlag::NameNotUtf8;
}

void LocalBackend::resolveTarget(int dirFd, const QByteArray &path, Entry *entry)
{
    NativeStat target;
    if (statAt(dirFd, path, true, &target) == 0)
        entry->targetType = target.type;
    else
        entry->flags |= EntryFlag::TargetUnknown;   // dangling, a loop, or no access
}

// --- metadata (XC-7) --------------------------------------------------------

Result LocalBackend::statEntry(const QString &path, bool follow, Entry *out)
{
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    NativeStat st;
    if (const int e = statAt(AT_FDCWD, native, follow, &st); e != 0)
        return errnoResult(e, display(native));
    Entry entry;
    entry.name = native == m_root ? QString() : nameOf(native);
    fillEntry(st, &entry);
    if (st.type == EntryType::Symlink)
        resolveTarget(AT_FDCWD, native, &entry);
    if (out)
        *out = entry;
    return Result::success();
}

Result LocalBackend::stat(const QString &path, Entry *out)
{
    return statEntry(path, true, out);
}

Result LocalBackend::lstat(const QString &path, Entry *out)
{
    return statEntry(path, false, out);
}

Result LocalBackend::list(const QString &dir, ListSink *sink, const ListOptions &options)
{
    if (!sink)
        return Result(Error::Internal, QStringLiteral("No listing sink"));
    QByteArray native;
    if (const Result r = prepare(dir, &native); !r.ok())
        return r;
    Fd fd(::open(native.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (!fd.valid())
        return systemFailure(native);
    const std::unique_ptr<DIR, int (*)(DIR *)> handle(::fdopendir(fd.get()), ::closedir);
    if (!handle)
        return systemFailure(native);
    fd.release();   // owned by the DIR stream now
    return Lister(*this, sink, options).run(handle.get());
}

// --- namespace operations (XC-8..XC-12, L-3) --------------------------------

Result LocalBackend::makeDir(const QString &path, bool exclusive)
{
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    if (::mkdir(native.constData(), FolderMode) == 0)
        return Result::success();
    const int error = errno;
    NativeStat st;
    if (error == EEXIST && !exclusive && statAt(AT_FDCWD, native, true, &st) == 0 && st.isDir())
        return Result::success();   // XC-8: an existing folder is fine
    return errnoResult(error, display(native));
}

Result LocalBackend::removeFile(const QString &path)
{
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    NativeStat st;
    if (const int e = statAt(AT_FDCWD, native, false, &st); e != 0)
        return errnoResult(e, display(native));
    if (st.isDir())   // XC-9; a symlink to a folder is removed itself
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(display(native)));
    if (::unlink(native.constData()) != 0)
        return systemFailure(native);
    return Result::success();
}

Result LocalBackend::removeDir(const QString &path)
{
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    if (::rmdir(native.constData()) == 0)
        return Result::success();
    const int error = errno == EEXIST ? ENOTEMPTY : errno;   // POSIX allows either
    return errnoResult(error, display(native));
}

Result LocalBackend::rename(const QString &from, const QString &to, RenameMode mode)
{
    QByteArray source;
    QByteArray target;
    Result r = prepare(from, &source);
    if (r.ok())
        r = resolve(to, &target);
    if (!r.ok())
        return r;
    NativeStat src;
    if (const int e = statAt(AT_FDCWD, source, false, &src); e != 0)
        return errnoResult(e, display(source));
    NativeStat dst;
    const bool targetExists = statAt(AT_FDCWD, target, false, &dst) == 0;

    if (targetExists && dst.sameFile(src))
        r = renameSameFile(source, target, mode);
    else if (mode == RenameMode::NoReplace)
        r = renameNoReplace(source, target, src.isDir());
    else if (targetExists && dst.isDir())   // XC-10: a folder is never replaced
        r = alreadyExists(target);
    else
        r = plainRename(source, target);
    if (r.ok()) {
        // L-7: make the new name durable (Transfer's commit is a rename).
        syncFolder(parentOf(target));
        if (parentOf(source) != parentOf(target))
            syncFolder(parentOf(source));
    }
    return r;
}

Result LocalBackend::renameSameFile(const QByteArray &from, const QByteArray &to, RenameMode mode) const
{
    if (from == to)
        return Result::success();
    // A case-only rename on a case-insensitive file system: one entry.
    if (Names::decode(from).compare(Names::decode(to), Qt::CaseInsensitive) == 0)
        return plainRename(from, to);
    // Two hard links of one file.
    if (mode == RenameMode::NoReplace)
        return alreadyExists(to);
    // rename(2) leaves both names in place; Replace means `from` goes away.
    if (::unlink(from.constData()) != 0)
        return systemFailure(from);
    return Result::success();
}

Result LocalBackend::renameNoReplace(const QByteArray &from, const QByteArray &to, bool isDir) const
{
    if (m_tryNativeNoReplace) {
        if (renameat2Call(from, to, RenameNoReplace) == 0)
            return Result::success();
        const int error = errno;
        if (error != EINVAL && error != ENOSYS)
            return errnoResult(error, display(to));
        // No RENAME_NOREPLACE on this kernel or file system (L-3).
    }
    return isDir ? renameChecked(from, to) : renameLinked(from, to);
}

Result LocalBackend::renameLinked(const QByteArray &from, const QByteArray &to) const
{
    // link() fails with EEXIST atomically; unlink() then drops the old name.
    if (::link(from.constData(), to.constData()) != 0) {
        const int error = errno;
        if (error == EPERM || error == EOPNOTSUPP || error == EMLINK || error == ENOSYS)
            return renameChecked(from, to);   // no hard links here
        return errnoResult(error, display(to));
    }
    if (::unlink(from.constData()) != 0) {
        const int error = errno;
        ::unlink(to.constData());
        return errnoResult(error, display(from));
    }
    return Result::success();
}

Result LocalBackend::renameChecked(const QByteArray &from, const QByteArray &to) const
{
    // XC-10: the documented race between this check and rename().
    NativeStat existing;
    if (statAt(AT_FDCWD, to, false, &existing) == 0)
        return alreadyExists(to);
    return plainRename(from, to);
}

Result LocalBackend::setAttributes(const QString &path, const AttributeChanges &changes)
{
    // XC-11: every field is checked before anything changes.
    if (changes.mode >= 0 && (changes.mode & ~07777) != 0)
        return Result(Error::Internal, QStringLiteral("Invalid mode %1").arg(changes.mode, 0, 8));
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    NativeStat st;
    if (const int e = statAt(AT_FDCWD, native, true, &st); e != 0)
        return errnoResult(e, display(native));
    if (changes.mode >= 0 && ::chmod(native.constData(), static_cast<mode_t>(changes.mode)) != 0)
        return systemFailure(native);
    if (changes.modified.isValid() || changes.accessed.isValid()) {
        const std::array<struct timespec, 2> times = { toTimespec(changes.accessed), toTimespec(changes.modified) };
        if (::utimensat(AT_FDCWD, native.constData(), times.data(), 0) != 0)
            return systemFailure(native);
    }
    return Result::success();
}

Result LocalBackend::readLink(const QString &path, QString *target)
{
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    std::vector<char> buffer(InitialLinkBuffer);
    for (;;) {
        const ssize_t n = ::readlink(native.constData(), buffer.data(), buffer.size());
        if (n < 0 && errno == EINVAL)
            return Result(Error::InvalidName, QStringLiteral("%1 is not a symbolic link").arg(display(native)));
        if (n < 0)
            return systemFailure(native);
        if (static_cast<size_t>(n) < buffer.size()) {
            if (target)
                *target = Names::decode(QByteArray(buffer.data(), static_cast<int>(n)));   // XC-12: verbatim
            return Result::success();
        }
        if (buffer.size() >= MaxLinkBuffer)
            return Result(Error::Internal, QStringLiteral("Link target too long"));
        buffer.resize(buffer.size() * 2);
    }
}

Result LocalBackend::makeSymlink(const QString &target, const QString &linkPath)
{
    QByteArray native;
    if (const Result r = prepare(linkPath, &native); !r.ok())
        return r;
    if (target.isEmpty() || target.contains(QChar(0)) || !Names::isEncodable(target))
        return Result(Error::InvalidName, QStringLiteral("Invalid link target"));
    // XC-12: stored verbatim; a relative target is relative to the link's folder.
    if (::symlink(Names::encode(target).constData(), native.constData()) != 0)
        return systemFailure(native);
    return Result::success();
}

Result LocalBackend::makeHardlink(const QString &existing, const QString &newPath)
{
    QByteArray source;
    QByteArray target;
    Result r = prepare(existing, &source);
    if (r.ok())
        r = resolve(newPath, &target);
    if (!r.ok())
        return r;
    if (::link(source.constData(), target.constData()) != 0)
        return systemFailure(target);
    return Result::success();
}

// --- space (L-6) ------------------------------------------------------------

Result LocalBackend::spaceInfo(const QString &dir, SpaceInfo *out)
{
    QByteArray native;
    if (const Result r = prepare(dir, &native); !r.ok())
        return r;
    struct statvfs vfs {};
    if (::statvfs(native.constData(), &vfs) != 0)
        return systemFailure(native);
    const auto unit = static_cast<qint64>(vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize);
    SpaceInfo info;
    info.free = static_cast<qint64>(vfs.f_bavail) * unit;
    info.total = static_cast<qint64>(vfs.f_blocks) * unit;
    info.used = static_cast<qint64>(vfs.f_blocks - vfs.f_bfree) * unit;
    if (out)
        *out = info;
    return Result::success();
}

} // namespace NetVfs::Local
