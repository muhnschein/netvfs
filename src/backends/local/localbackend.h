// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_LOCALBACKEND_H
#define NETVFS_LOCALBACKEND_H

#include "backend.h"
#include "localutil.h"

#include <atomic>
#include <memory>

namespace NetVfs::Local {

// Shared by the backend and its handles.
struct Context {
    std::atomic<bool> canceled { false };
    // disconnect() starts a new generation; older handles are dead and report ConnectionLost.
    quint64 generation = 0;
    int requestTimeoutMs = 0;

    Waiter waiter() const { return Waiter(&canceled, requestTimeoutMs); }
};

// Local file system through POSIX calls. connect() needs no network; identity Kind::None,
// credentials ignored. Option "root" (default "/") is the base of relative paths.
// Names are raw bytes; entries from statx() (birth time where available); listings use lstat
// semantics.
// rename(NoReplace): renameat2(RENAME_NOREPLACE), else link()+unlink() for files and a stat check
// for folders. rename(Replace) is rename(2). NativeNoReplace reported when the kernel has renameat2
// and the root's file system is known to implement it (decided at connect without creating
// anything). Option "native_noreplace=false" forces the fallback.
// rename() fsyncs the parent folder(s) so Transfer's commit survives a crash. No privilege
// escalation.
// FIFO, socket and device I/O waits with poll() in 100 ms slices so cancel() and the request
// timeout apply; one syscall blocked by the kernel on a dead device is the exception.
class LocalBackend : public Backend
{
public:
    LocalBackend() = default;
    ~LocalBackend() override;

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
    Result upload(QIODevice *source, const QString &path, const UploadOptions &options,
                  Progress *progress) override;
    Result download(const QString &path, QIODevice *sink, const DownloadOptions &options,
                    Progress *progress) override;

    Result copy(const QString &from, const QString &to, const CopyOptions &options) override;
    Result checksum(const QString &path, const QString &algorithm, QByteArray *digest) override;
    Result spaceInfo(const QString &dir, SpaceInfo *out) override;
    Result keepAlive() override;

    void cancel() override;
    void resetCancel() override;
    void disconnect() override;

    using Backend::authenticate;
    using Backend::list;

private:
    enum class State { Idle, Connected, SignedIn, Closed };
    class Lister;

    void close();
    Result checkReady() const;
    Result resolve(const QString &path, QByteArray *native) const;
    Result prepare(const QString &path, QByteArray *native) const;
    Result statEntry(const QString &path, bool follow, Entry *out);
    void fillEntry(const NativeStat &st, Entry *out);

    std::shared_ptr<Context> m_context = std::make_shared<Context>();
    State m_state = State::Idle;
    QByteArray m_root;
    Capabilities m_capabilities;
    bool m_tryNativeNoReplace = true;
    AccountNames m_names;
};

}
#endif
