// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_LOCALBACKEND_H
#define NETVFS_LOCALBACKEND_H

#include "backend.h"
#include "localutil.h"

#include <atomic>
#include <memory>

namespace NetVfs::Local {

// Shared by the backend and its handles (XC-13).
struct Context {
    std::atomic<bool> canceled { false };
    // disconnect() starts a new generation; handles of older ones are dead
    // and report ConnectionLost.
    quint64 generation = 0;
    int requestTimeoutMs = 0;

    Waiter waiter() const { return Waiter(&canceled, requestTimeoutMs); }
};

// SPEC-v2 section 6.5: the local file system through POSIX calls.
//
// L-1: connect() succeeds without a network; the identity is Kind::None and
// credentials are ignored. Option "root" (default "/") is the base of
// relative paths; absolute paths are file system absolute.
// L-2: names are raw bytes (Names); entries come from statx() (birth time
// where the file system has it), listings use lstat semantics.
// L-3: rename(NoReplace) uses renameat2(RENAME_NOREPLACE), falling back to
// link()+unlink() for files and a stat check for folders where the kernel or
// file system lacks it; rename(Replace) is rename(2) (AtomicReplace).
// NativeNoReplace is reported when the kernel has renameat2 and the root's
// file system is one known to implement RENAME_NOREPLACE (decided without
// creating anything at connect). Option "native_noreplace=false" forces the
// fallback (tests, file systems that misreport the flag).
// L-7: rename() fsyncs the parent folder(s) afterwards, so that a commit by
// Transfer (upload to a temporary name, then rename) survives a crash.
// L-8: no privilege escalation; everything runs with the caller's rights.
//
// Handles: no limit beyond the process's descriptor limit. Reads and writes
// on FIFOs, sockets and devices wait with poll() in 100 ms slices, so
// cancel() (C-9) and the request timeout (C-14) apply; a single syscall
// blocked by the kernel on a dead device is the documented exception (L-6).
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

} // namespace NetVfs::Local

#endif
