// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBBACKEND_H
#define NETVFS_SMBBACKEND_H

#include "backend.h"
#include "smbsession.h"
#include "smbutil.h"

#include <atomic>
#include <memory>
#include <vector>

namespace NetVfs::Smb {

// SPEC-smb, SPEC-v2 §6.2. All libsmb2 contexts of one instance, and its
// handles, are used by one thread at a time (M-13, ThreadGate; a hand-over
// between calls is allowed, C-8); cancel() and disconnect() cover every
// one of them.
//
// Share mode (option "share" set): one context, paths relative to the share.
// Server mode (XM-2, "share" empty): authenticate() signs in to IPC$, which
// proves the credentials and the profile and serves keepAlive(); the root
// "/" lists shares (XM-3, XM-7); "/<share>/<rest>" goes through a context of
// its own per share, opened on first use with the same credentials, at most
// MaxShareSessions at a time (least recently used closed first; a context
// with open handles is never closed for that).
class SmbBackend final : public Backend
{
public:
    SmbBackend();
    ~SmbBackend() override;
    SmbBackend(const SmbBackend &) = delete;
    SmbBackend &operator=(const SmbBackend &) = delete;

    using Backend::authenticate;
    using Backend::list;

    Result connect(const ConnectionParams &params, ServerIdentity *seen) override;
    Result authenticate(const Credentials &credentials, AuthPrompter *prompter) override;
    Capabilities capabilities() const override;

    Result stat(const QString &path, Entry *out) override;
    Result list(const QString &dir, ListSink *sink, const ListOptions &options) override;

    Result makeDir(const QString &path, bool exclusive) override;
    Result removeFile(const QString &path) override;
    Result removeDir(const QString &path) override;
    Result rename(const QString &from, const QString &to, RenameMode mode) override;
    Result setAttributes(const QString &path, const AttributeChanges &changes) override;

    Result openRead(const QString &path, ReadHandle **out) override;
    Result openWrite(const QString &path, const WriteOptions &options, WriteHandle **out) override;
    Result upload(QIODevice *source, const QString &path, const UploadOptions &options, Progress *progress) override;
    Result download(const QString &path, QIODevice *sink, const DownloadOptions &options, Progress *progress) override;

    Result spaceInfo(const QString &dir, SpaceInfo *out) override;
    Result keepAlive() override;

    void cancel() override;
    void resetCancel() override;
    void disconnect() override;

    static constexpr int MaxShareSessions = 4;      // XM-2

private:
    // Where a path leads: the server-mode root, or a session and the path
    // inside its share (empty for the share's own root).
    struct Location {
        bool root = false;
        Session *session = nullptr;
        QByteArray path;
        QString share;
    };
    Result checkSignedIn() const;
    Result locate(const QString &path, Location *out);
    Result sessionFor(const QString &share, Session **out);
    Result evictOne();
    // Server mode: the root or a share itself ("/", "/<share>").
    bool shareLevel(const QString &path) const;
    bool enumerationEnabled() const;
    Result enumerateShares(QStringList *names, QVariantMap *remarks);
    Result listRoot(ListSink *sink, const ListOptions &options);
    // disconnect() without virtual dispatch; also used by the destructor.
    void shutdown() noexcept;

    ConnectionParams m_params;
    Profile m_profile = Profile::Strict;
    QString m_user;
    QString m_domain;
    QByteArray m_secret;            // server mode: for shares opened later; wiped on disconnect
    QString m_address;              // numeric address that answered connect()
    bool m_probed = false;
    bool m_serverMode = false;
    ThreadGate m_gate;                  // M-13: one thread at a time
    std::atomic<bool> m_cancel { false };
    std::unique_ptr<Session> m_main;                    // the share, or IPC$ in server mode
    std::vector<std::unique_ptr<Session>> m_shares;     // server mode (XM-2)
    quint64 m_useClock = 0;
};

} // namespace NetVfs::Smb

#endif
