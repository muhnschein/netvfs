// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_RSBACKEND_H
#define NETVFS_RSBACKEND_H

// Backend over one connection of libnetvfs-rs.so. A plugin's BackendFactory::create() is
// createBackend() with its provider. Rust takes one call at a time per connection, from any thread.
#include "backend.h"
#include "netvfs_rs.h"

#include <mutex>

namespace NetVfs::Rs {

// Internal when libnetvfs-rs.so is missing, Unsupported when it has no such provider.
Result createBackend(const QString &provider, Backend **out);

class RsBackend final : public Backend
{
public:
    RsBackend(const nvr_table *table, nvr_conn *conn) : m_t(table), m_conn(conn) {}
    // Closes what is left open and disconnects (conn_free).
    ~RsBackend() override;

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
    Result statWith(const QString &path, bool follow, Entry *out);
    Result fetchCapabilities(Capabilities *out) const;
    template <typename Call>
    Result onPath(const QString &path, const Call &call) const;
    template <typename Call>
    Result onPaths(const QString &first, const QString &second, const Call &call) const;

    const nvr_table *m_t;
    nvr_conn *m_conn;
    QString m_domain;
    bool m_authenticated = false;
    Capabilities m_capabilities;
    // Prompter of a running authenticate(), which cancel() wakes.
    std::mutex m_prompterMutex;
    AuthPrompter *m_prompter = nullptr;
};

}
#endif
