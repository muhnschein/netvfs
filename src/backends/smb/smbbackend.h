// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBBACKEND_H
#define NETVFS_SMBBACKEND_H

#include "backend.h"
#include "smbutil.h"

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

struct smb2_context;
struct smb2fh;

namespace NetVfs::Smb {

struct Call;

// SPEC-smb. One instance owns one smb2_context, used only from the thread
// that called connect() (M-13). Requests go through libsmb2's asynchronous
// API and a poll loop so that cancel() and timeouts can abandon a request
// that is stalled on the network (M-12, C-9).
class SmbBackend final : public Backend
{
public:
    SmbBackend();
    ~SmbBackend() override;
    SmbBackend(const SmbBackend &) = delete;
    SmbBackend &operator=(const SmbBackend &) = delete;

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

    // How long closing a file after a cancel or failure may take before that
    // request is abandoned too, so that Canceled comes back within C-9's 2 s.
    static constexpr int DrainMs = 1000;
    // Margin over the library's own request timeout (M-7) before the poll
    // loop gives up on a request by itself.
    static constexpr int BackstopMs = 5000;

private:
    enum class Wait { Cancellable, Drain };
    Result checkUsable() const;
    // `start` issues the libsmb2 request: int (smb2_context *, Call *).
    template <typename Starter>
    Result request(std::unique_ptr<Call> &call, Starter start, const QString &context,
                   Wait wait = Wait::Cancellable);
    Result await(std::unique_ptr<Call> &call, Wait wait);
    void abandon(std::unique_ptr<Call> &call);
    void destroyContext();
    // disconnect() without virtual dispatch; also used by the destructor.
    void shutdown() noexcept;

    Result statPath(const QByteArray &path, Entry *out);
    Result unlinkPath(const QByteArray &path, const QString &context);
    Result makeDir(const QByteArray &path);
    Result openFile(const QByteArray &path, int flags, smb2fh **fh);
    Result closeFile(smb2fh *fh, const Result &outcome);
    Result writeAll(smb2fh *fh, QIODevice *source, Progress *progress);
    Result writeChunk(smb2fh *fh, const QByteArray &buffer, qint64 length, quint64 offset);
    Result readChunk(smb2fh *fh, quint64 offset, quint32 count, QByteArray *buffer, quint32 *got);
    Result fileSize(smb2fh *fh, qint64 *size);
    Result copyToSink(smb2fh *fh, qint64 size, QIODevice *sink, Progress *progress);
    Result readRange(smb2fh *fh, qint64 offset, qint64 length, QByteArray *out);

    smb2_context *m_ctx = nullptr;
    ConnectionParams m_params;
    QString m_address;              // numeric address that answered connect()
    bool m_probed = false;
    bool m_broken = false;
    Stage m_stage = Stage::SessionSetup;
    std::thread::id m_owner;
    std::atomic<bool> m_cancel { false };
    std::vector<std::unique_ptr<Call>> m_orphans;
};

// M-5: libsmb2 lets a file named by NTLM_USER_FILE replace the password set
// with smb2_set_password() (lib/init.c: smb2_set_user() and smb2_set_domain()
// call smb2_set_password_from_file(); lib/ntlmssp.c does it again when the
// server's challenge supplies the domain). The variable is removed from the
// process environment before every session setup.
void neutraliseUserFile();

} // namespace NetVfs::Smb

#endif
