// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBFILES_H
#define NETVFS_SMBFILES_H

#include "backend.h"
#include "smbsession.h"

#include <deque>

namespace NetVfs::Smb {

// XM-4: SMB has no POSIX modes or owners; times and attributes map directly.
Entry entryFrom(const QString &name, const smb2_stat_64 &st);

Result openFile(Session &session, const QByteArray &path, int flags, smb2fh **fh);
// After a failure or a cancel the handle is still closed, but within a
// bounded time (C-9), and the first error is what the caller sees.
Result closeFile(Session &session, smb2fh *fh, const Result &outcome);
Result fileStat(Session &session, smb2fh *fh, Entry *out);
// XC-11: SET_INFO FileBasicInformation; an invalid time is left alone.
Result setTimes(Session &session, const QByteArray &path, const QDateTime &modified, const QDateTime &accessed);
// XC-11: whether SMB can store this time (FILETIME, as libsmb2 encodes it).
bool timeRepresentable(const QDateTime &time);

// XC-13, XM-6: one open file with pipelined reads of chunkSize (M-11), up
// to MaxInFlight bytes requested ahead (read() for its own range, and
// readAhead() as a hint). Belongs to its session; never outlives it in a
// usable state (invalidate()).
class Reader final : public ReadHandle, public SessionFile
{
public:
    Reader(Session *session, smb2fh *fh, qint64 size);
    ~Reader() override;
    Reader(const Reader &) = delete;
    Reader &operator=(const Reader &) = delete;

    qint64 size() const override { return m_size; }
    Result read(qint64 offset, qint64 maxBytes, QByteArray *out) override;
    void readAhead(qint64 offset, qint64 bytes) override;
    Result close() override;
    void invalidate() override;
    // close() with the outcome of what the backend did with the file: a
    // failure closes within C-9's bound and is what comes back.
    Result closeWith(const Result &outcome);

private:
    struct Chunk {
        quint64 offset = 0;
        quint32 count = 0;
        quint32 got = 0;                // bytes the server returned (once ready)
        quint32 used = 0;               // bytes already handed out
        bool ready = false;
        std::unique_ptr<Call> call;
    };
    // close() without virtual dispatch, for the destructor.
    void shut() noexcept;
    Result usable() const;
    quint64 queueEnd() const;
    qint64 queued() const;
    Result issue(quint64 offset, quint32 count);
    Result fill(quint64 from, quint64 to);
    void discard();
    // Takes what the front chunk holds for [*position, end); false at EOF.
    Result consume(quint64 *position, quint64 end, QByteArray *out, bool *eof);

    Session *m_session;
    ThreadGate *m_gate;
    smb2fh *m_fh;
    const qint64 m_size;
    const quint32 m_chunk;
    bool m_lost = false;
    std::deque<Chunk> m_queue;
};

// XC-13, XM-6: sequential writes, pipelined like Reader. commit() flushes,
// closes and applies WriteOptions::modified (SetModifiedOnUpload).
class Writer final : public WriteHandle, public SessionFile
{
public:
    Writer(Session *session, smb2fh *fh, const QByteArray &path, const WriteOptions &options);
    ~Writer() override;
    Writer(const Writer &) = delete;
    Writer &operator=(const Writer &) = delete;

    Result write(const char *data, qint64 length) override;
    qint64 position() const override { return m_position; }
    Result commit() override;
    void abort() override;
    void invalidate() override;

private:
    struct Pending {
        quint64 offset = 0;
        quint32 count = 0;
        std::unique_ptr<Call> call;
    };
    // abort() without virtual dispatch, for the destructor.
    void shut() noexcept;
    Result usable() const;
    Result send();
    Result retireOldest();
    Result writeRest(const QByteArray &data, quint32 from, quint64 offset);
    Result fail(const Result &r);
    void drop();

    Session *m_session;
    ThreadGate *m_gate;
    smb2fh *m_fh;
    const QByteArray m_path;
    const QDateTime m_modified;
    const quint32 m_chunk;
    qint64 m_position;
    quint64 m_sent;
    QByteArray m_buffer;
    std::deque<Pending> m_inFlight;
    qint64 m_inFlightBytes = 0;
    bool m_lost = false;
    Result m_failed;
};

} // namespace NetVfs::Smb

#endif
