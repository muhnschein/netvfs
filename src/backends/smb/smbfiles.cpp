// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbfiles.h"

#include <QtCore/QDateTime>

#include <algorithm>
#include <limits>
#include <numeric>

namespace NetVfs::Smb {

namespace {

// Latest time FILETIME holds (year 30828); SMB cannot store anything before
// 1601, and libsmb2 reads tv_sec 0 as "leave alone", so this backend sets
// times after 1970 only.
const qint64 MaxFileTimeSeconds = 910692730085LL;

QDateTime timeOf(uint64_t seconds, uint64_t nanoseconds)
{
    if (seconds == 0 && nanoseconds == 0)
        return QDateTime();
    return QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(seconds) * 1000 + static_cast<qint64>(nanoseconds / 1000000),
                                          Qt::UTC);
}

EntryType typeOf(uint32_t smbType)
{
    switch (smbType) {
    case SMB2_TYPE_FILE:
        return EntryType::File;
    case SMB2_TYPE_DIRECTORY:
        return EntryType::Directory;
    case SMB2_TYPE_LINK:
        return EntryType::Symlink;   // XM-4: a reparse point reported as a link
    default:
        return EntryType::Special;   // FIFOs, devices, sockets (WSL reparse tags)
    }
}

smb2_timeval timevalOf(const QDateTime &time)
{
    smb2_timeval tv = {};
    if (!time.isValid())
        return tv;
    const qint64 ms = time.toMSecsSinceEpoch();
    tv.tv_sec = static_cast<time_t>(ms / 1000);
    tv.tv_usec = static_cast<long>((ms % 1000) * 1000);
    return tv;
}

Result invalidRange()
{
    return Result(Error::Internal, QStringLiteral("invalid range"));
}

Result closedFile()
{
    return Result(Error::Internal, QStringLiteral("the file is closed"));
}

Result lostFile()
{
    return Result(Error::ConnectionLost, QLatin1String(ConnectionLostMessage));
}

} // namespace

Entry entryFrom(const QString &name, const smb2_stat_64 &st)
{
    Entry entry;
    entry.name = name;
    entry.type = typeOf(st.smb2_type);
    if (entry.type != EntryType::Directory)
        entry.size = static_cast<qint64>(std::min<uint64_t>(st.smb2_size, std::numeric_limits<qint64>::max()));
    entry.modified = timeOf(st.smb2_mtime, st.smb2_mtime_nsec);
    entry.accessed = timeOf(st.smb2_atime, st.smb2_atime_nsec);
    entry.created = timeOf(st.smb2_btime, st.smb2_btime_nsec);
    if (st.smb2_attributes & SMB2_FILE_ATTRIBUTE_HIDDEN)
        entry.flags |= EntryFlag::Hidden;
    if (st.smb2_attributes & SMB2_FILE_ATTRIBUTE_READONLY)
        entry.flags |= EntryFlag::ReadOnly;
    if (st.smb2_attributes & SMB2_FILE_ATTRIBUTE_SYSTEM)
        entry.flags |= EntryFlag::System;
    return entry;
}

Result openFile(Session &session, const QByteArray &path, int flags, smb2fh **fh)
{
    auto call = std::make_unique<Call>();
    const Result r = session.request(call, [&path, flags](smb2_context *ctx, Call *c) {
        return smb2_open_async(ctx, path.constData(), flags, netvfs_smb_complete_open, c->completion());
    }, QStringLiteral("open"));
    if (r.ok())
        *fh = call->fh;
    return r;
}

Result closeFile(Session &session, smb2fh *fh, const Result &outcome)
{
    auto call = std::make_unique<Call>();
    const Result r = session.request(call, [fh](smb2_context *ctx, Call *c) {
        return smb2_close_async(ctx, fh, netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("close"), outcome.ok() ? Session::Wait::Cancellable : Session::Wait::Drain);
    return outcome.ok() ? r : outcome;
}

Result fileStat(Session &session, smb2fh *fh, Entry *out)
{
    auto call = std::make_unique<Call>();
    const Result r = session.request(call, [fh](smb2_context *ctx, Call *c) {
        return smb2_fstat_async(ctx, fh, &c->st, netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("stat"));
    if (r.ok())
        *out = entryFrom(QString(), call->st);
    return r;
}

bool timeRepresentable(const QDateTime &time)
{
    if (!time.isValid())
        return true;
    const qint64 seconds = time.toMSecsSinceEpoch() / 1000;
    return seconds > 0 && seconds < MaxFileTimeSeconds;
}

Result setTimes(Session &session, const QByteArray &path, const QDateTime &modified, const QDateTime &accessed)
{
    if (!timeRepresentable(modified) || !timeRepresentable(accessed))
        return Result(Error::Unsupported, QStringLiteral("SMB stores times between 1970 and 30828 only"));
    smb2_file_basic_info info = {};
    info.last_write_time = timevalOf(modified);     // zero: left alone
    info.last_access_time = timevalOf(accessed);
    auto call = std::make_unique<Call>();
    return session.request(call, [&path, &info](smb2_context *ctx, Call *c) {
        return netvfs_smb_set_basic_info_async(ctx, path.constData(), &info, c->completion());
    }, QStringLiteral("set attributes"));
}

// ------------------------------------------------------------------ Reader

Reader::Reader(Session *session, smb2fh *fh, qint64 size)
    : m_session(session), m_gate(session->gate()), m_fh(fh), m_size(size), m_chunk(session->readChunk())
{
    m_session->attach(this);
}

Reader::~Reader()
{
    shut();
}

void Reader::shut() noexcept
{
    closeWith(m_fh && m_session->canceled() ? Result(Error::Canceled) : Result());
}

Result Reader::usable() const
{
    if (m_lost)
        return lostFile();
    if (!m_fh)
        return closedFile();
    return m_session->checkUsable();
}

quint64 Reader::queueEnd() const
{
    return m_queue.empty() ? 0 : m_queue.back().offset + m_queue.back().count;
}

qint64 Reader::queued() const
{
    return std::accumulate(m_queue.begin(), m_queue.end(), qint64(0),
                           [](qint64 sum, const Chunk &chunk) { return sum + chunk.count - chunk.used; });
}

Result Reader::issue(quint64 offset, quint32 count)
{
    Chunk chunk;
    chunk.offset = offset;
    chunk.count = count;
    chunk.call = std::make_unique<Call>();
    chunk.call->buffer.resize(static_cast<int>(count));
    auto *data = reinterpret_cast<uint8_t *>(chunk.call->buffer.data());
    smb2fh *fh = m_fh;
    const Result r = m_session->begin(chunk.call.get(), [fh, data, count, offset](smb2_context *ctx, Call *c) {
        return smb2_pread_async(ctx, fh, data, count, offset, netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("read"));
    if (r.ok())
        m_queue.push_back(std::move(chunk));
    return r;
}

Result Reader::fill(quint64 from, quint64 to)
{
    // XM-6, C-10: at most MaxInFlight bytes requested and not yet handed out.
    quint64 next = m_queue.empty() ? from : queueEnd();
    while (next < to && (m_queue.empty() || queued() + m_chunk <= MaxInFlight)) {
        const auto count = static_cast<quint32>(std::min<quint64>(m_chunk, to - next));
        if (Result r = issue(next, count); !r.ok())
            return r;
        next += count;
    }
    return Result::success();
}

void Reader::discard()
{
    for (Chunk &chunk : m_queue) {
        if (!chunk.ready)
            m_session->abandon(chunk.call);
    }
    m_queue.clear();
}

Result Reader::consume(quint64 *position, quint64 end, QByteArray *out, bool *eof)
{
    Chunk &chunk = m_queue.front();
    if (!chunk.ready) {
        if (Result r = m_session->finish(chunk.call, QStringLiteral("read")); !r.ok())
            return r;
        chunk.ready = true;
        chunk.got = std::min(static_cast<quint32>(chunk.call->status), chunk.count);
    }
    const auto take = static_cast<quint32>(std::min<quint64>(chunk.got - chunk.used, end - *position));
    out->append(chunk.call->buffer.constData() + chunk.used, static_cast<int>(take));
    chunk.used += take;
    *position += take;
    if (chunk.used == chunk.got) {
        // A short read is the end of the file; what was asked beyond is moot.
        *eof = chunk.got < chunk.count;
        m_queue.pop_front();
        if (*eof)
            discard();
    }
    return Result::success();
}

Result Reader::read(qint64 offset, qint64 maxBytes, QByteArray *out)
{
    if (out)
        out->clear();
    const GateHold hold(m_gate);       // M-13
    if (!hold.entered())
        return GateHold::busy();
    if (Result r = usable(); !r.ok())
        return r;
    // C-9: also when what is asked for has arrived already.
    if (m_session->canceled())
        return Result(Error::Canceled);
    if (offset < 0 || maxBytes < 0 || maxBytes > std::numeric_limits<int>::max())
        return invalidRange();
    auto position = static_cast<quint64>(offset);
    const quint64 end = position + static_cast<quint64>(maxBytes);
    if (!m_queue.empty() && m_queue.front().offset + m_queue.front().used != position)
        discard();      // not where the queue continues: a new position
    QByteArray data;
    data.reserve(static_cast<int>(std::min<qint64>(maxBytes, MaxInFlight)));
    bool eof = false;
    while (position < end && !eof) {
        Result r = fill(position, end);
        if (r.ok())
            r = consume(&position, end, &data, &eof);
        if (!r.ok()) {
            discard();
            return r;
        }
    }
    if (out)
        *out = data;
    return Result::success();
}

void Reader::readAhead(qint64 offset, qint64 bytes)
{
    const GateHold hold(m_gate);       // M-13
    if (!hold.entered() || !usable().ok() || offset < 0 || bytes <= 0)
        return;
    const auto from = static_cast<quint64>(offset);
    if (!m_queue.empty() && (from < m_queue.front().offset + m_queue.front().used || from > queueEnd()))
        discard();
    quint64 to = from + static_cast<quint64>(std::min<qint64>(bytes, MaxInFlight));
    if (m_size >= 0)
        to = std::min(to, std::max(from, static_cast<quint64>(m_size)));
    // A hint: a request that cannot start now is simply not made.
    fill(from, to);
}

Result Reader::closeWith(const Result &outcome)
{
    if (!m_fh)
        return m_lost ? lostFile() : outcome;
    const GateHold hold(m_gate);       // M-13
    if (!hold.entered())
        return GateHold::busy();
    discard();
    smb2fh *fh = m_fh;
    m_fh = nullptr;
    m_session->detach(this);
    return closeFile(*m_session, fh, outcome);
}

Result Reader::close()
{
    // A canceled backend still closes the file, within C-9's bound.
    return closeWith(m_fh && m_session->canceled() ? Result(Error::Canceled) : Result());
}

void Reader::invalidate()
{
    discard();
    m_session->closeLater(m_fh);
    m_fh = nullptr;
    m_lost = true;
}

// ------------------------------------------------------------------ Writer

Writer::Writer(Session *session, smb2fh *fh, const QByteArray &path, const WriteOptions &options)
    : m_session(session), m_gate(session->gate()), m_fh(fh), m_path(path), m_modified(options.modified), m_chunk(session->writeChunk()),
      m_position(options.disposition == WriteOptions::Disposition::Resume ? options.resumeOffset : 0),
      m_sent(static_cast<quint64>(m_position))
{
    m_session->attach(this);
}

Writer::~Writer()
{
    shut();
}

Result Writer::usable() const
{
    if (m_lost)
        return lostFile();
    if (!m_fh)
        return closedFile();
    if (!m_failed.ok())
        return m_failed;
    return m_session->checkUsable();
}

Result Writer::fail(const Result &r)
{
    // A failed write leaves the file in an unknown state: later writes and
    // commit() report the same failure (abort() still closes the file).
    m_failed = r;
    drop();
    return r;
}

Result Writer::write(const char *data, qint64 length)
{
    const GateHold hold(m_gate);       // M-13
    if (!hold.entered())
        return GateHold::busy();
    if (Result r = usable(); !r.ok())
        return r;
    if (length < 0)
        return invalidRange();
    qint64 done = 0;
    while (done < length) {
        const qint64 take = std::min<qint64>(m_chunk - static_cast<quint32>(m_buffer.size()), length - done);
        m_buffer.append(data + done, static_cast<int>(take));
        done += take;
        if (static_cast<quint32>(m_buffer.size()) < m_chunk)
            continue;
        if (Result r = send(); !r.ok())
            return fail(r);
    }
    m_position += length;
    return Result::success();
}

Result Writer::send()
{
    const auto count = static_cast<quint32>(m_buffer.size());
    // XM-6, C-10: at most MaxInFlight bytes on the way.
    while (!m_inFlight.empty() && m_inFlightBytes + count > MaxInFlight) {
        if (Result r = retireOldest(); !r.ok())
            return r;
    }
    Pending pending;
    pending.offset = m_sent;
    pending.count = count;
    pending.call = std::make_unique<Call>();
    pending.call->buffer = m_buffer;        // owned by the request while it runs
    m_buffer = QByteArray();
    const auto *data = reinterpret_cast<const uint8_t *>(pending.call->buffer.constData());
    smb2fh *fh = m_fh;
    const quint64 offset = m_sent;
    const Result r = m_session->begin(pending.call.get(), [fh, data, count, offset](smb2_context *ctx, Call *c) {
        return smb2_pwrite_async(ctx, fh, data, count, offset, netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("write"));
    if (!r.ok())
        return r;
    m_sent += count;
    m_inFlightBytes += count;
    m_inFlight.push_back(std::move(pending));
    return r;
}

Result Writer::retireOldest()
{
    Pending pending = std::move(m_inFlight.front());
    m_inFlight.pop_front();
    m_inFlightBytes -= pending.count;
    if (Result r = m_session->finish(pending.call, QStringLiteral("write")); !r.ok())
        return r;
    const auto written = static_cast<quint32>(pending.call->status);
    if (written == 0)
        return Result(Error::ProtocolError, QStringLiteral("write: the server accepted no data"));
    if (written < pending.count)
        return writeRest(pending.call->buffer, written, pending.offset + written);
    return Result::success();
}

Result Writer::writeRest(const QByteArray &data, quint32 from, quint64 offset)
{
    // A short write (the server took less than asked): the rest goes
    // synchronously, in order.
    auto done = from;
    while (done < static_cast<quint32>(data.size())) {
        auto call = std::make_unique<Call>();
        call->buffer = data;
        const auto *bytes = reinterpret_cast<const uint8_t *>(call->buffer.constData()) + done;
        const auto count = static_cast<quint32>(data.size()) - done;
        const quint64 at = offset + (done - from);
        smb2fh *fh = m_fh;
        const Result r = m_session->request(call, [fh, bytes, count, at](smb2_context *ctx, Call *c) {
            return smb2_pwrite_async(ctx, fh, bytes, count, at, netvfs_smb_complete_plain, c->completion());
        }, QStringLiteral("write"));
        if (!r.ok())
            return r;
        if (call->status == 0)
            return Result(Error::ProtocolError, QStringLiteral("write: the server accepted no data"));
        done += static_cast<quint32>(call->status);
    }
    return Result::success();
}

void Writer::drop()
{
    for (Pending &pending : m_inFlight)
        m_session->abandon(pending.call);
    m_inFlight.clear();
    m_inFlightBytes = 0;
    m_buffer.clear();
}

Result Writer::commit()
{
    const GateHold hold(m_gate);       // M-13
    if (!hold.entered())
        return GateHold::busy();
    Result r = usable();
    if (!m_fh)
        return r;
    if (r.ok() && !m_buffer.isEmpty())
        r = send();
    while (r.ok() && !m_inFlight.empty())
        r = retireOldest();
    if (r.ok()) {
        // C-12: flush to stable storage before the size check and rename.
        auto call = std::make_unique<Call>();
        smb2fh *fh = m_fh;
        r = m_session->request(call, [fh](smb2_context *ctx, Call *c) {
            return smb2_fsync_async(ctx, fh, netvfs_smb_complete_plain, c->completion());
        }, QStringLiteral("flush"));
    }
    drop();
    smb2fh *fh = m_fh;
    m_fh = nullptr;
    m_session->detach(this);
    r = closeFile(*m_session, fh, r);
    // XC-14: the time is set after the close, so that no later write of
    // this handle can move it again.
    if (r.ok() && m_modified.isValid())
        r = setTimes(*m_session, m_path, m_modified, QDateTime());
    return r;
}

void Writer::abort()
{
    shut();
}

void Writer::shut() noexcept
{
    if (!m_fh)
        return;
    const GateHold hold(m_gate);       // M-13
    if (!hold.entered())
        return;
    drop();
    smb2fh *fh = m_fh;
    m_fh = nullptr;
    m_session->detach(this);
    closeFile(*m_session, fh, Result(Error::Canceled));
}

void Writer::invalidate()
{
    drop();
    m_session->closeLater(m_fh);
    m_fh = nullptr;
    m_lost = true;
}

} // namespace NetVfs::Smb
