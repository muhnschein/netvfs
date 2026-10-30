// SPDX-License-Identifier: LGPL-2.1-or-later
#include "rshandles.h"
#include "rsmarshal.h"

#include <limits>
#include <utility>

namespace NetVfs::Rs {

namespace {

constexpr qint64 MaxReadBytes = std::numeric_limits<int>::max() / 2;

Result invalid(const char *what)
{
    return Result(Error::Internal, QStringLiteral("Invalid %1").arg(QLatin1String(what)));
}

}
RsReadHandle::~RsReadHandle()
{
    if (m_h)
        m_t->free(m_t->read_close(m_h));
}

Result RsReadHandle::read(qint64 offset, qint64 maxBytes, QByteArray *out)
{
    if (out)
        out->clear();
    if (maxBytes < 0 || maxBytes > MaxReadBytes)
        return invalid("range");
    QByteArray data(static_cast<int>(maxBytes), Qt::Uninitialized);
    size_t got = 0;
    const Result r = resultOf(m_t, m_t->read(m_h, offset, reinterpret_cast<uint8_t *>(data.data()),
                                             static_cast<size_t>(data.size()), &got));
    data.resize(static_cast<int>(got));
    if (out && r.ok())
        *out = data;
    return r;
}

void RsReadHandle::readAhead(qint64 offset, qint64 bytes)
{
    m_t->read_ahead(m_h, offset, bytes);
}

Result RsReadHandle::close()
{
    return resultOf(m_t, m_t->read_close(std::exchange(m_h, nullptr)));
}

RsWriteHandle::~RsWriteHandle()
{
    m_t->abort(m_h);
}

Result RsWriteHandle::write(const char *data, qint64 length)
{
    if (length < 0)
        return invalid("length");
    return resultOf(m_t, m_t->write(m_h, reinterpret_cast<const uint8_t *>(data), static_cast<size_t>(length)));
}

qint64 RsWriteHandle::position() const
{
    return m_t->position(m_h);
}

Result RsWriteHandle::commit()
{
    return resultOf(m_t, m_t->commit(std::exchange(m_h, nullptr)));
}

void RsWriteHandle::abort()
{
    m_t->abort(std::exchange(m_h, nullptr));
}

}