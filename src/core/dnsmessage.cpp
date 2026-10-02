// SPDX-License-Identifier: LGPL-2.1-or-later
#include "dnsmessage.h"

#include <QtCore/QHash>

namespace NetVfs::Dns {

namespace {

constexpr int PointerFlag = 0xC0;          // top two bits of a length byte: compression pointer
constexpr int PointerOffsetMask = 0x3F;
constexpr int MaxPointerTarget = 0x3FFF;   // a pointer has 14 offset bits
constexpr quint16 CacheFlushBit = 0x8000;  // class: cache-flush (records), QU (questions)
constexpr int QuestionMinSize = 5;         // root name + type + class
constexpr int RecordMinSize = 11;          // root name + type + class + ttl + rdlength
constexpr int Ipv4Size = 4;
constexpr int Ipv6Size = 16;
constexpr int SrvFixedSize = 6;            // priority, weight, port
constexpr int MaxTxtStringSize = 255;
constexpr int MaxRdataSize = 0xFFFF;
constexpr int OpcodeShift = 11;
constexpr int EscapeDigits = 3;
constexpr int DecimalBase = 10;
constexpr int MaxEscapeValue = 255;
constexpr uchar FirstPrintable = 0x20;
constexpr uchar Delete = 0x7F;

bool fail(QString *error, const char *why)
{
    if (error)
        *error = QString::fromLatin1(why);
    return false;
}

void appendEscaped(QByteArray *out, char c)
{
    const auto u = static_cast<uchar>(c);
    if (c == '.' || c == '\\') {
        out->append('\\');
        out->append(c);
    } else if (u < FirstPrintable || u == Delete) {
        out->append('\\');
        out->append(static_cast<char>('0' + u / 100));
        out->append(static_cast<char>('0' + (u / DecimalBase) % DecimalBase));
        out->append(static_cast<char>('0' + u % DecimalBase));
    } else {
        out->append(c);   // includes bytes >= 0x80: UTF-8 stays readable
    }
}

// Cursor over the packet. Every read checks its bounds first.
class Reader
{
public:
    explicit Reader(const QByteArray &data) : m_data(data.constData()), m_size(data.size()) {}

    int pos() const { return m_pos; }
    int size() const { return m_size; }
    int remaining() const { return m_size - m_pos; }
    void seek(int pos) { m_pos = pos; }

    bool u8(int *v)
    {
        if (remaining() < 1)
            return false;
        *v = byteAt(m_pos++);
        return true;
    }

    bool u16(quint16 *v)
    {
        if (remaining() < 2)
            return false;
        *v = static_cast<quint16>((byteAt(m_pos) << 8) | byteAt(m_pos + 1));
        m_pos += 2;
        return true;
    }

    bool u32(quint32 *v)
    {
        quint16 hi = 0;
        quint16 lo = 0;
        if (!u16(&hi) || !u16(&lo))
            return false;
        *v = (static_cast<quint32>(hi) << 16) | lo;
        return true;
    }

    bool bytes(int n, QByteArray *out)
    {
        if (n < 0 || remaining() < n)
            return false;
        *out = QByteArray(m_data + m_pos, n);
        m_pos += n;
        return true;
    }

    // Reads a (possibly compressed) name at the cursor. The cursor ends after
    // the name as it appears at this position: after the first pointer, or after
    // the root label. A pointer must point strictly backwards, so a chain of
    // pointers ends; labels between pointers add to the name length, which is
    // capped, so a cycle through labels ends too.
    bool name(QByteArray *out, QString *error)
    {
        QByteArray result;
        int p = m_pos;
        int resume = -1;
        int wireLength = 1;                      // the root label
        for (;;) {
            if (p >= m_size)
                return fail(error, "name runs past the end of the packet");
            const int len = byteAt(p);
            if (len == 0)
                break;
            if ((len & PointerFlag) == PointerFlag) {
                if (!followPointer(&p, &resume, error))
                    return false;
                continue;
            }
            if ((len & PointerFlag) != 0)
                return fail(error, "reserved label type");
            if (p + 1 + len > m_size)
                return fail(error, "label runs past the end of the packet");
            wireLength += len + 1;
            if (wireLength > MaxNameLength)
                return fail(error, "name longer than 255 bytes");
            appendLabel(&result, p + 1, len);
            p += 1 + len;
        }
        m_pos = resume >= 0 ? resume : p + 1;
        *out = result;
        return true;
    }

private:
    int byteAt(int i) const { return static_cast<uchar>(m_data[i]); }

    bool followPointer(int *p, int *resume, QString *error) const
    {
        if (*p + 1 >= m_size)
            return fail(error, "truncated compression pointer");
        const int target = ((byteAt(*p) & PointerOffsetMask) << 8) | byteAt(*p + 1);
        if (*resume < 0)
            *resume = *p + 2;
        if (target >= *p)
            return fail(error, "compression pointer does not point backwards");
        *p = target;
        return true;
    }

    void appendLabel(QByteArray *result, int start, int len) const
    {
        if (!result->isEmpty())
            result->append('.');
        for (int i = 0; i < len; ++i)
            appendEscaped(result, m_data[start + i]);
    }

    const char *m_data;
    int m_size;
    int m_pos = 0;
};

bool decodeQuestion(Reader *r, Question *q, QString *error)
{
    quint16 cls = 0;
    if (!r->name(&q->name, error))
        return false;
    if (!r->u16(&q->type) || !r->u16(&cls))
        return fail(error, "truncated question");
    q->unicastResponse = (cls & CacheFlushBit) != 0;
    q->cls = static_cast<quint16>(cls & ~CacheFlushBit);
    return true;
}

bool decodeTxt(Reader *r, int end, QList<QByteArray> *txt, QString *error)
{
    if (r->pos() == end) {
        txt->append(QByteArray());       // RFC 6763 section 6.1: zero length equals one empty string
        return true;
    }
    while (r->pos() < end) {
        int len = 0;
        QByteArray s;
        if (!r->u8(&len) || !r->bytes(len, &s))
            return fail(error, "malformed TXT record");
        txt->append(s);
    }
    return true;
}

bool decodeAddress(Reader *r, quint16 type, int rdlength, QHostAddress *address, QString *error)
{
    QByteArray raw;
    if (type == TypeA) {
        if (rdlength != Ipv4Size || !r->bytes(Ipv4Size, &raw))
            return fail(error, "bad A record length");
        quint32 v = 0;
        for (int i = 0; i < Ipv4Size; ++i)
            v = (v << 8) | static_cast<uchar>(raw[i]);
        address->setAddress(v);
        return true;
    }
    if (rdlength != Ipv6Size || !r->bytes(Ipv6Size, &raw))
        return fail(error, "bad AAAA record length");
    Q_IPV6ADDR v6 = {};
    for (int i = 0; i < Ipv6Size; ++i)
        v6[i] = static_cast<quint8>(raw[i]);
    address->setAddress(v6);
    return true;
}

bool decodeSrv(Reader *r, int end, Record *rec, QString *error)
{
    if (end - r->pos() < SrvFixedSize + 1)
        return fail(error, "SRV record too short");
    if (!r->u16(&rec->priority) || !r->u16(&rec->weight) || !r->u16(&rec->port))
        return fail(error, "SRV record too short");
    return r->name(&rec->target, error);
}

bool decodeRdata(Reader *r, int end, Record *rec, QString *error)
{
    const int rdlength = end - r->pos();
    switch (rec->type) {
    case TypePtr:
        return r->name(&rec->target, error);
    case TypeSrv:
        return decodeSrv(r, end, rec, error);
    case TypeTxt:
        return decodeTxt(r, end, &rec->txt, error);
    case TypeA:
    case TypeAaaa:
        return decodeAddress(r, rec->type, rdlength, &rec->address, error);
    default:
        return r->bytes(rdlength, &rec->rdata);
    }
}

bool decodeRecord(Reader *r, Record *rec, QString *error)
{
    quint16 cls = 0;
    quint16 rdlength = 0;
    if (!r->name(&rec->name, error))
        return false;
    if (!r->u16(&rec->type) || !r->u16(&cls) || !r->u32(&rec->ttl) || !r->u16(&rdlength))
        return fail(error, "truncated record header");
    rec->cacheFlush = (cls & CacheFlushBit) != 0;
    rec->cls = static_cast<quint16>(cls & ~CacheFlushBit);
    if (r->remaining() < rdlength)
        return fail(error, "record data runs past the end of the packet");
    const int end = r->pos() + rdlength;
    if (!decodeRdata(r, end, rec, error))
        return false;
    if (r->pos() != end)
        return fail(error, "record data length mismatch");
    return true;
}

bool decodeRecords(Reader *r, int count, QVector<Record> *out, QString *error)
{
    out->reserve(count);
    for (int i = 0; i < count; ++i) {
        Record rec;
        if (!decodeRecord(r, &rec, error))
            return false;
        out->append(rec);
    }
    return true;
}

struct Counts {
    quint16 questions = 0;
    quint16 answers = 0;
    quint16 authority = 0;
    quint16 additional = 0;
    int records() const { return answers + authority + additional; }
};

bool decodeBody(Reader *r, const Counts &c, Message *msg, QString *error)
{
    msg->questions.reserve(c.questions);
    for (int i = 0; i < c.questions; ++i) {
        Question q;
        if (!decodeQuestion(r, &q, error))
            return false;
        msg->questions.append(q);
    }
    return decodeRecords(r, c.answers, &msg->answers, error)
        && decodeRecords(r, c.authority, &msg->authority, error)
        && decodeRecords(r, c.additional, &msg->additional, error);
}

// Appends to a growing packet; remembers where name suffixes were written so
// later names can point at them.
class Writer
{
public:
    explicit Writer(bool compress) : m_compress(compress) {}

    bool ok() const { return m_ok; }
    int size() const { return m_buf.size(); }
    const QByteArray &data() const { return m_buf; }

    void u8(int v) { m_buf.append(static_cast<char>(v)); }
    void u16(quint16 v)
    {
        u8(v >> 8);
        u8(v & 0xFF);
    }
    void u32(quint32 v)
    {
        u16(static_cast<quint16>(v >> 16));
        u16(static_cast<quint16>(v & 0xFFFF));
    }
    void patch16(int at, quint16 v)
    {
        m_buf[at] = static_cast<char>(v >> 8);
        m_buf[at + 1] = static_cast<char>(v & 0xFF);
    }
    void raw(const QByteArray &b) { m_buf.append(b); }
    void invalidate() { m_ok = false; }

    void name(const QByteArray &presentation, bool allowPointer)
    {
        bool good = false;
        const QList<QByteArray> labels = splitName(presentation, &good);
        if (!good || !wireLengthFits(labels)) {
            m_ok = false;
            return;
        }
        for (int i = 0; i < labels.size(); ++i) {
            const QByteArray suffix = canonicalName(joinName(labels.mid(i)));
            if (const auto known = m_offsets.constFind(suffix);
                allowPointer && m_compress && known != m_offsets.constEnd()) {
                u16(static_cast<quint16>((PointerFlag << 8) | known.value()));
                return;
            }
            if (m_buf.size() <= MaxPointerTarget)
                m_offsets.insert(suffix, m_buf.size());
            u8(labels.at(i).size());
            raw(labels.at(i));
        }
        u8(0);
    }

private:
    static bool wireLengthFits(const QList<QByteArray> &labels)
    {
        int wire = 1;
        for (const QByteArray &label : labels) {
            if (label.isEmpty() || label.size() > MaxLabelLength)
                return false;
            wire += label.size() + 1;
        }
        return wire <= MaxNameLength;
    }

    QByteArray m_buf;
    QHash<QByteArray, int> m_offsets;
    bool m_compress;
    bool m_ok = true;
};

void writeAddress(Writer *w, const Record &rec)
{
    if (rec.type == TypeA) {
        if (rec.address.protocol() != QAbstractSocket::IPv4Protocol) {
            w->invalidate();
            return;
        }
        w->u32(rec.address.toIPv4Address());
        return;
    }
    if (rec.address.protocol() != QAbstractSocket::IPv6Protocol) {
        w->invalidate();
        return;
    }
    const Q_IPV6ADDR v6 = rec.address.toIPv6Address();
    for (int i = 0; i < Ipv6Size; ++i)
        w->u8(v6[i]);
}

void writeTxt(Writer *w, const QList<QByteArray> &txt)
{
    if (txt.isEmpty()) {
        w->u8(0);                       // RFC 6763 section 6.1: a TXT record is never empty
        return;
    }
    for (const QByteArray &s : txt) {
        if (s.size() > MaxTxtStringSize) {
            w->invalidate();
            return;
        }
        w->u8(s.size());
        w->raw(s);
    }
}

void writeRdata(Writer *w, const Record &rec)
{
    switch (rec.type) {
    case TypePtr:
        w->name(rec.target, true);
        break;
    case TypeSrv:
        w->u16(rec.priority);
        w->u16(rec.weight);
        w->u16(rec.port);
        w->name(rec.target, false);
        break;
    case TypeTxt:
        writeTxt(w, rec.txt);
        break;
    case TypeA:
    case TypeAaaa:
        writeAddress(w, rec);
        break;
    default:
        w->raw(rec.rdata);
        break;
    }
}

void writeRecord(Writer *w, const Record &rec)
{
    w->name(rec.name, true);
    w->u16(rec.type);
    w->u16(static_cast<quint16>(rec.cls | (rec.cacheFlush ? CacheFlushBit : 0)));
    w->u32(rec.ttl);
    const int lengthAt = w->size();
    w->u16(0);
    writeRdata(w, rec);
    const int rdlength = w->size() - lengthAt - 2;
    if (rdlength > MaxRdataSize) {
        w->invalidate();
        return;
    }
    w->patch16(lengthAt, static_cast<quint16>(rdlength));
}

bool countFits(const Message &m)
{
    constexpr int Max = 0xFFFF;
    return m.questions.size() <= Max && m.answers.size() <= Max && m.authority.size() <= Max
        && m.additional.size() <= Max;
}

void writeSection(Writer *w, const QVector<Record> &records)
{
    for (const Record &r : records)
        writeRecord(w, r);
}

} // namespace

bool decode(const QByteArray &packet, Message *out, QString *error)
{
    *out = Message();
    if (packet.size() < HeaderSize || packet.size() > MaxPacketSize)
        return fail(error, "packet size out of range");
    Reader r(packet);
    Counts c;
    quint16 flags = 0;
    quint16 id = 0;
    r.u16(&id);
    r.u16(&flags);
    r.u16(&c.questions);
    r.u16(&c.answers);
    r.u16(&c.authority);
    r.u16(&c.additional);
    // Counts that cannot fit into the packet are rejected before anything is
    // allocated for them.
    if (c.questions + c.records() > MaxRecords)
        return fail(error, "too many records");
    if (c.questions * QuestionMinSize + c.records() * RecordMinSize > r.remaining())
        return fail(error, "record counts exceed the packet size");
    Message msg;
    msg.id = id;
    msg.flags = flags;
    if (!decodeBody(&r, c, &msg, error))
        return false;
    *out = msg;
    return true;
}

QByteArray encode(const Message &message, bool compress)
{
    if (!countFits(message))
        return QByteArray();
    Writer w(compress);
    w.u16(message.id);
    w.u16(message.flags);
    w.u16(static_cast<quint16>(message.questions.size()));
    w.u16(static_cast<quint16>(message.answers.size()));
    w.u16(static_cast<quint16>(message.authority.size()));
    w.u16(static_cast<quint16>(message.additional.size()));
    for (const Question &q : message.questions) {
        w.name(q.name, true);
        w.u16(q.type);
        w.u16(static_cast<quint16>(q.cls | (q.unicastResponse ? CacheFlushBit : 0)));
    }
    writeSection(&w, message.answers);
    writeSection(&w, message.authority);
    writeSection(&w, message.additional);
    if (!w.ok() || w.size() > MaxPacketSize)
        return QByteArray();
    return w.data();
}

namespace {

// Parses "\DDD" or "\X" at name[*i] == '\\'; appends the byte, advances *i.
bool parseEscape(const QByteArray &name, int *i, QByteArray *label)
{
    const int n = name.size();
    if (*i + 1 >= n)
        return false;
    if (const char next = name.at(*i + 1); next < '0' || next > '9') {
        label->append(next);
        *i += 2;
        return true;
    }
    if (*i + EscapeDigits >= n)
        return false;
    int value = 0;
    for (int k = 1; k <= EscapeDigits; ++k) {
        const char d = name.at(*i + k);
        if (d < '0' || d > '9')
            return false;
        value = value * DecimalBase + (d - '0');
    }
    if (value > MaxEscapeValue)
        return false;
    label->append(static_cast<char>(value));
    *i += 1 + EscapeDigits;
    return true;
}

} // namespace

QList<QByteArray> splitName(const QByteArray &name, bool *ok)
{
    QList<QByteArray> labels;
    QByteArray current;
    bool good = true;
    int i = 0;
    while (good && i < name.size()) {
        const char c = name.at(i);
        if (c == '.') {
            good = !current.isEmpty();
            labels.append(current);
            current.clear();
            ++i;
        } else if (c == '\\') {
            good = parseEscape(name, &i, &current);
        } else {
            current.append(c);
            ++i;
        }
    }
    if (!current.isEmpty())
        labels.append(current);
    if (ok)
        *ok = good;
    return labels;
}

QByteArray joinName(const QList<QByteArray> &labels)
{
    QByteArray out;
    for (const QByteArray &label : labels) {
        if (!out.isEmpty())
            out.append('.');
        for (const char c : label)
            appendEscaped(&out, c);
    }
    return out;
}

QByteArray canonicalName(const QByteArray &name)
{
    return name.toLower();
}

namespace {

bool findTxt(const QList<QByteArray> &txt, const QByteArray &key, QByteArray *value)
{
    const QByteArray wanted = key.toLower();
    for (const QByteArray &s : txt) {
        const int eq = s.indexOf('=');
        if (const QByteArray k = (eq >= 0 ? s.left(eq) : s).toLower(); !k.isEmpty() && k == wanted) {
            *value = eq >= 0 ? s.mid(eq + 1) : QByteArray();
            return true;
        }
    }
    return false;
}

} // namespace

QByteArray txtValue(const QList<QByteArray> &txt, const QByteArray &key, const QByteArray &fallback)
{
    QByteArray value;
    return findTxt(txt, key, &value) ? value : fallback;
}

bool txtHasKey(const QList<QByteArray> &txt, const QByteArray &key)
{
    QByteArray ignored;
    return findTxt(txt, key, &ignored);
}

} // namespace NetVfs::Dns
