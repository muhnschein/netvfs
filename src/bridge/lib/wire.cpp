// SPDX-License-Identifier: LGPL-2.1-or-later
#include "wire.h"

#include <dbus/dbus.h>

namespace NetVfs::Bridge {

void MessageUnref::operator()(DBusMessage *message) const
{
    if (message)
        dbus_message_unref(message);
}

SharedMessage shareMessage(DBusMessage *message)
{
    if (!message)
        return SharedMessage();
    dbus_message_ref(message);
    return SharedMessage(message, MessageUnref());
}

// ----------------------------------------------------------------- decoding

namespace {

class Decoder
{
public:
    explicit Decoder(const DecodeLimits &limits) : m_limits(limits) {}

    Result value(DBusMessageIter *iter, int depth, QVariant *out);

private:
    Result basic(DBusMessageIter *iter, int type, QVariant *out) const;
    Result array(DBusMessageIter *iter, int depth, QVariant *out);
    Result dict(DBusMessageIter *sub, int depth, QVariant *out);
    Result list(DBusMessageIter *sub, int depth, QVariant *out);

    static Result tooComplex() { return Result(Error::ProtocolError, QStringLiteral("Argument too complex")); }

    DecodeLimits m_limits;
};

Result Decoder::basic(DBusMessageIter *iter, int type, QVariant *out) const
{
    DBusBasicValue v;
    dbus_message_iter_get_basic(iter, &v);
    switch (type) {
    case DBUS_TYPE_BYTE:
        *out = QVariant(uint(v.byt));
        break;
    case DBUS_TYPE_BOOLEAN:
        *out = QVariant(v.bool_val != 0);
        break;
    case DBUS_TYPE_INT16:
        *out = QVariant(int(v.i16));
        break;
    case DBUS_TYPE_UINT16:
        *out = QVariant(uint(v.u16));
        break;
    case DBUS_TYPE_INT32:
        *out = QVariant(int(v.i32));
        break;
    case DBUS_TYPE_UINT32:
        *out = QVariant(uint(v.u32));
        break;
    case DBUS_TYPE_INT64:
        *out = QVariant(qlonglong(v.i64));
        break;
    case DBUS_TYPE_UINT64:
        *out = QVariant(qulonglong(v.u64));
        break;
    case DBUS_TYPE_DOUBLE:
        *out = QVariant(v.dbl);
        break;
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
    case DBUS_TYPE_SIGNATURE:
        *out = QVariant(QString::fromUtf8(v.str));
        break;
    case DBUS_TYPE_UNIX_FD:
        *out = QVariant::fromValue(UnixFd(v.fd));
        break;
    default:
        return Result(Error::ProtocolError, QStringLiteral("Unsupported argument type"));
    }
    return Result::success();
}

Result Decoder::value(DBusMessageIter *iter, int depth, QVariant *out)
{
    const int type = dbus_message_iter_get_arg_type(iter);
    if (type == DBUS_TYPE_ARRAY)
        return array(iter, depth, out);
    if (type == DBUS_TYPE_STRUCT || type == DBUS_TYPE_VARIANT) {
        if (depth >= m_limits.maxDepth)
            return tooComplex();
        DBusMessageIter sub;
        dbus_message_iter_recurse(iter, &sub);
        if (type == DBUS_TYPE_VARIANT)
            return value(&sub, depth + 1, out);
        return list(&sub, depth + 1, out);
    }
    return basic(iter, type, out);
}

Result Decoder::array(DBusMessageIter *iter, int depth, QVariant *out)
{
    if (depth >= m_limits.maxDepth)
        return tooComplex();
    const int element = dbus_message_iter_get_element_type(iter);
    DBusMessageIter sub;
    dbus_message_iter_recurse(iter, &sub);
    if (element == DBUS_TYPE_BYTE) {
        const char *data = nullptr;
        int n = 0;
        dbus_message_iter_get_fixed_array(&sub, &data, &n);
        *out = QVariant(QByteArray(data, n));
        return Result::success();
    }
    if (element == DBUS_TYPE_DICT_ENTRY)
        return dict(&sub, depth + 1, out);
    if (element == DBUS_TYPE_STRING) {
        QStringList strings;
        for (; dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID; dbus_message_iter_next(&sub)) {
            if (strings.size() >= m_limits.maxElements)
                return tooComplex();
            const char *s = nullptr;
            dbus_message_iter_get_basic(&sub, &s);
            strings << QString::fromUtf8(s);
        }
        *out = QVariant(strings);
        return Result::success();
    }
    return list(&sub, depth + 1, out);
}

Result Decoder::dict(DBusMessageIter *sub, int depth, QVariant *out)
{
    QVariantMap map;
    int count = 0;
    while (dbus_message_iter_get_arg_type(sub) != DBUS_TYPE_INVALID) {
        if (++count > m_limits.maxElements)
            return tooComplex();
        DBusMessageIter entry;
        dbus_message_iter_recurse(sub, &entry);
        if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
            return Result(Error::ProtocolError, QStringLiteral("Dictionary keys must be strings"));
        const char *key = nullptr;
        dbus_message_iter_get_basic(&entry, &key);
        dbus_message_iter_next(&entry);
        QVariant v;
        if (const Result r = value(&entry, depth, &v); !r.ok())
            return r;
        map.insert(QString::fromUtf8(key), v);
        dbus_message_iter_next(sub);
    }
    *out = QVariant(map);
    return Result::success();
}

Result Decoder::list(DBusMessageIter *sub, int depth, QVariant *out)
{
    QVariantList items;
    while (dbus_message_iter_get_arg_type(sub) != DBUS_TYPE_INVALID) {
        if (items.size() >= m_limits.maxElements)
            return tooComplex();
        QVariant v;
        if (const Result r = value(sub, depth, &v); !r.ok())
            return r;
        items << v;
        dbus_message_iter_next(sub);
    }
    *out = QVariant(items);
    return Result::success();
}

// libdbus aborts on strings with NUL characters (a failed check); QString
// may hold them. U+FFFD stands in.
QByteArray wireString(const QString &v)
{
    QString copy = v;
    copy.replace(QChar(0), QChar(0xFFFD));
    return copy.toUtf8();
}

} // namespace

Result decodeArguments(DBusMessage *message, QVariantList *out, const DecodeLimits &limits)
{
    out->clear();
    DBusMessageIter iter;
    if (!dbus_message_iter_init(message, &iter))
        return Result::success();
    Decoder decoder(limits);
    for (; dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INVALID; dbus_message_iter_next(&iter)) {
        QVariant v;
        if (const Result r = decoder.value(&iter, 0, &v); !r.ok()) {
            out->clear();
            return r;
        }
        out->append(v);
    }
    return Result::success();
}

// ------------------------------------------------------------------ writing

QByteArray variantSignature(const QVariant &v)
{
    switch (int(v.type())) {
    case QMetaType::Bool:
        return "b";
    case QMetaType::Int:
        return "i";
    case QMetaType::UInt:
        return "u";
    case QMetaType::LongLong:
        return "x";
    case QMetaType::ULongLong:
        return "t";
    case QMetaType::Double:
        return "d";
    case QMetaType::QString:
        return "s";
    case QMetaType::QByteArray:
        return "ay";
    case QMetaType::QStringList:
        return "as";
    case QMetaType::QVariantMap:
        return "a{sv}";
    case QMetaType::QVariantList:
        return "av";
    default:
        return QByteArray();
    }
}

WireWriter::WireWriter(DBusMessage *message)
{
    auto iter = std::make_unique<DBusMessageIter>();
    dbus_message_iter_init_append(message, iter.get());
    m_stack.push_back(std::move(iter));
}

WireWriter::~WireWriter()
{
    // Abandon containers left open so libdbus does not keep a half-built message.
    m_ok = false;
    while (m_stack.size() > 1)
        close();
}

DBusMessageIter *WireWriter::top()
{
    return m_stack.back().get();
}

template <typename T>
void WireWriter::appendBasic(int type, const T *value)
{
    if (m_ok && top() && !dbus_message_iter_append_basic(top(), type, value))
        m_ok = false;
}

WireWriter &WireWriter::byte(quint8 v)
{
    const unsigned char b = v;
    appendBasic(DBUS_TYPE_BYTE, &b);
    return *this;
}

WireWriter &WireWriter::boolean(bool v)
{
    const dbus_bool_t b = v ? TRUE : FALSE;
    appendBasic(DBUS_TYPE_BOOLEAN, &b);
    return *this;
}

WireWriter &WireWriter::int32(qint32 v)
{
    const dbus_int32_t i = v;
    appendBasic(DBUS_TYPE_INT32, &i);
    return *this;
}

WireWriter &WireWriter::uint16(quint16 v)
{
    const dbus_uint16_t q = v;
    appendBasic(DBUS_TYPE_UINT16, &q);
    return *this;
}

WireWriter &WireWriter::uint32(quint32 v)
{
    const dbus_uint32_t u = v;
    appendBasic(DBUS_TYPE_UINT32, &u);
    return *this;
}

WireWriter &WireWriter::int64(qint64 v)
{
    const dbus_int64_t x = v;
    appendBasic(DBUS_TYPE_INT64, &x);
    return *this;
}

WireWriter &WireWriter::string(const QString &v)
{
    const QByteArray utf8 = wireString(v);
    const char *s = utf8.constData();
    appendBasic(DBUS_TYPE_STRING, &s);
    return *this;
}

WireWriter &WireWriter::bytes(const QByteArray &v)
{
    openArray(DBUS_TYPE_BYTE_AS_STRING);
    if (m_ok && top()) {
        const char *data = v.constData();
        if (!dbus_message_iter_append_fixed_array(top(), DBUS_TYPE_BYTE, &data, v.size()))
            m_ok = false;
    }
    return close();
}

WireWriter &WireWriter::strings(const QStringList &v)
{
    openArray(DBUS_TYPE_STRING_AS_STRING);
    for (const QString &s : v)
        string(s);
    return close();
}

WireWriter &WireWriter::unixFd(int fd)
{
    appendBasic(DBUS_TYPE_UNIX_FD, &fd);
    return *this;
}

WireWriter &WireWriter::variantMap(const QVariantMap &v)
{
    openArray("{sv}");
    for (auto it = v.constBegin(); it != v.constEnd() && m_ok; ++it) {
        open(DBUS_TYPE_DICT_ENTRY, nullptr);
        string(it.key());
        variant(it.value());
        close();
    }
    return close();
}

bool WireWriter::appendVariantValue(const QVariant &v)
{
    switch (int(v.type())) {
    case QMetaType::Bool:
        boolean(v.toBool());
        break;
    case QMetaType::Int:
        int32(v.toInt());
        break;
    case QMetaType::UInt:
        uint32(v.toUInt());
        break;
    case QMetaType::LongLong:
        int64(v.toLongLong());
        break;
    case QMetaType::ULongLong: {
        const dbus_uint64_t t = v.toULongLong();
        appendBasic(DBUS_TYPE_UINT64, &t);
        break;
    }
    case QMetaType::Double: {
        const double d = v.toDouble();
        appendBasic(DBUS_TYPE_DOUBLE, &d);
        break;
    }
    case QMetaType::QString:
        string(v.toString());
        break;
    case QMetaType::QByteArray:
        bytes(v.toByteArray());
        break;
    case QMetaType::QStringList:
        strings(v.toStringList());
        break;
    case QMetaType::QVariantMap:
        variantMap(v.toMap());
        break;
    case QMetaType::QVariantList: {
        openArray("v");
        const QVariantList items = v.toList();
        for (const QVariant &item : items)
            variant(item);
        close();
        break;
    }
    default:
        return false;
    }
    return true;
}

WireWriter &WireWriter::variant(const QVariant &v)
{
    const QByteArray signature = variantSignature(v);
    if (signature.isEmpty())
        m_ok = false;
    if (!m_ok)
        return *this;
    open(DBUS_TYPE_VARIANT, signature.constData());
    if (!appendVariantValue(v))
        m_ok = false;
    return close();
}

// A failed open pushes a null level so that open/close pairs stay balanced.
void WireWriter::open(int type, const char *signature)
{
    std::unique_ptr<DBusMessageIter> sub;
    if (DBusMessageIter *parent = top(); m_ok && parent) {
        sub = std::make_unique<DBusMessageIter>();
        if (!dbus_message_iter_open_container(parent, type, signature, sub.get())) {
            m_ok = false;
            sub.reset();
        }
    }
    m_stack.push_back(std::move(sub));
}

WireWriter &WireWriter::openStruct()
{
    open(DBUS_TYPE_STRUCT, nullptr);
    return *this;
}

WireWriter &WireWriter::openArray(const char *elementSignature)
{
    open(DBUS_TYPE_ARRAY, elementSignature);
    return *this;
}

WireWriter &WireWriter::close()
{
    if (m_stack.size() <= 1)
        return *this;
    std::unique_ptr<DBusMessageIter> sub = std::move(m_stack.back());
    m_stack.pop_back();
    DBusMessageIter *parent = top();
    if (!sub || !parent)
        return *this;
    if (!m_ok)
        dbus_message_iter_abandon_container(parent, sub.get());
    else if (!dbus_message_iter_close_container(parent, sub.get()))
        m_ok = false;
    return *this;
}

} // namespace NetVfs::Bridge
