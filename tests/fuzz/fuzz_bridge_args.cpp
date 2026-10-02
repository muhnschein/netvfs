// SPDX-License-Identifier: LGPL-2.1-or-later
// SPEC-v2 XT-7, XSEC-7: the bridge's argument validation, fed with decoded
// argument tuples as the adaptor hands them over (wire.h decodeArguments ->
// args.h validateCall), without D-Bus. The input picks a method and, per
// argument, a value of the declared type or, sometimes, of another type.
// Properties: validation never crashes; what it accepts is normalised and in
// range; secrets end up only in the Call.
//
// fuzz-sources: src/bridge/lib/args.cpp src/bridge/lib/unixfd.cpp src/core/names.cpp src/core/paths.cpp src/core/secure.cpp src/core/error.cpp src/core/types.cpp
// fuzz-includes: src/bridge/lib
#include "args.h"
#include "paths.h"
#include "unixfd.h"

#include <QtCore/QVariantMap>

#include <cstddef>
#include <cstdint>

using namespace NetVfs;
using namespace NetVfs::Bridge;

namespace {

void require(bool condition)
{
    if (!condition)
        __builtin_trap();
}

class Input
{
public:
    Input(const uint8_t *data, size_t size) : m_data(data), m_size(size) {}

    bool empty() const { return m_pos >= m_size; }
    uint8_t byte() { return empty() ? 0 : m_data[m_pos++]; }
    quint32 u32()
    {
        quint32 v = 0;
        for (int i = 0; i < 4; ++i)
            v = (v << 8) | byte();
        return v;
    }
    qint64 i64()
    {
        quint64 v = 0;
        for (int i = 0; i < 8; ++i)
            v = (v << 8) | byte();
        return static_cast<qint64>(v);
    }
    QByteArray bytes()
    {
        const int n = std::min<int>(byte() | (byte() << 4), int(m_size - std::min(m_pos, m_size)));
        QByteArray out(reinterpret_cast<const char *>(m_data + m_pos), n);
        m_pos += size_t(n);
        return out;
    }
    QString text() { return QString::fromUtf8(bytes()); }

private:
    const uint8_t *m_data;
    size_t m_size;
    size_t m_pos = 0;
};

QVariant anyScalar(Input &in);

QVariantMap options(Input &in)
{
    static const char *const keys[] = { "mode", "mtimeMs", "atimeMs", "recursive", "replace", "maxDepth",
                                        "followSymlinks", "postOrder", "offset", "size", "disposition",
                                        "createMode", "lane", "user", "security_profile", "accept", "answers",
                                        "bogus" };
    QVariantMap map;
    const int n = in.byte() % 6;
    for (int i = 0; i < n; ++i) {
        const char *key = keys[in.byte() % (sizeof(keys) / sizeof(keys[0]))];
        if (QByteArray(key) == "answers" && in.byte() % 2) {
            QVariantList answers;
            const int count = in.byte() % 20;
            for (int j = 0; j < count; ++j)
                answers << QVariant(in.bytes());
            map.insert(QLatin1String(key), answers);
        } else {
            map.insert(QLatin1String(key), anyScalar(in));
        }
    }
    return map;
}

QVariant anyScalar(Input &in)
{
    switch (in.byte() % 8) {
    case 0:
        return QVariant(in.byte() % 2 == 1);
    case 1:
        return QVariant(int(in.u32()));
    case 2:
        return QVariant(in.u32());
    case 3:
        return QVariant(qlonglong(in.i64()));
    case 4:
        return QVariant(qulonglong(in.i64()));
    case 5:
        return QVariant(in.text());
    case 6:
        return QVariant(in.bytes());
    default:
        return QVariant::fromValue(UnixFd());
    }
}

// A value of D-Bus type `type` (one complete type), as decodeArguments makes it.
QVariant valueFor(Input &in, const QByteArray &type)
{
    if (in.byte() % 16 == 0)
        return anyScalar(in);   // a wrong type now and then
    if (type == "u")
        return QVariant(in.u32());
    if (type == "x")
        return QVariant(qlonglong(in.i64()));
    if (type == "b")
        return QVariant(in.byte() % 2 == 1);
    if (type == "s")
        return QVariant(in.byte() % 2 ? in.text() : QString::fromLatin1(in.byte() % 2 ? "account:1" : "bulk"));
    if (type == "ay")
        return QVariant(in.bytes());
    if (type == "h")
        return QVariant::fromValue(UnixFd());
    return QVariant(options(in));
}

QList<QByteArray> split(const char *signature)
{
    QList<QByteArray> parts;
    const QByteArray s(signature);
    int start = 0;
    int depth = 0;
    for (int i = 0; i < s.size(); ++i) {
        if (s.at(i) == '(' || s.at(i) == '{')
            ++depth;
        else if (s.at(i) == ')' || s.at(i) == '}')
            --depth;
        if (depth == 0 && s.at(i) != 'a') {
            parts << s.mid(start, i - start + 1);
            start = i + 1;
        }
    }
    return parts;
}

void checkAccepted(const Call &call, const QVariantList &args)
{
    QString again;
    if (!call.path.isEmpty())
        require(Paths::normalize(call.path, &again).ok() && again == call.path);
    if (!call.path2.isEmpty())
        require(Paths::normalize(call.path2, &again).ok() && again == call.path2);
    require(call.offset >= 0 && call.offset <= Limits::MaxOffset);
    require(call.length >= 0);
    if (call.method == Method::List)
        require(call.number >= 1 && call.number <= quint32(Limits::MaxListBatch));
    if (call.method == Method::Read)
        require(call.length <= Limits::MaxReadBytes);
    require(call.transfer.offset >= 0 && call.transfer.size >= -1);
    require(call.attributes.mode >= -1 && call.attributes.mode <= 07777);
    require(call.tree.maxDepth >= -1 && call.tree.maxDepth <= Limits::MaxWalkDepth);
    if (!call.loc.isEmpty())
        require(isValidLocationId(call.loc));
    if (call.method == Method::ConnectAdHoc)
        require(!args.at(1).isValid());   // the secret left the argument list
    require(call.secret.size() <= Limits::MaxSecretBytes);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Input in(data, size);
    const QVector<MethodInfo> &all = methods();
    const MethodInfo &method = all.at(in.byte() % all.size());
    QByteArray signature(method.in);
    const QList<QByteArray> types = split(method.in);
    QVariantList args;
    for (const QByteArray &type : types)
        args << valueFor(in, type);
    if (in.byte() % 32 == 0 && !args.isEmpty())
        args.removeLast();                          // a count that does not fit the signature
    if (in.byte() % 32 == 0)
        signature = in.bytes();                     // a signature that does not fit the method
    Call call;
    const Result r = validateCall(QLatin1String(method.name), QString::fromLatin1(signature), &args, &call);
    if (r.ok())
        checkAccepted(call, args);
    wipeSecrets(&call);
    require(call.secret.isEmpty() && call.answer.answers.isEmpty());
    return 0;
}
