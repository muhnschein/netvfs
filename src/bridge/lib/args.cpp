// SPDX-License-Identifier: LGPL-2.1-or-later
#include "args.h"

#include "names.h"
#include "unixfd.h"
#include "paths.h"
#include "secure.h"

#include <algorithm>
#include <functional>
#include <limits>

namespace NetVfs::Bridge {

namespace {

const char EntrySig[] = "(ayyyxxxxixxssqays)";

Result invalidArgs(const QString &what)
{
    return Result(Error::ProtocolError, what);
}

bool isType(const QVariant &v, int type)
{
    return v.userType() == type;
}

bool toInt64(const QVariant &v, qint64 *out)
{
    switch (v.userType()) {
    case QMetaType::Int:
    case QMetaType::UInt:
    case QMetaType::LongLong:
        *out = v.toLongLong();
        return true;
    case QMetaType::ULongLong:
        if (v.toULongLong() > static_cast<qulonglong>(std::numeric_limits<qint64>::max()))
            return false;
        *out = v.toLongLong();
        return true;
    default:
        return false;
    }
}

Result getString(const QVariantList &args, int i, int maxLength, QString *out)
{
    const QVariant &v = args.at(i);
    if (!isType(v, QMetaType::QString))
        return invalidArgs(QStringLiteral("Argument %1 must be a string").arg(i + 1));
    const QString s = v.toString();
    if (s.size() > maxLength)
        return invalidArgs(QStringLiteral("Argument %1 is too long").arg(i + 1));
    *out = s;
    return Result::success();
}

Result getToken(const QVariantList &args, int i, int maxLength, QString *out)
{
    QString s;
    if (const Result r = getString(args, i, maxLength, &s); !r.ok())
        return r;
    if (!isValidToken(s, maxLength))
        return invalidArgs(QStringLiteral("Argument %1 is not a valid name").arg(i + 1));
    *out = s;
    return Result::success();
}

Result getBool(const QVariantList &args, int i, bool *out)
{
    if (!isType(args.at(i), QMetaType::Bool))
        return invalidArgs(QStringLiteral("Argument %1 must be a boolean").arg(i + 1));
    *out = args.at(i).toBool();
    return Result::success();
}

Result getUInt(const QVariantList &args, int i, quint32 *out)
{
    if (!isType(args.at(i), QMetaType::UInt))
        return invalidArgs(QStringLiteral("Argument %1 must be an unsigned integer").arg(i + 1));
    *out = args.at(i).toUInt();
    return Result::success();
}

Result getOffset(const QVariantList &args, int i, qint64 *out)
{
    if (!isType(args.at(i), QMetaType::LongLong))
        return invalidArgs(QStringLiteral("Argument %1 must be a 64-bit integer").arg(i + 1));
    const qint64 v = args.at(i).toLongLong();
    if (v < 0 || v > Limits::MaxOffset)
        return invalidArgs(QStringLiteral("Argument %1 is out of range").arg(i + 1));
    *out = v;
    return Result::success();
}

Result getPath(const QVariantList &args, int i, QString *out)
{
    return validatePath(args.at(i), out);
}

Result getLoc(const QVariantList &args, int i, QString *out)
{
    return validateLocationId(args.at(i), out);
}

// ------------------------------------------------------------- option maps

Result getMap(const QVariantList &args, int i, QVariantMap *out)
{
    if (!isType(args.at(i), QMetaType::QVariantMap))
        return invalidArgs(QStringLiteral("Argument %1 must be a dictionary").arg(i + 1));
    *out = args.at(i).toMap();
    return Result::success();
}

template <typename OptionHandler>
Result forEachOption(const QVariantList &args, int i, Call *call, const OptionHandler &handler)
{
    QVariantMap map;
    if (const Result r = getMap(args, i, &map); !r.ok())
        return r;
    for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
        if (const Result r = handler(it.key(), it.value(), call); !r.ok())
            return r;
    }
    return Result::success();
}

Result unknownOption(const QString &key)
{
    return invalidArgs(QStringLiteral("Unknown option \"%1\"").arg(key.left(Limits::MaxShortString)));
}

Result optionBool(const QString &key, const QVariant &value, bool *out)
{
    if (!isType(value, QMetaType::Bool))
        return invalidArgs(QStringLiteral("Option \"%1\" must be a boolean").arg(key));
    *out = value.toBool();
    return Result::success();
}

Result optionInt(const QString &key, const QVariant &value, qint64 min, qint64 max, qint64 *out)
{
    qint64 v = 0;
    if (!toInt64(value, &v))
        return invalidArgs(QStringLiteral("Option \"%1\" must be an integer").arg(key));
    if (v < min || v > max)
        return invalidArgs(QStringLiteral("Option \"%1\" is out of range").arg(key));
    *out = v;
    return Result::success();
}

Result optionMode(const QString &key, const QVariant &value, qint32 *out)
{
    qint64 v = 0;
    if (const Result r = optionInt(key, value, 0, 07777, &v); !r.ok())
        return r;
    *out = static_cast<qint32>(v);
    return Result::success();
}

Result optionTime(const QString &key, const QVariant &value, QDateTime *out)
{
    qint64 v = 0;
    if (const Result r = optionInt(key, value, Limits::MinTimeMs, Limits::MaxTimeMs, &v); !r.ok())
        return r;
    *out = QDateTime::fromMSecsSinceEpoch(v, Qt::UTC);
    return Result::success();
}

Result attributeOption(const QString &key, const QVariant &value, Call *call)
{
    if (key == QLatin1String("mode"))
        return optionMode(key, value, &call->attributes.mode);
    if (key == QLatin1String("mtimeMs"))
        return optionTime(key, value, &call->attributes.modified);
    if (key == QLatin1String("atimeMs"))
        return optionTime(key, value, &call->attributes.accessed);
    return unknownOption(key);
}

Result copyOption(const QString &key, const QVariant &value, Call *call)
{
    if (key == QLatin1String("recursive"))
        return optionBool(key, value, &call->tree.recursive);
    if (key == QLatin1String("replace"))
        return optionBool(key, value, &call->tree.replace);
    return unknownOption(key);
}

Result walkOption(const QString &key, const QVariant &value, Call *call)
{
    if (key == QLatin1String("maxDepth")) {
        qint64 depth = 0;
        const Result r = optionInt(key, value, -1, Limits::MaxWalkDepth, &depth);
        call->tree.maxDepth = static_cast<int>(depth);
        return r;
    }
    if (key == QLatin1String("followSymlinks"))
        return optionBool(key, value, &call->tree.followSymlinks);
    if (key == QLatin1String("postOrder"))
        return optionBool(key, value, &call->tree.postOrder);
    return unknownOption(key);
}

Result laneOption(const QString &key, const QVariant &value, Call *call)
{
    if (!isType(value, QMetaType::QString))
        return invalidArgs(QStringLiteral("Option \"%1\" must be a string").arg(key));
    return validateLane(value, call->lane, &call->lane);
}

Result dispositionOption(const QString &key, const QVariant &value, Call *call)
{
    if (const QString s = isType(value, QMetaType::QString) ? value.toString() : QString();
        s == QLatin1String("create"))
        call->transfer.disposition = WriteOptions::CreateNew;
    else if (s == QLatin1String("truncate"))
        call->transfer.disposition = WriteOptions::Truncate;
    else if (s == QLatin1String("resume"))
        call->transfer.disposition = WriteOptions::Resume;
    else
        return invalidArgs(QStringLiteral("Option \"%1\" must be create, truncate or resume").arg(key));
    return Result::success();
}

// Upload and Download share the keys; Download ignores the write-only ones
// by refusing them.
Result transferCommonOption(const QString &key, const QVariant &value, Call *call, bool *handled)
{
    *handled = true;
    if (key == QLatin1String("offset"))
        return optionInt(key, value, 0, Limits::MaxOffset, &call->transfer.offset);
    if (key == QLatin1String("size"))
        return optionInt(key, value, -1, Limits::MaxOffset, &call->transfer.size);
    if (key == QLatin1String("lane"))
        return laneOption(key, value, call);
    *handled = false;
    return Result::success();
}

Result uploadOption(const QString &key, const QVariant &value, Call *call)
{
    bool handled = false;
    if (const Result r = transferCommonOption(key, value, call, &handled); handled)
        return r;
    if (key == QLatin1String("disposition"))
        return dispositionOption(key, value, call);
    if (key == QLatin1String("createMode"))
        return optionMode(key, value, &call->transfer.createMode);
    if (key == QLatin1String("mtimeMs")) {
        call->transfer.hasMtime = true;
        return optionInt(key, value, Limits::MinTimeMs, Limits::MaxTimeMs, &call->transfer.mtimeMs);
    }
    return unknownOption(key);
}

Result downloadOption(const QString &key, const QVariant &value, Call *call)
{
    bool handled = false;
    if (const Result r = transferCommonOption(key, value, call, &handled); handled)
        return r;
    return unknownOption(key);
}

Result adHocOption(const QString &key, const QVariant &value, Call *call)
{
    if (!isType(value, QMetaType::QString) || value.toString().size() > Limits::MaxShortString)
        return invalidArgs(QStringLiteral("Option \"%1\" must be a short string").arg(key));
    const QString s = value.toString();
    if (key == QLatin1String("user")) {
        if (s.contains(QChar(0)))
            return invalidArgs(QStringLiteral("Option \"user\" contains NUL"));
        call->adHoc.user = s;
        return Result::success();
    }
    if (key == QLatin1String("security_profile")) {
        if (static const QStringList profiles = { QStringLiteral("strict"), QStringLiteral("signed"),
                                                  QStringLiteral("legacy"), QStringLiteral("guest") };
            !profiles.contains(s))
            return invalidArgs(QStringLiteral("Unknown security profile"));
        call->adHoc.securityProfile = s;
        return Result::success();
    }
    return unknownOption(key);
}

Result answerOption(const QString &key, const QVariant &value, Call *call)
{
    if (key == QLatin1String("accept"))
        return optionBool(key, value, &call->answer.accept);
    if (key != QLatin1String("answers"))
        return unknownOption(key);
    if (!isType(value, QMetaType::QVariantList))
        return invalidArgs(QStringLiteral("Option \"answers\" must be an array of byte arrays"));
    const QVariantList items = value.toList();
    if (items.size() > Limits::MaxAnswers)
        return invalidArgs(QStringLiteral("Too many answers"));
    for (const QVariant &item : items) {
        if (!isType(item, QMetaType::QByteArray) || item.toByteArray().size() > Limits::MaxShortString * 4)
            return invalidArgs(QStringLiteral("Invalid answer"));
        call->answer.answers << item.toByteArray();
    }
    return Result::success();
}

// Number of complete types in a valid signature ("saya{sv}" -> 3).
int completeTypeCount(const char *signature)
{
    int count = 0;
    int depth = 0;
    for (const char *p = signature; *p; ++p) {
        const char c = *p;
        if (c == '(' || c == '{')
            ++depth;
        else if (c == ')' || c == '}')
            --depth;
        if (depth == 0 && c != 'a')
            ++count;
    }
    return count;
}

// --------------------------------------------------------- per-method rules

using Validator = std::function<Result(const QVariantList &args, Call *call)>;

Result vNone(const QVariantList &, Call *)
{
    return Result::success();
}

Result vHello(const QVariantList &args, Call *call)
{
    if (const Result r = getUInt(args, 0, &call->number); !r.ok())
        return r;
    if (call->number == 0)
        return invalidArgs(QStringLiteral("Protocol version 0 does not exist"));
    return getString(args, 1, Limits::MaxShortString, &call->text);
}

Result vLoc(const QVariantList &args, Call *call)
{
    return getLoc(args, 0, &call->loc);
}

Result vLocPath(const QVariantList &args, Call *call)
{
    if (const Result r = getLoc(args, 0, &call->loc); !r.ok())
        return r;
    return getPath(args, 1, &call->path);
}

Result vLocPathPath(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPath(args, call); !r.ok())
        return r;
    return getPath(args, 2, &call->path2);
}

Result vConnectAdHoc(const QVariantList &args, Call *call)
{
    if (const Result r = getString(args, 0, Limits::MaxUrlLength, &call->text); !r.ok())
        return r;
    if (!isType(args.at(1), QMetaType::QByteArray))
        return invalidArgs(QStringLiteral("Argument 2 must be a byte array"));
    // XB-16: Call::secret becomes the only holder (validateCall clears the argument).
    call->secret = args.at(1).toByteArray();
    if (call->secret.size() > Limits::MaxSecretBytes)
        return invalidArgs(QStringLiteral("Secret too long"));
    return forEachOption(args, 2, call, adHocOption);
}

Result vDiscover(const QVariantList &args, Call *call)
{
    return getBool(args, 0, &call->flag);
}

Result vList(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPath(args, call); !r.ok())
        return r;
    if (const Result r = validateLane(args.at(2), Lane::Interactive, &call->lane); !r.ok())
        return r;
    if (const Result r = getUInt(args, 3, &call->number); !r.ok())
        return r;
    if (call->number == 0)
        call->number = Limits::DefaultListBatch;
    if (call->number > static_cast<quint32>(Limits::MaxListBatch))
        return invalidArgs(QStringLiteral("Batch size above %1").arg(Limits::MaxListBatch));
    return Result::success();
}

Result vStat(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPath(args, call); !r.ok())
        return r;
    if (const Result r = getBool(args, 2, &call->flag); !r.ok())
        return r;
    return validateLane(args.at(3), Lane::Interactive, &call->lane);
}

Result vChecksum(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPath(args, call); !r.ok())
        return r;
    return getToken(args, 2, 32, &call->text);
}

Result vLocPathBool(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPath(args, call); !r.ok())
        return r;
    return getBool(args, 2, &call->flag);
}

Result vRename(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPathPath(args, call); !r.ok())
        return r;
    return getBool(args, 3, &call->flag);
}

Result vSetAttributes(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPath(args, call); !r.ok())
        return r;
    return forEachOption(args, 2, call, attributeOption);
}

// XC-12: the link target is stored verbatim (not normalised, may be
// relative); only its size and NUL bytes are checked.
Result vMakeSymlink(const QVariantList &args, Call *call)
{
    if (const Result r = getLoc(args, 0, &call->loc); !r.ok())
        return r;
    const QVariant &target = args.at(1);
    if (!isType(target, QMetaType::QByteArray))
        return invalidArgs(QStringLiteral("Argument 2 must be a byte array"));
    const QByteArray bytes = target.toByteArray();
    if (bytes.isEmpty() || bytes.size() > Limits::MaxPathBytes || bytes.contains('\0'))
        return Result(Error::InvalidName, QStringLiteral("Invalid link target"));
    call->linkTarget = Names::decode(bytes);
    return getPath(args, 2, &call->path2);
}

Result vServerCopy(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPathPath(args, call); !r.ok())
        return r;
    return forEachOption(args, 3, call, copyOption);
}

Result vOpenRead(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPath(args, call); !r.ok())
        return r;
    return validateLane(args.at(2), Lane::Stream, &call->lane);
}

Result vRead(const QVariantList &args, Call *call)
{
    if (const Result r = getUInt(args, 0, &call->number); !r.ok())
        return r;
    if (const Result r = getOffset(args, 1, &call->offset); !r.ok())
        return r;
    quint32 max = 0;
    if (const Result r = getUInt(args, 2, &max); !r.ok())
        return r;
    if (max > Limits::MaxReadBytes)
        return invalidArgs(QStringLiteral("Read size above 1 MiB"));
    call->length = max;
    return Result::success();
}

Result vReadAhead(const QVariantList &args, Call *call)
{
    if (const Result r = getUInt(args, 0, &call->number); !r.ok())
        return r;
    if (const Result r = getOffset(args, 1, &call->offset); !r.ok())
        return r;
    if (const Result r = getOffset(args, 2, &call->length); !r.ok())
        return r;
    call->length = std::min(call->length, Limits::MaxReadAheadBytes);   // a hint: capped, not refused
    return Result::success();
}

Result vId(const QVariantList &args, Call *call)
{
    return getUInt(args, 0, &call->number);
}

template <typename OptionHandler>
Result vTransfer(const QVariantList &args, Call *call, const OptionHandler &handler)
{
    if (const Result r = vLocPath(args, call); !r.ok())
        return r;
    if (!isType(args.at(2), qMetaTypeId<UnixFd>()))
        return invalidArgs(QStringLiteral("Argument 3 must be a file descriptor"));
    call->fd = args.at(2).value<UnixFd>();
    call->lane = Lane::Bulk;
    if (const Result r = forEachOption(args, 3, call, handler); !r.ok())
        return r;
    if (const TransferOptions &t = call->transfer; t.disposition == WriteOptions::Resume && t.offset == 0)
        return invalidArgs(QStringLiteral("Resume needs an offset"));
    return Result::success();
}

Result vUpload(const QVariantList &args, Call *call)
{
    return vTransfer(args, call, uploadOption);
}

Result vDownload(const QVariantList &args, Call *call)
{
    return vTransfer(args, call, downloadOption);
}

Result vCopyAcross(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPath(args, call); !r.ok())
        return r;
    if (const Result r = getLoc(args, 2, &call->loc2); !r.ok())
        return r;
    if (const Result r = getPath(args, 3, &call->path2); !r.ok())
        return r;
    call->lane = Lane::Bulk;
    return forEachOption(args, 4, call, copyOption);
}

Result vRemoveTree(const QVariantList &args, Call *call)
{
    call->lane = Lane::Bulk;
    return vLocPath(args, call);
}

Result vWalk(const QVariantList &args, Call *call)
{
    if (const Result r = vLocPath(args, call); !r.ok())
        return r;
    call->lane = Lane::Bulk;
    return forEachOption(args, 2, call, walkOption);
}

Result vAnswer(const QVariantList &args, Call *call)
{
    if (const Result r = getString(args, 0, Limits::MaxIdLength, &call->text); !r.ok())
        return r;
    if (!isValidLocationId(call->text))
        return invalidArgs(QStringLiteral("Invalid question id"));
    // Keyboard-interactive answers are secrets (validateCall clears the argument).
    return forEachOption(args, 1, call, answerOption);
}

Result vProvider(const QVariantList &args, Call *call)
{
    return getToken(args, 0, 32, &call->text);
}

// XB-16: the secrets of ConnectAdHoc (the secret) and Answer (the options with
// the answers) live in the Call only, whatever the outcome of the validation.
void dropSecretArguments(Method method, QVariantList *args)
{
    if (method == Method::ConnectAdHoc || method == Method::Answer)
        (*args)[1] = QVariant();
}

struct Rule {
    MethodInfo info;
    Validator validator;
};

const QVector<Rule> &rules()
{
    static const QVector<Rule> table = {
        { { Method::Hello, "Hello", "us", "usas", Lane::Interactive, false }, vHello },
        { { Method::GetConsent, "GetConsent", "", "s", Lane::Interactive, false }, vNone },
        { { Method::RequestConsent, "RequestConsent", "", "", Lane::Interactive, false }, vNone },
        { { Method::ListLocations, "ListLocations", "", "a(sssa{sv})", Lane::Interactive, false }, vNone },
        { { Method::Capabilities, "Capabilities", "s", "(asasx)", Lane::Interactive, true }, vLoc },
        { { Method::Disconnect, "Disconnect", "s", "", Lane::Interactive, true }, vLoc },
        { { Method::ConnectAdHoc, "ConnectAdHoc", "saya{sv}", "s", Lane::Interactive, true }, vConnectAdHoc },
        { { Method::ForgetAdHoc, "ForgetAdHoc", "s", "", Lane::Interactive, true }, vLoc },
        { { Method::Discover, "Discover", "b", "", Lane::Interactive, true }, vDiscover },
        { { Method::List, "List", "saysu", "u", Lane::Interactive, true }, vList },
        { { Method::Stat, "Stat", "saybs", EntrySig, Lane::Interactive, true }, vStat },
        { { Method::ReadLink, "ReadLink", "say", "ay", Lane::Interactive, true }, vLocPath },
        { { Method::SpaceInfo, "SpaceInfo", "say", "xxx", Lane::Interactive, true }, vLocPath },
        { { Method::Checksum, "Checksum", "says", "ay", Lane::Bulk, true }, vChecksum },
        { { Method::MakeDir, "MakeDir", "sayb", "", Lane::Interactive, true }, vLocPathBool },
        { { Method::RemoveFile, "RemoveFile", "say", "", Lane::Interactive, true }, vLocPath },
        { { Method::RemoveDir, "RemoveDir", "say", "", Lane::Interactive, true }, vLocPath },
        { { Method::Rename, "Rename", "sayayb", "", Lane::Interactive, true }, vRename },
        { { Method::SetAttributes, "SetAttributes", "saya{sv}", "", Lane::Interactive, true }, vSetAttributes },
        { { Method::MakeSymlink, "MakeSymlink", "sayay", "", Lane::Interactive, true }, vMakeSymlink },
        { { Method::MakeHardlink, "MakeHardlink", "sayay", "", Lane::Interactive, true }, vLocPathPath },
        { { Method::ServerCopy, "ServerCopy", "sayaya{sv}", "", Lane::Bulk, true }, vServerCopy },
        { { Method::OpenRead, "OpenRead", "says", "ux", Lane::Stream, true }, vOpenRead },
        { { Method::Read, "Read", "uxu", "ay", Lane::Stream, true }, vRead },
        { { Method::ReadAhead, "ReadAhead", "uxx", "", Lane::Stream, true }, vReadAhead },
        { { Method::Close, "Close", "u", "", Lane::Stream, true }, vId },
        { { Method::Upload, "Upload", "sayha{sv}", "u", Lane::Bulk, true }, vUpload },
        { { Method::Download, "Download", "sayha{sv}", "u", Lane::Bulk, true }, vDownload },
        { { Method::CopyAcross, "CopyAcross", "saysaya{sv}", "u", Lane::Bulk, true }, vCopyAcross },
        { { Method::RemoveTree, "RemoveTree", "say", "u", Lane::Bulk, true }, vRemoveTree },
        { { Method::Walk, "Walk", "saya{sv}", "u", Lane::Bulk, true }, vWalk },
        { { Method::Cancel, "Cancel", "u", "", Lane::Interactive, false }, vId },
        { { Method::Answer, "Answer", "sa{sv}", "", Lane::Interactive, false }, vAnswer },
        { { Method::OpenAccountSettings, "OpenAccountSettings", "s", "", Lane::Interactive, true }, vLoc },
        { { Method::AddAccount, "AddAccount", "s", "", Lane::Interactive, true }, vProvider },
    };
    return table;
}

} // namespace

QString laneName(Lane lane)
{
    switch (lane) {
    case Lane::Bulk:
        return QStringLiteral("bulk");
    case Lane::Stream:
        return QStringLiteral("stream");
    case Lane::Interactive:
        break;
    }
    return QStringLiteral("interactive");
}

const QVector<MethodInfo> &methods()
{
    static const QVector<MethodInfo> list = []() {
        QVector<MethodInfo> result;
        for (const Rule &rule : rules())
            result << rule.info;
        return result;
    }();
    return list;
}

const MethodInfo *findMethod(const QString &name)
{
    const QVector<MethodInfo> &all = methods();
    const auto it = std::find_if(all.cbegin(), all.cend(),
                                 [&name](const MethodInfo &m) { return name == QLatin1String(m.name); });
    return it == all.cend() ? nullptr : it;
}

void wipeSecrets(Call *call)
{
    secureWipe(call->secret);
    for (QByteArray &answer : call->answer.answers)
        secureWipe(answer);
    call->answer.answers.clear();
}

bool isValidToken(const QString &value, int maxLength)
{
    if (value.isEmpty() || value.size() > maxLength)
        return false;
    return std::all_of(value.cbegin(), value.cend(), [](QChar c) {
        const ushort u = c.unicode();
        return (u >= 'a' && u <= 'z') || (u >= '0' && u <= '9') || u == '-';
    });
}

// "account:12", "adhoc:3", question ids "q7".
bool isValidLocationId(const QString &id)
{
    if (id.isEmpty() || id.size() > Limits::MaxIdLength)
        return false;
    return std::all_of(id.cbegin(), id.cend(), [](QChar c) {
        const ushort u = c.unicode();
        return (u >= 'a' && u <= 'z') || (u >= '0' && u <= '9') || u == '-' || u == ':';
    });
}

Result validatePath(const QVariant &bytes, QString *out)
{
    if (!isType(bytes, QMetaType::QByteArray))
        return invalidArgs(QStringLiteral("A path must be a byte array"));
    const QByteArray raw = bytes.toByteArray();
    if (raw.size() > Limits::MaxPathBytes)
        return Result(Error::InvalidName, QStringLiteral("Path too long"));
    if (raw.contains('\0'))
        return Result(Error::InvalidName, QStringLiteral("Path contains NUL"));
    return Paths::normalize(Names::decode(raw), out);
}

Result validateLocationId(const QVariant &value, QString *out)
{
    if (!isType(value, QMetaType::QString) || !isValidLocationId(value.toString()))
        return invalidArgs(QStringLiteral("Invalid location id"));
    *out = value.toString();
    return Result::success();
}

Result validateLane(const QVariant &value, Lane fallback, Lane *out)
{
    if (!isType(value, QMetaType::QString))
        return invalidArgs(QStringLiteral("A lane must be a string"));
    if (const QString s = value.toString(); s.isEmpty())
        *out = fallback;
    else if (s == QLatin1String("interactive"))
        *out = Lane::Interactive;
    else if (s == QLatin1String("bulk"))
        *out = Lane::Bulk;
    else if (s == QLatin1String("stream"))
        *out = Lane::Stream;
    else
        return invalidArgs(QStringLiteral("Unknown lane"));
    return Result::success();
}

Result validateCall(const QString &member, const QString &signature, QVariantList *args, Call *out)
{
    const QVector<Rule> &table = rules();
    const auto it = std::find_if(table.cbegin(), table.cend(),
                                 [&member](const Rule &r) { return member == QLatin1String(r.info.name); });
    if (it == table.cend())
        return Result(Error::Unsupported, QStringLiteral("No such method"));
    if (signature != QLatin1String(it->info.in))
        return invalidArgs(QStringLiteral("%1 takes (%2)").arg(member, QLatin1String(it->info.in)));
    if (args->size() != completeTypeCount(it->info.in))
        return invalidArgs(QStringLiteral("Wrong number of arguments"));
    Call call;
    call.method = it->info.method;
    call.lane = it->info.lane;
    const Result r = it->validator(*args, &call);
    dropSecretArguments(call.method, args);
    *out = call;
    return r;
}

} // namespace NetVfs::Bridge
