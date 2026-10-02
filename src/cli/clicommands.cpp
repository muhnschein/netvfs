// SPDX-License-Identifier: LGPL-2.1-or-later
#include "clicontext.h"

#include "cliformat.h"
#include "discovery.h"
#include "names.h"
#include "ops.h"
#include "paths.h"
#include "probe.h"
#include "transfer.h"
#include "url.h"

#include <QtCore/QBuffer>
#include <QtCore/QEventLoop>
#include <QtCore/QRegExp>
#include <QtCore/QTimer>

#include <algorithm>
#include <array>

namespace NetVfs::Cli {

namespace {

const int DefaultDiscoverSeconds = 3;
const int MaxDiscoverSeconds = 3600;
const int MillisPerSecond = 1000;
const int OctalBase = 8;
const char DefaultChecksum[] = "sha256";

// ------------------------------------------------------------ argument values

bool parseCount(const QString &text, qint64 *out)
{
    bool ok = false;
    const qint64 value = text.toLongLong(&ok);
    if (!ok || value < 0)
        return false;
    *out = value;
    return true;
}

bool parseMode(const QString &text, qint32 *out)
{
    static const QRegExp pattern(QStringLiteral("[0-7]{1,4}"));
    if (!pattern.exactMatch(text))
        return false;
    *out = text.toInt(nullptr, OctalBase);
    return true;
}

// ISO 8601; a time without zone is UTC (not the local zone).
bool parseTime(const QString &text, QDateTime *out)
{
    QDateTime time = QDateTime::fromString(text, Qt::ISODate);
    if (!time.isValid())
        return false;
    if (time.timeSpec() == Qt::LocalTime)
        time.setTimeSpec(Qt::UTC);
    *out = time.toUTC();
    return true;
}

QDateTime nowSeconds()
{
    return QDateTime::fromMSecsSinceEpoch(QDateTime::currentMSecsSinceEpoch() / MillisPerSecond * MillisPerSecond)
        .toUTC();
}

RenameMode modeOf(const CommandLine &cmd)
{
    return cmd.has(QStringLiteral("replace")) ? RenameMode::Replace : RenameMode::NoReplace;
}

// ------------------------------------------------------------------- output

// Raw bytes of `cat` onto the output stream: the underlying device when there
// is one (stdout), else, for a string-backed stream (tests), Latin-1 text.
class OutputSink : public QIODevice
{
public:
    explicit OutputSink(QTextStream &out) : m_out(out) { open(QIODevice::WriteOnly); }
    bool isSequential() const override { return true; }

protected:
    qint64 readData(char *, qint64) override { return -1; }
    qint64 writeData(const char *data, qint64 length) override
    {
        QIODevice *device = m_out.device();
        if (!device) {
            m_out << QString::fromLatin1(data, static_cast<int>(length));
            return length;
        }
        m_out.flush();
        qint64 done = 0;
        while (done < length) {
            const qint64 n = device->write(data + done, length - done);
            if (n <= 0)
                return -1;
            done += n;
        }
        return length;
    }

private:
    QTextStream &m_out;
};

// Entries sorted by name for stable output.
class Collector : public ListSink
{
public:
    bool entries(const QVector<Entry> &batch) override
    {
        m_entries += batch;
        return true;
    }
    QVector<Entry> sorted() const
    {
        QVector<Entry> result = m_entries;
        std::sort(result.begin(), result.end(), [](const Entry &a, const Entry &b) { return a.name < b.name; });
        return result;
    }

private:
    QVector<Entry> m_entries;
};

void printEntries(const Context &c, const QVector<Entry> &entries, bool longFormat)
{
    if (c.cmd.has(QStringLiteral("json"))) {
        QJsonArray array;
        for (const Entry &e : entries)
            array.append(entryJson(e));
        c.out << jsonText(array);
        return;
    }
    for (const Entry &e : entries)
        c.out << (longFormat ? longLine(e) : shortLine(e)) << '\n';
}

// ----------------------------------------------------------------- handlers

Result cmdIdentify(const Context &c)
{
    ServerIdentity seen;
    const Result r = c.backend->connect(c.options.main.params, &seen);
    if (!r.ok())
        return r;
    if (seen.isEmpty()) {
        c.out << "none\n";
        return r;
    }
    for (const QString &line : identityLines(seen))
        c.out << line << '\n';
    return r;
}

Result cmdVerify(const Context &c)
{
    qint64 freeBytes = -1;
    const Result r = verifyAccess(c.backend, c.cmd.positional.at(0), &freeBytes);
    if (r.ok())
        c.out << "ok free=" << freeBytes << '\n';
    return r;
}

Result cmdLs(const Context &c)
{
    Collector collector;
    const Result r = c.backend->list(c.cmd.positional.at(0), &collector, ListOptions());
    printEntries(c, collector.sorted(), c.cmd.has(QStringLiteral("long")));
    return r;
}

Result printStat(const Context &c, bool follow)
{
    const QString &path = c.cmd.positional.at(0);
    Entry entry;
    const Result r = follow ? c.backend->stat(path, &entry) : c.backend->lstat(path, &entry);
    if (!r.ok())
        return r;
    if (c.cmd.has(QStringLiteral("json")))
        c.out << jsonText(entryJson(entry, path));
    else
        c.out << longLine(entry, path) << '\n';
    return r;
}

Result cmdStat(const Context &c)
{
    return printStat(c, true);
}

Result cmdLstat(const Context &c)
{
    return printStat(c, false);
}

Result cmdPut(const Context &c)
{
    return Transfer::uploadFile(c.backend, c.cmd.positional.at(0), c.cmd.positional.at(1));
}

Result cmdGet(const Context &c)
{
    return Transfer::downloadFile(c.backend, c.cmd.positional.at(0), c.cmd.positional.at(1));
}

Result cmdCat(const Context &c)
{
    DownloadOptions options;
    qint64 value = 0;
    if (parseCount(c.cmd.value(QStringLiteral("offset")), &value))
        options.offset = value;
    if (parseCount(c.cmd.value(QStringLiteral("length")), &value))
        options.length = value;
    OutputSink sink(c.out);
    return c.backend->download(c.cmd.positional.at(0), &sink, options, nullptr);
}

Result cmdMkdir(const Context &c)
{
    const QString &path = c.cmd.positional.at(0);
    if (c.cmd.has(QStringLiteral("parents")))
        return c.backend->makePath(path);
    return c.backend->makeDir(path, c.cmd.has(QStringLiteral("exclusive")));
}

Result cmdRm(const Context &c)
{
    const QString &path = c.cmd.positional.at(0);
    if (c.cmd.has(QStringLiteral("recursive")))
        return Ops::removeTree(c.backend, path);
    return c.backend->removeFile(path);
}

Result cmdRmdir(const Context &c)
{
    return c.backend->removeDir(c.cmd.positional.at(0));
}

Result cmdMv(const Context &c)
{
    return c.backend->rename(c.cmd.positional.at(0), c.cmd.positional.at(1), modeOf(c.cmd));
}

// Another location for `cp --to-url`: the URL, then --to-option and
// --to-host-key on top; the secret variable defaults to the main one.
Result targetLocation(const Context &c, Location *target)
{
    QVariantMap overrides;
    for (const QString &pair : c.cmd.values.value(QStringLiteral("to-option"))) {
        const int eq = pair.indexOf(QLatin1Char('='));
        overrides.insert(pair.left(eq), pair.mid(eq + 1));
    }
    if (c.cmd.values.contains(QStringLiteral("to-host-key")))
        overrides.insert(QStringLiteral("host_key"), c.cmd.value(QStringLiteral("to-host-key")));
    target->secretEnv = c.cmd.value(QStringLiteral("to-secret-env"), c.options.main.secretEnv);
    return resolveLocation(target, c.cmd.value(QStringLiteral("to-url")), overrides);
}

Result cmdCp(const Context &c)
{
    const bool recursive = c.cmd.has(QStringLiteral("recursive"));
    const bool crossLocation = c.cmd.values.contains(QStringLiteral("to-url"));
    Location target = c.options.main;
    if (crossLocation) {
        target = Location();
        const Result located = targetLocation(c, &target);
        if (!located.ok())
            return located;
    }
    QString destination;
    const Result resolved = resolvePath(target.basePath, c.cmd.positional.at(1), &destination);
    if (!resolved.ok())
        return resolved;
    const QString &source = c.cmd.positional.at(0);

    if (!crossLocation) {
        // XC-17: a server-side copy when the server can do it.
        const Capabilities caps = c.backend->capabilities();
        if (caps.has(Capability::ServerCopy) && (!recursive || caps.has(Capability::ServerCopyRecursive))) {
            CopyOptions options;
            options.recursive = recursive;
            options.mode = modeOf(c.cmd);
            return c.backend->copy(source, destination, options);
        }
    }
    // XH-5: across two connections, a second one to the same location unless
    // --to-url names another.
    QScopedPointer<Backend> second;
    const Result opened = c.connector.open(target, &second);
    if (!opened.ok())
        return opened;
    Ops::CopyAcrossOptions options;
    options.recursive = recursive;
    options.mode = modeOf(c.cmd);
    const Result r = Ops::copyAcross(c.backend, source, second.data(), destination, options);
    second->disconnect();
    return r;
}

Result cmdChmod(const Context &c)
{
    qint32 mode = -1;
    parseMode(c.cmd.positional.at(0), &mode);
    AttributeChanges changes;
    changes.mode = mode;
    return c.backend->setAttributes(c.cmd.positional.at(1), changes);
}

Result createEmptyFile(const Context &c, const QString &path, const QDateTime &time)
{
    QBuffer empty;
    empty.open(QIODevice::ReadOnly);
    UploadOptions options;
    options.write.disposition = WriteOptions::CreateNew;
    options.write.modified = time;
    Result r = c.backend->upload(&empty, path, options, nullptr);
    if (r.ok() && c.backend->capabilities().has(Capability::SetModified)) {
        AttributeChanges changes;
        changes.modified = time;
        r = c.backend->setAttributes(path, changes);
    }
    return r;
}

Result cmdTouch(const Context &c)
{
    const QString &path = c.cmd.positional.at(0);
    QDateTime time = nowSeconds();
    if (c.cmd.values.contains(QStringLiteral("mtime")))
        parseTime(c.cmd.value(QStringLiteral("mtime")), &time);
    // A missing file is created empty, whatever the server can set on it.
    Entry existing;
    const Result found = c.backend->lstat(path, &existing);
    if (found.error() == Error::NotFound)
        return createEmptyFile(c, path, time);
    if (!found.ok())
        return found;
    AttributeChanges changes;
    changes.modified = time;
    return c.backend->setAttributes(path, changes);
}

Result cmdLn(const Context &c)
{
    if (c.cmd.has(QStringLiteral("symbolic")))
        return c.backend->makeSymlink(c.cmd.positional.at(0), c.cmd.positional.at(1));
    return c.backend->makeHardlink(c.cmd.positional.at(0), c.cmd.positional.at(1));
}

Result cmdReadlink(const Context &c)
{
    QString target;
    const Result r = c.backend->readLink(c.cmd.positional.at(0), &target);
    if (r.ok())
        c.out << sanitizeForTerminal(Names::display(target)) << '\n';
    return r;
}

QString sizeText(qint64 value)
{
    return value < 0 ? QStringLiteral("unknown") : QString::number(value);
}

Result cmdDf(const Context &c)
{
    const QString &path = c.cmd.positional.at(0);
    if (c.cmd.has(QStringLiteral("all"))) {
        SpaceInfo info;
        const Result r = c.backend->spaceInfo(path, &info);
        if (r.ok()) {
            c.out << "free=" << sizeText(info.free) << " total=" << sizeText(info.total)
                  << " used=" << sizeText(info.used) << '\n';
        }
        return r;
    }
    qint64 bytes = -1;
    const Result r = c.backend->freeSpace(path, &bytes);
    if (r.ok())
        c.out << bytes << '\n';
    return r;
}

Result cmdSum(const Context &c)
{
    const QString &path = c.cmd.positional.at(0);
    QByteArray digest;
    const Result r = c.backend->checksum(path, c.cmd.value(QStringLiteral("algo"), QLatin1String(DefaultChecksum)),
                                         &digest);
    if (r.ok())
        c.out << QString::fromLatin1(digest.toHex()) << "  " << sanitizeForTerminal(Names::display(path)) << '\n';
    return r;
}

Result cmdCaps(const Context &c)
{
    const Capabilities caps = c.backend->capabilities();
    if (c.cmd.has(QStringLiteral("json"))) {
        c.out << jsonText(capabilitiesJson(caps));
        return Result::success();
    }
    for (const QString &line : capabilitiesLines(caps))
        c.out << line << '\n';
    return Result::success();
}

// The shares of an SMB server: the folders at the root of a location without
// a share (SPEC-v2 XM-2, server mode).
Result cmdShares(const Context &c)
{
    Collector collector;
    const Result r = c.backend->list(QStringLiteral("/"), &collector, ListOptions());
    QVector<Entry> shares;
    for (const Entry &e : collector.sorted()) {
        if (e.isDir())
            shares.append(e);
    }
    if (c.cmd.has(QStringLiteral("json"))) {
        printEntries(c, shares, false);
        return r;
    }
    for (const Entry &e : shares)
        c.out << sanitizeForTerminal(Names::display(e.name)) << '\n';
    return r;
}

Result cmdDiscover(const Context &c)
{
    const int seconds = c.cmd.value(QStringLiteral("seconds"), QString::number(DefaultDiscoverSeconds)).toInt();
    Discovery discovery;
    const bool started = discovery.start();
    QEventLoop loop;
    QTimer::singleShot(seconds * MillisPerSecond, &loop, &QEventLoop::quit);
    loop.exec();
    const QVector<ServiceView> views = mergeServices(discovery.services());
    discovery.stop();
    if (!started && views.isEmpty())
        return Result(Error::NetworkUnreachable, QStringLiteral("Cannot open the mDNS sockets"));
    for (const ServiceView &view : views)
        c.out << serviceLine(view) << '\n';
    return Result::success();
}

// ----------------------------------------------------------------- checkers

QString checkMkdir(const CommandLine &cmd, Options *options)
{
    Q_UNUSED(options)
    if (cmd.has(QStringLiteral("parents")) && cmd.has(QStringLiteral("exclusive")))
        return QStringLiteral("mkdir: -p and --exclusive cannot be combined");
    return QString();
}

QString checkCat(const CommandLine &cmd, Options *options)
{
    Q_UNUSED(options)
    qint64 value = 0;
    for (const char *key : { "offset", "length" }) {
        if (cmd.values.contains(QLatin1String(key)) && !parseCount(cmd.value(QLatin1String(key)), &value))
            return QStringLiteral("cat: --%1 needs a non-negative number").arg(QLatin1String(key));
    }
    return QString();
}

QString checkChmod(const CommandLine &cmd, Options *options)
{
    Q_UNUSED(options)
    qint32 mode = 0;
    if (!parseMode(cmd.positional.at(0), &mode))
        return QStringLiteral("chmod: MODE must be octal permission bits (for example 644)");
    return QString();
}

QString checkTouch(const CommandLine &cmd, Options *options)
{
    Q_UNUSED(options)
    QDateTime time;
    if (cmd.values.contains(QStringLiteral("mtime")) && !parseTime(cmd.value(QStringLiteral("mtime")), &time))
        return QStringLiteral("touch: --mtime needs an ISO 8601 time such as 2024-05-17T12:30:00Z");
    return QString();
}

QString checkLn(const CommandLine &cmd, Options *options)
{
    Q_UNUSED(options)
    if (!cmd.has(QStringLiteral("symbolic")) && cmd.positional.at(1).isEmpty())
        return QStringLiteral("ln: the new name must not be empty");
    return QString();
}

QString checkCp(const CommandLine &cmd, Options *options)
{
    Q_UNUSED(options)
    if (!cmd.values.contains(QStringLiteral("to-url"))) {
        for (const char *key : { "to-secret-env", "to-host-key", "to-option" }) {
            if (cmd.values.contains(QLatin1String(key)))
                return QStringLiteral("cp: --%1 needs --to-url").arg(QLatin1String(key));
        }
    }
    for (const QString &pair : cmd.values.value(QStringLiteral("to-option"))) {
        if (pair.indexOf(QLatin1Char('=')) <= 0)
            return QStringLiteral("cp: --to-option needs KEY=VALUE");
    }
    return QString();
}

QString checkSum(const CommandLine &cmd, Options *options)
{
    Q_UNUSED(options)
    if (cmd.values.contains(QStringLiteral("algo")) && cmd.value(QStringLiteral("algo")).isEmpty())
        return QStringLiteral("sum: --algo needs an algorithm name");
    return QString();
}

QString checkShares(const CommandLine &cmd, Options *options)
{
    Q_UNUSED(cmd)
    if (options->main.params.provider != QLatin1String("smb") && options->url.isEmpty())
        return QStringLiteral("shares: only SMB locations have shares (--provider smb)");
    // The root of a location without a share lists the shares (XM-2).
    options->overrides.insert(QStringLiteral("share"), QString());
    return QString();
}

QString checkDiscover(const CommandLine &cmd, Options *options)
{
    Q_UNUSED(options)
    if (!cmd.values.contains(QStringLiteral("seconds")))
        return QString();
    bool ok = false;
    const int seconds = cmd.value(QStringLiteral("seconds")).toInt(&ok);
    if (!ok || seconds < 0 || seconds > MaxDiscoverSeconds)
        return QStringLiteral("discover: --seconds needs a number from 0 to %1").arg(MaxDiscoverSeconds);
    return QString();
}

const std::array<CommandSpec, 22> &table()
{
    static const std::array<CommandSpec, 22> commands = { {
        { "identify", "", "", Needs::Backend, cmdIdentify, nullptr },
        { "verify", "", "r", Needs::Session, cmdVerify, nullptr },
        { "ls", "l|long json", "r", Needs::Session, cmdLs, nullptr },
        { "stat", "json", "r", Needs::Session, cmdStat, nullptr },
        { "lstat", "json", "r", Needs::Session, cmdLstat, nullptr },
        { "put", "", "lr", Needs::Session, cmdPut, nullptr },
        { "get", "", "rl", Needs::Session, cmdGet, nullptr },
        { "cat", "offset= length=", "r", Needs::Session, cmdCat, checkCat },
        { "mkdir", "p|parents exclusive", "r", Needs::Session, cmdMkdir, checkMkdir },
        { "rm", "r|recursive", "r", Needs::Session, cmdRm, nullptr },
        { "rmdir", "", "r", Needs::Session, cmdRmdir, nullptr },
        { "mv", "replace", "rr", Needs::Session, cmdMv, nullptr },
        { "cp", "r|recursive replace to-url= to-secret-env= to-host-key= to-option=", "rl", Needs::Session, cmdCp,
          checkCp },
        { "chmod", "", "lr", Needs::Session, cmdChmod, checkChmod },
        { "touch", "mtime=", "r", Needs::Session, cmdTouch, checkTouch },
        { "ln", "s|symbolic", "lr", Needs::Session, cmdLn, checkLn },
        { "readlink", "", "r", Needs::Session, cmdReadlink, nullptr },
        { "df", "all", "r", Needs::Session, cmdDf, nullptr },
        { "sum", "algo=", "r", Needs::Session, cmdSum, checkSum },
        { "caps", "json", "", Needs::Session, cmdCaps, nullptr },
        { "shares", "json", "", Needs::Session, cmdShares, checkShares },
        { "discover", "seconds=", "", Needs::Nothing, cmdDiscover, checkDiscover },
    } };
    return commands;
}

// ------------------------------------------------------------- flag parsing

struct FlagSpec {
    QString longName;
    QChar shortName;
    bool takesValue = false;
};

QVector<FlagSpec> flagsOf(const CommandSpec &spec)
{
    QVector<FlagSpec> flags;
    const QStringList tokens = QString::fromLatin1(spec.flags).split(QLatin1Char(' '), NETVFS_SKIP_EMPTY_PARTS);
    for (QString token : tokens) {
        FlagSpec flag;
        if (token.endsWith(QLatin1Char('='))) {
            flag.takesValue = true;
            token.chop(1);
        }
        const int bar = token.indexOf(QLatin1Char('|'));
        if (bar > 0) {
            flag.shortName = token.at(0);
            token = token.mid(bar + 1);
        }
        flag.longName = token;
        flags.append(flag);
    }
    return flags;
}

const FlagSpec *findLong(const QVector<FlagSpec> &flags, const QString &name)
{
    for (const FlagSpec &flag : flags) {
        if (flag.longName == name)
            return &flag;
    }
    return nullptr;
}

const FlagSpec *findShort(const QVector<FlagSpec> &flags, QChar name)
{
    for (const FlagSpec &flag : flags) {
        if (!flag.shortName.isNull() && flag.shortName == name)
            return &flag;
    }
    return nullptr;
}

// Takes the flag at args[index]; `*consumed` is the number of arguments it used
// (the flag, and its value when it has one).
bool takeFlag(const QVector<FlagSpec> &flags, const QStringList &args, int index, int *consumed, CommandLine *out,
              QString *error)
{
    const QString arg = args.at(index);
    QVector<const FlagSpec *> found;
    if (arg.startsWith(QLatin1String("--"))) {
        found.append(findLong(flags, arg.mid(2)));
    } else {
        for (int k = 1; k < arg.size(); ++k)
            found.append(findShort(flags, arg.at(k)));
    }
    *consumed = 1;
    for (const FlagSpec *flag : found) {
        if (!flag) {
            *error = QStringLiteral("unknown option ") + arg;
            return false;
        }
        if (!flag->takesValue) {
            out->flags.insert(flag->longName);
            continue;
        }
        if (index + *consumed >= args.size()) {
            *error = arg + QStringLiteral(" needs a value");
            return false;
        }
        out->values[flag->longName].append(args.at(index + *consumed));
        ++*consumed;
    }
    return true;
}

bool isFlag(const QString &arg)
{
    return arg.size() > 1 && arg.startsWith(QLatin1Char('-'));
}

} // namespace

const CommandSpec *findCommand(const QString &name)
{
    for (const CommandSpec &spec : table()) {
        if (name == QLatin1String(spec.name))
            return &spec;
    }
    return nullptr;
}

QVector<const CommandSpec *> allCommands()
{
    QVector<const CommandSpec *> all;
    for (const CommandSpec &spec : table())
        all.append(&spec);
    return all;
}

bool parseCommandLine(const CommandSpec &spec, const QStringList &args, CommandLine *out, QString *error)
{
    const QVector<FlagSpec> flags = flagsOf(spec);
    bool flagsEnded = false;
    int next = 0;
    while (next < args.size()) {
        const QString &arg = args.at(next);
        int consumed = 1;
        if (!flagsEnded && arg == QLatin1String("--")) {
            flagsEnded = true;
        } else if (!flagsEnded && isFlag(arg)) {
            if (!takeFlag(flags, args, next, &consumed, out, error))
                return false;
        } else {
            out->positional.append(arg);
        }
        next += consumed;
    }
    if (out->positional.size() != static_cast<int>(qstrlen(spec.kinds))) {
        *error = QStringLiteral("%1: wrong number of arguments").arg(QLatin1String(spec.name));
        return false;
    }
    return true;
}

Result resolvePath(const QString &basePath, const QString &argument, QString *out)
{
    QString path = argument;
    if (!basePath.isEmpty() && !argument.startsWith(QLatin1Char('/')))
        path = Paths::join(basePath, argument);
    return Paths::normalize(path, out);
}

} // namespace NetVfs::Cli
