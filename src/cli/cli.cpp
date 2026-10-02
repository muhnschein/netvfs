// SPDX-License-Identifier: LGPL-2.1-or-later
#include "cli.h"

#include "backendloader.h"
#include "identity.h"
#include "paths.h"
#include "probe.h"
#include "secure.h"
#include "transfer.h"

#include <QtCore/QFile>
#include <QtCore/QScopedPointer>
#include <QtCore/QTextStream>

#include <array>

namespace NetVfs::Cli {

namespace {

const int ExitUsage = 2;
const int ExitErrorBase = 10;

const char Usage[] =
    "usage: netvfs-cli --provider P --host H [--port N] [--user U]\n"
    "                  [--option KEY=VALUE]... [--secret-env VAR] COMMAND [ARGS]\n"
    "\n"
    "The secret is read from the environment variable named by --secret-env\n"
    "(default NETVFS_SECRET). Options are provider keys, for example\n"
    "host_key, auth_mode, share, domain, require_encryption.\n"
    "\n"
    "commands:\n"
    "  identify              connect without credentials, print the server identity\n"
    "  verify DIR            sign in, create DIR, write and delete a probe file\n"
    "  ls DIR                list a directory\n"
    "  stat PATH             print size, type and modification time\n"
    "  put LOCAL REMOTE      upload via REMOTE.part, then rename\n"
    "  get REMOTE LOCAL      download via LOCAL.part, then rename\n"
    "  mkdir DIR             create DIR and its parents\n"
    "  rm PATH               remove a file\n"
    "  mv FROM TO            rename, replacing TO\n"
    "  df DIR                print free bytes\n";

struct Options {
    ConnectionParams params;
    QString secretEnv = QStringLiteral("NETVFS_SECRET");
    QString command;
    QStringList args;
};

bool parse(const QStringList &arguments, Options *options, QString *error)
{
    int i = 0;
    auto value = [&](const QString &name, QString *out) {
        if (i + 1 >= arguments.size()) {
            *error = name + QStringLiteral(" needs a value");
            return false;
        }
        *out = arguments.at(++i);
        return true;
    };

    for (; i < arguments.size(); ++i) {
        const QString arg = arguments.at(i);
        QString v;
        if (!arg.startsWith(QLatin1String("--"))) {
            options->command = arg;
            options->args = arguments.mid(i + 1);
            break;
        }
        if (!value(arg, &v))
            return false;
        if (arg == QLatin1String("--provider")) {
            options->params.provider = v;
        } else if (arg == QLatin1String("--host")) {
            options->params.host = v;
        } else if (arg == QLatin1String("--port")) {
            bool ok = false;
            options->params.port = v.toInt(&ok);
            if (!ok) {
                *error = QStringLiteral("invalid port");
                return false;
            }
        } else if (arg == QLatin1String("--user")) {
            options->params.username = v;
        } else if (arg == QLatin1String("--option")) {
            const int eq = v.indexOf(QLatin1Char('='));
            if (eq <= 0) {
                *error = QStringLiteral("--option needs KEY=VALUE");
                return false;
            }
            options->params.options.insert(v.left(eq), v.mid(eq + 1));
        } else if (arg == QLatin1String("--secret-env")) {
            options->secretEnv = v;
        } else {
            *error = QStringLiteral("unknown option ") + arg;
            return false;
        }
    }
    if (options->params.provider.isEmpty() || options->params.host.isEmpty() || options->command.isEmpty()) {
        *error = QStringLiteral("--provider, --host and a command are required");
        return false;
    }
    return true;
}

int expectedArgs(const QString &command)
{
    struct Command {
        const char *name;
        int args;
    };
    static const std::array<Command, 10> table = { {
        { "identify", 0 }, { "verify", 1 }, { "ls", 1 }, { "stat", 1 }, { "put", 2 },
        { "get", 2 }, { "mkdir", 1 }, { "rm", 1 }, { "mv", 2 }, { "df", 1 },
    } };
    for (const auto &entry : table) {
        if (command == QLatin1String(entry.name))
            return entry.args;
    }
    return -1;
}

int fail(QTextStream &err, const Result &result)
{
    err << "error: " << result.toString() << '\n';
    err.flush();
    return ExitErrorBase + static_cast<int>(result.error());
}

Result runCommand(Backend *backend, const Options &options, QTextStream &out)
{
    const QStringList &a = options.args;
    const QString &command = options.command;
    if (command == QLatin1String("verify")) {
        qint64 freeBytes = -1;
        const Result r = verifyAccess(backend, a.at(0), &freeBytes);
        if (r.ok())
            out << "ok free=" << freeBytes << '\n';
        return r;
    }
    if (command == QLatin1String("ls")) {
        QVector<Entry> entries;
        const Result r = backend->list(a.at(0), &entries);
        for (const Entry &e : entries)
            out << (e.isDir ? 'd' : '-') << ' ' << e.size << ' ' << e.name << '\n';
        return r;
    }
    if (command == QLatin1String("stat")) {
        Entry e;
        const Result r = backend->stat(a.at(0), &e);
        if (r.ok())
            out << (e.isDir ? 'd' : '-') << ' ' << e.size << ' ' << e.modified.toUTC().toString(Qt::ISODate) << '\n';
        return r;
    }
    if (command == QLatin1String("put"))
        return Transfer::uploadFile(backend, a.at(0), a.at(1));
    if (command == QLatin1String("get"))
        return Transfer::downloadFile(backend, a.at(0), a.at(1));
    if (command == QLatin1String("mkdir"))
        return backend->makePath(a.at(0));
    if (command == QLatin1String("rm"))
        return backend->remove(a.at(0));
    if (command == QLatin1String("mv"))
        return backend->rename(a.at(0), a.at(1));
    // df
    qint64 bytes = -1;
    const Result r = backend->freeSpace(a.at(0), &bytes);
    if (r.ok())
        out << bytes << '\n';
    return r;
}

} // namespace

int run(const QStringList &arguments, QTextStream &out, QTextStream &err)
{
    Options options;
    if (QString error; !parse(arguments, &options, &error) || expectedArgs(options.command) != options.args.size()) {
        if (error.isEmpty())
            error = QStringLiteral("unknown command or wrong number of arguments");
        err << "netvfs-cli: " << error << "\n\n" << Usage;
        err.flush();
        return ExitUsage;
    }

    Result r;
    QScopedPointer<Backend> backend(BackendLoader::create(options.params.provider, &r));
    if (!backend)
        return fail(err, r);

    if (options.command == QLatin1String("identify")) {
        ServerIdentity seen;
        r = backend->connect(options.params, &seen);
        if (!r.ok())
            return fail(err, r);
        if (seen.isEmpty())
            out << "none\n";
        else
            out << seen.fingerprint << '\n' << seen.toPin() << '\n';
        backend->disconnect();
        out.flush();
        return 0;
    }

    QByteArray secret = qgetenv(options.secretEnv.toLocal8Bit().constData());
    const Credentials credentials(options.params.username, secret);
    secureWipe(secret);

    r = establish(backend.data(), options.params, credentials);
    if (r.ok())
        r = runCommand(backend.data(), options, out);
    backend->disconnect();
    out.flush();
    return r.ok() ? 0 : fail(err, r);
}

} // namespace NetVfs::Cli
