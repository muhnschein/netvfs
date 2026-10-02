// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CLI_CONTEXT_H
#define NETVFS_CLI_CONTEXT_H

#include "backend.h"

#include <QtCore/QHash>
#include <QtCore/QScopedPointer>
#include <QtCore/QSet>
#include <QtCore/QStringList>
#include <QtCore/QTextStream>
#include <QtCore/QVariantMap>

// Internal structures of netvfs-cli: the parsed command line and the command
// table (see cli.cpp for the exit codes, clicommands.cpp for the commands).
namespace NetVfs::Cli {

// One place a command works on: connection parameters, the folder a URL
// pointed at (relative arguments resolve against it) and where the secret
// comes from. The secret is only ever read from this environment variable.
struct Location {
    ConnectionParams params;
    QString basePath;
    QString secretEnv = QStringLiteral("NETVFS_SECRET");
};

struct Options {
    Location main;
    QString url;                    // --url, resolved by resolveLocation()
    QVariantMap overrides;          // --option, --host-key, --profile: applied after the URL
    bool explicitLocation = false;  // --provider/--host/--port/--user given
    bool prompt = false;            // --prompt
    bool help = false;              // --help
    QString command;
    QStringList args;
};

// Arguments after the command name.
struct CommandLine {
    QSet<QString> flags;                    // boolean flags, by long name
    QHash<QString, QStringList> values;     // flags with a value, by long name (repeatable)
    QStringList positional;                 // remote path arguments are already resolved

    bool has(const QString &flag) const { return flags.contains(flag); }
    QString value(const QString &key, const QString &fallback = QString()) const
    {
        const QStringList list = values.value(key);
        return list.isEmpty() ? fallback : list.last();
    }
};

// Opens connections for a location: loads the backend, runs the identity
// check and signs in (SEC-1, C-7), with the prompter of --prompt if any.
class Connector
{
public:
    explicit Connector(AuthPrompter *prompter) : m_prompter(prompter) {}
    Result establishOn(Backend *backend, const Location &location) const;
    Result open(const Location &location, QScopedPointer<Backend> *backend) const;

private:
    AuthPrompter *m_prompter;
};

struct Context {
    Backend *backend;
    const Options &options;
    const CommandLine &cmd;
    const Connector &connector;
    QTextStream &out;
    QTextStream &err;
};

using Handler = Result (*)(const Context &);
// Validates argument values before anything is connected; may adjust the
// options. Returns a usage message, empty if fine.
using Checker = QString (*)(const CommandLine &, Options *);

enum class Needs { Nothing, Backend, Session };

struct CommandSpec {
    const char *name;
    // Space separated: "r|recursive" (short and long boolean), "json" (long
    // boolean), "offset=" (long with a value, repeatable).
    const char *flags;
    // One letter per positional argument: 'r' a remote path (resolved against
    // the URL's folder), 'l' used as given.
    const char *kinds;
    Needs needs;
    Handler handler;
    Checker check;
};

const CommandSpec *findCommand(const QString &name);
QVector<const CommandSpec *> allCommands();
// Splits `args` into flags and positional arguments per the spec ("--" ends
// the flags); false with a message for a usage error.
bool parseCommandLine(const CommandSpec &spec, const QStringList &args, CommandLine *out, QString *error);
// Normalises `argument` below `basePath` (absolute arguments stay absolute).
Result resolvePath(const QString &basePath, const QString &argument, QString *out);
// Fills `location` from its URL (if any) and then applies `overrides`.
Result resolveLocation(Location *location, const QString &url, const QVariantMap &overrides);

} // namespace NetVfs::Cli

#endif
