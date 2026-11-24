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

namespace NetVfs::Cli {
struct Location {
    ConnectionParams params;
    QString basePath;
    QString secretEnv = QStringLiteral("NETVFS_SECRET");
};

struct Options {
    Location main;
    QString url;
    QVariantMap overrides;
    bool explicitLocation = false;
    bool prompt = false;
    bool help = false;
    QString command;
    QStringList args;
};

struct CommandLine {
    QSet<QString> flags;
    QHash<QString, QStringList> values;
    QStringList positional;
    bool has(const QString &flag) const { return flags.contains(flag); }
    QString value(const QString &key, const QString &fallback = QString()) const
    {
        const QStringList list = values.value(key);
        return list.isEmpty() ? fallback : list.last();
    }
};

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
using Checker = QString (*)(const CommandLine &, const Options &);
using Adjuster = void (*)(Options *);

enum class Needs { Nothing, Backend, Session };

struct CommandSpec {
    const char *name;
    const char *flags;
    const char *kinds;
    Needs needs;
    Handler handler;
    Checker check;
    Adjuster adjust;
};

const CommandSpec *findCommand(const QString &name);
QVector<const CommandSpec *> allCommands();
bool parseCommandLine(const CommandSpec &spec, const QStringList &args, CommandLine *out, QString *error);
Result resolvePath(const QString &basePath, const QString &argument, QString *out);
Result resolveLocation(Location *location, const QString &url, const QVariantMap &overrides);

}
#endif
