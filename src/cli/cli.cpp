// SPDX-License-Identifier: LGPL-2.1-or-later
// The command line, locations and connections of netvfs-cli; the commands are
// in clicommands.cpp and the output formats in cliformat.cpp. See cli.h for
// the full description and the exit codes.
#include "cli.h"

#include "backendloader.h"
#include "cliprompt.h"
#include "clicontext.h"
#include "identity.h"
#include "secure.h"
#include "url.h"

#include <QtCore/QIODevice>

namespace NetVfs::Cli {

namespace {

const int ExitUsage = 2;
const int ExitErrorBase = 10;
const int MaxPort = 65535;

const char Usage[] =
    "usage: netvfs-cli (--url URL | --provider P --host H [--port N] [--user U])\n"
    "                  [--option KEY=VALUE]... [--host-key PIN] [--profile PROFILE]\n"
    "                  [--secret-env VAR] [--prompt] COMMAND [FLAGS] [ARGS]\n"
    "       netvfs-cli discover [--seconds N]\n"
    "\n"
    "A location is a URL (sftp://, smb://host[/share[/path]], dav(s)://, http(s)://,\n"
    "ftp(s)://, file://; a user name is fine, a password is refused) or\n"
    "--provider/--host/--port/--user. Relative paths resolve against the URL's path.\n"
    "The secret is read from the environment variable named by --secret-env (default\n"
    "NETVFS_SECRET), never from the command line; --prompt answers server questions\n"
    "(keyboard-interactive) on the terminal. --option sets provider keys such as\n"
    "auth_mode, share, domain; --host-key PIN pins the server identity (SSH key or\n"
    "\"tls-spki-sha256 ...\"); --profile is the SMB security profile (strict, signed,\n"
    "legacy, guest).\n"
    "\n"
    "commands:\n"
    "  identify                     connect without credentials, print the server identity\n"
    "                               (fingerprint, pin; TLS: certificate details and advice)\n"
    "  verify DIR                   sign in, create DIR, write and delete a probe file\n"
    "  ls [-l] [--json] DIR         list; -l: mode owner group size mtime(UTC) flags name\n"
    "  stat [--json] PATH           the same full entry, following symlinks\n"
    "  lstat [--json] PATH          the entry itself\n"
    "  cat [--offset N] [--length N] PATH   write the file (or a range) to stdout\n"
    "  put LOCAL REMOTE             upload via REMOTE.part, then rename\n"
    "  get REMOTE LOCAL             download via LOCAL.part, then rename\n"
    "  mkdir [-p] [--exclusive] DIR create a folder (-p: with parents)\n"
    "  rm [-r] PATH                 remove a file or link (-r: a tree, links are not followed)\n"
    "  rmdir DIR                    remove an empty folder\n"
    "  mv [--replace] FROM TO       rename; an existing TO is an error unless --replace\n"
    "  cp [-r] [--replace] [--to-url URL [--to-secret-env VAR] [--to-host-key PIN]\n"
    "     [--to-option K=V]] FROM TO\n"
    "                               copy on the server if it can, else across two connections\n"
    "  chmod MODE PATH              set permission bits (octal)\n"
    "  touch [--mtime ISO8601] PATH set the modification time; creates an empty file\n"
    "  ln [-s] TARGET LINK          symbolic (-s) or hard link\n"
    "  readlink PATH                print a link's target\n"
    "  df [--all] DIR               free bytes (--all: free, total, used)\n"
    "  sum [--algo ALGO] PATH       checksum by the server (default sha256)\n"
    "  caps [--json]                capabilities, checksum algorithms, name length limit\n"
    "  shares [--json]              SMB: list the shares of the server\n"
    "  discover [--seconds N]       find servers with mDNS (default 3 seconds)\n"
    "\n"
    "exit codes: 0 success, 2 usage error, 10 + error number for failures\n"
    "(14 identity unknown, 15 identity changed, 16 authentication failed, ...).\n";

bool takesNoValue(const QString &arg)
{
    return arg == QLatin1String("--prompt") || arg == QLatin1String("--help") || arg == QLatin1String("-h");
}

bool validProfile(const QString &profile)
{
    return profile == QLatin1String("strict") || profile == QLatin1String("signed")
        || profile == QLatin1String("legacy") || profile == QLatin1String("guest");
}

// Options that give the location by parts.
bool applyLocationOption(const QString &arg, const QString &value, Options *options, QString *error)
{
    ConnectionParams &params = options->main.params;
    options->explicitLocation = true;
    if (arg == QLatin1String("--provider")) {
        params.provider = value;
    } else if (arg == QLatin1String("--host")) {
        params.host = value;
    } else if (arg == QLatin1String("--user")) {
        params.username = value;
    } else {
        bool ok = false;
        params.port = value.toInt(&ok);
        if (!ok || params.port < 1 || params.port > MaxPort) {
            *error = QStringLiteral("invalid port");
            return false;
        }
    }
    return true;
}

bool applyValueOption(const QString &arg, const QString &value, Options *options, QString *error)
{
    if (arg == QLatin1String("--option")) {
        const int eq = value.indexOf(QLatin1Char('='));
        if (eq <= 0) {
            *error = QStringLiteral("--option needs KEY=VALUE");
            return false;
        }
        options->overrides.insert(value.left(eq), value.mid(eq + 1));
    } else if (arg == QLatin1String("--host-key")) {
        // SSH and "tls-spki-sha256 ..." pins alike.
        if (ServerIdentity::fromPin(value).isEmpty()) {
            *error = QStringLiteral("--host-key needs a pin as printed by identify");
            return false;
        }
        options->overrides.insert(QStringLiteral("host_key"), value);
    } else if (arg == QLatin1String("--profile")) {
        if (!validProfile(value)) {
            *error = QStringLiteral("--profile must be strict, signed, legacy or guest");
            return false;
        }
        options->overrides.insert(QStringLiteral("security_profile"), value);
    } else if (arg == QLatin1String("--secret-env")) {
        options->main.secretEnv = value;
    } else if (arg == QLatin1String("--url")) {
        options->url = value;
    } else if (arg == QLatin1String("--provider") || arg == QLatin1String("--host")
               || arg == QLatin1String("--port") || arg == QLatin1String("--user")) {
        return applyLocationOption(arg, value, options, error);
    } else {
        *error = QStringLiteral("unknown option ") + arg;
        return false;
    }
    return true;
}

bool parse(const QStringList &arguments, Options *options, QString *error)
{
    for (int i = 0; i < arguments.size(); ++i) {
        const QString arg = arguments.at(i);
        if (!arg.startsWith(QLatin1Char('-'))) {
            options->command = arg;
            options->args = arguments.mid(i + 1);
            break;
        }
        if (takesNoValue(arg)) {
            options->prompt = options->prompt || arg == QLatin1String("--prompt");
            options->help = options->help || arg != QLatin1String("--prompt");
            continue;
        }
        if (i + 1 >= arguments.size()) {
            *error = arg + QStringLiteral(" needs a value");
            return false;
        }
        if (!applyValueOption(arg, arguments.at(++i), options, error))
            return false;
    }
    if (options->help)
        return true;
    if (options->command.isEmpty()) {
        *error = QStringLiteral("a command is required");
        return false;
    }
    if (!options->url.isEmpty() && options->explicitLocation) {
        *error = QStringLiteral("--url cannot be combined with --provider, --host, --port or --user");
        return false;
    }
    return true;
}

int fail(QTextStream &err, const Result &result)
{
    err << "error: " << result.toString() << '\n';
    if (result.error() == Error::ServerIdentityUnknown) {
        err << "hint: run `netvfs-cli ... identify`, check the fingerprint, then pass the pin with --host-key\n";
    }
    err.flush();
    return ExitErrorBase + static_cast<int>(result.error());
}

int usageError(QTextStream &err, const QString &message)
{
    err << "netvfs-cli: " << message << "\n\n" << Usage;
    err.flush();
    return ExitUsage;
}

bool locationGiven(const ConnectionParams &params)
{
    if (params.provider.isEmpty())
        return false;
    return !params.host.isEmpty() || params.provider == QLatin1String("local");
}

// Everything between the parsed command line and the handler.
struct Prepared {
    const CommandSpec *spec = nullptr;
    CommandLine cmd;
};

Result resolveRemotePaths(const Options &options, Prepared *prepared)
{
    const QByteArray kinds = prepared->spec->kinds;
    for (int i = 0; i < kinds.size(); ++i) {
        if (kinds.at(i) != 'r')
            continue;
        QString path;
        if (const Result r = resolvePath(options.main.basePath, prepared->cmd.positional.at(i), &path); !r.ok())
            return r;
        prepared->cmd.positional[i] = path;
    }
    return Result::success();
}

// Prompter of --prompt: the controlling terminal, or `input` (tests).
class PromptSetup
{
public:
    PromptSetup(bool wanted, QIODevice *input, QTextStream *prompts)
    {
        if (!wanted)
            return;
        if (input) {
            m_prompter.reset(new TerminalPrompter(input, prompts, nullptr));
        } else if (m_terminal.open()) {
            m_prompter.reset(new TerminalPrompter(m_terminal.device(), prompts, &m_terminal));
        } else {
            m_failed = true;
        }
    }
    AuthPrompter *prompter() const { return m_prompter.data(); }
    bool failed() const { return m_failed; }

private:
    Terminal m_terminal;
    QScopedPointer<TerminalPrompter> m_prompter;
    bool m_failed = false;
};

int runWithBackend(const Prepared &prepared, Options *options, const Connector &connector, QTextStream &out,
                   QTextStream &err)
{
    Result r;
    QScopedPointer<Backend> backend(BackendLoader::create(options->main.params.provider, &r));
    if (!backend)
        return fail(err, r);
    if (prepared.spec->needs == Needs::Session)
        r = connector.establishOn(backend.data(), options->main);
    if (r.ok()) {
        const Context context { backend.data(), *options, prepared.cmd, connector, out, err };
        r = prepared.spec->handler(context);
    }
    backend->disconnect();
    out.flush();
    return r.ok() ? 0 : fail(err, r);
}

} // namespace

Result Connector::establishOn(Backend *backend, const Location &location) const
{
    QByteArray secret = qgetenv(location.secretEnv.toLocal8Bit().constData());
    const Credentials credentials(location.params.username, secret);
    secureWipe(secret);
    return establish(backend, location.params, credentials, nullptr, m_prompter);
}

Result Connector::open(const Location &location, QScopedPointer<Backend> *backend) const
{
    Result r;
    backend->reset(BackendLoader::create(location.params.provider, &r));
    if (!*backend)
        return r;
    r = establishOn(backend->data(), location);
    if (!r.ok())
        backend->reset();
    return r;
}

Result resolveLocation(Location *location, const QString &url, const QVariantMap &overrides)
{
    if (!url.isEmpty()) {
        // XH-6: a password in the URL is rejected and never stored.
        QString path;
        if (const Result r = Url::parse(url, &location->params, &path); !r.ok())
            return r;
        location->basePath = path;
    }
    for (auto it = overrides.constBegin(); it != overrides.constEnd(); ++it)
        location->params.options.insert(it.key(), it.value());
    return Result::success();
}

int run(const QStringList &arguments, QTextStream &out, QTextStream &err, QIODevice *promptInput)
{
    Options options;
    QString error;
    if (!parse(arguments, &options, &error))
        return usageError(err, error);
    if (options.help) {
        out << Usage;
        out.flush();
        return 0;
    }
    Prepared prepared;
    prepared.spec = findCommand(options.command);
    if (!prepared.spec)
        return usageError(err, QStringLiteral("unknown command ") + options.command);
    if (!parseCommandLine(*prepared.spec, options.args, &prepared.cmd, &error))
        return usageError(err, error);
    if (prepared.spec->check) {
        error = prepared.spec->check(prepared.cmd, &options);
        if (!error.isEmpty())
            return usageError(err, error);
    }

    PromptSetup prompt(options.prompt, promptInput, &err);
    if (prompt.failed())
        return fail(err, Result(Error::AuthFailed, QStringLiteral("--prompt needs a terminal")));
    const Connector connector(prompt.prompter());
    const Context nothing { nullptr, options, prepared.cmd, connector, out, err };
    if (prepared.spec->needs == Needs::Nothing) {
        const Result r = prepared.spec->handler(nothing);
        out.flush();
        return r.ok() ? 0 : fail(err, r);
    }

    if (const Result r = resolveLocation(&options.main, options.url, options.overrides); !r.ok())
        return fail(err, r);
    if (!locationGiven(options.main.params))
        return usageError(err, QStringLiteral("--url, or --provider and --host, is required"));
    if (const Result r = resolveRemotePaths(options, &prepared); !r.ok())
        return fail(err, r);
    return runWithBackend(prepared, &options, connector, out, err);
}

} // namespace NetVfs::Cli
