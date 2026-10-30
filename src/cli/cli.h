// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CLI_H
#define NETVFS_CLI_H

#include <QtCore/QStringList>

class QIODevice;
class QTextStream;

// Location: --url (sftp://, ssh://, smb://host[/share[/path]], file://; a password is rejected with
// SecurityPolicy) or --provider/--host/--port/--user (local needs no host); not mixed. --option,
// --host-key, --profile apply to both and win over the URL. A relative path argument resolves
// against the URL's path.
// Secrets never come from the command line: from the variable named by --secret-env (default
// NETVFS_SECRET) or typed on the terminal for a server prompt (--prompt, echo off).
// Commands run only with a pinned identity (--host-key PIN or --option host_key=PIN; `identify`
// prints it); otherwise ServerIdentityUnknown before any credential is sent.
// Exit codes: 0 success, 2 usage error (usage on stderr), 10 + NetVfs::Error for failures (error
// name on stderr). `--help` prints usage to stdout, exits 0.
namespace NetVfs::Cli {

// `promptInput` (tests) replaces the terminal for --prompt answers.
int run(const QStringList &arguments, QTextStream &out, QTextStream &err, QIODevice *promptInput = nullptr);

}
#endif
