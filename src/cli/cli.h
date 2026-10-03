// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CLI_H
#define NETVFS_CLI_H

#include <QtCore/QStringList>

class QIODevice;
class QTextStream;

// netvfs-cli (SPEC 12.2, SPEC-v2 XC-CLI).
//
//   netvfs-cli (--url URL | --provider P --host H [--port N] [--user U])
//              [--option KEY=VALUE]... [--host-key PIN] [--profile PROFILE]
//              [--secret-env VAR] [--prompt] COMMAND [FLAGS] [ARGS]
//
// Location: either --url (sftp://, ssh://, smb://host[/share[/path]], dav(s)://,
// http(s)://, ftp(s)://, file://; a user name is accepted, a password is
// rejected with SecurityPolicy) or --provider/--host/--port/--user (the local
// provider needs no host). The two forms cannot be mixed; --option, --host-key
// and --profile apply to both and win over what the URL implies. Paths below a
// URL's folder: a relative argument resolves against the URL's path.
//
// Secrets are never taken from the command line: the secret is read from the
// environment variable named by --secret-env (default NETVFS_SECRET), or
// typed on the terminal in answer to a server prompt (--prompt, echo off).
//
// Identity: `identify` connects without credentials and prints the identity:
// the fingerprint, the pin (SSH "algorithm base64key" or TLS "tls-spki-sha256
// base64spki") and, for TLS, the certificate details and tls_verify_peer
// advice. Commands run only when the identity is pinned with --host-key PIN
// (or --option host_key=PIN), or, for TLS, the certificate is trusted by the
// system; otherwise they fail with ServerIdentityUnknown before any
// credential is sent.
//
// Commands (flags follow the command name; "--" ends the flags):
//   identify                     print the server identity (no sign-in)
//   verify DIR                   sign in, create DIR, write and delete a probe file
//   ls [-l] [--json] DIR         list (sorted by name); -l: mode owner group size
//                                mtime(UTC) flags name; --json: array of entries
//   stat [--json] PATH           the same full entry, following symlinks
//   lstat [--json] PATH          the entry itself (no symlink following)
//   cat [--offset N] [--length N] PATH   write the bytes to stdout
//   put LOCAL REMOTE             upload via REMOTE.part, then rename (replaces)
//   get REMOTE LOCAL             download via LOCAL.part, then rename
//   mkdir [-p] [--exclusive] DIR create one folder; -p: with parents; --exclusive:
//                                an existing entry is an error
//   rm [-r] PATH                 remove a file or symlink; -r: a whole tree (symlinks
//                                are removed, never followed)
//   rmdir DIR                    remove an empty folder
//   mv [--replace] FROM TO       rename; refuses to replace TO unless --replace
//   cp [-r] [--replace] [--to-url URL [--to-secret-env VAR] [--to-host-key PIN]
//      [--to-option K=V]...] FROM TO
//                                server-side copy when the server reports ServerCopy
//                                (and ServerCopyRecursive for -r), else a streamed
//                                copy over a second connection, to the same location
//                                or to --to-url (TO is relative to that URL's path)
//   chmod MODE PATH              set the permission bits (octal)
//   touch [--mtime ISO8601] PATH set the modification time (default now; a time
//                                without zone is UTC); creates an empty file if missing
//   ln [-s] TARGET LINK          -s: symbolic link (TARGET verbatim), else hard link
//   readlink PATH                print a symlink's target
//   df [--all] DIR               free bytes; --all: free= total= used=
//   sum [--algo ALGO] PATH       checksum computed by the server (default sha256)
//   caps [--json]                capabilities, checksum algorithms, name length limit
//   shares [--json]              SMB: the shares of the server (lists the root of
//                                the location with an empty share)
//   discover [--seconds N]       browse mDNS for N seconds (default 3); one line per
//                                server: URL, name, service types, addresses
//
// `--prompt` answers keyboard-interactive questions from the controlling terminal.
//
// Exit codes: 0 success, 2 usage error (usage text on stderr), 10 + NetVfs::Error
// for failures (for example 14 = ServerIdentityUnknown, 15 = ServerIdentityChanged,
// 16 = AuthFailed; the error name goes to stderr). `--help` prints the usage
// text to stdout and exits 0.
namespace NetVfs::Cli {

// Runs one invocation; returns the process exit code. `promptInput` (tests)
// replaces the terminal for --prompt answers.
int run(const QStringList &arguments, QTextStream &out, QTextStream &err, QIODevice *promptInput = nullptr);

} // namespace NetVfs::Cli

#endif
