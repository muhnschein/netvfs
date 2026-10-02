// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SFTPSHELL_H
#define NETVFS_SFTPSHELL_H

#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QStringList>

// SPEC-v2 XS-9: command lines for the exec channel and parsers for what the
// fixed helper commands print. Pure functions: the unit tests compile this
// file directly. Every parser is defensive (XSEC-3): output it does not
// fully understand is a parse failure, never a guess.
namespace NetVfs::Sftp {

// POSIX single-quote quoting of one word: 'it'\''s' for "it's". The result
// is one word for any POSIX shell, whatever bytes `word` holds (NUL aside,
// which no path contains).
QByteArray shellQuote(const QByteArray &word);
// The words quoted and joined with spaces.
QByteArray shellCommand(const QList<QByteArray> &argv);

// Sign-in probe: proves that the exec channel runs commands through a
// POSIX shell that honours our quoting, and lists the helper tools found.
struct ShellTools {
    bool cp = false;
    bool sha256sum = false;
    bool shasum = false;
    bool find = false;
};
QByteArray probeCommand();
// False unless `out` starts with exactly the two lines probeCommand()
// prints itself; tools are the remaining lines naming a known tool.
bool parseProbe(const QByteArray &out, ShellTools *tools);

// Checksums: "sha256sum -- PATH" and "shasum -a 256 -- PATH".
QList<QByteArray> sha256sumCommand(const QByteArray &path);
QList<QByteArray> shasumCommand(const QByteArray &path);
// The first line of either tool: an optional '\' (escaped name), 64 hex
// digits, a space. `digest` gets the 32 raw bytes.
bool parseSha256Output(const QByteArray &out, QByteArray *digest);

// Server copy: "cp -p -- SRC DST", "cp -pR -- SRC DST".
QList<QByteArray> copyCommand(const QByteArray &source, const QByteArray &target, bool recursive);

// serverFind: "find DIR -name PATTERN -print0"; DIR must be absolute so
// that it cannot be read as an option or expression.
QList<QByteArray> findCommand(const QByteArray &dir, const QByteArray &namePattern);
// NUL-terminated paths, each `dir` itself or below it. With `truncated`
// the unterminated last piece is dropped; without it, it is a parse
// failure. At most `maxResults` paths; false on anything unexpected.
bool parseFindOutput(const QByteArray &out, const QByteArray &dir, bool truncated, int maxResults,
                     QList<QByteArray> *paths);

} // namespace NetVfs::Sftp

#endif
