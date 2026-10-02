// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sftpshell.h"

#include <algorithm>

namespace NetVfs::Sftp {

namespace {

constexpr int Sha256HexLength = 64;
constexpr const char *ProbeMarker = "netvfs-probe";
// Every character a shell would otherwise interpret, so that the probe
// proves the quoting rules hold on this server.
constexpr const char *ProbeQuoted = "it's \"q\" $HOME \\ * `x` ;|&";

bool isHex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool belowOrAt(const QByteArray &path, const QByteArray &dir)
{
    if (path == dir)
        return true;
    const QByteArray prefix = dir.endsWith('/') ? dir : dir + '/';
    return path.size() > prefix.size() && path.startsWith(prefix);
}

} // namespace

QByteArray shellQuote(const QByteArray &word)
{
    QByteArray quoted;
    quoted.reserve(word.size() + 2);
    quoted += '\'';
    for (const char c : word) {
        if (c == '\'')
            quoted += "'\\''";
        else
            quoted += c;
    }
    quoted += '\'';
    return quoted;
}

QByteArray shellCommand(const QList<QByteArray> &argv)
{
    QByteArray command;
    for (const QByteArray &word : argv) {
        if (!command.isEmpty())
            command += ' ';
        command += shellQuote(word);
    }
    return command;
}

QByteArray probeCommand()
{
    return shellCommand({ "printf", "%s\\n", ProbeMarker, ProbeQuoted })
        + "; for t in cp sha256sum shasum find; do command -v \"$t\" >/dev/null 2>&1 && printf '%s\\n' \"$t\"; done; true";
}

bool parseProbe(const QByteArray &out, ShellTools *tools)
{
    const QList<QByteArray> lines = out.split('\n');
    if (lines.size() < 3 || lines.at(0) != ProbeMarker || lines.at(1) != ProbeQuoted || !lines.last().isEmpty())
        return false;
    ShellTools found;
    for (int i = 2; i < lines.size() - 1; ++i) {
        const QByteArray &line = lines.at(i);
        if (line == "cp")
            found.cp = true;
        else if (line == "sha256sum")
            found.sha256sum = true;
        else if (line == "shasum")
            found.shasum = true;
        else if (line == "find")
            found.find = true;
        else
            return false;
    }
    *tools = found;
    return true;
}

QList<QByteArray> sha256sumCommand(const QByteArray &path)
{
    return { "sha256sum", "--", path };
}

QList<QByteArray> shasumCommand(const QByteArray &path)
{
    return { "shasum", "-a", "256", "--", path };
}

bool parseSha256Output(const QByteArray &out, QByteArray *digest)
{
    // GNU coreutils and Perl's shasum mark escaped names with a leading '\'.
    const int start = out.startsWith('\\') ? 1 : 0;
    if (out.size() < start + Sha256HexLength + 1 || out.at(start + Sha256HexLength) != ' ')
        return false;
    const QByteArray hex = out.mid(start, Sha256HexLength);
    if (!std::all_of(hex.cbegin(), hex.cend(), isHex))
        return false;
    *digest = QByteArray::fromHex(hex);
    return true;
}

QList<QByteArray> copyCommand(const QByteArray &source, const QByteArray &target, bool recursive)
{
    return { "cp", recursive ? "-pR" : "-p", "--", source, target };
}

QList<QByteArray> findCommand(const QByteArray &dir, const QByteArray &namePattern)
{
    return { "find", dir, "-name", namePattern, "-print0" };
}

bool parseFindOutput(const QByteArray &out, const QByteArray &dir, bool truncated, int maxResults,
                     QList<QByteArray> *paths)
{
    QList<QByteArray> pieces = out.split('\0');
    // A complete output ends with NUL, so the last piece is empty.
    const QByteArray rest = pieces.takeLast();
    if (!rest.isEmpty() && !truncated)
        return false;
    QList<QByteArray> found;
    for (const QByteArray &piece : pieces) {
        if (found.size() >= maxResults)
            break;
        if (!belowOrAt(piece, dir))
            return false;
        found.append(piece);
    }
    *paths = found;
    return true;
}

} // namespace NetVfs::Sftp
