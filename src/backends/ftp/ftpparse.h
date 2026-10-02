// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_FTPPARSE_H
#define NETVFS_FTPPARSE_H

#include "types.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QList>
#include <QtCore/QSet>
#include <QtCore/QVector>

// Parsers for FTP server output (SPEC-v2 F-2, F-3). Pure functions over
// bytes, without any I/O, so that the unit tests and the libFuzzer harness
// (XT-3) can drive them directly. Every parser is strict: input that does
// not match the expected shape is rejected, never guessed.
namespace NetVfs::Ftp {

// One complete server reply: the three digit code and its lines without
// CR LF (for a multi-line reply the first, the continuation and the last
// line).
struct Reply {
    int code = 0;
    QList<QByteArray> lines;

    bool isValid() const { return code > 0; }
    // The text of the first line after "ddd" and its separator.
    QByteArray text() const;
};

// Reassembles replies from the header callback, which libcurl calls with
// every line the server sends on the control connection (greeting, login
// replies, replies to quoted commands). Partial lines are buffered (at most
// MaxLineBytes; longer lines are cut there).
class ReplyReader
{
public:
    static constexpr int MaxLineBytes = 16 * 1024;
    static constexpr int MaxReplyLines = 4096;
    static constexpr int MaxReplies = 64;

    void feed(const char *data, size_t size);
    // The last complete reply; invalid if none arrived since reset().
    const Reply &last() const { return m_last; }
    // The complete replies since reset(), oldest first (the newest
    // MaxReplies).
    const QVector<Reply> &replies() const { return m_replies; }
    // Number of complete replies since reset().
    int count() const { return m_count; }
    void reset();

private:
    void line(const QByteArray &text);
    void completed();

    QByteArray m_partial;
    Reply m_current;
    bool m_inMulti = false;
    Reply m_last;
    QVector<Reply> m_replies;
    int m_count = 0;
};

// FEAT reply (RFC 2389): upper-cased feature names, and their parameters.
struct Features {
    QSet<QByteArray> names;          // "MLST", "UTF8", "MFMT", "REST", ...
    QByteArray restParameter;        // "STREAM" for "REST STREAM"
    QByteArray mlstFacts;            // "type*;size*;modify*;..."

    bool has(const char *name) const { return names.contains(QByteArray(name)); }
    bool restStream() const;
};
Features parseFeatures(const Reply &reply);

// 257 reply to PWD/MKD: the quoted path with "" as an escaped quote
// (RFC 959). False if the reply has no quoted path.
bool parsePathReply(const Reply &reply, QByteArray *path);
// 213 reply to SIZE. -1 if malformed.
qint64 parseSizeReply(const Reply &reply);
// "YYYYMMDDHHMMSS[.s+]" (RFC 3659 time-val, UTC). Invalid if malformed.
QDateTime parseTimeVal(const QByteArray &text);
// 213 reply to MDTM. Invalid if malformed.
QDateTime parseMdtmReply(const Reply &reply);
// "YYYYMMDDHHMMSS" for MFMT (UTC).
QByteArray formatTimeVal(const QDateTime &time);

// One MLSD line or the fact line of an MLST reply: "fact=value;...; name".
// The name is everything after the first space (RFC 3659 7.2). "cdir" and
// "pdir" entries yield Skip. MLST replies carry a full path as the name;
// the caller replaces entry->name.
enum class LineResult { Entry, Skip, Invalid };
LineResult parseMlsxLine(const QByteArray &line, Entry *entry);
// The fact line of a 250 reply to MLST; "cdir" counts as a folder here.
LineResult parseMlstReply(const Reply &reply, Entry *entry);

// One line of a LIST reply in Unix ("ls -l") or DOS/IIS format. Times are
// server-local and are taken as UTC with extra["timeApproximate"] = true.
// A Unix time without a year resolves to the latest such date that is not
// more than one day after `now` (ls prints the year for anything older
// than six months; the day of slack covers time zones). "total N" lines,
// empty lines, "." and ".." yield Skip.
LineResult parseListLine(const QByteArray &line, const QDateTime &now, Entry *entry);

// Streaming listing parser (XC-6): feed() takes data as the transfer
// delivers it and appends the entries of complete lines; finish() parses a
// last unterminated line. Lines longer than MaxLineBytes are invalid.
class ListingParser
{
public:
    static constexpr int MaxLineBytes = 64 * 1024;

    ListingParser(bool mlsd, const QDateTime &now);
    void feed(const char *data, size_t size, QVector<Entry> *out);
    void finish(QVector<Entry> *out);
    // Lines that could not be parsed (F-3: skipped and counted).
    int invalidLines() const { return m_invalid; }

private:
    void parse(const QByteArray &line, QVector<Entry> *out);

    bool m_mlsd;
    QDateTime m_now;
    QByteArray m_partial;
    bool m_overlong = false;
    int m_invalid = 0;
};

// Yearless "Mon DD" resolution (see parseListLine). Invalid if no such day.
QDate resolveYearlessDate(int month, int day, const QDate &today);

} // namespace NetVfs::Ftp

#endif
