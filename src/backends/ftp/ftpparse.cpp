// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ftpparse.h"
#include "names.h"

#include <array>

namespace NetVfs::Ftp {

namespace {

constexpr int CodeLength = 3;
constexpr int TimeValDigits = 14;
constexpr int TwoDigitYearPivot = 70;      // DOS listings: 70..99 → 19xx
constexpr int MaxLinkCount = 1 << 30;
constexpr int HoursPerHalfDay = 12;
constexpr int MaxListTokens = 4096;
constexpr int PermissionChars = 9;
constexpr int MinYear = 1970;
constexpr int MaxYear = 9999;
constexpr int MillisecondDigits = 3;
constexpr int LastSecond = 59;
constexpr int LeapSecond = 60;

constexpr std::array<const char *, 12> MonthNames = {
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"
};

bool isDigit(char c)
{
    return c >= '0' && c <= '9';
}

bool allDigits(const QByteArray &text)
{
    if (text.isEmpty())
        return false;
    for (const char c : text) {
        if (!isDigit(c))
            return false;
    }
    return true;
}

// Non-negative decimal number; -1 if malformed or too large.
qint64 number(const QByteArray &text)
{
    if (!allDigits(text) || text.size() > 18)
        return -1;
    bool ok = false;
    const qint64 value = text.toLongLong(&ok);
    return ok ? value : -1;
}

int digits(const QByteArray &text, int from, int count)
{
    int value = 0;
    for (int i = from; i < from + count; ++i)
        value = value * 10 + (text.at(i) - '0');
    return value;
}

// The reply code of a line that starts a reply ("ddd " / "ddd-" / "ddd"),
// else 0.
int replyCode(const QByteArray &line)
{
    if (line.size() < CodeLength)
        return 0;
    if (line.at(0) < '1' || line.at(0) > '5' || !isDigit(line.at(1)) || !isDigit(line.at(2)))
        return 0;
    if (line.size() > CodeLength && line.at(CodeLength) != ' ' && line.at(CodeLength) != '-')
        return 0;
    return digits(line, 0, CodeLength);
}

QByteArray stripCr(const QByteArray &line)
{
    if (line.endsWith('\r'))
        return line.left(line.size() - 1);
    return line;
}

// A name as the last component of a listing: no separators, no NUL, not
// "." or ".." (C-15).
bool validName(const QByteArray &name)
{
    return !name.isEmpty() && !name.contains('/') && !name.contains('\0')
        && name != "." && name != "..";
}

void setName(Entry *entry, const QByteArray &name)
{
    entry->name = Names::decode(name);
    if (Names::hasEscapes(entry->name))
        entry->flags |= EntryFlag::NameNotUtf8;
}

// ---------------------------------------------------------------- MLSx facts

EntryType unixType(const QByteArray &value, QByteArray *target)
{
    // "OS.unix=slink:<target>" (vsftpd-style), "OS.unix=symlink",
    // "OS.unix=chr-13/29", "OS.unix=blk-...", "OS.unix=fifo", "OS.unix=socket"
    const QByteArray kind = value.mid(int(sizeof("os.unix=")) - 1);
    const QByteArray lower = kind.toLower();
    if (lower.startsWith("slink")) {
        const int colon = kind.indexOf(':');
        if (colon >= 0)
            *target = kind.mid(colon + 1);
        return EntryType::Symlink;
    }
    if (lower == "symlink")
        return EntryType::Symlink;
    if (lower.startsWith("chr") || lower.startsWith("blk") || lower == "fifo" || lower == "socket")
        return EntryType::Special;
    return EntryType::Unknown;
}

// False for "cdir"/"pdir" in a listing (the entry is skipped).
bool applyType(const QByteArray &value, bool listing, Entry *entry)
{
    const QByteArray lower = value.toLower();
    const bool self = lower == "cdir" || lower == "pdir";
    if (self && listing)
        return false;
    if (lower == "file") {
        entry->type = EntryType::File;
    } else if (lower == "dir" || self) {
        entry->type = EntryType::Directory;
    } else if (lower.startsWith("os.unix=")) {
        QByteArray target;
        entry->type = unixType(value, &target);
        if (!target.isEmpty())
            entry->extra.insert(QStringLiteral("linkTarget"), Names::decode(target));
    }
    if (entry->type == EntryType::Symlink)
        entry->flags |= EntryFlag::TargetUnknown;
    return true;
}

bool applyId(const QByteArray &value, qint64 *id)
{
    *id = number(value);
    return *id >= 0;
}

bool applyOwner(const QByteArray &value, qint64 *id, QString *name)
{
    if (allDigits(value)) {
        *id = number(value);
        return *id >= 0;
    }
    *name = QString::fromUtf8(value);
    return true;
}

bool applyMode(const QByteArray &value, Entry *entry)
{
    bool ok = false;
    const int mode = value.toInt(&ok, 8);
    if (!ok || mode < 0)
        return false;
    entry->mode = mode & 07777;
    return true;
}

bool applyTime(const QByteArray &value, QDateTime *out)
{
    *out = parseTimeVal(value);
    return out->isValid();
}

bool applySize(const QByteArray &value, Entry *entry)
{
    entry->size = number(value);
    return entry->size >= 0;
}

// Applies one fact. Returns false for a malformed value. Unknown facts are
// ignored (RFC 3659 7.5).
bool applyFact(const QByteArray &fact, const QByteArray &value, Entry *entry)
{
    if (fact == "size")
        return applySize(value, entry);
    if (fact == "modify")
        return applyTime(value, &entry->modified);
    if (fact == "create")
        return applyTime(value, &entry->created);
    if (fact == "unix.mode")
        return applyMode(value, entry);
    if (fact == "unix.uid")
        return applyId(value, &entry->uid);
    if (fact == "unix.gid")
        return applyId(value, &entry->gid);
    if (fact == "unix.owner")
        return applyOwner(value, &entry->uid, &entry->owner);
    if (fact == "unix.group")
        return applyOwner(value, &entry->gid, &entry->group);
    if (fact == "unix.ownername")
        entry->owner = QString::fromUtf8(value);
    else if (fact == "unix.groupname")
        entry->group = QString::fromUtf8(value);
    else if (fact == "perm")
        entry->extra.insert(QStringLiteral("perm"), QString::fromLatin1(value));
    else if (fact == "unique")
        entry->extra.insert(QStringLiteral("unique"), QString::fromLatin1(value));
    else if (fact == "media-type")
        entry->contentType = QString::fromLatin1(value);
    return true;
}

// ------------------------------------------------------------- LIST helpers

struct Token {
    int start = 0;
    int end = 0;   // one past the last byte
};

QVector<Token> tokenize(const QByteArray &line)
{
    QVector<Token> tokens;
    int i = 0;
    const int n = line.size();
    while (i < n && tokens.size() < MaxListTokens) {
        while (i < n && line.at(i) == ' ')
            ++i;
        if (i >= n)
            break;
        Token token;
        token.start = i;
        while (i < n && line.at(i) != ' ')
            ++i;
        token.end = i;
        tokens.append(token);
    }
    return tokens;
}

QByteArray text(const QByteArray &line, const Token &token)
{
    return line.mid(token.start, token.end - token.start);
}

int monthNumber(const QByteArray &token)
{
    const QByteArray lower = token.toLower();
    for (int i = 0; i < int(MonthNames.size()); ++i) {
        if (lower == MonthNames.at(size_t(i)))
            return i + 1;
    }
    return 0;
}

int dayNumber(const QByteArray &token)
{
    if (token.size() > 2 || !allDigits(token))
        return 0;
    const int day = token.toInt();
    return day >= 1 && day <= 31 ? day : 0;
}

bool parseClock(const QByteArray &token, QTime *time)
{
    // "H:MM" or "HH:MM"
    const int colon = token.indexOf(':');
    if (colon < 1 || colon > 2 || token.size() != colon + 3)
        return false;
    const QByteArray hours = token.left(colon);
    const QByteArray minutes = token.mid(colon + 1);
    if (!allDigits(hours) || !allDigits(minutes))
        return false;
    *time = QTime(hours.toInt(), minutes.toInt());
    return time->isValid();
}

// Mode bits for permission character `c` at position `i` (0..8) of
// "rwxrwxrwx"; s/t/S/T in an execute slot add setuid, setgid or sticky.
// -1 if `c` does not belong there.
int permissionBits(int i, char c)
{
    static constexpr std::array<char, PermissionChars> Letters = { 'r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x' };
    static constexpr std::array<int, 3> SpecialBits = { 04000, 02000, 01000 };
    const int bit = 1 << (PermissionChars - 1 - i);
    if (c == Letters.at(size_t(i)))
        return bit;
    if (c == '-')
        return 0;
    if ((i % 3) != 2)
        return -1;
    const int special = SpecialBits.at(size_t(i / 3));
    const bool sticky = i == PermissionChars - 1;
    if (c == (sticky ? 't' : 's'))
        return bit | special;
    if (c == (sticky ? 'T' : 'S'))
        return special;
    return -1;
}

// Permission string "-rwxr-xr-x" (optionally followed by an ACL marker).
bool parsePermissions(const QByteArray &token, Entry *entry)
{
    if (token.size() != PermissionChars + 1
        && !(token.size() == PermissionChars + 2 && QByteArray("+.@").contains(token.at(PermissionChars + 1))))
        return false;
    switch (token.at(0)) {
    case '-': entry->type = EntryType::File; break;
    case 'd': entry->type = EntryType::Directory; break;
    case 'l': entry->type = EntryType::Symlink; entry->flags |= EntryFlag::TargetUnknown; break;
    case 'c': case 'b': case 'p': case 's': entry->type = EntryType::Special; break;
    default: return false;
    }
    int mode = 0;
    for (int i = 0; i < PermissionChars; ++i) {
        const int bits = permissionBits(i, token.at(i + 1));
        if (bits < 0)
            return false;
        mode |= bits;
    }
    entry->mode = mode;
    return true;
}

struct UnixFields {
    int month = 0;   // token index of the month
    int size = 0;    // token index of the size
};

bool timeOrYear(const QByteArray &token)
{
    QTime ignored;
    return parseClock(token, &ignored) || (token.size() == 4 && allDigits(token));
}

// Finds "<size> <Mon> <day> <HH:MM|YYYY>" followed by at least one name byte.
bool locateDate(const QByteArray &line, const QVector<Token> &tokens, UnixFields *fields)
{
    for (int m = 3; m + 2 < tokens.size(); ++m) {
        if (monthNumber(text(line, tokens.at(m))) == 0 || dayNumber(text(line, tokens.at(m + 1))) == 0)
            continue;
        if (!timeOrYear(text(line, tokens.at(m + 2))) || !allDigits(text(line, tokens.at(m - 1))))
            continue;
        if (tokens.at(m + 2).end + 1 >= line.size())
            continue;   // no name
        fields->month = m;
        fields->size = m - 1;
        return true;
    }
    return false;
}

bool applyUnixOwners(const QByteArray &line, const QVector<Token> &tokens, int first, int last, Entry *entry)
{
    // tokens [first, last) are owner and group (either may be missing)
    const int count = last - first;
    if (count > 2)
        return false;
    if (count >= 1 && !applyOwner(text(line, tokens.at(first)), &entry->uid, &entry->owner))
        return false;
    if (count == 2 && !applyOwner(text(line, tokens.at(first + 1)), &entry->gid, &entry->group))
        return false;
    return true;
}

bool applyUnixDate(const QByteArray &line, const QVector<Token> &tokens, int month, const QDateTime &now, Entry *entry)
{
    const int monthValue = monthNumber(text(line, tokens.at(month)));
    const int day = dayNumber(text(line, tokens.at(month + 1)));
    const QByteArray last = text(line, tokens.at(month + 2));
    QTime time(0, 0);
    QDate date;
    if (parseClock(last, &time))
        date = resolveYearlessDate(monthValue, day, now.date());
    else
        date = QDate(last.toInt(), monthValue, day);
    if (!date.isValid())
        return false;
    entry->modified = QDateTime(date, time, Qt::UTC);
    entry->extra.insert(QStringLiteral("timeApproximate"), true);
    return true;
}

bool applyUnixName(const QByteArray &line, int start, Entry *entry)
{
    QByteArray name = line.mid(start);
    if (entry->type == EntryType::Symlink) {
        const int arrow = name.indexOf(" -> ");
        if (arrow >= 0) {
            entry->extra.insert(QStringLiteral("linkTarget"), Names::decode(name.mid(arrow + 4)));
            name = name.left(arrow);
        }
    }
    if (name == "." || name == "..")
        return true;
    if (!validName(name))
        return false;
    setName(entry, name);
    return true;
}

LineResult parseUnixLine(const QByteArray &line, const QDateTime &now, Entry *entry)
{
    const QVector<Token> tokens = tokenize(line);
    if (tokens.size() < 6 || !parsePermissions(text(line, tokens.at(0)), entry))
        return LineResult::Invalid;
    UnixFields fields;
    if (!locateDate(line, tokens, &fields))
        return LineResult::Invalid;
    const bool hasLinks = allDigits(text(line, tokens.at(1))) && number(text(line, tokens.at(1))) < MaxLinkCount;
    int ownersEnd = fields.size;
    if (entry->type == EntryType::Special && text(line, tokens.at(fields.size - 1)).endsWith(','))
        --ownersEnd;   // "major, minor" of a device
    else if (entry->type != EntryType::Special)
        entry->size = number(text(line, tokens.at(fields.size)));
    if (!applyUnixOwners(line, tokens, hasLinks ? 2 : 1, ownersEnd, entry))
        return LineResult::Invalid;
    if (!applyUnixDate(line, tokens, fields.month, now, entry))
        return LineResult::Invalid;
    if (!applyUnixName(line, tokens.at(fields.month + 2).end + 1, entry))
        return LineResult::Invalid;
    return entry->name.isEmpty() ? LineResult::Skip : LineResult::Entry;
}

// "MM-DD-YY", "MM-DD-YYYY" or "YYYY-MM-DD".
QDate parseDosDate(const QByteArray &token)
{
    const QList<QByteArray> parts = token.split('-');
    if (parts.size() != 3)
        return QDate();
    for (const QByteArray &part : parts) {
        if (!allDigits(part))
            return QDate();
    }
    if (parts.at(0).size() == 4 && parts.at(1).size() == 2 && parts.at(2).size() == 2)
        return QDate(parts.at(0).toInt(), parts.at(1).toInt(), parts.at(2).toInt());
    if (parts.at(0).size() != 2 || parts.at(1).size() != 2)
        return QDate();
    int year = parts.at(2).toInt();
    if (parts.at(2).size() == 2)
        year += year < TwoDigitYearPivot ? 2000 : 1900;
    else if (parts.at(2).size() != 4)
        return QDate();
    return QDate(year, parts.at(0).toInt(), parts.at(1).toInt());
}

// "HH:MM", "HH:MMAM", "HH:MMPM"; `suffix` is a following "AM"/"PM" token.
bool parseDosTime(QByteArray token, const QByteArray &suffix, QTime *time, bool *usedSuffix)
{
    QByteArray meridiem;
    const QByteArray upper = token.toUpper();
    if (upper.endsWith("AM") || upper.endsWith("PM")) {
        meridiem = upper.right(2);
        token.chop(2);
    } else if (suffix.toUpper() == "AM" || suffix.toUpper() == "PM") {
        meridiem = suffix.toUpper();
        *usedSuffix = true;
    }
    if (!parseClock(token, time))
        return false;
    if (meridiem.isEmpty())
        return true;
    int hour = time->hour();
    if (hour < 1 || hour > HoursPerHalfDay)
        return false;
    hour %= HoursPerHalfDay;
    if (meridiem == "PM")
        hour += HoursPerHalfDay;
    *time = QTime(hour, time->minute());
    return true;
}

LineResult parseDosLine(const QByteArray &line, Entry *entry)
{
    const QVector<Token> tokens = tokenize(line);
    if (tokens.size() < 4)
        return LineResult::Invalid;
    const QDate date = parseDosDate(text(line, tokens.at(0)));
    QTime time;
    bool usedSuffix = false;
    if (!date.isValid() || !parseDosTime(text(line, tokens.at(1)), text(line, tokens.at(2)), &time, &usedSuffix))
        return LineResult::Invalid;
    const int kind = usedSuffix ? 3 : 2;
    if (kind + 1 >= tokens.size())
        return LineResult::Invalid;
    const QByteArray what = text(line, tokens.at(kind));
    if (what.toUpper() == "<DIR>") {
        entry->type = EntryType::Directory;
    } else if (allDigits(what)) {
        entry->type = EntryType::File;
        entry->size = number(what);
        if (entry->size < 0)
            return LineResult::Invalid;
    } else {
        return LineResult::Invalid;
    }
    const QByteArray name = line.mid(tokens.at(kind + 1).start);
    if (name == "." || name == "..")
        return LineResult::Skip;
    if (!validName(name))
        return LineResult::Invalid;
    setName(entry, name);
    entry->modified = QDateTime(date, time, Qt::UTC);
    entry->extra.insert(QStringLiteral("timeApproximate"), true);
    return LineResult::Entry;
}

bool isTotalLine(const QByteArray &line)
{
    return line.startsWith("total ") && allDigits(line.mid(6).trimmed());
}

} // namespace

// -------------------------------------------------------------------- replies

QByteArray Reply::text() const
{
    if (lines.isEmpty())
        return QByteArray();
    return lines.first().mid(CodeLength + 1);
}

void ReplyReader::feed(const char *data, size_t size)
{
    const QByteArray chunk(data, int(size));
    int from = 0;
    while (from < chunk.size()) {
        const int newline = chunk.indexOf('\n', from);
        const int end = newline < 0 ? chunk.size() : newline;
        const int room = MaxLineBytes - m_partial.size();
        if (room > 0)
            m_partial += chunk.mid(from, qMin(room, end - from));
        if (newline < 0)
            break;
        line(stripCr(m_partial));
        m_partial.clear();
        from = newline + 1;
    }
}

void ReplyReader::reset()
{
    m_partial.clear();
    m_current = Reply();
    m_inMulti = false;
    m_last = Reply();
    m_replies.clear();
    m_count = 0;
}

void ReplyReader::completed()
{
    m_last = m_current;
    ++m_count;
    if (m_replies.size() >= MaxReplies)
        m_replies.removeFirst();
    m_replies.append(m_current);
}

void ReplyReader::line(const QByteArray &text)
{
    if (!m_inMulti) {
        const int code = replyCode(text);
        if (code == 0)
            return;   // stray text outside a reply
        m_current = Reply();
        m_current.code = code;
        m_current.lines.append(text);
        if (text.size() > CodeLength && text.at(CodeLength) == '-') {
            m_inMulti = true;
            return;
        }
        completed();
        return;
    }
    if (m_current.lines.size() < MaxReplyLines)
        m_current.lines.append(text);
    if (replyCode(text) == m_current.code && (text.size() == CodeLength || text.at(CodeLength) == ' ')) {
        m_inMulti = false;
        completed();
    }
}

bool Features::restStream() const
{
    return names.contains("REST") && restParameter.toUpper().split(' ').contains("STREAM");
}

Features parseFeatures(const Reply &reply)
{
    Features features;
    if (reply.code != 211)
        return features;
    for (int i = 1; i + 1 < reply.lines.size(); ++i) {
        const QByteArray line = reply.lines.at(i).trimmed();
        if (line.isEmpty())
            continue;
        const int space = line.indexOf(' ');
        const QByteArray name = (space < 0 ? line : line.left(space)).toUpper();
        const QByteArray parameter = space < 0 ? QByteArray() : line.mid(space + 1).trimmed();
        features.names.insert(name);
        if (name == "REST")
            features.restParameter = parameter;
        else if (name == "MLST")
            features.mlstFacts = parameter;
    }
    return features;
}

bool parsePathReply(const Reply &reply, QByteArray *path)
{
    if (reply.code != 257 || reply.lines.isEmpty())
        return false;
    const QByteArray &line = reply.lines.first();
    int i = line.indexOf('"');
    if (i < 0)
        return false;
    QByteArray result;
    for (++i; i < line.size(); ++i) {
        if (line.at(i) != '"') {
            result += line.at(i);
            continue;
        }
        if (i + 1 < line.size() && line.at(i + 1) == '"') {
            result += '"';
            ++i;
            continue;
        }
        *path = result;
        return !result.isEmpty();
    }
    return false;
}

qint64 parseSizeReply(const Reply &reply)
{
    if (reply.code != 213)
        return -1;
    return number(reply.text().trimmed());
}

QDateTime parseTimeVal(const QByteArray &value)
{
    if (value.size() < TimeValDigits || !allDigits(value.left(TimeValDigits)))
        return QDateTime();
    int milliseconds = 0;
    if (value.size() > TimeValDigits) {
        const QByteArray fraction = value.mid(TimeValDigits + 1);
        if (value.at(TimeValDigits) != '.' || !allDigits(fraction))
            return QDateTime();
        milliseconds = (fraction + "00").left(MillisecondDigits).toInt();
    }
    const int year = digits(value, 0, 4);
    if (year < MinYear || year > MaxYear)
        return QDateTime();
    int second = digits(value, 12, 2);
    if (second == LeapSecond)
        second = LastSecond;
    const QDate date(year, digits(value, 4, 2), digits(value, 6, 2));
    const QTime time(digits(value, 8, 2), digits(value, 10, 2), second, milliseconds);
    if (!date.isValid() || !time.isValid())
        return QDateTime();
    return QDateTime(date, time, Qt::UTC);
}

QDateTime parseMdtmReply(const Reply &reply)
{
    if (reply.code != 213)
        return QDateTime();
    return parseTimeVal(reply.text().trimmed());
}

QByteArray formatTimeVal(const QDateTime &time)
{
    return time.toUTC().toString(QStringLiteral("yyyyMMddHHmmss")).toLatin1();
}

namespace {

LineResult parseFacts(const QByteArray &rawLine, bool listing, Entry *entry)
{
    const QByteArray line = stripCr(rawLine);
    const int space = line.indexOf(' ');
    if (space < 0 || space + 1 >= line.size())
        return LineResult::Invalid;
    *entry = Entry();
    const QList<QByteArray> facts = line.left(space).split(';');
    for (const QByteArray &fact : facts) {
        if (fact.isEmpty())
            continue;
        const int equals = fact.indexOf('=');
        if (equals <= 0)
            return LineResult::Invalid;
        const QByteArray name = fact.left(equals).toLower();
        const QByteArray value = fact.mid(equals + 1);
        if (name == "type") {
            if (!applyType(value, listing, entry))
                return LineResult::Skip;
        } else if (!applyFact(name, value, entry)) {
            return LineResult::Invalid;
        }
    }
    const QByteArray name = line.mid(space + 1);
    if (name.contains('\0'))
        return LineResult::Invalid;
    setName(entry, name);
    return LineResult::Entry;
}

} // namespace

LineResult parseMlsxLine(const QByteArray &line, Entry *entry)
{
    return parseFacts(line, true, entry);
}

LineResult parseMlstReply(const Reply &reply, Entry *entry)
{
    if (reply.code != 250)
        return LineResult::Invalid;
    for (int i = 1; i < reply.lines.size(); ++i) {
        const QByteArray &line = reply.lines.at(i);
        if (line.startsWith(' '))
            return parseFacts(line.mid(1), false, entry);
    }
    return LineResult::Invalid;
}

LineResult parseListLine(const QByteArray &rawLine, const QDateTime &now, Entry *entry)
{
    const QByteArray line = stripCr(rawLine);
    if (line.trimmed().isEmpty() || isTotalLine(line))
        return LineResult::Skip;
    *entry = Entry();
    if (isDigit(line.at(0)))
        return parseDosLine(line, entry);
    return parseUnixLine(line, now, entry);
}

QDate resolveYearlessDate(int month, int day, const QDate &today)
{
    const QDate limit = today.addDays(1);
    for (int year = today.year(); year >= today.year() - 1; --year) {
        const QDate date(year, month, day);
        if (date.isValid() && date <= limit)
            return date;
    }
    return QDate();
}

// -------------------------------------------------------------------- listing

ListingParser::ListingParser(bool mlsd, const QDateTime &now)
    : m_mlsd(mlsd), m_now(now)
{
}

void ListingParser::feed(const char *data, size_t size, QVector<Entry> *out)
{
    const QByteArray chunk(data, int(size));
    int from = 0;
    while (from < chunk.size()) {
        const int newline = chunk.indexOf('\n', from);
        const int end = newline < 0 ? chunk.size() : newline;
        if (!m_overlong) {
            m_partial += chunk.mid(from, end - from);
            if (m_partial.size() > MaxLineBytes) {
                m_overlong = true;
                m_partial.clear();
            }
        }
        if (newline < 0)
            break;
        if (m_overlong)
            ++m_invalid;
        else
            parse(m_partial, out);
        m_partial.clear();
        m_overlong = false;
        from = newline + 1;
    }
}

void ListingParser::finish(QVector<Entry> *out)
{
    if (m_overlong)
        ++m_invalid;
    else if (!m_partial.isEmpty())
        parse(m_partial, out);
    m_partial.clear();
    m_overlong = false;
}

void ListingParser::parse(const QByteArray &line, QVector<Entry> *out)
{
    Entry entry;
    LineResult result = LineResult::Invalid;
    if (m_mlsd) {
        result = parseMlsxLine(line, &entry);
        if (result == LineResult::Entry) {
            const QByteArray name = Names::encode(entry.name);
            if (name == "." || name == "..")
                result = LineResult::Skip;
            else if (!validName(name))
                result = LineResult::Invalid;
        }
    } else {
        result = parseListLine(line, m_now, &entry);
    }
    if (result == LineResult::Entry)
        out->append(entry);
    else if (result == LineResult::Invalid && !stripCr(line).isEmpty())
        ++m_invalid;
}

} // namespace NetVfs::Ftp
