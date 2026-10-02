// SPDX-License-Identifier: LGPL-2.1-or-later
#include "names.h"

namespace NetVfs::Names {

namespace {

constexpr char16_t EscapeBase = 0xDC00;
constexpr char16_t Replacement = 0xFFFD;

bool isEscape(char16_t u)
{
    return u >= EscapeBase + 0x80 && u <= EscapeBase + 0xFF;
}

// True if a high surrogate followed by a low surrogate starts at `i`.
bool pairAt(const QString &text, int i)
{
    return i + 1 < text.size() && QChar::isHighSurrogate(text.at(i).unicode())
        && QChar::isLowSurrogate(text.at(i + 1).unicode());
}

bool isContinuation(uint b)
{
    return (b & 0xC0) == 0x80;
}

// Length of the well-formed UTF-8 sequence starting at `i` (RFC 3629,
// Unicode table 3-7), or 0 if ill-formed. Stores the code point.
int sequenceLength(const QByteArray &bytes, int i, uint *codePoint)
{
    const auto at = [&bytes](int k) { return static_cast<uint>(static_cast<uchar>(bytes.at(k))); };
    const uint b0 = at(i);
    const int remaining = bytes.size() - i;
    if (b0 < 0x80) {
        *codePoint = b0;
        return 1;
    }
    int length = 0;
    uint lo = 0x80;
    uint hi = 0xBF;
    uint cp = 0;
    if (b0 >= 0xC2 && b0 <= 0xDF) {
        length = 2;
        cp = b0 & 0x1F;
    } else if (b0 >= 0xE0 && b0 <= 0xEF) {
        length = 3;
        cp = b0 & 0x0F;
        if (b0 == 0xE0)
            lo = 0xA0;          // overlong
        else if (b0 == 0xED)
            hi = 0x9F;          // UTF-16 surrogates
    } else if (b0 >= 0xF0 && b0 <= 0xF4) {
        length = 4;
        cp = b0 & 0x07;
        if (b0 == 0xF0)
            lo = 0x90;          // overlong
        else if (b0 == 0xF4)
            hi = 0x8F;          // > U+10FFFF
    } else {
        return 0;
    }
    if (remaining < length)
        return 0;
    const uint b1 = at(i + 1);
    if (b1 < lo || b1 > hi)
        return 0;
    cp = (cp << 6) | (b1 & 0x3F);
    for (int k = 2; k < length; ++k) {
        const uint b = at(i + k);
        if (!isContinuation(b))
            return 0;
        cp = (cp << 6) | (b & 0x3F);
    }
    *codePoint = cp;
    return length;
}

void appendUtf8(QByteArray *out, uint cp)
{
    if (cp < 0x80) {
        out->append(char(cp));
    } else if (cp < 0x800) {
        out->append(char(0xC0 | (cp >> 6)));
        out->append(char(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out->append(char(0xE0 | (cp >> 12)));
        out->append(char(0x80 | ((cp >> 6) & 0x3F)));
        out->append(char(0x80 | (cp & 0x3F)));
    } else {
        out->append(char(0xF0 | (cp >> 18)));
        out->append(char(0x80 | ((cp >> 12) & 0x3F)));
        out->append(char(0x80 | ((cp >> 6) & 0x3F)));
        out->append(char(0x80 | (cp & 0x3F)));
    }
}

} // namespace

QString decode(const QByteArray &bytes)
{
    QString result;
    result.reserve(bytes.size());
    int i = 0;
    while (i < bytes.size()) {
        uint cp = 0;
        const int length = sequenceLength(bytes, i, &cp);
        if (length == 0) {
            result.append(QChar(ushort(EscapeBase + uchar(bytes.at(i)))));
            ++i;
            continue;
        }
        if (cp >= 0x10000) {
            result.append(QChar(QChar::highSurrogate(cp)));
            result.append(QChar(QChar::lowSurrogate(cp)));
        } else {
            result.append(QChar(ushort(cp)));
        }
        i += length;
    }
    return result;
}

QByteArray encode(const QString &name)
{
    QByteArray out;
    out.reserve(name.size());
    const int n = name.size();
    int i = 0;
    while (i < n) {
        const char16_t u = name.at(i).unicode();
        if (pairAt(name, i)) {
            appendUtf8(&out, QChar::surrogateToUcs4(u, name.at(i + 1).unicode()));
            ++i;   // the low surrogate
        } else if (isEscape(u)) {
            out.append(char(u - EscapeBase));
        } else if (QChar::isSurrogate(u)) {
            appendUtf8(&out, Replacement);   // not produced by decode(); see isEncodable()
        } else {
            appendUtf8(&out, u);
        }
        ++i;
    }
    return out;
}

bool isEncodable(const QString &name)
{
    const int n = name.size();
    int i = 0;
    while (i < n) {
        if (pairAt(name, i)) {
            i += 2;
            continue;
        }
        const char16_t u = name.at(i).unicode();
        if (QChar::isSurrogate(u) && !isEscape(u))
            return false;
        ++i;
    }
    return true;
}

QString display(const QString &name)
{
    QString result = name;
    const int n = result.size();
    int i = 0;
    while (i < n) {
        if (pairAt(result, i)) {
            i += 2;
            continue;
        }
        if (QChar::isSurrogate(result.at(i).unicode()))
            result[i] = QChar(ushort(Replacement));
        ++i;
    }
    return result;
}

bool hasEscapes(const QString &name)
{
    const int n = name.size();
    int i = 0;
    while (i < n) {
        if (pairAt(name, i)) {
            i += 2;
            continue;
        }
        if (isEscape(name.at(i).unicode()))
            return true;
        ++i;
    }
    return false;
}

} // namespace NetVfs::Names
