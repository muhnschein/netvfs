// SPDX-License-Identifier: LGPL-2.1-or-later
#include "paths.h"
#include "names.h"

#include <array>

namespace NetVfs::Paths {

Result normalize(const QString &path, QString *normalized)
{
    if (path.contains(QChar(0)))
        return Result(Error::InvalidName, QStringLiteral("Path contains a NUL character"));

    const bool absolute = path.startsWith(QLatin1Char('/'));
    const QStringList parts = path.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS);
    for (const QString &part : parts) {
        if (part == QLatin1String(".") || part == QLatin1String(".."))
            return Result(Error::InvalidName, QStringLiteral("Path components \".\" and \"..\" are not allowed"));
    }

    QString result = parts.join(QLatin1Char('/'));
    if (absolute)
        result.prepend(QLatin1Char('/'));
    if (normalized)
        *normalized = result;
    return Result::success();
}

bool isAbsolute(const QString &normalizedPath)
{
    return normalizedPath.startsWith(QLatin1Char('/'));
}

QStringList components(const QString &normalizedPath)
{
    return normalizedPath.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS);
}

QString join(const QString &dir, const QString &name)
{
    if (dir.isEmpty())
        return name;
    if (dir.endsWith(QLatin1Char('/')))
        return dir + name;
    return dir + QLatin1Char('/') + name;
}

QString parent(const QString &normalizedPath)
{
    const int slash = normalizedPath.lastIndexOf(QLatin1Char('/'));
    if (slash < 0)
        return QString();
    if (slash == 0)
        return QStringLiteral("/");
    return normalizedPath.left(slash);
}

QString fileName(const QString &normalizedPath)
{
    const int slash = normalizedPath.lastIndexOf(QLatin1Char('/'));
    return slash < 0 ? normalizedPath : normalizedPath.mid(slash + 1);
}

QString windowsComponentProblem(const QString &component)
{
    static const QString forbidden = QStringLiteral("\\:*?\"<>|");
    for (const QChar c : component) {
        if (forbidden.contains(c))
            return QStringLiteral("\"%1\" contains the character %2").arg(component, QString(c));
        if (c.unicode() < 0x20)
            return QStringLiteral("\"%1\" contains a control character").arg(component);
    }
    if (component.endsWith(QLatin1Char(' ')) || component.endsWith(QLatin1Char('.')))
        return QStringLiteral("\"%1\" ends in a space or a dot").arg(component);
    return QString();
}

Result checkWindowsPath(const QString &normalizedPath)
{
    for (const QString &component : components(normalizedPath)) {
        if (const QString problem = windowsComponentProblem(component); !problem.isEmpty())
            return Result(Error::Internal, problem);
    }
    return Result::success();
}

namespace {

constexpr QChar Placeholder = QLatin1Char('_');
constexpr ushort FirstPrintable = 0x20;

bool isReservedDeviceStem(const QString &stem)
{
    static const std::array<const char *, 4> plain = { "CON", "PRN", "AUX", "NUL" };
    const QString upper = stem.toUpper();
    for (const char *name : plain) {
        if (upper == QLatin1String(name))
            return true;
    }
    if (upper.size() == 4 && (upper.startsWith(QLatin1String("COM")) || upper.startsWith(QLatin1String("LPT"))))
        return upper.at(3) >= QLatin1Char('1') && upper.at(3) <= QLatin1Char('9');
    return false;
}

bool mustReplace(QChar c, bool windows)
{
    if (c == QLatin1Char('/') || c.unicode() == 0)
        return true;
    if (!windows)
        return false;
    return c.unicode() < FirstPrintable || QStringLiteral("\\:*?\"<>|").contains(c);
}

QString replaceForbidden(const QString &name, bool windows)
{
    QString result = name;
    for (QChar &c : result) {
        if (mustReplace(c, windows))
            c = Placeholder;
    }
    return result;
}

void stripTrailingSpacesAndDots(QString *name)
{
    while (name->endsWith(QLatin1Char(' ')) || name->endsWith(QLatin1Char('.')))
        name->chop(1);
}

// Longest prefix of `text` whose UTF-8 encoding (Names::encode) fits in
// `maxBytes`, never splitting a code point.
QString truncateBytes(const QString &text, qint64 maxBytes)
{
    qint64 used = 0;
    int end = 0;
    while (end < text.size()) {
        const bool pair = text.at(end).isHighSurrogate() && end + 1 < text.size()
            && text.at(end + 1).isLowSurrogate();
        const int step = pair ? 2 : 1;
        const qint64 bytes = Names::encode(text.mid(end, step)).size();
        if (used + bytes > maxBytes)
            break;
        used += bytes;
        end += step;
    }
    return text.left(end);
}

// Truncates to `maxBytes`, keeping the extension when it leaves room for at
// least one byte of the stem.
QString fitBytes(const QString &name, qint64 maxBytes)
{
    if (maxBytes <= 0 || Names::encode(name).size() <= maxBytes)
        return name;
    if (const int dot = name.lastIndexOf(QLatin1Char('.')); dot > 0) {
        const QString extension = name.mid(dot);
        if (const qint64 extensionBytes = Names::encode(extension).size(); extensionBytes < maxBytes) {
            const QString stem = truncateBytes(name.left(dot), maxBytes - extensionBytes);
            if (!stem.isEmpty())
                return stem + extension;
        }
    }
    return truncateBytes(name, maxBytes);
}

QString stemOf(const QString &name)
{
    const int dot = name.indexOf(QLatin1Char('.'));
    return dot < 0 ? name : name.left(dot);
}

// Windows treats "CON.txt" like "CON": the '_' goes after the stem.
QString avoidReservedName(const QString &name)
{
    const QString stem = stemOf(name);
    return stem + Placeholder + name.mid(stem.size());
}

} // namespace

QString sanitizeFor(const Capabilities &capabilities, const QString &name)
{
    const bool windows = capabilities.has(Capability::WindowsNames);
    QString result = replaceForbidden(name, windows);
    if (windows)
        stripTrailingSpacesAndDots(&result);
    result = fitBytes(result, capabilities.maxNameBytes);
    if (windows) {
        stripTrailingSpacesAndDots(&result);
        if (isReservedDeviceStem(stemOf(result))) {
            // The '_' needs a byte; trimming may also make the stem harmless.
            const qint64 room = capabilities.maxNameBytes > 1 ? capabilities.maxNameBytes - 1 : capabilities.maxNameBytes;
            result = fitBytes(result, room);
            stripTrailingSpacesAndDots(&result);
            if (isReservedDeviceStem(stemOf(result)))
                result = avoidReservedName(result);
        }
    }
    if (result.isEmpty() || result == QLatin1String(".") || result == QLatin1String(".."))
        return QString(Placeholder);
    return result;
}

} // namespace NetVfs::Paths
