// SPDX-License-Identifier: LGPL-2.1-or-later
#include "paths.h"

namespace NetVfs::Paths {

Result normalize(const QString &path, QString *normalized)
{
    if (path.contains(QChar(0)))
        return Result(Error::Internal, QStringLiteral("Path contains a NUL character"));

    const bool absolute = path.startsWith(QLatin1Char('/'));
    const QStringList parts = path.split(QLatin1Char('/'), NETVFS_SKIP_EMPTY_PARTS);
    for (const QString &part : parts) {
        if (part == QLatin1String(".") || part == QLatin1String(".."))
            return Result(Error::Internal, QStringLiteral("Path components \".\" and \"..\" are not allowed"));
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
        const QString problem = windowsComponentProblem(component);
        if (!problem.isEmpty())
            return Result(Error::Internal, problem);
    }
    return Result::success();
}

} // namespace NetVfs::Paths
