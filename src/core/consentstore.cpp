// SPDX-License-Identifier: LGPL-2.1-or-later
#include "consentstore.h"
#include "logging.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>

#include <algorithm>

namespace NetVfs {

namespace {

const char ConsumersDirDefault[] = "/usr/share/netvfs/consumers";
const char ConsentGroup[] = "Consent";
constexpr int MaxIdLength = 64;
constexpr int MaxPathLength = 1024;
constexpr qint64 MaxConsumerFileBytes = 16 * 1024;

bool isIdChar(QChar c)
{
    const ushort u = c.unicode();
    return (u >= 'a' && u <= 'z') || (u >= '0' && u <= '9') || u == '-';
}

// Characters allowed in paths that end up in systemd unit files (no '%',
// no whitespace, no quotes, no backslash).
bool isPathChar(QChar c)
{
    const ushort u = c.unicode();
    return (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') || (u >= '0' && u <= '9')
        || u == '/' || u == '.' || u == '_' || u == '-' || u == '+';
}

bool hasOnlyPathChars(const QString &path)
{
    return std::all_of(path.cbegin(), path.cend(), isPathChar);
}

// No empty, "." or ".." components (a leading '/' is checked by the caller).
bool hasCleanComponents(const QString &path)
{
    const QStringList parts = path.split(QLatin1Char('/'));
    return std::none_of(parts.cbegin(), parts.cend(), [](const QString &part) {
        return part.isEmpty() || part == QLatin1String(".") || part == QLatin1String("..");
    });
}

Result invalid(const QString &path, const QString &why)
{
    return Result(Error::InvalidName, QStringLiteral("Invalid consumer file %1: %2").arg(path, why));
}

} // namespace

bool ConsumerInfo::isValidId(const QString &id)
{
    return !id.isEmpty() && id.size() <= MaxIdLength && std::all_of(id.cbegin(), id.cend(), isIdChar);
}

bool ConsumerInfo::isValidDataDir(const QString &dataDir)
{
    return !dataDir.isEmpty() && dataDir.size() <= MaxPathLength && !dataDir.startsWith(QLatin1Char('/'))
        && hasOnlyPathChars(dataDir) && hasCleanComponents(dataDir);
}

bool ConsumerInfo::isValidExecutable(const QString &executable)
{
    return executable.size() > 1 && executable.size() <= MaxPathLength && executable.startsWith(QLatin1Char('/'))
        && hasOnlyPathChars(executable) && hasCleanComponents(executable.mid(1));
}

QString consentToString(Consent consent)
{
    switch (consent) {
    case Consent::Granted:
        return QStringLiteral("granted");
    case Consent::Denied:
        return QStringLiteral("denied");
    case Consent::Unknown:
        break;
    }
    return QStringLiteral("unknown");
}

Consent consentFromString(const QString &value)
{
    if (value == QLatin1String("granted"))
        return Consent::Granted;
    if (value == QLatin1String("denied"))
        return Consent::Denied;
    return Consent::Unknown;
}

ConsentStore::ConsentStore()
    : m_path(defaultFilePath())
{
}

ConsentStore::ConsentStore(const QString &filePath)
    : m_path(filePath)
{
}

QString ConsentStore::defaultFilePath()
{
    return QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)
        + QStringLiteral("/netvfs/bridge.conf");
}

Consent ConsentStore::consent(const QString &id) const
{
    if (!ConsumerInfo::isValidId(id))
        return Consent::Unknown;
    const QSettings settings(m_path, QSettings::IniFormat);
    return consentFromString(settings.value(QLatin1String(ConsentGroup) + QLatin1Char('/') + id).toString());
}

void ConsentStore::setConsent(const QString &id, Consent consent) const
{
    if (!ConsumerInfo::isValidId(id))
        return;
    QDir().mkpath(QFileInfo(m_path).absolutePath());
    QSettings settings(m_path, QSettings::IniFormat);
    const QString key = QLatin1String(ConsentGroup) + QLatin1Char('/') + id;
    if (consent == Consent::Unknown)
        settings.remove(key);
    else
        settings.setValue(key, consentToString(consent));
    settings.sync();
    if (settings.status() != QSettings::NoError)
        qCWarning(lcNetVfsCore) << "Cannot store the consent of" << id;
}

QString ConsentStore::consumersDir()
{
    const QByteArray overridden = qgetenv("NETVFS_CONSUMERS_DIR");
    return overridden.isEmpty() ? QString::fromLatin1(ConsumersDirDefault) : QString::fromLocal8Bit(overridden);
}

QVector<ConsumerInfo> ConsentStore::consumers()
{
    QVector<ConsumerInfo> result;
    const QDir dir(consumersDir());
    const QStringList files = dir.entryList(QStringList(QStringLiteral("*.conf")), QDir::Files, QDir::Name);
    for (const QString &file : files) {
        ConsumerInfo info;
        const Result r = parseConsumerFile(dir.filePath(file), &info);
        if (r.ok())
            result.append(info);
        else
            qCWarning(lcNetVfsCore).noquote() << r.message();
    }
    return result;
}

Result ConsentStore::loadConsumer(const QString &id, ConsumerInfo *out)
{
    if (!ConsumerInfo::isValidId(id))
        return Result(Error::InvalidName, QStringLiteral("Invalid consumer id"));
    return parseConsumerFile(consumersDir() + QLatin1Char('/') + id + QStringLiteral(".conf"), out);
}

// Strict reader for the [Consumer] group: no QSettings (which would turn
// "a, b" into a list and accept many syntaxes the generator does not).
Result ConsentStore::parseConsumerFile(const QString &path, ConsumerInfo *out)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return Result(Error::NotFound, QStringLiteral("Cannot read consumer file %1").arg(path));
    if (file.size() > MaxConsumerFileBytes)
        return invalid(path, QStringLiteral("too large"));
    const QList<QByteArray> lines = file.readAll().split('\n');
    ConsumerInfo info;
    bool inGroup = false;
    for (const QByteArray &raw : lines) {
        const QString line = QString::fromUtf8(raw).trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#')) || line.startsWith(QLatin1Char(';')))
            continue;
        if (line.startsWith(QLatin1Char('['))) {
            inGroup = line == QLatin1String("[Consumer]");
            continue;
        }
        const int eq = line.indexOf(QLatin1Char('='));
        if (!inGroup || eq <= 0)
            continue;
        const QString key = line.left(eq).trimmed();
        const QString value = line.mid(eq + 1).trimmed();
        if (key == QLatin1String("Id"))
            info.id = value;
        else if (key == QLatin1String("DisplayName"))
            info.displayName = value;
        else if (key == QLatin1String("Executable"))
            info.executable = value;
        else if (key == QLatin1String("DataDir"))
            info.dataDir = value;
    }
    if (const QString stem = QFileInfo(path).completeBaseName(); !ConsumerInfo::isValidId(info.id) || info.id != stem)
        return invalid(path, QStringLiteral("Id must match [a-z0-9-]+ and the file name"));
    if (info.displayName.isEmpty())
        return invalid(path, QStringLiteral("DisplayName is empty"));
    if (!ConsumerInfo::isValidExecutable(info.executable))
        return invalid(path, QStringLiteral("Executable must be an absolute path"));
    if (!ConsumerInfo::isValidDataDir(info.dataDir))
        return invalid(path, QStringLiteral("DataDir must be relative to the home folder, without \"..\""));
    if (out)
        *out = info;
    return Result::success();
}

} // namespace NetVfs
