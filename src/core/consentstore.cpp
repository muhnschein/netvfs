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
const char AccessGroup[] = "Access";
constexpr int MaxIdLength = 64;
constexpr int MaxPathLength = 1024;
constexpr qint64 MaxConsumerFileBytes = 16 * 1024;

bool isIdChar(QChar c)
{
    const ushort u = c.unicode();
    return (u >= 'a' && u <= 'z') || (u >= '0' && u <= '9') || u == '-';
}

// Chars allowed in paths that end up in systemd unit files: no '%', whitespace, quotes, backslash.
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

}
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

bool isAccessLevel(const QString &word)
{
    return word == QLatin1String("full") || word == QLatin1String("read-add") || word == QLatin1String("read")
        || word == QLatin1String("add");
}

QString AppConsent::choice(int accountId) const
{
    if (const QString own = accounts.value(accountId); !own.isEmpty())
        return own;
    return newAccounts == QLatin1String("ask") ? QString() : newAccounts;
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

namespace {

bool isChoice(const QString &word)
{
    return word == QLatin1String("denied") || isAccessLevel(word);
}

// Positive int written as such ("01", "+1" are not).
int accountIdOf(const QString &key)
{
    bool ok = false;
    const int id = key.toInt(&ok);
    return ok && id > 0 && QString::number(id) == key ? id : 0;
}

}

AppConsent ConsentStore::consent(const QString &id) const
{
    AppConsent result;
    if (!ConsumerInfo::isValidId(id))
        return result;
    QSettings settings(m_path, QSettings::IniFormat);
    if (const QString word = settings.value(QLatin1String(ConsentGroup) + QLatin1Char('/') + id).toString();
        word == QLatin1String("granted"))
        result.newAccounts = QStringLiteral("full");
    else if (word == QLatin1String("ask") || isChoice(word))
        result.newAccounts = word;
    settings.beginGroup(QLatin1String(AccessGroup) + QLatin1Char('/') + id);
    for (const QString &key : settings.childKeys()) {
        const QString choice = settings.value(key).toString();
        if (const int account = accountIdOf(key); account > 0 && isChoice(choice))
            result.accounts.insert(account, choice);
    }
    return result;
}

bool ConsentStore::setConsent(const QString &id, const AppConsent &consent) const
{
    if (!ConsumerInfo::isValidId(id))
        return false;
    QDir().mkpath(QFileInfo(m_path).absolutePath());
    QSettings settings(m_path, QSettings::IniFormat);
    settings.remove(QLatin1String(AccessGroup) + QLatin1Char('/') + id);
    for (auto it = consent.accounts.cbegin(); it != consent.accounts.cend(); ++it) {
        if (it.key() > 0 && isChoice(it.value()))
            settings.setValue(QStringLiteral("%1/%2/%3").arg(QLatin1String(AccessGroup), id).arg(it.key()), it.value());
    }
    const QString key = QLatin1String(ConsentGroup) + QLatin1Char('/') + id;
    if (consent.isDecided())
        settings.setValue(key, consent.newAccounts);
    else
        settings.remove(key);
    settings.sync();
    if (settings.status() != QSettings::NoError) {
        qCWarning(lcNetVfsCore) << "Cannot store what" << id << "may do";
        return false;
    }
    return true;
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

// Strict [Consumer] reader: QSettings would turn "a, b" into a list.
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
        else if (key == QLatin1String("Access") && isAccessLevel(value))
            info.access = value;
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

}