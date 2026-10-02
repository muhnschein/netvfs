// SPDX-License-Identifier: LGPL-2.1-or-later
#include "consentstore.h"
#include "logging.h"

#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QRegularExpression>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>

#include <algorithm>

namespace NetVfs {

namespace {
const char ConsentGroup[] = "Consent";
const char ConsumerGroup[] = "Consumer";
const char ConsumersDirectory[] = "/usr/share/netvfs/consumers";
const char ConsumersEnv[] = "NETVFS_CONSUMERS_DIR";
const char Granted[] = "granted";
const char Denied[] = "denied";
const char UnknownText[] = "unknown";

QString key(const QString &consumerId)
{
    return QLatin1String(ConsentGroup) + QLatin1Char('/') + consumerId;
}

bool readConsumer(const QFileInfo &file, ConsumerInfo *info)
{
    QSettings settings(file.filePath(), QSettings::IniFormat);
    settings.beginGroup(QLatin1String(ConsumerGroup));
    info->id = settings.value(QStringLiteral("Id")).toString();
    info->displayName = settings.value(QStringLiteral("DisplayName")).toString().trimmed();
    info->executable = settings.value(QStringLiteral("Executable")).toString();
    info->dataDir = settings.value(QStringLiteral("DataDir")).toString();
    if (info->displayName.isEmpty())
        info->displayName = info->id;
    return settings.status() == QSettings::NoError && ConsentStore::isValidConsumerId(info->id)
            && info->id == file.completeBaseName();
}
} // namespace

ConsentStore::ConsentStore(const QString &path)
    : m_path(path.isEmpty() ? defaultPath() : path)
{
}

QString ConsentStore::defaultPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)
            + QStringLiteral("/netvfs/bridge.conf");
}

bool ConsentStore::isValidConsumerId(const QString &consumerId)
{
    static const QRegularExpression pattern(QStringLiteral("^[A-Za-z0-9._-]+$"));
    return pattern.match(consumerId).hasMatch();
}

QString ConsentStore::consentToString(Consent consent)
{
    switch (consent) {
    case Consent::Granted:
        return QLatin1String(Granted);
    case Consent::Denied:
        return QLatin1String(Denied);
    case Consent::Unknown:
        break;
    }
    return QLatin1String(UnknownText);
}

Consent ConsentStore::consentFromString(const QString &value)
{
    if (value == QLatin1String(Granted))
        return Consent::Granted;
    if (value == QLatin1String(Denied))
        return Consent::Denied;
    return Consent::Unknown;
}

Consent ConsentStore::consent(const QString &consumerId) const
{
    if (!isValidConsumerId(consumerId))
        return Consent::Unknown;
    const QSettings settings(m_path, QSettings::IniFormat);
    return consentFromString(settings.value(key(consumerId)).toString());
}

bool ConsentStore::setConsent(const QString &consumerId, Consent consent)
{
    if (!isValidConsumerId(consumerId))
        return false;
    QDir().mkpath(QFileInfo(m_path).absolutePath());
    QSettings settings(m_path, QSettings::IniFormat);
    if (consent == Consent::Unknown)
        settings.remove(key(consumerId));
    else
        settings.setValue(key(consumerId), consentToString(consent));
    settings.sync();   // XB-6: a revocation reaches a running bridge now
    if (settings.status() != QSettings::NoError) {
        qCWarning(lcNetVfsCore) << "Cannot write the consent file";
        return false;
    }
    qCDebug(lcNetVfsCore) << "Consent of" << consumerId << "is now" << consentToString(consent);
    return true;
}

QString ConsentStore::consumersDirectory()
{
    const QString overridden = QString::fromLocal8Bit(qgetenv(ConsumersEnv));
    return overridden.isEmpty() ? QLatin1String(ConsumersDirectory) : overridden;
}

QVector<ConsumerInfo> ConsentStore::consumers()
{
    QVector<ConsumerInfo> result;
    const QFileInfoList files = QDir(consumersDirectory()).entryInfoList({ QStringLiteral("*.conf") }, QDir::Files);
    for (const QFileInfo &file : files) {
        ConsumerInfo info;
        if (readConsumer(file, &info))
            result << info;
        else
            qCWarning(lcNetVfsCore) << "Ignoring consumer registration" << file.fileName();
    }
    std::sort(result.begin(), result.end(),
              [](const ConsumerInfo &a, const ConsumerInfo &b) { return a.id < b.id; });
    return result;
}

} // namespace NetVfs
