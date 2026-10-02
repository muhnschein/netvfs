// SPDX-License-Identifier: LGPL-2.1-or-later
#include "knownhosts.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QSaveFile>
#include <QtCore/QStandardPaths>

#include <algorithm>

namespace NetVfs {
namespace Bridge {

namespace {
constexpr qint64 MaxFileBytes = 1 << 20;

bool isValidKey(const QString &key)
{
    return !key.isEmpty() && !key.contains(QLatin1Char(' ')) && !key.contains(QLatin1Char('\n'));
}
} // namespace

KnownHosts::KnownHosts(const QString &filePath)
    : m_path(filePath)
{
}

QString KnownHosts::defaultFilePath(const QString &consumerId)
{
    return QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
        + QStringLiteral("/netvfs/bridge/") + consumerId + QStringLiteral("/known_hosts");
}

void KnownHosts::loadLocked() const
{
    if (m_loaded)
        return;
    m_loaded = true;
    QFile file(m_path);
    if (!file.open(QIODevice::ReadOnly))
        return;
    const QList<QByteArray> lines = file.read(MaxFileBytes).split('\n');
    for (const QByteArray &line : lines) {
        const int space = line.indexOf(' ');
        if (space <= 0)
            continue;
        m_pins.insert(QString::fromUtf8(line.left(space)), QString::fromUtf8(line.mid(space + 1)).trimmed());
    }
}

bool KnownHosts::saveLocked() const
{
    QDir().mkpath(QFileInfo(m_path).absolutePath());
    QSaveFile file(m_path);
    if (!file.open(QIODevice::WriteOnly))
        return false;
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    QStringList keys = m_pins.keys();
    std::sort(keys.begin(), keys.end());
    for (const QString &key : keys)
        file.write(key.toUtf8() + ' ' + m_pins.value(key).toUtf8() + '\n');
    return file.commit();
}

QString KnownHosts::pin(const QString &key) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    loadLocked();
    return m_pins.value(key);
}

bool KnownHosts::setPin(const QString &key, const QString &pin)
{
    if (!isValidKey(key) || pin.isEmpty() || pin.contains(QLatin1Char('\n')))
        return false;
    std::lock_guard<std::mutex> lock(m_mutex);
    loadLocked();
    m_pins.insert(key, pin);
    return saveLocked();
}

bool KnownHosts::remove(const QString &key)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    loadLocked();
    if (m_pins.remove(key) == 0)
        return true;
    return saveLocked();
}

} // namespace Bridge
} // namespace NetVfs
