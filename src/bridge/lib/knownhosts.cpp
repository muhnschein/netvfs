// SPDX-License-Identifier: LGPL-2.1-or-later
#include "knownhosts.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QSaveFile>
#include <QtCore/QStandardPaths>

#include <algorithm>

namespace NetVfs::Bridge {

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

// Called with the mutex held (the state is only reachable through it).
void KnownHosts::load(const QString &path, State *state)
{
    if (state->loaded)
        return;
    state->loaded = true;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return;
    const QList<QByteArray> lines = file.read(MaxFileBytes).split('\n');
    for (const QByteArray &line : lines) {
        const int space = line.indexOf(' ');
        if (space <= 0)
            continue;
        state->pins.insert(QString::fromUtf8(line.left(space)), QString::fromUtf8(line.mid(space + 1)).trimmed());
    }
}

bool KnownHosts::save(const QString &path, const State &state)
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly))
        return false;
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    QStringList keys = state.pins.keys();
    std::sort(keys.begin(), keys.end());
    for (const QString &key : keys)
        file.write(key.toUtf8() + ' ' + state.pins.value(key).toUtf8() + '\n');
    return file.commit();
}

QString KnownHosts::pin(const QString &key) const
{
    std::scoped_lock lock(m_mutex);
    load(m_path, &m_state);
    return m_state.pins.value(key);
}

bool KnownHosts::setPin(const QString &key, const QString &pin)
{
    if (!isValidKey(key) || pin.isEmpty() || pin.contains(QLatin1Char('\n')))
        return false;
    std::scoped_lock lock(m_mutex);
    load(m_path, &m_state);
    m_state.pins.insert(key, pin);
    return save(m_path, m_state);
}

bool KnownHosts::remove(const QString &key)
{
    std::scoped_lock lock(m_mutex);
    load(m_path, &m_state);
    if (m_state.pins.remove(key) == 0)
        return true;
    return save(m_path, m_state);
}

} // namespace NetVfs::Bridge
