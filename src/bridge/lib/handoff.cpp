// SPDX-License-Identifier: LGPL-2.1-or-later
#include "handoff.h"

#include <QtCore/QFileInfo>
#include <QtCore/QSettings>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>

#include <algorithm>

namespace NetVfs::Bridge {

namespace {

const char DefaultConfig[] = "/usr/share/netvfs/bridge/handoff.conf";

bool isDBusName(const QString &s, QChar separator)
{
    if (s.isEmpty() || s.size() > 255)
        return false;
    return std::all_of(s.cbegin(), s.cend(), [separator](QChar c) {
        return (c.isLetterOrNumber() && c.unicode() < 128) || c == QLatin1Char('_') || c == separator;
    });
}

bool parseArgument(const QString &spec, int accountId, const QString &provider, QVariant *out)
{
    if (spec.indexOf(QLatin1Char(':')) != 1)
        return false;
    QString value = spec.mid(2);
    value.replace(QStringLiteral("{accountId}"), QString::number(accountId));
    value.replace(QStringLiteral("{provider}"), provider);
    bool ok = true;
    switch (spec.at(0).unicode()) {
    case 's':
        *out = value;
        break;
    case 'i':
        *out = value.toInt(&ok);
        break;
    case 'u':
        *out = value.toUInt(&ok);
        break;
    case 'b':
        ok = value == QLatin1String("true") || value == QLatin1String("false");
        *out = value == QLatin1String("true");
        break;
    default:
        return false;
    }
    return ok;
}

Result sessionBusLauncher(const HandoffCall &call)
{
    QDBusMessage message = QDBusMessage::createMethodCall(call.service, call.path, call.interface, call.method);
    message.setArguments(call.arguments);
    if (!QDBusConnection::sessionBus().send(message))
        return Result(Error::Unsupported, QStringLiteral("Settings cannot be opened"));
    return Result::success();
}

} // namespace

Handoff::Handoff(const QString &configPath)
    : m_configPath(configPath)
    , m_launcher(sessionBusLauncher)
{
}

QString Handoff::defaultConfigPath()
{
    return QString::fromLatin1(DefaultConfig);
}

Result Handoff::resolve(const QString &group, int accountId, const QString &provider, HandoffCall *out) const
{
    if (!QFileInfo::exists(m_configPath))
        return Result(Error::Unsupported, QStringLiteral("No settings handoff is configured"));
    QSettings settings(m_configPath, QSettings::IniFormat);
    settings.beginGroup(group);
    HandoffCall call;
    call.service = settings.value(QStringLiteral("Service")).toString();
    call.path = settings.value(QStringLiteral("Path")).toString();
    call.interface = settings.value(QStringLiteral("Interface")).toString();
    call.method = settings.value(QStringLiteral("Method")).toString();
    const QStringList arguments = settings.value(QStringLiteral("Arguments")).toStringList();
    if (call.service.isEmpty() && call.method.isEmpty())
        return Result(Error::Unsupported, QStringLiteral("No settings handoff is configured"));
    if (!isDBusName(call.service, QLatin1Char('.')) || !isDBusName(call.interface, QLatin1Char('.'))
            || !isDBusName(call.method, QChar()) || !call.path.startsWith(QLatin1Char('/'))
            || !isDBusName(call.path.mid(1), QLatin1Char('/'))) {
        return Result(Error::InvalidName, QStringLiteral("Invalid settings handoff entry %1").arg(group));
    }
    for (const QString &spec : arguments) {
        if (spec.trimmed().isEmpty())
            continue;   // "Arguments=" is an empty list
        QVariant value;
        if (!parseArgument(spec.trimmed(), accountId, provider, &value))
            return Result(Error::InvalidName, QStringLiteral("Invalid settings handoff argument in %1").arg(group));
        call.arguments << value;
    }
    *out = call;
    return Result::success();
}

Result Handoff::run(const QString &group, int accountId, const QString &provider) const
{
    HandoffCall call;
    if (const Result r = resolve(group, accountId, provider, &call); !r.ok())
        return r;
    return m_launcher ? m_launcher(call) : Result(Error::Unsupported);
}

Result Handoff::openAccountSettings(int accountId, const QString &provider) const
{
    return run(QStringLiteral("OpenAccountSettings"), accountId, provider);
}

Result Handoff::addAccount(const QString &provider) const
{
    return run(QStringLiteral("AddAccount"), 0, provider);
}

} // namespace NetVfs::Bridge
