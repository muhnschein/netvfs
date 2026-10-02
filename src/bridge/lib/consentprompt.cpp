// SPDX-License-Identifier: LGPL-2.1-or-later
#include "consentprompt.h"

#include "bridgelog.h"

#include <QtCore/QCoreApplication>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusReply>

namespace NetVfs::Bridge {

namespace {
const char NotificationsService[] = "org.freedesktop.Notifications";
const char NotificationsPath[] = "/org/freedesktop/Notifications";
const char NotificationsInterface[] = "org.freedesktop.Notifications";
const char AllowAction[] = "allow";
const char DenyAction[] = "deny";
constexpr int NeverExpires = 0;
} // namespace

ConsentPrompt::~ConsentPrompt() = default;

NotificationConsentPrompt::NotificationConsentPrompt(QObject *parent)
    : ConsentPrompt(parent)
{
}

NotificationConsentPrompt::~NotificationConsentPrompt()
{
    withdraw();
}

void NotificationConsentPrompt::show(const QString &displayName)
{
    QDBusConnection bus = QDBusConnection::sessionBus();
    if (!m_connected) {
        bus.connect(QLatin1String(NotificationsService), QLatin1String(NotificationsPath),
                    QLatin1String(NotificationsInterface), QStringLiteral("ActionInvoked"), this,
                    SLOT(onActionInvoked(uint,QString)));
        bus.connect(QLatin1String(NotificationsService), QLatin1String(NotificationsPath),
                    QLatin1String(NotificationsInterface), QStringLiteral("NotificationClosed"), this,
                    SLOT(onClosed(uint,uint)));
        m_connected = true;
    }
    QDBusMessage call = QDBusMessage::createMethodCall(QLatin1String(NotificationsService),
                                                      QLatin1String(NotificationsPath),
                                                      QLatin1String(NotificationsInterface), QStringLiteral("Notify"));
    const QString summary = QCoreApplication::translate("netvfs-bridge", "%1 wants to use your network locations")
                                .arg(displayName);
    const QStringList actions = { QLatin1String(AllowAction),
                                  QCoreApplication::translate("netvfs-bridge", "Allow"),
                                  QLatin1String(DenyAction),
                                  QCoreApplication::translate("netvfs-bridge", "Don't allow") };
    QVariantMap hints;
    hints.insert(QStringLiteral("category"), QStringLiteral("x-nemo.general"));
    hints.insert(QStringLiteral("urgency"), QVariant::fromValue<uchar>(1));
    call << QStringLiteral("netvfs") << m_id << QString() << summary << QString() << actions << hints
         << NeverExpires;
    constexpr int NotifyTimeoutMs = 5000;
    const QDBusReply<uint> reply = bus.call(call, QDBus::Block, NotifyTimeoutMs);
    if (reply.isValid())
        m_id = reply.value();
    else
        qCWarning(lcNetVfsBridge) << "Cannot post the consent notification:" << reply.error().message();
}

void NotificationConsentPrompt::withdraw()
{
    if (m_id == 0)
        return;
    QDBusMessage call = QDBusMessage::createMethodCall(QLatin1String(NotificationsService),
                                                      QLatin1String(NotificationsPath),
                                                      QLatin1String(NotificationsInterface),
                                                      QStringLiteral("CloseNotification"));
    call << m_id;
    QDBusConnection::sessionBus().send(call);
    m_id = 0;
}

void NotificationConsentPrompt::onActionInvoked(uint id, const QString &action)
{
    if (id == 0 || id != m_id)
        return;
    m_id = 0;
    if (action == QLatin1String(AllowAction))
        emit answered(true);
    else if (action == QLatin1String(DenyAction))
        emit answered(false);
    else
        emit dismissed();
}

void NotificationConsentPrompt::onClosed(uint id, uint reason)
{
    Q_UNUSED(reason)
    if (id == 0 || id != m_id)
        return;
    m_id = 0;
    emit dismissed();
}

} // namespace NetVfs::Bridge
