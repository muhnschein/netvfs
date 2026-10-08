// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_CONSENTPROMPT_H
#define NETVFS_BRIDGE_CONSENTPROMPT_H

#include <QtCore/QObject>
#include <QtCore/QString>

// SPEC-v2 XB-6: asking the user whether a consumer may use the network
// locations. The bridge, not the consumer, handles the answer.
namespace NetVfs {
namespace Bridge {

class ConsentPrompt : public QObject
{
    Q_OBJECT
public:
    using QObject::QObject;
    ~ConsentPrompt() override;

    // Shows (or replaces) the question for `displayName`.
    virtual void show(const QString &displayName) = 0;
    // Removes a shown question (the decision was taken elsewhere).
    virtual void withdraw() = 0;
    virtual bool isShown() const = 0;

Q_SIGNALS:
    void answered(bool allow);
    // Closed without an answer.
    void dismissed();
};

// org.freedesktop.Notifications on the session bus: a notification
// "<DisplayName> wants to use your network locations" with the actions
// "allow" (Allow) and "deny" (Don't allow), answered through ActionInvoked.
// Whether lipstick on Sailfish OS 5.2 shows freedesktop actions and emits
// ActionInvoked to a process that does not own a bus name is unverified on a
// device; Settings (the org.netvfs.accounts pages) can always grant or revoke.
class NotificationConsentPrompt final : public ConsentPrompt
{
    Q_OBJECT
public:
    explicit NotificationConsentPrompt(QObject *parent = nullptr);
    ~NotificationConsentPrompt() override;

    void show(const QString &displayName) override;
    void withdraw() override;
    bool isShown() const override { return m_id != 0; }

private Q_SLOTS:
    void onActionInvoked(uint id, const QString &action);
    void onClosed(uint id, uint reason);

private:
    uint m_id = 0;
    bool m_connected = false;
};

} // namespace Bridge
} // namespace NetVfs

#endif
