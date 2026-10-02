// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BUTEO_REPLYHANDLER_H
#define NETVFS_BUTEO_REPLYHANDLER_H

#include <QtCore/QObject>
#include <QtDBus/QDBusError>
#include <QtDBus/QDBusMessage>

#include <functional>

namespace NetVfs {

// Receiver for one asynchronous D-Bus call made with
// QDBusConnection::callWithCallback(). Runs its callback at most once, for
// the reply or the error message, and then reports itself delivered.
class ReplyHandler : public QObject
{
    Q_OBJECT
public:
    using Callback = std::function<void(const QDBusMessage &)>;

    explicit ReplyHandler(const Callback &done) : m_done(done) {}
    Q_DISABLE_COPY(ReplyHandler)

    bool delivered() const { return m_delivered; }

public Q_SLOTS:
    void onReply(const QDBusMessage &reply)
    {
        if (m_delivered)
            return;
        m_delivered = true;
        m_done(reply);
    }

    void onError(const QDBusError &error, const QDBusMessage &reply)
    {
        Q_UNUSED(error)
        onReply(reply);
    }

private:
    Callback m_done;
    bool m_delivered = false;
};

} // namespace NetVfs

#endif
