// SPDX-License-Identifier: LGPL-2.1-or-later
#include "runtime.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QEvent>

namespace NetVfs::Bridge {

namespace {

class FunctorEvent : public QEvent
{
public:
    explicit FunctorEvent(std::function<void()> fn)
        : QEvent(eventType()), m_fn(std::move(fn))
    {
    }

    static QEvent::Type eventType()
    {
        static const auto type = static_cast<QEvent::Type>(QEvent::registerEventType());
        return type;
    }

    void run() const
    {
        if (m_fn)
            m_fn();
    }

private:
    std::function<void()> m_fn;
};

} // namespace

MainQueue::MainQueue(QObject *parent)
    : QObject(parent)
{
}

void MainQueue::post(std::function<void()> fn)
{
    QCoreApplication::postEvent(this, new FunctorEvent(std::move(fn)));
}

bool MainQueue::event(QEvent *event)
{
    if (event->type() == FunctorEvent::eventType()) {
        static_cast<FunctorEvent *>(event)->run();
        return true;
    }
    return QObject::event(event);
}

} // namespace NetVfs::Bridge
