// SPDX-License-Identifier: LGPL-2.1-or-later
#include "questions.h"

namespace NetVfs {
namespace Bridge {

QString QuestionBroker::ask(quint64 sessionId, const QString &kind, const QVariantMap &details, const Done &done)
{
    const QString id = QStringLiteral("q") + QString::number(m_next++);
    m_pending.insert(id, Pending { sessionId, done });
    if (!m_emitter || !m_emitter(sessionId, id, kind, details))
        cancel(id);
    return id;
}

bool QuestionBroker::answer(quint64 sessionId, const QString &id, QuestionAnswer answer)
{
    const auto it = m_pending.find(id);
    if (it == m_pending.end() || it->sessionId != sessionId)
        return false;
    const Done done = it->done;
    m_pending.erase(it);
    done(true, std::move(answer));
    return true;
}

void QuestionBroker::cancel(const QString &id)
{
    const auto it = m_pending.find(id);
    if (it == m_pending.end())
        return;
    const Done done = it->done;
    m_pending.erase(it);
    done(false, QuestionAnswer());
}

void QuestionBroker::dropSession(quint64 sessionId)
{
    QStringList ids;
    for (auto it = m_pending.cbegin(); it != m_pending.cend(); ++it) {
        if (it->sessionId == sessionId)
            ids << it.key();
    }
    for (const QString &id : ids)
        cancel(id);
}

} // namespace Bridge
} // namespace NetVfs
