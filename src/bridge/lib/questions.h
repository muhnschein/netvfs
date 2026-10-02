// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_QUESTIONS_H
#define NETVFS_BRIDGE_QUESTIONS_H

#include "args.h"

#include <QtCore/QHash>
#include <QtCore/QString>
#include <QtCore/QVariantMap>

#include <functional>

// SPEC-v2 XB-10 Questions: Question(s id, s kind, a{sv}) goes to the session
// whose request needs the answer; Answer(s id, a{sv}) resolves it. Kinds:
//   identity-unknown      ad-hoc first contact (XB-14); answer {"accept": b}
//   keyboard-interactive  AuthPrompter relay (XC-15);  answer {"accept": b, "answers": aay}
//   insecure-consent      ad-hoc only (W-2, XM-1);     answer {"accept": b}
// A question ends unanswered when its session goes away or its request is
// canceled. Main thread only.
namespace NetVfs {
namespace Bridge {

namespace QuestionKind {
constexpr const char *IdentityUnknown = "identity-unknown";
constexpr const char *KeyboardInteractive = "keyboard-interactive";
constexpr const char *InsecureConsent = "insecure-consent";
} // namespace QuestionKind

class QuestionBroker
{
public:
    // `answered` false: no answer (session gone, canceled, or the session's
    // emitter failed). Called exactly once.
    using Done = std::function<void(bool answered, QuestionAnswer answer)>;
    // Sends the Question signal to the session; false if it does not exist.
    using Emitter = std::function<bool(quint64 sessionId, const QString &id, const QString &kind,
                                       const QVariantMap &details)>;

    void setEmitter(const Emitter &emitter) { m_emitter = emitter; }

    QString ask(quint64 sessionId, const QString &kind, const QVariantMap &details, const Done &done);
    // False if `id` is not a pending question of `sessionId` (answers to other
    // sessions' questions are refused).
    bool answer(quint64 sessionId, const QString &id, QuestionAnswer answer);
    void cancel(const QString &id);
    void dropSession(quint64 sessionId);
    int pending() const { return m_pending.size(); }

private:
    struct Pending {
        quint64 sessionId = 0;
        Done done;
    };

    Emitter m_emitter;
    QHash<QString, Pending> m_pending;
    quint64 m_next = 1;
};

} // namespace Bridge
} // namespace NetVfs

#endif
