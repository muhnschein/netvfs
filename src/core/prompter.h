// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_PROMPTER_H
#define NETVFS_PROMPTER_H

#include "types.h"

#include <functional>
#include <memory>

namespace NetVfs {

// AuthPrompter for consumers that ask the person on another thread than the backend's (UI, bridge
// Question/Answer relay, terminal).
// answer() runs on the backend thread: hands the question to `ask`, waits for respond(), decline()
// or cancel() from any thread. Backend::cancel() calls cancel() so a canceled sign-in never blocks
// on a person. cancel() stays in effect until reset().
// Answers passed to respond() are copied once into the backend's vector and the held copy wiped;
// caller wipes its own.
class NETVFS_EXPORT BlockingPrompter : public AuthPrompter
{
public:
    struct Question {
        QString name;
        QString instruction;
        QVector<AuthPrompt> prompts;
    };
    // Called on the backend thread; must not block (hand off and return).
    using Ask = std::function<void(const Question &question)>;

    explicit BlockingPrompter(const Ask &ask);
    ~BlockingPrompter() override;
    BlockingPrompter(const BlockingPrompter &) = delete;
    BlockingPrompter &operator=(const BlockingPrompter &) = delete;

    bool answer(const QString &name, const QString &instruction, const QVector<AuthPrompt> &prompts,
                QVector<QByteArray> *answers) override;
    void cancel() override;

    // Thread-safe. Ignored unless answer() is waiting.
    void respond(const QVector<QByteArray> &answers);
    void decline();
    void reset();
    bool waiting() const;

    struct State;

private:
    std::unique_ptr<State> m_state;
};

}
#endif
