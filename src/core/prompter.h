// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_PROMPTER_H
#define NETVFS_PROMPTER_H

#include "types.h"

#include <functional>
#include <memory>

namespace NetVfs {

// SPEC-v2 XC-15, XC-22: an AuthPrompter for consumers that ask the person
// on another thread than the backend's (a user interface, the bridge's
// Question/Answer relay, a terminal reader).
//
// answer() runs on the backend thread: it hands the question to `ask` and
// then waits until respond(), decline() or cancel() is called from any
// thread. Backend::cancel() calls cancel() while answer() waits, so a
// canceled sign-in never blocks on a person who does not answer. A cancel()
// stays in effect for later questions until reset().
//
// The answers handed to respond() are copied once into the backend's
// vector and the copy held here is wiped (SEC-5, XSEC-6); the caller wipes
// its own.
class NETVFS_EXPORT BlockingPrompter : public AuthPrompter
{
public:
    struct Question {
        QString name;
        QString instruction;
        QVector<AuthPrompt> prompts;
    };
    // Called on the backend thread with the question; must not block (hand
    // it to the thread that asks the person and return).
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
    // Clears a previous cancel().
    void reset();
    // True while answer() waits for respond()/decline()/cancel().
    bool waiting() const;

    struct State;

private:
    std::unique_ptr<State> m_state;
};

} // namespace NetVfs

#endif
