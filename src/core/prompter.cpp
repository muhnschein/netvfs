// SPDX-License-Identifier: LGPL-2.1-or-later
#include "prompter.h"
#include "secure.h"
#include "statemutex.h"

#include <condition_variable>
#include <mutex>

namespace NetVfs {

// std::mutex rather than QMutex for the reason given in boundedpipe.cpp
// (ThreadSanitizer).
struct BlockingPrompter::State
{
    enum class Phase { Idle, Waiting, Answered, Declined };

    explicit State(const Ask &a) : ask(a) {}

    Ask ask;
    StateMutex guard;
    std::condition_variable changed;
    Phase phase = Phase::Idle;
    bool canceled = false;
    QVector<QByteArray> answers;

    void wipeAnswers()
    {
        for (QByteArray &answer : answers)
            secureWipe(answer);
        answers.clear();
    }
};

BlockingPrompter::BlockingPrompter(const Ask &ask) : m_state(std::make_unique<State>(ask)) {}

BlockingPrompter::~BlockingPrompter()
{
    m_state->wipeAnswers();
}

bool BlockingPrompter::answer(const QString &name, const QString &instruction, const QVector<AuthPrompt> &prompts,
                              QVector<QByteArray> *answers)
{
    {
        const auto lock = m_state->guard.lock();
        if (m_state->canceled)
            return false;
        m_state->wipeAnswers();
        m_state->phase = State::Phase::Waiting;
    }
    if (m_state->ask)
        m_state->ask(Question { name, instruction, prompts });

    auto lock = m_state->guard.lock();
    m_state->changed.wait(lock, [this]() { return m_state->canceled || m_state->phase != State::Phase::Waiting; });
    const bool answered = !m_state->canceled && m_state->phase == State::Phase::Answered;
    if (answered && answers) {
        // The backend's copies must not share data with ours, so that
        // wiping ours really overwrites the bytes we held.
        *answers = m_state->answers;
        for (QByteArray &answer : *answers)
            answer.detach();
    }
    m_state->wipeAnswers();
    m_state->phase = State::Phase::Idle;
    return answered;
}

void BlockingPrompter::respond(const QVector<QByteArray> &answers)
{
    const auto lock = m_state->guard.lock();
    if (m_state->phase != State::Phase::Waiting)
        return;
    m_state->answers = answers;
    for (QByteArray &answer : m_state->answers)
        answer.detach();
    m_state->phase = State::Phase::Answered;
    m_state->changed.notify_all();
}

void BlockingPrompter::decline()
{
    const auto lock = m_state->guard.lock();
    if (m_state->phase != State::Phase::Waiting)
        return;
    m_state->phase = State::Phase::Declined;
    m_state->changed.notify_all();
}

void BlockingPrompter::cancel()
{
    const auto lock = m_state->guard.lock();
    m_state->canceled = true;
    m_state->changed.notify_all();
}

void BlockingPrompter::reset()
{
    const auto lock = m_state->guard.lock();
    m_state->canceled = false;
}

bool BlockingPrompter::waiting() const
{
    const auto lock = m_state->guard.lock();
    return m_state->phase == State::Phase::Waiting;
}

} // namespace NetVfs
