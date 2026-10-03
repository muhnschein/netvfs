// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_RUNTIME_H
#define NETVFS_BRIDGE_RUNTIME_H

#include <QtCore/QObject>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>

// Threading helpers of the bridge. The main thread owns every D-Bus
// connection and all bookkeeping; backends run on worker threads (C-8) and
// report back by posting functors to the MainQueue.
namespace NetVfs::Bridge {

// Lives for the whole process on the main thread; functors posted from any
// thread run there in order. Functors must not capture pointers to objects
// that may die meanwhile: capture ids and look them up.
class MainQueue : public QObject
{
public:
    explicit MainQueue(QObject *parent = nullptr);
    void post(std::function<void()> fn);

protected:
    bool event(QEvent *event) override;
};

// Cancellation of one request or job (XB-13). Set from the main thread,
// polled by workers, file descriptor devices and prompt waits.
struct CancelToken {
    std::atomic<bool> canceled { false };
    bool isCanceled() const { return canceled.load(); }
    void cancel() { canceled.store(true); }
};
using CancelTokenPtr = std::shared_ptr<CancelToken>;

// One value handed from the main thread to a waiting worker. wait() returns
// false when the token was canceled or the timeout passed first.
template <typename T>
class Rendezvous
{
public:
    void set(T value)
    {
        std::scoped_lock lock(m_mutex);
        if (m_done)
            return;
        m_value = std::move(value);
        m_done = true;
        m_cond.notify_all();
    }

    bool wait(const CancelToken *token, int timeoutMs, T *out)
    {
        using Clock = std::chrono::steady_clock;
        const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
        std::unique_lock lock(m_mutex);
        while (!m_done) {
            if ((token && token->isCanceled()) || Clock::now() >= deadline)
                return false;
            m_cond.wait_for(lock, std::chrono::milliseconds(PollSliceMs));
        }
        *out = std::move(m_value);   // moved: secrets keep a single owner (SEC-5)
        return true;
    }

private:
    static constexpr int PollSliceMs = 100;
    std::mutex m_mutex;
    std::condition_variable m_cond;
    T m_value {};
    bool m_done = false;
};

} // namespace NetVfs::Bridge

#endif
