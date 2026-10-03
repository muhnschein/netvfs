// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_STATEMUTEX_H
#define NETVFS_STATEMUTEX_H

#include <mutex>

// Internal to the core library (not installed): the mutex of a shared state
// object. It only hands out locks, so no other access to it is possible and
// the state's fields can stay plain data. std::mutex rather than QMutex for
// the reason given in boundedpipe.cpp (ThreadSanitizer).
namespace NetVfs {

class StateMutex
{
public:
    std::unique_lock<std::mutex> lock() const { return std::unique_lock<std::mutex>(m_mutex); }

private:
    mutable std::mutex m_mutex;
};

} // namespace NetVfs

#endif
