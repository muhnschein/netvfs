// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_STATEMUTEX_H
#define NETVFS_STATEMUTEX_H

#include <mutex>

// Internal. Mutex of a shared state object; only hands out locks, so fields stay plain data.
// std::mutex for the TSan reason in boundedpipe.cpp.
namespace NetVfs {

class StateMutex
{
public:
    std::unique_lock<std::mutex> lock() const { return std::unique_lock<std::mutex>(m_mutex); }

private:
    mutable std::mutex m_mutex;
};

}
#endif
