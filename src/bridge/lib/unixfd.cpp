// SPDX-License-Identifier: LGPL-2.1-or-later
#include "unixfd.h"

#include <unistd.h>

namespace NetVfs::Bridge {

struct UnixFd::Owner {
    explicit Owner(int f) : fd(f) {}
    ~Owner()
    {
        if (fd >= 0)
            ::close(fd);
    }
    Owner(const Owner &) = delete;
    Owner &operator=(const Owner &) = delete;
    int fd = -1;
};

UnixFd::UnixFd(int fd)
    : m_owner(fd >= 0 ? std::make_shared<Owner>(fd) : nullptr)
{
}

int UnixFd::fd() const
{
    return m_owner ? m_owner->fd : -1;
}

int UnixFd::take()
{
    if (!m_owner)
        return -1;
    const int fd = m_owner->fd;
    m_owner->fd = -1;
    m_owner.reset();
    return fd;
}

} // namespace NetVfs::Bridge
