// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_UNIXFD_H
#define NETVFS_BRIDGE_UNIXFD_H

#include <QtCore/QMetaType>

#include <memory>

namespace NetVfs {
namespace Bridge {

// A file descriptor received in a message (D-Bus "h"). The descriptor is
// owned and closed when the last copy goes away, unless take() moved it out.
class UnixFd
{
public:
    UnixFd() = default;
    explicit UnixFd(int fd);

    int fd() const;                   // -1 if none (or taken)
    bool isValid() const { return fd() >= 0; }
    int take();                       // the caller owns the result

private:
    struct Owner;
    std::shared_ptr<Owner> m_owner;
};

} // namespace Bridge
} // namespace NetVfs

Q_DECLARE_METATYPE(NetVfs::Bridge::UnixFd)

#endif
