// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_REFERENCEHELPER_H
#define NETVFS_TEST_REFERENCEHELPER_H

#include <QtCore/QByteArray>
#include <QtCore/QStringList>

namespace Accounts {
class Manager;
}

namespace NetVfs {
namespace Test {

// The golden reference for netvfs-accounts: the C++ helper of netvfs 0.3
// (AccountsHelper::serve over libaccounts-qt and AccountStore), kept as it
// was. The Rust helper must answer every request with the same bytes, except
// for the text of a PermissionDenied message (which named libaccounts'
// error).
QByteArray referenceServe(Accounts::Manager *manager, const QStringList &arguments);

} // namespace Test
} // namespace NetVfs

#endif
