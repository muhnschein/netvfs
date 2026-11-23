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
QByteArray referenceServe(Accounts::Manager *manager, const QStringList &arguments);

}
}

#endif
