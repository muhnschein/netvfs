// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CLI_H
#define NETVFS_CLI_H

#include <QtCore/QStringList>

class QIODevice;
class QTextStream;

namespace NetVfs::Cli {
int run(const QStringList &arguments, QTextStream &out, QTextStream &err, QIODevice *promptInput = nullptr);

}
#endif
