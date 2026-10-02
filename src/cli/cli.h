// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CLI_H
#define NETVFS_CLI_H

#include <QtCore/QStringList>

class QTextStream;

namespace NetVfs {
namespace Cli {

// Runs one netvfs-cli invocation (SPEC 12.2); returns the process exit code.
// Exit codes: 0 success, 2 usage error, 10 + NetVfs::Error for failures.
int run(const QStringList &arguments, QTextStream &out, QTextStream &err);

} // namespace Cli
} // namespace NetVfs

#endif
