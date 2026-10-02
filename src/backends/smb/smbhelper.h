// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBHELPER_H
#define NETVFS_SMBHELPER_H

#include "smbshares.h"

#include <atomic>

namespace NetVfs::Smb {

// SPEC-v2 XM-7: the installed share enumeration helper. The environment
// variable NETVFS_SMB_SHARES_HELPER, when set, names another binary (the
// build tree's, for tests); it is read only when present, and whoever can
// set a process's environment controls that process anyway (LD_PRELOAD).
QString shareHelperPath();
bool shareHelperInstalled();

// Runs the helper: the request goes to its stdin (and is wiped, XSEC-6),
// its stdout is read up to MaxShareOutputBytes. The helper is killed on
// `cancel` (Canceled) and after `timeoutMs` (Timeout). A crash, a non-zero
// exit without an error line, or malformed output is ProtocolError.
Result runShareHelper(const QString &program, QByteArray *request, int timeoutMs, const std::atomic<bool> &cancel,
                      QVector<ShareInfo> *shares);

} // namespace NetVfs::Smb

#endif
