// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CONFORMANCE_TARGET_H
#define NETVFS_CONFORMANCE_TARGET_H

#include "types.h"

#include <QtCore/QMap>
#include <QtCore/QVector>

// one backend instance under test. The JSON format is
// described in tests/conformance/README.md.
namespace Conformance {

// A second way into the same server through a proxy that can stop
// answering (sftpproxy.py, flipproxy.py, httpstall.py, ftpstall.py).
struct StallProxy {
    NetVfs::ConnectionParams params;
    QString engage;
    QString release;
    bool enabled = false;
};

struct Target {
    QString name;
    NetVfs::ConnectionParams params;
    QString user;
    QString secretEnv;
    bool trustOnFirstUse = false;      // accept the identity seen when no host_key is set
    QString baseDir;
    QString hostPath;
    int listCount = 10000;
    bool fifoStall = false;
    StallProxy stallProxy;
    QString restart;
    QMap<QString, QString> skip;
};

// Targets from $NETVFS_CONFORMANCE_CONFIG, else the default: the local
// backend in two configurations below `scratch` (a fresh temporary folder).
// $NETVFS_CONFORMANCE_TARGETS (comma separated names) narrows the list.
bool loadTargets(const QString &scratch, QVector<Target> *out, QString *error);

// $NETVFS_CONFORMANCE_HEAVY: "0" skips heavy cases, "1" runs them even
// where they are expensive (no hostPath); unset: run where cheap.
enum class Heavy { Skip, Cheap, Always };
Heavy heavyMode();

} // namespace Conformance

#endif
