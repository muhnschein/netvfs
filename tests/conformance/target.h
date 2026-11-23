// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CONFORMANCE_TARGET_H
#define NETVFS_CONFORMANCE_TARGET_H

#include "types.h"

#include <QtCore/QMap>
#include <QtCore/QVector>

namespace Conformance {
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
    bool trustOnFirstUse = false;
    QString baseDir;
    QString hostPath;
    int listCount = 10000;
    bool fifoStall = false;
    StallProxy stallProxy;
    QString restart;
    QMap<QString, QString> skip;
};

bool loadTargets(const QString &scratch, QVector<Target> *out, QString *error);

enum class Heavy { Skip, Cheap, Always };
Heavy heavyMode();

}

#endif
