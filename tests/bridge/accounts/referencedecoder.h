// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_REFERENCEDECODER_H
#define NETVFS_TEST_REFERENCEDECODER_H

#include "accountstore.h"
#include "types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QVector>

namespace NetVfs { // NOSONAR
namespace Test {

struct AccountLocation {
    int accountId = 0;
    QString provider;
    QString displayName;
    ConnectionParams params;
    QString filesRoot;
    Attention attention = Attention::None;
};

struct FilesAccess {
    ConnectionParams params;
    quint32 credentialsId = 0;
    bool secretOptional = false;
};

Result decodeList(const QByteArray &answer, QVector<AccountLocation> *accounts);
Result decodeFiles(const QByteArray &answer, FilesAccess *access);
Result decodeStatus(const QByteArray &answer);

}
}

#endif
