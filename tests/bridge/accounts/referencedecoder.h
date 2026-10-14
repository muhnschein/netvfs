// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_REFERENCEDECODER_H
#define NETVFS_TEST_REFERENCEDECODER_H

#include "accountstore.h"
#include "types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QVector>

// SPEC-v2 XB-2a: the answers of netvfs-accounts as the C++ bridge of netvfs
// 0.4 decoded them (its AccountsHelper), kept as the reference that reads
// the Rust helper's bytes back for the golden tests. The bridge itself is
// Rust now and decodes them in rust/netvfs-bridge/src/accounts/qds.rs.
//
// Two definitions, not NetVfs::Test: the moc of Qt 5.6 (Sailfish OS) cannot
// parse a nested namespace definition.
namespace NetVfs { // NOSONAR(cpp:S5812)
namespace Test {

// A netvfs account with the Files service enabled, as `list` reports it.
struct AccountLocation {
    int accountId = 0;
    QString provider;
    QString displayName;
    ConnectionParams params;
    QString filesRoot;
    Attention attention = Attention::None;
};

// What `files <id>` answers, ready for the secret lookup.
struct FilesAccess {
    ConnectionParams params;       // paramsForService(Files)
    quint32 credentialsId = 0;
    bool secretOptional = false;   // XA-7
};

// A malformed answer is ProtocolError; otherwise the helper's own result.
// The format is that of a QDataStream of version Qt_5_6: the qint32 error
// and the QString message, then for
//   list   qint32 count, per account: qint32 id, QString provider and
//          display name, the parameters, QString files root, qint32 attention
//   files  the parameters, quint32 credentials id, bool secret optional
// where the parameters are QString provider, QString host, qint32 port,
// QString username, QVariantMap options, qint32 connect and request timeout.
Result decodeList(const QByteArray &answer, QVector<AccountLocation> *accounts);
Result decodeFiles(const QByteArray &answer, FilesAccess *access);
Result decodeStatus(const QByteArray &answer);

} // namespace Test
} // namespace NetVfs

#endif
