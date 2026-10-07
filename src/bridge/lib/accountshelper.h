// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_ACCOUNTSHELPER_H
#define NETVFS_BRIDGE_ACCOUNTSHELPER_H

#include "location.h"

#include <QtCore/QByteArray>
#include <QtCore/QStringList>

#include <functional>
#include <memory>
#include <vector>

namespace Accounts {
class Manager;
}

class QDBusMessage;
class QProcess;
class QTimer;

// SPEC-v2 XB-2a: on Sailfish OS only the group `privileged` can read the
// accounts database. The bridge itself runs without it; the one program that
// has it is /usr/libexec/netvfs/netvfs-accounts (setgid privileged), which
// links no backend and talks to no server. The bridge starts it once per
// request:
//
//   netvfs-accounts list                          the Files accounts (XA-1)
//   netvfs-accounts files <id>                    what a connection to a listed
//                                                 account needs, policy checked (XA-4)
//   netvfs-accounts attention <id> <state> [pin]  records auth-failed or
//                                                 server-identity-changed (XB-14)
//
// and reads its answer from stdout. Secrets stay with signond: the bridge
// looks them up itself with the credentials id the helper reports.
//
// Two definitions, not NetVfs::Bridge: the moc of Qt 5.6 (Sailfish OS) cannot
// parse a nested namespace definition.
namespace NetVfs { // NOSONAR(cpp:S5812)
namespace Bridge {

// What `files <id>` answers, ready for the secret lookup.
struct FilesAccess {
    ConnectionParams params;       // paramsForService(Files)
    quint32 credentialsId = 0;
    bool secretOptional = false;   // XA-7
};

namespace AccountsHelper {

// The installed helper, or the one NETVFS_ACCOUNTS_HELPER names (the build
// tree's, for tests). Whoever sets the bridge's environment controls the
// bridge anyway; the helper itself ignores such variables when set-id.
QString path();

// The helper's side: answers `arguments` (without the program name) from
// `manager`. Always writes an answer, also for an error.
QByteArray serve(Accounts::Manager *manager, const QStringList &arguments);

// The bridge's side. A malformed answer is ProtocolError; otherwise the
// helper's own result.
Result decodeList(const QByteArray &answer, QVector<AccountLocation> *accounts);
Result decodeFiles(const QByteArray &answer, FilesAccess *access);
Result decodeStatus(const QByteArray &answer);

} // namespace AccountsHelper

// The bridge's account directory: everything through netvfs-accounts.
// libaccounts announces changes on the session bus (writers send the
// AccountChanged signal), which needs no access to the database.
class HelperAccountsDirectory : public AccountDirectory
{
    Q_OBJECT
public:
    explicit HelperAccountsDirectory(const QString &program = AccountsHelper::path(), QObject *parent = nullptr);
    ~HelperAccountsDirectory() override;

    QVector<AccountLocation> filesAccounts() override;
    void fetch(int accountId, const Fetched &done) override;
    void setAttention(int accountId, Attention attention, const QString &seenPin) override;

private Q_SLOTS:
    void onAccountChanged(const QDBusMessage &message);

private:
    using Finished = std::function<void(const Result &started, const QByteArray &answer)>;
    // Runs the helper without blocking; `finished` runs exactly once.
    void start(const QStringList &arguments, const Finished &finished);
    // Hands `process`'s answer to `finished` once, whichever of its signals
    // comes first.
    void finish(QProcess *process, const Result &result, const Finished &finished);

    QString m_program;
    QTimer *m_changed;
    std::vector<std::unique_ptr<QProcess>> m_running;
};

} // namespace Bridge
} // namespace NetVfs

#endif
