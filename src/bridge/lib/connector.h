// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_CONNECTOR_H
#define NETVFS_BRIDGE_CONNECTOR_H

#include "knownhosts.h"
#include "questions.h"
#include "worker.h"

namespace NetVfs::Bridge {

class BridgeServer;

// SPEC-v2 XB-12, XB-14, C-7: how the bridge opens a connection.
//  - Accounts: parameters and secret from the accounts database and signond
//    (fetched on the main thread), then NetVfs::establish(): connect, check
//    the identity against the account's pin, only then authenticate. An
//    identity or authentication failure is returned as an error and sets the
//    account's attention state as Buteo does; resolution happens in Settings.
//  - Ad-hoc: connect, check the identity against this consumer's
//    known_hosts. An unknown identity becomes Question(identity-unknown) with
//    the full ServerIdentity; an accepted one is pinned. A changed identity is
//    ServerIdentityChanged (re-pinning needs ForgetAdHoc). Only then the
//    secret the consumer gave is used.
//  - Keyboard-interactive prompts are relayed as Question(keyboard-interactive)
//    to the session whose request opened the connection; cancel ends the wait.
class BridgeConnector : public Connector
{
public:
    BridgeConnector(BridgeServer *server, KnownHosts *knownHosts, int questionTimeoutMs);

    Result establish(Backend *backend, const LocationSpec &spec, const TaskContext &context) override;

    // Worker thread: asks the session and waits (false: declined, canceled,
    // timed out or no session).
    bool ask(const TaskContext &context, const QString &kind, const QVariantMap &details, QuestionAnswer *answer);

    static QVariantMap identityDetails(const ServerIdentity &identity, const LocationSpec &spec);

private:
    Result establishAccount(Backend *backend, const LocationSpec &spec, const TaskContext &context);
    Result establishAdHoc(Backend *backend, const LocationSpec &spec, const TaskContext &context);
    Result checkAdHocIdentity(const ServerIdentity &seen, const LocationSpec &spec, const TaskContext &context);

    BridgeServer *m_server;
    KnownHosts *m_knownHosts;
    int m_questionTimeoutMs;
};

// AuthPrompter for one establish (XC-15), relaying through questions.
class QuestionPrompter : public AuthPrompter
{
public:
    QuestionPrompter(BridgeConnector *connector, const TaskContext &context);
    bool answer(const QString &name, const QString &instruction, const QVector<AuthPrompt> &prompts,
                QVector<QByteArray> *answers) override;

private:
    BridgeConnector *m_connector;
    TaskContext m_context;
};

} // namespace NetVfs::Bridge

#endif
