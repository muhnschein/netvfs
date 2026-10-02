// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_HANDOFF_H
#define NETVFS_BRIDGE_HANDOFF_H

#include "error.h"

#include <QtCore/QString>
#include <QtCore/QVariantList>

#include <functional>

// SPEC-v2 XB-15: account changes happen in Settings. OpenAccountSettings and
// AddAccount call the platform's settings D-Bus interface on the session bus.
//
// Which entry points open a specific account page or the creation flow for a
// provider on Sailfish OS 5.2 is an open question (SPEC-v2 §14 Q4) that needs
// a device. The calls are therefore a table in a configuration file shipped
// with the package (/usr/share/netvfs/bridge/handoff.conf):
//
//   [OpenAccountSettings]
//   Service=com.jolla.settings
//   Path=/com/jolla/settings/ui
//   Interface=com.jolla.settings.ui
//   Method=showAccounts
//   Arguments=
//
// Arguments: ','-separated typed values "s:text", "i:42", "u:42", "b:true" (no commas
// inside a value), with the placeholders {accountId} and {provider}.
namespace NetVfs {
namespace Bridge {

struct HandoffCall {
    QString service;
    QString path;
    QString interface;
    QString method;
    QVariantList arguments;
};

class Handoff
{
public:
    using Launcher = std::function<Result(const HandoffCall &call)>;

    // Missing or invalid file: every handoff is Unsupported.
    explicit Handoff(const QString &configPath = defaultConfigPath());
    static QString defaultConfigPath();

    // Default launcher: asynchronous call on the session bus (no reply awaited).
    void setLauncher(const Launcher &launcher) { m_launcher = launcher; }

    Result openAccountSettings(int accountId, const QString &provider) const;
    Result addAccount(const QString &provider) const;

    // Exposed for tests: builds the call of `group` (InvalidName on a bad table).
    Result resolve(const QString &group, int accountId, const QString &provider, HandoffCall *out) const;

private:
    Result run(const QString &group, int accountId, const QString &provider) const;

    QString m_configPath;
    Launcher m_launcher;
};

} // namespace Bridge
} // namespace NetVfs

#endif
