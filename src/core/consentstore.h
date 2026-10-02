// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CONSENTSTORE_H
#define NETVFS_CONSENTSTORE_H

#include "netvfs_global.h"

#include <QtCore/QString>
#include <QtCore/QVector>

namespace NetVfs {

// SPEC-v2 XB-6: whether the user lets a sandboxed consumer use netvfs
// locations through netvfs-bridge.
enum class Consent { Unknown, Granted, Denied };

// A consumer registered by /usr/share/netvfs/consumers/<id>.conf (XB-3).
struct ConsumerInfo {
    QString id;
    QString displayName;   // falls back to the id
    QString executable;
    QString dataDir;
};

// Consent per consumer in ~/.config/netvfs/bridge.conf (INI):
//
//   [Consent]
//   lautta=granted
//
// Written by the settings page ("Apps using network locations") and by the
// bridge's notification actions; read by the bridge. Every setConsent()
// writes the file at once, so the file is the contract: the bridge watches
// it (QFileSystemWatcher) and closes a revoked consumer's connections
// immediately. QSettings may replace the file when writing, so a watcher
// re-adds the path (or watches the folder) after each change.
//
// Consumer ids are [A-Za-z0-9._-]+; any other id reads as Unknown and is
// never written.
class NETVFS_EXPORT ConsentStore
{
public:
    // `path` empty: defaultPath().
    explicit ConsentStore(const QString &path = QString());

    // $XDG_CONFIG_HOME/netvfs/bridge.conf (~/.config/netvfs/bridge.conf).
    static QString defaultPath();
    QString path() const { return m_path; }

    Consent consent(const QString &consumerId) const;
    // Unknown removes the entry. Returns false when the id is invalid or
    // the file could not be written.
    bool setConsent(const QString &consumerId, Consent consent);

    static QString consentToString(Consent consent);       // "unknown" | "granted" | "denied"
    static Consent consentFromString(const QString &value); // anything else: Unknown
    static bool isValidConsumerId(const QString &consumerId);

    // /usr/share/netvfs/consumers (NETVFS_CONSUMERS_DIR overrides it, for tests).
    static QString consumersDirectory();
    // The registered consumers, sorted by id. Files whose [Consumer] Id is
    // missing, invalid or different from the file's base name are skipped.
    static QVector<ConsumerInfo> consumers();

private:
    QString m_path;
};

} // namespace NetVfs

#endif
