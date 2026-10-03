// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CONSENTSTORE_H
#define NETVFS_CONSENTSTORE_H

#include "error.h"

#include <QtCore/QString>
#include <QtCore/QVector>

namespace NetVfs {

// SPEC-v2 XB-3: a consumer of netvfs-bridge, registered by
// /usr/share/netvfs/consumers/<id>.conf (directory overridable with
// NETVFS_CONSUMERS_DIR):
//
//   [Consumer]
//   Id=lautta
//   DisplayName=Lautta
//   Executable=/usr/bin/harbour-lautta
//   DataDir=.local/share/org.netvfs/lautta
struct NETVFS_EXPORT ConsumerInfo {
    QString id;               // [a-z0-9-]+, equal to the file name stem
    QString displayName;      // non-empty
    QString executable;       // absolute, normalised
    QString dataDir;          // relative to $HOME, no "." or ".." components

    // Shared rules (the systemd generator applies the same ones).
    static bool isValidId(const QString &id);
    static bool isValidDataDir(const QString &dataDir);
    static bool isValidExecutable(const QString &executable);
};

// SPEC-v2 XB-6: the user's decision per consumer, stored in
// ~/.config/netvfs/bridge.conf ([Consent] <id>=granted|denied).
enum class Consent { Unknown, Granted, Denied };

NETVFS_EXPORT QString consentToString(Consent consent);      // "unknown", "granted", "denied"
NETVFS_EXPORT Consent consentFromString(const QString &value);

class NETVFS_EXPORT ConsentStore
{
public:
    // The default file ($XDG_CONFIG_HOME/netvfs/bridge.conf).
    ConsentStore();
    explicit ConsentStore(const QString &filePath);

    static QString defaultFilePath();
    QString filePath() const { return m_path; }

    // Reads the file on every call, so changes by other processes are seen.
    Consent consent(const QString &id) const;
    // Unknown removes the entry.
    void setConsent(const QString &id, Consent consent) const;

    // Registered consumers, sorted by id; invalid files are skipped with a warning.
    static QString consumersDir();
    static QVector<ConsumerInfo> consumers();
    // Loads and validates <consumersDir>/<id>.conf.
    static Result loadConsumer(const QString &id, ConsumerInfo *out);
    static Result parseConsumerFile(const QString &path, ConsumerInfo *out);

private:
    QString m_path;
};

} // namespace NetVfs

#endif
