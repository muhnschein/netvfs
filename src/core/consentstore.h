// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CONSENTSTORE_H
#define NETVFS_CONSENTSTORE_H

#include "error.h"

#include <QtCore/QString>
#include <QtCore/QVector>

namespace NetVfs {

// Consumer of netvfs-bridge, registered by /usr/share/netvfs/consumers/<id>.conf
// (NETVFS_CONSUMERS_DIR overrides):
// [Consumer]
// Id=lautta
// DisplayName=Lautta
// Executable=/usr/bin/harbour-lautta
// DataDir=.local/share/org.netvfs/lautta
struct NETVFS_EXPORT ConsumerInfo {
    QString id;
    QString displayName;
    QString executable;
    QString dataDir;
    static bool isValidId(const QString &id);
    static bool isValidDataDir(const QString &dataDir);
    static bool isValidExecutable(const QString &executable);
};

// Per-consumer decision in ~/.config/netvfs/bridge.conf ([Consent] <id>=granted or denied).
enum class Consent { Unknown, Granted, Denied };

NETVFS_EXPORT QString consentToString(Consent consent);
NETVFS_EXPORT Consent consentFromString(const QString &value);

class NETVFS_EXPORT ConsentStore
{
public:
    ConsentStore();
    explicit ConsentStore(const QString &filePath);

    static QString defaultFilePath();
    QString filePath() const { return m_path; }

    // Reads the file on every call.
    Consent consent(const QString &id) const;
    void setConsent(const QString &id, Consent consent) const;

    static QString consumersDir();
    static QVector<ConsumerInfo> consumers();
    static Result loadConsumer(const QString &id, ConsumerInfo *out);
    static Result parseConsumerFile(const QString &path, ConsumerInfo *out);

private:
    QString m_path;
};

}
#endif
