// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_KNOWNHOSTS_H
#define NETVFS_BRIDGE_KNOWNHOSTS_H

#include <QtCore/QHash>
#include <QtCore/QString>

#include <mutex>

// SPEC-v2 XB-14: identities the user accepted for ad-hoc locations of one
// consumer, in ~/.local/share/netvfs/bridge/<id>/known_hosts. One line per
// endpoint: "<provider>://<host>:<port> <pin>" (pin as ServerIdentity::toPin).
// Thread-safe: workers read pins during establish.
namespace NetVfs::Bridge {

class KnownHosts
{
public:
    explicit KnownHosts(const QString &filePath);

    static QString defaultFilePath(const QString &consumerId);

    QString pin(const QString &key) const;
    bool setPin(const QString &key, const QString &pin);
    bool remove(const QString &key);

private:
    struct State {
        QHash<QString, QString> pins;
        bool loaded = false;
    };
    static void load(const QString &path, State *state);
    static bool save(const QString &path, const State &state);

    QString m_path;
    mutable std::mutex m_mutex;
    mutable State m_state;      // guarded by m_mutex, loaded on first use
};

} // namespace NetVfs::Bridge

#endif
