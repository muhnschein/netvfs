// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TYPES_H
#define NETVFS_TYPES_H

#include "netvfs_global.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QString>
#include <QtCore/QVariantMap>

namespace NetVfs {

struct Entry {
    QString name;
    qint64 size = 0;
    QDateTime modified;
    bool isDir = false;
};

// Server identity as seen during connect(). Empty for protocols without one (SMB).
struct NETVFS_EXPORT ServerIdentity {
    QString algorithm;      // e.g. "ssh-ed25519"
    QByteArray publicKey;   // raw key blob
    QString fingerprint;    // "SHA256:..." as printed by ssh-keygen -lf

    bool isEmpty() const { return publicKey.isEmpty(); }

    // Pin format stored in the account: "<algorithm> <base64 blob>".
    QString toPin() const;
    static ServerIdentity fromPin(const QString &pin);

    friend bool operator==(const ServerIdentity &a, const ServerIdentity &b)
    {
        return a.algorithm == b.algorithm && a.publicKey == b.publicKey;
    }
    friend bool operator!=(const ServerIdentity &a, const ServerIdentity &b) { return !(a == b); }
};

// Connection parameters. Provider-specific values live in `options`, keyed
// without the "netvfs/<provider>/" prefix (for example "host_key", "share").
struct ConnectionParams {
    QString provider;       // "sftp", "smb", ...
    QString host;
    int port = 0;           // 0: protocol default
    QString username;
    QVariantMap options;
    int connectTimeoutMs = 15000;   // SPEC C-14
    int requestTimeoutMs = 60000;   // SPEC C-14

    QString option(const QString &key, const QString &fallback = QString()) const
    {
        return options.value(key, fallback).toString();
    }
};

// Credentials; the secret is wiped on destruction (SEC-5).
class NETVFS_EXPORT Credentials
{
public:
    Credentials() = default;
    Credentials(const QString &userName, const QByteArray &secret);
    Credentials(const Credentials &other);
    Credentials &operator=(const Credentials &other);
    ~Credentials();

    QString userName;
    QByteArray secret;

    void wipe();
};

// Progress sink for streamed transfers. Called on the transferring thread.
class Progress
{
public:
    virtual ~Progress() = default;
    virtual void update(qint64 done, qint64 total) = 0;
};

} // namespace NetVfs

#endif
