// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SSHKEYS_H
#define NETVFS_SSHKEYS_H

#include "backend.h"

#include <QtCore/QObject>

namespace NetVfs {

// Private part wiped on destruction; copies are deep.
struct NETVFS_EXPORT SshKeyMaterial {
    SshKeyMaterial() = default;
    SshKeyMaterial(const SshKeyMaterial &other);
    SshKeyMaterial &operator=(const SshKeyMaterial &other);
    ~SshKeyMaterial();

    QByteArray privateKey;
    QString algorithm;
    QString publicLine;
    QString fingerprint;
    void wipe();
};

// SSH key operations (rust/netvfs-sftp), implemented by the SFTP plugin's root object so SSH code
// lives only in the SFTP package. Obtain with BackendLoader::sshKeyTools().
class NETVFS_EXPORT SshKeyTools
{
public:
    virtual ~SshKeyTools();

    virtual Result generate(SshKeyMaterial *out) = 0;
    // Accepts Ed25519 and ECDSA in OpenSSH, PKCS#8 or SEC1 format. AuthFailed when encrypted and
    // `passphrase` missing or wrong; Unsupported for other types and formats.
    virtual Result importKey(const QByteArray &fileContents, const QByteArray &passphrase,
                             SshKeyMaterial *out) = 0;
    virtual Result describe(const QByteArray &privateKey, SshKeyMaterial *out) = 0;
};

// Secret = "netvfs-key-v1:" + base64(private key, OpenSSH format).
NETVFS_EXPORT extern const char KeySecretPrefix[];
NETVFS_EXPORT QByteArray encodeKeySecret(const QByteArray &privateKey);
NETVFS_EXPORT bool isKeySecret(const QByteArray &secret);
NETVFS_EXPORT bool decodeKeySecret(const QByteArray &secret, QByteArray *privateKey);

// On an authenticated backend: creates ".ssh" (0700), appends `publicLine` to
// ".ssh/authorized_keys" (0600) unless present. File replaced via .part and rename.
NETVFS_EXPORT Result installAuthorizedKey(Backend *backend, const QString &publicLine);

}
Q_DECLARE_INTERFACE(NetVfs::SshKeyTools, "org.netvfs.SshKeyTools")

#endif
