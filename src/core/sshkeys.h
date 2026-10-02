// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SSHKEYS_H
#define NETVFS_SSHKEYS_H

#include "backend.h"

#include <QtCore/QObject>

namespace NetVfs {

// A key pair; the private part is wiped on destruction (SEC-5).
struct NETVFS_EXPORT SshKeyMaterial {
    SshKeyMaterial() = default;
    // Copies are deep so that wiping one copy never affects another.
    SshKeyMaterial(const SshKeyMaterial &other);
    SshKeyMaterial &operator=(const SshKeyMaterial &other);
    ~SshKeyMaterial();

    QByteArray privateKey;   // unencrypted, OpenSSH format ("-----BEGIN OPENSSH PRIVATE KEY-----")
    QString algorithm;       // "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", ...
    QString publicLine;      // authorized_keys line "<algorithm> <base64> sailfish-backup"
    QString fingerprint;     // "SHA256:..."

    void wipe();
};

// Key operations that need libssh. Implemented by the SFTP backend plugin's
// root object, so that libssh code lives only in the SFTP package
// (SPEC-sftp 5.1). Obtain with BackendLoader::sshKeyTools().
class NETVFS_EXPORT SshKeyTools
{
public:
    virtual ~SshKeyTools();

    // Ed25519 via ssh_pki_generate_key() (SPEC-sftp 5.1).
    virtual Result generate(SshKeyMaterial *out) = 0;
    // Accepts Ed25519, ECDSA and RSA in OpenSSH or PEM format. Returns
    // AuthFailed when the file is encrypted and `passphrase` is missing or
    // wrong, Unsupported for key types rejected by S-15.
    virtual Result importKey(const QByteArray &fileContents, const QByteArray &passphrase,
                             SshKeyMaterial *out) = 0;
    // Recomputes algorithm, public line and fingerprint from a private key.
    virtual Result describe(const QByteArray &privateKey, SshKeyMaterial *out) = 0;
};

// SPEC-sftp 2: Secret = "netvfs-key-v1:" + base64(private key, OpenSSH format).
NETVFS_EXPORT extern const char KeySecretPrefix[];
NETVFS_EXPORT QByteArray encodeKeySecret(const QByteArray &privateKey);
NETVFS_EXPORT bool isKeySecret(const QByteArray &secret);
// Returns false if `secret` is not a key secret or is malformed.
NETVFS_EXPORT bool decodeKeySecret(const QByteArray &secret, QByteArray *privateKey);

// SPEC-sftp S-17: on an authenticated backend, creates ".ssh" (0700) and
// appends `publicLine` to ".ssh/authorized_keys" (0600) unless an identical
// key is already present. The file is replaced via a .part file and rename.
NETVFS_EXPORT Result installAuthorizedKey(Backend *backend, const QString &publicLine);

} // namespace NetVfs

Q_DECLARE_INTERFACE(NetVfs::SshKeyTools, "org.netvfs.SshKeyTools/1.0")

#endif
