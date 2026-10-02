// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sshkeytools.h"
#include "sftpsupport.h"
#include "sshutil.h"

namespace NetVfs::Sftp {

namespace {

// S-15 checks on the parsed key, then the material: private key re-exported
// unencrypted in OpenSSH format, authorized_keys line and fingerprint.
Result fillMaterial(ssh_key key, SshKeyMaterial *out)
{
    ssh_key exported = nullptr;
    if (ssh_pki_export_privkey_to_pubkey(key, &exported) != SSH_OK)
        return Result(Error::Internal, QStringLiteral("Cannot derive the public key"));
    const KeyPtr publicKey(exported);

    const QString type = keyTypeName(publicKey.get());
    const QByteArray blob = publicKeyBlob(publicKey.get());
    const Result r = checkKeyType(type, rsaBitsFromBlob(blob));
    if (!r.ok())
        return r;

    CString privateText;
    if (ssh_pki_export_privkey_base64_format(key, nullptr, nullptr, nullptr, privateText.out(),
                                             SSH_FILE_FORMAT_OPENSSH) != SSH_OK || !privateText.get())
        return Result(Error::Internal, QStringLiteral("Cannot export the private key"));

    if (out) {
        out->wipe();
        out->privateKey = privateText.bytes();
        out->algorithm = type;
        out->publicLine = QStringLiteral("%1 %2 %3")
                              .arg(type, QString::fromLatin1(blob.toBase64()), QLatin1String(PublicKeyComment));
        out->fingerprint = sha256Fingerprint(publicKey.get());
    }
    return Result::success();
}

} // namespace

Result generateKey(SshKeyMaterial *out)
{
    ensureLibraryInitialized();
    ssh_key generated = nullptr;
    if (ssh_pki_generate_key(SSH_KEYTYPE_ED25519, nullptr, &generated) != SSH_OK)
        return Result(Error::Internal, QStringLiteral("Key generation failed"));
    const KeyPtr key(generated);
    return fillMaterial(key.get(), out);
}

Result importKey(const QByteArray &fileContents, const QByteArray &passphrase, SshKeyMaterial *out)
{
    ensureLibraryInitialized();
    const KeyFileInfo info = inspectKeyFile(fileContents);
    Result r = checkKeyFile(info);
    if (!r.ok())
        return r;
    KeyPtr key;
    r = importPrivateKey(fileContents, passphrase, &key);
    if (!r.ok() && info.encrypted) {
        return Result(Error::AuthFailed, passphrase.isEmpty()
                                             ? QStringLiteral("The key is protected by a passphrase")
                                             : QStringLiteral("The passphrase is not correct"));
    }
    if (!r.ok())
        return r;
    return fillMaterial(key.get(), out);
}

Result describeKey(const QByteArray &privateKey, SshKeyMaterial *out)
{
    return importKey(privateKey, QByteArray(), out);
}

} // namespace NetVfs::Sftp
