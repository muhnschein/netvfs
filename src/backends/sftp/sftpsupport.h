// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SFTPSUPPORT_H
#define NETVFS_SFTPSUPPORT_H

#include "error.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <cstddef>
#include <cstdint>

// Policy and mapping helpers of the SFTP backend that need no server. They
// only use libssh constants, so the unit tests compile this file directly.
namespace NetVfs::Sftp {

constexpr const char *AuthModePassword = "password";
constexpr const char *AuthModePublicKey = "publickey";

// SPEC-sftp S-21.
constexpr size_t MaxChunkSize = 256 * 1024;
constexpr size_t FallbackChunkSize = 32 * 1024;
constexpr size_t RequestWindow = 16;

// libssh RSA_MIN_KEY_SIZE (include/libssh/pki.h, not installed): the default
// minimum when SSH_OPTIONS_RSA_MIN_SIZE is not set (S-15).
constexpr int RsaMinimumBits = 1024;

// S-5: host key signature algorithms that belong to a pinned key type, or an
// empty array when the type is unknown (libssh defaults then apply, and the
// identity check refuses the key anyway).
QByteArray hostKeyAlgorithmsFor(const QString &pinnedType);

// S-21: the smaller of the server's limit and 256 KiB, or 32 KiB without limits.
size_t chunkSize(bool serverHasLimits, uint64_t serverLimit);

// Error mapping table (SPEC-sftp 7). `sshMessage` is ssh_get_error().
Result connectFailure(const QString &sshMessage);
// True for a key exchange failure about the host key algorithm (S-5 retry).
bool isHostKeyMismatch(const QString &sshMessage);
Result sftpStatusFailure(int sftpStatus, const QString &sshMessage, const QString &context);
// SFTP subsystem start-up failure; `requestDenied` is SSH_REQUEST_DENIED.
Result subsystemFailure(bool requestDenied, int sftpStatus, const QString &sshMessage);
// "SSH_FX_FAILURE during write while statvfs reports no free space" (7):
// the server reports less free space than the write that failed.
bool looksLikeFullDisk(int sftpStatus, qint64 freeBytes, qint64 attempted);

// S-14: human readable list of the methods in an ssh_userauth_list() mask.
QString acceptedMethodsText(int methods);
Result authDenied(int methods);
Result authPartial();
Result interactiveNotSupported();

// Secret / auth_mode consistency (SPEC-sftp 2): the backend never sends a
// key secret as a password and never treats a password as a key.
Result checkSecretForMode(const QString &authMode, const QByteArray &secret);

// --- private key files (S-15) -----------------------------------------------

struct KeyFileInfo {
    enum Format { Unknown, OpenSsh, Pem, PublicKey };
    Format format = Unknown;
    bool encrypted = false;
    QString keyType;        // from the OpenSSH container, the PEM label or a public line
};

KeyFileInfo inspectKeyFile(const QByteArray &contents);
// Unsupported with a clear message for DSA, security-key, certificate and
// public key files and for content that is no key at all; success otherwise.
Result checkKeyFile(const KeyFileInfo &info);
// Unsupported unless `keyType` is Ed25519, ECDSA or RSA of at least
// RsaMinimumBits bits.
Result checkKeyType(const QString &keyType, int rsaBits);
// Modulus size of an "ssh-rsa" public key blob, or 0.
int rsaBitsFromBlob(const QByteArray &publicKeyBlob);

} // namespace NetVfs::Sftp

#endif
