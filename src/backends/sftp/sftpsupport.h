// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SFTPSUPPORT_H
#define NETVFS_SFTPSUPPORT_H

#include "error.h"
#include "types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <cstddef>
#include <cstdint>
#include <functional>

// Policy and mapping helpers of the SFTP backend that need no server. They
// only use libssh constants, so the unit tests compile this file directly.
namespace NetVfs::Sftp {

constexpr const char *AuthModePassword = "password";
constexpr const char *AuthModePublicKey = "publickey";
constexpr const char *AuthModeInteractive = "interactive";   // XS-11

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
Result interactiveDeclined();

// --- keyboard-interactive (S-11, XS-11) ---------------------------------------

// What to do with one SSH_AUTH_INFO round of `prompts` prompts.
enum class RoundAction {
    Acknowledge,        // no prompts (OpenSSH sends one after PAM succeeded)
    AnswerWithSecret,   // S-11: the stored password answers a single non-echo prompt
    AskPrompter,        // XS-11
    Refuse              // S-11: any other shape without a prompter
};
// `secretUsable`: password mode and the stored password has not answered a
// round yet. Without a prompter this is exactly S-11 (the prompt's text does
// not matter). With one, the stored password only answers a prompt that
// asks for a password (`passwordPrompt`, isPasswordPrompt()); a one-time
// code is never answered with it.
RoundAction keyboardInteractiveAction(int prompts, bool firstEchoes, bool passwordPrompt, bool secretUsable,
                                      bool hasPrompter);
bool isPasswordPrompt(const QString &text);

enum class PromptOutcome { Answered, Declined, BadAnswers, Rejected };
// One round through `prompter`: the answers come back in `*answers` (the
// caller's), each goes to `setAnswer(index, answer)`, and every answer is
// overwritten with zero bytes before this returns, whatever the outcome
// (SEC-5, XSEC-6). BadAnswers: not one answer per prompt. Rejected:
// `setAnswer` failed.
PromptOutcome promptRound(AuthPrompter *prompter, const QString &name, const QString &instruction,
                          const QVector<AuthPrompt> &prompts, QVector<QByteArray> *answers,
                          const std::function<bool(int, const QByteArray &)> &setAnswer);

// --- channels, links, attributes, resume --------------------------------------

// XC-21: a refused channel open. OpenSSH refuses a session channel beyond
// MaxSessions as "administratively prohibited" (reason 1): TooManyConnections.
Result channelOpenFailure(const QString &sshMessage);

// XS-4: how sftp_symlink(target, link) has to be called so that the link
// is created at `link`. libssh sends OpenSSH's (reversed) argument order to
// servers whose banner says OpenSSH and the draft's order to all others;
// server families with a verified order are listed in sftpsupport.cpp.
enum class SymlinkOrder {
    Unverified,   // unknown server: makeSymlink is Unsupported
    AsLibssh,     // sftp_symlink(target, link)
    Swapped       // the server wants OpenSSH's order without an OpenSSH banner
};
SymlinkOrder symlinkOrderFor(const QString &serverBanner, bool openSshBanner);
// XC-7: servers whose SSH_FXP_LSTAT follows a symlink in the last path
// component (ProFTPD mod_sftp); the backend then asks READLINK as well.
bool lstatFollowsLinks(const QString &serverBanner);

// XC-13: Resume continues only at the current remote size; anything else
// is the ProtocolError Transfer and the other backends report.
Result checkResumeOffset(qint64 remoteSize, qint64 resumeOffset);

// XC-11, XS-5: SFTP v3 stores permission bits (07777) and 32-bit unsigned
// seconds; anything outside is refused before anything changes.
Result checkAttributeChanges(const AttributeChanges &changes);

// Secret / auth_mode consistency (SPEC-sftp 2): the backend never sends a
// key secret as a password and never treats a password as a key.
Result checkSecretForMode(const QString &authMode, const QByteArray &secret);

// --- private key files (S-15) -----------------------------------------------

struct KeyFileInfo {
    enum class Format { Unknown, OpenSsh, Pem, PublicKey };
    Format format = Format::Unknown;
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
