// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SSHUTIL_H
#define NETVFS_SSHUTIL_H

#include "error.h"
#include "types.h"

#include <libssh/callbacks.h>
#include <libssh/libssh.h>

#include <QtCore/QStringList>

#include <memory>

namespace NetVfs::Sftp {

// S-4: ssh_init() exactly once per process.
void ensureLibraryInitialized();

struct KeyDeleter {
    void operator()(ssh_key key) const { ssh_key_free(key); }
};
using KeyPtr = std::unique_ptr<ssh_key_struct, KeyDeleter>;

// Takes ownership of a libssh-allocated string and wipes it before freeing.
class CString
{
public:
    CString() = default;
    CString(const CString &) = delete;
    CString &operator=(const CString &) = delete;
    ~CString();

    char **out() { return &m_data; }
    const char *get() const { return m_data; }
    QByteArray bytes() const { return QByteArray(m_data); }

private:
    char *m_data = nullptr;
};

QString keyTypeName(ssh_key key);
QByteArray publicKeyBlob(ssh_key key);         // raw wire blob of the public part
QString sha256Fingerprint(ssh_key key);         // "SHA256:..." (S-6)
ServerIdentity identityOf(ssh_key key);

// libssh keeps only its last error message, and a socket error in the same
// poll round can replace "kex error ..." after a failed key exchange (S-2).
// While an ErrorTrail exists, the messages libssh records on this thread are
// collected as well; libssh reports them to its thread-local log callback at
// SSH_LOG_TRACE. Afterwards the callback stays installed but idle.
class ErrorTrail
{
public:
    ErrorTrail();
    ErrorTrail(const ErrorTrail &) = delete;
    ErrorTrail &operator=(const ErrorTrail &) = delete;
    ~ErrorTrail();

    void record(const char *message);
    // The key exchange failure, if one was recorded; otherwise `last`.
    QString explain(const QString &last) const;

private:
    QStringList m_messages;
    int m_previousLevel = 0;
};

// S-12: ssh_pki_import_privkey_base64() on the whole key file text. Never
// prompts: without a passphrase an encrypted key simply fails. The copies
// made for libssh are wiped.
Result importPrivateKey(const QByteArray &text, const QByteArray &passphrase, KeyPtr *key);

} // namespace NetVfs::Sftp

#endif
