// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sshutil.h"
#include "secure.h"

#include <cstring>
#include <mutex>

namespace NetVfs::Sftp {

namespace {
ErrorTrail *&activeTrail()
{
    thread_local ErrorTrail *trail = nullptr;
    return trail;
}
} // namespace

ErrorTrail::ErrorTrail()
    : m_previousLevel(ssh_get_log_level())
{
    activeTrail() = this;
    // A generic lambda converts to ssh_logging_callback.
    ssh_set_log_callback([](int priority, const char *, const char *message, auto) {
        if (ErrorTrail *trail = activeTrail(); trail && priority == SSH_LOG_TRACE)
            trail->record(message);
    });
    ssh_set_log_level(SSH_LOG_TRACE);
}

ErrorTrail::~ErrorTrail()
{
    ssh_set_log_level(m_previousLevel);
    activeTrail() = nullptr;
}

void ErrorTrail::record(const char *message)
{
    if (const QString line = QString::fromUtf8(message); line.contains(QLatin1String("kex error")))
        m_messages << line;
}

QString ErrorTrail::explain(const QString &last) const
{
    if (m_messages.isEmpty() || last.contains(QLatin1String("kex error")))
        return last;
    // "function: message" as libssh formats it for callbacks.
    const QString first = m_messages.constFirst();
    return first.mid(first.indexOf(QLatin1String("kex error")));
}

void ensureLibraryInitialized()
{
    static std::once_flag once;
    std::call_once(once, [] { ssh_init(); });
}

CString::~CString()
{
    if (m_data) {
        volatile char *p = m_data;
        for (size_t n = std::strlen(m_data); n > 0; --n)
            *p++ = 0;
        ssh_string_free_char(m_data);
    }
}

QString keyTypeName(ssh_key key)
{
    const char *name = ssh_key_type_to_char(ssh_key_type(key));
    return name ? QString::fromLatin1(name) : QString();
}

QByteArray publicKeyBlob(ssh_key key)
{
    CString base64;
    if (ssh_pki_export_pubkey_base64(key, base64.out()) != SSH_OK || !base64.get())
        return QByteArray();
    return QByteArray::fromBase64(base64.bytes());
}

QString sha256Fingerprint(ssh_key key)
{
    unsigned char *hash = nullptr;
    size_t length = 0;
    if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &length) != SSH_OK)
        return QString();
    CString text;
    *text.out() = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, length);
    ssh_clean_pubkey_hash(&hash);
    return QString::fromLatin1(text.get());
}

ServerIdentity identityOf(ssh_key key)
{
    ServerIdentity identity;
    identity.algorithm = keyTypeName(key);
    identity.publicKey = publicKeyBlob(key);
    identity.fingerprint = sha256Fingerprint(key);
    return identity;
}

Result importPrivateKey(const QByteArray &text, const QByteArray &passphrase, KeyPtr *key)
{
    QByteArray terminated(text.constData(), text.size());
    QByteArray pass(passphrase.constData(), passphrase.size());
    // An empty (not NULL) passphrase: with NULL, OpenSSL's default PEM
    // callback would prompt on the terminal for an encrypted key.
    ssh_key parsed = nullptr;
    const int rc = ssh_pki_import_privkey_base64(terminated.constData(), pass.constData(), nullptr, nullptr,
                                                 &parsed);
    secureWipe(terminated);
    secureWipe(pass);
    if (rc != SSH_OK)
        return Result(Error::Unsupported, QStringLiteral("The file is not a key this app can use (Ed25519, "
                                                         "ECDSA or RSA in OpenSSH or PEM format)"));
    key->reset(parsed);
    return Result::success();
}

} // namespace NetVfs::Sftp
