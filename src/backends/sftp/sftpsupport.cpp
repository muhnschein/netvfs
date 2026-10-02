// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sftpsupport.h"
#include "sshkeys.h"

#include <QtCore/QStringList>

#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <algorithm>
#include <array>

namespace NetVfs::Sftp {

namespace {

constexpr const char *OpenSshBegin = "-----BEGIN OPENSSH PRIVATE KEY-----";
constexpr const char *OpenSshEnd = "-----END OPENSSH PRIVATE KEY-----";
constexpr const char *CertificateSuffix = "-cert-v01@openssh.com";
constexpr const char *DsaType = "ssh-dss";

// Reads the big-endian SSH wire encoding (RFC 4251 section 5).
class WireReader
{
public:
    explicit WireReader(const QByteArray &data) : m_data(data) {}

    bool readUint32(quint32 *value)
    {
        if (m_data.size() - m_pos < 4)
            return false;
        quint32 result = 0;
        for (int i = 0; i < 4; ++i)
            result = (result << 8) | static_cast<uchar>(m_data.at(m_pos + i));
        *value = result;
        m_pos += 4;
        return true;
    }

    bool readString(QByteArray *value)
    {
        quint32 length = 0;
        if (!readUint32(&length) || length > static_cast<quint32>(m_data.size() - m_pos))
            return false;
        *value = m_data.mid(m_pos, static_cast<int>(length));
        m_pos += static_cast<int>(length);
        return true;
    }

private:
    const QByteArray m_data;
    int m_pos = 0;
};

QString keyTypeOfBlob(const QByteArray &blob)
{
    WireReader reader(blob);
    QByteArray type;
    return reader.readString(&type) ? QString::fromLatin1(type) : QString();
}

// "openssh-key-v1\0", cipher, kdf, kdf options, key count, first public key
// (PROTOCOL.key in OpenSSH). The public part is never encrypted.
bool parseOpenSshContainer(const QByteArray &binary, KeyFileInfo *info)
{
    const QByteArray magic("openssh-key-v1", 15);   // with the terminating NUL
    if (!binary.startsWith(magic))
        return false;
    WireReader reader(binary.mid(magic.size()));
    QByteArray cipher;
    QByteArray kdf;
    QByteArray kdfOptions;
    quint32 count = 0;
    QByteArray publicKey;
    if (!reader.readString(&cipher) || !reader.readString(&kdf) || !reader.readString(&kdfOptions)
            || !reader.readUint32(&count) || count < 1 || !reader.readString(&publicKey))
        return false;
    info->encrypted = cipher != "none";
    info->keyType = keyTypeOfBlob(publicKey);
    return !info->keyType.isEmpty();
}

KeyFileInfo inspectOpenSsh(const QByteArray &text)
{
    KeyFileInfo info;
    const int begin = text.indexOf(OpenSshBegin);
    const int end = text.indexOf(OpenSshEnd);
    if (begin < 0 || end < begin)
        return info;
    const int bodyStart = begin + static_cast<int>(qstrlen(OpenSshBegin));
    QByteArray body = text.mid(bodyStart, end - bodyStart).simplified();
    body.replace(' ', QByteArray());
    if (parseOpenSshContainer(QByteArray::fromBase64(body), &info))
        info.format = KeyFileInfo::OpenSsh;
    return info;
}

// The base64 payload between the first "-----BEGIN" and "-----END" lines.
QByteArray pemBody(const QByteArray &text)
{
    const int begin = text.indexOf('\n', text.indexOf("-----BEGIN"));
    const int end = text.indexOf("-----END");
    if (begin < 0 || end < begin)
        return QByteArray();
    return QByteArray::fromBase64(text.mid(begin + 1, end - begin - 1));
}

KeyFileInfo inspectPem(const QByteArray &text)
{
    struct Label {
        const char *label;
        const char *type;
        bool encrypted;
    };
    static const std::array<Label, 5> labels = { {
        { "-----BEGIN RSA PRIVATE KEY-----", "ssh-rsa", false },
        { "-----BEGIN EC PRIVATE KEY-----", "ecdsa", false },
        { "-----BEGIN DSA PRIVATE KEY-----", DsaType, false },
        { "-----BEGIN PRIVATE KEY-----", "", false },
        { "-----BEGIN ENCRYPTED PRIVATE KEY-----", "", true },
    } };
    KeyFileInfo info;
    for (const Label &entry : labels) {
        if (!text.contains(entry.label))
            continue;
        info.format = KeyFileInfo::Pem;
        info.keyType = QString::fromLatin1(entry.type);
        info.encrypted = entry.encrypted || text.contains("Proc-Type: 4,ENCRYPTED");
        break;
    }
    // PKCS#8 names the algorithm only inside the DER structure; DSA
    // (OID 1.2.840.10040.4.1) is the one S-15 needs to recognise there.
    if (info.format == KeyFileInfo::Pem && info.keyType.isEmpty() && !info.encrypted
            && pemBody(text).contains(QByteArray("\x06\x07\x2a\x86\x48\xce\x38\x04\x01", 9)))
        info.keyType = QString::fromLatin1(DsaType);
    return info;
}

KeyFileInfo inspectPublicLine(const QByteArray &text)
{
    KeyFileInfo info;
    if (const QList<QByteArray> fields = text.simplified().split(' ');
            fields.size() >= 2 && fields.at(1).startsWith("AAAA")) {
        info.format = KeyFileInfo::PublicKey;
        info.keyType = QString::fromLatin1(fields.at(0));
    }
    return info;
}

Result unsupportedKey(const QString &message)
{
    return Result(Error::Unsupported, message);
}

bool isCertificate(const QString &keyType)
{
    return keyType.endsWith(QLatin1String(CertificateSuffix));
}

bool isSecurityKey(const QString &keyType)
{
    return keyType.startsWith(QLatin1String("sk-"));
}

Result certificateRejected()
{
    return unsupportedKey(QStringLiteral("SSH certificates are not supported; choose a private key file"));
}

Result securityKeyRejected()
{
    return unsupportedKey(QStringLiteral("Security-key (FIDO) keys are not supported"));
}

} // namespace

QByteArray hostKeyAlgorithmsFor(const QString &pinnedType)
{
    if (pinnedType == QLatin1String("ssh-ed25519"))
        return QByteArrayLiteral("ssh-ed25519");
    if (pinnedType == QLatin1String("ecdsa-sha2-nistp256") || pinnedType == QLatin1String("ecdsa-sha2-nistp384")
            || pinnedType == QLatin1String("ecdsa-sha2-nistp521"))
        return pinnedType.toLatin1();
    if (pinnedType == QLatin1String("ssh-rsa"))
        return QByteArrayLiteral("rsa-sha2-512,rsa-sha2-256");
    return QByteArray();
}

size_t chunkSize(bool serverHasLimits, uint64_t serverLimit)
{
    if (!serverHasLimits || serverLimit == 0)
        return FallbackChunkSize;
    return static_cast<size_t>(std::min<uint64_t>(serverLimit, MaxChunkSize));
}

bool isHostKeyMismatch(const QString &sshMessage)
{
    return sshMessage.contains(QLatin1String("no match for method server host key algo"));
}

Result connectFailure(const QString &sshMessage)
{
    if (sshMessage.contains(QLatin1String("kex error")) || sshMessage.contains(QLatin1String("no match for method")))
        return Result(Error::SecurityPolicy,
                      QStringLiteral("The server offers no algorithm this app accepts (%1)").arg(sshMessage));
    if (sshMessage.contains(QLatin1String("timeout"), Qt::CaseInsensitive)
            || sshMessage.contains(QLatin1String("timed out")))
        return Result(Error::Timeout, sshMessage);
    static const std::array<const char *, 8> network = { {
        "refused", "unreachable", "Failed to resolve", "No route", "Socket error", "reset by peer",
        "Received EOF", "Connection closed",
    } };
    const bool unreachable = std::any_of(network.cbegin(), network.cend(), [&sshMessage](const char *needle) {
        return sshMessage.contains(QLatin1String(needle), Qt::CaseInsensitive);
    });
    return Result(unreachable ? Error::NetworkUnreachable : Error::ProtocolError, sshMessage);
}

Result sftpStatusFailure(int sftpStatus, const QString &sshMessage, const QString &context)
{
    switch (sftpStatus) {
    case SSH_FX_NO_SUCH_FILE:
    case SSH_FX_NO_SUCH_PATH:
        return Result(Error::NotFound, QStringLiteral("%1: not found").arg(context));
    case SSH_FX_PERMISSION_DENIED:
    case SSH_FX_WRITE_PROTECT:
        return Result(Error::PermissionDenied, QStringLiteral("%1: permission denied").arg(context));
    case SSH_FX_FILE_ALREADY_EXISTS:
        return Result(Error::AlreadyExists, QStringLiteral("%1: already exists").arg(context));
    case SSH_FX_OP_UNSUPPORTED:
        return Result(Error::Unsupported, QStringLiteral("%1: not supported by the server").arg(context));
    case SSH_FX_NO_CONNECTION:
    case SSH_FX_CONNECTION_LOST:
        return Result(Error::NetworkUnreachable, QStringLiteral("%1: %2").arg(context, sshMessage));
    default:
        break;
    }
    const Error error = sshMessage.contains(QLatin1String("Timeout"), Qt::CaseInsensitive) ? Error::Timeout
                                                                                          : Error::ProtocolError;
    return Result(error, QStringLiteral("%1: %2").arg(context, sshMessage));
}

Result subsystemFailure(bool requestDenied, int sftpStatus, const QString &sshMessage)
{
    if (requestDenied || sftpStatus == SSH_FX_EOF)
        return Result(Error::Unsupported, QStringLiteral("SFTP is not enabled for this user"));
    return connectFailure(sshMessage);
}

bool looksLikeFullDisk(int sftpStatus, qint64 freeBytes, qint64 attempted)
{
    return sftpStatus == SSH_FX_FAILURE && freeBytes >= 0 && freeBytes < attempted;
}

QString acceptedMethodsText(int methods)
{
    const auto mask = static_cast<unsigned>(methods);
    if (mask == SSH_AUTH_METHOD_PUBLICKEY)
        return QStringLiteral("This server only accepts SSH keys (publickey).");
    struct Method {
        unsigned bit;
        const char *name;
    };
    static const std::array<Method, 5> names = { {
        { SSH_AUTH_METHOD_PUBLICKEY, "publickey" },
        { SSH_AUTH_METHOD_PASSWORD, "password" },
        { SSH_AUTH_METHOD_INTERACTIVE, "keyboard-interactive" },
        { SSH_AUTH_METHOD_HOSTBASED, "hostbased" },
        { SSH_AUTH_METHOD_GSSAPI_MIC, "gssapi-with-mic" },
    } };
    QStringList accepted;
    for (const Method &entry : names) {
        if (mask & entry.bit)
            accepted << QLatin1String(entry.name);
    }
    if (accepted.isEmpty())
        return QStringLiteral("The server named no sign-in method it accepts.");
    return QStringLiteral("The server accepts: %1.").arg(accepted.join(QStringLiteral(", ")));
}

Result authDenied(int methods)
{
    return Result(Error::AuthFailed, QStringLiteral("Sign-in was refused. ") + acceptedMethodsText(methods));
}

Result authPartial()
{
    return Result(Error::AuthFailed,
                  QStringLiteral("The server requires a second sign-in step (multi-factor sign-in), "
                                 "which is not supported"));
}

Result interactiveNotSupported()
{
    return Result(Error::AuthFailed,
                  QStringLiteral("The server needs interactive sign-in, which is not supported"));
}

Result checkSecretForMode(const QString &authMode, const QByteArray &secret)
{
    if (authMode == QLatin1String(AuthModePassword)) {
        if (isKeySecret(secret))
            return Result(Error::AuthFailed,
                          QStringLiteral("The account uses a password, but the stored credential is a key"));
        return Result::success();
    }
    if (authMode == QLatin1String(AuthModePublicKey)) {
        if (!decodeKeySecret(secret, nullptr))
            return Result(Error::AuthFailed,
                          QStringLiteral("The account uses an SSH key, but no valid key is stored"));
        return Result::success();
    }
    return Result(Error::Internal, QStringLiteral("Unknown sign-in method \"%1\"").arg(authMode));
}

KeyFileInfo inspectKeyFile(const QByteArray &contents)
{
    KeyFileInfo info = inspectOpenSsh(contents);
    if (info.format == KeyFileInfo::Unknown)
        info = inspectPem(contents);
    if (info.format == KeyFileInfo::Unknown)
        info = inspectPublicLine(contents);
    return info;
}

Result checkKeyFile(const KeyFileInfo &info)
{
    if (isCertificate(info.keyType))
        return certificateRejected();
    if (info.format == KeyFileInfo::PublicKey)
        return unsupportedKey(QStringLiteral("This is a public key; choose the private key file"));
    if (info.format == KeyFileInfo::Unknown)
        return unsupportedKey(QStringLiteral("The file is not a private key in OpenSSH or PEM format"));
    if (info.keyType == QLatin1String(DsaType))
        return unsupportedKey(QStringLiteral("DSA keys are not supported; use an Ed25519, ECDSA or RSA key"));
    if (isSecurityKey(info.keyType))
        return securityKeyRejected();
    return Result::success();
}

Result checkKeyType(const QString &keyType, int rsaBits)
{
    // The key types a host key may be pinned to are exactly the accepted ones.
    if (!hostKeyAlgorithmsFor(keyType).isEmpty()) {
        if (keyType != QLatin1String("ssh-rsa") || rsaBits >= RsaMinimumBits)
            return Result::success();
        return unsupportedKey(QStringLiteral("RSA keys need at least %1 bits; this key has %2")
                                  .arg(RsaMinimumBits).arg(rsaBits));
    }
    if (isCertificate(keyType))
        return certificateRejected();
    if (isSecurityKey(keyType))
        return securityKeyRejected();
    return unsupportedKey(QStringLiteral("Key type %1 is not supported; use an Ed25519, ECDSA or RSA key")
                              .arg(keyType.isEmpty() ? QStringLiteral("(unknown)") : keyType));
}

int rsaBitsFromBlob(const QByteArray &publicKeyBlob)
{
    WireReader reader(publicKeyBlob);
    QByteArray type;
    QByteArray exponent;
    QByteArray modulus;
    if (!reader.readString(&type) || type != "ssh-rsa" || !reader.readString(&exponent)
            || !reader.readString(&modulus))
        return 0;
    int start = 0;
    while (start < modulus.size() && modulus.at(start) == '\0')
        ++start;
    if (start == modulus.size())
        return 0;
    int bits = (modulus.size() - start - 1) * 8;
    for (auto top = static_cast<uchar>(modulus.at(start)); top != 0; top >>= 1)
        ++bits;
    return bits;
}

} // namespace NetVfs::Sftp
