// SPDX-License-Identifier: LGPL-2.1-or-later
#include "curltls.h"

#include <QtCore/QUrl>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <memory>

namespace NetVfs::CurlTls {

namespace {

constexpr const char *CertFileVariable = "SSL_CERT_FILE";
constexpr const char *CertDirVariable = "SSL_CERT_DIR";
constexpr int AppDataIndex = 0;
constexpr int IpV6AddressBytes = 16;
constexpr int IpV4AddressBytes = 4;

struct BioDeleter { void operator()(BIO *b) const { BIO_free(b); } };
struct StoreDeleter { void operator()(X509_STORE *s) const { X509_STORE_free(s); } };
struct StoreCtxDeleter { void operator()(X509_STORE_CTX *c) const { X509_STORE_CTX_free(c); } };
struct NamesDeleter { void operator()(GENERAL_NAMES *n) const { GENERAL_NAMES_free(n); } };
struct DerDeleter { void operator()(unsigned char *p) const { OPENSSL_free(p); } };

QByteArray spkiDer(X509 *leaf)
{
    unsigned char *raw = nullptr;
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(leaf), &raw);
    const std::unique_ptr<unsigned char, DerDeleter> der(raw);
    if (length <= 0 || !der)
        return QByteArray();
    return QByteArray(reinterpret_cast<const char *>(der.get()), length);
}

QString nameText(const X509_NAME *name)
{
    const std::unique_ptr<BIO, BioDeleter> bio(BIO_new(BIO_s_mem()));
    if (!bio || X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253) < 0)
        return QString();
    char *data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    return QString::fromUtf8(data, int(length));
}

QDateTime asn1Time(const ASN1_TIME *time)
{
    struct tm parts = {};
    if (!time || ASN1_TIME_to_tm(time, &parts) != 1)
        return QDateTime();
    return QDateTime(QDate(parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday),
                     QTime(parts.tm_hour, parts.tm_min, parts.tm_sec), Qt::UTC);
}

QString ipText(const ASN1_OCTET_STRING *ip)
{
    const QByteArray bytes(reinterpret_cast<const char *>(ASN1_STRING_get0_data(ip)), ASN1_STRING_length(ip));
    if (bytes.size() == IpV4AddressBytes) {
        return QStringLiteral("%1.%2.%3.%4").arg(uchar(bytes.at(0))).arg(uchar(bytes.at(1)))
            .arg(uchar(bytes.at(2))).arg(uchar(bytes.at(3)));
    }
    if (bytes.size() == IpV6AddressBytes) {
        QStringList groups;
        for (int i = 0; i < IpV6AddressBytes; i += 2)
            groups.append(QString::number((uchar(bytes.at(i)) << 8) | uchar(bytes.at(i + 1)), 16));
        return groups.join(QLatin1Char(':'));
    }
    return QString();
}

QStringList subjectAltNames(X509 *leaf)
{
    QStringList names;
    const std::unique_ptr<GENERAL_NAMES, NamesDeleter> sans(
        static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(leaf, NID_subject_alt_name, nullptr, nullptr)));
    if (!sans)
        return names;
    for (int i = 0; i < sk_GENERAL_NAME_num(sans.get()); ++i) {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(sans.get(), i);
        if (name->type == GEN_DNS) {
            const ASN1_IA5STRING *dns = name->d.dNSName;
            names.append(QString::fromLatin1(reinterpret_cast<const char *>(ASN1_STRING_get0_data(dns)),
                                             ASN1_STRING_length(dns)));
        } else if (name->type == GEN_IPADD) {
            names.append(ipText(name->d.iPAddress));
        }
    }
    return names;
}

QVariantMap describe(X509 *leaf, STACK_OF(X509) *presented)
{
    QVariantMap details;
    details.insert(QStringLiteral("subject"), nameText(X509_get_subject_name(leaf)));
    details.insert(QStringLiteral("issuer"), nameText(X509_get_issuer_name(leaf)));
    details.insert(QStringLiteral("notBefore"), asn1Time(X509_get0_notBefore(leaf)));
    details.insert(QStringLiteral("notAfter"), asn1Time(X509_get0_notAfter(leaf)));
    details.insert(QStringLiteral("sans"), subjectAltNames(leaf));
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength = 0;
    if (X509_digest(leaf, EVP_sha256(), digest, &digestLength) == 1) {
        details.insert(QStringLiteral("certSha256"),
                       QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(digest), int(digestLength)).toHex()));
    }
    QStringList chain;
    for (int i = 0; presented && i < sk_X509_num(presented); ++i)
        chain.append(nameText(X509_get_subject_name(sk_X509_value(presented, i))));
    details.insert(QStringLiteral("chain"), chain);
    return details;
}

int problemFor(int error)
{
    switch (error) {
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        return ServerIdentity::SelfSigned;
    case X509_V_ERR_CERT_HAS_EXPIRED:
        return ServerIdentity::Expired;
    case X509_V_ERR_CERT_NOT_YET_VALID:
        return ServerIdentity::NotYetValid;
    case X509_V_ERR_HOSTNAME_MISMATCH:
    case X509_V_ERR_IP_ADDRESS_MISMATCH:
        return ServerIdentity::HostnameMismatch;
    default:
        // SELF_SIGNED_CERT_IN_CHAIN, UNABLE_TO_GET_ISSUER_CERT(_LOCALLY),
        // UNABLE_TO_VERIFY_LEAF_SIGNATURE, CERT_UNTRUSTED and anything else
        // that breaks the path to a trust anchor.
        return ServerIdentity::UntrustedRoot;
    }
}

// Verify callback: records every problem and lets verification go on, so
// that all of them are reported (expired and wrong host name, say).
int collectProblems(int ok, X509_STORE_CTX *ctx)
{
    if (!ok) {
        auto *problems = static_cast<int *>(X509_STORE_CTX_get_ex_data(ctx, AppDataIndex));
        if (problems)
            *problems |= problemFor(X509_STORE_CTX_get_error(ctx));
    }
    return 1;
}

bool setHost(X509_VERIFY_PARAM *param, const QString &host)
{
    QString bare = host;
    if (bare.startsWith(QLatin1Char('[')) && bare.endsWith(QLatin1Char(']')))
        bare = bare.mid(1, bare.size() - 2);
    const QByteArray ascii = QUrl::toAce(bare);
    const QByteArray literal = bare.toLatin1();
    if (X509_VERIFY_PARAM_set1_ip_asc(param, literal.constData()) == 1)
        return true;
    return !ascii.isEmpty() && X509_VERIFY_PARAM_set1_host(param, ascii.constData(), size_t(ascii.size())) == 1;
}

// Returns the problem bits; `trusted` is true when the chain verified
// against the anchors and the host name matched.
int verifyChain(X509 *leaf, STACK_OF(X509) *presented, const QString &host, const TrustAnchors &anchors,
                bool *trusted)
{
    *trusted = false;
    int problems = 0;
    const std::unique_ptr<X509_STORE, StoreDeleter> store(X509_STORE_new());
    const std::unique_ptr<X509_STORE_CTX, StoreCtxDeleter> ctx(X509_STORE_CTX_new());
    if (!store || !ctx)
        return ServerIdentity::UntrustedRoot;
    const char *file = anchors.caFile.isEmpty() ? nullptr : anchors.caFile.constData();
    const char *path = anchors.caPath.isEmpty() ? nullptr : anchors.caPath.constData();
    if (file || path)
        X509_STORE_load_locations(store.get(), file, path);
    if (X509_STORE_CTX_init(ctx.get(), store.get(), leaf, presented) != 1)
        return ServerIdentity::UntrustedRoot;
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx.get());
    X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_SERVER);
    if (!setHost(param, host))
        problems |= ServerIdentity::HostnameMismatch;
    X509_STORE_CTX_set_ex_data(ctx.get(), AppDataIndex, &problems);
    X509_STORE_CTX_set_verify_cb(ctx.get(), collectProblems);
    const int verified = X509_verify_cert(ctx.get());
    *trusted = verified == 1 && problems == 0;
    if (verified != 1 && problems == 0)
        problems = ServerIdentity::UntrustedRoot;
    return problems;
}

} // namespace

bool isOpenSsl()
{
    const curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
    return info && info->ssl_version && QByteArray(info->ssl_version).startsWith("OpenSSL");
}

TrustAnchors trustAnchors(CURL *easy)
{
    TrustAnchors anchors;
    const QByteArray file = qgetenv(CertFileVariable);
    const QByteArray dir = qgetenv(CertDirVariable);
    if (!file.isEmpty() || !dir.isEmpty()) {
        anchors.caFile = file;
        anchors.caPath = dir;
        anchors.fromEnvironment = true;
        return anchors;
    }
    char *value = nullptr;
    if (curl_easy_getinfo(easy, CURLINFO_CAINFO, &value) == CURLE_OK && value)
        anchors.caFile = value;
    value = nullptr;
    if (curl_easy_getinfo(easy, CURLINFO_CAPATH, &value) == CURLE_OK && value)
        anchors.caPath = value;
    return anchors;
}

CURLcode applyTrustAnchors(CURL *easy, const TrustAnchors &anchors)
{
    if (!anchors.fromEnvironment)
        return CURLE_OK;
    CURLcode code = curl_easy_setopt(easy, CURLOPT_CAINFO,
                                     anchors.caFile.isEmpty() ? nullptr : anchors.caFile.constData());
    if (code == CURLE_OK) {
        code = curl_easy_setopt(easy, CURLOPT_CAPATH,
                                anchors.caPath.isEmpty() ? nullptr : anchors.caPath.constData());
    }
    return code;
}

ServerIdentity evaluate(X509 *leaf, STACK_OF(X509) *presented, const QString &host, const TrustAnchors &anchors)
{
    if (!leaf)
        return ServerIdentity();
    ServerIdentity identity = ServerIdentity::fromTlsSpki(spkiDer(leaf));
    if (identity.isEmpty())
        return identity;
    identity.details = describe(leaf, presented);
    bool trusted = false;
    identity.problems = verifyChain(leaf, presented, host, anchors, &trusted);
    identity.systemTrusted = trusted;
    return identity;
}

IdentityProbe::IdentityProbe(const QString &host, const TrustAnchors &anchors)
    : m_host(host), m_anchors(anchors)
{
}

CURLcode IdentityProbe::install(CURL *easy)
{
    // libcurl's own checks are off: the probe's verify callback decides, and
    // it always ends the handshake.
    CURLcode code = curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_SSL_SESSIONID_CACHE, 0L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_SSL_CTX_FUNCTION, &IdentityProbe::sslContext);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_SSL_CTX_DATA, this);
    return code;
}

CURLcode IdentityProbe::sslContext(CURL *, void *sslCtx, void *self)
{
    auto *ctx = static_cast<SSL_CTX *>(sslCtx);
    // VERIFY_PEER makes OpenSSL abort the handshake when verify() fails;
    // with VERIFY_NONE the result would be ignored.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(ctx, &IdentityProbe::verify, self);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    return CURLE_OK;
}

int IdentityProbe::verify(X509_STORE_CTX *store, void *self)
{
    auto *probe = static_cast<IdentityProbe *>(self);
    probe->m_identity = evaluate(X509_STORE_CTX_get0_cert(store), X509_STORE_CTX_get0_untrusted(store),
                                 probe->m_host, probe->m_anchors);
    probe->m_captured = !probe->m_identity.isEmpty();
    X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}

Result applyIdentityPolicy(CURL *easy, const QString &pin, bool pinTrusted, const ServerIdentity &seen)
{
    QString pinned;
    bool verifyPeer = false;
    if (!pin.isEmpty()) {
        const ServerIdentity stored = ServerIdentity::fromPin(pin);
        if (stored.kind != ServerIdentity::Kind::TlsCertificate) {
            return Result(Error::ServerIdentityChanged,
                          QStringLiteral("The stored server key is not a TLS certificate key"));
        }
        if (pinTrusted && !seen.systemTrusted) {
            return Result(Error::ServerIdentityChanged,
                          QStringLiteral("The pinned certificate is no longer trusted by the system"));
        }
        pinned = stored.fingerprint;
        verifyPeer = pinTrusted;
    } else if (seen.systemTrusted) {
        verifyPeer = true;
    } else if (!seen.isEmpty()) {
        pinned = seen.fingerprint;
    } else {
        return Result(Error::Internal, QStringLiteral("No server certificate was seen during connect"));
    }
    const QByteArray pinOption = pinned.isEmpty() ? QByteArray() : "sha256//" + pinned.toLatin1();
    CURLcode code = curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, verifyPeer ? 1L : 0L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, verifyPeer ? 2L : 0L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_PINNEDPUBLICKEY, pinOption.isEmpty() ? nullptr : pinOption.constData());
    if (code != CURLE_OK)
        return Result(Error::Internal, QStringLiteral("libcurl rejected the TLS settings"));
    return Result::success();
}

} // namespace NetVfs::CurlTls
