// SPDX-License-Identifier: LGPL-2.1-or-later
#include "davtls.h"

#include <QtCore/QStringList>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <array>
#include <ctime>
#include <memory>
#include <vector>

namespace NetVfs::WebDav {

namespace {

constexpr int Ipv4Length = 4;
constexpr int Ipv6Length = 16;

struct X509Free {
    void operator()(X509 *x) const { X509_free(x); }
};
struct BioFree {
    void operator()(BIO *b) const { BIO_free(b); }
};
struct StoreFree {
    void operator()(X509_STORE *s) const { X509_STORE_free(s); }
};
struct StoreCtxFree {
    void operator()(X509_STORE_CTX *c) const { X509_STORE_CTX_free(c); }
};
struct StackFree {
    void operator()(STACK_OF(X509) *s) const { sk_X509_free(s); }
};
struct NamesFree {
    void operator()(GENERAL_NAMES *n) const { GENERAL_NAMES_free(n); }
};
using X509Ptr = std::unique_ptr<X509, X509Free>;

X509Ptr parsePem(const QByteArray &pem)
{
    std::unique_ptr<BIO, BioFree> bio(BIO_new_mem_buf(pem.constData(), pem.size()));
    if (!bio)
        return X509Ptr();
    return X509Ptr(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

QByteArray spkiDer(X509 *cert)
{
    X509_PUBKEY *key = X509_get_X509_PUBKEY(cert);
    const int length = key ? i2d_X509_PUBKEY(key, nullptr) : 0;
    if (length <= 0)
        return QByteArray();
    QByteArray der(length, Qt::Uninitialized);
    auto *cursor = reinterpret_cast<unsigned char *>(der.data());
    if (i2d_X509_PUBKEY(key, &cursor) != length)
        return QByteArray();
    return der;
}

QString nameString(const X509_NAME *name)
{
    std::unique_ptr<BIO, BioFree> bio(BIO_new(BIO_s_mem()));
    if (!bio || X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253) < 0)
        return QString();
    char *data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    return QString::fromUtf8(data, int(length));
}

QDateTime asn1Time(const ASN1_TIME *time)
{
    std::tm parts {};
    if (!time || ASN1_TIME_to_tm(time, &parts) != 1)
        return QDateTime();
    const QDate date(parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday);
    const QTime clock(parts.tm_hour, parts.tm_min, parts.tm_sec);
    return QDateTime(date, clock, Qt::UTC);
}

QString ipString(const ASN1_OCTET_STRING *ip)
{
    const int length = ASN1_STRING_length(ip);
    const unsigned char *bytes = ASN1_STRING_get0_data(ip);
    QStringList parts;
    if (length == Ipv4Length) {
        for (int i = 0; i < length; ++i)
            parts << QString::number(bytes[i]);
        return parts.join(QLatin1Char('.'));
    }
    if (length == Ipv6Length) {
        for (int i = 0; i < length; i += 2)
            parts << QString::number((bytes[i] << 8) | bytes[i + 1], 16);
        return parts.join(QLatin1Char(':'));
    }
    return QString();
}

QStringList subjectAltNames(X509 *cert)
{
    QStringList result;
    std::unique_ptr<GENERAL_NAMES, NamesFree> names(
        static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)));
    if (!names)
        return result;
    for (int i = 0; i < sk_GENERAL_NAME_num(names.get()); ++i) {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(names.get(), i);
        if (name->type == GEN_DNS) {
            const ASN1_STRING *dns = name->d.dNSName;
            result << QStringLiteral("DNS:") + QString::fromLatin1(
                          reinterpret_cast<const char *>(ASN1_STRING_get0_data(dns)), ASN1_STRING_length(dns));
        } else if (name->type == GEN_IPADD) {
            result << QStringLiteral("IP:") + ipString(name->d.iPAddress);
        }
    }
    return result;
}

QString certificateSha256(X509 *cert)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int length = 0;
    if (X509_digest(cert, EVP_sha256(), digest.data(), &length) != 1)
        return QString();
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(digest.data()), int(length)).toHex());
}

int problemFor(int verifyError)
{
    switch (verifyError) {
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        return ServerIdentity::SelfSigned;
    case X509_V_ERR_CERT_HAS_EXPIRED:
        return ServerIdentity::Expired;
    case X509_V_ERR_CERT_NOT_YET_VALID:
        return ServerIdentity::NotYetValid;
    default:
        return ServerIdentity::UntrustedRoot;
    }
}

// Records every verification error instead of stopping at the first.
int collectProblems(int ok, X509_STORE_CTX *ctx)
{
    if (!ok) {
        auto *problems = static_cast<int *>(X509_STORE_CTX_get_ex_data(ctx, 0));
        if (problems)
            *problems |= problemFor(X509_STORE_CTX_get_error(ctx));
    }
    return 1;
}

bool loadStore(X509_STORE *store, const TrustStore &trust)
{
    if (trust.caFile.isEmpty() && trust.caPath.isEmpty())
        return X509_STORE_set_default_paths(store) == 1;
    bool loaded = false;
    if (!trust.caFile.isEmpty()) {
        X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        loaded = lookup && X509_LOOKUP_load_file(lookup, trust.caFile.constData(), X509_FILETYPE_PEM) == 1;
    }
    if (!trust.caPath.isEmpty()) {
        X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
        loaded = (lookup && X509_LOOKUP_add_dir(lookup, trust.caPath.constData(), X509_FILETYPE_PEM) == 1) || loaded;
    }
    return loaded;
}

int chainProblems(const std::vector<X509Ptr> &chain, const TrustStore &trust, time_t at)
{
    std::unique_ptr<X509_STORE, StoreFree> store(X509_STORE_new());
    std::unique_ptr<X509_STORE_CTX, StoreCtxFree> ctx(X509_STORE_CTX_new());
    std::unique_ptr<STACK_OF(X509), StackFree> untrusted(sk_X509_new_null());
    if (!store || !ctx || !untrusted || !loadStore(store.get(), trust))
        return ServerIdentity::UntrustedRoot;
    for (size_t i = 1; i < chain.size(); ++i)
        sk_X509_push(untrusted.get(), chain[i].get());
    if (X509_STORE_CTX_init(ctx.get(), store.get(), chain.front().get(), untrusted.get()) != 1)
        return ServerIdentity::UntrustedRoot;
    int problems = 0;
    X509_STORE_CTX_set_ex_data(ctx.get(), 0, &problems);
    X509_STORE_CTX_set_verify_cb(ctx.get(), collectProblems);
    X509_STORE_CTX_set_time(ctx.get(), 0, at);
    if (X509_verify_cert(ctx.get()) != 1 && problems == 0)
        problems = ServerIdentity::UntrustedRoot;
    return problems;
}

bool isIpv4Literal(const QByteArray &host)
{
    if (host.count('.') != 3)
        return false;
    for (const char c : host) {
        if (c != '.' && (c < '0' || c > '9'))
            return false;
    }
    return true;
}

int leafProblems(X509 *leaf, const QByteArray &host, time_t at)
{
    int problems = 0;
    if (X509_cmp_time(X509_get0_notAfter(leaf), &at) < 0)
        problems |= ServerIdentity::Expired;
    if (X509_cmp_time(X509_get0_notBefore(leaf), &at) > 0)
        problems |= ServerIdentity::NotYetValid;
    QByteArray name = host;
    if (name.startsWith('[') && name.endsWith(']'))
        name = name.mid(1, name.size() - 2);
    const bool literal = name.contains(':') || isIpv4Literal(name);
    const bool matches = literal ? X509_check_ip_asc(leaf, name.constData(), 0) == 1
                                 : X509_check_host(leaf, name.constData(), size_t(name.size()), 0, nullptr) == 1;
    if (!matches)
        problems |= ServerIdentity::HostnameMismatch;
    return problems;
}

} // namespace

ServerIdentity identityFromChain(const QVector<QByteArray> &pemChain, const QByteArray &host, ChainCheck check,
                                 const TrustStore &store, const QDateTime &now)
{
    std::vector<X509Ptr> chain;
    for (const QByteArray &pem : pemChain) {
        X509Ptr cert = parsePem(pem);
        if (!cert)
            break;
        chain.push_back(std::move(cert));
    }
    if (chain.empty())
        return ServerIdentity();
    X509 *leaf = chain.front().get();
    ServerIdentity identity = ServerIdentity::fromTlsSpki(spkiDer(leaf));
    if (identity.isEmpty())
        return identity;
    identity.details.insert(QStringLiteral("subject"), nameString(X509_get_subject_name(leaf)));
    identity.details.insert(QStringLiteral("issuer"), nameString(X509_get_issuer_name(leaf)));
    identity.details.insert(QStringLiteral("notBefore"), asn1Time(X509_get0_notBefore(leaf)));
    identity.details.insert(QStringLiteral("notAfter"), asn1Time(X509_get0_notAfter(leaf)));
    identity.details.insert(QStringLiteral("sans"), subjectAltNames(leaf));
    identity.details.insert(QStringLiteral("certSha256"), certificateSha256(leaf));

    if (check == ChainCheck::Verified) {
        identity.systemTrusted = true;
        return identity;
    }
    const time_t at = time_t(now.toMSecsSinceEpoch() / 1000);
    int problems = leafProblems(leaf, host, at) | chainProblems(chain, store, at);
    // A self-signed leaf is its own (untrusted) root; report it once.
    if (problems & ServerIdentity::SelfSigned)
        problems &= ~int(ServerIdentity::UntrustedRoot);
    if (check == ChainCheck::Failed && problems == 0)
        problems = ServerIdentity::UntrustedRoot;   // libcurl's store disagrees with ours
    identity.problems = problems;
    identity.systemTrusted = problems == 0;
    return identity;
}

} // namespace NetVfs::WebDav
