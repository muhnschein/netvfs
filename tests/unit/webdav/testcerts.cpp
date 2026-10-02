// SPDX-License-Identifier: LGPL-2.1-or-later
#include "testcerts.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <atomic>

namespace {

constexpr long SecondsPerDay = 24 * 60 * 60;
std::atomic<long> serial { 1 };

QByteArray drain(BIO *bio)
{
    char *data = nullptr;
    const long length = BIO_get_mem_data(bio, &data);
    QByteArray result(data, int(length));
    BIO_free(bio);
    return result;
}

void addExtension(X509 *cert, X509V3_CTX *ctx, int nid, const QByteArray &value)
{
    X509_EXTENSION *extension = X509V3_EXT_conf_nid(nullptr, ctx, nid, value.constData());
    if (extension) {
        X509_add_ext(cert, extension, -1);
        X509_EXTENSION_free(extension);
    }
}

X509 *readCertificate(const QByteArray &pem)
{
    BIO *bio = BIO_new_mem_buf(pem.constData(), pem.size());
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

EVP_PKEY *readKey(const QByteArray &pem)
{
    BIO *bio = BIO_new_mem_buf(pem.constData(), pem.size());
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
}

} // namespace

TestCertificate makeCertificate(const CertificateOptions &options)
{
    EVP_PKEY *key = EVP_EC_gen("P-256");
    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial++);
    X509_gmtime_adj(X509_getm_notBefore(cert), options.notBeforeDays * SecondsPerDay);
    X509_gmtime_adj(X509_getm_notAfter(cert), options.notAfterDays * SecondsPerDay);
    X509_set_pubkey(cert, key);
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("netvfs tests"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(options.commonName.constData()), -1, -1, 0);

    X509 *issuerCert = options.issuer ? readCertificate(options.issuer->certificatePem) : nullptr;
    EVP_PKEY *issuerKey = options.issuer ? readKey(options.issuer->keyPem) : nullptr;
    X509_set_issuer_name(cert, issuerCert ? X509_get_subject_name(issuerCert) : name);

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuerCert ? issuerCert : cert, cert, nullptr, nullptr, 0);
    addExtension(cert, &ctx, NID_basic_constraints, options.authority ? "critical,CA:TRUE" : "CA:FALSE");
    if (options.authority)
        addExtension(cert, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    addExtension(cert, &ctx, NID_subject_key_identifier, "hash");
    if (!options.subjectAltNames.isEmpty())
        addExtension(cert, &ctx, NID_subject_alt_name, options.subjectAltNames);
    X509_sign(cert, issuerKey ? issuerKey : key, EVP_sha256());

    TestCertificate result;
    BIO *certBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(certBio, cert);
    result.certificatePem = drain(certBio);
    BIO *keyBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(keyBio, key, nullptr, nullptr, 0, nullptr, nullptr);
    result.keyPem = drain(keyBio);
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), nullptr);
    result.spkiDer.resize(length);
    auto *cursor = reinterpret_cast<unsigned char *>(result.spkiDer.data());
    i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &cursor);

    X509_free(issuerCert);
    EVP_PKEY_free(issuerKey);
    X509_free(cert);
    EVP_PKEY_free(key);
    return result;
}
