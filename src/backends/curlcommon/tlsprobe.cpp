// SPDX-License-Identifier: LGPL-2.1-or-later
#include "tlsprobe.h"

#include <QtCore/QUrl>

#include <openssl/ssl.h>

namespace NetVfs::CurlTls {

bool isOpenSsl()
{
    const curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
    return info && info->ssl_version && QByteArray(info->ssl_version).startsWith("OpenSSL");
}

TrustStore trustStore(CURL *easy, const QByteArray &testCaFile)
{
    TrustStore store;
    if (!testCaFile.isEmpty()) {
        store.caFile = testCaFile;
        return store;
    }
    const char *value = nullptr;
    if (curl_easy_getinfo(easy, CURLINFO_CAINFO, &value) == CURLE_OK && value)
        store.caFile = value;
    value = nullptr;
    if (curl_easy_getinfo(easy, CURLINFO_CAPATH, &value) == CURLE_OK && value)
        store.caPath = value;
    return store;
}

CURLcode applyTestCaFile(CURL *easy, const QByteArray &testCaFile)
{
    if (testCaFile.isEmpty())
        return CURLE_OK;
    const CURLcode code = curl_easy_setopt(easy, CURLOPT_CAINFO, testCaFile.constData());
    if (code != CURLE_OK)
        return code;
    return curl_easy_setopt(easy, CURLOPT_CAPATH, static_cast<const char *>(nullptr));
}

IdentityProbe::IdentityProbe(const QString &host, const TrustStore &store)
    : m_host(QUrl::toAce(host)), m_store(store)
{
    if (m_host.isEmpty())
        m_host = host.toLatin1();   // IP literals
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
    probe->m_identity = identityFromCertificates(X509_STORE_CTX_get0_cert(store),
                                                 X509_STORE_CTX_get0_untrusted(store), probe->m_host,
                                                 ChainCheck::NotChecked, probe->m_store);
    probe->m_captured = !probe->m_identity.isEmpty();
    X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;   // never complete this handshake (C-7)
}

Result applyIdentityPolicy(CURL *easy, const QString &pin, bool verifyPeer, const ServerIdentity &seen)
{
    QString pinned;
    bool verify = false;
    if (!pin.isEmpty()) {
        const ServerIdentity stored = ServerIdentity::fromPin(pin);
        if (stored.kind != ServerIdentity::Kind::TlsCertificate) {
            return Result(Error::ServerIdentityChanged,
                          QStringLiteral("The stored server key is not a TLS certificate key"));
        }
        if (verifyPeer && !seen.systemTrusted) {
            return Result(Error::ServerIdentityChanged,
                          QStringLiteral("The pinned server certificate is no longer trusted by the system"));
        }
        pinned = stored.fingerprint;
        verify = verifyPeer;
    } else if (seen.systemTrusted) {
        verify = true;
    } else if (!seen.isEmpty()) {
        pinned = seen.fingerprint;
    } else {
        return Result(Error::Internal, QStringLiteral("No server certificate was seen during connect"));
    }
    const QByteArray pinOption = pinned.isEmpty() ? QByteArray() : "sha256//" + pinned.toLatin1();
    CURLcode code = curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, verify ? 1L : 0L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, verify ? 2L : 0L);
    if (code == CURLE_OK) {
        code = curl_easy_setopt(easy, CURLOPT_PINNEDPUBLICKEY,
                                pinOption.isEmpty() ? static_cast<const char *>(nullptr) : pinOption.constData());
    }
    if (code != CURLE_OK)
        return Result(Error::Internal, QStringLiteral("libcurl rejected the TLS settings"));
    return Result::success();
}

} // namespace NetVfs::CurlTls
