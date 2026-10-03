// SPDX-License-Identifier: LGPL-2.1-or-later
#include "tlsprobe.h"

#include <QtCore/QUrl>

namespace NetVfs::CurlTls {

bool isOpenSsl()
{
    const curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
    return info && info->ssl_version && QByteArray(info->ssl_version).startsWith("OpenSSL");
}

TrustStore trustStore(const Curl::EasyHandle &easy, const QByteArray &testCaFile)
{
    TrustStore store;
    if (!testCaFile.isEmpty()) {
        store.caFile = testCaFile;
        return store;
    }
    const char *value = nullptr;
    if (curl_easy_getinfo(easy.get(), CURLINFO_CAINFO, &value) == CURLE_OK && value)
        store.caFile = value;
    value = nullptr;
    if (curl_easy_getinfo(easy.get(), CURLINFO_CAPATH, &value) == CURLE_OK && value)
        store.caPath = value;
    return store;
}

CURLcode applyTestCaFile(const Curl::EasyHandle &easy, const QByteArray &testCaFile)
{
    if (testCaFile.isEmpty())
        return CURLE_OK;
    if (const CURLcode code = curl_easy_setopt(easy.get(), CURLOPT_CAINFO, testCaFile.constData()); code != CURLE_OK)
        return code;
    return curl_easy_setopt(easy.get(), CURLOPT_CAPATH, static_cast<const char *>(nullptr));
}

IdentityProbe::IdentityProbe(const QString &host, const TrustStore &store, ChainCheck check)
    : m_host(QUrl::toAce(host)), m_store(store), m_check(check)
{
    if (m_host.isEmpty())
        m_host = host.toLatin1();   // IP literals
}

IdentityProbe::~IdentityProbe()
{
    netvfs_tls_capture_release(&m_capture);
}

CURLcode IdentityProbe::install(const Curl::EasyHandle &easy)
{
    CURLcode code = curl_easy_setopt(easy.get(), CURLOPT_SSL_SESSIONID_CACHE, 0L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy.get(), CURLOPT_SSL_CTX_FUNCTION, netvfs_tls_capture_ssl_context);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy.get(), CURLOPT_SSL_CTX_DATA, &m_capture);
    return code;
}

void IdentityProbe::analyse() const
{
    if (m_analysed)
        return;
    m_analysed = true;
    m_identity = identityFromCertificates(m_capture.leaf, m_capture.untrusted, m_host, m_check, m_store);
}

bool IdentityProbe::captured() const
{
    return !identity().isEmpty();
}

const ServerIdentity &IdentityProbe::identity() const
{
    analyse();
    return m_identity;
}

Result applyIdentityPolicy(const Curl::EasyHandle &easy, const QString &pin, bool verifyPeer,
                           const ServerIdentity &seen)
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
    CURLcode code = curl_easy_setopt(easy.get(), CURLOPT_SSL_VERIFYPEER, verify ? 1L : 0L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(easy.get(), CURLOPT_SSL_VERIFYHOST, verify ? 2L : 0L);
    if (code == CURLE_OK) {
        code = curl_easy_setopt(easy.get(), CURLOPT_PINNEDPUBLICKEY,
                                pinOption.isEmpty() ? static_cast<const char *>(nullptr) : pinOption.constData());
    }
    if (code != CURLE_OK)
        return Result(Error::Internal, QStringLiteral("libcurl rejected the TLS settings"));
    return Result::success();
}

} // namespace NetVfs::CurlTls
