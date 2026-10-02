// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CURLTLS_H
#define NETVFS_CURLTLS_H

#include "error.h"
#include "types.h"

#include <curl/curl.h>
#include <openssl/x509.h>

// TLS server identity for libcurl based backends (SPEC-v2 XC-16, W-3, W-4,
// F-1). Protocol neutral: nothing in here knows about FTP, so that WebDAV
// can share it. Requires libcurl with the OpenSSL TLS backend (the one
// Sailfish OS ships); isOpenSsl() lets a backend refuse anything else.
namespace NetVfs::CurlTls {

// The trust anchors a system-trust verdict is based on. By default the CA
// bundle and folder libcurl was built with (CURLINFO_CAINFO/CAPATH).
// When the OpenSSL environment variables SSL_CERT_FILE or SSL_CERT_DIR are
// set, they replace libcurl's defaults, for the identity evaluation and the
// connections alike; the interop suites use this to trust a test CA.
struct TrustAnchors {
    QByteArray caFile;
    QByteArray caPath;
    bool fromEnvironment = false;
};

bool isOpenSsl();
TrustAnchors trustAnchors(CURL *easy);
// Sets CURLOPT_CAINFO/CAPATH when the anchors come from the environment.
CURLcode applyTrustAnchors(CURL *easy, const TrustAnchors &anchors);

// Evaluates a chain as presented by the server: the leaf's SPKI (the pin),
// details (subject, issuer, notBefore, notAfter, sans, certSha256, chain),
// systemTrusted (chain to an anchor and host name match) and the problem
// bits of ServerIdentity. `host` is the name the user entered (IDN allowed)
// or an IP literal.
ServerIdentity evaluate(X509 *leaf, STACK_OF(X509) *presented, const QString &host,
                        const TrustAnchors &anchors);

// C-7 for protocols where libcurl offers no stop between the TLS handshake
// and the first authenticated command (FTP sends USER right after AUTH TLS):
// install() makes the handshake of `easy` record the server's chain and
// then fail on the client side, so nothing at all is sent over TLS on that
// connection. Also turns off session resumption (a resumed handshake has no
// certificate) and libcurl's own verification (the probe does its own).
class IdentityProbe
{
public:
    IdentityProbe(const QString &host, const TrustAnchors &anchors);
    IdentityProbe(const IdentityProbe &) = delete;
    IdentityProbe &operator=(const IdentityProbe &) = delete;

    CURLcode install(CURL *easy);
    bool captured() const { return m_captured; }
    const ServerIdentity &identity() const { return m_identity; }

private:
    static CURLcode sslContext(CURL *easy, void *sslCtx, void *self);
    static int verify(X509_STORE_CTX *store, void *self);

    QString m_host;
    TrustAnchors m_anchors;
    bool m_captured = false;
    ServerIdentity m_identity;
};

// W-4: verification for a connection that will carry credentials.
//  - pin (host_key "tls-spki-sha256 ..."): CURLOPT_PINNEDPUBLICKEY enforces
//    it; peer and host name verification are on exactly when the pin was
//    taken from a system-trusted chain (`pinTrusted`, account option
//    "pin_trusted"); a pinned chain that is no longer trusted is refused as
//    ServerIdentityChanged before anything is sent.
//  - no pin, `seen` system trusted: peer and host name verification.
//  - no pin, `seen` not trusted: the caller accepted the certificate it saw
//    in connect(), so exactly that SPKI is pinned.
Result applyIdentityPolicy(CURL *easy, const QString &pin, bool pinTrusted, const ServerIdentity &seen);

} // namespace NetVfs::CurlTls

#endif
