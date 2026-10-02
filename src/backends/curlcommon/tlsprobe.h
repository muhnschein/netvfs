// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TLSPROBE_H
#define NETVFS_TLSPROBE_H

#include "curlhandles.h"
#include "error.h"
#include "tlscallbacks.h"
#include "tlsidentity.h"

#include <curl/curl.h>

// TLS identity collection and enforcement for libcurl based backends
// (SPEC-v2 XC-16, W-3, W-4, C-7). Protocol neutral; used by the FTP and the
// WebDAV backend. Requires libcurl with the OpenSSL TLS backend (the one
// Sailfish OS ships); isOpenSsl() lets a backend refuse anything else.
namespace NetVfs::CurlTls {

bool isOpenSsl();

// The anchors a "system trusted" verdict and libcurl's verification use:
// libcurl's CA bundle and folder (CURLINFO_CAINFO/CAPATH), or, when
// `testCaFile` is set (option "test_ca_file", honoured only in builds with
// NETVFS_TLS_TEST_HOOKS, never in the shipped plugins), that file alone.
TrustStore trustStore(const Curl::EasyHandle &easy, const QByteArray &testCaFile);
// Points libcurl's verification at the test CA file, if there is one.
CURLcode applyTestCaFile(const Curl::EasyHandle &easy, const QByteArray &testCaFile);

// C-7 for protocols where libcurl offers no stop between the TLS handshake
// and the first authenticated command (FTP sends USER right after AUTH TLS),
// and W-3 for a server whose certificate is not trusted: install() makes the
// handshake of `easy` record the server's chain and then fail on the client
// side, so nothing at all is sent over TLS on that connection. libcurl's
// verification stays on: the handshake can only end in a failure, never in a
// connection. Session resumption is off (a resumed handshake has no
// certificate). `check` tells identity() how the caller's own verification
// of the same server went (ChainCheck).
class IdentityProbe
{
public:
    IdentityProbe(const QString &host, const TrustStore &store, ChainCheck check = ChainCheck::NotChecked);
    ~IdentityProbe();
    IdentityProbe(const IdentityProbe &) = delete;
    IdentityProbe &operator=(const IdentityProbe &) = delete;

    CURLcode install(const Curl::EasyHandle &easy);
    // True when the handshake got as far as the server's certificate.
    bool captured() const;
    const ServerIdentity &identity() const;

private:
    void analyse() const;

    QByteArray m_host;
    TrustStore m_store;
    ChainCheck m_check;
    NetVfsTlsCapture m_capture {};
    mutable bool m_analysed = false;
    mutable ServerIdentity m_identity;
};

// W-4 for a connection that will carry credentials (the semantics of the
// WebDAV backend):
//  - pin (host_key "tls-spki-sha256 ..."): CURLOPT_PINNEDPUBLICKEY enforces
//    it; peer and host name verification are on exactly when the account
//    option "tls_verify_peer" is true (the pinned chain was system trusted
//    when the user accepted it); such a pinned chain that is no longer
//    trusted is refused as ServerIdentityChanged before anything is sent.
//  - no pin, `seen` system trusted: peer and host name verification.
//  - no pin, `seen` not trusted: the caller accepted the certificate it saw
//    in connect(), so exactly that SPKI is pinned.
Result applyIdentityPolicy(const Curl::EasyHandle &easy, const QString &pin, bool verifyPeer, const ServerIdentity &seen);

} // namespace NetVfs::CurlTls

#endif
