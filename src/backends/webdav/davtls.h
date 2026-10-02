// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DAVTLS_H
#define NETVFS_DAVTLS_H

#include "types.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QVector>

// TLS server identity of the WebDAV backend (SPEC-v2 XC-16, W-3, W-4): turns
// the certificate chain libcurl reports (CURLOPT_CERTINFO, PEM, leaf first)
// into a ServerIdentity with details and problems.
namespace NetVfs::WebDav {

// The CA certificates "system trust" means: libcurl's CA bundle and
// directory (CURLINFO_CAINFO / CURLINFO_CAPATH). Both empty: OpenSSL's
// default locations.
struct TrustStore {
    QByteArray caFile;
    QByteArray caPath;
};

// How the chain was checked by libcurl during the handshake.
enum class ChainCheck {
    Verified,       // peer and host name verified: systemTrusted, no problems
    Failed,         // verification failed: problems are analysed here
    NotChecked      // verification was off (pinned, W-4): analysed here
};

// Identity of the leaf certificate: kind TlsCertificate, algorithm
// "tls-spki-sha256", publicKey the DER SubjectPublicKeyInfo, fingerprint
// its base64 SHA-256 (curl pin form), details
//   subject, issuer   RFC 2253 strings
//   notBefore, notAfter QDateTime (UTC)
//   sans              QStringList ("DNS:name", "IP:address")
//   certSha256        lower-case hex SHA-256 of the DER certificate
// and problems (ServerIdentity::Problem bits) derived from verifying the
// chain against `store` at `now` and from the host name. An empty identity
// when the chain cannot be parsed.
ServerIdentity identityFromChain(const QVector<QByteArray> &pemChain, const QByteArray &host,
                                 ChainCheck check, const TrustStore &store,
                                 const QDateTime &now = QDateTime::currentDateTimeUtc());

} // namespace NetVfs::WebDav

#endif
