// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TESTCERTS_H
#define NETVFS_TESTCERTS_H

#include <QtCore/QByteArray>

// Throw-away certificates for the TLS tests (P-256 keys, SHA-256).
struct TestCertificate {
    QByteArray certificatePem;
    QByteArray keyPem;
    QByteArray spkiDer;
};

struct CertificateOptions {
    QByteArray commonName = "localhost";
    QByteArray subjectAltNames = "DNS:localhost,IP:127.0.0.1";   // empty: none
    const TestCertificate *issuer = nullptr;                    // null: self-signed
    bool authority = false;
    int notBeforeDays = -1;          // relative to now
    int notAfterDays = 30;
};

TestCertificate makeCertificate(const CertificateOptions &options);

#endif
