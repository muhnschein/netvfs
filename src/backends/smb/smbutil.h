// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBUTIL_H
#define NETVFS_SMBUTIL_H

#include "error.h"

#include <QtCore/QByteArray>
#include <QtCore/QVariantMap>

#include <atomic>

namespace NetVfs::Smb {

// Where a request failed. It decides what a failure without NT status means
// (SPEC-smb 5, error mapping).
enum class Stage {
    SessionSetup,   // negotiate, session setup and tree connect, after TCP connect
    Established     // requests on an authenticated session
};

inline constexpr const char *ServerClosedMessage =
    "the server closed the connection; it may not support SMB 3, signing or encryption";
inline constexpr const char *SessionRefusedMessage =
    "the server refused the session; it may require a protocol version, cipher or signing algorithm "
    "this device does not offer (SMB 3 with AES-128-CCM and AES-128-CMAC), or deny this account the share";
inline constexpr const char *ConnectionLostMessage = "the connection to the server was lost";

inline constexpr quint32 MaxChunkSize = 1024 * 1024;        // M-11
inline constexpr quint32 FallbackChunkSize = 64 * 1024;     // server reported no maximum

// M-11: min(server maximum, 1 MiB).
quint32 chunkSize(quint32 serverMaximum);

// M-8, M-9, C-15: normalizes, strips a leading '/', rejects Windows-invalid
// components. `out` is UTF-8, relative to the share root, '/' separated.
Result translatePath(const QString &path, QByteArray *out);

// Classifies a failed libsmb2 request. `ntStatus` is smb2_get_nterror() (the
// only input that distinguishes server answers); `errnoValue` (positive) only
// distinguishes TCP-level failures when there is no NT status.
Result errorForStatus(quint32 ntStatus, int errnoValue, Stage stage, const QString &context);

// The connection broke while a request was outstanding: SecurityPolicy during
// session setup (the server dropped us), NetworkUnreachable afterwards.
Result connectionLost(Stage stage);

// A failed TCP connect (M-10): Timeout, Canceled or NetworkUnreachable.
Result errorForSocket(int errnoValue, const QString &context);

// M-3: options["require_encryption"], default true.
bool requireEncryption(const QVariantMap &options);

// M-1: SMB 3.0, 3.0.2 and 3.1.1 only.
bool isSmb3Dialect(quint16 dialect);
QString dialectName(quint16 dialect);

// "host" or "host:port" in the form smb2_connect_share() parses ("[v6]:port").
QByteArray serverString(const QString &numericHost, int port);

// M-10: resolves `host` and opens (then closes) a TCP connection to `port`
// within `timeoutMs`, polling `cancel`. On success `*numericHost` is the
// address that answered.
Result probeTcp(const QString &host, int port, int timeoutMs, const std::atomic<bool> &cancel,
                QString *numericHost);

} // namespace NetVfs::Smb

#endif
