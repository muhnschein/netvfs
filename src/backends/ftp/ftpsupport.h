// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_FTPSUPPORT_H
#define NETVFS_FTPSUPPORT_H

#include "error.h"
#include "ftpparse.h"
#include "types.h"

#include <QtCore/QLoggingCategory>

#include <curl/curl.h>

Q_DECLARE_LOGGING_CATEGORY(lcNetVfsFtp)

// Policy and mapping helpers of the FTP backend that need no server: the
// connection options (F-1, XSEC-2), the remote path and URL encoding (XC-4)
// and the error mapping (F-7, W-13). Unit tested in tests/unit/ftp.
namespace NetVfs::Ftp {

enum class TlsMode { Explicit, Implicit, None };

struct Settings {
    TlsMode tlsMode = TlsMode::Explicit;
    QString host;
    int port = 0;
    QString pin;              // "host_key", "tls-spki-sha256 <base64 SPKI>"
    bool pinTrusted = false;  // "pin_trusted": the pin was taken from a system-trusted chain (W-4)
};

constexpr int ExplicitPort = 21;
constexpr int ImplicitPort = 990;

// Reads the options "tls_mode" (explicit | implicit | none, default
// explicit), "allow_insecure", "host_key" and "pin_trusted". `none`
// without allow_insecure=true is SecurityPolicy (F-1); unknown modes are
// SecurityPolicy as well (no silent fallback, XSEC-2).
Result settingsFrom(const ConnectionParams &params, Settings *out);

// "ftp://host:port/" or "ftps://host:port/" (IPv6 literals in brackets).
QByteArray baseUrl(const Settings &settings);
// Percent-encodes remote path bytes for a URL path after the base URL: an
// absolute path starts with "%2F" (RFC 1738 3.2.2), separators stay, every
// byte outside the unreserved set is escaped (also ';' so that libcurl
// never sees a ";type=" suffix).
QByteArray urlPath(const QByteArray &remotePath);

// Remote path bytes for a normalized netvfs path (C-15): a relative path
// is resolved against `home` (the login directory, S-19 semantics), and
// names are encoded losslessly (XC-4). InvalidName for CR, LF or
// characters the codec cannot encode, which could otherwise end a command
// on the control connection.
Result remotePath(const QString &path, const QByteArray &home, QByteArray *out);
// The parent folder and last component of an absolute remote path.
QByteArray remoteParent(const QByteArray &remote);

// F-7: maps a negative completion reply to an error. `ambiguous` is set when
// the code alone did not decide and the message heuristics fell back (a
// 550 that names no reason), so that callers may refine with a stat.
Result replyError(const Reply &reply, const QString &context, bool *ambiguous = nullptr);

// W-13 transport mapping for a libcurl result, given the last reply the
// server sent during the request (may be invalid) and whether cancel()
// was requested.
Result curlError(CURLcode code, const Reply &reply, bool canceled, const QString &context);

// XSEC-2 for explicit FTPS. Distribution builds of libcurl refuse to reuse
// an explicit-TLS control connection when TLS is required (CURLUSESSL_ALL),
// so every request would open a new connection and sign in again. The
// control connection therefore runs in libcurl's "try" mode, and this guard
// enforces "TLS or nothing" on the server replies, which libcurl hands to
// the header callback before it acts on them: a greeting must be followed
// by 234 to AUTH TLS (else USER would follow in clear text), and the reply
// to PROT P must be positive (else data would flow in clear text). A
// greeting that claims a completed login (230) is refused as well. A
// verdict other than Continue makes the header callback abort the request
// before libcurl sends anything else.
class TlsGuard
{
public:
    enum class Verdict { Continue, AuthRefused, ProtectionRefused, Unexpected };

    Verdict reply(int code);
    void reset() { m_state = State::Idle; }

private:
    enum class State { Idle, AwaitAuth, AwaitLogin, AwaitPbsz, AwaitProt };
    State m_state = State::Idle;
};

// Log helper (XSEC-5): the reply as text, for debug output only.
QString replyForLog(const Reply &reply);

} // namespace NetVfs::Ftp

#endif
