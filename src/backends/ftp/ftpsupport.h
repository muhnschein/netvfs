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
    bool verifyPeer = false;  // "tls_verify_peer": the pinned chain was system trusted (W-4)
    QByteArray testCaFile;    // "test_ca_file", builds with NETVFS_TLS_TEST_HOOKS only
};

constexpr int ExplicitPort = 21;
constexpr int ImplicitPort = 990;

// Reads the options "tls_mode" (explicit | implicit | none, default
// explicit), "allow_insecure", "host_key" and "tls_verify_peer". `none`
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

// XSEC-2 for explicit FTPS. Some builds of libcurl (measured: Ubuntu 24.04's
// 8.5.0-2ubuntu10.15, which carries a security backport on connection
// reuse; vanilla 8.5.0 and 8.20.0 reuse the connection) refuse to reuse an
// explicit-TLS control connection when TLS is required (CURLUSESSL_ALL), so
// every request would open a new connection and sign in again. The control
// connection therefore runs in libcurl's "try" mode, in which libcurl itself
// carries on in clear text when AUTH TLS or PROT P is refused, and this guard
// enforces "TLS or nothing" on the server replies, which libcurl hands to
// the header callback before it acts on them: a greeting must be followed
// by 234 to AUTH TLS (else USER would follow in clear text), and the reply
// to PROT P must be positive (else data would flow in clear text). A
// greeting that claims a completed login (230) is refused as well. A
// verdict other than Continue makes the header callback abort the request
// before libcurl sends anything else.
//
// The guard must see the replies exactly as libcurl does, or a crafted
// reply could hide a refusal from it: feed() therefore splits the bytes
// into lines and ends a reply at the first line that is "ddd " (three
// digits and a space), whatever the reply started with (libcurl's
// ftp_endofresp), instead of using the stricter RFC 959 grammar of
// ReplyReader. A new request starts with reset(); a 220 counts as a
// greeting only then, never as the answer to AUTH TLS.
class TlsGuard
{
public:
    enum class Verdict { Continue, AuthRefused, ProtectionRefused, Unexpected };

    // The bytes of one header callback call. The first verdict other than
    // Continue is returned at once.
    Verdict feed(const char *data, size_t size);
    // One complete reply with `code` (what feed() extracts).
    Verdict reply(int code);
    // A new request: the control connection is either the established one
    // (nothing to wait for) or a new one that starts with a greeting.
    void reset();
    // The line that completed the reply of the last verdict, for the log.
    const QByteArray &lastLine() const { return m_lastLine; }

private:
    enum class State { Idle, AwaitAuth, AwaitLogin, AwaitPbsz, AwaitProt };
    static constexpr int MaxLineBytes = 512;
    State m_state = State::Idle;
    QByteArray m_line;       // the line being received (cut at MaxLineBytes)
    QByteArray m_lastLine;
};

// Log helper (XSEC-5): the reply as text, for debug output only.
QString replyForLog(const Reply &reply);
// The same for one raw line of server text.
QString lineForLog(const QByteArray &line);

} // namespace NetVfs::Ftp

#endif
