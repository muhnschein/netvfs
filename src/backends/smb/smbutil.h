// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBUTIL_H
#define NETVFS_SMBUTIL_H

#include "error.h"

#include <QtCore/QByteArray>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>

#include <atomic>

#include <signal.h>

struct smb2_context;

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
inline constexpr const char *ShareRefusedMessage =
    "the server refused the share: this account may not use it, or the server and this device have no "
    "encryption cipher in common";
inline constexpr const char *ConnectionLostMessage = "the connection to the server was lost";
inline constexpr const char *GuestMappedMessage =
    "the server signed this account in as a guest instead of checking the password; "
    "the security profile does not allow that";
inline constexpr const char *DfsDetail = "DFS referral";        // XM-9

inline constexpr quint32 MaxChunkSize = 1024 * 1024;        // M-11
inline constexpr quint32 FallbackChunkSize = 64 * 1024;     // server reported no maximum
inline constexpr qint64 MaxInFlight = 4 * 1024 * 1024;      // XM-6: per handle

// M-11: min(server maximum, 1 MiB).
quint32 chunkSize(quint32 serverMaximum);

// ------------------------------------------------------- profiles (XM-1)

// SPEC-v2 XM-1 (amends M-1..M-3). The account option "security_profile"
// selects one; "require_encryption=false" without it means Signed.
enum class Profile { Strict, Signed, Legacy, Guest };

enum class Encryption {
    Required,       // smb2_set_seal(1): the session fails without encryption
    IfServerAsks,   // seal not set: libsmb2 encrypts when the server or the share requires it
    Off             // smb2_set_seal(0): encryption is not offered
};

struct ProfileSettings {
    quint16 version = 0;            // smb2_set_version(): SMB2_VERSION_ANY3 or SMB2_VERSION_ANY
    bool signing = true;            // signing required
    Encryption encryption = Encryption::Required;
    bool guest = false;             // empty user name, no password (NTLMSSP anonymous)
};

// Unknown profile names are SecurityPolicy: nothing weaker is guessed (XSEC-2).
Result profileFromOptions(const QVariantMap &options, Profile *out);
ProfileSettings settingsFor(Profile profile);
QString profileName(Profile profile);
// M-1, defence in depth: the dialect the server chose must be one the
// profile offered.
bool dialectAllowed(Profile profile, quint16 dialect);
// XM-1: SMB2_SESSION_FLAG_IS_GUEST or _IS_NULL in a session that was meant
// to be authenticated is SecurityPolicy; the guest profile accepts them.
Result checkSessionFlags(Profile profile, quint16 sessionFlags);

// SPEC-smb section 3 as amended by XM-1, on a fresh context: dialects,
// signing, encryption, NTLMSSP, the request timeout (M-7) and the identity.
// The guest profile sends an empty user name and no password. M-5: the
// password is set last, after neutraliseUserFile().
void applyProfile(smb2_context *ctx, Profile profile, const QString &user, const QString &domain,
                  const QByteArray &secret, int requestTimeoutMs);
// After smb2_connect_share() on a context set up by applyProfile(): the
// negotiated dialect (M-1) and the session flags (guest mapping).
Result checkSession(smb2_context *ctx, Profile profile);

// M-1: SMB 3.0, 3.0.2 and 3.1.1.
bool isSmb3Dialect(quint16 dialect);
QString dialectName(quint16 dialect);

// --------------------------------------------------- shares (XM-2, XM-3)

// XM-3: options["shares"], a QStringList or a comma separated string;
// trimmed, invalid names dropped, de-duplicated without regard to case
// (share names are case-insensitive), first spelling kept.
QStringList configuredShares(const QVariantMap &options);
// Appends the names of `more` that `list` does not contain yet (case-insensitive).
void mergeShareNames(QStringList *list, const QStringList &more);

// ------------------------------------------------------- paths and names

// XC-4 for SMB: libsmb2 converts UTF-16 names to UTF-8 and writes unpaired
// surrogates as their 3-byte form (WTF-8, vendor/patches/libsmb2/0006).
// decodeName() turns such a unit into the same lone QChar, encodeName()
// reverses it exactly, so names that Windows allows survive the round trip.
QString decodeName(const char *utf8);
QByteArray encodeName(const QString &name);

// M-8, M-9, C-15: normalizes, strips a leading '/', rejects Windows-invalid
// components. `out` is WTF-8 (encodeName), relative to the share root, '/'
// separated.
Result translatePath(const QString &path, QByteArray *out);

// XM-2: a path in server mode is "/<share>/<rest>". `share` is empty for
// the root; `rest` is relative to the share's root (empty for the share
// itself).
Result splitServerPath(const QString &path, QString *share, QByteArray *rest);

// ---------------------------------------------------------------- errors

// Classifies a failed libsmb2 request. `ntStatus` is smb2_get_nterror() (the
// only input that distinguishes server answers); `errnoValue` (positive) only
// distinguishes TCP-level failures when there is no NT status.
Result errorForStatus(quint32 ntStatus, int errnoValue, Stage stage, const QString &context);

// The connection broke while a request was outstanding: SecurityPolicy during
// session setup (the server dropped us), ConnectionLost afterwards (XC-21).
Result connectionLost(Stage stage);

// A failed TCP connect (M-10): Timeout, Canceled or NetworkUnreachable.
Result errorForSocket(int errnoValue, const QString &context);

// "host" or "host:port" in the form smb2_connect_share() parses ("[v6]:port").
QByteArray serverString(const QString &numericHost, int port);

// M-10: resolves `host` and opens (then closes) a TCP connection to `port`
// within `timeoutMs`, polling `cancel`. On success `*numericHost` is the
// address that answered.
Result probeTcp(const QString &host, int port, int timeoutMs, const std::atomic<bool> &cancel,
                QString *numericHost);

// M-5: libsmb2 lets a file named by NTLM_USER_FILE replace the password set
// with smb2_set_password() (lib/init.c: smb2_set_user() and smb2_set_domain()
// call smb2_set_password_from_file(); lib/ntlmssp.c does it again when the
// server's challenge supplies the domain). The variable is removed from the
// process environment before every session setup and before the share
// enumeration helper starts.
void neutraliseUserFile();

// libsmb2 writes with writev(), and the share helper's stdin is a pipe; a
// peer that went away would otherwise kill the whole process with SIGPIPE.
// The signal is blocked on this thread while the guard lives and one raised
// meanwhile is discarded.
class SigPipeGuard
{
public:
    SigPipeGuard();
    ~SigPipeGuard();
    SigPipeGuard(const SigPipeGuard &) = delete;
    SigPipeGuard &operator=(const SigPipeGuard &) = delete;

private:
    sigset_t m_set = {};
    sigset_t m_old = {};
};

} // namespace NetVfs::Smb

#endif
