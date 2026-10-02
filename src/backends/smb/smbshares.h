// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBSHARES_H
#define NETVFS_SMBSHARES_H

#include "error.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QVector>

// SPEC-v2 XM-7: the data that crosses the process boundary to and from the
// share enumeration helper netvfs-smb-shares. Pure functions without libsmb2,
// shared by the plugin and the helper, and fuzzed (tests/fuzz/fuzz_smb_shares.cpp).
//
// Request (backend -> helper, on the helper's stdin, never argv or the
// environment): a sequence of fields, each a 32-bit big-endian length and
// that many bytes, in this order: the magic "netvfs-smb-shares/1", server
// ("host" or "host:port", numeric), user, domain, profile name, request
// timeout in milliseconds (decimal), secret. Nothing may follow.
//
// Reply (helper -> backend, on stdout): JSON objects, one per line:
//   {"name":"share","type":0,"remark":"text"}      one per share
//   {"end":N}                                     last line on success, N shares
//   {"error":"<errorName>","message":"text"}      last line on failure
namespace NetVfs::Smb {

inline constexpr const char *ShareRequestMagic = "netvfs-smb-shares/1";
inline constexpr int MaxShareRequestBytes = 64 * 1024;
inline constexpr int MaxShareOutputBytes = 1024 * 1024;
inline constexpr int MaxShareLineBytes = 8 * 1024;
inline constexpr int MaxShares = 4096;
inline constexpr int MaxRemarkLength = 256;
inline constexpr int MaxHelperMessageLength = 512;

// SHARE_INFO_1 type (MS-SRVS 2.2.2.4): the low byte is the kind, the high
// bits are flags (STYPE_SPECIAL, STYPE_TEMPORARY, cluster kinds).
inline constexpr quint32 ShareTypeMask = 0xff;
inline constexpr quint32 ShareTypeDiskTree = 0;
inline constexpr quint32 ShareTypeIpc = 3;

struct ShareRequest {
    QByteArray server;
    QByteArray user;
    QByteArray domain;
    QByteArray profile;
    int requestTimeoutMs = 0;
    QByteArray secret;
};

struct ShareInfo {
    QString name;
    quint32 type = 0;
    QString remark;
};

// A share name as the root of server mode lists it (XM-2): not empty, at
// most 80 UTF-16 units (NNLEN), none of / \ : * ? " < > | [ ] + = ; , (what
// Windows refuses), control characters or lone surrogates, not "." or "..".
bool validShareName(const QString &name);

QByteArray encodeShareRequest(const ShareRequest &request);
// False for anything but exactly one well-formed request.
bool decodeShareRequest(const QByteArray &data, ShareRequest *out);

// One reply line (without the newline).
QByteArray shareLine(const ShareInfo &share);
QByteArray endLine(int count);
QByteArray errorLine(const Result &result);

// XM-7: the helper's stdout, parsed defensively. Every limit above is
// enforced; anything malformed, truncated (no end line, a count that does
// not match) or oversized is ProtocolError; an error line becomes its
// Result (only errors a server or the network can cause pass through,
// others are ProtocolError). Shares with invalid names are an error, not
// skipped; duplicate names (case-insensitive) keep the first.
Result parseShareOutput(const QByteArray &output, QVector<ShareInfo> *shares);

// XM-7: only disk shares are listed; names ending in '$' (administrative
// shares such as C$ or ADMIN$) only with show_admin_shares=true.
bool shareVisible(const ShareInfo &share, bool showAdminShares);

} // namespace NetVfs::Smb

#endif
