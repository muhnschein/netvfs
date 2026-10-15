// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_URL_H
#define NETVFS_URL_H

#include "error.h"
#include "types.h"

// SPEC-v2 XH-6: location URLs.
//   sftp://, ssh://                  -> provider "sftp"
//   smb://host[/share[/path]]        -> provider "smb", option "share"
//   file://                          -> provider "local"
// User info may carry a user name; a password (any ':' in the user info, even
// an empty password) is rejected with SecurityPolicy "passwords in URLs are
// not accepted" and never stored. IDN hosts are kept in Unicode in
// ConnectionParams::host (punycode on the wire is the backend's job, see
// toAce()); IPv6 literals use brackets in the URL and none in
// ConnectionParams::host.
//
// Decisions the spec leaves open:
//  - Errors: an unknown scheme, a dav://, davs://, ftp:// or ftps:// URL ("no
//    longer supported"), or a "file://" URL naming a remote host, is
//    Unsupported; a password is SecurityPolicy; every other malformed URL
//    (no scheme or host, bad port, bad IPv6 literal, bad percent escape, a
//    query or fragment, a control character, a "." or ".." path component, an
//    encoded NUL) is InvalidName. On any error the outputs are untouched.
//  - Ports: 1-65535. A port equal to the scheme's default (sftp/ssh 22,
//    smb 445) is stored as 0.
//  - SMB: the first path component is the option "share" (omitted if there is
//    none); the rest is the location path with a leading '/', or empty.
//  - sftp, local: the location path is the decoded URL path ("" for no
//    path, "/" for the root, else absolute). A relative location path given to
//    format() becomes absolute in the URL.
//  - file://: provider "local", empty host ("localhost" is accepted).
//  - Percent escapes are decoded to bytes and then Names::decode()d, so
//    non-UTF-8 bytes survive (XC-4); format() encodes Names::encode() bytes
//    and keeps only unreserved characters and '/' unescaped. The scheme and
//    ASCII host names are lower-cased; punycode labels are decoded with
//    QUrl::fromAce (only below top-level domains Qt allows for IDN).
//  - Raw characters in a URL are accepted as is (spaces in a path, non-ASCII
//    in a host); only control characters are refused.
namespace NetVfs::Url {

// Fills provider, host, port, username and the options named above (those
// URL-derived option keys are reset first; other fields and options are kept).
// `path` (optional) receives the location path below the connection root,
// normalised (Paths::normalize) and lossless per XC-4.
NETVFS_EXPORT Result parse(const QString &url, ConnectionParams *params, QString *path);
// Empty string for a provider without a URL scheme.
NETVFS_EXPORT QString format(const ConnectionParams &params, const QString &path);
// Host name for the wire: punycode for IDN, brackets stripped for IPv6.
// Empty for a name that cannot be converted.
NETVFS_EXPORT QByteArray toAce(const QString &host);

} // namespace NetVfs::Url

#endif
