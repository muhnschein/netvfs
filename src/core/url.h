// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_URL_H
#define NETVFS_URL_H

#include "error.h"
#include "types.h"

// Location URLs: sftp://, ssh:// = provider "sftp"; smb://host[/share[/path]] = "smb", option
// "share"; file:// = "local" (empty host, "localhost" accepted).
// A password in user info (any ':') is rejected with SecurityPolicy and never stored. IDN hosts
// stay Unicode in ConnectionParams::host (punycode is the backend's job, toAce()); IPv6 literals
// bracketed in the URL, not in host.
// Errors: unknown scheme, dav/davs/ftp/ftps, or file:// naming a remote host: Unsupported;
// password: SecurityPolicy; any other malformed URL (no scheme or host, bad port, bad IPv6 literal,
// bad escape, query or fragment, control char, "." or ".." component, encoded NUL): InvalidName.
// Outputs untouched on error.
// Ports 1-65535; default (sftp/ssh 22, smb 445) stored as 0.
// SMB: first path component is option "share" (omitted if none); rest is the location path with
// leading '/', or empty. sftp, local: decoded URL path ("" none, "/" root, else absolute); relative
// path given to format() becomes absolute.
// Escapes decode to bytes then Names::decode(); format() encodes Names::encode() bytes, leaves only
// unreserved chars and '/' unescaped. Scheme and ASCII hosts lower-cased; punycode decoded with
// QUrl::fromAce.
// Raw characters accepted as is (spaces in path, non-ASCII host); only control characters refused.
namespace NetVfs::Url {

// Fills provider, host, port, username and URL-derived options (those reset first; other fields and
// options kept). `path` (optional) gets the location path below the connection root,
// Paths::normalize()d.
NETVFS_EXPORT Result parse(const QString &url, ConnectionParams *params, QString *path);
NETVFS_EXPORT QString format(const ConnectionParams &params, const QString &path);
// Wire host name: punycode for IDN, IPv6 brackets stripped. Empty if unconvertible.
NETVFS_EXPORT QByteArray toAce(const QString &host);

}
#endif
