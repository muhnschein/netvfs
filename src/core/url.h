// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_URL_H
#define NETVFS_URL_H

#include "error.h"
#include "types.h"

// SPEC-v2 XH-6: location URLs.
//   sftp://, ssh://                  -> provider "sftp"
//   smb://host[/share[/path]]        -> provider "smb", option "share"
//   dav://, davs://, http://, https:// -> provider "webdav", options "tls", "base_path"
//   ftp://, ftps://                  -> provider "ftp", option "tls_mode"
//   file://                          -> provider "local"
// User info may carry a user name; a password is rejected with
// SecurityPolicy "passwords in URLs are not accepted" and never stored.
// IDN hosts are kept in Unicode in ConnectionParams::host (punycode on the
// wire is the backend's job, see toAce()); IPv6 literals use brackets.
namespace NetVfs::Url {

// `path` receives the location path below the connection root (normalised,
// lossless per XC-4 after percent-decoding).
NETVFS_EXPORT Result parse(const QString &url, ConnectionParams *params, QString *path);
NETVFS_EXPORT QString format(const ConnectionParams &params, const QString &path);
// Host name for the wire: punycode for IDN, brackets stripped for IPv6.
NETVFS_EXPORT QByteArray toAce(const QString &host);

} // namespace NetVfs::Url

#endif
