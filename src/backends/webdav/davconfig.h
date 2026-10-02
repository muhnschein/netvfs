// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DAVCONFIG_H
#define NETVFS_DAVCONFIG_H

#include "davurl.h"
#include "types.h"

#include <QtCore/QMap>
#include <QtCore/QStringList>

// Account options and server features of the WebDAV backend (SPEC-v2 W-2,
// W-3, W-4, W-10, W-11).
namespace NetVfs::WebDav {

enum class Flavor { Auto, Nextcloud, Generic };

struct Config {
    Origin origin;
    QByteArray basePath;            // encoded, "/" ... "/"
    QString username;               // ConnectionParams::username (fallback)
    Flavor flavor = Flavor::Auto;
    bool tokenAuth = false;         // auth_mode=token: the secret is a Bearer token
    QString pin;                    // host_key
    bool pinVerifyPeer = false;     // tls_verify_peer (W-4, see webdavbackend.h)
    QByteArray testCaFile;          // test_ca_file (test builds only)

    QByteArray baseUrl() const { return origin.toUrl() + basePath; }
};

// Options (W-2):
//   tls             "https" (default) | "http" (needs allow_insecure=true)
//   allow_insecure  the account's consent to plain HTTP
//   base_path       default "/"
//   auth_mode       "password" (default) | "token"
//   flavor          "auto" (default) | "nextcloud" | "generic"
//   host_key        TLS pin "tls-spki-sha256 <base64 SPKI>" (XC-16)
//   tls_verify_peer with a pin: also verify chain and host name (W-4)
// SecurityPolicy for plain HTTP without consent, Internal for unknown
// values, NetworkUnreachable for an unusable host name.
Result parseConfig(const ConnectionParams &params, Config *out);

// What an OPTIONS answer tells about the server (W-3).
struct ServerFeatures {
    QStringList davClasses;          // DAV header tokens, lower case
    bool partialUpdate = false;      // "sabredav-partialupdate" (W-10)
    bool nextcloudHints = false;     // see detectFeatures()
};

// Nextcloud/ownCloud detection for flavor=auto, from the response headers
// of OPTIONS (no status.php request): a DAV token starting with
// "nextcloud-", "nc-" or "oc-"; a Set-Cookie for "nc_sameSiteCookie*",
// "oc_sessionPassphrase" or an "oc<instance id>" session; or a base path
// below "/remote.php/". `headers` are lower-case names as in Response.
ServerFeatures detectFeatures(const QMap<QByteArray, QByteArray> &headers, const QByteArray &basePath);

} // namespace NetVfs::WebDav

#endif
