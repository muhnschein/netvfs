// SPDX-License-Identifier: LGPL-2.1-or-later
#include "davconfig.h"

#include <QtCore/QRegularExpression>

#include <algorithm>

namespace NetVfs::WebDav {

namespace {

Result parseFlavor(const QString &value, Flavor *out)
{
    if (value.isEmpty() || value == QLatin1String("auto"))
        *out = Flavor::Auto;
    else if (value == QLatin1String("nextcloud"))
        *out = Flavor::Nextcloud;
    else if (value == QLatin1String("generic"))
        *out = Flavor::Generic;
    else
        return Result(Error::Internal, QStringLiteral("Unknown WebDAV flavor \"%1\"").arg(value));
    return Result::success();
}

Result parseScheme(const ConnectionParams &params, QByteArray *scheme)
{
    const QString tls = params.option(QStringLiteral("tls"), QStringLiteral("https"));
    if (tls == QLatin1String("https")) {
        *scheme = "https";
        return Result::success();
    }
    if (tls != QLatin1String("http"))
        return Result(Error::Internal, QStringLiteral("Unknown tls option \"%1\"").arg(tls));
    // W-2, W-5: plain HTTP only with the account's explicit consent.
    if (!params.flag(QStringLiteral("allow_insecure")))
        return Result(Error::SecurityPolicy, QStringLiteral("Unencrypted HTTP needs the account's consent (allow_insecure)"));
    *scheme = "http";
    return Result::success();
}

bool hasNextcloudToken(const QStringList &classes)
{
    return std::any_of(classes.begin(), classes.end(), [](const QString &token) {
        return token.startsWith(QLatin1String("nextcloud-")) || token.startsWith(QLatin1String("nc-"))
            || token.startsWith(QLatin1String("oc-"));
    });
}

bool hasNextcloudCookie(const QByteArray &setCookie)
{
    static const QRegularExpression session(QStringLiteral("(^|[,;]\\s*)oc[a-z0-9]{10}="));
    const QString cookies = QString::fromLatin1(setCookie);
    return cookies.contains(QLatin1String("nc_sameSiteCookie")) || cookies.contains(QLatin1String("oc_sessionPassphrase"))
        || session.match(cookies).hasMatch();
}

} // namespace

Result parseConfig(const ConnectionParams &params, Config *out)
{
    Config config;
    Result r = parseScheme(params, &config.origin.scheme);
    if (!r.ok())
        return r;
    config.origin.host = hostForUrl(params.host);
    if (config.origin.host.isEmpty())
        return Result(Error::NetworkUnreachable, QStringLiteral("Invalid server name"));
    config.origin.port = params.port > 0 ? params.port : defaultPort(config.origin.scheme);
    r = encodeBasePath(params.option(QStringLiteral("base_path"), QStringLiteral("/")), &config.basePath);
    if (!r.ok())
        return r;
    const QString authMode = params.option(QStringLiteral("auth_mode"), QStringLiteral("password"));
    if (authMode != QLatin1String("password") && authMode != QLatin1String("token"))
        return Result(Error::Internal, QStringLiteral("Unknown auth_mode \"%1\"").arg(authMode));
    config.tokenAuth = authMode == QLatin1String("token");
    r = parseFlavor(params.option(QStringLiteral("flavor")), &config.flavor);
    if (!r.ok())
        return r;
    config.username = params.username;
    config.pin = params.option(QStringLiteral("host_key")).trimmed();
    config.pinVerifyPeer = params.flag(QStringLiteral("tls_verify_peer"));
    *out = config;
    return Result::success();
}

ServerFeatures detectFeatures(const QMap<QByteArray, QByteArray> &headers, const QByteArray &basePath)
{
    ServerFeatures features;
    for (const QByteArray &token : headers.value("dav").split(',')) {
        if (const QString item = QString::fromLatin1(token.trimmed()).toLower(); !item.isEmpty())
            features.davClasses << item;
    }
    features.partialUpdate = features.davClasses.contains(QStringLiteral("sabredav-partialupdate"));
    features.nextcloudHints = hasNextcloudToken(features.davClasses) || hasNextcloudCookie(headers.value("set-cookie"))
        || basePath.contains("/remote.php/");
    return features;
}

} // namespace NetVfs::WebDav
