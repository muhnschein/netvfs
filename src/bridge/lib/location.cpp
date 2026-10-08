// SPDX-License-Identifier: LGPL-2.1-or-later
#include "location.h"

#include "names.h"
#include "url.h"

namespace NetVfs::Bridge {

QString LocationSpec::hostKey() const
{
    return provider + QStringLiteral("://") + params.host.toLower() + QLatin1Char(':') + QString::number(params.port);
}

QVariantMap LocationSpec::info() const
{
    QVariantMap map;
    map.insert(QStringLiteral("kind"), kind == LocationKind::Account ? QStringLiteral("account")
                                                                       : QStringLiteral("adhoc"));
    map.insert(QStringLiteral("host"), params.host);
    if (params.port > 0)
        map.insert(QStringLiteral("port"), params.port);
    if (!params.username.isEmpty())
        map.insert(QStringLiteral("user"), params.username);
    map.insert(QStringLiteral("path"), Names::encode(startPath));
    if (const QString url = Url::format(params, startPath); !url.isEmpty())
        map.insert(QStringLiteral("url"), url);
    if (kind == LocationKind::Account) {
        map.insert(QStringLiteral("accountId"), accountId);
        if (attention != Attention::None)
            map.insert(QStringLiteral("attention"), attentionToString(attention));
    }
    return map;
}

AccountDirectory::~AccountDirectory() = default;

} // namespace NetVfs::Bridge
