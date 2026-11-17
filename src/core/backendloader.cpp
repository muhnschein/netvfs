// SPDX-License-Identifier: LGPL-2.1-or-later
#include "backendloader.h"
#include "logging.h"

#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonObject>
#include <QtCore/QPluginLoader>
#include <QtCore/QRegularExpression>

#ifndef NETVFS_BACKEND_DIR
#define NETVFS_BACKEND_DIR "/usr/lib64/netvfs/backends"
#endif

namespace NetVfs {

namespace {
bool validProviderName(const QString &provider)
{
    static const QRegularExpression pattern(QStringLiteral("^[a-z0-9]+$"));
    return pattern.match(provider).hasMatch();
}

QObject *pluginFor(const QString &provider)
{
    if (!validProviderName(provider))
        return nullptr;
    const QString fileName = QStringLiteral("libnetvfs-%1.so").arg(provider);
    for (const QString &dir : BackendLoader::searchPaths()) {
        const QString path = QDir(dir).absoluteFilePath(fileName);
        if (!QFileInfo(path).exists())
            continue;
        // Loader kept loaded on purpose: plugins stay mapped until exit.
        QPluginLoader loader(path);
        QObject *root = loader.instance();
        const BackendFactory *factory = qobject_cast<BackendFactory *>(root);
        if (!factory) {
            qCWarning(lcNetVfsCore) << "Not a netvfs backend:" << path << loader.errorString();
            continue;
        }
        if (factory->provider() != provider) {
            qCWarning(lcNetVfsCore) << "Backend" << path << "reports provider" << factory->provider();
            continue;
        }
        return root;
    }
    return nullptr;
}

BackendFactory *factoryFor(const QString &provider)
{
    return qobject_cast<BackendFactory *>(pluginFor(provider));
}
}

QStringList BackendLoader::searchPaths()
{
    QStringList paths;
    if (const QByteArray env = qgetenv("NETVFS_BACKEND_PATH"); !env.isEmpty())
        paths += QString::fromLocal8Bit(env).split(QLatin1Char(':'), NETVFS_SKIP_EMPTY_PARTS);
    paths << QStringLiteral(NETVFS_BACKEND_DIR);
    return paths;
}

Backend *BackendLoader::create(const QString &provider, Result *result)
{
    BackendFactory *factory = factoryFor(provider);
    Backend *backend = nullptr;
    const Result r = factory ? factory->create(&backend)
                             : Result(Error::Unsupported,
                                      QStringLiteral("No backend installed for provider \"%1\"").arg(provider));
    if (result)
        *result = r;
    return backend;
}

bool BackendLoader::isAvailable(const QString &provider)
{
    return factoryFor(provider) != nullptr;
}

SshKeyTools *BackendLoader::sshKeyTools()
{
    return qobject_cast<SshKeyTools *>(pluginFor(QStringLiteral("sftp")));
}

}