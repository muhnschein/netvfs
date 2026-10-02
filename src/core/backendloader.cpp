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
        // The loader instance is intentionally kept loaded: the root object is
        // shared per process and plugins stay mapped until exit.
        QPluginLoader loader(path);
        // XC-1: the metadata names the interface version; a plugin built for
        // another API version is never instantiated (its classes may still
        // cast to the current interface).
        if (const QString iid = loader.metaData().value(QStringLiteral("IID")).toString();
                !iid.isEmpty() && iid != QLatin1String(NETVFS_BACKEND_FACTORY_IID)) {
            qCWarning(lcNetVfsCore) << "Backend" << path << "has interface" << iid << "but"
                                    << NETVFS_BACKEND_FACTORY_IID << "is expected";
            continue;
        }
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
} // namespace

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
    Backend *backend = factory ? factory->create() : nullptr;
    if (result) {
        *result = backend ? Result::success()
                          : Result(Error::Unsupported,
                                   QStringLiteral("No backend installed for provider \"%1\"").arg(provider));
    }
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

} // namespace NetVfs
