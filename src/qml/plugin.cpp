// SPDX-License-Identifier: LGPL-2.1-or-later
#include "consentmodel.h"
#include "netvfshelpers.h"
#include "netvfsprobe.h"
#include "providerdescriptors.h"
#include "sshkeytool.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QLocale>
#include <QtCore/QTranslator>
#include <QtQml/QQmlEngine>
#include <QtQml/QQmlExtensionPlugin>
#include <QtQml/qqml.h>

#include <memory>

#ifndef NETVFS_TRANSLATIONS_DIR
#define NETVFS_TRANSLATIONS_DIR "/usr/share/translations"
#endif

namespace {

// Installed into the application while the engine lives (as the platform's
// account plugins do), so qsTrId() in our pages resolves.
class EngineTranslator : public QTranslator
{
    Q_DISABLE_COPY(EngineTranslator)
public:
    explicit EngineTranslator(QObject *parent)
        : QTranslator(parent)
    {
    }

    ~EngineTranslator() override
    {
        if (m_installed)
            QCoreApplication::removeTranslator(this);
    }

    void loadAndInstall(const QString &fileName)
    {
        if (load(fileName, QStringLiteral(NETVFS_TRANSLATIONS_DIR)))
            m_installed = QCoreApplication::installTranslator(this);
    }

    void loadAndInstall(const QLocale &locale, const QString &fileName)
    {
        if (load(locale, fileName, QStringLiteral("-"), QStringLiteral(NETVFS_TRANSLATIONS_DIR)))
            m_installed = QCoreApplication::installTranslator(this);
    }

private:
    bool m_installed = false;
};


} // namespace

class NetVfsAccountsPlugin : public QQmlExtensionPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.qt-project.Qt.QQmlExtensionInterface")

public:
    void initializeEngine(QQmlEngine *engine, const char *uri) override
    {
        Q_UNUSED(uri)
        // Engineering English first, so the locale's translation wins.
        auto engineering = std::make_unique<EngineTranslator>(engine);
        engineering->loadAndInstall(QStringLiteral("netvfs_eng_en"));
        engineering.release();   // owned by the engine
        auto translation = std::make_unique<EngineTranslator>(engine);
        translation->loadAndInstall(QLocale(), QStringLiteral("netvfs"));
        translation.release();
    }

    void registerTypes(const char *uri) override
    {
        Q_ASSERT(QLatin1String(uri) == QLatin1String("org.netvfs.accounts"));
        qmlRegisterType<NetVfsUi::NetVfsProbe>(uri, 1, 0, "NetVfsProbe");
        qmlRegisterType<NetVfsUi::SshKeyTool>(uri, 1, 0, "SshKeyTool");
        qmlRegisterType<NetVfsUi::ConsentModel>(uri, 1, 0, "NetVfsConsentModel");
        // Singletons are owned by the engine.
        qmlRegisterSingletonType<NetVfsUi::Helpers>(uri, 1, 0, "NetVfsHelpers", [](QQmlEngine *, QJSEngine *) -> QObject * {
            return std::make_unique<NetVfsUi::Helpers>().release();
        });
        qmlRegisterSingletonType<NetVfsUi::InputRules>(uri, 1, 0, "NetVfsInput", [](QQmlEngine *, QJSEngine *) -> QObject * {
            return std::make_unique<NetVfsUi::InputRules>().release();
        });
        qmlRegisterSingletonType<NetVfsUi::ProviderDescriptors>(
                    uri, 1, 0, "NetVfsProviders", [](QQmlEngine *, QJSEngine *) -> QObject * {
            return std::make_unique<NetVfsUi::ProviderDescriptors>().release();
        });
    }
};

#include "plugin.moc"
