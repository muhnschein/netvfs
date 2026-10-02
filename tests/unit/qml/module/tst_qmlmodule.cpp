// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakebackend.h"

#include <QtCore/QDir>
#include <QtCore/QDirIterator>
#include <QtCore/QFile>
#include <QtCore/QProcess>
#include <QtCore/QRegularExpression>
#include <QtCore/QSet>
#include <QtCore/QStandardPaths>
#include <QtCore/QTranslator>
#include <QtCore/QXmlStreamReader>
#include <QtQml/QQmlComponent>
#include <QtQml/QQmlEngine>
#include <QtTest/QtTest>

#include <memory>

namespace {
const QString SourceDir = QStringLiteral(NETVFS_SOURCE_DIR);
const QString BuildDir = QStringLiteral(NETVFS_TEST_BUILD_DIR);

QString readFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return QString();
    return QString::fromUtf8(file.readAll());
}

QStringList filesIn(const QString &dir, const QStringList &patterns)
{
    QStringList files;
    QDirIterator it(SourceDir + QLatin1Char('/') + dir, patterns, QDir::Files);
    while (it.hasNext())
        files << it.next();
    files.sort();
    return files;
}

QStringList qmlFiles()
{
    return filesIn(QStringLiteral("src/qml"), { QStringLiteral("*.qml") })
            + filesIn(QStringLiteral("accounts/ui"), { QStringLiteral("*.qml") });
}

// Source without // comments, so rules match code only.
QString codeOf(const QString &path)
{
    QStringList lines = readFile(path).split(QLatin1Char('\n'));
    static const QRegularExpression comment(QStringLiteral("(^|\\s)//.*$"));
    for (QString &line : lines)
        line.remove(comment);
    return lines.join(QLatin1Char('\n'));
}

QSet<QString> matches(const QString &text, const QRegularExpression &pattern)
{
    QSet<QString> found;
    QRegularExpressionMatchIterator it = pattern.globalMatch(text);
    while (it.hasNext())
        found.insert(it.next().captured(1));
    return found;
}

// Element values of a provider or service file, keyed by path
// ("service/type", "setting:method", ...); attributes as "element@attr".
QMap<QString, QString> readXml(const QString &path)
{
    QMap<QString, QString> values;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return values;
    QXmlStreamReader xml(&file);
    QStringList stack;
    QString settingName;
    while (!xml.atEnd()) {
        xml.readNext();
        if (xml.isStartElement()) {
            stack << xml.name().toString();
            for (const QXmlStreamAttribute &attribute : xml.attributes())
                values.insert(stack.join(QLatin1Char('/')) + QLatin1Char('@') + attribute.name().toString(),
                              attribute.value().toString());
            settingName = xml.attributes().value(QStringLiteral("name")).toString();
        } else if (xml.isEndElement()) {
            stack.removeLast();
        } else if (xml.isCharacters() && !xml.isWhitespace()) {
            const QString key = stack.last() == QLatin1String("setting")
                    ? QStringLiteral("setting:") + settingName : stack.join(QLatin1Char('/'));
            values.insert(key, xml.text().toString());
        }
    }
    if (xml.hasError())
        values.insert(QStringLiteral("error"), xml.errorString());
    return values;
}
} // namespace

class TestQmlModule : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase()
    {
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
    }

    void pluginRegistersTypes()
    {
        // SPEC 7.2: the C++ types of org.netvfs.accounts 1.0, usable from QML.
        QQmlEngine engine;
        engine.addImportPath(BuildDir + QStringLiteral("/qml"));
        QQmlComponent component(&engine);
        component.setData(
            "import QtQml 2.0\n"
            "import org.netvfs.accounts 1.0\n"
            "QtObject {\n"
            "    property NetVfsProbe probe: NetVfsProbe {}\n"
            "    property SshKeyTool keys: SshKeyTool {}\n"
            "    property int port: NetVfsHelpers.defaultPort(\"smb\")\n"
            "    property bool idle: probe.state === NetVfsProbe.Idle && !probe.busy\n"
            "    property bool unchecked: probe.identityStatus === NetVfsProbe.IdentityNotChecked\n"
            "    property int authFailed: NetVfsProbe.AuthFailed\n"
            "    property bool keyEmpty: keys.state === SshKeyTool.Empty && !keys.hasKey\n"
            "    property string app: NetVfsHelpers.credentialsApplication\n"
            "    property string folder: NetVfsHelpers.defaultBackupsPath\n"
            "    property bool identified: probe.state === NetVfsProbe.Identified\n"
            "    function run() {\n"
            "        probe.identify(NetVfsHelpers.makeParams(\"fake\", \"server\", \"\", \"user\", {}))\n"
            "    }\n"
            "}\n",
            QUrl());
        std::unique_ptr<QObject> object(component.create());
        QVERIFY2(object, qPrintable(component.errorString()));
        QCOMPARE(object->property("port").toInt(), 445);
        QVERIFY(object->property("idle").toBool());
        QVERIFY(object->property("unchecked").toBool());
        QCOMPARE(object->property("authFailed").toInt(), 6);
        QVERIFY(object->property("keyEmpty").toBool());
        QCOMPARE(object->property("app").toString(), QStringLiteral("netvfs"));
        QCOMPARE(object->property("folder").toString(), QStringLiteral("Sailfish OS/Backups"));

        NetVfs::Test::FakeServer::instance()->reset();
        QVERIFY(QMetaObject::invokeMethod(object.get(), "run"));
        QTRY_VERIFY(object->property("identified").toBool());
    }

    void qmldirMatchesFiles()
    {
        const QString qmldir = readFile(SourceDir + QStringLiteral("/src/qml/qmldir"));
        QVERIFY(qmldir.startsWith(QStringLiteral("module org.netvfs.accounts\nplugin netvfsaccountsplugin\n")));
        const QSet<QString> listed = matches(qmldir, QRegularExpression(QStringLiteral("^\\w+ 1\\.0 (\\w+\\.qml)$"),
                                                                        QRegularExpression::MultilineOption));
        QSet<QString> present;
        for (const QString &file : filesIn(QStringLiteral("src/qml"), { QStringLiteral("*.qml") }))
            present.insert(QFileInfo(file).fileName());
        QCOMPARE(listed, present);
        const QString pri = readFile(SourceDir + QStringLiteral("/src/qml/qml.pri"));
        for (const QString &file : present)
            QVERIFY2(pri.contains(QStringLiteral("    ") + file), qPrintable(file + QStringLiteral(" not installed")));
        for (const QString &file : present)
            QVERIFY2(QFile::exists(BuildDir + QStringLiteral("/qml/org/netvfs/accounts/") + file), qPrintable(file));
    }

    void qmllintAccepts_data()
    {
        QTest::addColumn<QString>("file");
        for (const QString &file : qmlFiles())
            QTest::newRow(qPrintable(QFileInfo(file).fileName())) << file;
    }

    void qmllintAccepts()
    {
        QFETCH(QString, file);
        QString qmllint = QStandardPaths::findExecutable(QStringLiteral("qmllint"), { QStringLiteral(NETVFS_TEST_QT_BINS) });
        if (qmllint.isEmpty())
            qmllint = QStandardPaths::findExecutable(QStringLiteral("qmllint"));
        if (qmllint.isEmpty())
            QSKIP("qmllint is not installed");
        QProcess process;
        process.setProcessChannelMode(QProcess::MergedChannels);
        process.start(qmllint, { file });
        QVERIFY(process.waitForFinished(30000));
        QVERIFY2(process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0,
                 qPrintable(QString::fromLocal8Bit(process.readAll())));
    }

    void qt56Compatible_data()
    {
        QTest::addColumn<QString>("file");
        for (const QString &file : qmlFiles())
            QTest::newRow(qPrintable(QFileInfo(file).fileName())) << file;
    }

    void qt56Compatible()
    {
        // The target runs Qt 5.6: ES5 JavaScript and no QML features from later releases.
        QFETCH(QString, file);
        const QString code = codeOf(file);
        const struct {
            const char *pattern;
            const char *what;
        } rules[] = {
            { "=>", "arrow function" },
            { "\\blet\\s+\\w", "let" },
            { "\\bconst\\s+\\w", "const" },
            { "`", "template literal" },
            { "\\?\\?|\\?\\.", "?? or ?." },
            { "\\brequired\\s+property\\b", "required property (5.15)" },
            { "^\\s*component\\s+\\w+\\s*:", "inline component (5.15)" },
            { "\\b(top|bottom|left|right)?[pP]adding\\s*:", "positioner padding (5.7)" },
            { "Qt\\.callLater", "Qt.callLater (5.8)" },
        };
        for (const auto &rule : rules) {
            const QRegularExpression pattern(QLatin1String(rule.pattern), QRegularExpression::MultilineOption);
            QVERIFY2(!pattern.match(code).hasMatch(), rule.what);
        }
        static const QRegularExpression quickImport(QStringLiteral("^import QtQuick (\\d+)\\.(\\d+)"),
                                                    QRegularExpression::MultilineOption);
        const QRegularExpressionMatch match = quickImport.match(code);
        QVERIFY2(match.hasMatch(), "imports QtQuick");
        QVERIFY2(match.captured(1).toInt() == 2 && match.captured(2).toInt() <= 6, "QtQuick 2.6 at most");
    }

    void platformTypes()
    {
        // U-1, U-2, R1: only the closed types and members listed in SPEC 7.1.
        const QSet<QString> closedTypes {
            QStringLiteral("AccountCreationAgent"), QStringLiteral("AccountSettingsAgent"),
            QStringLiteral("AccountCredentialsAgent"), QStringLiteral("AccountBusyPage"),
            QStringLiteral("StandardAccountSettingsPullDownMenu"), QStringLiteral("AccountCredentialsUpdater")
        };
        const QSet<QString> openTypes {
            // QtQuick, Silica, Sailfish.Pickers, Sailfish.Accounts
            QStringLiteral("Item"), QStringLiteral("Column"), QStringLiteral("Row"), QStringLiteral("Component"),
            QStringLiteral("QtObject"), QStringLiteral("Dialog"), QStringLiteral("Page"),
            QStringLiteral("SilicaFlickable"), QStringLiteral("DialogHeader"), QStringLiteral("PageHeader"),
            QStringLiteral("Label"), QStringLiteral("TextField"), QStringLiteral("PasswordField"),
            QStringLiteral("ComboBox"), QStringLiteral("ContextMenu"), QStringLiteral("MenuItem"),
            QStringLiteral("TextSwitch"), QStringLiteral("Button"), QStringLiteral("SectionHeader"),
            QStringLiteral("DetailItem"), QStringLiteral("VerticalScrollDecorator"), QStringLiteral("BusyIndicator"),
            QStringLiteral("FilePickerPage"), QStringLiteral("Account"), QStringLiteral("AccountManager"),
            // org.netvfs.accounts
            QStringLiteral("NetVfsProbe"), QStringLiteral("SshKeyTool"), QStringLiteral("NetVfsAccountSetup"),
            QStringLiteral("NetVfsCreationAgent"), QStringLiteral("NetVfsSettingsAgent"),
            QStringLiteral("NetVfsUpdateAgent"), QStringLiteral("NetVfsSettingsPage"),
            QStringLiteral("ConnectionDialog"), QStringLiteral("ProbeBusyPage"),
            QStringLiteral("ServerIdentityDialog"), QStringLiteral("SshKeyPage")
        };
        const QSet<QString> agentMembers {
            QStringLiteral("initialPage"), QStringLiteral("delayDeletion"), QStringLiteral("accountManager"),
            QStringLiteral("accountProvider"), QStringLiteral("endDestination"), QStringLiteral("endDestinationAction"),
            QStringLiteral("endDestinationProperties"), QStringLiteral("endDestinationReplaceTarget"),
            QStringLiteral("accountCreated"), QStringLiteral("accountCreationError"),
            QStringLiteral("goToEndDestination"), QStringLiteral("accountId"), QStringLiteral("accountsHeaderText"),
            QStringLiteral("accountIsReadOnly"), QStringLiteral("accountNotSignedIn"),
            QStringLiteral("accountDeletionRequested"), QStringLiteral("canCancelUpdate"),
            QStringLiteral("credentialsUpdated"), QStringLiteral("credentialsUpdateError")
        };
        static const QRegularExpression instantiation(QStringLiteral("(?:^|[\\s:])([A-Z]\\w*)\\s*\\{"),
                                                      QRegularExpression::MultilineOption);
        static const QRegularExpression agentUse(QStringLiteral("\\b(?:root|agent)\\.([a-zA-Z_]\\w*)"));
        static const QRegularExpression declared(
                    QStringLiteral("(?:property\\s+[\\w.]+\\s+|function\\s+|signal\\s+)([a-zA-Z_]\\w*)"));
        for (const QString &file : qmlFiles()) {
            const QString code = codeOf(file);
            for (const QString &forbidden : { QStringLiteral("OnlineSync"), QStringLiteral("AccountFactory"),
                                               QStringLiteral("StandardAccountSettingsDisplay"),
                                               QStringLiteral("AccountAuthenticator") })
                QVERIFY2(!code.contains(forbidden), qPrintable(file + QStringLiteral(": ") + forbidden));
            for (const QString &type : matches(code, instantiation))
                QVERIFY2(closedTypes.contains(type) || openTypes.contains(type),
                         qPrintable(file + QStringLiteral(": unexpected type ") + type));
            const QSet<QString> own = matches(code, declared);
            for (const QString &member : matches(code, agentUse))
                QVERIFY2(own.contains(member) || agentMembers.contains(member),
                         qPrintable(file + QStringLiteral(": agent member outside SPEC 7.1: ") + member));
        }
    }

    void uiFiles_data()
    {
        QTest::addColumn<QString>("file");
        QTest::addColumn<QString>("type");
        QTest::addColumn<QString>("provider");
        for (const QString &p : { QStringLiteral("sftp"), QStringLiteral("smb") }) {
            QTest::newRow(qPrintable(p)) << p + QStringLiteral(".qml") << "NetVfsCreationAgent" << p;
            QTest::newRow(qPrintable(p + QStringLiteral("-settings"))) << p + QStringLiteral("-settings.qml")
                                                                       << "NetVfsSettingsAgent" << p;
            QTest::newRow(qPrintable(p + QStringLiteral("-update"))) << p + QStringLiteral("-update.qml")
                                                                     << "NetVfsUpdateAgent" << p;
        }
    }

    void uiFiles()
    {
        // SPEC 3.1: /usr/share/accounts/ui/<p>.qml, <p>-settings.qml, <p>-update.qml
        QFETCH(QString, file);
        QFETCH(QString, type);
        QFETCH(QString, provider);
        const QString code = codeOf(SourceDir + QStringLiteral("/accounts/ui/") + file);
        QVERIFY(code.contains(QStringLiteral("import org.netvfs.accounts 1.0")));
        QVERIFY(code.contains(type + QStringLiteral(" {")));
        QVERIFY(code.contains(QStringLiteral("provider: \"") + provider + QLatin1Char('"')));
        const QString pro = readFile(SourceDir + QStringLiteral("/accounts/files.pro"));
        QVERIFY(pro.contains(QStringLiteral("NETVFS_PROVIDERS = sftp smb")));
    }

    void providerFiles_data()
    {
        QTest::addColumn<QString>("provider");
        QTest::addColumn<QString>("name");
        QTest::newRow("sftp") << "sftp" << "SFTP";
        QTest::newRow("smb") << "smb" << "SMB";
    }

    void providerFiles()
    {
        // SPEC 6.1 and 3.2/3.3: discovery by the Backup page depends on these values.
        QFETCH(QString, provider);
        QFETCH(QString, name);
        const QString providerPath = BuildDir + QStringLiteral("/accounts/providers/") + provider + QStringLiteral(".provider");
        const QMap<QString, QString> p = readXml(providerPath);
        QVERIFY2(!p.isEmpty() && !p.contains(QStringLiteral("error")), qPrintable(providerPath));
        QCOMPARE(p.value(QStringLiteral("provider@id")), provider);
        QCOMPARE(p.value(QStringLiteral("provider@version")), QStringLiteral("1.0"));
        QCOMPARE(p.value(QStringLiteral("provider/name")), name);
        QVERIFY(!p.value(QStringLiteral("provider/description")).isEmpty());
        QCOMPARE(p.value(QStringLiteral("provider/icon")), QStringLiteral("image://theme/graphic-service-") + provider);
        QVERIFY2(!readFile(providerPath).contains(QStringLiteral("<tag")), "no user-group tag (SPEC 6.1, V2)");

        const QString servicePath = BuildDir + QStringLiteral("/accounts/services/") + provider + QStringLiteral("-backup.service");
        const QMap<QString, QString> s = readXml(servicePath);
        QVERIFY2(!s.isEmpty() && !s.contains(QStringLiteral("error")), qPrintable(servicePath));
        QCOMPARE(s.value(QStringLiteral("service@id")), provider + QStringLiteral("-backup"));
        QCOMPARE(s.value(QStringLiteral("service/type")), QStringLiteral("storage"));
        QCOMPARE(s.value(QStringLiteral("service/name")), QStringLiteral("Backups"));
        QCOMPARE(s.value(QStringLiteral("service/icon")), QStringLiteral("image://theme/icon-m-storage"));
        QCOMPARE(s.value(QStringLiteral("service/provider")), provider);
        QCOMPARE(s.value(QStringLiteral("setting:sync_profile_templates")),
                 QStringLiteral("[\"%1.Backup\", \"%1.BackupQuery\", \"%1.BackupRestore\"]").arg(provider));
        QCOMPARE(s.value(QStringLiteral("service/template/setting@type")), QStringLiteral("as"));
        QCOMPARE(s.value(QStringLiteral("setting:method")), QStringLiteral("password"));
        QCOMPARE(s.value(QStringLiteral("setting:mechanism")), QStringLiteral("password"));
        QCOMPARE(s.value(QStringLiteral("service/template/group@name")), QStringLiteral("auth"));
    }

    void icons_data()
    {
        QTest::addColumn<QString>("provider");
        QTest::newRow("sftp") << "sftp";
        QTest::newRow("smb") << "smb";
    }

    void icons()
    {
        const QString path = SourceDir + QStringLiteral("/accounts/icons/svgs/icons/graphic-service-")
                + QTest::currentDataTag() + QStringLiteral(".svg");
        const QMap<QString, QString> svg = readXml(path);
        QVERIFY2(!svg.isEmpty() && !svg.contains(QStringLiteral("error")), qPrintable(path));
        QCOMPARE(svg.value(QStringLiteral("svg@width")), QStringLiteral("86"));
        QCOMPARE(svg.value(QStringLiteral("svg@height")), QStringLiteral("86"));
        QVERIFY2(!readFile(path).contains(QStringLiteral("href")), "self-contained artwork");
    }

    void translationsComplete()
    {
        // Every id used in the UI has an engineering English text in the catalogue.
        QTranslator translator;
        QVERIFY(translator.load(QStringLiteral("netvfs_eng_en"), BuildDir + QStringLiteral("/translations")));
        static const QRegularExpression call(QStringLiteral("q[st]TrId\\(\"([^\"]+)\"\\)"));
        QStringList files = qmlFiles();
        files += filesIn(QStringLiteral("src/qml"), { QStringLiteral("*.cpp") });
        int ids = 0;
        for (const QString &file : files) {
            for (const QString &id : matches(readFile(file), call)) {
                ++ids;
                QVERIFY2(id.startsWith(QStringLiteral("settings-accounts-netvfs-")), qPrintable(id));
                const QString text = translator.translate(nullptr, id.toUtf8().constData());
                QVERIFY2(!text.isEmpty() && text != id, qPrintable(file + QStringLiteral(": ") + id));
            }
        }
        QVERIFY(ids > 50);
    }
};

QTEST_GUILESS_MAIN(TestQmlModule)
#include "tst_qmlmodule.moc"
