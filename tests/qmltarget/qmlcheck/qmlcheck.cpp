// SPDX-License-Identifier: LGPL-2.1-or-later
// Compiles QML documents with the target's QML engine (Qt 5.6): syntax, ES5
// JavaScript, imports, types and property names are checked against the real
// Sailfish.Silica, Sailfish.Accounts and Sailfish.Pickers modules, the built
// org.netvfs.accounts module and stubs of the closed agent types that carry
// only the members of SPEC 7.1 (risk R1).
//
// With --create each document is also instantiated and every QML warning
// that names one of the checked files (binding errors such as unknown
// identifiers) counts as a failure.
//
// Usage: qmlcheck [--create] -I <import path>... <file.qml>...
#include <QtGui/QGuiApplication>
#include <QtQml/QQmlComponent>
#include <QtQml/QQmlEngine>

#include <cstdio>
#include <memory>

namespace {
struct Options {
    bool create = false;
    QStringList importPaths;
    QStringList files;
};

Options parse(const QStringList &args)
{
    Options options;
    for (int i = 0; i < args.size(); ++i) {
        if (args.at(i) == QLatin1String("--create"))
            options.create = true;
        else if (args.at(i) == QLatin1String("-I") && i + 1 < args.size())
            options.importPaths << args.at(++i);
        else
            options.files << args.at(i);
    }
    return options;
}

// Warnings about our own documents; Silica internals may warn without a window.
int ownWarnings(const QList<QQmlError> &warnings)
{
    int count = 0;
    for (const QQmlError &warning : warnings) {
        const QString text = warning.toString();
        const bool ours = text.contains(QLatin1String("/src/qml/")) || text.contains(QLatin1String("/accounts/ui/"))
                || text.contains(QLatin1String("/org/netvfs/accounts/"))
                || text.contains(QLatin1String("/tests/qmltarget/selftest/"));
        std::printf("%s %s\n", ours ? "WARNING" : "note   ", qPrintable(text));
        if (ours)
            ++count;
    }
    return count;
}

bool check(const Options &options, const QString &file)
{
    QQmlEngine engine;
    for (const QString &path : options.importPaths)
        engine.addImportPath(path);
    QList<QQmlError> warnings;
    QObject::connect(&engine, &QQmlEngine::warnings, [&warnings](const QList<QQmlError> &list) { warnings += list; });
    QQmlComponent component(&engine, QUrl::fromLocalFile(file), QQmlComponent::PreferSynchronous);
    while (component.isLoading())
        QCoreApplication::processEvents();
    if (!component.isReady()) {
        for (const QQmlError &error : component.errors())
            std::printf("ERROR   %s\n", qPrintable(error.toString()));
        return false;
    }
    if (options.create) {
        std::unique_ptr<QObject> object(component.create());
        QCoreApplication::processEvents();
        if (!object) {
            for (const QQmlError &error : component.errors())
                std::printf("ERROR   %s\n", qPrintable(error.toString()));
            return false;
        }
    }
    return ownWarnings(warnings) == 0;
}
} // namespace

int main(int argc, char **argv)
{
    QGuiApplication app(argc, argv);
    const Options options = parse(QCoreApplication::arguments().mid(1));
    int failures = 0;
    for (const QString &file : options.files) {
        const bool ok = check(options, file);
        std::printf("%s %s\n", ok ? "ok     " : "FAILED ", qPrintable(file));
        if (!ok)
            ++failures;
    }
    std::printf("%d of %d files failed\n", failures, static_cast<int>(options.files.size()));
    return failures ? 1 : 0;
}
