// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs-bridge-generator (SPEC-v2 XB-3, XB-4, XT-7): golden unit files,
// validation of consumer files (the same rules as ConsumerInfo), and the
// folder deletion/recreation logic of the rendezvous check, run against a
// fake systemctl because CI has no systemd --user.
#include "consentstore.h"

#include <QtCore/QDir>
#include <QtCore/QDirIterator>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QProcess>
#include <QtCore/QRegularExpression>
#include <QtCore/QStandardPaths>
#include <QtCore/QTemporaryDir>
#include <QtTest/QtTest>

using namespace NetVfs;

namespace {

const QString Generator = QStringLiteral(NETVFS_TEST_BIN_DIR "/netvfs-bridge-generator");
const QString Inputs = QStringLiteral(NETVFS_SOURCE_DIR "/tests/bridge/generator/consumers");
const QString Golden = QStringLiteral(NETVFS_SOURCE_DIR "/tests/bridge/generator/golden");

struct Run {
    int exitCode = -1;
    QString stderrText;
};

Run generate(const QString &consumers, const QStringList &args)
{
    QProcess p;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("NETVFS_CONSUMERS_DIR"), consumers);
    p.setProcessEnvironment(env);
    p.start(Generator, args);
    p.waitForFinished(10000);
    Run run;
    run.exitCode = p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1;
    run.stderrText = QString::fromUtf8(p.readAllStandardError());
    return run;
}

QByteArray readFile(const QString &path)
{
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

QStringList tree(const QString &root)
{
    QStringList entries;
    QDirIterator it(root, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::System, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        entries << QDir(root).relativeFilePath(it.filePath());
    }
    entries.sort();
    return entries;
}

QString writeConsumer(const QTemporaryDir &dir, const QString &id, const QString &dataDir,
                      const QString &executable = QStringLiteral("/usr/bin/x"))
{
    const QString folder = dir.path() + QStringLiteral("/in-") + id;
    QDir().mkpath(folder);
    QFile f(folder + QLatin1Char('/') + id + QStringLiteral(".conf"));
    if (f.open(QIODevice::WriteOnly)) {
        f.write("[Consumer]\nId=" + id.toUtf8() + "\nDisplayName=X\nExecutable=" + executable.toUtf8()
                + "\nDataDir=" + dataDir.toUtf8() + "\n");
    }
    return folder;
}

} // namespace

class tst_Generator : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void goldenUnits();
    void skipsInvalidConsumers();
    void sameRulesAsLibrary_data();
    void sameRulesAsLibrary();
    void usageAndMissingFolder();
    void shippedConsumer();
    void rendezvousCheck_data();
    void rendezvousCheck();
    void systemdAccepts();
};

void tst_Generator::goldenUnits()
{
    QTemporaryDir out;
    const Run run = generate(Inputs, { out.path(), out.path(), out.path() });
    QCOMPARE(run.exitCode, 0);
    QCOMPARE(tree(out.path()), tree(Golden));
    for (const QString &entry : tree(Golden)) {
        const QFileInfo golden(Golden + QLatin1Char('/') + entry);
        const QFileInfo actual(out.path() + QLatin1Char('/') + entry);
        if (golden.isSymLink()) {
            QVERIFY2(actual.isSymLink(), qPrintable(entry));
            QCOMPARE(QFile::symLinkTarget(actual.filePath()).section(QLatin1Char('/'), -1),
                     QFile::symLinkTarget(golden.filePath()).section(QLatin1Char('/'), -1));
            QCOMPARE(readFile(actual.filePath()).isEmpty(), false);   // the link resolves
            continue;
        }
        if (golden.isDir())
            continue;
        QByteArray expected = readFile(golden.filePath());
        expected.replace("@CONSUMERS@", Inputs.toUtf8());
        QCOMPARE(QString::fromUtf8(readFile(actual.filePath())), QString::fromUtf8(expected));
    }
    // XB-4 essentials, spelled out.
    const QByteArray socket = readFile(out.path() + QStringLiteral("/netvfs-bridge@lautta.socket"));
    QVERIFY(socket.contains("ListenStream=%h/.local/share/org.netvfs/lautta/netvfs/bridge.sock\n"));
    QVERIFY(socket.contains("SocketMode=0600\n"));
    QVERIFY(socket.contains("DirectoryMode=0700\n"));
    QVERIFY(socket.contains("Accept=no\n"));
    const QByteArray path = readFile(out.path() + QStringLiteral("/netvfs-bridge@lautta.path"));
    QVERIFY(path.contains("PathChanged=%h/.local/share/org.netvfs/lautta\n"));
    QVERIFY(path.contains("Unit=netvfs-bridge-rendezvous@lautta.service\n"));
}

void tst_Generator::skipsInvalidConsumers()
{
    QTemporaryDir out;
    const Run run = generate(Inputs, { out.path() });
    QCOMPARE(run.exitCode, 0);   // generators never fail the boot over a bad file
    for (const char *name : { "Upper.conf", "absolute.conf", "escape.conf", "mismatch.conf", "newline.conf",
                              "specifier.conf" })
        QVERIFY2(run.stderrText.contains(QLatin1String(name)), name);
    QVERIFY(!run.stderrText.contains(QLatin1String("lautta.conf")));
    for (const QString &entry : tree(out.path()))
        QVERIFY2(entry.contains(QLatin1String("lautta")) || entry.contains(QLatin1String("photos"))
                     || entry.endsWith(QLatin1String(".wants")), qPrintable(entry));
}

void tst_Generator::sameRulesAsLibrary_data()
{
    QTest::addColumn<QString>("dataDir");
    QTest::addColumn<QString>("executable");
    QTest::newRow("plain") << ".local/share/org.netvfs/app" << "/usr/bin/harbour-app";
    QTest::newRow("dotdot") << ".local/share/../../x" << "/usr/bin/x";
    QTest::newRow("dot") << "./x" << "/usr/bin/x";
    QTest::newRow("trailing slash") << "x/" << "/usr/bin/x";
    QTest::newRow("double slash") << "x//y" << "/usr/bin/x";
    QTest::newRow("absolute") << "/x" << "/usr/bin/x";
    QTest::newRow("space") << "a b" << "/usr/bin/x";
    QTest::newRow("percent") << "a%h" << "/usr/bin/x";
    QTest::newRow("quote") << "a\"b" << "/usr/bin/x";
    QTest::newRow("dollar") << "a$b" << "/usr/bin/x";
    QTest::newRow("hidden ok") << ".x/.y" << "/usr/bin/x";
    QTest::newRow("relative exe") << "x" << "usr/bin/x";
    QTest::newRow("exe dotdot") << "x" << "/usr/../bin/sh";
    QTest::newRow("exe root") << "x" << "/";
}

void tst_Generator::sameRulesAsLibrary()
{
    QFETCH(QString, dataDir);
    QFETCH(QString, executable);
    QTemporaryDir dir;
    QTemporaryDir out;
    const QString folder = writeConsumer(dir, QStringLiteral("probe"), dataDir, executable);
    const Run run = generate(folder, { out.path() });
    QCOMPARE(run.exitCode, 0);
    const bool generated = QFile::exists(out.path() + QStringLiteral("/netvfs-bridge@probe.socket"));
    ConsumerInfo info;
    const bool accepted = ConsentStore::parseConsumerFile(folder + QStringLiteral("/probe.conf"), &info).ok();
    QCOMPARE(generated, accepted);
}

void tst_Generator::usageAndMissingFolder()
{
    QCOMPARE(generate(Inputs, {}).exitCode, 1);
    QTemporaryDir out;
    QCOMPARE(generate(QStringLiteral("/nonexistent/consumers"), { out.path() }).exitCode, 0);
    QVERIFY(tree(out.path()).isEmpty());
    // An unusable output folder is reported.
    QCOMPARE(generate(Inputs, { QStringLiteral("/nonexistent/out") }).exitCode, 1);
}

void tst_Generator::shippedConsumer()
{
    ConsumerInfo info;
    QVERIFY(ConsentStore::parseConsumerFile(QStringLiteral(NETVFS_SOURCE_DIR "/src/bridge/data/lautta.conf"), &info).ok());
    QCOMPARE(info.id, QStringLiteral("lautta"));
    QCOMPARE(info.executable, QStringLiteral("/usr/bin/harbour-lautta"));
    QVERIFY(readFile(Golden + QStringLiteral("/netvfs-bridge@lautta.service"))
                .contains("ExecStart=/usr/libexec/netvfs/netvfs-bridge lautta\n"));
}

void tst_Generator::rendezvousCheck_data()
{
    QTest::addColumn<bool>("socketExists");
    QTest::addColumn<bool>("unitActive");
    QTest::addColumn<bool>("restart");
    // XB-4: the folder was deleted and recreated -> the socket is gone -> restart.
    QTest::newRow("socket missing") << false << true << true;
    QTest::newRow("unit inactive") << true << false << true;
    QTest::newRow("both fine") << true << true << false;
    QTest::newRow("nothing") << false << false << true;
}

void tst_Generator::rendezvousCheck()
{
    QFETCH(bool, socketExists);
    QFETCH(bool, unitActive);
    QFETCH(bool, restart);
    QTemporaryDir out;
    QCOMPARE(generate(Inputs, { out.path() }).exitCode, 0);
    const QString unit = QString::fromUtf8(readFile(out.path() + QStringLiteral("/netvfs-bridge-rendezvous@lautta.service")));
    const QRegularExpression exec(QStringLiteral("ExecStart=/bin/sh -c '(.*)' (\\S+) (\\S+)\\n"));
    const QRegularExpressionMatch m = exec.match(unit);
    QVERIFY2(m.hasMatch(), qPrintable(unit));

    QTemporaryDir home;
    const QString socketPath = QString(m.captured(2)).replace(QStringLiteral("%h"), home.path());
    QCOMPARE(m.captured(3), QStringLiteral("netvfs-bridge@lautta.socket"));
    if (socketExists) {
        QDir().mkpath(QFileInfo(socketPath).absolutePath());
        QVERIFY(QProcess::execute(QStringLiteral("python3"),
                                  { QStringLiteral("-c"),
                                    QStringLiteral("import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])"),
                                    socketPath }) == 0);
    }
    // A fake systemctl that logs its arguments.
    QTemporaryDir bin;
    const QString log = bin.path() + QStringLiteral("/log");
    QFile fake(bin.path() + QStringLiteral("/systemctl"));
    QVERIFY(fake.open(QIODevice::WriteOnly));
    fake.write("#!/bin/sh\necho \"$*\" >> '" + log.toUtf8() + "'\n"
               "case \"$*\" in *is-active*) exit " + QByteArray(unitActive ? "0" : "3") + ";; esac\nexit 0\n");
    fake.close();
    fake.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);

    // systemd turns "$$" into "$" before running the command.
    const QString script = m.captured(1).replace(QStringLiteral("$$"), QStringLiteral("$"));
    QProcess sh;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("PATH"), bin.path() + QStringLiteral(":/usr/bin:/bin"));
    sh.setProcessEnvironment(env);
    sh.start(QStringLiteral("/bin/sh"), { QStringLiteral("-c"), script, socketPath, m.captured(3) });
    QVERIFY(sh.waitForFinished(5000));
    QCOMPARE(sh.exitCode(), 0);
    const QString calls = QString::fromUtf8(readFile(log));
    QCOMPARE(calls.contains(QLatin1String("--user restart netvfs-bridge@lautta.socket")), restart);
}

void tst_Generator::systemdAccepts()
{
    const QString analyze = QStandardPaths::findExecutable(QStringLiteral("systemd-analyze"));
    if (analyze.isEmpty())
        QSKIP("systemd-analyze is not installed");
    QTemporaryDir out;
    QTemporaryDir runtime;
    QCOMPARE(generate(Inputs, { out.path() }).exitCode, 0);
    QProcess p;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("XDG_RUNTIME_DIR"), runtime.path());
    env.insert(QStringLiteral("SYSTEMD_UNIT_PATH"), out.path() + QLatin1Char(':'));
    p.setProcessEnvironment(env);
    p.setWorkingDirectory(out.path());
    p.start(analyze, { QStringLiteral("--user"), QStringLiteral("verify"), QStringLiteral("netvfs-bridge@lautta.socket"),
                       QStringLiteral("netvfs-bridge@lautta.path"), QStringLiteral("netvfs-bridge-rendezvous@lautta.service") });
    QVERIFY(p.waitForFinished(30000));
    const QString output = QString::fromUtf8(p.readAllStandardError() + p.readAllStandardOutput());
    if (output.contains(QLatin1String("Failed to initialize manager")))
        QSKIP("no usable systemd manager here");
    // The bridge binary is not installed on a build host; anything else is a unit error.
    for (const QString &line : output.split(QLatin1Char('\n'), NETVFS_SKIP_EMPTY_PARTS)) {
        if (line.contains(QLatin1String("is not executable")) || line.contains(QLatin1String("system bus")))
            continue;
        QFAIL(qPrintable(line));
    }
}

QTEST_GUILESS_MAIN(tst_Generator)
#include "tst_generator.moc"
