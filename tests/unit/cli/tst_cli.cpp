// SPDX-License-Identifier: LGPL-2.1-or-later
#include "cli.h"
#include "fakebackend.h"

#include <QtCore/QTemporaryDir>
#include <QtCore/QTextStream>
#include <QtTest/QtTest>

using namespace NetVfs;
using NetVfs::Test::FakeServer;

class TestCli : public QObject
{
    Q_OBJECT

private:
    QString out;
    QString err;

    int run(const QStringList &command)
    {
        out.clear();
        err.clear();
        QTextStream o(&out);
        QTextStream e(&err);
        QStringList args = { QStringLiteral("--provider"), QStringLiteral("fake"), QStringLiteral("--host"),
                             QStringLiteral("h"), QStringLiteral("--port"), QStringLiteral("22"),
                             QStringLiteral("--user"), QStringLiteral("user") };
        return Cli::run(args + command, o, e);
    }

private slots:
    void initTestCase()
    {
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
        qputenv("NETVFS_SECRET", "secret");
    }

    void init() { FakeServer::instance()->reset(); }

    void usage()
    {
        QTextStream o(&out);
        QTextStream e(&err);
        QCOMPARE(Cli::run(QStringList(), o, e), 2);
        QVERIFY(err.contains(QStringLiteral("usage:")));
        QCOMPARE(run({ QStringLiteral("bogus") }), 2);
        QCOMPARE(run({ QStringLiteral("ls") }), 2);
        QCOMPARE(run({ QStringLiteral("--port") }), 2);
        QCOMPARE(run({ QStringLiteral("--port"), QStringLiteral("x"), QStringLiteral("identify") }), 2);
        QCOMPARE(run({ QStringLiteral("--option"), QStringLiteral("novalue"), QStringLiteral("identify") }), 2);
        QCOMPARE(run({ QStringLiteral("--frobnicate"), QStringLiteral("1"), QStringLiteral("identify") }), 2);
        QCOMPARE(Cli::run({ QStringLiteral("--provider"), QStringLiteral("nosuch"), QStringLiteral("--host"),
                            QStringLiteral("h"), QStringLiteral("identify") }, o, e),
                 10 + int(Error::Unsupported));
    }

    void identify()
    {
        QCOMPARE(run({ QStringLiteral("identify") }), 0);
        QCOMPARE(out, QStringLiteral("none\n"));

        ServerIdentity id;
        id.algorithm = QStringLiteral("ssh-ed25519");
        id.publicKey = "KEYBLOB";
        id.fingerprint = QStringLiteral("SHA256:fp");
        FakeServer::instance()->identity = id;
        QCOMPARE(run({ QStringLiteral("identify") }), 0);
        QCOMPARE(out, QStringLiteral("SHA256:fp\n") + id.toPin() + QLatin1Char('\n'));
        // Pinned: commands run; unpinned: refused before authentication.
        QCOMPARE(run({ QStringLiteral("ls"), QString() }), 10 + int(Error::ServerIdentityUnknown));
        QCOMPARE(run({ QStringLiteral("--option"), QStringLiteral("host_key=") + id.toPin(), QStringLiteral("ls"),
                       QString() }), 0);

        FakeServer::instance()->connectResult = Result(Error::NetworkUnreachable, QStringLiteral("down"));
        QCOMPARE(run({ QStringLiteral("identify") }), 10 + int(Error::NetworkUnreachable));
        QVERIFY(err.contains(QStringLiteral("NetworkUnreachable: down")));
    }

    void fileCommands()
    {
        QTemporaryDir dir;
        const QString local = dir.filePath(QStringLiteral("in"));
        QFile file(local);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("payload");
        file.close();

        QCOMPARE(run({ QStringLiteral("verify"), QStringLiteral("B") }), 0);
        QVERIFY(out.startsWith(QStringLiteral("ok free=")));
        QCOMPARE(run({ QStringLiteral("mkdir"), QStringLiteral("a/b") }), 0);
        QCOMPARE(run({ QStringLiteral("put"), local, QStringLiteral("a/b/f") }), 0);
        QCOMPARE(run({ QStringLiteral("ls"), QStringLiteral("a") }), 0);
        QCOMPARE(out, QStringLiteral("d 0 b\n"));
        QCOMPARE(run({ QStringLiteral("stat"), QStringLiteral("a/b/f") }), 0);
        QVERIFY(out.startsWith(QStringLiteral("- 7 ")));
        QCOMPARE(run({ QStringLiteral("mv"), QStringLiteral("a/b/f"), QStringLiteral("a/b/g") }), 0);
        QCOMPARE(run({ QStringLiteral("get"), QStringLiteral("a/b/g"), dir.filePath(QStringLiteral("out")) }), 0);
        QFile back(dir.filePath(QStringLiteral("out")));
        QVERIFY(back.open(QIODevice::ReadOnly));
        QCOMPARE(back.readAll(), QByteArray("payload"));
        QCOMPARE(run({ QStringLiteral("df"), QStringLiteral("a") }), 0);
        QCOMPARE(out.trimmed().toLongLong(), FakeServer::instance()->freeBytes);
        QCOMPARE(run({ QStringLiteral("rm"), QStringLiteral("a/b/g") }), 0);
        QCOMPARE(run({ QStringLiteral("rm"), QStringLiteral("a/b/g") }), 10 + int(Error::NotFound));
        QCOMPARE(run({ QStringLiteral("stat"), QStringLiteral("a/b/g") }), 10 + int(Error::NotFound));
        FakeServer::instance()->freeBytes = -1;
        QCOMPARE(run({ QStringLiteral("df"), QStringLiteral("a") }), 10 + int(Error::Unsupported));
    }

    void wrongSecret()
    {
        QCOMPARE(run({ QStringLiteral("--secret-env"), QStringLiteral("NETVFS_NO_SUCH_VAR"), QStringLiteral("ls"),
                       QString() }),
                 10 + int(Error::AuthFailed));
    }
};

QTEST_GUILESS_MAIN(TestCli)
#include "tst_cli.moc"
