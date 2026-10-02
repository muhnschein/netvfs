// SPDX-License-Identifier: LGPL-2.1-or-later
#include "cli.h"
#include "cliformat.h"
#include "cliprompt.h"
#include "fakebackend.h"
#include "names.h"

#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QTemporaryDir>
#include <QtCore/QTextStream>
#include <QtTest/QtTest>

using namespace NetVfs;
using NetVfs::Test::FakeServer;

namespace {

int code(Error error)
{
    return 10 + static_cast<int>(error);
}

QString S(const char *text)
{
    return QString::fromLatin1(text);
}

QDateTime utc(const char *iso)
{
    return QDateTime::fromString(QString::fromLatin1(iso), Qt::ISODate).toUTC();
}

// Records the terminal echo switches of a prompt.
class EchoRecorder : public Cli::EchoControl
{
public:
    bool setEcho(bool on) override
    {
        calls << on;
        return result;
    }
    QVector<bool> calls;
    bool result = true;
};

} // namespace

class TestCli : public QObject
{
    Q_OBJECT

private:
    QString out;
    QString err;

    int runArgs(const QStringList &args, QIODevice *prompt = nullptr)
    {
        out.clear();
        err.clear();
        QTextStream o(&out);
        QTextStream e(&err);
        return Cli::run(args, o, e, prompt);
    }

    int run(const QStringList &command)
    {
        const QStringList args = { S("--provider"), S("fake"), S("--host"), S("h"), S("--port"), S("22"),
                                   S("--user"), S("user") };
        return runArgs(args + command);
    }

    int runLocal(const QString &root, const QStringList &command)
    {
        return runArgs(QStringList({ S("--provider"), S("local"), S("--option"), S("root=") + root }) + command);
    }

    QJsonDocument json() const { return QJsonDocument::fromJson(out.toUtf8()); }

    static bool localPluginAvailable()
    {
        return QFileInfo::exists(QStringLiteral(NETVFS_TEST_BACKEND_DIR "/libnetvfs-local.so"));
    }

private slots:
    void initTestCase()
    {
        qputenv("NETVFS_BACKEND_PATH",
                QByteArray(NETVFS_TEST_FAKE_BACKEND_DIR ":" NETVFS_TEST_BACKEND_DIR));
        qputenv("NETVFS_SECRET", "secret");
    }

    void init() { FakeServer::instance()->reset(); }

    // ------------------------------------------------------------- arguments

    void usage()
    {
        QTextStream o(&out);
        QTextStream e(&err);
        QCOMPARE(Cli::run(QStringList(), o, e), 2);
        QVERIFY(err.contains(S("usage:")));
        QCOMPARE(run({ S("bogus") }), 2);
        QCOMPARE(run({ S("ls") }), 2);
        QCOMPARE(run({ S("ls"), S("a"), S("b") }), 2);
        QCOMPARE(run({ S("ls"), S("--nosuchflag"), S("a") }), 2);
        QCOMPARE(runArgs({ S("--port") }), 2);
        QCOMPARE(run({ S("--port"), S("x"), S("identify") }), 2);
        QCOMPARE(runArgs({ S("--provider"), S("fake"), S("--host"), S("h"), S("--port"), S("0"), S("identify") }), 2);
        QCOMPARE(runArgs({ S("--provider"), S("fake"), S("--host"), S("h"), S("--port"), S("65536"), S("identify") }), 2);
        QCOMPARE(run({ S("--option"), S("novalue"), S("identify") }), 2);
        QCOMPARE(run({ S("--frobnicate"), S("1"), S("identify") }), 2);
        QCOMPARE(runArgs({ S("--provider"), S("fake"), S("identify") }), 2);   // no host
        QCOMPARE(runArgs({ S("--provider"), S("fake"), S("--host"), S("h") }), 2);   // no command
        QCOMPARE(runArgs({ S("--provider"), S("nosuch"), S("--host"), S("h"), S("identify") }),
                 code(Error::Unsupported));
    }

    void help()
    {
        QCOMPARE(runArgs({ S("--help") }), 0);
        QVERIFY(out.startsWith(S("usage:")));
        for (const char *command : { "identify", "verify", "ls", "stat", "lstat", "cat", "put", "get", "mkdir", "rm",
                                     "rmdir", "mv", "cp", "chmod", "touch", "ln", "readlink", "df", "sum", "caps",
                                     "shares", "discover" }) {
            QVERIFY2(out.contains(S("\n  ") + S(command) + QLatin1Char(' ')), command);
        }
        QVERIFY(err.isEmpty());
    }

    void secretNeverFromArgv()
    {
        // There is no option that takes the secret itself ...
        QCOMPARE(run({ S("--secret"), S("secret"), S("ls"), QString() }), 2);
        QCOMPARE(run({ S("--password"), S("secret"), S("ls"), QString() }), 2);
        // ... and --secret-env names a variable, it is not the secret.
        QCOMPARE(run({ S("--secret-env"), S("secret"), S("ls"), QString() }), code(Error::AuthFailed));
        qputenv("NETVFS_CLI_TEST_SECRET", "secret");
        QCOMPARE(run({ S("--secret-env"), S("NETVFS_CLI_TEST_SECRET"), S("ls"), QString() }), 0);
        qunsetenv("NETVFS_CLI_TEST_SECRET");
    }

    void wrongSecret()
    {
        QCOMPARE(run({ S("--secret-env"), S("NETVFS_NO_SUCH_VAR"), S("ls"), QString() }), code(Error::AuthFailed));
    }

    void profileAndHostKeyOptions()
    {
        QCOMPARE(run({ S("--profile"), S("legacy"), S("ls"), QString() }), 0);
        QCOMPARE(FakeServer::instance()->lastParams.option(S("security_profile")), S("legacy"));
        QCOMPARE(run({ S("--profile"), S("bogus"), S("ls"), QString() }), 2);
        QCOMPARE(run({ S("--host-key"), S("garbage"), S("ls"), QString() }), 2);

        ServerIdentity ssh;
        ssh.kind = ServerIdentity::Kind::SshHostKey;
        ssh.algorithm = S("ssh-ed25519");
        ssh.publicKey = "KEYBLOB";
        ssh.fingerprint = S("SHA256:fp");
        FakeServer::instance()->identity = ssh;
        QCOMPARE(run({ S("--host-key"), ssh.toPin(), S("ls"), QString() }), 0);
        QCOMPARE(FakeServer::instance()->lastParams.option(S("host_key")), ssh.toPin());

        const ServerIdentity tls = ServerIdentity::fromTlsSpki("SPKIDER");
        FakeServer::instance()->identity = tls;
        QCOMPARE(run({ S("--host-key"), tls.toPin(), S("ls"), QString() }), 0);
        QCOMPARE(FakeServer::instance()->lastParams.option(S("host_key")), tls.toPin());
        // The pin of another key is refused.
        QCOMPARE(run({ S("--host-key"), ssh.toPin(), S("ls"), QString() }), code(Error::ServerIdentityChanged));
    }

    // ------------------------------------------------------------------ URLs

    void urlRejectsPassword()
    {
        QCOMPARE(runArgs({ S("--url"), S("sftp://alice:hunter2@example.org/home"), S("ls"), QString() }),
                 code(Error::SecurityPolicy));
        QVERIFY(err.contains(S("passwords in URLs are not accepted")));
        QVERIFY(!err.contains(S("hunter2")));
        QVERIFY(FakeServer::instance()->log.isEmpty());
        QCOMPARE(runArgs({ S("--url"), S("sftp://alice:@example.org/"), S("ls"), QString() }),
                 code(Error::SecurityPolicy));
    }

    void urlErrors()
    {
        QCOMPARE(runArgs({ S("--url"), S("gopher://h/"), S("ls"), QString() }), code(Error::Unsupported));
        QCOMPARE(runArgs({ S("--url"), S("sftp:///nohost"), S("ls"), QString() }), code(Error::InvalidName));
        // The URL replaces --provider/--host/--port/--user.
        QCOMPARE(runArgs({ S("--url"), S("sftp://h/"), S("--host"), S("h"), S("ls"), QString() }), 2);
        QCOMPARE(runArgs({ S("--url"), S("sftp://h/"), S("--user"), S("u"), S("ls"), QString() }), 2);
    }

    void urlLocalEndToEnd()
    {
        if (!localPluginAvailable())
            QSKIP("libnetvfs-local.so is not built");
        QTemporaryDir dir;
        QVERIFY(QDir(dir.path()).mkpath(S("sub/inner")));
        QFile file(dir.filePath(S("sub/inner/f")));
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("12345");
        file.close();
        const QString url = S("file://") + dir.path() + S("/sub");
        // Relative arguments resolve against the URL's folder, absolute ones do not.
        QCOMPARE(runArgs({ S("--url"), url, S("ls"), S("inner") }), 0);
        QCOMPARE(out, S("- 5 f\n"));
        QCOMPARE(runArgs({ S("--url"), url, S("ls"), S("") }), 0);
        QCOMPARE(out, S("d -1 inner\n"));
        QCOMPARE(runArgs({ S("--url"), url, S("cat"), S("inner/f") }), 0);
        QCOMPARE(out, S("12345"));
        QCOMPARE(runArgs({ S("--url"), url, S("cat"), dir.path() + S("/sub/inner/f") }), 0);
        QCOMPARE(out, S("12345"));
        QCOMPARE(runArgs({ S("--url"), url, S("ls"), S("../x") }), code(Error::InvalidName));
    }

    // ------------------------------------------------------------- identity

    void identify()
    {
        QCOMPARE(run({ S("identify") }), 0);
        QCOMPARE(out, S("none\n"));

        ServerIdentity id;
        id.kind = ServerIdentity::Kind::SshHostKey;
        id.algorithm = S("ssh-ed25519");
        id.publicKey = "KEYBLOB";
        id.fingerprint = S("SHA256:fp");
        FakeServer::instance()->identity = id;
        QCOMPARE(run({ S("identify") }), 0);
        QCOMPARE(out, S("SHA256:fp\n") + id.toPin() + QLatin1Char('\n'));
        // Pinned: commands run; unpinned: refused before authentication.
        FakeServer::instance()->log.clear();
        QCOMPARE(run({ S("ls"), QString() }), code(Error::ServerIdentityUnknown));
        QVERIFY(err.contains(S("--host-key")));
        QVERIFY(!FakeServer::instance()->log.contains(S("authenticate")));
        QCOMPARE(run({ S("--option"), S("host_key=") + id.toPin(), S("ls"), QString() }), 0);

        FakeServer::instance()->connectResult = Result(Error::NetworkUnreachable, S("down"));
        QCOMPARE(run({ S("identify") }), code(Error::NetworkUnreachable));
        QVERIFY(err.contains(S("NetworkUnreachable: down")));
    }

    void identifyTls()
    {
        ServerIdentity id = ServerIdentity::fromTlsSpki("SPKIDER");
        id.systemTrusted = false;
        id.problems = ServerIdentity::SelfSigned | ServerIdentity::HostnameMismatch;
        id.details.insert(S("subject"), S("CN=nas.local\x1b[31m"));
        id.details.insert(S("issuer"), S("CN=nas.local"));
        id.details.insert(S("notBefore"), S("2024-01-01T00:00:00Z"));
        id.details.insert(S("notAfter"), S("2034-01-01T00:00:00Z"));
        id.details.insert(S("sans"), QStringList({ S("nas.local"), S("nas") }));
        id.details.insert(S("certSha256"), S("abcd"));
        FakeServer::instance()->identity = id;

        QCOMPARE(run({ S("identify") }), 0);
        const QStringList lines = out.split(QLatin1Char('\n'));
        QCOMPARE(lines.at(0), id.fingerprint);
        QCOMPARE(lines.at(1), id.toPin());
        QVERIFY(lines.at(1).startsWith(S("tls-spki-sha256 ")));
        QVERIFY(lines.contains(S("system-trusted: no")));
        QVERIFY(lines.contains(S("problems: self-signed hostname-mismatch")));
        QVERIFY(lines.contains(S("subject: CN=nas.local?[31m")));   // escape sequences never reach the terminal
        QVERIFY(lines.contains(S("sans: nas.local, nas")));
        QVERIFY(lines.contains(S("cert-sha256: abcd")));
        QVERIFY(out.contains(S("advice: pin it with --host-key and leave tls_verify_peer unset")));
        QVERIFY(!out.contains(QChar(0x1b)));

        // Trusted by the system: no pin needed, and the advice names tls_verify_peer=true.
        id.systemTrusted = true;
        id.problems = 0;
        FakeServer::instance()->identity = id;
        QCOMPARE(run({ S("identify") }), 0);
        QVERIFY(out.contains(S("system-trusted: yes")));
        QVERIFY(!out.contains(S("problems:")));
        QVERIFY(out.contains(S("--option tls_verify_peer=true")));
        QCOMPARE(run({ S("ls"), QString() }), 0);
        // Untrusted and unpinned: refused.
        id.systemTrusted = false;
        FakeServer::instance()->identity = id;
        QCOMPARE(run({ S("ls"), QString() }), code(Error::ServerIdentityUnknown));
    }

    // -------------------------------------------------------------- commands

    void fileCommands()
    {
        QTemporaryDir dir;
        const QString local = dir.filePath(S("in"));
        QFile file(local);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write("payload");
        file.close();

        QCOMPARE(run({ S("verify"), S("B") }), 0);
        QVERIFY(out.startsWith(S("ok free=")));
        QCOMPARE(run({ S("mkdir"), S("-p"), S("a/b") }), 0);
        QCOMPARE(run({ S("put"), local, S("a/b/f") }), 0);
        QCOMPARE(run({ S("ls"), S("a") }), 0);
        QCOMPARE(out, S("d -1 b\n"));   // XC-2: unknown size
        QCOMPARE(run({ S("stat"), S("a/b/f") }), 0);
        QVERIFY2(out.startsWith(S("-rw------- - - 7 ")), qPrintable(out));
        QVERIFY(out.endsWith(S(" - a/b/f\n")));
        QCOMPARE(run({ S("mv"), S("a/b/f"), S("a/b/g") }), 0);
        QCOMPARE(run({ S("get"), S("a/b/g"), dir.filePath(S("out")) }), 0);
        QFile back(dir.filePath(S("out")));
        QVERIFY(back.open(QIODevice::ReadOnly));
        QCOMPARE(back.readAll(), QByteArray("payload"));
        QCOMPARE(run({ S("df"), S("a") }), 0);
        QCOMPARE(out.trimmed().toLongLong(), FakeServer::instance()->freeBytes);
        QCOMPARE(run({ S("rm"), S("a/b/g") }), 0);
        QCOMPARE(run({ S("rm"), S("a/b/g") }), code(Error::NotFound));
        QCOMPARE(run({ S("stat"), S("a/b/g") }), code(Error::NotFound));
        FakeServer::instance()->freeBytes = -1;
        QCOMPARE(run({ S("df"), S("a") }), code(Error::Unsupported));
    }

    void listLong()
    {
        FakeServer *server = FakeServer::instance();
        server->addFile(S("d/file"), "abc", utc("2024-05-17T12:30:00Z"), 0640);
        server->addDir(S("d/folder"), 0755);
        server->addSymlink(S("d/link"), S("file"));
        QCOMPARE(run({ S("ls"), S("-l"), S("d") }), 0);
        const QStringList lines = out.split(QLatin1Char('\n'), NETVFS_SKIP_EMPTY_PARTS);
        QCOMPARE(lines.size(), 3);
        QCOMPARE(lines.at(0), S("-rw-r----- - - 3 2024-05-17T12:30:00Z - file"));
        QVERIFY(lines.at(1).startsWith(S("drwxr-xr-x - - ")));
        QVERIFY(lines.at(1).endsWith(S(" folder")));
        QVERIFY(lines.at(2).startsWith(S("l")));
        QVERIFY(lines.at(2).endsWith(S(" link")));
        // Plain ls: type, size, name; sorted by name.
        QCOMPARE(run({ S("ls"), S("d") }), 0);
        QCOMPARE(out.split(QLatin1Char('\n')).at(0), S("- 3 file"));
    }

    void formatting()
    {
        Entry e;
        e.name = S("n");
        e.type = EntryType::File;
        e.mode = 04755;
        e.owner = S("alice");
        e.group = S("users");
        e.size = 12;
        e.modified = utc("2020-01-02T03:04:05Z");
        e.flags = EntryFlag::Hidden | EntryFlag::ReadOnly;
        QCOMPARE(Cli::modeString(e), S("-rwsr-xr-x"));
        QCOMPARE(Cli::longLine(e), S("-rwsr-xr-x alice users 12 2020-01-02T03:04:05Z HR n"));
        e.mode = 01777;
        e.type = EntryType::Directory;
        QCOMPARE(Cli::modeString(e), S("drwxrwxrwt"));
        e.mode = 02640;
        QCOMPARE(Cli::modeString(e), S("drw-r-S---"));
        e.mode = 01000;
        QCOMPARE(Cli::modeString(e), S("d--------T"));
        e.mode = -1;
        e.owner.clear();
        e.group.clear();
        e.uid = 1000;
        e.gid = 100;
        e.size = -1;
        e.modified = QDateTime();
        e.flags = EntryFlags();
        QCOMPARE(Cli::longLine(e), S("d????????? 1000 100 - - - n"));
        e.uid = -1;
        e.gid = -1;
        QCOMPARE(Cli::longLine(e), S("d????????? - - - - - n"));
        QCOMPARE(Cli::flagsString(EntryFlag::System | EntryFlag::NameNotUtf8 | EntryFlag::TargetUnknown), S("SNT"));
        e.type = EntryType::Symlink;
        e.targetType = EntryType::Directory;
        QCOMPARE(Cli::shortLine(e), S("d -1 n"));
        e.targetType = EntryType::Unknown;
        QCOMPARE(Cli::shortLine(e), S("l -1 n"));
        // Names are shown with U+FFFD for escaped bytes, control characters are neutralised.
        e.name = Names::decode("a\xff" "b");
        QCOMPARE(Cli::shortLine(e), S("l -1 a") + QString(QChar(0xfffd)) + S("b"));
        e.name = S("a\x1b[2Jb");
        QCOMPARE(Cli::shortLine(e), S("l -1 a?[2Jb"));
    }

    void listJson()
    {
        FakeServer *server = FakeServer::instance();
        server->addFile(S("d/file"), "abc", utc("2024-05-17T12:30:00Z"), 0640);
        server->addDir(S("d/folder"));
        server->addSymlink(S("d/link"), S("file"));
        server->addFile(Names::decode("d/bad\xff" "name"), "x");
        QCOMPARE(run({ S("ls"), S("--json"), S("d") }), 0);
        const QJsonArray entries = json().array();
        QCOMPARE(entries.size(), 4);
        QJsonObject file;
        QJsonObject bad;
        QJsonObject link;
        QJsonObject folder;
        for (const QJsonValue &value : entries) {
            const QJsonObject o = value.toObject();
            const QString name = o.value(S("name")).toString();
            if (name == S("file"))
                file = o;
            else if (name == S("link"))
                link = o;
            else if (name == S("folder"))
                folder = o;
            else
                bad = o;
        }
        QCOMPARE(file.value(S("type")).toString(), S("file"));
        QCOMPARE(file.value(S("size")).toInt(), 3);
        QCOMPARE(file.value(S("mode")).toInt(), 0640);
        QCOMPARE(file.value(S("modified")).toString(), S("2024-05-17T12:30:00Z"));
        QVERIFY(file.value(S("uid")).isNull());
        QVERIFY(file.value(S("owner")).isNull());
        QVERIFY(file.value(S("flags")).toArray().isEmpty());
        QVERIFY(!file.contains(S("nameBytes")));
        QVERIFY(!file.contains(S("targetType")));
        QCOMPARE(folder.value(S("type")).toString(), S("directory"));
        QVERIFY(folder.value(S("size")).isNull());   // unknown, not -1
        QCOMPARE(link.value(S("type")).toString(), S("symlink"));
        QVERIFY(link.contains(S("targetType")));
        // XC-4: the name as displayed plus the exact bytes.
        QCOMPARE(bad.value(S("name")).toString(), S("bad") + QString(QChar(0xfffd)) + S("name"));
        QCOMPARE(QByteArray::fromBase64(bad.value(S("nameBytes")).toString().toLatin1()), QByteArray("bad\xff" "name"));
        QCOMPARE(bad.value(S("flags")).toArray().at(0).toString(), S("nameNotUtf8"));
    }

    void statAndLstat()
    {
        FakeServer *server = FakeServer::instance();
        server->addFile(S("t"), "abcd", utc("2024-05-17T12:30:00Z"));
        server->addSymlink(S("l"), S("t"));
        QCOMPARE(run({ S("stat"), S("l") }), 0);
        QVERIFY2(out.startsWith(S("-")), qPrintable(out));      // followed: the file
        QVERIFY(out.contains(S(" 4 ")));
        QCOMPARE(run({ S("lstat"), S("l") }), 0);
        QVERIFY2(out.startsWith(S("l")), qPrintable(out));      // the link itself
        QVERIFY(out.endsWith(S(" l\n")));
        QCOMPARE(run({ S("stat"), S("--json"), S("l") }), 0);
        QCOMPARE(json().object().value(S("type")).toString(), S("file"));
        QCOMPARE(json().object().value(S("name")).toString(), S("l"));
        QCOMPARE(run({ S("lstat"), S("--json"), S("l") }), 0);
        QCOMPARE(json().object().value(S("type")).toString(), S("symlink"));
        QCOMPARE(run({ S("lstat"), S("nothing") }), code(Error::NotFound));
    }

    void mkdirModes()
    {
        FakeServer *server = FakeServer::instance();
        QCOMPARE(run({ S("mkdir"), S("a/b") }), code(Error::NotFound));   // no parents without -p
        QVERIFY(!server->exists(S("a")));
        QCOMPARE(run({ S("mkdir"), S("a") }), 0);
        QCOMPARE(run({ S("mkdir"), S("a") }), 0);                          // an existing folder is fine ...
        QCOMPARE(run({ S("mkdir"), S("--exclusive"), S("a") }), code(Error::AlreadyExists));   // ... unless exclusive
        QCOMPARE(run({ S("mkdir"), S("-p"), S("x/y/z") }), 0);
        QVERIFY(server->exists(S("x/y/z")));
        QCOMPARE(run({ S("mkdir"), S("-p"), S("--exclusive"), S("q") }), 2);
    }

    void removal()
    {
        FakeServer *server = FakeServer::instance();
        server->addFile(S("keep/precious"), "p");
        server->addFile(S("tree/sub/f"), "f");
        server->addFile(S("tree/g"), "g");
        server->addSymlink(S("tree/sub/out"), S("/keep"));
        server->addSymlink(S("tree/filelink"), S("/keep/precious"));
        QCOMPARE(run({ S("rm"), S("tree") }), code(Error::IsADirectory));
        QCOMPARE(run({ S("rmdir"), S("tree") }), code(Error::DirectoryNotEmpty));
        QCOMPARE(run({ S("rmdir"), S("tree/g") }), code(Error::NotADirectory));
        QCOMPARE(run({ S("rm"), S("-r"), S("/") }), code(Error::InvalidName));
        QVERIFY(server->exists(S("tree/g")));
        // XH-2: links are removed, never followed.
        QCOMPARE(run({ S("rm"), S("-r"), S("tree") }), 0);
        QVERIFY(!server->exists(S("tree")));
        QVERIFY(server->exists(S("keep/precious")));
        QCOMPARE(run({ S("rm"), S("-r"), S("tree") }), code(Error::NotFound));
        QCOMPARE(run({ S("rmdir"), S("keep") }), code(Error::DirectoryNotEmpty));
        QCOMPARE(run({ S("rm"), S("keep/precious") }), 0);
        QCOMPARE(run({ S("rmdir"), S("keep") }), 0);
        QVERIFY(!server->exists(S("keep")));
    }

    void moveDoesNotReplaceByDefault()
    {
        FakeServer *server = FakeServer::instance();
        server->addFile(S("a"), "AAA");
        server->addFile(S("b"), "BBB");
        QCOMPARE(run({ S("mv"), S("a"), S("b") }), code(Error::AlreadyExists));
        QCOMPARE(server->fileData(S("a")), QByteArray("AAA"));
        QCOMPARE(server->fileData(S("b")), QByteArray("BBB"));
        QCOMPARE(run({ S("mv"), S("--replace"), S("a"), S("b") }), 0);
        QVERIFY(!server->exists(S("a")));
        QCOMPARE(server->fileData(S("b")), QByteArray("AAA"));
        QCOMPARE(run({ S("mv"), S("b"), S("c") }), 0);
        QVERIFY(server->exists(S("c")));
    }

    void copyOnServer()
    {
        FakeServer *server = FakeServer::instance();
        server->addFile(S("src/f"), "data");
        server->addFile(S("dst"), "old");
        QCOMPARE(run({ S("cp"), S("src/f"), S("copy") }), 0);
        QVERIFY(server->log.contains(S("copy:src/f->copy")));
        QCOMPARE(server->fileData(S("copy")), QByteArray("data"));
        // NoReplace by default.
        QCOMPARE(run({ S("cp"), S("src/f"), S("dst") }), code(Error::AlreadyExists));
        QCOMPARE(server->fileData(S("dst")), QByteArray("old"));
        QCOMPARE(run({ S("cp"), S("--replace"), S("src/f"), S("dst") }), 0);
        QCOMPARE(server->fileData(S("dst")), QByteArray("data"));
        // A folder needs -r.
        QVERIFY(run({ S("cp"), S("src"), S("srccopy") }) != 0);
        server->log.clear();
        QCOMPARE(run({ S("cp"), S("-r"), S("src"), S("srccopy") }), 0);
        QVERIFY(server->log.contains(S("copy:src->srccopy")));
        QCOMPARE(server->fileData(S("srccopy/f")), QByteArray("data"));
    }

    void copyAcrossConnections()
    {
        FakeServer *server = FakeServer::instance();
        server->addFile(S("src/f"), "data");
        server->addFile(S("src/sub/g"), "more");
        // No server-side copy: streamed over a second connection.
        server->capabilities.flags.remove(Capability::ServerCopy);
        QCOMPARE(run({ S("cp"), S("src/f"), S("copy") }), 0);
        QVERIFY(!server->log.contains(S("copy:src/f->copy")));
        QCOMPARE(server->fileData(S("copy")), QByteArray("data"));
        QCOMPARE(run({ S("cp"), S("src/f"), S("copy") }), code(Error::AlreadyExists));
        QCOMPARE(run({ S("cp"), S("--replace"), S("src/f"), S("copy") }), 0);
        QCOMPARE(run({ S("cp"), S("-r"), S("src"), S("tree") }), 0);
        QCOMPARE(server->fileData(S("tree/sub/g")), QByteArray("more"));
        // Server copy without ServerCopyRecursive also goes across for -r.
        server->capabilities.flags.insert(Capability::ServerCopy);
        server->capabilities.flags.remove(Capability::ServerCopyRecursive);
        server->log.clear();
        QCOMPARE(run({ S("cp"), S("-r"), S("src"), S("tree2") }), 0);
        QVERIFY(!server->log.contains(S("copy:src->tree2")));
        QCOMPARE(server->fileData(S("tree2/sub/g")), QByteArray("more"));
        QCOMPARE(run({ S("cp"), S("src/f"), S("single") }), 0);
        QVERIFY(server->log.contains(S("copy:src/f->single")));
    }

    void copyToOtherLocation()
    {
        if (!localPluginAvailable())
            QSKIP("libnetvfs-local.so is not built");
        FakeServer *server = FakeServer::instance();
        server->addFile(S("src/f"), "data");
        server->addFile(S("src/sub/g"), "more");
        QTemporaryDir dir;
        const QString url = S("file://") + dir.path();
        QCOMPARE(run({ S("cp"), S("--to-url"), url, S("src/f"), S("f") }), 0);
        QFile copied(dir.filePath(S("f")));
        QVERIFY(copied.open(QIODevice::ReadOnly));
        QCOMPARE(copied.readAll(), QByteArray("data"));
        QCOMPARE(run({ S("cp"), S("--to-url"), url, S("src/f"), S("f") }), code(Error::AlreadyExists));
        QCOMPARE(run({ S("cp"), S("-r"), S("--to-url"), url, S("src"), S("tree") }), 0);
        QVERIFY(QFileInfo::exists(dir.filePath(S("tree/sub/g"))));
        // The destination's own options and checks.
        QCOMPARE(run({ S("cp"), S("--to-option"), S("novalue"), S("--to-url"), url, S("src/f"), S("h") }), 2);
        QCOMPARE(run({ S("cp"), S("--to-secret-env"), S("X"), S("src/f"), S("h") }), 2);
        QCOMPARE(run({ S("cp"), S("--to-url"), S("file://h.example/x"), S("src/f"), S("h") }), code(Error::Unsupported));
        QCOMPARE(run({ S("cp"), S("--to-url"), S("sftp://u:p@h/"), S("src/f"), S("h") }), code(Error::SecurityPolicy));
    }

    void catRanges()
    {
        QByteArray data;
        for (int i = 0; i < 256; ++i)
            data.append(static_cast<char>(i));
        FakeServer::instance()->addFile(S("bin"), data);
        QCOMPARE(run({ S("cat"), S("bin") }), 0);
        QCOMPARE(out.toLatin1(), data);       // a string-backed stream gets the bytes as Latin-1
        QCOMPARE(run({ S("cat"), S("--offset"), S("10"), S("bin") }), 0);
        QCOMPARE(out.toLatin1(), data.mid(10));
        QCOMPARE(run({ S("cat"), S("--length"), S("5"), S("bin") }), 0);
        QCOMPARE(out.toLatin1(), data.left(5));
        QCOMPARE(run({ S("cat"), S("--offset"), S("100"), S("--length"), S("7"), S("bin") }), 0);
        QCOMPARE(out.toLatin1(), data.mid(100, 7));
        QCOMPARE(run({ S("cat"), S("--offset"), S("-1"), S("bin") }), 2);
        QCOMPARE(run({ S("cat"), S("--length"), S("x"), S("bin") }), 2);
        QCOMPARE(run({ S("cat"), S("--offset"), S("1") }), 2);
        QCOMPARE(run({ S("cat"), S("nothing") }), code(Error::NotFound));
    }

    void catToDevice()
    {
        FakeServer::instance()->addFile(S("bin"), QByteArray("\x00\xffraw\n", 6));
        QByteArray collected;
        QBuffer device(&collected);
        QVERIFY(device.open(QIODevice::WriteOnly));
        QTextStream o(&device);
        QTextStream e(&err);
        QCOMPARE(Cli::run({ S("--provider"), S("fake"), S("--host"), S("h"), S("--user"), S("user"), S("cat"), S("bin") },
                          o, e),
                 0);
        QCOMPARE(collected, QByteArray("\x00\xffraw\n", 6));    // raw bytes, no text encoding
    }

    void attributes()
    {
        FakeServer *server = FakeServer::instance();
        server->addFile(S("f"), "x", utc("2000-01-01T00:00:00Z"), 0644);
        QCOMPARE(run({ S("chmod"), S("600"), S("f") }), 0);
        QCOMPARE(server->node(S("f")).mode, 0600);
        QCOMPARE(run({ S("chmod"), S("4755"), S("f") }), 0);
        QCOMPARE(server->node(S("f")).mode, 04755);
        QCOMPARE(run({ S("chmod"), S("0644"), S("f") }), 0);
        QCOMPARE(server->node(S("f")).mode, 0644);
        QCOMPARE(run({ S("chmod"), S("rw"), S("f") }), 2);
        QCOMPARE(run({ S("chmod"), S("789"), S("f") }), 2);
        QCOMPARE(run({ S("chmod"), S("77777"), S("f") }), 2);
        QCOMPARE(run({ S("chmod"), S("644"), S("nothing") }), code(Error::NotFound));

        QCOMPARE(run({ S("touch"), S("--mtime"), S("2021-03-04T05:06:07Z"), S("f") }), 0);
        QCOMPARE(server->node(S("f")).modified.toUTC(), utc("2021-03-04T05:06:07Z"));
        // A time without a zone is UTC.
        QCOMPARE(run({ S("touch"), S("--mtime"), S("2022-03-04T05:06:07"), S("f") }), 0);
        QCOMPARE(server->node(S("f")).modified.toUTC(), utc("2022-03-04T05:06:07Z"));
        QCOMPARE(run({ S("touch"), S("--mtime"), S("yesterday"), S("f") }), 2);
        // Missing: created empty, with the time.
        QVERIFY(!server->exists(S("new")));
        QCOMPARE(run({ S("touch"), S("--mtime"), S("2019-01-02T03:04:05Z"), S("new") }), 0);
        QVERIFY(server->exists(S("new")));
        QCOMPARE(server->fileData(S("new")), QByteArray());
        QCOMPARE(server->node(S("new")).modified.toUTC(), utc("2019-01-02T03:04:05Z"));
        // No --mtime: now.
        const QDateTime before = QDateTime::currentDateTimeUtc().addSecs(-2);
        QCOMPARE(run({ S("touch"), S("f") }), 0);
        QVERIFY(server->node(S("f")).modified >= before);
        QCOMPARE(run({ S("touch"), S("nodir/new") }), code(Error::NotFound));
        // Without SetModified the server says so; nothing is created for it.
        server->capabilities.flags.remove(Capability::SetModified);
        QCOMPARE(run({ S("touch"), S("f") }), code(Error::Unsupported));
    }

    void links()
    {
        FakeServer *server = FakeServer::instance();
        server->addFile(S("t"), "x");
        QCOMPARE(run({ S("ln"), S("-s"), S("t"), S("l") }), 0);
        QCOMPARE(server->node(S("l")).target, S("t"));
        QCOMPARE(run({ S("readlink"), S("l") }), 0);
        QCOMPARE(out, S("t\n"));
        // Targets are verbatim: relative and dangling are fine.
        QCOMPARE(run({ S("ln"), S("-s"), S("../x/y"), S("l2") }), 0);
        QCOMPARE(run({ S("readlink"), S("l2") }), 0);
        QCOMPARE(out, S("../x/y\n"));
        QVERIFY(run({ S("readlink"), S("t") }) != 0);   // not a link
        QCOMPARE(run({ S("ln"), S("t"), S("hard") }), 0);
        QCOMPARE(server->fileData(S("hard")), QByteArray("x"));
        QCOMPARE(run({ S("ln"), S("-s"), S("t"), S("l") }), code(Error::AlreadyExists));
        server->capabilities.flags.remove(Capability::Symlinks);
        QCOMPARE(run({ S("ln"), S("-s"), S("t"), S("l3") }), code(Error::Unsupported));
    }

    void spaceAndSums()
    {
        FakeServer *server = FakeServer::instance();
        server->addFile(S("f"), "hello");
        QCOMPARE(run({ S("df"), S("--all"), S("") }), 0);
        QCOMPARE(out, S("free=%1 total=%2 used=%3\n").arg(server->freeBytes).arg(server->totalBytes)
                                  .arg(server->totalBytes - server->freeBytes));
        QCOMPARE(run({ S("sum"), S("f") }), 0);
        QVERIFY2(out.endsWith(S("  f\n")), qPrintable(out));
        const QString hex = out.left(out.indexOf(QLatin1Char(' ')));
        QCOMPARE(hex.size(), 64);                                          // sha256 by default
        QCOMPARE(run({ S("sum"), S("--algo"), S("md5"), S("f") }), 0);
        QCOMPARE(out.left(out.indexOf(QLatin1Char(' '))).size(), 32);
        QCOMPARE(run({ S("sum"), S("--algo"), S("crc99"), S("f") }), code(Error::Unsupported));
        QCOMPARE(run({ S("sum"), S("--algo"), QString(), S("f") }), 2);
        QCOMPARE(run({ S("sum"), S("nothing") }), code(Error::NotFound));
    }

    void capabilities()
    {
        FakeServer *server = FakeServer::instance();
        server->capabilities.maxNameBytes = 255;
        QCOMPARE(run({ S("caps") }), 0);
        const QStringList lines = out.split(QLatin1Char('\n'));
        QVERIFY(lines.at(0).startsWith(S("capabilities: ")));
        QVERIFY(lines.at(0).contains(S("Symlinks")));
        QVERIFY(lines.at(0).contains(S("ServerCopy")));
        QVERIFY(lines.contains(S("checksums: sha256 md5")));
        QVERIFY(lines.contains(S("maxNameBytes: 255")));
        QCOMPARE(run({ S("caps"), S("--json") }), 0);
        const QJsonObject object = json().object();
        QVERIFY(object.value(S("capabilities")).toArray().contains(QJsonValue(S("Symlinks"))));
        QCOMPARE(object.value(S("checksums")).toArray().size(), 2);
        QCOMPARE(object.value(S("maxNameBytes")).toInt(), 255);
        server->capabilities.maxNameBytes = -1;
        QCOMPARE(run({ S("caps") }), 0);
        QVERIFY(out.contains(S("maxNameBytes: unknown")));
        QCOMPARE(run({ S("caps"), S("extra") }), 2);
    }

    void shares()
    {
        // Only SMB locations have shares; the CLI lists the root of the location with an empty share.
        QCOMPARE(run({ S("shares") }), 2);
        QCOMPARE(runArgs({ S("shares"), S("extra") }), 2);
        if (!QFileInfo::exists(QStringLiteral(NETVFS_TEST_BACKEND_DIR "/libnetvfs-smb.so")))
            QSKIP("libnetvfs-smb.so is not built");
        // The share named in the URL is dropped; nothing listens on port 1.
        const int result = runArgs({ S("--url"), S("smb://alice@127.0.0.1:1/share"), S("shares") });
        QVERIFY2(result != 0 && result != 2, qPrintable(err));
    }

    // ------------------------------------------------------------- discovery

    void discoverCommand()
    {
        QCOMPARE(runArgs({ S("discover"), S("--seconds"), S("x") }), 2);
        QCOMPARE(runArgs({ S("discover"), S("--seconds"), S("-1") }), 2);
        QCOMPARE(runArgs({ S("discover"), S("--seconds"), S("99999") }), 2);
        QCOMPARE(runArgs({ S("discover"), S("stray") }), 2);
        // No location needed; without multicast the sockets cannot be opened.
        const int result = runArgs({ S("discover"), S("--seconds"), S("0") });
        QVERIFY2(result == 0 || result == code(Error::NetworkUnreachable), qPrintable(err));
    }

    void discoverMerging()
    {
        DiscoveredService ssh;
        ssh.instanceName = S("My NAS");
        ssh.serviceType = S("_ssh._tcp");
        ssh.provider = S("sftp");
        ssh.host = S("nas.local");
        ssh.port = 22;
        ssh.addresses << QHostAddress(S("192.168.1.5"));
        DiscoveredService sftp = ssh;
        sftp.serviceType = S("_sftp-ssh._tcp");
        DiscoveredService smb;
        smb.instanceName = S("My\tNAS");
        smb.serviceType = S("_smb._tcp");
        smb.provider = S("smb");
        smb.host = S("nas.local");
        smb.port = 445;
        DiscoveredService dav;
        dav.instanceName = S("Cloud");
        dav.serviceType = S("_webdavs._tcp");
        dav.provider = S("webdav");
        dav.tls = S("https");
        dav.host = S("cloud.local");
        dav.port = 8443;
        dav.path = S("/dav");

        const QVector<Cli::ServiceView> views = Cli::mergeServices({ ssh, smb, sftp, dav });
        QCOMPARE(views.size(), 3);   // _ssh and _sftp-ssh of one endpoint are one entry
        QMap<QString, Cli::ServiceView> byProvider;
        for (const Cli::ServiceView &view : views)
            byProvider.insert(view.service.provider, view);
        QCOMPARE(byProvider.value(S("sftp")).serviceTypes, QStringList({ S("_sftp-ssh._tcp"), S("_ssh._tcp") }));
        QCOMPARE(byProvider.value(S("sftp")).url, S("sftp://nas.local:22/"));
        QCOMPARE(byProvider.value(S("smb")).url, S("smb://nas.local:445"));
        QCOMPARE(byProvider.value(S("webdav")).url, S("https://cloud.local:8443/dav"));
        QCOMPARE(Cli::serviceLine(byProvider.value(S("sftp"))),
                 S("sftp://nas.local:22/\tMy NAS\t_sftp-ssh._tcp,_ssh._tcp\t192.168.1.5"));
        QCOMPARE(Cli::serviceLine(byProvider.value(S("smb"))), S("smb://nas.local:445\tMy NAS\t_smb._tcp\t"));
        // Different ports of one host are different endpoints.
        DiscoveredService other = ssh;
        other.port = 2222;
        QCOMPARE(Cli::mergeServices({ ssh, other }).size(), 2);
    }

    // ---------------------------------------------------------------- prompt

    void promptAuthentication()
    {
        FakeServer::instance()->otp = "123456";
        // Without --prompt interactive methods are not tried.
        QCOMPARE(run({ S("ls"), QString() }), code(Error::AuthFailed));
        QBuffer input;
        input.setData("123456\n");
        QVERIFY(input.open(QIODevice::ReadOnly));
        QCOMPARE(runArgs({ S("--provider"), S("fake"), S("--host"), S("h"), S("--user"), S("user"), S("--prompt"),
                           S("ls"), QString() }, &input),
                 0);
        QVERIFY(err.contains(S("Verification code: ")));   // prompts go to stderr, not stdout
        QVERIFY(!out.contains(S("Verification")));
        QBuffer wrong;
        wrong.setData("000000\n");
        QVERIFY(wrong.open(QIODevice::ReadOnly));
        QCOMPARE(runArgs({ S("--provider"), S("fake"), S("--host"), S("h"), S("--user"), S("user"), S("--prompt"),
                           S("ls"), QString() }, &wrong),
                 code(Error::AuthFailed));
    }

    void promptHidesSecrets()
    {
        QBuffer input;
        input.setData("first\nsecond\r\n");
        QVERIFY(input.open(QIODevice::ReadOnly));
        QString shown;
        QTextStream prompts(&shown);
        EchoRecorder echo;
        Cli::TerminalPrompter prompter(&input, &prompts, &echo);
        AuthPrompt visible;
        visible.text = S("User: ");
        visible.echo = true;
        AuthPrompt hidden;
        hidden.text = S("Password: ");
        hidden.echo = false;
        QVector<QByteArray> answers;
        QVERIFY(prompter.answer(S("name"), S("instruction"), { hidden, visible }, &answers));
        QCOMPARE(answers, QVector<QByteArray>({ "first", "second" }));
        // Echo is off only around the no-echo prompt, and back on afterwards.
        QCOMPARE(echo.calls, QVector<bool>({ false, true }));
        QVERIFY(shown.startsWith(S("name\ninstruction\nPassword: ")));
        QVERIFY(shown.contains(S("User: ")));
    }

    void promptRefusesWhenEchoCannotBeDisabled()
    {
        QBuffer input;
        input.setData("secret\n");
        QVERIFY(input.open(QIODevice::ReadOnly));
        QString shown;
        QTextStream prompts(&shown);
        EchoRecorder echo;
        echo.result = false;
        Cli::TerminalPrompter prompter(&input, &prompts, &echo);
        AuthPrompt hidden;
        hidden.text = S("Password: ");
        QVector<QByteArray> answers;
        QVERIFY(!prompter.answer(QString(), QString(), { hidden }, &answers));
        QVERIFY(answers.isEmpty());
        QCOMPARE(input.pos(), qint64(0));    // nothing was read
    }

    void promptSanitisesServerText()
    {
        QBuffer input;
        input.setData("x\n");
        QVERIFY(input.open(QIODevice::ReadOnly));
        QString shown;
        QTextStream prompts(&shown);
        Cli::TerminalPrompter prompter(&input, &prompts, nullptr);
        AuthPrompt prompt;
        prompt.text = S("Code\x1b[2J: ");
        prompt.echo = true;
        QVector<QByteArray> answers;
        QVERIFY(prompter.answer(S("a\x07"), S("b\x1b]0;x"), { prompt }, &answers));
        QVERIFY(!shown.contains(QChar(0x1b)));
        QVERIFY(!shown.contains(QChar(0x07)));
        QVERIFY(shown.contains(S("Code?[2J: ")));
    }

    void promptEndOfInputDeclines()
    {
        QBuffer input;
        input.setData("one\n");
        QVERIFY(input.open(QIODevice::ReadOnly));
        QString shown;
        QTextStream prompts(&shown);
        Cli::TerminalPrompter prompter(&input, &prompts, nullptr);
        AuthPrompt prompt;
        prompt.text = S("? ");
        prompt.echo = true;
        QVector<QByteArray> answers;
        QVERIFY(!prompter.answer(QString(), QString(), { prompt, prompt }, &answers));
        QVERIFY(answers.isEmpty());
    }

    // --------------------------------------------------------- local backend

    void localEndToEnd()
    {
        if (!localPluginAvailable())
            QSKIP("libnetvfs-local.so is not built");
        QTemporaryDir dir;
        QTemporaryDir outside;
        QVERIFY(QFile::link(outside.path(), dir.filePath(S("escape"))));
        QFile source(dir.filePath(S("source")));
        QVERIFY(source.open(QIODevice::WriteOnly));
        source.write("0123456789");
        source.close();
        QFile keep(outside.filePath(S("keep")));
        QVERIFY(keep.open(QIODevice::WriteOnly));
        keep.write("k");
        keep.close();

        const QString root = dir.path();
        QCOMPARE(runLocal(root, { S("mkdir"), S("-p"), S("a/b") }), 0);
        QCOMPARE(runLocal(root, { S("put"), root + S("/source"), S("a/b/f") }), 0);
        QCOMPARE(runLocal(root, { S("ls"), S("-l"), S("a/b") }), 0);
        QVERIFY2(out.contains(QRegExp(S("^-rw------- \\S+ \\S+ 10 \\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ - f\n$"))),
                 qPrintable(out));
        QCOMPARE(runLocal(root, { S("cat"), S("--offset"), S("3"), S("--length"), S("4"), S("a/b/f") }), 0);
        QCOMPARE(out, S("3456"));
        QCOMPARE(runLocal(root, { S("chmod"), S("640"), S("a/b/f") }), 0);
        QCOMPARE(runLocal(root, { S("stat"), S("a/b/f") }), 0);
        QVERIFY(out.startsWith(S("-rw-r-----")));
        QCOMPARE(runLocal(root, { S("touch"), S("--mtime"), S("2020-01-02T03:04:05Z"), S("a/b/f") }), 0);
        QCOMPARE(runLocal(root, { S("stat"), S("--json"), S("a/b/f") }), 0);
        QCOMPARE(json().object().value(S("modified")).toString(), S("2020-01-02T03:04:05Z"));
        QCOMPARE(runLocal(root, { S("touch"), S("a/created") }), 0);
        QCOMPARE(QFileInfo(dir.filePath(S("a/created"))).size(), qint64(0));

        QCOMPARE(runLocal(root, { S("sum"), S("a/b/f") }), 0);
        QCOMPARE(out.left(64).toLatin1(), QCryptographicHash::hash("0123456789", QCryptographicHash::Sha256).toHex());
        QCOMPARE(runLocal(root, { S("ln"), S("-s"), S("b/f"), S("a/link") }), 0);
        QCOMPARE(runLocal(root, { S("readlink"), S("a/link") }), 0);
        QCOMPARE(out, S("b/f\n"));
        QCOMPARE(runLocal(root, { S("lstat"), S("a/link") }), 0);
        QVERIFY(out.startsWith(S("l")));
        QCOMPARE(runLocal(root, { S("df"), S("") }), 0);
        QVERIFY(out.trimmed().toLongLong() > 0);
        QCOMPARE(runLocal(root, { S("caps") }), 0);
        QVERIFY(out.contains(S("Symlinks")));

        QCOMPARE(runLocal(root, { S("cp"), S("a/b/f"), S("a/copy") }), 0);
        QCOMPARE(runLocal(root, { S("cp"), S("a/b/f"), S("a/copy") }), code(Error::AlreadyExists));
        QCOMPARE(runLocal(root, { S("cp"), S("-r"), S("a"), S("a2") }), 0);
        QVERIFY(QFileInfo::exists(dir.filePath(S("a2/b/f"))));
        QCOMPARE(runLocal(root, { S("mv"), S("a2"), S("a3") }), 0);
        QCOMPARE(runLocal(root, { S("mv"), S("a3"), S("a") }), code(Error::AlreadyExists));
        QVERIFY(QFileInfo::exists(dir.filePath(S("a3/b/f"))));

        // rm -r removes the link to the outside folder, not what it points to.
        QCOMPARE(runLocal(root, { S("ln"), S("-s"), outside.path(), S("a3/out") }), 0);
        QCOMPARE(runLocal(root, { S("rm"), S("-r"), S("a3") }), 0);
        QVERIFY(!QFileInfo::exists(dir.filePath(S("a3"))));
        QVERIFY(QFileInfo::exists(outside.filePath(S("keep"))));
        QCOMPARE(runLocal(root, { S("rm"), S("a/b/f") }), 0);
        QCOMPARE(runLocal(root, { S("rmdir"), S("a/b") }), 0);
        QCOMPARE(runLocal(root, { S("rmdir"), S("a") }), code(Error::DirectoryNotEmpty));
    }
};

QTEST_GUILESS_MAIN(TestCli)
#include "tst_cli.moc"
