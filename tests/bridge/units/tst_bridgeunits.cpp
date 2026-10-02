// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs-bridge building blocks (SPEC-v2 XT-7): argument validation (XSEC-7),
// the D-Bus codec (XB-9), file descriptor checks (XB-11), the peer check
// (XB-5), consumer registration and consent (XB-3, XB-6), known hosts
// (XB-14), questions and the settings handoff table (XB-15).
#include "args.h"
#include "consentstore.h"
#include "fdcheck.h"
#include "handoff.h"
#include "knownhosts.h"
#include "names.h"
#include "peercheck.h"
#include "protocol.h"
#include "questions.h"
#include "wire.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>
#include <QtTest/QtTest>

#include <dbus/dbus.h>

#include <array>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace NetVfs;
using namespace NetVfs::Bridge;

namespace QTest {
template<>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest

namespace {

Result validate(const QString &member, const QString &signature, QVariantList args, Call *call = nullptr)
{
    Call local;
    return validateCall(member, signature, &args, call ? call : &local);
}

QVariant bytes(const char *s)
{
    return QVariant(QByteArray(s));
}

void writeFile(const QString &path, const QByteArray &data)
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
    f.write(data);
}

// A fake /proc with one process.
struct FakeProc {
    QTemporaryDir dir;
    QString procRoot() const { return dir.path(); }

    void addProcess(int pid, const QString &exe, qint64 startTime)
    {
        const QString base = dir.path() + QLatin1Char('/') + QString::number(pid);
        QDir().mkpath(base);
        QFile::remove(base + QStringLiteral("/exe"));
        QFile::link(exe, base + QStringLiteral("/exe"));
        setStartTime(pid, startTime);
    }
    void setStartTime(int pid, qint64 startTime)
    {
        // Field 22 is starttime; comm with spaces and parentheses on purpose.
        QByteArray stat = QByteArray::number(pid) + " (we (ird) name) S";
        for (int field = 4; field <= 21; ++field)
            stat += " 0";
        stat += ' ' + QByteArray::number(startTime) + " 0 0\n";
        writeFile(dir.path() + QLatin1Char('/') + QString::number(pid) + QStringLiteral("/stat"), stat);
    }
    void setPidfd(int fd, int pid)
    {
        writeFile(dir.path() + QStringLiteral("/self/fdinfo/") + QString::number(fd),
                  "pos:\t0\nflags:\t02000002\nPid:\t" + QByteArray::number(pid) + "\n");
    }
};

PeerChecker::Environment fakeEnvironment(const FakeProc &proc, uid_t uid, int pid, int pidfd = -1)
{
    PeerChecker::Environment env;
    env.procRoot = proc.procRoot();
    env.ownUid = 4242;
    env.credentials = [uid, pid, pidfd](int, PeerCredentials *out) {
        out->uid = uid;
        out->pid = pid;
        out->pidfd = pidfd >= 0 ? ::dup(0) : -1;
        return true;
    };
    env.openPidfd = [](pid_t) { return -1; };
    env.bootTicksNow = []() { return qint64(100000); };
    return env;
}

} // namespace

class tst_BridgeUnits : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void methodTable();
    void signaturesAndCounts();
    void paths_data();
    void paths();
    void numbers();
    void options();
    void identifiers();
    void secretsMovedAndWiped();
    void wireRoundTrip();
    void errorReplies();
    void fdChecks();
    void uploadLength();
    void fdDeviceOffsets();
    void peerUid();
    void peerExecutable();
    void peerPidReuse();
    void peerPidfd();
    void peerRealProcess();
    void consumers();
    void consent();
    void knownHosts();
    void questions();
    void handoff();
};

void tst_BridgeUnits::methodTable()
{
    // Every method of XB-10 exactly once.
    const QStringList expected = {
        "Hello", "GetConsent", "RequestConsent", "ListLocations", "Capabilities", "Disconnect", "ConnectAdHoc",
        "ForgetAdHoc", "Discover", "List", "Stat", "ReadLink", "SpaceInfo", "Checksum", "MakeDir", "RemoveFile",
        "RemoveDir", "Rename", "SetAttributes", "MakeSymlink", "MakeHardlink", "ServerCopy", "OpenRead", "Read",
        "ReadAhead", "Close", "Upload", "Download", "CopyAcross", "RemoveTree", "Walk", "Cancel", "Answer",
        "OpenAccountSettings", "AddAccount"
    };
    QStringList names;
    for (const MethodInfo &m : methods())
        names << QLatin1String(m.name);
    QCOMPARE(names, expected);
    QVERIFY(findMethod(QStringLiteral("Stat"))->needsConsent);
    QVERIFY(!findMethod(QStringLiteral("Hello"))->needsConsent);
    QVERIFY(!findMethod(QStringLiteral("ListLocations"))->needsConsent);   // returns nothing instead (XB-6)
    QVERIFY(!findMethod(QStringLiteral("Nope")));
}

void tst_BridgeUnits::signaturesAndCounts()
{
    QCOMPARE(validate("Hello", "us", { 1u, QStringLiteral("x") }).error(), Error::None);
    QCOMPARE(validate("Hello", "su", { QStringLiteral("x"), 1u }).error(), Error::ProtocolError);
    QCOMPARE(validate("Hello", "us", { 1u }).error(), Error::ProtocolError);              // count
    QCOMPARE(validate("Hello", "us", { 1u, QStringLiteral("x"), 2u }).error(), Error::ProtocolError);
    QCOMPARE(validate("Hello", "us", { QStringLiteral("x"), 1u }).error(), Error::ProtocolError); // types
    QCOMPARE(validate("Hello", "us", { 0u, QStringLiteral("x") }).error(), Error::ProtocolError); // protocol 0
    QCOMPARE(validate("Frobnicate", "", {}).error(), Error::Unsupported);
    QCOMPARE(validate("Stat", "saybs", { QStringLiteral("account:1"), bytes("a"), true, QString() }).error(),
             Error::None);
    // A Download whose "h" is not a file descriptor.
    QCOMPARE(validate("Download", "sayha{sv}", { QStringLiteral("account:1"), bytes("a"), 5, QVariantMap() }).error(),
             Error::ProtocolError);
}

void tst_BridgeUnits::paths_data()
{
    QTest::addColumn<QByteArray>("raw");
    QTest::addColumn<int>("error");
    QTest::addColumn<QString>("normalized");
    QTest::newRow("plain") << QByteArray("docs/a.txt") << int(Error::None) << QStringLiteral("docs/a.txt");
    QTest::newRow("collapse") << QByteArray("/docs//a/") << int(Error::None) << QStringLiteral("/docs/a");
    QTest::newRow("dotdot") << QByteArray("docs/../etc") << int(Error::InvalidName) << QString();
    QTest::newRow("dot") << QByteArray("./a") << int(Error::InvalidName) << QString();
    QTest::newRow("nul") << QByteArray("a\0b", 3) << int(Error::InvalidName) << QString();
    QTest::newRow("latin1") << QByteArray("caf\xe9") << int(Error::None) << Names::decode(QByteArray("caf\xe9"));
    QTest::newRow("long") << QByteArray(Limits::MaxPathBytes + 1, 'a') << int(Error::InvalidName) << QString();
    QTest::newRow("max") << QByteArray(Limits::MaxPathBytes, 'a') << int(Error::None)
                         << QString(Limits::MaxPathBytes, QLatin1Char('a'));
}

void tst_BridgeUnits::paths()
{
    QFETCH(QByteArray, raw);
    QFETCH(int, error);
    QFETCH(QString, normalized);
    Call call;
    const Result r = validate("RemoveFile", "say", { QStringLiteral("account:1"), QVariant(raw) }, &call);
    QCOMPARE(int(r.error()), error);
    if (r.ok())
        QCOMPARE(call.path, normalized);
    // Both paths of a two-path call are checked.
    const Result r2 = validate("Rename", "sayayb", { QStringLiteral("account:1"), bytes("ok"), QVariant(raw), false });
    QCOMPARE(int(r2.error()), error);
    // A path must be bytes, never a string (XB-9).
    QCOMPARE(validatePath(QVariant(QString::fromLatin1(raw)), &normalized).error(), Error::ProtocolError);
}

void tst_BridgeUnits::numbers()
{
    const QString loc = QStringLiteral("account:1");
    Call call;
    // List batch: 0 is the default, at most 512 (XB-17).
    QVERIFY(validate("List", "saysu", { loc, bytes(""), QString(), 0u }, &call).ok());
    QCOMPARE(call.number, quint32(Limits::DefaultListBatch));
    QVERIFY(validate("List", "saysu", { loc, bytes(""), QString(), 512u }, &call).ok());
    QCOMPARE(validate("List", "saysu", { loc, bytes(""), QString(), 513u }).error(), Error::ProtocolError);
    // Read: at most 1 MiB, offsets >= 0.
    QVERIFY(validate("Read", "uxu", { 1u, qlonglong(0), uint(Limits::MaxReadBytes) }, &call).ok());
    QCOMPARE(call.length, qint64(Limits::MaxReadBytes));
    QCOMPARE(validate("Read", "uxu", { 1u, qlonglong(0), uint(Limits::MaxReadBytes) + 1 }).error(), Error::ProtocolError);
    QCOMPARE(validate("Read", "uxu", { 1u, qlonglong(-1), 1u }).error(), Error::ProtocolError);
    QCOMPARE(validate("Read", "uxu", { 1u, qlonglong(Limits::MaxOffset) + 1, 1u }).error(), Error::ProtocolError);
    QVERIFY(validate("Read", "uxu", { 1u, qlonglong(Limits::MaxOffset), 1u }).ok());
    // ReadAhead is a hint: capped, not refused.
    QVERIFY(validate("ReadAhead", "uxx", { 1u, qlonglong(0), qlonglong(1) << 40 }, &call).ok());
    QCOMPARE(call.length, Limits::MaxReadAheadBytes);
    QCOMPARE(validate("ReadAhead", "uxx", { 1u, qlonglong(0), qlonglong(-5) }).error(), Error::ProtocolError);
}

void tst_BridgeUnits::options()
{
    const QString loc = QStringLiteral("account:1");
    Call call;
    QVariantMap attributes { { "mode", 0644 }, { "mtimeMs", qlonglong(1000) } };
    QVERIFY(validate("SetAttributes", "saya{sv}", { loc, bytes("a"), attributes }, &call).ok());
    QCOMPARE(call.attributes.mode, 0644);
    QCOMPARE(call.attributes.modified, QDateTime::fromMSecsSinceEpoch(1000, Qt::UTC));
    QCOMPARE(validate("SetAttributes", "saya{sv}", { loc, bytes("a"), QVariantMap { { "mode", 010000 } } }).error(),
             Error::ProtocolError);
    QCOMPARE(validate("SetAttributes", "saya{sv}", { loc, bytes("a"), QVariantMap { { "mode", "644" } } }).error(),
             Error::ProtocolError);
    QCOMPARE(validate("SetAttributes", "saya{sv}", { loc, bytes("a"), QVariantMap { { "owner", 1 } } }).error(),
             Error::ProtocolError);   // unknown keys are refused
    QCOMPARE(validate("SetAttributes", "saya{sv}",
                      { loc, bytes("a"), QVariantMap { { "mtimeMs", Limits::MaxTimeMs + 1 } } }).error(),
             Error::ProtocolError);

    const QVariant fd = QVariant::fromValue(UnixFd());
    QVariantMap upload { { "offset", qlonglong(10) }, { "size", qlonglong(5) }, { "disposition", "resume" },
                         { "createMode", 0600 }, { "lane", "stream" } };
    QVERIFY(validate("Upload", "sayha{sv}", { loc, bytes("a"), fd, upload }, &call).ok());
    QCOMPARE(call.transfer.offset, qint64(10));
    QCOMPARE(call.transfer.size, qint64(5));
    QCOMPARE(call.transfer.disposition, WriteOptions::Resume);
    QCOMPARE(call.transfer.createMode, 0600);
    QCOMPARE(call.lane, Lane::Stream);
    QCOMPARE(validate("Upload", "sayha{sv}", { loc, bytes("a"), fd, QVariantMap { { "disposition", "resume" } } }).error(),
             Error::ProtocolError);   // resume needs an offset
    QCOMPARE(validate("Upload", "sayha{sv}", { loc, bytes("a"), fd, QVariantMap { { "size", qlonglong(-2) } } }).error(),
             Error::ProtocolError);
    QCOMPARE(validate("Download", "sayha{sv}", { loc, bytes("a"), fd, QVariantMap { { "createMode", 0600 } } }).error(),
             Error::ProtocolError);   // write-only option
    QVERIFY(validate("Download", "sayha{sv}", { loc, bytes("a"), fd, QVariantMap { { "offset", 7u } } }, &call).ok());
    QCOMPARE(call.transfer.offset, qint64(7));
    QCOMPARE(call.lane, Lane::Bulk);
    QCOMPARE(validate("Download", "sayha{sv}", { loc, bytes("a"), fd, QVariantMap { { "offset", qulonglong(-1) } } }).error(),
             Error::ProtocolError);

    QVERIFY(validate("Walk", "saya{sv}", { loc, bytes(""), QVariantMap { { "maxDepth", 3 }, { "followSymlinks", true } } },
                     &call).ok());
    QCOMPARE(call.tree.maxDepth, 3);
    QVERIFY(call.tree.followSymlinks);
    QCOMPARE(validate("Walk", "saya{sv}", { loc, bytes(""), QVariantMap { { "maxDepth", 5000 } } }).error(),
             Error::ProtocolError);
    QCOMPARE(validate("ServerCopy", "sayaya{sv}", { loc, bytes("a"), bytes("b"), QVariantMap { { "recursive", 1 } } }).error(),
             Error::ProtocolError);
    QCOMPARE(validate("Stat", "saybs", { loc, bytes("a"), true, QStringLiteral("fast") }).error(), Error::ProtocolError);
    // Symlink targets are verbatim but bounded.
    QVERIFY(validate("MakeSymlink", "sayay", { loc, bytes("../x"), bytes("l") }, &call).ok());
    QCOMPARE(call.linkTarget, QStringLiteral("../x"));
    QCOMPARE(validate("MakeSymlink", "sayay", { loc, bytes(""), bytes("l") }).error(), Error::InvalidName);
}

void tst_BridgeUnits::identifiers()
{
    QVERIFY(isValidLocationId(QStringLiteral("account:12")));
    QVERIFY(isValidLocationId(QStringLiteral("adhoc:3")));
    QVERIFY(!isValidLocationId(QStringLiteral("Account:1")));
    QVERIFY(!isValidLocationId(QStringLiteral("a/b")));
    QVERIFY(!isValidLocationId(QString(Limits::MaxIdLength + 1, QLatin1Char('a'))));
    QVERIFY(isValidToken(QStringLiteral("sha256"), 32));
    QVERIFY(!isValidToken(QStringLiteral("SHA256"), 32));
    QVERIFY(!isValidToken(QString(), 32));
    QCOMPARE(validate("Checksum", "says", { QStringLiteral("account:1"), bytes("a"), QStringLiteral("md 5") }).error(),
             Error::ProtocolError);
    QCOMPARE(validate("AddAccount", "s", { QStringLiteral("../sftp") }).error(), Error::ProtocolError);
    QCOMPARE(validate("Capabilities", "s", { QStringLiteral("") }).error(), Error::ProtocolError);
}

void tst_BridgeUnits::secretsMovedAndWiped()
{
    QVariantList args { QStringLiteral("sftp://h/"), QVariant(QByteArray("hunter2")), QVariantMap() };
    Call call;
    QVERIFY(validateCall(QStringLiteral("ConnectAdHoc"), QStringLiteral("saya{sv}"), &args, &call).ok());
    QVERIFY(!args.at(1).isValid());                 // only the Call holds the secret now
    QCOMPARE(call.secret, QByteArray("hunter2"));
    wipeSecrets(&call);
    QVERIFY(call.secret.isEmpty());

    QVariantList answer { QStringLiteral("q1"),
                          QVariantMap { { "accept", true }, { "answers", QVariantList { QByteArray("123456") } } } };
    QVERIFY(validateCall(QStringLiteral("Answer"), QStringLiteral("sa{sv}"), &answer, &call).ok());
    QVERIFY(!answer.at(1).isValid());
    QCOMPARE(call.answer.answers.size(), 1);
    wipeSecrets(&call);
    QVERIFY(call.answer.answers.isEmpty());

    QVariantList tooLong { QStringLiteral("sftp://h/"), QVariant(QByteArray(Limits::MaxSecretBytes + 1, 'x')),
                           QVariantMap() };
    QCOMPARE(validateCall(QStringLiteral("ConnectAdHoc"), QStringLiteral("saya{sv}"), &tooLong, &call).error(),
             Error::ProtocolError);
}

void tst_BridgeUnits::wireRoundTrip()
{
    MessagePtr message(dbus_message_new_signal("/a", "b.c", "D"));
    Entry entry;
    entry.name = Names::decode(QByteArray("n\xff"));
    entry.type = EntryType::Symlink;
    entry.targetType = EntryType::Directory;
    entry.size = 42;
    entry.modified = QDateTime::fromMSecsSinceEpoch(1234, Qt::UTC);
    entry.mode = 0755;
    entry.uid = 7;
    entry.owner = QStringLiteral("o");
    entry.flags = EntryFlag::Hidden | EntryFlag::NameNotUtf8;
    entry.etag = "e";
    {
        WireWriter w(message.get());
        Protocol::writeEntry(w, entry);
        w.variantMap(QVariantMap { { "x", qlonglong(5) }, { "s", QStringLiteral("t") }, { "b", true },
                                   { "ay", QByteArray("z") }, { "as", QStringList { "p", "q" } } });
        w.string(QString(QStringLiteral("nul")) + QChar(0));   // must not abort libdbus
        QVERIFY(w.ok());
    }
    QCOMPARE(QByteArray(dbus_message_get_signature(message.get())),
             QByteArray(Protocol::EntrySignature) + "a{sv}s");
    QVariantList args;
    QVERIFY(decodeArguments(message.get(), &args).ok());
    QCOMPARE(args.size(), 3);
    const QVariantList e = args.at(0).toList();
    QCOMPARE(e.size(), 15);
    QCOMPARE(e.at(0).toByteArray(), QByteArray("n\xff"));
    QCOMPARE(e.at(1).toUInt(), 3u);
    QCOMPARE(e.at(2).toUInt(), 2u);
    QCOMPARE(e.at(3).toLongLong(), 42);
    QCOMPARE(e.at(4).toLongLong(), 1234);
    QCOMPARE(e.at(5).toLongLong(), -1);
    QCOMPARE(e.at(7).toInt(), 0755);
    QCOMPARE(e.at(12).toUInt(), 0x9u);
    const QVariantMap map = args.at(1).toMap();
    QCOMPARE(map.value("x").toLongLong(), 5);
    QCOMPARE(map.value("ay").toByteArray(), QByteArray("z"));
    QCOMPARE(map.value("as").toStringList(), QStringList({ "p", "q" }));
    QCOMPARE(args.at(2).toString(), QString(QStringLiteral("nul")) + QChar(0xFFFD));

    // A value the wire cannot carry fails cleanly.
    MessagePtr bad(dbus_message_new_signal("/a", "b.c", "D"));
    WireWriter w(bad.get());
    w.variantMap(QVariantMap { { "d", QDate(2020, 1, 1) } });
    QVERIFY(!w.ok());

    // Decoder limits.
    MessagePtr deep(dbus_message_new_signal("/a", "b.c", "D"));
    {
        WireWriter dw(deep.get());
        QVariantList nested { 1 };
        for (int i = 0; i < 10; ++i)
            nested = QVariantList { QVariant(nested) };
        dw.variant(QVariant(nested));
        QVERIFY(dw.ok());
    }
    QCOMPARE(decodeArguments(deep.get(), &args).error(), Error::ProtocolError);
}

void tst_BridgeUnits::errorReplies()
{
    MessagePtr call(dbus_message_new_method_call(nullptr, "/org/netvfs/Bridge", "org.netvfs.Bridge1", "Stat"));
    dbus_message_set_serial(call.get(), 7);
    MessagePtr reply = Protocol::errorReply(call.get(), Protocol::errorNameFor(Result(Error::NotFound), false),
                                            Result(Error::TooManyConnections, QStringLiteral("busy"), QStringLiteral("d"), 1500));
    QCOMPARE(QByteArray(dbus_message_get_error_name(reply.get())), QByteArray("org.netvfs.Error.NotFound"));
    QVariantList args;
    QVERIFY(decodeArguments(reply.get(), &args).ok());
    QCOMPARE(args.at(0).toString(), QStringLiteral("busy"));
    QCOMPARE(args.at(1).toMap().value("retryAfterMs").toLongLong(), 1500);
    QCOMPARE(args.at(1).toMap().value("detail").toString(), QStringLiteral("d"));
    QCOMPARE(Protocol::errorNameFor(Result(Error::ProtocolError), true), QStringLiteral("org.freedesktop.DBus.Error.InvalidArgs"));
    QCOMPARE(Protocol::errorNameFor(Result(Error::InvalidName), true), QStringLiteral("org.netvfs.Error.InvalidName"));
    QCOMPARE(Protocol::errorNameFor(Result(Error::ProtocolError), false), QStringLiteral("org.netvfs.Error.ProtocolError"));
}

void tst_BridgeUnits::fdChecks()
{
    QTemporaryDir dir;
    const QByteArray file = QFile::encodeName(dir.path() + QStringLiteral("/f"));
    writeFile(QString::fromLocal8Bit(file), "0123456789");
    FdInfo info;

    const int rd = ::open(file.constData(), O_RDONLY);
    QVERIFY(checkTransferFd(rd, FdAccess::Read, &info).ok());
    QVERIFY(!info.fifo);
    QCOMPARE(info.size, qint64(10));
    QCOMPARE(checkTransferFd(rd, FdAccess::Write, &info).error(), Error::PermissionDenied);   // download into read-only
    ::close(rd);

    const int wr = ::open(file.constData(), O_WRONLY);
    QVERIFY(checkTransferFd(wr, FdAccess::Write, &info).ok());
    QCOMPARE(checkTransferFd(wr, FdAccess::Read, &info).error(), Error::PermissionDenied);
    ::close(wr);

    const int rw = ::open(file.constData(), O_RDWR);
    QVERIFY(checkTransferFd(rw, FdAccess::Read, &info).ok());
    QVERIFY(checkTransferFd(rw, FdAccess::Write, &info).ok());
    ::close(rw);

    const int append = ::open(file.constData(), O_WRONLY | O_APPEND);
    QCOMPARE(checkTransferFd(append, FdAccess::Write, &info).error(), Error::PermissionDenied);
    ::close(append);

    const int path = ::open(file.constData(), O_PATH);
    QCOMPARE(checkTransferFd(path, FdAccess::Read, &info).error(), Error::PermissionDenied);
    ::close(path);

    const int folder = ::open(QFile::encodeName(dir.path()).constData(), O_RDONLY | O_DIRECTORY);
    QCOMPARE(checkTransferFd(folder, FdAccess::Read, &info).error(), Error::PermissionDenied);
    ::close(folder);

    std::array<int, 2> pipeFds {};
    QCOMPARE(::pipe(pipeFds.data()), 0);
    QVERIFY(checkTransferFd(pipeFds[0], FdAccess::Read, &info).ok());
    QVERIFY(info.fifo);
    QCOMPARE(checkTransferFd(pipeFds[0], FdAccess::Write, &info).error(), Error::PermissionDenied);
    QVERIFY(checkTransferFd(pipeFds[1], FdAccess::Write, &info).ok());
    ::close(pipeFds[0]);
    ::close(pipeFds[1]);

    QCOMPARE(checkTransferFd(-1, FdAccess::Read, &info).error(), Error::PermissionDenied);
    QCOMPARE(checkTransferFd(9999, FdAccess::Read, &info).error(), Error::PermissionDenied);
}

void tst_BridgeUnits::uploadLength()
{
    FdInfo fifo;
    fifo.fifo = true;
    FdInfo regular;
    QCOMPARE(checkUploadLength(fifo, -1, QStringLiteral("webdav")).error(), Error::Unsupported);
    QVERIFY(checkUploadLength(fifo, 10, QStringLiteral("webdav")).ok());
    QVERIFY(checkUploadLength(fifo, -1, QStringLiteral("sftp")).ok());
    QVERIFY(checkUploadLength(regular, -1, QStringLiteral("webdav")).ok());
}

void tst_BridgeUnits::fdDeviceOffsets()
{
    QTemporaryDir dir;
    const QByteArray file = QFile::encodeName(dir.path() + QStringLiteral("/f"));
    writeFile(QString::fromLocal8Bit(file), "0123456789");
    const int fd = ::open(file.constData(), O_RDWR);
    ::lseek(fd, 3, SEEK_SET);   // the consumer's offset must not matter
    FdInfo info;
    QVERIFY(checkTransferFd(fd, FdAccess::Read, &info).ok());
    std::atomic<bool> canceled { false };
    {
        FdDevice in(fd, info, 4, 3, &canceled);
        QVERIFY(in.open(QIODevice::ReadOnly | QIODevice::Unbuffered));
        QCOMPARE(in.size(), qint64(3));
        QCOMPARE(in.readAll(), QByteArray("456"));
        QVERIFY(in.seek(1));
        QCOMPARE(in.read(1), QByteArray("5"));
    }
    {
        FdDevice out(fd, info, 8, -1, &canceled);
        QVERIFY(out.open(QIODevice::WriteOnly | QIODevice::Unbuffered));
        QCOMPARE(out.write("ABCD"), qint64(4));
        QCOMPARE(out.transferred(), qint64(4));
    }
    QCOMPARE(::lseek(fd, 0, SEEK_CUR), off_t(3));
    ::close(fd);   // the device does not own the descriptor
    QFile f(QString::fromLocal8Bit(file));
    QVERIFY(f.open(QIODevice::ReadOnly));
    QCOMPARE(f.readAll(), QByteArray("01234567ABCD"));

    // A FIFO read gives up when canceled, without data arriving.
    std::array<int, 2> pipeFds {};
    QCOMPARE(::pipe(pipeFds.data()), 0);
    FdInfo fifoInfo;
    QVERIFY(checkTransferFd(pipeFds[0], FdAccess::Read, &fifoInfo).ok());
    FdDevice fifo(pipeFds[0], fifoInfo, 0, -1, &canceled);
    QVERIFY(fifo.open(QIODevice::ReadOnly | QIODevice::Unbuffered));
    QVERIFY(fifo.isSequential());
    canceled.store(true);
    QElapsedTimer timer;
    timer.start();
    char c = 0;
    QCOMPARE(fifo.read(&c, 1), qint64(-1));
    QVERIFY(timer.elapsed() < 1000);
    ::close(pipeFds[0]);
    ::close(pipeFds[1]);
}

void tst_BridgeUnits::peerUid()
{
    FakeProc proc;
    const QString exe = QCoreApplication::applicationFilePath();
    proc.addProcess(100, exe, 50);
    PeerChecker good(exe, fakeEnvironment(proc, 4242, 100));
    QVERIFY(good.check(3).ok());
    PeerChecker otherUid(exe, fakeEnvironment(proc, 1000, 100));
    QCOMPARE(otherUid.check(3).error(), Error::PermissionDenied);
    PeerChecker root(exe, fakeEnvironment(proc, 0, 100));
    QCOMPARE(root.check(3).error(), Error::PermissionDenied);
    PeerChecker::Environment none = fakeEnvironment(proc, 4242, 100);
    none.credentials = [](int, PeerCredentials *) { return false; };
    QCOMPARE(PeerChecker(exe, none).check(3).error(), Error::PermissionDenied);
}

void tst_BridgeUnits::peerExecutable()
{
    FakeProc proc;
    QTemporaryDir dir;
    const QString registered = dir.path() + QStringLiteral("/harbour-app");
    const QString other = dir.path() + QStringLiteral("/other-app");
    writeFile(registered, "a");
    writeFile(other, "b");
    proc.addProcess(100, registered, 50);
    proc.addProcess(101, other, 50);
    QVERIFY(PeerChecker(registered, fakeEnvironment(proc, 4242, 100)).check(3).ok());
    QCOMPARE(PeerChecker(registered, fakeEnvironment(proc, 4242, 101)).check(3).error(), Error::PermissionDenied);
    QCOMPARE(PeerChecker(dir.path() + QStringLiteral("/missing"), fakeEnvironment(proc, 4242, 100)).check(3).error(),
             Error::PermissionDenied);
    // A process that is gone.
    QCOMPARE(PeerChecker(registered, fakeEnvironment(proc, 4242, 555)).check(3).error(), Error::PermissionDenied);
}

void tst_BridgeUnits::peerPidReuse()
{
    FakeProc proc;
    const QString exe = QCoreApplication::applicationFilePath();
    proc.addProcess(100, exe, 50);
    // The pid was reused while exe was read: another start time afterwards.
    PeerChecker::Environment env = fakeEnvironment(proc, 4242, 100);
    env.afterExeRead = [&proc]() { proc.setStartTime(100, 51); };
    QCOMPARE(PeerChecker(exe, env).check(3).error(), Error::PermissionDenied);
    // A process started after the connection was accepted cannot be the peer.
    proc.setStartTime(100, 200000);
    QCOMPARE(PeerChecker(exe, fakeEnvironment(proc, 4242, 100)).check(3).error(), Error::PermissionDenied);
    proc.setStartTime(100, 100000);
    QVERIFY(PeerChecker(exe, fakeEnvironment(proc, 4242, 100)).check(3).ok());
}

void tst_BridgeUnits::peerPidfd()
{
    FakeProc proc;
    const QString exe = QCoreApplication::applicationFilePath();
    proc.addProcess(100, exe, 50);
    // pidfd_open() path: the pidfd must still name pid 100 after the reads.
    PeerChecker::Environment env = fakeEnvironment(proc, 4242, 100);
    int opened = -1;
    env.openPidfd = [&opened](pid_t) {
        opened = ::dup(0);
        return opened;
    };
    env.afterExeRead = [&proc, &opened]() { proc.setPidfd(opened, 100); };
    QVERIFY(PeerChecker(exe, env).check(3).ok());
    env.afterExeRead = [&proc, &opened]() { proc.setPidfd(opened, -1); };   // the process exited
    QCOMPARE(PeerChecker(exe, env).check(3).error(), Error::PermissionDenied);
}

void tst_BridgeUnits::peerRealProcess()
{
    // The real /proc and SO_PEERCRED on a socketpair: this test process.
    std::array<int, 2> sv {};
    QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv.data()), 0);
    QVERIFY(PeerChecker(QCoreApplication::applicationFilePath()).check(sv[0]).ok());
    QCOMPARE(PeerChecker(QStringLiteral("/bin/sh")).check(sv[0]).error(), Error::PermissionDenied);
    ::close(sv[0]);
    ::close(sv[1]);
}

void tst_BridgeUnits::consumers()
{
    QTemporaryDir dir;
    qputenv("NETVFS_CONSUMERS_DIR", QFile::encodeName(dir.path()));
    writeFile(dir.path() + "/lautta.conf",
              "[Consumer]\nId=lautta\nDisplayName=Lautta, the browser\nExecutable=/usr/bin/harbour-lautta\n"
              "DataDir=.local/share/org.netvfs/lautta\n");
    writeFile(dir.path() + "/dotdot.conf",
              "[Consumer]\nId=dotdot\nDisplayName=X\nExecutable=/usr/bin/x\nDataDir=.local/../../etc\n");
    writeFile(dir.path() + "/absolute.conf",
              "[Consumer]\nId=absolute\nDisplayName=X\nExecutable=/usr/bin/x\nDataDir=/etc\n");
    writeFile(dir.path() + "/mismatch.conf",
              "[Consumer]\nId=other\nDisplayName=X\nExecutable=/usr/bin/x\nDataDir=a\n");
    writeFile(dir.path() + "/relexe.conf",
              "[Consumer]\nId=relexe\nDisplayName=X\nExecutable=bin/x\nDataDir=a\n");
    writeFile(dir.path() + "/percent.conf",
              "[Consumer]\nId=percent\nDisplayName=X\nExecutable=/usr/bin/x\nDataDir=a%h\n");
    const QVector<ConsumerInfo> list = ConsentStore::consumers();
    QCOMPARE(list.size(), 1);
    QCOMPARE(list.at(0).id, QStringLiteral("lautta"));
    QCOMPARE(list.at(0).displayName, QStringLiteral("Lautta, the browser"));
    ConsumerInfo info;
    QVERIFY(ConsentStore::loadConsumer(QStringLiteral("lautta"), &info).ok());
    QCOMPARE(info.dataDir, QStringLiteral(".local/share/org.netvfs/lautta"));
    QVERIFY(!ConsentStore::loadConsumer(QStringLiteral("dotdot"), &info).ok());
    QVERIFY(!ConsentStore::loadConsumer(QStringLiteral("../x"), &info).ok());
    QVERIFY(!ConsumerInfo::isValidId(QStringLiteral("Lautta")));
    QVERIFY(!ConsumerInfo::isValidDataDir(QStringLiteral("a//b")));
    QVERIFY(ConsumerInfo::isValidExecutable(QStringLiteral("/usr/bin/harbour-lautta")));
    QVERIFY(!ConsumerInfo::isValidExecutable(QStringLiteral("/usr/../bin/sh")));
    qunsetenv("NETVFS_CONSUMERS_DIR");
}

void tst_BridgeUnits::consent()
{
    QTemporaryDir dir;
    ConsentStore store(dir.path() + QStringLiteral("/sub/bridge.conf"));
    QCOMPARE(store.consent(QStringLiteral("lautta")), Consent::Unknown);
    store.setConsent(QStringLiteral("lautta"), Consent::Granted);
    QCOMPARE(ConsentStore(store.filePath()).consent(QStringLiteral("lautta")), Consent::Granted);
    QCOMPARE(store.consent(QStringLiteral("other")), Consent::Unknown);
    store.setConsent(QStringLiteral("lautta"), Consent::Denied);
    QCOMPARE(store.consent(QStringLiteral("lautta")), Consent::Denied);
    store.setConsent(QStringLiteral("lautta"), Consent::Unknown);
    QCOMPARE(store.consent(QStringLiteral("lautta")), Consent::Unknown);
    QCOMPARE(consentToString(Consent::Granted), QStringLiteral("granted"));
    QCOMPARE(consentFromString(QStringLiteral("yes")), Consent::Unknown);
}

void tst_BridgeUnits::knownHosts()
{
    QTemporaryDir dir;
    const QString path = dir.path() + QStringLiteral("/b/known_hosts");
    {
        KnownHosts hosts(path);
        QVERIFY(hosts.pin(QStringLiteral("sftp://h:0")).isEmpty());
        QVERIFY(hosts.setPin(QStringLiteral("sftp://h:0"), QStringLiteral("ssh-ed25519 AAAA")));
        QVERIFY(!hosts.setPin(QStringLiteral("bad key"), QStringLiteral("x")));
    }
    KnownHosts reread(path);
    QCOMPARE(reread.pin(QStringLiteral("sftp://h:0")), QStringLiteral("ssh-ed25519 AAAA"));
    QCOMPARE(QFileInfo(path).permissions() & (QFileDevice::ReadOther | QFileDevice::ReadGroup), QFileDevice::Permissions());
    QVERIFY(reread.remove(QStringLiteral("sftp://h:0")));
    QVERIFY(KnownHosts(path).pin(QStringLiteral("sftp://h:0")).isEmpty());
}

void tst_BridgeUnits::questions()
{
    QuestionBroker broker;
    QStringList sent;
    broker.setEmitter([&sent](quint64 session, const QString &id, const QString &kind, const QVariantMap &) {
        sent << QStringLiteral("%1:%2:%3").arg(session).arg(id, kind);
        return session != 9;
    });
    int answered = 0;
    bool accepted = false;
    const QString id = broker.ask(1, QStringLiteral("identity-unknown"), QVariantMap(),
                                  [&](bool ok, QuestionAnswer a) { answered += ok ? 1 : 0; accepted = a.accept; });
    QCOMPARE(sent.size(), 1);
    QuestionAnswer yes;
    yes.accept = true;
    QVERIFY(!broker.answer(2, id, yes));   // another session cannot answer
    QVERIFY(broker.answer(1, id, yes));
    QCOMPARE(answered, 1);
    QVERIFY(accepted);
    QVERIFY(!broker.answer(1, id, yes));   // answered once only

    int dropped = 0;
    broker.ask(3, QStringLiteral("keyboard-interactive"), QVariantMap(), [&](bool ok, QuestionAnswer) { dropped += ok ? 0 : 1; });
    broker.dropSession(3);
    QCOMPARE(dropped, 1);
    broker.ask(9, QStringLiteral("x"), QVariantMap(), [&](bool ok, QuestionAnswer) { dropped += ok ? 0 : 1; });
    QCOMPARE(dropped, 2);   // no such session: ends at once
    QCOMPARE(broker.pending(), 0);
}

void tst_BridgeUnits::handoff()
{
    QTemporaryDir dir;
    const QString path = dir.path() + QStringLiteral("/handoff.conf");
    Handoff missing(path);
    QCOMPARE(missing.addAccount(QStringLiteral("sftp")).error(), Error::Unsupported);
    writeFile(path, "[OpenAccountSettings]\nService=com.example.settings\nPath=/ui\nInterface=com.example.ui\n"
                    "Method=showAccount\nArguments=i:{accountId},s:{provider}\n"
                    "[AddAccount]\nService=com.example.settings\nPath=/ui\nInterface=com.example.ui\n"
                    "Method=bad method\n");
    Handoff handoff(path);
    QList<HandoffCall> calls;
    handoff.setLauncher([&calls](const HandoffCall &call) {
        calls << call;
        return Result::success();
    });
    QVERIFY(handoff.openAccountSettings(12, QStringLiteral("sftp")).ok());
    QCOMPARE(calls.size(), 1);
    QCOMPARE(calls.at(0).method, QStringLiteral("showAccount"));
    QCOMPARE(calls.at(0).arguments, QVariantList({ 12, QStringLiteral("sftp") }));
    QCOMPARE(handoff.addAccount(QStringLiteral("sftp")).error(), Error::InvalidName);
    QCOMPARE(calls.size(), 1);

    // The shipped table parses.
    Handoff shipped(QStringLiteral(NETVFS_SOURCE_DIR "/src/bridge/data/handoff.conf"));
    HandoffCall call;
    QVERIFY(shipped.resolve(QStringLiteral("OpenAccountSettings"), 1, QStringLiteral("sftp"), &call).ok());
    QCOMPARE(call.service, QStringLiteral("com.jolla.settings"));
}

QTEST_GUILESS_MAIN(tst_BridgeUnits)
#include "tst_bridgeunits.moc"
