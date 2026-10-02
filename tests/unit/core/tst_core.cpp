// SPDX-License-Identifier: LGPL-2.1-or-later
#include "backendloader.h"
#include "error.h"
#include "fakebackend.h"
#include "identity.h"
#include "names.h"
#include "paths.h"
#include "probe.h"
#include "secure.h"
#include "sshkeys.h"
#include "types.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QScopedPointer>
#include <QtTest/QtTest>

#include <memory>

using namespace NetVfs;
using NetVfs::Test::FakeBackend;
using NetVfs::Test::FakeServer;

namespace {

// Implements only the pure virtual methods, so that the defaults and the
// non-virtual helpers of Backend can be checked (SPEC-v2 §4.10).
class MinimalBackend : public Backend
{
public:
    using Backend::authenticate;
    using Backend::list;

    QStringList calls;
    QSet<QString> dirs;
    QVector<Entry> listing;
    Result listResult;
    Result failMakeDirAt;
    QString failMakeDirPath;

    Result connect(const ConnectionParams &, ServerIdentity *) override { return Result(); }
    Result authenticate(const Credentials &, AuthPrompter *) override { return Result(); }
    Capabilities capabilities() const override { return Capabilities(); }
    Result stat(const QString &path, Entry *out) override
    {
        calls << QStringLiteral("stat:") + path;
        out->name = path;
        out->type = EntryType::Symlink;
        return Result();
    }
    Result list(const QString &dir, ListSink *sink, const ListOptions &options) override
    {
        calls << QStringLiteral("list:%1:%2").arg(dir).arg(options.batchSize);
        for (const Entry &e : listing) {
            if (!sink->entries(QVector<Entry>({ e })))
                return Result(Error::Canceled);
        }
        return listResult;
    }
    Result makeDir(const QString &path, bool exclusive) override
    {
        calls << QStringLiteral("makeDir:%1:%2").arg(path).arg(exclusive);
        if (path == failMakeDirPath)
            return failMakeDirAt;
        return Result();
    }
    Result removeFile(const QString &path) override
    {
        calls << QStringLiteral("removeFile:") + path;
        return dirs.contains(path) ? Result(Error::IsADirectory) : Result();
    }
    Result removeDir(const QString &path) override
    {
        calls << QStringLiteral("removeDir:") + path;
        return Result();
    }
    Result rename(const QString &, const QString &, RenameMode) override { return Result(Error::Unsupported); }
    Result upload(QIODevice *, const QString &, const UploadOptions &, Progress *) override
    {
        return Result(Error::Unsupported);
    }
    Result download(const QString &, QIODevice *, const DownloadOptions &, Progress *) override
    {
        return Result(Error::Unsupported);
    }
    Result keepAlive() override { return Result(); }
    void cancel() override {}
    void resetCancel() override {}
    void disconnect() override {}
};

} // namespace

class TestCore : public QObject
{
    Q_OBJECT

private:
    static ServerIdentity ed25519(char fill)
    {
        ServerIdentity id;
        id.algorithm = QStringLiteral("ssh-ed25519");
        id.publicKey = QByteArray(51, fill);
        id.fingerprint = QStringLiteral("SHA256:abc");
        return id;
    }

private slots:
    void init() { FakeServer::instance()->reset(); }

    void errorNames()
    {
        for (int i = 0; i <= static_cast<int>(Error::NotModified); ++i) {
            const Error e = static_cast<Error>(i);
            QCOMPARE(errorFromName(errorName(e)), e);
        }
        QCOMPARE(errorName(Error::ServerIdentityChanged), QStringLiteral("ServerIdentityChanged"));
        QCOMPARE(errorFromName(QStringLiteral("bogus")), Error::Internal);
        QCOMPARE(Result(Error::NotFound, QStringLiteral("x")).toString(), QStringLiteral("NotFound: x"));
        QCOMPARE(Result(Error::Timeout).toString(), QStringLiteral("Timeout"));
        QVERIFY(Result::success().ok());
        QVERIFY(!Result(Error::Canceled).ok());
    }

    // XC-21: the names of the v2 errors are part of the API (CLI, bridge).
    void errorNamesV2_data()
    {
        QTest::addColumn<int>("error");
        QTest::addColumn<QString>("name");
        QTest::newRow("ConnectionLost") << static_cast<int>(Error::ConnectionLost) << "ConnectionLost";
        QTest::newRow("NotADirectory") << static_cast<int>(Error::NotADirectory) << "NotADirectory";
        QTest::newRow("IsADirectory") << static_cast<int>(Error::IsADirectory) << "IsADirectory";
        QTest::newRow("DirectoryNotEmpty") << static_cast<int>(Error::DirectoryNotEmpty) << "DirectoryNotEmpty";
        QTest::newRow("InvalidName") << static_cast<int>(Error::InvalidName) << "InvalidName";
        QTest::newRow("ReadOnlyFilesystem") << static_cast<int>(Error::ReadOnlyFilesystem) << "ReadOnlyFilesystem";
        QTest::newRow("Locked") << static_cast<int>(Error::Locked) << "Locked";
        QTest::newRow("TooManyConnections") << static_cast<int>(Error::TooManyConnections) << "TooManyConnections";
        QTest::newRow("RateLimited") << static_cast<int>(Error::RateLimited) << "RateLimited";
        QTest::newRow("NotModified") << static_cast<int>(Error::NotModified) << "NotModified";
        QTest::newRow("Internal") << static_cast<int>(Error::Internal) << "Internal";
        QTest::newRow("None") << static_cast<int>(Error::None) << "None";
    }

    void errorNamesV2()
    {
        QFETCH(int, error);
        QFETCH(QString, name);
        QCOMPARE(errorName(static_cast<Error>(error)), name);
        QCOMPARE(static_cast<int>(errorFromName(name)), error);
    }

    // XC-24
    void resultDetailAndRetryAfter()
    {
        const Result plain(Error::NotFound, QStringLiteral("gone"));
        QVERIFY(plain.detail().isEmpty());
        QCOMPARE(plain.retryAfterMs(), qint64(-1));
        QCOMPARE(Result().retryAfterMs(), qint64(-1));

        const Result limited(Error::RateLimited, QStringLiteral("slow down"), QStringLiteral("HTTP 429"), 1500);
        QCOMPARE(limited.error(), Error::RateLimited);
        QCOMPARE(limited.message(), QStringLiteral("slow down"));
        QCOMPARE(limited.detail(), QStringLiteral("HTTP 429"));
        QCOMPARE(limited.retryAfterMs(), qint64(1500));
        QCOMPARE(limited.toString(), QStringLiteral("RateLimited: slow down"));   // detail stays out

        Result chained(Error::ProtocolError);
        chained.setDetail(QStringLiteral("status 4")).setRetryAfterMs(20);
        QCOMPARE(chained.detail(), QStringLiteral("status 4"));
        QCOMPARE(chained.retryAfterMs(), qint64(20));
        const Result defaulted(Error::Locked, QStringLiteral("m"), QStringLiteral("d"));
        QCOMPARE(defaulted.retryAfterMs(), qint64(-1));
    }

    // XC-2, XC-3
    void entryTypes()
    {
        Entry e;
        QCOMPARE(e.size, qint64(-1));
        QCOMPARE(e.mode, -1);
        QCOMPARE(e.uid, qint64(-1));
        QCOMPARE(e.gid, qint64(-1));
        QVERIFY(!e.modified.isValid());
        QVERIFY(!e.isDir() && !e.isFile());
        e.type = EntryType::File;
        QVERIFY(e.isFile() && !e.isDir());
        e.type = EntryType::Directory;
        QVERIFY(e.isDir() && !e.isFile());
        e.type = EntryType::Special;
        QVERIFY(!e.isDir() && !e.isFile());
        e.type = EntryType::Symlink;
        QVERIFY(!e.isDir() && !e.isFile());
        e.targetType = EntryType::Directory;
        QVERIFY(e.isDir() && !e.isFile());
        e.targetType = EntryType::File;
        QVERIFY(e.isFile() && !e.isDir());
        e.targetType = EntryType::Symlink;
        QVERIFY(!e.isDir() && !e.isFile());
        e.type = EntryType::File;
        e.targetType = EntryType::Directory;   // ignored for non-links
        QVERIFY(e.isFile() && !e.isDir());
    }

    // XC-5
    void capabilityNames()
    {
        const QVector<Capability> all = allCapabilities();
        QCOMPARE(all.size(), static_cast<int>(Capability::ETags) + 1);
        QSet<QString> seen;
        for (const Capability c : all) {
            const QString name = capabilityName(c);
            QVERIFY(!name.isEmpty());
            QVERIFY(!seen.contains(name));
            seen.insert(name);
            Capability back = c == Capability::ETags ? Capability::Symlinks : Capability::ETags;
            QVERIFY(capabilityFromName(name, &back));
            QCOMPARE(back, c);
        }
        QCOMPARE(capabilityName(Capability::AtomicPut), QStringLiteral("AtomicPut"));
        QCOMPARE(capabilityName(Capability::NativeNoReplace), QStringLiteral("NativeNoReplace"));
        Capability untouched = Capability::Symlinks;
        QVERIFY(!capabilityFromName(QStringLiteral("atomicput"), &untouched));
        QVERIFY(!capabilityFromName(QString(), nullptr));
        QCOMPARE(untouched, Capability::Symlinks);
        QVERIFY(capabilityFromName(QStringLiteral("ETags"), nullptr));

        Capabilities caps;
        QVERIFY(!caps.has(Capability::SpaceInfo));
        QVERIFY(caps.names().isEmpty());
        caps.flags << Capability::SpaceInfo << Capability::AtomicReplace << Capability::Checksums;
        QVERIFY(caps.has(Capability::SpaceInfo));
        QCOMPARE(caps.names(), QStringList({ QStringLiteral("AtomicReplace"), QStringLiteral("Checksums"),
                                             QStringLiteral("SpaceInfo") }));
        QCOMPARE(caps.maxNameBytes, qint64(-1));
    }

    void normalize_data()
    {
        QTest::addColumn<QString>("input");
        QTest::addColumn<bool>("ok");
        QTest::addColumn<QString>("expected");
        QTest::newRow("empty") << QString() << true << QString();
        QTest::newRow("relative") << "Sailfish OS/Backups" << true << "Sailfish OS/Backups";
        QTest::newRow("slashes") << "a//b///c/" << true << "a/b/c";
        QTest::newRow("absolute") << "/srv/backup/" << true << "/srv/backup";
        QTest::newRow("root") << "/" << true << "/";
        QTest::newRow("dot") << "a/./b" << false << QString();
        QTest::newRow("dotdot") << "../etc" << false << QString();
        QTest::newRow("trailing dotdot") << "a/.." << false << QString();
        QTest::newRow("dots in name") << "a/..b/c." << true << "a/..b/c.";
        QTest::newRow("nul") << QString(QStringLiteral("a") + QChar(0) + QStringLiteral("b")) << false << QString();
    }

    void normalize()
    {
        QFETCH(QString, input);
        QFETCH(bool, ok);
        QFETCH(QString, expected);
        QString out = QStringLiteral("unchanged");
        const Result r = Paths::normalize(input, &out);
        QCOMPARE(r.ok(), ok);
        if (ok)
            QCOMPARE(out, expected);
        else
            QCOMPARE(out, QStringLiteral("unchanged"));
    }

    void pathHelpers()
    {
        QVERIFY(Paths::isAbsolute(QStringLiteral("/a")));
        QVERIFY(!Paths::isAbsolute(QStringLiteral("a")));
        QCOMPARE(Paths::components(QStringLiteral("/a/b")), QStringList({ QStringLiteral("a"), QStringLiteral("b") }));
        QCOMPARE(Paths::join(QString(), QStringLiteral("f")), QStringLiteral("f"));
        QCOMPARE(Paths::join(QStringLiteral("/"), QStringLiteral("f")), QStringLiteral("/f"));
        QCOMPARE(Paths::join(QStringLiteral("d"), QStringLiteral("f")), QStringLiteral("d/f"));
        QCOMPARE(Paths::parent(QStringLiteral("d/e/f")), QStringLiteral("d/e"));
        QCOMPARE(Paths::parent(QStringLiteral("/f")), QStringLiteral("/"));
        QCOMPARE(Paths::parent(QStringLiteral("f")), QString());
        QCOMPARE(Paths::fileName(QStringLiteral("d/e/f.tar")), QStringLiteral("f.tar"));
        QCOMPARE(Paths::fileName(QStringLiteral("f")), QStringLiteral("f"));
    }

    void windowsComponents_data()
    {
        QTest::addColumn<QString>("path");
        QTest::addColumn<bool>("ok");
        QTest::newRow("plain") << "Sailfish OS/Backups" << true;
        QTest::newRow("unicode") << QString::fromUtf8("Sicherung/Gerät") << true;
        for (const char c : QByteArray("\\:*?\"<>|"))
            QTest::newRow(QByteArray("char ") .append(c).constData()) << QString(QStringLiteral("a") + QLatin1Char(c)) << false;
        QTest::newRow("trailing space") << "dir /x" << false;
        QTest::newRow("trailing dot") << "dir./x" << false;
        QTest::newRow("control") << QString(QStringLiteral("a") + QChar(1)) << false;
    }

    void windowsComponents()
    {
        QFETCH(QString, path);
        QFETCH(bool, ok);
        QCOMPARE(Paths::checkWindowsPath(path).ok(), ok);
    }

    void pins()
    {
        const ServerIdentity id = ed25519('k');
        const QString pin = id.toPin();
        QVERIFY(pin.startsWith(QStringLiteral("ssh-ed25519 ")));
        QCOMPARE(ServerIdentity::fromPin(pin), id);
        QVERIFY(ServerIdentity::fromPin(QStringLiteral("ssh-ed25519")).isEmpty());
        QVERIFY(ServerIdentity::fromPin(QStringLiteral("ssh-ed25519 !!!notbase64")).isEmpty());
        QVERIFY(ServerIdentity::fromPin(QStringLiteral("a b c")).isEmpty());
        QVERIFY(ServerIdentity().toPin().isEmpty());
        QVERIFY(ed25519('a') != ed25519('b'));
    }

    // XC-16: SSH pins keep their format; TLS pins carry the SPKI.
    void pinsV2()
    {
        const ServerIdentity ssh = ServerIdentity::fromPin(ed25519('k').toPin());
        QCOMPARE(ssh.kind, ServerIdentity::Kind::SshHostKey);
        QCOMPARE(ssh.toPin(), QStringLiteral("ssh-ed25519 ") + QString::fromLatin1(QByteArray(51, 'k').toBase64()));

        const QByteArray spki = QByteArrayLiteral("\x30\x59\x30\x13 not really DER");
        const ServerIdentity tls = ServerIdentity::fromTlsSpki(spki);
        QCOMPARE(tls.kind, ServerIdentity::Kind::TlsCertificate);
        QCOMPARE(tls.algorithm, QStringLiteral("tls-spki-sha256"));
        QCOMPARE(tls.publicKey, spki);
        QCOMPARE(tls.fingerprint,
                 QString::fromLatin1(QCryptographicHash::hash(spki, QCryptographicHash::Sha256).toBase64()));
        QVERIFY(!tls.systemTrusted);
        QCOMPARE(tls.toPin(), QStringLiteral("tls-spki-sha256 ") + QString::fromLatin1(spki.toBase64()));

        const ServerIdentity back = ServerIdentity::fromPin(tls.toPin());
        QCOMPARE(back.kind, ServerIdentity::Kind::TlsCertificate);
        QCOMPARE(back, tls);
        QCOMPARE(back.fingerprint, tls.fingerprint);
        QVERIFY(ServerIdentity::fromTlsSpki(QByteArray()).isEmpty());
        QCOMPARE(ServerIdentity::fromTlsSpki(QByteArray()).kind, ServerIdentity::Kind::None);

        // The same key bytes under another algorithm are another identity.
        ServerIdentity sshWithSameBytes;
        sshWithSameBytes.algorithm = QStringLiteral("ssh-ed25519");
        sshWithSameBytes.publicKey = spki;
        QVERIFY(sshWithSameBytes != tls);
    }

    // XC-16 amends S-7 for TLS.
    void identityPolicyTls()
    {
        ServerIdentity seen = ServerIdentity::fromTlsSpki(QByteArrayLiteral("spki-one"));
        const ServerIdentity other = ServerIdentity::fromTlsSpki(QByteArrayLiteral("spki-two"));

        seen.systemTrusted = true;
        QVERIFY(checkServerIdentity(seen, QString()).ok());                 // no prompt
        QVERIFY(checkServerIdentity(seen, seen.toPin()).ok());
        QCOMPARE(checkServerIdentity(seen, other.toPin()).error(), Error::ServerIdentityChanged);
        QCOMPARE(checkServerIdentity(seen, ed25519('k').toPin()).error(), Error::ServerIdentityChanged);

        seen.systemTrusted = false;
        const Result unknown = checkServerIdentity(seen, QString());
        QCOMPARE(unknown.error(), Error::ServerIdentityUnknown);
        QVERIFY(unknown.message().contains(seen.fingerprint));
        QVERIFY(checkServerIdentity(seen, seen.toPin()).ok());              // the pin decides
        const Result changed = checkServerIdentity(seen, other.toPin());
        QCOMPARE(changed.error(), Error::ServerIdentityChanged);
        QVERIFY(changed.message().contains(seen.fingerprint));

        // SSH is never accepted without a pin, whatever systemTrusted says.
        ServerIdentity ssh = ed25519('k');
        ssh.kind = ServerIdentity::Kind::SshHostKey;
        ssh.systemTrusted = true;
        QCOMPARE(checkServerIdentity(ssh, QString()).error(), Error::ServerIdentityUnknown);
    }

    void identityPolicy()
    {
        const ServerIdentity seen = ed25519('k');
        QVERIFY(checkServerIdentity(ServerIdentity(), QString()).ok());
        QCOMPARE(checkServerIdentity(ServerIdentity(), seen.toPin()).error(), Error::ServerIdentityChanged);
        QCOMPARE(checkServerIdentity(seen, QString()).error(), Error::ServerIdentityUnknown);
        QVERIFY(checkServerIdentity(seen, seen.toPin()).ok());
        QCOMPARE(checkServerIdentity(seen, ed25519('x').toPin()).error(), Error::ServerIdentityChanged);
        ServerIdentity otherAlgorithm = seen;
        otherAlgorithm.algorithm = QStringLiteral("ssh-rsa");
        QCOMPARE(checkServerIdentity(seen, otherAlgorithm.toPin()).error(), Error::ServerIdentityChanged);
    }

    // SEC-1 / C-7: no authentication request before the identity matches.
    void establishChecksIdentityBeforeAuth()
    {
        FakeServer *server = FakeServer::instance();
        server->identity = ed25519('k');
        FakeBackend backend;
        ConnectionParams params;
        params.options.insert(QStringLiteral("host_key"), ed25519('z').toPin());
        ServerIdentity seen;
        const Result r = establish(&backend, params, Credentials(QStringLiteral("user"), "secret"), &seen);
        QCOMPARE(r.error(), Error::ServerIdentityChanged);
        QCOMPARE(seen, server->identity);
        QVERIFY(!server->log.contains(QStringLiteral("authenticate")));
        QCOMPARE(server->log.last(), QStringLiteral("disconnect"));

        server->log.clear();
        QCOMPARE(establish(&backend, ConnectionParams(), Credentials(QStringLiteral("user"), "secret")).error(),
                 Error::ServerIdentityUnknown);
        QVERIFY(!server->log.contains(QStringLiteral("authenticate")));
    }

    void establishSuccessAndFailures()
    {
        FakeServer *server = FakeServer::instance();
        server->identity = ed25519('k');
        ConnectionParams params;
        params.options.insert(QStringLiteral("host_key"), server->identity.toPin());
        FakeBackend backend;
        QVERIFY(establish(&backend, params, Credentials(QStringLiteral("user"), "secret")).ok());
        QCOMPARE(server->log, QStringList({ QStringLiteral("connect"), QStringLiteral("authenticate") }));

        FakeBackend wrong;
        QCOMPARE(establish(&wrong, params, Credentials(QStringLiteral("user"), "nope")).error(), Error::AuthFailed);
        QCOMPARE(server->log.last(), QStringLiteral("disconnect"));

        server->connectResult = Result(Error::NetworkUnreachable);
        FakeBackend unreachable;
        QCOMPARE(establish(&unreachable, params, Credentials()).error(), Error::NetworkUnreachable);
    }

    void credentialsWipe()
    {
        QByteArray secret("hunter2");
        Credentials c(QStringLiteral("u"), secret);
        secureWipe(secret);
        QVERIFY(secret.isEmpty());
        QCOMPARE(c.secret, QByteArray("hunter2"));   // deep copy
        Credentials copy(c);
        Credentials assigned;
        assigned = c;
        assigned = assigned;
        c.wipe();
        QVERIFY(c.secret.isEmpty());
        QCOMPARE(copy.secret, QByteArray("hunter2"));
        QCOMPARE(assigned.secret, QByteArray("hunter2"));
        QString text = QStringLiteral("pw");
        secureWipe(text);
        QVERIFY(text.isEmpty());
        QByteArray empty;
        secureWipe(empty);
        QVERIFY(empty.isEmpty());
    }

    void verifyAccessWritesAndRemovesProbe()
    {
        FakeServer *server = FakeServer::instance();
        FakeBackend backend;
        ConnectionParams params;
        QVERIFY(establish(&backend, params, Credentials(QStringLiteral("user"), "secret")).ok());
        qint64 freeBytes = 0;
        QVERIFY(verifyAccess(&backend, QStringLiteral("Sailfish OS/Backups"), &freeBytes).ok());
        QCOMPARE(freeBytes, server->freeBytes);
        QVERIFY(server->exists(QStringLiteral("Sailfish OS/Backups")));
        QCOMPARE(server->nodes.size(), 2);   // two directories, no probe left
        bool sawProbe = false;
        for (const QString &entry : server->log)
            sawProbe |= entry.startsWith(QStringLiteral("upload:Sailfish OS/Backups/.netvfs-probe-"));
        QVERIFY(sawProbe);

        server->freeBytes = -1;
        QVERIFY(verifyAccess(&backend, QStringLiteral("x"), &freeBytes).ok());
        QCOMPARE(freeBytes, qint64(-1));

        server->failOps.insert(QStringLiteral("upload"), Result(Error::PermissionDenied));
        QCOMPARE(verifyAccess(&backend, QStringLiteral("x")).error(), Error::PermissionDenied);
        server->failOps.insert(QStringLiteral("makeDir"), Result(Error::PermissionDenied));
        QCOMPARE(verifyAccess(&backend, QStringLiteral("y")).error(), Error::PermissionDenied);
        QCOMPARE(verifyAccess(&backend, QStringLiteral("../y")).ok(), false);
        server->failOps.insert(QStringLiteral("removeFile"), Result(Error::PermissionDenied));
        QCOMPARE(verifyAccess(&backend, QStringLiteral("x")).error(), Error::PermissionDenied);
        server->freeBytes = 10;
        server->failOps.insert(QStringLiteral("spaceInfo"), Result(Error::Timeout));
        QCOMPARE(verifyAccess(&backend, QStringLiteral("x")).error(), Error::Timeout);
    }

    void loader()
    {
        qputenv("NETVFS_BACKEND_PATH", QByteArray("/nonexistent:") + NETVFS_TEST_FAKE_BACKEND_DIR);
        QVERIFY(BackendLoader::searchPaths().contains(QStringLiteral(NETVFS_TEST_FAKE_BACKEND_DIR)));
        QVERIFY(BackendLoader::isAvailable(QStringLiteral("fake")));
        QVERIFY(!BackendLoader::isAvailable(QStringLiteral("nosuch")));
        QVERIFY(!BackendLoader::isAvailable(QStringLiteral("../evil")));
        Result r;
        QScopedPointer<Backend> backend(BackendLoader::create(QStringLiteral("fake"), &r));
        QVERIFY(r.ok());
        QVERIFY(backend);
        QVERIFY(!BackendLoader::create(QStringLiteral("nosuch"), &r));
        QCOMPARE(r.error(), Error::Unsupported);
        QVERIFY(!BackendLoader::create(QStringLiteral("nosuch")));
    }

    void keySecrets()
    {
        const QByteArray key("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n");
        const QByteArray secret = encodeKeySecret(key);
        QVERIFY(secret.startsWith("netvfs-key-v1:"));
        QVERIFY(!secret.contains('\n'));   // A-4: single line
        QVERIFY(isKeySecret(secret));
        QVERIFY(!isKeySecret("hunter2"));
        QByteArray decoded;
        QVERIFY(decodeKeySecret(secret, &decoded));
        QCOMPARE(decoded, key);
        QVERIFY(decodeKeySecret(secret, nullptr));
        QVERIFY(!decodeKeySecret("hunter2", &decoded));
        QVERIFY(!decodeKeySecret("netvfs-key-v1:", &decoded));
        QVERIFY(!decodeKeySecret("netvfs-key-v1:%%%", &decoded));
        SshKeyMaterial material;
        material.privateKey = key;
        SshKeyMaterial copy = material;
        material.wipe();
        QVERIFY(material.privateKey.isEmpty());
        QCOMPARE(copy.privateKey, key);
    }

    void installAuthorizedKey()
    {
        FakeServer *server = FakeServer::instance();
        FakeBackend backend;
        QVERIFY(establish(&backend, ConnectionParams(), Credentials(QStringLiteral("user"), "secret")).ok());
        const QString line = QStringLiteral("ssh-ed25519 AAAAC3Nza sailfish-backup");

        QVERIFY(NetVfs::installAuthorizedKey(&backend, line).ok());
        QVERIFY(server->nodes.value(QStringLiteral(".ssh")).isDir());
        QCOMPARE(server->node(QStringLiteral(".ssh/authorized_keys")).mode, 0600);
        QCOMPARE(server->fileData(QStringLiteral(".ssh/authorized_keys")), QByteArray("ssh-ed25519 AAAAC3Nza sailfish-backup\n"));
        QVERIFY(server->log.contains(QStringLiteral("rename:.ssh/authorized_keys.part->.ssh/authorized_keys:replace")));

        // Already present (other comment, with options): unchanged.
        server->addFile(QStringLiteral(".ssh/authorized_keys"), "no-pty ssh-ed25519 AAAAC3Nza old comment");
        QVERIFY(NetVfs::installAuthorizedKey(&backend, line).ok());
        QCOMPARE(server->fileData(QStringLiteral(".ssh/authorized_keys")), QByteArray("no-pty ssh-ed25519 AAAAC3Nza old comment"));

        // Appended after existing keys; missing final newline repaired.
        server->addFile(QStringLiteral(".ssh/authorized_keys"), "ssh-rsa AAAAB3 other");
        QVERIFY(NetVfs::installAuthorizedKey(&backend, line).ok());
        QCOMPARE(server->fileData(QStringLiteral(".ssh/authorized_keys")),
                 QByteArray("ssh-rsa AAAAB3 other\nssh-ed25519 AAAAC3Nza sailfish-backup\n"));

        QCOMPARE(NetVfs::installAuthorizedKey(&backend, QStringLiteral("garbage")).error(), Error::Internal);
        QCOMPARE(NetVfs::installAuthorizedKey(&backend, line + QStringLiteral("\nssh-rsa X")).error(), Error::Internal);
        server->failOps.insert(QStringLiteral("makeDir"), Result(Error::PermissionDenied));
        QCOMPARE(NetVfs::installAuthorizedKey(&backend, line).error(), Error::PermissionDenied);
        server->failOps.insert(QStringLiteral("stat"), Result(Error::Timeout));
        QCOMPARE(NetVfs::installAuthorizedKey(&backend, line).error(), Error::Timeout);
        server->failOps.insert(QStringLiteral("download"), Result(Error::PermissionDenied));
        QCOMPARE(NetVfs::installAuthorizedKey(&backend, line).error(), Error::PermissionDenied);
    }

    void loaderHasNoKeyToolsWithoutSftp()
    {
        qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
        if (BackendLoader::isAvailable(QStringLiteral("sftp")))
            QSKIP("an SFTP backend is installed system-wide");
        QVERIFY(!BackendLoader::sshKeyTools());
    }

    void loaderRejectsWrongProviderAndNonPlugins()
    {
        QTemporaryDir dir;
        // A file with the right name that is not a plugin.
        QFile bogus(dir.filePath(QStringLiteral("libnetvfs-bogus.so")));
        QVERIFY(bogus.open(QIODevice::WriteOnly));
        bogus.write("not an ELF file");
        bogus.close();
        // The fake plugin under another provider's name.
        QVERIFY(QFile::copy(QStringLiteral(NETVFS_TEST_FAKE_BACKEND_DIR "/libnetvfs-fake.so"),
                            dir.filePath(QStringLiteral("libnetvfs-other.so"))));
        qputenv("NETVFS_BACKEND_PATH", dir.path().toLocal8Bit());
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("Not a netvfs backend")));
        QVERIFY(!BackendLoader::isAvailable(QStringLiteral("bogus")));
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("reports provider")));
        QVERIFY(!BackendLoader::isAvailable(QStringLiteral("other")));
        // XC-1: a plugin declaring another interface version is not loaded.
        QVERIFY(QFile::copy(QStringLiteral(NETVFS_TEST_FAKE_BACKEND_DIR "/libnetvfs-oldiid.so"),
                            dir.filePath(QStringLiteral("libnetvfs-oldiid.so"))));
        QTest::ignoreMessage(QtWarningMsg,
                             QRegularExpression(QStringLiteral("BackendFactory/1.0.*BackendFactory/2.0 is expected")));
        QVERIFY(!BackendLoader::isAvailable(QStringLiteral("oldiid")));
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("BackendFactory/2.0 is expected")));
        QVERIFY(!BackendLoader::create(QStringLiteral("oldiid")));
        qunsetenv("NETVFS_BACKEND_PATH");
        QCOMPARE(BackendLoader::searchPaths().size(), 1);
    }

    // §4.10: methods with a default implementation are Unsupported.
    void backendDefaults()
    {
        MinimalBackend b;
        Entry e;
        QVERIFY(b.lstat(QStringLiteral("x"), &e).ok());   // lstat defaults to stat
        QCOMPARE(b.calls, QStringList({ QStringLiteral("stat:x") }));
        QCOMPARE(e.type, EntryType::Symlink);
        QCOMPARE(b.removeTreeNative(QStringLiteral("x")).error(), Error::Unsupported);
        AttributeChanges changes;
        changes.mode = 0644;
        QCOMPARE(b.setAttributes(QStringLiteral("x"), changes).error(), Error::Unsupported);
        QString target;
        QCOMPARE(b.readLink(QStringLiteral("x"), &target).error(), Error::Unsupported);
        QCOMPARE(b.makeSymlink(QStringLiteral("t"), QStringLiteral("x")).error(), Error::Unsupported);
        QCOMPARE(b.makeHardlink(QStringLiteral("t"), QStringLiteral("x")).error(), Error::Unsupported);
        ReadHandle *reader = reinterpret_cast<ReadHandle *>(&b);
        QCOMPARE(b.openRead(QStringLiteral("x"), &reader).error(), Error::Unsupported);
        QVERIFY(!reader);
        WriteHandle *writer = reinterpret_cast<WriteHandle *>(&b);
        QCOMPARE(b.openWrite(QStringLiteral("x"), WriteOptions(), &writer).error(), Error::Unsupported);
        QVERIFY(!writer);
        QCOMPARE(b.copy(QStringLiteral("a"), QStringLiteral("b"), CopyOptions()).error(), Error::Unsupported);
        QByteArray digest;
        QCOMPARE(b.checksum(QStringLiteral("a"), QStringLiteral("sha256"), &digest).error(), Error::Unsupported);
        SpaceInfo space;
        QCOMPARE(b.spaceInfo(QStringLiteral("a"), &space).error(), Error::Unsupported);
        qint64 bytes = 7;
        QCOMPARE(b.freeSpace(QStringLiteral("a"), &bytes).error(), Error::Unsupported);
        QCOMPARE(bytes, qint64(7));
        QByteArray data("old");
        QCOMPARE(b.read(QStringLiteral("a"), 0, 1, &data).error(), Error::Unsupported);
        QVERIFY(b.authenticate(Credentials()).ok());
    }

    void backendListHelper()
    {
        MinimalBackend b;
        for (const char *name : { "a", "b", "c" }) {
            Entry e;
            e.name = QLatin1String(name);
            b.listing << e;
        }
        QVector<Entry> out;
        QVERIFY(b.list(QStringLiteral("d"), &out).ok());
        QCOMPARE(out.size(), 3);
        QCOMPARE(out.at(2).name, QStringLiteral("c"));
        QCOMPARE(b.calls, QStringList({ QStringLiteral("list:d:256") }));

        b.listResult = Result(Error::Timeout);
        out = QVector<Entry>({ Entry() });
        QCOMPARE(b.list(QStringLiteral("d"), &out).error(), Error::Timeout);
        QVERIFY(out.isEmpty());   // no partial listing
        QCOMPARE(b.list(QStringLiteral("d"), nullptr).error(), Error::Timeout);
    }

    void backendRemoveHelper()
    {
        MinimalBackend b;
        b.dirs << QStringLiteral("dir");
        QVERIFY(b.remove(QStringLiteral("file")).ok());
        QCOMPARE(b.calls, QStringList({ QStringLiteral("removeFile:file") }));
        b.calls.clear();
        QVERIFY(b.remove(QStringLiteral("dir")).ok());
        QCOMPARE(b.calls, QStringList({ QStringLiteral("removeFile:dir"), QStringLiteral("removeDir:dir") }));

        FakeServer *server = FakeServer::instance();
        FakeBackend fake;
        QVERIFY(establish(&fake, ConnectionParams(), Credentials(QStringLiteral("user"), "secret")).ok());
        server->addDir(QStringLiteral("full/sub"));
        QCOMPARE(fake.remove(QStringLiteral("full")).error(), Error::DirectoryNotEmpty);
        QVERIFY(fake.remove(QStringLiteral("full/sub")).ok());
        QVERIFY(fake.remove(QStringLiteral("full")).ok());
        QCOMPARE(fake.remove(QStringLiteral("full")).error(), Error::NotFound);
    }

    void backendMakePathHelper()
    {
        MinimalBackend b;
        QVERIFY(b.makePath(QStringLiteral("a//b/c/")).ok());
        QCOMPARE(b.calls, QStringList({ QStringLiteral("makeDir:a:0"), QStringLiteral("makeDir:a/b:0"),
                                        QStringLiteral("makeDir:a/b/c:0") }));
        b.calls.clear();
        QVERIFY(b.makePath(QStringLiteral("/x/y")).ok());
        QCOMPARE(b.calls, QStringList({ QStringLiteral("makeDir:/x:0"), QStringLiteral("makeDir:/x/y:0") }));
        b.calls.clear();
        QVERIFY(b.makePath(QString()).ok());
        QVERIFY(b.makePath(QStringLiteral("/")).ok());
        QVERIFY(b.calls.isEmpty());
        QVERIFY(!b.makePath(QStringLiteral("a/../b")).ok());
        QVERIFY(b.calls.isEmpty());

        b.failMakeDirPath = QStringLiteral("a/b");
        b.failMakeDirAt = Result(Error::AlreadyExists);
        QCOMPARE(b.makePath(QStringLiteral("a/b/c")).error(), Error::AlreadyExists);
        QCOMPARE(b.calls, QStringList({ QStringLiteral("makeDir:a:0"), QStringLiteral("makeDir:a/b:0") }));
    }

    void backendReadAndSpaceHelpers()
    {
        FakeServer *server = FakeServer::instance();
        FakeBackend b;
        QVERIFY(establish(&b, ConnectionParams(), Credentials(QStringLiteral("user"), "secret")).ok());
        QByteArray big(2 * 1024 * 1024 + 123, Qt::Uninitialized);
        for (int i = 0; i < big.size(); ++i)
            big[i] = static_cast<char>(i * 7);
        server->addFile(QStringLiteral("f"), big);

        QByteArray out;
        QVERIFY(b.read(QStringLiteral("f"), 5, 10, &out).ok());
        QCOMPARE(out, big.mid(5, 10));
        QVERIFY(b.read(QStringLiteral("f"), 100, -1, &out).ok());   // to EOF, several handle reads
        QCOMPARE(out, big.mid(100));
        QVERIFY(server->log.filter(QStringLiteral("read:f")).size() > 2);
        QVERIFY(server->log.contains(QStringLiteral("close:f")));
        QVERIFY(b.read(QStringLiteral("f"), big.size() - 3, 10, &out).ok());   // short read at EOF
        QCOMPARE(out, big.right(3));
        QVERIFY(b.read(QStringLiteral("f"), big.size() + 10, 10, &out).ok());
        QVERIFY(out.isEmpty());
        QCOMPARE(b.read(QStringLiteral("f"), -1, 10, &out).error(), Error::Internal);
        QCOMPARE(b.read(QStringLiteral("f"), 0, -2, &out).error(), Error::Internal);
        out = "stale";
        QCOMPARE(b.read(QStringLiteral("missing"), 0, 10, &out).error(), Error::NotFound);
        server->failOps.insert(QStringLiteral("read"), Result(Error::Timeout));
        QCOMPARE(b.read(QStringLiteral("f"), 0, 10, &out).error(), Error::Timeout);
        QVERIFY(out.isEmpty());
        server->failOps.insert(QStringLiteral("close"), Result(Error::Timeout));
        server->capabilities.flags.remove(Capability::ReadHandles);
        QCOMPARE(b.read(QStringLiteral("f"), 0, 10, &out).error(), Error::Unsupported);

        qint64 bytes = 0;
        server->freeBytes = 123;
        QVERIFY(b.freeSpace(QString(), &bytes).ok());
        QCOMPARE(bytes, qint64(123));
        server->freeBytes = -1;
        QCOMPARE(b.freeSpace(QString(), &bytes).error(), Error::Unsupported);
        server->freeBytes = 5;
        server->failOps.insert(QStringLiteral("spaceInfo"), Result(Error::Timeout));
        QCOMPARE(b.freeSpace(QString(), &bytes).error(), Error::Timeout);
        server->capabilities.flags.remove(Capability::SpaceInfo);
        QCOMPARE(b.freeSpace(QString(), &bytes).error(), Error::Unsupported);
        QCOMPARE(bytes, qint64(123));
    }

    // XC-4: lossless names.
    void namesValidUtf8_data()
    {
        QTest::addColumn<QByteArray>("bytes");
        QTest::addColumn<QString>("text");
        QTest::newRow("empty") << QByteArray() << QString();
        QTest::newRow("ascii") << QByteArray("Backups 2026.tar") << QStringLiteral("Backups 2026.tar");
        QTest::newRow("2-byte") << QByteArray("caf\xc3\xa9") << QString::fromUtf8("caf\xc3\xa9");
        QTest::newRow("3-byte") << QByteArray("\xe2\x82\xac") << QString(QChar(0x20AC));
        QTest::newRow("4-byte") << QByteArray("\xf0\x9f\x98\x80!")
                                << QString::fromUcs4(std::array<uint, 2>({ 0x1F600, '!' }).data(), 2);
        QTest::newRow("max") << QByteArray("\xf4\x8f\xbf\xbf") << QString::fromUcs4(std::array<uint, 1>({ 0x10FFFF }).data(), 1);
        QTest::newRow("nfd") << QByteArray("e\xcc\x81") << QString::fromUtf8("e\xcc\x81");
        QTest::newRow("replacement char") << QByteArray("\xef\xbf\xbd") << QString(QChar(0xFFFD));
    }

    void namesValidUtf8()
    {
        QFETCH(QByteArray, bytes);
        QFETCH(QString, text);
        QCOMPARE(Names::decode(bytes), text);
        QCOMPARE(Names::encode(text), bytes);
        QVERIFY(!Names::hasEscapes(text));
        QVERIFY(Names::isEncodable(text));
        QCOMPARE(Names::display(text), text);
    }

    void namesInvalidUtf8_data()
    {
        QTest::addColumn<QByteArray>("bytes");
        QTest::addColumn<QString>("expected");   // '~' stands for "escape of the byte at this position"
        QTest::newRow("latin1") << QByteArray("caf\xe9") << QStringLiteral("caf~");
        QTest::newRow("overlong 2") << QByteArray("\xc0\xaf") << QStringLiteral("~~");
        QTest::newRow("overlong 3") << QByteArray("\xe0\x80\xaf") << QStringLiteral("~~~");
        QTest::newRow("overlong 4") << QByteArray("\xf0\x80\x80\xaf") << QStringLiteral("~~~~");
        QTest::newRow("surrogate in utf-8") << QByteArray("\xed\xa0\x80") << QStringLiteral("~~~");
        QTest::newRow("low surrogate in utf-8") << QByteArray("a\xed\xbf\xbf") << QStringLiteral("a~~~");
        QTest::newRow("above max") << QByteArray("\xf4\x90\x80\x80") << QStringLiteral("~~~~");
        QTest::newRow("f5") << QByteArray("\xf5\x80\x80\x80") << QStringLiteral("~~~~");
        QTest::newRow("ff") << QByteArray("\xff") << QStringLiteral("~");
        QTest::newRow("truncated 2") << QByteArray("x\xc3") << QStringLiteral("x~");
        QTest::newRow("truncated 3") << QByteArray("\xe2\x82") << QStringLiteral("~~");
        QTest::newRow("truncated 3 inside") << QByteArray("a\xe2\x82z") << QStringLiteral("a~~z");
        QTest::newRow("truncated 4") << QByteArray("\xf0\x9f\x98") << QStringLiteral("~~~");
        QTest::newRow("lone continuation") << QByteArray("\x80") << QStringLiteral("~");
        QTest::newRow("continuations") << QByteArray("a\xbf\x80" "b") << QStringLiteral("a~~b");
        QTest::newRow("valid after invalid") << QByteArray("\xff\xc3\xa9") << QString(QStringLiteral("~") + QChar(0xE9));
        QTest::newRow("bad second byte") << QByteArray("\xc3(") << QStringLiteral("~(");
    }

    void namesInvalidUtf8()
    {
        QFETCH(QByteArray, bytes);
        QFETCH(QString, expected);
        QString want;
        for (int i = 0, k = 0; i < expected.size(); ++i) {
            if (expected.at(i) == QLatin1Char('~')) {
                want.append(QChar(static_cast<ushort>(0xDC00 + static_cast<uchar>(bytes.at(k)))));
                ++k;
            } else {
                want.append(expected.at(i));
                k += Names::encode(QString(expected.at(i))).size();
            }
        }
        const QString decoded = Names::decode(bytes);
        QCOMPARE(decoded, want);
        QVERIFY(Names::hasEscapes(decoded));
        QVERIFY(Names::isEncodable(decoded));
        QCOMPARE(Names::encode(decoded), bytes);
        const QString shown = Names::display(decoded);
        QVERIFY(!shown.contains(QChar(static_cast<ushort>(0xDC00 + 0xFF))));
        QCOMPARE(shown.count(QChar(0xFFFD)), expected.count(QLatin1Char('~')));
    }

    void namesAllSingleBytes()
    {
        for (int b = 0; b < 256; ++b) {
            const QByteArray bytes(1, static_cast<char>(b));
            const QString decoded = Names::decode(bytes);
            QCOMPARE(decoded.size(), 1);
            QCOMPARE(Names::encode(decoded), bytes);
            QCOMPARE(Names::hasEscapes(decoded), b >= 0x80);
            if (b >= 0x80)
                QCOMPARE(static_cast<int>(decoded.at(0).unicode()), 0xDC00 + b);
            else
                QCOMPARE(static_cast<int>(decoded.at(0).unicode()), b);
        }
    }

    void namesRandomRoundTrip()
    {
        // A fixed LCG, so failures reproduce (no QRandomGenerator on Qt 5.6).
        quint32 state = 0x2545F491u;
        const auto next = [&state]() {
            state = state * 1664525u + 1013904223u;
            return state >> 24;
        };
        for (int round = 0; round < 5000; ++round) {
            QByteArray bytes;
            const int length = static_cast<int>(next() % 24);
            for (int i = 0; i < length; ++i) {
                const quint32 r = next();
                // Bias towards multi-byte lead and continuation bytes.
                bytes.append(static_cast<char>(r < 64 ? r : 0x80 | (r & 0x7F)));
            }
            const QString decoded = Names::decode(bytes);
            QVERIFY(Names::isEncodable(decoded));
            QCOMPARE(Names::encode(decoded), bytes);
            QCOMPARE(Names::decode(Names::encode(decoded)), decoded);
            if (!Names::hasEscapes(decoded))
                QCOMPARE(decoded, QString::fromUtf8(bytes.constData(), bytes.size()));
        }
    }

    void namesForeignSurrogates()
    {
        // Lone UTF-16 surrogates that decode() never produces (SMB names).
        const QString high = QStringLiteral("a") + QChar(0xD800) + QStringLiteral("b");
        QVERIFY(!Names::isEncodable(high));
        QVERIFY(!Names::hasEscapes(high));
        QCOMPARE(Names::encode(high), QByteArray("a\xef\xbf\xbd" "b"));
        QCOMPARE(Names::display(high), QString(QStringLiteral("a") + QChar(0xFFFD) + QStringLiteral("b")));
        const QString escapedAscii = QString(QChar(0xDC41));   // an "escape" of a byte below 0x80
        QVERIFY(!Names::isEncodable(escapedAscii));
        QVERIFY(!Names::hasEscapes(escapedAscii));
        const QString lowFirst = QString(QChar(0xDE00)) + QChar(0xD800);
        QVERIFY(!Names::isEncodable(lowFirst));
        const QString pair = QString::fromUcs4(std::array<uint, 1>({ 0x1F600 }).data(), 1);
        QVERIFY(Names::isEncodable(pair));
        QCOMPARE(Names::display(pair), pair);
        QVERIFY(!Names::hasEscapes(pair + QStringLiteral("x")));
        QVERIFY(Names::hasEscapes(pair + Names::decode(QByteArray("\xfe"))));
    }
};

QTEST_GUILESS_MAIN(TestCore)
#include "tst_core.moc"
