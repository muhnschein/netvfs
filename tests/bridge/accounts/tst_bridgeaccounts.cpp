// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs-accounts (SPEC-v2 XB-2a): the setgid helper that is the bridge's
// only access to the accounts database, its answers, its environment when
// set-id, its confinement (sandbox.h), and the bridge's side that runs it.
#include "accountsfixture.h"
#include "accountshelper.h"
#include "privileges.h"
#include "sandbox.h"

#include <Accounts/Manager>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>
#include <QtTest/QtTest>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <memory>
#include <thread>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sched.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace NetVfs;
using namespace NetVfs::Bridge;
using NetVfs::Test::AccountsFixture;

namespace QTest {
template<>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest

namespace {

const QString Helper = QStringLiteral(NETVFS_TEST_LIBEXEC_DIR "/netvfs-accounts");

QVariantMap globals(const QString &host, const QVariantMap &extra = QVariantMap())
{
    QVariantMap map { { QStringLiteral("netvfs/host"), host },
                      { QStringLiteral("netvfs/port"), 2222 },
                      { QStringLiteral("netvfs/username"), QStringLiteral("alice") } };
    for (auto it = extra.constBegin(); it != extra.constEnd(); ++it)
        map.insert(it.key(), it.value());
    return map;
}

QByteArray serve(AccountsFixture *fixture, const QStringList &arguments)
{
    return AccountsHelper::serve(fixture->manager(), arguments);
}

// Restores the environment after prepareSetIdProcess().
class SavedEnvironment
{
public:
    SavedEnvironment()
    {
        for (char **entry = environ; *entry; ++entry) {
            const QByteArray variable(*entry);
            const int eq = variable.indexOf('=');
            m_saved.append({ variable.left(eq), variable.mid(eq + 1) });
        }
    }
    ~SavedEnvironment()
    {
        QList<QByteArray> names;
        for (char **entry = environ; *entry; ++entry)
            names << QByteArray(*entry).left(QByteArray(*entry).indexOf('='));
        for (const QByteArray &name : names)
            qunsetenv(name.constData());
        for (const auto &[name, value] : m_saved)
            qputenv(name.constData(), value);
    }

private:
    QList<QPair<QByteArray, QByteArray>> m_saved;
};

// The exit status of a child that runs `body`, which may confine it for good.
template<typename Body>
int inChild(Body body)
{
    std::fflush(nullptr);
    const pid_t pid = ::fork();
    if (pid == 0)
        ::_exit(body());
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

// In a child: the number of the first check that failed, 0 if none did.
class Checks
{
public:
    void operator()(bool ok)
    {
        ++m_count;
        if (!ok && m_failed == 0)
            m_failed = m_count;
    }
    int failed() const { return m_failed; }

private:
    int m_count = 0;
    int m_failed = 0;
};

// A child status meaning that the kernel has no Landlock.
constexpr int NoLandlock = 77;

bool failsWith(int result, int error)
{
    return result == -1 && errno == error;
}

} // namespace

class tst_BridgeAccounts : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();
    void list();
    void files();
    void filesPolicy();
    void attention();
    void usage();
    void databaseUnusable();
    void malformedAnswers();
    void setIdEnvironment();
    void sandboxDescriptors();
    void sandboxProcessState();
    void sandboxSyscalls();
    void sandboxFilesystem();
    void sandboxLandlockLevels();
    void sandboxAccountsDirectories();
    void sandboxGroup();
    void helperWithClosedDescriptors();
    void directoryLists();
    void directoryFailures();
    void directoryFetch();
    void directoryAttention();
    void directoryChangeSignal();

private:
    // A session bus of this test's own: other tests that write accounts at
    // the same time would announce their changes here too.
    QProcess busDaemon;
    std::unique_ptr<AccountsFixture> fixture;
    int listed = 0;      // fake, Files enabled
    int unlisted = 0;    // fake, Files service disabled
};

void tst_BridgeAccounts::initTestCase()
{
    busDaemon.start(QStringLiteral("dbus-daemon"), { QStringLiteral("--session"), QStringLiteral("--nofork"),
                                                     QStringLiteral("--print-address") });
    QVERIFY2(busDaemon.waitForStarted(), "dbus-daemon is needed");
    QVERIFY(busDaemon.waitForReadyRead(10000));
    const QByteArray address = busDaemon.readLine().trimmed();
    QVERIFY(!address.isEmpty());
    // Before the first use of the session bus in this process; the helpers
    // and libaccounts inherit it.
    qputenv("DBUS_SESSION_BUS_ADDRESS", address);
}

void tst_BridgeAccounts::cleanupTestCase()
{
    busDaemon.kill();
    busDaemon.waitForFinished();
}

void tst_BridgeAccounts::init()
{
    fixture = std::make_unique<AccountsFixture>(
        QStringList { QStringLiteral("fake"), QStringLiteral("smb") });
    listed = fixture->createAccount(QStringLiteral("fake"), globals(QStringLiteral("files.example")), QString(), 7);
    QVERIFY(listed > 0);
    QVERIFY(fixture->setService(listed, QStringLiteral("fake-files"), true,
                                { { QStringLiteral("files_root"), QStringLiteral("photos//2026/") } }));
    unlisted = fixture->createAccount(QStringLiteral("fake"), globals(QStringLiteral("backup.example")));
    QVERIFY(unlisted > 0);
}

void tst_BridgeAccounts::cleanup()
{
    fixture.reset();
}

void tst_BridgeAccounts::list()
{
    // XA-1: only enabled accounts with the Files service enabled.
    QVector<AccountLocation> accounts;
    QVERIFY(AccountsHelper::decodeList(serve(fixture.get(), { QStringLiteral("list") }), &accounts).ok());
    QCOMPARE(accounts.size(), 1);
    const AccountLocation &a = accounts.at(0);
    QCOMPARE(a.accountId, listed);
    QCOMPARE(a.provider, QStringLiteral("fake"));
    QCOMPARE(a.displayName, QStringLiteral("alice@files.example"));
    QCOMPARE(a.params.host, QStringLiteral("files.example"));
    QCOMPARE(a.params.port, 2222);
    QCOMPARE(a.params.username, QStringLiteral("alice"));
    QCOMPARE(a.filesRoot, QStringLiteral("photos/2026"));
    QCOMPARE(a.attention, Attention::None);

    QVERIFY(fixture->setService(listed, QString(), false));
    QVERIFY(AccountsHelper::decodeList(serve(fixture.get(), { QStringLiteral("list") }), &accounts).ok());
    QVERIFY(accounts.isEmpty());
}

void tst_BridgeAccounts::files()
{
    FilesAccess access;
    QVERIFY(AccountsHelper::decodeFiles(serve(fixture.get(), { QStringLiteral("files"), QString::number(listed) }),
                                        &access).ok());
    QCOMPARE(access.params.host, QStringLiteral("files.example"));
    QCOMPARE(access.params.provider, QStringLiteral("fake"));
    QCOMPARE(access.credentialsId, 7u);
    QVERIFY(!access.secretOptional);
    // Only listed accounts: not one whose Files service is off, nor ids that
    // are not ids.
    for (const QString &id : { QString::number(unlisted), QStringLiteral("999"), QStringLiteral("0"),
                               QStringLiteral("-1"), QStringLiteral("x"), QString() }) {
        QCOMPARE(AccountsHelper::decodeFiles(serve(fixture.get(), { QStringLiteral("files"), id }), &access).error(),
                 Error::NotFound);
    }
}

void tst_BridgeAccounts::filesPolicy()
{
    // XA-4 is applied by the helper, before the bridge looks up a secret.
    const int bogus = fixture->createAccount(
        QStringLiteral("smb"), globals(QStringLiteral("nas.example"),
                                       { { QStringLiteral("netvfs/smb/security_profile"), QStringLiteral("bogus") } }));
    QVERIFY(fixture->setService(bogus, QStringLiteral("smb-files"), true));
    FilesAccess access;
    QCOMPARE(AccountsHelper::decodeFiles(serve(fixture.get(), { QStringLiteral("files"), QString::number(bogus) }),
                                         &access).error(),
             Error::SecurityPolicy);
    // XA-7: a guest profile with consent needs no secret.
    const int guest = fixture->createAccount(
        QStringLiteral("smb"), globals(QStringLiteral("guest.example"),
                                       { { QStringLiteral("netvfs/smb/security_profile"), QStringLiteral("guest") },
                                         { QStringLiteral("netvfs/smb/allow_insecure"), true } }));
    QVERIFY(fixture->setService(guest, QStringLiteral("smb-files"), true));
    QVERIFY(AccountsHelper::decodeFiles(serve(fixture.get(), { QStringLiteral("files"), QString::number(guest) }),
                                        &access).ok());
    QVERIFY(access.secretOptional);
}

void tst_BridgeAccounts::attention()
{
    // XB-14: recorded for a listed account, as a Files run.
    QVERIFY(AccountsHelper::decodeStatus(serve(fixture.get(), { QStringLiteral("attention"), QString::number(listed),
                                                                QStringLiteral("server-identity-changed"),
                                                                QStringLiteral("SHA256:pin") }))
                .ok());
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(),
             QStringLiteral("server-identity-changed"));
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/fake/host_key_seen")).toString(), QStringLiteral("SHA256:pin"));
    QCOMPARE(fixture->value(listed, QStringLiteral("CredentialsNeedUpdateFrom")).toString(),
             QStringLiteral("fake-files"));
    QVERIFY(AccountsHelper::decodeStatus(serve(fixture.get(), { QStringLiteral("attention"), QString::number(listed),
                                                                QStringLiteral("auth-failed") }))
                .ok());
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));

    // Clearing it is not the bridge's, and anyone can run the helper.
    for (const QString &state : { QStringLiteral("none"), QString(), QStringLiteral("whatever") }) {
        QCOMPARE(AccountsHelper::decodeStatus(serve(fixture.get(), { QStringLiteral("attention"),
                                                                     QString::number(listed), state }))
                     .error(),
                 Error::Unsupported);
    }
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));
    // Nor on an account the bridge does not list.
    QCOMPARE(AccountsHelper::decodeStatus(serve(fixture.get(), { QStringLiteral("attention"), QString::number(unlisted),
                                                                 QStringLiteral("auth-failed") }))
                 .error(),
             Error::NotFound);
    QVERIFY(fixture->value(unlisted, QStringLiteral("netvfs/attention")).toString().isEmpty());
}

void tst_BridgeAccounts::usage()
{
    const QList<QStringList> invalid {
        {},
        { QStringLiteral("list"), QStringLiteral("extra") },
        { QStringLiteral("files") },
        { QStringLiteral("files"), QString::number(listed), QStringLiteral("extra") },
        { QStringLiteral("attention"), QString::number(listed) },
        { QStringLiteral("attention"), QString::number(listed), QStringLiteral("auth-failed"), QStringLiteral("p"),
          QStringLiteral("extra") },
        { QStringLiteral("secret"), QString::number(listed) },
    };
    for (const QStringList &arguments : invalid)
        QCOMPARE(AccountsHelper::decodeStatus(serve(fixture.get(), arguments)).error(), Error::Unsupported);
}

void tst_BridgeAccounts::databaseUnusable()
{
    // What a helper without the group sees on Sailfish OS: an error naming
    // the setgid bit, not an empty list.
    fixture.reset();
    QTemporaryDir dir;
    QFile file(dir.path() + QStringLiteral("/file"));
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.close();
    const QByteArray saved = qgetenv("ACCOUNTS");
    qputenv("ACCOUNTS", QFile::encodeName(dir.path() + QStringLiteral("/file/accounts")));
    QByteArray answer;
    {
        Accounts::Manager manager;
        answer = AccountsHelper::serve(&manager, { QStringLiteral("list") });
    }
    if (saved.isNull())
        qunsetenv("ACCOUNTS");
    else
        qputenv("ACCOUNTS", saved);
    QVector<AccountLocation> accounts;
    const Result r = AccountsHelper::decodeList(answer, &accounts);
    QCOMPARE(r.error(), Error::PermissionDenied);
    QVERIFY2(r.message().contains(QLatin1String("setgid privileged")), qPrintable(r.message()));
}

void tst_BridgeAccounts::malformedAnswers()
{
    const QByteArray good = serve(fixture.get(), { QStringLiteral("list") });
    QVector<AccountLocation> accounts;
    QVERIFY(AccountsHelper::decodeList(good, &accounts).ok());
    QCOMPARE(AccountsHelper::decodeList(QByteArray(), &accounts).error(), Error::ProtocolError);
    QCOMPARE(AccountsHelper::decodeList("garbage", &accounts).error(), Error::ProtocolError);
    QCOMPARE(AccountsHelper::decodeList(good.left(good.size() - 1), &accounts).error(), Error::ProtocolError);
    QCOMPARE(AccountsHelper::decodeList(good + 'x', &accounts).error(), Error::ProtocolError);
    QCOMPARE(accounts.size(), 1);   // untouched by the failures
    FilesAccess access;
    QCOMPARE(AccountsHelper::decodeFiles(good, &access).error(), Error::ProtocolError);
    QCOMPARE(AccountsHelper::decodeStatus(good).error(), Error::ProtocolError);
    // Another kind of answer is no list either.
    const QByteArray files = serve(fixture.get(), { QStringLiteral("files"), QString::number(listed) });
    QCOMPARE(AccountsHelper::decodeList(files, &accounts).error(), Error::ProtocolError);
}

void tst_BridgeAccounts::setIdEnvironment()
{
    // XB-2a: what a setgid helper keeps from its caller's environment.
    for (const char *name : { "LANG", "LANGUAGE", "LC_ALL", "LC_TIME", "TZ", "XDG_RUNTIME_DIR",
                              "DBUS_SESSION_BUS_ADDRESS" })
        QVERIFY2(keptInSetIdProcess(name), name);
    for (const char *name : { "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "ACCOUNTS", "AG_PROVIDERS", "AG_SERVICES",
                              "AG_APPLICATIONS", "NETVFS_ACCOUNTS_HELPER", "QT_PLUGIN_PATH", "QT_LOGGING_RULES",
                              "LD_PRELOAD", "GIO_EXTRA_MODULES", "PATH", "LANGX", "XLANG", "" })
        QVERIFY2(!keptInSetIdProcess(name), name);

    QList<QByteArray> removed;
    bool prepared = false;
    QByteArray home;
    QByteArray accounts;
    QByteArray lang;
    struct rlimit coreBefore {};
    struct rlimit coreAfter {};
    ::getrlimit(RLIMIT_CORE, &coreBefore);
    {
        const SavedEnvironment saved;
        qputenv("HOME", "/tmp/someone-else");
        qputenv("ACCOUNTS", "/tmp/evil");
        qputenv("LANG", "fi_FI.UTF-8");
        // A core limit of its own to drop (the soft limit may start at 0).
        const struct rlimit coreOpen { coreBefore.rlim_max, coreBefore.rlim_max };
        QVERIFY(coreOpen.rlim_cur != 0);
        ::setrlimit(RLIMIT_CORE, &coreOpen);
        prepared = prepareSetIdProcess(&removed);
        ::getrlimit(RLIMIT_CORE, &coreAfter);
        ::setrlimit(RLIMIT_CORE, &coreBefore);
        home = qgetenv("HOME");
        accounts = qgetenv("ACCOUNTS");
        lang = qgetenv("LANG");
    }
    const struct passwd *user = ::getpwuid(::getuid());
    QVERIFY(user && user->pw_dir);
    QVERIFY(prepared);
    QCOMPARE(home, QByteArray(user->pw_dir));   // the real uid's, not the caller's
    QVERIFY(accounts.isNull());
    QCOMPARE(lang, QByteArray("fi_FI.UTF-8"));
    QVERIFY(removed.contains("ACCOUNTS"));
    QVERIFY(!removed.contains("LANG"));
    QCOMPARE(coreAfter.rlim_cur, rlim_t(0));
    QCOMPARE(coreAfter.rlim_max, coreBefore.rlim_max);
    QCOMPARE(qgetenv("ACCOUNTS"), QFile::encodeName(fixture->path()));   // restored
}

void tst_BridgeAccounts::sandboxDescriptors()
{
    // XB-2a: a caller's closed stdio becomes /dev/null, so that no file the
    // helper opens receives its answer; other inherited descriptors close.
    struct stat devNull {};
    QCOMPARE(::stat("/dev/null", &devNull), 0);
    const int status = inChild([&devNull] {
        const int inherited = ::open("/dev/null", O_RDONLY);
        ::close(STDIN_FILENO);
        ::close(STDERR_FILENO);
        Checks check;
        check(inherited > STDERR_FILENO);
        check(sanitizeDescriptors());
        for (const int fd : { STDIN_FILENO, STDERR_FILENO }) {
            struct stat st {};
            check(::fstat(fd, &st) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == devNull.st_rdev);
        }
        check(failsWith(::fcntl(inherited, F_GETFD), EBADF));
        return check.failed();
    });
    QCOMPARE(status, 0);
}

void tst_BridgeAccounts::sandboxProcessState()
{
    const int status = inChild([] {
        ::umask(0);
        ::signal(SIGTERM, SIG_IGN);
        sigset_t blocked;
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGUSR1);
        ::sigprocmask(SIG_BLOCK, &blocked, nullptr);
        struct rlimit size {};
        ::getrlimit(RLIMIT_FSIZE, &size);
        size.rlim_cur = std::min<rlim_t>(size.rlim_max, 4096);
        ::setrlimit(RLIMIT_FSIZE, &size);

        resetProcessState();
        Checks check;
        check(::umask(022) == 077);
        struct sigaction action {};
        check(::sigaction(SIGTERM, nullptr, &action) == 0 && action.sa_handler == SIG_DFL);
        sigset_t now;
        check(::sigprocmask(SIG_BLOCK, nullptr, &now) == 0 && sigismember(&now, SIGUSR1) == 0);
        check(::getrlimit(RLIMIT_FSIZE, &size) == 0 && size.rlim_cur == size.rlim_max);
        return check.failed();
    });
    QCOMPARE(status, 0);
}

void tst_BridgeAccounts::sandboxSyscalls()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QByteArray file = QFile::encodeName(dir.filePath(QStringLiteral("file")));
    const QByteArray other = QFile::encodeName(dir.filePath(QStringLiteral("other")));
    const QByteArray folder = QFile::encodeName(dir.filePath(QStringLiteral("folder")));
    const int status = inChild([&] {
        if (!restrictSyscalls())
            return 99;
        Checks check;
        check(failsWith(::execl("/bin/false", "false", nullptr), EPERM));
        check(failsWith(::socket(AF_INET, SOCK_STREAM, 0), EPERM));
        check(failsWith(::socket(AF_INET6, SOCK_DGRAM, 0), EPERM));
        check(failsWith(::socket(AF_NETLINK, SOCK_RAW, 0), EPERM));
        check(::socket(AF_UNIX, SOCK_STREAM, 0) >= 0);
        int pair[2];
        check(::socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        check(failsWith(::unshare(CLONE_NEWUSER), EPERM));
        check(failsWith(::syscall(SYS_bpf, 0, nullptr, 0), EPERM));
        // No file with a setuid or setgid bit, however it is made.
        const int fd = ::open(file.constData(), O_CREAT | O_WRONLY, 0600);
        check(fd >= 0);
        check(failsWith(::fchmod(fd, 02755), EPERM));
        check(failsWith(::chmod(file.constData(), 04755), EPERM));
        check(failsWith(::fchmodat(AT_FDCWD, file.constData(), 02700, 0), EPERM));
        check(::chmod(file.constData(), 0640) == 0);
        check(failsWith(::open(other.constData(), O_CREAT | O_WRONLY, 02755), EPERM));
        // Without O_CREAT the mode is unused, whatever a raw syscall passes.
        check(::syscall(SYS_openat, AT_FDCWD, file.constData(), O_RDONLY, 06755) >= 0);
        check(failsWith(::mkdir(folder.constData(), 02755), EPERM));
        check(::mkdir(folder.constData(), 0700) == 0);
        check(failsWith(::open(folder.constData(), O_TMPFILE | O_WRONLY, 02755), EPERM));
#if !defined(__SANITIZE_ADDRESS__)
        check(failsWith(::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr), EPERM));
#endif
        // Threads still start: clone3 fails with ENOSYS and glibc uses clone.
        bool ran = false;
        std::thread thread([&ran] { ran = true; });
        thread.join();
        check(ran);
        return check.failed();
    });
    if (status == 99)
        QSKIP("no seccomp filters on this kernel or architecture");
    QCOMPARE(status, 0);
}

void tst_BridgeAccounts::sandboxFilesystem()
{
    QTemporaryDir allowed;
    QTemporaryDir denied;
    QVERIFY(allowed.isValid() && denied.isValid());
    const QByteArray secret = QFile::encodeName(denied.filePath(QStringLiteral("secret")));
    QFile secretFile(QFile::decodeName(secret));
    QVERIFY(secretFile.open(QIODevice::WriteOnly));
    secretFile.close();
    const QByteArray allowedDir = QFile::encodeName(allowed.path());
    const QByteArray created = allowedDir + "/accounts.db-wal";
    const QByteArray outside = QFile::encodeName(denied.filePath(QStringLiteral("planted")));
    const int status = inChild([&] {
        // A database folder that does not exist yet needs no rule.
        const FilesystemRestriction restriction = restrictFilesystem({ allowedDir, "/nonexistent/accounts" }, false);
        if (restriction.abi == 0)
            return NoLandlock;
        Checks check;
        check(restriction.enforced);
        // The database folder: create, write, truncate, remove.
        const int fd = ::open(created.constData(), O_CREAT | O_RDWR, 0600);
        check(fd >= 0);
        check(::write(fd, "x", 1) == 1);
        check(::ftruncate(fd, 0) == 0);
        check(::unlink(created.constData()) == 0);
        // Anything else: read-only system folders, nothing beyond them.
        check(::open("/etc/passwd", O_RDONLY | O_CLOEXEC) >= 0);
        check(::open("/dev/null", O_WRONLY | O_CLOEXEC) >= 0);
        check(failsWith(::open(secret.constData(), O_RDONLY), EACCES));
        check(failsWith(::open(outside.constData(), O_CREAT | O_WRONLY, 0600), EACCES));
        check(failsWith(::execl("/bin/false", "false", nullptr), EACCES));
        if (restriction.abi >= 4) {
            const int tcp = ::socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in local {};
            local.sin_family = AF_INET;
            local.sin_port = htons(1);
            local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            check(failsWith(::connect(tcp, reinterpret_cast<const sockaddr *>(&local), sizeof local), EACCES));
        }
        if (restriction.abi >= 6)
            check(failsWith(::kill(::getppid(), 0), EPERM));
        return check.failed();
    });
    if (status == NoLandlock)
        QSKIP("no Landlock on this kernel");
    QCOMPARE(status, 0);
}

void tst_BridgeAccounts::sandboxLandlockLevels()
{
    // Each Landlock ABI adds its rights; a newer kernel than this code knows
    // gets what the newest known one handles.
    const auto same = [](const LandlockAccess &a, const LandlockAccess &b) {
        return a.fs == b.fs && a.net == b.net && a.scoped == b.scoped;
    };
    const auto widens = [](std::uint64_t smaller, std::uint64_t larger) {
        return smaller != larger && (smaller & larger) == smaller;
    };
    QVector<LandlockAccess> levels;
    for (int abi = 0; abi <= LandlockNewestAbi + 2; ++abi)
        levels << landlockAccess(abi, false);
    QVERIFY(same(levels.at(0), LandlockAccess()));
    QVERIFY(levels.at(1).fs != 0 && levels.at(1).net == 0 && levels.at(1).scoped == 0);
    QVERIFY(widens(levels.at(1).fs, levels.at(2).fs));   // renames and links
    QVERIFY(widens(levels.at(2).fs, levels.at(3).fs));   // truncation
    QCOMPARE(levels.at(4).fs, levels.at(3).fs);          // TCP
    QVERIFY(levels.at(3).net == 0 && levels.at(4).net != 0);
    QVERIFY(widens(levels.at(4).fs, levels.at(5).fs));   // device ioctls
    QVERIFY(levels.at(5).scoped == 0 && levels.at(6).scoped != 0);   // signals, abstract sockets
    for (int abi = 7; abi < levels.size(); ++abi)
        QVERIFY2(same(levels.at(abi), levels.at(6)), qPrintable(QString::number(abi)));
    // An abstract session bus keeps its socket, not the signals.
    const LandlockAccess abstractBus = landlockAccess(LandlockNewestAbi, true);
    QVERIFY(widens(abstractBus.scoped, levels.at(6).scoped) && abstractBus.scoped != 0);
    QVERIFY(same(landlockAccess(5, true), levels.at(5)));
}

void tst_BridgeAccounts::sandboxAccountsDirectories()
{
    // ACCOUNTS (a test's database) wins; else the Sailfish OS folder and the
    // upstream one, below the XDG folders or HOME.
    const SavedEnvironment saved;
    qputenv("ACCOUNTS", "/tmp/fixture");
    QCOMPARE(accountsDirectories(), QList<QByteArray>({ "/tmp/fixture" }));
    qunsetenv("ACCOUNTS");
    qputenv("HOME", "/home/someone");
    qunsetenv("XDG_DATA_HOME");
    qputenv("XDG_CONFIG_HOME", "relative");   // not a folder XDG allows
    QCOMPARE(accountsDirectories(), QList<QByteArray>({ "/home/someone/.local/share/system/privileged/Accounts",
                                                         "/home/someone/.config/libaccounts-glib" }));
    qputenv("XDG_DATA_HOME", "/data");
    qputenv("XDG_CONFIG_HOME", "/config");
    QCOMPARE(accountsDirectories(),
             QList<QByteArray>({ "/data/system/privileged/Accounts", "/config/libaccounts-glib" }));
}

void tst_BridgeAccounts::sandboxGroup()
{
    // Not set-id here: real, effective and saved gid stay the real one. The
    // set-id case is the device's (tools/ci cannot install setgid files).
    QVERIFY(dropSetIdGroup());
    gid_t r = 0;
    gid_t e = 0;
    gid_t s = 0;
    QCOMPARE(::getresgid(&r, &e, &s), 0);
    QCOMPARE(e, ::getgid());
    QCOMPARE(s, ::getgid());
}

void tst_BridgeAccounts::helperWithClosedDescriptors()
{
    // The built helper, confined, started with stdin and stderr closed.
    QProcess helper;
    helper.start(QStringLiteral("/bin/sh"), { QStringLiteral("-c"), QStringLiteral("exec \"$0\" list 0<&- 2>&-"),
                                             Helper });
    QVERIFY(helper.waitForFinished(10000));
    QCOMPARE(helper.exitCode(), 0);
    QVector<AccountLocation> accounts;
    QVERIFY(AccountsHelper::decodeList(helper.readAllStandardOutput(), &accounts).ok());
    QCOMPARE(accounts.size(), 1);
}

void tst_BridgeAccounts::directoryLists()
{
    // The built helper, through the bridge's side (it inherits the private
    // database's environment and is not set-id here).
    HelperAccountsDirectory directory(Helper);
    const QVector<AccountLocation> accounts = directory.filesAccounts();
    QCOMPARE(accounts.size(), 1);
    QCOMPARE(accounts.at(0).accountId, listed);
    QCOMPARE(accounts.at(0).params.host, QStringLiteral("files.example"));
}

void tst_BridgeAccounts::directoryFailures()
{
    // A missing or failing helper lists nothing, and says why.
    QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("^Cannot list the accounts")));
    QVERIFY(HelperAccountsDirectory(QStringLiteral("/nonexistent/netvfs-accounts")).filesAccounts().isEmpty());
    QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("^Cannot list the accounts.*/bin/false")));
    QVERIFY(HelperAccountsDirectory(QStringLiteral("/bin/false")).filesAccounts().isEmpty());
    QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("^Cannot list the accounts.*malformed")));
    QVERIFY(HelperAccountsDirectory(QStringLiteral("/bin/true")).filesAccounts().isEmpty());
}

void tst_BridgeAccounts::directoryFetch()
{
    // An account the helper does not hand out fails before signond is asked.
    HelperAccountsDirectory directory(Helper);
    Result result(Error::Internal);
    bool called = false;
    directory.fetch(unlisted, [&](const Result &r, const ConnectionParams &params, const Credentials &) {
        result = r;
        called = true;
        QVERIFY(params.host.isEmpty());
    });
    QTRY_VERIFY_WITH_TIMEOUT(called, 10000);
    QCOMPARE(result.error(), Error::NotFound);

    called = false;
    HelperAccountsDirectory missing(QStringLiteral("/nonexistent/netvfs-accounts"));
    missing.fetch(listed, [&](const Result &r, const ConnectionParams &, const Credentials &) {
        result = r;
        called = true;
    });
    QTRY_VERIFY_WITH_TIMEOUT(called, 10000);
    QCOMPARE(result.error(), Error::Unsupported);
}

void tst_BridgeAccounts::directoryAttention()
{
    HelperAccountsDirectory directory(Helper);
    QSignalSpy changed(&directory, &AccountDirectory::changed);
    directory.setAttention(listed, Attention::AuthFailed, QString());
    QTRY_VERIFY_WITH_TIMEOUT(changed.count() >= 1, 10000);
    QCOMPARE(fixture->value(listed, QStringLiteral("netvfs/attention")).toString(), QStringLiteral("auth-failed"));

    // A refused write is logged, and nothing changed.
    QTest::qWait(500);   // the refresh for the write's own AccountChanged
    changed.clear();
    QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("^Cannot record the attention state")));
    directory.setAttention(unlisted, Attention::AuthFailed, QString());
    QTRY_VERIFY_WITH_TIMEOUT(directory.findChildren<QProcess *>().isEmpty(), 10000);
    QTest::qWait(500);
    QCOMPARE(changed.count(), 0);

    // A helper whose own AccountChanged never reaches the bus (as a set-id
    // one may not): the bridge lists again all the same.
    QTemporaryDir dir;
    QFile answer(dir.path() + QStringLiteral("/answer"));
    QVERIFY(answer.open(QIODevice::WriteOnly));
    answer.write(serve(fixture.get(), { QStringLiteral("attention"), QString::number(listed),
                                        QStringLiteral("auth-failed") }));
    answer.close();
    QFile script(dir.path() + QStringLiteral("/helper"));
    QVERIFY(script.open(QIODevice::WriteOnly));
    script.write("#!/bin/sh\nexec cat '" + QFile::encodeName(answer.fileName()) + "'\n");
    script.close();
    QVERIFY(script.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    QTest::qWait(500);   // the signals of the write above
    HelperAccountsDirectory quiet(script.fileName());
    QSignalSpy quietChanged(&quiet, &AccountDirectory::changed);
    quiet.setAttention(listed, Attention::AuthFailed, QString());
    QTRY_COMPARE_WITH_TIMEOUT(quietChanged.count(), 1, 10000);
}

void tst_BridgeAccounts::directoryChangeSignal()
{
    // libaccounts' writers announce changes on the session bus, on a path
    // per service type; the several signals of one write make one refresh.
    HelperAccountsDirectory directory(Helper);
    QSignalSpy changed(&directory, &AccountDirectory::changed);
    QDBusConnection bus = QDBusConnection::sessionBus();
    QVERIFY(bus.isConnected());
    QVERIFY(bus.send(QDBusMessage::createSignal(QStringLiteral("/org/example/other"),
                                                QStringLiteral("com.google.code.AccountsSSO.Accounts"),
                                                QStringLiteral("Unrelated"))));
    QVERIFY(bus.send(QDBusMessage::createSignal(QStringLiteral("/org/example/other"), QStringLiteral("org.example.Other"),
                                                QStringLiteral("AccountChanged"))));
    QTest::qWait(500);
    QCOMPARE(changed.count(), 0);

    // Real writes, as Settings makes them: two in a row, one refresh.
    QVERIFY(fixture->setService(listed, QStringLiteral("fake-files"), false));
    QVERIFY(fixture->setService(listed, QStringLiteral("fake-files"), true));
    QTRY_COMPARE_WITH_TIMEOUT(changed.count(), 1, 5000);
    QTest::qWait(500);
    QCOMPARE(changed.count(), 1);
}

QTEST_GUILESS_MAIN(tst_BridgeAccounts)
#include "tst_bridgeaccounts.moc"
