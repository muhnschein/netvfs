// SPDX-License-Identifier: LGPL-2.1-or-later
// The netvfs-bridge binary under socket activation (SPEC-v2 XB-2, XB-4):
// the test plays systemd (a listening socket on fd 3, LISTEN_FDS and
// LISTEN_PID), talks to the bridge through it and expects the idle exit.
#include "bridgetest.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>
#include <QtTest/QtTest>

#include <csignal>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace NetVfs;
using namespace NetVfs::BridgeTest;

namespace {

const QByteArray BridgeBinary = NETVFS_TEST_BIN_DIR "/netvfs-bridge";

void writeFile(const QString &path, const QByteArray &content)
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(content);
}

int listenOn(const QString &path)
{
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    const QByteArray bytes = QFile::encodeName(path);
    if (fd < 0 || bytes.size() >= int(sizeof(addr.sun_path)))
        return -1;
    std::copy(bytes.constBegin(), bytes.constEnd(), addr.sun_path);
    if (::bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0 || ::listen(fd, 8) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// Starts the bridge with `listenFd` as the socket-activated fd 3. LISTEN_PID
// must be the bridge's own pid: a shell sets it to $$ and execs the bridge.
pid_t spawnActivated(int listenFd, const QProcessEnvironment &environment, const QByteArray &consumer)
{
    std::vector<QByteArray> envStore;
    for (const QString &entry : environment.toStringList())
        envStore.push_back(entry.toLocal8Bit());
    envStore.push_back("LISTEN_FDS=1");
    std::vector<char *> envp;
    for (QByteArray &e : envStore)
        envp.push_back(e.data());
    envp.push_back(nullptr);
    QByteArray sh = "/bin/sh";
    QByteArray dashC = "-c";
    QByteArray script = "LISTEN_PID=$$; export LISTEN_PID; exec \"$0\" \"$1\"";
    QByteArray bridge = BridgeBinary;
    QByteArray id = consumer;
    std::vector<char *> argv { sh.data(), dashC.data(), script.data(), bridge.data(), id.data(), nullptr };

    const pid_t pid = ::fork();
    if (pid == 0) {
        // Only async-signal-safe calls between fork and exec.
        const bool placed = listenFd == 3 ? ::fcntl(3, F_SETFD, 0) == 0 : ::dup2(listenFd, 3) == 3;
        if (!placed)
            ::_exit(126);
        ::execve(argv[0], argv.data(), envp.data());
        ::_exit(127);
    }
    return pid;
}

int waitExit(pid_t pid, int timeoutMs)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeoutMs) {
        int status = 0;
        if (::waitpid(pid, &status, WNOHANG) == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(10);
    }
    ::kill(pid, SIGKILL);
    ::waitpid(pid, nullptr, 0);
    return -1;
}

} // namespace

class tst_BridgeProcess : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void socketActivation();
    void unknownConsumer();
};

void tst_BridgeProcess::socketActivation()
{
    QTemporaryDir dir;
    const QString exe = QCoreApplication::applicationFilePath();
    writeFile(dir.path() + QStringLiteral("/consumers/proc-test.conf"),
              "[Consumer]\nId=proc-test\nDisplayName=Process test\nExecutable=" + exe.toUtf8()
              + "\nDataDir=.local/share/proc-test\n");
    writeFile(dir.path() + QStringLiteral("/config/netvfs/bridge.conf"), "[Consent]\nproc-test=granted\n");
    QDir().mkpath(dir.path() + QStringLiteral("/home"));
    QDir().mkpath(dir.path() + QStringLiteral("/accounts"));
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("HOME"), dir.path() + QStringLiteral("/home"));
    env.insert(QStringLiteral("XDG_CONFIG_HOME"), dir.path() + QStringLiteral("/config"));
    env.insert(QStringLiteral("XDG_DATA_HOME"), dir.path() + QStringLiteral("/data"));
    env.insert(QStringLiteral("NETVFS_CONSUMERS_DIR"), dir.path() + QStringLiteral("/consumers"));
    env.insert(QStringLiteral("NETVFS_BACKEND_PATH"), QStringLiteral(NETVFS_TEST_FAKE_BACKEND_DIR));
    env.insert(QStringLiteral("NETVFS_BRIDGE_IDLE_EXIT_MS"), QStringLiteral("500"));
    env.insert(QStringLiteral("ACCOUNTS"), dir.path() + QStringLiteral("/accounts"));
    env.insert(QStringLiteral("AG_PROVIDERS"), dir.path() + QStringLiteral("/accounts"));
    env.insert(QStringLiteral("AG_SERVICES"), dir.path() + QStringLiteral("/accounts"));
    env.remove(QStringLiteral("LISTEN_PID"));
    env.remove(QStringLiteral("LISTEN_FDS"));

    const QString socketPath = dir.path() + QStringLiteral("/bridge.sock");
    const int listenFd = listenOn(socketPath);
    QVERIFY(listenFd >= 0);
    const pid_t pid = spawnActivated(listenFd, env, "proc-test");
    QVERIFY(pid > 0);
    ::close(listenFd);   // systemd keeps its copy; ours is not needed any more

    {
        TestClient client(QStringLiteral("unix:path=") + socketPath);
        const TestClient::Message hello = client.hello();
        QVERIFY2(hello.valid && !hello.isError, qPrintable(hello.name));
        QCOMPARE(client.call("GetConsent").args.value(0).toString(), QStringLiteral("granted"));
        QCOMPARE(client.call("ListLocations").args.value(0).toList().size(), 0);
        client.close();
    }
    // XB-2: gone after the idle time with no client and no job.
    QCOMPARE(waitExit(pid, 10000), 0);
    // XB-4: the bridge wrote nothing into the consumer's folder.
    QVERIFY(!QFileInfo::exists(dir.path() + QStringLiteral("/home/.local/share/proc-test")));
}

void tst_BridgeProcess::unknownConsumer()
{
    QTemporaryDir dir;
    QProcess p;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("NETVFS_CONSUMERS_DIR"), dir.path());
    p.setProcessEnvironment(env);
    p.start(QString::fromLocal8Bit(BridgeBinary), { QStringLiteral("nobody") });
    QVERIFY(p.waitForFinished(10000));
    QCOMPARE(p.exitCode(), 1);
    p.start(QString::fromLocal8Bit(BridgeBinary), QStringList());
    QVERIFY(p.waitForFinished(10000));
    QCOMPARE(p.exitCode(), 2);
}

QTEST_GUILESS_MAIN(tst_BridgeProcess)
#include "tst_bridgeprocess.moc"
