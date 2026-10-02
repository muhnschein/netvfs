// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbhelper.h"
#include "smbutil.h"

#include "logging.h"
#include "secure.h"

#include <QtCore/QElapsedTimer>

#include <array>
#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

// smb.pro passes the install path (smbhelper.pri); this is the same default.
#ifndef NETVFS_SMB_SHARES_HELPER
#define NETVFS_SMB_SHARES_HELPER "/usr/libexec/netvfs/netvfs-smb-shares"
#endif

namespace NetVfs::Smb {

namespace {

const int PollSliceMs = 100;
const char *const HelperVariable = "NETVFS_SMB_SHARES_HELPER";

class Fd
{
public:
    Fd() = default;
    ~Fd() { reset(); }
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    int get() const { return m_fd; }
    int *ptr() { return &m_fd; }
    void reset()
    {
        if (m_fd >= 0)
            ::close(m_fd);
        m_fd = -1;
    }

private:
    int m_fd = -1;
};

struct Pipe {
    Fd read;
    Fd write;
    bool open()
    {
        std::array<int, 2> fds = { -1, -1 };
        if (::pipe2(fds.data(), O_CLOEXEC) != 0)
            return false;
        *read.ptr() = fds[0];
        *write.ptr() = fds[1];
        return true;
    }
};

// The child: stopped and reaped exactly once.
class Child
{
public:
    explicit Child(pid_t pid) : m_pid(pid) {}
    ~Child() { kill(); }
    Child(const Child &) = delete;
    Child &operator=(const Child &) = delete;

    void kill()
    {
        if (m_pid <= 0)
            return;
        ::kill(m_pid, SIGKILL);
        wait();
    }
    // The exit status once the process ended; false while it runs.
    bool poll(int *status)
    {
        if (m_pid <= 0) {
            *status = m_status;
            return true;
        }
        const pid_t rc = ::waitpid(m_pid, &m_status, WNOHANG);
        if (rc == 0)
            return false;
        m_pid = -1;
        *status = m_status;
        return true;
    }

private:
    void wait()
    {
        while (::waitpid(m_pid, &m_status, 0) < 0 && errno == EINTR) {
            // retry
        }
        m_pid = -1;
    }

    pid_t m_pid;
    int m_status = 0;
};

Result helperFailed(const QString &what)
{
    return Result(Error::ProtocolError, QStringLiteral("the share list helper failed: %1").arg(what));
}

// Waits for `events` on `fd` in slices, honouring cancel and the deadline.
Result waitFor(int fd, short events, const QElapsedTimer &clock, int timeoutMs, const std::atomic<bool> &cancel)
{
    for (;;) {
        if (cancel)
            return Result(Error::Canceled);
        if (clock.elapsed() > timeoutMs)
            return Result(Error::Timeout, QStringLiteral("the share list did not arrive in time"));
        pollfd pfd = {};
        pfd.fd = fd;
        pfd.events = events;
        const int rc = ::poll(&pfd, 1, PollSliceMs);
        if (rc > 0)
            return Result::success();
        if (rc < 0 && errno != EINTR)
            return helperFailed(QStringLiteral("poll"));
    }
}

Result sendRequest(int fd, const QByteArray &request, const QElapsedTimer &clock, int timeoutMs,
                   const std::atomic<bool> &cancel)
{
    const SigPipeGuard guard;
    int sent = 0;
    while (sent < request.size()) {
        if (Result r = waitFor(fd, POLLOUT, clock, timeoutMs, cancel); !r.ok())
            return r;
        const ssize_t n = ::write(fd, request.constData() + sent, static_cast<size_t>(request.size() - sent));
        if (n < 0 && errno != EINTR && errno != EAGAIN)
            return helperFailed(QStringLiteral("it did not take the request"));
        if (n > 0)
            sent += static_cast<int>(n);
    }
    return Result::success();
}

Result receiveOutput(int fd, QByteArray *output, const QElapsedTimer &clock, int timeoutMs,
                     const std::atomic<bool> &cancel)
{
    std::array<char, 16384> buffer = {};
    for (;;) {
        if (Result r = waitFor(fd, POLLIN, clock, timeoutMs, cancel); !r.ok())
            return r;
        const ssize_t n = ::read(fd, buffer.data(), buffer.size());
        if (n == 0)
            return Result::success();
        if (n < 0 && errno != EINTR && errno != EAGAIN)
            return helperFailed(QStringLiteral("cannot read its output"));
        if (n > 0)
            output->append(buffer.data(), static_cast<int>(n));
        if (output->size() > MaxShareOutputBytes)
            return helperFailed(QStringLiteral("too much output"));
    }
}

Result awaitExit(Child *child, int *status, const QElapsedTimer &clock, int timeoutMs, const std::atomic<bool> &cancel)
{
    while (!child->poll(status)) {
        if (cancel)
            return Result(Error::Canceled);
        if (clock.elapsed() > timeoutMs)
            return Result(Error::Timeout, QStringLiteral("the share list did not arrive in time"));
        ::poll(nullptr, 0, PollSliceMs / 10);
    }
    return Result::success();
}

Result spawnHelper(const QString &program, Pipe *input, Pipe *output, pid_t *pid)
{
    if (!input->open() || !output->open())
        return helperFailed(QStringLiteral("no pipe"));
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, input->read.get(), STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, output->write.get(), STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    const QByteArray path = program.toLocal8Bit();
    std::array<char *, 2> argv = { const_cast<char *>(path.constData()), nullptr };
    const int rc = ::posix_spawn(pid, path.constData(), &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    input->read.reset();
    output->write.reset();
    if (rc != 0)
        return helperFailed(QStringLiteral("cannot start it (%1)").arg(QString::fromLocal8Bit(strerror(rc))));
    return Result::success();
}

// What the exit status and the output say together.
Result outcome(int status, const QByteArray &output, QVector<ShareInfo> *shares)
{
    if (WIFSIGNALED(status))
        return helperFailed(QStringLiteral("it crashed (signal %1)").arg(WTERMSIG(status)));
    const int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    const Result r = parseShareOutput(output, shares);
    if (code == 0 && r.error() != Error::ProtocolError && !r.ok()) {
        shares->clear();
        return helperFailed(QStringLiteral("it reported an error and success"));
    }
    if (code != 0 && r.ok()) {
        shares->clear();
        return helperFailed(QStringLiteral("exit status %1").arg(code));
    }
    return r;
}

} // namespace

QString shareHelperPath()
{
    if (qEnvironmentVariableIsSet(HelperVariable))
        return QString::fromLocal8Bit(qgetenv(HelperVariable));
    return QStringLiteral(NETVFS_SMB_SHARES_HELPER);
}

bool shareHelperInstalled()
{
    const QByteArray path = shareHelperPath().toLocal8Bit();
    return !path.isEmpty() && ::access(path.constData(), X_OK) == 0;
}

Result runShareHelper(const QString &program, QByteArray *request, int timeoutMs, const std::atomic<bool> &cancel,
                      QVector<ShareInfo> *shares)
{
    shares->clear();
    // M-5: the helper inherits the environment.
    neutraliseUserFile();
    Pipe input;
    Pipe output;
    pid_t pid = -1;
    Result r = spawnHelper(program, &input, &output, &pid);
    if (!r.ok()) {
        secureWipe(*request);
        return r;
    }
    Child child(pid);
    QElapsedTimer clock;
    clock.start();
    r = sendRequest(input.write.get(), *request, clock, timeoutMs, cancel);
    secureWipe(*request);           // XSEC-6
    input.write.reset();
    QByteArray text;
    if (r.ok())
        r = receiveOutput(output.read.get(), &text, clock, timeoutMs, cancel);
    int status = 0;
    if (r.ok())
        r = awaitExit(&child, &status, clock, timeoutMs, cancel);
    if (!r.ok())
        return r;                   // ~Child kills it
    return outcome(status, text, shares);
}

} // namespace NetVfs::Smb
