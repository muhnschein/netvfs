// SPDX-License-Identifier: LGPL-2.1-or-later
// Shell exec channel and the helpers built on it (SPEC-v2 XS-9; amends
// SPEC-sftp S-3: an exec channel is opened only with allow_shell=true).
//
// Commands are fixed templates (sftpshell.h) whose every word is quoted by
// netvfs; their output is parsed defensively and anything unexpected is
// Unsupported, never a guess (XSEC-3). The exec channel runs while the
// session is non-blocking, so cancel() (channel close) and the timeout end
// every wait within C-9's bound.
#include "logging.h"
#include "names.h"
#include "paths.h"
#include "sftpinternal.h"

#include <QtCore/QElapsedTimer>

#include <poll.h>

#include <algorithm>
#include <array>

namespace NetVfs::Sftp {

namespace {

constexpr const char *AllowShellOption = "allow_shell";
constexpr qint64 HelperOutputLimit = 64 * 1024;
constexpr qint64 ProbeOutputLimit = 4096;
constexpr qint64 FindBytesPerResult = 4096;
constexpr qint64 MaxFindOutput = 16 * 1024 * 1024;
constexpr int ReadBufferSize = 32 * 1024;
constexpr int SessionOpenAttempts = 4;
constexpr int SessionRetryMs = 200;

// The session is non-blocking while it exists (exec, then back).
class NonBlocking
{
public:
    explicit NonBlocking(ssh_session session) : m_session(session) { ssh_set_blocking(m_session, 0); }
    ~NonBlocking() { ssh_set_blocking(m_session, 1); }
    NonBlocking(const NonBlocking &) = delete;
    NonBlocking &operator=(const NonBlocking &) = delete;

private:
    ssh_session m_session;
};

QString firstLine(const QByteArray &output)
{
    return Names::display(Names::decode(output.left(output.indexOf('\n')).left(512)));
}

Result commandFailed(const char *what, const ExecResult &result)
{
    return Result(Error::ProtocolError,
                  QStringLiteral("%1 failed on the server (exit status %2)").arg(QLatin1String(what)).arg(result.exitStatus),
                  firstLine(result.err));
}

} // namespace

// One command on its own channel.
class SftpBackend::Shell
{
public:
    Shell(const SftpBackend &backend, const ExecOptions &options)
        : m_b(backend), m_options(options),
          m_timeoutMs(options.timeoutMs < 0 ? backend.m_params.requestTimeoutMs : options.timeoutMs)
    {
        m_started.start();
    }
    Shell(const Shell &) = delete;
    Shell &operator=(const Shell &) = delete;
    ~Shell() { closeChannel(); }

    Result run(const QByteArray &command, ExecResult *result);

private:
    Result wait() const;
    Result openOnce();
    Result open();
    Result start(const QByteArray &command);
    Result collect(ExecResult *result);
    bool keep(const char *data, int n, QByteArray *stream, ExecResult *result) const;
    Result exitStatus(ExecResult *result);
    void closeChannel();

    const SftpBackend &m_b;
    const ExecOptions m_options;
    const int m_timeoutMs;
    QElapsedTimer m_started;
    ssh_channel m_channel = nullptr;
};

Result SftpBackend::Shell::wait() const
{
    if (m_b.m_canceled)
        return canceled();   // C-9: the destructor closes the channel
    if (m_timeoutMs > 0 && m_started.elapsed() >= m_timeoutMs)
        return Result(Error::Timeout, QStringLiteral("The command did not finish within %1 s").arg(m_timeoutMs / 1000));
    if (!ssh_is_connected(m_b.m_session))
        return Result(Error::ConnectionLost, text(ssh_get_error(m_b.m_session)));
    pollfd fd {};
    fd.fd = ssh_get_fd(m_b.m_session);
    fd.events = POLLIN;
    ::poll(&fd, 1, PollIntervalMs);
    return Result::success();
}

Result SftpBackend::Shell::openOnce()
{
    m_channel = ssh_channel_new(m_b.m_session);
    if (!m_channel)
        return Requests(m_b).established(Result(Error::Internal, text(ssh_get_error(m_b.m_session))));
    for (;;) {
        const int rc = ssh_channel_open_session(m_channel);
        if (rc == SSH_OK)
            return Result::success();
        if (rc != SSH_AGAIN)
            return Requests(m_b).established(channelOpenFailure(text(ssh_get_error(m_b.m_session))));   // XC-21
        if (const Result r = wait(); !r.ok())
            return r;
    }
}

Result SftpBackend::Shell::open()
{
    // OpenSSH frees the session of a closed channel only after it handled
    // the packets that arrived together with the close, so a channel opened
    // right after another one ended can still meet MaxSessions: try again
    // for a moment before reporting TooManyConnections (XC-21).
    Result r = openOnce();
    for (int attempt = 1; attempt < SessionOpenAttempts && r.error() == Error::TooManyConnections; ++attempt) {
        closeChannel();
        for (int waited = 0; waited < SessionRetryMs; waited += PollIntervalMs) {
            if (const Result stop = wait(); !stop.ok())
                return stop;
        }
        r = openOnce();
    }
    return r;
}

Result SftpBackend::Shell::start(const QByteArray &command)
{
    for (;;) {
        const int rc = ssh_channel_request_exec(m_channel, command.constData());
        if (rc == SSH_OK)
            return Result::success();
        if (rc != SSH_AGAIN)
            return Requests(m_b).established(Result(Error::Unsupported, QStringLiteral("The server does not run commands"),
                                          text(ssh_get_error(m_b.m_session))));
        if (const Result r = wait(); !r.ok())
            return r;
    }
}

// Appends up to the cap; false once output had to be dropped.
bool SftpBackend::Shell::keep(const char *data, int n, QByteArray *stream, ExecResult *result) const
{
    const qint64 room = std::max<qint64>(0, m_options.maxOutput - stream->size());
    stream->append(data, static_cast<int>(std::min<qint64>(room, n)));
    if (n > room)
        result->truncated = true;
    return n <= room;
}

Result SftpBackend::Shell::collect(ExecResult *result)
{
    std::array<char, ReadBufferSize> buffer {};
    const auto size = static_cast<uint32_t>(buffer.size());
    for (;;) {
        const int out = ssh_channel_read_nonblocking(m_channel, buffer.data(), size, 0);
        if (out > 0 && !keep(buffer.data(), out, &result->out, result))
            return Result::success();   // run() closes the channel
        const int err = ssh_channel_read_nonblocking(m_channel, buffer.data(), size, 1);
        if (err > 0 && !keep(buffer.data(), err, &result->err, result))
            return Result::success();
        if ((out < 0 && out != SSH_EOF) || (err < 0 && err != SSH_EOF))
            return Requests(m_b).established(Result(Error::ProtocolError, text(ssh_get_error(m_b.m_session))));
        if (out > 0 || err > 0)
            continue;
        if (ssh_channel_is_eof(m_channel) || ssh_channel_is_closed(m_channel))
            return Result::success();
        if (const Result r = wait(); !r.ok())
            return r;
    }
}

Result SftpBackend::Shell::exitStatus(ExecResult *result)
{
    for (;;) {
        uint32_t code = 0;
        char *signal = nullptr;
        const int rc = ssh_channel_get_exit_state(m_channel, &code, &signal, nullptr);
        if (rc == SSH_OK) {
            result->exitStatus = signal ? -1 : static_cast<int>(code);
            ssh_string_free_char(signal);
            return Result::success();
        }
        if (rc != SSH_AGAIN || ssh_channel_is_closed(m_channel))
            return Result::success();   // no status reported: -1
        if (const Result r = wait(); !r.ok())
            return r;
    }
}

void SftpBackend::Shell::closeChannel()
{
    // Closing ends a command that still runs (C-9): its output has nowhere
    // to go any more.
    // A channel the server refused must not be closed: libssh would send
    // the close to remote channel 0, which is the sftp channel.
    if (m_channel) {
        if (ssh_channel_is_open(m_channel))
            ssh_channel_close(m_channel);
        ssh_channel_free(m_channel);
        m_channel = nullptr;
    }
}

Result SftpBackend::Shell::run(const QByteArray &command, ExecResult *result)
{
    *result = ExecResult();
    const NonBlocking nonBlocking(m_b.m_session);
    Result r = open();
    if (r.ok())
        r = start(command);
    if (r.ok())
        r = collect(result);
    if (r.ok() && !result->truncated)
        r = exitStatus(result);
    if (r.ok() && m_b.m_canceled)
        r = canceled();
    closeChannel();
    return r;
}

// --- helpers over Shell -----------------------------------------------------------

class SftpBackend::Tools
{
public:
    explicit Tools(const SftpBackend &backend) : m_b(backend), m_q(backend) {}

    bool available() const { return m_b.m_sftp && m_b.m_shell; }
    Result run(const QList<QByteArray> &argv, const ExecOptions &options, ExecResult *result) const;
    Result checkCopyTarget(const QByteArray &source, const QByteArray &target, const CopyOptions &options) const;
    Result sha256(const QByteArray &remote, QByteArray *digest) const;
    Result find(const QByteArray &start, const QString &base, const QString &namePattern, int maxResults,
                QStringList *paths) const;

private:
    const SftpBackend &m_b;
    const Requests m_q;
};

Result SftpBackend::Tools::run(const QList<QByteArray> &argv, const ExecOptions &options, ExecResult *result) const
{
    return Shell(m_b, options).run(shellCommand(argv), result);
}

Result SftpBackend::Tools::checkCopyTarget(const QByteArray &source, const QByteArray &target,
                                           const CopyOptions &options) const
{
    // XC-17: like rename, a folder is never replaced and NoReplace refuses
    // anything that exists (a stat check: a documented race).
    Entry from;
    if (const Result r = m_q.statRemote(source, &from, false); !r.ok())
        return r;
    if (from.type == EntryType::Directory && !options.recursive)
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(display(source)));
    Entry to;
    const Result r = m_q.statRemote(target, &to, false);
    const bool refused = to.type == EntryType::Directory || options.mode == RenameMode::NoReplace
        || from.type == EntryType::Directory || source == target;
    if (r.ok() && refused)
        return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(display(target)));
    if (r.ok() || r.error() != Error::NotFound)
        return r;
    // cp would report a missing parent folder only in words.
    const int slash = target.lastIndexOf('/');
    return slash > 0 ? m_q.statRemote(target.left(slash), nullptr) : Result::success();
}

Result SftpBackend::Tools::sha256(const QByteArray &remote, QByteArray *digest) const
{
    // sha256sum, then shasum -a 256 (XS-9).
    QVector<QList<QByteArray>> commands;
    if (m_b.m_shellTools.sha256sum)
        commands.append(sha256sumCommand(remote));
    if (m_b.m_shellTools.shasum)
        commands.append(shasumCommand(remote));
    ExecOptions options;
    options.maxOutput = HelperOutputLimit;
    options.timeoutMs = 0;   // proportional to the data; cancel() ends it
    for (const QList<QByteArray> &command : commands) {
        ExecResult result;
        if (const Result r = run(command, options, &result); !r.ok())
            return r;
        if (QByteArray raw; result.exitStatus == 0 && !result.truncated && parseSha256Output(result.out, &raw)) {
            if (digest)
                *digest = raw;
            return Result::success();
        }
    }
    return Result(Error::Unsupported, QStringLiteral("The server's checksum output was not understood"));
}

Result SftpBackend::Tools::find(const QByteArray &start, const QString &base, const QString &namePattern,
                                int maxResults, QStringList *paths) const
{
    ExecOptions options;
    options.maxOutput = std::min(MaxFindOutput, FindBytesPerResult * (static_cast<qint64>(maxResults) + 1));
    options.timeoutMs = 0;   // cancel() ends a long search
    ExecResult result;
    const Result r = run(findCommand(start, Names::encode(namePattern)), options, &result);
    if (!r.ok())
        return r;
    // find exits 1 when it could not enter some folders; what it printed counts.
    QList<QByteArray> found;
    if (!parseFindOutput(result.out, start, result.truncated, maxResults, &found))
        return Result(Error::Unsupported, QStringLiteral("The server's find output was not understood"));
    for (const QByteArray &item : found) {
        QByteArray suffix = item.mid(start.size());
        while (suffix.startsWith('/'))
            suffix.remove(0, 1);
        paths->append(suffix.isEmpty() ? base : Paths::join(base, Names::decode(suffix)));
    }
    return Result::success();
}

// --- sign-in probe ------------------------------------------------------------

void SftpBackend::Connection::detectShell()
{
    m_b.m_shell = false;
    if (!m_b.m_params.flag(QLatin1String(AllowShellOption)))
        return;   // S-3 unchanged
    ExecOptions options;
    options.maxOutput = ProbeOutputLimit;
    ExecResult result;
    const Result r = Shell(m_b, options).run(probeCommand(), &result);
    m_b.m_shell = r.ok() && result.exitStatus == 0 && !result.truncated && parseProbe(result.out, &m_b.m_shellTools);
    qCDebug(lcNetVfsSftp) << "Shell probe" << r.toString() << "exit" << result.exitStatus << "usable" << m_b.m_shell
                          << "cp" << m_b.m_shellTools.cp << "sha256sum" << m_b.m_shellTools.sha256sum
                          << "shasum" << m_b.m_shellTools.shasum << "find" << m_b.m_shellTools.find;
}

// --- ShellExec and the API calls served through it ------------------------------------

Result SftpBackend::exec(const QStringList &argv, const ExecOptions &options, ExecResult *result)
{
    const Tools tools(*this);
    Result r = Requests(*this).checkReady();
    if (r.ok() && !tools.available())
        return Result(Error::Unsupported, QStringLiteral("Running commands is not enabled for this account"));
    if (!r.ok())
        return r;
    if (argv.isEmpty() || !result || options.maxOutput < 0)
        return Result(Error::Internal, QStringLiteral("Invalid command"));
    QList<QByteArray> words;
    for (const QString &word : argv) {
        if (word.contains(QChar(0)) || !Names::isEncodable(word))
            return Result(Error::InvalidName, QStringLiteral("A command argument cannot be sent to the server"));
        words.append(Names::encode(word));
    }
    return tools.run(words, options, result);
}

Result SftpBackend::find(const QString &dir, const QString &namePattern, int maxResults, QStringList *paths)
{
    const Requests q(*this);
    QByteArray remote;
    Result r = q.checkReady();
    if (r.ok() && !(Tools(*this).available() && m_shellTools.find))
        return Result(Error::Unsupported, QStringLiteral("Searching on the server is not available"));
    QString base;
    if (r.ok())
        r = Paths::normalize(dir, &base);
    if (r.ok())
        r = q.resolve(dir, &remote);
    Entry entry;
    if (r.ok())
        r = q.statRemote(remote, &entry);
    if (!r.ok())
        return r;
    if (!entry.isDir())
        return Result(Error::NotADirectory, QStringLiteral("%1 is not a folder").arg(display(remote)));
    if (namePattern.isEmpty() || namePattern.contains(QChar(0)) || !Names::isEncodable(namePattern))
        return Result(Error::InvalidName, QStringLiteral("Invalid search pattern"));
    paths->clear();
    if (maxResults <= 0)
        return Result::success();
    // An absolute start cannot be taken for an option or an expression.
    const QByteArray start = remote.startsWith('/') ? remote : QByteArray("./") + remote;
    return Tools(*this).find(start, base, namePattern, maxResults, paths);
}

Result SftpBackend::copy(const QString &from, const QString &to, const CopyOptions &options)
{
    const Requests q(*this);
    const Tools tools(*this);
    QByteArray source;
    QByteArray target;
    Result r = q.checkReady();
    if (r.ok() && !(tools.available() && m_shellTools.cp))
        return Result(Error::Unsupported, QStringLiteral("The server cannot copy files"));
    if (r.ok())
        r = q.resolve(from, &source);
    if (r.ok())
        r = q.resolve(to, &target);
    if (r.ok())
        r = tools.checkCopyTarget(source, target, options);
    if (!r.ok())
        return r;
    ExecOptions exec;
    exec.maxOutput = HelperOutputLimit;
    exec.timeoutMs = 0;   // proportional to the data; cancel() ends it
    ExecResult result;
    r = tools.run(copyCommand(source, target, options.recursive), exec, &result);
    if (r.ok() && result.exitStatus != 0)
        r = commandFailed("cp", result);
    return r;
}

Result SftpBackend::checksum(const QString &path, const QString &algorithm, QByteArray *digest)
{
    const Requests q(*this);
    Result r = q.checkReady();
    if (r.ok() && !m_capabilities.checksumAlgorithms.contains(algorithm))
        return Result(Error::Unsupported, QStringLiteral("The server cannot compute %1 checksums").arg(algorithm));
    QByteArray remote;
    if (r.ok())
        r = q.resolve(path, &remote);
    Entry entry;
    if (r.ok())
        r = q.statRemote(remote, &entry);
    if (!r.ok())
        return r;
    if (entry.type == EntryType::Directory)
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(display(remote)));
    return Tools(*this).sha256(remote, digest);
}

} // namespace NetVfs::Sftp
