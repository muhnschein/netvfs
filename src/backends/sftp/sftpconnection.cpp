// SPDX-License-Identifier: LGPL-2.1-or-later
// Connection set-up, capabilities and teardown (SPEC-sftp S-1..S-7, S-19,
// S-21, S-22; SPEC-v2 XC-5, XS-2, XS-4, XS-6).
#include "logging.h"
#include "sftpinternal.h"
#include "sshutil.h"

namespace NetVfs::Sftp {

namespace {

constexpr const char *HostKeyOption = "host_key";
constexpr const char *UsersGroupsExtension = "users-groups-by-id@openssh.com";
constexpr const char *NullDevice = "/dev/null";
constexpr int DefaultPort = 22;
constexpr int DefaultConnectTimeoutMs = 15000;   // C-14
constexpr int DefaultRequestTimeoutMs = 60000;   // C-14

bool supported(sftp_session sftp, const char *extension, const char *version)
{
    return sftp_extension_supported(sftp, extension, version) != 0;
}

// A one-entry id map for users-groups-by-id@openssh.com.
sftp_name_id_map single(uint32_t id)
{
    sftp_name_id_map map = sftp_name_id_map_new(1);
    if (map)
        map->ids[0] = id;
    return map;
}

} // namespace

Result SftpBackend::Connection::open(const ConnectionParams &params, ServerIdentity *seen)
{
    close();
    if (m_b.m_canceled)
        return canceled();
    if (params.host.isEmpty() || params.host.contains(QLatin1Char('@')))
        return Result(Error::Internal, QStringLiteral("Invalid server name"));
    ensureLibraryInitialized();

    m_b.m_params = params;
    if (m_b.m_params.connectTimeoutMs <= 0)
        m_b.m_params.connectTimeoutMs = DefaultConnectTimeoutMs;
    if (m_b.m_params.requestTimeoutMs <= 0)
        m_b.m_params.requestTimeoutMs = DefaultRequestTimeoutMs;

    const bool pinned = !params.option(QLatin1String(HostKeyOption)).isEmpty();
    Result r = openTransport(pinned, seen);
    if (!r.ok() && pinned && isHostKeyMismatch(r.message())) {
        // The server no longer offers the pinned key type (S-5). Connect once
        // more without the restriction, so that the caller sees the key the
        // server presents now and reports ServerIdentityChanged (S-7).
        close();
        r = openTransport(false, seen);
    }
    if (r.ok() && m_b.m_canceled)
        r = canceled();
    if (!r.ok())
        close();
    return r;
}

Result SftpBackend::Connection::openTransport(bool restrictHostKey, ServerIdentity *seen)
{
    m_b.m_session = ssh_new();
    if (!m_b.m_session)
        return Result(Error::Internal, QStringLiteral("Out of memory"));
    if (const Result r = applyOptions(restrictHostKey); !r.ok())
        return r;
    m_b.configureSession(m_b.m_session);

    qCDebug(lcNetVfsSftp) << "Connecting to" << m_b.m_params.host << "port" << m_b.m_params.port;
    // S-3: no ssh_session_is_known_server(); the caller compares the pin.
    if (ErrorTrail trail; ssh_connect(m_b.m_session) != SSH_OK)
        return connectFailure(trail.explain(text(ssh_get_error(m_b.m_session))));

    ssh_key key = nullptr;
    if (ssh_get_server_publickey(m_b.m_session, &key) != SSH_OK)
        return Requests(m_b).sessionFailure();
    const KeyPtr serverKey(key);
    const ServerIdentity identity = identityOf(serverKey.get());
    if (seen)
        *seen = identity;
    // SEC-1: even a caller that skips the identity check cannot sign in to a
    // server whose key differs from the pin.
    const QString pin = m_b.m_params.option(QLatin1String(HostKeyOption));
    m_b.m_identityMismatch = !pin.isEmpty() && ServerIdentity::fromPin(pin) != identity;

    qCDebug(lcNetVfsSftp) << "Key exchange" << ssh_get_kex_algo(m_b.m_session)
                          << "cipher" << ssh_get_cipher_out(m_b.m_session)
                          << "host key" << identity.algorithm << identity.fingerprint
                          << "banner" << text(ssh_get_serverbanner(m_b.m_session));
    return Result::success();
}

Result SftpBackend::Connection::applyOptions(bool restrictHostKey) const
{
    // S-1. Algorithm lists stay at libssh defaults (S-2); S-5 only narrows
    // the host key algorithms to the pinned type.
    ssh_session session = m_b.m_session;
    const ConnectionParams &params = m_b.m_params;
    const bool processConfig = false;
    const int port = params.port > 0 ? params.port : DefaultPort;
    const QByteArray host = params.host.toUtf8();
    const QByteArray user = params.username.toUtf8();
    bool ok = ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &processConfig) == SSH_OK
            && ssh_options_set(session, SSH_OPTIONS_HOST, host.constData()) == SSH_OK
            && ssh_options_set(session, SSH_OPTIONS_PORT, &port) == SSH_OK
            && ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, NullDevice) == SSH_OK
            && ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, NullDevice) == SSH_OK
            && ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "no") == SSH_OK
            && Requests(m_b).setTimeout(params.connectTimeoutMs);
    if (ok && !user.isEmpty())
        ok = ssh_options_set(session, SSH_OPTIONS_USER, user.constData()) == SSH_OK;
    if (ok && restrictHostKey) {
        const ServerIdentity pinned = ServerIdentity::fromPin(params.option(QLatin1String(HostKeyOption)));
        if (const QByteArray algorithms = hostKeyAlgorithmsFor(pinned.algorithm); !algorithms.isEmpty())
            ok = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, algorithms.constData()) == SSH_OK;
    }
    if (!ok)
        return Result(Error::Internal, QStringLiteral("Cannot apply connection settings: %1")
                                           .arg(text(ssh_get_error(session))));
    return Result::success();
}

void SftpBackend::Connection::close()
{
    invalidateHandles();   // XC-13: open handles end with the connection
    if (m_b.m_sftp) {
        sftp_free(m_b.m_sftp);
        m_b.m_sftp = nullptr;
    }
    if (m_b.m_session) {
        if (ssh_is_connected(m_b.m_session))
            ssh_disconnect(m_b.m_session);
        ssh_free(m_b.m_session);
        m_b.m_session = nullptr;
    }
    m_b.m_home.clear();
    m_b.m_identityMismatch = false;
    m_b.m_features = ServerFeatures();
    m_b.m_symlinkOrder = SymlinkOrder::Unverified;
    m_b.m_shell = false;
    m_b.m_shellTools = ShellTools();
    {
        const std::scoped_lock lock(m_b.m_namesMutex);
        m_b.m_userNames.clear();
        m_b.m_groupNames.clear();
    }
    m_b.m_capabilities = Capabilities();
}

void SftpBackend::Connection::setPrompter(AuthPrompter *prompter)
{
    const std::scoped_lock lock(m_b.m_prompterMutex);
    m_b.m_prompter = prompter;
}

int SftpBackend::Connection::interrupted(const sftp_interrupt_struct *interrupt)
{
    // libssh asks this every 100 ms while a blocking sftp call waits for its
    // response (vendor/patches/libssh/0002): cancel() ends the wait (C-9).
    return *interrupt->canceled ? 1 : 0;
}

Result SftpBackend::Connection::openSftp()
{
    // S-3: the sftp subsystem; an exec channel only for XS-9 (detectShell()).
    m_b.m_sftp = sftp_new(m_b.m_session);
    if (!m_b.m_sftp) {
        const QString message = text(ssh_get_error(m_b.m_session));
        if (message.contains(QLatin1String("Channel opening failure")))
            return channelOpenFailure(message);   // XC-21
        return subsystemFailure(ssh_get_error_code(m_b.m_session) == SSH_REQUEST_DENIED, SSH_FX_OK, message);
    }
    if (sftp_init(m_b.m_sftp) != SSH_OK) {
        const Result r = subsystemFailure(false, sftp_get_error(m_b.m_sftp), text(ssh_get_error(m_b.m_session)));
        sftp_free(m_b.m_sftp);
        m_b.m_sftp = nullptr;
        return r;
    }
    sftp_set_interrupt_callback(m_b.m_sftp, &Connection::interrupted, &m_b.m_interrupt);

    m_b.m_features.fsync = supported(m_b.m_sftp, "fsync@openssh.com", "1");
    m_b.m_features.statvfs = supported(m_b.m_sftp, "statvfs@openssh.com", "2");
    m_b.m_features.posixRename = supported(m_b.m_sftp, "posix-rename@openssh.com", "1");
    m_b.m_features.hardlink = supported(m_b.m_sftp, "hardlink@openssh.com", "1");
    const bool hasLimits = supported(m_b.m_sftp, "limits@openssh.com", "1");
    uint64_t writeLimit = 0;
    uint64_t readLimit = 0;
    if (sftp_limits_t limits = hasLimits ? sftp_limits(m_b.m_sftp) : nullptr) {
        writeLimit = limits->max_write_length;
        readLimit = limits->max_read_length;
        sftp_limits_free(limits);
    }
    m_b.m_chunks.write = chunkSize(hasLimits, writeLimit);   // S-21
    m_b.m_chunks.read = chunkSize(hasLimits, readLimit);

    // S-19: relative paths are relative to the start directory, resolved once.
    char *home = sftp_canonicalize_path(m_b.m_sftp, ".");
    m_b.m_home = home ? QByteArray(home) : QByteArray();
    ssh_string_free_char(home);
    detectOwnership();
    detectShell();
    detectCapabilities();

    qCDebug(lcNetVfsSftp) << "SFTP version" << sftp_server_version(m_b.m_sftp) << "fsync" << m_b.m_features.fsync
                          << "statvfs" << m_b.m_features.statvfs << "posix-rename" << m_b.m_features.posixRename
                          << "hardlink" << m_b.m_features.hardlink << "users-groups" << m_b.m_features.usersGroups
                          << "shell" << m_b.m_shell << "chunk" << m_b.m_chunks.write << m_b.m_chunks.read
                          << "start" << m_b.m_home;
    return Result::success();
}

void SftpBackend::Connection::detectOwnership()
{
    // XS-2: Ownership only when users-groups-by-id@openssh.com answers; the
    // start directory's owner is the first name in the cache.
    m_b.m_features.usersGroups = false;
    if (!supported(m_b.m_sftp, UsersGroupsExtension, "1"))
        return;
    sftp_attributes attributes = sftp_stat(m_b.m_sftp, m_b.m_home.isEmpty() ? "." : m_b.m_home.constData());
    if (!attributes)
        return;
    sftp_name_id_map users = single(attributes->uid);
    sftp_name_id_map groups = single(attributes->gid);
    sftp_attributes_free(attributes);
    m_b.m_features.usersGroups = users && groups && sftp_get_users_groups_by_id(m_b.m_sftp, users, groups) == 0;
    if (m_b.m_features.usersGroups) {
        const std::scoped_lock lock(m_b.m_namesMutex);
        m_b.m_userNames.insert(users->ids[0], text(users->names[0]));
        m_b.m_groupNames.insert(groups->ids[0], text(groups->names[0]));
    }
    sftp_name_id_map_free(users);
    sftp_name_id_map_free(groups);
}

void SftpBackend::Connection::detectCapabilities()
{
    // XC-5: only what this backend implements and the interop suite tests.
    const bool openSsh = ssh_get_openssh_version(m_b.m_session) > 0;
    m_b.m_features.nativeNoReplace = openSsh;   // XS-6, by banner
    const QString banner = text(ssh_get_serverbanner(m_b.m_session));
    m_b.m_symlinkOrder = symlinkOrderFor(banner, openSsh);   // XS-4
    m_b.m_features.lstatFollows = lstatFollowsLinks(banner);
    Capabilities &caps = m_b.m_capabilities;
    caps = Capabilities();
    // XS-5, XS-7
    caps.flags << Capability::ReadHandles << Capability::EfficientRanges << Capability::WriteResume
               << Capability::PosixModes << Capability::SetModified << Capability::SetModifiedOnUpload;
    if (m_b.m_symlinkOrder != SymlinkOrder::Unverified)
        caps.flags << Capability::Symlinks;
    if (m_b.m_features.hardlink)
        caps.flags << Capability::Hardlinks;
    if (m_b.m_features.usersGroups)
        caps.flags << Capability::Ownership;
    if (m_b.m_features.statvfs)
        caps.flags << Capability::SpaceInfo;
    if (m_b.m_features.posixRename)
        caps.flags << Capability::AtomicReplace;
    if (m_b.m_features.nativeNoReplace)
        caps.flags << Capability::NativeNoReplace;
    // XS-9. XS-10: OpenSSH's copy-data extension would serve ServerCopy
    // without a shell, but libssh 0.12.2 does not expose it; switch to it
    // once upstream does (tracked against libssh), keeping the shell as the
    // fallback.
    if (m_b.m_shell) {
        caps.flags << Capability::ShellExec;
        if (m_b.m_shellTools.cp)
            caps.flags << Capability::ServerCopy << Capability::ServerCopyRecursive;
        if (m_b.m_shellTools.sha256sum || m_b.m_shellTools.shasum) {
            caps.flags << Capability::Checksums;
            caps.checksumAlgorithms << QStringLiteral("sha256");
        }
    }
    caps.maxReadChunk = static_cast<qint64>(m_b.m_chunks.read);
    caps.maxWriteChunk = static_cast<qint64>(m_b.m_chunks.write);
}

} // namespace NetVfs::Sftp
