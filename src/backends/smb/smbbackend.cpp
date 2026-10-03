// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbbackend.h"
#include "smbfiles.h"
#include "smbhelper.h"
#include "smbops.h"
#include "smbsession.h"

#include "logging.h"
#include "paths.h"
#include "secure.h"

#include <QtCore/QIODevice>

#include <algorithm>

namespace NetVfs::Smb {

namespace {

const int DefaultPort = 445;
const char *const IpcShare = "IPC$";
const qint64 MaxNameBytes = 255;        // UTF-8 bytes; Samba on Linux file systems, NTFS in ASCII

Result invalidRange()
{
    return Result(Error::Internal, QStringLiteral("invalid range"));
}

// XM-2: what the root of server mode allows.
Result rootDenied(const QString &what)
{
    return Result(Error::PermissionDenied, QStringLiteral("%1: the server root holds only the shares").arg(what));
}

Result shareRootDenied(const QString &what)
{
    return Result(Error::PermissionDenied, QStringLiteral("%1: a share cannot be removed or renamed").arg(what));
}

Result stopped()
{
    return Result(Error::Canceled, QStringLiteral("The listing was stopped"));
}

} // namespace

SmbBackend::SmbBackend() = default;

SmbBackend::~SmbBackend()
{
    shutdown();
}

Result SmbBackend::connect(const ConnectionParams &params, ServerIdentity *seen)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    disconnect();
    // SMB has no server identity (SPEC-smb 3); signing keyed by the password
    // authenticates the server instead. XT-5 is vacuous here: nothing is
    // sent before authenticate(), which must send the credentials.
    if (seen)
        *seen = ServerIdentity();
    m_params = params;
    const int port = params.port > 0 ? params.port : DefaultPort;
    qCDebug(lcNetVfsSmb) << "Connecting to" << params.host << "port" << port;
    // M-10: only resolve and check that the port answers; the library call
    // needs the credentials and happens in authenticate().
    Result r = probeTcp(params.host, port, params.connectTimeoutMs, m_cancel, &m_address);
    m_probed = r.ok();
    return r;
}

Result SmbBackend::authenticate(const Credentials &credentials, AuthPrompter *prompter)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    Q_UNUSED(prompter)   // NTLMSSP has no interactive step
    if (!m_probed || m_main)
        return Result(Error::Internal, QStringLiteral("authenticate() needs a successful connect()"));
    // XM-1: the backend enforces the profile it is given; which profile a
    // service may use is AccountSession's decision (XA-4). XSEC-2: a
    // failure is never retried with a weaker one.
    if (Result r = profileFromOptions(m_params.options, &m_profile); !r.ok())
        return r;
    const bool guest = settingsFor(m_profile).guest;
    const QString share = m_params.option(QStringLiteral("share")).trimmed();
    m_serverMode = share.isEmpty();
    m_user = credentials.userName.isEmpty() ? m_params.username : credentials.userName;
    m_domain = m_params.option(QStringLiteral("domain"));
    if (!guest && (m_user.isEmpty() || credentials.secret.isEmpty()))
        return Result(Error::AuthFailed, QStringLiteral("A user name and a password are required"));
    if (guest)
        m_user.clear();

    auto session = std::make_unique<Session>(m_serverMode ? QLatin1String(IpcShare) : share, m_cancel,
                                             m_params.requestTimeoutMs, &m_gate);
    const Result r = session->signIn(serverString(m_address, m_params.port), m_profile, m_user, m_domain,
                                     credentials.secret);
    if (!r.ok())
        return r;
    m_main = std::move(session);
    // Server mode opens shares later with the same credentials (XM-2).
    if (m_serverMode && !guest)
        m_secret = credentials.secret;
    return r;
}

Result SmbBackend::checkSignedIn() const
{
    if (!m_main)
        return Result(Error::Internal, QStringLiteral("Not signed in"));
    return m_main->checkUsable();
}

bool SmbBackend::shareLevel(const QString &path) const
{
    QString share;
    QByteArray inside;
    return m_serverMode && splitServerPath(path, &share, &inside).ok() && inside.isEmpty();
}

bool SmbBackend::enumerationEnabled() const
{
    // XM-7: on by default in server mode; reported only with the helper.
    return m_serverMode && m_params.flag(QStringLiteral("share_enumeration"), true) && shareHelperInstalled();
}

Capabilities SmbBackend::capabilities() const
{
    // XC-5: what this backend implements and the interop suite tests.
    Capabilities caps;
    if (!m_main || !m_main->established())
        return caps;
    caps.flags << Capability::NativeNoReplace << Capability::AtomicReplace   // XM-5
               << Capability::ReadHandles << Capability::EfficientRanges     // XM-6
               << Capability::WriteResume << Capability::SetModified << Capability::SetModifiedOnUpload
               << Capability::SpaceInfo                                     // XM-8
               // XM-4, M-9. SMB clients treat every share as case-insensitive
               // (Windows does, Samba's default "case sensitive = auto" does
               // for clients without POSIX extensions); a consumer that
               // avoids names differing only in case is right on a
               // case-sensitive share too. FILE_CASE_SENSITIVE_SEARCH would
               // not tell: Samba reports it either way.
               << Capability::CaseInsensitive << Capability::WindowsNames;
    if (enumerationEnabled())
        caps.flags << Capability::ShareEnumeration;
    caps.maxNameBytes = MaxNameBytes;
    caps.maxReadChunk = m_main->readChunk();
    caps.maxWriteChunk = m_main->writeChunk();
    return caps;
}

// ----------------------------------------------------------- sessions (XM-2)

Result SmbBackend::evictOne()
{
    Session *oldest = nullptr;
    for (const auto &session : m_shares) {
        if (!session->hasFiles() && (!oldest || session->lastUse < oldest->lastUse))
            oldest = session.get();
    }
    if (!oldest) {
        return Result(Error::TooManyConnections,
                      QStringLiteral("Files are open on %1 shares already; close some first").arg(MaxShareSessions));
    }
    qCDebug(lcNetVfsSmb) << "Closing the least recently used share" << oldest->share();
    oldest->close();
    m_shares.erase(std::find_if(m_shares.begin(), m_shares.end(),
                                [oldest](const std::unique_ptr<Session> &s) { return s.get() == oldest; }));
    return Result::success();
}

Result SmbBackend::sessionFor(const QString &share, Session **out)
{
    for (auto it = m_shares.begin(); it != m_shares.end(); ++it) {
        if ((*it)->share().compare(share, Qt::CaseInsensitive) != 0)
            continue;
        // A broken context is replaced unless files still refer to it
        // (they, and it, answer ConnectionLost).
        if ((*it)->broken() && !(*it)->hasFiles()) {
            m_shares.erase(it);
            break;
        }
        (*it)->lastUse = ++m_useClock;
        *out = it->get();
        return Result::success();
    }
    if (static_cast<int>(m_shares.size()) >= MaxShareSessions) {
        if (Result r = evictOne(); !r.ok())
            return r;
    }
    auto session = std::make_unique<Session>(share, m_cancel, m_params.requestTimeoutMs, &m_gate);
    if (Result r = session->signIn(serverString(m_address, m_params.port), m_profile, m_user, m_domain, m_secret);
        !r.ok())
        return r;
    session->lastUse = ++m_useClock;
    *out = session.get();
    m_shares.push_back(std::move(session));
    return Result::success();
}

Result SmbBackend::locate(const QString &path, Location *out)
{
    // M-9: an invalid name is refused before anything else.
    const Result valid = m_serverMode ? splitServerPath(path, &out->share, &out->path) : translatePath(path, &out->path);
    if (!valid.ok())
        return valid;
    if (Result r = checkSignedIn(); !r.ok())
        return r;
    if (!m_serverMode) {
        out->session = m_main.get();
        return Result::success();
    }
    out->root = out->share.isEmpty();
    if (out->root)
        return Result::success();
    return sessionFor(out->share, &out->session);
}

// ------------------------------------------------------------ share list

Result SmbBackend::enumerateShares(QStringList *names, QVariantMap *remarks)
{
    ShareRequest request;
    request.server = serverString(m_address, m_params.port);
    request.user = m_user.toUtf8();
    request.domain = m_domain.toUtf8();
    request.profile = profileName(m_profile).toUtf8();
    request.requestTimeoutMs = m_params.requestTimeoutMs;
    request.secret = m_secret;
    QByteArray encoded = encodeShareRequest(request);
    secureWipe(request.secret);
    QVector<ShareInfo> found;
    const int timeoutMs = m_params.connectTimeoutMs + m_params.requestTimeoutMs;
    const Result r = runShareHelper(shareHelperPath(), &encoded, timeoutMs, m_cancel, &found);
    if (!r.ok())
        return r;
    const bool showAdmin = m_params.flag(QStringLiteral("show_admin_shares"), false);
    for (const ShareInfo &share : found) {
        if (!shareVisible(share, showAdmin))
            continue;
        names->append(share.name);
        if (!share.remark.isEmpty())
            remarks->insert(share.name.toLower(), share.remark);
    }
    return r;
}

Result SmbBackend::listRoot(ListSink *sink, const ListOptions &options)
{
    // XM-3: the shares the user saved, then what enumeration finds.
    QStringList names = configuredShares(m_params.options);
    QVariantMap remarks;
    if (enumerationEnabled()) {
        QStringList found;
        if (Result r = enumerateShares(&found, &remarks); !r.ok())
            return r;
        mergeShareNames(&names, found);
    }
    QVector<Entry> batch;
    const int batchSize = qMax(1, options.batchSize);
    for (const QString &name : names) {
        Entry entry;
        entry.name = name;
        entry.type = EntryType::Directory;
        if (const QVariant remark = remarks.value(name.toLower()); remark.isValid())
            entry.extra.insert(QStringLiteral("remark"), remark);
        batch.append(entry);
        if (batch.size() < batchSize)
            continue;
        if (m_cancel)
            return Result(Error::Canceled);
        if (!sink->entries(batch))
            return stopped();
        batch.clear();
    }
    if (!batch.isEmpty() && !sink->entries(batch))
        return stopped();
    return Result::success();
}

// ------------------------------------------------------------ namespace

Result SmbBackend::stat(const QString &path, Entry *out)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    Location at;
    if (Result r = locate(path, &at); !r.ok())
        return r;
    if (at.root) {
        // XM-2: the server root is a folder of shares.
        if (out) {
            *out = Entry();
            out->type = EntryType::Directory;
        }
        return Result::success();
    }
    const Result r = Ops::statPath(*at.session, at.path, out);
    if (r.ok() && out && at.path.isEmpty())
        out->name = at.share;
    return r;
}

Result SmbBackend::list(const QString &dir, ListSink *sink, const ListOptions &options)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    Location at;
    if (Result r = locate(dir, &at); !r.ok())
        return r;
    if (at.root)
        return listRoot(sink, options);
    return Ops::listPath(*at.session, at.path, sink, options);
}

Result SmbBackend::makeDir(const QString &path, bool exclusive)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    Location at;
    const Result r = locate(path, &at);
    // XM-2: a share that does not exist cannot be made.
    if (r.error() == Error::NotFound && m_serverMode && at.path.isEmpty())
        return rootDenied(QStringLiteral("create folder"));
    if (!r.ok())
        return r;
    if (at.root)
        return rootDenied(QStringLiteral("create folder"));
    if (at.path.isEmpty())   // the share root exists
        return exclusive ? Result(Error::AlreadyExists, QStringLiteral("create folder: the share root exists"))
                         : Result::success();
    return Ops::makeDirectory(*at.session, at.path, exclusive);
}

Result SmbBackend::removeFile(const QString &path)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    Location at;
    if (Result r = locate(path, &at); !r.ok())
        return r;
    if (at.root)
        return rootDenied(QStringLiteral("remove"));
    return Ops::removeFile(*at.session, at.path);
}

Result SmbBackend::removeDir(const QString &path)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    Location at;
    if (Result r = locate(path, &at); !r.ok())
        return r;
    if (at.root)
        return rootDenied(QStringLiteral("remove folder"));
    if (at.path.isEmpty())
        return shareRootDenied(QStringLiteral("remove folder"));
    return Ops::removeDirectory(*at.session, at.path);
}

Result SmbBackend::rename(const QString &from, const QString &to, RenameMode mode)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    // XM-2: the root and the shares themselves are refused before any
    // share is opened.
    if (shareLevel(from) || shareLevel(to))
        return shareRootDenied(QStringLiteral("rename"));
    Location source;
    Location target;
    Result r = locate(from, &source);
    if (r.ok())
        r = locate(to, &target);
    if (!r.ok())
        return r;
    if (source.path.isEmpty() || target.path.isEmpty())
        return shareRootDenied(QStringLiteral("rename"));
    if (source.session != target.session)
        return Result(Error::Unsupported, QStringLiteral("rename: SMB cannot move between shares"));
    if (mode == RenameMode::Replace)
        return Ops::renameReplacing(*source.session, source.path, target.path);
    // XM-5, XC-10: the server refuses an existing target (NativeNoReplace).
    return Ops::renamePath(*source.session, source.path, target.path);
}

Result SmbBackend::setAttributes(const QString &path, const AttributeChanges &changes)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    // XC-11: every field is checked before anything changes.
    if (changes.mode >= 0)
        return Result(Error::Unsupported, QStringLiteral("SMB has no permission bits"));
    if (!timeRepresentable(changes.modified) || !timeRepresentable(changes.accessed))
        return Result(Error::Unsupported, QStringLiteral("SMB stores times between 1970 and 30828 only"));
    Location at;
    if (Result r = locate(path, &at); !r.ok())
        return r;
    if (at.root)
        return rootDenied(QStringLiteral("set attributes"));
    if (changes.isEmpty())
        return Ops::statPath(*at.session, at.path, nullptr);
    return setTimes(*at.session, at.path, changes.modified, changes.accessed);
}

Result SmbBackend::spaceInfo(const QString &dir, SpaceInfo *out)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    Location at;
    if (Result r = locate(dir, &at); !r.ok())
        return r;
    if (at.root)
        return rootDenied(QStringLiteral("free space"));
    return Ops::spaceInfo(*at.session, at.path, out);
}

Result SmbBackend::keepAlive()
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    // XM-8: SMB2 ECHO, on IPC$ in server mode.
    if (Result r = checkSignedIn(); !r.ok())
        return r;
    return Ops::echo(*m_main);
}

// ------------------------------------------------------------- files (XM-6)

Result SmbBackend::openWrite(const QString &path, const WriteOptions &options, WriteHandle **out)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    *out = nullptr;
    if (options.disposition == WriteOptions::Disposition::Resume && options.resumeOffset < 0)
        return invalidRange();
    // XM-2: no files beside the shares ("/name" is a share, not a file).
    if (shareLevel(path))
        return rootDenied(QStringLiteral("open"));
    Location at;
    if (Result r = locate(path, &at); !r.ok())
        return r;
    smb2fh *fh = nullptr;
    const Result r = Ops::openForWrite(*at.session, at.path, options, &fh);
    if (r.ok()) {
        auto writer = std::make_unique<Writer>(at.session, fh, at.path, options);
        *out = writer.release();    // XC-13: the caller owns the handle
    }
    return r;
}

Result SmbBackend::upload(QIODevice *source, const QString &path, const UploadOptions &options, Progress *progress)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    WriteHandle *raw = nullptr;
    if (Result r = openWrite(path, options.write, &raw); !r.ok())
        return r;
    const std::unique_ptr<WriteHandle> writer(raw);
    const qint64 base = options.write.disposition == WriteOptions::Disposition::Resume ? options.write.resumeOffset : 0;
    if (Result r = Ops::writeAll(*m_main, source, writer.get(), progress, base); !r.ok()) {
        writer->abort();
        return r;
    }
    return writer->commit();
}

Result SmbBackend::openRead(const QString &path, ReadHandle **out)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    *out = nullptr;
    Location at;
    if (Result r = locate(path, &at); !r.ok())
        return r;
    if (at.root)
        return rootDenied(QStringLiteral("open"));
    smb2fh *fh = nullptr;
    qint64 size = -1;
    const Result r = Ops::openForRead(*at.session, at.path, &fh, &size);
    if (r.ok()) {
        auto reader = std::make_unique<Reader>(at.session, fh, size);
        *out = reader.release();    // XC-13: the caller owns the handle
    }
    return r;
}

Result SmbBackend::download(const QString &path, QIODevice *sink, const DownloadOptions &options, Progress *progress)
{
    const GateHold hold(&m_gate);     // M-13
    if (!hold.entered())
        return GateHold::busy();
    if (options.offset < 0 || options.length < -1)
        return invalidRange();
    Location at;
    if (Result r = locate(path, &at); !r.ok())
        return r;
    if (at.root)
        return rootDenied(QStringLiteral("download"));
    smb2fh *fh = nullptr;
    qint64 size = -1;
    if (Result r = Ops::openForRead(*at.session, at.path, &fh, &size); !r.ok())
        return r;
    Reader reader(at.session, fh, size);
    const qint64 known = qMax<qint64>(size, 0);
    const qint64 end = options.length < 0 ? known : qMin(known, options.offset + options.length);
    const Result r = Ops::copyToSink(*at.session, &reader, options.offset, end, sink, progress);
    return reader.closeWith(r);
}


// ------------------------------------------------------------- lifetime

void SmbBackend::cancel()
{
    m_cancel = true;
}

void SmbBackend::resetCancel()
{
    m_cancel = false;
}

void SmbBackend::disconnect()
{
    shutdown();
}

void SmbBackend::shutdown() noexcept
{
    // Called while another thread is inside only by a caller that breaks
    // C-8; the contexts go anyway, just without a graceful tree disconnect.
    const GateHold hold(&m_gate);
    // Every context of this instance: the shares, then IPC$ or the share.
    for (const auto &session : m_shares)
        session->close();
    m_shares.clear();
    if (m_main)
        m_main->close();
    m_main.reset();
    secureWipe(m_secret);
    m_secret.clear();
    m_probed = false;
}

} // namespace NetVfs::Smb
