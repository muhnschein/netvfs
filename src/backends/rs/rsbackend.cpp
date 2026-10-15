// SPDX-License-Identifier: LGPL-2.1-or-later
#include "rsbackend.h"
#include "rshandles.h"
#include "rshooks.h"
#include "rsloader.h"
#include "rsmarshal.h"

#include <QtCore/QIODevice>

#include <memory>

namespace NetVfs::Rs {

Result createBackend(const QString &provider, Backend **out)
{
    *out = nullptr;
    Result r;
    const nvr_table *t = table(&r);
    if (!t)
        return r;
    const QByteArray name = provider.toUtf8();
    nvr_conn *conn = nullptr;
    r = resultOf(t, t->conn_new(view(name), &conn));
    if (r.ok())
        *out = std::make_unique<RsBackend>(t, conn).release();   // the caller owns it
    return r;
}

RsBackend::~RsBackend()
{
    m_t->conn_free(m_conn);
}

template <typename Call>
Result RsBackend::onPath(const QString &path, const Call &call) const
{
    QByteArray bytes;
    if (Result r = encodePath(path, &bytes); !r.ok())
        return r;
    return resultOf(m_t, call(view(bytes)));
}

template <typename Call>
Result RsBackend::onPaths(const QString &first, const QString &second, const Call &call) const
{
    QByteArray a;
    QByteArray b;
    if (Result r = encodePath(first, &a); !r.ok())
        return r;
    if (Result r = encodePath(second, &b); !r.ok())
        return r;
    return resultOf(m_t, call(view(a), view(b)));
}

// ---- connection

Result RsBackend::connect(const ConnectionParams &params, ServerIdentity *seen)
{
    Ffi::HoldArena arena;
    const nvb_params p = paramsOf(arena, params);
    m_domain = params.option(QStringLiteral("domain"));
    nvb_identity *raw = nullptr;
    const Result r = resultOf(m_t, m_t->connect(m_conn, &p, &raw));
    const Block<nvb_identity> identity(raw, Free(m_t));
    if (seen)
        *seen = identity ? identityOf(*identity) : ServerIdentity();
    return r;
}

Result RsBackend::authenticate(const Credentials &credentials, AuthPrompter *prompter)
{
    const QByteArray user = credentials.userName.toUtf8();
    const QByteArray domain = m_domain.toUtf8();
    const nvr_credentials c { view(user), view(credentials.secret), view(domain) };
    Hooks hooks(m_t);
    const nvr_prompter *hook = hooks.prompter(prompter);
    {
        const std::scoped_lock lock(m_prompterMutex);
        m_prompter = prompter;
    }
    const Result r = hooks.result(resultOf(m_t, m_t->authenticate(m_conn, &c, hook)));
    {
        const std::scoped_lock lock(m_prompterMutex);
        m_prompter = nullptr;
    }
    // XC-5: from now on the capabilities stay as they are.
    m_authenticated = r.ok() && fetchCapabilities(&m_capabilities).ok();
    return r;
}

Result RsBackend::fetchCapabilities(Capabilities *out) const
{
    nvb_capabilities *raw = nullptr;
    const Result r = resultOf(m_t, m_t->capabilities(m_conn, &raw));
    const Block<nvb_capabilities> block(raw, Free(m_t));
    *out = block ? capabilitiesOf(*block) : Capabilities();
    return r;
}

Capabilities RsBackend::capabilities() const
{
    if (m_authenticated)
        return m_capabilities;
    Capabilities now;
    fetchCapabilities(&now);
    return now;
}

Result RsBackend::keepAlive()
{
    return resultOf(m_t, m_t->keep_alive(m_conn));
}

void RsBackend::cancel()
{
    m_t->cancel(m_conn);
    const std::scoped_lock lock(m_prompterMutex);
    if (m_prompter)
        m_prompter->cancel();
}

void RsBackend::resetCancel()
{
    m_t->reset_cancel(m_conn);
}

void RsBackend::disconnect()
{
    m_t->disconnect(m_conn);
}

// ---- metadata and namespace

Result RsBackend::statWith(const QString &path, bool follow, Entry *out)
{
    nvb_entry *raw = nullptr;
    const Result r = onPath(path, [this, follow, &raw](nvb_bytes p) {
        return m_t->stat(m_conn, p, follow ? 1 : 0, &raw);
    });
    const Block<nvb_entry> entry(raw, Free(m_t));
    if (out)
        *out = entry ? entryOf(*entry) : Entry();
    return r;
}

Result RsBackend::stat(const QString &path, Entry *out)
{
    return statWith(path, true, out);
}

Result RsBackend::lstat(const QString &path, Entry *out)
{
    return statWith(path, false, out);
}

Result RsBackend::list(const QString &dir, ListSink *sink, const ListOptions &options)
{
    if (!sink)
        return Result(Error::Internal, QStringLiteral("No listing sink"));
    Hooks hooks(m_t);
    const nvb_list_sink_fn batch = hooks.list(sink);
    return hooks.result(onPath(dir, [this, &options, batch, &hooks](nvb_bytes p) {
        return m_t->list(m_conn, p, static_cast<uint32_t>(qMax(1, options.batchSize)),
                         options.resolveSymlinkTypes ? 1 : 0, batch, &hooks);
    }));
}

Result RsBackend::makeDir(const QString &path, bool exclusive)
{
    return onPath(path, [this, exclusive](nvb_bytes p) { return m_t->make_dir(m_conn, p, exclusive ? 1 : 0); });
}

Result RsBackend::removeFile(const QString &path)
{
    return onPath(path, [this](nvb_bytes p) { return m_t->remove_file(m_conn, p); });
}

Result RsBackend::removeDir(const QString &path)
{
    return onPath(path, [this](nvb_bytes p) { return m_t->remove_dir(m_conn, p); });
}

Result RsBackend::rename(const QString &from, const QString &to, RenameMode mode)
{
    return onPaths(from, to, [this, mode](nvb_bytes a, nvb_bytes b) {
        return m_t->rename(m_conn, a, b, mode == RenameMode::Replace ? 1 : 0);
    });
}

Result RsBackend::setAttributes(const QString &path, const AttributeChanges &changes)
{
    const nvb_attributes a = attributesOf(changes);
    return onPath(path, [this, &a](nvb_bytes p) { return m_t->set_attributes(m_conn, p, &a); });
}

Result RsBackend::readLink(const QString &path, QString *target)
{
    nvb_blob *raw = nullptr;
    const Result r = onPath(path, [this, &raw](nvb_bytes p) { return m_t->read_link(m_conn, p, &raw); });
    const Block<nvb_blob> link(raw, Free(m_t));
    if (target)
        *target = link ? Names::decode(Ffi::toByteArray(link->data)) : QString();
    return r;
}

// XC-12: the target goes verbatim, as the bytes of its name.
Result RsBackend::makeSymlink(const QString &target, const QString &linkPath)
{
    return onPaths(target, linkPath,
                   [this](nvb_bytes a, nvb_bytes b) { return m_t->make_symlink(m_conn, a, b); });
}

Result RsBackend::makeHardlink(const QString &existing, const QString &newPath)
{
    return onPaths(existing, newPath,
                   [this](nvb_bytes a, nvb_bytes b) { return m_t->make_hardlink(m_conn, a, b); });
}

Result RsBackend::copy(const QString &from, const QString &to, const CopyOptions &options)
{
    return onPaths(from, to, [this, &options](nvb_bytes a, nvb_bytes b) {
        return m_t->copy(m_conn, a, b, options.recursive ? 1 : 0, options.mode == RenameMode::Replace ? 1 : 0);
    });
}

Result RsBackend::checksum(const QString &path, const QString &algorithm, QByteArray *digest)
{
    const QByteArray name = algorithm.toUtf8();
    nvb_blob *raw = nullptr;
    const Result r = onPath(path, [this, &name, &raw](nvb_bytes p) {
        return m_t->checksum(m_conn, p, view(name), &raw);
    });
    const Block<nvb_blob> sum(raw, Free(m_t));
    if (digest)
        *digest = sum ? Ffi::toByteArray(sum->data) : QByteArray();
    return r;
}

Result RsBackend::spaceInfo(const QString &dir, SpaceInfo *out)
{
    nvb_space space { -1, -1, -1 };
    const Result r = onPath(dir, [this, &space](nvb_bytes p) { return m_t->space_info(m_conn, p, &space); });
    if (out)
        *out = SpaceInfo { space.free_bytes, space.total_bytes, space.used_bytes };
    return r;
}

// ---- handles and transfers

Result RsBackend::openRead(const QString &path, ReadHandle **out)
{
    nvr_read *raw = nullptr;
    int64_t size = -1;
    const Result r = onPath(path, [this, &raw, &size](nvb_bytes p) { return m_t->open_read(m_conn, p, &raw, &size); });
    auto handle = raw ? std::make_unique<RsReadHandle>(m_t, raw, size) : nullptr;
    if (out)
        *out = handle.release();   // the caller owns it
    return r;
}

Result RsBackend::openWrite(const QString &path, const WriteOptions &options, WriteHandle **out)
{
    const nvr_write_opts o = writeOptionsOf(options);
    nvr_write *raw = nullptr;
    const Result r = onPath(path, [this, &o, &raw](nvb_bytes p) { return m_t->open_write(m_conn, p, &o, &raw); });
    auto handle = raw ? std::make_unique<RsWriteHandle>(m_t, raw) : nullptr;
    if (out)
        *out = handle.release();   // the caller owns it
    return r;
}

Result RsBackend::upload(QIODevice *source, const QString &path, const UploadOptions &options, Progress *progress)
{
    if (!source)
        return Result(Error::Internal, QStringLiteral("No source"));
    Hooks hooks(m_t);
    const nvb_upload_opts o = uploadOptionsOf(options.write);
    const nvb_io *io = hooks.source(source);
    const nvb_progress *watch = hooks.progress(progress);
    return hooks.result(onPath(path, [this, &o, io, watch](nvb_bytes p) {
        return m_t->upload(m_conn, p, &o, io, watch);
    }));
}

Result RsBackend::download(const QString &path, QIODevice *sink, const DownloadOptions &options, Progress *progress)
{
    if (!sink)
        return Result(Error::Internal, QStringLiteral("No sink"));
    Hooks hooks(m_t);
    const nvb_io *io = hooks.sink(sink);
    const nvb_progress *watch = hooks.progress(progress);
    return hooks.result(onPath(path, [this, &options, io, watch](nvb_bytes p) {
        return m_t->download(m_conn, p, options.offset, options.length, io, watch);
    }));
}

} // namespace NetVfs::Rs
