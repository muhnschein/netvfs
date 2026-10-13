// SPDX-License-Identifier: LGPL-2.1-or-later
// Tree operations over src/core/ops.h (XH-2, XH-3, XH-5): the adapters the
// C++ bridge had in sessionjobs.cpp, with the C callbacks in place of its
// batches and progress signals.
#include "ffi_p.h"

#include <stdexcept>

namespace NetVfs::Ffi {

namespace {

// Design §1.2: visit() per entry; listFailed() goes on unless
// stop_on_list_error (the bridge skips unreadable sub-folders).
class WalkAdapter final : public Ops::WalkVisitor
{
public:
    WalkAdapter(nvb_walk_visit_fn visit, void *ctx, bool stopOnListError)
        : m_visit(visit), m_ctx(ctx), m_stopOnListError(stopOnListError)
    {
    }

    bool visit(const QString &path, const Entry &entry, int, bool *) override
    {
        HoldArena arena;
        nvb_entry item {};
        fillEntry(arena, &item, entry);
        return m_visit(m_ctx, arena.bytes(Names::encode(path)), &item) != 0;
    }

    bool listFailed(const QString &, const Result &) override { return !m_stopOnListError; }

private:
    nvb_walk_visit_fn m_visit;
    void *m_ctx;
    bool m_stopOnListError;
};

Ops::WalkOptions walkOptionsOf(const nvb_walk_opts *opts)
{
    Ops::WalkOptions options;
    if (!opts)
        return options;
    // §6.9: postOrder is a no-op on the wire (leave() is not reported).
    options.postOrder = opts->post_order != 0;
    options.maxDepth = opts->max_depth;
    options.symlinks = opts->follow_symlinks ? Ops::SymlinkPolicy::Follow : Ops::SymlinkPolicy::Never;
    return options;
}

} // namespace

nvb_error *removeTree(nvb_conn *conn, nvb_bytes path, const nvb_progress *progress, int64_t *files,
                      int64_t *dirs) noexcept
{
    return guarded([conn, path, progress, files, dirs]() {
        Backend *backend = backendOf(conn);
        ProgressAdapter adapter(progress);
        Ops::TreeCounts counts;
        const Result r = Ops::removeTree(backend, toPath(path), &adapter, Ops::RemoveTreeOptions(), &counts);
        if (files)
            *files = counts.files;
        if (dirs)
            *dirs = counts.dirs;
        return r;
    });
}

nvb_error *walk(nvb_conn *conn, nvb_bytes root, const nvb_walk_opts *opts, nvb_walk_visit_fn visit,
                void *ctx) noexcept
{
    return guarded([conn, root, opts, visit, ctx]() {
        Backend *backend = backendOf(conn);
        if (!visit)
            throw std::invalid_argument("no visitor");
        WalkAdapter visitor(visit, ctx, opts && opts->stop_on_list_error);
        return Ops::walk(backend, toPath(root), &visitor, walkOptionsOf(opts));
    });
}

// T5: both connections belong to the calling thread.
nvb_error *copyAcross(nvb_conn *source, nvb_bytes sourcePath, nvb_conn *destination, nvb_bytes destinationPath,
                      int32_t recursive, int32_t replace, const nvb_progress *progress) noexcept
{
    return guarded([source, sourcePath, destination, destinationPath, recursive, replace, progress]() {
        Backend *from = backendOf(source);
        Backend *to = backendOf(destination);
        Ops::CopyAcrossOptions options;
        options.recursive = recursive != 0;
        options.mode = replace ? RenameMode::Replace : RenameMode::NoReplace;
        ProgressAdapter adapter(progress);
        return Ops::copyAcross(from, toPath(sourcePath), to, toPath(destinationPath), options, &adapter);
    });
}

} // namespace NetVfs::Ffi
