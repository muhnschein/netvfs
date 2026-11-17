// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ffi_p.h"

#include <functional>
#include <stdexcept>

namespace NetVfs::Ffi {

namespace {

// visit() per entry; listFailed() goes on unless stop_on_list_error (unreadable sub-folders are
// skipped).
class WalkAdapter final : public Ops::WalkVisitor
{
public:
    using Visit = std::function<bool(nvb_bytes path, const nvb_entry *entry)>;

    WalkAdapter(Visit visit, bool stopOnListError) : m_visit(std::move(visit)), m_stopOnListError(stopOnListError) {}

    bool visit(const QString &path, const Entry &entry, int, bool *) override
    {
        HoldArena arena;
        nvb_entry item {};
        fillEntry(arena, &item, entry);
        return m_visit(arena.bytes(Names::encode(path)), &item);
    }

    bool listFailed(const QString &, const Result &) override { return !m_stopOnListError; }

private:
    Visit m_visit;
    bool m_stopOnListError;
};

Ops::WalkOptions walkOptionsOf(const nvb_walk_opts *opts)
{
    Ops::WalkOptions options;
    if (!opts)
        return options;
    // postOrder is a no-op on the wire (leave() is not reported).
    options.postOrder = opts->post_order != 0;
    options.maxDepth = opts->max_depth;
    options.symlinks = opts->follow_symlinks ? Ops::SymlinkPolicy::Follow : Ops::SymlinkPolicy::Never;
    return options;
}

}
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
        const auto callVisit = [visit, ctx](nvb_bytes path, const nvb_entry *entry) {
            return visit(ctx, path, entry) != 0;
        };
        WalkAdapter visitor(callVisit, opts && opts->stop_on_list_error);
        return Ops::walk(backend, toPath(root), &visitor, walkOptionsOf(opts));
    });
}

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

}