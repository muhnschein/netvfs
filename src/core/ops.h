// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_OPS_H
#define NETVFS_OPS_H

#include "backend.h"

#include <QtCore/QSet>

// SPEC-v2 XH-2, XH-3, XH-5: tree operations built on Backend.
namespace NetVfs::Ops {

class TreeProgress
{
public:
    virtual ~TreeProgress() = default;
    // Called after each removed entry; return false to stop (Canceled).
    virtual bool removed(const QString &path, bool isDir, qint64 files, qint64 dirs)
    {
        Q_UNUSED(path) Q_UNUSED(isDir) Q_UNUSED(files) Q_UNUSED(dirs)
        return true;
    }
    // Called when removing `path` failed while continueOnError is set.
    virtual void failed(const QString &path, const Result &result) { Q_UNUSED(path) Q_UNUSED(result) }
};

struct RemoveTreeOptions {
    bool useNative = false;          // removeTreeNative() when RecursiveDelete is reported
    bool continueOnError = false;
};

struct TreeCounts {
    qint64 files = 0;                // non-directories, including symlinks
    qint64 dirs = 0;
    qint64 failed = 0;
};

// XH-2: depth-first, lists then deletes, never follows symlinks, honours
// cancel between entries, stops at the first error unless continueOnError
// (then returns the first error after visiting everything). Removing a
// non-directory removes just that entry.
NETVFS_EXPORT Result removeTree(Backend *backend, const QString &path, TreeProgress *progress = nullptr,
                                const RemoveTreeOptions &options = RemoveTreeOptions(),
                                TreeCounts *counts = nullptr);

enum class SymlinkPolicy { Never, Follow };

struct WalkOptions {
    bool preOrder = true;            // visit a folder before its children
    bool postOrder = false;          // visit a folder again after its children (leave())
    SymlinkPolicy symlinks = SymlinkPolicy::Never;
    int maxDepth = -1;               // -1 unlimited; 0: only the root's children
    int batchSize = 256;
};

class WalkVisitor
{
public:
    virtual ~WalkVisitor() = default;
    // `path` is the entry's full path, `depth` 0 for the root's children.
    // Return false to stop the walk (Canceled). For folders, set
    // `*descend = false` to skip the subtree.
    virtual bool visit(const QString &path, const Entry &entry, int depth, bool *descend) = 0;
    // Post-order callback for folders (WalkOptions::postOrder).
    virtual bool leave(const QString &path, const Entry &entry, int depth)
    {
        Q_UNUSED(path) Q_UNUSED(entry) Q_UNUSED(depth)
        return true;
    }
    // A sub-folder could not be listed; return false to stop with that error.
    virtual bool listFailed(const QString &path, const Result &result)
    {
        Q_UNUSED(path) Q_UNUSED(result)
        return false;
    }
};

// XH-3: streaming recursive traversal. With SymlinkPolicy::Follow, symlinked
// folders are descended into with loop detection by the set of resolved
// folder paths on the current branch (a loop is skipped, not an error).
NETVFS_EXPORT Result walk(Backend *backend, const QString &root, WalkVisitor *visitor,
                          const WalkOptions &options = WalkOptions());

struct CopyAcrossOptions {
    qint64 pipeCapacity = 4 << 20;   // BoundedPipe ring size (C-10)
    RenameMode mode = RenameMode::NoReplace;
    bool recursive = false;          // folders: walk + makeDir + per-file copy
    bool preserveModified = true;    // when the destination reports SetModified(OnUpload)
};

// XH-5: reference copy between two backends (possibly two protocols) through
// a BoundedPipe: the source download runs on a worker thread, the destination
// upload on the calling thread, constant memory. Both backends must be idle
// and owned by the calling thread; the source backend is used from the
// worker thread for the duration of the call only (C-8 hand-over).
NETVFS_EXPORT Result copyAcross(Backend *source, const QString &sourcePath,
                                Backend *destination, const QString &destinationPath,
                                const CopyAcrossOptions &options = CopyAcrossOptions(),
                                Progress *progress = nullptr);

} // namespace NetVfs::Ops

#endif
