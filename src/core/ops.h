// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_OPS_H
#define NETVFS_OPS_H

#include "backend.h"

#include <QtCore/QSet>

namespace NetVfs::Ops {

class TreeProgress
{
public:
    virtual ~TreeProgress() = default;
    virtual bool removed(const QString &path, bool isDir, qint64 files, qint64 dirs)
    {
        Q_UNUSED(path) Q_UNUSED(isDir) Q_UNUSED(files) Q_UNUSED(dirs)
        return true;
    }
    virtual void failed(const QString &path, const Result &result) { Q_UNUSED(path) Q_UNUSED(result) }
};

struct RemoveTreeOptions {
    bool useNative = false;
    bool continueOnError = false;
};

struct TreeCounts {
    qint64 files = 0;
    qint64 dirs = 0;
    qint64 failed = 0;
};

// Depth-first, lists then deletes, never follows symlinks (link to folder removed with
// removeFile()). Cancel checked between entries. Stops at first error unless continueOnError (then
// returns first error after visiting everything; folder with a failed entry below is not attempted;
// Canceled and ConnectionLost always stop). Empty path or "/" is InvalidName. options.useNative
// with RecursiveDelete: one removeTreeNative() call (counts hold only the root); Unsupported falls
// back.
NETVFS_EXPORT Result removeTree(Backend *backend, const QString &path, TreeProgress *progress = nullptr,
                                const RemoveTreeOptions &options = RemoveTreeOptions(),
                                TreeCounts *counts = nullptr);

enum class SymlinkPolicy { Never, Follow };

struct WalkOptions {
    bool preOrder = true;
    bool postOrder = false;
    SymlinkPolicy symlinks = SymlinkPolicy::Never;
    int maxDepth = -1;
    int batchSize = 256;
};

class WalkVisitor
{
public:
    virtual ~WalkVisitor() = default;
    // `path` is the full path, `depth` 0 for the root's children. false stops the walk (Canceled).
    // For folders `*descend = false` skips the subtree.
    virtual bool visit(const QString &path, const Entry &entry, int depth, bool *descend) = 0;
    virtual bool leave(const QString &path, const Entry &entry, int depth)
    {
        Q_UNUSED(path) Q_UNUSED(entry) Q_UNUSED(depth)
        return true;
    }
    virtual bool listFailed(const QString &path, const Result &result)
    {
        Q_UNUSED(path) Q_UNUSED(result)
        return false;
    }
};

// Streaming traversal: one folder's listing in memory at a time. preOrder false: visit() after
// children, `*descend` ignored; postOrder adds leave(). Folder at maxDepth or with `*descend =
// false` not entered. SymlinkPolicy::Follow detects loops by resolved folder paths on the current
// branch (readLink() resolved against the containing folder): a loop link is a leaf; unresolvable
// link is a leaf. Deeper than 4096 levels: ProtocolError.
NETVFS_EXPORT Result walk(Backend *backend, const QString &root, WalkVisitor *visitor,
                          const WalkOptions &options = WalkOptions());

struct CopyAcrossOptions {
    qint64 pipeCapacity = 4 << 20;
    RenameMode mode = RenameMode::NoReplace;
    bool recursive = false;
    bool preserveModified = true;
};

// Copy between two backends through a BoundedPipe: source download on a worker thread, destination
// upload (Transfer::upload) on the calling thread. Backends must be different, idle, owned by the
// calling thread; source is used from the worker for the call only. Failure on either side fails
// the pipe; first failure is the result. Progress::update()/canceled() only on the calling thread;
// canceled() polled once per destination chunk. Folder source needs `recursive` (else
// IsADirectory): folders via makeDir (root exclusively under NoReplace), links to files copied as
// files, links to folders and dangling links skipped. Recursive progress total is -1.
NETVFS_EXPORT Result copyAcross(Backend *source, const QString &sourcePath,
                                Backend *destination, const QString &destinationPath,
                                const CopyAcrossOptions &options = CopyAcrossOptions(),
                                Progress *progress = nullptr);

}
#endif
