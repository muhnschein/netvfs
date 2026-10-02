// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ops.h"
#include "boundedpipe.h"
#include "logging.h"
#include "paths.h"
#include "transfer.h"

#include <QtCore/QStringList>
#include <QtCore/QVector>

#include <memory>
#include <system_error>
#include <thread>

namespace NetVfs::Ops {

namespace {

// A directory tree deeper than PATH_MAX allows is a hostile or broken server.
constexpr int MaxTreeDepth = 4096;

bool isFatal(const Result &r)
{
    return r.error() == Error::Canceled || r.error() == Error::ConnectionLost;
}

void countRemoved(TreeCounts *counts, bool isDir)
{
    if (isDir)
        ++counts->dirs;
    else
        ++counts->files;
}

// Collects a whole listing; the backend is not re-entered while a folder is
// being processed.
class CollectSink : public ListSink
{
public:
    explicit CollectSink(QVector<Entry> *out) : m_out(out) {}
    bool entries(const QVector<Entry> &batch) override
    {
        *m_out += batch;
        return true;
    }

private:
    QVector<Entry> *m_out;
};

// Collapses "." and ".." against `base` (an identity, see Walker). ".." above
// the start of a relative identity is kept literally.
QString resolveTarget(const QString &base, const QString &target)
{
    const bool absolute = target.startsWith(QLatin1Char('/'));
    QStringList parts = absolute ? QStringList() : Paths::components(base);
    const bool baseAbsolute = !absolute && Paths::isAbsolute(base);
    for (const QString &part : Paths::components(target)) {
        if (part == QLatin1String(".")) {
            continue;
        }
        if (part != QLatin1String("..")) {
            parts.append(part);
        } else if (!parts.isEmpty() && parts.last() != QLatin1String("..")) {
            parts.removeLast();
        } else if (!absolute && !baseAbsolute) {
            parts.append(part);
        }
    }
    const QString joined = parts.join(QLatin1Char('/'));
    return (absolute || baseAbsolute) ? QLatin1Char('/') + joined : joined;
}

struct Frame {
    QString path;
    QString identity;
    Entry entry;
    int depth = -1;              // depth of the folder's own entry; the root has -1
    QVector<Entry> children;
    int next = 0;
};

class Walker
{
public:
    Walker(Backend *backend, WalkVisitor *visitor, const WalkOptions &options)
        : m_backend(backend), m_visitor(visitor), m_options(options) {}

    Result run(const QString &root);

private:
    Result list(Frame *frame);
    Result pushFolder(const QString &path, const QString &identity, const Entry &entry, int depth);
    Result step(const Frame &parent, const Entry &entry);
    Result finish(const Frame &frame);
    // Follow policy: is `entry` a symlink to a folder, and which folder is it?
    bool followTarget(const QString &path, const Frame &parent, const Entry &entry, QString *identity);
    Result leaf(const QString &path, const Entry &entry, int depth);

    Backend *m_backend;
    WalkVisitor *m_visitor;
    WalkOptions m_options;
    QVector<Frame> m_stack;
    QSet<QString> m_branch;      // identities of the folders on the current branch
};

Result Walker::list(Frame *frame)
{
    ListOptions listOptions;
    listOptions.batchSize = m_options.batchSize;
    CollectSink sink(&frame->children);
    const Result r = m_backend->list(frame->path, &sink, listOptions);
    if (r.ok())
        return r;
    frame->children.clear();
    if (isFatal(r) || !m_visitor->listFailed(frame->path, r))
        return r;
    return Result::success();
}

Result Walker::pushFolder(const QString &path, const QString &identity, const Entry &entry, int depth)
{
    if (depth >= MaxTreeDepth)
        return Result(Error::ProtocolError, QStringLiteral("The folder tree is too deep"));
    Frame frame;
    frame.path = path;
    frame.identity = identity;
    frame.entry = entry;
    frame.depth = depth;
    const Result r = list(&frame);
    if (!r.ok())
        return r;
    m_branch.insert(identity);
    m_stack.append(frame);
    return r;
}

bool Walker::followTarget(const QString &path, const Frame &parent, const Entry &entry, QString *identity)
{
    EntryType target = entry.targetType;
    if (target == EntryType::Unknown) {
        Entry resolved;
        if (!m_backend->stat(path, &resolved).ok())
            return false;
        target = resolved.type;
    }
    QString link;
    if (target != EntryType::Directory || !m_backend->readLink(path, &link).ok())
        return false;
    *identity = resolveTarget(parent.identity, link);
    return true;
}

Result Walker::leaf(const QString &path, const Entry &entry, int depth)
{
    bool descend = false;
    return m_visitor->visit(path, entry, depth, &descend) ? Result::success() : Result(Error::Canceled);
}

Result Walker::step(const Frame &parent, const Entry &entry)
{
    const QString path = Paths::join(parent.path, entry.name);
    const int depth = parent.depth + 1;
    QString identity = Paths::join(parent.identity, entry.name);
    bool folder = entry.type == EntryType::Directory;
    if (!folder && entry.type == EntryType::Symlink && m_options.symlinks == SymlinkPolicy::Follow)
        folder = followTarget(path, parent, entry, &identity);
    // A loop is skipped, not an error: the link is reported as a leaf.
    if (!folder || m_branch.contains(identity))
        return leaf(path, entry, depth);

    if (m_options.preOrder) {
        bool descend = true;
        if (!m_visitor->visit(path, entry, depth, &descend))
            return Result(Error::Canceled);
        if (!descend)
            return Result::success();
    }
    if (m_options.maxDepth >= 0 && depth >= m_options.maxDepth) {
        Frame closed;
        closed.path = path;
        closed.entry = entry;
        closed.depth = depth;
        return finish(closed);
    }
    return pushFolder(path, identity, entry, depth);
}

Result Walker::finish(const Frame &frame)
{
    if (!m_options.preOrder) {
        bool descend = false;
        if (!m_visitor->visit(frame.path, frame.entry, frame.depth, &descend))
            return Result(Error::Canceled);
    }
    if (m_options.postOrder && !m_visitor->leave(frame.path, frame.entry, frame.depth))
        return Result(Error::Canceled);
    return Result::success();
}

Result Walker::run(const QString &root)
{
    Frame top;
    top.path = root;
    top.identity = root;
    top.depth = -1;
    Result r = list(&top);
    if (!r.ok())
        return r;
    m_branch.insert(root);
    m_stack.append(top);
    while (!m_stack.isEmpty()) {
        const int index = m_stack.size() - 1;
        Frame &top = m_stack[index];
        if (top.next < top.children.size()) {
            const Entry entry = top.children.at(top.next++);
            // `step` appends to the stack: hand it a copy of the parent data.
            Frame parent;
            parent.path = top.path;
            parent.identity = top.identity;
            parent.depth = top.depth;
            r = step(parent, entry);
        } else {
            const Frame done = top;
            m_stack.removeLast();
            m_branch.remove(done.identity);
            r = index == 0 ? Result::success() : finish(done);
        }
        if (!r.ok())
            return r;
    }
    return Result::success();
}

} // namespace

Result walk(Backend *backend, const QString &root, WalkVisitor *visitor, const WalkOptions &options)
{
    QString normalized;
    const Result r = Paths::normalize(root, &normalized);
    if (!r.ok())
        return r;
    Walker walker(backend, visitor, options);
    return walker.run(normalized);
}

// ------------------------------------------------------------ removeTree (XH-2)

namespace {

class RemoveVisitor : public WalkVisitor
{
public:
    RemoveVisitor(Backend *backend, TreeProgress *progress, bool continueOnError, TreeCounts *counts)
        : m_backend(backend), m_progress(progress), m_continue(continueOnError), m_counts(counts) {}

    bool visit(const QString &path, const Entry &entry, int depth, bool *descend) override
    {
        Q_UNUSED(depth)
        if (entry.type != EntryType::Directory)
            return removeEntry(path, false);
        // Never follow a link even if the backend listed it as a folder.
        Entry real;
        const Result r = m_backend->lstat(path, &real);
        if (!r.ok() || real.type != EntryType::Directory) {
            *descend = false;
            if (r.error() == Error::NotFound)
                return true;       // already gone
            return r.ok() ? removeEntry(path, false) : fail(path, r);
        }
        m_marks.append(m_failures);
        return true;
    }

    bool leave(const QString &path, const Entry &entry, int depth) override
    {
        Q_UNUSED(entry) Q_UNUSED(depth)
        const qint64 mark = m_marks.takeLast();
        if (mark != m_failures)
            return true;       // something below is left: removing the folder would fail
        return removeEntry(path, true);
    }

    bool listFailed(const QString &path, const Result &result) override { return fail(path, result); }

    // Removes `path` (a file or an empty folder). False stops the walk.
    bool removeEntry(const QString &path, bool isDir)
    {
        const Result r = isDir ? m_backend->removeDir(path) : m_backend->removeFile(path);
        if (!r.ok() && r.error() != Error::NotFound)
            return fail(path, r);
        if (r.ok()) {
            countRemoved(m_counts, isDir);
            if (m_progress && !m_progress->removed(path, isDir, m_counts->files, m_counts->dirs)) {
                m_stopped = true;
                return false;
            }
        }
        return true;
    }

    bool fail(const QString &path, const Result &r)
    {
        if (isFatal(r) || !m_continue) {
            m_fatal = r;
            return false;
        }
        ++m_counts->failed;
        ++m_failures;
        if (m_first.ok())
            m_first = r;
        if (m_progress)
            m_progress->failed(path, r);
        return true;
    }

    qint64 failures() const { return m_failures; }
    bool stopped() const { return m_stopped; }
    const Result &fatal() const { return m_fatal; }
    const Result &first() const { return m_first; }

private:
    Backend *m_backend;
    TreeProgress *m_progress;
    bool m_continue;
    TreeCounts *m_counts;
    QVector<qint64> m_marks;
    qint64 m_failures = 0;
    bool m_stopped = false;
    Result m_fatal;
    Result m_first;
};

Result nativeRemove(Backend *backend, const QString &path, TreeProgress *progress, TreeCounts *counts)
{
    const Result r = backend->removeTreeNative(path);
    if (r.ok()) {
        ++counts->dirs;
        if (progress && !progress->removed(path, true, counts->files, counts->dirs))
            return Result(Error::Canceled);
    }
    return r;
}

Result removeRoot(Backend *backend, const QString &path, bool isDir, TreeProgress *progress, TreeCounts *counts)
{
    const Result r = isDir ? backend->removeDir(path) : backend->removeFile(path);
    if (!r.ok())
        return r;
    countRemoved(counts, isDir);
    if (progress && !progress->removed(path, isDir, counts->files, counts->dirs))
        return Result(Error::Canceled);
    return r;
}

Result removeContents(Backend *backend, const QString &path, TreeProgress *progress,
                      const RemoveTreeOptions &options, TreeCounts *counts)
{
    RemoveVisitor visitor(backend, progress, options.continueOnError, counts);
    WalkOptions walkOptions;
    walkOptions.preOrder = true;
    walkOptions.postOrder = true;
    walkOptions.symlinks = SymlinkPolicy::Never;
    const Result walked = walk(backend, path, &visitor, walkOptions);
    if (!visitor.fatal().ok())
        return visitor.fatal();
    if (visitor.stopped())
        return Result(Error::Canceled);
    if (!walked.ok()) {
        if (options.continueOnError && !isFatal(walked)) {
            ++counts->failed;
            if (progress)
                progress->failed(path, walked);
        }
        return walked;
    }
    if (visitor.failures() > 0)
        return visitor.first();
    const Result removed = removeRoot(backend, path, true, progress, counts);
    if (!removed.ok() && options.continueOnError && !isFatal(removed)) {
        ++counts->failed;
        if (progress)
            progress->failed(path, removed);
    }
    return removed;
}

} // namespace

Result removeTree(Backend *backend, const QString &path, TreeProgress *progress,
                  const RemoveTreeOptions &options, TreeCounts *counts)
{
    TreeCounts local;
    TreeCounts *tally = counts ? counts : &local;
    *tally = TreeCounts();
    QString normalized;
    Result r = Paths::normalize(path, &normalized);
    if (!r.ok())
        return r;
    if (normalized.isEmpty() || normalized == QLatin1String("/"))
        return Result(Error::InvalidName, QStringLiteral("Refusing to remove the root folder"));

    Entry entry;
    r = backend->lstat(normalized, &entry);
    if (!r.ok())
        return r;
    if (entry.type != EntryType::Directory)
        return removeRoot(backend, normalized, false, progress, tally);

    if (options.useNative && backend->capabilities().has(Capability::RecursiveDelete)) {
        r = nativeRemove(backend, normalized, progress, tally);
        if (r.error() != Error::Unsupported)
            return r;
    }
    return removeContents(backend, normalized, progress, options, tally);
}

// ------------------------------------------------------------ copyAcross (XH-5)

namespace {

// Source side, on the worker thread: touches only the pipe, never the
// caller's Progress (which belongs to the calling thread).
class SourceProgress : public Progress
{
public:
    explicit SourceProgress(BoundedPipe *pipe) : m_pipe(pipe) {}
    void update(qint64, qint64) override {}
    bool canceled() const override { return !m_pipe->result().ok(); }

private:
    BoundedPipe *m_pipe;
};

// Destination side, on the calling thread: forwards to the caller's Progress
// and turns its cancel request into a pipe failure.
class DestinationProgress : public Progress
{
public:
    DestinationProgress(BoundedPipe *pipe, Progress *outer, qint64 base, qint64 total)
        : m_pipe(pipe), m_outer(outer), m_base(base), m_total(total) {}

    void update(qint64 done, qint64 total) override
    {
        Q_UNUSED(total)
        if (m_outer)
            m_outer->update(m_base + done, m_total);
    }

    bool canceled() const override
    {
        if (m_outer && m_outer->canceled())
            m_pipe->cancel();
        return !m_pipe->result().ok();
    }

private:
    BoundedPipe *m_pipe;
    Progress *m_outer;
    qint64 m_base;
    qint64 m_total;
};

struct FileJob {
    Backend *source = nullptr;
    QString sourcePath;
    Backend *destination = nullptr;
    QString destinationPath;
    qint64 size = -1;
    QDateTime modified;
    qint64 base = 0;             // bytes of earlier files, for progress
    qint64 total = -1;
};

Transfer::TransferPolicy policyFor(const FileJob &job, const CopyAcrossOptions &options)
{
    const Capabilities caps = job.destination->capabilities();
    Transfer::TransferPolicy policy;
    policy.useTempName = !caps.has(Capability::AtomicPut);
    policy.commitMode = options.mode;
    policy.createMode = -1;
    if (options.preserveModified && job.modified.isValid()
        && (caps.has(Capability::SetModified) || caps.has(Capability::SetModifiedOnUpload))) {
        policy.modified = job.modified;
    }
    return policy;
}

// Runs the source download on a worker thread into `pipe`.
class DownloadWorker
{
public:
    DownloadWorker(const FileJob &job, BoundedPipe *pipe) : m_job(job), m_pipe(pipe), m_progress(pipe) {}

    bool start()
    {
        try {
            m_thread = std::thread([this] { run(); });
        } catch (const std::system_error &) {
            return false;
        }
        return true;
    }
    void join()
    {
        if (m_thread.joinable())
            m_thread.join();
    }
    const Result &result() const { return m_result; }

private:
    void run()
    {
        m_result = m_job.source->download(m_job.sourcePath, m_pipe->writer(), DownloadOptions(), &m_progress);
        if (m_result.ok())
            m_pipe->writer()->close();
        else
            m_pipe->fail(m_result);
    }

    FileJob m_job;
    BoundedPipe *m_pipe;
    SourceProgress m_progress;
    Result m_result;
    std::thread m_thread;
};

Result copyFile(const FileJob &job, const CopyAcrossOptions &options, Progress *progress)
{
    BoundedPipe pipe(options.pipeCapacity);
    DownloadWorker worker(job, &pipe);
    if (!worker.start())
        return Result(Error::Internal, QStringLiteral("Cannot start the download thread"));

    DestinationProgress destinationProgress(&pipe, progress, job.base, job.total);
    const Result uploaded = Transfer::upload(job.destination, pipe.reader(), job.size, job.destinationPath,
                                             &destinationProgress, policyFor(job, options));
    if (!uploaded.ok()) {
        pipe.fail(uploaded);       // wakes a download blocked on a full pipe
        worker.join();
        return pipe.result();
    }
    // The destination is done. A source that still has data fails on its
    // next write, so the worker cannot block here.
    const bool sourceHadFailed = !pipe.result().ok();
    pipe.reader()->close();
    worker.join();
    if (worker.result().ok())
        return Result::success();
    if (sourceHadFailed)
        return worker.result();
    return Result(Error::Internal, QStringLiteral("The source delivered more data than the destination consumed"));
}

class CopyTreeVisitor : public WalkVisitor
{
public:
    CopyTreeVisitor(Backend *source, const QString &sourceRoot, Backend *destination, const QString &destinationRoot,
                    const CopyAcrossOptions &options, Progress *progress)
        : m_source(source), m_destination(destination), m_options(options), m_progress(progress)
    {
        m_sourcePrefix = sourceRoot.isEmpty() || sourceRoot.endsWith(QLatin1Char('/'))
            ? sourceRoot : sourceRoot + QLatin1Char('/');
        m_destinationRoot = destinationRoot;
    }

    bool visit(const QString &path, const Entry &entry, int depth, bool *descend) override
    {
        Q_UNUSED(depth)
        Q_UNUSED(descend)
        if (m_progress && m_progress->canceled()) {
            m_result = Result(Error::Canceled);
            return false;
        }
        const QString target = Paths::join(m_destinationRoot, path.mid(m_sourcePrefix.size()));
        if (entry.type == EntryType::Directory)
            m_result = m_destination->makeDir(target, false);
        else if (entry.type == EntryType::File)
            m_result = copyOne(path, target, entry);
        else if (entry.type == EntryType::Symlink)
            m_result = copyLinked(path, target);
        return m_result.ok();
    }

    const Result &result() const { return m_result; }

private:
    Result copyOne(const QString &path, const QString &target, const Entry &entry)
    {
        FileJob job;
        job.source = m_source;
        job.sourcePath = path;
        job.destination = m_destination;
        job.destinationPath = target;
        job.size = entry.size;
        job.modified = entry.modified;
        job.base = m_done;
        const Result r = copyFile(job, m_options, m_progress);
        if (r.ok() && entry.size > 0)
            m_done += entry.size;
        return r;
    }

    // Links to files are copied as files; links to folders (loops) and
    // dangling links are skipped.
    Result copyLinked(const QString &path, const QString &target)
    {
        Entry resolved;
        if (!m_source->stat(path, &resolved).ok() || resolved.type != EntryType::File)
            return Result::success();
        return copyOne(path, target, resolved);
    }

    Backend *m_source;
    Backend *m_destination;
    CopyAcrossOptions m_options;
    Progress *m_progress;
    QString m_sourcePrefix;
    QString m_destinationRoot;
    qint64 m_done = 0;
    Result m_result;
};

Result copyTree(Backend *source, const QString &sourcePath, Backend *destination, const QString &destinationPath,
                const CopyAcrossOptions &options, Progress *progress)
{
    Result r = destination->makeDir(destinationPath, options.mode == RenameMode::NoReplace);
    if (!r.ok())
        return r;
    CopyTreeVisitor visitor(source, sourcePath, destination, destinationPath, options, progress);
    r = walk(source, sourcePath, &visitor);
    return visitor.result().ok() ? r : visitor.result();
}

} // namespace

Result copyAcross(Backend *source, const QString &sourcePath, Backend *destination, const QString &destinationPath,
                  const CopyAcrossOptions &options, Progress *progress)
{
    if (source == destination)
        return Result(Error::Internal, QStringLiteral("Source and destination must be different backends"));
    QString from;
    QString to;
    Result r = Paths::normalize(sourcePath, &from);
    if (r.ok())
        r = Paths::normalize(destinationPath, &to);
    if (!r.ok())
        return r;
    if (Paths::fileName(to).isEmpty())
        return Result(Error::InvalidName, QStringLiteral("The destination has no name"));

    Entry entry;
    r = source->stat(from, &entry);
    if (!r.ok())
        return r;
    if (entry.type == EntryType::Directory) {
        if (!options.recursive)
            return Result(Error::IsADirectory, QStringLiteral("The source is a folder and recursive is not set"));
        return copyTree(source, from, destination, to, options, progress);
    }

    FileJob job;
    job.source = source;
    job.sourcePath = from;
    job.destination = destination;
    job.destinationPath = to;
    job.size = entry.size;
    job.modified = entry.modified;
    job.total = entry.size;
    return copyFile(job, options, progress);
}

} // namespace NetVfs::Ops
