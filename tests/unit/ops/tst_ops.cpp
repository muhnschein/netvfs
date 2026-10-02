// SPDX-License-Identifier: LGPL-2.1-or-later
// SPEC-v2 XH-2, XH-3, XH-5: Ops::removeTree, Ops::walk, Ops::copyAcross.
#include "memorybackend.h"
#include "ops.h"

#include <QtCore/QElapsedTimer>
#include <QtTest/QtTest>

#include <atomic>
#include <thread>

using namespace NetVfs;
using namespace NetVfs::Ops;

namespace {

class RecordingProgress : public TreeProgress
{
public:
    bool removed(const QString &path, bool isDir, qint64 files, qint64 dirs) override
    {
        removedPaths << path;
        lastFiles = files;
        lastDirs = dirs;
        Q_UNUSED(isDir)
        return stopAfter < 0 || removedPaths.size() < stopAfter;
    }
    void failed(const QString &path, const Result &result) override
    {
        failedPaths << path;
        failedErrors << result.error();
    }

    int stopAfter = -1;
    QStringList removedPaths;
    QStringList failedPaths;
    QVector<Error> failedErrors;
    qint64 lastFiles = 0;
    qint64 lastDirs = 0;
};

class Recorder : public WalkVisitor
{
public:
    bool visit(const QString &path, const Entry &entry, int depth, bool *descend) override
    {
        events << QStringLiteral("V %1 %2").arg(path).arg(depth);
        types.insert(path, entry.type);
        if (path == noDescendAt)
            *descend = false;
        return path != stopAt;
    }
    bool leave(const QString &path, const Entry &, int depth) override
    {
        events << QStringLiteral("L %1 %2").arg(path).arg(depth);
        return true;
    }
    bool listFailed(const QString &path, const Result &result) override
    {
        listFailures << path;
        Q_UNUSED(result)
        return continueOnListFailure;
    }

    QStringList events;
    QStringList listFailures;
    QMap<QString, EntryType> types;
    QString noDescendAt;
    QString stopAt;
    bool continueOnListFailure = false;
};

// Progress for copyAcross; only ever called on the calling thread.
class CopyProgress : public Progress
{
public:
    void update(qint64 done, qint64 total) override
    {
        ++updates;
        lastDone = done;
        lastTotal = total;
        if (cancelAfterUpdates >= 0 && updates > cancelAfterUpdates)
            cancelRequested = true;
    }
    bool canceled() const override { return cancelRequested; }

    int updates = 0;
    qint64 lastDone = 0;
    qint64 lastTotal = 0;
    int cancelAfterUpdates = -1;
    bool cancelRequested = false;
};

QStringList withPrefix(const QStringList &list, const QString &prefix)
{
    return list.filter(QRegExp(QStringLiteral("^%1").arg(QRegExp::escape(prefix))));
}

QString sharedTimestamp()
{
    return QStringLiteral("2020-01-02T03:04:05Z");
}

} // namespace

class TstOps : public QObject
{
    Q_OBJECT

    static void makeTree(MemoryBackend *be)
    {
        be->addDir(QStringLiteral("a"));
        be->addDir(QStringLiteral("a/b"));
        be->addFile(QStringLiteral("a/b/f1"), "one");
        be->addFile(QStringLiteral("a/b/f2"), "two");
        be->addDir(QStringLiteral("a/c"));
        be->addFile(QStringLiteral("a/f3"), "three");
        be->addDir(QStringLiteral("other"));
        be->addFile(QStringLiteral("other/keep.txt"), "keep");
        be->addSymlink(QStringLiteral("a/link"), QStringLiteral("../other"));
    }

    static QStringList removals(const MemoryBackend &be)
    {
        QStringList out;
        for (const QString &line : be.log) {
            if (line.startsWith(QLatin1String("removeFile ")) || line.startsWith(QLatin1String("removeDir ")))
                out << line;
        }
        return out;
    }

private slots:
    // ---------------------------------------------------------------- removeTree

    void removeTreeOrderAndCounts()
    {
        MemoryBackend be;
        makeTree(&be);
        RecordingProgress progress;
        TreeCounts counts;
        QVERIFY(removeTree(&be, QStringLiteral("a"), &progress, RemoveTreeOptions(), &counts).ok());
        QCOMPARE(counts.files, qint64(4));      // f1 f2 f3 and the link
        QCOMPARE(counts.dirs, qint64(3));       // b c a
        QCOMPARE(counts.failed, qint64(0));
        QCOMPARE(progress.removedPaths.size(), 7);
        QCOMPARE(progress.lastFiles, qint64(4));
        QCOMPARE(progress.lastDirs, qint64(3));
        QVERIFY(!be.exists(QStringLiteral("a")));
        QCOMPARE(be.paths(), QStringList({ QStringLiteral("other"), QStringLiteral("other/keep.txt") }));

        // Every folder is removed after everything below it, the root last.
        const QStringList ops = removals(be);
        QCOMPARE(ops.size(), 7);
        for (int i = 0; i < ops.size(); ++i) {
            if (!ops.at(i).startsWith(QLatin1String("removeDir ")))
                continue;
            const QString dir = ops.at(i).mid(10) + QLatin1Char('/');
            for (int later = i + 1; later < ops.size(); ++later)
                QVERIFY2(!ops.at(later).contains(dir), qPrintable(ops.at(later)));
        }
        QCOMPARE(ops.last(), QStringLiteral("removeDir a"));
    }

    void removeTreeCountsParameterIsOptional()
    {
        MemoryBackend be;
        makeTree(&be);
        QVERIFY(removeTree(&be, QStringLiteral("a")).ok());
        QVERIFY(!be.exists(QStringLiteral("a/b/f1")));
    }

    void removeTreeNeverFollowsSymlinks()
    {
        MemoryBackend be;
        makeTree(&be);
        QVERIFY(removeTree(&be, QStringLiteral("a")).ok());
        QVERIFY(be.exists(QStringLiteral("other/keep.txt")));
        QVERIFY(be.log.contains(QStringLiteral("removeFile a/link")));
        QVERIFY(withPrefix(be.log, QStringLiteral("list other")).isEmpty());
        QVERIFY(withPrefix(be.log, QStringLiteral("list a/link")).isEmpty());
    }

    // A backend whose listing reports a link to a folder as a folder must not
    // make removeTree enter it: the lstat check catches it.
    void removeTreeDoesNotTrustListedFolderType()
    {
        MemoryBackend be;
        makeTree(&be);
        be.listSymlinksAsTargets = true;
        QVERIFY(removeTree(&be, QStringLiteral("a")).ok());
        QVERIFY(be.exists(QStringLiteral("other/keep.txt")));
        QVERIFY(be.log.contains(QStringLiteral("removeFile a/link")));
        QVERIFY(withPrefix(be.log, QStringLiteral("list a/link")).isEmpty());
    }

    void removeTreeOnSymlinkRoot()
    {
        MemoryBackend be;
        makeTree(&be);
        TreeCounts counts;
        QVERIFY(removeTree(&be, QStringLiteral("a/link"), nullptr, RemoveTreeOptions(), &counts).ok());
        QCOMPARE(counts.files, qint64(1));
        QCOMPARE(counts.dirs, qint64(0));
        QVERIFY(!be.exists(QStringLiteral("a/link")));
        QVERIFY(be.exists(QStringLiteral("other/keep.txt")));
        QCOMPARE(withPrefix(be.log, QStringLiteral("list")).size(), 0);
    }

    void removeTreeOnFileAndMissing()
    {
        MemoryBackend be;
        makeTree(&be);
        TreeCounts counts;
        QVERIFY(removeTree(&be, QStringLiteral("a/f3"), nullptr, RemoveTreeOptions(), &counts).ok());
        QCOMPARE(counts.files, qint64(1));
        QVERIFY(!be.exists(QStringLiteral("a/f3")));
        QCOMPARE(removeTree(&be, QStringLiteral("a/missing")).error(), Error::NotFound);
    }

    void removeTreeRefusesTheRoot()
    {
        MemoryBackend be;
        makeTree(&be);
        QCOMPARE(removeTree(&be, QString()).error(), Error::InvalidName);
        QCOMPARE(removeTree(&be, QStringLiteral("/")).error(), Error::InvalidName);
        QCOMPARE(removeTree(&be, QStringLiteral("a/../b")).error(), Error::InvalidName);
        QVERIFY(be.log.isEmpty());
    }

    void removeTreeStopsAtFirstError()
    {
        MemoryBackend be;
        makeTree(&be);
        be.intercept = [](const QString &op, const QString &path) {
            return op == QLatin1String("removeFile") && path == QLatin1String("a/b/f1")
                ? Result(Error::PermissionDenied, QStringLiteral("no")) : Result::success();
        };
        RecordingProgress progress;
        TreeCounts counts;
        const Result r = removeTree(&be, QStringLiteral("a"), &progress, RemoveTreeOptions(), &counts);
        QCOMPARE(r.error(), Error::PermissionDenied);
        QVERIFY(be.exists(QStringLiteral("a/b/f1")));
        QVERIFY(be.exists(QStringLiteral("a/b/f2")));    // never reached
        QVERIFY(be.exists(QStringLiteral("a/c")));
        QCOMPARE(counts.files, qint64(0));
        QVERIFY(progress.failedPaths.isEmpty());          // only continueOnError reports failures
    }

    void removeTreeContinueOnError()
    {
        MemoryBackend be;
        makeTree(&be);
        be.intercept = [](const QString &op, const QString &path) {
            return op == QLatin1String("removeFile") && path == QLatin1String("a/b/f1")
                ? Result(Error::PermissionDenied, QStringLiteral("no")) : Result::success();
        };
        RemoveTreeOptions options;
        options.continueOnError = true;
        RecordingProgress progress;
        TreeCounts counts;
        const Result r = removeTree(&be, QStringLiteral("a"), &progress, options, &counts);
        QCOMPARE(r.error(), Error::PermissionDenied);
        QCOMPARE(counts.failed, qint64(1));
        QCOMPARE(counts.files, qint64(3));       // f2 f3 link
        QCOMPARE(counts.dirs, qint64(1));        // c
        QCOMPARE(progress.failedPaths, QStringList({ QStringLiteral("a/b/f1") }));
        QCOMPARE(progress.failedErrors, QVector<Error>({ Error::PermissionDenied }));
        QCOMPARE(be.paths(), QStringList({ QStringLiteral("a"), QStringLiteral("a/b"), QStringLiteral("a/b/f1"),
                                           QStringLiteral("other"), QStringLiteral("other/keep.txt") }));
        // The folders above the failure were not even attempted.
        QVERIFY(!be.log.contains(QStringLiteral("removeDir a/b")));
        QVERIFY(!be.log.contains(QStringLiteral("removeDir a")));
    }

    void removeTreeContinueOnListFailure()
    {
        MemoryBackend be;
        makeTree(&be);
        be.intercept = [](const QString &op, const QString &path) {
            return op == QLatin1String("list") && path == QLatin1String("a/b")
                ? Result(Error::PermissionDenied) : Result::success();
        };
        RemoveTreeOptions options;
        options.continueOnError = true;
        RecordingProgress progress;
        TreeCounts counts;
        QCOMPARE(removeTree(&be, QStringLiteral("a"), &progress, options, &counts).error(), Error::PermissionDenied);
        QCOMPARE(counts.failed, qint64(1));
        QCOMPARE(progress.failedPaths, QStringList({ QStringLiteral("a/b") }));
        QVERIFY(be.exists(QStringLiteral("a/b/f1")));
        QVERIFY(be.exists(QStringLiteral("a/b")));
        QVERIFY(be.exists(QStringLiteral("a")));
        QVERIFY(!be.exists(QStringLiteral("a/f3")));
        QVERIFY(!be.exists(QStringLiteral("a/c")));

        MemoryBackend strict;
        makeTree(&strict);
        strict.intercept = be.intercept;
        QCOMPARE(removeTree(&strict, QStringLiteral("a")).error(), Error::PermissionDenied);
        QVERIFY(strict.exists(QStringLiteral("a/f3")) || strict.exists(QStringLiteral("a/c")));
    }

    void removeTreeConnectionLostIsFatal()
    {
        MemoryBackend be;
        makeTree(&be);
        be.intercept = [](const QString &op, const QString &path) {
            return op == QLatin1String("removeFile") && path == QLatin1String("a/b/f1")
                ? Result(Error::ConnectionLost) : Result::success();
        };
        RemoveTreeOptions options;
        options.continueOnError = true;
        QCOMPARE(removeTree(&be, QStringLiteral("a"), nullptr, options).error(), Error::ConnectionLost);
        QVERIFY(be.exists(QStringLiteral("a/b/f2")));
        QVERIFY(be.exists(QStringLiteral("a/f3")));
    }

    void removeTreeCancelBetweenEntries()
    {
        for (const bool continueOnError : { false, true }) {
            MemoryBackend be;
            makeTree(&be);
            RecordingProgress progress;
            progress.stopAfter = 2;
            RemoveTreeOptions options;
            options.continueOnError = continueOnError;
            TreeCounts counts;
            QCOMPARE(removeTree(&be, QStringLiteral("a"), &progress, options, &counts).error(), Error::Canceled);
            QCOMPARE(removals(be).size(), 2);
            QCOMPARE(counts.files + counts.dirs, qint64(2));
            QVERIFY(be.exists(QStringLiteral("a/f3")));
        }
    }

    void removeTreeBackendCancel()
    {
        MemoryBackend be;
        makeTree(&be);
        int removedFiles = 0;
        be.intercept = [&](const QString &op, const QString &) {
            if (op == QLatin1String("removeFile") && ++removedFiles == 2)
                be.cancel();
            return Result::success();
        };
        QCOMPARE(removeTree(&be, QStringLiteral("a")).error(), Error::Canceled);
        QVERIFY(be.exists(QStringLiteral("a/f3")));
    }

    void removeTreeUsesNativeDelete()
    {
        MemoryBackend be;
        makeTree(&be);
        be.caps.flags.insert(Capability::RecursiveDelete);
        RemoveTreeOptions options;
        options.useNative = true;
        RecordingProgress progress;
        TreeCounts counts;
        QVERIFY(removeTree(&be, QStringLiteral("a"), &progress, options, &counts).ok());
        QVERIFY(be.log.contains(QStringLiteral("removeTreeNative a")));
        QVERIFY(removals(be).isEmpty());
        QVERIFY(withPrefix(be.log, QStringLiteral("list")).isEmpty());
        QVERIFY(!be.exists(QStringLiteral("a")));
        QVERIFY(be.exists(QStringLiteral("other/keep.txt")));
        QCOMPARE(counts.dirs, qint64(1));
        QCOMPARE(progress.removedPaths, QStringList({ QStringLiteral("a") }));
    }

    void removeTreeNativeNeedsTheCapabilityAndTheOption()
    {
        {
            MemoryBackend be;          // option set, capability missing
            makeTree(&be);
            RemoveTreeOptions options;
            options.useNative = true;
            QVERIFY(removeTree(&be, QStringLiteral("a"), nullptr, options).ok());
            QVERIFY(!be.log.contains(QStringLiteral("removeTreeNative a")));
            QVERIFY(!removals(be).isEmpty());
        }
        {
            MemoryBackend be;          // capability present, option not set
            makeTree(&be);
            be.caps.flags.insert(Capability::RecursiveDelete);
            QVERIFY(removeTree(&be, QStringLiteral("a")).ok());
            QVERIFY(!be.log.contains(QStringLiteral("removeTreeNative a")));
            QVERIFY(!removals(be).isEmpty());
        }
    }

    void removeTreeNativeUnsupportedFallsBack()
    {
        MemoryBackend be;
        makeTree(&be);
        be.caps.flags.insert(Capability::RecursiveDelete);
        be.intercept = [](const QString &op, const QString &) {
            return op == QLatin1String("removeTreeNative") ? Result(Error::Unsupported) : Result::success();
        };
        RemoveTreeOptions options;
        options.useNative = true;
        TreeCounts counts;
        QVERIFY(removeTree(&be, QStringLiteral("a"), nullptr, options, &counts).ok());
        QVERIFY(!be.exists(QStringLiteral("a")));
        QCOMPARE(counts.files, qint64(4));
    }

    void removeTreeNativeFailureIsReported()
    {
        MemoryBackend be;
        makeTree(&be);
        be.caps.flags.insert(Capability::RecursiveDelete);
        be.intercept = [](const QString &op, const QString &) {
            return op == QLatin1String("removeTreeNative") ? Result(Error::PermissionDenied) : Result::success();
        };
        RemoveTreeOptions options;
        options.useNative = true;
        QCOMPARE(removeTree(&be, QStringLiteral("a"), nullptr, options).error(), Error::PermissionDenied);
        QVERIFY(be.exists(QStringLiteral("a/f3")));
    }

    // ---------------------------------------------------------------- walk

    static void makeWalkTree(MemoryBackend *be)
    {
        be->addDir(QStringLiteral("t"));
        be->addFile(QStringLiteral("t/f"), "f");
        be->addDir(QStringLiteral("t/x"));
        be->addFile(QStringLiteral("t/x/y.txt"), "y");
        be->addDir(QStringLiteral("t/x/z"));
    }

    void walkPreOrder()
    {
        MemoryBackend be;
        makeWalkTree(&be);
        Recorder visitor;
        QVERIFY(walk(&be, QStringLiteral("t"), &visitor).ok());
        QCOMPARE(visitor.events, QStringList({ QStringLiteral("V t/f 0"), QStringLiteral("V t/x 0"),
                                               QStringLiteral("V t/x/y.txt 1"), QStringLiteral("V t/x/z 1") }));
        QCOMPARE(visitor.types.value(QStringLiteral("t/x")), EntryType::Directory);
        QCOMPARE(visitor.types.value(QStringLiteral("t/f")), EntryType::File);
    }

    void walkPreAndPostOrder()
    {
        MemoryBackend be;
        makeWalkTree(&be);
        Recorder visitor;
        WalkOptions options;
        options.postOrder = true;
        QVERIFY(walk(&be, QStringLiteral("t"), &visitor, options).ok());
        QCOMPARE(visitor.events, QStringList({ QStringLiteral("V t/f 0"), QStringLiteral("V t/x 0"),
                                               QStringLiteral("V t/x/y.txt 1"), QStringLiteral("V t/x/z 1"),
                                               QStringLiteral("L t/x/z 1"), QStringLiteral("L t/x 0") }));
    }

    void walkPostOrderOnly()
    {
        MemoryBackend be;
        makeWalkTree(&be);
        Recorder visitor;
        WalkOptions options;
        options.preOrder = false;
        QVERIFY(walk(&be, QStringLiteral("t"), &visitor, options).ok());
        QCOMPARE(visitor.events, QStringList({ QStringLiteral("V t/f 0"), QStringLiteral("V t/x/y.txt 1"),
                                               QStringLiteral("V t/x/z 1"), QStringLiteral("V t/x 0") }));
    }

    void walkDepthLimit()
    {
        MemoryBackend be;
        makeWalkTree(&be);
        {
            Recorder visitor;
            WalkOptions options;
            options.maxDepth = 0;
            options.postOrder = true;
            QVERIFY(walk(&be, QStringLiteral("t"), &visitor, options).ok());
            // Only the root's children; the folder at the limit is not listed.
            QCOMPARE(visitor.events, QStringList({ QStringLiteral("V t/f 0"), QStringLiteral("V t/x 0"),
                                                   QStringLiteral("L t/x 0") }));
            QVERIFY(!be.log.contains(QStringLiteral("list t/x")));
        }
        {
            Recorder visitor;
            WalkOptions options;
            options.maxDepth = 1;
            QVERIFY(walk(&be, QStringLiteral("t"), &visitor, options).ok());
            QCOMPARE(visitor.events.size(), 4);
        }
        {
            Recorder visitor;
            WalkOptions options;
            options.maxDepth = -1;
            QVERIFY(walk(&be, QStringLiteral("t"), &visitor, options).ok());
            QCOMPARE(visitor.events.size(), 4);
        }
    }

    void walkSkipsSubtreeOnDescendFalse()
    {
        MemoryBackend be;
        makeWalkTree(&be);
        Recorder visitor;
        visitor.noDescendAt = QStringLiteral("t/x");
        WalkOptions options;
        options.postOrder = true;
        QVERIFY(walk(&be, QStringLiteral("t"), &visitor, options).ok());
        QCOMPARE(visitor.events, QStringList({ QStringLiteral("V t/f 0"), QStringLiteral("V t/x 0") }));
        QVERIFY(!be.log.contains(QStringLiteral("list t/x")));
    }

    void walkStopsWhenVisitorReturnsFalse()
    {
        MemoryBackend be;
        makeWalkTree(&be);
        Recorder visitor;
        visitor.stopAt = QStringLiteral("t/x");
        QCOMPARE(walk(&be, QStringLiteral("t"), &visitor).error(), Error::Canceled);
        QCOMPARE(visitor.events.last(), QStringLiteral("V t/x 0"));
    }

    void walkListFailure()
    {
        MemoryBackend be;
        makeWalkTree(&be);
        be.intercept = [](const QString &op, const QString &path) {
            return op == QLatin1String("list") && path == QLatin1String("t/x")
                ? Result(Error::PermissionDenied) : Result::success();
        };
        {
            Recorder visitor;
            QCOMPARE(walk(&be, QStringLiteral("t"), &visitor).error(), Error::PermissionDenied);
            QCOMPARE(visitor.listFailures, QStringList({ QStringLiteral("t/x") }));
        }
        {
            Recorder visitor;
            visitor.continueOnListFailure = true;
            WalkOptions options;
            options.postOrder = true;
            QVERIFY(walk(&be, QStringLiteral("t"), &visitor, options).ok());
            QCOMPARE(visitor.events.last(), QStringLiteral("L t/x 0"));
        }
        {
            Recorder visitor;                         // the root itself cannot be listed
            QCOMPARE(walk(&be, QStringLiteral("t/x"), &visitor).error(), Error::PermissionDenied);
        }
    }

    void walkBatchesAreStreamed()
    {
        MemoryBackend be;
        be.addDir(QStringLiteral("big"));
        for (int i = 0; i < 25; ++i)
            be.addFile(QStringLiteral("big/f%1").arg(i, 2, 10, QLatin1Char('0')), "x");
        Recorder visitor;
        WalkOptions options;
        options.batchSize = 10;
        QVERIFY(walk(&be, QStringLiteral("big"), &visitor, options).ok());
        QCOMPARE(visitor.events.size(), 25);
        QCOMPARE(visitor.events.first(), QStringLiteral("V big/f00 0"));
        QCOMPARE(visitor.events.last(), QStringLiteral("V big/f24 0"));
    }

    static void makeLinkTree(MemoryBackend *be)
    {
        be->addDir(QStringLiteral("w"));
        be->addDir(QStringLiteral("w/real"));
        be->addFile(QStringLiteral("w/real/f.txt"), "f");
        be->addSymlink(QStringLiteral("w/real/up"), QStringLiteral(".."));            // loop to w
        be->addSymlink(QStringLiteral("w/ln"), QStringLiteral("real"));               // folder link
        be->addSymlink(QStringLiteral("w/file-link"), QStringLiteral("real/f.txt"));
        be->addSymlink(QStringLiteral("w/dangling"), QStringLiteral("nowhere"));
    }

    void walkNeverFollowsLinks()
    {
        MemoryBackend be;
        makeLinkTree(&be);
        Recorder visitor;
        QVERIFY(walk(&be, QStringLiteral("w"), &visitor).ok());
        QVERIFY(visitor.events.contains(QStringLiteral("V w/ln 0")));
        QCOMPARE(visitor.types.value(QStringLiteral("w/ln")), EntryType::Symlink);
        QVERIFY(withPrefix(visitor.events, QStringLiteral("V w/ln/")).isEmpty());
        QVERIFY(!be.log.contains(QStringLiteral("list w/ln")));
        QVERIFY(visitor.events.contains(QStringLiteral("V w/real/f.txt 1")));
    }

    void walkFollowsLinksAndSkipsLoops()
    {
        MemoryBackend be;
        makeLinkTree(&be);
        Recorder visitor;
        WalkOptions options;
        options.symlinks = SymlinkPolicy::Follow;
        options.postOrder = true;
        QVERIFY(walk(&be, QStringLiteral("w"), &visitor, options).ok());
        // The folder link is descended into ...
        QVERIFY(visitor.events.contains(QStringLiteral("V w/ln 0")));
        QVERIFY(visitor.events.contains(QStringLiteral("V w/ln/f.txt 1")));
        QVERIFY(visitor.events.contains(QStringLiteral("L w/ln 0")));
        // ... file links, dangling links and loops are leaves ...
        QVERIFY(visitor.events.contains(QStringLiteral("V w/file-link 0")));
        QVERIFY(visitor.events.contains(QStringLiteral("V w/dangling 0")));
        QVERIFY(!visitor.events.contains(QStringLiteral("L w/file-link 0")));
        // ... and "up" (a link back to w) is reported but never entered, in both places.
        QVERIFY(visitor.events.contains(QStringLiteral("V w/real/up 1")));
        QVERIFY(visitor.events.contains(QStringLiteral("V w/ln/up 1")));
        QVERIFY(withPrefix(visitor.events, QStringLiteral("V w/real/up/")).isEmpty());
        QVERIFY(withPrefix(visitor.events, QStringLiteral("V w/ln/up/")).isEmpty());
        QVERIFY(!visitor.events.contains(QStringLiteral("L w/real/up 1")));
    }

    void walkDetectsMutualLoops()
    {
        MemoryBackend be;
        be.addDir(QStringLiteral("p"));
        be.addDir(QStringLiteral("p/A"));
        be.addDir(QStringLiteral("p/B"));
        be.addSymlink(QStringLiteral("p/A/lnB"), QStringLiteral("../B"));
        be.addSymlink(QStringLiteral("p/B/lnA"), QStringLiteral("../A"));
        Recorder visitor;
        WalkOptions options;
        options.symlinks = SymlinkPolicy::Follow;
        QVERIFY(walk(&be, QStringLiteral("p"), &visitor, options).ok());
        QVERIFY(visitor.events.contains(QStringLiteral("V p/A/lnB 1")));
        QVERIFY(visitor.events.contains(QStringLiteral("V p/A/lnB/lnA 2")));    // the loop, as a leaf
        QVERIFY(visitor.events.contains(QStringLiteral("V p/B/lnA/lnB 2")));
        for (const QString &event : visitor.events)
            QVERIFY2(!event.contains(QStringLiteral("lnB/lnA/")) && !event.contains(QStringLiteral("lnA/lnB/")),
                     qPrintable(event));
    }

    void walkDetectsAbsoluteLoops()
    {
        MemoryBackend be;
        be.addDir(QStringLiteral("q"));
        be.addDir(QStringLiteral("q/sub"));
        be.addSymlink(QStringLiteral("q/sub/self"), QStringLiteral("/q"));
        Recorder visitor;
        WalkOptions options;
        options.symlinks = SymlinkPolicy::Follow;
        QVERIFY(walk(&be, QStringLiteral("/q"), &visitor, options).ok());
        QCOMPARE(visitor.events, QStringList({ QStringLiteral("V /q/sub 0"), QStringLiteral("V /q/sub/self 1") }));
    }

    void walkFollowedLinkToSiblingIsNotALoop()
    {
        MemoryBackend be;
        be.addDir(QStringLiteral("r"));
        be.addDir(QStringLiteral("r/d1"));
        be.addFile(QStringLiteral("r/d1/file"), "x");
        be.addSymlink(QStringLiteral("r/d2"), QStringLiteral("d1"));
        Recorder visitor;
        WalkOptions options;
        options.symlinks = SymlinkPolicy::Follow;
        QVERIFY(walk(&be, QStringLiteral("r"), &visitor, options).ok());
        QVERIFY(visitor.events.contains(QStringLiteral("V r/d1/file 1")));
        QVERIFY(visitor.events.contains(QStringLiteral("V r/d2/file 1")));
    }

    // ---------------------------------------------------------------- copyAcross

    static QByteArray randomData(int size)
    {
        QByteArray data(size, Qt::Uninitialized);
        quint32 state = 12345;
        for (char &c : data) {
            state = state * 1664525u + 1013904223u;
            c = char(state >> 24);
        }
        return data;
    }

    void copyAcrossFile()
    {
        MemoryBackend source;
        MemoryBackend destination;
        const QByteArray data = randomData(300000);
        source.addDir(QStringLiteral("src"));
        source.addFile(QStringLiteral("src/f"), data);
        destination.addDir(QStringLiteral("dst"));
        CopyProgress progress;
        CopyAcrossOptions options;
        options.pipeCapacity = 32 * 1024;
        QVERIFY(copyAcross(&source, QStringLiteral("src/f"), &destination, QStringLiteral("dst/g"), options,
                           &progress).ok());
        QCOMPARE(destination.fileData(QStringLiteral("dst/g")), data);
        QCOMPARE(destination.paths(), QStringList({ QStringLiteral("dst"), QStringLiteral("dst/g") }));   // no .part left
        QVERIFY(progress.updates > 0);
        QCOMPARE(progress.lastDone, qint64(data.size()));
        QCOMPARE(progress.lastTotal, qint64(data.size()));
        QVERIFY(destination.log.contains(QStringLiteral("rename dst/g.part")));
    }

    void copyAcrossAtomicPutSkipsTemporaryName()
    {
        MemoryBackend source;
        MemoryBackend destination;
        source.addFile(QStringLiteral("f"), "hello");
        destination.addDir(QStringLiteral("dst"));
        destination.caps.flags.insert(Capability::AtomicPut);
        QVERIFY(copyAcross(&source, QStringLiteral("f"), &destination, QStringLiteral("dst/g")).ok());
        QCOMPARE(destination.fileData(QStringLiteral("dst/g")), QByteArray("hello"));
        QVERIFY(!destination.log.contains(QStringLiteral("upload dst/g.part")));
    }

    void copyAcrossEmptyFile()
    {
        MemoryBackend source;
        MemoryBackend destination;
        source.addFile(QStringLiteral("empty"), QByteArray());
        QVERIFY(copyAcross(&source, QStringLiteral("empty"), &destination, QStringLiteral("e2")).ok());
        QVERIFY(destination.exists(QStringLiteral("e2")));
        QCOMPARE(destination.node(QStringLiteral("e2")).size, qint64(0));
    }

    void copyAcrossPreservesModified()
    {
        MemoryBackend source;
        source.addFile(QStringLiteral("f"), "x");
        const QDateTime stamp = QDateTime::fromString(sharedTimestamp(), Qt::ISODate);
        QVERIFY(stamp.isValid());
        {
            MemoryBackend destination;
            destination.caps.flags.insert(Capability::SetModifiedOnUpload);
            QVERIFY(copyAcross(&source, QStringLiteral("f"), &destination, QStringLiteral("g")).ok());
            QCOMPARE(destination.node(QStringLiteral("g")).modified, stamp);
        }
        {
            MemoryBackend destination;               // capability missing
            QVERIFY(copyAcross(&source, QStringLiteral("f"), &destination, QStringLiteral("g")).ok());
            QVERIFY(!destination.node(QStringLiteral("g")).modified.isValid());
        }
        {
            MemoryBackend destination;               // option off
            destination.caps.flags.insert(Capability::SetModified);
            destination.caps.flags.insert(Capability::SetModifiedOnUpload);
            CopyAcrossOptions options;
            options.preserveModified = false;
            QVERIFY(copyAcross(&source, QStringLiteral("f"), &destination, QStringLiteral("g"), options).ok());
            QVERIFY(!destination.node(QStringLiteral("g")).modified.isValid());
        }
    }

    void copyAcrossModes()
    {
        MemoryBackend source;
        MemoryBackend destination;
        source.addFile(QStringLiteral("f"), "new");
        destination.addFile(QStringLiteral("g"), "old");
        CopyAcrossOptions options;
        QCOMPARE(copyAcross(&source, QStringLiteral("f"), &destination, QStringLiteral("g"), options).error(),
                 Error::AlreadyExists);
        QCOMPARE(destination.fileData(QStringLiteral("g")), QByteArray("old"));
        QVERIFY(!destination.exists(QStringLiteral("g.part")));
        options.mode = RenameMode::Replace;
        QVERIFY(copyAcross(&source, QStringLiteral("f"), &destination, QStringLiteral("g"), options).ok());
        QCOMPARE(destination.fileData(QStringLiteral("g")), QByteArray("new"));
    }

    void copyAcrossArgumentErrors()
    {
        MemoryBackend source;
        MemoryBackend destination;
        source.addFile(QStringLiteral("f"), "x");
        source.addDir(QStringLiteral("d"));
        QCOMPARE(copyAcross(&source, QStringLiteral("missing"), &destination, QStringLiteral("g")).error(),
                 Error::NotFound);
        QVERIFY(destination.paths().isEmpty());
        QCOMPARE(copyAcross(&source, QStringLiteral("f"), &source, QStringLiteral("g")).error(), Error::Internal);
        QCOMPARE(copyAcross(&source, QStringLiteral("f"), &destination, QString()).error(), Error::InvalidName);
        QCOMPARE(copyAcross(&source, QStringLiteral("../f"), &destination, QStringLiteral("g")).error(),
                 Error::InvalidName);
        QCOMPARE(copyAcross(&source, QStringLiteral("d"), &destination, QStringLiteral("g")).error(),
                 Error::IsADirectory);
        QVERIFY(!destination.exists(QStringLiteral("g")));
    }

    void copyAcrossSourceFailure()
    {
        MemoryBackend source;
        MemoryBackend destination;
        source.addGenerated(QStringLiteral("f"), 4 * 1024 * 1024);
        source.failDownloadAfter = 40000;
        QElapsedTimer timer;
        timer.start();
        CopyAcrossOptions options;
        options.pipeCapacity = 16 * 1024;
        const Result r = copyAcross(&source, QStringLiteral("f"), &destination, QStringLiteral("g"), options);
        QCOMPARE(r.error(), Error::ConnectionLost);
        QVERIFY(timer.elapsed() < 2000);
        QVERIFY(destination.paths().isEmpty());              // neither "g" nor "g.part"
        QVERIFY(destination.log.contains(QStringLiteral("removeFile g.part")));
    }

    void copyAcrossDestinationFailure()
    {
        MemoryBackend source;
        MemoryBackend destination;
        source.addGenerated(QStringLiteral("f"), 64 * 1024 * 1024);
        destination.failUploadAfter = 40000;
        QElapsedTimer timer;
        timer.start();
        CopyAcrossOptions options;
        options.pipeCapacity = 16 * 1024;
        const Result r = copyAcross(&source, QStringLiteral("f"), &destination, QStringLiteral("g"), options);
        QCOMPARE(r.error(), Error::NoSpace);
        // The source thread was blocked on the full pipe and has been released.
        QVERIFY(timer.elapsed() < 2000);
        QVERIFY(source.bytesWritten < 64 * 1024 + 4 * 16 * 1024);
        QVERIFY(destination.paths().isEmpty());
    }

    void copyAcrossCancel()
    {
        MemoryBackend source;
        MemoryBackend destination;
        source.addGenerated(QStringLiteral("f"), 256 * 1024 * 1024);
        destination.chunkDelayUs = 100;
        CopyProgress progress;
        progress.cancelAfterUpdates = 20;
        CopyAcrossOptions options;
        options.pipeCapacity = 64 * 1024;
        QElapsedTimer timer;
        timer.start();
        const Result r = copyAcross(&source, QStringLiteral("f"), &destination, QStringLiteral("g"), options,
                                    &progress);
        QCOMPARE(r.error(), Error::Canceled);
        QVERIFY2(timer.elapsed() < 2000, "cancel took too long");
        QVERIFY(destination.paths().isEmpty());              // the temporary file was removed
        QVERIFY(source.bytesWritten < 4 * 1024 * 1024);
    }

    void copyAcrossCanceledBeforeStart()
    {
        MemoryBackend source;
        MemoryBackend destination;
        source.addFile(QStringLiteral("f"), randomData(100000));
        CopyProgress progress;
        progress.cancelRequested = true;
        QCOMPARE(copyAcross(&source, QStringLiteral("f"), &destination, QStringLiteral("g"),
                            CopyAcrossOptions(), &progress).error(), Error::Canceled);
        QVERIFY(destination.paths().isEmpty());
    }

    // 64 MiB through a 64 KiB pipe: the source never runs more than the pipe
    // (plus one chunk on each side) ahead of the destination.
    void copyAcrossLargeFileStreamsInConstantMemory()
    {
        MemoryBackend source;
        MemoryBackend destination;
        const qint64 size = 64LL * 1024 * 1024;
        source.addGenerated(QStringLiteral("big"), size);
        source.chunkSize = 32 * 1024;
        destination.chunkSize = 32 * 1024;
        destination.discardData = true;
        destination.chunkDelayUs = 5;          // a slow destination: the pipe fills up

        std::atomic<bool> stop { false };
        std::atomic<qint64> worstLead { 0 };
        std::thread monitor([&] {
            while (!stop) {
                const qint64 written = source.bytesWritten;     // sampled first: the lead is never overestimated
                const qint64 read = destination.bytesRead;
                worstLead = qMax(worstLead.load(), written - read);
                std::this_thread::yield();
            }
        });
        CopyAcrossOptions options;
        options.pipeCapacity = 64 * 1024;
        const Result r = copyAcross(&source, QStringLiteral("big"), &destination, QStringLiteral("copy"), options);
        stop = true;
        monitor.join();
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(destination.node(QStringLiteral("copy")).size, size);
        QCOMPARE(destination.node(QStringLiteral("copy")).hash, MemoryBackend::patternHash(size));
        QVERIFY2(worstLead <= options.pipeCapacity + 2 * 32 * 1024, qPrintable(QString::number(worstLead)));
        QVERIFY(worstLead > 0);
    }

    static void makeCopyTree(MemoryBackend *be)
    {
        be->addDir(QStringLiteral("src"));
        be->addDir(QStringLiteral("src/d1"));
        be->addFile(QStringLiteral("src/d1/a.txt"), "aaa");
        be->addFile(QStringLiteral("src/d1/b.bin"), randomData(70000));
        be->addDir(QStringLiteral("src/e"));
        be->addFile(QStringLiteral("src/top.txt"), "top");
        be->addSymlink(QStringLiteral("src/lnk"), QStringLiteral("top.txt"));
        be->addSymlink(QStringLiteral("src/dlnk"), QStringLiteral("d1"));
        be->addSymlink(QStringLiteral("src/dangling"), QStringLiteral("nowhere"));
    }

    void copyAcrossRecursive()
    {
        MemoryBackend source;
        MemoryBackend destination;
        makeCopyTree(&source);
        destination.addDir(QStringLiteral("dst"));
        CopyProgress progress;
        CopyAcrossOptions options;
        options.recursive = true;
        options.pipeCapacity = 16 * 1024;
        const Result r = copyAcross(&source, QStringLiteral("src"), &destination, QStringLiteral("dst/copy"), options,
                                    &progress);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(destination.paths(), QStringList({ QStringLiteral("dst"), QStringLiteral("dst/copy"),
                                                    QStringLiteral("dst/copy/d1"), QStringLiteral("dst/copy/d1/a.txt"),
                                                    QStringLiteral("dst/copy/d1/b.bin"), QStringLiteral("dst/copy/e"),
                                                    QStringLiteral("dst/copy/lnk"), QStringLiteral("dst/copy/top.txt") }));
        QCOMPARE(destination.fileData(QStringLiteral("dst/copy/d1/b.bin")), source.fileData(QStringLiteral("src/d1/b.bin")));
        QCOMPARE(destination.fileData(QStringLiteral("dst/copy/lnk")), QByteArray("top"));    // link followed to a file
        QCOMPARE(destination.node(QStringLiteral("dst/copy/e")).type, EntryType::Directory);
        QCOMPARE(progress.lastDone, qint64(3 + 70000 + 3 + 3));
        QCOMPARE(progress.lastTotal, qint64(-1));
    }

    void copyAcrossRecursiveModes()
    {
        MemoryBackend source;
        MemoryBackend destination;
        makeCopyTree(&source);
        destination.addDir(QStringLiteral("dst"));
        CopyAcrossOptions options;
        QCOMPARE(copyAcross(&source, QStringLiteral("src"), &destination, QStringLiteral("dst/copy"), options).error(),
                 Error::IsADirectory);
        QVERIFY(!destination.exists(QStringLiteral("dst/copy")));

        options.recursive = true;
        QVERIFY(copyAcross(&source, QStringLiteral("src"), &destination, QStringLiteral("dst/copy"), options).ok());
        // NoReplace: an existing destination folder is an error ...
        QCOMPARE(copyAcross(&source, QStringLiteral("src"), &destination, QStringLiteral("dst/copy"), options).error(),
                 Error::AlreadyExists);
        // ... even an empty one, before any file is touched.
        destination.addDir(QStringLiteral("dst/empty"));
        QCOMPARE(copyAcross(&source, QStringLiteral("src"), &destination, QStringLiteral("dst/empty"), options).error(),
                 Error::AlreadyExists);
        QVERIFY(!destination.exists(QStringLiteral("dst/empty/top.txt")));
        QVERIFY(!destination.exists(QStringLiteral("dst/empty/d1")));
        // ... Replace merges into it and overwrites files.
        destination.addFile(QStringLiteral("dst/copy/top.txt"), "stale");
        options.mode = RenameMode::Replace;
        QVERIFY(copyAcross(&source, QStringLiteral("src"), &destination, QStringLiteral("dst/copy"), options).ok());
        QCOMPARE(destination.fileData(QStringLiteral("dst/copy/top.txt")), QByteArray("top"));
    }

    void copyAcrossRecursiveStopsAtFirstFailure()
    {
        MemoryBackend source;
        MemoryBackend destination;
        makeCopyTree(&source);
        destination.addDir(QStringLiteral("dst"));
        source.intercept = [](const QString &op, const QString &path) {
            return op == QLatin1String("download") && path == QLatin1String("src/d1/b.bin")
                ? Result(Error::PermissionDenied) : Result::success();
        };
        CopyAcrossOptions options;
        options.recursive = true;
        QCOMPARE(copyAcross(&source, QStringLiteral("src"), &destination, QStringLiteral("dst/copy"), options).error(),
                 Error::PermissionDenied);
        QVERIFY(destination.exists(QStringLiteral("dst/copy/d1/a.txt")));
        QVERIFY(!destination.exists(QStringLiteral("dst/copy/top.txt")));
        QVERIFY(!destination.exists(QStringLiteral("dst/copy/d1/b.bin.part")));
    }

    void copyAcrossRecursiveCancel()
    {
        MemoryBackend source;
        MemoryBackend destination;
        makeCopyTree(&source);
        destination.addDir(QStringLiteral("dst"));
        CopyProgress progress;
        progress.cancelRequested = true;
        CopyAcrossOptions options;
        options.recursive = true;
        QCOMPARE(copyAcross(&source, QStringLiteral("src"), &destination, QStringLiteral("dst/copy"), options,
                            &progress).error(), Error::Canceled);
        QVERIFY(!destination.exists(QStringLiteral("dst/copy/top.txt")));
    }
};

QTEST_GUILESS_MAIN(TstOps)
#include "tst_ops.moc"
