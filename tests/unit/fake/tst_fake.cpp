// SPDX-License-Identifier: LGPL-2.1-or-later
// The in-memory FakeBackend is the reference double for consumers and core
// helpers, so its v2 semantics (SPEC-v2 §4) are tested here.
#include "fakebackend.h"
#include "identity.h"
#include "names.h"

#include <QtCore/QBuffer>
#include <QtCore/QCryptographicHash>
#include <QtTest/QtTest>

#include <memory>

using namespace NetVfs;
using NetVfs::Test::FakeBackend;
using NetVfs::Test::FakeServer;

namespace QTest {
template<>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
} // namespace QTest

namespace {

class Collect : public ListSink
{
public:
    bool entries(const QVector<Entry> &batch) override
    {
        sizes << batch.size();
        all += batch;
        return sizes.size() < stopAfter;
    }
    QVector<int> sizes;
    QVector<Entry> all;
    int stopAfter = 1000;
};

class Prompter : public AuthPrompter
{
public:
    bool answer(const QString &, const QString &, const QVector<AuthPrompt> &prompts,
                QVector<QByteArray> *answers) override
    {
        asked += prompts.size();
        if (!reply.isEmpty())
            *answers = QVector<QByteArray>({ reply });
        return !reply.isEmpty();
    }
    QByteArray reply;
    int asked = 0;
};

Entry entryNamed(const QVector<Entry> &entries, const QString &name)
{
    for (const Entry &e : entries) {
        if (e.name == name)
            return e;
    }
    return Entry();
}

} // namespace

class TestFake : public QObject
{
    Q_OBJECT

private:
    FakeServer *server = FakeServer::instance();
    std::unique_ptr<FakeBackend> b;

    bool put(const QString &path, const QByteArray &data, const UploadOptions &options = UploadOptions())
    {
        QByteArray copy = data;
        QBuffer buffer(&copy);
        buffer.open(QIODevice::ReadOnly);
        return b->upload(&buffer, path, options, nullptr).ok();
    }

private slots:
    void init()
    {
        server->reset();
        b = std::make_unique<FakeBackend>();
        QVERIFY(establish(b.get(), ConnectionParams(), Credentials(QStringLiteral("user"), "secret")).ok());
    }

    void capabilitiesSwitch()
    {
        QCOMPARE(b->capabilities().flags, FakeServer::fullCapabilities().flags);
        QVERIFY(!b->capabilities().has(Capability::AtomicPut));
        server->capabilities.flags.remove(Capability::Symlinks);
        QVERIFY(!b->capabilities().has(Capability::Symlinks));
        QCOMPARE(b->makeSymlink(QStringLiteral("t"), QStringLiteral("l")).error(), Error::Unsupported);
        QVERIFY(!server->exists(QStringLiteral("l")));
    }

    void entriesAndTypes()
    {
        const QDateTime when(QDate(2024, 1, 2), QTime(3, 4, 5), Qt::UTC);
        server->addFile(QStringLiteral("d/f"), "12345", when, 0640);
        server->addSymlink(QStringLiteral("d/l"), QStringLiteral("f"));
        server->addSpecial(QStringLiteral("d/fifo"));
        Entry e;
        QVERIFY(b->stat(QStringLiteral("d/f"), &e).ok());
        QCOMPARE(e.type, EntryType::File);
        QCOMPARE(e.size, qint64(5));
        QCOMPARE(e.mode, 0640);
        QCOMPARE(e.modified, when);
        QVERIFY(b->stat(QStringLiteral("d"), &e).ok());
        QCOMPARE(e.type, EntryType::Directory);
        QCOMPARE(e.size, qint64(-1));
        QVERIFY(b->stat(QString(), &e).ok());
        QVERIFY(e.isDir());
        // XC-7
        QVERIFY(b->stat(QStringLiteral("d/l"), &e).ok());
        QCOMPARE(e.type, EntryType::File);
        QCOMPARE(e.name, QStringLiteral("l"));
        QVERIFY(b->lstat(QStringLiteral("d/l"), &e).ok());
        QCOMPARE(e.type, EntryType::Symlink);
        QCOMPARE(e.targetType, EntryType::File);
        QVERIFY(b->lstat(QStringLiteral("d/fifo"), &e).ok());
        QCOMPARE(e.type, EntryType::Special);
        QCOMPARE(b->stat(QStringLiteral("d/none"), &e).error(), Error::NotFound);
        QCOMPARE(b->stat(QStringLiteral("d/f/x"), &e).error(), Error::NotFound);
        QCOMPARE(b->stat(QStringLiteral("../x"), &e).error(), Error::InvalidName);
        const QString odd = Names::decode(QByteArray("caf\xe9"));
        server->addFile(odd, "x");
        QVERIFY(b->stat(odd, &e).ok());
        QVERIFY(e.flags.testFlag(EntryFlag::NameNotUtf8));
    }

    void symlinkResolution()
    {
        server->addDir(QStringLiteral("a/b"));
        server->addFile(QStringLiteral("a/b/f"), "x");
        server->addSymlink(QStringLiteral("rel"), QStringLiteral("a/b"));
        server->addSymlink(QStringLiteral("a/up"), QStringLiteral("../a/b/f"));
        server->addSymlink(QStringLiteral("abs"), QStringLiteral("/a/b"));
        server->addSymlink(QStringLiteral("loop1"), QStringLiteral("loop2"));
        server->addSymlink(QStringLiteral("loop2"), QStringLiteral("loop1"));
        server->addSymlink(QStringLiteral("dangling"), QStringLiteral("nowhere"));
        Entry e;
        QVERIFY(b->stat(QStringLiteral("rel/f"), &e).ok());
        QVERIFY(b->stat(QStringLiteral("abs/f"), &e).ok());
        QVERIFY(b->stat(QStringLiteral("a/up"), &e).ok());
        QCOMPARE(e.type, EntryType::File);
        QCOMPARE(b->stat(QStringLiteral("loop1"), &e).error(), Error::ProtocolError);
        QCOMPARE(b->stat(QStringLiteral("dangling"), &e).error(), Error::NotFound);
        QVERIFY(b->lstat(QStringLiteral("dangling"), &e).ok());
        QVERIFY(e.flags.testFlag(EntryFlag::TargetUnknown));
        QString target;
        QVERIFY(b->readLink(QStringLiteral("abs"), &target).ok());
        QCOMPARE(target, QStringLiteral("/a/b"));
        QCOMPARE(b->readLink(QStringLiteral("a/b/f"), &target).error(), Error::ProtocolError);
        QVERIFY(b->makeSymlink(QStringLiteral("a/b/f"), QStringLiteral("new")).ok());
        QCOMPARE(b->makeSymlink(QStringLiteral("x"), QStringLiteral("new")).error(), Error::AlreadyExists);
        QVERIFY(b->stat(QStringLiteral("new"), &e).ok());
        // removeFile removes the link, not its target.
        QVERIFY(b->removeFile(QStringLiteral("rel")).ok());
        QVERIFY(server->exists(QStringLiteral("a/b/f")));
    }

    // XC-6
    void listingInBatches()
    {
        for (int i = 0; i < 10; ++i)
            server->addFile(QStringLiteral("d/f%1").arg(i), QByteArray(i, 'x'));
        server->addSymlink(QStringLiteral("d/link"), QStringLiteral("f1"));
        Collect sink;
        ListOptions options;
        options.batchSize = 4;
        QVERIFY(b->list(QStringLiteral("d"), &sink, options).ok());
        QCOMPARE(sink.sizes, QVector<int>({ 4, 4, 3 }));
        QCOMPARE(entryNamed(sink.all, QStringLiteral("link")).targetType, EntryType::Unknown);
        Collect resolved;
        options.resolveSymlinkTypes = true;
        QVERIFY(b->list(QStringLiteral("d"), &resolved, options).ok());
        QCOMPARE(entryNamed(resolved.all, QStringLiteral("link")).targetType, EntryType::File);
        Collect stopping;
        stopping.stopAfter = 1;
        QCOMPARE(b->list(QStringLiteral("d"), &stopping, options).error(), Error::Canceled);
        QCOMPARE(stopping.sizes.size(), 1);
        QVector<Entry> all;
        QCOMPARE(b->list(QStringLiteral("d/f1"), &all).error(), Error::NotADirectory);
        QCOMPARE(b->list(QStringLiteral("none"), &all).error(), Error::NotFound);
        QVERIFY(b->list(QString(), &all).ok());
        QCOMPARE(all.size(), 1);
    }

    // XC-8, XC-9
    void namespaceOperations()
    {
        QVERIFY(b->makeDir(QStringLiteral("d"), true).ok());
        QCOMPARE(b->makeDir(QStringLiteral("d"), true).error(), Error::AlreadyExists);
        QVERIFY(b->makeDir(QStringLiteral("d"), false).ok());
        QCOMPARE(b->makeDir(QStringLiteral("x/y"), false).error(), Error::NotFound);
        QVERIFY(put(QStringLiteral("d/f"), "x"));
        QCOMPARE(b->makeDir(QStringLiteral("d/f"), false).error(), Error::AlreadyExists);
        QCOMPARE(b->makeDir(QStringLiteral("d/f/g"), false).error(), Error::NotADirectory);
        QCOMPARE(b->removeFile(QStringLiteral("d")).error(), Error::IsADirectory);
        QCOMPARE(b->removeDir(QStringLiteral("d")).error(), Error::DirectoryNotEmpty);
        QCOMPARE(b->removeDir(QStringLiteral("d/f")).error(), Error::NotADirectory);
        QCOMPARE(b->removeDir(QString()).error(), Error::PermissionDenied);
        QCOMPARE(b->removeFile(QStringLiteral("none")).error(), Error::NotFound);
        QVERIFY(b->removeFile(QStringLiteral("d/f")).ok());
        QVERIFY(b->removeDir(QStringLiteral("d")).ok());
        // dir_mode as the SFTP backend reads it.
        ConnectionParams params;
        params.options.insert(QStringLiteral("dir_mode"), QStringLiteral("0700"));
        FakeBackend other;
        QVERIFY(establish(&other, params, Credentials(QStringLiteral("user"), "secret")).ok());
        QVERIFY(other.makePath(QStringLiteral("p/q")).ok());
        QCOMPARE(server->node(QStringLiteral("p/q")).mode, 0700);
        QVERIFY(b->makeDir(QStringLiteral("r"), true).ok());
        QCOMPARE(server->node(QStringLiteral("r")).mode, FakeServer::DefaultDirMode);
        // Native tree delete.
        QVERIFY(b->removeTreeNative(QStringLiteral("p")).ok());
        QVERIFY(!server->exists(QStringLiteral("p/q")));
        server->capabilities.flags.remove(Capability::RecursiveDelete);
        QCOMPARE(b->removeTreeNative(QStringLiteral("r")).error(), Error::Unsupported);
    }

    // XC-10
    void renameModes()
    {
        server->addFile(QStringLiteral("a"), "A");
        server->addFile(QStringLiteral("b"), "B");
        server->addFile(QStringLiteral("dir/inner"), "I");
        QCOMPARE(b->rename(QStringLiteral("a"), QStringLiteral("b"), RenameMode::NoReplace).error(), Error::AlreadyExists);
        QCOMPARE(server->fileData(QStringLiteral("b")), QByteArray("B"));
        QVERIFY(b->rename(QStringLiteral("a"), QStringLiteral("b"), RenameMode::Replace).ok());
        QCOMPARE(server->fileData(QStringLiteral("b")), QByteArray("A"));
        QVERIFY(!server->exists(QStringLiteral("a")));
        QCOMPARE(b->rename(QStringLiteral("b"), QStringLiteral("dir"), RenameMode::Replace).error(), Error::AlreadyExists);
        QCOMPARE(b->rename(QStringLiteral("none"), QStringLiteral("x"), RenameMode::NoReplace).error(), Error::NotFound);
        QCOMPARE(b->rename(QStringLiteral("dir"), QStringLiteral("dir/sub"), RenameMode::NoReplace).error(),
                 Error::InvalidName);
        QVERIFY(b->rename(QStringLiteral("dir"), QStringLiteral("moved"), RenameMode::NoReplace).ok());
        QCOMPARE(server->fileData(QStringLiteral("moved/inner")), QByteArray("I"));
        QVERIFY(server->log.contains(QStringLiteral("rename:a->b:replace")));
        QVERIFY(server->log.contains(QStringLiteral("rename:dir->moved")));
    }

    // XC-11, XC-12
    void attributesAndLinks()
    {
        server->addFile(QStringLiteral("f"), "data");
        AttributeChanges changes;
        changes.mode = 0600;
        changes.modified = QDateTime(QDate(2020, 1, 1), QTime(0, 0), Qt::UTC);
        QVERIFY(b->setAttributes(QStringLiteral("f"), changes).ok());
        QCOMPARE(server->node(QStringLiteral("f")).mode, 0600);
        QCOMPARE(server->node(QStringLiteral("f")).modified, changes.modified);
        server->capabilities.flags.remove(Capability::SetModified);
        changes.mode = 0644;
        QCOMPARE(b->setAttributes(QStringLiteral("f"), changes).error(), Error::Unsupported);
        QCOMPARE(server->node(QStringLiteral("f")).mode, 0600);   // nothing changed
        QVERIFY(b->makeHardlink(QStringLiteral("f"), QStringLiteral("h")).ok());
        UploadOptions truncate;
        truncate.write.disposition = WriteOptions::Truncate;
        QVERIFY(put(QStringLiteral("h"), "new", truncate));
        QCOMPARE(server->fileData(QStringLiteral("f")), QByteArray("new"));
        server->addDir(QStringLiteral("d"));
        QCOMPARE(b->makeHardlink(QStringLiteral("d"), QStringLiteral("d2")).error(), Error::PermissionDenied);
    }

    // XC-13, XC-14
    void handlesAndTransfers()
    {
        QByteArray data(200 * 1024, Qt::Uninitialized);
        for (int i = 0; i < data.size(); ++i)
            data[i] = static_cast<char>(i);
        UploadOptions options;
        options.write.createMode = 0600;
        QVERIFY(put(QStringLiteral("f"), data, options));
        QCOMPARE(server->node(QStringLiteral("f")).mode, 0600);
        QVERIFY(!put(QStringLiteral("f"), "again"));   // CreateNew
        QCOMPARE(server->fileData(QStringLiteral("f")), data);

        ReadHandle *raw = nullptr;
        QVERIFY(b->openRead(QStringLiteral("f"), &raw).ok());
        std::unique_ptr<ReadHandle> reader(raw);
        QCOMPARE(reader->size(), qint64(data.size()));
        QByteArray part;
        QVERIFY(reader->read(10, 5, &part).ok());
        QCOMPARE(part, data.mid(10, 5));
        QVERIFY(reader->read(data.size() - 2, 10, &part).ok());
        QCOMPARE(part, data.right(2));
        QVERIFY(reader->read(data.size() + 1, 10, &part).ok());
        QVERIFY(part.isEmpty());
        QVERIFY(reader->close().ok());

        WriteOptions resume;
        resume.disposition = WriteOptions::Resume;
        resume.resumeOffset = 7;
        WriteHandle *writer = nullptr;
        QCOMPARE(b->openWrite(QStringLiteral("f"), resume, &writer).error(), Error::ProtocolError);
        resume.resumeOffset = data.size();
        QVERIFY(b->openWrite(QStringLiteral("f"), resume, &writer).ok());
        std::unique_ptr<WriteHandle> w(writer);
        QVERIFY(w->write("tail", 4).ok());
        QCOMPARE(w->position(), qint64(data.size() + 4));
        QVERIFY(w->commit().ok());
        QCOMPARE(server->fileData(QStringLiteral("f")), data + "tail");

        QByteArray received;
        QBuffer sink(&received);
        sink.open(QIODevice::WriteOnly);
        DownloadOptions range;
        range.offset = 100;
        range.length = 70000;
        QVERIFY(b->download(QStringLiteral("f"), &sink, range, nullptr).ok());
        QCOMPARE(received, data.mid(100, 70000));

        // Handles go stale with the connection.
        QVERIFY(b->openRead(QStringLiteral("f"), &raw).ok());
        reader.reset(raw);
        b->disconnect();
        QCOMPARE(reader->read(0, 1, &part).error(), Error::ConnectionLost);
        QCOMPARE(b->keepAlive().error(), Error::Internal);   // not signed in
    }

    // XC-17..20
    void serverSideWork()
    {
        server->addFile(QStringLiteral("d/f"), "abc");
        QVERIFY(b->copy(QStringLiteral("d/f"), QStringLiteral("d/g"), CopyOptions()).ok());
        QCOMPARE(server->fileData(QStringLiteral("d/g")), QByteArray("abc"));
        QCOMPARE(b->copy(QStringLiteral("d/f"), QStringLiteral("d/g"), CopyOptions()).error(), Error::AlreadyExists);
        QCOMPARE(b->copy(QStringLiteral("d"), QStringLiteral("e"), CopyOptions()).error(), Error::IsADirectory);
        CopyOptions recursive;
        recursive.recursive = true;
        QVERIFY(b->copy(QStringLiteral("d"), QStringLiteral("e"), recursive).ok());
        QCOMPARE(server->fileData(QStringLiteral("e/g")), QByteArray("abc"));
        QByteArray digest;
        QVERIFY(b->checksum(QStringLiteral("d/f"), QStringLiteral("sha256"), &digest).ok());
        QCOMPARE(digest, QCryptographicHash::hash("abc", QCryptographicHash::Sha256));
        QCOMPARE(b->checksum(QStringLiteral("d/f"), QStringLiteral("crc32"), &digest).error(), Error::Unsupported);
        SpaceInfo space;
        QVERIFY(b->spaceInfo(QString(), &space).ok());
        QCOMPARE(space.free, server->freeBytes);
        QCOMPARE(space.used, server->totalBytes - server->freeBytes);
        QVERIFY(b->keepAlive().ok());
        server->failOps.insert(QStringLiteral("keepAlive"), Result(Error::ConnectionLost));
        QCOMPARE(b->keepAlive().error(), Error::ConnectionLost);
    }

    // XC-15
    void secondFactor()
    {
        server->otp = "123456";
        FakeBackend other;
        QCOMPARE(establish(&other, ConnectionParams(), Credentials(QStringLiteral("user"), "secret")).error(),
                 Error::AuthFailed);
        Prompter prompter;
        prompter.reply = "000000";
        QCOMPARE(establish(&other, ConnectionParams(), Credentials(QStringLiteral("user"), "secret"), nullptr,
                           &prompter).error(),
                 Error::AuthFailed);
        prompter.reply = "123456";
        QVERIFY(establish(&other, ConnectionParams(), Credentials(QStringLiteral("user"), "secret"), nullptr,
                          &prompter).ok());
        QCOMPARE(prompter.asked, 2);
    }

    void cancelAndFaults()
    {
        server->addFile(QStringLiteral("f"), "x");
        server->failOps.insert(QStringLiteral("stat"), Result(Error::Timeout));
        Entry e;
        QCOMPARE(b->stat(QStringLiteral("f"), &e).error(), Error::Timeout);
        QVERIFY(b->stat(QStringLiteral("f"), &e).ok());   // once
        b->cancel();
        QCOMPARE(b->stat(QStringLiteral("f"), &e).error(), Error::Canceled);
        b->resetCancel();
        QVERIFY(b->stat(QStringLiteral("f"), &e).ok());
        server->failUploadAfterBytes = 10;
        QByteArray data(1000, 'z');
        QBuffer buffer(&data);
        buffer.open(QIODevice::ReadOnly);
        UploadOptions truncate;
        truncate.write.disposition = WriteOptions::Truncate;
        QCOMPARE(b->upload(&buffer, QStringLiteral("f"), truncate, nullptr).error(), Error::ConnectionLost);
    }
};

QTEST_GUILESS_MAIN(TestFake)
#include "tst_fake.moc"
