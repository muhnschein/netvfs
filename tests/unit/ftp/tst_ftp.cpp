// SPDX-License-Identifier: LGPL-2.1-or-later
// FTP backend helpers (SPEC-v2 6.4): parsers (F-2, F-3, XT-3 seeds), path
// and URL encoding (XC-4), the F-7 / W-13 error mapping, the explicit-TLS
// guard (XSEC-2) and the TLS identity evaluation (XC-16, W-3) over
// certificates the test makes with OpenSSL.
#include "ftpparse.h"
#include "ftpsupport.h"
#include "names.h"
#include "tlsprobe.h"

#include <QtCore/QTemporaryDir>
#include <QtTest/QtTest>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <memory>

using namespace NetVfs;
using namespace NetVfs::Ftp;

Q_DECLARE_METATYPE(NetVfs::Error)

namespace QTest {
template<>
char *toString(const NetVfs::Error &error)
{
    return qstrdup(qPrintable(NetVfs::errorName(error)));
}
template<>
char *toString(const NetVfs::EntryType &type)
{
    return qstrdup(QByteArray::number(int(type)).constData());
}
template<>
char *toString(const NetVfs::Ftp::LineResult &result)
{
    return qstrdup(QByteArray::number(int(result)).constData());
}
template<>
char *toString(const NetVfs::Ftp::TlsGuard::Verdict &verdict)
{
    return qstrdup(QByteArray::number(int(verdict)).constData());
}
} // namespace QTest

namespace {

constexpr qint64 Day = 24 * 60 * 60;

void feed(ReplyReader *reader, const QByteArray &data)
{
    reader->feed(data.constData(), size_t(data.size()));
}

Reply reply(const QList<QByteArray> &lines)
{
    ReplyReader reader;
    for (const QByteArray &line : lines) {
        const QByteArray wire = line + "\r\n";
        reader.feed(wire.constData(), size_t(wire.size()));
    }
    return reader.last();
}

Entry listLine(const QByteArray &line, LineResult *result = nullptr,
               const QDateTime &now = QDateTime(QDate(2026, 10, 2), QTime(12, 0), Qt::UTC))
{
    Entry entry;
    const LineResult r = parseListLine(line, now, &entry);
    if (result)
        *result = r;
    return entry;
}

Entry mlsx(const QByteArray &line, LineResult *result = nullptr)
{
    Entry entry;
    const LineResult r = parseMlsxLine(line, &entry);
    if (result)
        *result = r;
    return entry;
}

// ------------------------------------------------------------ certificates

struct KeyDeleter { void operator()(EVP_PKEY *k) const { EVP_PKEY_free(k); } };
struct CertDeleter { void operator()(X509 *c) const { X509_free(c); } };
struct CtxDeleter { void operator()(EVP_PKEY_CTX *c) const { EVP_PKEY_CTX_free(c); } };
using Key = std::unique_ptr<EVP_PKEY, KeyDeleter>;
using Cert = std::unique_ptr<X509, CertDeleter>;

ServerIdentity evaluate(X509 *leaf, STACK_OF(X509) *presented, const char *host, const CurlTls::TrustStore &store)
{
    return CurlTls::identityFromCertificates(leaf, presented, QByteArray(host), CurlTls::ChainCheck::NotChecked, store);
}

Key makeKey()
{
    std::unique_ptr<EVP_PKEY_CTX, CtxDeleter> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    EVP_PKEY *key = nullptr;
    if (ctx && EVP_PKEY_keygen_init(ctx.get()) == 1
        && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) == 1)
        EVP_PKEY_keygen(ctx.get(), &key);
    return Key(key);
}

void addExtension(X509 *cert, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
}

// A certificate for `cn` with `sans`, valid from `from` to `to` seconds
// relative to now, signed by `issuerKey` (`issuer` null: self-signed).
Cert makeCert(EVP_PKEY *key, const char *cn, const char *sans, long from, long to, X509 *issuer = nullptr,
              EVP_PKEY *issuerKey = nullptr, bool ca = false)
{
    Cert cert(X509_new());
    X509_set_version(cert.get(), 2);
    // Unique enough for a test run: the subject differs per certificate.
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), long(qHash(QByteArray(cn)) & 0x7fffffff) + from);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), from);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), to);
    X509_set_pubkey(cert.get(), key);
    X509_NAME *name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(cn), -1, -1, 0);
    X509_set_issuer_name(cert.get(), issuer ? X509_get_subject_name(issuer) : name);
    X509 *signer = issuer ? issuer : cert.get();
    addExtension(cert.get(), signer, NID_basic_constraints, ca ? "critical,CA:TRUE" : "CA:FALSE");
    if (ca)
        addExtension(cert.get(), signer, NID_key_usage, "critical,keyCertSign,cRLSign");
    if (sans)
        addExtension(cert.get(), signer, NID_subject_alt_name, sans);
    X509_sign(cert.get(), issuerKey ? issuerKey : key, EVP_sha256());
    return cert;
}

QString writePem(const QString &path, X509 *cert)
{
    BIO *bio = BIO_new_file(path.toLocal8Bit().constData(), "w");
    PEM_write_bio_X509(bio, cert);
    BIO_free(bio);
    return path;
}

QByteArray spki(X509 *cert)
{
    unsigned char *der = nullptr;
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
    QByteArray result(reinterpret_cast<const char *>(der), length);
    OPENSSL_free(der);
    return result;
}

} // namespace

class TestFtp : public QObject
{
    Q_OBJECT

private slots:
    // ------------------------------------------------------------ replies

    void replyReader()
    {
        ReplyReader reader;
        QVERIFY(!reader.last().isValid());
        const QByteArray wire = "220-Welcome\r\n220-second line\r\n 220 not the end\r\n220 Done\r\n331 Password";
        // Fed in odd pieces, as a network would.
        for (int i = 0; i < wire.size(); i += 7)
            reader.feed(wire.constData() + i, size_t(qMin(7, wire.size() - i)));
        QCOMPARE(reader.count(), 1);
        QCOMPARE(reader.last().code, 220);
        QCOMPARE(reader.last().lines.size(), 4);
        QCOMPARE(reader.last().text(), QByteArray("Welcome"));
        feed(&reader, "\r\n");
        QCOMPARE(reader.count(), 2);
        QCOMPARE(reader.last().code, 331);
        QCOMPARE(reader.replies().size(), 2);
        // Stray text outside a reply is ignored; so are non-reply codes.
        feed(&reader, "garbage\r\n600 nope\r\n12 x\r\n");
        QCOMPARE(reader.count(), 2);
        // Multi-line replies end only with the same code and a space.
        feed(&reader, "211-Features:\r\n MLST\r\n211-still\r\n212 other\r\n211 End\r\n");
        QCOMPARE(reader.last().code, 211);
        QCOMPARE(reader.last().lines.size(), 5);
        feed(&reader, "200\r\n");
        QCOMPARE(reader.last().code, 200);
        reader.reset();
        QVERIFY(!reader.last().isValid());
        QCOMPARE(reader.count(), 0);
    }

    void replyReaderLimits()
    {
        ReplyReader reader;
        const QByteArray longLine = "250 " + QByteArray(ReplyReader::MaxLineBytes * 2, 'x') + "\r\n";
        reader.feed(longLine.constData(), size_t(longLine.size()));
        QCOMPARE(reader.last().code, 250);
        QCOMPARE(reader.last().lines.first().size(), ReplyReader::MaxLineBytes);
        for (int i = 0; i < ReplyReader::MaxReplies + 10; ++i)
            feed(&reader, "200 ok\r\n");
        QCOMPARE(reader.replies().size(), ReplyReader::MaxReplies);
        QCOMPARE(reader.count(), ReplyReader::MaxReplies + 11);
    }

    void features()
    {
        const Features f = parseFeatures(reply({ "211-Extensions supported:", " UTF8", " MLST type*;size*;modify*;",
                                                 " MLSD", " REST STREAM", " mfmt", "", "211 End." }));
        QVERIFY(f.has("UTF8"));
        QVERIFY(f.has("MLST"));
        QVERIFY(f.has("MFMT"));   // upper-cased
        QVERIFY(!f.has("SIZE"));
        QVERIFY(f.restStream());
        QCOMPARE(f.mlstFacts, QByteArray("type*;size*;modify*;"));
        QVERIFY(!parseFeatures(reply({ "211-x", " REST", "211 End" })).restStream());
        QVERIFY(!parseFeatures(reply({ "211-x", " REST STREAMING", "211 End" })).restStream());
        QVERIFY(parseFeatures(reply({ "500 FEAT not understood" })).names.isEmpty());
        QVERIFY(parseFeatures(reply({ "211 no features" })).names.isEmpty());
    }

    void pathReply()
    {
        QByteArray path;
        QVERIFY(parsePathReply(reply({ "257 \"/home/alice\" is the current directory" }), &path));
        QCOMPARE(path, QByteArray("/home/alice"));
        QVERIFY(parsePathReply(reply({ "257 \"/a \"\"quoted\"\" dir\" created" }), &path));
        QCOMPARE(path, QByteArray("/a \"quoted\" dir"));
        QVERIFY(parsePathReply(reply({ "257 \"/caf\xe9\"" }), &path));
        QCOMPARE(path, QByteArray("/caf\xe9"));
        QVERIFY(!parsePathReply(reply({ "257 no quotes" }), &path));
        QVERIFY(!parsePathReply(reply({ "257 \"unterminated" }), &path));
        QVERIFY(!parsePathReply(reply({ "257 \"\"" }), &path));
        QVERIFY(!parsePathReply(reply({ "550 \"/x\"" }), &path));
    }

    void sizeAndTimes()
    {
        QCOMPARE(parseSizeReply(reply({ "213 3150049" })), qint64(3150049));
        QCOMPARE(parseSizeReply(reply({ "213 0" })), qint64(0));
        QCOMPARE(parseSizeReply(reply({ "213 12x" })), qint64(-1));
        QCOMPARE(parseSizeReply(reply({ "213 -5" })), qint64(-1));
        QCOMPARE(parseSizeReply(reply({ "213 99999999999999999999" })), qint64(-1));
        QCOMPARE(parseSizeReply(reply({ "550 nope" })), qint64(-1));

        QCOMPARE(parseTimeVal("20210304050607"), QDateTime(QDate(2021, 3, 4), QTime(5, 6, 7), Qt::UTC));
        QCOMPARE(parseTimeVal("20210304050607.5"), QDateTime(QDate(2021, 3, 4), QTime(5, 6, 7, 500), Qt::UTC));
        QCOMPARE(parseTimeVal("20210304050607.123456"), QDateTime(QDate(2021, 3, 4), QTime(5, 6, 7, 123), Qt::UTC));
        QCOMPARE(parseTimeVal("20161231235960"), QDateTime(QDate(2016, 12, 31), QTime(23, 59, 59), Qt::UTC));
        QVERIFY(!parseTimeVal("2021030405060").isValid());
        QVERIFY(!parseTimeVal("20211304050607").isValid());
        QVERIFY(!parseTimeVal("20210304050607x").isValid());
        QVERIFY(!parseTimeVal("20210304050607.").isValid());
        QVERIFY(!parseTimeVal("19690304050607").isValid());
        QCOMPARE(parseMdtmReply(reply({ "213 20210304050607" })), QDateTime(QDate(2021, 3, 4), QTime(5, 6, 7), Qt::UTC));
        QVERIFY(!parseMdtmReply(reply({ "550 20210304050607" })).isValid());
        const QDateTime local(QDate(2021, 3, 4), QTime(5, 6, 7), Qt::OffsetFromUTC, 3600);
        QCOMPARE(formatTimeVal(local), QByteArray("20210304040607"));
    }

    // ------------------------------------------------------------- MLSx

    void mlsxFacts()
    {
        LineResult r;
        Entry e = mlsx("type=file;size=1234;modify=20210304050607.25;perm=adfrw;UNIX.mode=0640;UNIX.uid=1001;"
                       "UNIX.gid=100;unique=801g1;media-type=text/plain; name with ; and spaces",
                       &r);
        QCOMPARE(r, LineResult::Entry);
        QCOMPARE(e.name, QStringLiteral("name with ; and spaces"));
        QCOMPARE(e.type, EntryType::File);
        QCOMPARE(e.size, qint64(1234));
        QCOMPARE(e.modified, QDateTime(QDate(2021, 3, 4), QTime(5, 6, 7, 250), Qt::UTC));
        QCOMPARE(e.mode, 0640);
        QCOMPARE(e.uid, qint64(1001));
        QCOMPARE(e.gid, qint64(100));
        QCOMPARE(e.extra.value(QStringLiteral("perm")).toString(), QStringLiteral("adfrw"));
        QCOMPARE(e.extra.value(QStringLiteral("unique")).toString(), QStringLiteral("801g1"));
        QCOMPARE(e.contentType, QStringLiteral("text/plain"));
        QVERIFY(!e.extra.contains(QStringLiteral("timeApproximate")));

        e = mlsx("Type=dir;Modify=20200101000000;Create=20190101000000;UNIX.owner=alice;UNIX.group=staff; docs", &r);
        QCOMPARE(r, LineResult::Entry);
        QCOMPARE(e.type, EntryType::Directory);
        QCOMPARE(e.owner, QStringLiteral("alice"));
        QCOMPARE(e.group, QStringLiteral("staff"));
        QCOMPARE(e.uid, qint64(-1));
        QCOMPARE(e.created, QDateTime(QDate(2019, 1, 1), QTime(0, 0), Qt::UTC));
        QCOMPARE(e.size, qint64(-1));

        e = mlsx("type=file;unix.owner=1000;unix.group=1000;unix.ownername=bob;unix.groupname=users; f");
        QCOMPARE(e.uid, qint64(1000));
        QCOMPARE(e.gid, qint64(1000));
        QCOMPARE(e.owner, QStringLiteral("bob"));
        QCOMPARE(e.group, QStringLiteral("users"));

        e = mlsx("type=OS.unix=slink:/etc/target;size=11; link", &r);
        QCOMPARE(e.type, EntryType::Symlink);
        QVERIFY(e.flags & EntryFlag::TargetUnknown);
        QCOMPARE(e.extra.value(QStringLiteral("linkTarget")).toString(), QStringLiteral("/etc/target"));
        QCOMPARE(mlsx("type=OS.unix=symlink; l").type, EntryType::Symlink);
        QCOMPARE(mlsx("type=OS.unix=chr-13/29; tty").type, EntryType::Special);
        QCOMPARE(mlsx("type=OS.unix=fifo; p").type, EntryType::Special);
        QCOMPARE(mlsx("type=OS.unix=door; d").type, EntryType::Unknown);
        QCOMPARE(mlsx("type=weird; w").type, EntryType::Unknown);
        QCOMPARE(mlsx("size=3; nameless type").type, EntryType::Unknown);
        QCOMPARE(mlsx(" only-a-name").name, QStringLiteral("only-a-name"));

        mlsx("type=cdir;modify=20200101000000; .", &r);
        QCOMPARE(r, LineResult::Skip);
        mlsx("type=pdir; ..", &r);
        QCOMPARE(r, LineResult::Skip);

        e = mlsx("type=file;size=1; caf\xe9\r", &r);
        QCOMPARE(r, LineResult::Entry);
        QCOMPARE(e.name, Names::decode("caf\xe9"));
        QVERIFY(e.flags & EntryFlag::NameNotUtf8);
        QVERIFY(!(mlsx("type=file; caf\xc3\xa9").flags & EntryFlag::NameNotUtf8));

        for (const QByteArray &bad : { QByteArray("type=file;size=1;nospace"), QByteArray("type=file;size=x; f"),
                                       QByteArray("type=file;size=-1; f"), QByteArray("type=file;modify=2021; f"),
                                       QByteArray("type=file;unix.mode=9z; f"), QByteArray("type=file;broken; f"),
                                       QByteArray("type=file;unix.uid=bob; f"), QByteArray("type=file;=x; f"),
                                       QByteArray("type=file; "), QByteArray("") }) {
            mlsx(bad, &r);
            QVERIFY2(r == LineResult::Invalid, bad.constData());
        }
    }

    void mlstReply()
    {
        Entry e;
        QCOMPARE(parseMlstReply(reply({ "250-Begin", " type=cdir;sizd=4096;modify=20261002152306;UNIX.mode=0755; /",
                                        "250 End." }),
                                &e),
                 LineResult::Entry);
        QCOMPARE(e.type, EntryType::Directory);
        QCOMPARE(e.mode, 0755);
        QCOMPARE(parseMlstReply(reply({ "250-Listing /x", " type=file;size=5; /home/a b", "250 End" }), &e),
                 LineResult::Entry);
        QCOMPARE(e.type, EntryType::File);
        QCOMPARE(e.size, qint64(5));
        QCOMPARE(parseMlstReply(reply({ "550 Not found" }), &e), LineResult::Invalid);
        QCOMPARE(parseMlstReply(reply({ "250-Begin", "no leading space", "250 End" }), &e), LineResult::Invalid);
    }

    // -------------------------------------------------------------- LIST

    void unixListing()
    {
        LineResult r;
        Entry e = listLine("-rw-r--r--    1 1001     1001       100000 Oct 02 15:23 up load.bin", &r);
        QCOMPARE(r, LineResult::Entry);
        QCOMPARE(e.name, QStringLiteral("up load.bin"));
        QCOMPARE(e.type, EntryType::File);
        QCOMPARE(e.size, qint64(100000));
        QCOMPARE(e.mode, 0644);
        QCOMPARE(e.uid, qint64(1001));
        QCOMPARE(e.gid, qint64(1001));
        QCOMPARE(e.modified, QDateTime(QDate(2026, 10, 2), QTime(15, 23), Qt::UTC));
        QVERIFY(e.extra.value(QStringLiteral("timeApproximate")).toBool());

        e = listLine("drwxr-x---    2 alice    staff        4096 Mar 31  2024 sub dir", &r);
        QCOMPARE(e.type, EntryType::Directory);
        QCOMPARE(e.owner, QStringLiteral("alice"));
        QCOMPARE(e.group, QStringLiteral("staff"));
        QCOMPARE(e.mode, 0750);
        QCOMPARE(e.modified, QDateTime(QDate(2024, 3, 31), QTime(0, 0), Qt::UTC));
        QCOMPARE(e.name, QStringLiteral("sub dir"));

        // Leading spaces in a name survive (one separator after the time).
        QCOMPARE(listLine("-rw-r--r-- 1 u g 1 Jan  1  2020  leading").name, QStringLiteral(" leading"));
        // Names that look like fields.
        QCOMPARE(listLine("-rw-r--r-- 1 u g 1 Jan  1  2020 Jan 1 2020 x").name, QStringLiteral("Jan 1 2020 x"));
        QCOMPARE(listLine("-rw-r--r-- 1 u g 1 Jan  1 12:00 -> odd").name, QStringLiteral("-> odd"));

        e = listLine("lrwxrwxrwx    1 0        0               9 Oct 02 15:23 link -> plain.txt", &r);
        QCOMPARE(e.type, EntryType::Symlink);
        QVERIFY(e.flags & EntryFlag::TargetUnknown);
        QCOMPARE(e.name, QStringLiteral("link"));
        QCOMPARE(e.extra.value(QStringLiteral("linkTarget")).toString(), QStringLiteral("plain.txt"));

        e = listLine("crw-rw-rw-    1 root     root       1,   3 Oct 02 15:23 null", &r);
        QCOMPARE(r, LineResult::Entry);
        QCOMPARE(e.type, EntryType::Special);
        QCOMPARE(e.size, qint64(-1));
        QCOMPARE(e.owner, QStringLiteral("root"));
        QCOMPARE(e.group, QStringLiteral("root"));

        // Without group column, without link count, ACL markers, special bits.
        e = listLine("-rw-r--r-- 1 owner 1234 Jan  1  2020 nogroup", &r);
        QCOMPARE(r, LineResult::Entry);
        QCOMPARE(e.owner, QStringLiteral("owner"));
        QVERIFY(e.group.isEmpty());
        QCOMPARE(e.size, qint64(1234));
        QCOMPARE(listLine("-rw-r--r--+ 1 u g 5 Jan  1  2020 acl", &r).name, QStringLiteral("acl"));
        QCOMPARE(r, LineResult::Entry);
        QCOMPARE(listLine("-rwsr-sr-t 1 u g 5 Jan  1  2020 bits").mode, 07755);
        QCOMPARE(listLine("-rwSr-Sr-T 1 u g 5 Jan  1  2020 bits").mode, 07644);
        QCOMPARE(listLine("drwxr-xr-x folder owner 0 Jan  1  2020 nolinks", &r).name, QStringLiteral("nolinks"));
        QCOMPARE(r, LineResult::Entry);
        QCOMPARE(listLine("prw-r--r-- 1 u g 0 Jan  1  2020 fifo").type, EntryType::Special);

        // Non-UTF-8 bytes stay lossless.
        e = listLine("-rw-r--r-- 1 u g 1 Jan  1  2020 caf\xe9\r", &r);
        QCOMPARE(e.name, Names::decode("caf\xe9"));
        QVERIFY(e.flags & EntryFlag::NameNotUtf8);

        for (const QByteArray &skip : { QByteArray("total 12"), QByteArray(""), QByteArray("   "),
                                        QByteArray("drwxr-xr-x 2 u g 4096 Oct 02 15:23 ."),
                                        QByteArray("drwxr-xr-x 2 u g 4096 Oct 02 15:23 ..") }) {
            listLine(skip, &r);
            QVERIFY2(r == LineResult::Skip, skip.constData());
        }
        for (const QByteArray &bad : {
                 QByteArray("garbage line"), QByteArray("xrw-r--r-- 1 u g 1 Jan 1 2020 f"),
                 QByteArray("-rw-r--r-- 1 u g 1 Foo 1 2020 f"), QByteArray("-rw-r--r-- 1 u g 1 Jan 32 2020 f"),
                 QByteArray("-rw-r--r-- 1 u g 1 Jan 1 25:00 f"), QByteArray("-rw-r--r-- 1 u g 1 Jan 1 2020"),
                 QByteArray("-rw-r--r-- 1 u g x Jan 1 2020 f"), QByteArray("-rwxrwxrwz 1 u g 1 Jan 1 2020 f"),
                 QByteArray("-rw-r--r-- 1 a b c 1 Jan 1 2020 f"), QByteArray("-rw-r--r-- 1 u g 1 Feb 30 2020 f"),
                 QByteArray("-rw-r--r-- 1 u g 1 Jan 1 2020 a/b"), QByteArray("-rw-r--r--x 1 u g 1 Jan 1 2020 f"),
                 QByteArray("total x") }) {
            listLine(bad, &r);
            QVERIFY2(r == LineResult::Invalid, bad.constData());
        }
    }

    // F-3: "within six months" for times without a year.
    void yearlessDates_data()
    {
        QTest::addColumn<QDate>("today");
        QTest::addColumn<int>("month");
        QTest::addColumn<int>("day");
        QTest::addColumn<QDate>("expected");
        const QDate today(2026, 10, 2);
        QTest::newRow("today") << today << 10 << 2 << QDate(2026, 10, 2);
        QTest::newRow("tomorrow (time zones)") << today << 10 << 3 << QDate(2026, 10, 3);
        QTest::newRow("two days ahead: last year") << today << 10 << 4 << QDate(2025, 10, 4);
        QTest::newRow("december: last year") << today << 12 << 31 << QDate(2025, 12, 31);
        QTest::newRow("six months ago") << today << 4 << 2 << QDate(2026, 4, 2);
        QTest::newRow("january") << today << 1 << 1 << QDate(2026, 1, 1);
        QTest::newRow("new year, december") << QDate(2027, 1, 5) << 12 << 20 << QDate(2026, 12, 20);
        QTest::newRow("leap day from last year") << QDate(2025, 3, 1) << 2 << 29 << QDate(2024, 2, 29);
        QTest::newRow("leap day this year") << QDate(2028, 3, 1) << 2 << 29 << QDate(2028, 2, 29);
        QTest::newRow("no such leap day") << today << 2 << 29 << QDate();
    }

    void yearlessDates()
    {
        QFETCH(QDate, today);
        QFETCH(int, month);
        QFETCH(int, day);
        QFETCH(QDate, expected);
        QCOMPARE(resolveYearlessDate(month, day, today), expected);
    }

    void yearlessListing()
    {
        const QDateTime now(QDate(2026, 1, 10), QTime(8, 0), Qt::UTC);
        LineResult r;
        QCOMPARE(listLine("-rw-r--r-- 1 u g 1 Dec 30 23:59 f", &r, now).modified,
                 QDateTime(QDate(2025, 12, 30), QTime(23, 59), Qt::UTC));
        QCOMPARE(listLine("-rw-r--r-- 1 u g 1 Jan 10 07:00 f", &r, now).modified,
                 QDateTime(QDate(2026, 1, 10), QTime(7, 0), Qt::UTC));
    }

    void dosListing()
    {
        LineResult r;
        Entry e = listLine("10-02-26  03:23PM       <DIR>          My Folder", &r);
        QCOMPARE(r, LineResult::Entry);
        QCOMPARE(e.type, EntryType::Directory);
        QCOMPARE(e.name, QStringLiteral("My Folder"));
        QCOMPARE(e.modified, QDateTime(QDate(2026, 10, 2), QTime(15, 23), Qt::UTC));
        QVERIFY(e.extra.value(QStringLiteral("timeApproximate")).toBool());
        e = listLine("01-15-1999  12:05AM              1234567 report.doc", &r);
        QCOMPARE(e.type, EntryType::File);
        QCOMPARE(e.size, qint64(1234567));
        QCOMPARE(e.modified, QDateTime(QDate(1999, 1, 15), QTime(0, 5), Qt::UTC));
        e = listLine("12-31-69  12:00PM 1 a", &r);
        QCOMPARE(e.modified, QDateTime(QDate(2069, 12, 31), QTime(12, 0), Qt::UTC));
        e = listLine("01-01-70  23:59 1 b", &r);
        QCOMPARE(e.modified, QDateTime(QDate(1970, 1, 1), QTime(23, 59), Qt::UTC));
        e = listLine("2024-03-03  11:30 PM  <DIR> c", &r);
        QCOMPARE(r, LineResult::Entry);
        QCOMPARE(e.modified, QDateTime(QDate(2024, 3, 3), QTime(23, 30), Qt::UTC));
        listLine("10-02-26  03:23PM <DIR> .", &r);
        QCOMPARE(r, LineResult::Skip);
        for (const QByteArray &bad : { QByteArray("10-02-26  03:23PM"), QByteArray("13-02-26 03:23PM 1 x"),
                                       QByteArray("10-02-26 13:23PM 1 x"), QByteArray("10-02-26 03:23PM big x"),
                                       QByteArray("10-02 03:23PM 1 x"), QByteArray("10-02-2 03:23 1 x"),
                                       QByteArray("1x-02-26 03:23 1 x"), QByteArray("10-02-26 3:2 1 x") }) {
            listLine(bad, &r);
            QVERIFY2(r == LineResult::Invalid, bad.constData());
        }
    }

    void listingParser()
    {
        const QDateTime now(QDate(2026, 10, 2), QTime(12, 0), Qt::UTC);
        ListingParser parser(false, now);
        QVector<Entry> out;
        const QByteArray data = "total 8\r\n-rw-r--r-- 1 u g 1 Jan  1  2020 a\r\nnonsense\r\n"
                                "-rw-r--r-- 1 u g 2 Jan  1  2020 b\r\n-rw-r--r-- 1 u g 3 Jan  1  2020 c";
        for (int i = 0; i < data.size(); i += 5)
            parser.feed(data.constData() + i, size_t(qMin(5, data.size() - i)), &out);
        QCOMPARE(out.size(), 2);
        parser.finish(&out);
        QCOMPARE(out.size(), 3);
        QCOMPARE(out.at(2).name, QStringLiteral("c"));
        QCOMPARE(parser.invalidLines(), 1);

        // An overlong line is dropped and counted, the next one parses.
        ListingParser bounded(false, now);
        out.clear();
        const QByteArray huge(ListingParser::MaxLineBytes + 10, 'x');
        bounded.feed(huge.constData(), size_t(huge.size()), &out);
        bounded.feed(huge.constData(), size_t(huge.size()), &out);
        const QByteArray rest = "\n-rw-r--r-- 1 u g 1 Jan  1  2020 ok\n";
        bounded.feed(rest.constData(), size_t(rest.size()), &out);
        bounded.finish(&out);
        QCOMPARE(out.size(), 1);
        QCOMPARE(bounded.invalidLines(), 1);

        ListingParser mlsd(true, now);
        out.clear();
        const QByteArray facts = "type=cdir; .\r\ntype=pdir; ..\r\ntype=file;size=1; f\r\ntype=file; a/b\r\n"
                                 "type=dir; .\r\nbroken\r\n\r\n";
        mlsd.feed(facts.constData(), size_t(facts.size()), &out);
        mlsd.finish(&out);
        QCOMPARE(out.size(), 1);
        QCOMPARE(out.at(0).name, QStringLiteral("f"));
        QCOMPARE(mlsd.invalidLines(), 2);
    }

    // ------------------------------------------------------- settings, paths

    void settings()
    {
        ConnectionParams p;
        p.host = QStringLiteral("ftp.example.org");
        Settings s;
        QVERIFY(settingsFrom(p, &s).ok());
        QCOMPARE(s.tlsMode, TlsMode::Explicit);
        QCOMPARE(s.port, 21);
        QVERIFY(!s.verifyPeer);
        QVERIFY(s.testCaFile.isEmpty());
        p.options.insert(QStringLiteral("tls_mode"), QStringLiteral("implicit"));
        p.options.insert(QStringLiteral("host_key"), QStringLiteral(" tls-spki-sha256 AAAA "));
        p.options.insert(QStringLiteral("tls_verify_peer"), QStringLiteral("true"));
        p.options.insert(QStringLiteral("test_ca_file"), QStringLiteral("/tmp/ca.pem"));
        QVERIFY(settingsFrom(p, &s).ok());
        QCOMPARE(s.tlsMode, TlsMode::Implicit);
        QCOMPARE(s.port, 990);
        QCOMPARE(s.pin, QStringLiteral("tls-spki-sha256 AAAA"));
        QVERIFY(s.verifyPeer);
        QCOMPARE(s.testCaFile, QByteArray("/tmp/ca.pem"));   // NETVFS_TLS_TEST_HOOKS build
        p.port = 2121;
        QVERIFY(settingsFrom(p, &s).ok());
        QCOMPARE(s.port, 2121);
        // F-1: plain FTP only with the insecure consent; nothing unknown.
        p.options.insert(QStringLiteral("tls_mode"), QStringLiteral("none"));
        QCOMPARE(settingsFrom(p, &s).error(), Error::SecurityPolicy);
        p.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("false"));
        QCOMPARE(settingsFrom(p, &s).error(), Error::SecurityPolicy);
        p.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
        QVERIFY(settingsFrom(p, &s).ok());
        QCOMPARE(s.tlsMode, TlsMode::None);
        p.options.insert(QStringLiteral("tls_mode"), QStringLiteral("ssl"));
        QCOMPARE(settingsFrom(p, &s).error(), Error::SecurityPolicy);
        p.options.insert(QStringLiteral("tls_mode"), QStringLiteral("Explicit"));
        QVERIFY(settingsFrom(p, &s).ok());
        p.host = QStringLiteral("user@host");
        QCOMPARE(settingsFrom(p, &s).error(), Error::Internal);
        p.host.clear();
        QCOMPARE(settingsFrom(p, &s).error(), Error::Internal);
        p.host = QStringLiteral("h");
        p.port = 70000;
        QCOMPARE(settingsFrom(p, &s).error(), Error::Internal);
    }

    void urls()
    {
        Settings s;
        s.host = QStringLiteral("ftp.example.org");
        s.port = 21;
        QCOMPARE(baseUrl(s), QByteArray("ftp://ftp.example.org:21/"));
        s.tlsMode = TlsMode::Implicit;
        s.host = QStringLiteral("::1");
        s.port = 990;
        QCOMPARE(baseUrl(s), QByteArray("ftps://[::1]:990/"));
        QCOMPARE(urlPath("/home/alice/a b;type=a%"), QByteArray("%2Fhome/alice/a%20b%3Btype%3Da%25"));
        QCOMPARE(urlPath("rel/x"), QByteArray("rel/x"));
        QCOMPARE(urlPath("/"), QByteArray("%2F"));
        QCOMPARE(urlPath("/caf\xe9?#[]"), QByteArray("%2Fcaf%E9%3F%23%5B%5D"));
        QCOMPARE(urlPath("A-z_0.9~"), QByteArray("A-z_0.9~"));
    }

    void remotePaths()
    {
        QByteArray out;
        QVERIFY(remotePath(QStringLiteral("a/b"), "/home/alice", &out).ok());
        QCOMPARE(out, QByteArray("/home/alice/a/b"));
        QVERIFY(remotePath(QStringLiteral("a"), "/", &out).ok());
        QCOMPARE(out, QByteArray("/a"));
        QVERIFY(remotePath(QString(), "/home/alice", &out).ok());
        QCOMPARE(out, QByteArray("/home/alice"));
        QVERIFY(remotePath(QStringLiteral("/etc//x/"), "/home/alice", &out).ok());
        QCOMPARE(out, QByteArray("/etc/x"));
        QVERIFY(remotePath(Names::decode("caf\xe9"), "/h", &out).ok());
        QCOMPARE(out, QByteArray("/h/caf\xe9"));
        QCOMPARE(remotePath(QStringLiteral("a\r\nDELE x"), "/h", &out).error(), Error::InvalidName);
        QCOMPARE(remotePath(QStringLiteral("a\nb"), "/h", &out).error(), Error::InvalidName);
        QCOMPARE(remotePath(QString(QChar(0xD800)), "/h", &out).error(), Error::InvalidName);
        QVERIFY(!remotePath(QStringLiteral("a/../b"), "/h", &out).ok());
        QCOMPARE(remoteParent("/home/alice/x"), QByteArray("/home/alice"));
        QCOMPARE(remoteParent("/x"), QByteArray("/"));
        QCOMPARE(remoteParent("/"), QByteArray("/"));
    }

    // ------------------------------------------------------------- F-7

    void replyErrors_data()
    {
        QTest::addColumn<QByteArray>("line");
        QTest::addColumn<Error>("error");
        QTest::addColumn<bool>("ambiguous");
        QTest::newRow("530") << QByteArray("530 Login incorrect.") << Error::AuthFailed << false;
        QTest::newRow("550 no such file") << QByteArray("550 No such file or directory") << Error::NotFound << false;
        QTest::newRow("550 not found") << QByteArray("550 /x: File not found") << Error::NotFound << false;
        QTest::newRow("550 does not exist") << QByteArray("550 Directory does not exist") << Error::NotFound << false;
        QTest::newRow("550 can't find") << QByteArray("550 Can't find file") << Error::NotFound << false;
        QTest::newRow("550 permission") << QByteArray("550 Permission denied.") << Error::PermissionDenied << false;
        QTest::newRow("550 access denied") << QByteArray("550 Access is denied.") << Error::PermissionDenied << false;
        QTest::newRow("550 not allowed") << QByteArray("550 Operation not allowed") << Error::PermissionDenied << false;
        QTest::newRow("550 exists") << QByteArray("550 File exists") << Error::AlreadyExists << false;
        QTest::newRow("550 not empty") << QByteArray("550 Directory not empty") << Error::DirectoryNotEmpty << false;
        QTest::newRow("550 not a dir") << QByteArray("550 Not a directory") << Error::NotADirectory << false;
        QTest::newRow("550 is a dir") << QByteArray("550 Is a directory") << Error::IsADirectory << false;
        QTest::newRow("550 vague") << QByteArray("550 Failed to open file.") << Error::PermissionDenied << true;
        QTest::newRow("550 empty") << QByteArray("550") << Error::PermissionDenied << true;
        QTest::newRow("552") << QByteArray("552 Disk full") << Error::NoSpace << false;
        QTest::newRow("452") << QByteArray("452 Insufficient storage") << Error::NoSpace << false;
        QTest::newRow("553") << QByteArray("553 Could not create file.") << Error::InvalidName << false;
        QTest::newRow("421 users") << QByteArray("421 There are too many connected users, please try later.")
                                   << Error::TooManyConnections << false;
        QTest::newRow("421 per ip") << QByteArray("421 Too many connections from your IP")
                                    << Error::TooManyConnections << false;
        QTest::newRow("421 timeout") << QByteArray("421 Timeout.") << Error::ConnectionLost << false;
        QTest::newRow("426") << QByteArray("426 Connection closed; transfer aborted.") << Error::ConnectionLost << false;
        QTest::newRow("425") << QByteArray("425 Can't open data connection.") << Error::ConnectionLost << false;
        QTest::newRow("450") << QByteArray("450 File busy") << Error::Locked << false;
        QTest::newRow("500") << QByteArray("500 Unknown command.") << Error::Unsupported << false;
        QTest::newRow("502") << QByteArray("502 Not implemented") << Error::Unsupported << false;
        QTest::newRow("504") << QByteArray("504 Unknown command") << Error::Unsupported << false;
        QTest::newRow("501") << QByteArray("501 Syntax error") << Error::ProtocolError << false;
        QTest::newRow("522") << QByteArray("522 SSL connection failed") << Error::ProtocolError << false;
    }

    void replyErrors()
    {
        QFETCH(QByteArray, line);
        QFETCH(Error, error);
        QFETCH(bool, ambiguous);
        bool vague = !ambiguous;
        const Result r = replyError(reply({ line }), QStringLiteral("Doing"), &vague);
        QCOMPARE(r.error(), error);
        QCOMPARE(vague, ambiguous);
        QVERIFY(r.message().startsWith(QLatin1String("Doing: ")));
        QVERIFY(r.detail().startsWith(QStringLiteral("FTP %1").arg(QString::fromLatin1(line.left(3)))));
        QCOMPARE(replyError(reply({ line }), QStringLiteral("x")).error(), error);
    }

    void curlErrors()
    {
        const Reply none;
        QCOMPARE(curlError(CURLE_OPERATION_TIMEDOUT, none, false, QString()).error(), Error::Timeout);
        QCOMPARE(curlError(CURLE_COULDNT_CONNECT, none, false, QString()).error(), Error::NetworkUnreachable);
        QCOMPARE(curlError(CURLE_COULDNT_RESOLVE_HOST, none, false, QString()).error(), Error::NetworkUnreachable);
        QCOMPARE(curlError(CURLE_SSL_PINNEDPUBKEYNOTMATCH, none, false, QString()).error(),
                 Error::ServerIdentityChanged);
        QCOMPARE(curlError(CURLE_PEER_FAILED_VERIFICATION, none, false, QString()).error(),
                 Error::ServerIdentityChanged);
        QCOMPARE(curlError(CURLE_USE_SSL_FAILED, reply({ "500 AUTH not understood" }), false, QString()).error(),
                 Error::SecurityPolicy);
        QCOMPARE(curlError(CURLE_SSL_CONNECT_ERROR, none, false, QString()).error(), Error::SecurityPolicy);
        QCOMPARE(curlError(CURLE_ABORTED_BY_CALLBACK, none, false, QString()).error(), Error::Canceled);
        QCOMPARE(curlError(CURLE_RECV_ERROR, reply({ "550 x" }), true, QString()).error(), Error::Canceled);
        QCOMPARE(curlError(CURLE_RECV_ERROR, none, false, QString()).error(), Error::ConnectionLost);
        QCOMPARE(curlError(CURLE_SEND_ERROR, none, false, QString()).error(), Error::ConnectionLost);
        QCOMPARE(curlError(CURLE_GOT_NOTHING, none, false, QString()).error(), Error::ConnectionLost);
        QCOMPARE(curlError(CURLE_PARTIAL_FILE, none, false, QString()).error(), Error::ConnectionLost);
        QCOMPARE(curlError(CURLE_WRITE_ERROR, none, false, QString()).error(), Error::Internal);
        // Server replies decide where libcurl only says "the server refused".
        QCOMPARE(curlError(CURLE_LOGIN_DENIED, reply({ "530 Login incorrect." }), false, QString()).error(),
                 Error::AuthFailed);
        QCOMPARE(curlError(CURLE_LOGIN_DENIED, none, false, QString()).error(), Error::AuthFailed);
        QCOMPARE(curlError(CURLE_QUOTE_ERROR, reply({ "550 No such file" }), false, QString()).error(),
                 Error::NotFound);
        QCOMPARE(curlError(CURLE_UPLOAD_FAILED, reply({ "552 Quota" }), false, QString()).error(), Error::NoSpace);
        QCOMPARE(curlError(CURLE_UPLOAD_FAILED, none, false, QString()).error(), Error::PermissionDenied);
        QCOMPARE(curlError(CURLE_REMOTE_FILE_NOT_FOUND, none, false, QString()).error(), Error::NotFound);
        QCOMPARE(curlError(CURLE_REMOTE_ACCESS_DENIED, none, false, QString()).error(), Error::PermissionDenied);
        QCOMPARE(curlError(CURLE_REMOTE_DISK_FULL, none, false, QString()).error(), Error::NoSpace);
        QCOMPARE(curlError(CURLE_FTP_COULDNT_USE_REST, none, false, QString()).error(), Error::Unsupported);
        QCOMPARE(curlError(CURLE_WEIRD_SERVER_REPLY, reply({ "421 Too many users" }), false, QString()).error(),
                 Error::TooManyConnections);
        QCOMPARE(curlError(CURLE_WEIRD_SERVER_REPLY, reply({ "226 ok" }), false, QString()).error(),
                 Error::ProtocolError);
        const Result r = curlError(CURLE_FTP_WEIRD_PASV_REPLY, none, false, QStringLiteral("Listing"));
        QCOMPARE(r.error(), Error::ProtocolError);
        QVERIFY(r.detail().startsWith(QLatin1String("curl ")));
    }

    // ------------------------------------------------------------ XSEC-2

    void tlsGuard()
    {
        using V = TlsGuard::Verdict;
        TlsGuard guard;
        // Before any greeting: ordinary replies pass, a login claim does not.
        QCOMPARE(guard.reply(200), V::Continue);
        QCOMPARE(guard.reply(230), V::Unexpected);
        // A full explicit-TLS sign-in.
        for (const int code : { 220, 234, 331, 230, 200, 200, 257, 211, 200, 229 })
            QCOMPARE(guard.reply(code), V::Continue);
        // A later login claim outside the sequence is refused.
        QCOMPARE(guard.reply(230), V::Unexpected);
        // AUTH TLS refused (also "530 please login with USER and PASS").
        guard.reset();
        QCOMPARE(guard.reply(220), V::Continue);
        QCOMPARE(guard.reply(500), V::AuthRefused);
        guard.reset();
        QCOMPARE(guard.reply(220), V::Continue);
        QCOMPARE(guard.reply(530), V::AuthRefused);
        // Whatever else is not 234, a 220 ("service ready", the greeting's
        // code) and codes outside the RFC 959 range included: libcurl would
        // go on with "AUTH SSL" and USER in clear text.
        for (const int code : { 220, 200, 230, 334, 431, 502, 534, 600, 999, 0 }) {
            guard.reset();
            QCOMPARE(guard.reply(220), V::Continue);
            QCOMPARE(guard.reply(code), V::AuthRefused);
        }
        // PROT P refused.
        guard.reset();
        for (const int code : { 220, 234, 331, 230, 200 })
            QCOMPARE(guard.reply(code), V::Continue);
        QCOMPARE(guard.reply(536), V::ProtectionRefused);
        // A greeting in the middle of a sign-in is not one.
        for (const QVector<int> &prefix : { QVector<int> { 220, 234 }, QVector<int> { 220, 234, 230 } }) {
            guard.reset();
            for (const int code : prefix)
                QCOMPARE(guard.reply(code), V::Continue);
            QCOMPARE(guard.reply(220), V::Unexpected);
        }
        // A failed login leaves the guard waiting; every request starts anew,
        // so a greeting that claims a login after it is refused (230 is what
        // libcurl takes for the greeting in "try" mode: no AUTH TLS, no USER).
        guard.reset();
        for (const int code : { 220, 234, 331, 530 })
            QCOMPARE(guard.reply(code), V::Continue);
        guard.reset();
        QCOMPARE(guard.reply(230), V::Unexpected);
        guard.reset();
        for (const int code : { 220, 234, 230, 500, 200 })
            QCOMPARE(guard.reply(code), V::Continue);
        // A 230 straight after the greeting (no AUTH answer) is refused.
        guard.reset();
        QCOMPARE(guard.reply(220), V::Continue);
        QCOMPARE(guard.reply(230), V::AuthRefused);
        guard.reset();
        QCOMPARE(guard.reply(331), V::Continue);
    }

    // XSEC-2: the guard splits the header callback's bytes into replies the
    // way libcurl does (ftp_endofresp: the first line that is "ddd "), because
    // that is what libcurl acts on.
    void tlsGuardFollowsLibcurl()
    {
        using V = TlsGuard::Verdict;
        const auto feed = [](TlsGuard *guard, const char *text) { return guard->feed(text, strlen(text)); };
        TlsGuard guard;
        QCOMPARE(feed(&guard, "220 netvfs\r\n234 go\r\n331 pass\r\n230 in\r\n200 pbsz\r\n200 prot\r\n"), V::Continue);
        QCOMPARE(feed(&guard, "230 out of sequence\r\n"), V::Unexpected);

        // Replies cut anywhere, byte by byte.
        guard.reset();
        const QByteArray stream("220-banner\r\n 220 indented\r\n220 end\r\n234 go\r\n");
        for (const char c : stream)
            QCOMPARE(guard.feed(&c, 1), V::Continue);
        QCOMPARE(feed(&guard, "331 a\r\n"), V::Continue);

        // A multi-line AUTH answer that starts like a success but ends with
        // a refusal: libcurl sees the 500 (the closing line only has to be
        // "ddd "), so must the guard.
        guard.reset();
        QCOMPARE(feed(&guard, "220 hi\r\n"), V::Continue);
        QCOMPARE(feed(&guard, "234-fine\r\n500 not really\r\n"), V::AuthRefused);
        QCOMPARE(QString::fromLatin1(guard.lastLine()), QStringLiteral("500 not really\r\n"));
        // ... and the other way round: libcurl takes it as 234 and starts TLS.
        guard.reset();
        QCOMPARE(feed(&guard, "220 hi\r\n"), V::Continue);
        QCOMPARE(feed(&guard, "500-no\r\n234 yes\r\n"), V::Continue);
        // The greeting hidden behind a continuation line.
        guard.reset();
        QCOMPARE(feed(&guard, "220-hi\r\n230 logged in\r\n"), V::Unexpected);

        // Codes outside 1xx..5xx still end a reply for libcurl.
        for (const char *answer : { "600 x\r\n", "999 x\r\n", "000 x\r\n", "220 x\r\n", "230 x\r\n" }) {
            guard.reset();
            QCOMPARE(feed(&guard, "220 hi\r\n"), V::Continue);
            QCOMPARE(feed(&guard, answer), V::AuthRefused);
        }
        // Lines that are not the end of a reply (libcurl waits for more).
        guard.reset();
        QCOMPARE(feed(&guard, "220 hi\r\n"), V::Continue);
        for (const char *line : { "234\r\n", "23x ok\r\n", "2345 x\r\n", " 500 x\r\n", "500-x\r\n", "garbage\r\n", "\r\n" })
            QCOMPARE(feed(&guard, line), V::Continue);
        QCOMPARE(feed(&guard, "534 now\r\n"), V::AuthRefused);

        // Very long lines are cut, the end of the reply is still found.
        guard.reset();
        QCOMPARE(feed(&guard, "220 hi\r\n"), V::Continue);
        const QByteArray longLine = "234-" + QByteArray(100000, 'x') + "\r\n503 bye\r\n";
        QCOMPARE(guard.feed(longLine.constData(), size_t(longLine.size())), V::AuthRefused);
        QVERIFY(guard.lastLine().size() <= 512);
        // A bare LF ends a line, too.
        guard.reset();
        QCOMPARE(feed(&guard, "220 hi\n500 no\n"), V::AuthRefused);
    }

    // ------------------------------------------------------- XC-16, W-3

    void tlsIdentity()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const Key caKey = makeKey();
        const Cert ca = makeCert(caKey.get(), "Test CA", nullptr, -Day, 30 * Day, nullptr, nullptr, true);
        const QString caFile = writePem(dir.filePath(QStringLiteral("ca.pem")), ca.get());
        CurlTls::TrustStore anchors;
        anchors.caFile = caFile.toLocal8Bit();
        CurlTls::TrustStore none;

        const Key key = makeKey();
        const Cert good = makeCert(key.get(), "server", "DNS:ftp.example.org,IP:127.0.0.1", -Day, 30 * Day,
                                   ca.get(), caKey.get());
        ServerIdentity id = evaluate(good.get(), nullptr, "ftp.example.org", anchors);
        QCOMPARE(id.kind, ServerIdentity::Kind::TlsCertificate);
        QCOMPARE(id.algorithm, QStringLiteral("tls-spki-sha256"));
        QCOMPARE(id.publicKey, spki(good.get()));
        QCOMPARE(id.fingerprint,
                 QString::fromLatin1(QCryptographicHash::hash(spki(good.get()), QCryptographicHash::Sha256).toBase64()));
        QVERIFY(id.systemTrusted);
        QCOMPARE(id.problems, 0);
        QCOMPARE(id.details.value(QStringLiteral("subject")).toString(), QStringLiteral("CN=server"));
        QCOMPARE(id.details.value(QStringLiteral("issuer")).toString(), QStringLiteral("CN=Test CA"));
        QCOMPARE(id.details.value(QStringLiteral("sans")).toStringList(),
                 QStringList({ QStringLiteral("DNS:ftp.example.org"), QStringLiteral("IP:127.0.0.1") }));
        QCOMPARE(id.details.value(QStringLiteral("certSha256")).toString().size(), 64);
        QVERIFY(id.details.value(QStringLiteral("notBefore")).toDateTime() < QDateTime::currentDateTimeUtc());
        QVERIFY(id.details.value(QStringLiteral("notAfter")).toDateTime() > QDateTime::currentDateTimeUtc());
        QCOMPARE(ServerIdentity::fromPin(id.toPin()), id);

        // IP literals, also in brackets, match IP SANs.
        QVERIFY(evaluate(good.get(), nullptr, "127.0.0.1", anchors).systemTrusted);
        QVERIFY(evaluate(good.get(), nullptr, "[127.0.0.1]", anchors).systemTrusted);
        id = evaluate(good.get(), nullptr, "127.0.0.2", anchors);
        QVERIFY(!id.systemTrusted);
        QCOMPARE(id.problems, int(ServerIdentity::HostnameMismatch));
        id = evaluate(good.get(), nullptr, "other.example.org", anchors);
        QVERIFY(!id.systemTrusted);
        QCOMPARE(id.problems, int(ServerIdentity::HostnameMismatch));
        // Without the anchor the chain is untrusted.
        id = evaluate(good.get(), nullptr, "ftp.example.org", none);
        QVERIFY(!id.systemTrusted);
        QCOMPARE(id.problems, int(ServerIdentity::UntrustedRoot));

        const Cert self = makeCert(key.get(), "self", "DNS:ftp.example.org", -Day, Day);
        id = evaluate(self.get(), nullptr, "ftp.example.org", anchors);
        QVERIFY(!id.systemTrusted);
        QVERIFY(id.problems & ServerIdentity::SelfSigned);
        QVERIFY(!(id.problems & ServerIdentity::HostnameMismatch));
        QCOMPARE(id.publicKey, spki(good.get()));   // same key, same pin

        const Cert expired = makeCert(key.get(), "old", "DNS:ftp.example.org", -10 * Day, -Day, ca.get(),
                                      caKey.get());
        id = evaluate(expired.get(), nullptr, "ftp.example.org", anchors);
        QVERIFY(!id.systemTrusted);
        QCOMPARE(id.problems, int(ServerIdentity::Expired));
        const Cert future = makeCert(key.get(), "new", "DNS:ftp.example.org", Day, 10 * Day, ca.get(), caKey.get());
        id = evaluate(future.get(), nullptr, "ftp.example.org", anchors);
        QCOMPARE(id.problems, int(ServerIdentity::NotYetValid));
        const Cert both = makeCert(key.get(), "x", "DNS:elsewhere", -10 * Day, -Day, ca.get(), caKey.get());
        id = evaluate(both.get(), nullptr, "ftp.example.org", anchors);
        QCOMPARE(id.problems, int(ServerIdentity::Expired | ServerIdentity::HostnameMismatch));

        // An intermediate presented by the server completes the chain.
        const Key midKey = makeKey();
        const Cert mid = makeCert(midKey.get(), "Mid CA", nullptr, -Day, 30 * Day, ca.get(), caKey.get(), true);
        const Cert leaf = makeCert(key.get(), "leaf", "DNS:ftp.example.org", -Day, Day, mid.get(), midKey.get());
        STACK_OF(X509) *chain = sk_X509_new_null();
        sk_X509_push(chain, leaf.get());
        sk_X509_push(chain, mid.get());
        id = evaluate(leaf.get(), chain, "ftp.example.org", anchors);
        QVERIFY(id.systemTrusted);
        id = evaluate(leaf.get(), nullptr, "ftp.example.org", anchors);
        QVERIFY(!id.systemTrusted);
        QCOMPARE(id.problems, int(ServerIdentity::UntrustedRoot));
        sk_X509_free(chain);

        QVERIFY(evaluate(nullptr, nullptr, "x", anchors).isEmpty());
    }

    void trustStore()
    {
        CURL *easy = curl_easy_init();
        QVERIFY(easy);
        CurlTls::TrustStore store = CurlTls::trustStore(easy, QByteArray("/tmp/test-ca.pem"));
        QCOMPARE(store.caFile, QByteArray("/tmp/test-ca.pem"));
        QVERIFY(store.caPath.isEmpty());
        QCOMPARE(CurlTls::applyTestCaFile(easy, "/tmp/test-ca.pem"), CURLE_OK);
        // Without the hook: libcurl's own bundle.
        store = CurlTls::trustStore(easy, QByteArray());
        QVERIFY(!store.caFile.isEmpty() || !store.caPath.isEmpty());
        QVERIFY(store.caFile != "/tmp/test-ca.pem");
        QCOMPARE(CurlTls::applyTestCaFile(easy, QByteArray()), CURLE_OK);
        QVERIFY(CurlTls::isOpenSsl());
        curl_easy_cleanup(easy);
    }

    // W-4 decisions that do not need a server.
    void identityPolicy()
    {
        CURL *easy = curl_easy_init();
        QVERIFY(easy);
        const ServerIdentity seen = ServerIdentity::fromTlsSpki(QByteArray("spki"));
        ServerIdentity trusted = seen;
        trusted.systemTrusted = true;
        QVERIFY(CurlTls::applyIdentityPolicy(easy, seen.toPin(), false, seen).ok());
        QVERIFY(CurlTls::applyIdentityPolicy(easy, seen.toPin(), true, trusted).ok());
        QVERIFY(CurlTls::applyIdentityPolicy(easy, QString(), false, trusted).ok());
        QVERIFY(CurlTls::applyIdentityPolicy(easy, QString(), false, seen).ok());
        // A pin taken from a trusted chain that is no longer trusted.
        QCOMPARE(CurlTls::applyIdentityPolicy(easy, seen.toPin(), true, seen).error(), Error::ServerIdentityChanged);
        // An SSH host key pin on an FTPS account.
        QCOMPARE(CurlTls::applyIdentityPolicy(easy, QStringLiteral("ssh-ed25519 AAAA"), false, seen).error(),
                 Error::ServerIdentityChanged);
        QCOMPARE(CurlTls::applyIdentityPolicy(easy, QString(), false, ServerIdentity()).error(), Error::Internal);
        curl_easy_cleanup(easy);
    }
};

QTEST_GUILESS_MAIN(TestFtp)
#include "tst_ftp.moc"
