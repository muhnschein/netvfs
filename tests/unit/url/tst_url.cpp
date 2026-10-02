// SPDX-License-Identifier: LGPL-2.1-or-later
// SPEC-v2 XH-6 (Url), XH-7 (Paths::sanitizeFor), XC-4 (Paths::normalize amendment).
#include "names.h"
#include "paths.h"
#include "url.h"

#include <QtTest/QtTest>

using namespace NetVfs;

Q_DECLARE_METATYPE(NetVfs::Error)

namespace {

QString surrogate(int byte)
{
    return QString(QChar(ushort(0xDC00 + byte)));
}

QString opt(const ConnectionParams &p, const char *key)
{
    return p.option(QLatin1String(key));
}

} // namespace

class TstUrl : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase() { qRegisterMetaType<NetVfs::Error>(); }

    // ------------------------------------------------------------------ parse

    void parse_data()
    {
        QTest::addColumn<QString>("url");
        QTest::addColumn<QString>("provider");
        QTest::addColumn<QString>("host");
        QTest::addColumn<int>("port");
        QTest::addColumn<QString>("user");
        QTest::addColumn<QString>("options");     // "key=value;..." in key order
        QTest::addColumn<QString>("path");

        QTest::newRow("sftp bare") << "sftp://example.com" << "sftp" << "example.com" << 0 << "" << "" << "";
        QTest::newRow("sftp full") << "sftp://alice@example.com:2222/home/alice" << "sftp" << "example.com" << 2222
                                   << "alice" << "" << "/home/alice";
        QTest::newRow("sftp root") << "sftp://h/" << "sftp" << "h" << 0 << "" << "" << "/";
        QTest::newRow("ssh alias") << "ssh://h/x" << "sftp" << "h" << 0 << "" << "" << "/x";
        QTest::newRow("default port dropped") << "sftp://h:22/x" << "sftp" << "h" << 0 << "" << "" << "/x";
        QTest::newRow("other default is a port") << "sftp://h:445/x" << "sftp" << "h" << 445 << "" << "" << "/x";
        QTest::newRow("scheme and host case") << "SFTP://Host/x" << "sftp" << "host" << 0 << "" << "" << "/x";
        QTest::newRow("slashes collapse") << "sftp://h//a///b/" << "sftp" << "h" << 0 << "" << "" << "/a/b";
        QTest::newRow("empty port") << "sftp://h:/x" << "sftp" << "h" << 0 << "" << "" << "/x";
        QTest::newRow("percent path") << "sftp://h/%E2%82%AC%20x" << "sftp" << "h" << 0 << "" << "" << QString::fromUtf8("/\xE2\x82\xAC x");
        QTest::newRow("raw space in path") << "sftp://h/My Docs" << "sftp" << "h" << 0 << "" << "" << "/My Docs";
        QTest::newRow("user escapes") << "sftp://a%40b%3Ac@h" << "sftp" << "h" << 0 << "a@b:c" << "" << "";
        QTest::newRow("user with raw at") << "sftp://a@b@h" << "sftp" << "h" << 0 << "a@b" << "" << "";

        QTest::newRow("smb server") << "smb://nas" << "smb" << "nas" << 0 << "" << "" << "";
        QTest::newRow("smb share") << "smb://nas/media" << "smb" << "nas" << 0 << "" << "share=media" << "";
        QTest::newRow("smb share slash") << "smb://nas/media/" << "smb" << "nas" << 0 << "" << "share=media" << "";
        QTest::newRow("smb path") << "smb://bob@nas:4455/Photos%20Backup/2024/a%20b.jpg" << "smb" << "nas" << 4455
                                  << "bob" << "share=Photos Backup" << "/2024/a b.jpg";
        QTest::newRow("smb default port") << "smb://nas:445/s/x" << "smb" << "nas" << 0 << "" << "share=s" << "/x";

        QTest::newRow("https") << "https://cloud.example.com/remote.php/dav/files/me/" << "webdav" << "cloud.example.com"
                               << 0 << "" << "base_path=/remote.php/dav/files/me;tls=https" << "";
        QTest::newRow("https default port") << "https://h:443/" << "webdav" << "h" << 0 << "" << "tls=https" << "";
        QTest::newRow("https bare") << "https://h" << "webdav" << "h" << 0 << "" << "tls=https" << "";
        QTest::newRow("http") << "http://h:8080/dav" << "webdav" << "h" << 8080 << "" << "base_path=/dav;tls=http" << "";
        QTest::newRow("http default port") << "http://h:80/dav" << "webdav" << "h" << 0 << "" << "base_path=/dav;tls=http" << "";
        QTest::newRow("dav is plain") << "dav://h/x" << "webdav" << "h" << 0 << "" << "base_path=/x;tls=http" << "";
        QTest::newRow("davs is tls") << "davs://u@h/x/y" << "webdav" << "h" << 0 << "u" << "base_path=/x/y;tls=https" << "";
        QTest::newRow("webdav escapes") << "https://h/a%20b/c" << "webdav" << "h" << 0 << "" << "base_path=/a b/c;tls=https" << "";

        QTest::newRow("ftp explicit") << "ftp://u@h/dir" << "ftp" << "h" << 0 << "u" << "tls_mode=explicit" << "/dir";
        QTest::newRow("ftp port") << "ftp://h:2121" << "ftp" << "h" << 2121 << "" << "tls_mode=explicit" << "";
        QTest::newRow("ftps implicit") << "ftps://h/x" << "ftp" << "h" << 0 << "" << "tls_mode=implicit" << "/x";
        QTest::newRow("ftps default port") << "ftps://h:990/x" << "ftp" << "h" << 0 << "" << "tls_mode=implicit" << "/x";
        QTest::newRow("ftp default port") << "ftp://h:21" << "ftp" << "h" << 0 << "" << "tls_mode=explicit" << "";

        QTest::newRow("file") << "file:///tmp/x%20y" << "local" << "" << 0 << "" << "" << "/tmp/x y";
        QTest::newRow("file root") << "file:///" << "local" << "" << 0 << "" << "" << "/";
        QTest::newRow("file localhost") << "file://localhost/tmp" << "local" << "" << 0 << "" << "" << "/tmp";

        QTest::newRow("ipv6") << "sftp://[2001:db8::1]:2222/x" << "sftp" << "2001:db8::1" << 2222 << "" << "" << "/x";
        QTest::newRow("ipv6 loopback") << "smb://[::1]/share" << "smb" << "::1" << 0 << "" << "share=share" << "";
        QTest::newRow("ipv4") << "sftp://192.168.1.10" << "sftp" << "192.168.1.10" << 0 << "" << "" << "";

        QTest::newRow("idn unicode") << QString::fromUtf8("sftp://b\xC3\xBC" "cher.example/x") << "sftp"
                                     << QString::fromUtf8("b\xC3\xBC" "cher.example") << 0 << "" << "" << "/x";
        // QUrl::fromAce decodes labels only below top-level domains that allow IDN.
        QTest::newRow("idn punycode") << "sftp://xn--bcher-kva.de/x" << "sftp"
                                      << QString::fromUtf8("b\xC3\xBC" "cher.de") << 0 << "" << "" << "/x";
        QTest::newRow("punycode below a tld without idn") << "sftp://xn--bcher-kva.example/x" << "sftp"
                                                          << "xn--bcher-kva.example" << 0 << "" << "" << "/x";
        QTest::newRow("idn percent") << "sftp://b%C3%BCcher.example" << "sftp"
                                     << QString::fromUtf8("b\xC3\xBC" "cher.example") << 0 << "" << "" << "";
    }

    void parse()
    {
        QFETCH(QString, url);
        QFETCH(QString, provider);
        QFETCH(QString, host);
        QFETCH(int, port);
        QFETCH(QString, user);
        QFETCH(QString, options);
        QFETCH(QString, path);

        ConnectionParams params;
        QString location = QStringLiteral("untouched");
        const Result r = Url::parse(url, &params, &location);
        QVERIFY2(r.ok(), qPrintable(r.toString()));
        QCOMPARE(params.provider, provider);
        QCOMPARE(params.host, host);
        QCOMPARE(params.port, port);
        QCOMPARE(params.username, user);
        QCOMPARE(location, path);
        QStringList actual;
        for (auto it = params.options.constBegin(); it != params.options.constEnd(); ++it)
            actual << it.key() + QLatin1Char('=') + it.value().toString();
        actual.sort();
        QCOMPARE(actual.join(QLatin1Char(';')), options);
    }

    void parseKeepsNonUtf8PathBytes()
    {
        ConnectionParams params;
        QString path;
        QVERIFY(Url::parse(QStringLiteral("sftp://h/a%FFb%80"), &params, &path).ok());
        QCOMPARE(path, QStringLiteral("/a") + surrogate(0xFF) + QStringLiteral("b") + surrogate(0x80));
        QCOMPARE(Names::encode(path), QByteArray("/a\xFF" "b\x80"));
        QVERIFY(Names::hasEscapes(path));
        QCOMPARE(Url::format(params, path), QStringLiteral("sftp://h/a%FFb%80"));
    }

    void parseKeepsOtherOutputsOnFailure()
    {
        ConnectionParams params;
        params.provider = QStringLiteral("keep");
        params.host = QStringLiteral("keep");
        QString path = QStringLiteral("keep");
        QVERIFY(!Url::parse(QStringLiteral("sftp://h/../x"), &params, &path).ok());
        QCOMPARE(params.provider, QStringLiteral("keep"));
        QCOMPARE(params.host, QStringLiteral("keep"));
        QCOMPARE(path, QStringLiteral("keep"));
        QVERIFY(!Url::parse(QStringLiteral("sftp://u:p@h/"), &params, &path).ok());
        QCOMPARE(params.host, QStringLiteral("keep"));
    }

    void parseKeepsUnrelatedFields()
    {
        ConnectionParams params;
        params.connectTimeoutMs = 1234;
        params.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
        params.options.insert(QStringLiteral("tls"), QStringLiteral("stale"));
        QString path;
        QVERIFY(Url::parse(QStringLiteral("sftp://h"), &params, &path).ok());
        QCOMPARE(params.connectTimeoutMs, 1234);
        QCOMPARE(opt(params, "allow_insecure"), QStringLiteral("true"));
        QVERIFY(!params.options.contains(QStringLiteral("tls")));     // URL-derived keys are reset
        QVERIFY(Url::parse(QStringLiteral("sftp://h"), &params, nullptr).ok());   // path is optional
    }

    // ------------------------------------------------------------------ rejection

    void reject_data()
    {
        QTest::addColumn<QString>("url");
        QTest::addColumn<Error>("error");

        QTest::newRow("password") << "sftp://u:p@h/" << Error::SecurityPolicy;
        QTest::newRow("password smb") << "smb://u:secret@nas/share" << Error::SecurityPolicy;
        QTest::newRow("password webdav") << "https://u:pw@h/dav" << Error::SecurityPolicy;
        QTest::newRow("empty password") << "ftp://u:@h/" << Error::SecurityPolicy;
        QTest::newRow("password only") << "sftp://:p@h/" << Error::SecurityPolicy;
        QTest::newRow("password beats other errors") << "gopher://u:p@h/" << Error::Unsupported;

        QTest::newRow("unknown scheme") << "gopher://h/" << Error::Unsupported;
        QTest::newRow("scp") << "scp://h/x" << Error::Unsupported;
        QTest::newRow("file with host") << "file://remote/tmp" << Error::Unsupported;
        QTest::newRow("empty") << "" << Error::InvalidName;
        QTest::newRow("no scheme") << "example.com/x" << Error::InvalidName;
        QTest::newRow("no separator") << "javascript:alert(1)" << Error::InvalidName;
        QTest::newRow("empty scheme") << "://h" << Error::InvalidName;
        QTest::newRow("bad scheme char") << "sf tp://h" << Error::InvalidName;

        QTest::newRow("no host") << "sftp://" << Error::InvalidName;
        QTest::newRow("no host with path") << "sftp:///x" << Error::InvalidName;
        QTest::newRow("no host with user") << "sftp://u@/x" << Error::InvalidName;
        QTest::newRow("file with user") << "file://u@/x" << Error::InvalidName;
        QTest::newRow("file with port") << "file://:80/x" << Error::InvalidName;
        QTest::newRow("port zero") << "sftp://h:0/" << Error::InvalidName;
        QTest::newRow("port too large") << "sftp://h:65536/" << Error::InvalidName;
        QTest::newRow("port long") << "sftp://h:000022/" << Error::InvalidName;
        QTest::newRow("port letters") << "sftp://h:ssh/" << Error::InvalidName;
        QTest::newRow("port negative") << "sftp://h:-1/" << Error::InvalidName;
        QTest::newRow("ipv6 unterminated") << "sftp://[::1/x" << Error::InvalidName;
        QTest::newRow("ipv6 bad chars") << "sftp://[xyz::1]/" << Error::InvalidName;
        QTest::newRow("ipv6 trailing") << "sftp://[::1]x/" << Error::InvalidName;
        QTest::newRow("ipv6 no colon") << "sftp://[abcd]/" << Error::InvalidName;
        QTest::newRow("ipv6 zone") << "sftp://[fe80::1%25eth0]/" << Error::InvalidName;
        QTest::newRow("host with space") << "sftp://a b/" << Error::InvalidName;
        QTest::newRow("host with encoded slash") << "sftp://a%2Fb/x" << Error::InvalidName;
        QTest::newRow("host with encoded colon") << "sftp://a%3Ab/x" << Error::InvalidName;
        QTest::newRow("host not utf8") << "sftp://a%FFb/x" << Error::InvalidName;
        QTest::newRow("two colons") << "sftp://a:b:22/x" << Error::InvalidName;

        QTest::newRow("dot component") << "sftp://h/a/./b" << Error::InvalidName;
        QTest::newRow("dotdot component") << "sftp://h/a/../b" << Error::InvalidName;
        QTest::newRow("encoded dotdot") << "sftp://h/%2e%2E/x" << Error::InvalidName;
        QTest::newRow("trailing dotdot") << "smb://h/s/.." << Error::InvalidName;
        QTest::newRow("encoded NUL") << "sftp://h/a%00b" << Error::InvalidName;
        QTest::newRow("bad escape") << "sftp://h/%zz" << Error::InvalidName;
        QTest::newRow("short escape") << "sftp://h/a%4" << Error::InvalidName;
        QTest::newRow("lone percent") << "sftp://h/%" << Error::InvalidName;
        QTest::newRow("bad escape in user") << "sftp://u%zz@h/" << Error::InvalidName;
        QTest::newRow("query") << "sftp://h/a?x=1" << Error::InvalidName;
        QTest::newRow("fragment") << "sftp://h/a#top" << Error::InvalidName;
        QTest::newRow("query without path") << "https://h?x" << Error::InvalidName;
        QTest::newRow("control char") << QStringLiteral("sftp://h/a\nb") << Error::InvalidName;
        QTest::newRow("NUL char") << QString(QStringLiteral("sftp://h/a") + QChar(0) + QStringLiteral("b")) << Error::InvalidName;
    }

    void reject()
    {
        QFETCH(QString, url);
        QFETCH(Error, error);
        ConnectionParams params;
        QString path;
        const Result r = Url::parse(url, &params, &path);
        QVERIFY(!r.ok());
        QCOMPARE(r.error(), error);
    }

    void passwordMessageIsFixedAndLeaksNothing()
    {
        ConnectionParams params;
        QString path;
        const Result r = Url::parse(QStringLiteral("sftp://alice:hunter2@h/"), &params, &path);
        QCOMPARE(r.error(), Error::SecurityPolicy);
        QCOMPARE(r.message(), QStringLiteral("passwords in URLs are not accepted"));
        QVERIFY(!r.toString().contains(QLatin1String("hunter2")));
        QVERIFY(!r.detail().contains(QLatin1String("hunter2")));
        QVERIFY(params.username.isEmpty());          // never stored
        QVERIFY(params.host.isEmpty());
    }

    // ------------------------------------------------------------------ format

    void format()
    {
        ConnectionParams p;
        p.provider = QStringLiteral("sftp");
        p.host = QStringLiteral("h");
        p.username = QStringLiteral("a b");
        p.port = 2222;
        QCOMPARE(Url::format(p, QStringLiteral("/x y/z")), QStringLiteral("sftp://a%20b@h:2222/x%20y/z"));
        QCOMPARE(Url::format(p, QStringLiteral("rel")), QStringLiteral("sftp://a%20b@h:2222/rel"));
        QCOMPARE(Url::format(p, QString()), QStringLiteral("sftp://a%20b@h:2222"));
        p.username.clear();
        p.port = 0;
        p.host = QStringLiteral("2001:db8::1");
        QCOMPARE(Url::format(p, QStringLiteral("/")), QStringLiteral("sftp://[2001:db8::1]/"));
        p.username = QStringLiteral("a@b:c/d");
        p.host = QStringLiteral("h");
        QCOMPARE(Url::format(p, QString()), QStringLiteral("sftp://a%40b%3Ac%2Fd@h"));

        ConnectionParams smb;
        smb.provider = QStringLiteral("smb");
        smb.host = QStringLiteral("nas");
        QCOMPARE(Url::format(smb, QString()), QStringLiteral("smb://nas"));
        QCOMPARE(Url::format(smb, QStringLiteral("/ignored")), QStringLiteral("smb://nas"));   // no share, no path
        smb.options.insert(QStringLiteral("share"), QStringLiteral("My Share"));
        QCOMPARE(Url::format(smb, QString()), QStringLiteral("smb://nas/My%20Share"));
        QCOMPARE(Url::format(smb, QStringLiteral("/dir/f.txt")), QStringLiteral("smb://nas/My%20Share/dir/f.txt"));
        QCOMPARE(Url::format(smb, QStringLiteral("dir")), QStringLiteral("smb://nas/My%20Share/dir"));

        ConnectionParams dav;
        dav.provider = QStringLiteral("webdav");
        dav.host = QStringLiteral("h");
        QCOMPARE(Url::format(dav, QString()), QStringLiteral("https://h"));
        dav.options.insert(QStringLiteral("tls"), QStringLiteral("http"));
        dav.options.insert(QStringLiteral("base_path"), QStringLiteral("/remote.php/dav"));
        dav.port = 8080;
        QCOMPARE(Url::format(dav, QString()), QStringLiteral("http://h:8080/remote.php/dav"));
        QCOMPARE(Url::format(dav, QStringLiteral("files/me")), QStringLiteral("http://h:8080/remote.php/dav/files/me"));
        dav.options.insert(QStringLiteral("base_path"), QStringLiteral("/"));
        QCOMPARE(Url::format(dav, QStringLiteral("/x")), QStringLiteral("http://h:8080/x"));

        ConnectionParams ftp;
        ftp.provider = QStringLiteral("ftp");
        ftp.host = QStringLiteral("h");
        QCOMPARE(Url::format(ftp, QStringLiteral("/d")), QStringLiteral("ftp://h/d"));
        ftp.options.insert(QStringLiteral("tls_mode"), QStringLiteral("implicit"));
        QCOMPARE(Url::format(ftp, QStringLiteral("/d")), QStringLiteral("ftps://h/d"));
        ftp.options.insert(QStringLiteral("tls_mode"), QStringLiteral("none"));   // not expressible: the safe scheme
        QCOMPARE(Url::format(ftp, QString()), QStringLiteral("ftp://h"));

        ConnectionParams local;
        local.provider = QStringLiteral("local");
        QCOMPARE(Url::format(local, QStringLiteral("/tmp/a b")), QStringLiteral("file:///tmp/a%20b"));

        ConnectionParams unknown;
        unknown.provider = QStringLiteral("nfs");
        QVERIFY(Url::format(unknown, QStringLiteral("/x")).isEmpty());
    }

    void formatEncodesNonAscii()
    {
        ConnectionParams p;
        p.provider = QStringLiteral("sftp");
        p.host = QString::fromUtf8("b\xC3\xBC" "cher.example");
        QCOMPARE(Url::format(p, QString::fromUtf8("/\xE2\x82\xAC")), QString::fromUtf8("sftp://b\xC3\xBC" "cher.example/%E2%82%AC"));
    }

    // parse(format(parse(u))) is stable for everything parse accepts.
    void roundTrip_data()
    {
        QTest::addColumn<QString>("url");
        const QStringList urls = {
            "sftp://example.com", "sftp://alice@example.com:2222/home/alice", "sftp://h/", "ssh://h/x",
            "sftp://h:22/x", "SFTP://Host/x", "sftp://h//a///b/", "sftp://h/%E2%82%AC%20x", "sftp://h/My Docs",
            "sftp://a%40b%3Ac@h", "sftp://a@b@h", "smb://nas", "smb://nas/media", "smb://nas/media/",
            "smb://bob@nas:4455/Photos%20Backup/2024/a%20b.jpg", "https://cloud.example.com/remote.php/dav/files/me/",
            "https://h", "http://h:8080/dav", "dav://h/x", "davs://u@h/x/y", "https://h/a%20b/c",
            "ftp://u@h/dir", "ftp://h:2121", "ftps://h/x", "ftps://h:990/x", "file:///tmp/x%20y", "file:///",
            "file://localhost/tmp", "sftp://[2001:db8::1]:2222/x", "smb://[::1]/share", "sftp://192.168.1.10",
            "sftp://b%C3%BCcher.example", "sftp://xn--bcher-kva.de/x", "sftp://xn--bcher-kva.example/x", "sftp://h/a%FFb%80",
            "smb://nas/a%2Fb/c", "sftp://h/a%2Fb", "sftp://h/%F0%9F%98%80", "sftp://h/a%25b",
        };
        for (const QString &url : urls)
            QTest::newRow(qPrintable(url)) << url;
    }

    void roundTrip()
    {
        QFETCH(QString, url);
        ConnectionParams first;
        QString firstPath;
        QVERIFY(Url::parse(url, &first, &firstPath).ok());
        const QString formatted = Url::format(first, firstPath);
        QVERIFY(!formatted.isEmpty());
        ConnectionParams second;
        QString secondPath;
        const Result r = Url::parse(formatted, &second, &secondPath);
        QVERIFY2(r.ok(), qPrintable(formatted + QLatin1Char(' ') + r.toString()));
        QCOMPARE(second.provider, first.provider);
        QCOMPARE(second.host, first.host);
        QCOMPARE(second.port, first.port);
        QCOMPARE(second.username, first.username);
        QCOMPARE(second.options, first.options);
        QCOMPARE(secondPath, firstPath);
        QCOMPARE(Url::format(second, secondPath), formatted);     // and the text is a fixed point
    }

    // ------------------------------------------------------------------ toAce

    void toAce()
    {
        QCOMPARE(Url::toAce(QString::fromUtf8("b\xC3\xBC" "cher.example")), QByteArray("xn--bcher-kva.example"));
        QCOMPARE(Url::toAce(QStringLiteral("example.com")), QByteArray("example.com"));
        QCOMPARE(Url::toAce(QStringLiteral("[2001:db8::1]")), QByteArray("2001:db8::1"));
        QCOMPARE(Url::toAce(QStringLiteral("::1")), QByteArray("::1"));
        QCOMPARE(Url::toAce(QStringLiteral("192.168.0.1")), QByteArray("192.168.0.1"));
    }

    // ------------------------------------------------------------------ Paths::normalize (XC-4)

    void normalizeAcceptsLoneSurrogates()
    {
        QString out;
        const QString escaped = QStringLiteral("a/") + surrogate(0xFF) + QStringLiteral("/b");
        QVERIFY(Paths::normalize(escaped, &out).ok());
        QCOMPARE(out, escaped);
        const QString decoded = Names::decode(QByteArray("dir/\xFE\xFF.txt"));
        QVERIFY(Paths::normalize(decoded, &out).ok());
        QCOMPARE(out, decoded);
        QString raw = QStringLiteral("x");
        raw.append(QChar(0xD800));       // an unpaired UTF-16 surrogate is accepted as well
        QVERIFY(Paths::normalize(raw, &out).ok());
        QCOMPARE(out, raw);
    }

    void normalizeRejectsWithInvalidName()
    {
        QString out = QStringLiteral("unchanged");
        const QStringList bad = { QStringLiteral("a/./b"), QStringLiteral("../x"), QStringLiteral("a/.."),
                                  QStringLiteral("."), QStringLiteral(".."),
                                  QStringLiteral("a") + QChar(0) + QStringLiteral("b") };
        for (const QString &path : bad) {
            const Result r = Paths::normalize(path, &out);
            QVERIFY(!r.ok());
            QCOMPARE(r.error(), Error::InvalidName);
            QCOMPARE(out, QStringLiteral("unchanged"));
        }
        QVERIFY(Paths::normalize(QStringLiteral("a/..b/c."), &out).ok());
    }

    // ------------------------------------------------------------------ Paths::sanitizeFor (XH-7)

    void sanitize_data()
    {
        QTest::addColumn<bool>("windows");
        QTest::addColumn<qint64>("maxBytes");
        QTest::addColumn<QString>("input");
        QTest::addColumn<QString>("expected");

        QTest::newRow("posix plain") << false << qint64(-1) << "report.txt" << "report.txt";
        QTest::newRow("posix keeps windows chars") << false << qint64(-1) << "a:b*c?.txt" << "a:b*c?.txt";
        QTest::newRow("posix keeps trailing dot") << false << qint64(-1) << "name." << "name.";
        QTest::newRow("posix keeps device name") << false << qint64(-1) << "CON" << "CON";
        QTest::newRow("slash") << false << qint64(-1) << "a/b" << "a_b";
        QTest::newRow("nul") << false << qint64(-1) << QString(QStringLiteral("a") + QChar(0) + QStringLiteral("b")) << "a_b";
        QTest::newRow("empty") << false << qint64(-1) << "" << "_";
        QTest::newRow("dot") << false << qint64(-1) << "." << "_";
        QTest::newRow("dotdot") << false << qint64(-1) << ".." << "_";
        QTest::newRow("three dots on posix") << false << qint64(-1) << "..." << "...";

        QTest::newRow("windows plain") << true << qint64(-1) << "report.txt" << "report.txt";
        QTest::newRow("windows forbidden") << true << qint64(-1) << "a:b*c?.txt" << "a_b_c_.txt";
        QTest::newRow("windows all forbidden") << true << qint64(-1) << "\\:*?\"<>|" << "________";
        QTest::newRow("windows control") << true << qint64(-1) << QStringLiteral("a\x01" "b\x1F") << "a_b_";
        QTest::newRow("windows trailing") << true << qint64(-1) << "trail. . " << "trail";
        QTest::newRow("windows only dots") << true << qint64(-1) << "..." << "_";
        QTest::newRow("windows only spaces") << true << qint64(-1) << "   " << "_";
        QTest::newRow("windows dotdot") << true << qint64(-1) << ".." << "_";
        QTest::newRow("windows leading dot kept") << true << qint64(-1) << ".hidden" << ".hidden";
        QTest::newRow("windows leading space kept") << true << qint64(-1) << " a" << " a";
        QTest::newRow("windows CON") << true << qint64(-1) << "CON" << "CON_";
        QTest::newRow("windows con.txt") << true << qint64(-1) << "con.txt" << "con_.txt";
        QTest::newRow("windows Com1") << true << qint64(-1) << "Com1" << "Com1_";
        QTest::newRow("windows LPT9.log") << true << qint64(-1) << "LPT9.log" << "LPT9_.log";
        QTest::newRow("windows nul") << true << qint64(-1) << "nul" << "nul_";
        QTest::newRow("windows prn") << true << qint64(-1) << "PRN.tar.gz" << "PRN_.tar.gz";
        QTest::newRow("windows aux dot") << true << qint64(-1) << "aux." << "aux_";
        QTest::newRow("windows COM0 is fine") << true << qint64(-1) << "COM0" << "COM0";
        QTest::newRow("windows COM10 is fine") << true << qint64(-1) << "COM10" << "COM10";
        QTest::newRow("windows CONSOLE is fine") << true << qint64(-1) << "CONSOLE" << "CONSOLE";
        QTest::newRow("windows xCON is fine") << true << qint64(-1) << "xCON" << "xCON";
        QTest::newRow("windows slash") << true << qint64(-1) << "a/b\\c" << "a_b_c";

        QTest::newRow("max keeps extension") << false << qint64(10) << "abcdefghijklmnop.txt" << "abcdef.txt";
        QTest::newRow("max without extension") << false << qint64(10) << "abcdefghijklmnop" << "abcdefghij";
        QTest::newRow("max fits") << false << qint64(10) << "abcdefghij" << "abcdefghij";
        QTest::newRow("max zero is no limit") << false << qint64(0) << "abcdefghijklmnop" << "abcdefghijklmnop";
        QTest::newRow("max two byte chars") << false << qint64(5) << QString::fromUtf8("\xC3\xA9\xC3\xA9\xC3\xA9") << QString::fromUtf8("\xC3\xA9\xC3\xA9");
        QTest::newRow("max emoji whole") << false << qint64(5) << QString::fromUtf8("a\xF0\x9F\x98\x80" "b") << QString::fromUtf8("a\xF0\x9F\x98\x80");
        QTest::newRow("max emoji dropped") << false << qint64(3) << QString::fromUtf8("a\xF0\x9F\x98\x80") << "a";
        QTest::newRow("max emoji only") << false << qint64(4) << QString::fromUtf8("\xF0\x9F\x98\x80\xF0\x9F\x98\x80") << QString::fromUtf8("\xF0\x9F\x98\x80");
        QTest::newRow("max too small for first char") << false << qint64(1) << QString::fromUtf8("\xC3\xA9") << "_";
        QTest::newRow("max long extension truncated whole") << false << qint64(5) << "a.verylongext" << "a.ver";
        QTest::newRow("max leading dot is not an extension") << false << qint64(5) << ".bashrc_long" << ".bash";
        QTest::newRow("max extension of multibyte") << false << qint64(9) << QString::fromUtf8("abcdefgh.t\xC3\xA9xt") << QString::fromUtf8("abc.t\xC3\xA9xt");
        QTest::newRow("max escapes are one byte") << false << qint64(3) << (QStringLiteral("x") + surrogate(0xFF).repeated(5)) << (QStringLiteral("x") + surrogate(0xFF).repeated(2));
        QTest::newRow("max 255") << false << qint64(255) << QString(300, QLatin1Char('a')) + QStringLiteral(".txt") << QString(251, QLatin1Char('a')) + QStringLiteral(".txt");
        QTest::newRow("windows and max") << true << qint64(8) << "a:very long name.txt" << "a_ve.txt";
        QTest::newRow("windows trailing dot does not hide the extension") << true << qint64(10) << "aaaaaaaaaaaaaa.txt." << "aaaaaa.txt";
        QTest::newRow("windows max leaves trailing space") << true << qint64(5) << "abcd efgh" << "abcd";
        QTest::newRow("windows max reserved fits") << true << qint64(4) << "CON" << "CON_";
        QTest::newRow("windows max trims reserved stem") << true << qint64(7) << "CON.txt" << "CO.txt";
        QTest::newRow("windows max reserved needs room") << true << qint64(5) << "LPT1" << "LPT1_";
    }

    void sanitize()
    {
        QFETCH(bool, windows);
        QFETCH(qint64, maxBytes);
        QFETCH(QString, input);
        QFETCH(QString, expected);
        Capabilities caps;
        if (windows)
            caps.flags.insert(Capability::WindowsNames);
        caps.maxNameBytes = maxBytes;
        const QString result = Paths::sanitizeFor(caps, input);
        QCOMPARE(result, expected);
        QVERIFY(!result.isEmpty());
        QVERIFY(result != QLatin1String(".") && result != QLatin1String(".."));
        QVERIFY(!result.contains(QLatin1Char('/')));
        if (maxBytes > 0)
            QVERIFY(Names::encode(result).size() <= maxBytes);
        if (windows)
            QVERIFY2(Paths::windowsComponentProblem(result).isEmpty(), qPrintable(result));
        QCOMPARE(Paths::sanitizeFor(caps, result), result);        // idempotent
    }

    void sanitizeNeverBreaksCodePoints()
    {
        Capabilities caps;
        const QString name = QString::fromUtf8("\xF0\x9F\x98\x80\xC3\xA9z\xE2\x82\xAC.\xF0\x9F\x98\x80");
        for (qint64 max = 1; max <= 20; ++max) {
            caps.maxNameBytes = max;
            const QString result = Paths::sanitizeFor(caps, name);
            QVERIFY(!result.isEmpty());
            for (int i = 0; i < result.size(); ++i) {
                const QChar c = result.at(i);
                QVERIFY2(!c.isSurrogate() || (c.isHighSurrogate() && i + 1 < result.size() && result.at(i + 1).isLowSurrogate())
                             || (c.isLowSurrogate() && i > 0 && result.at(i - 1).isHighSurrogate()),
                         qPrintable(QString::number(max)));
            }
            // A one-byte limit cannot hold any of the characters: the fallback name is used.
            if (max >= 4 || result != QLatin1String("_"))
                QVERIFY(Names::encode(result).size() <= max);
        }
    }
};

QTEST_GUILESS_MAIN(TstUrl)
#include "tst_url.moc"
