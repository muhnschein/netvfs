// SPDX-License-Identifier: LGPL-2.1-or-later
#include "discovery.h"
#include "discoverytestutil.h"
#include "discoverytransport.h"
#include "dnsmessage.h"

#include <QtNetwork/QUdpSocket>
#include <QtTest/QtTest>

#include <climits>

using namespace NetVfs;
using NetVfs::Test::addressRecord;
using NetVfs::Test::announcement;
using NetVfs::Test::ptrRecord;
using NetVfs::Test::response;
using NetVfs::Test::srvRecord;
using NetVfs::Test::txtRecord;

int runDnsMessageTests(int argc, char **argv);

namespace {

class FakeClock : public DiscoveryClock
{
public:
    qint64 monotonicMs() const override { return ms; }
    QDateTime wallTime() const override { return wall; }
    void advance(qint64 delta)
    {
        ms += delta;
        wall = wall.addMSecs(delta);
    }

    qint64 ms = 1000000;
    QDateTime wall = QDateTime(QDate(2026, 1, 1), QTime(12, 0), Qt::UTC);
};

// Records what Discovery sends and lets the test feed it datagrams.
class FakeTransport : public DiscoveryTransport
{
public:
    bool open() override
    {
        ++openCalls;
        opened = openResult;
        return opened;
    }
    void close() override
    {
        ++closeCalls;
        opened = false;
    }
    bool isOpen() const override { return opened; }
    void send(const QByteArray &datagram) override
    {
        if (opened)
            sent.append(datagram);
    }

    void deliver(const Dns::Message &m) { emit datagramReceived(Dns::encode(m), QHostAddress(QStringLiteral("192.0.2.1"))); }
    void deliverRaw(const QByteArray &raw) { emit datagramReceived(raw, QHostAddress(QStringLiteral("192.0.2.1"))); }

    // Decodes and forgets everything sent so far.
    QVector<Dns::Message> drain()
    {
        QVector<Dns::Message> out;
        for (const QByteArray &d : qAsConst(sent)) {
            Dns::Message m;
            if (Dns::decode(d, &m))
                out.append(m);
        }
        sent.clear();
        return out;
    }

    bool openResult = true;
    bool opened = false;
    int openCalls = 0;
    int closeCalls = 0;
    QList<QByteArray> sent;
};

const char *typeText(quint16 type)
{
    switch (type) {
    case Dns::TypeA: return "A";
    case Dns::TypeAaaa: return "AAAA";
    case Dns::TypePtr: return "PTR";
    case Dns::TypeSrv: return "SRV";
    case Dns::TypeTxt: return "TXT";
    default: return "?";
    }
}

QStringList questionTexts(const Dns::Message &m)
{
    QStringList out;
    for (const Dns::Question &q : m.questions)
        out.append(QStringLiteral("%1 %2").arg(QLatin1String(typeText(q.type)), QString::fromLatin1(q.name)));
    return out;
}

// Everything asked in a batch of sent datagrams.
QStringList allQuestions(const QVector<Dns::Message> &messages)
{
    QStringList out;
    for (const Dns::Message &m : messages)
        out += questionTexts(m);
    return out;
}

struct Rig {
    Rig()
    {
        discovery.setClock(&clock);
        QObject::connect(&discovery, &Discovery::found, &discovery, [this](const DiscoveredService &s) {
            found.append(s);
            log.append(QStringLiteral("found ") + s.instanceName);
        });
        QObject::connect(&discovery, &Discovery::updated, &discovery, [this](const DiscoveredService &s) {
            updated.append(s);
            log.append(QStringLiteral("updated ") + s.instanceName);
        });
        QObject::connect(&discovery, &Discovery::lost, &discovery, [this](const DiscoveredService &s) {
            lost.append(s);
            log.append(QStringLiteral("lost ") + s.instanceName);
        });
    }

    void advance(qint64 ms)
    {
        clock.advance(ms);
        discovery.runTimers();
    }

    FakeClock clock;
    FakeTransport *transport = new FakeTransport;
    Discovery discovery{transport};
    QVector<DiscoveredService> found;
    QVector<DiscoveredService> updated;
    QVector<DiscoveredService> lost;
    QStringList log;
};

QList<QHostAddress> addresses(const QStringList &texts)
{
    QList<QHostAddress> out;
    for (const QString &t : texts)
        out.append(QHostAddress(t));
    return out;
}

} // namespace

class TestDiscovery : public QObject
{
    Q_OBJECT

private slots:
    // ------------------------------------------------------------ lifecycle

    void browseQueryAsksForTheSixServiceTypes()
    {
        Rig rig;
        QVERIFY(rig.discovery.start());
        const QVector<Dns::Message> sent = rig.transport->drain();
        QCOMPARE(sent.size(), 1);
        QVERIFY(!sent[0].isResponse());
        QCOMPARE(questionTexts(sent[0]),
                 (QStringList{QStringLiteral("PTR _sftp-ssh._tcp.local"), QStringLiteral("PTR _ssh._tcp.local"),
                              QStringLiteral("PTR _smb._tcp.local"), QStringLiteral("PTR _webdav._tcp.local"),
                              QStringLiteral("PTR _webdavs._tcp.local"), QStringLiteral("PTR _ftp._tcp.local")}));
        for (const Dns::Question &q : sent[0].questions)
            QVERIFY(!q.unicastResponse);
        QCOMPARE(browsedServiceTypes().size(), 6);
        QVERIFY(sent[0].answers.isEmpty());
    }

    void queriesBackOffFromOneToSixtySeconds()
    {
        const int expected[] = {1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000, 60000};
        for (int n = 0; n < 9; ++n)
            QCOMPARE(Discovery::queryIntervalMs(n), expected[n]);
        QCOMPARE(Discovery::queryIntervalMs(-5), 1000);
        QCOMPARE(Discovery::queryIntervalMs(1000), 60000);
        QCOMPARE(Discovery::queryIntervalMs(INT_MAX), 60000);

        Rig rig;
        rig.discovery.start();
        QCOMPARE(rig.transport->drain().size(), 1);
        for (const int gap : expected) {
            rig.advance(gap - 1);
            QCOMPARE(rig.transport->drain().size(), 0);
            rig.advance(1);
            QCOMPARE(rig.transport->drain().size(), 1);
        }
        rig.advance(0);                         // no time passed: nothing is sent
        QCOMPARE(rig.transport->drain().size(), 0);
    }

    void refreshRestartsTheBackoff()
    {
        Rig rig;
        rig.discovery.start();
        rig.advance(1000);
        rig.advance(2000);
        rig.advance(4000);
        rig.transport->drain();
        rig.discovery.refresh();
        QCOMPARE(rig.transport->drain().size(), 1);
        rig.advance(999);
        QCOMPARE(rig.transport->drain().size(), 0);
        rig.advance(1);                          // the gap after a refresh is 1 s again
        QCOMPARE(rig.transport->drain().size(), 1);
        rig.discovery.stop();
        rig.discovery.refresh();                 // not running: no effect
        QCOMPARE(rig.transport->drain().size(), 0);
    }

    void startAndStopAreReferenceCounted()
    {
        Rig rig;
        QVERIFY(!rig.discovery.isRunning());
        QCOMPARE(rig.transport->openCalls, 0);
        QVERIFY(rig.discovery.start());
        QVERIFY(rig.discovery.start());
        QCOMPARE(rig.discovery.consumers(), 2);
        QCOMPARE(rig.transport->openCalls, 1);
        QCOMPARE(rig.transport->drain().size(), 1);     // only the first start() sends

        rig.discovery.stop();
        QVERIFY(rig.discovery.isRunning());
        QVERIFY(rig.transport->isOpen());
        QCOMPARE(rig.transport->closeCalls, 0);
        rig.advance(1000);
        QCOMPARE(rig.transport->drain().size(), 1);     // the remaining consumer still gets queries

        rig.discovery.stop();
        QVERIFY(!rig.discovery.isRunning());
        QVERIFY(!rig.transport->isOpen());
        QCOMPARE(rig.transport->closeCalls, 1);
        rig.advance(60000);
        QCOMPARE(rig.transport->sent.size(), 0);        // nothing is sent while stopped

        rig.discovery.stop();                           // unmatched stop: ignored
        QCOMPARE(rig.discovery.consumers(), 0);
        QCOMPARE(rig.transport->closeCalls, 1);
        QVERIFY(rig.discovery.start());                 // and the object still works afterwards
        QCOMPARE(rig.discovery.consumers(), 1);
        QCOMPARE(rig.transport->openCalls, 2);
        QCOMPARE(rig.transport->drain().size(), 1);
    }

    void ignoresDatagramsWhileStopped()
    {
        Rig rig;
        rig.discovery.start();
        rig.discovery.stop();
        rig.transport->deliver(announcement("_ssh._tcp", "box", "box.local", 22, QStringLiteral("192.0.2.5")));
        QVERIFY(rig.found.isEmpty());
        QVERIFY(rig.discovery.services().isEmpty());
    }

    void stoppingDropsTheCacheWithoutSignals()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(announcement("_ssh._tcp", "box", "box.local", 22, QStringLiteral("192.0.2.5")));
        QCOMPARE(rig.found.size(), 1);
        rig.discovery.stop();
        QVERIFY(rig.lost.isEmpty());
        QVERIFY(rig.discovery.services().isEmpty());
        rig.discovery.start();
        QVERIFY(rig.discovery.services().isEmpty());
        rig.transport->deliver(announcement("_ssh._tcp", "box", "box.local", 22, QStringLiteral("192.0.2.5")));
        QCOMPARE(rig.found.size(), 2);                   // a new consumer sees it again
    }

    void keepsRetryingToOpenTheSocket()
    {
        Rig rig;
        rig.transport->openResult = false;
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression(QStringLiteral("no mDNS socket")));
        QVERIFY(!rig.discovery.start());
        QVERIFY(rig.discovery.isRunning());
        QCOMPARE(rig.transport->sent.size(), 0);
        rig.transport->openResult = true;
        rig.advance(1000);
        QVERIFY(rig.transport->isOpen());
        QCOMPARE(rig.transport->drain().size(), 1);
    }

    void aHandlerThatStopsEndsTheDelivery()
    {
        Rig rig;
        rig.discovery.start();
        connect(&rig.discovery, &Discovery::found, this, [&rig](const DiscoveredService &) { rig.discovery.stop(); });
        Dns::Message m = announcement("_ssh._tcp", "one", "one.local", 22, QStringLiteral("192.0.2.1"));
        const Dns::Message second = announcement("_ssh._tcp", "two", "two.local", 22, QStringLiteral("192.0.2.2"));
        m.answers += second.answers;
        m.additional += second.additional;
        rig.transport->deliver(m);
        QCOMPARE(rig.found.size(), 1);
        QVERIFY(!rig.discovery.isRunning());
    }

    // ---------------------------------------------------------- announcements

    void anAnnouncementIsFoundOnce()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(announcement("_sftp-ssh._tcp", "My Host", "host.local", 22, QStringLiteral("192.0.2.10")));
        QCOMPARE(rig.found.size(), 1);
        const DiscoveredService s = rig.found[0];
        QCOMPARE(s.instanceName, QStringLiteral("My Host"));
        QCOMPARE(s.serviceType, QStringLiteral("_sftp-ssh._tcp"));
        QCOMPARE(s.provider, QStringLiteral("sftp"));
        QCOMPARE(s.host, QStringLiteral("host.local"));
        QCOMPARE(s.port, 22);
        QCOMPARE(s.addresses, addresses({QStringLiteral("192.0.2.10")}));
        QVERIFY(s.path.isEmpty());
        QVERIFY(s.user.isEmpty());
        QCOMPARE(s.lastSeen, rig.clock.wall);
        QCOMPARE(s.key(), QStringLiteral("_sftp-ssh._tcp/my host"));
        QCOMPARE(s.endpointKey(), QStringLiteral("sftp|host.local|22"));
        QCOMPARE(rig.discovery.services().size(), 1);

        // The same announcement again: no signal, but lastSeen moves.
        rig.clock.advance(5000);
        rig.transport->deliver(announcement("_sftp-ssh._tcp", "My Host", "host.local", 22, QStringLiteral("192.0.2.10")));
        QCOMPARE(rig.found.size(), 1);
        QVERIFY(rig.updated.isEmpty());
        QCOMPARE(rig.discovery.services()[0].lastSeen, rig.clock.wall);
    }

    void mapsEveryServiceTypeToAProvider()
    {
        struct Row { const char *type; const char *provider; const char *tls; quint16 port; };
        const Row rows[] = {
            {"_sftp-ssh._tcp", "sftp", "", 22},   {"_ssh._tcp", "sftp", "", 22},
            {"_smb._tcp", "smb", "", 445},        {"_webdav._tcp", "webdav", "http", 80},
            {"_webdavs._tcp", "webdav", "https", 443}, {"_ftp._tcp", "ftp", "", 21},
        };
        Rig rig;
        rig.discovery.start();
        for (const Row &row : rows) {
            rig.transport->deliver(announcement(row.type, "srv", "srv.local", row.port, QStringLiteral("192.0.2.20")));
            const DiscoveredService s = rig.found.last();
            QCOMPARE(s.serviceType, QString::fromLatin1(row.type));
            QCOMPARE(s.provider, QString::fromLatin1(row.provider));
            QCOMPARE(s.tls, QString::fromLatin1(row.tls));
            QCOMPARE(s.port, int(row.port));

            QString provider;
            QString tls;
            QVERIFY(providerForServiceType(QString::fromLatin1(row.type).toUpper(), &provider, &tls));
            QCOMPARE(provider, QString::fromLatin1(row.provider));
            QCOMPARE(tls, QString::fromLatin1(row.tls));
        }
        QCOMPARE(rig.found.size(), 6);
        QVERIFY(!providerForServiceType(QStringLiteral("_http._tcp"), nullptr));
        QVERIFY(!providerForServiceType(QStringLiteral("_smb._udp"), nullptr));
        QVERIFY(!providerForServiceType(QString(), nullptr));
    }

    void webdavAndFtpTakePathAndUserFromTxt()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(announcement("_webdavs._tcp", "Cloud", "cloud.local", 443, QStringLiteral("192.0.2.30"),
                                            {"txtvers=1", "path=/remote.php/dav", "u=alice", "p=hunter2"}));
        rig.transport->deliver(announcement("_ftp._tcp", "Files", "files.local", 21, QStringLiteral("192.0.2.31"),
                                            {"path=pub/data", "u=anonymous"}));
        rig.transport->deliver(announcement("_smb._tcp", "Nas", "nas.local", 445, QStringLiteral("192.0.2.32"),
                                            {"path=/ignored", "u=ignored"}));
        QCOMPARE(rig.found.size(), 3);
        QCOMPARE(rig.found[0].path, QStringLiteral("/remote.php/dav"));
        QCOMPARE(rig.found[0].user, QStringLiteral("alice"));
        QCOMPARE(rig.found[1].path, QStringLiteral("/pub/data"));       // always absolute
        QCOMPARE(rig.found[1].user, QStringLiteral("anonymous"));
        QVERIFY(rig.found[2].path.isEmpty());                            // only webdav and ftp read them
        QVERIFY(rig.found[2].user.isEmpty());
    }

    void sanitisesNamesAndTxtValues()
    {
        Rig rig;
        rig.discovery.start();
        const QByteArray instance = "Ev\x01il\x1b[31m\\.Nas";
        rig.transport->deliver(announcement("_webdav._tcp", instance, "box.local", 80, QStringLiteral("192.0.2.40"),
                                            {"path=/a\x01" "b", "u=bo\x07" "b"}));
        QCOMPARE(rig.found.size(), 1);
        QCOMPARE(rig.found[0].instanceName, QStringLiteral("Evil[31m.Nas"));
        QCOMPARE(rig.found[0].path, QStringLiteral("/ab"));
        QCOMPARE(rig.found[0].user, QStringLiteral("bob"));

    }

    // ------------------------------------------------------------- resolution

    void resolvesPtrSrvTxtAndAddressesStepByStep()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->drain();
        const QByteArray type = "_webdav._tcp";
        const QByteArray inst = "Drive";
        const QString instName = QStringLiteral("drive._webdav._tcp.local");

        // PTR alone: nothing to report yet, SRV and TXT are asked for at once.
        rig.transport->deliver(response({ptrRecord(type, inst)}));
        QVERIFY(rig.found.isEmpty());
        QStringList asked = allQuestions(rig.transport->drain());
        QVERIFY(asked.contains(QStringLiteral("SRV ") + instName));
        QVERIFY(asked.contains(QStringLiteral("TXT ") + instName));
        QCOMPARE(asked.size(), 2);

        // SRV: the host's addresses are asked for.
        rig.transport->deliver(response({}, {srvRecord(type, inst, "drive-host.local", 8080)}));
        QVERIFY(rig.found.isEmpty());
        asked = allQuestions(rig.transport->drain());
        QVERIFY(asked.contains(QStringLiteral("A drive-host.local")));
        QVERIFY(asked.contains(QStringLiteral("AAAA drive-host.local")));
        QVERIFY(!asked.contains(QStringLiteral("SRV ") + instName));

        // TXT and the address: now it is complete (webdav needs the TXT path).
        rig.transport->deliver(response({}, {txtRecord(type, inst, {"path=/dav"})}));
        QVERIFY(rig.found.isEmpty());
        rig.transport->deliver(response({}, {addressRecord("drive-host.local", QStringLiteral("192.0.2.50")),
                                             addressRecord("drive-host.local", QStringLiteral("2001:db8::50"))}));
        QCOMPARE(rig.found.size(), 1);
        QCOMPARE(rig.found[0].port, 8080);
        QCOMPARE(rig.found[0].path, QStringLiteral("/dav"));
        QCOMPARE(rig.found[0].addresses, addresses({QStringLiteral("192.0.2.50"), QStringLiteral("2001:db8::50")}));
        QCOMPARE(allQuestions(rig.transport->drain()).size(), 0);        // nothing left to ask
    }

    void anSftpServiceDoesNotNeedItsTxtRecord()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(response({ptrRecord("_ssh._tcp", "box")},
                                        {srvRecord("_ssh._tcp", "box", "box.local", 22),
                                         addressRecord("box.local", QStringLiteral("192.0.2.60"))}));
        QCOMPARE(rig.found.size(), 1);
    }

    void givesUpWaitingForAddressesAfterThreeQueries()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->drain();
        rig.transport->deliver(response({ptrRecord("_ssh._tcp", "box")}, {srvRecord("_ssh._tcp", "box", "box.local", 22)}));
        auto addressQueriesSent = [&rig]() {
            const QStringList asked = allQuestions(rig.transport->drain());
            return asked.count(QStringLiteral("A box.local")) + asked.count(QStringLiteral("AAAA box.local"));
        };
        int addressQueries = addressQueriesSent();
        QCOMPARE(addressQueries, 2);                       // A and AAAA, at once
        QVERIFY(rig.found.isEmpty());

        // Retries after 1 s and 2 s, then one more wait of 4 s before the service is reported as it is.
        rig.advance(1000);
        addressQueries += addressQueriesSent();
        rig.advance(2000);
        addressQueries += addressQueriesSent();
        QCOMPARE(addressQueries, 6);
        rig.advance(3999);
        addressQueries += addressQueriesSent();
        QCOMPARE(addressQueries, 6);                       // no fourth attempt
        QVERIFY(rig.found.isEmpty());
        rig.advance(1);
        QCOMPARE(rig.found.size(), 1);
        QVERIFY(rig.found[0].addresses.isEmpty());
        QCOMPARE(rig.found[0].host, QStringLiteral("box.local"));

        // A late address completes it.
        rig.transport->deliver(response({}, {addressRecord("box.local", QStringLiteral("192.0.2.61"))}));
        QCOMPARE(rig.updated.size(), 1);
        QCOMPARE(rig.updated[0].addresses, addresses({QStringLiteral("192.0.2.61")}));
    }

    void reportsChangesAsUpdates()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(announcement("_webdav._tcp", "dav", "dav.local", 80, QStringLiteral("192.0.2.70"),
                                            {"path=/a"}));
        QCOMPARE(rig.found.size(), 1);

        rig.transport->deliver(response({}, {txtRecord("_webdav._tcp", "dav", {"path=/b", "u=carol"})}));
        QCOMPARE(rig.updated.size(), 1);
        QCOMPARE(rig.updated.last().path, QStringLiteral("/b"));
        QCOMPARE(rig.updated.last().user, QStringLiteral("carol"));

        rig.transport->deliver(response({}, {srvRecord("_webdav._tcp", "dav", "dav.local", 8080)}));
        QCOMPARE(rig.updated.size(), 2);
        QCOMPARE(rig.updated.last().port, 8080);

        // A second address, IPv6 sorts after IPv4.
        rig.transport->deliver(response({}, {addressRecord("dav.local", QStringLiteral("2001:db8::7"), 120, false),
                                             addressRecord("dav.local", QStringLiteral("192.0.2.71"), 120, false)}));
        QCOMPARE(rig.updated.size(), 3);
        QCOMPARE(rig.updated.last().addresses,
                 addresses({QStringLiteral("192.0.2.70"), QStringLiteral("192.0.2.71"), QStringLiteral("2001:db8::7")}));

        // Re-announcing the same data changes nothing.
        rig.transport->deliver(response({}, {txtRecord("_webdav._tcp", "dav", {"path=/b", "u=carol"})}));
        QCOMPARE(rig.updated.size(), 3);
        QCOMPARE(rig.found.size(), 1);
        QVERIFY(rig.lost.isEmpty());
    }

    void aCacheFlushRecordReplacesOlderAddresses()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(announcement("_ssh._tcp", "box", "box.local", 22, QStringLiteral("192.0.2.80")));
        rig.advance(2000);
        rig.transport->deliver(response({}, {addressRecord("box.local", QStringLiteral("192.0.2.81"))}));
        QCOMPARE(rig.updated.size(), 1);
        QCOMPARE(rig.updated[0].addresses, addresses({QStringLiteral("192.0.2.81")}));

        // Two flush records of one answer both stay.
        rig.advance(2000);
        rig.transport->deliver(response({}, {addressRecord("box.local", QStringLiteral("192.0.2.82")),
                                             addressRecord("box.local", QStringLiteral("192.0.2.83"))}));
        QCOMPARE(rig.updated.last().addresses, addresses({QStringLiteral("192.0.2.82"), QStringLiteral("192.0.2.83")}));
    }

    void anAddressGoodbyeRemovesJustThatAddress()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(response({ptrRecord("_ssh._tcp", "box")},
                                        {srvRecord("_ssh._tcp", "box", "box.local", 22),
                                         addressRecord("box.local", QStringLiteral("192.0.2.84"), 120, false),
                                         addressRecord("box.local", QStringLiteral("192.0.2.85"), 120, false)}));
        rig.transport->deliver(response({}, {addressRecord("box.local", QStringLiteral("192.0.2.84"), 0, false)}));
        QCOMPARE(rig.updated.size(), 1);
        QCOMPARE(rig.updated[0].addresses, addresses({QStringLiteral("192.0.2.85")}));
        QVERIFY(rig.lost.isEmpty());
    }

    // ----------------------------------------------------------- goodbye / TTL

    void aPtrGoodbyeLosesTheServiceImmediately()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(announcement("_smb._tcp", "Nas", "nas.local", 445, QStringLiteral("192.0.2.90")));
        QCOMPARE(rig.found.size(), 1);
        rig.transport->deliver(response({ptrRecord("_smb._tcp", "Nas", 0)}));
        QCOMPARE(rig.lost.size(), 1);                    // no timer pass needed
        QCOMPARE(rig.lost[0].host, QStringLiteral("nas.local"));
        QCOMPARE(rig.lost[0].port, 445);
        QCOMPARE(rig.lost[0].instanceName, QStringLiteral("Nas"));
        QVERIFY(rig.discovery.services().isEmpty());
        rig.transport->deliver(response({ptrRecord("_smb._tcp", "Nas", 0)}));       // again: nothing
        QCOMPARE(rig.lost.size(), 1);
        rig.advance(10000000);
        QCOMPARE(rig.lost.size(), 1);
    }

    void anSrvGoodbyeLosesTheServiceToo()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(announcement("_smb._tcp", "Nas", "nas.local", 445, QStringLiteral("192.0.2.91")));
        rig.transport->deliver(response({}, {srvRecord("_smb._tcp", "Nas", "nas.local", 445, 0)}));
        QCOMPARE(rig.lost.size(), 1);
    }

    void aGoodbyeForAnUnknownServiceIsIgnored()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(response({ptrRecord("_smb._tcp", "Nobody", 0)}));
        QVERIFY(rig.log.isEmpty());
    }

    void servicesExpireWhenTheirTtlRunsOut()
    {
        Rig rig;
        rig.discovery.start();
        const quint32 ttl = 10;
        rig.transport->deliver(response({ptrRecord("_ssh._tcp", "box", ttl)},
                                        {srvRecord("_ssh._tcp", "box", "box.local", 22, ttl),
                                         txtRecord("_ssh._tcp", "box", {}, ttl),
                                         addressRecord("box.local", QStringLiteral("192.0.2.92"), ttl)}));
        QCOMPARE(rig.found.size(), 1);
        rig.transport->drain();

        // Refresh queries at 80, 90 and 95 percent of the TTL (RFC 6762 section 5.2).
        rig.advance(7999);
        QCOMPARE(allQuestions(rig.transport->drain()).filter(QStringLiteral("SRV box")).size(), 0);
        rig.advance(1);
        QStringList asked = allQuestions(rig.transport->drain());
        QVERIFY(asked.contains(QStringLiteral("SRV box._ssh._tcp.local")));
        QVERIFY(asked.contains(QStringLiteral("TXT box._ssh._tcp.local")));
        QVERIFY(asked.contains(QStringLiteral("A box.local")));
        rig.advance(1000);
        QVERIFY(allQuestions(rig.transport->drain()).contains(QStringLiteral("SRV box._ssh._tcp.local")));
        rig.advance(500);
        QVERIFY(allQuestions(rig.transport->drain()).contains(QStringLiteral("SRV box._ssh._tcp.local")));
        rig.advance(400);
        QCOMPARE(allQuestions(rig.transport->drain()).filter(QStringLiteral("SRV box")).size(), 0);   // three stages only

        rig.advance(99);                                 // 9999 ms after the announcement
        QVERIFY(rig.lost.isEmpty());
        rig.advance(1);                                  // exactly the TTL
        QCOMPARE(rig.lost.size(), 1);
        QCOMPARE(rig.lost[0].host, QStringLiteral("box.local"));
        QVERIFY(rig.discovery.services().isEmpty());
    }

    void anAnsweredRefreshKeepsTheServiceAlive()
    {
        Rig rig;
        rig.discovery.start();
        const Dns::Message shortLived =
            response({ptrRecord("_ssh._tcp", "box", 10)}, {srvRecord("_ssh._tcp", "box", "box.local", 22, 10),
                                                           txtRecord("_ssh._tcp", "box", {}, 10),
                                                           addressRecord("box.local", QStringLiteral("192.0.2.93"), 10)});
        rig.transport->deliver(shortLived);
        for (int i = 0; i < 5; ++i) {
            rig.advance(8000);
            rig.transport->deliver(shortLived);          // the answer to the refresh query
        }
        QVERIFY(rig.lost.isEmpty());
        QCOMPARE(rig.found.size(), 1);
        QVERIFY(rig.updated.isEmpty());
    }

    void aServiceIsLostWhenItsSrvExpiresAndFoundAgainWhenItReturns()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(announcement("_ssh._tcp", "box", "box.local", 22, QStringLiteral("192.0.2.94")));
        rig.advance(119999);
        QVERIFY(rig.lost.isEmpty());
        rig.advance(1);
        QCOMPARE(rig.lost.size(), 1);                    // SRV and A lapsed (120 s), PTR (75 min) did not
        rig.transport->deliver(announcement("_ssh._tcp", "box", "box.local", 22, QStringLiteral("192.0.2.94")));
        QCOMPARE(rig.found.size(), 2);
        QCOMPARE(rig.log, (QStringList{QStringLiteral("found box"), QStringLiteral("lost box"),
                                       QStringLiteral("found box")}));
    }

    void aServiceThatLosesItsAddressIsNotAnnouncedAgainWithoutOne()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(response({ptrRecord("_ssh._tcp", "box")},
                                        {srvRecord("_ssh._tcp", "box", "box.local", 22),
                                         addressRecord("box.local", QStringLiteral("192.0.2.97"), 10)}));
        QCOMPARE(rig.found.size(), 1);
        rig.advance(10000);
        QCOMPARE(rig.lost.size(), 1);
        rig.advance(60000);                              // the resolution attempts run out meanwhile
        QCOMPARE(rig.found.size(), 1);
        rig.transport->deliver(response({}, {addressRecord("box.local", QStringLiteral("192.0.2.98"))}));
        QCOMPARE(rig.found.size(), 2);                   // but a returning address brings it back
        QCOMPARE(rig.found[1].addresses, addresses({QStringLiteral("192.0.2.98")}));
    }

    void aVeryLongTtlIsClamped()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(response({ptrRecord("_ssh._tcp", "box", 0xFFFFFFFFu)},
                                        {srvRecord("_ssh._tcp", "box", "box.local", 22, 0xFFFFFFFFu),
                                         addressRecord("box.local", QStringLiteral("192.0.2.95"), 0xFFFFFFFFu)}));
        QCOMPARE(rig.found.size(), 1);
        rig.advance(7199 * 1000);
        QVERIFY(rig.lost.isEmpty());
        rig.advance(1000);
        QCOMPARE(rig.lost.size(), 1);
    }

    void knownAnswersSuppressRepeatedResponses()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(announcement("_ssh._tcp", "Mixed Case", "box.local", 22, QStringLiteral("192.0.2.96")));
        rig.transport->drain();
        rig.advance(1000);
        QVector<Dns::Message> sent = rig.transport->drain();
        const Dns::Message *browse = nullptr;
        for (const Dns::Message &m : sent) {
            if (m.questions.size() == 6)
                browse = &m;
        }
        QVERIFY(browse);
        QCOMPARE(browse->answers.size(), 1);
        QCOMPARE(browse->answers[0].type, quint16(Dns::TypePtr));
        QCOMPARE(browse->answers[0].name, QByteArray("_ssh._tcp.local"));
        QCOMPARE(browse->answers[0].target, QByteArray("Mixed Case._ssh._tcp.local"));
        QCOMPARE(browse->answers[0].ttl, quint32(4499));

        // With less than half of the TTL left the answer is no longer offered.
        rig.advance(2300 * 1000);
        sent = rig.transport->drain();
        for (const Dns::Message &m : sent) {
            if (m.questions.size() == 6)
                QVERIFY(m.answers.isEmpty());
        }
    }

    // --------------------------------------------------------- hostile input

    void ignoresMalformedAndUnrelatedMessages()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliverRaw(QByteArray());
        rig.transport->deliverRaw(QByteArray("garbage that is no DNS message at all"));
        rig.transport->deliverRaw(QByteArray(100, '\xff'));

        const Dns::Message good = announcement("_ssh._tcp", "box", "box.local", 22, QStringLiteral("192.0.2.100"));
        Dns::Message query = good;
        query.flags = 0;                                  // a query, not a response
        rig.transport->deliver(query);
        Dns::Message opcode = good;
        opcode.flags |= (1 << 11);
        rig.transport->deliver(opcode);
        Dns::Message rcode = good;
        rcode.flags |= 3;
        rig.transport->deliver(rcode);
        Dns::Message foreign = good;
        for (Dns::Record &r : foreign.answers)
            r.cls = 3;                                    // CHAOS
        for (Dns::Record &r : foreign.additional)
            r.cls = 3;
        rig.transport->deliver(foreign);
        QVERIFY(rig.log.isEmpty());

        rig.transport->deliver(good);
        QCOMPARE(rig.found.size(), 1);
    }

    void ignoresServiceTypesAndNamesItDidNotAskFor()
    {
        Rig rig;
        rig.discovery.start();
        auto ptrTo = [](const QByteArray &type, const QByteArray &target) {
            Dns::Record r = ptrRecord(type, "x");
            r.target = target;
            return r;
        };
        const QVector<Dns::Record> srv = {srvRecord("_ssh._tcp", "x", "x.local", 22)};
        // Unbrowsed type; target of another type; two labels in front; no instance label; wrong domain.
        rig.transport->deliver(response({ptrTo("_http._tcp", "x._http._tcp.local"),
                                         ptrTo("_ssh._tcp", "x._smb._tcp.local"),
                                         ptrTo("_ssh._tcp", "a.b._ssh._tcp.local"),
                                         ptrTo("_ssh._tcp", "_ssh._tcp.local"),
                                         ptrTo("_ssh._tcp", "x._ssh._tcp.example.com")},
                                        srv + QVector<Dns::Record>{addressRecord("x.local", QStringLiteral("192.0.2.101"))}));
        rig.advance(20000);
        QVERIFY(rig.log.isEmpty());
        QVERIFY(rig.discovery.services().isEmpty());
        // An instance label that contains a dot escaped is one label and fine.
        Dns::Record ok = ptrRecord("_ssh._tcp", "x");
        ok.target = "a\\.b._ssh._tcp.local";
        rig.transport->deliver(response({ok}, {srvRecord("_ssh._tcp", "a\\.b", "x.local", 22),
                                               addressRecord("x.local", QStringLiteral("192.0.2.101"))}));
        QCOMPARE(rig.found.size(), 1);
        QCOMPARE(rig.found[0].instanceName, QStringLiteral("a.b"));
    }

    void rejectsSrvTargetsThatAreNotPlainHostNames()
    {
        const char *const bad[] = {"evil/path.local", "user@evil.local", "evil:22.local", "a b.local", "a\\.b.local",
                                   "evil?x.local", "evil#.local", "[::1].local", "", "ev\\001il.local", "pct%41.local"};
        for (const char *target : bad) {
            Rig rig;
            rig.discovery.start();
            rig.transport->deliver(response({ptrRecord("_ssh._tcp", "box")},
                                            {srvRecord("_ssh._tcp", "box", target, 22),
                                             addressRecord(target, QStringLiteral("192.0.2.102"))}));
            rig.advance(20000);
            QVERIFY2(rig.found.isEmpty(), target);
        }
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(response({ptrRecord("_ssh._tcp", "box")},
                                        {srvRecord("_ssh._tcp", "box", "host.local", 0),    // port 0: not available
                                         addressRecord("host.local", QStringLiteral("192.0.2.103"))}));
        rig.advance(20000);
        QVERIFY(rig.found.isEmpty());
        // Letters, digits, '-', '_' and UTF-8 are fine.
        rig.transport->deliver(announcement("_ssh._tcp", "ok", "Büro_nas-1.local", 22, QStringLiteral("192.0.2.104")));
        QCOMPARE(rig.found.size(), 1);
        QCOMPARE(rig.found[0].host, QStringLiteral("Büro_nas-1.local"));
    }

    void dropsUnusableAddresses()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(response({ptrRecord("_ssh._tcp", "box")},
                                        {srvRecord("_ssh._tcp", "box", "box.local", 22),
                                         addressRecord("box.local", QStringLiteral("127.0.0.1"), 120, false),
                                         addressRecord("box.local", QStringLiteral("0.0.0.0"), 120, false),
                                         addressRecord("box.local", QStringLiteral("224.0.0.251"), 120, false),
                                         addressRecord("box.local", QStringLiteral("::1"), 120, false),
                                         addressRecord("box.local", QStringLiteral("::"), 120, false),
                                         addressRecord("box.local", QStringLiteral("fe80::1"), 120, false),
                                         addressRecord("box.local", QStringLiteral("ff02::fb"), 120, false),
                                         addressRecord("box.local", QStringLiteral("169.254.7.7"), 120, false),
                                         addressRecord("box.local", QStringLiteral("fd00::7"), 120, false)}));
        rig.advance(10000);
        QCOMPARE(rig.found.size(), 1);
        QCOMPARE(rig.found[0].addresses, addresses({QStringLiteral("169.254.7.7"), QStringLiteral("fd00::7")}));
    }

    void ignoresAddressesOfHostsNoServiceUses()
    {
        Rig rig;
        rig.discovery.start();
        rig.transport->deliver(response({}, {addressRecord("stranger.local", QStringLiteral("192.0.2.105"))}));
        rig.transport->deliver(announcement("_ssh._tcp", "box", "box.local", 22, QStringLiteral("192.0.2.106")));
        QCOMPARE(rig.found[0].addresses, addresses({QStringLiteral("192.0.2.106")}));
    }

    void boundsWhatItRemembers()
    {
        Rig rig;
        rig.discovery.start();
        for (int i = 0; i < 300; ++i) {
            const QByteArray name = "n" + QByteArray::number(i);
            rig.transport->deliver(announcement("_ssh._tcp", name, name + ".local", 22,
                                                QStringLiteral("192.0.2.%1").arg(i % 250 + 1)));
        }
        QCOMPARE(rig.discovery.services().size(), 256);
        QCOMPARE(rig.found.size(), 256);

        Rig many;
        many.discovery.start();
        QVector<Dns::Record> additional = {srvRecord("_ssh._tcp", "box", "box.local", 22)};
        for (int i = 1; i <= 20; ++i)
            additional.append(addressRecord("box.local", QStringLiteral("192.0.2.%1").arg(i), 120, false));
        many.transport->deliver(response({ptrRecord("_ssh._tcp", "box")}, additional));
        QCOMPARE(many.found.size(), 1);
        QCOMPARE(many.found[0].addresses.size(), 8);
    }

    // ------------------------------------------------------------ templates

    void buildsConnectionTemplatesWithoutSecrets()
    {
        DiscoveredService dav;
        dav.provider = QStringLiteral("webdav");
        dav.tls = QStringLiteral("https");
        dav.host = QStringLiteral("cloud.local");
        dav.port = 8443;
        dav.path = QStringLiteral("/remote.php/dav");
        dav.user = QStringLiteral("alice");
        QString path;
        ConnectionParams p = toConnectionParams(dav, &path);
        QCOMPARE(p.provider, QStringLiteral("webdav"));
        QCOMPARE(p.host, QStringLiteral("cloud.local"));
        QCOMPARE(p.port, 8443);
        QCOMPARE(p.username, QStringLiteral("alice"));
        QCOMPARE(p.option(QStringLiteral("tls")), QStringLiteral("https"));
        QCOMPARE(p.option(QStringLiteral("base_path")), QStringLiteral("/remote.php/dav"));
        QVERIFY(!p.options.contains(QStringLiteral("allow_insecure")));
        QCOMPARE(path, QStringLiteral("/"));

        dav.tls = QStringLiteral("http");
        dav.path.clear();
        p = toConnectionParams(dav, &path);
        QCOMPARE(p.option(QStringLiteral("tls")), QStringLiteral("http"));
        QCOMPARE(p.option(QStringLiteral("base_path")), QStringLiteral("/"));
        QVERIFY(!p.flag(QStringLiteral("allow_insecure")));        // consent is the user's to give

        DiscoveredService ftp;
        ftp.provider = QStringLiteral("ftp");
        ftp.host = QStringLiteral("files.local");
        ftp.port = 21;
        ftp.path = QStringLiteral("/pub");
        p = toConnectionParams(ftp, &path);
        QCOMPARE(p.provider, QStringLiteral("ftp"));
        QCOMPARE(path, QStringLiteral("/pub"));
        QVERIFY(p.options.isEmpty());

        DiscoveredService smb;
        smb.provider = QStringLiteral("smb");
        smb.host = QStringLiteral("nas.local");
        smb.port = 445;
        p = toConnectionParams(smb, &path);
        QCOMPARE(p.provider, QStringLiteral("smb"));
        QVERIFY(!p.options.contains(QStringLiteral("share")));    // server mode
        QCOMPARE(path, QStringLiteral("/"));
        QVERIFY(p.username.isEmpty());

        DiscoveredService sftp;
        sftp.provider = QStringLiteral("sftp");
        sftp.port = 22;
        sftp.addresses = addresses({QStringLiteral("2001:db8::1")});
        p = toConnectionParams(sftp);                              // no host name: first address
        QCOMPARE(p.host, QStringLiteral("2001:db8::1"));
        QCOMPARE(p.port, 22);
    }

    // ------------------------------------------------------------- transport

    void recognisesOnLinkSenders()
    {
        QNetworkAddressEntry v4;
        v4.setIp(QHostAddress(QStringLiteral("192.168.1.5")));
        v4.setPrefixLength(24);
        QNetworkAddressEntry v6;
        v6.setIp(QHostAddress(QStringLiteral("2001:db8:1::5")));
        v6.setPrefixLength(64);
        const QList<QNetworkAddressEntry> entries = {v4, v6};
        auto on = [&entries](const char *a) { return MulticastTransport::isOnLink(QHostAddress(QString::fromLatin1(a)), entries); };
        QVERIFY(on("192.168.1.77"));
        QVERIFY(!on("192.168.2.1"));
        QVERIFY(!on("8.8.8.8"));
        QVERIFY(on("2001:db8:1::99"));
        QVERIFY(!on("2001:db8:2::99"));
        QVERIFY(on("fe80::1234"));                       // link-local needs no entry
        QVERIFY(!MulticastTransport::isOnLink(QHostAddress(QStringLiteral("10.0.0.1")), {}));
        QVERIFY(MulticastTransport::isOnLink(QHostAddress(QStringLiteral("fe80::1")), {}));
    }

    void talksToRealSocketsOnLoopback()
    {
        QUdpSocket peer;
        QVERIFY(peer.bind(QHostAddress(QHostAddress::LocalHost), 0));
        MulticastTransport::Options options;
        options.port = 0;
        options.requiredSourcePort = peer.localPort();
        options.ipv6 = false;
        options.multicast = false;
        options.unicastAddress = QHostAddress::LocalHost;
        options.unicastPort = peer.localPort();
        auto *transport = new MulticastTransport(options);
        Discovery discovery(transport);
        QVector<DiscoveredService> found;
        connect(&discovery, &Discovery::found, this, [&found](const DiscoveredService &s) { found.append(s); });

        QVERIFY(discovery.start());
        QVERIFY(transport->isOpen());
        QVERIFY(transport->localPort() != 0);

        // The browse query arrives at the peer.
        QTRY_VERIFY(peer.hasPendingDatagrams());
        QByteArray query(static_cast<int>(peer.pendingDatagramSize()), Qt::Uninitialized);
        peer.readDatagram(query.data(), query.size());
        Dns::Message m;
        QVERIFY(Dns::decode(query, &m));
        QCOMPARE(m.questions.size(), 6);

        // An announcement from the right port is found.
        const QByteArray wire = Dns::encode(announcement("_smb._tcp", "Loop Nas", "loop.local", 445, QStringLiteral("192.0.2.110")));
        QVERIFY(peer.writeDatagram(wire, QHostAddress::LocalHost, transport->localPort()) == wire.size());
        QTRY_COMPARE(found.size(), 1);
        QCOMPARE(found[0].instanceName, QStringLiteral("Loop Nas"));
        QCOMPARE(found[0].provider, QStringLiteral("smb"));

        // The same bytes from another source port are dropped by the transport.
        QUdpSocket other;
        QVERIFY(other.bind(QHostAddress(QHostAddress::LocalHost), 0));
        const QByteArray second = Dns::encode(announcement("_smb._tcp", "Other", "other.local", 445, QStringLiteral("192.0.2.111")));
        QVERIFY(other.writeDatagram(second, QHostAddress::LocalHost, transport->localPort()) == second.size());
        // Garbage from the right port is dropped by the parser.
        QVERIFY(peer.writeDatagram(QByteArray(40, '\xc0'), QHostAddress::LocalHost, transport->localPort()) == 40);
        QTest::qWait(200);
        QCOMPARE(found.size(), 1);

        discovery.stop();
        QVERIFY(!transport->isOpen());
        QCOMPARE(transport->localPort(), quint16(0));
    }

    void multicastSocketsOpenAndSendWithoutError()
    {
        MulticastTransport::Options options;
        options.port = 0;                  // never collide with a system responder on 5353
        options.requiredSourcePort = 0;
        MulticastTransport transport(options);
        if (!transport.open())
            QSKIP("no multicast capable socket in this environment");
        QVERIFY(transport.isOpen());
        QVERIFY(transport.open());          // idempotent
        transport.send(Dns::encode(Dns::Message()));
        transport.close();
        QVERIFY(!transport.isOpen());
        transport.send(QByteArray("ignored"));      // closed: no effect
    }
};

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    int status = runDnsMessageTests(argc, argv);
    TestDiscovery discoveryTests;
    status |= QTest::qExec(&discoveryTests, argc, argv);
    return status;
}

#include "tst_discovery.moc"
