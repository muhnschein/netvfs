// SPDX-License-Identifier: LGPL-2.1-or-later
#include "discoverytestutil.h"
#include "dnsmessage.h"

#include <QtTest/QtTest>

using namespace NetVfs;
using namespace NetVfs::Dns;
using NetVfs::Test::hexBytes;
using NetVfs::Test::Pkt;

namespace {

// An avahi style answer to a PTR query for _smb._tcp.local: the PTR in the
// answer section, SRV, TXT and A in the additional section, names compressed
// against the question name and the instance name. Written byte by byte.
QByteArray avahiResponse()
{
    Pkt p;
    p.header(0, 0x8400, 0, 1, 0, 3);
    const int typeName = p.size();                       // "_smb._tcp.local" at offset 12
    p.name("_smb._tcp.local");
    const int localOffset = typeName + 10;               // "local" after two 5 byte labels
    p.u16(TypePtr).u16(ClassIn).u32(4500);
    int lengthAt = p.size();
    p.u16(0);
    const int instanceOffset = p.size();
    p.label("My NAS").ptr(typeName);
    p.patch16(lengthAt, p.size() - lengthAt - 2);

    p.ptr(instanceOffset).u16(TypeSrv).u16(0x8001).u32(120);
    lengthAt = p.size();
    p.u16(0).u16(0).u16(0).u16(445).label("nas").ptr(localOffset);
    p.patch16(lengthAt, p.size() - lengthAt - 2);

    p.ptr(instanceOffset).u16(TypeTxt).u16(0x8001).u32(4500).u16(10).label("txtvers=1");

    p.label("nas").ptr(localOffset).u16(TypeA).u16(0x8001).u32(120).u16(4).u8(192).u8(0).u8(2).u8(7);
    return p.bytes();
}

bool rejects(const QByteArray &packet)
{
    Message m;
    QString why;
    const bool ok = decode(packet, &m, &why);
    return !ok && !why.isEmpty() && m.answers.isEmpty() && m.questions.isEmpty();
}

// A packet with one question whose name is `name` (bytes as given), then type/class.
QByteArray questionWith(const QByteArray &nameBytes)
{
    Pkt p;
    p.header(0, 0, 1, 0, 0, 0);
    p.raw(nameBytes).u16(TypePtr).u16(ClassIn);
    return p.bytes();
}

QByteArray answerWith(int type, const QByteArray &rdata, int rdlength = -1)
{
    Pkt p;
    p.header(0, 0x8400, 0, 1, 0, 0);
    p.name("x.local").u16(type).u16(ClassIn).u32(10).u16(rdlength < 0 ? rdata.size() : rdlength).raw(rdata);
    return p.bytes();
}

Message sampleMessage()
{
    Message m;
    m.id = 0x1234;
    m.flags = FlagResponse | FlagAuthoritative;
    Question q;
    q.name = "_webdav._tcp.local";
    q.type = TypePtr;
    q.unicastResponse = true;
    m.questions.append(q);
    Record ptr;
    ptr.name = "_webdav._tcp.local";
    ptr.type = TypePtr;
    ptr.ttl = 4500;
    ptr.target = "Files\\.Box._webdav._tcp.local";
    m.answers.append(ptr);
    Record srv;
    srv.name = ptr.target;
    srv.type = TypeSrv;
    srv.cacheFlush = true;
    srv.ttl = 120;
    srv.priority = 1;
    srv.weight = 2;
    srv.port = 8080;
    srv.target = "box.local";
    m.additional.append(srv);
    Record txt;
    txt.name = ptr.target;
    txt.type = TypeTxt;
    txt.cacheFlush = true;
    txt.ttl = 4500;
    txt.txt = {"path=/dav", "u=alice", "flag"};
    m.additional.append(txt);
    Record a;
    a.name = "box.local";
    a.type = TypeA;
    a.ttl = 120;
    a.address = QHostAddress(QStringLiteral("192.0.2.9"));
    m.additional.append(a);
    Record aaaa;
    aaaa.name = "box.local";
    aaaa.type = TypeAaaa;
    aaaa.ttl = 120;
    aaaa.address = QHostAddress(QStringLiteral("2001:db8::9"));
    m.additional.append(aaaa);
    Record other;
    other.name = "box.local";
    other.type = 47;           // NSEC: carried verbatim
    other.ttl = 120;
    other.rdata = hexBytes("00010203");
    m.additional.append(other);
    return m;
}

} // namespace

class TestDnsMessage : public QObject
{
    Q_OBJECT

private slots:
    void decodesAnAvahiStyleResponse()
    {
        Message m;
        QString why;
        QVERIFY2(decode(avahiResponse(), &m, &why), qPrintable(why));
        QVERIFY(m.isResponse());
        QCOMPARE(m.opcode(), 0);
        QCOMPARE(m.rcode(), 0);
        QCOMPARE(m.answers.size(), 1);
        QCOMPARE(m.additional.size(), 3);
        QCOMPARE(m.answers[0].name, QByteArray("_smb._tcp.local"));
        QCOMPARE(m.answers[0].type, quint16(TypePtr));
        QCOMPARE(m.answers[0].ttl, quint32(4500));
        QVERIFY(!m.answers[0].cacheFlush);
        QCOMPARE(m.answers[0].target, QByteArray("My NAS._smb._tcp.local"));

        const Record &srv = m.additional[0];
        QCOMPARE(srv.name, QByteArray("My NAS._smb._tcp.local"));
        QCOMPARE(srv.type, quint16(TypeSrv));
        QVERIFY(srv.cacheFlush);
        QCOMPARE(srv.cls, quint16(ClassIn));
        QCOMPARE(srv.ttl, quint32(120));
        QCOMPARE(srv.port, quint16(445));
        QCOMPARE(srv.target, QByteArray("nas.local"));

        const Record &txt = m.additional[1];
        QCOMPARE(txt.type, quint16(TypeTxt));
        QCOMPARE(txt.txt, QList<QByteArray>{"txtvers=1"});

        const Record &a = m.additional[2];
        QCOMPARE(a.name, QByteArray("nas.local"));
        QCOMPARE(a.type, quint16(TypeA));
        QCOMPARE(a.address, QHostAddress(QStringLiteral("192.0.2.7")));
    }

    void decodesAQuestionWithTheUnicastBit()
    {
        Pkt p;
        p.header(0x42, 0, 2, 0, 0, 0);
        p.name("_ssh._tcp.local").u16(TypePtr).u16(0x8001);
        p.label("host").ptr(12 + 10).u16(TypeAny).u16(ClassIn);       // "host.local", pointer into "local"
        Message m;
        QVERIFY(decode(p.bytes(), &m));
        QCOMPARE(m.id, quint16(0x42));
        QVERIFY(!m.isResponse());
        QCOMPARE(m.questions.size(), 2);
        QVERIFY(m.questions[0].unicastResponse);
        QCOMPARE(m.questions[0].cls, quint16(ClassIn));
        QCOMPARE(m.questions[0].name, QByteArray("_ssh._tcp.local"));
        QVERIFY(!m.questions[1].unicastResponse);
        QCOMPARE(m.questions[1].name, QByteArray("host.local"));
        QCOMPARE(m.questions[1].type, quint16(TypeAny));
    }

    void decodesAAAAAndEmptyTxtAndUnknownTypes()
    {
        Message m;
        QVERIFY(decode(answerWith(TypeAaaa, hexBytes("20010db8000000000000000000000001")), &m));
        QCOMPARE(m.answers[0].address, QHostAddress(QStringLiteral("2001:db8::1")));
        QVERIFY(decode(answerWith(TypeTxt, hexBytes("00")), &m));
        QCOMPARE(m.answers[0].txt, QList<QByteArray>{QByteArray()});
        QVERIFY(decode(answerWith(99, hexBytes("deadbeef")), &m));
        QCOMPARE(m.answers[0].rdata, hexBytes("deadbeef"));
        QVERIFY(decode(answerWith(99, QByteArray()), &m));
    }

    void escapesLabelsWithDotsAndControlBytes()
    {
        Pkt p;
        p.header(0, 0, 1, 0, 0, 0);
        p.label("a.b").label(QByteArray("c\\d\x01", 4)).label("local").u8(0).u16(TypePtr).u16(ClassIn);
        Message m;
        QVERIFY(decode(p.bytes(), &m));
        QCOMPARE(m.questions[0].name, QByteArray("a\\.b.c\\\\d\\001.local"));
        bool ok = false;
        const QList<QByteArray> labels = splitName(m.questions[0].name, &ok);
        QVERIFY(ok);
        QCOMPARE(labels.size(), 3);
        QCOMPARE(labels[0], QByteArray("a.b"));
        QCOMPARE(labels[1], QByteArray("c\\d\x01", 4));
        QCOMPARE(joinName(labels), m.questions[0].name);
    }

    void keepsUtf8InNames()
    {
        const QByteArray utf8 = QStringLiteral("Büro-NAS ☃").toUtf8();
        Pkt p;
        p.header(0, 0, 1, 0, 0, 0);
        p.label(utf8).label("local").u8(0).u16(TypePtr).u16(ClassIn);
        Message m;
        QVERIFY(decode(p.bytes(), &m));
        QCOMPARE(m.questions[0].name, utf8 + ".local");
    }

    // ----------------------------------------------------------- malformed

    void rejectsShortAndOversizedPackets()
    {
        QVERIFY(rejects(QByteArray()));
        QVERIFY(rejects(QByteArray(11, '\0')));
        QVERIFY(rejects(QByteArray(MaxPacketSize + 1, '\0')));
        Message m;
        QVERIFY(decode(QByteArray(HeaderSize, '\0'), &m));        // an empty message is fine
    }

    void rejectsCountsThatCannotFit()
    {
        Pkt p;
        p.header(0, 0x8400, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);
        QVERIFY(rejects(p.bytes()));
        Pkt q;
        q.header(0, 0, 1, 0, 0, 0);                               // promises a question, has none
        QVERIFY(rejects(q.bytes()));
        Pkt r;
        r.header(0, 0x8400, 0, 1000, 0, 0);                       // more than MaxRecords
        r.raw(QByteArray(11 * 1000, '\0'));
        QVERIFY(rejects(r.bytes()));
    }

    void rejectsCompressionPointerLoops()
    {
        // A pointer to itself.
        QVERIFY(rejects(questionWith(hexBytes("c00c"))));
        // A pointer pointing forward.
        QVERIFY(rejects(questionWith(hexBytes("c00e") + hexBytes("0161") + hexBytes("00"))));
        // Two pointers to each other: the second one points forward.
        Pkt p;
        p.header(0, 0, 1, 0, 0, 0);
        p.ptr(14).ptr(12).u16(TypePtr).u16(ClassIn);
        QVERIFY(rejects(p.bytes()));
        // A pointer past the end of the packet.
        QVERIFY(rejects(questionWith(hexBytes("c3ff"))));
        // A truncated pointer.
        Pkt t;
        t.header(0, 0, 1, 0, 0, 0);
        t.u8(0xC0);
        QVERIFY(rejects(t.bytes()));
    }

    void rejectsLabelLoopsThroughBackwardPointers()
    {
        // At 12: label "a", then a pointer back to 12. Every pointer points
        // backwards, but the name never ends: the 255 byte cap stops it.
        Pkt p;
        p.header(0, 0, 1, 0, 0, 0);
        p.label("a").ptr(12).u16(TypePtr).u16(ClassIn);
        QVERIFY(rejects(p.bytes()));
    }

    void rejectsOverlongAndReservedNames()
    {
        Pkt longName;
        longName.header(0, 0, 1, 0, 0, 0);
        const QByteArray sixtyThree(63, 'x');
        for (int i = 0; i < 4; ++i)
            longName.label(sixtyThree);                           // 4 * 64 = 256 > 255
        longName.u8(0).u16(TypePtr).u16(ClassIn);
        QVERIFY(rejects(longName.bytes()));

        Pkt maxName;                                              // 3 * 64 + 61 + 1 = 254 bytes: fine
        maxName.header(0, 0, 1, 0, 0, 0);
        for (int i = 0; i < 3; ++i)
            maxName.label(sixtyThree);
        maxName.label(QByteArray(60, 'y')).u8(0).u16(TypePtr).u16(ClassIn);
        Message m;
        QVERIFY(decode(maxName.bytes(), &m));

        QVERIFY(rejects(questionWith(hexBytes("40") + QByteArray(64, 'x') + hexBytes("00"))));   // 01xxxxxx
        QVERIFY(rejects(questionWith(hexBytes("80") + hexBytes("00"))));                         // 10xxxxxx
    }

    void rejectsLabelsPastTheEnd()
    {
        QVERIFY(rejects(questionWith(hexBytes("3f6161"))));       // claims 63 bytes, has 2
        Pkt p;
        p.header(0, 0, 1, 0, 0, 0);
        p.label("abc");                                           // no root label, no type/class
        QVERIFY(rejects(p.bytes()));
    }

    void rejectsBadRecords()
    {
        // rdlength beyond the packet, for a type that is skipped
        QVERIFY(rejects(answerWith(99, hexBytes("0102"), 3)));
        QVERIFY(rejects(answerWith(99, hexBytes("0102"), 0xFFFF)));
        // address records of the wrong size
        QVERIFY(rejects(answerWith(TypeA, hexBytes("c0000207"), 3)));
        QVERIFY(rejects(answerWith(TypeA, hexBytes("c000020700"))));
        QVERIFY(rejects(answerWith(TypeA, hexBytes("c00002"))));
        QVERIFY(rejects(answerWith(TypeAaaa, QByteArray(15, '\x01'))));
        QVERIFY(rejects(answerWith(TypeAaaa, QByteArray(17, '\x01'))));
        // SRV too short, with a target running past the record
        QVERIFY(rejects(answerWith(TypeSrv, hexBytes("000000000050"))));
        QVERIFY(rejects(answerWith(TypeSrv, hexBytes("00000000005003") + QByteArray("abc"))));
        // PTR whose name is longer than its rdlength
        QVERIFY(rejects(answerWith(TypePtr, hexBytes("026162") + hexBytes("00"), 2)));
        // TXT string overruns the record: at the end of the packet, and into a following record
        QVERIFY(rejects(answerWith(TypeTxt, hexBytes("0561626364"))));
        Pkt overrun;
        overrun.header(0, 0x8400, 0, 2, 0, 0);
        overrun.name("x.local").u16(TypeTxt).u16(ClassIn).u32(10).u16(3).raw(hexBytes("056162"));
        overrun.name("y.local").u16(TypeA).u16(ClassIn).u32(10).u16(4).raw(hexBytes("c0000207"));
        QVERIFY(rejects(overrun.bytes()));
        // trailing garbage after a PTR name inside the record
        QVERIFY(rejects(answerWith(TypePtr, hexBytes("0161000000"))));
        // truncated record header
        Pkt p;
        p.header(0, 0x8400, 0, 1, 0, 0);
        p.name("x.local").u16(TypePtr).u16(ClassIn).u16(0);
        QVERIFY(rejects(p.bytes()));
    }

    void rejectsEveryTruncationOfAValidPacket()
    {
        const QByteArray full = avahiResponse();
        Message m;
        QVERIFY(decode(full, &m));
        for (int len = 0; len < full.size(); ++len) {
            QVERIFY2(rejects(full.left(len)), qPrintable(QStringLiteral("prefix of %1 bytes accepted").arg(len)));
        }
    }

    void survivesEveryByteMutation()
    {
        const QByteArray full = avahiResponse();
        const int patterns[] = {0x00, 0x01, 0x3F, 0x40, 0x80, 0xBF, 0xC0, 0xFF};
        int decoded = 0;
        for (int i = 0; i < full.size(); ++i) {
            for (const int v : patterns) {
                QByteArray mutated = full;
                mutated[i] = static_cast<char>(v);
                Message m;
                if (decode(mutated, &m))
                    ++decoded;
                else
                    QVERIFY(m.answers.isEmpty() && m.additional.isEmpty() && m.questions.isEmpty());
            }
        }
        QVERIFY(decoded > 0);                // the mutations that keep the packet valid exist
    }

    // -------------------------------------------------------------- encoder

    void roundTripsAMessageWithEveryRecordType()
    {
        const Message in = sampleMessage();
        for (const bool compress : {true, false}) {
            const QByteArray wire = encode(in, compress);
            QVERIFY(!wire.isEmpty());
            Message out;
            QString why;
            QVERIFY2(decode(wire, &out, &why), qPrintable(why));
            QCOMPARE(out.id, in.id);
            QCOMPARE(out.flags, in.flags);
            QCOMPARE(out.questions.size(), 1);
            QCOMPARE(out.questions[0].name, in.questions[0].name);
            QVERIFY(out.questions[0].unicastResponse);
            QCOMPARE(out.answers.size(), 1);
            QCOMPARE(out.additional.size(), 5);
            QCOMPARE(out.answers[0].target, in.answers[0].target);
            QCOMPARE(out.additional[0].port, quint16(8080));
            QCOMPARE(out.additional[0].priority, quint16(1));
            QCOMPARE(out.additional[0].weight, quint16(2));
            QCOMPARE(out.additional[0].target, QByteArray("box.local"));
            QVERIFY(out.additional[0].cacheFlush);
            QCOMPARE(out.additional[1].txt, in.additional[1].txt);
            QCOMPARE(out.additional[2].address, in.additional[2].address);
            QCOMPARE(out.additional[3].address, in.additional[3].address);
            QCOMPARE(out.additional[4].rdata, in.additional[4].rdata);
        }
    }

    void compressionShrinksThePacketAndSrvTargetsStayUncompressed()
    {
        const Message in = sampleMessage();
        const QByteArray compressed = encode(in, true);
        const QByteArray plain = encode(in, false);
        QVERIFY(compressed.size() < plain.size());
        // The compressed form contains a pointer to the question name at offset 12.
        QVERIFY(compressed.contains(hexBytes("c00c")));
        QVERIFY(!plain.contains(hexBytes("c00c")));

        Message m;
        m.flags = FlagResponse;
        Record ptr;
        ptr.name = "_smb._tcp.local";
        ptr.type = TypePtr;
        ptr.target = "N._smb._tcp.local";
        m.answers.append(ptr);
        Record srv;
        srv.name = "N._smb._tcp.local";
        srv.type = TypeSrv;
        srv.target = "nas.local";
        srv.port = 445;
        m.answers.append(srv);
        const QByteArray wire = encode(m, true);
        QCOMPARE(wire.right(1), QByteArray(1, '\0'));          // SRV target ends with the root label, not a pointer
    }

    void matchesAHandWrittenEncoding()
    {
        Message m;
        m.flags = FlagResponse | FlagAuthoritative;
        Record a;
        a.name = "a.local";
        a.type = TypeA;
        a.ttl = 1;
        a.cacheFlush = true;
        a.address = QHostAddress(QStringLiteral("10.0.0.1"));
        m.answers.append(a);
        Pkt p;
        p.header(0, 0x8400, 0, 1, 0, 0).name("a.local").u16(TypeA).u16(0x8001).u32(1).u16(4).u8(10).u8(0).u8(0).u8(1);
        QCOMPARE(encode(m), p.bytes());
    }

    void compressionIsCaseInsensitive()
    {
        Message m;
        Question q1;
        q1.name = "Foo.LOCAL";
        q1.type = TypeA;
        Question q2;
        q2.name = "bar.local";
        q2.type = TypeA;
        m.questions = {q1, q2};
        const QByteArray wire = encode(m);
        Message out;
        QVERIFY(decode(wire, &out));
        QCOMPARE(canonicalName(out.questions[1].name), QByteArray("bar.local"));
        QVERIFY(wire.contains(hexBytes("c0")));                  // "local" of the second name is a pointer
    }

    void encoderRefusesWhatCannotBeRepresented()
    {
        Message m;
        Question q;
        q.type = TypeA;
        q.name = QByteArray(64, 'x') + ".local";
        m.questions = {q};
        QVERIFY(encode(m).isEmpty());                            // label of 64 bytes
        q.name = QByteArray(63, 'x') + "." + QByteArray(63, 'y') + "." + QByteArray(63, 'z') + "." + QByteArray(63, 'w');
        m.questions = {q};
        QVERIFY(encode(m).isEmpty());                            // 256 bytes on the wire
        q.name = "a..b";
        m.questions = {q};
        QVERIFY(encode(m).isEmpty());
        q.name = "bad\\";
        m.questions = {q};
        QVERIFY(encode(m).isEmpty());

        Message t;
        Record txt;
        txt.name = "x.local";
        txt.type = TypeTxt;
        txt.txt = {QByteArray(256, 'v')};
        t.answers = {txt};
        QVERIFY(encode(t).isEmpty());                            // string over 255 bytes
        txt.txt = {QByteArray(255, 'v')};
        t.answers = {txt};
        QVERIFY(!encode(t).isEmpty());

        Message wrong;
        Record a;
        a.name = "x.local";
        a.type = TypeA;
        a.address = QHostAddress(QStringLiteral("::1"));
        wrong.answers = {a};
        QVERIFY(encode(wrong).isEmpty());                        // IPv6 address in an A record
        Record aaaa;
        aaaa.name = "x.local";
        aaaa.type = TypeAaaa;
        aaaa.address = QHostAddress(QStringLiteral("10.0.0.1"));
        wrong.answers = {aaaa};
        QVERIFY(encode(wrong).isEmpty());

        Message big;
        Record unknown;
        unknown.name = "x.local";
        unknown.type = 99;
        unknown.rdata = QByteArray(1000, 'z');
        for (int i = 0; i < 10; ++i)
            big.answers.append(unknown);
        QVERIFY(encode(big).isEmpty());                          // over MaxPacketSize
        Record huge = unknown;
        huge.rdata = QByteArray(70000, 'z');
        Message h;
        h.answers = {huge};
        QVERIFY(encode(h).isEmpty());                            // rdlength over 65535
    }

    void emptyTxtEncodesAsOneEmptyString()
    {
        Message m;
        Record txt;
        txt.name = "x.local";
        txt.type = TypeTxt;
        m.answers = {txt};
        Message out;
        QVERIFY(decode(encode(m), &out));
        QCOMPARE(out.answers[0].txt, QList<QByteArray>{QByteArray()});
    }

    // ---------------------------------------------------------------- names

    void splitsAndJoinsNames()
    {
        bool ok = false;
        QCOMPARE(splitName("a.b.c", &ok), (QList<QByteArray>{"a", "b", "c"}));
        QVERIFY(ok);
        QCOMPARE(splitName("a.b.", &ok), (QList<QByteArray>{"a", "b"}));
        QVERIFY(ok);
        QVERIFY(splitName(QByteArray(), &ok).isEmpty());
        QVERIFY(ok);
        splitName("a..b", &ok);
        QVERIFY(!ok);
        splitName(".", &ok);
        QVERIFY(!ok);
        splitName("a\\", &ok);
        QVERIFY(!ok);
        splitName("a\\3", &ok);
        QVERIFY(!ok);
        splitName("a\\999", &ok);
        QVERIFY(!ok);
        QCOMPARE(splitName("a\\046b.c", &ok), (QList<QByteArray>{"a.b", "c"}));
        QVERIFY(ok);
        QCOMPARE(splitName("a\\.b\\\\.c", &ok), (QList<QByteArray>{"a.b\\", "c"}));
        QVERIFY(ok);
        QCOMPARE(joinName({"a.b", "c"}), QByteArray("a\\.b.c"));
        QCOMPARE(canonicalName("My NAS._SMB._tcp.LOCAL"), QByteArray("my nas._smb._tcp.local"));
    }

    void readsTxtAttributes()
    {
        const QList<QByteArray> txt = {"txtvers=1", "Path=/dav", "u=", "bool", "=novalue", "path=/second"};
        QCOMPARE(txtValue(txt, "path"), QByteArray("/dav"));       // case-insensitive key, first wins
        QCOMPARE(txtValue(txt, "PATH"), QByteArray("/dav"));
        QCOMPARE(txtValue(txt, "u", "x"), QByteArray());           // present but empty
        QCOMPARE(txtValue(txt, "missing", "fallback"), QByteArray("fallback"));
        QVERIFY(txtHasKey(txt, "bool"));
        QCOMPARE(txtValue(txt, "bool", "x"), QByteArray());
        QVERIFY(!txtHasKey(txt, "novalue"));                       // an empty key never matches
        QVERIFY(!txtHasKey(txt, "txtver"));
    }
};

int runDnsMessageTests(int argc, char **argv)
{
    TestDnsMessage test;
    return QTest::qExec(&test, argc, argv);
}

#include "tst_dnsmessage.moc"
