// SPDX-License-Identifier: LGPL-2.1-or-later
// The bridge protocol contract (SPEC-v2 XT-7), shared with the consumer's
// fake bridge: the introspection XML in this folder and the golden message
// sequences (*.json, format in README.md) replayed against the real bridge
// with the FakeBackend (provider "fake", account "account:1").
#include "bridgetest.h"

#include "args.h"
#include "fakebackend.h"
#include "protocol.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QXmlStreamReader>
#include <QtTest/QtTest>

using namespace NetVfs;
using namespace NetVfs::BridgeTest;
using NetVfs::Bridge::WireWriter;

namespace {

const QString ContractDir = QStringLiteral(NETVFS_SOURCE_DIR "/tests/bridge/contract");

struct XmlMember {
    QByteArray in;
    QByteArray out;
};

struct XmlInterface {
    QMap<QString, XmlMember> methods;
    QMap<QString, QByteArray> signalSignatures;
};

QByteArray readFile(const QString &path)
{
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

void readMember(QXmlStreamReader &xml, bool isSignal, XmlInterface *out)
{
    const QString name = xml.attributes().value(QStringLiteral("name")).toString();
    XmlMember member;
    while (xml.readNextStartElement()) {
        if (xml.name() == QLatin1String("arg")) {
            const QByteArray type = xml.attributes().value(QStringLiteral("type")).toString().toLatin1();
            if (!isSignal && xml.attributes().value(QStringLiteral("direction")) == QLatin1String("out"))
                member.out += type;
            else
                member.in += type;
        }
        xml.skipCurrentElement();
    }
    if (isSignal)
        out->signalSignatures.insert(name, member.in);
    else
        out->methods.insert(name, member);
}

XmlInterface parseInterface(const QByteArray &data, const QString &interfaceName)
{
    XmlInterface result;
    QXmlStreamReader xml(data);
    bool inside = false;
    while (!xml.atEnd()) {
        xml.readNext();
        if (xml.isEndElement() && xml.name() == QLatin1String("interface"))
            inside = false;
        if (!xml.isStartElement())
            continue;
        if (xml.name() == QLatin1String("interface"))
            inside = xml.attributes().value(QStringLiteral("name")) == interfaceName;
        else if (inside && (xml.name() == QLatin1String("method") || xml.name() == QLatin1String("signal")))
            readMember(xml, xml.name() == QLatin1String("signal"), &result);
    }
    return result;
}

QJsonValue substitute(const QJsonValue &value, const QHash<QString, QJsonValue> &vars)
{
    if (value.isString() && vars.contains(value.toString()))
        return vars.value(value.toString());
    if (value.isArray()) {
        QJsonArray out;
        for (const QJsonValue &v : value.toArray())
            out.append(substitute(v, vars));
        return out;
    }
    return value;
}

QJsonArray argsToJson(const QVariantList &args)
{
    QJsonArray out;
    for (const QVariant &v : args)
        out.append(toJson(v));
    return out;
}

} // namespace

class tst_Contract : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void contractCopyIsCurrent();
    void introspection();
    void methodTableMatchesXml();
    void goldenSequences_data();
    void goldenSequences();
};

void tst_Contract::contractCopyIsCurrent()
{
    // The XML the bridge serves (src) and the contract copy must not drift.
    QCOMPARE(readFile(ContractDir + QStringLiteral("/org.netvfs.Bridge1.xml")),
             readFile(QStringLiteral(NETVFS_SOURCE_DIR "/src/bridge/lib/org.netvfs.Bridge1.xml")));
}

void tst_Contract::introspection()
{
    Fixture f;
    auto c = f.client();
    const TestClient::Message reply = c->waitReply(c->send("Introspect", TestClient::Args(),
                                                           "org.freedesktop.DBus.Introspectable"));
    QVERIFY2(!reply.isError, qPrintable(reply.name));
    QCOMPARE(reply.args.value(0).toString().toUtf8(), readFile(ContractDir + QStringLiteral("/org.netvfs.Bridge1.xml")));
    // libdbus answers Peer.Ping itself.
    QVERIFY(!c->waitReply(c->send("Ping", TestClient::Args(), "org.freedesktop.DBus.Peer")).isError);
}

void tst_Contract::methodTableMatchesXml()
{
    const XmlInterface xml = parseInterface(readFile(ContractDir + QStringLiteral("/org.netvfs.Bridge1.xml")),
                                            QStringLiteral("org.netvfs.Bridge1"));
    QStringList implemented;
    for (const Bridge::MethodInfo &m : Bridge::methods()) {
        const QString name = QLatin1String(m.name);
        implemented << name;
        QVERIFY2(xml.methods.contains(name), qPrintable(name));
        QCOMPARE(xml.methods.value(name).in, QByteArray(m.in));
        QCOMPARE(xml.methods.value(name).out, QByteArray(m.out));
    }
    QStringList declared = xml.methods.keys();
    declared.sort();
    implemented.sort();
    QCOMPARE(implemented, declared);
    const QStringList expectedSignals = { "ConsentChanged", "JobFinished", "JobProgress", "ListBatch", "ListDone",
                                          "LocationsChanged", "NearbyChanged", "Question", "WalkBatch" };
    QCOMPARE(xml.signalSignatures.keys(), expectedSignals);
    QCOMPARE(xml.signalSignatures.value("ListBatch"), QByteArray("ua") + Bridge::Protocol::EntrySignature);
}

void tst_Contract::goldenSequences_data()
{
    QTest::addColumn<QString>("file");
    const QStringList files = QDir(ContractDir).entryList(QStringList(QStringLiteral("*.json")), QDir::Files, QDir::Name);
    QVERIFY(files.size() >= 6);
    for (const QString &name : files)
        QTest::newRow(qPrintable(name)) << ContractDir + QLatin1Char('/') + name;
}

void tst_Contract::goldenSequences()
{
    QFETCH(QString, file);
    QJsonParseError error;
    const QJsonObject script = QJsonDocument::fromJson(readFile(file), &error).object();
    QCOMPARE(error.error, QJsonParseError::NoError);
    const XmlInterface xml = parseInterface(readFile(ContractDir + QStringLiteral("/org.netvfs.Bridge1.xml")),
                                            QStringLiteral("org.netvfs.Bridge1"));

    const Consent consent = consentFromString(script.value(QStringLiteral("consent")).toString());
    Fixture f(consent);
    const QJsonObject files = script.value(QStringLiteral("files")).toObject();
    for (auto it = files.constBegin(); it != files.constEnd(); ++it)
        Test::FakeServer::instance()->addFile(it.key(), it.value().toString().toUtf8());
    auto c = f.client();

    QHash<QString, QJsonValue> vars;
    int index = 0;
    for (const QJsonValue &stepValue : script.value(QStringLiteral("steps")).toArray()) {
        const QJsonObject step = stepValue.toObject();
        const QString where = QStringLiteral("step %1").arg(index++);
        QString why;
        if (step.contains(QStringLiteral("signal"))) {
            const QString member = step.value(QStringLiteral("signal")).toString();
            const TestClient::Message m = c->waitSignal(member);
            QVERIFY2(m.valid, qPrintable(where + QStringLiteral(": no signal ") + member));
            QCOMPARE(m.signature, xml.signalSignatures.value(member));
            QVERIFY2(matchJson(step.value(QStringLiteral("args")), argsToJson(m.args), &vars, &why),
                     qPrintable(where + QStringLiteral(": ") + why + QStringLiteral(" in ")
                                + QString::fromUtf8(QJsonDocument(argsToJson(m.args)).toJson(QJsonDocument::Compact))));
            continue;
        }
        const QByteArray member = step.value(QStringLiteral("call")).toString().toLatin1();
        const QByteArray signature = step.value(QStringLiteral("sig")).toString().toLatin1();
        const QJsonArray args = substitute(step.value(QStringLiteral("args")), vars).toArray();
        const TestClient::Message m = c->call(member.constData(), [&](WireWriter &w) {
            const QList<QByteArray> types = splitSignature(signature);
            for (int i = 0; i < types.size(); ++i)
                writeJson(w, types.at(i), args.at(i));
        });
        QVERIFY2(m.valid, qPrintable(where + QStringLiteral(": no reply")));
        if (step.contains(QStringLiteral("error"))) {
            QVERIFY2(m.isError, qPrintable(where + QStringLiteral(": expected an error")));
            QCOMPARE(m.name, step.value(QStringLiteral("error")).toString());
            continue;
        }
        QVERIFY2(!m.isError, qPrintable(where + QStringLiteral(": ") + m.name + QLatin1Char(' ')
                                        + m.args.value(0).toString()));
        if (xml.methods.contains(QString::fromLatin1(member)))
            QCOMPARE(m.signature, xml.methods.value(QString::fromLatin1(member)).out);
        QVERIFY2(matchJson(step.value(QStringLiteral("reply")), argsToJson(m.args), &vars, &why),
                 qPrintable(where + QStringLiteral(": ") + why + QStringLiteral(" in ")
                            + QString::fromUtf8(QJsonDocument(argsToJson(m.args)).toJson(QJsonDocument::Compact))));
    }
}

QTEST_GUILESS_MAIN(tst_Contract)
#include "tst_contract.moc"
