// SPDX-License-Identifier: LGPL-2.1-or-later
// The bridge protocol contract, shared with the consumer's
// fake bridge: the introspection XML in this folder and the golden message
// sequences (*.json, format in README.md) replayed against the netvfs-bridge
// binary with the FakeBackend (provider "fake", account "account:1"). The
// client is libdbus, the bridge zbus: these cases also show
// that the two agree on authentication, fd passing and error replies.
#include "bridgetest.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QTemporaryFile>
#include <QtCore/QXmlStreamReader>
#include <QtTest/QtTest>

#include <fcntl.h>
#include <unistd.h>

using namespace NetVfs;
using namespace NetVfs::BridgeTest;

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
    void introspection();
    void signalsOfTheXml();
    void unixFdPassing();
    void errorDetails();
    void goldenSequences_data();
    void goldenSequences();
};

void tst_Contract::introspection()
{
    BridgeProcess f;
    QVERIFY(f.start());
    auto c = f.client();
    QVERIFY(c->isConnected());
    const TestClient::Message reply = c->waitReply(c->send("Introspect", TestClient::Args(),
                                                           "org.freedesktop.DBus.Introspectable"));
    QVERIFY2(reply.valid && !reply.isError, qPrintable(reply.name));
    QCOMPARE(reply.args.value(0).toString().toUtf8(), readFile(ContractDir + QStringLiteral("/org.netvfs.Bridge1.xml")));
    const TestClient::Message ping = c->waitReply(c->send("Ping", TestClient::Args(), "org.freedesktop.DBus.Peer"));
    QVERIFY(ping.valid && !ping.isError);
    // Nothing else lives on the connection.
    const TestClient::Message other = c->waitReply(c->send("Introspect", TestClient::Args(),
                                                           "org.freedesktop.DBus.Introspectable", "/org/other"));
    QVERIFY(other.isError);
    QCOMPARE(other.name, QStringLiteral("org.freedesktop.DBus.Error.UnknownMethod"));
    c->close();
    QCOMPARE(f.waitExit(), 0);
}

void tst_Contract::signalsOfTheXml()
{
    const XmlInterface xml = parseInterface(readFile(ContractDir + QStringLiteral("/org.netvfs.Bridge1.xml")),
                                            QStringLiteral("org.netvfs.Bridge1"));
    const QStringList expectedSignals = { "ConsentChanged", "DrivesChanged", "JobFinished", "JobProgress",
                                          "ListBatch", "ListDone", "LocationsChanged", "NearbyChanged",
                                          "Question", "WalkBatch" };
    QCOMPARE(xml.signalSignatures.keys(), expectedSignals);
    QCOMPARE(xml.signalSignatures.value("ListBatch"), QByteArray("ua(ayyyxxxxixxssqays)"));
}

void tst_Contract::unixFdPassing()
{
    // Upload and Download take an fd the consumer opened; libdbus
    // sends it, the bridge's zbus must have negotiated fd passing.
    BridgeProcess f;
    QVERIFY(f.start());
    auto c = f.client();
    QVERIFY(c->hello().valid);
    QVERIFY(c->canPassUnixFds());
    QTemporaryFile source;
    QVERIFY(source.open());
    const QByteArray content = QByteArray("through a descriptor\n").repeated(1000);
    QCOMPARE(source.write(content), qint64(content.size()));
    QVERIFY(source.flush());
    const int readFd = ::open(QFile::encodeName(source.fileName()).constData(), O_RDONLY | O_CLOEXEC);
    QVERIFY(readFd >= 0);
    const TestClient::Message upload = c->call("Upload", [&](WireWriter &w) {
        w.string(QStringLiteral("account:1")).bytes("/uploaded.txt").unixFd(readFd).variantMap(QVariantMap());
    });
    ::close(readFd);
    QVERIFY2(upload.valid && !upload.isError, qPrintable(upload.name + QLatin1Char(' ') + upload.args.value(0).toString()));
    const uint uploadJob = upload.args.value(0).toUInt();
    const TestClient::Message uploaded = c->waitSignal(QStringLiteral("JobFinished"), [&](const QVariantList &args) {
        return args.value(0).toUInt() == uploadJob;
    }, 10000);
    QVERIFY(uploaded.valid);
    QVERIFY2(uploaded.args.value(1).toString().isEmpty(), qPrintable(uploaded.args.value(2).toString()));

    QTemporaryFile target;
    QVERIFY(target.open());
    const int writeFd = ::open(QFile::encodeName(target.fileName()).constData(), O_WRONLY | O_CLOEXEC);
    QVERIFY(writeFd >= 0);
    const TestClient::Message download = c->call("Download", [&](WireWriter &w) {
        w.string(QStringLiteral("account:1")).bytes("/uploaded.txt").unixFd(writeFd).variantMap(QVariantMap());
    });
    ::close(writeFd);
    QVERIFY2(download.valid && !download.isError, qPrintable(download.name));
    const uint downloadJob = download.args.value(0).toUInt();
    const TestClient::Message downloaded = c->waitSignal(QStringLiteral("JobFinished"), [&](const QVariantList &args) {
        return args.value(0).toUInt() == downloadJob;
    }, 10000);
    QVERIFY(downloaded.valid);
    QVERIFY2(downloaded.args.value(1).toString().isEmpty(), qPrintable(downloaded.args.value(2).toString()));
    QCOMPARE(target.readAll(), content);
    c->close();
    QCOMPARE(f.waitExit(), 0);
}

void tst_Contract::errorDetails()
{
    // an error reply carries the message and an a{sv} with
    // retryAfterMs, as libdbus decodes it.
    BridgeProcess f;
    f.addFile("f.txt", "12345");
    QVERIFY(f.start());
    auto c = f.client();
    QVERIFY(c->hello().valid);
    const auto openRead = [&c]() {
        return c->call("OpenRead", [](WireWriter &w) {
            w.string(QStringLiteral("account:1")).bytes("/f.txt").string(QStringLiteral("stream"));
        });
    };
    for (int i = 0; i < 16; ++i) {
        const TestClient::Message opened = openRead();
        QVERIFY2(opened.valid && !opened.isError, qPrintable(opened.name));
        QCOMPARE(opened.signature, QByteArray("ux"));
    }
    const TestClient::Message refused = openRead();
    QVERIFY(refused.isError);
    QCOMPARE(refused.name, QStringLiteral("org.netvfs.Error.TooManyConnections"));
    QCOMPARE(refused.signature, QByteArray("sa{sv}"));
    QVERIFY(!refused.args.value(0).toString().isEmpty());
    QCOMPARE(refused.args.value(1).toMap().value(QStringLiteral("retryAfterMs")).toLongLong(), 1000);
    c->close();
    QCOMPARE(f.waitExit(), 0);
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

    BridgeProcess f(script.value(QStringLiteral("consent")).toString());
    const QJsonObject files = script.value(QStringLiteral("files")).toObject();
    for (auto it = files.constBegin(); it != files.constEnd(); ++it)
        f.addFile(it.key().toUtf8(), it.value().toString().toUtf8());
    QVERIFY(f.start());
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
    c->close();
    QCOMPARE(f.waitExit(), 0);
}

QTEST_GUILESS_MAIN(tst_Contract)
#include "tst_contract.moc"
