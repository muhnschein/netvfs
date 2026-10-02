// SPDX-License-Identifier: LGPL-2.1-or-later
#include "bridgetest.h"

#include "fakebackend.h"
#include "protocol.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QElapsedTimer>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QTextCodec>

#include <dbus/dbus.h>

namespace NetVfs {
namespace BridgeTest {

namespace {

bool spin(const std::function<bool()> &done, int timeoutMs)
{
    QElapsedTimer timer;
    timer.start();
    while (!done()) {
        if (timer.elapsed() > timeoutMs)
            return false;
        QCoreApplication::processEvents(QEventLoop::AllEvents | QEventLoop::WaitForMoreEvents, 10);
    }
    return true;
}

} // namespace

// ------------------------------------------------------------- TestClient

TestClient::TestClient(const QString &address, QObject *parent)
    : QObject(parent)
{
    Result r;
    m_connection = Bridge::WireConnection::connectTo(address, &r, this);
    if (m_connection)
        m_connection->setHandler([this](DBusMessage *message) { onMessage(message); });
}

TestClient::~TestClient() = default;

bool TestClient::isConnected() const
{
    return m_connection && m_connection->isConnected();
}

void TestClient::onMessage(DBusMessage *raw)
{
    Message m;
    m.valid = true;
    m.signature = dbus_message_get_signature(raw);
    Bridge::decodeArguments(raw, &m.args);
    const int type = dbus_message_get_type(raw);
    if (type == DBUS_MESSAGE_TYPE_SIGNAL) {
        m.name = QString::fromUtf8(dbus_message_get_member(raw));
        m_signals.append(m);
        return;
    }
    if (type == DBUS_MESSAGE_TYPE_ERROR) {
        m.isError = true;
        m.name = QString::fromUtf8(dbus_message_get_error_name(raw));
    }
    m_replies.insert(dbus_message_get_reply_serial(raw), m);
}

quint32 TestClient::send(const char *member, const Args &args, const char *interface)
{
    if (!m_connection)
        return 0;
    Bridge::MessagePtr message(dbus_message_new_method_call(nullptr, Bridge::Protocol::ObjectPath,
                                                            interface ? interface : Bridge::Protocol::Interface, member));
    if (args) {
        WireWriter w(message.get());
        args(w);
        if (!w.ok())
            return 0;
    }
    return m_connection->send(std::move(message));
}

TestClient::Message TestClient::waitReply(quint32 serial, int timeoutMs)
{
    if (serial == 0)
        return Message();
    spin([this, serial]() { return m_replies.contains(serial) || !isConnected(); }, timeoutMs);
    return m_replies.take(serial);
}

TestClient::Message TestClient::call(const char *member, const Args &args, int timeoutMs)
{
    return waitReply(send(member, args), timeoutMs);
}

TestClient::Message TestClient::waitSignal(const QString &member, const std::function<bool(const QVariantList &)> &accept,
                                           int timeoutMs)
{
    Message found;
    spin([&]() {
        for (int i = 0; i < m_signals.size(); ++i) {
            if (m_signals.at(i).name == member && (!accept || accept(m_signals.at(i).args))) {
                found = m_signals.takeAt(i);
                return true;
            }
        }
        return false;
    }, timeoutMs);
    return found;
}

int TestClient::signalCount(const QString &member) const
{
    int n = 0;
    for (const Message &m : m_signals)
        n += m.name == member ? 1 : 0;
    return n;
}

bool TestClient::waitDisconnected(int timeoutMs)
{
    return spin([this]() { return !isConnected(); }, timeoutMs);
}

void TestClient::close()
{
    if (m_connection)
        m_connection->close();
}

TestClient::Message TestClient::hello()
{
    return call("Hello", [](WireWriter &w) { w.uint32(1).string(QStringLiteral("test")); });
}

// ----------------------------------------------------------- FakeAccounts

Bridge::AccountLocation FakeAccounts::fakeAccount(int id)
{
    Bridge::AccountLocation a;
    a.accountId = id;
    a.provider = QStringLiteral("fake");
    a.displayName = QStringLiteral("Fake %1").arg(id);
    a.params.provider = QStringLiteral("fake");
    a.params.host = QStringLiteral("fake.example");
    a.params.username = QStringLiteral("user");
    return a;
}

void FakeAccounts::fetch(int accountId, const Fetched &done)
{
    ++fetches;
    if (!fetchResult.ok()) {
        done(fetchResult, ConnectionParams(), Credentials());
        return;
    }
    for (const Bridge::AccountLocation &a : accounts) {
        if (a.accountId == accountId) {
            done(Result::success(), a.params, Credentials(QStringLiteral("user"), QByteArray("secret")));
            return;
        }
    }
    done(Result(Error::NotFound, QStringLiteral("no account")), ConnectionParams(), Credentials());
}

void FakeAccounts::setAttention(int accountId, Attention value, const QString &)
{
    attention.append(qMakePair(accountId, value));
}

// ---------------------------------------------------------------- Fixture

Fixture::Fixture(Consent consent, bool start)
{
    qputenv("NETVFS_BACKEND_PATH", NETVFS_TEST_FAKE_BACKEND_DIR);
    Test::FakeServer::instance()->reset();
    config.consumer.id = QStringLiteral("test");
    config.consumer.displayName = QStringLiteral("Test");
    config.consumer.executable = QCoreApplication::applicationFilePath();
    config.consumer.dataDir = QStringLiteral("data");
    config.listenAddress = QStringLiteral("unix:path=") + dir.path() + QStringLiteral("/bridge.sock");
    config.consentFile = dir.path() + QStringLiteral("/config/bridge.conf");
    config.knownHostsFile = dir.path() + QStringLiteral("/known_hosts");
    config.handoffConfig = dir.path() + QStringLiteral("/handoff.conf");
    config.idleExitMs = 300;
    accounts = new FakeAccounts;
    accounts->accounts << FakeAccounts::fakeAccount(1);
    prompt = new FakePrompt;
    config.accounts = accounts;
    config.prompt = prompt;
    setConsent(consent);
    if (start)
        startServer();
}

Fixture::~Fixture()
{
    server.reset();
}

void Fixture::setConsent(Consent consent)
{
    ConsentStore(config.consentFile).setConsent(config.consumer.id, consent);
}

void Fixture::startServer()
{
    server = std::make_unique<Bridge::BridgeServer>(config);
    if (server->start().ok())
        address = config.listenAddress;
}

std::unique_ptr<TestClient> Fixture::client()
{
    auto c = std::make_unique<TestClient>(address);
    return c;
}

std::unique_ptr<TestClient> Fixture::helloClient()
{
    auto c = client();
    c->hello();
    return c;
}

// ------------------------------------------------------------------- JSON

QList<QByteArray> splitSignature(const QByteArray &signature)
{
    QList<QByteArray> parts;
    int start = 0;
    int depth = 0;
    for (int i = 0; i < signature.size(); ++i) {
        const char c = signature.at(i);
        if (c == '(' || c == '{')
            ++depth;
        else if (c == ')' || c == '}')
            --depth;
        if (depth == 0 && c != 'a') {
            parts << signature.mid(start, i - start + 1);
            start = i + 1;
        }
    }
    return parts;
}

namespace {

bool bytesFromJson(const QJsonValue &value, QByteArray *out)
{
    const QJsonObject o = value.toObject();
    if (o.contains(QStringLiteral("bytes"))) {
        *out = o.value(QStringLiteral("bytes")).toString().toUtf8();
        return true;
    }
    if (o.contains(QStringLiteral("hex"))) {
        *out = QByteArray::fromHex(o.value(QStringLiteral("hex")).toString().toLatin1());
        return true;
    }
    return false;
}

QVariant variantFromJson(const QJsonValue &value)
{
    if (value.isBool())
        return value.toBool();
    if (value.isDouble())
        return qlonglong(value.toDouble());
    if (value.isString())
        return value.toString();
    if (value.isArray()) {
        QStringList strings;
        for (const QJsonValue &v : value.toArray())
            strings << v.toString();
        return strings;
    }
    QByteArray bytes;
    if (bytesFromJson(value, &bytes))
        return bytes;
    return QVariant();
}

bool writeBasic(WireWriter &w, char type, const QJsonValue &value)
{
    const qint64 n = static_cast<qint64>(value.toDouble());
    switch (type) {
    case 'y':
        w.byte(static_cast<quint8>(n));
        return true;
    case 'b':
        w.boolean(value.toBool());
        return true;
    case 'q':
        w.uint16(static_cast<quint16>(n));
        return true;
    case 'i':
        w.int32(static_cast<qint32>(n));
        return true;
    case 'u':
        w.uint32(static_cast<quint32>(n));
        return true;
    case 'x':
        w.int64(n);
        return true;
    case 's':
        w.string(value.toString());
        return true;
    default:
        return false;
    }
}

} // namespace

bool writeJson(WireWriter &w, const QByteArray &signature, const QJsonValue &value)
{
    if (signature == "ay") {
        QByteArray bytes;
        if (!bytesFromJson(value, &bytes))
            return false;
        w.bytes(bytes);
        return w.ok();
    }
    if (signature == "a{sv}") {
        QVariantMap map;
        const QJsonObject o = value.toObject();
        for (auto it = o.constBegin(); it != o.constEnd(); ++it)
            map.insert(it.key(), variantFromJson(it.value()));
        w.variantMap(map);
        return w.ok();
    }
    if (signature.startsWith('a')) {
        const QByteArray element = signature.mid(1);
        w.openArray(element.constData());
        for (const QJsonValue &item : value.toArray())
            writeJson(w, element, item);
        w.close();
        return w.ok();
    }
    if (signature.startsWith('(')) {
        const QList<QByteArray> fields = splitSignature(signature.mid(1, signature.size() - 2));
        const QJsonArray items = value.toArray();
        w.openStruct();
        for (int i = 0; i < fields.size(); ++i)
            writeJson(w, fields.at(i), items.at(i));
        w.close();
        return w.ok();
    }
    return signature.size() == 1 && writeBasic(w, signature.at(0), value) && w.ok();
}

QJsonValue toJson(const QVariant &value)
{
    switch (value.userType()) {
    case QMetaType::QByteArray: {
        const QByteArray bytes = value.toByteArray();
        QTextCodec::ConverterState state;
        const QString text = QTextCodec::codecForName("UTF-8")->toUnicode(bytes.constData(), bytes.size(), &state);
        QJsonObject o;
        if (state.invalidChars == 0)
            o.insert(QStringLiteral("bytes"), text);
        else
            o.insert(QStringLiteral("hex"), QString::fromLatin1(bytes.toHex()));
        return o;
    }
    case QMetaType::QVariantList: {
        QJsonArray a;
        for (const QVariant &v : value.toList())
            a.append(toJson(v));
        return a;
    }
    case QMetaType::QStringList:
        return QJsonArray::fromStringList(value.toStringList());
    case QMetaType::QVariantMap: {
        QJsonObject o;
        const QVariantMap map = value.toMap();
        for (auto it = map.constBegin(); it != map.constEnd(); ++it)
            o.insert(it.key(), toJson(it.value()));
        return o;
    }
    case QMetaType::Bool:
        return value.toBool();
    case QMetaType::QString:
        return value.toString();
    default:
        return QJsonValue(static_cast<double>(value.toLongLong()));
    }
}

bool matchJson(const QJsonValue &expected, const QJsonValue &actual, QHash<QString, QJsonValue> *vars, QString *why)
{
    if (expected.isString()) {
        const QString e = expected.toString();
        if (e == QLatin1String("*"))
            return true;
        if (e.startsWith(QLatin1Char('$'))) {
            if (!vars->contains(e)) {
                vars->insert(e, actual);
                return true;
            }
            if (vars->value(e) == actual)
                return true;
            *why = QStringLiteral("%1 is %2").arg(e, QString::number(actual.toDouble()));
            return false;
        }
    }
    if (expected.isObject() && actual.isObject()) {
        const QJsonObject e = expected.toObject();
        const QJsonObject a = actual.toObject();
        for (auto it = e.constBegin(); it != e.constEnd(); ++it) {
            if (!a.contains(it.key())) {
                *why = QStringLiteral("missing key %1").arg(it.key());
                return false;
            }
            if (!matchJson(it.value(), a.value(it.key()), vars, why))
                return false;
        }
        return true;
    }
    if (expected.isArray() && actual.isArray()) {
        QJsonArray e = expected.toArray();
        const QJsonArray a = actual.toArray();
        const bool prefix = !e.isEmpty() && e.last() == QJsonValue(QStringLiteral("..."));
        if (prefix)
            e.removeLast();
        if (prefix ? a.size() < e.size() : a.size() != e.size()) {
            *why = QStringLiteral("array of %1 instead of %2").arg(a.size()).arg(e.size());
            return false;
        }
        for (int i = 0; i < e.size(); ++i) {
            if (!matchJson(e.at(i), a.at(i), vars, why))
                return false;
        }
        return true;
    }
    if (expected == actual)
        return true;
    *why = QStringLiteral("value differs");
    return false;
}

} // namespace BridgeTest
} // namespace NetVfs
