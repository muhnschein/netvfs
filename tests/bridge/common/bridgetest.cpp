// SPDX-License-Identifier: LGPL-2.1-or-later
#include "bridgetest.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDataStream>
#include <QtCore/QDir>
#include <QtCore/QElapsedTimer>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QTextCodec>

#include <dbus/dbus.h>

namespace NetVfs {
namespace BridgeTest {

const char ObjectPath[] = "/org/netvfs/Bridge";
const char Interface[] = "org.netvfs.Bridge1";

namespace {

// The consumer the bridge serves and the time it stays without a client.
const char ConsumerId[] = "test";
const char IdleExitMs[] = "2000";

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

bool writeFile(const QString &path, const QByteArray &content)
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    return f.open(QIODevice::WriteOnly | QIODevice::Truncate) && f.write(content) == content.size();
}

// An answer of netvfs-accounts (XB-2a) that reports success: QDataStream
// Qt_5_6, error 0 and a null message, then `payload`.
QByteArray helperAnswer(const std::function<void(QDataStream &)> &payload = nullptr)
{
    QByteArray bytes;
    QDataStream stream(&bytes, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_5_6);
    stream << qint32(0) << QString();
    if (payload)
        payload(stream);
    return bytes;
}

// The connection parameters of account 1: provider, host, port, user name,
// options, connect and request timeout.
void writeAccountParams(QDataStream &stream)
{
    stream << QStringLiteral("fake") << QStringLiteral("fake.example") << qint32(0) << QStringLiteral("user")
           << QVariantMap() << qint32(0) << qint32(0);
}

} // namespace

// ------------------------------------------------------------- TestClient

TestClient::TestClient(const QString &address, QObject *parent)
    : QObject(parent)
{
    Result r;
    m_connection = WireConnection::connectTo(address, &r, this);
    if (m_connection)
        m_connection->setHandler([this](DBusMessage *message) { onMessage(message); });
}

TestClient::~TestClient() = default;

bool TestClient::isConnected() const
{
    return m_connection && m_connection->isConnected();
}

bool TestClient::canPassUnixFds() const
{
    return m_connection && m_connection->canPassUnixFds();
}

void TestClient::onMessage(DBusMessage *raw)
{
    Message m;
    m.valid = true;
    m.signature = dbus_message_get_signature(raw);
    decodeArguments(raw, &m.args);
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

quint32 TestClient::send(const char *member, const Args &args, const char *interface, const char *path)
{
    if (!m_connection)
        return 0;
    MessagePtr message(dbus_message_new_method_call(nullptr, path ? path : ObjectPath,
                                                    interface ? interface : Interface, member));
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
    return call("Hello", [](WireWriter &w) { w.string(QStringLiteral("test")); });
}

// ---------------------------------------------------------- the binary

QString bridgeBinary()
{
    return QStringLiteral(NETVFS_TEST_LIBEXEC_DIR "/netvfs-bridge");
}

QProcessEnvironment bridgeEnvironment()
{
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("NETVFS_BRIDGE_FFI"), QStringLiteral(NETVFS_TEST_BRIDGE_FFI));
    env.insert(QStringLiteral("NETVFS_BACKEND_PATH"), QStringLiteral(NETVFS_TEST_FAKE_BACKEND_DIR));
#ifdef NETVFS_TEST_BRIDGE_PRELOAD
    env.insert(QStringLiteral("LD_PRELOAD"), QStringLiteral(NETVFS_TEST_BRIDGE_PRELOAD));
#endif
    // Not socket-activated, and no session bus: no consent notification, no
    // account change signals.
    env.remove(QStringLiteral("LISTEN_PID"));
    env.remove(QStringLiteral("LISTEN_FDS"));
    env.remove(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"));
    return env;
}

// --------------------------------------------------------- BridgeProcess

BridgeProcess::BridgeProcess(const QString &consent)
    : m_consent(consent)
{
    m_process.setProcessChannelMode(QProcess::ForwardedChannels);
}

BridgeProcess::~BridgeProcess()
{
    if (m_process.state() != QProcess::NotRunning)
        waitExit();
}

void BridgeProcess::addFile(const QByteArray &path, const QByteArray &content)
{
    m_seed += "file " + ('/' + path).toHex() + ' ' + content.toHex() + '\n';
}

bool BridgeProcess::writeAccountsHelper() const
{
    const QString folder = m_dir.filePath(QStringLiteral("helper"));
    const QString script = folder + QStringLiteral("/netvfs-accounts");
    return writeFile(folder + QStringLiteral("/list"), helperAnswer([](QDataStream &s) {
               // One account: id, provider, display name, the parameters,
               // files root, attention.
               s << qint32(1) << qint32(1) << QStringLiteral("fake") << QStringLiteral("Fake 1");
               writeAccountParams(s);
               s << QStringLiteral("") << qint32(0);
           }))
        // XA-7: credentials id 0 with an optional secret, so no signond.
        && writeFile(folder + QStringLiteral("/files-1"), helperAnswer([](QDataStream &s) {
               writeAccountParams(s);
               s << quint32(0) << true;
           }))
        && writeFile(folder + QStringLiteral("/status"), helperAnswer())
        && writeFile(script, "#!/bin/sh\n"
                             "cd \"$(dirname \"$0\")\" || exit 1\n"
                             "case \"$1\" in\n"
                             "list) exec cat list ;;\n"
                             "files) exec cat \"files-$2\" ;;\n"
                             "*) exec cat status ;;\n"
                             "esac\n")
        && QFile::setPermissions(script, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
}

bool BridgeProcess::writeFiles() const
{
    const QByteArray id = ConsumerId;
    const QByteArray executable = QFile::encodeName(QCoreApplication::applicationFilePath());
    QByteArray consent = "[Consent]\n";
    if (m_consent != QLatin1String("unknown"))
        consent += id + '=' + m_consent.toUtf8() + '\n';
    return m_dir.isValid()
        && writeFile(m_dir.filePath(QStringLiteral("consumers/%1.conf").arg(QLatin1String(ConsumerId))),
                     "[Consumer]\nId=" + id + "\nDisplayName=Test\nExecutable=" + executable
                         + "\nDataDir=.local/share/" + id + '\n')
        && writeFile(m_dir.filePath(QStringLiteral("config/netvfs/bridge.conf")), consent)
        && QDir().mkpath(m_dir.filePath(QStringLiteral("home")))
        && writeAccountsHelper()
        // The account's user, with no secret (see writeAccountsHelper).
        && writeFile(m_dir.filePath(QStringLiteral("seed")), m_seed + "credentials user\n");
}

bool BridgeProcess::start()
{
    if (!writeFiles())
        return false;
    QProcessEnvironment env = bridgeEnvironment();
    env.insert(QStringLiteral("HOME"), m_dir.filePath(QStringLiteral("home")));
    env.insert(QStringLiteral("XDG_CONFIG_HOME"), m_dir.filePath(QStringLiteral("config")));
    env.insert(QStringLiteral("XDG_DATA_HOME"), m_dir.filePath(QStringLiteral("data")));
    env.insert(QStringLiteral("NETVFS_CONSUMERS_DIR"), m_dir.filePath(QStringLiteral("consumers")));
    env.insert(QStringLiteral("NETVFS_ACCOUNTS_HELPER"), m_dir.filePath(QStringLiteral("helper/netvfs-accounts")));
    env.insert(QStringLiteral("NETVFS_FAKE_SEED"), m_dir.filePath(QStringLiteral("seed")));
    env.insert(QStringLiteral("NETVFS_BRIDGE_IDLE_EXIT_MS"), QLatin1String(IdleExitMs));
    m_process.setProcessEnvironment(env);
    m_process.start(bridgeBinary(), { QStringLiteral("--listen"), address(), QLatin1String(ConsumerId) });
    if (!m_process.waitForStarted(10000))
        return false;
    const QString socket = m_dir.filePath(QStringLiteral("bridge.sock"));
    return spin([&]() { return QFileInfo::exists(socket) || m_process.state() == QProcess::NotRunning; }, 10000)
        && m_process.state() == QProcess::Running;
}

QString BridgeProcess::address() const
{
    return QStringLiteral("unix:path=") + m_dir.filePath(QStringLiteral("bridge.sock"));
}

std::unique_ptr<TestClient> BridgeProcess::client() const
{
    return std::make_unique<TestClient>(address());
}

int BridgeProcess::waitExit(int timeoutMs)
{
    if (m_process.state() != QProcess::NotRunning && !m_process.waitForFinished(timeoutMs)) {
        m_process.kill();
        m_process.waitForFinished();
        return -1;
    }
    return m_process.exitStatus() == QProcess::NormalExit ? m_process.exitCode() : -1;
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
