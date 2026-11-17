// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_BRIDGETEST_H
#define NETVFS_TEST_BRIDGETEST_H

#include "wireconnection.h"

#include <QtCore/QHash>
#include <QtCore/QJsonValue>
#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtCore/QProcess>
#include <QtCore/QTemporaryDir>

#include <functional>
#include <memory>

// Black-box tests of the netvfs-bridge binary: a libdbus client, the bridge as its own process, and the
// JSON mapping of the contract's golden sequences.
namespace NetVfs {
namespace BridgeTest {

extern const char ObjectPath[];
extern const char Interface[];

class TestClient : public QObject
{
    Q_OBJECT
public:
    struct Message {
        bool isError = false;
        QString name;
        QByteArray signature;
        QVariantList args;
        bool valid = false;
    };
    using Args = std::function<void(WireWriter &w)>;

    explicit TestClient(const QString &address, QObject *parent = nullptr);
    ~TestClient() override;

    bool isConnected() const;
    bool canPassUnixFds() const;
    quint32 send(const char *member, const Args &args = Args(), const char *interface = nullptr,
                 const char *path = nullptr);
    Message waitReply(quint32 serial, int timeoutMs = 5000);
    Message call(const char *member, const Args &args = Args(), int timeoutMs = 5000);
    Message waitSignal(const QString &member, const std::function<bool(const QVariantList &)> &accept = nullptr,
                       int timeoutMs = 5000);
    int signalCount(const QString &member) const;
    bool waitDisconnected(int timeoutMs = 5000);
    void close();
    Message hello();

private:
    void onMessage(DBusMessage *message);

    WireConnection *m_connection = nullptr;
    QHash<quint32, Message> m_replies;
    QList<Message> m_signals;
};

// The build tree's netvfs-bridge and how it runs there: its C ABI, the fake backend plugin, and under
// SANITIZE=1 gcc's sanitizer runtimes loaded first.
QString bridgeBinary();
QProcessEnvironment bridgeEnvironment();

// The bridge serving consumer "test" (executable: this test) on `--listen unix:path=<folder>/bridge.sock`,
// with everything else in that temp folder: consumer file, home, bridge.conf with `consent` ("granted",
// "denied", or "unknown" for none), and as accounts helper a script answering with bytes this class wrote
// in the helper's format: one account "account:1" (provider "fake", "Fake 1", host fake.example, user
// "user", no stored secret, which may be missing). The FakeServer behind it gets addFile() files and that
// user with an empty secret via NETVFS_FAKE_SEED. The bridge ends with its idle exit once no client is left
// (NETVFS_BRIDGE_IDLE_EXIT_MS).
class BridgeProcess
{
public:
    explicit BridgeProcess(const QString &consent = QStringLiteral("granted"));
    ~BridgeProcess();
    BridgeProcess(const BridgeProcess &) = delete;
    BridgeProcess &operator=(const BridgeProcess &) = delete;

    void addFile(const QByteArray &path, const QByteArray &content);   // before start()
    bool start();
    QString address() const;
    std::unique_ptr<TestClient> client() const;
    int waitExit(int timeoutMs = 10000);

private:
    bool writeFiles() const;
    bool writeAccountsHelper() const;

    QTemporaryDir m_dir;
    QString m_consent;
    QByteArray m_seed;
    QProcess m_process;
};


// Writes `value` as D-Bus type `signature` (one complete type). JSON mapping:
// numbers for y q u i x t, true/false for b, strings for s, {"bytes": "text"}
// or {"hex": "00ff"} for ay, arrays for arrays and structs, objects for a{sv}
// (values: integer -> x, boolean -> b, string -> s, {"bytes"/"hex"} -> ay,
// array of strings -> as).
bool writeJson(WireWriter &writer, const QByteArray &signature, const QJsonValue &value);
// Decoded arguments as JSON (byte arrays as {"bytes": ...} when valid UTF-8,
// else {"hex": ...}).
QJsonValue toJson(const QVariant &value);
// Expected-vs-actual: "*" matches anything, "$name" binds a variable on first
// use and must be equal afterwards, objects match the listed keys only, an
// array whose last element is "..." matches a prefix.
bool matchJson(const QJsonValue &expected, const QJsonValue &actual, QHash<QString, QJsonValue> *vars,
               QString *why);
QList<QByteArray> splitSignature(const QByteArray &signature);

} // namespace BridgeTest
} // namespace NetVfs

#endif
