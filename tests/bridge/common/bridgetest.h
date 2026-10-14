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

// The black-box tests of the netvfs-bridge binary (SPEC-v2 XT-7, design
// §4.3): a libdbus client, the bridge as a process of its own, and the JSON
// mapping of the contract's golden sequences.
namespace NetVfs {
namespace BridgeTest {

extern const char ObjectPath[];   // XB-8: /org/netvfs/Bridge
extern const char Interface[];    // org.netvfs.Bridge1

// A consumer client over the peer-to-peer socket, driven by the event loop of
// the test thread.
class TestClient : public QObject
{
    Q_OBJECT
public:
    struct Message {
        bool isError = false;
        QString name;                 // error name or signal member
        QByteArray signature;
        QVariantList args;
        bool valid = false;
    };
    using Args = std::function<void(WireWriter &w)>;

    explicit TestClient(const QString &address, QObject *parent = nullptr);
    ~TestClient() override;

    bool isConnected() const;
    bool canPassUnixFds() const;
    // Sends a call; returns its serial (0 on failure).
    quint32 send(const char *member, const Args &args = Args(), const char *interface = nullptr,
                 const char *path = nullptr);
    Message waitReply(quint32 serial, int timeoutMs = 5000);
    Message call(const char *member, const Args &args = Args(), int timeoutMs = 5000);
    // Next unconsumed signal `member` matching `accept`.
    Message waitSignal(const QString &member, const std::function<bool(const QVariantList &)> &accept = nullptr,
                       int timeoutMs = 5000);
    int signalCount(const QString &member) const;
    bool waitDisconnected(int timeoutMs = 5000);
    void close();
    // Hello from client "test".
    Message hello();

private:
    void onMessage(DBusMessage *message);

    WireConnection *m_connection = nullptr;
    QHash<quint32, Message> m_replies;
    QList<Message> m_signals;
};

// The build tree's netvfs-bridge (rust/netvfs-bridge) and how it runs there:
// its C ABI (libnetvfs-bridge-ffi.so) and the fake backend plugin of the
// build, and under SANITIZE=1 gcc's sanitizer runtimes loaded first.
QString bridgeBinary();
QProcessEnvironment bridgeEnvironment();

// The bridge serving consumer "test", whose executable is this test, on
// `--listen unix:path=<folder>/bridge.sock`, with everything else in that
// temporary folder too: the consumer file, home, bridge.conf with `consent`
// ("granted", "denied", or "unknown" for none), and as accounts helper a
// script that answers with bytes this class wrote in the helper's format
// (XB-2a): one account, "account:1" (provider "fake", "Fake 1", host
// fake.example, user "user", no stored secret, which may be missing). The
// FakeServer behind it gets the files of addFile() and that user with an
// empty secret through NETVFS_FAKE_SEED (design §4.1). The bridge ends with
// its idle exit once no client is left (NETVFS_BRIDGE_IDLE_EXIT_MS).
class BridgeProcess
{
public:
    explicit BridgeProcess(const QString &consent = QStringLiteral("granted"));
    ~BridgeProcess();
    BridgeProcess(const BridgeProcess &) = delete;
    BridgeProcess &operator=(const BridgeProcess &) = delete;

    void addFile(const QByteArray &path, const QByteArray &content);   // before start()
    // Starts the bridge and waits for its socket; false when it did not come.
    bool start();
    QString address() const;
    std::unique_ptr<TestClient> client() const;
    // Waits for the bridge to exit (after the clients have gone, the idle
    // exit); its exit code, or -1 when it had to be killed.
    int waitExit(int timeoutMs = 10000);

private:
    bool writeFiles() const;
    bool writeAccountsHelper() const;

    QTemporaryDir m_dir;
    QString m_consent;
    QByteArray m_seed;
    QProcess m_process;
};

// ------------------------------------------------- JSON <-> D-Bus (contract)

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
// Splits a signature into complete types ("saya{sv}" -> s, ay, a{sv}).
QList<QByteArray> splitSignature(const QByteArray &signature);

} // namespace BridgeTest
} // namespace NetVfs

#endif
