// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_BRIDGETEST_H
#define NETVFS_TEST_BRIDGETEST_H

#include "bridgeserver.h"
#include "wireconnection.h"

#include <QtCore/QJsonValue>
#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtCore/QTemporaryDir>

#include <functional>
#include <memory>

// Test doubles and a libdbus client for the bridge tests (SPEC-v2 XT-7).
namespace NetVfs {
namespace BridgeTest {

using Bridge::WireWriter;

// A consumer client over the peer-to-peer socket, driven by the event loop of
// the test thread (the bridge runs in the same thread).
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
    // Sends a call; returns its serial (0 on failure).
    quint32 send(const char *member, const Args &args = Args(), const char *interface = nullptr);
    Message waitReply(quint32 serial, int timeoutMs = 5000);
    Message call(const char *member, const Args &args = Args(), int timeoutMs = 5000);
    // Next unconsumed signal `member` matching `accept`.
    Message waitSignal(const QString &member, const std::function<bool(const QVariantList &)> &accept = nullptr,
                       int timeoutMs = 5000);
    int signalCount(const QString &member) const;
    bool waitDisconnected(int timeoutMs = 5000);
    void close();
    // Hello with protocol 1.
    Message hello();

private:
    void onMessage(DBusMessage *message);

    Bridge::WireConnection *m_connection = nullptr;
    QHash<quint32, Message> m_replies;
    QList<Message> m_signals;
};

// Accounts with a Files service, without libaccounts.
class FakeAccounts : public Bridge::AccountDirectory
{
    Q_OBJECT
public:
    QVector<Bridge::AccountLocation> accounts;
    Result fetchResult;
    QList<QPair<int, Attention>> attention;
    int fetches = 0;

    QVector<Bridge::AccountLocation> filesAccounts() override { return accounts; }
    void fetch(int accountId, const Fetched &done) override;
    void setAttention(int accountId, Attention value, const QString &seenPin) override;
    void notifyChanged() { emit changed(); }

    // One account "account:1" on the in-memory FakeServer (provider "fake").
    static Bridge::AccountLocation fakeAccount(int id = 1);
};

class FakePrompt : public Bridge::ConsentPrompt
{
    Q_OBJECT
public:
    int shown = 0;
    bool visible = false;
    void show(const QString &) override
    {
        ++shown;
        visible = true;
    }
    void withdraw() override { visible = false; }
    bool isShown() const override { return visible; }
    void answer(bool allow)
    {
        visible = false;
        emit answered(allow);
    }
};

// A BridgeServer on a socket in a temporary folder, with fake accounts, a
// fake consent prompt and the fake backend plugin.
class Fixture
{
public:
    explicit Fixture(Consent consent = Consent::Granted, bool start = true);
    ~Fixture();

    QTemporaryDir dir;
    Bridge::BridgeConfig config;
    FakeAccounts *accounts = nullptr;     // owned by the server
    FakePrompt *prompt = nullptr;         // owned by the server
    std::unique_ptr<Bridge::BridgeServer> server;
    QString address;

    void setConsent(Consent consent);     // writes bridge.conf like netvfs-ui would
    void startServer();
    std::unique_ptr<TestClient> client();
    // Connected client after Hello.
    std::unique_ptr<TestClient> helloClient();
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
