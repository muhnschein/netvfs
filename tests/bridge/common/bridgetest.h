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

QString bridgeBinary();
QProcessEnvironment bridgeEnvironment();

class BridgeProcess
{
public:
    explicit BridgeProcess(const QString &consent = QStringLiteral("full"));
    ~BridgeProcess();
    BridgeProcess(const BridgeProcess &) = delete;
    BridgeProcess &operator=(const BridgeProcess &) = delete;

    void addFile(const QByteArray &path, const QByteArray &content);
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

bool writeJson(WireWriter &writer, const QByteArray &signature, const QJsonValue &value);
QJsonValue toJson(const QVariant &value);
bool matchJson(const QJsonValue &expected, const QJsonValue &actual, QHash<QString, QJsonValue> *vars,
               QString *why);
QList<QByteArray> splitSignature(const QByteArray &signature);

}
}

#endif
