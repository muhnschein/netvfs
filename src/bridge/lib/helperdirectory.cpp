// SPDX-License-Identifier: LGPL-2.1-or-later
// The bridge's side of netvfs-accounts (XB-2a); the protocol is in
// accountshelper.cpp, which the helper links without this file.
#include "accountshelper.h"

#include "bridgelog.h"
#include "secretsource.h"

#include <QtCore/QPointer>
#include <QtCore/QProcess>
#include <QtCore/QTimer>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>

namespace NetVfs::Bridge {

namespace {

constexpr int HelperTimeoutMs = 10000;
constexpr qint64 MaxAnswerBytes = 1 << 20;
// Writers send several signals for one change; one refresh for all of them.
constexpr int ChangedDelayMs = 200;

// libaccounts-glib (ag-internals.h): the signal every writer sends on the
// session bus, on one object path per service type.
const char AccountsInterface[] = "com.google.code.AccountsSSO.Accounts";
const char AccountChangedSignal[] = "AccountChanged";
const char EndedProperty[] = "netvfsEnded";

Result helperFailed(const QProcess &process)
{
    if (process.error() == QProcess::FailedToStart)
        return Result(Error::Unsupported, QStringLiteral("Cannot start %1: %2").arg(process.program(),
                                                                                     process.errorString()));
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
        return Result(Error::ProtocolError, QStringLiteral("%1 failed").arg(process.program()));
    return Result::success();
}

void configure(QProcess &process, const QString &program, const QStringList &arguments)
{
    // The helper's warnings go to the bridge's journal.
    process.setProcessChannelMode(QProcess::ForwardedErrorChannel);
    process.setProgram(program);
    process.setArguments(arguments);
}

// Ends a run of the helper started by start(): hands `finished` the result
// once, whichever of the process's signals comes first, and deletes the
// process from the event loop (this runs from one of its own signals).
template <typename Callback>
void endRun(QProcess *process, const Result &result, const Callback &finished)
{
    if (process->property(EndedProperty).toBool())
        return;
    process->setProperty(EndedProperty, true);
    const QByteArray answer = result.ok() ? process->read(MaxAnswerBytes) : QByteArray();
    process->deleteLater();
    finished(result, answer);
}

// signond, from the bridge itself (SPEC C-2, A-6, XA-7).
void fetchSecret(QObject *owner, const FilesAccess &access, const AccountDirectory::Fetched &done)
{
    auto *secrets = new SignonSecretSource(owner);
    secrets->setSecretOptional(access.secretOptional);
    QObject::connect(secrets, &SecretSource::fetched, owner, [secrets, access, done](const Credentials &fetched) {
        Credentials credentials = fetched;
        if (credentials.userName.isEmpty())
            credentials.userName = access.params.username;
        secrets->deleteLater();
        done(Result::success(), access.params, credentials);
        credentials.wipe();   // SEC-5: the connection keeps no copy beyond establish
    });
    QObject::connect(secrets, &SecretSource::failed, owner, [secrets, done](const Result &result) {
        secrets->deleteLater();
        done(result, ConnectionParams(), Credentials());
    });
    secrets->fetch(access.credentialsId);
}

} // namespace

HelperAccountsDirectory::HelperAccountsDirectory(const QString &program, QObject *parent)
    : AccountDirectory(parent)
    , m_program(program)
    , m_changed(new QTimer(this))
{
    m_changed->setSingleShot(true);
    m_changed->setInterval(ChangedDelayMs);
    connect(m_changed, &QTimer::timeout, this, &AccountDirectory::changed);
    // Any object path: libaccounts sends the signal on the path of each
    // service type it concerns.
    if (!QDBusConnection::sessionBus().connect(QString(), QString(), QLatin1String(AccountsInterface),
                                               QLatin1String(AccountChangedSignal), this,
                                               SLOT(onAccountChanged(QDBusMessage))))
        qCWarning(lcNetVfsBridge) << "No session bus: account changes are seen only after a restart";
}

HelperAccountsDirectory::~HelperAccountsDirectory() = default;

void HelperAccountsDirectory::onAccountChanged(const QDBusMessage &)
{
    if (!m_changed->isActive())
        m_changed->start();
}

QVector<AccountLocation> HelperAccountsDirectory::filesAccounts()
{
    // Synchronous, like the listing it replaces: at start and after a change.
    QProcess process;
    configure(process, m_program, { QStringLiteral("list") });
    process.start(QIODevice::ReadOnly);
    Result r;
    if (!process.waitForFinished(HelperTimeoutMs)) {
        r = process.error() == QProcess::FailedToStart
            ? helperFailed(process)
            : Result(Error::Timeout, QStringLiteral("%1 did not answer in time").arg(m_program));
        process.kill();
        process.waitForFinished();
    } else {
        r = helperFailed(process);
    }
    QVector<AccountLocation> accounts;
    if (r.ok())
        r = AccountsHelper::decodeList(process.read(MaxAnswerBytes), &accounts);
    if (!r.ok())
        qCWarning(lcNetVfsBridge).noquote() << "Cannot list the accounts, none is listed:" << r.toString();
    return accounts;
}

void HelperAccountsDirectory::start(const QStringList &arguments, const Finished &finished)
{
    auto *process = new QProcess(this);
    configure(*process, m_program, arguments);
    connect(process, &QProcess::errorOccurred, this, [process, finished](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart)
            endRun(process, helperFailed(*process), finished);
    });
    connect(process, static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished), this,
            [process, finished]() { endRun(process, helperFailed(*process), finished); });
    QTimer::singleShot(HelperTimeoutMs, process, [process, finished]() {
        process->kill();
        endRun(process, Result(Error::Timeout, QStringLiteral("%1 did not answer in time").arg(process->program())),
               finished);
    });
    process->start(QIODevice::ReadOnly);
}

void HelperAccountsDirectory::fetch(int accountId, const Fetched &done)
{
    QPointer<HelperAccountsDirectory> self(this);
    start({ QStringLiteral("files"), QString::number(accountId) },
          [self, accountId, done](const Result &started, const QByteArray &answer) {
              FilesAccess access;
              if (const Result r = started.ok() ? AccountsHelper::decodeFiles(answer, &access) : started;
                      !r.ok() || !self) {
                  qCDebug(lcNetVfsBridge) << "Account" << accountId << "for Files:" << r.toString();
                  done(r.ok() ? Result(Error::Canceled) : r, ConnectionParams(), Credentials());
                  return;
              }
              fetchSecret(self, access, done);
          });
}

void HelperAccountsDirectory::setAttention(int accountId, Attention attention, const QString &seenPin)
{
    QStringList arguments { QStringLiteral("attention"), QString::number(accountId), attentionToString(attention) };
    if (!seenPin.isEmpty())
        arguments << seenPin;
    QPointer<HelperAccountsDirectory> self(this);
    start(arguments, [self](const Result &started, const QByteArray &answer) {
        if (const Result r = started.ok() ? AccountsHelper::decodeStatus(answer) : started; !r.ok()) {
            qCWarning(lcNetVfsBridge) << "Cannot record the attention state:" << r.toString();
            return;
        }
        // The helper's own AccountChanged may not reach the bus (it is set-id).
        if (self)
            emit self->changed();
    });
}

} // namespace NetVfs::Bridge
