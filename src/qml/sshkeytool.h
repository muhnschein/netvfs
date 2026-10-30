// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_SSHKEYTOOL_H
#define NETVFS_QML_SSHKEYTOOL_H

#include "backendjobs.h"
#include "sshkeys.h"

#include <QtCore/QObject>
#include <QtCore/QVariantMap>

namespace NetVfsUi {

// `path` may be a file:// URL. Fails for files that cannot be key files (missing, too large).
NetVfs::Result readKeyFile(const QString &path, QByteArray *contents);

// Key generation and import, and installing the public key with a password. The private key stays
// in this object until account setup takes secret(); never written to disk.
class SshKeyTool : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(SshKeyTool)
    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(bool available READ available CONSTANT)
    Q_PROPERTY(bool hasKey READ hasKey NOTIFY stateChanged)
    Q_PROPERTY(QString algorithm READ algorithm NOTIFY stateChanged)
    Q_PROPERTY(QString publicKey READ publicKey NOTIFY stateChanged)
    Q_PROPERTY(QString fingerprint READ fingerprint NOTIFY stateChanged)
    Q_PROPERTY(QString errorText READ errorText NOTIFY stateChanged)
    Q_PROPERTY(QString errorDetail READ errorDetail NOTIFY stateChanged)
    Q_PROPERTY(InstallState installState READ installState NOTIFY installStateChanged)
    Q_PROPERTY(QString installErrorText READ installErrorText NOTIFY installStateChanged)
    Q_PROPERTY(QString installErrorDetail READ installErrorDetail NOTIFY installStateChanged)

public:
    enum class State { Empty, Working, NeedsPassphrase, Ready, Failed };
    Q_ENUM(State)
    enum class InstallState { InstallIdle, Installing, Installed, InstallFailed };
    Q_ENUM(InstallState)

    // `tools` defaults to the SFTP backend plugin's implementation.
    explicit SshKeyTool(QObject *parent = nullptr);
    SshKeyTool(NetVfs::SshKeyTools *tools, QObject *parent);
    ~SshKeyTool() override;

    State state() const { return m_state; }
    bool available() const { return m_tools != nullptr; }
    bool hasKey() const { return m_state == State::Ready; }
    QString algorithm() const { return m_key.algorithm; }
    QString publicKey() const { return m_key.publicLine; }
    QString fingerprint() const { return m_key.fingerprint; }
    QString errorText() const { return m_errorText; }
    QString errorDetail() const { return m_errorDetail; }
    InstallState installState() const { return m_installState; }
    QString installErrorText() const { return m_installErrorText; }
    QString installErrorDetail() const { return m_installErrorDetail; }

    Q_INVOKABLE void generate();
    // Asks for a passphrase (state NeedsPassphrase) when the file is encrypted.
    Q_INVOKABLE void importFile(const QString &path, const QString &passphrase = QString());
    // "netvfs-key-v1:<base64>" for createSignInCredentials(); empty while no key is held.
    Q_INVOKABLE QString secret() const;
    // Signs in once with `password` (not stored, wiped after use) and appends the public key to
    // ~/.ssh/authorized_keys. `params` must carry the accepted host key pin.
    Q_INVOKABLE void installWithPassword(const QVariantMap &params, const QString &password);
    Q_INVOKABLE void cancel();
    Q_INVOKABLE void clear();

Q_SIGNALS:
    void stateChanged();
    void installStateChanged();

private:
    enum class KeyJob { Generate, Import, ImportWithPassphrase };
    void runKeyJob(const std::function<NetVfs::Result(NetVfs::SshKeyMaterial *)> &operation, KeyJob job);
    void finishKeyJob(const NetVfs::Result &result, const NetVfs::SshKeyMaterial &material, KeyJob job);
    void setFailed(const QString &text, const QString &detail);
    void finishInstall(const NetVfs::Result &result);
    void setInstallState(InstallState state);

    NetVfs::SshKeyTools *m_tools;
    State m_state = State::Empty;
    NetVfs::SshKeyMaterial m_key;
    QString m_errorText;
    QString m_errorDetail;
    InstallState m_installState = InstallState::InstallIdle;
    QString m_installErrorText;
    QString m_installErrorDetail;
    BackendJobs m_keyJobs;
    BackendJobs m_installJobs;
};

}
#endif
