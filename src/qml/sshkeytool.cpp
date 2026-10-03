// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sshkeytool.h"
#include "backendloader.h"
#include "errortexts.h"
#include "identity.h"
#include "logging.h"
#include "netvfshelpers.h"
#include "probe.h"
#include "secure.h"

#include <QtCore/QFile>
#include <QtCore/QUrl>

#include <memory>

using namespace NetVfs;

namespace NetVfsUi {

namespace {
// Generous upper bound: an OpenSSH RSA-16384 private key is about 12 kB.
constexpr qint64 MaxKeyFileSize = 64 * 1024;

struct KeyOutcome {
    Result result;
    SshKeyMaterial material;
};

QString localPath(const QString &path)
{
    if (path.startsWith(QLatin1String("file:")))
        return QUrl(path).toLocalFile();
    return path;
}
} // namespace

Result readKeyFile(const QString &path, QByteArray *contents)
{
    QFile file(localPath(path));
    if (!file.open(QIODevice::ReadOnly))
        return Result(Error::NotFound, file.errorString());
    if (file.size() > MaxKeyFileSize)
        return Result(Error::Internal, QStringLiteral("The file is too large to be a private key"));
    *contents = file.readAll();
    return Result::success();
}

SshKeyTool::SshKeyTool(QObject *parent)
    : SshKeyTool(BackendLoader::sshKeyTools(), parent)
{
    if (!m_tools)
        qCWarning(lcNetVfsUi) << "SSH key support is not available: the SFTP backend is not installed";
}

SshKeyTool::SshKeyTool(SshKeyTools *tools, QObject *parent)
    : QObject(parent)
    , m_tools(tools)
{
}

SshKeyTool::~SshKeyTool()
{
    m_keyJobs.cancel();
    m_installJobs.cancel();
    m_key.wipe();
}

void SshKeyTool::generate()
{
    SshKeyTools *tools = m_tools;
    runKeyJob([tools](SshKeyMaterial *out) { return tools->generate(out); }, KeyJob::Generate);
}

void SshKeyTool::importFile(const QString &path, const QString &passphrase)
{
    SshKeyTools *tools = m_tools;
    // One shared, self-wiping copy of the passphrase (SEC-5).
    const auto secret = std::make_shared<Credentials>(QString(), passphrase.toUtf8());
    runKeyJob([tools, path, secret](SshKeyMaterial *out) {
        QByteArray contents;
        Result r = readKeyFile(path, &contents);
        if (r.ok())
            r = tools->importKey(contents, secret->secret, out);
        secureWipe(contents);
        secret->wipe();
        return r;
    }, passphrase.isEmpty() ? KeyJob::Import : KeyJob::ImportWithPassphrase);
}

void SshKeyTool::runKeyJob(const std::function<Result(SshKeyMaterial *)> &operation, KeyJob job)
{
    m_keyJobs.cancel();
    if (!m_tools) {
        setFailed(backendMissingText(), QString());
        return;
    }
    m_state = State::Working;
    emit stateChanged();
    auto outcome = std::make_shared<KeyOutcome>();
    m_keyJobs.start([operation, outcome](CancelToken *) {
        outcome->result = operation(&outcome->material);
    }, [this, outcome, job]() {
        finishKeyJob(outcome->result, outcome->material, job);
        outcome->material.wipe();
    });
}

void SshKeyTool::finishKeyJob(const Result &result, const SshKeyMaterial &material, KeyJob job)
{
    m_key.wipe();
    m_key = SshKeyMaterial();
    if (result.ok()) {
        m_key = material;
        m_state = State::Ready;
        m_errorText.clear();
        m_errorDetail.clear();
        emit stateChanged();
        return;
    }
    if (job != KeyJob::Generate && result.error() == Error::AuthFailed) {
        // An encrypted file: ask for the passphrase. The message is shown
        // only when a passphrase was given and was wrong.
        m_state = State::NeedsPassphrase;
        m_errorText = job == KeyJob::ImportWithPassphrase ? userErrorText(Error::AuthFailed, Activity::KeyFile)
                                                          : QString();
        m_errorDetail.clear();
        emit stateChanged();
        return;
    }
    setFailed(userErrorText(result.error(), job == KeyJob::Generate ? Activity::Connect : Activity::KeyFile),
              result.message());
}

void SshKeyTool::setFailed(const QString &text, const QString &detail)
{
    m_state = State::Failed;
    m_errorText = text;
    m_errorDetail = detail;
    emit stateChanged();
}

QString SshKeyTool::secret() const
{
    if (m_state != State::Ready || m_key.privateKey.isEmpty())
        return QString();
    QByteArray encoded = encodeKeySecret(m_key.privateKey);
    const QString value = QString::fromLatin1(encoded);
    secureWipe(encoded);
    return value;
}

void SshKeyTool::installWithPassword(const QVariantMap &paramsMap, const QString &password)
{
    m_installJobs.cancel();
    if (m_state != State::Ready) {
        finishInstall(Result(Error::Internal, QStringLiteral("No key to install")));
        return;
    }
    ConnectionParams params = paramsFromVariant(paramsMap);
    params.options.insert(QStringLiteral("auth_mode"), QStringLiteral("password"));
    params = withBackupDirMode(params);   // ~/.ssh stays private (S-20)
    Result result;
    Backend *backend = BackendLoader::create(params.provider, &result);
    if (!backend) {
        m_installState = InstallState::InstallFailed;
        m_installErrorText = backendMissingText();
        m_installErrorDetail = result.message();
        emit installStateChanged();
        return;
    }
    QByteArray bytes = password.toUtf8();
    const auto credentials = std::make_shared<Credentials>(params.username, bytes);
    secureWipe(bytes);
    const QString publicLine = m_key.publicLine;
    auto outcome = std::make_shared<Result>();
    setInstallState(InstallState::Installing);
    m_installJobs.start([backend, params, credentials, publicLine, outcome](CancelToken *token) {
        std::unique_ptr<Backend> owned(backend);
        token->attach(backend);
        Result r = establish(backend, params, *credentials);
        credentials->wipe();   // S-16: used once, not stored
        if (r.ok()) {
            r = installAuthorizedKey(backend, publicLine);
            backend->disconnect();
        }
        token->detach();
        *outcome = r;
    }, [this, outcome]() { finishInstall(*outcome); });
}

void SshKeyTool::finishInstall(const Result &result)
{
    if (result.ok()) {
        m_installErrorText.clear();
        m_installErrorDetail.clear();
        setInstallState(InstallState::Installed);
        return;
    }
    m_installErrorText = userErrorText(result.error(), Activity::InstallKey);
    m_installErrorDetail = result.message();
    setInstallState(InstallState::InstallFailed);
}

void SshKeyTool::setInstallState(InstallState state)
{
    m_installState = state;
    emit installStateChanged();
}

void SshKeyTool::cancel()
{
    if (m_keyJobs.isRunning()) {
        m_keyJobs.cancel();
        m_state = m_key.privateKey.isEmpty() ? State::Empty : State::Ready;
        emit stateChanged();
    }
    if (m_installJobs.isRunning()) {
        m_installJobs.cancel();
        setInstallState(InstallState::InstallIdle);
    }
}

void SshKeyTool::clear()
{
    m_keyJobs.cancel();
    m_installJobs.cancel();
    m_key.wipe();
    m_key = SshKeyMaterial();
    m_state = State::Empty;
    m_errorText.clear();
    m_errorDetail.clear();
    m_installState = InstallState::InstallIdle;
    m_installErrorText.clear();
    m_installErrorDetail.clear();
    emit stateChanged();
    emit installStateChanged();
}

} // namespace NetVfsUi
