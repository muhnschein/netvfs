// SPDX-License-Identifier: LGPL-2.1-or-later
#include "netvfshelpers.h"
#include "accountstore.h"
#include "backendloader.h"
#include "paths.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QRegularExpression>
#include <QtCore/QUrl>

using namespace NetVfs;

namespace NetVfsUi {

namespace {
constexpr const char *OptHostKey = "host_key";
constexpr const char *OptAuthMode = "auth_mode";
constexpr const char *OptPublicKey = "public_key";
constexpr const char *OptRequireEncryption = "require_encryption";
constexpr const char *AuthPassword = "password";
constexpr const char *AuthPublicKey = "publickey";
constexpr const char *ProviderSftp = "sftp";
constexpr const char *ProviderSmb = "smb";
constexpr const char *StateCredentialsMissing = "credentials-missing";
constexpr int MaxHostLength = 253;
constexpr int MaxLabelLength = 63;
constexpr int MaxShareLength = 80;

QString str(const char *latin1)
{
    return QLatin1String(latin1);
}

bool hasControlCharacter(const QString &text)
{
    for (const QChar c : text) {
        if (c.category() == QChar::Other_Control)
            return true;
    }
    return false;
}

bool isIpv6Literal(const QString &host)
{
    static const QRegularExpression pattern(QStringLiteral("^[0-9A-Fa-f:.]+(%[A-Za-z0-9_.-]+)?$"));
    return host.count(QLatin1Char(':')) >= 2 && pattern.match(host).hasMatch();
}

bool isDnsLabel(const QString &label)
{
    static const QRegularExpression pattern(QStringLiteral("^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?$"));
    return label.size() <= MaxLabelLength && pattern.match(label).hasMatch();
}

bool isHostName(const QString &host)
{
    QString name = host;
    if (name.endsWith(QLatin1Char('.')))
        name.chop(1);
    const QString ace = QString::fromLatin1(QUrl::toAce(name));
    if (ace.isEmpty() || ace.size() > MaxHostLength)
        return false;
    for (const QString &label : ace.split(QLatin1Char('.'))) {
        if (!isDnsLabel(label))
            return false;
    }
    return true;
}

QString stripBrackets(const QString &host)
{
    if (host.startsWith(QLatin1Char('[')) && host.endsWith(QLatin1Char(']')))
        return host.mid(1, host.size() - 2);
    return host;
}

QString providerOptionKey(const QString &provider, const QString &key)
{
    return Keys::providerKey(provider, key);
}

// Options that are written to the account; host_key_seen is owned by the
// attention mechanism (SPEC 6.4) and an empty pin is never stored.
bool isStorableOption(const QString &key, const QVariant &value)
{
    if (key == QLatin1String(Keys::HostKeySeen))
        return false;
    return !(key == QLatin1String(OptHostKey) && value.toString().isEmpty());
}

void insertOptions(QVariantMap *global, const ConnectionParams &params)
{
    for (auto it = params.options.constBegin(); it != params.options.constEnd(); ++it) {
        if (isStorableOption(it.key(), it.value()))
            global->insert(providerOptionKey(params.provider, it.key()), it.value());
    }
}
} // namespace

ConnectionParams paramsFromVariant(const QVariantMap &map)
{
    ConnectionParams params;
    params.provider = map.value(QStringLiteral("provider")).toString().trimmed();
    params.host = stripBrackets(map.value(QStringLiteral("host")).toString().trimmed());
    params.port = map.value(QStringLiteral("port")).toInt();
    params.username = map.value(QStringLiteral("username")).toString().trimmed();
    params.options = map.value(QStringLiteral("options")).toMap();
    return params;
}

QVariantMap paramsToVariant(const ConnectionParams &params)
{
    QVariantMap map;
    map.insert(QStringLiteral("provider"), params.provider);
    map.insert(QStringLiteral("host"), params.host);
    map.insert(QStringLiteral("port"), params.port);
    map.insert(QStringLiteral("username"), params.username);
    map.insert(QStringLiteral("options"), params.options);
    return map;
}

QString sha256Fingerprint(const QByteArray &publicKeyBlob)
{
    QByteArray encoded = QCryptographicHash::hash(publicKeyBlob, QCryptographicHash::Sha256).toBase64();
    while (encoded.endsWith('='))
        encoded.chop(1);
    return QStringLiteral("SHA256:") + QString::fromLatin1(encoded);
}

QVariantMap identityToVariant(const ServerIdentity &identity)
{
    QVariantMap map;
    if (identity.isEmpty())
        return map;
    map.insert(QStringLiteral("algorithm"), identity.algorithm);
    map.insert(QStringLiteral("fingerprint"),
               identity.fingerprint.isEmpty() ? sha256Fingerprint(identity.publicKey) : identity.fingerprint);
    map.insert(QStringLiteral("pin"), identity.toPin());
    return map;
}

Helpers::Helpers(QObject *parent)
    : QObject(parent)
{
}

QString Helpers::defaultBackupsPath() const
{
    return QLatin1String(DefaultBackupsPath);
}

QString Helpers::credentialsApplication() const
{
    return QLatin1String(CredentialsApplication);
}

QString Helpers::credentialsName() const
{
    return QLatin1String(CredentialsName);
}

QString Helpers::backupsPathKey() const
{
    return QLatin1String(Keys::BackupsPath);
}

int Helpers::defaultPort(const QString &provider) const
{
    if (provider == QLatin1String(ProviderSftp))
        return 22;
    if (provider == QLatin1String(ProviderSmb))
        return 445;
    return 0;
}

QString Helpers::backupServiceName(const QString &provider) const
{
    return NetVfs::backupServiceName(provider);
}

bool Helpers::isProviderInstalled(const QString &provider) const
{
    return BackendLoader::isAvailable(provider);
}

QString Helpers::hostProblem(const QString &host) const
{
    const QString value = host.trimmed();
    if (value.isEmpty()) {
        //% "Enter the server name or IP address."
        return qtTrId("settings-accounts-netvfs-la-host_empty");
    }
    if (value.contains(QLatin1String("://"))) {
        //% "Enter only the server name, without a prefix such as sftp:// or smb://."
        return qtTrId("settings-accounts-netvfs-la-host_url");
    }
    if (value.contains(QLatin1Char('@'))) {
        //% "Enter the user name in its own field."
        return qtTrId("settings-accounts-netvfs-la-host_user");
    }
    if (const QString bare = stripBrackets(value); isIpv6Literal(bare) || isHostName(bare))
        return QString();
    //% "This is not a valid server name or IP address."
    return qtTrId("settings-accounts-netvfs-la-host_invalid");
}

QString Helpers::portProblem(const QString &port) const
{
    const QString value = port.trimmed();
    if (value.isEmpty())
        return QString();
    static const QRegularExpression digits(QStringLiteral("^[0-9]{1,5}$"));
    if (const int number = value.toInt(); digits.match(value).hasMatch() && number >= 1 && number <= 65535)
        return QString();
    //% "The port must be a number from 1 to 65535."
    return qtTrId("settings-accounts-netvfs-la-port_invalid");
}

int Helpers::portValue(const QString &port) const
{
    return portProblem(port).isEmpty() ? port.trimmed().toInt() : 0;
}

QString Helpers::userNameProblem(const QString &userName) const
{
    const QString value = userName.trimmed();
    if (value.isEmpty()) {
        //% "Enter the user name."
        return qtTrId("settings-accounts-netvfs-la-user_empty");
    }
    if (hasControlCharacter(value)) {
        //% "The user name contains characters that are not allowed."
        return qtTrId("settings-accounts-netvfs-la-user_invalid");
    }
    return QString();
}

QString Helpers::shareProblem(const QString &share) const
{
    const QString value = share.trimmed();
    if (value.isEmpty()) {
        //% "Enter the name of the share."
        return qtTrId("settings-accounts-netvfs-la-share_empty");
    }
    if (value.contains(QLatin1Char('/')) || value.contains(QLatin1Char('\\'))) {
        //% "Enter only the share name. Put folders inside the share into the backups folder."
        return qtTrId("settings-accounts-netvfs-la-share_path");
    }
    if (value.size() > MaxShareLength || !Paths::windowsComponentProblem(value).isEmpty()) {
        //% "This is not a valid share name."
        return qtTrId("settings-accounts-netvfs-la-share_invalid");
    }
    return QString();
}

QString Helpers::backupsPathProblem(const QString &provider, const QString &path) const
{
    QString normalized;
    if (path.trimmed().isEmpty()) {
        //% "Enter the folder for backups."
        return qtTrId("settings-accounts-netvfs-la-folder_empty");
    }
    if (!Paths::normalize(path.trimmed(), &normalized).ok()) {
        //% "Folder names \".\" and \"..\" are not allowed."
        return qtTrId("settings-accounts-netvfs-la-folder_dots");
    }
    if (provider != QLatin1String(ProviderSmb))
        return QString();
    // SPEC-smb M-9: rejected before any connection is made.
    for (const QString &component : Paths::components(normalized)) {
        if (!Paths::windowsComponentProblem(component).isEmpty()) {
            //% "\"%1\" cannot be used as a folder name on an SMB server: names must not contain \\ : * ? \" < > | or end in a space or a dot."
            return qtTrId("settings-accounts-netvfs-la-folder_windows").arg(component);
        }
    }
    return QString();
}

QString Helpers::cleanBackupsPath(const QString &provider, const QString &path) const
{
    QString normalized;
    if (!Paths::normalize(path.trimmed(), &normalized).ok())
        return QString();
    if (provider == QLatin1String(ProviderSmb)) {
        while (normalized.startsWith(QLatin1Char('/')))
            normalized.remove(0, 1);
    }
    return normalized;
}

QString Helpers::accountLabel(const QString &userName, const QString &host) const
{
    return userName.trimmed() + QLatin1Char('@') + stripBrackets(host.trimmed());
}

QVariantMap Helpers::makeParams(const QString &provider, const QString &host, const QString &port,
                                const QString &userName, const QVariantMap &options) const
{
    ConnectionParams params;
    params.provider = provider;
    params.host = stripBrackets(host.trimmed());
    params.port = portValue(port);
    params.username = userName.trimmed();
    params.options = options;
    return paramsToVariant(params);
}

QVariantMap Helpers::withOptions(const QVariantMap &paramsMap, const QVariantMap &options) const
{
    ConnectionParams params = paramsFromVariant(paramsMap);
    for (auto it = options.constBegin(); it != options.constEnd(); ++it) {
        if (it.value().type() == QVariant::String && it.value().toString().isEmpty())
            params.options.remove(it.key());
        else
            params.options.insert(it.key(), it.value());
    }
    return paramsToVariant(params);
}

QVariantMap Helpers::paramsFromConfiguration(const QString &provider, const QVariantMap &configuration) const
{
    ConnectionParams params;
    params.provider = provider;
    params.host = configuration.value(str(Keys::Host)).toString();
    params.port = configuration.value(str(Keys::Port)).toInt();
    params.username = configuration.value(str(Keys::Username)).toString();
    const QString prefix = providerOptionKey(provider, QString());
    for (auto it = configuration.constBegin(); it != configuration.constEnd(); ++it) {
        if (it.key().startsWith(prefix))
            params.options.insert(it.key().mid(prefix.size()), it.value());
    }
    return paramsToVariant(params);
}

QVariantMap Helpers::creationSettings(const QVariantMap &paramsMap, const QString &backupsPath) const
{
    const ConnectionParams params = paramsFromVariant(paramsMap);
    QVariantMap global;
    global.insert(str(Keys::Host), params.host);
    global.insert(str(Keys::Port), params.port);
    global.insert(str(Keys::Username), params.username);
    insertOptions(&global, params);

    QVariantMap service;
    service.insert(str(Keys::BackupsPath), cleanBackupsPath(params.provider, backupsPath));

    QVariantMap result;
    result.insert(QStringLiteral("global"), global);
    result.insert(QStringLiteral("service"), service);
    result.insert(QStringLiteral("serviceName"), backupServiceName(params.provider));
    return result;
}

QVariantMap Helpers::credentialsLabelSettings(const QVariantMap &paramsMap) const
{
    const ConnectionParams params = paramsFromVariant(paramsMap);
    QVariantMap global;
    global.insert(str(Keys::DefaultCredentialsUsername), accountLabel(params.username, params.host));
    QVariantMap result;
    result.insert(QStringLiteral("global"), global);
    return result;
}

QVariantMap Helpers::updateSettings(const QVariantMap &paramsMap) const
{
    const ConnectionParams params = paramsFromVariant(paramsMap);
    QVariantMap global;
    global.insert(str(Keys::DefaultCredentialsUsername), accountLabel(params.username, params.host));
    global.insert(str(Keys::CredentialsNeedUpdate), false);
    insertOptions(&global, params);

    QStringList remove;
    remove << str(Keys::Attention) << str(Keys::CredentialsNeedUpdateFrom)
           << providerOptionKey(params.provider, str(Keys::HostKeySeen));
    if (params.option(str(OptAuthMode)) == QLatin1String(AuthPassword))
        remove << providerOptionKey(params.provider, str(OptPublicKey));

    QVariantMap result;
    result.insert(QStringLiteral("global"), global);
    result.insert(QStringLiteral("remove"), remove);
    return result;
}

QString Helpers::attentionState(const QVariantMap &configuration) const
{
    if (const Attention attention = attentionFromString(configuration.value(str(Keys::Attention)).toString());
            attention != Attention::None)
        return attentionToString(attention);
    if (configuration.value(str(Keys::CredentialsNeedUpdate)).toBool())
        return str(StateCredentialsMissing);
    return QString();
}

QString Helpers::attentionText(const QString &state) const
{
    switch (attentionFromString(state)) {
    case Attention::AuthFailed:
        //% "The server refused the stored password or key. Update the sign-in details to continue backing up."
        return qtTrId("settings-accounts-netvfs-la-attention_auth_failed");
    case Attention::ServerIdentityChanged:
        //% "The server presented a different identity than the one stored for this account. Backups are stopped until you check and accept it."
        return qtTrId("settings-accounts-netvfs-la-attention_identity_changed");
    case Attention::None:
        break;
    }
    if (state == QLatin1String(StateCredentialsMissing)) {
        //% "The sign-in details for this account are missing, for example after restoring the device. Enter them again to continue backing up."
        return qtTrId("settings-accounts-netvfs-la-attention_credentials_missing");
    }
    return QString();
}

QVariantMap Helpers::identityFromPin(const QString &pin) const
{
    return identityToVariant(ServerIdentity::fromPin(pin));
}

QString Helpers::seenPin(const QString &provider, const QVariantMap &configuration) const
{
    return configuration.value(providerOptionKey(provider, str(Keys::HostKeySeen))).toString();
}

QString Helpers::hostKeyHint(const QString &algorithm) const
{
    QString keyType = QStringLiteral("ed25519");
    if (algorithm.startsWith(QLatin1String("ecdsa-")))
        keyType = QStringLiteral("ecdsa");
    else if (algorithm == QLatin1String("ssh-rsa") || algorithm.startsWith(QLatin1String("rsa-")))
        keyType = QStringLiteral("rsa");
    const QString command = QStringLiteral("ssh-keygen -lf /etc/ssh/ssh_host_%1_key.pub").arg(keyType);
    //% "To compare, run this command on the server: %1"
    return qtTrId("settings-accounts-netvfs-la-host_key_hint").arg(command);
}

QString Helpers::transportSecurityText(const QVariantMap &paramsMap) const
{
    const ConnectionParams params = paramsFromVariant(paramsMap);
    if (params.provider != QLatin1String(ProviderSmb)) {
        //% "Encrypted (SSH)"
        return qtTrId("settings-accounts-netvfs-la-security_ssh");
    }
    if (params.options.value(str(OptRequireEncryption), true).toBool()) {
        //% "Signed and encrypted"
        return qtTrId("settings-accounts-netvfs-la-security_smb_encrypted");
    }
    //% "Signed, not encrypted"
    return qtTrId("settings-accounts-netvfs-la-security_smb_signed");
}

QString Helpers::authModeText(const QString &authMode) const
{
    if (authMode == QLatin1String(AuthPublicKey)) {
        //% "SSH key"
        return qtTrId("settings-accounts-netvfs-la-auth_key");
    }
    //% "Password"
    return qtTrId("settings-accounts-netvfs-la-auth_password");
}

} // namespace NetVfsUi
