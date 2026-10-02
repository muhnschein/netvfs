// SPDX-License-Identifier: LGPL-2.1-or-later
#include "netvfshelpers.h"
#include "accountstore.h"
#include "backendloader.h"
#include "errortexts.h"
#include "paths.h"
#include "servicepolicy.h"

#include <Accounts/Manager>
#include <Accounts/Service>

#include <QtCore/QCryptographicHash>
#include <QtCore/QRegularExpression>
#include <QtCore/QUrl>

#include <algorithm>

using namespace NetVfs;

namespace NetVfsUi {

namespace {
constexpr const char *OptHostKey = "host_key";
constexpr const char *OptAuthMode = "auth_mode";
constexpr const char *OptPublicKey = "public_key";
constexpr const char *AuthPublicKey = "publickey";
constexpr const char *AuthInteractive = "interactive";
constexpr const char *AuthToken = "token";
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
    return std::any_of(text.cbegin(), text.cend(),
                       [](const QChar c) { return c.category() == QChar::Other_Control; });
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
    const QStringList labels = ace.split(QLatin1Char('.'));
    return std::all_of(labels.cbegin(), labels.cend(), isDnsLabel);
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

QStringList tlsProblemTexts(int problems)
{
    QStringList texts;
    if (problems & ServerIdentity::SelfSigned) {
        //% "The certificate is self-signed: no certificate authority vouches for it."
        texts << qtTrId("settings-accounts-netvfs-la-tls_self_signed");
    }
    if (problems & ServerIdentity::UntrustedRoot) {
        //% "The certificate is issued by an authority this device does not trust."
        texts << qtTrId("settings-accounts-netvfs-la-tls_untrusted_root");
    }
    if (problems & ServerIdentity::Expired) {
        //% "The certificate has expired."
        texts << qtTrId("settings-accounts-netvfs-la-tls_expired");
    }
    if (problems & ServerIdentity::NotYetValid) {
        //% "The certificate is not valid yet."
        texts << qtTrId("settings-accounts-netvfs-la-tls_not_yet_valid");
    }
    if (problems & ServerIdentity::HostnameMismatch) {
        //% "The certificate is issued for a different server name."
        texts << qtTrId("settings-accounts-netvfs-la-tls_hostname_mismatch");
    }
    return texts;
}

QString colonHex(const QString &hex)
{
    QStringList pairs;
    const QString upper = hex.toUpper();
    for (int i = 0; i + 1 < upper.size(); i += 2)
        pairs << upper.mid(i, 2);
    return pairs.join(QLatin1Char(':'));
}

namespace {
QString dateText(const QVariant &value)
{
    const QDateTime time = value.toDateTime();
    return time.isValid() ? time.toUTC().toString(Qt::ISODate) : QString();
}

void insertTlsDetails(QVariantMap *map, const ServerIdentity &identity)
{
    const QVariantMap &details = identity.details;
    map->insert(QStringLiteral("subject"), details.value(QStringLiteral("subject")).toString());
    map->insert(QStringLiteral("issuer"), details.value(QStringLiteral("issuer")).toString());
    map->insert(QStringLiteral("notBefore"), dateText(details.value(QStringLiteral("notBefore"))));
    map->insert(QStringLiteral("notAfter"), dateText(details.value(QStringLiteral("notAfter"))));
    map->insert(QStringLiteral("sans"), details.value(QStringLiteral("sans")).toStringList());
    map->insert(QStringLiteral("certSha256"), colonHex(details.value(QStringLiteral("certSha256")).toString()));
    map->insert(QStringLiteral("systemTrusted"), identity.systemTrusted);
    map->insert(QStringLiteral("problems"), identity.problems);
    map->insert(QStringLiteral("problemTexts"), tlsProblemTexts(identity.problems));
}
} // namespace

QVariantMap identityToVariant(const ServerIdentity &identity)
{
    QVariantMap map;
    if (identity.isEmpty())
        return map;
    const bool tls = identity.kind == ServerIdentity::Kind::TlsCertificate;
    map.insert(QStringLiteral("kind"), tls ? QStringLiteral("tls") : QStringLiteral("ssh"));
    map.insert(QStringLiteral("algorithm"), identity.algorithm);
    map.insert(QStringLiteral("fingerprint"),
               identity.fingerprint.isEmpty() ? sha256Fingerprint(identity.publicKey) : identity.fingerprint);
    map.insert(QStringLiteral("pin"), identity.toPin());
    // XC-16, W-4: what to store on acceptance (host_key, tls_verify_peer).
    map.insert(QStringLiteral("pinOptions"), pinOptions(identity));
    if (tls)
        insertTlsDetails(&map, identity);
    return map;
}

InputRules::InputRules(QObject *parent)
    : QObject(parent)
{
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

QString Helpers::filesRootKey() const
{
    return QLatin1String(Keys::FilesRoot);
}

int InputRules::defaultPort(const QString &provider) const
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

QString Helpers::filesServiceName(const QString &provider) const
{
    return NetVfs::filesServiceName(provider);
}

bool Helpers::isProviderInstalled(const QString &provider) const
{
    return BackendLoader::isAvailable(provider);
}

bool Helpers::isServiceInstalled(const QString &serviceName) const
{
    Accounts::Manager manager;
    return manager.service(serviceName).isValid();
}

bool Helpers::serviceAllowed(const QVariantMap &params, const QString &service) const
{
    Service s = Service::Backup;
    return serviceFromId(service, &s) && checkServicePolicy(paramsFromVariant(params), s).ok();
}

QString Helpers::serviceRefusalText(const QVariantMap &params, const QString &service) const
{
    Service s = Service::Backup;
    if (!serviceFromId(service, &s))
        return userErrorText(Error::Internal);
    const Result r = checkServicePolicy(paramsFromVariant(params), s);
    if (r.ok())
        return QString();
    return userErrorText(r.error(), s == Service::Backup ? Activity::ServicePolicy : Activity::Connect);
}

bool Helpers::secretOptional(const QVariantMap &params) const
{
    return NetVfs::secretOptional(paramsFromVariant(params));
}

QString InputRules::hostProblem(const QString &host) const
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

QString InputRules::portProblem(const QString &port) const
{
    if (port.trimmed().isEmpty() || parsePort(port) > 0)
        return QString();
    //% "The port must be a number from 1 to 65535."
    return qtTrId("settings-accounts-netvfs-la-port_invalid");
}

int parsePort(const QString &port)
{
    static const QRegularExpression digits(QStringLiteral("^[0-9]{1,5}$"));
    const QString value = port.trimmed();
    if (const int number = value.toInt(); digits.match(value).hasMatch() && number >= 1 && number <= 65535)
        return number;
    return 0;
}

int InputRules::portValue(const QString &port) const
{
    return parsePort(port);
}

QString InputRules::userNameProblem(const QString &userName) const
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

QString InputRules::shareProblem(const QString &share) const
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

QString InputRules::serverPathProblem(const QString &path) const
{
    const QString value = path.trimmed();
    QString normalized;
    if (!value.startsWith(QLatin1Char('/')) || hasControlCharacter(value) || !Paths::normalize(value, &normalized).ok()) {
        //% "Enter a path that starts with /, for example /remote.php/dav/files/me/."
        return qtTrId("settings-accounts-netvfs-la-server_path_invalid");
    }
    return QString();
}

QString InputRules::backupsPathProblem(const QString &provider, const QString &path) const
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

QString InputRules::cleanBackupsPath(const QString &provider, const QString &path) const
{
    return cleanFolderPath(provider, path);
}

QString cleanFolderPath(const QString &provider, const QString &path)
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
    params.port = parsePort(port);
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

QVariantMap Helpers::creationSettings(const QVariantMap &paramsMap, const QVariantMap &services) const
{
    const ConnectionParams params = paramsFromVariant(paramsMap);
    QVariantMap global;
    global.insert(str(Keys::Host), params.host);
    global.insert(str(Keys::Port), params.port);
    global.insert(str(Keys::Username), params.username);
    insertOptions(&global, params);

    QVariantMap values;
    QStringList enable;
    if (services.value(QStringLiteral("backup")).toBool()) {
        const QString name = NetVfs::backupServiceName(params.provider);
        QVariantMap backup;
        backup.insert(str(Keys::BackupsPath),
                      cleanFolderPath(params.provider, services.value(QStringLiteral("backupsPath")).toString()));
        values.insert(name, backup);
        enable << name;
    }
    if (services.value(QStringLiteral("files")).toBool()) {
        // SPEC-v2-review 2.17: files_root is a setting of the files service.
        const QString name = NetVfs::filesServiceName(params.provider);
        QVariantMap files;
        files.insert(str(Keys::FilesRoot),
                     cleanFolderPath(params.provider, services.value(QStringLiteral("filesRoot")).toString()));
        values.insert(name, files);
        enable << name;
    }

    QVariantMap result;
    result.insert(QStringLiteral("global"), global);
    result.insert(QStringLiteral("services"), values);
    result.insert(QStringLiteral("enable"), enable);
    result.insert(QStringLiteral("signInService"), enable.value(0, NetVfs::filesServiceName(params.provider)));
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
    if (params.option(str(OptAuthMode)) != QLatin1String(AuthPublicKey))
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

QString Helpers::authModeText(const QString &authMode) const
{
    if (authMode == QLatin1String(AuthPublicKey)) {
        //% "SSH key"
        return qtTrId("settings-accounts-netvfs-la-auth_key");
    }
    if (authMode == QLatin1String(AuthInteractive)) {
        //% "Asked each time"
        return qtTrId("settings-accounts-netvfs-la-auth_interactive");
    }
    if (authMode == QLatin1String(AuthToken)) {
        //% "Access token"
        return qtTrId("settings-accounts-netvfs-la-auth_token");
    }
    //% "Password"
    return qtTrId("settings-accounts-netvfs-la-auth_password");
}

} // namespace NetVfsUi
