// SPDX-License-Identifier: LGPL-2.1-or-later
#include "providerdescriptors.h"
#include "logging.h"
#include "netvfshelpers.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QRegularExpression>
#include <QtCore/QSet>

#include <initializer_list>
#include <memory>

using namespace NetVfs;

namespace NetVfsUi {

namespace {
const char DefaultDirectory[] = "/usr/share/netvfs/providers";
const char DirectoryEnv[] = "NETVFS_PROVIDERS_DIR";
const char KeyHost[] = "host";
const char KeyPort[] = "port";
const char KeyUserName[] = "username";
const char KeyAuthMode[] = "auth_mode";
const char KeySource[] = "key_source";
const char TypeText[] = "text";
const char TypeSwitch[] = "switch";
const char TypeChoice[] = "choice";
const char TypeNote[] = "note";
const char SecretNone[] = "none";
constexpr int MaxPort = 65535;

QString str(const char *latin1)
{
    return QLatin1String(latin1);
}

QStringList list(std::initializer_list<const char *> items)
{
    QStringList result;
    for (const char *item : items)
        result << QLatin1String(item);
    return result;
}

Result invalid(const QString &what)
{
    return Result(Error::Internal, QStringLiteral("Invalid provider descriptor: ") + what);
}

bool isConnectionKey(const QString &key)
{
    return key == QLatin1String(KeyHost) || key == QLatin1String(KeyPort) || key == QLatin1String(KeyUserName);
}

// Values compare as strings; switches as "true"/"false".
QString valueText(const QVariant &value)
{
    if (value.type() == QVariant::Bool)
        return value.toBool() ? QStringLiteral("true") : QStringLiteral("false");
    return value.toString();
}

bool conditionHolds(const QVariantMap &condition, const QVariantMap &values)
{
    for (auto it = condition.constBegin(); it != condition.constEnd(); ++it) {
        if (!it.value().toStringList().contains(valueText(values.value(it.key()))))
            return false;
    }
    return true;
}

bool isTextId(const QJsonValue &value, const QSet<QString> &known)
{
    return value.isString() && known.contains(value.toString());
}

Result checkCondition(const QJsonValue &value, const QSet<QString> &keys, const QString &where)
{
    if (value.isUndefined())
        return Result::success();
    if (!value.isObject())
        return invalid(where + QStringLiteral(": condition is not an object"));
    const QJsonObject condition = value.toObject();
    for (auto it = condition.constBegin(); it != condition.constEnd(); ++it) {
        if (it.key() != QLatin1String(KeyAuthMode) && !keys.contains(it.key()))
            return invalid(where + QStringLiteral(": condition on unknown key ") + it.key());
        if (!it.value().isArray() || it.value().toArray().isEmpty())
            return invalid(where + QStringLiteral(": condition values must be a non-empty list"));
    }
    return Result::success();
}

Result checkServices(const QJsonObject &descriptor)
{
    const QJsonArray services = descriptor.value(QStringLiteral("services")).toArray();
    if (services.isEmpty())
        return invalid(QStringLiteral("no services"));
    QSet<QString> seen;
    for (const QJsonValue &service : services) {
        const QString id = service.toString();
        if (!list({ "backup", "files" }).contains(id) || seen.contains(id))
            return invalid(QStringLiteral("bad service ") + id);
        seen.insert(id);
    }
    return Result::success();
}

Result checkAuthMode(const QJsonObject &mode, const QSet<QString> &known)
{
    const QString id = mode.value(QStringLiteral("id")).toString();
    if (!list({ "password", "publickey", "interactive", "token" }).contains(id))
        return invalid(QStringLiteral("bad auth mode ") + id);
    if (!list({ "password", "token", "key", "none" }).contains(mode.value(QStringLiteral("secret")).toString()))
        return invalid(QStringLiteral("bad secret kind for ") + id);
    if (!isTextId(mode.value(QStringLiteral("label")), known))
        return invalid(QStringLiteral("unknown label for auth mode ") + id);
    const QJsonValue source = mode.value(QStringLiteral("source"));
    if (!source.isUndefined() && (id != QLatin1String("publickey")
                                  || !list({ "generate", "import" }).contains(source.toString())))
        return invalid(QStringLiteral("bad key source for ") + id);
    return Result::success();
}

Result checkAuthModes(const QJsonObject &descriptor, const QSet<QString> &known)
{
    const QJsonArray modes = descriptor.value(QStringLiteral("authModes")).toArray();
    if (modes.isEmpty())
        return invalid(QStringLiteral("no auth modes"));
    for (const QJsonValue &mode : modes) {
        if (const Result r = checkAuthMode(mode.toObject(), known); !r.ok())
            return r;
    }
    return Result::success();
}

Result checkChoices(const QJsonObject &field, const QSet<QString> &known, const QString &key)
{
    const QJsonArray choices = field.value(QStringLiteral("choices")).toArray();
    const bool isChoice = field.value(QStringLiteral("type")).toString() == QLatin1String(TypeChoice);
    if (!isChoice)
        return field.contains(QStringLiteral("choices")) ? invalid(key + QStringLiteral(": choices on a non-choice"))
                                                         : Result::success();
    if (choices.isEmpty())
        return invalid(key + QStringLiteral(": no choices"));
    QStringList values;
    for (const QJsonValue &choice : choices) {
        const QJsonObject object = choice.toObject();
        if (!object.value(QStringLiteral("value")).isString() || !isTextId(object.value(QStringLiteral("label")), known))
            return invalid(key + QStringLiteral(": bad choice"));
        values << object.value(QStringLiteral("value")).toString();
    }
    const QJsonValue def = field.value(QStringLiteral("default"));
    if (!def.isUndefined() && !values.contains(def.toString()))
        return invalid(key + QStringLiteral(": default is not a choice"));
    return Result::success();
}

Result checkFieldTexts(const QJsonObject &field, const QSet<QString> &known, const QString &key)
{
    if (!isTextId(field.value(QStringLiteral("label")), known))
        return invalid(key + QStringLiteral(": unknown label"));
    for (const QString &optional : { QStringLiteral("description"), QStringLiteral("placeholder") }) {
        const QJsonValue value = field.value(optional);
        if (!value.isUndefined() && !isTextId(value, known))
            return invalid(key + QStringLiteral(": unknown ") + optional);
    }
    return Result::success();
}

Result checkFieldShape(const QJsonObject &field, const QString &key)
{
    const QString type = field.value(QStringLiteral("type")).toString();
    if (!list({ TypeText, TypeSwitch, TypeChoice, TypeNote }).contains(type))
        return invalid(key + QStringLiteral(": bad type ") + type);
    const QJsonValue def = field.value(QStringLiteral("default"));
    if (!def.isUndefined() && (type == QLatin1String(TypeSwitch) ? !def.isBool() : !def.isString()))
        return invalid(key + QStringLiteral(": default has the wrong type"));
    const QJsonValue rule = field.value(QStringLiteral("validation"));
    if (!rule.isUndefined()
            && !list({ "host", "port", "userName", "share", "folder", "path", "consent" }).contains(rule.toString()))
        return invalid(key + QStringLiteral(": unknown validation ") + rule.toString());
    const QJsonValue input = field.value(QStringLiteral("input"));
    if (!input.isUndefined() && !list({ "url", "digits", "text" }).contains(input.toString()))
        return invalid(key + QStringLiteral(": bad input"));
    const QJsonValue service = field.value(QStringLiteral("service"));
    if (!service.isUndefined() && !list({ "backup", "files" }).contains(service.toString()))
        return invalid(key + QStringLiteral(": bad service"));
    if (!service.isUndefined() && isConnectionKey(key))
        return invalid(key + QStringLiteral(": a connection key cannot be a service setting"));
    return Result::success();
}

Result checkFields(const QJsonObject &descriptor, const QSet<QString> &known)
{
    const QJsonValue value = descriptor.value(QStringLiteral("fields"));
    if (!value.isArray())
        return invalid(QStringLiteral("no fields"));
    static const QRegularExpression keyPattern(QStringLiteral("^[a-z][a-z_]*$"));
    QSet<QString> keys;
    for (const QJsonValue &item : value.toArray()) {
        const QJsonObject field = item.toObject();
        const QString key = field.value(QStringLiteral("key")).toString();
        if (!keyPattern.match(key).hasMatch() || keys.contains(key) || key == QLatin1String(KeyAuthMode))
            return invalid(QStringLiteral("bad or duplicate key \"%1\"").arg(key));
        keys.insert(key);
        Result r = checkFieldShape(field, key);
        if (r.ok())
            r = checkFieldTexts(field, known, key);
        if (r.ok())
            r = checkChoices(field, known, key);
        if (!r.ok())
            return r;
    }
    for (const QJsonValue &item : value.toArray()) {
        const QJsonObject field = item.toObject();
        if (const Result r = checkCondition(field.value(QStringLiteral("visibleWhen")), keys,
                                            field.value(QStringLiteral("key")).toString()); !r.ok())
            return r;
    }
    return checkCondition(descriptor.value(QStringLiteral("noSecretWhen")), keys, QStringLiteral("noSecretWhen"));
}

QVariantList fieldsOf(const QVariantMap &descriptor)
{
    return descriptor.value(QStringLiteral("fields")).toList();
}

QString switchText(bool on)
{
    if (on) {
        //% "Yes"
        return qtTrId("settings-accounts-netvfs-la-yes");
    }
    //% "No"
    return qtTrId("settings-accounts-netvfs-la-no");
}

QString choiceLabel(const QVariantMap &field, const QString &value)
{
    for (const QVariant &choice : field.value(QStringLiteral("choices")).toList()) {
        const QVariantMap map = choice.toMap();
        if (map.value(QStringLiteral("value")).toString() == value)
            return qtTrId(map.value(QStringLiteral("label")).toString().toUtf8().constData());
    }
    return value;
}
} // namespace

ProviderDescriptors::ProviderDescriptors(QObject *parent)
    : QObject(parent)
    , m_rules(std::make_unique<InputRules>(this).release())   // owned by this (Qt parent)
{
}

ProviderDescriptors::~ProviderDescriptors() = default;

QString ProviderDescriptors::directory()
{
    const QString overridden = QString::fromLocal8Bit(qgetenv(DirectoryEnv));
    return overridden.isEmpty() ? str(DefaultDirectory) : overridden;
}

Result ProviderDescriptors::validate(const QJsonObject &descriptor, const QString &provider)
{
    if (descriptor.value(QStringLiteral("provider")).toString() != provider)
        return invalid(QStringLiteral("provider is not \"%1\"").arg(provider));
    const QJsonValue port = descriptor.value(QStringLiteral("defaultPort"));
    if (!port.isDouble() || port.toInt(-1) < 0 || port.toInt(-1) > MaxPort || port.toDouble() != port.toInt(-1))
        return invalid(QStringLiteral("bad defaultPort"));
    QSet<QString> known;
    for (const QString &id : knownTextIds())
        known.insert(id);
    Result r = checkServices(descriptor);
    if (r.ok())
        r = checkAuthModes(descriptor, known);
    if (r.ok())
        r = checkFields(descriptor, known);
    return r;
}

Result ProviderDescriptors::load(const QString &provider, QVariantMap *descriptor)
{
    static const QRegularExpression idPattern(QStringLiteral("^[a-z][a-z0-9_-]*$"));
    if (!idPattern.match(provider).hasMatch())
        return Result(Error::InvalidName, QStringLiteral("Bad provider id"));
    QFile file(QDir(directory()).filePath(provider + QStringLiteral(".json")));
    if (!file.open(QIODevice::ReadOnly))
        return Result(Error::NotFound, QStringLiteral("No descriptor for provider ") + provider);
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (!document.isObject())
        return invalid(parseError.errorString());
    const Result r = validate(document.object(), provider);
    if (r.ok() && descriptor)
        *descriptor = document.object().toVariantMap();
    return r;
}

QVariantMap ProviderDescriptors::descriptor(const QString &provider)
{
    const auto cached = m_cache.constFind(provider);
    if (cached != m_cache.constEnd())
        return cached.value();
    QVariantMap loaded;
    if (const Result r = load(provider, &loaded); !r.ok())
        qCWarning(lcNetVfsUi) << "Provider descriptor" << provider << r.toString();
    m_cache.insert(provider, loaded);
    return loaded;
}

QStringList ProviderDescriptors::providers() const
{
    QStringList result;
    const QStringList files = QDir(directory()).entryList({ QStringLiteral("*.json") }, QDir::Files, QDir::Name);
    for (const QString &file : files) {
        const QString provider = file.left(file.size() - int(sizeof(".json")) + 1);
        if (load(provider, nullptr).ok())
            result << provider;
    }
    return result;
}

QString ProviderDescriptors::text(const QString &id) const
{
    return id.isEmpty() ? QString() : qtTrId(id.toUtf8().constData());
}

QVariantMap ProviderDescriptors::initialValues(const QString &provider)
{
    const QVariantMap d = descriptor(provider);
    QVariantMap values;
    for (const QVariant &item : fieldsOf(d)) {
        const QVariantMap field = item.toMap();
        const QString type = field.value(QStringLiteral("type")).toString();
        if (type == QLatin1String(TypeNote))
            continue;
        QVariant value = field.value(QStringLiteral("default"));
        if (!value.isValid())
            value = type == QLatin1String(TypeSwitch) ? QVariant(false) : QVariant(QString());
        values.insert(field.value(QStringLiteral("key")).toString(), value);
    }
    const int port = d.value(QStringLiteral("defaultPort")).toInt();
    if (values.contains(str(KeyPort)) && values.value(str(KeyPort)).toString().isEmpty() && port > 0)
        values.insert(str(KeyPort), QString::number(port));
    const QVariantMap mode = d.value(QStringLiteral("authModes")).toList().value(0).toMap();
    values.insert(str(KeyAuthMode), mode.value(QStringLiteral("id")).toString());
    values.insert(str(KeySource), mode.value(QStringLiteral("source")).toString());
    return values;
}

bool ProviderDescriptors::isVisible(const QVariantMap &field, const QVariantMap &values,
                                    const QStringList &services) const
{
    const QString service = field.value(QStringLiteral("service")).toString();
    if (!service.isEmpty() && !services.contains(service))
        return false;
    return conditionHolds(field.value(QStringLiteral("visibleWhen")).toMap(), values);
}

QString ProviderDescriptors::ruleProblem(const QString &provider, const QString &rule, const QVariant &value) const
{
    const QString text = value.toString();
    if (rule == QLatin1String("host"))
        return m_rules->hostProblem(text);
    if (rule == QLatin1String("port"))
        return m_rules->portProblem(text);
    if (rule == QLatin1String("userName"))
        return m_rules->userNameProblem(text);
    if (rule == QLatin1String("share"))
        return m_rules->shareProblem(text);
    if (rule == QLatin1String("folder"))
        return m_rules->backupsPathProblem(provider, text);
    if (rule == QLatin1String("path"))
        return m_rules->serverPathProblem(text);
    if (rule == QLatin1String("consent") && !value.toBool()) {
        //% "Confirm that you accept the risk to continue."
        return qtTrId("settings-accounts-netvfs-la-consent_missing");
    }
    return QString();
}

QString ProviderDescriptors::problem(const QString &provider, const QVariantMap &field, const QVariantMap &values,
                                     const QStringList &services) const
{
    if (!isVisible(field, values, services))
        return QString();
    const QString rule = field.value(QStringLiteral("validation")).toString();
    if (rule.isEmpty())
        return QString();
    const QVariant value = values.value(field.value(QStringLiteral("key")).toString());
    if (field.value(QStringLiteral("optional")).toBool() && value.toString().trimmed().isEmpty())
        return QString();
    return ruleProblem(provider, rule, value);
}

bool ProviderDescriptors::isValid(const QString &provider, const QVariantMap &values, const QStringList &services)
{
    const QVariantMap d = descriptor(provider);
    if (d.isEmpty())
        return false;
    for (const QVariant &field : fieldsOf(d)) {
        if (!problem(provider, field.toMap(), values, services).isEmpty())
            return false;
    }
    return true;
}

bool ProviderDescriptors::offersService(const QString &provider, const QString &service)
{
    return descriptor(provider).value(QStringLiteral("services")).toStringList().contains(service);
}

QVariantMap ProviderDescriptors::authMode(const QString &provider, const QVariantMap &values)
{
    const QVariantList modes = descriptor(provider).value(QStringLiteral("authModes")).toList();
    const QString id = values.value(str(KeyAuthMode)).toString();
    const QString source = values.value(str(KeySource)).toString();
    for (const QVariant &item : modes) {
        const QVariantMap mode = item.toMap();
        if (mode.value(QStringLiteral("id")).toString() == id
                && mode.value(QStringLiteral("source")).toString() == source)
            return mode;
    }
    return modes.value(0).toMap();
}

QString ProviderDescriptors::secretKind(const QString &provider, const QVariantMap &values)
{
    const QVariantMap d = descriptor(provider);
    const QVariantMap noSecret = d.value(QStringLiteral("noSecretWhen")).toMap();
    if (!noSecret.isEmpty() && conditionHolds(noSecret, values))
        return str(SecretNone);
    const QString kind = authMode(provider, values).value(QStringLiteral("secret")).toString();
    return kind.isEmpty() ? str(SecretNone) : kind;
}

QVariantMap ProviderDescriptors::makeParams(const QString &provider, const QVariantMap &values,
                                            const QVariantMap &extraOptions)
{
    const QVariantMap d = descriptor(provider);
    QVariantMap options;
    QString user;
    for (const QVariant &item : fieldsOf(d)) {
        const QVariantMap field = item.toMap();
        const QString key = field.value(QStringLiteral("key")).toString();
        const bool stored = field.value(QStringLiteral("type")).toString() != QLatin1String(TypeNote)
                && !field.contains(QStringLiteral("service")) && !isConnectionKey(key);
        if (stored && isVisible(field, values, QStringList()))
            options.insert(key, values.value(key));
        if (key == QLatin1String(KeyUserName) && isVisible(field, values, QStringList()))
            user = values.value(key).toString();
    }
    if (d.value(QStringLiteral("authModes")).toList().size() > 1)
        options.insert(str(KeyAuthMode), authMode(provider, values).value(QStringLiteral("id")));
    for (auto it = extraOptions.constBegin(); it != extraOptions.constEnd(); ++it)
        options.insert(it.key(), it.value());
    ConnectionParams params;
    params.provider = provider;
    params.host = values.value(str(KeyHost)).toString().trimmed();
    if (params.host.startsWith(QLatin1Char('[')) && params.host.endsWith(QLatin1Char(']')))
        params.host = params.host.mid(1, params.host.size() - 2);
    params.port = parsePort(values.value(str(KeyPort)).toString());
    params.username = user.trimmed();
    params.options = options;
    return paramsToVariant(params);
}

QString ProviderDescriptors::serviceValue(const QString &provider, const QVariantMap &values, const QString &key)
{
    return cleanFolderPath(provider, values.value(key).toString());
}

QVariantList ProviderDescriptors::details(const QString &provider, const QVariantMap &paramsMap)
{
    const ConnectionParams params = paramsFromVariant(paramsMap);
    QVariantMap values = params.options;
    values.insert(str(KeyHost), params.host);
    values.insert(str(KeyPort), params.port > 0 ? QString::number(params.port) : QString());
    values.insert(str(KeyUserName), params.username);
    QVariantList result;
    for (const QVariant &item : fieldsOf(descriptor(provider))) {
        const QVariantMap field = item.toMap();
        const QString key = field.value(QStringLiteral("key")).toString();
        const QString type = field.value(QStringLiteral("type")).toString();
        if (type == QLatin1String(TypeNote) || field.contains(QStringLiteral("service")) || !values.contains(key)
                || !isVisible(field, values, QStringList()))
            continue;
        QString value = valueText(values.value(key));
        if (type == QLatin1String(TypeChoice))
            value = choiceLabel(field, value);
        else if (type == QLatin1String(TypeSwitch))
            value = switchText(values.value(key).toBool());
        if (value.isEmpty())
            continue;
        QVariantMap row;
        row.insert(QStringLiteral("label"), text(field.value(QStringLiteral("label")).toString()));
        row.insert(QStringLiteral("value"), value);
        result << row;
    }
    return result;
}

} // namespace NetVfsUi
