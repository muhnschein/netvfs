// SPDX-License-Identifier: LGPL-2.1-or-later
#include "servicepolicy.h"

namespace NetVfs {

namespace OptionKeys {
const char HostKey[] = "host_key";
const char AuthMode[] = "auth_mode";
const char SecurityProfile[] = "security_profile";
const char Share[] = "share";
const char Shares[] = "shares";
const char ShowAdminShares[] = "show_admin_shares";
const char AllowInsecure[] = "allow_insecure";
} // namespace OptionKeys

namespace SecurityProfiles {
const char Strict[] = "strict";
const char Signed[] = "signed";
const char Legacy[] = "legacy";
const char Guest[] = "guest";
} // namespace SecurityProfiles

namespace {
const char ProviderSmb[] = "smb";
const char AuthInteractive[] = "interactive";
const char ServiceBackup[] = "backup";
const char ServiceFiles[] = "files";

QString str(const char *latin1)
{
    return QLatin1String(latin1);
}

bool isSmb(const ConnectionParams &params)
{
    return params.provider == QLatin1String(ProviderSmb);
}

bool isKnownProfile(const QString &profile)
{
    return profile == QLatin1String(SecurityProfiles::Strict) || profile == QLatin1String(SecurityProfiles::Signed)
            || profile == QLatin1String(SecurityProfiles::Legacy) || profile == QLatin1String(SecurityProfiles::Guest);
}

Result refused(const QString &reason)
{
    return Result(Error::SecurityPolicy, reason);
}

// Rows of the XA-4 table that only concern Backup.
Result checkBackup(const ConnectionParams &params, bool insecure)
{
    if (params.flag(str(OptionKeys::AllowInsecure)))
        return refused(QStringLiteral("Accounts that allow insecure connections cannot be used for backups"));
    if (insecure)
        return refused(QStringLiteral("This connection security setting cannot be used for backups"));
    if (params.option(str(OptionKeys::AuthMode)) == QLatin1String(AuthInteractive))
        return refused(QStringLiteral("Interactive sign-in cannot be used for backups"));
    if (isSmb(params) && params.option(str(OptionKeys::Share)).trimmed().isEmpty())
        return refused(QStringLiteral("SMB backups need a share"));
    return Result::success();
}
} // namespace

QString serviceName(const QString &provider, Service service)
{
    return provider + QLatin1Char('-') + serviceId(service);
}

QString serviceId(Service service)
{
    return str(service == Service::Backup ? ServiceBackup : ServiceFiles);
}

bool serviceFromId(const QString &id, Service *service)
{
    if (id == QLatin1String(ServiceBackup))
        *service = Service::Backup;
    else if (id == QLatin1String(ServiceFiles))
        *service = Service::Files;
    else
        return false;
    return true;
}

QString securityProfile(const ConnectionParams &params)
{
    if (!isSmb(params))
        return QString();
    if (const QString profile = params.option(str(OptionKeys::SecurityProfile)).trimmed(); !profile.isEmpty())
        return profile;
    return str(SecurityProfiles::Strict);
}

bool isInsecureConfiguration(const ConnectionParams &params)
{
    if (isSmb(params)) {
        const QString profile = securityProfile(params);
        return profile == QLatin1String(SecurityProfiles::Legacy) || profile == QLatin1String(SecurityProfiles::Guest);
    }
    return false;
}

Result checkServicePolicy(const ConnectionParams &params, Service service)
{
    if (isSmb(params) && !isKnownProfile(securityProfile(params)))
        return refused(QStringLiteral("Unknown SMB security profile \"%1\"").arg(securityProfile(params)));
    const bool insecure = isInsecureConfiguration(params);
    if (service == Service::Backup)
        return checkBackup(params, insecure);
    if (insecure && !params.flag(str(OptionKeys::AllowInsecure)))
        return refused(QStringLiteral("This connection security setting needs the account's consent (allow_insecure)"));
    return Result::success();
}

bool secretOptional(const ConnectionParams &params)
{
    return params.option(str(OptionKeys::AuthMode)) == QLatin1String(AuthInteractive)
            || securityProfile(params) == QLatin1String(SecurityProfiles::Guest);
}

QVariantMap pinOptions(const ServerIdentity &identity)
{
    QVariantMap options;
    if (identity.isEmpty())
        return options;
    options.insert(str(OptionKeys::HostKey), identity.toPin());
    return options;
}

} // namespace NetVfs
