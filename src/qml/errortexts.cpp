// SPDX-License-Identifier: LGPL-2.1-or-later
#include "errortexts.h"

using namespace NetVfs;

namespace NetVfsUi {

namespace {
// Files verify (SPEC-v2-review 2.19): nothing is written, so the backup
// wording does not apply.
QString browseText(Error error)
{
    switch (error) {
    case Error::PermissionDenied:
        //% "The server does not allow reading the start folder."
        return qtTrId("settings-accounts-netvfs-la-error_browse_permission");
    case Error::NotFound:
        //% "The start folder was not found on the server."
        return qtTrId("settings-accounts-netvfs-la-error_browse_not_found");
    case Error::NotADirectory:
        //% "The start folder on the server is not a folder."
        return qtTrId("settings-accounts-netvfs-la-error_browse_not_a_folder");
    default:
        return QString();
    }
}

// Errors whose meaning depends on the activity; empty when the generic text applies.
QString activityText(Error error, Activity activity)
{
    if (activity == Activity::Browse)
        return browseText(error);
    if (activity == Activity::ServicePolicy && error == Error::SecurityPolicy) {
        //% "These settings cannot be used for backups. Backups need an encrypted and signed connection, a share and a sign-in that works without you."
        return qtTrId("settings-accounts-netvfs-la-error_service_policy_backup");
    }
    if (activity == Activity::StoredSecret && error == Error::AuthFailed) {
        //% "The stored password or key for this account could not be read. Update the sign-in details."
        return qtTrId("settings-accounts-netvfs-la-error_stored_secret");
    }
    if (activity == Activity::InstallKey && error == Error::AuthFailed) {
        //% "The server did not accept the password, so the key could not be installed."
        return qtTrId("settings-accounts-netvfs-la-error_install_auth");
    }
    if (activity == Activity::KeyFile && error == Error::Unsupported) {
        //% "This key type is not supported. Use an Ed25519, ECDSA or RSA (2048 bits or more) key without a certificate."
        return qtTrId("settings-accounts-netvfs-la-error_key_unsupported");
    }
    if (activity == Activity::KeyFile && error == Error::AuthFailed) {
        //% "The passphrase is not correct."
        return qtTrId("settings-accounts-netvfs-la-error_key_passphrase");
    }
    if (activity == Activity::KeyFile) {
        //% "The file could not be read as a private key."
        return qtTrId("settings-accounts-netvfs-la-error_key_file");
    }
    return QString();
}

QString genericText(Error error)
{
    switch (error) {
    case Error::None:
        return QString();
    case Error::Canceled:
        //% "The operation was canceled."
        return qtTrId("settings-accounts-netvfs-la-error_canceled");
    case Error::NetworkUnreachable:
        //% "Cannot reach the server. Check the server name, the port and the network connection."
        return qtTrId("settings-accounts-netvfs-la-error_unreachable");
    case Error::Timeout:
        //% "The server did not respond in time."
        return qtTrId("settings-accounts-netvfs-la-error_timeout");
    case Error::ServerIdentityUnknown:
        //% "The identity of the server has not been confirmed."
        return qtTrId("settings-accounts-netvfs-la-error_identity_unknown");
    case Error::ServerIdentityChanged:
        //% "The server presented a different identity than the one stored for this account. It may have been reinstalled, or someone may be intercepting the connection."
        return qtTrId("settings-accounts-netvfs-la-error_identity_changed");
    case Error::AuthFailed:
        //% "The server refused the sign-in. Check the user name and the password or key."
        return qtTrId("settings-accounts-netvfs-la-error_auth_failed");
    case Error::SecurityPolicy:
        //% "The server does not meet the security requirements of this account, for example because it offers no modern encryption."
        return qtTrId("settings-accounts-netvfs-la-error_security_policy");
    case Error::PermissionDenied:
        //% "The server does not allow writing to the backups folder."
        return qtTrId("settings-accounts-netvfs-la-error_permission");
    case Error::NotFound:
        //% "Not found on the server. Check the share name and the backups folder."
        return qtTrId("settings-accounts-netvfs-la-error_not_found");
    case Error::AlreadyExists:
        //% "Something that is not a folder already exists in place of the backups folder."
        return qtTrId("settings-accounts-netvfs-la-error_exists");
    case Error::NoSpace:
        //% "There is not enough free space on the server."
        return qtTrId("settings-accounts-netvfs-la-error_no_space");
    case Error::Unsupported:
        //% "The server does not support a feature that backups need."
        return qtTrId("settings-accounts-netvfs-la-error_unsupported");
    case Error::ProtocolError:
        //% "The server reported an error."
        return qtTrId("settings-accounts-netvfs-la-error_protocol");
    case Error::ConnectionLost:
        //% "The connection to the server was lost."
        return qtTrId("settings-accounts-netvfs-la-error_connection_lost");
    case Error::NotADirectory:
        //% "A part of the folder path on the server is not a folder."
        return qtTrId("settings-accounts-netvfs-la-error_not_a_directory");
    case Error::IsADirectory:
        //% "A folder on the server is in the way of a file."
        return qtTrId("settings-accounts-netvfs-la-error_is_a_directory");
    case Error::DirectoryNotEmpty:
        //% "The folder on the server is not empty."
        return qtTrId("settings-accounts-netvfs-la-error_directory_not_empty");
    case Error::InvalidName:
        //% "The server does not accept this name."
        return qtTrId("settings-accounts-netvfs-la-error_invalid_name");
    case Error::ReadOnlyFilesystem:
        //% "The storage on the server is read-only."
        return qtTrId("settings-accounts-netvfs-la-error_read_only");
    case Error::Locked:
        //% "The file is in use on the server."
        return qtTrId("settings-accounts-netvfs-la-error_locked");
    case Error::TooManyConnections:
        //% "The server does not accept more connections right now."
        return qtTrId("settings-accounts-netvfs-la-error_too_many_connections");
    case Error::RateLimited:
        //% "The server asks to wait before trying again."
        return qtTrId("settings-accounts-netvfs-la-error_rate_limited");
    case Error::NotModified:
        //% "The server reported no change."
        return qtTrId("settings-accounts-netvfs-la-error_not_modified");
    case Error::Internal:
        break;
    }
    //% "Something went wrong on this device."
    return qtTrId("settings-accounts-netvfs-la-error_internal");
}
} // namespace

QString userErrorText(Error error, Activity activity)
{
    if (error == Error::None)
        return QString();
    const QString specific = activityText(error, activity);
    return specific.isEmpty() ? genericText(error) : specific;
}

QString backendMissingText()
{
    //% "Support for this kind of server is not installed on this device."
    return qtTrId("settings-accounts-netvfs-la-error_backend_missing");
}

} // namespace NetVfsUi
