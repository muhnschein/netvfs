// SPDX-License-Identifier: LGPL-2.1-or-later
// Text ids that provider descriptors (SPEC-v2 XA-5) may use. The //% texts
// put them into the translation catalogue (lupdate); ProviderDescriptors
// refuses a descriptor with any other id, so every label is translatable.
#include "providerdescriptors.h"

#include <QtCore/QtGlobal>

#include <array>

namespace NetVfsUi {

namespace {
const std::array<const char *, 56> TextIds = { {
    //% "Server"
    QT_TRID_NOOP("settings-accounts-netvfs-la-server"),
    //% "Server name or IP address"
    QT_TRID_NOOP("settings-accounts-netvfs-ph-server"),
    //% "Port"
    QT_TRID_NOOP("settings-accounts-netvfs-la-port"),
    //% "Default port"
    QT_TRID_NOOP("settings-accounts-netvfs-ph-port_default"),
    //% "Share"
    QT_TRID_NOOP("settings-accounts-netvfs-la-share"),
    //% "Name of the shared folder on the server"
    QT_TRID_NOOP("settings-accounts-netvfs-ph-share"),
    //% "Leave empty to see all shares of the server. Backups need a share."
    QT_TRID_NOOP("settings-accounts-netvfs-la-share_optional"),
    //% "User name"
    QT_TRID_NOOP("settings-accounts-netvfs-la-user"),
    //% "Domain or workgroup (optional)"
    QT_TRID_NOOP("settings-accounts-netvfs-la-domain"),
    //% "Backups folder"
    QT_TRID_NOOP("settings-accounts-netvfs-la-backups_folder"),
    //% "Inside the share."
    QT_TRID_NOOP("settings-accounts-netvfs-la-folder_in_share"),
    //% "Relative to the home folder, or starting with / for an absolute path."
    QT_TRID_NOOP("settings-accounts-netvfs-la-folder_in_home"),
    //% "Relative to the server path."
    QT_TRID_NOOP("settings-accounts-netvfs-la-folder_in_base"),
    //% "Start folder"
    QT_TRID_NOOP("settings-accounts-netvfs-la-files_root"),
    //% "Password"
    QT_TRID_NOOP("settings-accounts-netvfs-me-password"),
    //% "SSH key: generate a new key"
    QT_TRID_NOOP("settings-accounts-netvfs-me-key_generate"),
    //% "SSH key: import a key file"
    QT_TRID_NOOP("settings-accounts-netvfs-me-key_import"),
    //% "Ask each time (one-time codes)"
    QT_TRID_NOOP("settings-accounts-netvfs-me-interactive"),
    //% "Access token"
    QT_TRID_NOOP("settings-accounts-netvfs-me-token"),
    //% "Use a strong password that you use nowhere else: any server this account connects to can try to guess it."
    QT_TRID_NOOP("settings-accounts-netvfs-la-smb_password_warning"),
    //% "After checking the server's identity you can copy the public key, or install it on the server with your password."
    QT_TRID_NOOP("settings-accounts-netvfs-la-key_mode_hint"),
    //% "The server asks for the password or a one-time code whenever files are browsed. Such an account cannot be used for backups."
    QT_TRID_NOOP("settings-accounts-netvfs-la-interactive_hint"),
    //% "Connection security"
    QT_TRID_NOOP("settings-accounts-netvfs-la-security_profile"),
    //% "Signed and encrypted (SMB 3)"
    QT_TRID_NOOP("settings-accounts-netvfs-me-profile_strict"),
    //% "Signed, encrypted when the server offers it (SMB 3)"
    QT_TRID_NOOP("settings-accounts-netvfs-me-profile_signed"),
    //% "Signed, older servers (SMB 2)"
    QT_TRID_NOOP("settings-accounts-netvfs-me-profile_legacy"),
    //% "Guest, without signing in"
    QT_TRID_NOOP("settings-accounts-netvfs-me-profile_guest"),
    //% "Show administrative shares"
    QT_TRID_NOOP("settings-accounts-netvfs-la-show_admin_shares"),
    //% "Shares whose name ends in $, such as C$."
    QT_TRID_NOOP("settings-accounts-netvfs-la-show_admin_shares_description"),
    //% "Allow an insecure connection"
    QT_TRID_NOOP("settings-accounts-netvfs-la-allow_insecure"),
    //% "Older SMB servers are not encrypted, and guest connections are not signed either: others on the network can read or change files. Never used for backups."
    QT_TRID_NOOP("settings-accounts-netvfs-la-allow_insecure_smb"),
    //% "Plain HTTP is not encrypted: others on the network can read the password and the files. Never used for backups."
    QT_TRID_NOOP("settings-accounts-netvfs-la-allow_insecure_http"),
    //% "FTP without TLS sends the password and the files unencrypted. Never used for backups."
    QT_TRID_NOOP("settings-accounts-netvfs-la-allow_insecure_ftp"),
    //% "Connection"
    QT_TRID_NOOP("settings-accounts-netvfs-la-tls"),
    //% "Encrypted (HTTPS)"
    QT_TRID_NOOP("settings-accounts-netvfs-me-tls_https"),
    //% "Not encrypted (HTTP)"
    QT_TRID_NOOP("settings-accounts-netvfs-me-tls_http"),
    //% "Path on the server"
    QT_TRID_NOOP("settings-accounts-netvfs-la-base_path"),
    //% "The WebDAV folder, for example /remote.php/dav/files/<user>/ on Nextcloud."
    QT_TRID_NOOP("settings-accounts-netvfs-la-base_path_description"),
    //% "Server type"
    QT_TRID_NOOP("settings-accounts-netvfs-la-flavor"),
    //% "Detect automatically"
    QT_TRID_NOOP("settings-accounts-netvfs-me-flavor_auto"),
    //% "Nextcloud or ownCloud"
    QT_TRID_NOOP("settings-accounts-netvfs-me-flavor_nextcloud"),
    //% "Other WebDAV server"
    QT_TRID_NOOP("settings-accounts-netvfs-me-flavor_generic"),
    //% "Encryption"
    QT_TRID_NOOP("settings-accounts-netvfs-la-tls_mode"),
    //% "TLS (explicit, usually port 21)"
    QT_TRID_NOOP("settings-accounts-netvfs-me-tls_explicit"),
    //% "TLS (implicit, usually port 990)"
    QT_TRID_NOOP("settings-accounts-netvfs-me-tls_implicit"),
    //% "None (plain FTP)"
    QT_TRID_NOOP("settings-accounts-netvfs-me-tls_none"),
    //% "Confirm trusted certificates too"
    QT_TRID_NOOP("settings-accounts-netvfs-la-pin_trusted"),
    //% "Also asks you to confirm a certificate that this device trusts, and accepts only that certificate later. Public certificates are replaced regularly, so you will be asked again then."
    QT_TRID_NOOP("settings-accounts-netvfs-la-pin_trusted_description"),
    //% "Allow commands on the server"
    QT_TRID_NOOP("settings-accounts-netvfs-la-allow_shell"),
    //% "Lets file browsing copy files on the server and compute checksums with shell commands. Never used for backups."
    QT_TRID_NOOP("settings-accounts-netvfs-la-allow_shell_description"),
    //% "Inside the share, or /share/folder when no share is set."
    QT_TRID_NOOP("settings-accounts-netvfs-la-files_root_smb"),
    //% "Accounts on this server are created by its administrator. Ask for an app password if the server uses two-step verification."
    QT_TRID_NOOP("settings-accounts-netvfs-la-webdav_password_hint"),
    //% "Create the token in the server's web interface, for example under Security in Nextcloud."
    QT_TRID_NOOP("settings-accounts-netvfs-la-token_hint"),
    //% "Leave empty for the home folder."
    QT_TRID_NOOP("settings-accounts-netvfs-la-files_root_home"),
    //% "Guests can only use shares that the server opens to everyone."
    QT_TRID_NOOP("settings-accounts-netvfs-la-guest_hint"),
    //% "Encrypted and signed connections are used by default. Change this only if the server cannot do better."
    QT_TRID_NOOP("settings-accounts-netvfs-la-security_profile_description"),
} };
} // namespace

QStringList ProviderDescriptors::knownTextIds()
{
    QStringList ids;
    for (const char *id : TextIds)
        ids << QLatin1String(id);
    return ids;
}

} // namespace NetVfsUi
