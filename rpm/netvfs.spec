# SPDX-License-Identifier: LGPL-2.1-or-later

%define use_source_date_epoch_as_buildtime 1
%define clamp_mtime_to_source_date_epoch 1
%define _buildhost netvfs-build

Name:       netvfs
Version:    1.0.0
Release:    1
Summary:    Remote file access accounts for Sailfish OS
License:    LGPL-2.1-or-later
URL:        https://github.com/muhnschein/netvfs
Source0:    %{name}-%{version}.tar.bz2
ExclusiveArch: aarch64

BuildRequires: qt5-qmake
BuildRequires: qt5-qttools-linguist
BuildRequires: sailfish-svg2png
BuildRequires: pkgconfig(Qt5Core)
BuildRequires: pkgconfig(Qt5DBus)
BuildRequires: pkgconfig(Qt5Network)
BuildRequires: pkgconfig(Qt5Concurrent)
BuildRequires: pkgconfig(Qt5Qml)
BuildRequires: pkgconfig(Qt5Quick)
BuildRequires: pkgconfig(accounts-qt5)
BuildRequires: pkgconfig(libsignon-qt5)
BuildRequires: pkgconfig(buteosyncfw5) >= 0.10.0

Requires:   sailfish-version >= 5.2.0
Requires:   sailfishsilica-qt5
Requires:   jolla-settings-accounts
Requires:   sailfish-components-accounts-qt5
Requires:   sailfish-components-pickers-qt5
Requires:   ca-certificates
Recommends: %{name}-backup = %{version}-%{release}

%description
Remote file access over SFTP, SMB, WebDAV and FTPS for Sailfish OS: account
providers in Settings > Accounts, network locations for apps, and the
command line tool netvfs-cli.

libnetvfs (accounts, credentials, sessions and errors over pluggable protocol
backends) with its SFTP, SMB, WebDAV, FTPS and local file system backends;
the remote backends are Rust (libnetvfs-rs.so; SMB 3.1.1 only, WebDAV and
FTPS over TLS 1.3 only). libnetvfs also links
QtNetwork, for the DNS-SD discovery of servers on the local network.

%package devel
Summary:    Development files for libnetvfs
Requires:   %{name} = %{version}-%{release}

%description devel
Headers and pkg-config file for building applications on libnetvfs.

%package backup
Summary:    SFTP, SMB, WebDAV and FTPS backups
License:    LGPL-2.1-or-later AND BSD-3-Clause
Requires:   %{name} = %{version}-%{release}
Requires:   buteo-syncfw-qt5-msyncd
Requires:   jolla-vault
Requires:   systemd

%description backup
SFTP, SMB, WebDAV and FTPS accounts as storage targets in Settings >
Backup: the <provider>-backup services and their Buteo backup plugins and
profiles. Without this package the accounts only provide files.

%package bridge
Summary:    Network locations for sandboxed apps
Requires:   %{name} = %{version}-%{release}
Requires:   systemd
Requires(pre): sailfish-setup

%description bridge
netvfs-bridge: serves netvfs locations to registered sandboxed
consumers over a socket in their data folder, without handing out secrets.

%prep
%setup -q -n %{name}-%{version}

%build
%qmake5 -r NETVFS_BUILD_TESTS=0 "VERSION=%{version}" \
    NETVFS_RUST_PREBUILT="$PWD/rust/prebuilt"
%make_build

%install
%qmake5_install

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%post backup
systemctl-user try-restart msyncd.service || :

%postun backup
systemctl-user try-restart msyncd.service || :

%post bridge
systemctl-user daemon-reload || :
systemctl-user start sockets.target paths.target || :
systemctl-user stop 'netvfs-bridge@*.service' || :

%preun bridge
if [ "$1" -eq 0 ]; then
    systemctl-user stop 'netvfs-bridge@*.path' 'netvfs-bridge@*.socket' 'netvfs-bridge@*.service' || :
fi

%postun bridge
systemctl-user daemon-reload || :

%files
%license LICENSE
%{_libdir}/libnetvfs.so.*
%dir %{_libdir}/netvfs
%dir %{_libdir}/netvfs/backends
%{_libdir}/netvfs/backends/libnetvfs-sftp.so
%{_libdir}/netvfs/backends/libnetvfs-smb.so
%{_libdir}/netvfs/backends/libnetvfs-webdav.so
%{_libdir}/netvfs/backends/libnetvfs-ftps.so
%{_libdir}/netvfs/backends/libnetvfs-local.so
%{_libdir}/netvfs/libnetvfs-rs.so
%dir %{_prefix}/libexec/netvfs
%dir %{_datadir}/netvfs
%{_datadir}/netvfs/providers
%dir %{_libdir}/qt5/qml/org/netvfs
%{_libdir}/qt5/qml/org/netvfs/accounts
%{_datadir}/accounts/service_types/netvfs-files.service-type
%{_datadir}/accounts/services/sftp-files.service
%{_datadir}/accounts/services/smb-files.service
%{_datadir}/accounts/services/webdav-files.service
%{_datadir}/accounts/services/ftps-files.service
%{_datadir}/accounts/providers/sftp.provider
%{_datadir}/accounts/providers/smb.provider
%{_datadir}/accounts/providers/webdav.provider
%{_datadir}/accounts/providers/ftps.provider
%{_datadir}/accounts/ui/sftp.qml
%{_datadir}/accounts/ui/sftp-settings.qml
%{_datadir}/accounts/ui/sftp-update.qml
%{_datadir}/accounts/ui/smb.qml
%{_datadir}/accounts/ui/smb-settings.qml
%{_datadir}/accounts/ui/smb-update.qml
%{_datadir}/accounts/ui/webdav.qml
%{_datadir}/accounts/ui/webdav-settings.qml
%{_datadir}/accounts/ui/webdav-update.qml
%{_datadir}/accounts/ui/ftps.qml
%{_datadir}/accounts/ui/ftps-settings.qml
%{_datadir}/accounts/ui/ftps-update.qml
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-sftp.png
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-smb.png
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-webdav.png
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-ftps.png
%{_datadir}/translations/netvfs*.qm
%{_bindir}/netvfs-cli

%files devel
%{_includedir}/netvfs
%{_libdir}/libnetvfs.so
%{_libdir}/pkgconfig/netvfs.pc

%files backup
%license src/buteo/lib/BSD-3-Clause.txt
%{_datadir}/accounts/services/sftp-backup.service
%{_libdir}/buteo-plugins-qt5/oopp/libsftp-backup-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libsftp-backupquery-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libsftp-backuprestore-client.so
%config %{_sysconfdir}/buteo/profiles/client/sftp-backup.xml
%config %{_sysconfdir}/buteo/profiles/client/sftp-backupquery.xml
%config %{_sysconfdir}/buteo/profiles/client/sftp-backuprestore.xml
%config %{_sysconfdir}/buteo/profiles/sync/sftp.Backup.xml
%config %{_sysconfdir}/buteo/profiles/sync/sftp.BackupQuery.xml
%config %{_sysconfdir}/buteo/profiles/sync/sftp.BackupRestore.xml
%{_datadir}/accounts/services/smb-backup.service
%{_libdir}/buteo-plugins-qt5/oopp/libsmb-backup-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libsmb-backupquery-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libsmb-backuprestore-client.so
%config %{_sysconfdir}/buteo/profiles/client/smb-backup.xml
%config %{_sysconfdir}/buteo/profiles/client/smb-backupquery.xml
%config %{_sysconfdir}/buteo/profiles/client/smb-backuprestore.xml
%config %{_sysconfdir}/buteo/profiles/sync/smb.Backup.xml
%config %{_sysconfdir}/buteo/profiles/sync/smb.BackupQuery.xml
%config %{_sysconfdir}/buteo/profiles/sync/smb.BackupRestore.xml
%{_datadir}/accounts/services/webdav-backup.service
%{_libdir}/buteo-plugins-qt5/oopp/libwebdav-backup-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libwebdav-backupquery-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libwebdav-backuprestore-client.so
%config %{_sysconfdir}/buteo/profiles/client/webdav-backup.xml
%config %{_sysconfdir}/buteo/profiles/client/webdav-backupquery.xml
%config %{_sysconfdir}/buteo/profiles/client/webdav-backuprestore.xml
%config %{_sysconfdir}/buteo/profiles/sync/webdav.Backup.xml
%config %{_sysconfdir}/buteo/profiles/sync/webdav.BackupQuery.xml
%config %{_sysconfdir}/buteo/profiles/sync/webdav.BackupRestore.xml
%{_datadir}/accounts/services/ftps-backup.service
%{_libdir}/buteo-plugins-qt5/oopp/libftps-backup-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libftps-backupquery-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libftps-backuprestore-client.so
%config %{_sysconfdir}/buteo/profiles/client/ftps-backup.xml
%config %{_sysconfdir}/buteo/profiles/client/ftps-backupquery.xml
%config %{_sysconfdir}/buteo/profiles/client/ftps-backuprestore.xml
%config %{_sysconfdir}/buteo/profiles/sync/ftps.Backup.xml
%config %{_sysconfdir}/buteo/profiles/sync/ftps.BackupQuery.xml
%config %{_sysconfdir}/buteo/profiles/sync/ftps.BackupRestore.xml

%files bridge
%{_prefix}/libexec/netvfs/netvfs-bridge
%{_libdir}/netvfs/libnetvfs-bridge-ffi.so
%attr(2755,root,privileged) %{_prefix}/libexec/netvfs/netvfs-accounts
%{_prefix}/lib/systemd/user-generators/netvfs-bridge-generator
%dir %{_datadir}/netvfs/consumers
%{_datadir}/netvfs/consumers/lautta.conf
%dir %{_datadir}/netvfs/bridge
%config %{_datadir}/netvfs/bridge/handoff.conf
%{_datadir}/jolla-settings/entries/netvfs-access.json
%{_datadir}/jolla-settings/pages/netvfs-access.qml
