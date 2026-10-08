# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Packages of SPEC-v2 XP-1 (amends SPEC 4.1, P-4, P-6):
#
#   netvfs          libnetvfs, all protocol backends and the SMB share helper,
#                   the account UI module, the account providers, the Files
#                   services, netvfs-cli, translations
#   netvfs-backup   SFTP and SMB backups: services, Buteo plugins and profiles
#   netvfs-bridge   netvfs-bridge and its setgid accounts helper, for
#                   sandboxed consumers
#   netvfs-devel    headers, pkg-config
#
# Since 0.3 the parts nobody installs on their own are one package; what
# stays separate pulls in something the rest does not need (Buteo, a setgid
# binary) or is only for development (XP-6).
#
# XC-1a: every package requires netvfs of the same build. Library
# dependencies (Qt, libaccounts-qt5, libsignon-qt5, libcurl, libdbus,
# libbuteosyncfw5) are added by rpm's automatic soname dependencies;
# tools/ci/check-rpm.sh checks the ones the split relies on.
# tools/ci/check-files.py checks that every installed file belongs to exactly
# one package.

Name:       netvfs
Version:    0.3.0
Release:    1
Summary:    Remote file access accounts for Sailfish OS
License:    LGPL-2.1-or-later
URL:        https://github.com/muhnschein/netvfs
Source0:    %{name}-%{version}.tar.bz2
# SPEC P-4
ExclusiveArch: aarch64

# SPEC P-5
BuildRequires: qt5-qmake
BuildRequires: qt5-qttools-linguist
BuildRequires: cmake
BuildRequires: openssl-devel
BuildRequires: sailfish-svg2png
BuildRequires: pkgconfig(Qt5Core)
BuildRequires: pkgconfig(Qt5DBus)
# SPEC-v2 XD-1: discovery in libnetvfs; the bridge's ad-hoc locations.
BuildRequires: pkgconfig(Qt5Network)
BuildRequires: pkgconfig(Qt5Concurrent)
BuildRequires: pkgconfig(Qt5Qml)
BuildRequires: pkgconfig(Qt5Quick)
BuildRequires: pkgconfig(accounts-qt5)
BuildRequires: pkgconfig(libsignon-qt5)
BuildRequires: pkgconfig(buteosyncfw5) >= 0.10.0
# SPEC-v2 W-1, F-1: the WebDAV and FTP backends use the system libcurl.
BuildRequires: pkgconfig(libcurl)
# SPEC-v2 XB-8: netvfs-bridge speaks peer-to-peer D-Bus through libdbus.
BuildRequires: pkgconfig(dbus-1)

Requires:   sailfish-version >= 5.2.0
Requires:   sailfishsilica-qt5
Requires:   jolla-settings-accounts
Requires:   sailfish-components-accounts-qt5
# The SSH key import page of the shared creation flow uses the system file
# picker (SPEC-sftp; the page is part of the module, so every account UI
# loads it).
Requires:   sailfish-components-pickers-qt5
# SPEC-v2 XSEC-4: CURLOPT_PROTOCOLS_STR (WebDAV and FTP backends)
Requires:   libcurl >= 7.85.0
# SPEC-v2 XP-2: updates keep the backups (see netvfs-backup).
Recommends: %{name}-backup = %{version}-%{release}
# SPEC-v2 XP-6: the packages of 0.2 that this one replaces.
Provides:   %{name}-core = %{version}-%{release}
Obsoletes:  %{name}-core < 0.3.0
Provides:   %{name}-ui = %{version}-%{release}
Obsoletes:  %{name}-ui < 0.3.0
Provides:   %{name}-backend-sftp = %{version}-%{release}
Obsoletes:  %{name}-backend-sftp < 0.3.0
Provides:   %{name}-backend-smb = %{version}-%{release}
Obsoletes:  %{name}-backend-smb < 0.3.0
Provides:   %{name}-backend-smb-shares = %{version}-%{release}
Obsoletes:  %{name}-backend-smb-shares < 0.3.0
Provides:   %{name}-backend-webdav = %{version}-%{release}
Obsoletes:  %{name}-backend-webdav < 0.3.0
Provides:   %{name}-backend-ftp = %{version}-%{release}
Obsoletes:  %{name}-backend-ftp < 0.3.0
Provides:   %{name}-backend-local = %{version}-%{release}
Obsoletes:  %{name}-backend-local < 0.3.0
Provides:   %{name}-files-services = %{version}-%{release}
Obsoletes:  %{name}-files-services < 0.3.0
Provides:   %{name}-account-sftp = %{version}-%{release}
Obsoletes:  %{name}-account-sftp < 0.3.0
Provides:   %{name}-account-smb = %{version}-%{release}
Obsoletes:  %{name}-account-smb < 0.3.0
Provides:   %{name}-account-webdav = %{version}-%{release}
Obsoletes:  %{name}-account-webdav < 0.3.0
Provides:   %{name}-account-ftp = %{version}-%{release}
Obsoletes:  %{name}-account-ftp < 0.3.0
Provides:   %{name}-cli = %{version}-%{release}
Obsoletes:  %{name}-cli < 0.3.0

%description
Remote file access over SFTP, SMB, WebDAV and FTP for Sailfish OS: account
providers in Settings > Accounts, network locations for apps, and the
command line tool netvfs-cli.

libnetvfs (accounts, credentials, sessions and errors over pluggable protocol
backends) with its SFTP, SMB, WebDAV, FTP and local file system backends. SMB
share enumeration runs in a helper process of its own (SPEC-v2 XM-7), so the
DCE/RPC parser never runs inside the SMB backend. Since 0.2 libnetvfs also
links QtNetwork, for the DNS-SD discovery of servers on the local network
(SPEC-v2 XD-1).

%package devel
Summary:    Development files for libnetvfs
Requires:   %{name} = %{version}-%{release}
Provides:   %{name}-core-devel = %{version}-%{release}
Obsoletes:  %{name}-core-devel < 0.3.0

%description devel
Headers and pkg-config file for building applications on libnetvfs.

%package backup
# SPEC-v2 XP-2: up to 0.1 netvfs-account-<p> contained the backup plugins,
# in 0.2 netvfs-backup-<p>. The Obsoletes state that this package takes them
# over; on update from 0.1 or 0.2 zypper and PackageKit install it because
# the Recommends of netvfs is new to them: a weak dependency that is new in
# an update is installed with it (tools/ci/check-upgrade.sh checks this).
Summary:    SFTP and SMB backups
Requires:   %{name} = %{version}-%{release}
Requires:   buteo-syncfw-qt5-msyncd
Requires:   jolla-vault
Requires:   systemd
Provides:   %{name}-backup-sftp = %{version}-%{release}
Provides:   %{name}-backup-smb = %{version}-%{release}
Obsoletes:  %{name}-backup-sftp < 0.3.0
Obsoletes:  %{name}-backup-smb < 0.3.0

%description backup
SFTP and SMB accounts as storage targets in Settings > Backup: the
sftp-backup and smb-backup services and their Buteo backup plugins and
profiles. Without this package the accounts only provide files.

%package bridge
# SPEC-v2 XP-5: separate, so that only devices with a sandboxed consumer get
# the setgid accounts helper; nothing requires it.
Summary:    Network locations for sandboxed apps
Requires:   %{name} = %{version}-%{release}
Requires:   systemd
# SPEC-v2 XB-2a: the group `privileged` of the setgid accounts helper (as
# mapplauncherd's boosters).
Requires(pre): sailfish-setup

%description bridge
netvfs-bridge (SPEC-v2 8a): serves netvfs locations to registered sandboxed
consumers over a socket in their data folder, without handing out secrets.

%prep
%setup -q -n %{name}-%{version}

%build
# SPEC P-1..P-3: vendored libraries first, static and position-independent.
./vendor/build-vendor.sh "$PWD/build-vendor"
%qmake5 -r VENDOR_PREFIX="$PWD/build-vendor" NETVFS_BUILD_TESTS=0 "VERSION=%{version}"
%make_build

%install
%qmake5_install

# Script bodies, not "-p /sbin/ldconfig": rpm passes the count of
# installed instances to a -p program as an argument, and ldconfig takes
# "1" for a folder and fails (0.1.0 did this; its removal script fails
# on update).
%post
/sbin/ldconfig

%postun
/sbin/ldconfig

# SPEC P-6: msyncd picks up new or removed plugins and profiles.
%post backup
systemctl-user try-restart msyncd.service || :

%postun backup
systemctl-user try-restart msyncd.service || :

# XB-3: the generator turns the consumer files into units on daemon-reload;
# starting the targets again starts the socket and path units they now want.
%post bridge
systemctl-user daemon-reload || :
systemctl-user start sockets.target paths.target || :

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
%{_libdir}/netvfs/backends/libnetvfs-ftp.so
%{_libdir}/netvfs/backends/libnetvfs-local.so
%dir %{_prefix}/libexec/netvfs
%{_prefix}/libexec/netvfs/netvfs-smb-shares
%dir %{_datadir}/netvfs
%{_datadir}/netvfs/providers
%dir %{_libdir}/qt5/qml/org/netvfs
%{_libdir}/qt5/qml/org/netvfs/accounts
%{_datadir}/accounts/service_types/netvfs-files.service-type
%{_datadir}/accounts/services/sftp-files.service
%{_datadir}/accounts/services/smb-files.service
%{_datadir}/accounts/services/webdav-files.service
%{_datadir}/accounts/services/ftp-files.service
%{_datadir}/accounts/providers/sftp.provider
%{_datadir}/accounts/providers/smb.provider
%{_datadir}/accounts/providers/webdav.provider
%{_datadir}/accounts/providers/ftp.provider
%{_datadir}/accounts/ui/sftp.qml
%{_datadir}/accounts/ui/sftp-settings.qml
%{_datadir}/accounts/ui/sftp-update.qml
%{_datadir}/accounts/ui/smb.qml
%{_datadir}/accounts/ui/smb-settings.qml
%{_datadir}/accounts/ui/smb-update.qml
%{_datadir}/accounts/ui/webdav.qml
%{_datadir}/accounts/ui/webdav-settings.qml
%{_datadir}/accounts/ui/webdav-update.qml
%{_datadir}/accounts/ui/ftp.qml
%{_datadir}/accounts/ui/ftp-settings.qml
%{_datadir}/accounts/ui/ftp-update.qml
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-sftp.png
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-smb.png
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-webdav.png
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-ftp.png
%{_datadir}/translations/netvfs*.qm
%{_bindir}/netvfs-cli

%files devel
%{_includedir}/netvfs
%{_libdir}/libnetvfs.so
%{_libdir}/pkgconfig/netvfs.pc

%files backup
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

%files bridge
%{_prefix}/libexec/netvfs/netvfs-bridge
# SPEC-v2 XB-2a: only the group `privileged` can read the accounts database.
%attr(2755,root,privileged) %{_prefix}/libexec/netvfs/netvfs-accounts
%{_prefix}/lib/systemd/user-generators/netvfs-bridge-generator
%dir %{_datadir}/netvfs/consumers
%{_datadir}/netvfs/consumers/lautta.conf
%dir %{_datadir}/netvfs/bridge
%config %{_datadir}/netvfs/bridge/handoff.conf

