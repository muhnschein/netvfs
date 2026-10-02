# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Package split of SPEC-v2 XP-1 (amends SPEC 4.1, P-4, P-6):
#
#   netvfs-core              libnetvfs, backend folder, translations
#   netvfs-core-devel        headers, pkg-config
#   netvfs-ui                QML module org.netvfs.accounts, provider descriptors
#   netvfs-backend-<p>       one protocol plugin each (sftp, smb, webdav, ftp, local)
#   netvfs-backend-smb-shares  share enumeration helper of the SMB server mode
#   netvfs-account-<p>       provider file, account UI, icon (sftp, smb, webdav, ftp)
#   netvfs-backup-<p>        <p>-backup service, Buteo plugins and profiles (sftp, smb)
#   netvfs-files-services    <p>-files services and their service type
#   netvfs-bridge            netvfs-bridge for sandboxed consumers
#   netvfs-cli               netvfs-cli
#
# XC-1a: every package requires netvfs-core of the same build. Library
# dependencies (Qt, libaccounts-qt5, libsignon-qt5, libcurl, libdbus,
# libbuteosyncfw5) are added by rpm's automatic soname dependencies;
# tools/ci/check-rpm.sh checks the ones the split relies on.
# tools/ci/check-files.py checks that every installed file belongs to exactly
# one package.

# SPEC-v2 XM-7, XP-3: the optional share enumeration helper of the SMB
# backend (netvfs-backend-smb-shares).
%bcond_with smb_shares

Name:       netvfs
Version:    0.2.0
Release:    1
Summary:    Remote file access and backup accounts for Sailfish OS
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

%description
Remote file access over SFTP, SMB, WebDAV and FTP for Sailfish OS: account
providers in Settings > Accounts, SFTP and SMB storage targets in
Settings > Backup, and network locations for sandboxed apps.

%package core
Summary:    Remote file access library
Requires:   sailfish-version >= 5.2.0

%description core
libnetvfs: accounts, credentials, sessions and errors over pluggable protocol
backends (installed separately as netvfs-backend-*). Since 0.2 libnetvfs also
links QtNetwork, for the DNS-SD discovery of servers on the local network
(SPEC-v2 XD-1).

%package core-devel
Summary:    Development files for libnetvfs
Requires:   %{name}-core = %{version}-%{release}

%description core-devel
Headers and pkg-config file for building applications on libnetvfs.

%package ui
Summary:    Account UI components for netvfs accounts
Requires:   %{name}-core = %{version}-%{release}
Requires:   sailfishsilica-qt5
Requires:   jolla-settings-accounts
Requires:   sailfish-components-accounts-qt5
# The SSH key import page of the shared creation flow uses the system file
# picker (SPEC-sftp; the page is part of the module, so every account UI
# loads it).
Requires:   sailfish-components-pickers-qt5

%description ui
The org.netvfs.accounts QML module shared by the account UIs (connection
and server identity dialogs, settings pages, the page listing the apps that
use network locations) and the provider descriptors (SPEC-v2 XA-5).

%package backend-sftp
Summary:    SFTP backend for libnetvfs
Requires:   %{name}-core = %{version}-%{release}

%description backend-sftp
libnetvfs-sftp.so: SFTP over a statically linked libssh.

%package backend-smb
Summary:    SMB backend for libnetvfs
Requires:   %{name}-core = %{version}-%{release}

%description backend-smb
libnetvfs-smb.so: SMB 2/3 over a statically linked libsmb2, without share
enumeration (SPEC 10.2 gate G-SMB item 4, SPEC-v2 XP-3).

%if %{with smb_shares}
%package backend-smb-shares
Summary:    Share enumeration helper for the SMB backend
Requires:   %{name}-core = %{version}-%{release}
Requires:   %{name}-backend-smb = %{version}-%{release}

%description backend-smb-shares
netvfs-smb-shares (SPEC-v2 XM-7): lists the shares of an SMB server in a
process of its own, so that the DCE/RPC parser never runs inside the
backend. Optional (XP-3): without it, shares are entered by name.
%endif

%package backend-webdav
Summary:    WebDAV backend for libnetvfs
Requires:   %{name}-core = %{version}-%{release}
# SPEC-v2 XSEC-4: CURLOPT_PROTOCOLS_STR
Requires:   libcurl >= 7.85.0

%description backend-webdav
libnetvfs-webdav.so: WebDAV (SPEC-v2 6.3) over the system libcurl.

%package backend-ftp
Summary:    FTP and FTPS backend for libnetvfs
Requires:   %{name}-core = %{version}-%{release}
# SPEC-v2 XSEC-4: CURLOPT_PROTOCOLS_STR
Requires:   libcurl >= 7.85.0

%description backend-ftp
libnetvfs-ftp.so: FTP and FTPS (SPEC-v2 6.4) over the system libcurl.

%package backend-local
Summary:    Local file system backend for libnetvfs
Requires:   %{name}-core = %{version}-%{release}

%description backend-local
libnetvfs-local.so: the local file system as a netvfs location (SPEC-v2
6.5), for the command line tool and in-process consumers.

%package files-services
Summary:    Files services of the netvfs accounts
Requires:   %{name}-core = %{version}-%{release}

%description files-services
The "<provider>-files" services of type netvfs-files (SPEC-v2 XA-1) for all
netvfs providers. A service only takes effect for accounts of its provider,
so the services of providers whose netvfs-account package is not installed
stay unused.

%package account-sftp
Summary:    SFTP account
Requires:   %{name}-core = %{version}-%{release}
Requires:   %{name}-ui = %{version}-%{release}
Requires:   %{name}-backend-sftp = %{version}-%{release}
# The account UI sets up the "Files" service, the only one without backups.
Requires:   %{name}-files-services = %{version}-%{release}
# SPEC-v2 XP-2: updates from 0.1 keep the backups (see netvfs-backup-sftp).
Recommends: %{name}-backup-sftp = %{version}-%{release}

%description account-sftp
"SFTP" account provider in Settings > Accounts.

%package account-smb
Summary:    SMB account
Requires:   %{name}-core = %{version}-%{release}
Requires:   %{name}-ui = %{version}-%{release}
Requires:   %{name}-backend-smb = %{version}-%{release}
Requires:   %{name}-files-services = %{version}-%{release}
# SPEC-v2 XP-2: updates from 0.1 keep the backups (see netvfs-backup-smb).
Recommends: %{name}-backup-smb = %{version}-%{release}

%description account-smb
"SMB" account provider in Settings > Accounts.

%package account-webdav
Summary:    WebDAV account
Requires:   %{name}-core = %{version}-%{release}
Requires:   %{name}-ui = %{version}-%{release}
Requires:   %{name}-backend-webdav = %{version}-%{release}
Requires:   %{name}-files-services = %{version}-%{release}

%description account-webdav
"WebDAV" account provider in Settings > Accounts.

%package account-ftp
Summary:    FTP account
Requires:   %{name}-core = %{version}-%{release}
Requires:   %{name}-ui = %{version}-%{release}
Requires:   %{name}-backend-ftp = %{version}-%{release}
Requires:   %{name}-files-services = %{version}-%{release}

%description account-ftp
"FTP" account provider in Settings > Accounts.

%package backup-sftp
# SPEC-v2 XP-2: up to 0.1 netvfs-account-<p> contained the backup plugins.
# The Obsoletes states that this package takes them over; it does not make
# zypper or PackageKit install it on update, because the same-named
# netvfs-account-<p> 0.2 is always the preferred update of the old package.
# The Recommends of netvfs-account-<p> does: a weak dependency that is new in
# an update is installed with it (tools/ci/check-upgrade.sh checks this).
Summary:    SFTP backups
Requires:   %{name}-core = %{version}-%{release}
Requires:   %{name}-account-sftp = %{version}-%{release}
Requires:   buteo-syncfw-qt5-msyncd
Requires:   jolla-vault
Requires:   systemd
Obsoletes:  %{name}-account-sftp < 0.2.0

%description backup-sftp
SFTP accounts as storage targets in Settings > Backup: the sftp-backup
service and the Buteo backup plugins and profiles.

%package backup-smb
Summary:    SMB backups
Requires:   %{name}-core = %{version}-%{release}
Requires:   %{name}-account-smb = %{version}-%{release}
Requires:   buteo-syncfw-qt5-msyncd
Requires:   jolla-vault
Requires:   systemd
Obsoletes:  %{name}-account-smb < 0.2.0

%description backup-smb
SMB accounts as storage targets in Settings > Backup: the smb-backup service
and the Buteo backup plugins and profiles.

%package bridge
# SPEC-v2 XP-5: no backend; accounts whose backend is missing are Unsupported.
Summary:    Network locations for sandboxed apps
Requires:   %{name}-core = %{version}-%{release}
Requires:   %{name}-ui = %{version}-%{release}
Requires:   %{name}-files-services = %{version}-%{release}
Requires:   systemd

%description bridge
netvfs-bridge (SPEC-v2 8a): serves netvfs locations to registered sandboxed
consumers over a socket in their data folder, without handing out secrets.

%package cli
Summary:    Command line tool for netvfs locations
Requires:   %{name}-core = %{version}-%{release}

%description cli
netvfs-cli (SPEC-v2 11): lists, reads and writes files on netvfs locations
from the command line, for tests and diagnostics.

%prep
%setup -q -n %{name}-%{version}

%build
# SPEC P-1..P-3: vendored libraries first, static and position-independent.
./vendor/build-vendor.sh "$PWD/build-vendor"
%qmake5 -r VENDOR_PREFIX="$PWD/build-vendor" NETVFS_BUILD_TESTS=0 "VERSION=%{version}"
%make_build

%install
%qmake5_install

%post core -p /sbin/ldconfig
%postun core -p /sbin/ldconfig

# SPEC P-6: msyncd picks up new or removed plugins and profiles.
%post backup-sftp
systemctl-user try-restart msyncd.service || :

%postun backup-sftp
systemctl-user try-restart msyncd.service || :

%post backup-smb
systemctl-user try-restart msyncd.service || :

%postun backup-smb
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

%files core
%license LICENSE
%{_libdir}/libnetvfs.so.*
%dir %{_libdir}/netvfs
%dir %{_libdir}/netvfs/backends
%dir %{_prefix}/libexec/netvfs
%dir %{_datadir}/netvfs
%{_datadir}/translations/netvfs*.qm

%files core-devel
%{_includedir}/netvfs
%{_libdir}/libnetvfs.so
%{_libdir}/pkgconfig/netvfs.pc

%files ui
%dir %{_libdir}/qt5/qml/org/netvfs
%{_libdir}/qt5/qml/org/netvfs/accounts
%{_datadir}/netvfs/providers

%files backend-sftp
%{_libdir}/netvfs/backends/libnetvfs-sftp.so

%files backend-smb
%{_libdir}/netvfs/backends/libnetvfs-smb.so

%if %{with smb_shares}
%files backend-smb-shares
%{_prefix}/libexec/netvfs/netvfs-smb-shares
%endif

%files backend-webdav
%{_libdir}/netvfs/backends/libnetvfs-webdav.so

%files backend-ftp
%{_libdir}/netvfs/backends/libnetvfs-ftp.so

%files backend-local
%{_libdir}/netvfs/backends/libnetvfs-local.so

%files files-services
%{_datadir}/accounts/service_types/netvfs-files.service-type
%{_datadir}/accounts/services/sftp-files.service
%{_datadir}/accounts/services/smb-files.service
%{_datadir}/accounts/services/webdav-files.service
%{_datadir}/accounts/services/ftp-files.service

%files account-sftp
%{_datadir}/accounts/providers/sftp.provider
%{_datadir}/accounts/ui/sftp.qml
%{_datadir}/accounts/ui/sftp-settings.qml
%{_datadir}/accounts/ui/sftp-update.qml
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-sftp.png

%files account-smb
%{_datadir}/accounts/providers/smb.provider
%{_datadir}/accounts/ui/smb.qml
%{_datadir}/accounts/ui/smb-settings.qml
%{_datadir}/accounts/ui/smb-update.qml
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-smb.png

%files account-webdav
%{_datadir}/accounts/providers/webdav.provider
%{_datadir}/accounts/ui/webdav.qml
%{_datadir}/accounts/ui/webdav-settings.qml
%{_datadir}/accounts/ui/webdav-update.qml
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-webdav.png

%files account-ftp
%{_datadir}/accounts/providers/ftp.provider
%{_datadir}/accounts/ui/ftp.qml
%{_datadir}/accounts/ui/ftp-settings.qml
%{_datadir}/accounts/ui/ftp-update.qml
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-ftp.png

%files backup-sftp
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

%files backup-smb
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
%{_prefix}/lib/systemd/user-generators/netvfs-bridge-generator
%dir %{_datadir}/netvfs/consumers
%{_datadir}/netvfs/consumers/lautta.conf
%dir %{_datadir}/netvfs/bridge
%config %{_datadir}/netvfs/bridge/handoff.conf

%files cli
%{_bindir}/netvfs-cli
