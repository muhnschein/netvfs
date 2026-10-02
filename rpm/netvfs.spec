# SPDX-License-Identifier: LGPL-2.1-or-later

Name:       netvfs
Version:    0.2.0
Release:    1
Summary:    SFTP and SMB backup accounts for Sailfish OS
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
BuildRequires: pkgconfig(Qt5Concurrent)
BuildRequires: pkgconfig(Qt5Qml)
BuildRequires: pkgconfig(Qt5Quick)
BuildRequires: pkgconfig(accounts-qt5)
BuildRequires: pkgconfig(libsignon-qt5)
BuildRequires: pkgconfig(buteosyncfw5) >= 0.10.0

%description
Adds "SFTP" and "SMB" account providers to Settings > Accounts that appear as
storage targets in Settings > Backup.

%package core
Summary:    Remote file access library and account UI components
Requires:   sailfish-version >= 5.2.0

%description core
libnetvfs (accounts, credentials, sessions, errors over pluggable protocol
backends) and the org.netvfs.accounts QML module used by the account UIs.

%package core-devel
Summary:    Development files for libnetvfs
Requires:   %{name}-core = %{version}-%{release}

%description core-devel
Headers and pkg-config file for building applications on libnetvfs.

%package account-sftp
Summary:    SFTP backup account
Requires:   %{name}-core = %{version}-%{release}
Requires:   sailfish-version >= 5.2.0
Requires:   jolla-settings-accounts
Requires:   jolla-vault
Requires:   buteo-syncfw-qt5-msyncd
Requires:   sailfish-components-accounts-qt5
Requires:   systemd

# The SSH key import page uses the system file picker.
Requires:   sailfish-components-pickers-qt5

%description account-sftp
SFTP account provider, backend (statically linked libssh) and Buteo backup
plugins.

%package account-smb
Summary:    SMB backup account
Requires:   %{name}-core = %{version}-%{release}
Requires:   sailfish-version >= 5.2.0
Requires:   jolla-settings-accounts
Requires:   jolla-vault
Requires:   buteo-syncfw-qt5-msyncd
Requires:   sailfish-components-accounts-qt5
Requires:   systemd

%description account-smb
SMB 3 account provider, backend (statically linked libsmb2) and Buteo backup
plugins.

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

# SPEC P-6
%post account-sftp
systemctl-user try-restart msyncd.service || :

%postun account-sftp
systemctl-user try-restart msyncd.service || :

%post account-smb
systemctl-user try-restart msyncd.service || :

%postun account-smb
systemctl-user try-restart msyncd.service || :

%files core
%license LICENSE
%{_libdir}/libnetvfs.so.*
%dir %{_libdir}/netvfs
%dir %{_libdir}/netvfs/backends
%{_libdir}/qt5/qml/org/netvfs/accounts
%{_datadir}/translations/netvfs*.qm

%files core-devel
%{_includedir}/netvfs
%{_libdir}/libnetvfs.so
%{_libdir}/pkgconfig/netvfs.pc

%files account-sftp
%{_libdir}/netvfs/backends/libnetvfs-sftp.so
%{_datadir}/accounts/providers/sftp.provider
%{_datadir}/accounts/services/sftp-backup.service
%{_datadir}/accounts/ui/sftp.qml
%{_datadir}/accounts/ui/sftp-settings.qml
%{_datadir}/accounts/ui/sftp-update.qml
%{_libdir}/buteo-plugins-qt5/oopp/libsftp-backup-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libsftp-backupquery-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libsftp-backuprestore-client.so
%config %{_sysconfdir}/buteo/profiles/client/sftp-backup.xml
%config %{_sysconfdir}/buteo/profiles/client/sftp-backupquery.xml
%config %{_sysconfdir}/buteo/profiles/client/sftp-backuprestore.xml
%config %{_sysconfdir}/buteo/profiles/sync/sftp.Backup.xml
%config %{_sysconfdir}/buteo/profiles/sync/sftp.BackupQuery.xml
%config %{_sysconfdir}/buteo/profiles/sync/sftp.BackupRestore.xml
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-sftp.png

%files account-smb
%{_libdir}/netvfs/backends/libnetvfs-smb.so
%{_datadir}/accounts/providers/smb.provider
%{_datadir}/accounts/services/smb-backup.service
%{_datadir}/accounts/ui/smb.qml
%{_datadir}/accounts/ui/smb-settings.qml
%{_datadir}/accounts/ui/smb-update.qml
%{_libdir}/buteo-plugins-qt5/oopp/libsmb-backup-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libsmb-backupquery-client.so
%{_libdir}/buteo-plugins-qt5/oopp/libsmb-backuprestore-client.so
%config %{_sysconfdir}/buteo/profiles/client/smb-backup.xml
%config %{_sysconfdir}/buteo/profiles/client/smb-backupquery.xml
%config %{_sysconfdir}/buteo/profiles/client/smb-backuprestore.xml
%config %{_sysconfdir}/buteo/profiles/sync/smb.Backup.xml
%config %{_sysconfdir}/buteo/profiles/sync/smb.BackupQuery.xml
%config %{_sysconfdir}/buteo/profiles/sync/smb.BackupRestore.xml
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-smb.png
