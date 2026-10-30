# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Packages:
#
#   netvfs          libnetvfs, all backends, libnetvfs-rs.so (Rust backends the plugins load), account UI
#   module, account providers, Files services, netvfs-cli, translations
#   netvfs-backup   SFTP and SMB backups: services, Buteo plugins and profiles
#   netvfs-bridge   netvfs-bridge and its setgid accounts helper (Rust), for sandboxed consumers, and
#   libnetvfs-bridge-ffi.so, the C ABI through which the bridge reaches the backends
#   netvfs-devel    headers, pkg-config
#
# Parts nobody installs alone are one package; what stays separate pulls in something the rest does not need
# (Buteo, a setgid binary) or is for development.
#
# Every package requires netvfs of the same build. Library dependencies come from rpm's automatic soname
# dependencies; tools/ci/check-rpm.sh checks the ones the split relies on, tools/ci/check-files.py that every
# installed file belongs to exactly one package.

Name:       netvfs
Version:    0.6.0
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
# Discovery in libnetvfs; the bridge's ad-hoc locations.
BuildRequires: pkgconfig(Qt5Network)
BuildRequires: pkgconfig(Qt5Concurrent)
BuildRequires: pkgconfig(Qt5Qml)
BuildRequires: pkgconfig(Qt5Quick)
BuildRequires: pkgconfig(accounts-qt5)
BuildRequires: pkgconfig(libsignon-qt5)
BuildRequires: pkgconfig(buteosyncfw5) >= 0.10.0
# netvfs-bridge and its accounts helper are Rust 1.95, which no SDK target ships: CI cross-builds them and
# libnetvfs-rs.so with the SDK's compiler and sysroot before this build (tools/ci/cross-build.sh); the spec
# installs them. Bridge speaks peer-to-peer D-Bus with zbus: no libdbus needed to build.

Requires:   sailfish-version >= 5.2.0
Requires:   sailfishsilica-qt5
Requires:   jolla-settings-accounts
Requires:   sailfish-components-accounts-qt5
# SSH key import page uses the system file picker; part of the module, so every account UI loads it.
Requires:   sailfish-components-pickers-qt5
# Backups come along unless removed.
Recommends: %{name}-backup = %{version}-%{release}

%description
Remote file access over SFTP and SMB for Sailfish OS: account
providers in Settings > Accounts, network locations for apps, and the
command line tool netvfs-cli.

libnetvfs (accounts, credentials, sessions and errors over pluggable protocol
backends) with its SFTP, SMB and local file system backends; the SFTP and
SMB backends are Rust (libnetvfs-rs.so; SMB 3.1.1 only). libnetvfs also links
QtNetwork, for the DNS-SD discovery of servers on the local network.

%package devel
Summary:    Development files for libnetvfs
Requires:   %{name} = %{version}-%{release}

%description devel
Headers and pkg-config file for building applications on libnetvfs.

%package backup
Summary:    SFTP and SMB backups
Requires:   %{name} = %{version}-%{release}
Requires:   buteo-syncfw-qt5-msyncd
Requires:   jolla-vault
Requires:   systemd

%description backup
SFTP and SMB accounts as storage targets in Settings > Backup: the
sftp-backup and smb-backup services and their Buteo backup plugins and
profiles. Without this package the accounts only provide files.

%package bridge
# Separate so only devices with a sandboxed consumer get the setgid accounts helper; nothing requires it.
Summary:    Network locations for sandboxed apps
Requires:   %{name} = %{version}-%{release}
Requires:   systemd
# Group `privileged` of the setgid accounts helper (as mapplauncherd's boosters).
Requires(pre): sailfish-setup

%description bridge
netvfs-bridge: serves netvfs locations to registered sandboxed
consumers over a socket in their data folder, without handing out secrets.

%prep
%setup -q -n %{name}-%{version}

%build
# Rust binaries and libnetvfs-rs.so, cross-built by CI into rust/prebuilt.
%qmake5 -r NETVFS_BUILD_TESTS=0 "VERSION=%{version}" \
    NETVFS_RUST_PREBUILT="$PWD/rust/prebuilt"
%make_build

%install
%qmake5_install

# Script bodies, not "-p /sbin/ldconfig": rpm passes the instance count to a -p program and ldconfig takes
# "1" for a folder and fails.
%post
/sbin/ldconfig

%postun
/sbin/ldconfig

# msyncd picks up new or removed plugins and profiles.
%post backup
systemctl-user try-restart msyncd.service || :

%postun backup
systemctl-user try-restart msyncd.service || :

# The generator turns consumer files into units on daemon-reload; starting the targets again starts the
# socket and path units they now want. A bridge still running the old binary stops; its socket stays, so the
# consumer's next connection starts the new one.
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
%{_libdir}/netvfs/backends/libnetvfs-local.so
# Rust backends, dlopen'd by their plugins next to the backend folder.
%{_libdir}/netvfs/libnetvfs-rs.so
# Bridge package's binaries.
%dir %{_prefix}/libexec/netvfs
%dir %{_datadir}/netvfs
%{_datadir}/netvfs/providers
%dir %{_libdir}/qt5/qml/org/netvfs
%{_libdir}/qt5/qml/org/netvfs/accounts
%{_datadir}/accounts/service_types/netvfs-files.service-type
%{_datadir}/accounts/services/sftp-files.service
%{_datadir}/accounts/services/smb-files.service
%{_datadir}/accounts/providers/sftp.provider
%{_datadir}/accounts/providers/smb.provider
%{_datadir}/accounts/ui/sftp.qml
%{_datadir}/accounts/ui/sftp-settings.qml
%{_datadir}/accounts/ui/sftp-update.qml
%{_datadir}/accounts/ui/smb.qml
%{_datadir}/accounts/ui/smb-settings.qml
%{_datadir}/accounts/ui/smb-update.qml
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-sftp.png
%{_datadir}/themes/sailfish-default/silica/*/icons/graphic-service-smb.png
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
# Backends' C ABI for the Rust netvfs-bridge (dlopen'd next to the backend folder, outside the linker path).
%{_libdir}/netvfs/libnetvfs-bridge-ffi.so
# Only group `privileged` can read the accounts database.
%attr(2755,root,privileged) %{_prefix}/libexec/netvfs/netvfs-accounts
%{_prefix}/lib/systemd/user-generators/netvfs-bridge-generator
%dir %{_datadir}/netvfs/consumers
%{_datadir}/netvfs/consumers/lautta.conf
%dir %{_datadir}/netvfs/bridge
%config %{_datadir}/netvfs/bridge/handoff.conf

