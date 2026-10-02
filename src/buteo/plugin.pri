# SPDX-License-Identifier: LGPL-2.1-or-later
# One Buteo client plugin lib<provider>-<operation>-client.so with its client
# profile and sync profile template (SPEC 3.3, 4.1, 8.1, 8.2). Set before
# including:
#   NETVFS_PROVIDER   sftp, smb
#   NETVFS_OPERATION  Backup, BackupQuery, BackupRestore
include(buteo.pri)

isEmpty(NETVFS_PROVIDER)|isEmpty(NETVFS_OPERATION): error("Set NETVFS_PROVIDER and NETVFS_OPERATION")

NETVFS_CLIENT_PROFILE = $${NETVFS_PROVIDER}-$$lower($$NETVFS_OPERATION)
NETVFS_SYNC_PROFILE = $${NETVFS_PROVIDER}.$${NETVFS_OPERATION}
NETVFS_SYNC_PROTOCOL = $$NETVFS_PROVIDER

TEMPLATE = lib
TARGET = $${NETVFS_CLIENT_PROFILE}-client
DESTDIR = $$NETVFS_BUTEO_PLUGIN_OUT
QT = core dbus
CONFIG += plugin hide_symbols

DEFINES += \
    NETVFS_BUTEO_PROVIDER=\\\"$$NETVFS_PROVIDER\\\" \
    NETVFS_BUTEO_OPERATION=$$NETVFS_OPERATION \
    NETVFS_BUTEO_LOADER_IID=\\\"org.netvfs.buteo.$${NETVFS_CLIENT_PROFILE}-client\\\"

SOURCES = $$PWD/loader/loader.cpp
LIBS += $$netvfsButeoLibs()
PRE_TARGETDEPS += $$NETVFS_BUTEO_LIB
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT
QMAKE_LFLAGS += -Wl,--no-undefined

# Profiles generated from one template per kind; only the names and the
# sync protocol differ between them.
clientprofile.input = $$PWD/profiles/client.xml.in
clientprofile.output = $$OUT_PWD/$${NETVFS_CLIENT_PROFILE}.xml
syncprofile.input = $$PWD/profiles/sync.xml.in
syncprofile.output = $$OUT_PWD/$${NETVFS_SYNC_PROFILE}.xml
QMAKE_SUBSTITUTES += clientprofile syncprofile

target.path = $$NETVFS_BUTEO_PLUGIN_INSTALL_DIR
client.files = $$clientprofile.output
client.path = /etc/buteo/profiles/client
sync.files = $$syncprofile.output
sync.path = /etc/buteo/profiles/sync
INSTALLS += target client sync
