# SPDX-License-Identifier: LGPL-2.1-or-later
# Shared settings for code that uses the Buteo sync framework (SPEC 8).
#
# Where libbuteosyncfw5 comes from is an explicit switch:
#   NETVFS_HOST_BUTEO=<prefix>  a host build of the pinned upstream library
#                               (vendor/host/build-host-buteo.sh, set by the
#                               top-level Makefile for development and CI)
#   unset                       pkg-config buteosyncfw5 (Sailfish SDK / RPM,
#                               from buteo-syncfw-qt5-devel)
include(../../common.pri)

isEmpty(NETVFS_HOST_BUTEO) {
    CONFIG += link_pkgconfig
    PKGCONFIG += buteosyncfw5
} else {
    INCLUDEPATH += $$NETVFS_HOST_BUTEO/include/buteosyncfw5
    # Third-party headers: no warnings from them against the newer host Qt.
    QMAKE_CXXFLAGS += -isystem $$NETVFS_HOST_BUTEO/include/buteosyncfw5
    LIBS += -L$$NETVFS_HOST_BUTEO/lib -lbuteosyncfw5
    QMAKE_RPATHDIR += $$NETVFS_HOST_BUTEO/lib
}

CONFIG += link_pkgconfig
PKGCONFIG += accounts-qt5
QT += dbus
INCLUDEPATH += $$PWD/lib

NETVFS_BUTEO_LIB = $$NETVFS_LIB_OUT/libnetvfs-buteo.a
NETVFS_BUTEO_PLUGIN_OUT = $$NETVFS_LIB_OUT/buteo-plugins-qt5/oopp
NETVFS_BUTEO_PLUGIN_INSTALL_DIR = $$[QT_INSTALL_LIBS]/buteo-plugins-qt5/oopp

# Links the static Buteo library (plus what it needs) into a plugin or a test.
defineReplace(netvfsButeoLibs) {
    return(-L$$NETVFS_LIB_OUT -lnetvfs-buteo $$netvfsCoreLibs())
}
