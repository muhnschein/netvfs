# SPDX-License-Identifier: LGPL-2.1-or-later
INCLUDEPATH += $$PWD
QT *= concurrent
CONFIG *= link_pkgconfig
PKGCONFIG *= accounts-qt5

HEADERS += \
    $$PWD/accessmodel.h \
    $$PWD/backendjobs.h \
    $$PWD/consentmodel.h \
    $$PWD/errortexts.h \
    $$PWD/netvfshelpers.h \
    $$PWD/netvfsprobe.h \
    $$PWD/providerdescriptors.h \
    $$PWD/sshkeytool.h

SOURCES += \
    $$PWD/accessmodel.cpp \
    $$PWD/backendjobs.cpp \
    $$PWD/consentmodel.cpp \
    $$PWD/errortexts.cpp \
    $$PWD/netvfshelpers.cpp \
    $$PWD/netvfsprobe.cpp \
    $$PWD/providerdescriptors.cpp \
    $$PWD/descriptortexts.cpp \
    $$PWD/sshkeytool.cpp

NETVFS_QML_MODULE_FILES = \
    qmldir \
    NetVfsAccountSetup.qml \
    NetVfsCreationAgent.qml \
    NetVfsSettingsAgent.qml \
    NetVfsUpdateAgent.qml \
    NetVfsSettingsPage.qml \
    NetVfsConsentPage.qml \
    NetVfsAccessPage.qml \
    NetVfsAccessRequestDialog.qml \
    AccessColumn.qml \
    AccessComboBox.qml \
    ConnectionDialog.qml \
    ProbeBusyPage.qml \
    ServerIdentityDialog.qml \
    SshKeyPage.qml
