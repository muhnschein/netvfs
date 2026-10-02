# SPDX-License-Identifier: LGPL-2.1-or-later
# Backend sources, shared by the plugin and by tests that compile them in
# (tests/unit/sftp, tests/interop/sftp). The includer links libssh.
INCLUDEPATH += $$PWD $$VENDOR_PREFIX/include

HEADERS += \
    $$PWD/sftpbackend.h \
    $$PWD/sftpinternal.h \
    $$PWD/sftpshell.h \
    $$PWD/sftpsupport.h \
    $$PWD/sshkeytools.h \
    $$PWD/sshutil.h

SOURCES += \
    $$PWD/sftpbackend.cpp \
    $$PWD/sftpconnection.cpp \
    $$PWD/sftpexec.cpp \
    $$PWD/sftpio.cpp \
    $$PWD/sftplogin.cpp \
    $$PWD/sftprequests.cpp \
    $$PWD/sftpshell.cpp \
    $$PWD/sftpsupport.cpp \
    $$PWD/sshkeytools.cpp \
    $$PWD/sshutil.cpp
