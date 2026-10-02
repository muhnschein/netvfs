# SPDX-License-Identifier: LGPL-2.1-or-later
# The netvfs-cli sources without main(), shared with tests/unit/cli.
QT += network
INCLUDEPATH += $$PWD
HEADERS += $$PWD/cli.h $$PWD/clicontext.h $$PWD/cliformat.h $$PWD/cliprompt.h
SOURCES += $$PWD/cli.cpp $$PWD/clicommands.cpp $$PWD/cliformat.cpp $$PWD/cliprompt.cpp
