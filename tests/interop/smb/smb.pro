# SPDX-License-Identifier: LGPL-2.1-or-later
# SMB interop driver: run by tests/interop/smb/run.sh against containerised
# Samba servers, not by "make check".
include(../../test.pri)
CONFIG -= testcase
TARGET = tst_interop_smb
SOURCES = tst_interop_smb.cpp
