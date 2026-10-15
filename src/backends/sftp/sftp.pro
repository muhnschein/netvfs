# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-sftp.so: provider "sftp" of libnetvfs-rs.so (rust/netvfs-sftp)
# through the shim (src/backends/rs), with the SSH key tools on its root
# object (SPEC-sftp 5.1, doc/RUST.md).
NETVFS_PROVIDER = sftp
include(../backend.pri)
include(../rs/rs.pri)

SOURCES += sftpplugin.cpp
