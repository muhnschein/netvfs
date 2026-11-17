# SPDX-License-Identifier: LGPL-2.1-or-later
# netvfs-bridge: the Rust bridge and its accounts helper (rust/, built by cargo),
# libnetvfs-bridge-ffi.so (C ABI to the C++ backends), the systemd user generator and shipped data.
TEMPLATE = subdirs
SUBDIRS = rust ffi generator data
