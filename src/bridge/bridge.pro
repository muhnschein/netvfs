# SPDX-License-Identifier: LGPL-2.1-or-later
# netvfs-bridge (SPEC-v2 section 8a): the Rust bridge and its accounts helper
# (rust/, built by cargo), libnetvfs-bridge-ffi.so (the C ABI through which
# the bridge reaches the C++ backends), the systemd user generator and the
# shipped data.
TEMPLATE = subdirs
SUBDIRS = rust ffi generator data
