# SPDX-License-Identifier: LGPL-2.1-or-later
# netvfs-bridge (SPEC-v2 section 8a): the bridge library (also linked by the
# tests), the daemon, its accounts helper, the systemd user generator, the
# shipped data and libnetvfs-bridge-ffi.so (the C ABI of the Rust bridge).
TEMPLATE = subdirs
SUBDIRS = lib app accounts generator data ffi
app.depends = lib
accounts.depends = lib
