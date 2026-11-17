# SPDX-License-Identifier: LGPL-2.1-or-later
# netvfs-bridge tests. The bridge's own tests are Rust (rust/netvfs-bridge/tests); these are C++: the C ABI (ffi, ffifake), accounts helper against its reference, generator, and the binary from a libdbus client (contract, process).
TEMPLATE = subdirs
SUBDIRS = accounts contract generator process ffifake ffi
ffi.depends = ffifake
