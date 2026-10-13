# SPDX-License-Identifier: LGPL-2.1-or-later
# netvfs-bridge tests (SPEC-v2 XT-7). The bridge's own tests are Rust
# (rust/netvfs-bridge/tests); these are the C++ side: the C ABI
# (ffi, ffifake), the accounts helper against its reference, the generator,
# and the binary from a libdbus client (contract, process).
TEMPLATE = subdirs
SUBDIRS = accounts contract generator process ffifake ffi
ffi.depends = ffifake
