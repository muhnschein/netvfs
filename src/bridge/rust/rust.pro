# SPDX-License-Identifier: LGPL-2.1-or-later
# The Rust binaries of netvfs-bridge (doc/RUST.md): the bridge itself
# (SPEC-v2 XB-2, rust/netvfs-bridge), which loads the backends through
# libnetvfs-bridge-ffi.so (../ffi), and netvfs-accounts (XB-2a, the setgid
# `privileged` reader of the accounts database, rust/netvfs-accounts), so
# that the bridge runs without the group. cargo builds them, qmake only puts
# them where the tests and the installation expect them.
#
# Variables that may be set on the qmake command line:
#   NETVFS_CARGO        the cargo to run (default: cargo)
#   NETVFS_RUST_TARGET  a target triple to build for (the SDK build:
#                       aarch64-unknown-linux-gnu)
#   NETVFS_CARGO_FLAGS  more cargo arguments
#   NETVFS_RUST_PREBUILT a folder with both binaries as CI cross-built them
#                       (tools/ci/cross-build.sh); installed as they are,
#                       cargo does not run. The RPM build sets it until an
#                       SDK target ships the rustc of rust-version
#                       (doc/RUST.md).
include(../../../common.pri)

TEMPLATE = aux

RUST_BINARIES = netvfs-bridge netvfs-accounts

isEmpty(NETVFS_CARGO): NETVFS_CARGO = cargo
CARGO_TARGET_DIR = $$NETVFS_BUILD/rust-target
CARGO_OUT = $$CARGO_TARGET_DIR/release
!isEmpty(NETVFS_RUST_TARGET) {
    CARGO_ARGS = --target $$NETVFS_RUST_TARGET
    CARGO_OUT = $$CARGO_TARGET_DIR/$$NETVFS_RUST_TARGET/release
}
LIBEXEC_DIR = $$NETVFS_BUILD/libexec/netvfs

# make coverage: instrumented binaries that write their counters to
# rust-coverage/ (LLVM_PROFILE_FILE, set by the Makefile), which the
# helper's confinement lets it write to (tools/ci/rust-coverage.sh reads
# them). The build scripts are instrumented too; theirs go there as well,
# not into rust/.
equals(NETVFS_COVERAGE, 1) {
    RUST_COVERAGE_DIR = $$NETVFS_BUILD/rust-coverage
    CARGO_ENV = mkdir -p $$shell_quote($$RUST_COVERAGE_DIR) && \
        RUSTFLAGS=\"-C instrument-coverage\" CARGO_PROFILE_RELEASE_STRIP=none \
        NETVFS_RUST_COVERAGE_DIR=$$shell_quote($$RUST_COVERAGE_DIR) \
        LLVM_PROFILE_FILE=$$shell_quote($$RUST_COVERAGE_DIR/build-%p-%m.profraw)
}

isEmpty(NETVFS_RUST_PREBUILT) {
    RUST_FROM = $$CARGO_OUT
    # Both packages in one cargo run, so that they share what they have in
    # common.
    RUST_COMMANDS = cd $$shell_quote($$NETVFS_ROOT/rust) && $$CARGO_ENV \
        $$NETVFS_CARGO build --release --locked -p netvfs-bridge -p netvfs-accounts \
            --bin netvfs-bridge --bin netvfs-accounts \
            --target-dir $$shell_quote($$CARGO_TARGET_DIR) $$CARGO_ARGS $$NETVFS_CARGO_FLAGS && \
        mkdir -p $$shell_quote($$LIBEXEC_DIR)
} else {
    RUST_FROM = $$NETVFS_RUST_PREBUILT
    RUST_COMMANDS = mkdir -p $$shell_quote($$LIBEXEC_DIR)
}
for(binary, RUST_BINARIES) {
    RUST_COMMANDS += && cp -f $$shell_quote($$RUST_FROM/$$binary) $$shell_quote($$LIBEXEC_DIR/$$binary)
    install_rust.files += $$LIBEXEC_DIR/$$binary
    QMAKE_CLEAN += $$LIBEXEC_DIR/$$binary
}

# cargo decides what is out of date; this always asks it.
rust.target = rust-binaries
rust.depends = FORCE
rust.commands = $$RUST_COMMANDS
first.depends = $$rust.target
QMAKE_EXTRA_TARGETS += rust first

# XB-2: both in /usr/libexec/netvfs (the generated units start the bridge
# there; the spec makes the helper setgid).
install_rust.path = /usr/libexec/netvfs
install_rust.CONFIG += no_check_exist executable
INSTALLS += install_rust
