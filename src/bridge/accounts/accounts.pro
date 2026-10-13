# SPDX-License-Identifier: LGPL-2.1-or-later
# netvfs-accounts (SPEC-v2 XB-2a): the setgid `privileged` reader of the
# accounts database, so that netvfs-bridge runs without the group. Written in
# Rust (rust/netvfs-accounts, doc/RUST.md): cargo builds it, qmake only puts
# it where the tests and the installation expect it.
#
# Variables that may be set on the qmake command line:
#   NETVFS_CARGO        the cargo to run (default: cargo)
#   NETVFS_RUST_TARGET  a target triple to build for (the SDK build:
#                       aarch64-unknown-linux-gnu)
#   NETVFS_CARGO_FLAGS  more cargo arguments
#   NETVFS_RUST_PREBUILT a folder with a netvfs-accounts that CI cross-built
#                       (tools/ci/cross-build.sh); installed as it is, cargo
#                       does not run. The RPM build sets it until an SDK
#                       target ships the rustc of rust-version (doc/RUST.md).
include(../../../common.pri)

TEMPLATE = aux

isEmpty(NETVFS_CARGO): NETVFS_CARGO = cargo
CARGO_TARGET_DIR = $$NETVFS_BUILD/rust-target
CARGO_OUT = $$CARGO_TARGET_DIR/release
!isEmpty(NETVFS_RUST_TARGET) {
    CARGO_ARGS = --target $$NETVFS_RUST_TARGET
    CARGO_OUT = $$CARGO_TARGET_DIR/$$NETVFS_RUST_TARGET/release
}
HELPER_DIR = $$NETVFS_BUILD/libexec/netvfs
HELPER = $$HELPER_DIR/netvfs-accounts

# make coverage: an instrumented helper that writes its counters to
# rust-coverage/ (LLVM_PROFILE_FILE, set by the Makefile), which its
# confinement lets it write to (tools/ci/rust-coverage.sh reads them). The
# build scripts are instrumented too; theirs go there as well, not into rust/.
equals(NETVFS_COVERAGE, 1) {
    RUST_COVERAGE_DIR = $$NETVFS_BUILD/rust-coverage
    CARGO_ENV = mkdir -p $$shell_quote($$RUST_COVERAGE_DIR) && \
        RUSTFLAGS=\"-C instrument-coverage\" CARGO_PROFILE_RELEASE_STRIP=none \
        NETVFS_RUST_COVERAGE_DIR=$$shell_quote($$RUST_COVERAGE_DIR) \
        LLVM_PROFILE_FILE=$$shell_quote($$RUST_COVERAGE_DIR/build-%p-%m.profraw)
}

# cargo decides what is out of date; this always asks it.
helper.target = $$HELPER
helper.depends = FORCE
isEmpty(NETVFS_RUST_PREBUILT) {
    helper.commands = cd $$shell_quote($$NETVFS_ROOT/rust) && $$CARGO_ENV \
        $$NETVFS_CARGO build --release --locked -p netvfs-accounts --bin netvfs-accounts \
            --target-dir $$shell_quote($$CARGO_TARGET_DIR) $$CARGO_ARGS $$NETVFS_CARGO_FLAGS && \
        mkdir -p $$shell_quote($$HELPER_DIR) && \
        cp -f $$shell_quote($$CARGO_OUT/netvfs-accounts) $$shell_quote($$HELPER)
} else {
    helper.commands = mkdir -p $$shell_quote($$HELPER_DIR) && \
        cp -f $$shell_quote($$NETVFS_RUST_PREBUILT/netvfs-accounts) $$shell_quote($$HELPER)
}
first.depends = $$helper.target
QMAKE_EXTRA_TARGETS += helper first

install_helper.files = $$HELPER
install_helper.path = /usr/libexec/netvfs
install_helper.CONFIG += no_check_exist executable
INSTALLS += install_helper

QMAKE_CLEAN += $$HELPER
