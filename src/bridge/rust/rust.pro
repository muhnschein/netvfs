# SPDX-License-Identifier: LGPL-2.1-or-later
# The Rust binaries of netvfs-bridge: the bridge (rust/netvfs-bridge), which loads backends through
# libnetvfs-bridge-ffi.so (../ffi), and netvfs-accounts (setgid `privileged` reader of the accounts
# database, rust/netvfs-accounts) so the bridge runs without the group. cargo builds them; qmake
# only puts them where tests and installation expect them.
# Variables on the qmake command line:
#   NETVFS_CARGO: cargo to run (default: cargo)
#   NETVFS_RUST_TARGET: target triple (SDK build: aarch64-unknown-linux-gnu)
#   NETVFS_CARGO_FLAGS: more cargo arguments
#   NETVFS_RUST_PREBUILT: folder with both binaries as CI cross-built them
#     (tools/ci/cross-build.sh), installed as is; cargo does not run. The RPM build sets it until an
#     SDK target ships rustc of rust-version.
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

# make coverage: instrumented binaries write counters to rust-coverage/ (LLVM_PROFILE_FILE, set by
# the Makefile), which the helper's confinement lets it write to (tools/ci/rust-coverage.sh reads
# them). Build scripts are instrumented too; theirs go there as well.
equals(NETVFS_COVERAGE, 1) {
    RUST_COVERAGE_DIR = $$NETVFS_BUILD/rust-coverage
    CARGO_ENV = mkdir -p $$shell_quote($$RUST_COVERAGE_DIR) && \
        RUSTFLAGS=\"-C instrument-coverage\" CARGO_PROFILE_RELEASE_STRIP=none \
        NETVFS_RUST_COVERAGE_DIR=$$shell_quote($$RUST_COVERAGE_DIR) \
        LLVM_PROFILE_FILE=$$shell_quote($$RUST_COVERAGE_DIR/build-%p-%m.profraw)
}

isEmpty(NETVFS_RUST_PREBUILT) {
    RUST_FROM = $$CARGO_OUT
    # Both packages in one cargo run so they share common work.
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

# cargo decides what is out of date; always ask it.
rust.target = rust-binaries
rust.depends = FORCE
rust.commands = $$RUST_COMMANDS
first.depends = $$rust.target
QMAKE_EXTRA_TARGETS += rust first

# Both in /usr/libexec/netvfs (generated units start the bridge there); helper is setgid.
install_rust.path = /usr/libexec/netvfs
install_rust.CONFIG += no_check_exist executable
INSTALLS += install_rust
