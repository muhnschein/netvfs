# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-rs.so with the mem backend (feature "testing") for the shim's
# tests, from cargo's rs-test profile (unoptimised, panics unwind as in
# rs-release). Never installed; the tests load it with $NETVFS_RS_LIB. It
# stays uninstrumented under NETVFS_SANITIZE (only the C++ side runs under
# ASan); under NETVFS_COVERAGE it counts, as the bridge does
# (src/bridge/rust/rust.pro), and tools/ci/rust-coverage.sh reads it.
include(../../../../common.pri)
include(../rstest.pri)

TEMPLATE = aux

isEmpty(NETVFS_CARGO): NETVFS_CARGO = cargo
equals(NETVFS_COVERAGE, 1) {
    RUST_COVERAGE_DIR = $$NETVFS_BUILD/rust-coverage
    CARGO_ENV = mkdir -p $$shell_quote($$RUST_COVERAGE_DIR) && \
        RUSTFLAGS=\"-C instrument-coverage\" \
        LLVM_PROFILE_FILE=$$shell_quote($$RUST_COVERAGE_DIR/build-%p-%m.profraw)
}

rslib.target = rs-test-library
rslib.depends = FORCE
rslib.commands = cd $$shell_quote($$NETVFS_ROOT/rust) && $$CARGO_ENV \
    $$NETVFS_CARGO build --profile rs-test --locked -p netvfs-backend --lib --features testing \
        --target-dir $$shell_quote($$NETVFS_BUILD/rust-target)
first.depends = $$rslib.target
QMAKE_EXTRA_TARGETS += rslib first
