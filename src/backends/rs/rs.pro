# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../../common.pri)

TEMPLATE = aux

isEmpty(NETVFS_CARGO): NETVFS_CARGO = cargo
CARGO_TARGET_DIR = $$NETVFS_BUILD/rust-target
CARGO_OUT = $$CARGO_TARGET_DIR/rs-release
!isEmpty(NETVFS_RUST_TARGET) {
    CARGO_ARGS = --target $$NETVFS_RUST_TARGET
    CARGO_OUT = $$CARGO_TARGET_DIR/$$NETVFS_RUST_TARGET/rs-release
}
RS_LIB_DIR = $$NETVFS_LIB_OUT/netvfs
RS_LIB = $$RS_LIB_DIR/libnetvfs-rs.so

isEmpty(NETVFS_RUST_PREBUILT) {
    RS_COMMANDS = cd $$shell_quote($$NETVFS_ROOT/rust) && \
        $$NETVFS_CARGO build --profile rs-release --locked -p netvfs-backend --lib \
            --target-dir $$shell_quote($$CARGO_TARGET_DIR) $$CARGO_ARGS $$NETVFS_CARGO_FLAGS && \
        mkdir -p $$shell_quote($$RS_LIB_DIR) && \
        cp -f $$shell_quote($$CARGO_OUT/libnetvfs_rs.so) $$shell_quote($$RS_LIB)
} else {
    RS_COMMANDS = mkdir -p $$shell_quote($$RS_LIB_DIR) && \
        cp -f $$shell_quote($$NETVFS_RUST_PREBUILT/libnetvfs-rs.so) $$shell_quote($$RS_LIB)
}

rslib.target = rs-library
rslib.depends = FORCE
rslib.commands = $$RS_COMMANDS
first.depends = $$rslib.target
QMAKE_EXTRA_TARGETS += rslib first
QMAKE_CLEAN += $$RS_LIB

install_rslib.files = $$RS_LIB
install_rslib.path = $$[QT_INSTALL_LIBS]/netvfs
install_rslib.CONFIG += no_check_exist executable
INSTALLS += install_rslib
