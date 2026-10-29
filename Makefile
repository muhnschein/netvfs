# SPDX-License-Identifier: LGPL-2.1-or-later
#
#   make               build everything
#   make check         Rust checks, unit tests, then the interop suite (needs docker)
#   make check-rust    the Rust workspace (rust/): format, lint, tests (nextest), lockfile, MSRV,
#                      netvfs-smb's crypto fence
#   make check-unit    unit tests only
#   make check-rust-ffi the Rust side of the C ABI against the built libnetvfs-bridge-ffi.so
#   make check-interop interop suite against containerised servers
#   make check-packaging  install tree against the RPM %files (SPEC-v2 XP-1, XP-3)
#   make coverage      unit + interop tests instrumented, writes build-coverage/coverage.xml
#                      (C++, gcovr) and build-coverage/rust-lcov.info (Rust, llvm-cov)
#   make clippy-report clippy findings as JSON for SonarQube, build-coverage/clippy.json
#   make SANITIZE=1 check   the same under ASan + UBSan
#   make HOST_BUTEO=0  use the system buteosyncfw5 (pkg-config) instead of
#                      building the pinned vendor/host/buteo-syncfw

QMAKE ?= $(shell command -v qmake-qt5 || command -v qmake)
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
QMAKE_ARGS ?=

ifeq ($(SANITIZE),1)
BUILD ?= build-asan
QMAKE_ARGS += NETVFS_SANITIZE=1
# ASan is heavy: one test per core, not nextest.toml's 32.
NEXTEST_ARGS = --test-threads num-cpus
export LSAN_OPTIONS := suppressions=$(CURDIR)/tools/sanitizer/lsan.supp:print_suppressions=0
else ifeq ($(COVERAGE),1)
BUILD ?= build-coverage
QMAKE_ARGS += NETVFS_COVERAGE=1
else
BUILD ?= build
endif

BUILD_DIR := $(abspath $(BUILD))
HOST_BUTEO ?= 1
ifeq ($(HOST_BUTEO),1)
QMAKE_ARGS += NETVFS_HOST_BUTEO=$(BUILD_DIR)/host-buteo
endif
TEST_ENV = QT_QPA_PLATFORM=offscreen

# The Rust helper (rust/, doc/RUST.md). Under COVERAGE=1 qmake builds it
# instrumented; every run writes its counters to RUST_COVERAGE_DIR, which its
# confinement lets it write to, and the crate's own tests count there too.
CARGO ?= cargo
# cargo nextest profile (rust/.config/nextest.toml); CI uses "ci".
NEXTEST_PROFILE ?= default
RUST_FEATURES = --features netvfs-accounts/probe,netvfs-bridge/testing,netvfs-bridge/test-bins,netvfs-backend/testing
# rust-toolchain.toml would override the toolchain a job installs, so the
# oldest supported one (rust-version) is named explicitly.
RUST_MSRV = $(shell sed -n -e 's/^rust-version = "\([0-9]*\.[0-9]*\)"/\1.0/p' \
    -e 's/^rust-version = "\([0-9]*\.[0-9]*\.[0-9]*\)"/\1/p' rust/Cargo.toml)
ifeq ($(COVERAGE),1)
RUST_COVERAGE_DIR := $(BUILD_DIR)/rust-coverage
RUST_PROFILE_FILE := LLVM_PROFILE_FILE=$(RUST_COVERAGE_DIR)/%p-%m.profraw
TEST_ENV += $(RUST_PROFILE_FILE)
RUST_ENV = RUSTFLAGS="-C instrument-coverage" NETVFS_RUST_COVERAGE_DIR=$(RUST_COVERAGE_DIR) \
    CARGO_TARGET_DIR=$(BUILD_DIR)/rust-test-target $(RUST_PROFILE_FILE)
else
RUST_ENV =
endif

.PHONY: all host-buteo configure check check-rust check-rust-ffi check-unit check-interop check-packaging \
    coverage clippy-report clean distclean

all: configure
	$(MAKE) -C $(BUILD_DIR) $(if $(findstring -j,$(MAKEFLAGS)),,-j$(JOBS))

# The host has no buteo packages; the Sailfish SDK build never runs this.
host-buteo:
ifeq ($(HOST_BUTEO),1)
	./vendor/host/build-host-buteo.sh $(BUILD_DIR)/host-buteo
endif

configure: host-buteo
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && $(QMAKE) -r $(CURDIR)/netvfs.pro $(QMAKE_ARGS)

check: check-rust check-unit check-rust-ffi check-interop

check-rust:
	./tools/ci/check-lockfile.sh rust/Cargo.lock
	./tools/ci/check-crypto-fence.sh
	cd rust && $(CARGO) fmt --all -- --check
	cd rust && $(CARGO) clippy --locked --workspace --all-targets $(RUST_FEATURES) -- -D warnings
	cd rust && $(RUST_ENV) $(CARGO) nextest run --locked --workspace $(RUST_FEATURES) --profile $(NEXTEST_PROFILE) $(NEXTEST_ARGS)
	cd rust && $(RUST_ENV) $(CARGO) test --locked --workspace --doc $(RUST_FEATURES)
	cd rust && $(CARGO) +$(RUST_MSRV) check --locked --workspace --all-targets $(RUST_FEATURES)

# netvfs-bridge's tests that need the C ABI, against the C++ library this
# build made, with the fake backend (rust/netvfs-bridge/tests: ffi, backend,
# server, and through the cargo-built binary process, contract,
# notifications and accounts; doc/RUST.md). The whole package runs, so no
# such test is missed. The same build as check-rust's (so `make coverage`
# finds its counters); there those tests only say they are skipped, since
# the variables are not set. Under SANITIZE=1 the library is instrumented
# with gcc's ASan, whose runtime must be loaded first: the test binary is not
# instrumented, so it is preloaded (and the bridge binary it starts inherits
# that). Into the test binary only, as cargo's target runner: preloaded into
# cargo and rustc as well, the runtime deadlocks rustc before anything is
# built.
FFI_TEST_ENV = NETVFS_BRIDGE_FFI=$(BUILD_DIR)/lib/netvfs/libnetvfs-bridge-ffi.so \
    NETVFS_BRIDGE_FFI_FAKE=$(BUILD_DIR)/lib/libnetvfs-bridge-ffi-fake.so \
    NETVFS_BACKEND_PATH=$(BUILD_DIR)/lib/netvfs/test-backends
ifeq ($(SANITIZE),1)
RUST_HOST := $(shell rustc -vV | sed -n 's/^host: //p' | tr a-z- A-Z_)
FFI_TEST_ENV += CARGO_TARGET_$(RUST_HOST)_RUNNER="env \
    LD_PRELOAD=$$($(CXX) -print-file-name=libasan.so):$$($(CXX) -print-file-name=libubsan.so)"
# Tests that measure the resident set skip that under ASan (its quarantine
# keeps freed memory), as in rust-sanitize.sh.
FFI_TEST_ENV += NETVFS_TEST_SANITIZER=address
endif
check-rust-ffi: all
	cd rust && $(TEST_ENV) $(FFI_TEST_ENV) $(RUST_ENV) $(CARGO) nextest run --locked --workspace $(RUST_FEATURES) \
	    --profile $(NEXTEST_PROFILE) $(NEXTEST_ARGS) -E 'package(netvfs-bridge)'

clippy-report:
	mkdir -p $(BUILD_DIR)
	cd rust && $(CARGO) clippy --locked --workspace --all-targets $(RUST_FEATURES) --message-format=json \
	    > $(BUILD_DIR)/clippy.json

# Test binaries side by side, each one's output kept together (-O): they mostly
# wait on event loops and timers; 90 s in series, 19 s on 4 cores.
check-unit: all
	$(TEST_ENV) dbus-run-session -- $(MAKE) -C $(BUILD_DIR)/tests \
	    $(if $(findstring -j,$(MAKEFLAGS)),,-j$(JOBS)) -Otarget check

check-interop: all
	$(TEST_ENV) ./tests/interop/run.sh $(BUILD_DIR)

# SPEC-v2 XP-1: every installed file in exactly one package of rpm/netvfs.spec
# (the host has no sailfish-svg2png, so no icons; tests install to /usr/tests,
# package builds skip them). The C ABI of netvfs-bridge
# is checked against the host's glibc, and the bridge must look for it where
# the spec puts it (tools/ci/check-ffi-lib.sh). So is libnetvfs-rs.so, and
# the plugins of the Rust backends (the test plugin of provider mem, the
# SFTP plugin and the SMB plugin) must look for it where qmake installs it
# (tools/ci/check-rs-lib.sh).
PACKAGE_ROOT := $(BUILD_DIR)/install-root
PACKAGE_FILES = ./tools/ci/check-files.py --map "$$($(QMAKE) -query QT_INSTALL_LIBS)=/usr/lib64" \
    --allow-missing '/usr/share/themes/*'
check-packaging: all
	rm -rf $(PACKAGE_ROOT)
	$(MAKE) -s -C $(BUILD_DIR) install INSTALL_ROOT=$(PACKAGE_ROOT) >/dev/null
	rm -rf $(PACKAGE_ROOT)/usr/tests
	$(PACKAGE_FILES) $(PACKAGE_ROOT)
	./tools/ci/check-ffi-lib.sh $(BUILD_DIR)/lib/netvfs/libnetvfs-bridge-ffi.so \
	    "$$($(PACKAGE_FILES) --list $(PACKAGE_ROOT) | sed -n 's|^ *\(/.*/libnetvfs-bridge-ffi\.so\)$$|\1|p')" \
	    $(BUILD_DIR)/libexec/netvfs/netvfs-bridge "$$(getconf GNU_LIBC_VERSION | cut -d ' ' -f 2)"
	./tools/ci/check-rs-lib.sh $(BUILD_DIR)/lib/netvfs/libnetvfs-rs.so "$$(getconf GNU_LIBC_VERSION | cut -d ' ' -f 2)" \
	    "$$($(QMAKE) -query QT_INSTALL_LIBS)/netvfs/libnetvfs-rs.so" $(BUILD_DIR)/lib/netvfs/test-backends/libnetvfs-mem.so \
	    $(BUILD_DIR)/lib/netvfs/backends/libnetvfs-sftp.so $(BUILD_DIR)/lib/netvfs/backends/libnetvfs-smb.so
	./tests/packaging/test_packaging.py

coverage:
	rm -rf $(abspath build-coverage)/rust-coverage
	$(MAKE) COVERAGE=1 check
	./tools/ci/rust-coverage.sh $(abspath build-coverage)
	gcovr --root $(CURDIR) --object-directory $(abspath build-coverage) \
	    --filter '$(CURDIR)/src/' --exclude '.*/moc_.*' \
	    --gcov-ignore-parse-errors=negative_hits.warn_once_per_file --gcov-ignore-errors=no_working_dir_found \
	    --exclude-throw-branches --exclude-unreachable-branches \
	    --sonarqube $(abspath build-coverage)/coverage.xml --print-summary

clean:
	rm -rf build build-asan build-coverage

distclean: clean
