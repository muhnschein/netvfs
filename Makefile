# SPDX-License-Identifier: LGPL-2.1-or-later
#
#   make               build everything (vendored libraries first)
#   make check         unit tests, then the interop suite (needs docker)
#   make check-unit    unit tests only
#   make check-interop interop suite against containerised servers
#   make coverage      unit + interop tests instrumented, writes build-coverage/coverage.xml
#   make SANITIZE=1 check   the same under ASan + UBSan (vendored libraries included)

QMAKE ?= $(shell command -v qmake-qt5 || command -v qmake)
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
QMAKE_ARGS ?=

ifeq ($(SANITIZE),1)
BUILD ?= build-asan
QMAKE_ARGS += NETVFS_SANITIZE=1
VENDOR_CFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer
else ifeq ($(COVERAGE),1)
BUILD ?= build-coverage
QMAKE_ARGS += NETVFS_COVERAGE=1
VENDOR_CFLAGS =
else
BUILD ?= build
VENDOR_CFLAGS =
endif

BUILD_DIR := $(abspath $(BUILD))
TEST_ENV = QT_QPA_PLATFORM=offscreen

.PHONY: all vendor configure check check-unit check-interop coverage clean distclean

all: configure
	$(MAKE) -C $(BUILD_DIR) $(if $(findstring -j,$(MAKEFLAGS)),,-j$(JOBS))

vendor:
	CFLAGS="$(VENDOR_CFLAGS)" LDFLAGS="$(VENDOR_CFLAGS)" ./vendor/build-vendor.sh $(BUILD_DIR)/vendor

configure: vendor
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && $(QMAKE) -r $(CURDIR)/netvfs.pro VENDOR_PREFIX=$(BUILD_DIR)/vendor $(QMAKE_ARGS)

check: check-unit check-interop

check-unit: all
	$(TEST_ENV) dbus-run-session -- $(MAKE) -C $(BUILD_DIR)/tests check

check-interop: all
	$(TEST_ENV) ./tests/interop/run.sh $(BUILD_DIR)

coverage:
	$(MAKE) COVERAGE=1 check
	gcovr --root $(CURDIR) --object-directory $(abspath build-coverage) \
	    --filter '$(CURDIR)/src/' --exclude '.*/moc_.*' \
	    --gcov-ignore-parse-errors=negative_hits.warn_once_per_file \
	    --sonarqube $(abspath build-coverage)/coverage.xml --print-summary

clean:
	rm -rf build build-asan build-coverage

distclean: clean
