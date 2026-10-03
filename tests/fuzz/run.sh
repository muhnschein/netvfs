#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Builds every tests/fuzz/fuzz_*.cpp as a libFuzzer binary (clang, ASan +
# UBSan) and runs each one for a fixed time budget.
#
#   tests/fuzz/run.sh <build-dir> [seconds]     (default 60 seconds per harness)
#
# Needs clang++ with the libFuzzer runtime (Ubuntu: clang libclang-rt-dev) and
# Qt5Core development files. Independent of qmake: each harness is compiled
# together with the core sources it names (see tests/fuzz/README.md). Binaries
# go to <build-dir>/fuzz, new corpus entries to <build-dir>/fuzz/work/<name>,
# crash reproducers to <build-dir>/fuzz/artifacts. Set FUZZ_ONLY="names url" to
# run a subset. Exit status is non-zero if any harness fails to build or crashes.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
[ $# -ge 1 ] || { echo "usage: $0 <build-dir> [seconds]" >&2; exit 2; }
mkdir -p "$1"
out=$(cd "$1" && pwd)/fuzz
budget=${2:-60}
CXX=${CXX:-clang++}
mkdir -p "$out/work" "$out/artifacts"

# Value of a "// fuzz-<key>: ..." directive in a harness (empty if absent).
directive() {
    key=$1
    harness=$2
    sed -n "s|^// fuzz-$key: *||p" "$harness" | head -n 1
}

qt_modules() {
    harness=$1
    modules=$(directive qt "$harness")
    [ -n "$modules" ] || modules=Core
    for m in $modules; do printf 'Qt5%s ' "$m"; done
}

build() {
    b_src=$1
    b_out=$2
    b_extra=""
    for s in $(directive sources "$b_src"); do b_extra="$b_extra $root/$s"; done
    b_includes=""
    for i in $(directive includes "$b_src"); do b_includes="$b_includes -I$root/$i"; done
    b_pkgs=$(qt_modules "$b_src")
    # shellcheck disable=SC2086
    $CXX -std=gnu++17 -g -O1 -fPIC -fno-omit-frame-pointer \
        -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
        -DNETVFS_BUILD_CORE -I"$root/src/core" $b_includes \
        $(pkg-config --cflags $b_pkgs) \
        "$b_src" $b_extra \
        $(pkg-config --libs $b_pkgs) \
        -o "$out/$b_out"
}

status=0
for src in "$here"/fuzz_*.cpp; do
    [ -e "$src" ] || continue
    stem=$(basename "$src" .cpp)
    name=${stem#fuzz_}
    if [ -n "${FUZZ_ONLY:-}" ] && ! echo " $FUZZ_ONLY " | grep -q " $name "; then
        continue
    fi
    echo "== $name: building"
    build "$src" "$stem"
    seeds="$here/corpus/$name"
    mkdir -p "$out/work/$name" "$seeds"
    options="-max_total_time=$budget -max_len=${FUZZ_MAX_LEN:-4096} -timeout=10 -rss_limit_mb=2048 -print_final_stats=1"
    options="$options -artifact_prefix=$out/artifacts/$name-"
    [ -f "$here/dict/$name.dict" ] && options="$options -dict=$here/dict/$name.dict"
    echo "== $name: fuzzing for ${budget}s"
    # shellcheck disable=SC2086
    if ! ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=0} \
         UBSAN_OPTIONS=${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1} \
         "$out/$stem" $options "$out/work/$name" "$seeds"; then
        echo "== $name: FAILED, reproducers in $out/artifacts" >&2
        status=1
    fi
done
exit $status
