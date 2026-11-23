#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
[ $# -ge 1 ] || { echo "usage: $0 <build-dir> [seconds]" >&2; exit 2; }
mkdir -p "$1"
out=$(cd "$1" && pwd)/fuzz
budget=${2:-60}
CXX=${CXX:-clang++}
mkdir -p "$out/work" "$out/artifacts"

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
    if ! ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=0} \
         UBSAN_OPTIONS=${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1} \
         "$out/$stem" $options "$out/work/$name" "$seeds"; then
        echo "== $name: FAILED, reproducers in $out/artifacts" >&2
        status=1
    fi
done
exit $status
