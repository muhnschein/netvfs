# Fuzzing

libFuzzer harnesses, clang (`-fsanitize=fuzzer,address,undefined`), no qmake. Needs `clang`, `libclang-rt-dev`, `qtbase5-dev`.

    tests/fuzz/run.sh <build-dir> [seconds]     # default: 60 s per harness
    FUZZ_ONLY="names url" tests/fuzz/run.sh build 10

`run.sh` builds each `tests/fuzz/fuzz_<name>.cpp` into `<build-dir>/fuzz/fuzz_<name>`, runs it for the budget, fails on build error or crash. Corpus growth: `<build-dir>/fuzz/work/<name>`; reproducers: `<build-dir>/fuzz/artifacts` (rerun: `<build-dir>/fuzz/fuzz_<name> <artifact>`). CI job "Fuzzing (fixed budget)".

| Harness | Property |
| --- | --- |
| `fuzz_names.cpp` | `Names::encode(Names::decode(x)) == x` for every byte string; UTF-16 input never crashes |
| `fuzz_url.cpp` | `Url::parse` never crashes; accepted input survives parse, format, parse unchanged |

Rust code (bridge, SMB codecs, SFTP client, key import): cargo-fuzz targets in `rust/fuzz` (`tools/ci/rust-fuzz.sh`).

## New harness: one file

1. `tests/fuzz/fuzz_<name>.cpp` with `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t)`. Violated property → crash (`__builtin_trap()`); never print or exit.
2. Directives near top (all optional):

       // fuzz-sources: src/core/url.cpp src/core/names.cpp src/core/paths.cpp
       // fuzz-includes: src/backends/local
       // fuzz-qt: Core

   `fuzz-sources`: repo-relative `.cpp` compiled in (only what parser needs); `src/core` always on include path; `fuzz-qt`: Qt modules for `pkg-config` (default `Core`). `NETVFS_BUILD_CORE` defined.
3. Seeds in `tests/fuzz/corpus/<name>/` (valid inputs of every kind, a few bad); optional dictionary `tests/fuzz/dict/<name>.dict`.

`run.sh` discovers file; CI runs it.
