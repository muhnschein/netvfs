# Fuzzing (SPEC-v2 XT-3)

libFuzzer harnesses built with clang (`-fsanitize=fuzzer,address,undefined`), independent of
qmake. Needs `clang`, `libclang-rt-dev` and `qtbase5-dev` (see `tools/ci/install-host-deps.sh`).

    tests/fuzz/run.sh <build-dir> [seconds]     # default: 60 s per harness
    FUZZ_ONLY="names url" tests/fuzz/run.sh build 10

`run.sh` builds every `tests/fuzz/fuzz_<name>.cpp` into `<build-dir>/fuzz/fuzz_<name>`, runs it for
the time budget and exits non-zero if a harness fails to build or finds a crash. New corpus entries
go to `<build-dir>/fuzz/work/<name>`, crash reproducers to `<build-dir>/fuzz/artifacts`
(re-run one with `<build-dir>/fuzz/fuzz_<name> <artifact>`). CI runs it in the job "Fuzzing (fixed
budget)".

## Harnesses

| Harness | Property |
| --- | --- |
| `fuzz_names.cpp` | `Names::encode(Names::decode(x)) == x` for every byte string; UTF-16 input never crashes |
| `fuzz_url.cpp` | `Url::parse` never crashes; what it accepts survives parse, format, parse unchanged |
| `fuzz_smb_shares.cpp` | the SMB share helper's output parser (XM-7) never crashes; what it accepts obeys the limits, holds only valid unique share names and survives the helper's writers; the request codec is canonical |

## Adding a harness: one file

1. Create `tests/fuzz/fuzz_<name>.cpp` with `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t)`.
   Make a violated property crash (`__builtin_trap()`); never print or exit.
2. Name what it needs in comment directives near the top (all optional):

       // fuzz-sources: src/core/names.cpp src/backends/webdav/multistatus.cpp
       // fuzz-includes: src/backends/webdav
       // fuzz-qt: Core Xml

   `fuzz-sources` are repository-relative `.cpp` files compiled into the harness (compile only what
   the parser needs, not whole plugins); `src/core` is always on the include path; `fuzz-qt` lists Qt
   modules (default `Core`) used for `pkg-config` flags. `NETVFS_BUILD_CORE` is defined.
3. Add seeds as small files in `tests/fuzz/corpus/<name>/` (valid inputs of every kind plus a few
   known-bad ones) and, optionally, a dictionary in `tests/fuzz/dict/<name>.dict`.

Nothing else needs changing: `run.sh` discovers the file and CI runs it.
