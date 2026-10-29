# Verifying the RPMs

Same commit, same RPMs, byte for byte (SPEC P-8). Check them:

```
$ git clone https://github.com/muhnschein/netvfs.git
$ cd netvfs
$ tools/verify-rpm.sh --ref <commit> netvfs-0.6.0-1.aarch64.rpm netvfs-bridge-0.6.0-1.aarch64.rpm
```

`<commit>`: full hash, branch or tag the RPMs were built from. CI artifact
`netvfs-rpms-aarch64` of a push to `main`: that push's commit. Of a pull
request: `refs/pull/<number>/merge` while the pull request is unchanged (CI
builds it merged into `main`). Any of the packages in one run: a line each,
exit is the worst.

Needs Linux on x86_64, git, Docker, sudo (`tools/ci/build-rpm.sh` hands
its build copy to the SDK user with it), the i386 C library (Ubuntu: `libc6-i386`;
the SDK's compiler is an i486 program) and rustup. First run: SDK image pull
(~13 GB unpacked, where Docker keeps images), ~15 min build. Builds in a fresh
clone under `~/.cache/netvfs-verify`, never in your tree: ~5 GB, checks for
6 GB free. Elsewhere: `NETVFS_WORKDIR=/some/big/disk tools/verify-rpm.sh …`.

| Result | Exit | Meaning |
|---|---|---|
| `VERIFIED` | 0 | Same file as the rebuild. |
| `SAME FILES` | 1 | Every file, mode, owner inside matches; packaging (build time, file dates, host) differs. Expected for RPMs built before P-8. |
| `DIFFERENT` | 2 | Files differ. Please open an issue with the output. |
| | 3 | Couldn't check (no Docker, no such commit, build failed). |

## What makes it reproducible

- Package build time and file dates: commit's time (`SOURCE_DATE_EPOCH`, set
  by `tools/ci/build-rpm.sh`); build host fixed (spec).
- Built from a copy of the tracked files without `.git`
  (`tools/ci/build-rpm.sh`): nothing left in the checkout gets in, and mb2
  takes the version from the spec (in a git tree it derives one from the
  latest tag, branch, time and hash).
- Build paths: the Rust binaries record none. `tools/ci/cross-build.sh` maps
  cargo home to `/cargo` (rustc `--remap-path-prefix`); cargo names the
  workspace's own sources relative to the checkout. C++ and packaging run in
  the SDK image at a fixed path.
- Build environment: SDK image pinned by digest (`.github/workflows/ci.yml`,
  job `rpm`: compilers, sysroot, Qt, rpm); Rust pinned
  (`rust/rust-toolchain.toml`).
- Inputs pinned: `rust/Cargo.lock` (crates by checksum), `rust/vendor` in the
  tree.

CI checks it on every push: job "RPMs rebuild byte for byte" runs
`tools/verify-rpm.sh` on the RPM job's packages, on another runner, from a
fresh clone at another path, with another cargo home, time zone, umask and
time.

## What it doesn't cover

- Sailfish SDK's compilers and libraries: upstream's image
  (`coderus/sailfishos-platform-sdk-aarch64`), trusted as by every Sailfish
  package, not rebuilt here. BuildRequires the image lacks (Buteo's devel
  files, `sailfish-svg2png`) come at build time from Jolla's 5.2.0.15 release
  repository: fixed by release, not by digest.
- Rust toolchain: rustup's release binaries, checked by rustup, not
  bootstrapped here.
- Podman, macOS, Windows, ARM hosts: untested. Image is x86_64; its build
  user (uid 100000) is beyond rootless Podman's default subordinate ids.
