# AGENTS.md

How to work on netvfs. What it is: `README.md`, `doc/SPEC.md` (platform contract, trust model, budgets, limits, roadmap). Read `doc/RUST.md` before first change. User's words in chat beat this file.

## Ground rules

- Don't know how to proceed → say "I don't know", stop, ask. Mark guesses as guesses. Unknown beats confident wrong.
- Bugs: find root cause, state it. Symptom fix ≠ fix.
- Measure twice, cut once. YAGNI: fight scope creep; meet user's intent minimally, realistically. Good return on cost; no gold-plating, no unasked refactors.
- Rule here fights task → say so loudly, get user's sign-off before breaking it.
- Options → lay them out, recommend one with reasons. Implement nothing until user clearly picks.

## Where the code stands

- Mid Rust rewrite. Rust (`rust/`, `doc/RUST.md`): accounts helper `netvfs-accounts`, `netvfs-bridge`, SFTP and SMB backends in `libnetvfs-rs.so`. Still C++/QML: `libnetvfs` core, local backend, ops, discovery, account UI, Buteo plugins, `netvfs-cli`, plugin shims (`src/backends/rs`), bridge C ABI (`src/bridge/ffi`).
- Moving more C++ to Rust = planned work package, on user's go. No drive-by ports.
- No backwards compatibility between parts that ship together: change both sides in one PR. No version handshakes, option aliases, transition code.
- C ABIs (`netvfs_rs.h`, `netvfs_bridge_ffi.h`): `#[repr(C)]` by hand, no bindgen; sizes and offsets pinned by tests.

## Done means

In this order; later step only once earlier ones hold:

1. Change implemented.
2. Tests added for it (regression test per bug).
3. Tests proven to bite: each fails with change reverted or mutated. Report how (e.g. "22/22 mutations caught"); name what headless tests can't prove. Rust: `tools/ci/ffi-libs.sh build-ffi && tools/ci/rust-mutants.sh diff origin/main build-ffi` (without FFI libraries bridge's FFI test catches nothing; CI runs same, 12 shards). C++ and cross-language: mutation in `tests/mutations/<list>.json` (`tools/mutation-check.py`). PR CI runs lists whose area PR touches, all weekly (`tools/ci/mutation-lists.py`). New crate → full-crate run (`mutants.yml`, by hand) before merge, results in PR.
4. `make check` green locally.
5. PR CI green: every CI job, SonarQube (quality gate, zero open issues or hotspots: `tools/ci/sonar-issues.py`), CodeQL.
6. Device: CI job "Sailfish OS 5.2 aarch64 RPMs" builds them on every push; run them on test phone (see "Device tests"); give user `netvfs-rpms-aarch64` artifact link of the green run and evidence. Change lautta uses → link lautta RPM too, say install order (netvfs first).
7. With RPMs: outline briefly what merging this PR risks and how you mitigated it.

PR opens as draft on first push. Mark ready for review only once steps 1–7 hold and their evidence is in PR body.

Docs-only change (docs, comments, no code or string change): steps 6–7 skipped; no phone run.

Backend and core code runs in every process that loads a backend (bridge, msyncd via Buteo, `netvfs-cli`, account UI) → cover all it reaches. Behaviour both protocols share → change and test SFTP and SMB.

User tests RPMs on phone; that test judges feel, lag, real servers. Say exactly what to check on device. Accounts and backups: create account per auth mode (wrong input: specific message, no account); manual backup, list, restore byte-identical; scheduled backup, screen off; server unreachable or upload cut: no leftover, no file without `.part`; changed host key or password: run fails, account not signed in, update flow fixes; account delete leaves server files.

## Device tests

- Test phone via `muhnschein-sfos-harness` workflow `do`. Its AGENTS.md rules every phone run (baseline, no blind taps, reboot, language, `clean_slate`, privacy); helpers: its README, `scripts/lib.sh`; netvfs specifics: its `apps/netvfs.md`. Test accounts and harness test servers only. Never run fork or others' PR code there: any job can root phone.
- Phone runs SFOS 5.1 (glibc 2.41: binaries run); packages Require `sailfish-version >= 5.2.0`. Until phone fits: no harness run without user's go for `apps/netvfs.nodeps`, results then hold on 5.1 only; say so.
- Install: `netvfs`, `netvfs-bridge`, `netvfs-backup` from one CI run, one transaction; lautta on top from its own run.
- Every run starts from named state; `state.txt` records it plus RPM names and sha256:
  - `clean`: wipe lautta if present, then netvfs packages, netvfs accounts (providers `sftp`, `smb`), `~/.config/netvfs`, `~/.local/share/netvfs`, `~/.cache/netvfs`; install.
  - `fixture:NAME`: `clean`, then restore snapshot saved with `fixture_save`.
  - `upgrade:FROM`: release FROM plus fixture, then install build over it. Required when change touches stored data, accounts, consent, known hosts, Buteo profiles or units.
- Footprint check (`fs_mark`, `footprint`): file touched outside known dirs → add to wipe or fail run. Leftovers taint results.
- Before/after: same start state, same steps.
- Change in bridge, backends, units: prove through a consumer (lautta, `netvfs-cli`) against harness SFTP/SMB servers. Accounts UI: Settings → Accounts shots. Backups: Buteo run, then restore.
- Privacy: user stays muhnschein, nothing more. Harness results come scrubbed (its AGENTS.md "Privacy"). PR evidence only from those files (crops, GIFs, charts made from them OK); never type identifiers in: host names, user names, keys, fingerprints included.
- Harness proves function and timing. Feel, lag, real servers stay user's call on device.

## Local checks

- `git submodule update --init --depth 1` before first build (`vendor/host/buteo-syncfw`: host-only Buteo, `make HOST_BUTEO=0` uses system's).
- Host deps (Ubuntu 24.04): `./tools/ci/install-host-deps.sh`, then `./tools/ci/cargo-tool.sh cargo-nextest 0.9.148`.
- `make check` = Rust checks, C++ unit tests, bridge tests against built C ABI, interop suite (OpenSSH, Samba containers: docker). CI adds `make check-packaging`, `make SANITIZE=1 check`, target tests under qemu, QML on SDK target (`tests/qmltarget/run-in-sdk.sh`).
- Rust interop tests without their servers (`NETVFS_SFTP_INTEROP_CONFIG`, `NETVFS_INTEROP_SMB_*`) pass at once, saying skipped. Skipped ≠ passed: say which steps skipped. Missing optional tool = SKIP locally, FAIL in CI.
- Iterating → run only what change touches: `cd rust && cargo nextest run -p netvfs-smb`, one C++ test binary from `build/tests`. Before every push: full `make check`. CI runs everything (docs-only PR: no build or test jobs, `tools/ci/changes.sh`).
- Local failure → rerun on untouched `main` before calling it environment.
- Gates catch device-only breakage (lockfile cargo 1.95 reads, Qt 5.6 QML, linked libs and GLIBC floor, `%files` lists, `NETVFS_WERROR=1`). Gate red → fix code, never loosen gate.
- `unsafe` only in modules RUST.md names; every block says why.
- No own cryptography: primitives from ring and RustCrypto, RustCrypto in `netvfs-smb`'s `crypto.rs` only (fence). PR touching `crypto.rs` → separate security review pass; PR body lists every change to it.
- Server and consumer data = hostile: every length checked against its cap before allocating. New decoder → fuzz target (`rust/fuzz`, `tests/fuzz`).
- Mutant exclusion (`rust/.cargo/mutants.toml`) only with proof it changes no observable behaviour, written beside it. `crypto.rs`: none.
- Tests wait on signals or conditions, not fixed sleeps or wall-clock asserts (those flake on loaded runners).
- New dependency must earn its keep: well maintained, widely used, more than someone's pet project, builds at Rust 1.95, `cargo deny` clean (second version only with reason in `rust/deny.toml`). Say why in RUST.md's dependency list. Update with pinned cargo: `cd rust && cargo update -p <crate>`. `russh` pins RustCrypto pre-releases: bump as one unit. `rust/vendor/ssh-key`, `rust/vendor/picky-asn1-der` = patched copies (`README.netvfs.md` in each).

## UI and words

- Account UI (`accounts/ui`, *Settings → Accounts*): Silica stock components, platform account types of `jolla-settings-accounts` (`AccountCreationAgent`, `AccountSettingsAgent`, `AccountCredentialsAgent`, `AccountBusyPage`, `StandardAccountSettingsPullDownMenu`); no `OnlineSync*`, `AccountFactory` (assume HTTP); built like existing pages.
- "Design first" / "no PR yet" → mockup, wait for approval, then code.
- Every string `qsTrId()` with `//%` engineering English; catalogue generated at build (`translations/translations.pro`).
- Host QML tests (`tests/unit/qml`) and target load (`tests/qmltarget`, real Silica) don't prove looks: unproven until device test. Say so.
- Phone = battery: no polling, no timers without work. Bridge keeps its idle exit; backups run when Buteo schedules them.

## Comments and docs

- Caveman-full = drop articles, filler, pleasantries, hedging. Fragments OK, short words. Identifiers, paths, code, errors exact. E.g. "`rust/Cargo.lock` from pinned cargo: resolver v3 prefers crates whose `rust-version` fits 1.95."
- Code comments, `doc/*.md`, this file: caveman-full. What is true now and why; keep constraints. No changelog, bug report, history, story (git's job): delete comment rather than turn it into history. Existing prose: rewrite what you touch, not more.
- Default: no comment. One only for constraint, external quirk, invariant code can't show; one line where possible, four max. Applies to new and touched code; trim old long comments when changing that code anyway, no sweep.
- SPDX header on every source file. Change to what `doc/SPEC.md` or `doc/RUST.md` states → update it, same PR; describe what exists, no change notes. Details stay in code and tests.
- `README.md`, `CHANGELOG.md`, release notes, forum posts: plain prose for users, as short and to the point as possible.
- User-visible change → line in `CHANGELOG.md` under `## Unreleased` (file or section missing → create it), same PR.
- No plans, research notes, scratch files in repo.

## Git and PRs

- One branch, one PR per task. Stacked PR only when asked.
- Bridge protocol (`org.netvfs.Bridge1`) change → PRs in netvfs and lautta together, lockstep. `tests/bridge/contract/` JSON and XML stay identical to lautta's `tests/bridge-contract/`.
- Unrelated finding → tell user; separate PR or issue, not this PR.
- Commit and PR titles: Conventional Commits, plain language, say outcome: `fix(bridge): ad-hoc ids are never reused after a restart`. Types `feat` `fix` `perf` `refactor` `test` `docs` `ci` `build` `chore`; scope = part or subsystem (`bridge`, `accounts`, `sftp`, `smb`, `backup`, `core`, `cli`, `rpm`, …). Body says why, plain prose; brief, to the point.
- PR body: the problem in a sentence or two, then how you fixed it. End with the model and harness that did the work.
- Final diff: no debug logging, no leftovers.
- Evidence shown in PR body, not just described:
  - UI → before/after device screenshots.
  - Transitions, feel, lag → before/after GIF (plays inline; mp4 by URL shows as link only). GIF from harness mp4 via `ffmpeg`.
  - Performance → before/after chart (image), numbers in table beside it.
  - Non-visual proof (tests, mutations, logs, CI times) → text.
- Evidence on GitHub, never in tree: push to orphan branch `evidence/pr-N`, embed by URL in PR, delete branch after merge.
- Flaky test → find and fix cause. Never add retries (nextest profile `ci` runs none by design: pass on second try = defect). Never re-run CI until green and call it done. Never skip test or loosen assert. One re-run OK only for infra failure before any test ran (runner lost, apt mirror timeout); say so.
- Merge only on user's explicit go. Merge commit, not squash/rebase.
- Before asking for merge go: `main` moved since PR's last green run → merge `main` in, CI green again. Each PR green alone ≠ merge green. GitHub enforces it too ("Require branches to be up to date").

## Releases

- Only on user's go. None cut yet, no tags; version in `rpm/netvfs.spec` and `rust/Cargo.toml`. Latest `main` commit green first, Sonar included: check main, not just PR.
- Strict semver: nothing breaking → minor.
- Before release: advisories against locked crates resolved (D-2); interop suite re-run after any dependency bump (D-3).

## Subagents

- Delegate only with tight, written scope.
- Models: only ones on cost/intelligence Pareto frontier ([Artificial Analysis](https://artificialanalysis.ai/), [Slopalytics](https://slopalytics.com/)). Dominated model = don't use. Cheapest frontier model that does the job well. If user names model for task, use that.
- Cheap-model output gets strong-model review: cheap models dropped facts, inverted conditions.

## Reporting

- Replies to user: caveman-full (see Comments and docs).
- Lead with result. Say what was verified, what wasn't, what is guess.
- Non-green step → name it and why. Never hide.
- Bug report → search GitHub issues first, link match.
