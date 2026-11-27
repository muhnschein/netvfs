# AGENTS.md

How to work on netvfs. What it is: `README.md`, `doc/SPEC.md` (platform contract, trust model, budgets, limits, roadmap). Read `doc/RUST.md` before first change. User's words in chat beat this file.

## Ground rules

- Don't know how to proceed → say "I don't know", stop, ask. Mark guesses as guesses. Unknown beats confident wrong.
- Bugs: find root cause, state it. Symptom fix ≠ fix.
- Measure twice, cut once. YAGNI: fight scope creep; meet user's intent minimally, realistically. Good return on cost; no gold-plating, no unasked refactors.
- Rule here fights task → say so loudly, get user's sign-off before breaking it.
- Options → lay them out, recommend one with reasons. Implement nothing until user clearly picks.

## Where the code stands

- Mid Rust rewrite: accounts helper, bridge, SFTP, SMB, WebDAV and FTPS backends are Rust (`rust/`, `doc/RUST.md`); rest C++/QML (`doc/SPEC.md` "Roadmap"). More porting = planned work package, on user's go. No drive-by ports.
- No backwards compatibility between parts that ship together: change both sides in one PR. No version handshakes, option aliases, transition code.
- C ABIs (`netvfs_rs.h`, `netvfs_bridge_ffi.h`): `#[repr(C)]` by hand, no bindgen; sizes and offsets pinned by tests.

## Done means

In this order; later step only once earlier ones hold:

1. Change implemented.
2. Tests added for it (regression test per bug).
3. Tests proven to bite: each fails with change reverted or mutated. Report how (e.g. "22/22 mutations caught"); name what headless tests can't prove. Rust: `tools/ci/ffi-libs.sh build-ffi && tools/ci/rust-mutants.sh diff origin/main build-ffi` (without FFI libraries bridge's FFI test catches nothing; CI runs same, 12 shards). C++ and cross-language: mutation in `tests/mutations/<list>.json` (`tools/mutation-check.py`); PR CI runs lists of areas PR touches, all weekly. New crate → full-crate run (`mutants.yml`, by hand) before merge, results in PR.
4. `make check` green locally.
5. PR CI green: every CI job, SonarQube (quality gate, zero open issues or hotspots: `tools/ci/sonar-issues.py`), CodeQL.
6. Device: CI job "Sailfish OS 5.2 aarch64 RPMs" builds them on every push; run them on test phone (see "Device tests"); give user `netvfs-rpms-aarch64` artifact link of the green run and evidence. Change lautta uses → link lautta RPM too, say install order (netvfs first).
7. With RPMs: outline briefly what merging this PR risks and how you mitigated it.

PR opens as draft on first push. Mark ready for review only once steps 1–7 hold and their evidence is posted (visual: project thread; text: PR body).

No phone run when change can't show on phone: docs, CI, build scripts (RPM contents unchanged), tests only. Steps 6–7 skipped; PR says why.

Backend and core code runs in every process that loads a backend (bridge, Buteo plugins, `netvfs-cli`, account UI) → cover all it reaches. Behaviour backends share → change and test SFTP, SMB, WebDAV, FTPS.

User tests RPMs on phone; that test judges feel, lag, real servers. Say exactly what to check: for accounts and backups `doc/SPEC.md` "Confirm on device" acceptance, per protocol (pinned certificate counts as host key); app access: each level allows only what it names, narrowing closes app's connections.

## Device tests

- QML target tests (`tests/qmltarget`) and OS file lookups (Silica QML, `jolla-settings-accounts`, sailjail profiles): SDK container, never phone.
- Test phone on the local SFOS test host via the harness's `local/run.sh` (`muhnschein-sfos-harness`, `local/README.md`). Its AGENTS.md rules every phone run; netvfs specifics (install, wipe, servers): its `apps/netvfs.md`. Never run fork or others' PR code there: any run can root phone.
- Every run starts from named state; `state.txt` records it plus RPM names and sha256:
  - `clean`: wipe lautta if present, netvfs packages, accounts and data (harness `apps/netvfs.md` "Clean start"); install.
  - `fixture:NAME`: `clean`, then restore snapshot saved with `fixture_save`.
  - `upgrade:FROM`: release FROM plus fixture, then install build over it. Required when change touches stored data, accounts, consent, known hosts, Buteo profiles or units.
- Footprint check (`fs_mark`, `footprint`): file touched outside known dirs → add to wipe or fail run. Leftovers taint results.
- Before/after: same start state, same steps, one `local/run.sh` run (both builds). Build already passed same steps → cite that run, no rerun. Run stopped on own script mistake → fix from its shots, rerun only failed steps.
- Bridge, backends, units: prove through a consumer (lautta, `netvfs-cli`) against harness servers (`nas_up`, `nextcloud_up`). Accounts UI: shots past Accounts list, never of it. Backups: Buteo run, then restore.
- Privacy: user stays muhnschein, nothing more (harness AGENTS.md "Privacy"). Evidence only from `local/publish.sh` output (crops, GIFs, charts made from it OK); never type identifiers in: host names, user names, keys, fingerprints included.

## Local checks

- `git submodule update --init --depth 1` before first build (`vendor/host/buteo-syncfw`: host-only Buteo, `make HOST_BUTEO=0` uses system's).
- Host deps (Ubuntu 24.04): `./tools/ci/install-host-deps.sh`, then `./tools/ci/cargo-tool.sh cargo-nextest 0.9.148`.
- `make check` = Rust checks, C++ unit tests, bridge tests against built C ABI, interop suite (`tests/interop`, server containers: docker). CI adds `make check-packaging`, `make SANITIZE=1 check`, target tests under qemu, QML on SDK target (`tests/qmltarget/run-in-sdk.sh`).
- Rust interop tests without their server's env (set by `tests/interop/*/run.sh`) pass at once, saying skipped. Skipped ≠ passed: say which steps skipped. Missing optional tool = SKIP locally, FAIL in CI.
- Iterating → run only what change touches: `cd rust && cargo nextest run -p netvfs-smb`, one C++ test binary from `build/tests`. Before every push: full `make check`. CI runs everything (docs-only PR: no build or test jobs, `tools/ci/changes.sh`).
- Local failure → rerun on untouched `main` before calling it environment.
- Gates catch device-only breakage (lockfile cargo 1.95 reads, Qt 5.6 QML, linked libs and GLIBC floor, `%files` lists, `NETVFS_WERROR=1`). Gate red → fix code, never loosen gate.
- `unsafe` only in modules RUST.md names; every block has `// SAFETY:` (clippy `undocumented_unsafe_blocks`).
- No own cryptography: primitives from ring and RustCrypto, RustCrypto in `netvfs-smb`'s `crypto.rs` only (fence). PR touching `crypto.rs` → separate security review pass; PR body lists every change to it.
- Server and consumer data = hostile: every length checked against its cap before allocating. New decoder → fuzz target (`rust/fuzz`, `tests/fuzz`).
- Mutant exclusion (`rust/.cargo/mutants.toml`) only with proof it changes no observable behaviour, in commit body and PR. `crypto.rs`: none.
- New dependency must earn its keep: well maintained, widely used, more than someone's pet project, builds at Rust 1.95, `cargo deny` clean (second version only with reason in `rust/deny.toml`). Say why in RUST.md's dependency list. Update with pinned cargo: `cd rust && cargo update -p <crate>`. `russh` pins RustCrypto pre-releases: bump as one unit. `rust/vendor/ssh-key`, `rust/vendor/picky-asn1-der` = patched copies (`README.netvfs.md` in each).

## New tests

Every added or changed test, before push:

- Honest: fails when behaviour its name claims breaks (step 3 proves it). No assert that cannot fail: tautology, check of own setup, assert in branch or loop that may not run, discarded result, timeout read as answer.
- Waits on signal or condition only: one the step under test alone makes, and makes once. No sleep, wall-clock assert. Timeout = hang guard: seconds for work of milliseconds. Fixed wait only for "nothing happens"; test name says so.
- Parallel-safe: passes alone and among 32 others (nextest `test-threads`). Own tempdir; no fixed port or path, shared HOME/XDG, env or cwd change, global state across tests.
- Runner stalls any thread for hundreds of ms: test still passes. Async or timing-sensitive → `cargo nextest run --stress-count 20 <filter>` on loaded host, or stall injected at race point; say which.

## UI and words

- Account UI (`accounts/ui`, `src/qml`): Silica stock components; of closed platform types only those `doc/SPEC.md` "Backup platform contract" names; built like existing pages.
- "Design first" / "no PR yet" → mockup, wait for approval, then code.
- Every string `qsTrId()` with `//%` engineering English; catalogue generated at build (`translations/translations.pro`).
- Host QML tests (`tests/unit/qml`) and target load (`tests/qmltarget`, real Silica) don't prove looks: unproven until device test. Say so.
- Phone = battery: no polling, no timers without work. Bridge keeps its idle exit; backups run when Buteo schedules them.

## Comments and docs

- Caveman-full = drop articles, filler, pleasantries, hedging. Fragments OK, short words. Identifiers, paths, code, errors exact. E.g. "`rust/Cargo.lock` from pinned cargo: resolver v3 prefers crates whose `rust-version` fits 1.95."
- No code comments, except public API docs: no why, issue reference, TODO, commented-out code; in any source, build or config file. Names and tests say what code does. `make check` runs `tools/no_comments.py`.
- No workarounds for this rule: no comment archive, no notes or doc file standing in for comments, no comment text hidden in strings or names. Only an absolutely critical fact (code breaks or regresses without it) gets written down: project memory, one short sentence each.
- Public API docs, concise (one line where it fits): Rust doc comments only where `missing_docs` or clippy (`# Errors`, `# Panics`, `# Safety`) demand them; installed headers (`PUBLIC_HEADERS`, `src/core/core.pro`); `org.netvfs.Bridge1.xml`. No doc comment on private items.
- Kept, because a tool or licence needs them: shebang; SPDX line 1 (line 2 after shebang or `<?xml`); attribution header with `SPDX-FileCopyrightText` (adapted BSD code in `src/buteo/lib`); `//%` lupdate source text; `// fuzz-<key>:` build lines in `tests/fuzz` harnesses; `// SAFETY:` above `unsafe`; bare `// NOSONAR`. Lint skips vendored code, CodeQL query copy, test data, `doc/`, `art/`, Markdown (`tools/no_comments.py`).
- SPDX header on every source file.
- `doc/*.md`, this file: caveman-full. What is true now and why; keep constraints. No changelog, bug report, history, story (git's job). Existing prose: rewrite what you touch, not more. Change to what `doc/SPEC.md` or `doc/RUST.md` states → update it, same PR. Details stay in code and tests.
- `README.md`, `CHANGELOG.md`, release notes, forum posts: plain prose for users, short and to the point.
- User-visible change → line in `CHANGELOG.md` under `## Unreleased` (missing → create it), same PR.
- No plans, research notes, scratch files in repo.

## Git and PRs

- One branch, one PR per task. Stacked PR only when asked.
- Bridge protocol (`org.netvfs.Bridge1`) change → PRs in netvfs and lautta together, lockstep. `tests/bridge/contract/` JSON and XML stay identical to lautta's `tests/bridge-contract/`.
- Unrelated finding → tell user; separate PR or issue, not this PR.
- Commit and PR titles: Conventional Commits, plain language, say outcome: `fix(bridge): ad-hoc ids are never reused after a restart`. Types `feat` `fix` `perf` `refactor` `test` `docs` `ci` `build` `chore`; scope = part or subsystem (`bridge`, `accounts`, `sftp`, `smb`, `webdav`, `ftps`, `backup`, `core`, `cli`, `rpm`, …). Body says why, plain prose, brief.
- PR body: the problem in a sentence or two, then how you fixed it. End with the model and harness that did the work.
- Final diff: no debug logging, no leftovers.
- Evidence shown, not just described: UI → before/after device screenshots; feel, lag, transitions → before/after GIF (from harness mp4 via `ffmpeg`) or mp4; performance → before/after chart plus numbers table; non-visual proof (tests, mutations, logs, CI times) → text. Visual in project thread, text in PR body, never on GitHub: no `evidence/` branches, uploads, assets in any branch.
- Flaky test → find and fix cause. Never retries (nextest profile `ci` has none: pass on second try = defect), re-running CI until green, skipped test, loosened assert. One re-run only for infra failure before any test ran (runner lost, apt mirror timeout); say so.
- Merge only on user's explicit go. Merge commit, not squash/rebase.
- Before asking for merge go: `main` moved since PR's last green run → merge `main` in, CI green again. Each PR green alone ≠ merge green.

## Releases

- Only on user's go. Tag `vX.Y.Z` on main's merge commit; GitHub release carries that commit's CI RPMs (`netvfs-rpms-aarch64`). Version in `rpm/netvfs.spec`, `rust/Cargo.toml`, `sonar-project.properties`. Latest `main` commit green first, Sonar included: check main, not just PR.
- Strict semver: nothing breaking → minor.
- Before release: advisories against locked crates resolved; interop suite re-run after any dependency bump; CI started by hand on release commit (`gh workflow run ci.yml --ref main`), job "RPMs rebuild byte for byte" green.

## Subagents

- Delegate only with tight, written scope.
- Models: only ones on cost/intelligence Pareto frontier ([Artificial Analysis](https://artificialanalysis.ai/), [Slopalytics](https://slopalytics.com/)). Dominated model = don't use. Cheapest frontier model that does the job well. If user names model for task, use that.
- Cheap-model output gets strong-model review: cheap models dropped facts, inverted conditions.

## Reporting

- Replies to user: caveman-full (see Comments and docs).
- Lead with result. Say what was verified, what wasn't, what is guess.
- Non-green step → name it and why. Never hide.
- Bug report → search GitHub issues first, link match.
