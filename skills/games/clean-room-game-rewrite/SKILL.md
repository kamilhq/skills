---
name: clean-room-game-rewrite
description: >
  Turn a PC game the user owns (GOG installer or installed folder; 32-bit Windows, MSVC-built) into a
  playable source rewrite in C++ or Rust (the user picks after the analysis) that builds a Windows exe,
  reads the user's own game data at run time and matches the original frame for frame. Clean-room:
  analysts extract the installer, gate on copy protection, recover and name all code with Ghidra, prove
  every data format with round-trip readers and write behaviour specs in their own words; a probe DLL
  records the unchanged original's per-frame traces; fresh implementer sessions that never see decompiled
  code write the game from specs and traces, with logged hand-overs and a release gate for copied code and
  assets. Use whenever the user wants to rewrite, reimplement, remake, source-port, decompile or
  reverse-engineer a game they own, build an open-source engine for it, decode its archives or formats, or
  mentions a GOG installer, setup_*.exe, innoextract or Ghidra headless - even for one step.
compatibility: >
  macOS, Linux or Windows host. Analysis: Python 3.9+ (stdlib only) and Ghidra 12.x with its JDK. Oracle and
  rewrite: Wine on macOS/Linux, an x86 MSVC (user-supplied; VS2010 SP1 is free from Microsoft) for the probe
  and a C++ rewrite, clang and Rust for a Rust rewrite. Run scripts/check_deps.sh first.
---

# Clean-room game rewrite

The end state the user wants: **give it the installer of a game they own, get back a playable game** - a
source tree in C++ or Rust that builds a Windows executable, loads the original's data from the user's
installation and plays like the original, proven by identical per-frame traces. Because it is written
clean-room, that tree is the one thing the user may publish; everything derived from the game stays on
their machine (`references/legal.md`; say once that this is not legal advice).

The work has two sides that never mix:
- **Analysis side** (the coordinator and analyst subagents): reads the user's copy of the game, its
  decompilation and the original running. Writes specs, format docs, the trace contract and tools.
- **Clean side** (implementers: fresh sessions that never had analysis in their context): reads only what
  `cleanroom.py pack` hands over, and writes the rewrite.

| # | Step | Side | Output | Gate |
|---|---|---|---|---|
| 0 | Ownership, legal, project | coordinator | private project, `.gitignore`, `decomp.json`, `cleanroom.py init` | the user confirms they own the game |
| 1 | Intake | analysis | game folder, SHA-256 manifest, protection report | identical to GOG's hash list; no copy protection or packer |
| 2 | Inventory | analysis | census of files, formats, archives, binaries | every file classified |
| 3 | Analysis | analysis | 3a recovered code, 3b names, 3c code inventory + `libraries.json`, 3d format readers + `docs/formats/`, 3e behaviour specs | 0 orphan instructions; every function classified; every file round-trips (archives: members verified); specs lint clean and cover every subsystem |
| 4 | Oracle | analysis | probe DLL on the unchanged original, `HOOKS.md`, scenarios, the oracle's traces | N runs of every scenario byte-identical |
| 5 | Language | the user | C++ or Rust | the user has chosen |
| 6 | Toolchain | clean | libraries at the pinned versions, the chosen language's Windows build | hello program uses every library on the game's data, `RESULT: OK` |
| 7 | Implementation | clean | the rewrite, by subsystem, in waves | it builds; every subsystem has a scenario |
| 8 | Compare | both | questions and answers until traces match | identical traces and saves in every scenario (or divergences documented and accepted) |
| 9 | Play and release | user, coordinator | the user plays it; LICENSE, README, notices | `release_check.py` passes; manual items checked with the user |

Start every session with `sh scripts/check_deps.sh` (all scripts are in this skill's `scripts/`). Do not
install proprietary software for the user, and never download a compiler or game files from unofficial
sources. Report progress with numbers a script produced (files read, functions recovered, scenarios
identical); when something is inferred rather than shown, or not done, say so.

## Step 0 - ownership, legal, project
Ask the user to confirm they own the game and for the installer path (GOG `setup_<game>_<ver>.exe` plus any
`.bin` parts beside it) or the installed folder. Explain once, briefly: copyright covers code and assets, not
behaviour or formats; so analysis stays private and only behaviour descriptions cross to the people who
write the rewrite; copy protection is never circumvented (`references/legal.md`). Do **not** ask about the
language yet: the specs are language-neutral, and the choice is better made once the game is understood.
Then `pipeline.py init --game NAME` (config, `.gitignore`) and `cleanroom.py init` (the record starts before
anyone reads decompiled code). Keep any GitHub repository of the project private; no absolute paths, names
or emails in committed files.

## Steps 1-2 - intake and inventory
`pipeline.py intake <setup.exe | folder>` extracts with the skill's own Inno Setup reader (`inno.py`), checks
every file against GOG's hash list, writes the manifest, and runs `protection_check.py`: on any copy
protection or packer (SafeDisc, SecuROM, StarForce, the Steam DRM wrapper, UPX, ...), stop and tell the user
- never remove, bypass or unpack one; suggest a DRM-free release (`references/intake.md`).
`pipeline.py inventory` lists every format, magic, XOR layer and archive; `pipeline.py archives` extracts
ZIP-based archives with their CRCs checked. List every PE binary for step 3.

## Step 3 - analysis (analysts only)
- **3a Code recovery.** `pipeline.py recover` runs `ghidra/run_recovery.sh` (aggressive finder, pointer
  tables, orphan code, code gaps, cleanup) and `code_coverage_check.py`. Gate: 0 orphan instructions, every
  gap shown to be data (`references/code-recovery.md`).
- **3b Naming.** `pipeline.py features`, namer -> auditor workflows per chunk, `pipeline.py names`; an
  architecture doc on the analysis side (`references/naming.md`).
- **3c Code inventory.** Game code vs libraries (name, exact version, build options) vs runtime; the
  libraries go to `rewrite/libraries.json` (`references/code-inventory.md`).
- **3d Formats.** One Python reader per format group (`tools/formats/fmt_<module>.py`), round trip on every
  file (`pipeline.py decode`, completeness gate), and a format doc per module in the analysts' own words
  (`docs/formats/`, no addresses) that crosses to the implementers (`references/formats.md`).
- **3e Behaviour specs.** One spec per subsystem (`cleanroom/specs/`): states, rules, formulas, timings,
  edge cases, constants as facts, the order of random draws, where data lives in the user's files - never
  code, pseudocode, addresses or the original's names. `cleanroom.py lint` must pass
  (`references/cleanroom.md` section 2). Refine them from traces once the oracle exists.
Delegate with builder -> skeptic -> fix and a completeness critic (`references/orchestration.md`).

## Step 4 - the oracle (analysts only)
The original game, unchanged on disk, plays scripted input and writes one trace line per logic frame. A
**probe** - a proxy DLL in place of a DLL the game loads (`wintools.py proxy` makes its `.def`;
`harness/probe_core.h` and `harness/harness_core.h` hold the generic halves) - replaces input after each
poll, fakes the clocks for one fixed step per frame, reads state at the documented addresses and hashes the
framebuffer at present. Write the contract in words first (`rewrite/harness/HOOKS.md`), then scenarios that
cover every subsystem, then `record_oracle.py --runs 3`: every run identical (`references/harness.md`).
Implementers will get the contract, the scenarios and the traces - never the probe.

## Step 5 - ask the user for the language
Now, with the game understood, ask which language the rewrite is written in. Offer:
- **C++** - closest to the original's runtime (the same compiler family can be used, so float and CRT
  behaviour match with the least effort); the probe's toolchain is reused.
- **Rust** - memory safety, a modern toolchain; needs explicit care for C numerics (`cnum.rs`), `unsafe`
  only in the FFI layer; libraries are bound as DLLs.
- Another language is possible, but the skill's build scripts and guides cover only these two: say so.
Record the answer (`decomp.json` `rewrite.language`) and add the matching guide (`references/cpp.md` or
`references/rust.md`) to every implementer workspace.

## Steps 6-8 - toolchain, implementation, comparison (clean side)
Implementers are new sessions, never forks, working in a folder outside the project with deny rules for it
(`references/cleanroom.md` section 1). Each gets a workspace from `cleanroom.py pack`: specs, format docs,
scenarios and the oracle's traces, `HOOKS.md`, `libraries.json`, the language guide, `RULES.md`.
- **6 Toolchain:** `build_libs.py` (sha256-pinned upstream sources), `cpp_build.py` or `rust_build.sh`, the
  hello program on the game's own data (`references/toolchains.md`).
- **7 Implementation:** an architect designs the tree and its stubs (`todo_spec!` / `TODO_SPEC` name the
  spec section), then parallel waves fill modules in private copies with `WAVE_NOTES.md`, then one
  integrator merges (`references/orchestration.md` section 4).
- **8 Compare:** `run_scenario.py` + `compare_traces.py` against the oracle's traces. A divergence the specs
  do not explain becomes a written question (`cleanroom.py record`), answered by an analyst as behaviour
  in a new spec section and handed over with a new `pack`. Widen the scenarios meanwhile.

## Step 9 - play and release
The user plays the rewrite on Windows. The coordinator re-runs every check itself (clean rebuild, every
scenario, `cleanroom.py verify`) and then `release_check.py` (log, assets, address markers and Ghidra names,
embedded tables, shared strings, original names, similarity fingerprints, notices). The clean tree lives in
its own repository; publishing is the user's decision and action (`references/cleanroom.md` section 9).

## Project config
Everything game-specific lives in the project: `decomp.json` (analysis keys: `references/pipeline.md`; a
`"rewrite"` section for the oracle, the toolchain and the clean room: `harness.md`, `toolchains.md`,
`cleanroom.md`), `rewrite/libraries.json`, `tools/formats/`, `cleanroom/`.

## Scripts
All in `scripts/`, Python 3.9+ standard library only, run as `python3 -I <script>`; `--help` on each. Every
Python script has a Node.js port in `scripts/js/` (same name, `.mjs`; same command line, output and files;
Node >= 20 built-ins only); `node scripts/js/parity/run_all.mjs` runs both on the same inputs and must
report every case identical. Change both sides together, with their parity cases, in one commit.

| Script | Step | Purpose |
|---|---|---|
| `check_deps.sh` | all | what is installed, per step, with install hints |
| `pipeline.py` | 0-3 | `init`, `intake`, `inventory`, `archives`, `recover`, `features`, `names`, `decode`, `completeness`, `status` from `decomp.json` |
| `inno.py`, `intake.py` | 1 | pure-Python Inno Setup reader; extraction, GOG hashdb gate, manifests |
| `protection_check.py` | 1 | copy-protection and packer gate |
| `inventory.py` | 2 | format census, magic and single-byte-XOR detection, archive member counts |
| `ghidra/run_recovery.sh` (+ `.java`), `code_coverage_check.py` | 3a | complete function recovery and decompile; independent coverage check |
| `ghidra/inspect.sh`, `peek.py` | 3 | read-only questions to a Ghidra project; bytes and strings at an address |
| `build_features.py`, `ghidra/apply_names.sh` | 3b | naming chunks, vtables; apply names |
| `verify.py`, `pngio.py`, `formats/` | 3d | the round-trip harness; generic readers (PNG, WAV, ZIP, text) |
| `wintools.py` | 3c, 4, 6 | PE exports/imports, COFF externals, import-library `.def`, the probe's forwarding `.def` (`proxy`) |
| `harness/probe_core.h`, `harness/harness_core.h` | 4, 7 | the probe's generic half; the trace contract's C half (replay, FNV-1a, framebuffer hash) |
| `run_scenario.py`, `record_oracle.py`, `compare_traces.py` | 4, 8 | one replay with one exe; the oracle's determinism record; frame-by-frame comparison |
| `run_wine.py`, `harness/keysend.cpp` | 6, 9 | run an exe from a fresh copy of the game folder; real key presses |
| `build_libs.py`, `cpp_build.py`, `msvc.sh`, `rust_build.sh`, `rust_gnu/`, `capi/`, `msvc_compat/` | 4, 6 | libraries from pinned upstream sources; C/C++ and Rust Windows builds (Rust without MinGW) |
| `rust/template/` | 7 | `stub.rs` (`todo_spec!`, log, panic hook), `cnum.rs` (MSVC `rand`, `ftol`, C numerics), `cbuf.rs` |
| `cleanroom.py` | 0, 3e-8 | `init`, `lint` (specs), `pack` (workspaces, refusing forbidden inputs), `record`, `verify` (the hash-chained log) |
| `release_check.py`, `cleanlib.py` | 9 | the release gate and its shared tokenizer, fingerprints and log |
| `examples/libraries_example.json` | 3c, 6 | a complete `libraries.json` for an SDL2 game with seven static libraries |

## Reference files
| File | Read when |
|---|---|
| `references/legal.md` | step 0: the two sides, the legal reasons behind every rule, copy protection, what may be committed |
| `references/dependencies.md` | setting up a machine |
| `references/pipeline.md` | running steps 1-3 with `pipeline.py`; writing `decomp.json` |
| `references/intake.md` | step 1; installer will not extract; starting from an installed folder; the protection gate |
| `references/code-recovery.md` | step 3a; coverage gaps; Ghidra pitfalls |
| `references/naming.md` | step 3b; CONTEXT template; applying names |
| `references/code-inventory.md` | step 3c: game vs library vs runtime, pinning library versions |
| `references/formats.md` | step 3d: the reader contract, honesty rules, archives, auditing |
| `references/cleanroom.md` | before step 3e and before every hand-over: roles, specs, workspaces, the question loop, data at run time, the record, the release gate, publishing |
| `references/harness.md` | steps 4 and 8: the probe, hook points, determinism, replay and trace formats, scenarios, comparison |
| `references/toolchains.md` | step 6 (and the probe's compiler in step 4): C++ and Rust Windows builds, `libraries.json`, the hello gate, MSVC under Wine |
| `references/cpp.md`, `references/rust.md` | step 7, in the chosen language: for implementers |
| `references/orchestration.md` | spawning subagents for any step: analysis workflows, implementation waves, verification, lessons |

## Validated so far
The analysis steps (intake, inventory, complete recovery, naming, round-trip readers) ran on a 2010s SDL2
game (VS2010 SP1) and a 2000s Direct3D game (Visual C++ 6.0, 13 binaries, about 9,500 files). The trace
harness (replay format, determinism record, comparison) and both toolchains were proven on the SDL2 game,
where rewrites made with an earlier, translation-based process matched the original in about twenty
scenarios; the release gate was calibrated against them (`cleanroom.md` section 7). Not yet validated: the
probe against a real game (`probe_core.h` is compiled, not run) and a complete clean-room rewrite end to end.
Say so when setting expectations: thousands of functions mean days of agent work and several question
rounds per subsystem.
