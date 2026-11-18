---
name: game-rewrite
description: Rewrite a PC game the user owns as complete, readable source code in C++ or Rust that builds a native Windows executable and plays like the original, using the game's own data files. Builds on the byte-identical-game-decomp skill (decoded data, recovered and named code, matched C++) and proves behaviour with a differential test harness (scripted input, frame-by-frame state traces against the original). Two modes - private (translated from the decompilation, never published) and publishable (clean-room: implementers who never see the decompilation write from behaviour specs and traces, with a logged hand-over and a release gate that checks for copied code, names, tables and assets). Use when the user wants a source port, a modernized or moddable rebuild, a C++ or Rust version of a game, an open-source engine reimplementation, or to "rewrite"/"reimplement"/"port" a game they own.
---

# Game rewrite (C++ or Rust)

The goal: from a game the user owns, a source tree in the language the user picks (C++ or Rust) that
builds a Windows executable which loads the game's own data and behaves like the original, frame for frame.

Ask which mode first (the decomp skill records it as `"mode"` in `decomp.json`; its
`references/legal-and-repo.md` has the reasons; say once that this is not legal advice):

| | Private (default) | Publishable |
|---|---|---|
| Step 4 | translate the matched C++ / pseudocode (`cpp.md`, `rust.md`): fastest, most exact | clean room (`cleanroom.md`): analysts write behaviour specs, fresh implementer sessions write their own design from them and the traces |
| Record | - | `cleanroom.py` (lint of specs, logged hand-overs, hash-chained log) |
| Output | stays in the user's local project, git-ignored, never published | may be published once `release_check.py` passes and the user has gone through its manual checklist |

A translated rewrite is a derivative work of the original code in any language, however clean it looks: it is
never published, and the people (or agent sessions) who worked on it cannot be clean-room implementers.

The rewrite stands on the decompilation, not on guesswork. Run the byte-identical-game-decomp skill first, at
least to these gates: game folder (phase 1), data decoded with formats documented (phase 3), complete code
recovery (phase 4), names (phase 5), byte-identical reassembly (phase 5b). Matched C++ (phase 6) is the best
starting point for a C++ rewrite and a good one for Rust; without it, the rewrite is written from the
decompiled pseudocode.

| Step | Output | Gate |
|---|---|---|
| 1 Inventory | which code is the game's, which is a library (name, exact version), which is the runtime | every function classified |
| 2 Toolchain | the chosen language's Windows build, upstream libraries at the pinned versions | a hello program using every library runs on Windows |
| 3 Oracle | the original game built with hooks: scripted input, a per-frame state trace, a framebuffer hash | N runs of each scenario give byte-identical traces and saves |
| 4 Rewrite | game code in the chosen language, organized by subsystem (publishable: clean room) | it builds; each subsystem has a scenario |
| 5 Compare | traces of the rewrite against the oracle | identical traces (and saves) for every scenario |
| 6 Play | the rewrite on Windows | the user plays it |
| 7 Release (publishable only) | the clean tree with LICENSE, README, notices | `release_check.py` passes; manual items checked with the user |

Details are in the references; read the one for each step before starting it.

| Reference | Read when |
|---|---|
| `references/inventory.md` | step 1: game code vs libraries vs runtime, pinning library versions from the binary, static or DLL |
| `references/toolchains.md` | step 2: C++ (original MSVC, or current MSVC / clang-cl), Rust (windows targets, raw-dylib, cross build without MinGW), `libraries.json`, the hello gate, Wine vs Windows |
| `references/harness.md` | steps 3 and 5: the oracle, hook points, determinism, replay and trace formats, scenarios, comparison, the hooks in the rewrite |
| `references/cpp.md` | step 4 in C++: from matched units (or pseudocode) to a clean tree by subsystem; the one-shot generator; what is scaffolding; extern-only data; link order; entry point; build; accounting; testing with real input |
| `references/rust.md` | step 4 in Rust: crate layout, the `Cx` context struct and the borrow rule, FFI to the library DLLs (C API shims, callbacks on other threads), the numeric fidelity checklist (x87 vs SSE, `ftol`, wrapping, signed `char`, argument order, macros that evaluate twice), strings, containers, UB the original relies on, the skeleton generator, testing |
| `references/cleanroom.md` | publishable mode, before step 4: roles and isolation, writing specs, workspaces, the question/answer loop, game data at run time, the log, the release gate and its calibration, settings, publishing |
| `references/orchestration.md` | before step 2 when agents do the work: which steps are single-agent, the wave pattern (brief, private copies, owned modules, WAVE_NOTES), integration, the comparison loop with the other rewrite as reference, widening scenarios, independent verification, operational lessons |

## Project config
Everything game-specific lives in the project, in a `"rewrite"` section of the decomp skill's
`decomp.json` (keys in `toolchains.md` and `harness.md`), and in `rewrite/libraries.json`. A sketch:
```json
"rewrite": {
  "libraries": "rewrite/libraries.json",
  "paths": {"downloads": "rewrite/third_party/downloads", "src": "rewrite/third_party/src", "build": "rewrite/third_party/build"},
  "toolchain": {"cl_mode": "wine", "machine": "x86"},
  "exe_name": "Game.exe", "game": "build/oracle/game", "runner": "wine", "wineprefix": "~/.wine",
  "env": {"replay": "GAME_REPLAY", "trace": "GAME_TRACE", "exit_frame": "GAME_EXIT_FRAME", "fb": "GAME_TRACE_FB"},
  "args": ["-savedir", "{basedir}\\"], "saves": "saves", "fps": 30,
  "trace": {"header": "GAME-TRACE 1", "frame_field": "f", "fields": ["gs", "p", "v", "fb"], "decode": {"v": "f32"}},
  "scenarios": "rewrite/harness/scenarios",
  "oracle": {"binary": "Game", "dir": "build/oracle", "files": ["rewrite/harness/hooks.h"],
             "edits": "rewrite/harness/oracle_edits.json", "traces": "rewrite/harness/oracle"}
}
```
On the user's Windows PC set `"runner": "native"` and `"cl_mode": "native"` (or leave them out: they default
by platform). Game-derived files (traces, saves, the oracle, the rewrite's source) stay local and out of
git, like the decomp skill's outputs.

## Scripts
All in `scripts/`, Python 3.9+ standard library only, run as `python3 -I <script>`; `--help` on each. Each
has a JavaScript port in `scripts/js/` (Node 20+ built-ins only, same command line, output and files);
`node scripts/js/parity/run_all.mjs` runs both on synthetic inputs (fake game, fake Wine and compiler,
made-up matched units, a tiny PE) and must report every case identical. Change both sides together; `--sync-docs` copies docstrings to the ports.

| Script | Step | Purpose |
|---|---|---|
| `build_libs.py` | 2 | `list`, `fetch` (sha256-pinned), `extract`, `build` (static for C++, DLLs for Rust), `runtime` (Rust gnu runtime) from `libraries.json` |
| `cpp_build.py` | 2, 4 | compile and link a C/C++ program with MSVC (Wine or native) against the static libraries |
| `rust_build.sh` | 2, 4 | cargo build for `i686-pc-windows-gnu` with `rust-lld` and no MinGW (macOS/Linux) |
| `rust_gnu/` | 2 | `crt_shim.c`, `.def` files, `gen_defs.py` (more imports for a newer std), `dlltool.py` + `bin/` stand-in for raw-dylib |
| `capi/`, `msvc_compat/` | 2 | C API shim example (tinyxml2), allocator and patched-copy wrappers; headers old MSVC lacks |
| `run_wine.py` | 2, 6 | run an exe from a fresh copy of the game folder (Wine or native), wait for its window, collect its log, retry |
| `wintools.py` | 2 | PE exports/imports, COFF externals, `.def` from a DLL |
| `build_oracle.py` | 3 | the oracle: matched source + hook files + checked edits, built by the decomp pipeline |
| `harness/harness_core.h` | 3, 4 | game-independent C/C++ half of the hooks |
| `run_scenario.py` | 3, 5 | one replay with one exe: scratch copy, contract variables, retries, trace and saves |
| `record_oracle.py` | 3 | N runs per scenario, determinism report, the oracle's traces and saves |
| `compare_traces.py` | 5 | frame-by-frame, field-aware trace comparison, first divergence, JSON summary |
| `cpp/cppsplit.py` | 4 | split matched units into top-level items with their annotations, classified |
| `cpp/account.py` | 4 | every `// FUNCTION`/`// STUB` annotation -> output file or reason; unaccounted ones fail |
| `cpp/emit.py` | 4 | one-shot generator: place annotated functions by config, drop scaffolding, canonical constants, headers |
| `cpp/gen_data.py` | 4 | C++ definitions of extern-only data, read from the exe's sections |
| `cpp/keysend.cpp` | 4, 6 | Win32 tool: post scripted key presses to a window by title (real input) |
| `examples/libraries_example.json` | 1, 2 | a complete `libraries.json` for an SDL2 game with seven static libraries (pins, evidence, build fields, C API shims, a patched copy, a prebuilt SDK) |
| `examples/cpp_config_example.json` | 4 | a small made-up cpp config that shows every key (placement, scaffolding patterns, renames, constants, data tables) |
| `rust/gen_skeleton.py` | 4 | `index`: function index from matched units (address, name, C++ head, unit, class, body; globals; class members); `generate`: one Rust stub per function with its address line, `src/state/statics.rs`, `names.tsv`, never over a hand-edited file |
| `rust/replace_fn.py` | 4 | replace functions in a `.rs` file by new versions, matched by their `// 0x<address>` line |
| `rust/template/` | 4 | `stub.rs` (stub macro, log file, panic hook), `cnum.rs` (MSVC `rand`, `ftol`, C numerics), `cbuf.rs` (`CBuf<N>` = `char[N]`): generic, copy into the crate |
| `cleanroom.py` | 4 (publishable) | `init`, `lint` (specs: Ghidra names, code blocks, token runs shared with the reference), `pack` (an implementer's workspace, refusing forbidden or failing inputs), `record` (questions, answers), `verify` (the hash-chained log) |
| `release_check.py` | 7 | the release gate: log, assets, address markers and Ghidra names, embedded tables, shared strings, original names, similarity fingerprints, notices; allow file with reasons |
| `cleanlib.py` | 4, 7 | shared: settings, tokenizer (C, C++, Rust), fingerprints, reference corpus, the log |
| `examples/rust_config_example.json` | 4 | a small made-up gen_skeleton config that shows every key (modules, class roles, placement rules, cx analysis, type mapping) |

## Validated on
End to end on a 2010s SDL2 game built with VS2010 SP1 (`/MT`, SDL2 as a DLL, seven static libraries):
libraries pinned from the binary, both toolchains' hello programs `RESULT: OK` under Wine on macOS, an oracle
with 4 edited main-loop functions and about twenty scenarios (1,000 to 5,000 frames each: menus, every play
mode, the level editor, test levels the harness wrote itself, every language family, seeded fuzz) that gave
byte-identical traces and saves in every run. Steps 1-5 were done for both languages:
- **C++ rewrite**: about a thousand game functions (every NONMATCHING one included) plus a rewritten
  `WinMain`, about 110 `.cpp`/`.h` files, built with the original compiler;
- **Rust rewrite**: every function translated from generated stubs (a few written by hand in the
  foundation), about 30 modules and 80,000 lines, `i686-pc-windows-gnu` with rust-lld and the libraries as
  DLLs, `unsafe` only in the FFI layer; built by 8 parallel translation waves and one integration
  (`orchestration.md`);
- **both identical to the original in every scenario**, framebuffer hash and save files included, and
  identical to each other in dozens of extra fuzz replays.
Step 6, a user playing the rewrite on Windows, is not part of what was validated.
The clean-room tools were calibrated on the same project (`cleanroom.md` section 7): the Rust translation
fails every release check (93 % code and 98 % constant fingerprints shared, 55 % of its function names the
original's), independent open-source implementations of the same jobs pass (0 % code, at most 14 %
constants, 7 % names). A complete clean-room rewrite has not been run end to end yet.
