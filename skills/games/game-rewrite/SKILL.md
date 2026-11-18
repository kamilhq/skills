---
name: game-rewrite
description: Rewrite a PC game the user owns as complete, readable source code in C++ or Rust that builds a native Windows executable and plays like the original, using the game's own data files. Builds on the byte-identical-game-decomp skill (decoded data, recovered and named code, matched C++) and proves behaviour with a differential test harness (scripted input, frame-by-frame state traces against the original). Use when the user wants a source port, a modernized or moddable rebuild, a C++ or Rust version of a game, or to "rewrite"/"reimplement"/"port" a game they own.
---

# Game rewrite (C++ or Rust)

The goal: from a game the user owns, a source tree in the language the user picks (C++ or Rust) that
builds a Windows executable which loads the game's own data and behaves like the original, frame for frame.
Nothing derived from the game is published: the rewrite lives in the user's local project, like every other
game-derived output of the byte-identical-game-decomp skill.

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
| 4 Rewrite | game code in the chosen language, organized by subsystem | it builds; each subsystem has a scenario |
| 5 Compare | traces of the rewrite against the oracle | identical traces (and saves) for every scenario |
| 6 Play | the rewrite on Windows | the user plays it |

Details are in the references; read the one for each step before starting it.

| Reference | Read when |
|---|---|
| `references/inventory.md` | step 1: game code vs libraries vs runtime, pinning library versions from the binary, static or DLL |
| `references/toolchains.md` | step 2: C++ (original MSVC, or current MSVC / clang-cl), Rust (windows targets, raw-dylib, cross build without MinGW), `libraries.json`, the hello gate, Wine vs Windows |
| `references/harness.md` | steps 3 and 5: the oracle, hook points, determinism, replay and trace formats, scenarios, comparison, the hooks in the rewrite |
| `references/cpp.md` | step 4 in C++: from matched units (or pseudocode) to a clean tree by subsystem; the one-shot generator; what is scaffolding; extern-only data; link order; entry point; build; accounting; testing with real input |
| `references/rust.md` | (planned) a Rust rewrite: module layout, FFI to libraries, translating MSVC C++ idioms |
| `references/orchestration.md` | (planned) splitting the rewrite across agents, review, the comparison loop |

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
  "args": ["-basedir", "{basedir}\\"], "saves": "saves", "fps": 30,
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
| `examples/libraries_vvvvvv.json` | 1, 2 | the validated case's complete `libraries.json` |
| `examples/cpp_config_vvvvvv.json` | 4 | the validated case's cpp config (placement, scaffolding patterns, renames, constants, data tables) |

## Validated on
VVVVVV 2.4.4 (VS2010 SP1, SDL2, seven static libraries): libraries pinned from the binary, both toolchains'
hello programs `RESULT: OK` under Wine on macOS, an oracle with 4 edited functions whose 3 scenarios (1,101
to 1,601 frames) gave byte-identical traces and saves in 3 of 3 runs each. The C++ rewrite: 976 game
functions brought over from the matched units (all 12 NONMATCHING included) plus a rewritten WinMain, in 60
`.cpp` and 49 `.h` files; it builds with VS2010 and all 3 scenarios are identical to the oracle, framebuffer
hash included, with byte-identical saves. The Rust rewrite is in progress.
