# Step 7 (C++) - Writing the rewrite in C++

For implementers: fresh agent sessions (or people) who never saw the decompilation. You write the game as
an ordinary C++ project from behaviour specs, format docs, the oracle's per-frame traces and the game's
own data files, read at run time. Nothing in the tree maps one-to-one to the original's code; the design,
the structure and the names are yours.

Output: the clean tree (`rewrite/clean` by default, usually its own repository outside the private
project), one folder per subsystem, that builds with the step-6 toolchain against the step-6 libraries.
Gate: **it builds, no `TODO_SPEC` is left in code a scenario reaches, every scenario is identical to the
oracle (traces with the framebuffer hash, and the save files) or the remaining divergence is documented and
accepted by the user, and `release_check.py` passes on the tree.** Step 8 (`harness.md`) is the comparison.

## 1. Your workspace
`cleanroom.py pack` builds it and logs the hand-over. Work only from it, the clean tree and the user's
installed game.

| In the workspace | What it is |
|---|---|
| `RULES.md` | what you may and may not open; read it first |
| `INPUTS.json` | every file handed over, with its SHA-256 |
| `cleanroom/specs/*.md` | behaviour specs: states, rules, formulas, timings in frames, constants, order of random draws |
| `docs/formats/*.md` | the game's file formats, in words |
| `rewrite/harness/HOOKS.md` (or the contract in a spec) | the trace contract: variables, replay format, every trace field and its hash input |
| `rewrite/harness/scenarios/*.txt`, the oracle's traces and saves | recordings of the original's behaviour, frame by frame |
| `rewrite/libraries.json` | the libraries and versions the game uses, and how they are built |

Allowed besides: the user's installed game (run it, watch it, read its data files from your code), public
documentation, the upstream open-source libraries the game uses, and this skill's generic tools (table
"Scripts" below). Never: decompiled or disassembled code, Ghidra projects, the analysts' tools (format readers,
the probe), names maps, private rewrites, or the original executable's bytes. Do not look up decompilations,
leaked source or other ports of this game either. If you come across any of it, stop and tell the
coordinator.

### Asking questions
When a spec is silent or a trace disagrees with it, ask in writing; do not guess from memory of the game.
Write `questions/<wave>-NN.md` in your workspace and hand it to the coordinator, who records it
(`cleanroom.py record --wave W --event question FILE`) and returns the answer as a new spec section in a
new pack. A good question names the scenario, the frame, the field, both values, the spec section you
followed, and asks about behaviour ("what happens to the timer when the player dies on the frame it
reaches zero?"), never about the original's code.

## 2. Design first
Read every spec of the first waves before writing code, then decide modules, state and names; later
waves extend the design. A layout that works for a 2D game of the 2000s-2010s:
```
src/
  main/       entry point, main loop, start-up and shut-down order, platform glue
  game/       game state, menus, cutscenes, save/load, settings
  render/     renderer, textures, fonts and text boxes, screen and window
  world/ entities/ script/ audio/ input/ editor/ text/ files/ util/   (as the specs describe them)
  harness/    the trace-contract hooks (section 6), a module of its own
```
- **Names are yours.** Use a consistent scheme of your own. The specs avoid the original's names, so
  collisions are rare; `release_check.py` fails a tree where more than 30 % of function definitions carry
  the analysts' names for the original (from 20 definitions on).
- **No address-like or decompiler-like text anywhere**: no `// 0x4013f0` comments, no "address" or
  "FUNCTION" comments with hex numbers, no identifiers such as `FUN_...`, `DAT_...`, `iVar1`, `param_1`,
  `local_10`, `undefined4`. The gate flags them even when you made them up.
- Name every spec section a function implements in a comment when it helps (`// specs/physics.md#jump`).
  That is the traceability the clean tree has.

## 3. Unwritten behaviour: `TODO_SPEC`
Build the whole program early and fill bodies in place. A function whose behaviour you have not written yet
logs once and returns a neutral value, so a partial program runs and a harness run lists, in order, what a
scenario reaches:
```cpp
// util/todo_spec.h
void todo_spec_log(const char* spec);   // appends "unimplemented: <spec>" to the program's log file
#define TODO_SPEC(spec) \
    do { static bool logged_ = false; if (!logged_) { logged_ = true; todo_spec_log(spec); } } while (0)

int Lift::travel_time(int floors) { TODO_SPEC("specs/lifts.md#timing"); return 0; }
```
The argument names a spec section, never an address or an original name. Progress is
`grep -rn 'TODO_SPEC(' src | wc -l`. The log goes to a file named by an environment variable of your choice
(`<GAME>_LOG`): a GUI program has no console.

## 4. Behaviour an MSVC-built x86 game demands
The traces compare float bits, random-number sequences and hashes, so "almost the same" fails. The specs
state the facts (float model, rounding, order of draws); the traces show where you missed one.
- **Compiler.** With the original compiler family named in the toolchain notes (e.g. VS2010 SP1) you get its
  float code (x87 by default before VS2012), its CRT `rand()`, `(int)` conversion and STL behaviour for free.
  With a current MSVC or clang-cl, add `/arch:IA32` on x86 when the spec says the original used x87, and
  expect last-bit float differences where you do not.
- **Order of side effects.** C++ leaves argument evaluation order unspecified; MSVC x86 usually evaluates
  right to left. When the spec gives the order of random draws (or stream reads, counters), put each call
  in its own statement in that order: `int dy = rand() % 5; int dx = rand() % 3; place(dx, dy);`.
- **Repeated evaluation.** A spec may say a value is drawn again for each comparison ("drawn up to three
  times; each comparison uses a new draw"): write exactly that, not a clamp helper that draws once.
- **Integers.** Signed overflow is undefined in C++ and the optimiser may assume it never happens; where a
  spec says a value wraps (timers, hashes, generators), compute in `unsigned` and convert. `char` is signed
  in MSVC, so bytes >= 0x80 read as `char` are negative; use `unsigned char` unless the spec says the
  negative value is visible.
- **Float to int.** `(int)` truncates toward zero; NaN and out-of-range values give `0x80000000` with MSVC.
  A spec that relies on that will say so.
- **Randomness.** Use the CRT `rand()` when the spec says the original did (MSVC: per thread, seed 1); port
  the game's own generators from the spec bit for bit. Every draw counts, renders included.
- **Text output.** Numbers written into saves or rendered text use the formatter the spec names (SDL has
  its own `SDL_snprintf`).
`rust.md` section 6 has the full checklist; it applies to C++ wherever the compiler differs from the
original's.

## 5. Game data and tables
Everything the game shows or plays comes from the user's installation at run time: graphics, sound,
music, text, levels, and tables of numbers, decoded with your own readers from the format docs.
- Small sets of constants a spec states as facts (speeds, timings, a palette of eight colours) are written
  by hand as named constants.
- Large tables (level layouts, text, credits, maps) are never typed into the source: the gate fails numeric
  tables of 1,024 or more items and string tables of 64 or more. Read them from the game's files.
- Data a spec places inside the original executable: do what the spec says (typically read it from the
  user's own copy at run time, at the location given, after checking the file's hash). Never open the exe to
  look, and never copy its bytes into the tree.
- No game files in the tree: the gate compares every file's SHA-256 with the game's and the decoded data.

## 6. Linking and running

### Global constructors run in link order
MSVC runs each object's dynamic initializers in the order the objects appear on the link line. If one
global's constructor uses another global, an alphabetical link can crash at start (a constructor reading a
table that is not built yet). Prefer no cross-global constructors at all: construct the state explicitly
in `main`, in the start-up order the spec describes. Where you keep global objects, link their files first,
in dependency order, and rerun the scenarios after any change to the order.

### Library pieces the prebuilt libraries lack
Some library code a game links is not in the library's default build (PhysFS's SDL bridge
`extras/physfsrwops.c` is not in `physfs.lib`). `libraries.json` and the toolchain notes list such pieces;
compile them from the pinned upstream source as they are, as part of the program.

### The entry point
An SDL2 game gets `WinMain` from SDL2main. The `SDL2main.lib` of a current SDL devel package is built by a
newer compiler than an old toolchain can link: write `WinMain` from SDL's `SDL_windows_main.c` of the
pinned version (UTF-16 command line to UTF-8 `argv`, then `SDL_main`), or define `SDL_MAIN_HANDLED` and
call `SDL_SetMainReady`. Link `/SUBSYSTEM:WINDOWS`.

### Build script
`cpp_build.py` compiles and links a small program in one go. For the tree, write a project build script
(about 200 lines) over its flags and library list:
- incremental: an object is rebuilt when its source or any project header it includes (recursively) is newer;
- parallel: several `cl` processes, a few sources each (a Wine process start costs about a second; 6
  processes of 3 files built 60 files in about 20 s, against 75 s serially);
- link order as above, extra library sources, `/MAP` for debugging, a `--debug` flavour (`/Od /Z7`);
- errors only by default (`--warnings` for all); a failed object is deleted so it is rebuilt next time.
Check the fast build against a one-shot `cpp_build.py` build once with the scenarios.

### The hooks as a module
Implement the trace contract (`harness.md`) in `src/harness/`, built on `scripts/harness/harness_core.h`
(replay parser, FNV-1a, float bits, framebuffer hash, line building, exit frame; the game's variable names
as macros). You write the game-specific half from the contract: which fields, their hash inputs, and the
calls at the contract's points (after every input poll, at the end of the logic frame, after the frame's
present, early-return paths included). Under replay: one fixed logic step per render, no interpolation.
Without the contract's variables the program plays in real time like the original.

## 7. Testing
1. **Builds** with the step-6 compiler and flags, no errors (warnings reviewed once).
2. **Scenarios** (step 8): `run_scenario.py` + `compare_traces.py` (`--ignore fb` first, then with `fb`),
   and `cmp` of every save file, for every scenario in the workspace. A small script that runs them all and
   writes one summary pays for itself. Work from the first differing frame and field; the program log's
   `unimplemented:` lines show which `TODO_SPEC` a scenario reached.
3. **Real input**: the harness replaces the input state, so it does not test the real input path. Build
   `scripts/harness/keysend.cpp` with the same compiler (`cl /nologo /O2 /MT keysend.cpp user32.lib`); it
   finds the window by title and posts `WM_KEYDOWN`/`WM_KEYUP` with scan codes from a script
   (`keysend.exe "Game" "wait:3000 tap:z:150 down:right wait:800 up:right"`). Under Wine run it in the same
   prefix as the game.
4. **Screenshots** of the real window at chosen times, from a scratch copy of the game folder with an empty
   save folder: language menu, title menu, a started game. Under Wine on macOS: `screencapture -l <window
   id>` with the id from CoreGraphics' window list. Compare by eye with the original running next to it.
5. **Not covered by scenarios is not verified**: list it (editor, user levels, extra modes, the ending,
   controller input). Ask the coordinator for scenarios before calling those subsystems done.

## 8. Deliberate differences
Record each in the tree's `DESIGN.md` or README with the reason behaviour is unchanged (or the accepted
divergence): state built in `main` instead of global constructors, a bounds check where the spec says the
original read past an array but the result never matters, the log file. Code layout, inlining and
addresses differ from the original by nature; the scenarios are the proof.

## Scripts
| Script | Use |
|---|---|
| `cpp_build.py` | compile and link with MSVC (Wine or native) against the static libraries of `build_libs.py` |
| `build_libs.py` | fetch, check and build the pinned libraries (`libraries.json`) |
| `msvc_compat/`, `capi/` | headers an old MSVC lacks; C API shims and allocator wrappers for libraries |
| `harness/harness_core.h` | the game-independent half of the trace contract |
| `harness/keysend.cpp` | post scripted key presses to a window by title (real input) |
| `run_wine.py`, `run_scenario.py`, `compare_traces.py` | run an exe from a scratch game folder; one scenario; compare traces |
The toolchain and harness were validated on a 2010s SDL2 game built with VS2010 SP1 (SDL2 as a DLL, seven
static libraries).

## Checklist
- [ ] `RULES.md` read; only the workspace, the clean tree and the installed game used.
- [ ] Design (modules, state, names) written down before the first wave's code.
- [ ] Builds with the step-6 toolchain; state built in a defined start-up order; library pieces and entry
      point from the pinned upstream sources.
- [ ] Hooks module at the contract's points; without the variables the game plays normally.
- [ ] Every open point asked in writing through the coordinator; answers came back as specs.
- [ ] No `TODO_SPEC` left in code a scenario reaches; game data read from the user's files at run time.
- [ ] Every scenario identical with `fb`, every save file identical (or divergences documented and
      accepted); real input and screenshots checked; untested subsystems listed.
- [ ] Deliberate differences written down; LICENSE, README and third-party notices at the top of the tree.
- [ ] The coordinator ran `release_check.py <tree>` (default `rewrite/clean`) and it passes.
