# Step 4 (C++) - From matched units to a clean source tree

Output: the game's code as an ordinary C++ project, one file per subsystem, one definition of every class,
global and function, that builds with the step-2 toolchain against the step-1 libraries and passes the
step-3 scenarios. Gate: **it builds, every function annotation of the decomp is accounted for, and every
scenario is identical to the oracle (traces with the framebuffer hash, and the save files)**.

Scale of a validated run (an SDL2 game built with VS2010 SP1): about 270 matched units (about 1,200
`// FUNCTION` and 70 `// STUB` annotations, a dozen `// NONMATCHING`) became about a thousand game functions
(every NONMATCHING one included) plus a rewritten WinMain, in about 60 `.cpp` and 50 `.h` files (about
80,000 lines, nearly half of the bytes level and map tables). It built with the original compiler in about
20 s from clean, and every scenario was identical to the oracle in every field, framebuffer hash included,
with byte-identical saves.

## 1. What a matched unit is, and why it is not yet a source tree
A matched unit (decomp skill, `matching-decomp.md`) is one guessed translation unit whose functions compile
to the original's bytes. To get there, units carry code whose only job is to steer one per-file compile:

| Scaffolding in the units | Why it existed | In the rewrite |
|---|---|---|
| forward declarations and `extern` declarations in every unit | each unit compiles alone | headers |
| stand-in types (SDL/library struct layouts, per-unit copies of game classes) | no shared header yet, or a layout for one call | the real library headers and one class header |
| stand-in copies of another unit's function (`static __declspec(noinline)` with the real body) | gives the caller the callee's register convention | dropped; the real function is called |
| `__declspec(noinline/safebuffers/nothrow)`, `__fastcall`, `__forceinline`, `#pragma optimize/inline_depth` | reproduce inlining, cookies, conventions | removed (`__forceinline` -> `inline`) |
| register-steering wrapper structs (`struct StrRef { std::string* p; }` passed by value, `FlagsArg`, ...) | keep a pointer or flag on the stack (the "EBX rule") | plain parameters again (by hand) |
| a second, descriptive name for one exe function (`fill_rect_xywh_rgb` next to the `fill_rect` overloads) | the defining unit and its callers were matched separately | one name: the callers' (`renames.members`) |
| scaffolding helpers (`*_caller`, `use_*`, `instantiate_*`, renamed inline copies like `X_inline`) | emit a COMDAT, an out-of-line copy, a call shape | dropped (`drop.functions`) |
| explicit template instantiations | emit an STL instance to compare | dropped; the STL makes them |
| `// CLFLAGS:` lines, `#pragma include_alias` | per-file flags, a broken SDK install | dropped; one flag set for the project |
| offset and size asserts (`typedef char check_X[sizeof(X) == 0xadc ? 1 : -1]`) | prove a layout against the binary | dropped (keep the offsets as comments) |
| per-unit copies of macros and enums | each unit compiles alone | one definition in a header |
| a constant spelled with the right value under the wrong name | each unit's local enum was guessed | renamed to the canonical name of that value (below) |
| volatile re-reads, no-op reads | order loads or registers | removed (by hand) |
| two names for one variable (same address) | units named it independently | one name (`renames.units`) |

What stays:
- **the logic of every matched function**, NONMATCHING ones included: they are correct C++ that only
  allocates registers differently (typically register tie-breaks), so the rewrite uses them as they are;
- **an address comment on every function** (`// 0x4013f0`): the decompile, the matched unit and the oracle
  stay one grep away, and the accounting (section 6) is done with it;
- class layouts in the original member order, offsets as comments (`// +0x158`), so a memory dump of the
  original still reads against the class.

What does not come over:
- **library internals** compiled into the exe (e.g. a C++ XML library's functions, an stb_vorbis copy inside
  the music units): the upstream library at the pinned version (step 1);
- **CRT and STL instances** (template instances, CRT objects): the compiler's own;
- **dynamic initializers and atexit thunks** (`??__E`/`??__F`): the compiler makes them again from the
  global definitions (`Game game;`);
- **Ghidra fragments** (`// STUB` of an address that is a jump target inside another function): the
  code is inside the parent's C++;
- implicit members that a unit spelled out (e.g. a copy constructor the implicit one equals).

## 2. Target layout
One folder per subsystem, one `.cpp` per class or per original source file where the unit names and strings
tell it (assert paths, log prefixes), a header next to each `.cpp`:
```
src/
  main/       entry point (WinMain), main loop and state tables, platform glue
  game/       game state class, save/load, settings, menus, cutscene state machine, logic, render
  graphics/   renderer class, texture loading, screen/window, text boxes
  entity/ map/ script/ music/ input/ editor/ localization/ filesystem/ util/    (as the game has them)
  harness/    the differential-test hooks (references/harness.md), a module of its own
```
Units are address-range guesses, so place by class first: every member of `Renderer` goes to
`graphics/Renderer.cpp` whatever unit matched it; free functions go by unit, single functions by name or
address where a unit mixed two source files (a unit that holds both a UTF-8 helper file and a string
formatting file, say).
The shared class headers of the decomp (`src_matched/<binary>/include/*.h`, one definition per class with
offsets checked) are the starting point of the class headers.

## 3. The generator: one shot, then by hand
`scripts/cpp/emit.py` does the mechanical part from a config (see Config below) and is run once into an empty
folder. Then the tree is fixed by hand until it compiles, links and passes the scenarios; the generator is
not run again over the edited tree (rerun it into a scratch folder to compare).
```bash
S=<skill>/scripts
python3 -I $S/cpp/cppsplit.py src_matched/GAME/012_*.cpp --items          # what the splitter sees
python3 -I $S/cpp/account.py --config rewrite/cpp/config.json --names decompiled_named_exe/index.json
python3 -I $S/cpp/emit.py --config rewrite/cpp/config.json --out rewrite/cpp/src --report rewrite/cpp/gen_report.json
python3 -I $S/cpp/gen_data.py --config rewrite/cpp/config.json --out rewrite/cpp/tables.inc
```
What it does, per unit (sorted), after dropping `drop.lines` (e.g. `// CLFLAGS:`) and applying
`renames.members`:
1. split into top-level items with their comment block (`cppsplit.py`): the annotation travels with the
   definition; namespaces and `extern "C"` blocks are entered;
2. drop forward/extern declarations, forward type declarations, instantiations, `#include`/`#pragma` lines,
   `// STUB` items;
3. every `// FUNCTION` definition goes to its destination (address > name > class > unit > default),
   cleaned (`drop.declspecs`, `drop.keywords`), renamed, with `// 0x<address>` above it;
4. an unannotated definition with the signature key of an annotated one is a stand-in: dropped. The key is
   the qualified name plus normalised parameter types (`Uint8` = `unsigned char`, `std::` stripped: config
   `type_aliases`, `strip_qualifiers`);
5. unannotated helpers matching `drop.functions` or `drop.keys` are scaffolding: dropped; the others (inline
   helpers the original inlined everywhere) are kept once per destination;
6. types defined in the shared headers or matching `drop.types` are dropped; other unit-local types are kept
   once per destination or moved to a header (`type_home`);
7. globals are kept once in the tree, file statics once per file;
8. constants are canonicalised (next section);
9. a file static that another file uses becomes public; each `.cpp` gets forward declarations of its
   statics, its header gets the public functions (with the default arguments the units' declarations had)
   and `extern` globals; includes are computed from the names a file uses.

On a project of about 270 units the generic generator reproduced a hand-written project generator exactly:
about a thousand functions placed, about 150 stand-ins and 50 scaffolding helpers dropped, about 1,800
forward and extern declarations and 180 stand-in types dropped, 50 inline helpers kept, a few statics made
public and a few constants replaced by numbers, in about 6 s (Python) or under 1 s (Node). The hand-fixing
phase then merged and split a handful of files.

What was left for the hand phase:
- wrapper structs back to plain parameters (`StrRef`, `CodepointArg`, `EndArg`, `FlagsArg`, `U8Arg`,
  `DataArg`), alias unions to one member name, a no-op read that only ordered registers;
- one name per exe function (the descriptive names of overloads: `fill_rect_xywh_rgb` -> `fill_rect`,
  `print_string` -> `text::print`, `update_tag_int` -> `xml::update_tag`);
- helpers a moved function needs in its new file, header include cycles, over-inclusion (a pruning pass:
  drop a project include when the file still compiles without it, `cl /Zs`);
- signatures that one unit had narrowed (a save function got its unused third parameter back; a
  `Window::init(const WindowSettings*)` that one unit had declared with a by-value struct);
- macro names that collide once `windows.h` is in (`THIS` as a parameter name).

## 4. Constants: right value, wrong name
Units guessed enums and flag macros locally. The number in the code is what the original was compiled with;
the name may not be. In one project a print flag `TEXT_BORDER` was `1<<17` in most units but `1<<4` in one
unit and `0x8` in another; `ENTITY_MOVING` was 1 in one unit and 2 in another. Renaming by name would change
behaviour.
The generator evaluates every unit's own object-like macros and enum constants (a small C constant-expression
evaluator: casts, shifts, ternaries, char literals) and compares them with the canonical values
(`constants.canonical`, the enums and macros of the shared headers and of `constants.headers`). Where a unit's
value differs, the unit's uses are renamed to the canonical name that has the unit's value in the same family
(the prefix before the first `_`; `constants.families` maps prefixes such as `KEYBOARD` -> `SDLK`), else to
the plain number (reported as `const_literal`). Names with no canonical counterpart stay unit-local, and
`#define A B` aliases are resolved the same way. Pick canonical values from the code that decodes them
(print flags from the function that decodes them), not from a unit. Expect a tenth of the units to get
renames (constants, aliases and variable names together) and a few values to become numbers (e.g. a unit
whose game-state enum was shifted by two).

## 5. Data the units only declared
Matched units often declare tables `extern`: they matched against the original's data, which nobody wrote
as source. The rewrite needs definitions:
- **initialised data** (`.rdata`/`.data`): read the bytes from the original exe by address, type and count,
  and write C++ initialisers: `scripts/cpp/gen_data.py` (`"data"` in the config: `va`, `type`, `count` or
  `dims`, `decl`, `format`; string tables become literals; pointers into another table become expressions
  through `symbols`, e.g. `glyph[12]`; floats with the fewest digits that read back to the same bits);
- **`.bss` data** (no raw bytes in the section): a zero-initialised definition in the file that uses it.
In one project, 15 tables (large level maps of `short`s, per-area music, an area map, room tables, text
shaping tables, credits lists, a glyph layout whose entries point into `glyph[]`) came from `.rdata`, and
`gen_data.py` reproduced all of them token for token; about 90 other extern-only globals lay in `.bss` (above
one address) and became zero definitions.

## 6. Accounting: every annotation has a place or a reason
`scripts/cpp/account.py` puts every `// FUNCTION` and `// STUB` annotation in exactly one category, from
the units and the finished tree (`// 0x<address>` comments), and lists what is unaccounted:
```bash
python3 -I $S/cpp/account.py --config rewrite/cpp/config.json --tree rewrite/cpp/src \
    --names decompiled_named_exe/index.json --map rewrite/cpp/function_map.json
```
Before the hand phase (no `--tree`) it checks that every game function has a destination (`planned`);
afterwards that every one is in the tree. Exit 1 while anything is unaccounted. The categories (shares from
one SDL2 game):

| Annotations | Share | In the rewrite |
|---|---|---|
| `// FUNCTION` with C++ in a game unit | about 3/4 | in the tree (plus WinMain rewritten), every NONMATCHING included |
| `// FUNCTION` dropped with a reason | a few | e.g. an implicit copy constructor (`dropped` in the config) |
| `// FUNCTION` dynamic initializer / atexit thunk | about 4% | compiler-generated from the global definitions |
| `// FUNCTION` in library units | about 15% | library internals, STL/CRT instances: upstream library, compiler |
| `// STUB` in library units | about 3% | CRT objects |
| `// STUB` Ghidra fragments | about 2% | inside their parents' C++ |
| `// STUB` rewritten | a few | e.g. SDL2main's `main_getcmdline` (in the tree) |

`tree_only` lists addresses the tree has but no annotation: functions written new (e.g. a logging init that
was a `jmp` the units missed) and the addresses on data tables. Record unannotated additions in the project's
README: inlined helpers kept once, functions the original folded (empty platform-service stubs).

## 7. Linking and running

### Global constructors run in link order
MSVC runs each object file's dynamic initializers in the order the objects appear on the link line. The
original's order is visible: its `??__E` thunks sit in address order in the initializer table (e.g.
localization tables, sound and music track lists, the script engine, the level editor, the renderer, the
music player, the game, input, the map, the entity list, the main loop's state). When a constructor uses
another global (e.g. `LevelEditor()` -> `reset()` -> a colour table in the script engine's global), an
alphabetical link crashes at start (there: in `reset` on a NULL map head). Fix: link the files that define
global objects first, in the original's initializer order, then the rest. Do not reorder by hand later
without rerunning the scenarios.

### Library pieces the prebuilt libraries lack
Some library code the original linked is not in the library's default build: an exe may contain PhysFS's
SDL_RWops bridge (`extras/physfsrwops.c`), which `physfs.lib` does not. Compile that file
from the pinned library source as it is, as part of the program. Check the inventory's library ranges
against the built libraries' exports.

### The entry point
A game that links `SDL2main` has its `WinMain` from SDL (next to `main_getcmdline`).
The `SDL2main.lib` of a current SDL devel package is built by a newer compiler than an old toolchain can
link; write `WinMain` from SDL's `SDL_windows_main.c` of the pinned version (UTF-16 command line to UTF-8
argv, then `SDL_main`) in `main/SDLMain.cpp`, and link `/SUBSYSTEM:WINDOWS` like the original.

### Build script
A small project build script (e.g. `rewrite/cpp/build.py`, about 200 lines) over `cpp_build.py`'s flags and
library list:
- incremental: an object is rebuilt when its source or any project header it includes (recursively) is newer;
- parallel: several `cl` processes at once, a few sources per process (a Wine process start costs about a
  second; e.g. 6 processes, 3 files each: about 20 s from clean for 60 files, versus 75 s serial);
- link order as above, extra library sources, `/MAP` for debugging, a `--debug` flavour (`/Od /Z7`);
- errors only by default (`--warnings` for all), and a failed object is deleted so it is rebuilt next time.
Check the fast build against a one-shot build once with the scenarios.

### The hooks as a module
The harness contract (`references/harness.md`) is a module of its own (e.g. `src/harness/Harness.cpp`,
adapted from the oracle's hook header; `scripts/harness/harness_core.h` holds the game-independent half),
called from the main loop at the same points as in the oracle: after every
input poll, at the end of the logic frame, at the end of the fixed-step function (both early returns and after
the present). Everything is behind the contract's environment variables: without them the rewrite plays like
the original.

## 8. Testing
1. **Builds** with the original compiler and flags, no errors (warnings reviewed once).
2. **Accounting** clean: `account.py --tree` exits 0.
3. **Scenarios**: `run_scenario.py` + `compare_traces.py` (`--ignore fb` first, then with `fb`), and `cmp` of
   every save file, for every scenario (`harness.md` section 9). A small project script that runs them all and
   writes one summary is worth having (e.g. `rewrite/cpp/tools/run_harness.py`: 1-2 minutes for three).
4. **Real input**: the harness replaces the input state, so it does not test the real input path. Post real
   key messages to the window: `scripts/cpp/keysend.cpp` (build it with the same compiler:
   `cl /nologo /O2 /MT keysend.cpp user32.lib`) finds the window by title and posts `WM_KEYDOWN`/`WM_KEYUP`
   with scan codes from a script (`keysend.exe "Game" "wait:3000 tap:z:150 down:right wait:800 up:right"`).
   Run it next to the game (under Wine: in the same prefix).
5. **Screenshots** of the real window at chosen times, from a scratch copy of the game folder with an empty
   save folder (the game's own save-folder option), to look at: language menu, title menu, a started game. On macOS under Wine:
   `screencapture -l <window id>` with the window id from CoreGraphics' window list (as `run_wine.py` finds
   titles). Expect focus loss to pause the game (its own behaviour).
6. **Not covered by scenarios** is not verified: list it (e.g. the editor, user levels, extra play modes, the
   later game, the ending, controller input, IME: compiled from the same matched code but not exercised).
   Add scenarios before calling those subsystems done.

## 9. Deliberate differences
Small changes that make the source cleaner without changing behaviour are fine, if each is recorded in the
project's README with the reason and why behaviour is the same:
- a parameter restored that the matched definition had dropped because it was unused;
- a reference overload replaced by the pointer one with the same code;
- a non-clamping macro copy replaced by the clamping canonical one where the arguments are always in range
  (e.g. a brightness macro in a volume slider, always 0..255);
- one name for one variable (two units' names for the same address).
Code layout, inlining and addresses differ from the original by nature; the scenarios are the proof.

## 10. Without matched units
The same layout and steps, but the functions are written from the decompiled pseudocode
(`decompiled_named_exe/functions/0x<addr>.c`), subsystem by subsystem, each against a scenario:
- start from the phase-5 names and the class layouts (vtables, constructors, allocation sizes);
- keep the `// 0x<address>` comment on every function, and use `account.py` with a units folder of
  skeletons (the decomp skill's `phase6_skeleton.py` writes one per unit with `// STUB` annotations; turn
  them into `// FUNCTION` as functions are written);
- expect more divergences per scenario: x87 float order, signedness, evaluation order of arguments, `rand()`
  call counts. Fix them from the first differing frame (`harness.md` section 9).

## Config (rewrite/cpp/config.json)
One JSON file for `account.py`, `emit.py` and `gen_data.py` (its `"data"` section). Paths are relative to the
project (`--project`, default the current folder). Regexes are matched against the whole name.

| Key | Meaning |
|---|---|
| `module` | annotation module name (`// FUNCTION: <module> 0x...`); others are ignored |
| `units`, `unit_id`, `unit_exts` | units folder; regex whose first group is a unit's id (`^([0-9]{3})_`); extensions |
| `library_units` | unit ids that contribute nothing (CRT, STL, library copies, SDL2main) |
| `unit_dest` | `{file: [unit ids]}` |
| `class_dest`, `name_dest`, `addr_dest`, `default_dest` | placement by class, free-function name, address; fallback file |
| `namespaces` | namespace names that qualify definitions (`void font::print(...)`) |
| `type_aliases`, `strip_qualifiers` | for signature keys (`"Uint8": "unsigned char"`, `"std::"`) |
| `drop.lines`, `drop.functions`, `drop.keys`, `drop.types`, `drop.macros`, `drop.includes` | scaffolding to drop (section 1) |
| `drop.declspecs`, `drop.keywords` | `["noinline", ...]`; `{"__fastcall": "", "__forceinline": "inline"}` |
| `renames.members`, `renames.global`, `renames.units` | identifier renames (section 1) |
| `constants.canonical`, `constants.headers`, `constants.families`, `constants.ignore` | section 4 |
| `headers` | `{unit-folder header: output header}`: shared class headers to copy |
| `type_home` | `{type: header}` for unit-local types several files need |
| `includes`, `system_includes`, `guard_prefix`, `banner` | include lines for every `.cpp`; `{<header>: regex}`; guard prefix; file comment (`{units}`) |
| `thunk_symbols`, `thunk_names`, `dropped` | account: thunk patterns (defaults `??__E/F`, `dynamic_initializer_for`...); `{address: reason}` |
| `data.pe`, `data.symbols`, `data.items` | gen_data (section 5; full list in `gen_data.py --help`) |

`scripts/examples/cpp_config_example.json` is a small made-up config that uses every key: placement of
units into subsystem files, scaffolding patterns, renames, canonical constants and data tables. A real
project's config has the same shape, only longer (dozens of files, hundreds of unit ids).

## Scripts
| Script | Purpose |
|---|---|
| `cpp/cppsplit.py` | split units into top-level items with annotations; classification; also the shared library of the others |
| `cpp/account.py` | every annotation -> file or reason; unaccounted ones fail; `--map` for the project |
| `cpp/emit.py` | the one-shot generator: placement, scaffolding removal, renames, constants, headers, includes, report |
| `cpp/gen_data.py` | C++ definitions of extern-only data from the exe's sections (PE32 and PE32+) |
| `cpp/keysend.cpp` | Win32 tool: post scripted key presses to a window by title |
Each Python script has a JavaScript port in `scripts/js/cpp/` with the same command line and output; the
parity suite covers them with made-up units and a PE built in the test.

## Checklist
- [ ] Layout by subsystem decided; config written; `account.py` (no tree) shows every game function `planned`.
- [ ] `emit.py` run once into an empty folder; report read (stand-ins, scaffolding, renames, `const_literal`, conflicts).
- [ ] Extern-only data defined (`gen_data.py` for initialised tables, zero definitions for `.bss`).
- [ ] Builds with the original compiler; global objects linked in the original's initializer order.
- [ ] Missing library pieces compiled from the pinned source; entry point written from the library's own code.
- [ ] Hooks module wired at the contract's points; without the variables the game plays normally.
- [ ] `account.py --tree` exits 0; NONMATCHING functions all in the tree.
- [ ] Every scenario identical with `fb`, every save file identical; real input and screenshots checked.
- [ ] Deliberate differences and untested subsystems written down in the project's README.
