# Steps 4 and 8 - The oracle, the trace, the comparison

"Behaves like the original, frame for frame" is checked by a differential test. The original and the
rewrite play the same scripted input, and each writes one line of game state per logic frame. The two
traces must be identical. The original game, unchanged on disk, run with a **probe** that injects the input
and writes the trace, is the **oracle**.

```
replay file ──> oracle (original exe + probe DLL) ──> oracle trace + save files ─┐
           └──> rewrite (same contract, own code)  ──> rewrite trace + save files ┴─> compare_traces.py, cmp
```

Step 4 (analysts) builds the probe, writes the scenarios and proves the oracle is deterministic. Step 8 runs
the rewrite on the same scenarios and compares. The hooks are a contract: the probe is one implementation of
it and the rewrite is another. Write the contract down per game (`rewrite/harness/HOOKS.md`) in words,
before writing any hook code: implementers get the contract, the scenarios and the oracle's traces, never
the probe's source (it holds addresses of the original).

## 1. The oracle: the original game and a probe
The original's files are never changed. The oracle is a copy of the game folder (`build/oracle/game`,
git-ignored) in which one DLL that the game imports by name is replaced by the **probe**, a proxy DLL:
1. **Pick the DLL.** From `wintools.py imports <game.exe>`: a DLL the game loads from its own folder that
   sees every frame - the media library (`SDL2.dll`, `SDL.dll`, `allegro*.dll`), the graphics API
   (`d3d8.dll`, `d3d9.dll`, `ddraw.dll`, `opengl32.dll`), input (`dinput8.dll`, `dinput.dll`) or the
   multimedia timer (`winmm.dll`). A library that ships with the game is easiest: it is not a system DLL, so
   Windows and Wine load the copy in the game folder anyway.
2. **Forward everything else.** Rename the original to `<name>_orig.dll` in the oracle folder and make the
   probe's `.def` with `wintools.py proxy <name>.dll <name>_orig --hook A,B <out.def>`: every export is
   forwarded to the original, except the hooked ones, which the probe defines and passes on through
   `probe_orig("A")`. Under Wine, a system DLL needs `WINEDLLOVERRIDES="<name>=n,b"` (`rewrite.extra_env`).
3. **Hook calls first, code second.** The library calls usually give everything:
   | Need | Hook (examples) |
   |---|---|
   | R: replace input | after `SDL_PollEvent`/`SDL_PumpEvents` returns, overwrite the keyboard state the game reads (`SDL_GetKeyboardState`'s array), `IDirectInputDevice8::GetDeviceState`, `GetAsyncKeyState`/`GetKeyboardState` |
   | T, F: frame end, framebuffer | the present call: `SDL_RenderPresent`, `SDL_GL_SwapWindow`, `SDL_Flip`, `IDirect3DDevice9::Present`, `SwapBuffers`; read the render target before presenting |
   | fixed step | the clocks the main loop reads: `SDL_GetTicks`, `timeGetTime`, `QueryPerformanceCounter`, `GetTickCount` advance by exactly one frame per present under replay |
   | trace fields | `probe_read(va, ...)` of the game state at the addresses the analysts documented (step 3) |
   Where a call cannot do it (the game polls input inside its own code, or its loop interpolates renders),
   patch the game's code in memory: `probe_patch_call(va, fn)` redirects one call site, `probe_patch_jmp`
   detours a whole function (`scripts/harness/probe_core.h`). Patch from `DllMain` or the first hooked call;
   never write a file of the game.
4. **Build it** with any x86 C compiler: `cpp_build.py` (MSVC, under Wine through `msvc.sh`) with
   `/LD` and the `.def`, from one `probe.c` that includes `harness_core.h` and `probe_core.h`. The probe's
   source lives in `analysis/probe/` (it holds the original's addresses: analysis side, forbidden to
   implementers).

Rules learned:
- **Without the variables the oracle plays like the original.** Check it: start it with no variables,
  then with only the trace variable (e.g. 300 frames traced with real-time play, exit code 0).
- **The probe must not change what it measures.** Every hook calls the original function and only then
  overwrites results; the trace is written outside the frame's logic (at the present call).
- **One probe per game version.** Addresses belong to one exe: the probe checks the exe's SHA-256 (or its
  PE timestamp and size) at start and refuses another build.
- **Clocks decide whether a fixed step is possible.** If the main loop takes its time step from a clock the
  probe can fake, one fixed step per render follows. If it runs a variable step or interpolates, the probe
  needs a code patch at the loop (point 3), and the contract says so.
- `probe_core.h` was compiled (clang, i686-pc-windows-msvc, C89) but not yet run against a game: test each
  hook on its own (log from it with `probe_log`) before recording.

## 2. Hook points
A **logic frame** is one step of the game's update. Define it exactly in the contract, e.g. everything from
the end of one call of the end-of-frame function to the end of the next. The trace line of frame f is written once frame f's
logic has finished and its render has been presented.

| Hook | Where | Does |
|---|---|---|
| R (input) | right after every input poll of the main loop | replaces the game's input state with the replay's keys for the current frame: key map cleared and set, controller axes and buttons zero, mouse buttons zero, text input off, window "active" |
| T (trace) | end of the logic frame | takes the snapshot of frame f (all fields but the framebuffer), increments the frame counter |
| F (framebuffer) | after the frame's render is presented (also on early-return paths) | hashes the game's internal render target, writes the line, quits at the exit frame |

The input hook runs after the poll, not instead of it: window events and quit still work. Whatever the
poll did to the input fields is overwritten.

The framebuffer of line f is the render that follows frame f's logic. In a game whose main loop runs a
per-state list of functions, that render can also contain what the list runs before its render entry in
frame f+1 (for a title screen: input and a fixed render). A rewrite with a different loop structure must
reproduce this order to get the same `fb` values.
The other fields only need frame f's state.

## 3. Determinism
The oracle must give the same trace on every run. Each source of variation needs a decision:

| Source | What to do (example: an SDL2 game) |
|---|---|
| Wall-clock timing | under replay, exactly one fixed logic step per rendered frame: the probe advances the faked clock by exactly one timestep per present (or, for a loop that cannot be driven by its clock, patches its accumulator), whatever the real clock says. Frame pacing (`SDL_Delay`) may run but changes nothing |
| Render interpolation | off under replay (`alpha = 1`): rendered positions are the current ones. A faked clock that gives whole steps usually makes the interpolation factor exactly 1 or 0; check which in the analysis |
| C runtime `rand()` | nothing to change, but it must be reproduced bit for bit: MSVC's is per thread, seed 1, `state = state * 214013 + 2531011; return (state >> 16) & 0x7fff`. Check whether the game ever calls `srand`. The number and order of calls (renders included) are behaviour: a game can have dozens of call sites, from screen shake to background particles |
| The game's own RNGs | find the seed. A game's own generator (e.g. xoshiro128+) may be seeded from the frame counter, with wall-clock seeding only behind a command-line option that the runner never passes |
| Settings and saves | the game starts from an empty folder each run: a command-line option for the data or save folder (e.g. `-savedir <empty folder>/`). Without such an option, redirect the save path (a hook, an environment variable, a fresh Wine prefix or a temporary `HOME`/`APPDATA`) |
| Window focus | losing focus must not pause or mute (set the game's own "don't pause" setting, input "active") |
| Audio clock | must not drive logic (e.g. music fades that step per frame are fine). Check every place the game reads audio position |
| Other clocks | list every time source in the logic (`SDL_GetTicks64`, `timeGetTime`, `_time64`, `QueryPerformanceCounter`): ideally ticks only pace frames (and seed an optional RNG), the calendar time only names screenshots |
| Threads | loading threads and audio callbacks must not change logic state, or must finish at a fixed frame |
| Pointer values | sorting or hashing by address differs between runs and between builds: find it before it shows up as a "random" divergence |
| Save contents | if saves hold the wall clock, mask it or compare them separately (saves that hold only the game clock are identical run to run) |

## 4. The replay file
```
# comment; blank lines are ignored
#! exit_frame=1500        <- runner metadata (a comment for the game)
#! seed=levels/test.lvl:../levels/test.lvl   <- copied into the fresh basedir before every try
#! arg=-level             <- one program argument per line (after rewrite.args, before --arg)
GAME-REPLAY 1             <- first non-comment line: the format and its version
0 -
40 z
43 -
120 right
300 right+z               # anything after the keys is ignored
```
- `<frame> <keys>`: from logic frame `<frame>` on, exactly these keys are held, until the next line. Frames
  are decimal and strictly increasing. Before the first line no key is held.
- `<keys>`: `-` (none) or key names joined by `+` (at most 16). Names: `a`-`z`, `0`-`9`, `left right up
  down enter escape space tab backspace delete kpenter lshift rshift lctrl rctrl lalt ralt f1`-`f12 comma
  period slash minus equals`. They map to SDL2 keycodes or Windows virtual-key codes (`harness_core.h`).
- An unreadable or invalid file ends the program with exit code 3, so a broken replay never runs as a free
  game.
- Held state rather than press events: a press is two lines (`40 z`, `43 -`). Menus that act on key-down
  need a release between presses.
- Mouse, controller or text input: extend the format with new line kinds and a new version number, in both
  implementations at once.

## 5. The trace format
```
GAME-TRACE 1
f=0 gs=1 st=0 sd=0 menu=26,4 room=0,0 p=- v=- ctl=0 ... fb=5768e67e
f=1 ...
```
Design rules:
- First line: the format name and version. Then one line per logic frame, frames 0, 1, 2, ... with no gaps,
  each ending in `\n`.
- Every line has every field, in a fixed order, as `name=value` separated by single spaces. No value
  contains a space. Absent things are `-` (no player entity: `p=- v=-`).
- Integers in decimal. **Floats as their IEEE-754 bit patterns** (`%08x` of the 32 bits), never printed
  decimals: rounding in printing would hide real differences or invent false ones. `compare_traces.py`
  shows them as numbers too (`"decode": {"v": "f32"}`).
- **Hash big state** with FNV-1a 32 (`h = 2166136261; h ^= byte; h *= 16777619`, empty input `811c9dc5`)
  over a defined byte sequence, e.g. for each entity the five 32-bit little-endian integers type, x, y,
  state, visible; for each text box, each line's bytes plus `0x0A`, then one `0x00`. Put the count next to
  the hash (`ents=12,1a2b3c4d`), so a length difference reads at once.
- Sets as sorted index lists (`flags=3,17,42`, `-` when empty).
- **The framebuffer last:** a hash of the internal render target before scaling, screen shake and the
  window's letterbox (e.g. the game's low-resolution render texture, read back as ARGB8888, hashing R, G, B
  of each pixel row by row, never alpha). It catches rendering bugs that no state field shows, but it depends on the
  renderer and driver: compare with `--ignore fb` first.
- Choose fields per subsystem, so the first differing field points at the code to read. A 2D game might use
  about 20: frame, game state, cutscene state and its delay, menu and option, room or level, player position,
  player velocity bits, control flags, deaths, respawn point, collectible count, flag set, collected set,
  text boxes (count + hash), music track, entities (count + hash), script running + position, game clock,
  fade mode, framebuffer.

Size: traces of about 1,000 to 1,600 frames with 20 fields take 200 to 400 KB. Small enough to keep in the
project (they are game-derived: keep them out of any public repository).

## 6. The run contract
| Item | Example value | Meaning |
|---|---|---|
| replay variable | `GAME_REPLAY` | replay file; input is scripted and the run is deterministic |
| trace variable | `GAME_TRACE` | trace file to create; independent of replay (tracing real play works) |
| framebuffer variable | `GAME_TRACE_FB` | `0`: no framebuffer hash (`fb=-`) |
| exit variable | `GAME_EXIT_FRAME` | after the line of frame N, close the trace and quit the game's normal way (settings and saves are written as in a real quit), exit code 0 |
| base folder argument | `-savedir <folder>/` (the game's own option) | empty folder per run: default settings, no saves, the user's own saves untouched |

`scripts/run_scenario.py` implements the runner side. It copies the game folder to a scratch folder, puts
the exe in under `rewrite.exe_name`, sets the variables (`rewrite.env`), passes `rewrite.args` with
`{basedir}` replaced, and waits for exit. A try counts when the trace has the header and exactly the lines
0..N. Otherwise it tries again: a try is abandoned at the timeout (60 s + 4x the scenario's real-time
length) or when the trace has not grown for 30 s. `--saves-out` collects the save folder. Under Wine it
passes `Z:\...` paths; with `--runner native` (Windows) host paths.

## 7. Scenarios
A scenario is a replay file with an exit frame. Cover each subsystem the rewrite has, so each subsystem has
a scenario whose trace must match before it counts as done (step 7's gate).

| Example scenario (a 2D platformer) | Frames | Covers |
|---|---|---|
| title menus, new game | 0-1100 | language menu, every main-menu entry, options and a volume slider, credits, the quit question answered "no", start of a new game |
| new game, intro, first rooms, map, save | 0-1600 | the whole intro cutscene with text boxes, a death and respawn, the core movement mechanic, a second cutscene, a checkpoint, all map tabs, an in-game save, a second death |
| first level without dying | 0-1500 | the same start, a long stretch of the core mechanic, a death far from the start, respawn, walking back |

Authoring (analysts): write the replay from the input handling found in step 3 (which keys, which menus need
a release), run it on the oracle with a framebuffer dump (a debugging aid in the probe that writes every N-th frame as
a PPM picture; not part of the contract), look at the pictures, fix the timings, then record. Mark
approximate frames as such in the contract (`~1002`). Plan more scenarios as the rewrite grows: editor,
every area, every boss, every menu, every save/load path, error paths (missing files).

## 8. Proving determinism (step 4 gate)
```bash
python3 -I <skill>/scripts/record_oracle.py --runs 3
```
Every scenario runs N times. All traces (framebuffer included) and all save folders must be byte-identical.
Then the first run's trace and saves go to `rewrite.oracle.traces` and `determinism.json` records, per
scenario and run: frames, tries, seconds per try, SHA-256 of the trace and of every save file, the
comparison with run 1, and the oracle exe's SHA-256. A non-deterministic scenario is not written.

Example: 3 scenarios x 3 runs, all byte-identical, including every save file (settings, the save slot,
progress). Each run took 17 to 31 s under Wine, and needed 1 to 3 tries because of start-up failures (about every
second start under load, one in five idle, the original exe too). The runs were made while another build
loaded the CPU, and with and without the framebuffer dump (which slows a run down), and still agreed: the
result does not depend on speed. Repeat the record after every probe rebuild.

## 9. Comparing (step 8)
```bash
python3 -I <skill>/scripts/run_scenario.py --exe build/rewrite/GAME.exe --game work/game \
    --scenario rewrite/harness/scenarios/01.txt --out /tmp/01.trace --saves-out /tmp/01.saves
python3 -I <skill>/scripts/compare_traces.py rewrite/harness/oracle/01.trace /tmp/01.trace --ignore fb
python3 -I <skill>/scripts/compare_traces.py rewrite/harness/oracle/01.trace /tmp/01.trace
cmp rewrite/harness/oracle/01.saves/<file> /tmp/01.saves/<file>
```
`compare_traces.py` prints the first frame where any field differs, every differing field there (floats
decoded), per field the first differing frame and the count, frames present in one trace only, and format
errors (fields not in the contract's order). Exit 0 identical, 1 different, 2 bad input. `--only` narrows the
fields, `--show N` prints the next N differing frames, `--json` saves the summary.

Working a divergence:
1. Compare with `--ignore fb` until the state matches; then add `fb`. A renderer difference shows only in
   `fb`; a state difference shows in its own field first.
2. Take the first differing frame and the first field. The field names the subsystem; the frame and the
   replay tell what happened (a key press, a room change, a cutscene step).
3. Implementers: find the cause with the rewrite's own logging and the specs; what the specs do not explain
   becomes a written question (`cleanroom.md` section 4). Analysts answer from the decompilation or, better,
   from a narrower trace of the original, and write the answer as behaviour.
4. Field too coarse? Analysts add a field to the probe and the contract (a new trace version), re-record the
   oracle, the implementers add it to the rewrite, and compare again. Hashes narrow down to one entity or one textbox by adding its index.
5. RNG drift shows as differences in random-driven fields some frames after the cause: count `rand()`
   calls per frame in both (a temporary field) to find the extra or missing call.

## 10. The hooks in the rewrite
The rewrite implements the same contract as a permanent, switched-off-by-default feature:
- the same variables, replay parser, exit behaviour and base-folder flag;
- the same frame structure: poll, input hook, logic, snapshot, render, framebuffer hash, write, exit check;
- under replay, one fixed step per render and no interpolation;
- the original's random number generators, bit for bit, called in the same order (a Rust rewrite needs its
  own MSVC `rand()`: per thread, seed 1, the LCG above; `scripts/rust/template/cnum.rs` has it);
- the same field definitions, byte orders and hash inputs.
`scripts/harness/harness_core.h` holds the game-independent half (replay parsing, FNV-1a, float bits,
framebuffer hash, line building, exit frame). It is this skill's code, not the game's: the probe and a C/C++
rewrite both include it, with the game's names in macros, and it may go into implementer workspaces. A Rust
rewrite ports it (about 360 lines of C). The parity test of this skill does not cover it (it was compiled
and run once as C89 and as C++ with clang): test it on the oracle first.

## 11. Config (decomp.json "rewrite", harness part)
```json
"rewrite": {
  "exe_name": "Game.exe", "runner": "wine", "wineprefix": "~/.wine",
  "env": {"replay": "GAME_REPLAY", "trace": "GAME_TRACE", "exit_frame": "GAME_EXIT_FRAME", "fb": "GAME_TRACE_FB"},
  "args": ["-savedir", "{basedir}\\"], "saves": "saves", "fps": 30,
  "trace": {"header": "GAME-TRACE 1", "frame_field": "f",
            "fields": ["gs", "st", "sd", "menu", "room", "p", "v", "...", "fb"], "decode": {"v": "f32"}},
  "scenarios": "rewrite/harness/scenarios",
  "extra_env": {"WINEDLLOVERRIDES": "SDL2=n,b"},
  "oracle": {"exe": "build/oracle/game/Game.exe", "traces": "rewrite/harness/oracle"}
}
```
| Key | Default | Meaning |
|---|---|---|
| `exe_name` | the exe's own name | name of the exe in the run folder (the game may look for its own name) |
| `game` | the exe's folder | folder with the game's data, copied for each run (leave it unset: the oracle runs from its own folder with the probe; pass `--game work/game` for the rewrite) |
| `env.*` | `GAME_REPLAY`, `GAME_TRACE`, `GAME_EXIT_FRAME`, `GAME_TRACE_FB` | variable names of the contract |
| `args` | none | program arguments; `{basedir}` (empty folder per try), `{game}` (the run folder) |
| `saves` | `""` (the whole basedir) | the save folder inside basedir, collected by `--saves-out` |
| `fps` | 30 | logic frames per second, for the default timeout |
| `trace.header`, `trace.frame_field`, `trace.fields`, `trace.decode` | none, `f`, none, none | trace checks and float display |
| `scenarios` | `rewrite/harness/scenarios` | `record_oracle.py` runs every `*.txt` there |
| `extra_env` | none | more variables for every run (e.g. `WINEDLLOVERRIDES` for the probe) |
| `oracle.exe`, `oracle.traces` | none, `oracle` next to `scenarios` | the original exe in the oracle folder; where `record_oracle.py` writes |

## Scripts
| Script | Step | Purpose |
|---|---|---|
| `wintools.py imports`, `wintools.py proxy` | 4 | which DLLs the game loads; the probe's forwarding `.def` |
| `harness/probe_core.h` | 4 | the probe's game-independent half: original exports, address mapping, memory reads, call/jump patches in memory, a log |
| `harness/harness_core.h` | 4, 7 | C/C++ half of the hooks: replay parser, FNV-1a, float bits, framebuffer hash, trace line, exit frame |
| `harness/keysend.cpp` | 4, 9 | Win32 tool: post scripted key presses to a window by title (real input, outside the contract) |
| `run_scenario.py` | 4, 8 | one scenario with one exe: scratch copy, variables, retries, trace and saves |
| `record_oracle.py` | 4 | N runs per scenario, determinism report, the oracle's traces and saves |
| `compare_traces.py` | 8 | frame-by-frame, field-aware comparison with a JSON summary |
The Python scripts have JavaScript ports in `scripts/js/` with the same command line and output
(`js/parity/run_all.mjs`).
