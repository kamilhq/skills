# Orchestration: splitting the rewrite across agents

A rewrite is days of agent work. One coordinator (the session the user talks to) plans, briefs agents, merges
and **verifies**; the agents do the work in bounded, checkable pieces. This file is the plan that took an
SDL2 game of about a thousand game functions from a matched decomp to a C++ and a Rust rewrite, both
identical to the original in about twenty scenarios, and what went wrong on the way.

## 1. The sequence
| # | Agent | Input | Output | Parallel? | Wall time seen |
|---|---|---|---|---|---|
| 1 | toolchain | inventory (step 1) | `libraries.json`, both flavours of the libraries, both hello programs `RESULT: OK` | alone | not recorded |
| 2 | harness / oracle | matched main loop, the toolchain | `HOOKS.md`, the oracle, 3 scenarios, determinism proven (3 runs each) | alone | about 7 h (includes hours the Mac slept, section 8) |
| 3 | C++ consolidation | matched units, oracle | the C++ rewrite: every game function, builds with the original compiler, 3 scenarios identical | **one agent** | about 1 h |
| 4a | scenario widening (+ C++ fixes) | oracle, C++ rewrite | about 16 more scenarios, fuzz generator, own test levels; C++ corrected where they diverged | parallel with 4b | about 1.75 h |
| 4b | Rust foundation | C++ rewrite, toolchain | the crate: skeleton (one stub per function), `Cx`, state structs, `ffi/`, harness, main loop, maths; builds | parallel with 4a | not recorded |
| 5 | Rust waves (8) | foundation, C++ rewrite, `BRIEF.md` | each: its modules translated in a private copy of the crate, `WAVE_NOTES.md` | **8 in parallel** | 13-25 min each |
| 6 | integration | the 8 copies, WAVE_NOTES, the corrected C++ | one crate, no stub, builds, all scenarios identical, extra runs against the C++ | alone | about 2 h |
| 7 | verification | everything | the coordinator's own re-run of every check | the coordinator | - |

## 2. What must be one agent, and why
- **Toolchain and harness.** Each is one long chain of dependent discoveries (a library pin that fails on the
  game's data, a hook that breaks the source build's function pairing). Splitting them only adds handoffs.
- **C++ consolidation.** The generator's output is fixed by hand until it compiles, and almost every fix
  touches shared headers (one class definition, one set of constants, include cycles). Parallel agents would
  edit the same headers and break each other's builds. One agent did it in about an hour.
- **Integration.** Merge decisions need the whole picture: which wave changed which signature, which state
  struct three waves edited.
- **Verification** belongs to the coordinator (section 7).

What parallelises well: translation of independent modules once the shared state is pinned (section 3), and
work that only reads shared state (scenario authoring next to the Rust foundation).

## 3. The wave pattern
**Before the waves (the foundation agent):** the crate builds with a stub for every function
(`rust.md` section 11), and everything shared is written and pinned: `Cx`, every state struct with all
fields, the enums, `ffi/` for every library, the harness module, the C numerics, the main loop. A wave that
must change shared state records it (below); pinning first keeps those changes rare (in the validated run 3
state files were edited by more than one wave, all resolvable).

**The brief** (`rewrite/rust_wave/BRIEF.md`, one file for all waves, plus a short task per wave naming its
modules). It says:
- setup: copy the crate to `rewrite/rust_wave/<wave>/` and build the copy with its own `CARGO_TARGET_DIR`;
- what to read first (`DESIGN.md`, `README.md`) and that its rules are binding;
- the source: the C++ rewrite (frame-proven), with the matched unit and the pseudocode as the truth when
  the C++ is unclear;
- the rules: fill every stub of your modules, keep address lines and signatures; edit only your files;
  same behaviour bit for bit (RNG order, integer types, float evaluation, string bytes), no improvements, no
  `unsafe` outside `ffi/`; large data by a script with count checks; no downloads, no commits, no absolute
  user paths; do not touch the main crate, other copies, the C++ rewrite, the harness;
- the report: files and line counts, functions translated / total, stubs left and why, every signature and
  state change, risky spots, build result.

**`WAVE_NOTES.md`** in every copy, required for every change that crosses the wave's modules:
- signature changes: function, old -> new, callers (and that the wave fixed them in its copy);
- state changes: the exact field added or retyped, with the C++ declaration and offset;
- new files (generated tables, new `ffi/` files) and new public helpers;
- assumptions about other modules' functions ("an empty string is taken as NULL");
- risky spots: where exact behaviour is uncertain (uninitialised locals, out-of-bounds reads, float spots).

**Sizes.** Split by module ownership, then balance by function count and difficulty; one big state machine
is a wave's main job on its own. A split of about 950 stubs that worked:

| Wave | Modules | Functions |
|---|---|---|
| graphics | renderer (3 files), screen | 174 |
| sys | music, sound, filesystem, xml, utilities, platform services, logging | 146 |
| loc | localization, font, bidi, string formatting, utf8, glyph tables | 130 |
| editor | level editor, user levels (+ their tables) | 125 |
| game | game (5 files: state machine, menus, saves, settings, text boxes) | 117 |
| entity | entities, text boxes | 92 |
| mapscript | map (+ room tables), script (+ built-in scripts) | 68 |
| gameloop | render, logic, input, input polling | 66 |
| (foundation) | main loop (18), maths and logging (15, hand-written) | 33 |

Each wave took 13 to 25 minutes. Stubs keep every copy building, so no wave waits for another; a wave that
calls a stub of another wave gets `Default` until the merge.

## 4. Integration
1. Files only one wave changed: copy from that wave (its modules, its generators, its new `ffi/` files).
2. Files several waves changed (shared state): three-way merge against the foundation
   (`git merge-file mine base theirs`, one wave after the other). In the validated run: 3 files; two waves
   had added the same field with the same type, merged once; the rest merged cleanly.
3. Build. The errors are the signature changes of WAVE_NOTES meeting callers in other waves: about two dozen
   errors, all of that kind (a function that gained `cx`, an `Option` return, a slice instead of a pointer).
   Fix the callers to the new signature.
4. Run every scenario (`--ignore fb` first, then with `fb`), compare the save folders. Work each divergence
   (section 5). The validated run needed 3 behaviour fixes, all found by the harness:
   - two functions decremented the wrong timers: members misnamed in a matched unit's class copy, inherited
     from the C++ rewrite before the C++ was corrected (`rust.md` section 9); seen as `fb` from frame 1408
     in one play mode's scenario;
   - a clamp macro that evaluates its random argument up to three times was translated as one evaluation
     (`rust.md` section 6); seen as `fb` in an editor fuzz run while its menu was open.
5. Update `DESIGN.md` / `README.md`: no placeholders left, deviations, results.

## 5. The comparison loop
Three programs play the same replay: the oracle, the C++ rewrite, the Rust rewrite.
1. Compare the Rust trace with the oracle's (`compare_traces.py --ignore fb`, then with `fb`). The first
   differing frame and field name the subsystem (`harness.md` section 9).
2. Run the C++ rewrite on the same replay. If it matches the oracle, the Rust translation of the code that ran
   in that frame differs from the C++: read both side by side. If both rewrites differ from the oracle in the
   same way, the bug is in their common source (a matched unit): fix the C++ first, then port the fix.
3. Dump framebuffers around the frame (`--fbdump DIR --fbdump-every N`) for `fb`-only differences: a
   render that state fields cannot show (a fading text that never fades, a colour).
4. RNG drift: a temporary trace field counting `rand()` calls per frame finds the extra or missing call
   (argument order, macro re-evaluation, a skipped render call).
5. Bisect inside a frame with temporary log lines in both rewrites (the C++ rewrite takes them easily; it is
   not the oracle), then remove them.

**Rewrite against rewrite.** Code no oracle scenario reaches can be checked cheaply by running random input
through both rewrites and comparing (no oracle recording needed). Example: 40 replays (main-game
playthroughs, play-mode prefixes + random input, own levels, editor fuzz runs, every language; about
140,000 frames), 39 identical, the 40th quitting by itself in both. These runs found the clamp bug. Their
limit: both rewrites can share a bug (the misnamed timers matched between them until an oracle scenario
showed it), so they widen coverage but do not replace oracle scenarios.

## 6. Widening the scenarios
Three scenarios prove the loop; they do not prove the game. Before the Rust waves end, widen:
- **every mode and menu**: play modes (time trials, challenge and assist modes, bonus levels), options
  (gameplay, graphics, accessibility toggles), credits and the ending, every language family the game ships
  (right-to-left, CJK);
- **fuzz with prefixes**: a seeded generator (`random.Random(seed)`) writes replays: a fixed prefix (menus
  that unlock modes and start a level) then random walks, jumps, map and pause menus for thousands of frames.
  Seeds are scenario names; keep only seeds that reach new places (a project `gen_fuzz.py summary` listing rooms, states,
  deaths);
- **own test levels**: levels the harness writes itself (no game content) that exercise every entity type
  and script command, loaded from the level list or a command-line option;
- **the editor** (or any tool mode): load a prepared file, drive every tool by keys;
- **seeded files and arguments**: a scenario may need a level in the base folder, an unlock file, a
  command-line option: `#! seed=<path in basedir>:<file>` and `#! arg=<argument>` lines in the scenario,
  which `run_scenario.py` copies into the fresh base folder before every try and passes to the program;
- **closed-loop authoring** for long scripted inputs: drive the oracle (hold right, press the action key when a
  text box waits, stop at a terminal), then freeze the resulting input as the replay.

Pitfalls seen:
- input the replay does not cover leaks in: hook R cleared the mouse buttons but not the pointer position, and
  the editor draws its cursor there. Under Wine that is the real pointer when it lies over the window.
  Record with the pointer away, and fix the contract (clear the position too) in its next version;
- real-time pacing: a setting that paces the loop to wall-clock time made a 3,500-frame run take 7 minutes;
  switch it off in the scenario;
- the game may quit by itself under random input (a menu option): cut the replay or bias the input.

Record every new scenario with `record_oracle.py --runs 2` (or 3); all runs byte-identical. In the validated
run: 16 new scenarios (about 1,000 to 5,000 frames), every one deterministic. The widening agent also fixed
the C++ rewrite where a new scenario diverged (the misnamed timers, seen in three scenarios).

## 7. Independent verification
The coordinator does not trust reports, its own agents' included. After the integration it re-runs the
decisive checks itself:
- clean rebuilds of both rewrites from an empty target folder;
- every scenario with both exes, traces compared with `cmp` and `compare_traces.py`, save folders with
  `diff -r`;
- a checksum of the user's real save folder before and after all runs (unchanged: every run uses a scratch
  base folder).
Also cheap and worth it: `grep` for `stub!(0x`, `unimplemented!`, `todo!` and `unsafe` outside `ffi/`, the
line and function counts of the report, and the decomp's byte-identical build (nothing in `src_matched`
touched). Tell the user what was re-run and what was only reported by an agent.

## 8. Operational lessons
| Problem | Seen as | Fix |
|---|---|---|
| macOS sleep | agents stalled for hours; Wine runs started before sleep never finished; audio stalled with the screen locked | keep the machine awake for the whole job (`caffeinate`, or the host's keep-awake) |
| Wine start crashes (about 40% under load, the original exe too) | exit codes 5/41, page faults, hangs before the window | runners retry (5 tries, stall timeout 30 s); judge a build only after several tries |
| `wineserver -k` between tries | parallel runs killed each other (`rc 1` after about 19 s) | one Wine prefix per concurrent run: an APFS clone (`cp -cR ~/.wine /tmp/prefix-N`), `WINEPREFIX` per run |
| translating from matched units | scaffolding copied, misnamed members inherited | translate from the clean, frame-proven C++ |
| shared state changed in parallel | merge conflicts, duplicated fields | pin `Cx` and the state structs before the waves; changes go through WAVE_NOTES |
| cross-module changes lost | build errors at the merge with no explanation | WAVE_NOTES required for every signature and state change |
| a stub panics | one missing function stops every scenario | generated stubs log `unimplemented 0x...` once and return `Default` |
| big tables typed by hand | silent typos | conversion by script with count checks against the source |
| a report says "identical" | it was a different build, or `--ignore fb` | the coordinator re-runs the checks itself (section 7) |

Runs per scenario took 10 to 30 s under Wine with replay (plus retries): budget a few minutes per exe for
twenty scenarios run one after the other, less with one Wine prefix per parallel run.

## 9. Sizes to expect (an SDL2 game of about 3,300 functions)
| | |
|---|---|
| inventory | about a third of the exe's functions game code, a quarter in seven libraries, the rest CRT / compiler |
| oracle | 4 main-loop functions edited, every other matched function kept; 3 scenarios, then about 20 (1,000-5,000 frames) |
| C++ rewrite | about a thousand functions + WinMain, about 110 files, about 80,000 lines, the original compiler, about 1 h of agent time |
| Rust rewrite | about 950 functions (almost all from stubs), about 30 modules, about 80,000 lines (a third generated), 8 waves of 13-25 min, integration about 2 h |
| result | both rewrites identical to the oracle in every scenario, framebuffer hash and saves included; extra Rust-vs-C++ fuzz replays identical |

## 10. Publishable mode
In a clean-room rewrite (`cleanroom.md`) the sequence changes: toolchain and harness/oracle (rows 1-2) stay
as they are; the C++ consolidation, the Rust foundation from stubs and the translation waves (rows 3-5) are
replaced by analysts writing specs and fresh implementer sessions writing their own design from packed
workspaces; widening the scenarios (row 4a) is unchanged and serves both. Never fork the coordinator into an
implementer (a fork carries the decompilation in its context), and never give an implementer the C++ or Rust
rewrite as a reference: in this mode the comparison loop's step 2 (reading both rewrites side by side) is
an analyst's job, and the answer goes back as a spec.

## Checklist
- [ ] Machine kept awake; one Wine prefix per concurrent run.
- [ ] Toolchain, harness and C++ consolidation each done by one agent, in that order.
- [ ] Rust foundation complete and pinned (stubs, `Cx`, state, `ffi/`, harness, main loop) before the waves.
- [ ] `BRIEF.md` written; each wave has a private copy, owned modules, its own target folder, a WAVE_NOTES.
- [ ] Scenarios widened (modes, options, languages, editor, own levels, fuzz) while the waves run.
- [ ] Integration: copies, three-way merges, call sites from WAVE_NOTES, every scenario identical.
- [ ] Rewrite-against-rewrite fuzz runs for code no scenario reaches.
- [ ] The coordinator re-ran every check itself and reported what it re-ran.
