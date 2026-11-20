# The clean room: roles, specs, hand-overs, the record, the release gate

Every rewrite this skill makes is written **clean-room**: by implementers who never see code derived from
the original, from written descriptions of its behaviour, its data formats and its traces. The original's
behaviour, rules and file formats are not protected; its code is (`legal.md` has the reasons and the law).
A rewrite translated from decompiled code would be a derivative work in any language, however much it was
cleaned up, so this skill has no translation path at all. This file is the process, the tools that keep the
record, and the release gate. It is not legal advice: tell the user so, and that a lawyer should look before
anything commercial.

What it costs: specs lose detail, so expect several rounds of comparing traces, and some divergences that
are cheaper to document than to chase. The oracle (`harness.md`) is what makes the rounds converge: every
question an implementer has can be asked of the original's traces first.

## 1. Roles
| Role | Reads | Writes | Who |
|---|---|---|---|
| Analyst | everything: the decompilation, names, format readers, the probe, the oracle's traces | behaviour specs, format docs, the trace contract, answers to questions | the coordinator or subagents with analysis context |
| Implementer | only its workspace (`cleanroom.py pack`), the clean tree, public documentation and libraries; it may run the user's game and watch it | the clean tree | fresh agent sessions that never had decompiled code in context |
| Coordinator | everything | briefs, packs, the log; never code in the clean tree | the session the user talks to |

- **Isolation is by context, not by instruction alone.** An implementer is a new session with a fresh context
  (not a fork of the coordinator: a fork inherits everything the coordinator read). Its brief names only its
  workspace and the clean tree; it never contains paths, names or snippets from the analysis.
- **Give implementers a separate folder.** Pack workspaces outside the project
  (`pack --out ../<game>-clean/workspace/<wave>`) and keep the clean tree in its own repository there, so
  the implementer's working folder holds nothing forbidden. For Claude Code sessions, add deny rules for the
  analysis project in that folder's `.claude/settings.json` (`"permissions": {"deny":
  ["Read(//<absolute project path>/**)"]}`) as a second guard. Instructions (the workspace's `RULES.md`)
  are the third.
- **Once dirty, always dirty.** A session or person who read the decompilation does not become an
  implementer later. If the user read decompiled code, they review behaviour, not the clean tree's code.
- **Third-party libraries are not the original.** Implementers may use the same open-source libraries the
  game used (`code-inventory.md`, `libraries.json`), from upstream, under their licences.

## 2. Specs (analysts)
One spec per feature or subsystem (`cleanroom/specs/<subsystem>.md`), in the analyst's own words:
- **Behaviour**: what happens each frame, state machines (states, events, transitions), rules, formulas in
  mathematical notation, timings in frames, edge cases ("two flips in one frame: the second is ignored").
- **Facts as facts**: constants that define behaviour ("gravity 0.5 px per frame, capped at 10"), the order
  of random-number draws when it changes the outcome, rounding ("truncated toward zero"), which C runtime
  generator a value comes from. These are findings about behaviour, not code.
- **Data**: which of the user's files hold what, in which format (`docs/formats/*.md`, written in step 3 in
  the analysts' own words, `formats.md`), and for data that sits inside the original executable (level
  layouts, text, tables): its location and layout in the user's exe, so the rewrite can read it at run time
  (section 5).
- **Interfaces**: the trace contract (`harness.md`): what each trace field means, in words; the libraries
  and their versions (`code-inventory.md`).
- **Program structure, in words**: the main loop's order of work per frame, the game states and how one
  leads to another. This is behaviour (it decides what a frame shows); the original's module and function
  layout is not.

Not in a spec: code in any language, pseudocode that follows a function line by line, the original's
function or variable names, addresses, the original's source file structure. Describe *what* and *when*, not
*how the original's code is laid out*. `cleanroom.py lint` checks every spec (Ghidra names, code blocks,
code-like lines, token runs shared with the reference code); `pack` refuses specs that fail it.

Coverage: list the subsystems in `cleanroom/specs/INDEX.md` with the scenarios that exercise each. Write
the specs for the first waves completely before the first hand-over; implementers design the whole tree
from them.

## 3. Workspaces (implementers)
`cleanroom.py pack --wave <name> --out <dir> <inputs...>` copies the inputs into the workspace with
`INPUTS.json` (paths, SHA-256, sizes) and `RULES.md`, and appends the hand-over to the log. It refuses inputs
outside the project, in a forbidden area (by path or real path) or failing lint, and logs the refusal.
A workspace typically holds:
- the wave's specs and the format docs it needs;
- scenario replays and the oracle's traces for them (`rewrite/harness/scenarios/`, `rewrite/harness/oracle/`):
  these are recordings of behaviour, like watching the game;
- the trace contract (`rewrite/harness/HOOKS.md`, in words) and the harness scripts' usage
  (`run_scenario.py`, `compare_traces.py`, `harness/harness_core.h`: this skill's own code, not the game's);
- the toolchain notes (`libraries.json`, `toolchains.md`, the chosen language's guide `cpp.md` or `rust.md`):
  libraries and compilers, not game code.

Implementers may run the user's original game and watch it. They never get the probe's source, the
original executable to disassemble, the decompilation, the analysts' format readers or the names maps.

## 4. The loop
1. An implementer designs the clean tree first (its own modules, state, names) from all specs of the first
   waves; later waves extend it. Nothing maps one-to-one to the original's functions, and nothing carries
   an address.
2. Each wave: implement from the workspace, build, run the scenarios with `run_scenario.py`, compare with
   `compare_traces.py` against the oracle's traces.
3. A divergence the specs do not explain becomes a written question (`cleanroom/questions/<wave>-NN.md`),
   logged with `cleanroom.py record --wave W --event question FILE`. An analyst answers in a new spec
   section (linted), logged with `record --event answer FILE` and handed over with a new `pack`. Answers
   describe behaviour ("the timer is decremented before the check"), never code.
4. Repeat until the traces are identical, or the remaining divergence is documented (uninitialised memory,
   undefined behaviour of the original) and accepted by the user.
The comparison-loop advice of `orchestration.md` section 5 applies, except that implementers bisect with
their own logging only; reading the original side by side is the analysts' job.

## 5. Game data at run time
Everything the game shows or plays comes from the user's installation at run time: graphics, sound,
music, text, levels, and also data compiled into the original executable. For the latter the rewrite opens
the user's exe, checks its SHA-256 against the versions it supports (one known version is fine), and reads
the tables at the offsets the spec gives. The source carries offsets, sizes and hashes - facts about the
user's file - never the data itself. `release_check.py` flags numeric tables of >= 1024 items, string tables
of >= 64 items and string literals shared with the original.

## 6. The record
`cleanroom.py init` creates `cleanroom/` (`specs/`, `questions/`, `README.md`) and `cleanroom/log.jsonl`;
every `pack`, `record` and refusal appends one JSON line with the SHA-256 of the previous line, so an edited
or removed line breaks the chain (`cleanroom.py verify`). The chain cannot protect its last line: commit the
log after every hand-over. Keep the log and the specs in the private project repository; they are the
evidence that the clean tree was written from them.

## 7. The release gate
`release_check.py [TREE]` (default tree `rewrite/clean`) must pass before anything is published:
| Check | Fails when |
|---|---|
| log | the log is missing, broken, has no `init` or no `pack`; the tree lies in a forbidden area |
| assets | a file of the tree equals (SHA-256) a file of the game, `extracted/` or `decoded/` |
| markers | address annotations (`// FUNCTION: 0x...`, `// 0x<address>` lines), `stub!(0x...)`, Ghidra names (`FUN_...`, `iVar1`, `param_1`, `in_EAX`, `undefined4` ...) |
| tables | an embedded numeric table of >= `table_items` numbers or string table of >= `string_items` strings |
| strings | string literals of >= `min_string` characters shared with the reference total more than `string_bytes` |
| names | more than `names_pct` % of the tree's function definitions carry a name the analysts gave the original |
| similarity | more than `code_pct` % of the tree's code fingerprints, or `const_pct` % of its constant-sequence fingerprints, are found in the reference; or one file above `file_pct` % |
| notices | no LICENSE/COPYING or README at the top; libraries linked but no third-party notice |

Fingerprints: token 12-grams with identifiers abstracted and string contents kept, taken only where they hold
at least two significant numbers or strings (numbers >= 32, floats that are not small multiples of 1/4), then
winnowed (window 4); constant sequences are 5-grams of significant numbers in order, which survive translation
into another language. The reference is the decompilation (raw and named exports) plus any folder listed in
`reference` (folders matching `**/third_party/**`, `**/build/**`, `**/target/**` left out). The tree's own
`third_party/`, `vendor/`, `target/`, `build/` are not checked.

Calibration (a project whose reference also held matched C++ of the same game and a C++ rewrite translated
from it, both made with tooling this skill no longer has):
| Tree | Code | Constants | Names |
|---|---|---|---|
| a Rust rewrite translated from that C++ | 93 % | 98 % | 55 % |
| independent Rust crates for the same jobs as libraries inside the exe (a Vorbis decoder vs the exe's stb_vorbis, a PNG decoder vs its lodepng, an image library, a maths library, a WAV library) | 0 % | 0-14 % (worst file 38 %) | 7 % |
| the original C/C++ sources of three libraries inside the exe (physfs, tinyxml2, lodepng) | 0-5 % | 0-26 % | - |

The last row is the gate's limit: Ghidra's pseudocode looks so unlike source code that even the true
original scores low against it. Code translated from source-like C++ is caught (first row); code someone
wrote by reading the raw pseudocode might not be, and with only the decompilation in the reference the
code check is weaker than in that calibration (the constants check is not: constants survive any
rewording). Isolating the implementers (section 1) is what prevents copying; the gate is evidence.

A finding that is legitimate (a codec's 1,500-entry table in the tree's own code, a file name string the
format requires) goes into the allow file with a reason: `cleanroom/allow.json`,
`{"findings": [{"check": "tables", "file": "src/codec.rs", "line": 12, "reason": "..."}]}`. Allowed findings
are listed in the report with their reasons. The gate cannot see copying it has no fingerprint for (the same
algorithm re-expressed from memory, structure copied without constants). It also prints what only a person
can check (name and branding, the README's statement that the original game is required, the repository
history).

## 8. Settings (decomp.json `rewrite.cleanroom`)
| Key | Default |
|---|---|
| `dir`, `specs`, `log`, `allow` | `cleanroom`, `<dir>/specs`, `<dir>/log.jsonl`, `<dir>/allow.json` |
| `tree` | `rewrite/clean` |
| `private` | `[]`: more folders of code derived from the original (forbidden and in the reference) |
| `forbidden` | every binary's `decompiled`, `named` (and `reassembled` if set); `paths.src` if set, `paths.analysis`, `paths.formats` (the analysts' readers), `rewrite.oracle.dir` if set; `private`; `**/*.gpr`, `**/*.rep` (Ghidra projects) |
| `reference` | every binary's `decompiled` and `named`, `paths.src` if set, `private` |
| `reference_exclude` | `**/build/**`, `**/target/**`, `**/third_party/**`, `**/.git/**` |
| `tree_exclude` | `third_party/**`, `vendor/**`, `target/**`, `build/**`, `.git/**` (relative to the tree) |
| `assets` | `paths.game`, `paths.extracted`, `paths.decoded` |
| `names` | `<paths.analysis>/<binary name>/names_apply.json` for every binary (JSON maps, lists of `{name}`, or TSV with the name in column 2) |
| `require_log` | `true` |
| `thresholds` | `code_pct` 10, `const_pct` 20, `file_pct` 50, `file_min` 20, `names_pct` 30, `names_min` 20, `table_items` 1024, `string_items` 64, `string_bytes` 2048, `min_string` 8, `spec_overlap` 3, `spec_code_lines` 3 |
Patterns are project-relative; `*` stays within a folder, `**` spans folders, and a pattern also matches
everything below a folder it matches. The probe lives in `analysis/probe/` and is forbidden with the rest of
the analysis. Building the reference index takes about 20 s and 300 MB for 17,000 reference files.

## 9. Publishing
- The clean tree lives in its own repository whose history never held game data or derived code. If it
  did, start a new repository rather than rewriting history.
- README: what the project is, that it needs the user's own copy of the game (and which version), how to
  point it at the installation, that it is not affiliated with the game's owner. No logos, no screenshots of
  the original's art in the repository.
- LICENSE for the project's own code only; third-party notices for every library.
- `release_check.py` passes (or every remaining finding is allowed with a reason the user agrees with);
  go through its `manual` list with the user. Publishing is the user's decision and action.

## Checklist
- [ ] `cleanroom.py init` run at step 0; the log committed after every hand-over.
- [ ] Implementers are fresh sessions working in a separate folder; deny rules set; briefs name only the
      workspace and the clean tree.
- [ ] Every spec passed `cleanroom.py lint`; every hand-over went through `pack` or `record`.
- [ ] The clean tree has its own design; no address line or original name maps into it.
- [ ] Game data, including tables inside the original exe, is read from the user's installation at run time.
- [ ] Traces identical in every scenario, or remaining divergences documented and accepted.
- [ ] `release_check.py` passes; the manual items checked with the user; the user publishes.
