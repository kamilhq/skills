# Clean-room rewrite (publishable mode)

A rewrite translated from the decompilation (the C++ and Rust flows in `cpp.md` and `rust.md`) is a
derivative work of the original code: it stays on the user's machine. A rewrite the user wants to publish
must be written **clean-room**: by implementers who never see code derived from the original, from written
descriptions of its behaviour, its data formats and its traces. The original's behaviour, rules and file
formats are not protected; its code is (the decomp skill's `references/legal-and-repo.md` has the reasons
and the law). This file is the process, the tools that keep the record, and the release gate.
It is not legal advice: tell the user so, and that a lawyer should look before anything commercial.

What it costs: specs lose detail, so expect more rounds of comparing traces than with translation, and
some divergences that are cheaper to document than to chase. What it keeps: the oracle, the scenarios, the
trace comparison and the toolchain of the private flow are used unchanged.

## 1. Roles
| Role | Reads | Writes | Who |
|---|---|---|---|
| Analyst | everything: decompilation, matched source, private rewrites, the oracle | behaviour specs, answers to questions | the coordinator or subagents with decomp context |
| Implementer | only its workspace (`cleanroom.py pack`), the clean tree, the traces it is given, the game's data files, public documentation and libraries | the clean tree | fresh agent sessions that never had decompiled code in context |
| Coordinator | everything | briefs, packs, the log; never code in the clean tree | the session the user talks to |

- **Isolation is by context, not by instruction alone.** An implementer is a new session with a fresh context
  (not a fork of the coordinator: a fork inherits everything the coordinator read). Its brief names only its
  workspace and the clean tree; it never contains paths, names or snippets from the decompilation.
- **Give implementers a separate folder.** Pack workspaces outside the project
  (`pack --out ../<game>-clean/workspace/<wave>`) and keep the clean tree in its own repository there, so
  the implementer's working folder holds nothing forbidden. For Claude Code sessions, add deny rules for the
  private project in that folder's `.claude/settings.json` (`"permissions": {"deny":
  ["Read(//<absolute project path>/**)"]}`) as a second guard. Instructions (the workspace's `RULES.md`)
  are the third.
- **Once dirty, always dirty.** A session or person who read the decompilation does not become an
  implementer later. If the user read decompiled code, they review behaviour, not the clean tree's code.
- **Third-party libraries are not the original.** Implementers may use the same open-source libraries the
  game used (`inventory.md`, `libraries.json`), from upstream, under their licences.

## 2. Specs (analysts)
One spec per feature or subsystem (`cleanroom/specs/<subsystem>.md`), in the analyst's own words:
- **Behaviour**: what happens each frame, state machines (states, events, transitions), rules, formulas in
  mathematical notation, timings in frames, edge cases ("two flips in one frame: the second is ignored").
- **Facts as facts**: constants that define behaviour ("gravity 0.5 px per frame, capped at 10"), the order
  of random-number draws when it changes the outcome, rounding ("truncated toward zero"). These are
  findings about behaviour, not code.
- **Data**: which of the user's files hold what, in which format (`docs/formats/*.md` from the decomp, which
  are already in the project's own words), and for data that sits inside the original executable (level
  layouts, text, tables): its location and layout in the user's exe, so the rewrite can read it at run time
  (section 5).
- **Interfaces**: the trace contract (`harness.md`): what each trace field means, in words.

Not in a spec: code in any language, pseudocode that follows a function line by line, the original's
function or variable names, addresses, the original's module structure. Describe *what* and *when*, not *how
the original's code is laid out*. `cleanroom.py lint` checks every spec (Ghidra names, code blocks, code-like
lines, token runs shared with the reference code); `pack` refuses specs that fail it.

## 3. Workspaces (implementers)
`cleanroom.py pack --wave <name> --out <dir> <inputs...>` copies the inputs into the workspace with
`INPUTS.json` (paths, SHA-256, sizes) and `RULES.md`, and appends the hand-over to the log. It refuses inputs
outside the project, in a forbidden area (by path or real path) or failing lint, and logs the refusal.
A workspace typically holds:
- the wave's specs and the format docs it needs;
- scenario replays and the oracle's traces for them (`rewrite/harness/scenarios/`, the oracle traces): these
  are recordings of behaviour, like watching the game;
- the trace contract and the harness scripts' usage (`run_scenario.py`, `compare_traces.py`);
- the toolchain notes (`libraries.json`, `toolchains.md`): libraries and compilers, not game code.

Implementers may run the user's original game and watch it. They never get the oracle's source, the
original executable to disassemble, the decompilation, the matched source, the private rewrites or the
names maps.

## 4. The loop
1. An implementer designs the clean tree first (its own modules, state, names) from all specs of the first
   waves; later waves extend it. There is no stub generator and no address line: nothing maps one-to-one to
   the original's functions.
2. Each wave: implement from the workspace, build, run the scenarios with `run_scenario.py`, compare with
   `compare_traces.py` against the oracle's traces.
3. A divergence the specs do not explain becomes a written question (`cleanroom/questions/<wave>-NN.md`),
   logged with `cleanroom.py record --wave W --event question FILE`. An analyst answers in a new spec
   section (linted), logged with `record --event answer FILE` and handed over with a new `pack`. Answers
   describe behaviour ("the timer is decremented before the check"), never code.
4. Repeat until the traces are identical, or the remaining divergence is documented (uninitialised memory,
   undefined behaviour of the original) and accepted by the user.
The comparison-loop advice of `orchestration.md` section 5 applies, except that implementers bisect with their
own logging only; reading the original side by side is the analysts' job.

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
| names | more than `names_pct` % of the tree's function definitions carry a phase-5 name of the original |
| similarity | more than `code_pct` % of the tree's code fingerprints, or `const_pct` % of its constant-sequence fingerprints, are found in the reference; or one file above `file_pct` % |
| notices | no LICENSE/COPYING or README at the top; libraries linked but no third-party notice |

Fingerprints: token 12-grams with identifiers abstracted and string contents kept, taken only where they hold
at least two significant numbers or strings (numbers >= 32, floats that are not small multiples of 1/4), then
winnowed (window 4); constant sequences are 5-grams of significant numbers in order, which survive translation
into another language. The reference is everything derived from the original code: the decompiled and named
exports, the matched source and the private rewrites (folders matching `**/third_party/**`, `**/build/**`,
`**/target/**` left out). The tree's own `third_party/`, `vendor/`, `target/`, `build/` are not checked.

Calibration on the validated project (an SDL2 game, the reference holding its decompilation, matched C++ and
C++ rewrite):
| Tree | Code | Constants | Names |
|---|---|---|---|
| the Rust rewrite translated from the C++ (`rust.md`) | 93 % | 98 % | 55 % |
| independent Rust crates for the same jobs as libraries inside the exe (a Vorbis decoder vs the exe's stb_vorbis, a PNG decoder vs its lodepng, an image library, a maths library, a WAV library) | 0 % | 0-14 % (worst file 38 %) | 7 % |
| the original C/C++ sources of three libraries inside the exe (physfs, tinyxml2, lodepng) | 0-5 % | 0-26 % | - |

The last row is the gate's limit: Ghidra's pseudocode looks so unlike source code that even the true
original scores low against it. Code written from the matched C++ or a private rewrite is caught (first row),
which is why those are in the reference; code someone wrote by reading the raw pseudocode might not be.
Isolating the implementers (section 1) is what prevents that.

A finding that is legitimate (a codec's 1,500-entry table in the tree's own code, a file name string the
format requires) goes into the allow file with a reason: `cleanroom/allow.json`,
`{"findings": [{"check": "tables", "file": "src/codec.rs", "line": 12, "reason": "..."}]}`. Allowed findings
are listed in the report with their reasons. The gate cannot see copying it has no fingerprint for (the same
algorithm re-expressed from memory, structure copied without constants): it is evidence, the process in
sections 1-6 is the protection. It also prints what only a person can check (name and branding, the README's
statement that the original game is required, the repository history).

## 8. Settings (decomp.json `rewrite.cleanroom`)
| Key | Default |
|---|---|
| `dir`, `specs`, `log`, `allow` | `cleanroom`, `<dir>/specs`, `<dir>/log.jsonl`, `<dir>/allow.json` |
| `tree` | `rewrite/clean` |
| `private` | `["rewrite/cpp", "rewrite/rust", "rewrite/rust_wave"]` (the private rewrites) |
| `forbidden` | every binary's `decompiled`, `named`, `reassembled`; `paths.src`, `paths.analysis`, `rewrite.oracle.dir`; `private`; `**/*.gpr`, `**/*.rep` (Ghidra projects) |
| `reference` | every binary's `decompiled` and `named`, `paths.src`, `private` |
| `reference_exclude` | `**/build/**`, `**/target/**`, `**/third_party/**`, `**/.git/**` |
| `tree_exclude` | `third_party/**`, `vendor/**`, `target/**`, `build/**`, `.git/**` (relative to the tree) |
| `assets` | `paths.game`, `paths.extracted`, `paths.decoded` |
| `names` | `<paths.analysis>/<binary name>/names_apply.json` for every binary (JSON maps, lists of `{name}`, or TSV with the name in column 2) |
| `require_log` | `true` |
| `thresholds` | `code_pct` 10, `const_pct` 20, `file_pct` 50, `file_min` 20, `names_pct` 30, `names_min` 20, `table_items` 1024, `string_items` 64, `string_bytes` 2048, `min_string` 8, `spec_overlap` 3, `spec_code_lines` 3 |
Patterns are project-relative; `*` stays within a folder, `**` spans folders, and a pattern also matches
everything below a folder it matches. Building the reference index takes about 20 s and 300 MB for 17,000
reference files.

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
- [ ] Mode is publishable (`decomp.json` `"mode"`); `cleanroom.py init` run; the log committed.
- [ ] Implementers are fresh sessions working in a separate folder; deny rules set; briefs name only the
      workspace and the clean tree.
- [ ] Every spec passed `cleanroom.py lint`; every hand-over went through `pack` or `record`.
- [ ] The clean tree has its own design; no generator, address line or original name maps into it.
- [ ] Game data, including tables inside the original exe, is read from the user's installation at run time.
- [ ] Traces identical in every scenario, or remaining divergences documented and accepted.
- [ ] `release_check.py` passes; the manual items checked with the user; the user publishes.
