# Orchestration: splitting the work across agents

A rewrite is days of agent work. One coordinator (the session the user talks to) plans, briefs agents, keeps
the clean-room record and **verifies**; agents do the work in bounded, checkable pieces. Two kinds of agent
never mix: analysts (anything on the analysis side) and implementers (fresh sessions on the clean side,
`cleanroom.md` section 1).

## 1. The sequence
| # | Side | Agents | Input | Output | Parallel? |
|---|---|---|---|---|---|
| 1-2 | analysis | coordinator | installer | game folder, manifest, inventory | alone |
| 3a | analysis | one per binary | game folder | complete recovery, decompiled export | per binary |
| 3b | analysis | namers -> auditors, per chunk | the export, `CONTEXT.md` | names, architecture doc | many (section 2) |
| 3c | analysis | one | names, the PE | code inventory, `libraries.json` | alone |
| 3d | analysis | builder -> skeptic, per format group | game data, loader code | format readers (round trip), `docs/formats/*.md` | many |
| 3e | analysis | spec writers, per subsystem | names, docs, the oracle once it exists | `cleanroom/specs/*.md`, linted | many |
| 4 | analysis | one | main loop, input and timing code | the probe, `HOOKS.md`, scenarios, determinism proven | alone |
| 5 | - | the user | - | the language | - |
| 6 | clean | one implementer | `libraries.json`, `toolchains.md` | libraries built, hello program `RESULT: OK` | alone |
| 7a | clean | one implementer (the architect) | all first-wave specs | the tree's design and foundation, builds, main loop + harness, first scenario running | alone |
| 7b | clean | implementers, one per wave | foundation, the wave's workspace | the wave's modules in a private copy, `WAVE_NOTES.md` | in parallel |
| 7c | clean | one implementer (the integrator) | the copies, WAVE_NOTES | one tree, builds, scenarios run | alone |
| 8 | both | implementers ask, analysts answer | traces, questions | identical traces | rounds |
| 9 | - | coordinator | everything | its own re-run of every check; `release_check.py` | alone |

Step 3e can start before step 4 (behaviour from the code) and is refined after it (behaviour from traces).
Widening the scenarios (section 6) runs on the analysis side next to steps 7-8.

## 2. Analysis workflows: build -> skeptic -> fix -> completeness critic
```js
const results = await pipeline(ITEMS,
  it => agent(buildPrompt(it), {label: `build:${it.id}`, schema: BUILD_SCHEMA}),
  async (built, it) => {
    let cur = built, rounds = 0
    let v = await agent(verifyPrompt(it, cur), {label: `verify:${it.id}`, schema: VERIFY_SCHEMA})
    while (v && v.verdict !== 'pass' && rounds < 2) {
      rounds++
      cur = (await agent(fixPrompt(it, cur, v), {label: `fix:${it.id}#${rounds}`, schema: BUILD_SCHEMA})) || cur
      v = await agent(verifyPrompt(it, cur), {label: `reverify:${it.id}#${rounds}`, schema: VERIFY_SCHEMA})
    }
    return {id: it.id, built: cur, verified: v, rounds}
  })
// then a barrier, and one critic over everything
```
- Use `pipeline` so each item verifies as soon as its build finishes.
- Every prompt starts with a shared COMMON block: project root, read-only inputs, the contract, the command
  to run, which files the agent may write (only its own module/chunk files), and "Python stdlib, run with -I".
- Builders return structured counts taken from the harness report, not from memory.

Skeptic essentials:
- "Assume the claim is wrong until proven." Re-run the harness into separate out/report dirs and compare
  the file count against an independent `find`.
- Format readers: read the code for leaks and inflated confidence; measure opaque bytes yourself; mutation
  test with an expected-location check; look at the output (images with the Read tool, plausible numbers).
- Naming: sample 20, decide what a function does BEFORE reading the given evidence.
- Specs: run `cleanroom.py lint`; check that the spec says *what and when* and could be implemented by
  someone who has never seen the code; no line-by-line paraphrase of a function.

Scale: format readers, one builder per format group (10-12 groups for a typical game); naming, chunks of
about 8k pseudocode lines (about 150 functions), so about 80-90 chunks for a 3.5 MB exe; specs, one writer
per subsystem from the architecture doc. Log what a bounded pass did not cover (no silent caps).

## 3. What must be one agent, and why
- **Toolchain, probe, architect, integrator.** Each is one long chain of dependent decisions (a library pin
  that fails on the game's data, a hook that disturbs what it measures, shared state every module uses).
  Splitting them only adds handoffs.
- **Verification** belongs to the coordinator (section 7).
What parallelises well: analysis per chunk or per format, and implementation of independent modules once
the shared state is pinned (section 4).

## 4. Implementation waves (clean side)
**Before the waves (the architect):** from all first-wave specs, design the tree: modules by subsystem,
one context/state structure, every state field the specs name, the library bindings, the harness module
(the trace contract), the main loop. Every function the waves will write exists as a stub that logs the
spec section it stands for (`todo_spec!` in Rust, an equivalent macro in C++) and returns a default, so
every copy builds. Pin shared state before the waves: a wave that must change it records it.

**The brief** (one file for all waves, plus a short task per wave naming its modules and its workspace). It
says:
- setup: copy the tree to the wave's own folder (outside the analysis project) and build it there with its
  own target folder;
- what to read first (the tree's `DESIGN.md`, the workspace's `RULES.md`) and that the rules are binding;
- the source: the specs and traces of the workspace, nothing else; questions in writing to the coordinator;
- the rules: fill every stub of your modules; edit only your files; behaviour exactly as specified (RNG
  order, integer types, float evaluation, string bytes), no improvements; data from the user's game files
  at run time, never typed in from memory; no downloads, no commits, no absolute user paths;
- the report: files and line counts, stubs left and why, every signature and state change, open questions,
  build result.

Never fork the coordinator or an analyst into an implementer (a fork carries the analysis in its
context). The brief never names analysis paths, addresses or the original's names.

**`WAVE_NOTES.md`** in every copy, required for every change that crosses the wave's modules: signature
changes (old -> new, callers fixed in the copy); state changes (the exact field added or retyped); new
files and public helpers; assumptions about other modules; risky spots (where the spec was unclear).

**Sizes.** Split by module ownership, then balance by the number of spec sections and their difficulty;
one big state machine is a wave's main job on its own. Eight waves of a few dozen to two hundred functions
each is a workable shape for a game of about a thousand game functions.

**Integration:** files one wave changed come from that wave; files several waves changed get a three-way
merge against the foundation (`git merge-file mine base theirs`); build; the remaining errors are the
signature changes of WAVE_NOTES meeting callers in other waves. Then every scenario (`--ignore fb` first).

## 5. The comparison loop
1. Compare the rewrite's trace with the oracle's (`compare_traces.py --ignore fb`, then with `fb`). The first
   differing frame and field name the subsystem (`harness.md` section 9).
2. The implementer checks its code against the spec for that subsystem and frame. If the spec does not
   decide the case, it writes a question; an analyst answers from the original - preferably with a narrower
   trace or a temporary probe field rather than from the code - as a new spec section (`cleanroom.md`
   section 4).
3. Dump framebuffers around the frame (`--fbdump DIR --fbdump-every N`) for `fb`-only differences.
4. RNG drift: a temporary trace field counting `rand()` calls per frame, added to both the probe and the
   rewrite, finds the extra or missing call.
5. Bisect inside a frame with temporary log lines in the rewrite, then remove them.
Code no oracle scenario reaches: add scenarios (section 6). Running two clean rewrites against each other is
cheap but both can share a misunderstanding of the same spec; it widens coverage, it does not replace the
oracle.

## 6. Widening the scenarios (analysis side)
A few scenarios prove the loop; they do not prove the game. While the waves run, widen:
- **every mode and menu**: play modes, options, credits and the ending, every language family the game ships
  (right-to-left, CJK);
- **fuzz with prefixes**: a seeded generator writes replays: a fixed prefix (menus that unlock modes and
  start a level) then random input for thousands of frames; keep only seeds that reach new places;
- **own test levels**: levels the harness writes itself (no game content) that exercise every entity type
  and script command;
- **tools in the game** (an editor): load a prepared file, drive every tool by keys;
- **seeded files and arguments**: `#! seed=<path in basedir>:<file>` and `#! arg=<argument>` lines, copied
  and passed by `run_scenario.py` before every try;
- **closed-loop authoring** for long inputs: drive the oracle, then freeze the input as the replay.
Pitfalls seen: input the replay does not cover leaks in (the mouse pointer position under Wine: clear it in
the contract); a real-time pacing setting makes long runs slow; random input can quit the game. Record every
new scenario with `record_oracle.py --runs 2` (or 3) and pack its traces for the implementers.

## 7. Independent verification
The coordinator does not trust reports, its own agents' included. It re-runs the decisive checks itself:
- a clean rebuild of the rewrite from an empty target folder;
- every scenario, traces compared with `cmp` and `compare_traces.py`, save folders with `diff -r`;
- a checksum of the user's real save folder before and after all runs (unchanged: every run uses a scratch
  base folder);
- `grep` for `todo_spec!`, `unimplemented!`, `todo!`, and `unsafe` outside the FFI layer;
- `cleanroom.py verify` and `release_check.py` on the tree.
Tell the user what was re-run and what was only reported by an agent.

## 8. Operational lessons
| Problem | Seen as | Fix |
|---|---|---|
| macOS sleep | agents stalled for hours; Wine runs started before sleep never finished | keep the machine awake for the whole job (`caffeinate`, or the host's keep-awake) |
| Wine start crashes (about 40% under load, the original exe too) | exit codes 5/41, page faults, hangs before the window | runners retry (5 tries, stall timeout 30 s); judge a build only after several tries |
| `wineserver -k` between tries | parallel runs killed each other | one Wine prefix per concurrent run: an APFS clone (`cp -cR ~/.wine /tmp/prefix-N`), `WINEPREFIX` per run |
| placeholder workflow args | a run started with `"__CHUNKS__"` instead of the list | pass the real JSON value; stop at once if it happens |
| trusting a log line | a Ghidra pass logged "created 56" but rolled back | confirm effects with an independent count |
| shared Ghidra project | parallel writers corrupt it | agents read the exported `.c`/`.tsv` files; `inspect.sh` is read-only |
| shared state changed in parallel | merge conflicts, duplicated fields | pin the state before the waves; changes go through WAVE_NOTES |
| a stub panics | one missing function stops every scenario | stubs log their spec section once and return a default |
| a report says "identical" | it was a different build, or `--ignore fb` | the coordinator re-runs the checks itself (section 7) |
| an implementer asks for the code | "just show me the function" | refuse; answer as behaviour, logged; never widen a workspace with analysis files |

Runs per scenario took 10 to 30 s under Wine with replay (plus retries): budget a few minutes per exe for
twenty scenarios run one after the other, less with one Wine prefix per parallel run.

## Checklist
- [ ] Machine kept awake; one Wine prefix per concurrent run.
- [ ] Analysts and implementers are different sessions; implementers are fresh, never forks.
- [ ] Toolchain, probe, architect and integrator each one agent.
- [ ] Foundation complete and pinned (stubs, state, bindings, harness, main loop) before the waves.
- [ ] Brief written; each wave has a private copy, owned modules, its own target folder, a WAVE_NOTES.
- [ ] Every hand-over through `cleanroom.py pack` / `record`; the log committed.
- [ ] Scenarios widened while the waves run.
- [ ] The coordinator re-ran every check itself and reported what it re-ran.
