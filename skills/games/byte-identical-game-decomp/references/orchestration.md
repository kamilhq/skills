# Orchestrating the phases with subagents

## Shape that worked: build -> skeptic -> fix (max 2 rounds) -> completeness critic
```js
const results = await pipeline(ITEMS,
  it => agent(buildPrompt(it), {label: `build:${it.id}`, schema: BUILD_SCHEMA, effort: 'high'}),
  async (built, it) => {
    let cur = built, rounds = 0
    let v = await agent(verifyPrompt(it, cur), {label: `verify:${it.id}`, schema: VERIFY_SCHEMA, effort: 'high'})
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
- Every prompt starts with a shared COMMON block: project root, read-only inputs, the contract, the
  command to run, which files the agent may write (only its own module/chunk files), and "Python stdlib,
  run with -I".
- Builders return structured counts taken from the harness report, not from memory.

## Skeptic prompt essentials
- "Assume the claim is wrong until proven." Re-run the harness into separate out/report dirs and compare
  the file count against an independent `find`.
- Read the implementation for leaks and inflated confidence; measure opaque bytes yourself.
- Mutation test with expected-location check; pristine copy rebuilds identically.
- Look at the output (images with the Read tool, plausibility of numbers, readable strings).
- Verdict pass only if all hold; issues must be concrete and actionable.
- For naming: sample 20, decide what a function does BEFORE reading the given evidence.

## Mistakes that happened - avoid them
- **Placeholder args.** Twice a workflow was launched with `args: "__CHUNKS__"` / issue lists set to
  placeholder strings. Always pass the real JSON value (`args: [{...}, ...]`), never a string you meant to
  substitute; for long lists, print the JSON with a script and paste it. If it happens, stop the run
  immediately, check nothing was written, relaunch.
- **Trusting a log line.** A Ghidra pass logged "created 56" but rolled back (nested transaction). Confirm
  effects with an independent count (export size, coverage).
- **Shared projects.** Parallel agents must not write to the same Ghidra project; give them the exported
  `.c`/`.tsv` files (read-only `inspect.sh` queries are fine).
- **Docs built on an incomplete input** (DLL function maps written before function recovery) must be
  refreshed when the input grows.
- **Minor-issue pass.** Skeptics that pass with minor issues still list them; run a short correction pass
  where each issue is re-checked against evidence (some verifier claims are themselves wrong - the
  correction agent should reject those with a reason).

## Scale guidance
- Data modules: one builder per format group (10-12 groups for a typical game).
- Naming: chunks of ~8k pseudocode lines (~150 functions) -> ~80-90 chunks for a 3.5 MB exe.
- Matching: one agent per translation unit or per batch of small functions; results feed the hybrid build
  serially (one integrator) so the byte-identity gate is checked after every swap.
- Log what a bounded pass did not cover (no silent caps).
