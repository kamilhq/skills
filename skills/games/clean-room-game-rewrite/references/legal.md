# Ownership, legal boundaries and repository rules

This is the legal frame the skill works in, not legal advice. Laws differ by country and the law is
unsettled at the edges; tell the user so once, and point them to a lawyer before anything commercial.

## The shape of the work
| | Analysis side (steps 1-4) | Clean side (steps 6-9) |
|---|---|---|
| Who | analysts and the coordinator | implementers: fresh sessions that never saw the analysis (`cleanroom.md`) |
| Reads | the user's own copy of the game, its decompilation, the probe, the oracle's traces | specs and format docs in the analysts' own words, traces, the user's game data at run time |
| Writes | specs, format docs, the trace contract, the project's tools | the rewrite |
| May leave the machine | tools, format specs in the project's own words, hashes, reports | the rewrite, after `release_check.py` passes and the user has gone through its manual items |
| Never leaves | everything derived from the game (below) | game data and anything copied from the analysis side |

The decompilation itself (recovered code, pseudocode, names maps, Ghidra projects, the probe) stays on the
user's machine, always. The rewrite is the only product meant for others, and only because it is written
on the clean side.

## Why each rule exists
- **Copyright covers expression, not function.** The original's code (as written, and in translation) and its
  assets are protected. Its behaviour, rules, algorithms as ideas, and file formats are not: US 17 U.S.C.
  102(b); in the EU, the Software Directive 2009/24/EC recital 11 and *SAS Institute v World Programming*
  (CJEU C-406/10, 2012: functionality, programming languages and data file formats are not protected).
  A rewrite that matches behaviour and reads the original data formats can be the rewriter's own work; one
  that copies or translates the code's expression cannot. That is why there is no translation step: specs
  carry behaviour, never code.
- **Studying the program.** EU: whoever may use a program may observe, study and test it while running it to
  find its underlying ideas (Directive art. 5(3)); decompiling is allowed only to make an independently
  created program interoperate, limited to what is needed, and the results may not be used to write a
  program substantially similar in its expression (art. 6). A contract cannot remove either (art. 8). US:
  disassembling to understand functional elements has been held fair use when it is the only way to reach
  them and the final product contains none of the copied code (*Sega v. Accolade*, 1992; *Sony v.
  Connectix*, 2000); a licence that forbids reverse engineering may still be enforced as a contract
  (*Bowers v. Baystate*, 2003). So: decompile only a copy the user owns, for their own analysis, keep the
  results private, and let only the analysts' descriptions cross to the clean side. Observing the running
  game (the probe, the traces) is the least contested way to learn its behaviour: prefer a trace to a
  reading of the code whenever both would answer a question.
- **Copy protection is a separate law.** Getting around technical protection measures is unlawful in itself,
  even for a game you own and even when no copyright infringement follows: US DMCA 17 U.S.C. 1201 (with
  narrow exemptions that should not be relied on), EU InfoSoc Directive 2001/29/EC art. 6 and Software
  Directive art. 7(1)(c). Step 1 runs `scripts/protection_check.py` on the game folder and the pipeline
  stops on a finding (SafeDisc, SecuROM, StarForce, the Steam DRM wrapper, packers). Never remove, bypass,
  emulate or "unwrap" a protection; suggest a DRM-free release (GOG) of the same game instead. The probe
  patches only the oracle's process in memory, in a game that passed this gate.
- **Assets stay the owner's.** Graphics, sound, music, text, levels and the executable are never copied into
  the rewrite. It reads them from the user's own installed game at run time, including data compiled into
  the original executable (`cleanroom.md` section 5).
- **Trademarks.** The game's name and logos belong to its owner. A published rewrite may name the game it
  works with ("an engine for X; requires X"), but must not look official, use the logos, or suggest
  endorsement.

## Rules for every project
- Work only on games the user owns, from their own installer or install. Ask once at the start.
- Run `cleanroom.py init` at the start, before anyone reads decompiled code: the log shows the order of
  events. A session that read the analysis never becomes an implementer.
- Tools, format specs (in the project's own words), analysis write-ups that hold no code, verification
  reports (file names, sizes, hashes), the clean-room log and the specs can be committed to the private
  project repository.
- Anything derived from the game stays local and git-ignored: extracted archives, decoded assets, previews,
  decompiled pseudocode, names maps that embed game strings, Ghidra projects, the probe, the oracle's
  traces and saves, implementer workspaces. Keep the project's GitHub repository private; publishing even
  the tooling publicly is the user's decision, and derived game content is never published.
- Do not download game files, compilers, SDKs, patches, cracks or "no-CD" executables from unofficial
  sources. Compilers, SDKs and the installer are user-supplied or come from their vendors (ask first).
- Privacy: no absolute local paths, usernames or emails in committed reports/docs; replace them with
  `<GAME_DIR>`, `.` etc.

## .gitignore template (the analysis project)
```gitignore
# Game-derived content (copyrighted; regenerate locally from your own installer)
/extracted/
/decoded/
/previews/
/decompiled*/
/analysis/
/work/
/build/
# clean room: implementer workspaces (copies), the oracle's traces
/cleanroom/workspaces/
/rewrite/harness/oracle/
__pycache__/
*.pyc
.DS_Store
```
`pipeline.py init` writes these lines. The clean tree (default `rewrite/clean/`) lives in its own repository;
`cleanroom/log.jsonl` and `cleanroom/specs/` stay in the private project repository as the record.

## Commit hygiene
- Commit after each gate with the numbers in the message (files read, functions recovered, scenarios
  identical).
- Commit `cleanroom/log.jsonl` after every hand-over: git history is what protects the last line of the
  hash chain.
- If a commit message turns out wrong after pushing, say so rather than force-pushing a rewrite.
