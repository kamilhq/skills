# Ownership, legal boundaries and repository rules

This is the legal frame the skills work in, not legal advice. Laws differ by country and the law is
unsettled at the edges; tell the user so once, and point them to a lawyer before anything commercial.

## The two modes
Every project is in one of two modes. Ask once, in phase 0, and record it in `decomp.json`
(`"mode": "private"` or `"publishable"`); the default is private.

| | Private (default) | Publishable |
|---|---|---|
| Purpose | study, preservation, modding for yourself, a rewrite you play yourself | a rewrite others may download |
| Who reads the decompilation | everyone working on the project | only analysts (game-rewrite `references/cleanroom.md`) |
| How the rewrite is written | from the matched C++ and the pseudocode (translation) | from written behaviour specs, format docs and traces (clean room) |
| What may leave the machine | tools, format specs in your own words, hashes, reports | the above + the clean-room rewrite, after `release_check.py` passes |
| What never leaves | everything derived from the game (below) | the same |

The decompilation itself (phases 3-6: decoded assets, pseudocode, names maps, reassembly, matched C++) is
always private, in both modes. A rewrite translated from it is a derivative work of the original code
however much it is cleaned up or ported to another language, so it is private too.

## Why each rule exists
- **Copyright covers expression, not function.** The original's code (as written, and in translation) and its
  assets are protected. Its behaviour, rules, algorithms as ideas, and file formats are not: US 17 U.S.C.
  102(b); in the EU, the Software Directive 2009/24/EC recital 11 and *SAS Institute v World Programming*
  (CJEU C-406/10, 2012: functionality, programming languages and data file formats are not protected).
  A rewrite that matches behaviour and reads the original data formats can be the rewriter's own work; one
  that copies the code's expression cannot.
- **Studying the program.** EU: whoever may use a program may observe, study and test it while running it to
  find its underlying ideas (Directive art. 5(3)); decompiling is allowed only to make an independently
  created program interoperate, limited to what is needed, and the results may not be used to write a
  program substantially similar in its expression (art. 6). A contract cannot remove either (art. 8). US:
  disassembling to understand functional elements has been held fair use when it is the only way to reach
  them and the final product contains none of the copied code (*Sega v. Accolade*, 1992; *Sony v.
  Connectix*, 2000); a licence that forbids reverse engineering may still be enforced as a contract
  (*Bowers v. Baystate*, 2003). So: decompile only a copy the user owns, for their own analysis, and keep the
  results private; never let decompiled expression flow into something published.
- **Copy protection is a separate law.** Getting around technical protection measures is unlawful in itself,
  even for a game you own and even when no copyright infringement follows: US DMCA 17 U.S.C. 1201 (with
  narrow exemptions that should not be relied on), EU InfoSoc Directive 2001/29/EC art. 6 and Software
  Directive art. 7(1)(c). Phase 1 runs `scripts/protection_check.py` on the game folder and the pipeline
  stops on a finding (SafeDisc, SecuROM, StarForce, the Steam DRM wrapper, packers). Never remove, bypass,
  emulate or "unwrap" a protection; suggest a DRM-free release (GOG) of the same game instead.
- **Assets stay the owner's.** Graphics, sound, music, text, levels and the executable are never copied into
  anything published. A rewrite reads them from the user's own installed game at run time.
- **Trademarks.** The game's name and logos belong to its owner. A published rewrite may name the game it
  works with ("an engine for X; requires X"), but must not look official, use the logos, or suggest
  endorsement.

## Rules for every project
- Work only on games the user owns, from their own installer or install. Ask once at the start.
- Ask for the mode (above) at the start. Switching from private to publishable later is possible, but the
  people (or agent sessions) who read the decompilation cannot become implementers of the clean room.
- Tools, format specs (in your own words, with addresses), analysis write-ups, verification reports (file
  names, sizes, hashes) are the project's own work and can be committed.
- Anything derived from the game stays local and git-ignored: extracted archives, decoded assets, previews,
  decompiled pseudocode, assembly from phase 5b, matched C++ from phase 6, names maps that embed game
  strings, Ghidra projects, the oracle, traces and saves, private rewrites. Keep a GitHub repo private;
  publishing even the tooling publicly is the user's decision, and derived game content is never published.
- Do not download game files, compilers, SDKs, patches, cracks or "no-CD" executables from unofficial
  sources. The original compiler, the era's SDKs and the installer are user-supplied.
- Privacy: no absolute local paths, usernames or emails in committed reports/docs; replace them with
  `<GAME_DIR>`, `.` etc. Scratch paths in docs must be replaced by repo-relative tool paths.

## .gitignore template
```gitignore
# Game-derived content (copyrighted; regenerate locally from your own installer)
/extracted/
/decoded/
/previews/
/decompiled*/
/reassembled/
/src_matched/
/analysis/
/work/
# private rewrites, oracle, traces (game-rewrite skill)
/rewrite/cpp/
/rewrite/rust/
/rewrite/rust_wave/
/rewrite/harness/oracle/
/build/
# clean-room workspaces (copies of specs and traces; the log and the specs themselves are committed)
/cleanroom/workspaces/
# verification scratch
/verify_out/
/verify_reports/
__pycache__/
*.pyc
.DS_Store
```
In publishable mode the clean-room tree (default `rewrite/clean/`) usually lives in its own repository;
`cleanroom/log.jsonl` and `cleanroom/specs/` stay in the private project repository as the record.

## Commit hygiene
- Commit after each phase gate with the numbers in the message (files identical, functions recovered).
- In publishable mode, commit `cleanroom/log.jsonl` after every hand-over: git history is what protects the
  last line of the hash chain.
- If a commit message turns out wrong after pushing, say so rather than force-pushing a rewrite.
