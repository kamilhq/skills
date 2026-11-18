# Phase 5 - naming functions and documenting the program

## Prepare
```bash
python3 -I scripts/build_features.py decompiled_full Game.exe analysis/      # features, vtables, chunks
python3 -I scripts/peek.py Game.exe 0x727420 ...                             # full strings at addresses
```
Gather landmarks before spawning namers (each is a free, high-confidence anchor):
- CRT entry (PE entry point) and what it calls with hInstance/cmdline = `WinMain`; `sprintf`/`malloc` etc.
- The static CRT/library range (MSVC 6 LIBCMT usually sits together near the end of `.text`).
- Imported DLL functions by name (C++ exports from the game's own DLLs are especially valuable: they give
  class names and method signatures, and show how the exe calls them).
- Strings that carry class/method names (`CModoAplicacionJuego::Error cargando ...`), file extensions,
  script keywords, error messages.
- Addresses already explained in phase 3 docs (`grep -rn "0x4[0-9a-f]\{5\}" docs/`).
- vtables (`pointer_tables.json`): `installed_by` = constructors/destructors; slots = virtual methods of one
  class.

## CONTEXT.md template (copy to analysis/CONTEXT.md and fill in)
```markdown
# Naming <Game>.exe: shared context for every agent
Goal: give every function a meaningful, evidence-backed name.
## Inputs (read-only)
- decompiled_full/functions/0x<addr>.c, decompiled_full/index.json
- analysis/features.json  {addr,size,lines,calls,strings,apis,ncallers}; callers: grep FUN_<addr>
- analysis/chunk_NN.json, analysis/chunks.json
- analysis/pointer_tables.json  (vtables: installed_by = ctor/dtor, slots = virtual methods)
- python3 -I <skill>/scripts/peek.py <exe> 0x<VA>   (full string text; Ghidra labels are truncated)
- docs/formats/*.md, docs/code/*.md  (cite documented addresses)
## Landmarks
<entry, WinMain, CRT range, DLL imports, class-name strings, known subsystem addresses>
## Naming rules
<the rules below>
## Output format
<the JSON format below>
```

## Naming rules
- Use the developer's own identifiers verbatim when the binary evidences them (strings, exported C++ names,
  script keywords), including non-English ones; otherwise clear English.
- `Class::Method` for methods (class `C` + PascalCase, consistent across the program), PascalCase free
  functions with an optional subsystem prefix, upstream names for CRT/libraries (`malloc`, `_ftol`, zlib's
  `inflate`, ...).
- Identifier characters only `[A-Za-z_][A-Za-z0-9_]*` per part. Ghidra rejects `~`: destructors are
  `Class::Destructor` and `Class::ScalarDeletingDestructor`.
- Stubs: `nullsub_<addr>`, `Return0_<addr>`.
- Confidence: high = direct evidence (string, import, documented call site, unambiguous behaviour);
  medium = strong structural inference (vtable membership + behaviour); low = plausible guess. Only
  high/medium are applied as names; low stays in JSON and as a comment.
- Every function appears exactly once; `"name": null` when nothing is defensible.

## Output format (analysis/names/chunk_NN.json)
```json
{"chunk": "NN", "functions": [
  {"addr": "0x409180", "name": "WinMain", "class": null, "kind": "free", "subsystem": "app",
   "confidence": "high", "evidence": "called by CRT entry 0x6c2619 with hInstance and command line"}
]}
```
`kind`: method, ctor, dtor, free, crt, lib, thunk, stub. `subsystem`: short tag (app, render, terrain,
unit, ai, script, gui, net, sound, video, file, math, mem, crt, ...).

## Workflow
Namer per chunk -> skeptical auditor per chunk (validates the file; samples 20 entries incl. the most-called;
decides independently what each does before reading the evidence; fails on > 3 wrong or > 4
overconfident) -> fixer (max 2 rounds) -> reconcile pass over groups of ~7 chunks with the global map
(upgrade unnamed/low using callers/callees named elsewhere; one class name per vtable; resolve duplicate
names) -> synthesis (merge to `names_final.json`, `names_apply.json` with only high/medium, disambiguate
duplicates deterministically, write the architecture doc). Prompt shapes: `orchestration.md`.
Namers work leaves-first (callees before callers) and use address adjacency (one source file's functions are
contiguous) without forcing it.

## Apply names and re-export
```bash
"$GHIDRA_HOME/support/analyzeHeadless" <project_dir> <name> -process <binary> -noanalysis \
  -scriptPath <skill>/scripts/ghidra -postScript RecoverAndExport.java <empty.txt> decompiled_named analysis/names_apply.json
```
`RecoverAndExport.java` creates a class namespace for `Class::Method` names and reports failures in
`name_failures.txt` (duplicates, invalid characters). Re-run until zero failures.

## Architecture doc
`docs/code/<Game>.exe.md`: how the binary was recovered (counts), naming statistics per confidence/
subsystem/kind, architecture by subsystem (main loop and modes, rendering, world/map loading, entities,
combat, AI, scripting, GUI, networking, sound/video, file system, CRT/libraries) with key classes, methods and
addresses, a table of the ~60 most important functions, and open questions. Cite addresses; quote at most a
few lines of decompiled code.
