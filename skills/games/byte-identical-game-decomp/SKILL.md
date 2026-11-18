---
name: byte-identical-game-decomp
description: >
  Turn a PC game the user owns (GOG installer or installed folder; 32-bit Windows, MSVC-built, late-90s/2000s
  era) into fully decoded, documented, byte-identical form: extract the installer, decode every data/archive
  format into ordinary files that rebuild bit-for-bit, recover and decompile ALL code (exe + DLLs) with
  Ghidra, name the functions, rebuild the binaries byte-identically from assembly, and progressively match
  functions in C/C++ with the original compiler (e.g. Visual C++ 6.0). Use this skill whenever the user
  wants to reverse-engineer, decompile, "recreate", preserve, mod or port a game they own, extract or decode
  game assets/archives (.pak/.dat/custom formats), get "byte-identical" or "matching" decompilation, rebuild a
  game exe from source, or mentions a GOG installer, setup_*.exe, innoextract, Ghidra headless, reccmp or
  decomp projects like LEGO Island/isledecomp - even if they only ask for one phase.
compatibility: >
  macOS, Linux or Windows host with Python 3.9+ (stdlib only) and Ghidra 12.x (+ the JDK it needs); nothing
  else is installed. Phase 6 also needs the game's original compiler (user-supplied, licensed) and, on
  macOS/Linux, Wine to run it. Details: references/dependencies.md. Run scripts/check_deps.sh first.
---

# Byte-identical game decompilation

The end state the user wants: **give it the installer of a game they own, get back everything in readable,
editable form that rebuilds the game's files byte for byte** - data and code. Nothing derived from the game
is published; the tools need the user's own installer, the way console decomp projects need your own ROM.
The decompilation is private in every case. A rewrite others may download is possible only through the
game-rewrite skill's clean-room mode, where the people who write it never see this skill's code output
(`references/legal-and-repo.md`).

The work is a pipeline of phases. Each phase has a hard acceptance gate (SHA-256 identity or full coverage),
so a later phase never builds on an unverified earlier one. Phases 3, 5 and 6 are large; they are designed
to be split across many subagents (see "Orchestration").

| # | Phase | Output | Gate |
|---|---|---|---|
| 0 | Ownership, legal, repo setup | mode (private / publishable), private repo, `.gitignore` for game-derived dirs | user confirms they own the game and picks the mode |
| 1 | Installer intake | game tree + SHA-256 manifest + protection report | extracted tree identical to a real install; no copy protection or packer |
| 2 | Inventory | census of formats, archives, XOR layers, binaries | every file classified |
| 3 | Data decoding | one decoder module per format group, decoded tree, previews | 100% files rebuild SHA-256-identical; opaque bytes reported |
| 4 | Code recovery | complete function set for exe + every DLL, decompiled | 0 orphan instructions; only data left outside functions |
| 5 | Naming + docs | names map, architecture docs, readable re-export | audited sample error rate under threshold |
| 5b | Reassembly | assembly + PE layout that rebuild each binary | SHA-256-identical exe/DLLs; pinned-bytes count reported |
| 6 | Matching decompilation | C/C++ per function, compiled with the original compiler | functions match; whole build SHA-256-identical |

Start every session with `sh scripts/check_deps.sh` (all scripts are in this skill's directory) and read
`references/dependencies.md` for anything missing. The pipeline is Python stdlib + Ghidra: do not add other
tools (no innoextract, ffmpeg, objdump, NASM, pip packages) - the skill's scripts cover those jobs. Do not
install proprietary software for the user, and never download a compiler or game files from unofficial
sources: the original compiler and the game installer are user-supplied.

## Running the pipeline
`scripts/pipeline.py` runs every phase on a project from one config file, `decomp.json` (game folder,
archives, format modules, binaries, compiler, how to start the game):
`init`, `intake`, `inventory`, `archives`, `decode`, `recover`, `features`, `names`, `reassemble`,
`skeleton`, `match`, `build`, `verify`, `status`. Each command checks its phase's gate and prints a JSON
summary; `status` shows every gate in one table. The config format and the commands are in
`references/pipeline.md`. The sections below explain what each phase does and how to judge its results;
the subagent work (decoders, naming, matching) is still yours to run.

## Phase 0 - ownership, legal, repo

Ask the user to confirm they own the game and to provide the installer path (GOG `setup_<game>_<ver>.exe`
plus any `.bin` parts beside it) or the installed folder. Explain once: the decoders/tools are theirs to keep
and share; anything derived from the game (extracted files, decoded assets, decompiled code, previews,
names maps containing game strings) stays local and out of git. Ask which mode the project is in and record
it as `"mode"` in `decomp.json`: **private** (default: everything stays on the user's machine, a later
rewrite may be translated from the matched code) or **publishable** (the user wants to release a rewrite
some day: it must then be written clean-room, by agents that never read the decompilation; plan that from
the start, see game-rewrite `references/cleanroom.md`). `references/legal-and-repo.md` has the reasons
(copyright covers code and assets, not behaviour or formats; decompiling is for the user's own analysis;
circumventing copy protection is unlawful on its own) - summarise them, and say it is not legal advice. Set up `.gitignore` before the first commit
(template in `references/legal-and-repo.md`) and keep any GitHub repo private unless the user decides
otherwise. Never put the user's name, paths or email into commits beyond what git config already holds;
replace absolute local paths in committed reports with placeholders like `<GAME_DIR>`.

## Phase 1 - installer intake

`python3 -I scripts/intake.py extract <setup.exe> <out>` unpacks the installer with the skill's own
pure-Python Inno Setup reader (`scripts/inno.py`; slices `setup_x-N.bin`, every file's stored checksum
verified). Then `intake.py verify-hashdb <game_dir>` checks every file against GOG's own MD5 list
(`goggame-<id>.hashdb`) - the gate - and `intake.py manifest` writes the SHA-256 manifest to commit.
`scripts/protection_check.py <game_dir>` is the second gate: on any copy protection (SafeDisc, SecuROM,
StarForce, the Steam DRM wrapper, ...) or packer, stop and tell the user - never remove, bypass or unpack
one; a heuristic warning needs the user's decision (`references/intake.md`). An
already installed folder works too (copy it; same gate). Details, GOG quirks (`{app}` vs `{tmp}` files,
installer-only folders, unsupported RAR-based `.bin` parts) are in `references/intake.md`.

## Phase 2 - inventory

`python3 -I scripts/inventory.py <game_dir>` lists every extension with sizes and detected format, flags
files that are a known format under a whole-file single-byte XOR (for example a `.pak` that is a ZIP XORed
with one constant byte), and counts members inside ZIP-based archives. Then:
- extract all archives into `extracted/` (verify each member's CRC/hash; refuse path traversal),
- build the full format list (archive members + loose files), grouped by extension and magic,
- list every PE binary (exe, dll, also `.asi`/`.flt`/`.drv` plugins) for phase 4,
- grep the exe's strings for file extensions to find formats loaded by name.
Group formats into modules of related work (e.g. "terrain grids", "map objects", "text/scripts",
"standard images", "standard audio", "archives themselves").

## Phase 3 - data decoding (byte-identical)

Every format gets a Python module `tools/formats/fmt_<module>.py` with `EXTS`, `decode_to_dir(data,
outdir)` and `encode_from_dir(outdir)`, tested by `scripts/verify.py` (copy it and `scripts/pngio.py` into
the project). The contract, why it is shaped this way, and the hard-won lessons are in
`references/data-decoding.md`; read it before writing or delegating any decoder. The essentials:

- **Decoded means usable**: JSON with named fields, PNG for pixels, WAV for PCM, UTF-8 text, OBJ for meshes -
  not hex dumps. Rebuild uses only the decoded folder.
- **Byte identity is checked by SHA-256 for every file**, never by sampling.
- **Honest opaque bytes**: bytes kept without understanding (uninitialised exporter memory, unknown fields)
  are stored as named fields and counted; known codecs kept verbatim (DXT blocks, Vorbis/Bink packets,
  ADPCM) are listed separately; where the kept stream is not a standard file anyone can open, a stdlib
  preview decoder makes one (DXT -> PNG, ADPCM -> WAV).
- **Archives last-but-not-least**: rebuilding the archive files themselves usually means reproducing the
  original compressor bit-exactly (this can mean porting a 20-year-old deflate implementation).
- Use the game's own loader code (phase 4 decompile, `scripts/ghidra/inspect.sh` on demand) to name fields; cite
  function addresses in each module's spec `docs/formats/<module>.md`.

Delegate with the builder -> skeptic -> fix loop in `references/orchestration.md`; the skeptic re-runs the
harness, reads the code for leaks (encode reading the source file, whole-file blobs, under-reported opaque
bytes), mutation-tests (edit one decoded value, confirm the rebuilt file changes exactly there) and looks at
decoded images. Finish with a completeness critic that proves every file in the game is covered.

## Phase 4 - complete code recovery

Ghidra's default analysis leaves out functions that are reached only through vtables, callback tables or
computed jumps - about 15% of all functions in a typical 2000s game exe, and up to a third of a DLL's.
`scripts/ghidra/run_recovery.sh <binary> <out_dir>` runs the full pipeline for one exe/dll:
aggressive instruction finder, unreferenced relocation-free regions marked as data, pointer-table targets,
orphan code, never-disassembled code gaps (in rounds, leaving alignment filler and switch index tables alone,
rejecting decodes whose flow leaves the image or splits instructions), removal of functions Ghidra made in
non-executable sections, then a coverage report and a decompile of every function to `<out_dir>/functions/0x<addr>.c` +
`index.json`. Gate: `ORPHANS ... orphan_instructions=0`, and every remaining gap in `coverage_gaps.txt` is
shown to be data (switch jump tables, PE structures, referenced strings and tables, unreferenced regions) -
and `scripts/code_coverage_check.py` agrees from the PE's relocations, directories and call targets: unreferenced functions few and explained, no `UNEXPLAINED` gap. The
orphan count alone passed while 571 false functions were present in one DLL. Why each step exists, how to check the residue, and what to do with
functions Ghidra cannot decompile (save their assembly; often CRT x87 helpers): `references/code-recovery.md`.
Re-run any earlier analysis docs that were based on an incomplete function set.

For questions the export does not answer, `sh scripts/ghidra/inspect.sh <project_dir> <binary> <addr>...`
asks the recovered Ghidra project read-only (code unit, containing function, references). Parallel
subagents grep the exported `.c` and `.tsv` files; never let two processes write to one Ghidra project.

## Phase 5 - naming and documentation

`python3 -I scripts/build_features.py <out_dir> <binary> analysis/` writes per-function features, pointer
tables (vtables with the constructors that install them) and address-contiguous chunks of ~8k pseudocode
lines. Copy `references/naming.md`'s CONTEXT template to `analysis/CONTEXT.md`, fill in the game's
landmarks (entry/WinMain, CRT range, DLL import names, documented addresses from phase 3 docs, class names
found in strings), then run the namer -> auditor -> fix workflow per chunk, a cross-chunk reconcile pass,
and a synthesis that writes `analysis/names_final.json`, `analysis/names_apply.json` and an architecture doc.
Apply names by re-running `RecoverAndExport.java` with the names file (it creates C++ namespaces for
`Class::Method`). Only high/medium-confidence names are applied; low ones stay as comments.

## Phase 5b - byte-identical reassembly

Before any C++ matching, make the binaries themselves rebuildable from text: PE headers/sections/imports/
relocations/resources as JSON, each function as an assembly text file (Ghidra's syntax from
`instructions.tsv`, names from phase 5), data sections as labelled data, Ghidra's assembler (it lists every
encoding of an instruction, so the original's is chosen) and a Python layout/PE writer. Gate:
SHA-256-identical exe and DLLs (`scripts/reassemble.py split|verify|editcheck`). Instructions whose
encoding needs an explicit choice (`{enc:N}`) or that the assembler cannot produce (`db` bytes) are counted -
the code-side analogue of opaque bytes. The design, label/relocation strategy and
verification are in `references/reassembly.md`. This is the safety net for phase 6: unmatched functions
simply stay in assembly and the build stays byte-identical.

## Phase 6 - matching decompilation

Rewrite functions in C/C++ until the original compiler produces the original bytes, swapping each matched
function in for its assembly. Identify the exact compiler build from the Rich header and codegen, install
the user's matching compiler (under Wine on macOS/Linux), discover compiler flags, then run a per-function
loop with `scripts/objcmp.py` (annotation comments `// FUNCTION: 0x<addr>` map source functions to original
addresses; it compares the compiler's COFF `.obj` bytes with the original, relocations masked, and reports
match %).
Everything about toolchain matching, flags, link order, CRT/library code (link it, don't rewrite it), the
per-function agent loop and the final whole-binary identity check is in `references/matching-decomp.md`.
Set expectations honestly: thousands of functions take a long time, some functions resist matching for
register-allocation reasons, and those stay in assembly without breaking byte identity.

## JavaScript ports (optional, parity-tested)
Every Python script also exists as a Node.js port in `scripts/js/` (same name, `.mjs`; same command line,
output and files; Node >= 20 built-ins only, no npm). Use either; they are kept in step and checked against
each other by `node scripts/js/parity/run_all.mjs` (run it after changing either side). The Ghidra scripts
(`ghidra/*.java`) and shell wrappers stay as they are. `scripts/js/README.md` has the porting rules, the
helper libraries and the known differences (tracebacks, help text width, internal zlib handle). When you
add or change a Python script, port the change and its parity test in the same commit.

## Orchestration and honesty

Large phases run as workflows of subagents (builder -> independent skeptic -> fix, max 2 rounds; then a
completeness critic). `references/orchestration.md` has the prompt shapes, the schemas, and the mistakes
that actually happened (passing a placeholder string instead of the real chunk list as workflow args;
nested Ghidra transactions silently rolling back; trusting a reported count without re-running it).

Report progress with numbers that a script produced: files identical / total, opaque bytes, functions
recovered, orphan instructions, names per confidence, functions matched. When something is inferred rather
than shown, say so. When a step is not done, say so.

## Reference files

| File | Read when |
|---|---|
| `references/pipeline.md` | running phases with `pipeline.py`; writing a project's `decomp.json` |
| `references/dependencies.md` | setting up a machine; check_deps reports something missing |
| `references/intake.md` | phase 1; installer will not extract; starting from an installed folder |
| `references/data-decoding.md` | writing, delegating or auditing any decoder |
| `references/code-recovery.md` | phase 4; interpreting coverage gaps; Ghidra pitfalls |
| `references/naming.md` | phase 5; CONTEXT template; naming rules; applying names |
| `references/reassembly.md` | phase 5b |
| `references/matching-decomp.md` | phase 6; compiler, flags, objcmp.py |
| `references/orchestration.md` | spawning workflows/subagents for any phase |
| `references/legal-and-repo.md` | phase 0: the two modes, the legal reasons behind every rule, copy protection, what may be committed, privacy |

## Scripts

| Script | Phase | Purpose |
|---|---|---|
| `scripts/check_deps.sh` | all | what is installed, per phase, with install hints |
| `scripts/pipeline.py` | all | runs every phase from `decomp.json`, with its gate; `status` table (references/pipeline.md) |
| `scripts/formats/` | 3 | generic decoders to copy into a project: PNG, WAV, ZIP (+ 7-Zip deflate port), text template (its README) |
| `scripts/inno.py` | 1 | pure-Python Inno Setup (GOG installer) reader: info, list, extract |
| `scripts/intake.py` | 1 | extraction via inno.py, GOG hashdb gate, SHA-256 manifests, tree comparison |
| `scripts/protection_check.py` | 1 | copy-protection and packer gate: file names, PE sections, imports, signatures, entry-point heuristics |
| `scripts/inventory.py` | 2 | format census, magic and single-byte-XOR detection, archive member counts |
| `scripts/verify.py` | 3 | the round-trip harness for every decoder module |
| `scripts/pngio.py` | 3 | stdlib PNG writer/reader for decoders |
| `scripts/ghidra/run_recovery.sh` (+ 8 `.java`) | 4 | complete function recovery, decompile and instruction listing of one exe/dll |
| `scripts/code_coverage_check.py` | 4 | independent check of a recovery from the PE: reachability of every function, every code pointer, gap classification |
| `scripts/ghidra/inspect.sh` (+ `Inspect.java`) | 4-6 | read-only questions to a recovered Ghidra project |
| `scripts/build_features.py` | 5 | features, vtables/pointer tables, naming chunks |
| `scripts/peek.py` | 5 | full string/bytes at a virtual address |
| `scripts/reassemble.py` | 5b | split a PE into assembly text + layout, build it back byte-identically, verify, editcheck |
| `scripts/ghidra/assemble.sh` (+ `AssembleLines.java`) | 5b | Ghidra's assembler over a batch of lines, all encodings, MSVC choice rule |
| `scripts/rich_header.py` | 6 | compiler/linker build fingerprints |
| `scripts/phase6_skeleton.py` | 6 | annotated source skeleton (STUB per own function, unit guesses) from phase-5 names |
| `scripts/msvc.sh` | 6 | run the user's cl/link under Wine with INCLUDE/LIB/PATH set (install: matching-decomp.md 1b) |
| `scripts/hybrid_link.py` | 6 | rebuild the binary with every matched function's code taken from its .obj (map / link / verify); `map --all` adds edited functions |
| `scripts/relink.py` | 6 | link the binary with the original link.exe (imports, passes, resources, .reloc), then counted post-link facts (prepare / link / finish); `--free` builds edited source with moving code |
| `scripts/objcmp.py` | 6 | COFF `.obj` vs original function comparison, annotation report, COFF writer |
| `scripts/objcmp_selftest.py` | 6 | self-test of objcmp.py on objects synthesised from a PE's own functions |
