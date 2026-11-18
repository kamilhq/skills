# Phase 4 - complete code recovery

## Why Ghidra's default analysis is not enough
Ghidra creates a function only where something calls it (or an export/entry points to it). In C++ games
built with MSVC 6 a large share of code is reached only indirectly:
- **virtual methods** - addresses stored in vtables in `.rdata`, never called directly;
- **callbacks** - window procs, thread procs, `qsort` comparators, script-command tables, passed by
  `push offset` / stored with `mov [x], offset` (Ghidra disassembles them as "found code from operand
  reference" but makes no function);
- **code behind computed jumps** - CRT x87 exception dispatch, static-initialiser thunks.
Typical result on a 2000s game exe: the recovery below adds about 15-20% to the functions Ghidra's default
analysis finds (most of them vtable targets, the rest orphan code); DLLs can gain 30-50%.

## The pipeline (`scripts/ghidra/run_recovery.sh <binary> <out_dir> [project_dir]`)
1. Import + full auto-analysis with **Aggressive Instruction Finder** enabled (`EnableAggressiveFinder.java`
   pre-script). On its own it often finds nothing extra, but it is cheap and helps some binaries.
2. `UnreferencedRegions.java` - only in a PE with relocations: an interval of `.text` between two anchors
   (relocation site, relocation target, export/entry) holding >= 32768 bytes that are not `00/CC/90` is not
   compiled code (code reaches a global, import, string, float constant or switch table every few hundred
   bytes; the longest relocation-free run in real code measured 7.2 KB, in a VS2010 game exe). Code in it reached by a
   branch or a fall-through from outside, transitively, is kept (the last C++ EH funclet before such a region,
   `mov eax, offset FuncInfo` / `jmp ___CxxFrameHandler`, has its relocation in the `mov`, so its `jmp` lies
   in the region); the rest is cleared and defined as a byte array so no later step decodes it (`UNREFREGION`
   lines with entropy).
3. `RecoverPointerTargets.java` - scan initialised non-executable memory for runs of >= 2 dwords pointing
   into code; create a function at each target not already inside a function or data. Targets inside an
   existing body are left alone (SEH funclets, switch cases). With relocations only relocated dwords count
   (UTF-16 text such as `4D 00 43 00` = 0x0043004D looks like a `.text` address); a target on `CC` never.
4. `CreateOrphanFunctions.java` - every disassembled instruction outside a function: a "head" is one that is
   referenced or that nothing falls through into; create functions there; repeat until none. Orphan
   alignment filler directly in front of code that already belongs to a function is cleared back to bytes
   (`padding_cleared=`), never made a function; so is a function made only of filler that nothing calls,
   jumps to or points to (a lone `int3` at the start of `.text` named `__break` by Function ID, referenced
   only by the header's BaseOfCode).
5. `DisassembleCodeGaps.java` - executable bytes that were never disassembled, in rounds until a round
   creates nothing. After a function is created in a gap, the rest of the same gap is processed at once
   (an import thunk table, `FF 25 <IAT slot>` x N, is one gap of N functions: one per round never finished
   within the 20-round cap), unless the new function ends in an unresolved computed jump other than
   `jmp [abs32]` - its switch cases follow and join it once the analysis between rounds reads the table.
   Per gap: skip alignment filler (`padLen()`: `CC`, `90`, `8B FF`, `66 90`, `lea r,[r+0]` in its 3/4/6/7-byte
   forms such as `8D 49 00`, `8D 64 24 00`, `8D 9B 00000000`, `8D A4 24 00000000`, and the `0F 1F` NOPs);
   if what follows is >= 2 code pointers it is an undecoded switch jump table; if an instruction *reads* it
   or it directly follows a pointer table (also tested from the table start, found by walking back over
   small byte values) it is a switch index table (`datatables_skipped=`); otherwise disassemble and create
   a function. Every fresh decode is checked first: if any flow (branch target or fall-through) leaves the
   image, enters a non-executable block, lands on bytes that do not decode or in the middle of an
   instruction, the bytes are data - the decode is cleared (`CODEGAPS_REJECT`, listed in
   `codegaps_failures.txt`) and nothing is created (DirectInput format tables decode as `call 0x017b16f0`,
   strings in a merged `.rdata` as `jb` into a string).
6. `CreateOrphanFunctions.java` again for code exposed by step 5.
7. `RemoveNonExecFunctions.java` - drop functions whose entry is in a non-executable block (Ghidra's own
   analysis can follow a data pointer into `.rdata` and disassemble embedded data) and clear them to bytes.
8. `RecoverAndExport.java <addresses.txt> <out_dir> [names.json]` - coverage report (multi-byte filler counts
   as padding), optional names, decompile every function to `functions/0x<addr>.c` with a header, write
   `index.json`.

Read the log lines `UNREFREGIONS`, `PTRTARGETS`, `ORPHANS`, `CODEGAPS`, `NONEXEC`, `COVERAGE`, `EXPORT`.

## Gate
- `ORPHANS ... orphan_instructions=0` on the last round.
- `EXPORT ... failed=0`, or every failure handled (below).
- Every entry in `coverage_gaps.txt` explained as data. Look at a sample with `scripts/peek.py` (bytes)
  and `scripts/ghidra/inspect.sh <project> <binary> <addr>` (what Ghidra has there, who references it):
  arrays of code addresses are jump/pointer tables; float constants and strings in `.text` happen too.
- Re-check against the PE itself, not Ghidra's own numbers: `python3 -I scripts/code_coverage_check.py
  <binary> <out_dir>` (reads `instructions.tsv`/`functions.tsv` written by `ExportListing.java`; exits 1
  unless every must-be-zero count is 0) classifies every function start
  as called / pointer (relocation target) / export / jump-only / **unreferenced**, and walks every gap byte
  by byte. Explained kinds, each with its evidence:
  - `filler`; `jump_table` (relocated code pointers; without relocations, dwords holding instruction starts
    in a run one of whose addresses an instruction uses, `jmp [ecx*4 + T]`); `index_bytes` (values below
    the preceding table's entry count);
  - `pe_metadata` - bytes the loader reads: data directories, import descriptors / lookup / address tables /
    hint-names / DLL names, export tables and names, debug data (in `.text` after `/MERGE:.rdata=.text`);
  - `string` - a printable NUL-terminated string at a relocation target (no relocations: at an instruction
    operand); `data_read` - from an address an instruction uses as a (relocated) memory operand (`movzx eax,
    byte [ecx + T]`) up to the next referenced address or branch target; zero bytes after either count with it;
  - `record_table` - an array of fixed-size records at a relocation target that only data points to, whose
    pointer slot (one dword per record, fixed offset) holds a relocated pointer to non-executable data or
    NULL in every record, >= 3 pointers, no branch into it (e.g. DirectInput `c_dfDIKeyboard`,
    `c_dfDIMouse`, `c_dfDIJoystick` from dinput8.lib, 16-byte `DIOBJECTDATAFORMAT` records with GUID pointers);
  - `unreferenced_region` - the `UnreferencedRegions.java` rule above, and no branch or fall-through into the
    gap (a tail-call `JMP` has flow `call` in `instructions.tsv` but does not fall through); entropy is
    reported: 7.99 for a removed protection layer's encrypted blob, ~5 for stale linker buffers;
  - `uninitialized` - past the section's file data (zero-filled by the loader).
  Anything else is `UNEXPLAINED`. Pointers into code are also explained when they hit `pe_metadata` (an IAT
  slot: `call [IAT]`), a `string` or a `record_table`. Without relocations there is no pointer evidence at
  all (`pointers` is empty) and no `unreferenced_region`; say so in the report. Targets:
  every direct call target is a function start; `unreferenced` functions are few and each explained
  (dead code after `ret`, tails behind `jmp eax`, code after a call to `abort`); no gap is `UNEXPLAINED`.
  A large unreferenced count, or unreferenced functions starting with filler bytes or with runs of small
  values (`04 04 04 ...`), means false functions, not recovered code.
- Every relocated pointer into `.text` should be a function start, inside a function body, the start of
  a jump/index table, or one of the data kinds above (`pointers` in the checker's summary; `UNEXPLAINED`
  must be 0).
- Calls Ghidra marks "Subroutine does not return" (the warning sits on the line *before* the call in the
  pseudocode): list the callees and confirm each really does not return (throw, exit, abort, terminate,
  invoke_watson, ExitProcess). A wrong one truncates every caller.

## Pitfalls that actually happened
- **Data in `.text` carved into functions** (a VC6 game with 13 PEs): its main exe carried a 1.95 MB
  encrypted blob (entropy 7.99, no relocation in or into it) left by a removed protection layer; a launcher
  exe and four renderer DLLs a ~64 KB stale linker buffer (source text, mangled names, MIDL strings, floats)
  at the end of `.text`; an audio DLL and a redistributable's setup exe had `.rdata`/`.idata` merged into
  `.text`; the main exe had DirectInput `c_dfDI*` format tables in `.text`. Before the fixes above, gap
  disassembly made 1,184 false functions in one renderer DLL (984 failed to decompile - not 3DNow!: Ghidra
  decodes `PFMUL`/`FEMMS` fine), 202 in the launcher, 54 in the main exe's blob; unrelocated UTF-16 dwords
  made 91 one-byte `int3` "functions" in the main exe; import thunk tables (133 thunks there) stayed
  unrecovered; two exes without `.reloc` crashed the checker.
- **False functions from filler and switch data** (a VS2010 game exe + a VS2019 `SDL2.dll`): before the
  fixes above, the pipeline passed its own gate while creating 571 false functions in SDL2.dll and 65 in
  the exe, and missing 6 real ones. Causes: MSVC loop-alignment filler inside functions (`8D 9B 00000000`,
  `8D 64 24 00`) not in the padding list, so the filler became a function running into its parent's loop;
  switch index byte tables after a resolved jump table disassembled as `add al, 4` (516 in SDL2); a gap
  list built once, so code after a gap's first new function was never visited; a D3D11 shader blob in
  `.rdata` made a function by Ghidra itself. `orphan_instructions=0` cannot catch any of these; only
  the reference check above does.
- **Jump tables decoded as code** (e.g. one game switch table decoded as 25 instructions): Ghidra
  sometimes flows into a switch table and disassembles it inside the function body, so no coverage metric
  sees it. `code_coverage_check.py` reports them (`jump_tables_decoded_as_code`); the containing
  function's pseudocode is wrong there; phase 5b found them because relocated dwords straddled
  instructions.
- **Immediate addresses are data references to code**: `push offset fn` (atexit destructors) and
  `mov eax, offset label; ret` (C++ catch continuations) create DATA references in Ghidra. A rule "data
  reference => table" skips real code; only READ references (`movzx r, byte [r + table]`) mark a table.
- **Nested transactions roll back everything**: in a GhidraScript, ending any sub-transaction with
  `commit=false` aborts the whole script's changes at the end - a "created 56 functions" log line with no
  effect on the export. Do not start your own transactions inside a script; validate before creating.
- **Gap metrics differ by definition**: "bytes outside functions" includes defined data; "undefined bytes"
  does not. Report which one you mean.
- **One Ghidra project, one writer**: parallel agents read the exported `.c`/`.tsv` files (and may run
  `inspect.sh`, which opens the project read-only); only one process at a time writes to a project.
- **Functions Ghidra cannot decompile** ("Overlapping input varnodes" etc.): save the assembly
  (its lines from `instructions.tsv`) as `0x<addr>.asm` beside the `.c` files with a comment saying
  why; identify it (often MSVC CRT x87 `pow`/`exp` helpers).
- **Functions in non-executable sections** (e.g. a D3D shader blob in `.rdata` reached through a data
  pointer) are removed by `RemoveNonExecFunctions.java`; they usually show up as decompile failures.
- **Thunks and externals** appear in the index (`KERNEL32.DLL::...`, `thunk_FUN_...`); they are not missing
  code.
- Any analysis written from an earlier, incomplete function set (function maps in docs) must be refreshed.

## Afterwards
Keep the Ghidra project (`project_dir`) - phase 5 applies names to it and re-exports. Commit the scripts and
the counts, not the decompiled output.
