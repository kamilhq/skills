# Phase 5b - rebuild each binary byte-identically from assembly

Status: built and verified on VVVVVV 2.4.4 (VVVVVV.exe and SDL2.dll both rebuild SHA-256-identical from
text, and pass the editability check). Tools: Python (stdlib) + Ghidra only:
`scripts/reassemble.py` (split / build / verify / editcheck), `scripts/ghidra/AssembleLines.java` +
`scripts/ghidra/assemble.sh` (Ghidra's assembler in a throw-away project holding a 16-byte dummy program).

```bash
python3 -I scripts/reassemble.py split  <binary> <decompiled_dir> reassembled/<name> [--names analysis/<name>/names_apply.json]
python3 -I scripts/reassemble.py verify <binary> reassembled/<name>          # gate: build from text, SHA-256
python3 -I scripts/reassemble.py editcheck <binary> reassembled/<name> <decompiled_dir>
```
Levels 0/1 below are implemented in a reduced form: headers and non-code sections are kept as bytes
(`raw/`), with every pointer into `.text` replaced by a label fixup and `.reloc` regenerated from label
references; imports/resources/exports are not decoded to JSON yet.

## What was learned building it (VVVVVV.exe 278,710 instructions, SDL2.dll 309,403)
- Ghidra re-assembles its own instruction text for every instruction (0 failures). Encoding choice: Ghidra
  returns all encodings; a fixed rule (fewest prefixes, shortest, MSVC's reg,r/m direction 8B/03/2B/3B...,
  REP before REPNE, then bytes) picks the original for 99.8%. The rest carry `{enc:N}` (exe 473, dll 613).
  Ambiguous renderings exist (`FMUL ST1` is D8 C9 or DC C9; `MOVSD.REP` is F2 or F3 A5).
- Ghidra cannot assemble relative branches at a dummy address, so Python encodes direct jmp/jcc/call itself.
  Branch SIZE must follow MSVC: start every branch long and shrink while the short form reaches (pessimistic
  relaxation). Start-short relaxation gives a smaller, different layout. The same `relax()` runs in split
  (to predict) and build; only mispredictions carry `{enc:1}` (long) / `{enc:2}` (short): exe 143, dll 105.
- Non-branch x86-32 encodings do not depend on the address, so assembled bytes are cached by text; labels
  are sized with a provisional 32-bit value first (lengths never depend on an absolute label's value).
- Jump tables Ghidra decoded as instructions (runs of >= 2 relocated code pointers overlapping instructions;
  VVVVVV: one switch table in a game function) are emitted as `dd` data: 25 instructions in the exe. A table
  whose unused entry 0 overlaps the previous, genuine instruction (CRT `memcpy`: `JMP [EAX*4 + table]` with
  the table base inside the preceding JMP) is referenced as `L_next-0x4` (label minus offset), so it still
  moves; do not turn that instruction into data.
- Emit `.text` only up to its virtual size; the zero file-alignment padding is added by build, otherwise
  any edit overflows the section.
- `.reloc` regenerates exactly with: pages ascending, offsets ascending, one ABSOLUTE pad entry when odd.

Gate numbers (cold, no cache): both binaries IDENTICAL in about 1.7 minutes each. Pins: exe `{enc}` 473 +
branch sizes 143 + 1 instruction (2 bytes) as `db`; dll 613 + 105 + 0. Editability: inserting a NOP after the
first instruction moved all 32,535 / 20,487 relocated pointers, every `.reloc` entry and all 50,760 /
37,124 direct branches consistently.

The rest of this file is the original design; where it says NASM, read Ghidra's assembler as above. Build it in this order and verify each level
before the next. The harness pattern is the same as data decoding: `decode_to_dir(pe_bytes, outdir)` /
`encode_from_dir(outdir)`, checked by SHA-256 with `scripts/verify.py` (module `fmt_pe`, EXTS
`['.exe', '.dll']`).

## Level 0 - structural PE round trip (no disassembly)
Decode: DOS header + stub, Rich header (decoded entries + XOR key; it is a checksum-keyed structure, so
regenerate it from entries and verify), PE/optional headers (every field named), data directories, section
table, each section's raw bytes as a file, overlay. Encode: write headers back, recompute what is derivable
(SizeOfImage, section alignment padding, optional-header checksum if it was set) and keep the rest.
Gate: all 7 Praetorians binaries identical. This is quick and isolates header handling from code.

## Level 1 - sections as structured data
- `.idata`/import directory -> JSON (DLLs, functions, hint/name, ordinals, IAT/ILT RVAs); regenerate the bytes.
- `.reloc` -> JSON list of fixup RVAs by page; regenerate. Later levels derive it from labels.
- `.rsrc` -> resource tree JSON + payload files (icons/dialogs/version info decoded where standard).
- exports (DLLs) -> JSON.
- `.rdata`/`.data` -> data with known structures typed (vtables as pointer arrays, strings, floats, jump
  tables) and the rest as byte runs.
Gate: identical again.

## Level 2 - code as assembly text, one file per function (no external assembler)
Source text comes from Ghidra's own listing (`instructions.tsv` from `ExportListing.java`, already written
by phase 4), so function boundaries match phase 4 exactly. For every function (plus inter-function filler
and the jump/index tables found in phase 4), emit one text file:
```
; FUNCTION 0x409180 WinMain  (size 2090)
WinMain:
    PUSH EBP
    MOV EBP,ESP
    ...
.L_409a10:                     ; jump target
    CALL CUnit::Update
```
- **Labels instead of addresses**: every relocated operand (from `.reloc`) and every branch target becomes a
  label (`CALL CUnit::Update`, `MOV EAX,dword ptr [g_pGame]`, `dd WinMain`), so moving code later just
  works. Non-relocated immediates stay numeric. Jump tables stay label arrays (`dd .case0, .case1`) inside
  their function's file.
- **Assembler = Ghidra.** A headless GhidraScript (to be written: `AssembleFunctions.java`) assembles each
  line with Ghidra's SLEIGH assembler (`ghidra.app.plugin.assembler.Assemblers`, `resolveLine` /
  `resolveTree`). Unlike a conventional assembler, this returns *every* encoding of an instruction, so the
  script keeps the one equal to the original bytes. If several encodings exist and Ghidra's default is not
  the original's, the line carries a short `{enc:N}` choice. If no encoding matches, or the assembler
  cannot parse the line, it is emitted as `db` bytes with the instruction text in a comment. Count
  `{enc:N}` lines and `db` lines/bytes per function and in total - the code analogue of opaque bytes - and
  drive them down.
- **Layout and linking in Python.** Section contents are laid out in address order with the original
  filler bytes (CC/90 fills differ), labels resolved in two passes (sizes are fixed because every
  instruction's encoding is fixed), `.reloc` regenerated from the label references, and the PE written by
  the level-0/1 writer. For phase 6's hybrid build, the same bytes and relocations are written as COFF
  objects (`objcmp.py`'s `write_obj`) so `link.exe` can mix them with compiled C++.
- Assembling the whole `.text` through Ghidra takes a while (hundreds of thousands of lines). Cache per
  function by a hash of its text and re-assemble only edited functions.
Gate: `.text` identical, then the whole PE identical with `.reloc` regenerated from label references.

## Level 3 - editability check
Prove the source is really editable: insert a NOP into a function early in `.text`, rebuild, run the game
under Wine and confirm it starts (or at least that relocations, jump tables and vtables all moved
consistently - a static check over every label). Then revert. This catches numeric addresses that should
have been labels.

## Notes
- Keep jump tables as label arrays (`dd .case0, .case1`) inside their function's file.
- SEH: `__except_handler3` scope tables in `.rdata` reference filter/handler funclets - make them labels.
- Data in `.text` (floats, strings) is rare in MSVC output but happens in hand-written CRT asm; keep as `db`.
- The output of this phase is still derived from the game: keep it out of git like the decompile.
