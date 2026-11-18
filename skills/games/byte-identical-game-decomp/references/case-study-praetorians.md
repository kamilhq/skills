# Case study: Praetorians (Pyro Studios, 2003, GOG)

Repository: the project this skill was extracted from (`tools/`, `docs/formats/`, `docs/code/`, `reports/`).

## Install
- 36 files, ~520 MB: `Praetorians.exe` (3.5 MB, PE32, linker 6.00, no RTTI, no symbols), 6 DLLs
  (`DLLSonido` sound engine, `DLLDShow` video, `DATA/ZipDll` archive reader, `binkw32` RAD Bink 1.5s,
  `Ogg`/`Vorbis` libogg/libvorbis 1.0), 15 `.pak` archives, 7 `.bik` videos, GOG metadata, PDF manual.
- GOG `goggame-1207658795.*` files, compatibility flag `16BitColor`.

## Data (phase 3): 4,463 files, 11 modules, 0 failures
| Module | Files | Opaque bytes |
|---|---|---|
| pak (15 archives, 8 are ZIP ^ 0xAB) | 15 | 44 (deflate window tails) |
| ptx textures | 1,572 | 0 |
| pba models | 848 | 42,112 (stale exporter memory in name slots) |
| audio wav/ogg | 733 | 0 |
| text dat/gui/mis/mss/trg/ogi/h/txt | 486 | 0 |
| images tga/dds/bmp | 342 | 320 (BMP row padding) |
| terrain pve/mlg/zac/h2o/esq/fog | 203 | 0 |
| mapobj mob/pia/pra/mur/ola | 117 | 0 |
| uibin fnb/ctg/ldr | 93 | 4 |
| pte map textures | 41 | 0 |
| misc bik/ico/zip/hashdb/... | 13 | 16 |
Quirks worth expecting in other games: whole-file XOR with detection by a failed EOCD scan
(`ZipDll` `FUN_10002640` + key set at `0x100011ea`); archives packed by two Info-ZIP-family packers needing
a bit-exact deflate port with an undocumented lazy-match rule; UTF-16LE+BOM string tables beside cp1252
scripts; exporter memory garbage in fixed name slots; a hand-written Bink audio decoder whose scale was 2x
off; Vorbis music mastered above full scale (float previews avoid clipping).

## Code (phase 4)
| Binary | Ghidra default | After recovery |
|---|---|---|
| Praetorians.exe | 11,174 | 13,124 |
| DLLDShow.dll | 564 | 838 |
| binkw32.dll | 415 | 635 (1 CRT pow helper undecompilable, kept as asm) |
| ZipDll.dll | 353 | 453 |
| DLLSonido.dll | 422 | 447 |
| Vorbis.dll | 200 | 223 |
| Ogg.dll | 150 | 158 (171 with the code-gap pass) |
Residue in the exe: ~15 KB outside functions = 152 undecoded switch jump tables + pointer tables.

## Toolchain fingerprints (for phase 6)
Rich headers (product id, build, count):
- Praetorians.exe: (12,7291,5) (11,8047,1) (10,8047,172) (14,7299,34) (4,8447,4) (29,9178,1) (25,9210,2)
- DLLSonido.dll: (12,7291,4) (14,7299,1) (10,8047,4) (4,8047,2) ... (19,8034,8) (1,0,144)
- ZipDll.dll: (10,8047,97) (10,8966,12) (11,8966,3) (4,8447,1) ...
Linker 6.00 build 8447 everywhere; compiler build 8966 appears in ZipDll (VC6 SP5 by public tables -
inferred); 8047 objects dominate - determine whether they are the CRT's or the game's before choosing a
service pack.

## Lessons
- Verify "complete" claims: the first decompile looked complete and was missing 15% of functions.
- Keep every pass measurable and re-runnable; the harness and reports made each claim checkable later.
