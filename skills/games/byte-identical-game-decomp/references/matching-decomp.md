# Phase 6 - matching decompilation with the original compiler

Goal: C/C++ source that the original compiler turns into the original bytes, function by function, until the
whole binary rebuilds identically. Precedent: the LEGO Island decomp (isledecomp, MSVC 4.2) and its tool
reccmp; this skill uses its own stdlib comparer `scripts/objcmp.py` instead (same annotation style, no
Python 3.11/pip/cvdump). Status in the reference project: not started; this is the plan. Tools: the user's
compiler (+ Wine on macOS/Linux), Python stdlib, Ghidra - nothing else.

## 1. Identify the toolchain exactly
- **Rich header** (between the DOS stub and `PE\0\0`, XOR-keyed): list of (product id, build, count). Decode
  it with `python3 -I scripts/rich_header.py <exe> <dlls...>`. Product ids map to tools (C compiler, C++ compiler, MASM, linker, import library, resource
  converter); builds identify versions. Praetorians.exe: linker 6.00 build 8447; compiler objects at build
  8047 (172 objects) and MASM 6.13 build 7299. Map builds to service packs with public Rich ID tables, and
  label that mapping as inferred until the user's `cl.exe` banner (`cl` with no args prints
  `Version 12.00.<build>`) confirms the same build.
- Static libraries carry their own Rich entries (LIBCMT objects compiled by Microsoft); a build seen only
  in large counts may be the CRT's, not the game's. Compare with the DLLs built by the same team (they
  show the developers' own compiler build when they link fewer libraries).
- The user must supply the matching compiler: Visual C++ 6.0 + service pack (+ Processor Pack if `/arch` or
  SSE appear) for the era this skill targets, or whatever MSVC the Rich header names (VVVVVV 2.4.4: VS2010
  SP1). On macOS/Linux install it under Wine; set `VC6_ROOT` (or the equivalent), `PATH`, `INCLUDE`, `LIB`
  for `cl.exe`/`link.exe`. Wine and the compiler are the only things phase 6 adds to Python + Ghidra.

## 1b. Installing the compiler under Wine (macOS/Linux)
Never run Visual Studio's setup under Wine (it needs .NET 4 and usually fails). Unpack the compiler's own MSI
packages with `msiexec /a` (an administrative install only extracts files) into a separate prefix, so the
user's game prefix is untouched. Worked example, VS2010 SP1 (cl 16.00.40219.01) - free from Microsoft, no
Visual Studio licence needed: Windows SDK 7.1 ISO (Download Center id 8442, `GRMSDK_EN_DVD.iso`, SHA-1
CDE254E83677C34C8FD509D6B733C32002FE3572) contains the VS2010 RTM compiler, CRT libraries and headers;
"Visual C++ 2010 SP1 Compiler Update for the Windows SDK 7.1" (id 4422, `VC-Compiler-KB2519277.exe`)
brings it to 40219. Ask before downloading (file, source, size); the user may also supply their own media.
```bash
export WINEPREFIX=$HOME/.wine-vs2010 WINEDLLOVERRIDES="mscoree,mshtml=" WINEDEBUG=-all
wineboot -i
hdiutil attach -readonly -nobrowse -mountpoint /tmp/sdk GRMSDK_EN_DVD.iso        # Linux: mount -o loop,ro
for p in vc_stdx86/vc_stdx86.msi WinSDKBuild/WinSDKBuild_x86.msi WinSDKWin32Tools/WinSDKWin32Tools_x86.msi \
         WinSDKTools/WinSDKTools_x86.msi; do                                   # WinSDKTools: mt.exe (relink)
  n=$(basename $p .msi)
  wine msiexec /a "Z:\tmp\sdk\Setup\$(echo $p | tr / '\\')" "TARGETDIR=C:\sdk71\$n" /qn   # quote '/l*v' in zsh
done
# move into the usual places
C=$WINEPREFIX/drive_c; mkdir -p "$C/Program Files (x86)/Microsoft SDKs"
cp -R "$C/sdk71/vc_stdx86/Program Files/Microsoft Visual Studio 10.0" "$C/Program Files (x86)/"
cp -R "$C/sdk71/WinSDKBuild_x86/Program Files/Microsoft SDKs/Windows" "$C/Program Files (x86)/Microsoft SDKs/"
cp -R "$C/sdk71/WinSDKWin32Tools_x86/Program Files/Microsoft SDKs/Windows/"* "$C/Program Files (x86)/Microsoft SDKs/Windows/"
cp "$C/sdk71/WinSDKTools_x86/Program Files/Microsoft SDKs/Windows/v7.1/Bin/mt.exe"* "$C/Program Files (x86)/Microsoft SDKs/Windows/v7.1/Bin/"
cp "$C/sdk71/vc_stdx86/Win/System/"*.dll "$C/windows/syswow64/"
# SP1: the update holds a complete new vc_stdx86.msi (not a patch): extract it and lay it over the RTM files
cp VC-Compiler-KB2519277.exe "$C/"; wine 'C:\VC-Compiler-KB2519277.exe' /extract:'C:\kb2519277' /q
wine msiexec /a 'C:\kb2519277\vc_stdx86.msi' 'TARGETDIR=C:\sp1\vc_stdx86' /qn
cp -R "$C/sp1/vc_stdx86/Program Files/Microsoft Visual Studio 10.0/." "$C/Program Files (x86)/Microsoft Visual Studio 10.0/"
cp "$C/sp1/vc_stdx86/Win/System/"*.dll "$C/windows/syswow64/"
sh scripts/msvc.sh --version      # must print 16.00.40219.01 / Linker 10.00.40219.01
```
`cl.exe` needs `Common7\IDE` (mspdb100.dll) on its path; `scripts/msvc.sh` sets WINEPATH, INCLUDE and LIB
(env MSVC_PREFIX / MSVC_VS / MSVC_SDK for other versions) and filters Wine noise. Pass relative file names
(cl reads a leading `/` as an option). Then confirm the build with a test program: compile one `.c` and one
`.cpp` file, link, and compare `rich_header.py` entries (product id + build) with the target's. Tested on
Apple Silicon (Wine 11, Rosetta): the VVVVVV test program's entries (147/30729, 158, 170, 171, 157 at 40219)
matched VVVVVV.exe, and the first real function (binaryBlob's constructor, `/O2 /MT /EHsc /GS /Oy- /Gy`)
compiled IDENTICAL.

## 2. Discover compiler flags
Compile small candidate functions and compare codegen with the original:
- optimisation: `/O2` vs `/O1` vs `/Ox` (frame pointer omission, inlining, string pooling);
- `/G5` vs `/G6` vs `/GB` (instruction scheduling differs visibly);
- `/Gy` (function-level linking: functions in separate COMDATs), `/GF` (string pooling);
- `/GX` (exceptions: presence of `__CxxFrameHandler` and unwind funclets), `/GR` (RTTI: absent here);
- calling conventions (`__thiscall` methods, `__stdcall` callbacks, `__cdecl` default);
- struct packing `/Zp`, `/QIfist`, `/Op` (float consistency changes x87 code).
Record the flag set per object if it varies (DLLs may differ from the exe).

## 2b. Lessons from the first matched project (VVVVVV 2.4.4, VS2010 SP1)
- **Flags are per source file.** One global flag set is a hypothesis, not a fact: compile every candidate
  with the variants (e.g. with and without `/EHsc`) and compare. VVVVVV: no function in the first 88 units
  needed `/EHsc`, 10 only matched without it (EH changes `std::string[N]` array init/teardown into `eh vector
  constructor iterator` calls and adds FS:[0] frames). Keep a per-file flags line in each unit
  (`// CLFLAGS: ...`, read by the project's match script) and split a unit file when its functions need
  different flags - they came from different source files.
- **LTCG (/GL + /LTCG) limits per-file matching.** Static functions can get custom register calling
  conventions (arguments in EAX/ESI/EDI, no prologue), cross-file inlining, and different register
  allocation. A per-file compile cannot reproduce these; detect them early (registers read before written
  at entry, stack args at shifted offsets), record them, and leave those functions in assembly (phase 5b
  keeps the binary identical). VVVVVV: 3 of 147 functions in the first units.
- **Compiler-generated functions** (dynamic initializers `??__E<var>@@YAXXZ`, atexit destructors
  `??__F<var>@@YAXXZ`) have no source name: annotate with the explicit decorated symbol and define only the
  global with its class's ctor/dtor declared out of line.
- **Annotation placement**: the definition must follow the annotation block directly - declarations go above.
- **Missing headers in partial installs**: the SDK 7.1 + KB2519277 route lacks `ammintrin.h`, which
  `<intrin.h>` (pulled in by `<vector>`/`<memory>`) includes; `#pragma include_alias(<ammintrin.h>,
  <crtdefs.h>)` before the STL includes fixes it without changing code generation.
- **Agent loop that worked**: one agent per 1-4 small translation units, a shared notes file of idioms and
  blockers updated after every wave, a compile-and-compare command per unit that can also score stubs, and
  an independent re-run of every unit (`match_all`) for the numbers. Final result for VVVVVV.exe: 1,202 of
  1,215 compile targets identical (98.9%) in 6 waves plus a clean-up pass (smallest units first, 4 -> 2 -> 1
  units per agent as functions grow; notes consolidated by an agent between waves).
- **Most "LTCG blockers" are not**: a per-file `/O2` compile gives file-static functions the same custom
  register conventions. Reproduce them with an unannotated `static __declspec(noinline)` stand-in with the
  callee's real body in the caller's file, keep pointer args on the stack with a one-pointer struct passed by
  value, and copy inlined cross-file callees as `static inline`. What remained (13) were register
  tie-breaks.
- **STL template instances** match with the same default flags: explicit instantiation
  (`template class std::vector<T>;`) or a small unannotated caller emits the COMDATs; annotate with the
  decorated symbol. Identical-COMDAT folding means one exe address serves several types.

## 3. Project layout and the comparer (`scripts/objcmp.py`)
- Source files with reccmp-style annotations, one per original translation unit where address ranges show
  unit boundaries:
  ```cpp
  // FUNCTION: PRAETORIANS 0x409180
  int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR cmd, int show) { ... }
  // FUNCTION: PRAETORIANS 0x40a2c0 ?Update@CUnit@@QAEXXZ      <- explicit decorated name when needed
  void CUnit::Update() { ... }
  // STUB: PRAETORIANS 0x40a400                                  <- placeholder, never fails the report
  // VTABLE: PRAETORIANS 0x715b24
  class CVideoListener { ... };
  // GLOBAL: PRAETORIANS 0x747164
  HMODULE g_hZipDll;
  ```
  Also `TEMPLATE`, `SYNTHETIC`, `LIBRARY`, `STRING`; the module name is optional (`--module` filters).
  Without an explicit symbol, the name before `(` is matched to the obj's decorated names (`_name`,
  `_name@N`, `@name@N`, `?Method@Class@@...`, `??0/??1/??4...`); no match or several -> reported, never
  guessed. Functions defined inside a class body, in `namespace {}`, templates and conversion operators
  need the explicit decorated name.
- Compile each unit with `cl.exe /c` and the discovered flags (`/Gy` puts each function in its own COMDAT,
  which the comparer reads directly). No PDB is needed.
- `python3 -I scripts/objcmp.py compare <obj> <symbol> <pe> <va> [size]` - one function: IDENTICAL or
  DIFFERENT with match ratio, first differing offset/VA and a hex view (masked bytes `..`, mismatches `^^`).
- `python3 -I scripts/objcmp.py report --pe <pe> --src <dir> --obj <dir> [--functions index.json]
  [--map names.txt] [--json out.json]` - every annotation: OK / DIFF / STUB / UNMAPPED / AMBIGUOUS / ERROR,
  then totals (functions identical / annotated, bytes identical / total). Exit 0 only if all compared
  functions are identical and nothing is unmapped/ambiguous.
- `python3 -I scripts/objcmp.py dump <obj>` - sections, COMDAT selection, symbols, relocations (debugging).
- How bytes are compared: bytes under an obj relocation (DIR32, DIR32NB, REL32, SECREL, SECTION) or an
  original `.reloc` fixup are masked, but the relocation's TARGET is still checked when its address is
  known (from `--map`, annotations, the PE import table for `__imp_` symbols, Ghidra default names
  `FUN_/DAT_/LAB_/PTR_<addr>`, or same-section symbols); unknown targets are inferred from the original
  bytes and must agree everywhere in the function. A fixup on one side without a relocation on the other
  is a difference. CC/90 padding after the original function is ignored; pass `--functions
  decompiled_exe/index.json` so the function end is known when functions abut.
- Limits to keep in mind: only byte-level comparison (no vtable/data/stack comparison as in reccmp); a VC6
  exe linked `/FIXED` has no `.reloc`, so only obj relocations mask the original; real `cl.exe` objects
  (`.debug$S`, `.drectve`, `$LN` labels, `.text$x` funclets, associative COMDATs) are parsed generically -
  check the first real objects with `dump`. `scripts/objcmp_selftest.py <pe> --functions index.json`
  re-runs the comparer's self-test (objects synthesised from the original's own functions).

## 3b. Proving the matches end to end without link.exe (`scripts/hybrid_link.py`)
`hybrid_link.py map` derives, once and from the original, a linker map: the identical functions, plus the
address of every symbol their relocations name. Externals are keyed by name, with an extra per-object view;
statics and `$LN` labels are keyed per object and section. `hybrid_link.py link|verify` then reads only the
phase-5b dir, the objects and that map:
1. build the phase-5b image;
2. wipe each matched function's slot and write the object's code with resolved relocations;
3. regenerate `.reloc` from the objects' DIR32 relocations plus the sites still in assembly;
4. compare SHA-256.

VVVVVV: 1,202 functions (510 KB, 57% of `.text`) gave an IDENTICAL exe. A one-byte change in one object
moves the first difference to exactly that byte.

- **Within-object conflicts:** the map step reports a symbol that one object places at two addresses (an
  off-by-one member offset hidden by relocation masking). Fix the layout and recompile.
- **Cross-object conflicts:** the same global declared with different layouts by different units, or a
  genuine duplicate such as two `__real` constants. These are listed, and must be removed by shared headers
  before a real `link.exe` link.

## 4. Relinking with link.exe (`scripts/relink.py`)
The step after the hybrid build: the real linker builds the exe from COFF objects, so link order, imports,
exports, resources and `.reloc` are link.exe's own work. Do the shared headers first: one definition per
class (offsets checked against the exe's relocations), every unit migrated and re-verified. Each global then
resolves to one address. VVVVVV went from 144 conflicting relocation sites to 1 (a real duplicate constant).

`relink.py prepare | link | finish` (docstring has the details):
- **Code:** every matched function is a COMDAT holding the compiler's bytes and relocations. Everything
  else is phase-5b assembly split at function starts, also as COMDATs. All of them are laid out by an
  `/ORDER` file in address order, with targets as `_A_<va>` symbols. Use `/OPT:REF` plus one `/INCLUDE` per
  piece: `/OPT:NOREF` keeps the jump thunks the SDK's code imports bring.
- **Data:** raw sections with DIR32 relocations. The export table goes in as `.edata`, with the original's
  alignment so it lands at the same RVA. The load config is the `__load_config_used` symbol. The IAT and
  import tables are left out for link to build.
- **Imports** are built by link.exe from import libraries:
  - Prefer the SDK's libraries; VVVVVV's 117 system imports had exactly the SDK 7.1 hints.
  - Generate the rest with `lib /DEF`. Write `name @hint DATA`: DATA avoids jump thunks. `@hint` alone
    makes an import by ordinal, so patch each short import member to name type NAME_NOPREFIX; the hint
    stays.
  - link.exe orders hint/name entries by pull order, and pulls in library-search passes. Read the passes
    from the original's hint/name table: a DLL earlier in library order starting a new run means a new
    pass. Reproduce them by putting the pieces that use pass-k imports into a library placed after the last
    import library of that pass.
  - The first object's undefined-symbol order sets the order within a pass. Explicit undefined symbols must
    come first in the COFF symbol table.
  - The IAT slot order inside a DLL's block is a link.exe-internal permutation that we could not reproduce
    from inputs. It is a post-link fact.
- **Resources:** if the original's `.rsrc` tail is `PADDINGXX…`, it was rewritten by UpdateResource, i.e.
  `mt.exe` embedding the manifest after link (VS2010 does this). Then the resources go to link.exe as a `.res`
  file without the manifest, and `mt.exe` (from WinSDKTools) adds the manifest. That also gives the
  checksum and SizeOfInitializedData the original has. Wine's UpdateResource writes CodePage 0 and a rounded
  VirtualSize where Windows wrote the ANSI code page and the exact size: 8 bytes of post-link facts.
- **`.reloc` size:** link.exe reserves 2 bytes per DIR32 relocation in its *inputs*, counting COMDATs that
  `/OPT:REF` discards. The original's discarded code makes its `.reloc` bigger than its table. One discarded
  COMDAT with the missing count (measured once) reproduces SizeOfImage and the file size.
- **Post-link facts** (`finish`), each counted: Rich header (from @comp.id records the relink inputs do not
  have; the PE header moves with e_lfanew), TimeDateStamp, IAT slot order, the UpdateResource bytes, then
  the recomputed checksum. VVVVVV: 730 of 2,321,408 bytes, final exe SHA-256-identical.
- **Not covered:** data defined in C++. Literals, constants, globals and vtables stay raw sections; the
  compiled objects' own data is not linked. That is the next phase, as large as function matching.

## 4b. Building from source: edits that move code (`relink.py --free`, `hybrid_link.py map --all`)
The identical relink proves the matches. A project is usable when an edited function can go into the
build, so make the free mode work and test it with an edit you can see:
- **`map --all`** also takes FUNCTIONs that no longer match. Their relocation targets cannot be read from
  the original's bytes, so they resolve by name:
  1. the identical functions' map;
  2. the address map (annotations of every unit, imports, Ghidra names);
  3. direct calls to imports (`_SDL_Foo`) map to the original's `jmp [IAT]` thunk;
  4. references into the function's own section (jump tables) stay relative to it;
  5. anything absent from the original (new literal, constant, static, helper) comes from the unit's
     object as a new section.
- **`relink.py --free`:**
  - An edited function replaces its original slot, up to the next function, and everything after it moves.
  - Two things are refused: pointers into its old interior, and short jumps of the remaining assembly that
    span it.
  - New code is linked after the original code, new data after the original data. Linking new `.rdata`
    ahead of the original data stopped VVVVVV from starting.
- **RVA tables have no base relocations,** so they must go to link.exe as DIR32NB relocations or they go
  stale when code moves: the SafeSEH handler table (read its count from the load-config struct, whose own
  Size can exceed the directory entry's) and the export table (directory pointers, function and name
  RVAs).
- **Verify a moved build with a differential check** (`relink.py check`). Use `/MAP` (always written) to map every original
  `_A_<va>` to its new address. Then check that each direct branch of the original and each `.reloc`
  pointer lands on its moved target. VVVVVV: 48,097 branches and 3,181 pointers, 0 mismatches. One
  corrupted call is caught.
- **Edited functions also need names nothing annotates.** Use the named function index (library functions,
  `FID_conflict:` CRT names). Resolve unchanged literals and floating-point constants to the original's
  bytes. Pair the rest in order with the original function: calls such as `__chkstk`, and the unit's statics
  through its relocated pointers, so a file-level static stays the variable other code uses.
- **Near-matches in the build.** Tag a FUNCTION that is right but not byte-identical with `// NONMATCHING`:
  the source build uses it, the identical build keeps the assembly. VVVVVV's 12 register tie-breaks run
  this way.
- **Run it.** Under Wine on macOS, CoreGraphics' window list (via ctypes, no screen-recording permission)
  gives the window title, so an edited title proves the edit is in the running game. Retry the launch:
  Wine sometimes ends a starting process silently, the original exe included.

## 5. Per-function matching loop (parallel agents)
For each function (start with leaves and small functions; skip CRT/library code - it links from the real
libs):
1. Draft C/C++ from the named Ghidra pseudocode, with real types (structs from field-offset analysis,
   vtables as classes).
2. Compile just that unit with the discovered flags and run `objcmp.py compare` (or `report` for the unit):
   the function's `.obj` bytes against the original, relocated fields masked, relocation targets checked.
3. Iterate on source shape (temporaries, loop forms, inline order, `register`-free tricks, signed/unsigned,
   struct field order) until identical. Record "equivalent but not matching" when stuck after N attempts,
   with the diff - it stays in assembly.
4. Swap the matched function into the hybrid build; rebuild; the whole binary must stay SHA-256-identical.
Track: functions matched / total, bytes matched / total, per subsystem.

Drafting is done by subagents from the named Ghidra pseudocode and `instructions.tsv`; no external
drafting tool is used. A draft counts as matched only when `objcmp.py` reports it IDENTICAL and the hybrid
build stays SHA-256-identical.

## 6. Expectations to state to the user
- Thousands of functions: a long-running effort even with many agents; small functions match quickly,
  large optimised ones can take many iterations; some may never match exactly (register allocation),
  without harming byte identity because they stay in assembly.
- C++ class layouts, inline functions from headers and template instantiations must be reconstructed for
  methods to match; vtable order must be exact.
- The result is derived from the game binary: keep it private; publish only tooling that requires the
  user's own copy.
