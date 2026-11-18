# Step 1 - Inventory: whose code is it?

A game binary holds four kinds of code. A rewrite treats them differently, so classify every function first.

| Kind | What it is | In the rewrite |
|---|---|---|
| Game code | written by the game's developers | rewritten by hand, subsystem by subsystem |
| Third-party library | zlib, SDL, PhysFS, lodepng, Bink, Miles, a Lua VM, ... linked statically | not rewritten: the same upstream library at the same version, built from source |
| C/C++ runtime | the compiler's CRT and STL instances: `malloc`, `printf`, `_ftol`, `std::vector<T>` code, start-up | not rewritten: comes from the rewrite's own compiler and runtime |
| Compiler support | security cookie checks, `__chkstk`, EH funclets, dynamic-initializer and atexit thunks, import thunks | not rewritten: the compiler makes it again |

Gate: every function of the exe (and of every DLL the game ships) is in exactly one class, with the evidence
for that class. Nothing stays "unknown".

The VVVVVV 2.4.4 case (VS2010 SP1, `/MT`): 3,253 functions in `VVVVVV.exe` after full recovery. The naming
pass tags gave about 1,160 CRT and compiler support, about 860 library functions in seven libraries
(PhysFS 269, tinyxml2 151, lodepng 147, FAudio 147, stb_vorbis 76, SheenBidi 60, c-hashmap 9), and about
1,240 game functions. The game ships `SDL2.dll` as a separate DLL, so SDL2 is a library by construction.

## Inputs from the decomp skill
- The phase-4 function set, complete (`code_coverage_check.py` clean). An incomplete set hides library
  code reached only through tables.
- Phase-5 names with `kind` (`crt`, `lib`, `method`, `free`, `thunk`, ...) and `subsystem`. These are a
  first cut, not the answer: namers mark library code with confidence, but the boundary is often wrong
  by a few functions.
- Matched units of phase 6, when they exist. A unit that matches with the original compiler is proven game
  code (or a proven library copy).
- The PE: imports, exports, the Rich header (`rich_header.py`), the section layout.

## How to classify
Work from the strongest evidence down.

1. **Imports.** Everything in a DLL the game ships next to the exe (`SDL2.dll`, `binkw32.dll`,
   `mss32.dll`) is a library. The exe's imports from it show which API it uses.
2. **Exports of the exe.** An exe that exports `PHYSFS_*` or `stb_vorbis_*` linked those libraries with
   their export macros still on. That names the library and says how it was built.
3. **Strings.** Version strings (`"20220717"`, `"1.2.3"`), copyright lines, assert messages with source
   paths (`..\src\png.c`), error tables, format names (`"PkZip/WinZip/Info-Zip compatible"`).
4. **Address ranges.** The linker places objects in link order. Library objects come as contiguous runs,
   and the CRT usually sits together near the end of `.text`. A run that starts with one known library
   function usually holds the rest of that library.
5. **Function sets.** Compare the names the binary has (from its strings, exports, call graph) with the
   functions of the candidate library. Missing modules tell which build options were used: VVVVVV has
   FAudio's core but no FACT, F3DAudio, FAPOFX or XNA_Song code, so only five source files were built.
6. **Constants and layouts.** CRC and Huffman tables, magic numbers, struct sizes passed to `malloc`,
   pool item sizes. They identify a library and often narrow its version.
7. **Call graph.** A function called only from library code, and calling only library or CRT code, is
   library code. A function in the library's range that calls game code is a callback or a game-side
   wrapper: check it by hand.

Mark CRT functions with the decomp skill's names where they exist (`FID_conflict:` names are CRT). The
exact CRT does not need pinning: the rewrite uses its own compiler's runtime. Compiler support needs no
pinning either.

### Borderline cases
- **Library code compiled inside a game unit.** VVVVVV compiles FAudio's copy of `stb_vorbis.h` inside its
  own music unit: the stb_vorbis functions are interleaved with `SoundTrack::` and `MusicTrack::` methods
  (one address range), and `FILE` is mapped to `SDL_RWops`. Classify those functions as the library, and
  note that the game configured it (I/O and allocator mapping). The rewrite reproduces the configuration,
  not the code.
- **Hooks the game supplies to a library.** lodepng built with `LODEPNG_NO_COMPILE_ALLOCATORS` calls
  `lodepng_malloc/realloc/free`, which VVVVVV defines itself (forwarding to `SDL_malloc`). Those three are
  game code; the rewrite defines them too.
- **STL instances.** `std::vector<entclass>::push_back` is runtime code with a game type. It is not
  rewritten: the rewrite's own STL provides it. Keep the type.
- **Modified libraries.** A studio's patched copy of zlib or Lua is a library with a patch. Record the patch
  (the diff against upstream that the binary shows) and apply it to the pinned upstream source.

## Pinning each library's version
The rewrite must call the same library code the original called, or behaviour drifts in ways no trace
explains (rounding, parsing corner cases, memory layout). Pin each library to one release or commit, with
evidence, before building anything.

| Evidence | Example from VVVVVV |
|---|---|
| A version function or constant | `PHYSFS_getLinkedVersion` stores 3, 2, 0; `FAudioLinkedVersion` returns 240200 (24.02.00) |
| A version string, then the repository history | lodepng's `"20220717"`: exactly one commit sets that `LODEPNG_VERSION_STRING` (18964554, the day after) |
| A feature present or absent | tinyxml2 has `XMLUtil::IsPrefixHex` (8.1.0 or later) and a two-argument `XMLDocument::Identify` (before 10.0.0) |
| One changed line of code | tinyxml2's `ParseDeep` calls `XMLNode::DeleteNode` (before commit 9efb6b0); c-hashmap's `iterate` has no 1000-step cap (dedf70e or later) but `set` still returns nothing (before the next commit) |
| Struct sizes and allocation sizes | c-hashmap `malloc(0x14)` + `calloc(20, 20)`; tinyxml2 pool items 0x3c/0x38/0x34/0x28 (but these held from 6.2.0 to 11.0.0: not decisive alone) |
| A file that first appears in some release | SheenBidi's chunked allocator from `Source/Object.c`, new in v2.9.0 and replaced by the next source commit |
| Behaviour that differs between versions | stb_vorbis: `open_memory(NULL)` leaves `*error` unset (v1.20; v1.21 sets it) |

How to narrow it down:
1. Get the candidate's history: release tags (the GitHub API tag list), or a blob-less clone in a scratch
   folder (`git clone --filter=blob:none`; delete it afterwards). Ask before downloading, as for any file.
2. Find the coarse range from version strings and feature presence.
3. Bisect the range with code differences you can see in the decompile: `git log -L` on a function, or
   `git log -S'<constant>'`.
4. When several releases fit and differ only in code the target platform never compiles (a `__ANDROID__`
   branch, a BSD `fseeko`), pick the release; record that the range was equivalent.
5. Compile the candidate's struct headers for the target (`clang --target=i686-pc-windows-msvc`) and
   compare `sizeof` and offsets with the binary when layouts matter.

### Patched copies: test the pin, do not trust it
A library the game got from another library may be a patched copy. VVVVVV's stb_vorbis is not upstream:
it is FAudio 24.02's `src/stb_vorbis.h`, which is stb_vorbis v1.20 plus FAudio's patches (an `fread`-based
`get8`, a zero-size `setup_malloc` fix, export macros). The exe's `get8` reads with `fread(&c, 1, 1, f)`,
which is FAudio's change. Plain upstream v1.20 failed with `VORBIS_outofmem` (3) on all 16 tracks of the
game's music file (Ogg streams without comments hit the zero-size allocation); FAudio's copy opened all 16.
Lesson: after pinning, run the library on the game's own data in the step-2 hello program. A pin is done
when the game's files load, not when the version string matches.

## Static or DLL
Decide per library:

| The original had it... | C++ rewrite | Rust rewrite |
|---|---|---|
| as a DLL in the game folder (`SDL2.dll`) | link the DLL's import library; ship or reuse the same DLL | `raw-dylib` against the same DLL |
| statically linked | static `.lib`, same flags as the original where known (`/MT`, `/GS`) | one DLL per library with its own static CRT (`toolchains.md` explains why) |
| statically, with its API exported from the exe | static, export macro kept (the exe keeps exporting it, as the original did) | DLL, exported |

Prefer the game's own copy of a shipped DLL at run time. VVVVVV's `SDL2.dll` (2.30.0) is a different
build from the official 2.30.0 release's DLL; the rewrite runs with the game's file and takes only
headers and the import library from the release.

## Recording the result
Write `rewrite/INVENTORY.md` (game-derived numbers stay in the project) and the machine-readable
`rewrite/libraries.json` (the input of `scripts/build_libs.py`, format in `toolchains.md`).

Function table: one row per address range or unit, not per function, with a count.

| Range | Functions | Class | Library / unit | Evidence |
|---|---|---|---|---|
| `<start>-<end>` | n | game | units 001-180 | matched units (phase 6) |
| 0x465930-0x46ded0 | n | game + library | music unit with stb_vorbis compiled inside | interleaved; `stb_vorbis_*` exported |
| 0x49b610 + 2 | 3 | game | lodepng allocator hooks | forward to `SDL_malloc` / `SDL_realloc` / `SDL_free` |
| `<start>-<end>` | 269 | library | PhysFS 3.2.0 | `PHYSFS_getLinkedVersion` (0x49d650) |
| ... | | | | |
| `<start>-<end>` | n | CRT / compiler | VS2010 LIBCMT | Rich header, `FID_conflict:` names |

(Addresses shown are the VVVVVV ones quoted elsewhere in this file; take the full table from the project's
own analysis.)

Library table: one row per library.

| Library | Version | Commit | Source | Configuration | Static / DLL | Evidence |
|---|---|---|---|---|---|---|
| PhysFS | 3.2.0 | eb3383b5 | GitHub tag release-3.2.0 | ZIP archiver only | static (exported) / DLL | linked-version function, archiver strings, exports |
| stb_vorbis | 1.20 + FAudio patches | FAudio 24.02 | FAudio's `src/stb_vorbis.h` | no pushdata API, no integer conversion | static / DLL | NULL-data behaviour, `fread` in `get8`; plain 1.20 cannot open the game's music |

Each library row becomes one entry of `libraries.json` (`version`, `commit`, `url`, `sha256`, `evidence`,
and the build fields). `scripts/examples/libraries_vvvvvv.json` is the complete file of the validated case.

## Checklist
- [ ] Function set complete (decomp phase 4 gate) and every function classified.
- [ ] Every library has a version or commit, an archive URL and an evidence line.
- [ ] Build options read from the binary (which modules, which defines, exported or not).
- [ ] Patched copies identified; the patch source found (another library, the studio's fork).
- [ ] Game-supplied hooks into libraries (allocators, I/O callbacks) listed as game code.
- [ ] Static or DLL decided per library and per language.
