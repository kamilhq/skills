# Step 6 - Toolchain: build for Windows, with the original's libraries

Run this after the user has picked the language (step 5). Output: a build of the chosen language for
Windows, the libraries pinned in step 3c built from upstream source at their pinned versions, and a hello
program. Gate: **the hello program uses every library on the game's own
data and runs on Windows** (on the user's PC, or under Wine while developing on macOS/Linux).

## Choosing the toolchain

| Language | Developing on Windows (the user's PC) | Developing on macOS / Linux |
|---|---|---|
| C++ | the original compiler family (e.g. VS2010 SP1, read from the Rich header in step 3c), or current MSVC or clang-cl | the same compilers under Wine, through this skill's `msvc.sh` |
| Rust | `i686-pc-windows-msvc` (or `x86_64-pc-windows-msvc`) with the Visual Studio Build Tools linker | `i686-pc-windows-gnu`, linked by the Rust toolchain's own `rust-lld`, no MinGW: `scripts/rust_build.sh` |

The target is a Windows exe. Building and testing under Wine on macOS or Linux is a convenience, not the goal:
everything must also build and run natively on Windows (`runner: native`, `cl_mode: native`).

### C++: which compiler
- **The original's compiler family (recommended when it is free to get):** the generated code then behaves
  like the original's in the parts no spec states exactly: x87 versus SSE2 float code, STL algorithms and
  container growth, CRT `rand()`. For a VS2010 SP1 game: `cl` 16.00.40219.01 (`_MSC_VER` 1600) from
  Windows SDK 7.1 plus the KB2519277 compiler update (below, "Installing MSVC under Wine"). Using the same
  compiler is not copying: the code is the implementers' own.
- **A modern compiler (or the user's choice):** current MSVC or clang-cl. Then expect float
  differences and check them with the harness (step 8). VS2010 compiles 32-bit float code for x87 by
  default (no `/arch` flag); VS2012 and later default to SSE2. Use `/arch:IA32` on x86 to stay with x87,
  or accept that some `v=` fields will diverge and fix the code that depends on the extra precision.
- Old compilers are C89 for C files. A C99 library (e.g. c-hashmap) is compiled by clang
  `--target=i686-pc-windows-msvc -fms-compatibility-version=16.00 -fms-runtime-lib=static -fno-addrsig`
  against the old MSVC headers; its objects link with the old `link.exe` (`-fno-addrsig` keeps them plain).
  `build_libs.py` does this for `"lang": "c99"`.

### Rust: which target
- **On Windows:** `rustup target add i686-pc-windows-msvc` (32-bit like the original; `x86_64` works too,
  but then pointer sizes in ported structs change). Rust's i686 targets do float math in SSE2: an x87
  original can differ in the last bit, as with a modern C++ compiler (the harness shows where). The MSVC linker comes with the Build Tools. Call the C
  libraries as DLLs with `#[link(name = "...", kind = "raw-dylib")]` (no import library needed) or link
  their import libraries from `<build>/dll/lib`. Static linking of `/MT` libraries into a Rust MSVC
  program is possible with `-C target-feature=+crt-static`, but only with one CRT for both sides.
- **From macOS/Linux:** `i686-pc-windows-gnu` with `rust-lld`. The 1.100 toolchain's self-contained
  folder has only `crt2.o`/`dllcrt2.o` and no MinGW libraries, so the skill provides the missing pieces
  (`build_libs.py runtime`, `rust_build.sh`):
  - `-C linker-flavor=ld.lld -C link-self-contained=no -C panic=abort`, linker = the toolchain's `rust-lld`;
  - `rust_gnu/crt_shim.c` (compiled by clang `--target=i686-w64-windows-gnu -ffreestanding`) becomes
    `libmingw32.a`: `mainCRTStartup` runs the `.CRT$XI*`/`.CRT$XC*` initialisers, calls rustc's `main`,
    runs `atexit` handlers; it also holds the TLS directory (std's thread-local destructors need it),
    no-op `__register_frame_info`, and trapping `_Unwind_*` stubs (no unwinder: panics abort);
  - import libraries for kernel32, ntdll, ws2_32, userenv, msvcrt and the synchronization API set come from
    `.def` files (`rust_gnu/defs`), the other `-l` names are empty archives;
  - a newer std that needs more system functions fails to link with `undefined symbol: _Foo@N`: save the
    output, run `rust_gnu/gen_defs.py <output> --syswow64 <prefix>/drive_c/windows/syswow64`, then
    `build_libs.py runtime` again;
  - `raw-dylib` on the gnu target makes rustc run `i686-w64-mingw32-dlltool`; `rust_gnu/bin/` has a
    stand-in (`dlltool.py`, or its JS port with `REWRITE_DLLTOOL=node`) that lets `rust-lld` build the
    library and then rewrites each import to the exact symbol rustc references (`__imp_SDL_Init`, import
    name `SDL_Init`). Use `import_name_type = "undecorated"` with `extern "C"`.

### Why the libraries are DLLs for Rust
Linking `/MT` library objects into a MinGW-mode Rust link would mix two C runtimes: two heaps, two `/GS`
cookie set-ups, `_chkstk`, CRT start-up and TLS in one image. One DLL per library keeps each library's CRT
private, is built with the same compiler and flags as the C++ flavour, and needs nothing on the Rust side
but `extern "C"` declarations. The cost:
- memory a DLL allocates is freed by that DLL (`lodepng_free`, `stb_vorbis_close`, `txml_doc_delete`);
- C++-only libraries need a C API (below);
- `#pragma pack(1)` structs (FAudio's) are `#[repr(C, packed)]`; check a struct returned by value
  (`stb_vorbis_get_info`, 24 bytes) and a `bool` returned from C99 code in the hello program.

## The C API shim pattern
A C++ library cannot be called from Rust directly. Write a flat C API and build it into the library's DLL
(`"dll_srcs"` in `libraries.json`). `scripts/capi/tinyxml2_capi.{h,cpp}` is the worked example (52
functions over tinyxml2, written against 9.0.0):
- opaque handle types that are the library's own objects (`txml_doc` = `XMLDocument*`), no wrappers;
- `extern "C"`, `__cdecl`, exported undecorated (`__declspec(dllexport)` under a build macro);
- NULL in, NULL out, so navigation chains need no checks;
- strings returned point into memory the library object owns, valid until it changes;
- every object the API creates has a delete function in the same DLL;
- error codes as `int` (the library's enum values); a version function (`txml_version`).
Write only what the game uses (the libraries spec from step 3c lists which API functions the original calls), and keep
it in the old compiler's dialect (C++03 for VS2010).

Two other shims in `scripts/capi/`:
- `lodepng_alloc.c`: allocator hooks a library expects from its host (`LODEPNG_NO_COMPILE_ALLOCATORS`). The
  static flavour leaves them to the program (as the game did); the DLL exports its own.
- `stb_vorbis_faudio.c`: builds a library from the patched copy that the game really contains (FAudio's
  `stb_vorbis.h`), supplying the macros its includer normally provides.

## Building the libraries: `build_libs.py`
```bash
S=<skill>/scripts
python3 -I $S/build_libs.py list                     # what is pinned, what is downloaded
python3 -I $S/build_libs.py fetch                    # download + sha256 check (ask the user first)
python3 -I $S/build_libs.py extract                  # unpack into rewrite/third_party/src/<dir>
python3 -I $S/build_libs.py build                    # static (C++) and dll (Rust) flavours
python3 -I $S/build_libs.py runtime                  # Rust gnu runtime (cross builds only)
```
Downloads: only from the official source the inventory names, pinned by SHA-256, and only after the user
agreed (name the files, the source and the sizes). A library without a pinned digest is reported
`unpinned` and fails the command until the digest is written into `libraries.json`.

Outputs under `rewrite/third_party/build/`: `static/{lib,include,bin}`, `dll/{bin,lib,include}`,
`rust-gnu/{rtlib,defs}`. Seven libraries built both flavours in about 20 s under Wine; check each DLL's
export count against the API the game uses (`wintools.py`).

### libraries.json
```json
{
 "defaults": {"cl": ["/nologo", "/c", "/O2", "/MT", "/W0", "/DNDEBUG", "..."], "dll_syslibs": ["kernel32.lib"]},
 "generate": {"lodepng_c.h": ["/* header carrying the configuration the library was built with */", "..."]},
 "libraries": [
  {"name": "physfs", "version": "3.2.0", "commit": "eb3383b5...", "evidence": "PHYSFS_getLinkedVersion ...",
   "url": "https://github.com/icculus/physfs/archive/refs/tags/release-3.2.0.tar.gz", "sha256": "1991500e...",
   "lang": "c", "srcs": ["src/physfs.c", "..."], "defines": ["PHYSFS_SUPPORTS_DEFAULT=0", "PHYSFS_SUPPORTS_ZIP=1"],
   "exports": "declspec", "headers": {"src/physfs.h": ""}, "dll": "physfs.dll"}
 ]
}
```
| Key | Meaning |
|---|---|
| `name`, `version`, `commit`, `evidence` | identity and the step-3c evidence (`list` shows them) |
| `url`, `sha256`, `archive` | download; `archive` = file name in downloads (default: the URL's last part) |
| `dir`, `strip`, `file` | folder under `src` (default `name`); leading path components to drop (`"auto"`: one common top folder); name for a single-file download |
| `kind` | `source` (default), `prebuilt` (copy `static_libs`, `dlls`; `include` folder for programs), `headers` (install headers only) |
| `lang` | `c` (cl `/TC`), `c++` (cl `/TP /EHsc`), `c99` (clang for the MSVC target) |
| `srcs`, `incs`, `defines` | sources, include folders, defines of both flavours |
| `static_defines`, `dll_defines`, `dll_srcs`, `dll_incs`, `dll_libs` | flavour-only additions (a C API shim, an export macro, the import library of a DLL it calls) |
| `exports` | `"declspec"` (the library marks its API) or a list of COFF symbol prefixes (`"_lodepng_"`) to export with `/EXPORT:` (data symbols get `,DATA`) |
| `headers`, `dll_headers` | `{pattern: subfolder}` or `{pattern: [subfolder, new name]}`; `*` and `?` in the last component |
| `lib`, `dll` | output names (default `<name>.lib`, `<name>.dll`) |
| `generate` (top level) | headers written into both include folders: configured wrappers such as `lodepng_c.h` |

Paths in a library entry are relative to its source folder; `{src}`, `{build}`, `{project}` and `{skill}`
(this skill's `scripts/`) start other roots. `scripts/examples/libraries_example.json` is a complete file
for an SDL2 game (nine entries, including the SDL2 devel zip as `prebuilt` and the upstream stb_vorbis kept
only as provenance).

Build settings from the original: `/MT` (static CRT), `/O2`, `/GS` (the original has security cookies),
the library's own feature defines as read from the binary, and its export macro where the original exe
exported the API (an exe that exports PhysFS, FAudio and stb_vorbis built them with their export macros;
a C++ rewrite linked with the static libraries exports them too).

## C++ programs: `cpp_build.py`
```bash
python3 -I $S/cpp_build.py --out build/hello-cpp/hello.exe --subsystem windows hello/cpp/hello.cpp
```
cl `/nologo /c /MT /GS /W3 /O2` (or `rewrite.toolchain.cflags`), one cl run per language (a Wine process
start costs about a second), link `/OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT` with every library of
`libraries.json` and the system libraries. `--subsystem windows` keeps `main()` as the entry
(`/ENTRY:mainCRTStartup`). Header rules learned the hard way:
- include the generated configured header (`lodepng_c.h`), not the library's raw header, when the raw one
  pulls in C++ (lodepng.h without `LODEPNG_NO_COMPILE_CPP` includes `<vector>`, which breaks inside
  `extern "C"`);
- wrap C headers without their own guards in `extern "C" {}` (c-hashmap's `map.h`);
- `#define SDL_MAIN_HANDLED` (SDL2main.lib of the release is built by a newer MSVC and is not needed).

## Rust programs: `rust_build.sh`
```bash
CARGO_TARGET_DIR=build/hello-rust/target sh $S/rust_build.sh --release --manifest-path hello/rust/Cargo.toml
```
No crates: every external function is a hand-written `extern "C"` block. Profiles set `panic = "abort"`.
Checked in a hello program this way: threads, `Mutex`, `thread_local!` destructors, `std::env::args`, `Instant`,
`sleep`. Not tried: `raw-dylib` data imports, stdcall imports.

## The hello program (the gate)
One small program per language that touches every library through the game's own files:

| Library | Hello check (example: an SDL2 game) |
|---|---|
| SDL2 | linked version, window with a title, renderer, a texture shown |
| PhysFS | mount the game's data archive, read files from it |
| lodepng | decode a game PNG, FNV-1a of the pixels |
| tinyxml2 | parse a game XML file: root element, attributes, element counts |
| stb_vorbis | open every music track, decode one fully (sample count), peak value |
| FAudio | engine, mastering and source voice, samples played after 1-4 s (about the output rate per second) |
| SheenBidi | runs of a mixed Hebrew/Latin string |
| c-hashmap | set, get, iterate |

Rules: log every step to a file next to the exe, end with `RESULT: OK (0 failure(s))`, exit 0. Cross-check
the numbers independently (e.g. decode the same PNG with Python's zlib + Adam7 to the same FNV-1a, read the
Ogg granule positions for the sample count, count the XML elements with grep). Both languages must print
the same values; the hello is the first place where a mis-pinned or mis-built library shows (the plain
stb_vorbis failed here).

## Running: Wine or Windows
`scripts/run_wine.py EXE --title T --log NAME --expect "RESULT: OK" [--extra-dir <build>/dll/bin]` copies the
game folder to a temporary folder (APFS clones on macOS: large archives cost nothing), adds the exe and
DLLs, runs it, waits for the window title, collects the log, retries.

| | Under Wine (macOS/Linux) | On Windows |
|---|---|---|
| runner | `wine` (env `WINE`, prefix `rewrite.wineprefix`, default `~/.wine`) | the exe itself (`runner: native`) |
| compiler | `msvc.sh` with the compiler's own prefix (`MSVC_PREFIX`), relative paths only | `cl`/`link` from a developer prompt (`cl_mode: native`) |
| Rust | `i686-pc-windows-gnu` + `rust_build.sh` | `cargo build --target i686-pc-windows-msvc` |
| window check | CoreGraphics window list (no screen-recording permission) | `EnumWindows` |
| start-up | crashes and hangs at random (below): retry | no such problems seen; one try should do |

Observed under Wine 11 on macOS (an SDL2 game, 2026):
- Starting processes crash or hang at random: `Unhandled page fault on read access to ...`, exit codes 5
  and 41, or a window that never finishes. The original game exe crashed the same way in 3 of 5 runs, so
  it is the environment, not the build. In one session the Rust hello passed in
  1 of 7 starts with DLLs that differed from a passing set only in their timestamps.
  `run_wine.py` and `run_scenario.py` retry; judge a build only after several tries.
- Audio needs the Mac awake: with the screen locked, SDL's audio thread stalled after one callback for
  every audio driver, and runs started before sleep never finished. Keep the machine awake for audio checks.
- `SDL_AUDIODRIVER` set on the macOS side had no effect on the Windows process; force SDL hints with
  `SDL_SetHint` in the program. (The harness variables do reach the program: the oracle reads them.)

## Gotchas
- `msvc.sh` takes relative paths: `cl` reads a leading `/` as an option. The scripts run the tools from the
  common parent folder of every path they pass.
- The SDK 7.1 install of VS2010 lacks `ammintrin.h` and `mm3dnow.h` (`<intrin.h>` fails with C1083 and an
  internal compiler error) and C99 `stdbool.h`: `scripts/msvc_compat/` has stand-ins; it is on every cl
  include path.
- llvm-lib `.def` syntax for stdcall imports: `_GetLastError@0 == GetLastError`. `GetLastError@0` gives a
  symbol without the underscore; `_GetLastError@0` alone makes the loader look for `_GetLastError@0`
  (Wine: "unimplemented function kernel32.dll._TlsAlloc@0").
- A DLL's `.exp` and an exe's `.lib`/`.exp` (written when objects carry `dllexport`) are deleted by the
  scripts.
- The release `SDL2.dll` and a game's `SDL2.dll` can be different builds of the same version: run with the
  game's.

## Installing MSVC under Wine (macOS/Linux)
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
         WinSDKTools/WinSDKTools_x86.msi; do                                   # WinSDKTools: mt.exe
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
(cl reads a leading `/` as an option). Tested on Apple Silicon (Wine 11, Rosetta). The same compiler builds
the probe (step 4).

## Project config (decomp.json "rewrite", build part)
| Key | Default | Used by |
|---|---|---|
| `libraries` | `rewrite/libraries.json` | build_libs, cpp_build |
| `paths.downloads`, `paths.src`, `paths.build` | `rewrite/third_party/{downloads,src,build}` | build_libs, cpp_build |
| `toolchain.cl_mode` | `wine` off Windows, `native` on it | build_libs, cpp_build |
| `toolchain.wineprefix`, `vs`, `sdk` | decomp.json's top-level `toolchain`, if any | -> `MSVC_PREFIX`, `MSVC_VS`, `MSVC_SDK` of msvc.sh |
| `toolchain.msvc_sh` | this skill's `scripts/msvc.sh` | where msvc.sh is (env `MSVC_SH`) |
| `toolchain.machine` | `x86` | `/MACHINE:`, clang target, export name decoration |
| `toolchain.cflags`, `toolchain.syslibs`, `toolchain.vs_include` | see cpp_build.py | C++ programs; clang `-isystem` folders |
| `game`, `runner`, `wineprefix`, `extra_env` | `paths.game`, by platform, `~/.wine`, none | run_wine, run_scenario |

Tested versions: VS2010 SP1 `cl` 16.00.40219.01 with SDK 7.1, Apple clang 21, Rust 1.100.0 with its
`rust-lld`, Wine 11.0, Python 3.9 and Node 26.
