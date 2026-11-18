# Dependencies

The pipeline needs **Python 3.9+ (standard library only) and Ghidra** (plus the JDK Ghidra runs on). Every
other step is implemented in this skill's `scripts/`. `sh scripts/check_deps.sh` checks what is present.
Phase 6 alone needs things no skill can ship: the game's original compiler (licensed, supplied by the
user) and, on macOS/Linux, Wine to run it.

| Need | Version tested | Install | Used for |
|---|---|---|---|
| Python | 3.9+ (3.9.6 tested) | system / `brew install python` | every script; stdlib only, run with `python3 -I`; no pip packages |
| Ghidra | 12.2 (12.1+ OK) | `brew install ghidra`, or unzip a release and set `GHIDRA_HOME` (folder with `support/analyzeHeadless`) | phases 4, 5, 5b: analysis, function recovery, decompiler, instruction listing (`ExportListing.java`), ad-hoc queries (`inspect.sh`), assembler for 5b |
| JDK | Ghidra's `application.java.min` (25 for 12.2, 21 for 12.1) | comes with `brew install ghidra`; else OpenJDK; set `JAVA_HOME` | runs Ghidra; GhidraScripts compile on the fly |
| Original compiler + linker + CRT libs | exactly the build in the Rich header | user-supplied, licensed (e.g. Visual C++ 6.0 + service pack). VS2010 SP1 is free from Microsoft as Windows SDK 7.1 + the VC++ 2010 SP1 compiler update: `matching-decomp.md` section 1b | phase 6 only: only it reproduces the original code bytes; run through `scripts/msvc.sh` |
| Wine | 11.0 | `brew install --cask wine-stable`; distro `wine` | phase 6 only, macOS/Linux only: runs the user's `cl.exe`/`link.exe` |
| Era SDK headers/libs (DirectX, Platform SDK) | as the game used | user-supplied | phase 6 only, when matched code includes them |

Disk: plan ~10x the install size (Praetorians: 0.5 GB install -> ~2 GB extracted+decoded, plus ~200 MB of
decompiles and Ghidra projects).

## What replaced the external tools earlier versions used
| Was | Now | Notes |
|---|---|---|
| innoextract | `scripts/inno.py` | pure-Python Inno Setup reader for GOG installers; versions it was tested on are in its docstring |
| unar / unrar | - | old GOG installers whose `.bin` parts are RAR archives are not supported: use an installed copy of the game (phase 1 accepts a folder) |
| Wine install as the intake reference | `intake.py verify-hashdb` | GOG's `goggame-<id>.hashdb` lists an MD5 per game file: an independent gate from GOG itself |
| ffmpeg previews | stdlib preview decoders, or none | standard files (`.ogg`, `.wav`, `.png`, `.mp3`) are the decoded form and need no preview; write a stdlib decoder only for a kept codec nobody can open (DXT -> PNG, raw ADPCM -> WAV) |
| objdump / llvm | `scripts/ghidra/ExportListing.java` (`instructions.tsv`), `scripts/peek.py` | every instruction with flow targets; `code_coverage_check.py` reads it |
| REA MCP | `scripts/ghidra/inspect.sh` | read-only questions to a recovered Ghidra project (code unit, containing function, references) |
| NASM / llvm-mc | Ghidra's assembler (all encodings of an instruction) + a Python PE/COFF writer | phase 5b, see `reassembly.md` |
| reccmp, cvdump, Python 3.11, CMake | `scripts/objcmp.py` | compares functions in the compiler's COFF `.obj` with the original bytes (relocations masked) |
| ReAgent, gh, shasum | - | not needed |

git is used for the project repository only; no script calls it.
