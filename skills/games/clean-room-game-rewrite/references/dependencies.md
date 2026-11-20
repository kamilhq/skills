# Dependencies

The analysis (steps 1-3) needs **Python 3.9+ (standard library only) and Ghidra** (plus the JDK Ghidra runs
on); every other analysis step is implemented in this skill's `scripts/`. The oracle and the rewrite
(steps 4-9) need Wine on macOS/Linux and a Windows toolchain for the language the user picks at step 5.
`sh scripts/check_deps.sh` checks what is present.

| Need | Version tested | Install | Used for |
|---|---|---|---|
| Python | 3.9+ (3.9.6 tested) | system / `brew install python` | every script; stdlib only, run with `python3 -I`; no pip packages |
| Node.js | 20+ (26 tested) | `brew install node`; distro `nodejs` | optional: the JavaScript ports in `scripts/js/` and their parity tests |
| Ghidra | 12.2 (12.1+ OK) | `brew install ghidra`, or unzip a release and set `GHIDRA_HOME` (folder with `support/analyzeHeadless`) | step 3: analysis, function recovery, decompiler, instruction listing (`ExportListing.java`), ad-hoc queries (`inspect.sh`) |
| JDK | Ghidra's `application.java.min` (25 for 12.2, 21 for 12.1) | comes with `brew install ghidra`; else OpenJDK; set `JAVA_HOME` | runs Ghidra; GhidraScripts compile on the fly |
| Wine | 11.0 | `brew install --cask wine-stable`; distro `wine` | macOS/Linux only: runs the original game (the oracle), the rewrite, and MSVC |
| MSVC (x86) | VS2010 SP1 `cl` 16.00.40219.01 tested | user-supplied or from Microsoft (VS2010 SP1 is free as Windows SDK 7.1 + the VC++ 2010 SP1 compiler update: `toolchains.md`) | the probe DLL (step 4), a C++ rewrite, the libraries (step 6); run through `scripts/msvc.sh` under Wine |
| clang | Apple clang 21 tested | `brew install llvm` / distro `clang` | C99 libraries, the Rust gnu runtime shim (step 6) |
| Rust | 1.100.0 tested | rustup, `rustup target add i686-pc-windows-gnu` (or `-msvc` on Windows) | a Rust rewrite (step 6 onwards) |

Disk: plan ~10x the install size (e.g. a 0.5 GB install -> ~2 GB extracted+decoded, plus ~200 MB of
decompiles and Ghidra projects).

## What replaced external tools
| Was | Now | Notes |
|---|---|---|
| innoextract | `scripts/inno.py` | pure-Python Inno Setup reader for GOG installers; versions it was tested on are in its docstring |
| unar / unrar | - | old GOG installers whose `.bin` parts are RAR archives are not supported: use an installed copy of the game (step 1 accepts a folder) |
| Wine install as the intake reference | `intake.py verify-hashdb` | GOG's `goggame-<id>.hashdb` lists an MD5 per game file: an independent gate from GOG itself |
| ffmpeg previews | stdlib preview decoders, or none | standard files (`.ogg`, `.wav`, `.png`, `.mp3`) are the decoded form and need no preview; write a stdlib decoder only for a kept codec nobody can open (DXT -> PNG, raw ADPCM -> WAV) |
| objdump / llvm | `scripts/ghidra/ExportListing.java` (`instructions.tsv`), `scripts/peek.py` | every instruction with flow targets; `code_coverage_check.py` reads it |
| REA MCP | `scripts/ghidra/inspect.sh` | read-only questions to a recovered Ghidra project (code unit, containing function, references) |
| dumpbin / a .def generator | `scripts/wintools.py` | exports, imports, COFF externals, import-library `.def`, the probe's forwarding `.def` |
| ReAgent, gh, shasum | - | not needed |

git is used for the project repository only; no script calls it.
