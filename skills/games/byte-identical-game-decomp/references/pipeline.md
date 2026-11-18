# The pipeline runner: one project config, every phase

`scripts/pipeline.py` (and its port `scripts/js/pipeline.mjs`, same commands and results) runs the whole
skill on a project folder from a single config file, `decomp.json` at the project root. Everything that
differs between games lives in that file and in the project's own format decoders; the runner and the
tools it calls are generic.

```bash
P=.claude/skills/byte-identical-game-decomp/scripts
python3 -I $P/pipeline.py init --game "Name 1.0"            # decomp.json skeleton, .gitignore, folders
python3 -I $P/pipeline.py intake <setup.exe>                # phase 1: extract + manifest + GOG hashdb gate
python3 -I $P/pipeline.py inventory                         # phase 2: census -> reports/inventory.json
python3 -I $P/pipeline.py archives                          # extract the configured archives -> extracted/
python3 -I $P/pipeline.py decode [--module M]               # phase 3: verify every module, then the completeness gate
python3 -I $P/pipeline.py recover [--binary B]              # phase 4: Ghidra recovery + decompile per binary
python3 -I $P/pipeline.py features [--binary B]             # phase 5 input: features/chunks for naming agents
python3 -I $P/pipeline.py names [--binary B]                # phase 5: apply analysis/<B>/names_apply.json -> decompiled_named
python3 -I $P/pipeline.py reassemble [--binary B]           # phase 5b: split to text, rebuild, SHA gate
python3 -I $P/pipeline.py skeleton [--binary B]             # phase 6 setup: src_matched/<B>/ units with annotations
python3 -I $P/pipeline.py match [--binary B] [--units ...]  # phase 6: compile + compare every unit
python3 -I $P/pipeline.py build [--mode source|identical] [--no-original] [--skip-data] [--run]
python3 -I $P/pipeline.py verify [--out build/game]         # SHA-256 of every built file against the game folder
python3 -I $P/pipeline.py status                            # one table: every phase, its gate, done or not
```
`--project DIR` (default: current directory) selects the project. Each command prints a JSON summary and
exits 0 only when its gate holds.

## decomp.json
```json
{
  "game": "VVVVVV 2.4.4",
  "paths": {"game": "work/game", "extracted": "extracted", "decoded": "decoded", "reports": "reports",
            "formats": "tools/formats", "analysis": "analysis", "src": "src_matched", "build": "build"},
  "archives": ["data.zip", "goggame-1207659753.hashdb"],
  "formats": [
    {"module": "text",   "trees": ["game"]},
    {"module": "png",    "trees": ["game", "extracted"]},
    {"module": "wav",    "trees": ["extracted"]},
    {"module": "zip",    "trees": ["game"]}
  ],
  "containers": ["data.zip", "goggame-1207659753.hashdb", "vvvvvvmusic.vvv"],
  "binaries": [
    {"name": "VVVVVV", "file": "VVVVVV.exe", "decompiled": "decompiled_exe",
     "named": "decompiled_named_exe", "reassembled": "reassembled/VVVVVV", "matching": true},
    {"name": "SDL2", "file": "SDL2.dll", "decompiled": "decompiled_sdl2",
     "named": "decompiled_named_sdl2", "reassembled": "reassembled/SDL2", "matching": false}
  ],
  "toolchain": {"compiler": "msvc", "version": "16.00.40219.01", "flags": "/O2 /MT /GS /Oy- /Gy",
                "wineprefix": "~/.wine-vs2010", "sdk_lib": "Program Files (x86)/Microsoft SDKs/Windows/v7.1/Lib"},
  "run": {"wineprefix": "~/.wine", "exe": "VVVVVV.exe"}
}
```
- `paths` are relative to the project (absolute paths work too); any can be omitted (these are the
  defaults). Two more: `work` (default `work`: the installer extraction `work/installer`, Ghidra projects
  `work/ghidra_<stem>`) and `manifest` (default `manifests/game.json`: `intake` writes the SHA-256
  manifest there, or compares a fresh extraction with it when it exists).
- `archives`: files of the game folder that are archives (ZIP-based) to extract into `extracted/<name>/` for
  decoding their members; a format module must also rebuild each archive itself.
- `formats`: the project's format modules (`<paths.formats>/fmt_<module>.py` / `.mjs`), in build order:
  archive modules last, since a build packs the members the other modules rebuilt. `trees` says where the
  module's files are (`game` and/or `extracted`). Which files a module handles is its own `EXTS`.
- Where `pipeline.mjs` finds the `.mjs` modules: `paths.formats_js` when it is set (`pipeline.py` ignores
  that key); otherwise `<parent>/js/<name>` of `paths.formats` when that folder exists (`tools/formats` ->
  `tools/js/formats`, the skill's `scripts/formats` -> `scripts/js/formats`: the layout of the skill's own
  ports); otherwise `paths.formats` itself (`.mjs` files beside the `.py` ones). Keep the two sets in step:
  a JS run decodes and builds with the `.mjs` modules only, and both must give the same files.
- `containers`: files that are decoded as containers (an embedded signature inside them is expected).
- An archive module keeps each archive's members under `members/` of its decoded folder (the skill's
  `fmt_zip`); another layout is set with `"members": "<dir>"` on that format entry.
- `binaries`: every PE of the game. `matching: false` binaries are rebuilt from their phase-5b text only.
  Optional per binary: `src` (default `<paths.src>/<name>`), `analysis` (`<paths.analysis>/<name>`),
  `ghidra_project` (`<paths.work>/ghidra_<stem>`).
- `toolchain`: the original compiler found in phase 6 (Rich header); `flags` is the default per-unit flag
  set (a unit's `// CLFLAGS:` line overrides it, then env `CLFLAGS`). `wineprefix` -> `msvc.sh`'s
  `MSVC_PREFIX`, optional `vs`/`sdk` -> `MSVC_VS`/`MSVC_SDK`; `sdk_lib` (string or list, relative to the
  prefix's `drive_c`) are the import-library folders `relink.py` gets as `--libdir`. Env `MATCH_PE=<exe>`
  compares with another exe, `SHOW_STUBS=1` also reports `// STUB` functions.
- `run`: how `build --run` starts the game (Wine prefix, which exe, `window`: the title prefix to wait for,
  default the exe's name). It waits for the window in the macOS window list (elsewhere: the process is
  still alive after 30 s) and tries 3 times.

## Where the results go
| Command | Writes |
|---|---|
| intake | `paths.game`, `<work>/installer`, the manifest, `reports/intake.json` |
| inventory | `reports/inventory.json` (gate: every file without a known magic is handled by a configured module or is a binary) |
| archives | `extracted/<archive>/`, `extracted/_members.json` (`--force` to extract again) |
| decode | `decoded/<module>/`, `reports/<tree>/<module>.json`, `reports/completeness.json` |
| recover / names | the binary's `decompiled` / `named` folder and its Ghidra project |
| features | `<analysis>/` of the binary |
| reassemble | `reassembled/<name>/` (split only when missing, or `--split --force`), `reports/reassemble/<name>.json` |
| skeleton | `<src>/` (refuses to overwrite units without `--force`) |
| match | objects in `build/obj/<name>/`, `reports/match/<name>.json` (per unit and function: OK/DIFF/NONMATCHING/STUB) |
| build | `build/game` (or `--out`), scratch in `build/work/`, `reports/build.json` |
| verify | `reports/verify.json` |

The phase-3 completeness gate needs no routing table: a file is covered when exactly one module's report
(reports/<tree>/<module>.json) lists it with its current SHA-256, every game file is either covered or a
configured binary, and no unexpected embedded container signature is found (hits inside the binaries are
listed apart: code constants and strings, covered by phase 4). `pipeline.py completeness` runs this gate alone.

## Generic format decoders in the skill
`scripts/formats/` (Python) and `scripts/js/formats/` (JS) hold decoders that are not game-specific and can
be copied into a project's `tools/formats/` or imported: PNG (with zlib-profile and deflate re-encoding),
WAV (RIFF), ZIP (including the 7-Zip deflate port for archives packed by 7-Zip) and plain text. A project
adds its own modules for its own formats with the same contract (references/data-decoding.md).

## The JavaScript runner
`node scripts/js/pipeline.mjs <command> ...` takes the same commands and options and writes the same files and
JSON summaries; it runs the JavaScript ports only (`intake.mjs`, `inventory.mjs`, `verify.mjs`,
`reassemble.mjs`, `objcmp.mjs`, `hybrid_link.mjs`, `relink.mjs`, ...) plus the same Ghidra wrappers, `msvc.sh`
and Wine, and the project's `.mjs` format modules (above). `build --run` reads the macOS window list through
`osascript` (JavaScript for Automation) instead of ctypes. `scripts/js/parity/pipeline.mjs` runs both runners
on a project, command by command, and compares their output and every file they write;
`scripts/js/parity/formats.mjs` does the same for the generic format modules.

## Validated on
| Game | Files | Data decoders | Binaries | Identical build | Notes |
|---|---|---|---|---|---|
| VVVVVV 2.4.4 (VS2010 SP1) | 283 | 7 modules, 351 files | 2 (exe matched in C++: 1,203 functions) | 283/283, also `--no-original` | source build runs, edits verified in game |
| Wars and Warriors: Joan of Arc 1.0 (VC6) | 9,569 | 27 modules, 9,556 files | 13 (phase-5b text) | 9,569/9,569, also `--no-original` | new game, first run of the generic flow: intake (GOG `{app}` files), 7 decoder groups in parallel, Ghidra + reassembly per binary; C++ matching waits for the user's Visual C++ 6.0 |
