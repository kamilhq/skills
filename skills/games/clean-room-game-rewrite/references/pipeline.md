# The pipeline runner: one project config, the analysis steps

`scripts/pipeline.py` (and its port `scripts/js/pipeline.mjs`, same commands and results) runs steps 1-3 of
the skill (the analysis side) on a project folder from a single config file, `decomp.json` at the project root. Everything that
differs between games lives in that file and in the project's own format decoders; the runner and the
tools it calls are generic.

```bash
P=.claude/skills/clean-room-game-rewrite/scripts
python3 -I $P/pipeline.py init --game "Name 1.0"            # decomp.json skeleton, .gitignore, folders
python3 -I $P/pipeline.py intake <setup.exe>                # step 1: extract + manifest + GOG hashdb + copy-protection gate
python3 -I $P/pipeline.py inventory                         # step 2: census -> reports/inventory.json
python3 -I $P/pipeline.py archives                          # extract the configured archives -> extracted/ (member checksums)
python3 -I $P/pipeline.py recover [--binary B]              # step 3a: Ghidra recovery + decompile per binary
python3 -I $P/pipeline.py features [--binary B]             # step 3b input: features/chunks for naming agents
python3 -I $P/pipeline.py names [--binary B]                # step 3b: apply analysis/<B>/names_apply.json -> decompiled_named
python3 -I $P/pipeline.py decode [--module M]               # step 3d: round trip of every reader, then the completeness gate
python3 -I $P/pipeline.py status                            # one table: every step, its gate, done or not
```
`--project DIR` (default: current directory) selects the project. Each command prints a JSON summary and
exits 0 only when its gate holds.

## decomp.json
```json
{
  "game": "Game 1.0",
  "paths": {"game": "work/game", "extracted": "extracted", "decoded": "decoded", "reports": "reports",
            "formats": "tools/formats", "analysis": "analysis", "build": "build"},
  "archives": ["assets.zip", "goggame-1234567890.hashdb"],
  "formats": [
    {"module": "text",   "trees": ["game"]},
    {"module": "png",    "trees": ["game", "extracted"]},
    {"module": "wav",    "trees": ["extracted"]},
    {"module": "zip",    "trees": ["game"]}
  ],
  "containers": ["assets.zip", "goggame-1234567890.hashdb", "music.pak"],
  "binaries": [
    {"name": "Game", "file": "Game.exe", "decompiled": "decompiled_exe", "named": "decompiled_named_exe"},
    {"name": "SDL2", "file": "SDL2.dll", "decompiled": "decompiled_sdl2", "named": "decompiled_named_sdl2"}
  ],
  "rewrite": {"...": "the oracle, the toolchain, the clean room: harness.md, toolchains.md, cleanroom.md"}
}
```
- `paths` are relative to the project (absolute paths work too); any can be omitted (these are the
  defaults). Two more: `work` (default `work`: the installer extraction `work/installer`, Ghidra projects
  `work/ghidra_<stem>`) and `manifest` (default `manifests/game.json`: `intake` writes the SHA-256
  manifest there, or compares a fresh extraction with it when it exists).
- `archives`: files of the game folder that are archives (ZIP-based) to extract into `extracted/<name>/` for
  reading their members (each member's CRC is checked). A reader for the archive file itself is optional
  (`formats.md` section 6); without one, list the archive under `containers`.
- `formats`: the project's format readers (`<paths.formats>/fmt_<module>.py` / `.mjs`). `trees` says where the
  module's files are (`game` and/or `extracted`). Which files a module handles is its own `EXTS`.
- Where `pipeline.mjs` finds the `.mjs` modules: `paths.formats_js` when it is set (`pipeline.py` ignores
  that key); otherwise `<parent>/js/<name>` of `paths.formats` when that folder exists (`tools/formats` ->
  `tools/js/formats`, the skill's `scripts/formats` -> `scripts/js/formats`: the layout of the skill's own
  ports); otherwise `paths.formats` itself (`.mjs` files beside the `.py` ones). Keep the two sets in step:
  a JS run decodes with the `.mjs` modules only, and both must give the same files.
- `containers`: files that are decoded as containers (an embedded signature inside them is expected).
- An archive module keeps each archive's members under `members/` of its decoded folder (the skill's
  `fmt_zip`); another layout is set with `"members": "<dir>"` on that format entry.
- `binaries`: every PE of the game. Optional per binary: `analysis` (`<paths.analysis>/<name>`),
  `ghidra_project` (`<paths.work>/ghidra_<stem>`).
- `rewrite`: everything after the analysis (the oracle, the trace contract, libraries, the toolchain, the
  clean-room settings); read by the rewrite-side scripts, not by `pipeline.py`.

## Where the results go
| Command | Writes |
|---|---|
| intake | `paths.game`, `<work>/installer`, the manifest, `reports/intake.json`, `reports/protection.json` |
| inventory | `reports/inventory.json` (gate: every file without a known magic is handled by a configured module or is a binary) |
| archives | `extracted/<archive>/`, `extracted/_members.json` (`--force` to extract again) |
| decode | `decoded/<module>/`, `reports/<tree>/<module>.json`, `reports/completeness.json` |
| recover / names | the binary's `decompiled` / `named` folder and its Ghidra project |
| features | `<analysis>/` of the binary |

The step-3d completeness gate needs no routing table: a file is covered when exactly one module's report
(reports/<tree>/<module>.json) lists it with its current SHA-256, every game file is either covered or a
configured binary, and no unexpected embedded container signature is found (hits inside the binaries are
listed apart: code constants and strings, covered by step 3a). `pipeline.py completeness` runs this gate alone.

## Generic format decoders in the skill
`scripts/formats/` (Python) and `scripts/js/formats/` (JS) hold decoders that are not game-specific and can
be copied into a project's `tools/formats/` or imported: PNG (with zlib-profile and deflate re-encoding),
WAV (RIFF), ZIP (including the 7-Zip deflate port for archives packed by 7-Zip) and plain text. A project
adds its own modules for its own formats with the same contract (references/formats.md).

## The JavaScript runner
`node scripts/js/pipeline.mjs <command> ...` takes the same commands and options and writes the same files and
JSON summaries; it runs the JavaScript ports only (`intake.mjs`, `inventory.mjs`, `verify.mjs`,
`code_coverage_check.mjs`, `build_features.mjs`, ...) plus the same Ghidra wrappers, and the project's `.mjs`
format modules (above). `scripts/js/parity/pipeline.mjs` runs both runners
on a project, command by command, and compares their output and every file they write;
`scripts/js/parity/formats.mjs` does the same for the generic format modules.

## Validated on
| Game | Files | Readers | Binaries | Notes |
|---|---|---|---|---|
| a 2010s SDL2 game (VS2010 SP1) | about 300 | 7 modules, about 350 files, all round trips identical | 2, complete recovery and names | the analysis steps of this runner, before the clean-room rewrite existed |
| a 2000s Direct3D game (Visual C++ 6.0) | about 9,500 | 27 modules, about 9,500 files | 13, complete recovery | intake of GOG `{app}` files, 7 reader groups in parallel |
