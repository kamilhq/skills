# JavaScript ports of the skill's scripts

Every Python script of this skill has a JavaScript (Node.js) port here, with the same name (`.mjs`), the
same command line, and the same results. The Python scripts stay: both are maintained until the ports have
shown parity on several projects. The Ghidra scripts (`ghidra/*.java`, run by Ghidra headless) and the shell
wrappers (`*.sh`) are not ported: Ghidra has no JavaScript scripting.

## Rules for every port
- **Runtime:** Node.js 20 or newer, ES modules (`.mjs`), only `node:` built-ins (`fs`, `path`, `zlib`,
  `crypto`, `child_process`, `os`, `url`). No npm packages, no `package.json` dependencies. Algorithms that
  Python's standard library provides and Node's does not (LZMA, bzip2, difflib) are ported into `lib/`.
- **Same interface:** subcommands, arguments, flags, defaults, stdout/stderr text, exit codes, and every
  file written must match the Python script. A port is done when its parity test shows identical output on
  real inputs.
- **Bytes, not strings:** binary data is `Buffer`/`Uint8Array`; read integers with `DataView` or
  `buf.readUInt32LE`; Python's `struct` formats map 1:1. Use `BigInt` only where Python values exceed 2^53.
- **JSON:** always through `lib/pyjson.mjs` (`dumps`, `dump`, `parse`, `load`). It reproduces
  `json.dumps` byte for byte (indent, `ensure_ascii`, float repr, key order) and keeps int/float and big
  integers when reading. Use `PyDict`/`Map` where keys may look like integers (JS reorders those in plain
  objects).
- **Order:** where Python iterates a `dict`, keep insertion order; where it sorts, sort with the same key
  (Python compares strings by code point: use `(a < b ? -1 : a > b ? 1 : 0)`, not `localeCompare`). Python
  `set` iteration of strings is randomized per run; if a Python script's output depends on it, note it in the
  parity test and compare in a canonical order.
- **zlib:** `node:zlib` with the same parameters (level, `windowBits`, `memLevel`, `strategy`). Byte-identical
  deflate output needs the same zlib build: check `process.versions.zlib` against Python's
  `zlib.ZLIB_RUNTIME_VERSION`. The hand-written deflate ports do not depend on zlib.
- **Text output:** Python `print` writes `\n`; `hex(n)` is `'0x' + n.toString(16)`; `f'{n:08x}'` is
  `n.toString(16).padStart(8, '0')`; Python `round()` is banker's rounding.
- **Running other tools:** `child_process.spawnSync` with the same arguments the Python script uses (Wine,
  `msvc.sh`, Ghidra wrappers).

## What is here
| Port | Python original | Library helpers it adds |
|---|---|---|
| `inno.mjs`, `intake.mjs`, `inventory.mjs` | inno.py, intake.py, inventory.py | `lib/lzma.mjs` (raw LZMA1/LZMA2 decoder), `lib/bzip2.mjs`, `lib/zipfile.mjs` (zipfile reading) |
| `verify.mjs`, `pngio.mjs` | verify.py, pngio.py | `lib/pyzlib.mjs` (zlib with Python's buffer/flush behaviour) |
| `objcmp.mjs`, `objcmp_selftest.mjs` | objcmp.py, objcmp_selftest.py | `lib/difflib.mjs` (SequenceMatcher) |
| `reassemble.mjs`, `peek.mjs`, `rich_header.mjs`, `phase6_skeleton.mjs`, `code_coverage_check.mjs`, `build_features.mjs` | same names | |
| `hybrid_link.mjs`, `relink.mjs` | hybrid_link.py, relink.py | |
| `pipeline.mjs` | pipeline.py (runs the JS tools; `.mjs` format modules as in references/pipeline.md) | |
| `formats/` (`fmt_png`, `fmt_png_zlib`, `fmt_png_deflate`, `pngio`, `fmt_wav`, `fmt_zip`, `fmt_zip_7zdeflate`, `fmt_text`) | `scripts/formats/*.py` | |

Shared Python-behaviour helpers: `lib/pyjson.mjs` (json), `lib/pyargparse.mjs` and `lib/pyshim.mjs` (argparse
parsing, usage/help/error text), `lib/pytools.mjs` and `lib/pycompat.mjs` (repr, rounding, path and string
functions, codecs). The ports were written in parallel, so these overlap; merging them is a cleanup for later
and must keep every parity test passing.

Project tools follow the same pattern in the project (e.g. `tools/js/` - `match.mjs`, `match_all.mjs`,
`build_game.mjs`, `verify.mjs`, `extract_archives.mjs`, `completeness.mjs`, `formats/fmt_*.mjs`).

## Parity tests
`parity/<script>.mjs` runs the Python script and its port on the same inputs and compares exit code, stdout,
and every output file byte for byte. Each prints one JSON summary:
`{"script", "cases", "identical", "different": [...], "python_seconds", "js_seconds"}` and exits 0 only when
everything is identical. `node parity/run_all.mjs [--quick] [--installer setup_x.exe ...] [--only NAME] [--skip NAME]` runs them all,
the skill's and the project's (`tools/js/parity`), from the project root.

Inputs are the project's local, git-ignored files (the user's own game), so the tests are not committed with
data: they take the paths from arguments or from the project layout described in the skill.

## Known differences (all tested outputs are identical)
- **Uncaught exceptions:** the JS prints the exception type and message Python would end with, and the same
  exit code, but not Python's traceback frames.
- **Help/usage text:** reproduced verbatim at Python's default 80 columns, naming the `.py` script. Python
  reflows it when `COLUMNS` is set; the JS does not.
- **Error messages for broken JSON inputs** come from `pyjson`'s parser, not Python's (same exit code).
- **Python `set` order:** where a Python script's output order depends on iterating a set of strings
  (randomized per run), the JS uses first-occurrence order; the parity tests compare those spots in
  canonical order. Known: `code_coverage_check` `summary.gap_nonpad_bytes_by_kind`.
- **Internal zlib handle:** `lib/pyzlib.mjs`, `inno.mjs` and `lib/zipfile.mjs` use node:zlib's internal
  `_handle.writeSync` for synchronous streaming and Python's exact output buffer sizes (needed for
  byte-identical level-0 PNG output). If a future Node removes it they fail with a clear error.
- **pipeline.mjs:** its log (stderr) names the JS tools in the `+ <command>` lines (`node x.mjs` and the
  same arguments, where Python shows `python3 -I x.py`); a missing format module is reported with its
  `.mjs` path; `build`'s scratch folder for archives is `build/work/archives_XXXXXX` (6 random characters,
  Python 8; removed at the end). The log lines of the parallel jobs of `decode` and `match` come in
  completion order on both sides.
- **Timestamps:** on macOS, `utimes` has microsecond resolution; Python sets nanoseconds. Installers so far
  store whole seconds.
- **Speed:** the pure-JS LZMA and bzip2 decoders are about 4x slower than Python's C libraries (installer
  extraction overall takes about the same time). Everything else is as fast or much faster: on one game, the
  7-Zip deflate of its 60 MB data archive took 6 s instead of 6 min, PNG re-encoding is 18x faster, and a full game build
  (tools/js/build_game.mjs) takes about 4.5 min instead of 10.
