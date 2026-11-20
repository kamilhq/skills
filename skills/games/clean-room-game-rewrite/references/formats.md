# Step 3d - data formats: readers that prove the spec

The rewrite reads the user's game files at run time, so it needs every format the game loads described
exactly. Analysts write that description (`docs/formats/<module>.md`, in their own words, field by field)
and prove it with a **reader**: a Python module that decodes every file into usable form and encodes it
back, byte for byte. A round trip that holds for every file shows the description covers every byte; the
opaque-byte count shows what is still not understood. The readers are analysis tools (they are written
with the game's loader code at hand): they stay on the analysis side and are forbidden to implementers.
The format docs cross over; that is what implementers write their own loaders from.

What may stop short of a round trip: the archive containers themselves (section 6). Their members are
proven by the archive's own checksums when extracted, and rebuilding the container bit for bit (the original
compressor) is not needed for a rewrite that only reads it.

## Table of contents
1. The module contract and why
2. Layout and running the harness
3. What "decoded" must mean
4. Honesty rules: opaque bytes, known codecs, previews
5. Recipes by format family
6. Archives: reading the containers, rebuilding them only if needed
7. Finding field meanings from the game's code
8. Delegation and auditing
9. Completeness

## 1. The module contract and why
```python
# tools/formats/fmt_<module>.py
EXTS = ['.ptx']                                  # lower-case; matched case-insensitively
def decode_to_dir(data: bytes, outdir: str) -> dict:   # returns {"opaque_bytes": N, "notes": [...]}
def encode_from_dir(outdir: str) -> bytes:              # rebuild from outdir ONLY
```
- Decoding into a directory (not an in-memory object) forces the decoded form to be complete on disk: what a
  human or a later tool edits is exactly what the encoder reads. A round trip through memory can hide state.
- `encode_from_dir` must not read the source file, anything outside `outdir`, or a stored hash/copy of the
  original. That is the difference between a decoder and a cache.
- Helpers go in `fmt_<module>_*.py` beside it; the harness puts `tools/formats` on `sys.path`.

## 2. Layout and running the harness
Copy `scripts/verify.py` to `tools/verify.py` and `scripts/pngio.py` to `tools/formats/pngio.py`.
```bash
python3 -I tools/verify.py ptx --src extracted                    # members extracted from archives
python3 -I tools/verify.py pak --src "<GAME_DIR>/DATA"             # the archive files themselves
python3 -I tools/verify.py misc --src "<GAME_DIR>"                 # loose top-level files
```
Writes `decoded/<module>/<relpath>/` and `reports/<module>.json` (per-file SHA-256, opaque bytes, failures
with first differing offset). Exit code is non-zero on any failure. A module is done at `failed == 0` over all
its files. Re-run every module after any shared helper changes.

## 3. What "decoded" must mean
| Data | Decoded representation |
|---|---|
| headers, records, tables | JSON with named fields, enums decoded to names (keep the raw value too if the mapping is inferred) |
| pixels | PNG (8-bit L/LA/RGB/RGBA via pngio), palette as JSON; one PNG per mip level/frame |
| PCM audio | WAV |
| text | UTF-8 `.txt` plus a JSON of encoding facts (original codec, BOM, line-ending runs, trailing bytes) |
| block-structured script/config text | parsed JSON tree in addition to the text |
| meshes | JSON (vertices, faces, UVs, normals, bones, keyframes) plus an OBJ preview |
| floats | stored so `struct.pack('<f', x)` reproduces the bits: `repr(float32)` and hex for NaN/-0.0/denormals |

## 4. Honesty rules
- **opaque_bytes** counts every source byte kept without interpretation: unknown fields, padding with
  non-zero content, uninitialised memory the original tools wrote. Store them as explicitly named fields
  (`unknown_0x10`, `padding_hex`, `<field>_stale_bytes`), never as an anonymous whole-file blob.
- Regenerate instead of storing when you can show the bytes are deterministic (always zero, a function of
  other fields, a checksum). Recompute CRCs, sizes, offsets, counts; do not store them.
- Uninitialised memory is common in 2000s-era exporters: fixed-size name slots filled with the previous
  string, stack garbage, `0xCD`/`0xCC` debug fill. Predict it (previous buffer of the same kind, constant
  fill) and store only the prediction misses. Done well, a 77 MB model set can need as little as 42 KB of
  misses.
- **Known codecs kept verbatim** (DXT1/3/5 blocks, Vorbis/Bink/Smacker packets, IMA-ADPCM when the original
  encoder's choices cannot be reproduced) are not opaque - they are standard, documented encodings - but list
  them in notes and the doc. A kept stream that is already a standard file (`.ogg`, `.mp3`, `.wav`, `.png`)
  needs no preview. For one nobody can open as is, write a stdlib preview decoder in a separate preview
  script whose outputs are never read by encoders: DXT -> PNG, IMA-ADPCM -> WAV, Bink/Smacker audio -> WAV
  (Bink audio can be decoded by hand). No external converters (no ffmpeg).
- Previews must be made from the REBUILT file (encode, check SHA-256, then convert) so they provably derive
  from the decoded data.
- A hand-written preview decoder must get levels/scales right (a Bink audio decoder that was off by
  exactly 2x: DCT-III scale 1/N vs 2/N, is a real example). Check numerically: peak/RMS in range, no clipping, sane duration
  from the container's sample count.

## 5. Recipes by format family
- **Standard images (TGA/BMP/DDS)**: TGA RLE re-encoding must reproduce the original packet boundaries -
  record the packet layout if the encoder's choices differ from yours. BMP: palette, bottom-up rows, row
  padding (can be non-zero garbage). DDS: decode DXT for preview, keep blocks; all mips.
- **WAV**: walk all RIFF chunks in order (fmt, fact, data, LIST, odd-size pad byte). IMA-ADPCM: try
  re-encoding deterministically from the decoded PCM; if the original encoder differs, keep the ADPCM payload.
- **Ogg**: every page, segment table, granule; recompute CRCs; decode the three Vorbis header packets to JSON;
  page layout rules (libogg version) determine page breaks - detect and regenerate rather than store.
- **Engine textures (custom)**: header, pixel format enum (16-bit 565/1555/4444, 32-bit, paletted, DXT),
  mip chain (often hand-authored, not a box filter - store every level), atlas/tile layout.
- **Models/animation**: chunked or versioned record streams; name slots with stale bytes; per-vertex
  records; quaternion order (state it as unknown until code confirms which component is w).
- **Map/terrain grids**: width/height header + 8/16/32-bit cells -> 16-bit grayscale PNG for viewing plus
  the canonical JSON/array; floats bit-exact.
- **Text/scripts**: detect encoding per file (cp1252 vs UTF-16LE+BOM vs mixed); keep CRLF/LF runs,
  trailing whitespace, missing final newline, stray binary bytes. Parse the engine's script syntax to JSON.
- **Fonts**: glyph table JSON + atlas PNG.
- **Bink/Smacker videos**: parse the container (header, frame index, audio track headers), keep frame payloads
  verbatim, recompute the index from sizes; preview audio with a stdlib decoder if worth it (video
  frames stay verbatim).

## 6. Archives: reading the containers, rebuilding them only if needed
For the rewrite, an archive needs a documented container layout (header fields, directory, compression,
obfuscation) and members extracted with their checksums verified (`pipeline.py archives`). That is the gate.
Rebuilding the container byte-identically is optional: worth it only when the user wants to repack (mods).
A rebuild means members as files + a manifest with every header field (local headers, central directory,
extra fields incl. Info-ZIP UT/SD, attributes, DOS dates, comments, member order) and the same compressed
streams. Order of attempts then:
1. Python zlib at levels 1-9 / memLevel / strategy - often reproduces only a subset.
2. Identify the original packer from `version made by`, extra fields, block structure (non-final deflate
   blocks ending at 32,767 symbols or multiples of 4,096 = Info-ZIP `ct_tally` heuristics), and port its
   deflate bit-exactly (one real case: Info-ZIP 2.3 and a "2.0/MS-DOS" packer, three parameter profiles, a
   cross-member 64 KB window and an undocumented lazy-match "far rule"; every stream regenerated).
3. Only as a last resort keep a member's raw compressed stream, counted and listed.
Whole-file obfuscation (e.g. XOR 0xAB) is part of the archive layer: decode, record the key, re-apply.

## 7. Finding field meanings from the game's code
Grep the step-3a decompile for the extension string or the magic, find the loader, and read how it parses:
field sizes, versions, flags and which values are ignored (ignored fields are often where stale bytes live).
Cite the function address in the reader's notes (analysis side), never in `docs/formats/` (it crosses
to the implementers: describe fields, not the loader). Empirical analysis across ALL files of a type (value histograms,
correlation with file size, constant fields) complements the code.

## 8. Delegation and auditing
One builder agent per module (formats that share code go together), then an independent skeptic, then a
fixer if rejected (max 2 rounds) - prompts in `orchestration.md`. The skeptic must: re-run the harness into a
separate out/report dir; read the module for leaks and under-reported opaque bytes; mutation-test (change one
pixel/number/char in a copy of the decoded folder, re-encode, confirm the change lands exactly where expected
and a pristine copy still rebuilds identically); open decoded images with the Read tool (noise/stripes =
fail); check plausibility of numbers; check the format doc matches the reader; run `cleanroom.py lint` on
the format doc.

## 9. Completeness
A final critic enumerates every file under the game folder and `extracted/`, maps it to a module by
extension (case-insensitive), confirms each is `ok` in its report with the current SHA-256, and looks for
nested containers (embedded ZIP/DDS/RIFF/Ogg/PNG signatures, extensionless files). Out-of-scope files (exe,
dll, pdf manual) are listed explicitly as such - code goes to step 3a.
