# Generic format decoders (phase 3)

Decoders that are not tied to one game, with the contract of `scripts/verify.py`
(`EXTS`, `decode_to_dir(data, outdir)`, `encode_from_dir(outdir)`; references/data-decoding.md).
Copy the ones you need into the project's `tools/formats/` (they import each other by name, so copy a
module together with its helpers) and add the project's own modules beside them.

| Module | Handles | Needs | Notes |
|---|---|---|---|
| `fmt_png.py` | `.png` | `pngio.py`, `fmt_png_zlib.py`, `fmt_png_deflate.py` | every chunk decoded; the IDAT stream is regenerated from the pixels with the zlib profile found on decode (C zlib levels/strategies, or the pure-Python deflate port for non-zlib encoders). Depends on the zlib build (recorded per file) |
| `fmt_wav.py` | `.wav` | - | canonical PCM `audio.wav` + RIFF chunk facts |
| `fmt_zip.py` | `.zip`, GOG `.hashdb` | `fmt_zip_7zdeflate.py` | every header field decoded, members as files under `members/`; deflate streams regenerated with zlib profiles or the bit-exact p7zip 9.20 deflate port (slow: about 6 min for 60 MB); streams nothing reproduces are kept as `raw_streams/` (opaque) |
| `fmt_text.py` | template: edit `EXTS` | - | UTF-8 text with LF + the facts (encoding, BOM, line-ending runs) that give the bytes back |
| `pngio.py` | - | - | stdlib PNG reader/writer (same as `scripts/pngio.py`) |

The pipeline runner (`scripts/pipeline.py`, references/pipeline.md) finds a project's modules in
`paths.formats` of `decomp.json` (default `tools/formats`); an archive module keeps its members under
`members/` of the archive's decoded folder, which the `build` command fills with the rebuilt members before
packing.

Each module has a JavaScript port with the same name in `scripts/js/formats/` (`.mjs`; same decoded files,
same rebuilt bytes; `js/parity/formats.mjs` checks them); a project that runs `js/pipeline.mjs` keeps its
`.mjs` copies in `tools/js/formats/` (references/pipeline.md).

These were first written for VVVVVV 2.4.4 (351 files identical); behaviour is unchanged from there, only
the docstrings and `fmt_text.EXTS` were made generic. Known limits: the 7-Zip port covers the multi-pass
optimal-parsing mode only; PNG re-encoding is tied to the zlib build the decode ran with.
