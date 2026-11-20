# Step 1 - installer intake

## Inputs to ask for
- The installer: `setup_<game>_<version>.exe` and, for large games, `setup_<game>_<version>-1.bin`, `-2.bin`
  ... in the same folder. Ask for the folder, not just the exe.
- Or an installed copy of the game (a folder copied from wherever the user installed it). Everything after
  extraction works the same on it.
- Confirmation they own the game (step 0).

## Extract (pure Python, no external tools)
```bash
python3 -I scripts/inno.py info "<path>/setup_game.exe"          # version, languages, files, parts needed
python3 -I scripts/intake.py extract "<path>/setup_game.exe" work/installer
```
`intake.py extract` runs `scripts/inno.py extract`, the skill's own Inno Setup reader:
- Reads the setup loader table, the compressed setup header (CRC-checked per 4 KiB block) and the file
  data (LZMA/LZMA2/zlib/bzip2/stored, Inno's x86 call filter), from the exe or from `-N.bin` slices.
- Verifies every file's stored checksum (SHA-1/MD5/CRC32 by version) and fails on any mismatch; refuses
  path traversal; `--collisions error` by default, so per-language copies cannot overwrite each other
  silently (`--language L` picks one).
- Reassembles GOG Galaxy split files (zlib parts in `{tmp}` entries, joined by the installer script's
  `before_install`/`after_install` calls) and checks their part and whole-file MD5s.
- Output layout (the same as innoextract `--gog --exclude-temp`): Galaxy-era installers put the game
  directly in `<out>/`; older installers put it in `<out>/app/` (extract prints which one). Installer-only
  folders sit beside it: `__redist/` (redistributables), `app/` (on Galaxy-era installers only
  `goggame-<id>.ico`, `webcache.zip`), `commonappdata/`; `{tmp}` files are left out. Copy the game folder
  without them (e.g. `rsync -a --exclude __redist --exclude app --exclude commonappdata`).
- Tested on Inno Setup 5.5.7 and 5.6.2 (unicode) GOG installers, byte-identical to innoextract on all of
  them. Header layouts 4.0.0-6.2.x are implemented from the documented structures but untested; an
  installer that fails the structural checks stops with exit 2 instead of writing garbage.
- Not supported (exit 2 with a message): Inno Setup 6.3+, pre-4.0, encrypted installers, and old GOG
  installers whose `.bin` parts are RAR archives. For those, use an installed copy of the game.
- Never execute the installer.

## Verify (gate)
```bash
python3 -I scripts/intake.py verify-hashdb work/game                 # GOG's own MD5 of every game file
python3 -I scripts/intake.py manifest work/game work/manifest_game.json
python3 -I scripts/intake.py compare work/manifest_game.json manifests/<game>_<ver>.json   # later runs
```
- `verify-hashdb` reads `goggame-<id>.hashdb` (a ZIP holding one file: uint32 header size 12, version 1,
  count, then count x [path[1024] UTF-8 NUL-padded, md5_hex[32]]). Gate: every listed file present with a
  matching MD5. The `goggame-*` files themselves are not listed (a hashdb cannot contain its own hash).
- Games without a hashdb (pre-Galaxy): the installer's per-file checksums, verified during extraction, are
  the gate; if the user also has an installed copy, `compare` the two manifests (`--allow 'unins000.*'`
  and save/config files written after first run).
- Record the manifest (paths, sizes, SHA-256; no game content) in the repo as the reference: later runs on
  another machine prove they started from the same version. If versions differ (GOG patches), say so and
  keep per-version manifests.

## Copy protection (gate)
```bash
python3 -I scripts/protection_check.py work/game --json reports/protection.json
```
Before any analysis, check the game for copy protection and packers: getting around them is unlawful in
itself (`references/legal.md`), whatever the purpose. The script looks at file names of protection
components, PE section names, imported DLLs and a known signature string (SafeDisc, SecuROM, StarForce,
LaserLock, CD-Cops, the Steam DRM wrapper; UPX, ASPack, MPRESS, PECompact, Petite, NsPack, Themida /
WinLicense, VMProtect, Enigma), and at the entry point of every PE (outside every section, in a writable
code section, or in a section with entropy >= 7.2 bits per byte).
- `verdict: clean` (exit 0): continue. Steamworks or GOG Galaxy imports are listed as `info`: APIs, not DRM.
- `verdict: protected` (exit 1): stop. Tell the user what was found and that the skill does not remove,
  bypass or emulate protections; a DRM-free release of the same game (GOG) can be used instead.
- `verdict: review` (exit 1): only heuristic warnings (an unknown packer is likely, not certain). Show them
  to the user and continue only on their decision; never unpack the binary.
`pipeline.py intake` runs it and fails its gate on any finding. GOG releases have passed so far.

## Notes
- Installers sometimes contain several language variants or optional components: check `inno.py info` /
  `inno.py list` and extract the set the user's install uses.
- GOG Galaxy `goggame-<id>.info` (JSON: game id, build id, play tasks) and `.hashdb` are part of the game
  folder; keep them.
