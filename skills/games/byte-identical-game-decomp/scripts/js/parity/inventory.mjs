#!/usr/bin/env node
// Parity test: inventory.py vs js/inventory.mjs.
//
//   node parity/inventory.mjs [--game work/game] [--python python3] [--keep]
//
// Cases (Python and JS run the same command one after the other with the same paths; exit code, stdout,
// stderr, --json file and extracted trees must match):
//   usage errors; census of --game (stdout + --json); --extract of --game; --only filters; an existing non-empty
//   destination with and without --force;
//   a synthetic game tree written by Python's zipfile: stored / deflate / bzip2 / LZMA members, directories,
//   UTF-8-flagged and cp437 names, a ZIP XORed with one byte (under a .pak name), two archives sharing a stem,
//   unsafe names (.., absolute, drive letter), case collisions, a member with a bad CRC, the encryption flag,
//   an unsupported method, a truncated zip, an empty zip, a zip with a comment, 66,000 members (ZIP64 end
//   records), GOG / web-cache zips (not game data), files with other magics, XORed magics, unknown files.
// Prints one JSON summary; exit 0 only when every case is identical.

import fs from 'node:fs'
import path from 'node:path'
import { Harness, argOpt, ROOT, SK, JS } from './intake_harness.mjs'

const h = new Harness('inventory')
const game = path.resolve(ROOT, argOpt(h.argv, '--game', 'work/game'))
const PY = path.join(SK, 'inventory.py'), JSI = path.join(JS, 'inventory.mjs')
const tmp = h.tmp('run')

// run both sides with the same paths; outputs written by each side are moved aside before the other runs
function both(name, args, { json = null, outDir = null, prepare = null } = {}) {
  const side = (s) => {
    if (json) fs.rmSync(json, { force: true })
    if (outDir) fs.rmSync(outDir, { recursive: true, force: true })
    if (prepare) prepare()
    const r = s === 'py' ? h.py(PY, args) : h.js(JSI, args)
    const keep = {}
    if (json && fs.existsSync(json)) { keep.json = json + '.' + s; fs.renameSync(json, keep.json) }
    if (outDir && fs.existsSync(outDir)) { keep.out = outDir + '.' + s; fs.rmSync(keep.out, { recursive: true, force: true }); fs.renameSync(outDir, keep.out) }
    return [r, keep]
  }
  const [p, pk] = side('py')
  const [j, jk] = side('js')
  const files = json ? [[pk.json ?? json + '.py', jk.json ?? json + '.js']] : []
  const trees = outDir ? [[pk.out ?? outDir + '.py', jk.out ?? outDir + '.js', { mtime: false }]] : []
  h.compareRuns(name, p, j, { files, trees })
  for (const k of [pk, jk]) { if (k.json) fs.rmSync(k.json, { force: true }); if (k.out) fs.rmSync(k.out, { recursive: true, force: true }) }
}

// ---- synthetic tree
const syn = path.join(tmp, 'syn')
const gen = h.run(h.python, ['-I', '-c', String.raw`
import io, os, random, sys, zipfile, zlib
root = sys.argv[1]
os.makedirs(root)
rng = random.Random(7)
def p(*a):
    q = os.path.join(root, *a); os.makedirs(os.path.dirname(q), exist_ok=True); return q
def zbytes(entries, comment=b""):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, data, method in entries:
            if name.endswith("/"):
                z.writestr(zipfile.ZipInfo(name), b"")
            else:
                z.writestr(name, data, compress_type=method)
        z.comment = comment
    return b.getvalue()
text = b"".join(b"line %d of some game text\r\n" % i for i in range(3000))
rnd = bytes(rng.randrange(256) for _ in range(50000))
S, D, B, L = zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA
open(p("DATA", "main.zip"), "wb").write(zbytes([("gfx/", b"", S), ("gfx/a.png", b"\x89PNG\r\n\x1a\n" + rnd[:4000], D),
    ("snd/b.ogg", b"OggS" + rnd[:3000], S), ("txt/readme.txt", text, B), ("txt/lzma.bin", rnd + text, L),
    ("noext", b"x", S), ("deep/er/still/file.dat", text[:100], D), ("empty.txt", b"", D)]))
xz = zbytes([("inside/one.txt", text, D), ("inside/two.bin", rnd[:777], S)])
open(p("DATA", "Textos.pak"), "wb").write(bytes(c ^ 0x5A for c in xz))
open(p("DATA", "Textos.dat"), "wb").write(zbytes([("t.txt", b"same stem", S)]))
open(p("DATA", "unsafe.zip"), "wb").write(zbytes([("../evil.txt", b"e", S), ("/abs.txt", b"a", S), ("C:drive.txt", b"c", S),
    ("dir/../x.txt", b"x", S), ("ok.txt", b"1", S), ("OK.TXT", b"2", S), ("a\\b.txt", b"bs", S), ("./dot/./f.txt", b"d", S),
    ("Dir/", b"", S), ("dir/", b"", S)]))
bc = bytearray(zbytes([("good.txt", b"good data", S), ("bad.txt", b"bad data here", S)]))
i = bc.find(b"bad data here"); bc[i] ^= 1
open(p("DATA", "badcrc.zip"), "wb").write(bytes(bc))
enc = bytearray(zbytes([("secret.txt", b"secret", S), ("plain.txt", b"plain", S)]))
for sig in (b"PK\x03\x04", b"PK\x01\x02"):
    j = enc.find(sig)
    off = 6 if sig == b"PK\x03\x04" else 8
    enc[j + off] |= 1
open(p("DATA", "encrypted.zip"), "wb").write(bytes(enc))
um = bytearray(zbytes([("weird.bin", b"method 99", S), ("fine.txt", b"fine", S)]))
for sig, off in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
    j = um.find(sig); um[j + off] = 99
open(p("DATA", "method99.zip"), "wb").write(bytes(um))
open(p("DATA", "truncated.zip"), "wb").write(zbytes([("t.txt", text, D)])[:500])
open(p("DATA", "empty.zip"), "wb").write(zbytes([]))
open(p("DATA", "commented.zip"), "wb").write(zbytes([("c.txt", b"comment test", D)], comment=b"a zip comment PK\x05\x06 inside"))
names = bytearray(zbytes([("caf\xe9-cp437.txt", b"cp", S)]))
open(p("DATA", "names.zip"), "wb").write(zbytes([("naïve-日本.txt", b"utf8 name", S), ("plain/ascii.txt", b"a", D)]))
cp = bytearray(zbytes([("cafe-cp437.txt", b"cp", S)]))
for sig, off in ((b"PK\x03\x04", 30), (b"PK\x01\x02", 46)):
    j = cp.find(sig); cp[j + off + 3] = 0x82          # 'e' -> cp437 0x82
open(p("DATA", "cp437.zip"), "wb").write(bytes(cp))
b = io.BytesIO()
with zipfile.ZipFile(b, "w") as z:
    for k in range(66000):
        z.writestr("m/%05d.txt" % k, b"")
open(p("BIG", "many.dat"), "wb").write(b.getvalue())
open(p("goggame-123.zip"), "wb").write(zbytes([("g.txt", b"gog", S)]))
open(p("webcache.zip"), "wb").write(zbytes([("w.html", b"<html>", D)]))
open(p("goggame-123.hashdb"), "wb").write(zbytes([("hashdb", b"\x0c\x00\x00\x00", S)]))
open(p("img", "real.png"), "wb").write(b"\x89PNG\r\n\x1a\n" + rnd[:100])
open(p("img", "hidden.png"), "wb").write(bytes(c ^ 0x33 for c in b"\x89PNG\r\n\x1a\n" + rnd[:100]))
open(p("img", "hidden.ogg"), "wb").write(bytes(c ^ 0xA5 for c in b"OggS" + rnd[:64]))
open(p("snd", "x.wav"), "wb").write(b"RIFF" + rnd[:50])
open(p("snd", "music.bin"), "wb").write(rnd[:200])
open(p("snd", "noext"), "wb").write(rnd[200:260])
open(p("txt", "a.txt"), "wb").write(text[:500])
open(p("txt", "u16.txt"), "wb").write("﻿hi".encode("utf-16-le"))
open(p("txt", "empty"), "wb").write(b"")
open(p("txt", "short.bin"), "wb").write(b"\x01\x02")
open(p("Zeta", "日本.bin"), "wb").write(b"BZh9" + rnd[:10])
open(p("alpha", "MZ.exe"), "wb").write(b"MZ" + rnd[:100])
`, syn])
if (gen.code !== 0) h.record('python_generator', false, gen.stderr.toString().slice(-2000))

// ---- usage
for (const args of [[], [game, syn], [path.join(tmp, 'nope')], [game, '--json'], [game, '--only'], [game, '--extract'],
  [path.join(game, 'readme.txt')], ['--force']]) {
  both(`usage:${args.join(' ').split(tmp).join('<TMP>').split(ROOT).join('<ROOT>')}`, args)
}

// ---- real game tree
const out = path.join(tmp, 'out')
const js = path.join(tmp, 'inv.json')
if (fs.existsSync(game)) {
  both('game:census', [game])
  both('game:census --json', [game, '--json', js], { json: js })
  both('game:--extract --json', [game, '--extract', out, '--json', js], { json: js, outDir: out })
  both('game:--extract --only *.zip', [game, '--extract', out, '--only', '*.zip'], { outDir: out })
  both('game:--extract --only nomatch', [game, '--extract', out, '--only', 'nomatch'], { outDir: out })
  const pre = () => { fs.mkdirSync(path.join(out, 'data'), { recursive: true }); fs.writeFileSync(path.join(out, 'data', 'old.txt'), 'old') }
  both('game:--extract existing destination', [game, '--extract', out], { outDir: out, prepare: pre })
  both('game:--extract existing destination --force', [game, '--force', '--extract', out], { outDir: out, prepare: pre })
}

// ---- synthetic tree
both('synthetic:census', [syn])
both('synthetic:census --json', [syn, '--json', js], { json: js })
both('synthetic:--extract (all but the 66,000-member archive)', [syn, '--extract', out, '--json', js, '--only', 'DATA/*', '--only', '*.zip',
  '--only', '*.hashdb'], { json: js, outDir: out })
both('synthetic:--extract --only DATA/TEXTOS.*', [syn, '--extract', out, '--only', 'DATA/TEXTOS.*'], { outDir: out })
both('synthetic:--extract --only [!D]*', [syn, '--extract', out, '--only', '[!D]*', '--only', 'BIG/none'], { outDir: out })

h.finish()
