#!/usr/bin/env node
// Parity test: js/lib/bzip2.mjs against Python 3.9's bz2.BZ2Decompressor (libbzip2 1.0.8).
//
//   node parity/bzip2.mjs [--python python3] [--keep]
//
// Streams: data (empty, 1 byte, text, random 800 KB / 2.5 MB, zeros, every run length 1..300, all byte values,
// text+random mix, a slice of work/game/SDL2.dll when present) compressed by Python's bz2 at levels 1-9;
// header/end-marker error streams; and randomised blocks (bzip2 0.9.0 style): the randomised bit is set in
// every block of some streams, the stream is decoded by the JS port without CRC checks, and the block and
// combined CRCs are patched to that output - Python must then accept it with the same bytes (checks the
// BZ2_rNums table and the randomisation logic against libbzip2).
// Modes per stream (one case each; Python and JS run the same steps): whole, chunked (fixed plans of input
// pieces and max_length), bytewise (tail fed one byte at a time: output after every prefix, eof and
// needs_input), cuts (stream[:k]), junk (trailing bytes -> unused_data), two (two streams back to back ->
// the second is unused_data), flips (single-bit corruptions -> output or error).
// Prints one JSON summary; exit 0 only when every case is identical.

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { BZ2Decompressor } from '../lib/bzip2.mjs'
import { parse } from '../lib/pyjson.mjs'
import { Harness, sha256, ROOT } from './intake_harness.mjs'

const h = new Harness('bzip2')
const work = h.tmp('work')

const PY = String.raw`
import bz2, hashlib, json, os, random, sys, time
mode, out, root = sys.argv[1], sys.argv[2], sys.argv[3]
H = lambda b: hashlib.sha256(b).hexdigest()
pysec = [0.0]

def mk(): return bz2.BZ2Decompressor()
def guard(fn):
    t0 = time.perf_counter()
    try:
        return fn()
    except (OSError, EOFError, ValueError) as e:
        return {"error": "%s: %s" % (type(e).__name__, e)}
    finally:
        pysec[0] += time.perf_counter() - t0

def whole(c):
    d = mk(); o = d.decompress(c)
    return {"len": len(o), "sha": H(o), "eof": d.eof, "needs_input": d.needs_input, "unused": H(d.unused_data), "ulen": len(d.unused_data)}

PLANS = {"small": [(1, 7), (997, 1), (13, 4096), (4096, 100), (64, -1), (500, 33)], "inno": [(1 << 20, 4 << 20)]}
def chunked(c, plan):
    d = mk(); pos = 0; k = 0; total = 0; h = hashlib.sha256()
    while not d.eof:
        n, m = plan[k % len(plan)]; k += 1
        if d.needs_input:
            if pos >= len(c): break
            piece = c[pos:pos + n]; pos += len(piece)
        else:
            piece = b""
        o = d.decompress(piece, m)
        h.update(o); total += len(o)
    return {"len": total, "sha": h.hexdigest(), "eof": d.eof, "needs_input": d.needs_input, "ulen": len(d.unused_data), "consumed": pos}

def bytewise(c, tail):
    d = mk(); start = max(0, len(c) - tail)
    o = d.decompress(c[:start]); lens = [len(o)]; flags = []
    for i in range(start, len(c)):
        if d.eof: break
        o = d.decompress(c[i:i + 1]); lens.append(len(o)); flags.append(int(d.eof) * 2 + int(d.needs_input))
    return {"start": start, "lens": H(json.dumps(lens).encode()), "flags": H(json.dumps(flags).encode()), "total": sum(lens), "eof": d.eof}

def cuts(c):
    res = []; n = len(c)
    for k in sorted(set([0, 1, 3, 4, 5, 10, n // 3, n // 2, n - 6, n - 1]) & set(range(n + 1))):
        try:
            d = mk(); o = d.decompress(c[:k]); res.append([k, len(o), H(o), d.eof, d.needs_input])
        except OSError as e:
            res.append([k, "error", str(e)])
    return {"cuts": res}

def flips(c, seed):
    r = random.Random(seed); res = []
    for _ in range(6):
        if not c: break
        pos = r.randrange(len(c)); bit = r.randrange(8)
        c2 = bytearray(c); c2[pos] ^= 1 << bit
        try:
            d = mk(); o = d.decompress(bytes(c2)); res.append([pos, bit, len(o), H(o), d.eof])
        except (OSError, EOFError) as e:
            res.append([pos, bit, "error", str(e)])
    return {"flips": res}

def decode_all(files, flipsets):
    results = []
    for i, fn in enumerate(files):
        c = open(os.path.join(out, fn), "rb").read()
        r = {"whole": guard(lambda: whole(c)), "chunked_small": guard(lambda: chunked(c, PLANS["small"])),
             "chunked_inno": guard(lambda: chunked(c, PLANS["inno"])),
             "bytewise": guard(lambda: bytewise(c, 20000 if len(c) < 20000 else 3000)), "cuts": guard(lambda: cuts(c))}
        if r["whole"].get("eof"):
            r["junk"] = guard(lambda: whole(c + b"JUNK\x00\xffDATA"))
            r["two"] = guard(lambda: whole(c + c))
        if flipsets and len(c) <= 300000:
            r["flips"] = guard(lambda: flips(c, i))
        results.append(r)
    return results

if mode == "gen":
    rng = random.Random(4242)
    WORDS = b"the quick brown fox jumps over lazy dog lorem ipsum dolor sit amet setup data inno gog galaxy".split()
    def text(n): return b" ".join(rng.choice(WORDS) for _ in range(n // 5))[:n]
    runs = b"".join(bytes([i % 251]) * i for i in range(1, 301)) * 3
    kinds = {"empty": b"", "byte": b"A", "text": text(300000), "random800k": rng.randbytes(800000),
             "random2m": rng.randbytes(2500000), "zeros": bytes(3 << 20), "runs": runs, "all256": bytes(range(256)) * 400,
             "mixed": b"".join(text(100000) if k % 2 == 0 else rng.randbytes(100000) for k in range(10))}
    dll = os.path.join(root, "work", "game", "SDL2.dll")
    if os.path.isfile(dll):
        kinds["exe"] = open(dll, "rb").read()[:1200000]
    streams = []
    def add(name, c):
        fn = "b%04d.bin" % len(streams); open(os.path.join(out, fn), "wb").write(c); streams.append({"name": name, "file": fn, "size": len(c)})
    for k, data in kinds.items():
        for lvl in (1, 5, 9):
            add("%s/l%d" % (k, lvl), bz2.compress(data, lvl))
    for lvl in (2, 3, 4, 6, 7, 8):
        add("text/l%d" % lvl, bz2.compress(kinds["text"], lvl))
    for name, c in (("hdr_BZh0", b"BZh0"), ("hdr_BZh", b"BZh"), ("hdr_B", b"B"), ("hdr_XZh9", b"XZh9"),
                    ("hdr_badblock", b"BZh91AY&SX"), ("hdr_badmagic2", b"BZh9\x31\x41\x00"),
                    ("empty_ok", b"BZh9\x17rE8P\x90\x00\x00\x00\x00"), ("empty_badcrc", b"BZh9\x17rE8P\x90\x00\x00\x00\x01"),
                    ("end_bad", b"BZh9\x17rE8Q")):
        add("crafted/" + name, c)
    res = decode_all([s["file"] for s in streams], True)
    json.dump({"streams": streams, "results": res, "seconds": pysec[0]}, open(os.path.join(out, "py.json"), "w"))
else:
    files = json.load(open(os.path.join(out, "rand.json")))
    res = decode_all(files, False)
    json.dump({"results": res, "seconds": pysec[0]}, open(os.path.join(out, "py_rand.json"), "w"))
`
fs.writeFileSync(path.join(work, 'gen.py'), PY)

const plain = (v) => JSON.parse(JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? Number(x) : x instanceof Map ? Object.fromEntries(x) : x)))
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b)
const H = sha256

function runPy(mode) {
  const r = h.run(h.python, ['-I', path.join(work, 'gen.py'), mode, work, ROOT])
  if (r.code !== 0) {
    h.record(`python_${mode}`, false, r.stderr.toString().slice(-2000))
    h.finish()
    process.exit()
  }
}

let jsSec = 0
function guard(fn) {
  const t0 = process.hrtime.bigint()
  try {
    return fn()
  } catch (e) {
    if (e && (e.name === 'OSError' || e.name === 'EOFError')) return { error: `${e.name}: ${e.message}` }
    throw e
  } finally { jsSec += Number(process.hrtime.bigint() - t0) / 1e9 }
}
const mk = () => new BZ2Decompressor()
function whole(c) {
  const d = mk(); const o = d.decompress(c)
  return { len: o.length, sha: H(o), eof: d.eof, needs_input: d.needs_input, unused: H(d.unused_data), ulen: d.unused_data.length }
}
function chunked(c, plan) {
  const d = mk()
  let pos = 0, k = 0, total = 0
  const hs = crypto.createHash('sha256')
  while (!d.eof) {
    const [n, m] = plan[k % plan.length]; k++
    let piece
    if (d.needs_input) {
      if (pos >= c.length) break
      piece = c.subarray(pos, pos + n); pos += piece.length
    } else piece = Buffer.alloc(0)
    const o = d.decompress(piece, m)
    hs.update(o); total += o.length
  }
  return { len: total, sha: hs.digest('hex'), eof: d.eof, needs_input: d.needs_input, ulen: d.unused_data.length, consumed: pos }
}
const pyJson = (a) => '[' + a.join(', ') + ']'
function bytewise(c, tail) {
  const d = mk()
  const start = Math.max(0, c.length - tail)
  let o = d.decompress(c.subarray(0, start))
  const lens = [o.length], flags = []
  for (let i = start; i < c.length; i++) {
    if (d.eof) break
    o = d.decompress(c.subarray(i, i + 1)); lens.push(o.length); flags.push((d.eof ? 2 : 0) + (d.needs_input ? 1 : 0))
  }
  return { start, lens: H(Buffer.from(pyJson(lens))), flags: H(Buffer.from(pyJson(flags))), total: lens.reduce((a, b) => a + b, 0), eof: d.eof }
}
function cuts(c) {
  const n = c.length
  const ks = [...new Set([0, 1, 3, 4, 5, 10, Math.floor(n / 3), Math.floor(n / 2), n - 6, n - 1])].filter((k) => k >= 0 && k <= n).sort((a, b) => a - b)
  const res = []
  for (const k of ks) {
    try {
      const d = mk(); const o = d.decompress(c.subarray(0, k))
      res.push([k, o.length, H(o), d.eof, d.needs_input])
    } catch (e) {
      if (e.name !== 'OSError') throw e
      res.push([k, 'error', e.message])
    }
  }
  return { cuts: res }
}
function flipsLike(c, pyFlips) {
  const res = []
  for (const [pos, bit] of pyFlips) {
    const c2 = Buffer.from(c); c2[pos] ^= 1 << bit
    try {
      const d = mk(); const o = d.decompress(c2)
      res.push([pos, bit, o.length, H(o), d.eof])
    } catch (e) {
      if (e.name !== 'OSError' && e.name !== 'EOFError') throw e
      res.push([pos, bit, 'error', e.message])
    }
  }
  return { flips: res }
}
function decodeJs(c, py) {
  const js = { whole: guard(() => whole(c)), chunked_small: guard(() => chunked(c, PLANS.small)),
    chunked_inno: guard(() => chunked(c, PLANS.inno)), bytewise: guard(() => bytewise(c, c.length < 20000 ? 20000 : 3000)),
    cuts: guard(() => cuts(c)) }
  if (py.junk) js.junk = guard(() => whole(Buffer.concat([c, Buffer.from('JUNK\x00\xffDATA', 'latin1')])))
  if (py.two) js.two = guard(() => whole(Buffer.concat([c, c])))
  if (py.flips) js.flips = guard(() => flipsLike(c, py.flips.flips))
  return js
}
const PLANS = { small: [[1, 7], [997, 1], [13, 4096], [4096, 100], [64, -1], [500, 33]], inno: [[1 << 20, 4 << 20]] }

// ---- base streams
runPy('gen')
const pyRes = parse(fs.readFileSync(path.join(work, 'py.json'), 'utf8'))
let pySec = Number(pyRes.get('seconds'))
const streams = pyRes.get('streams')
streams.forEach((s, i) => {
  const c = fs.readFileSync(path.join(work, s.get('file')))
  const py = plain(pyRes.get('results')[i])
  const js = decodeJs(c, py)
  for (const mode of Object.keys(py)) {
    const ok = eq(py[mode], js[mode])
    h.record(`${s.get('name')}:${mode}`, ok, ok ? null : { python: py[mode], js: js[mode] })
  }
})

// ---- randomised streams: set the randomised bit in every block, patch CRCs to the JS output
const setBits = (b, bit, n, v) => {
  for (let k = 0; k < n; k++) {
    const p = bit + k, m = 0x80 >> (p & 7)
    if ((v >>> (n - 1 - k)) & 1) b[p >> 3] |= m; else b[p >> 3] &= ~m
  }
}
const randFiles = []
for (const s of streams) {
  const name = s.get('name')
  if (!/^(random800k|text|exe|mixed|all256)\/l[159]$/.test(name)) continue
  const c = Buffer.from(fs.readFileSync(path.join(work, s.get('file'))))
  const probe = mk(); probe._blocks = []; probe.decompress(c)
  for (const b of probe._blocks) setBits(c, b.start + 48 + 32, 1, 1)
  const d = mk(); d._ignoreCrc = true; d._blocks = []
  d.decompress(c)
  let combined = 0
  for (const b of d._blocks) {
    setBits(c, b.start + 48, 32, b.crc)
    combined = (((combined << 1) | (combined >>> 31)) ^ b.crc) >>> 0
  }
  setBits(c, d._endBitPos + 48, 32, combined)
  const fn = `rand_${s.get('file')}`
  fs.writeFileSync(path.join(work, fn), c)
  randFiles.push([name, fn])
}
fs.writeFileSync(path.join(work, 'rand.json'), JSON.stringify(randFiles.map((x) => x[1])))
runPy('rand')
const pyRand = parse(fs.readFileSync(path.join(work, 'py_rand.json'), 'utf8'))
pySec += Number(pyRand.get('seconds'))
randFiles.forEach(([name, fn], i) => {
  const c = fs.readFileSync(path.join(work, fn))
  const py = plain(pyRand.get('results')[i])
  const js = decodeJs(c, py)
  for (const mode of Object.keys(py)) {
    const ok = eq(py[mode], js[mode])
    h.record(`randomised/${name}:${mode}`, ok, ok ? null : { python: py[mode], js: js[mode] })
  }
  // the randomised decode must be accepted by libbzip2 (no error) for the table check to mean anything
  if (py.whole.error) h.record(`randomised/${name}:accepted_by_libbzip2`, false, py.whole)
})
h.pySec = pySec
h.jsSec = jsSec
h.finish({ streams: streams.length, randomised_streams: randFiles.length })
