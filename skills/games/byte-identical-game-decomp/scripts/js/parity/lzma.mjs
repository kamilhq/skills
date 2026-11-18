#!/usr/bin/env node
// Parity test: js/lib/lzma.mjs (raw LZMA1 / LZMA2) against Python 3.9's lzma.LZMADecompressor(FORMAT_RAW).
//
//   node parity/lzma.mjs [--installer setup.exe ...] [--python python3] [--keep]
//
// Streams: data (empty, 1 byte, text, random 64 KiB / 3 MiB, zeros, records, text+random mix, and a slice of
// work/game/SDL2.dll when present) compressed by Python's lzma in FORMAT_RAW with LZMA1 and LZMA2 filters over
// presets 0-9 (+extreme), lc/lp/pb combinations, dictionary sizes 4 KiB .. 16 MiB, match finders hc3/hc4/bt2/
// bt3/bt4, fast/normal modes, nice_len 8/273; invalid filter options; and, with --installer, the LZMA1 header
// blocks and LZMA2 chunks inno.py reads from each installer (captured by wrapping its decompressors).
// Modes per stream, each one case (Python and JS run the same steps):
//   whole     decompress(all) -> output, eof, needs_input, unused_data, or the error text
//   chunked   input pieces and max_length from a fixed plan, fed while needs_input, drained otherwise
//   bytewise  the stream's tail fed one byte at a time: output length after every byte (= output for every
//             prefix, i.e. liblzma's resumable decoding), eof and needs_input after every byte
//   cuts      decompress(stream[:k]) for a few k
//   junk      stream + trailing bytes -> unused_data
//   flips     single-bit corruptions -> output or error text
// Prints one JSON summary; exit 0 only when every case is identical.

import fs from 'node:fs'
import crypto from 'node:crypto'
import path from 'node:path'
import { LZMADecompressor, FORMAT_RAW } from '../lib/lzma.mjs'
import { parse } from '../lib/pyjson.mjs'
import { Harness, argAll, sha256, ROOT, SK } from './intake_harness.mjs'

const h = new Harness('lzma')
const installers = argAll(h.argv, '--installer')
const work = h.tmp('work')

const PY = String.raw`
import hashlib, json, lzma, os, random, sys, time
out, sk, root = sys.argv[1], sys.argv[2], sys.argv[3]
installers = sys.argv[4:]
H = lambda b: hashlib.sha256(b).hexdigest()
rng = random.Random(20261117)
pysec = [0.0]

WORDS = b"the quick brown fox jumps over lazy dog lorem ipsum dolor sit amet setup data inno gog galaxy".split()
def text(n): return b" ".join(rng.choice(WORDS) for _ in range(n // 5))[:n]
kinds = {
  "empty": b"", "byte": b"A", "text": text(200000), "random64k": rng.randbytes(65536),
  "random3m": rng.randbytes(3 << 20), "zeros": bytes(2 << 20),
  "records": b"".join(b"REC%08d" % (i * 7 % 1000) + bytes([i & 255, (i >> 3) & 255]) * 10 for i in range(30000)),
  "mixed": b"".join(text(100000) if k % 2 == 0 else rng.randbytes(100000) for k in range(12)),
}
dll = os.path.join(root, "work", "game", "SDL2.dll")
if os.path.isfile(dll):
    kinds["exe"] = open(dll, "rb").read()[:1500000]

L1, L2 = lzma.FILTER_LZMA1, lzma.FILTER_LZMA2
configs = []
def cfg(name, fid, kindset, **kw): configs.append((name, fid, kindset, kw))
ALL = list(kinds)
SOME = [k for k in ("text", "mixed", "exe", "records") if k in kinds]
cfg("l1_default", L1, ALL, dict_size=1 << 20)
cfg("l2_preset6", L2, ALL, preset=6)
cfg("l1_dict4k", L1, ALL, dict_size=4096)
cfg("l2_dict4k", L2, ALL, dict_size=4096)
for p in (0, 1, 3, 9):
    cfg("l1_preset%d" % p, L1, SOME, preset=p)
    cfg("l2_preset%d" % p, L2, SOME, preset=p)
cfg("l1_extreme", L1, SOME, preset=6 | lzma.PRESET_EXTREME)
cfg("l2_extreme9", L2, SOME, preset=9 | lzma.PRESET_EXTREME)
for lc, lp, pb in ((0, 0, 0), (4, 0, 2), (0, 4, 0), (1, 3, 4), (2, 2, 1), (3, 1, 3), (0, 2, 4)):
    cfg("l1_lc%dlp%dpb%d" % (lc, lp, pb), L1, SOME, lc=lc, lp=lp, pb=pb, dict_size=1 << 18)
    cfg("l2_lc%dlp%dpb%d" % (lc, lp, pb), L2, SOME, lc=lc, lp=lp, pb=pb, dict_size=1 << 18)
for mf in ("hc3", "hc4", "bt2", "bt3", "bt4"):
    cfg("l1_mf_" + mf, L1, SOME, mf=getattr(lzma, "MF_" + mf.upper()), mode=lzma.MODE_FAST if mf.startswith("hc") else lzma.MODE_NORMAL)
cfg("l1_nice8", L1, SOME, nice_len=8, dict_size=1 << 16)
cfg("l2_nice273", L2, SOME, nice_len=273, mode=lzma.MODE_NORMAL, mf=lzma.MF_BT4, depth=0)
cfg("l1_dict16m", L1, SOME, dict_size=16 << 20)
cfg("l2_dict64k", L2, SOME, dict_size=1 << 16)

def decfilter(enc):
    # the decoder settings the encoder used (props round trip), as a real raw stream reader would know them
    d = lzma._decode_filter_properties(enc["id"], lzma._encode_filter_properties(enc))
    f = {"id": enc["id"], "dict_size": d["dict_size"]}
    if enc["id"] == L1:
        f.update(lc=d["lc"], lp=d["lp"], pb=d["pb"])
    return f

streams = []
def add_stream(name, comp, f):
    fn = "s%04d.bin" % len(streams)
    open(os.path.join(out, fn), "wb").write(comp)
    streams.append({"name": name, "file": fn, "filter": f, "size": len(comp)})

for name, fid, kindset, kw in configs:
    for k in kindset:
        enc = {"id": fid}
        enc.update(kw)
        c = lzma.compress(kinds[k], format=lzma.FORMAT_RAW, filters=[enc])
        f = decfilter(enc)
        add_stream("%s/%s" % (name, k), c, f)

# real streams from installers: wrap inno.py's decompressor factories
if installers:
    sys.path.insert(0, sk)
    import inno
    cap = []
    def wrap(factory, kind):
        def f(arg):
            d = factory(arg)
            rec = {"kind": kind, "arg": arg.hex() if isinstance(arg, (bytes, bytearray)) else arg, "data": []}
            cap.append(rec)
            class W:
                def decompress(self, data, max_length=-1):
                    rec["data"].append(bytes(data)); return d.decompress(data, max_length)
                eof = property(lambda self: d.eof)
                needs_input = property(lambda self: d.needs_input)
                unused_data = property(lambda self: d.unused_data)
            return W()
        return f
    inno.lzma1_decompressor = wrap(inno.lzma1_decompressor, "lzma1")
    inno.lzma2_decompressor = wrap(inno.lzma2_decompressor, "lzma2")
    for inst in installers:
        n0 = len(cap)
        s = inno.open_setup(inst)
        inno.Engine(s, inno.build_targets(inno.plan(s, include_temp=True), "rename"), out_dir=None, verify_all=True).run()
        for j, rec in enumerate(cap[n0:]):
            comp = b"".join(rec["data"])
            if rec["kind"] == "lzma1":
                p = bytes.fromhex(rec["arg"]); d = p[0]
                f = {"id": L1, "dict_size": max(int.from_bytes(p[1:5], "little"), 4096), "lc": d % 9, "lp": d // 9 % 5, "pb": d // 45}
            else:
                pr = rec["arg"]
                f = {"id": L2, "dict_size": 0xFFFFFFFF if pr == 40 else (2 | (pr & 1)) << (pr // 2 + 11)}
            add_stream("installer%d/%s#%d" % (installers.index(inst), rec["kind"], j), comp, f)

def mk(f):
    return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[f])

def guard(fn):
    t0 = time.perf_counter()
    try:
        return fn()
    except (lzma.LZMAError, EOFError, ValueError, TypeError) as e:
        return {"error": "%s: %s" % (type(e).__name__, e)}
    finally:
        pysec[0] += time.perf_counter() - t0

def whole(c, f):
    d = mk(f); o = d.decompress(c)
    return {"len": len(o), "sha": H(o), "eof": d.eof, "needs_input": d.needs_input, "unused": d.unused_data.hex()}

PLANS = {"small": [(1, 7), (997, 1), (13, 4096), (4096, 100), (64, -1), (500, 33)],
         "inno": [(1 << 20, 4 << 20)]}
def chunked(c, f, plan):
    d = mk(f); pos = 0; k = 0; total = 0; h = hashlib.sha256(); calls = 0
    while not d.eof:
        n, m = plan[k % len(plan)]; k += 1
        if d.needs_input:
            if pos >= len(c): break
            piece = c[pos:pos + n]; pos += len(piece)
        else:
            piece = b""
        o = d.decompress(piece, m); calls += 1
        h.update(o); total += len(o)
    return {"len": total, "sha": h.hexdigest(), "eof": d.eof, "needs_input": d.needs_input,
            "unused": d.unused_data.hex(), "consumed": pos}

def bytewise(c, f, tail):
    d = mk(f); start = max(0, len(c) - tail)
    o = d.decompress(c[:start]); lens = [len(o)]; flags = []
    for i in range(start, len(c)):
        if d.eof: break
        o = d.decompress(c[i:i + 1]); lens.append(len(o)); flags.append(int(d.eof) * 2 + int(d.needs_input))
    return {"start": start, "lens": H(json.dumps(lens).encode()), "flags": H(json.dumps(flags).encode()),
            "total": sum(lens), "eof": d.eof}

def cuts(c, f):
    res = []
    n = len(c)
    for k in sorted(set([0, 1, 5, 6, n // 3, n // 2, n - 6, n - 1]) & set(range(n + 1))):
        try:
            d = mk(f); o = d.decompress(c[:k])
            res.append([k, len(o), H(o), d.eof, d.needs_input])
        except lzma.LZMAError as e:
            res.append([k, "error", str(e)])
    return {"cuts": res}

def junk(c, f):
    return whole(c + b"JUNK\x00\xffDATA", f)

def flips(c, f, seed):
    r = random.Random(seed); res = []
    for _ in range(6):
        if not c: break
        pos = r.randrange(len(c)); bit = r.randrange(8)
        c2 = bytearray(c); c2[pos] ^= 1 << bit
        try:
            d = mk(f); o = d.decompress(bytes(c2))
            res.append([pos, bit, len(o), H(o), d.eof])
        except lzma.LZMAError as e:
            res.append([pos, bit, "error", str(e)])
    return {"flips": res}

results = []
for i, s in enumerate(streams):
    c = open(os.path.join(out, s["file"]), "rb").read()
    f = s["filter"]
    r = {"whole": guard(lambda: whole(c, f)), "chunked_small": guard(lambda: chunked(c, f, PLANS["small"])),
         "chunked_inno": guard(lambda: chunked(c, f, PLANS["inno"])),
         "bytewise": guard(lambda: bytewise(c, f, 20000 if len(c) < 20000 else 3000)),
         "cuts": guard(lambda: cuts(c, f))}
    if r["whole"].get("eof"):
        r["junk"] = guard(lambda: junk(c, f))
    if len(c) <= 300000:
        r["flips"] = guard(lambda: flips(c, f, i))
    results.append(r)

bad = []
for name, f in (("l1_lc5", {"id": L1, "lc": 5}), ("l1_lc4lp1", {"id": L1, "lc": 4, "lp": 1}), ("l1_pb5", {"id": L1, "pb": 5})):
    bad.append([name, f, guard(lambda: whole(b"\x00" * 10, f))])

json.dump({"streams": streams, "results": results, "bad": bad, "plans": PLANS, "seconds": pysec[0]},
          open(os.path.join(out, "py.json"), "w"))
`

fs.writeFileSync(path.join(work, 'gen.py'), PY)
const pr = h.run(h.python, ['-I', path.join(work, 'gen.py'), work, SK, ROOT, ...installers])
if (pr.code !== 0) {
  process.stderr.write(pr.stderr)
  h.record('python_generator', false, pr.stderr.toString().slice(-2000))
  h.finish()
  process.exit()
}
const pyRes = parse(fs.readFileSync(path.join(work, 'py.json'), 'utf8'))
h.pySec = Number(pyRes.get('seconds'))

const plain = (v) => JSON.parse(JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? Number(x) : x instanceof Map ? Object.fromEntries(x) : x)))

const mkDec = (f) => new LZMADecompressor({ format: FORMAT_RAW, filters: [f] })
let jsSec = 0
function guard(fn) {
  const t0 = process.hrtime.bigint()
  try {
    return fn()
  } catch (e) {
    if (e && (e.name === 'LZMAError' || e.name === 'EOFError')) return { error: `${e.name}: ${e.message}` }
    throw e
  } finally {
    jsSec += Number(process.hrtime.bigint() - t0) / 1e9
  }
}
const H = sha256
function whole(c, f) {
  const d = mkDec(f); const o = d.decompress(c)
  return { len: o.length, sha: H(o), eof: d.eof, needs_input: d.needs_input, unused: d.unused_data.toString('hex') }
}
function chunked(c, f, plan) {
  const d = mkDec(f)
  let pos = 0, k = 0, total = 0
  const hs = createHash()
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
  return { len: total, sha: hs.digest('hex'), eof: d.eof, needs_input: d.needs_input, unused: d.unused_data.toString('hex'), consumed: pos }
}
const createHash = () => crypto.createHash('sha256')
const pyJson = (a) => '[' + a.map((x) => String(x)).join(', ') + ']'
function bytewise(c, f, tail) {
  const d = mkDec(f)
  const start = Math.max(0, c.length - tail)
  let o = d.decompress(c.subarray(0, start))
  const lens = [o.length], flags = []
  for (let i = start; i < c.length; i++) {
    if (d.eof) break
    o = d.decompress(c.subarray(i, i + 1)); lens.push(o.length); flags.push((d.eof ? 2 : 0) + (d.needs_input ? 1 : 0))
  }
  return { start, lens: H(Buffer.from(pyJson(lens))), flags: H(Buffer.from(pyJson(flags))), total: lens.reduce((a, b) => a + b, 0), eof: d.eof }
}
function cuts(c, f) {
  const n = c.length
  const ks = [...new Set([0, 1, 5, 6, Math.floor(n / 3), Math.floor(n / 2), n - 6, n - 1])].filter((k) => k >= 0 && k <= n).sort((a, b) => a - b)
  const res = []
  for (const k of ks) {
    try {
      const d = mkDec(f); const o = d.decompress(c.subarray(0, k))
      res.push([k, o.length, H(o), d.eof, d.needs_input])
    } catch (e) {
      if (e.name !== 'LZMAError') throw e
      res.push([k, 'error', e.message])
    }
  }
  return { cuts: res }
}
const junk = (c, f) => whole(Buffer.concat([c, Buffer.from('JUNK\x00\xffDATA', 'latin1')]), f)

// Python's random.Random(seed).randrange cannot be reproduced cheaply: flips use the positions Python chose
function flipsLike(c, f, pyFlips) {
  const res = []
  for (const it of pyFlips) {
    const [pos, bit] = it
    const c2 = Buffer.from(c); c2[pos] ^= 1 << bit
    try {
      const d = mkDec(f); const o = d.decompress(c2)
      res.push([pos, bit, o.length, H(o), d.eof])
    } catch (e) {
      if (e.name !== 'LZMAError') throw e
      res.push([pos, bit, 'error', e.message])
    }
  }
  return { flips: res }
}

const streams = pyRes.get('streams')
const results = pyRes.get('results')
const plans = plain(pyRes.get('plans'))
const filterOf = (s) => {
  const f = plain(s.get('filter'))
  f.id = f.id === 33 ? 'lzma2' : 'lzma1'
  return f
}
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b)
for (let i = 0; i < streams.length; i++) {
  const s = streams[i]
  const c = fs.readFileSync(path.join(work, s.get('file')))
  const f = filterOf(s)
  const py = plain(results[i])
  const js = {
    whole: guard(() => whole(c, f)),
    chunked_small: guard(() => chunked(c, f, plans.small)),
    chunked_inno: guard(() => chunked(c, f, plans.inno)),
    bytewise: guard(() => bytewise(c, f, c.length < 20000 ? 20000 : 3000)),
    cuts: guard(() => cuts(c, f)),
  }
  if (py.junk) js.junk = guard(() => junk(c, f))
  if (py.flips) js.flips = py.flips.error ? py.flips : guard(() => flipsLike(c, f, py.flips.flips))
  for (const mode of Object.keys(py)) {
    const ok = eq(py[mode], js[mode])
    h.record(`${s.get('name')}:${mode}`, ok, ok ? null : { python: py[mode], js: js[mode] })
  }
}
for (const b of pyRes.get('bad')) {
  const [name, f, pyr] = plain(b)
  f.id = 'lzma1'
  let jr
  try { jr = whole(Buffer.alloc(10), f) } catch (e) { jr = { error: `${e.name}: ${e.message}` } }
  const ok = eq(pyr, jr)
  h.record(`invalid_options/${name}`, ok, ok ? null : { python: pyr, js: jr })
}
h.jsSec = jsSec
h.finish({ streams: streams.length })
