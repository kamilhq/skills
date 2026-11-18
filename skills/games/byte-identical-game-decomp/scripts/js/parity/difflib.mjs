#!/usr/bin/env node
// Parity test: js/lib/difflib.mjs SequenceMatcher against Python 3.9's difflib.SequenceMatcher.
//
//   node parity/difflib.mjs [--root PROJECT] [--python python3] [--seed N] [--random N]
//
// Cases: random integer / string / tuple sequences (lengths 0..600, small alphabets so there are many
// duplicates; b of 200+ items exercises the autojunk "popular" heuristic), mixed int/float/bool equality,
// isjunk sets, sub-range find_longest_match calls, and real data from the project (byte windows of
// work/game/VVVVVV.exe at function starts from decompiled_named_exe/index.json, lines and characters of
// src_matched/VVVVVV/*.cpp). For every case and both autojunk settings: get_matching_blocks, get_opcodes,
// get_grouped_opcodes, ratio, quick_ratio, real_quick_ratio, bjunk/bpopular counts.
// Prints one JSON summary; exit 0 only when every case is identical.
import { spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SequenceMatcher } from '../lib/difflib.mjs'
import { dumps, parse, pyFloat, pyFloatRepr } from '../lib/pyjson.mjs'

const argv = process.argv.slice(2)
const opt = (name, def) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : def }
const ROOT = opt('--root', process.cwd())
const PY = opt('--python', 'python3')
let seed = Number(opt('--seed', '12345')) >>> 0
const NRANDOM = Number(opt('--random', '400'))

function rnd() {   // xorshift32, deterministic
  seed ^= seed << 13; seed >>>= 0
  seed ^= seed >>> 17
  seed ^= seed << 5; seed >>>= 0
  return seed / 4294967296
}
const ri = (n) => Math.floor(rnd() * n)

// ---- cases. Element encoding shared with the Python side: number/str/bool/null as JSON; float as a JSON
// float (PyFloat); tuple as {"t": [...]}.
const cases = []
const add = (name, a, b, extra = {}) => cases.push({ name, a, b, ...extra })

function randSeq(len, alpha, kind) {
  const out = []
  for (let i = 0; i < len; i++) {
    const v = ri(alpha)
    if (kind === 'int') out.push(v)
    else if (kind === 'str') out.push('abcdefghijklmnopqrstuvwxyz0123456789'[v % 36])
    else if (kind === 'tuple') out.push(rnd() < 0.3 ? { t: ['?', ri(5)] } : v)
    else if (kind === 'mixed') out.push([v, pyFloat(v), v === 1, v === 0 ? false : v, String(v)][ri(5)])
  }
  return out
}
function mutate(seq, rate, alpha, kind) {
  const out = []
  for (const x of seq) {
    const r = rnd()
    if (r < rate / 3) continue
    if (r < 2 * rate / 3) { out.push(...randSeq(1, alpha, kind)); continue }
    if (r < rate) { out.push(x); out.push(...randSeq(1 + ri(3), alpha, kind)); continue }
    out.push(x)
  }
  return out
}
const kinds = ['int', 'str', 'tuple', 'mixed']
for (let n = 0; n < NRANDOM; n++) {
  const kind = kinds[n % kinds.length]
  const big = rnd() < 0.4
  const la = big ? 150 + ri(450) : ri(60)
  const alpha = [2, 3, 5, 10, 40, 300][ri(6)]
  const a = randSeq(la, alpha, kind)
  const b = rnd() < 0.7 ? mutate(a, rnd() * 0.5, alpha, kind) : randSeq(big ? 150 + ri(450) : ri(60), alpha, kind)
  const extra = {}
  if (rnd() < 0.25) extra.junk = randSeq(1 + ri(2), alpha, kind)
  if (rnd() < 0.3) {
    const la2 = a.length, lb2 = b.length
    const alo = ri(la2 + 1), blo = ri(lb2 + 1)
    extra.flm = [alo, alo + ri(la2 - alo + 1), blo, blo + ri(lb2 - blo + 1)]
  }
  add(`random#${n} ${kind} ${a.length}x${b.length} alpha ${alpha}`, a, b, extra)
}
// edge cases
add('empty/empty', [], [])
add('empty/x', [], [1, 2, 3])
add('x/empty', ['a'], [])
add('all same 300', Array(300).fill(7), Array(250).fill(7))
add('popular boundary 200 (ntest 3)', [...Array(196).keys(), 1, 1, 1, 2], [...Array(196).keys(), 1, 1, 2, 2])
add('popular exactly ntest', Array.from({ length: 200 }, (_, i) => i % 67), Array.from({ length: 200 }, (_, i) => i % 66))
add('199 vs 200 items', Array.from({ length: 199 }, (_, i) => i % 5), Array.from({ length: 199 }, (_, i) => i % 5))
add('200 items', Array.from({ length: 200 }, (_, i) => i % 5), Array.from({ length: 200 }, (_, i) => i % 5))
add('int/float/bool equality', [1, pyFloat(2), true, false, 0, null, 'x'], [pyFloat(1), 2, 1, 0, false, null, 'x'])
add('tuples like hybrid_link', [5, { t: ['?', 1] }, 7, { t: ['?', 3] }, 5], [5, 6, 7, 8, 5, { t: ['?', 1] }])
add('string junk', 'private Thread currentThread;'.split(''), 'private volatile Thread currentThread;'.split(''),
  { junk: [' '] })

// real data
const exe = join(ROOT, 'work/game/VVVVVV.exe'), idx = join(ROOT, 'decompiled_named_exe/index.json')
let real = 0
if (existsSync(exe) && existsSync(idx)) {
  const d = readFileSync(exe)
  const base = d.readUInt32LE(d.readUInt32LE(0x3c) + 24 + 28)
  // .text file offset: first section header
  const o = d.readUInt32LE(0x3c), opt0 = o + 24, so = opt0 + d.readUInt16LE(o + 20)
  const va0 = d.readUInt32LE(so + 12), raw0 = d.readUInt32LE(so + 20), rsz = d.readUInt32LE(so + 16)
  const funcs = parse(readFileSync(idx, 'utf8')).get('functions')
  const addrs = funcs.map((f) => parseInt(String(f.get('address')), 16)).filter((x) => x >= base + va0 && x < base + va0 + rsz)
  for (let k = 0; k < 60; k++) {
    const x = addrs[ri(addrs.length)], y = addrs[ri(addrs.length)]
    const n1 = 20 + ri(900), n2 = 20 + ri(900)
    const off = (v) => raw0 + (v - base - va0)
    const a = Array.from(d.subarray(off(x), off(x) + n1)), b = Array.from(d.subarray(off(y), off(y) + n2))
    // objcmp-style: masked positions become 256
    for (let i = 0; i < a.length; i++) if (rnd() < 0.05) a[i] = 256
    add(`exe bytes 0x${x.toString(16)}+${n1} vs 0x${y.toString(16)}+${n2}`, a, b)
    real++
  }
  // a function against a mutated copy of itself (the typical objcmp DIFF case)
  for (let k = 0; k < 20; k++) {
    const x = addrs[ri(addrs.length)], n1 = 50 + ri(1500)
    const a = Array.from(d.subarray(raw0 + (x - base - va0), raw0 + (x - base - va0) + n1))
    add(`exe bytes 0x${x.toString(16)}+${n1} vs mutated`, a, mutate(a, 0.05, 256, 'int'))
    real++
  }
}
const srcDir = join(ROOT, 'src_matched/VVVVVV')
if (existsSync(srcDir)) {
  const files = readdirSync(srcDir).filter((f) => f.endsWith('.cpp')).sort()
  for (let k = 0; k < 30 && files.length; k++) {
    const f1 = files[ri(files.length)], f2 = files[ri(files.length)]
    const l1 = readFileSync(join(srcDir, f1), 'utf8').split('\n'), l2 = readFileSync(join(srcDir, f2), 'utf8').split('\n')
    add(`lines ${f1} vs ${f2}`, l1, k % 2 ? l2 : mutate(l1, 0.1, 3, 'str'))
    const t1 = l1.slice(0, 40).join('\n'), t2 = (k % 2 ? l2 : l1).slice(0, 40).join('\n')
    add(`chars ${f1} vs ${f2}`, t1, t2, { str: true, junk: k % 3 ? undefined : [' ', '\n'] })
    real += 2
  }
}

// ---- JS side
function decode(x) {
  if (x && typeof x === 'object' && !Array.isArray(x) && x.t) return x.t.map(decode)
  return x
}
function runJs(c, autojunk) {
  const a = c.str ? c.a : c.a.map(decode), b = c.str ? c.b : c.b.map(decode)
  let isjunk = null
  if (c.junk) {
    const jk = new SequenceMatcher(null, c.junk.map(decode), [], false)._ak
    const set = new Set(Array.from(jk))
    const probe = new SequenceMatcher(null, [], [], false)
    isjunk = (e) => { probe.set_seq1([e]); return set.has(probe._ak[0]) }
  }
  const sm = new SequenceMatcher(isjunk, a, b, autojunk)
  const r = {
    blocks: sm.get_matching_blocks().map((m) => [m.a, m.b, m.size]),
    opcodes: sm.get_opcodes(),
    grouped: sm.get_grouped_opcodes(3),
    ratio: pyFloatRepr(sm.ratio()),
    quick: pyFloatRepr(sm.quick_ratio()),
    real_quick: pyFloatRepr(sm.real_quick_ratio()),
    njunk: sm._bjunk.size,
    npopular: sm._bpopular.size,
  }
  if (c.flm) { const m = sm.find_longest_match(...c.flm); r.flm = [m.a, m.b, m.size] }
  return r
}

const PYCODE = String.raw`
import difflib, json, sys, time
def dec(x):
    if isinstance(x, dict):
        return tuple(dec(e) for e in x['t'])
    return x
cases = json.load(open(sys.argv[1]))
out = []
t0 = time.time()
for c in cases:
    a = c['a'] if c.get('str') else [dec(e) for e in c['a']]
    b = c['b'] if c.get('str') else [dec(e) for e in c['b']]
    for aj in (True, False):
        isjunk = None
        if c.get('junk'):
            js = set(dec(e) for e in c['junk'])
            isjunk = js.__contains__
        sm = difflib.SequenceMatcher(isjunk, a, b, autojunk=aj)
        r = {'blocks': [list(m) for m in sm.get_matching_blocks()], 'opcodes': [list(o) for o in sm.get_opcodes()],
             'grouped': [[list(o) for o in g] for g in sm.get_grouped_opcodes(3)],
             'ratio': repr(sm.ratio()), 'quick': repr(sm.quick_ratio()), 'real_quick': repr(sm.real_quick_ratio()),
             'njunk': len(sm.bjunk), 'npopular': len(sm.bpopular)}
        if c.get('flm'):
            r['flm'] = list(sm.find_longest_match(*c['flm']))
        out.append(r)
json.dump({'results': out, 'seconds': time.time() - t0}, open(sys.argv[2], 'w'))
`

const tmp = mkdtempSync(join(tmpdir(), 'parity_difflib_'))
try {
  const cin = join(tmp, 'cases.json'), cout = join(tmp, 'out.json')
  writeFileSync(cin, dumps(cases))
  const p = spawnSync(PY, ['-I', '-c', PYCODE, cin, cout], { encoding: 'utf8', maxBuffer: 1 << 28 })
  if (p.status !== 0) {
    process.stdout.write(dumps({ script: 'difflib', error: 'python failed', stderr: p.stderr.slice(-2000) }) + '\n')
    process.exitCode = 1
  } else {
    const pyOut = JSON.parse(readFileSync(cout, 'utf8'))
    const t0 = process.hrtime.bigint()
    const jsOut = []
    for (const c of cases) for (const aj of [true, false]) jsOut.push(runJs(c, aj))
    const jsSec = Number(process.hrtime.bigint() - t0) / 1e9
    const different = []
    let k = 0
    for (const c of cases) {
      for (const aj of [true, false]) {
        const a = JSON.stringify(jsOut[k]), b = JSON.stringify(pyOut.results[k])
        if (a !== b) different.push(`${c.name} autojunk=${aj}`)
        k++
      }
    }
    const summary = { script: 'difflib', cases: k, identical: k - different.length, different: different.slice(0, 50),
                      real_data_cases: real * 2, python_seconds: +pyOut.seconds.toFixed(3), js_seconds: +jsSec.toFixed(3) }
    process.stdout.write(JSON.stringify(summary) + '\n')
    process.exitCode = different.length ? 1 : 0
  }
} finally {
  rmSync(tmp, { recursive: true, force: true })
}
