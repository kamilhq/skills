#!/usr/bin/env node
// objcmp_selftest.mjs <pe> [--functions index.json] [--work DIR] [--count 20]
//
// JavaScript port of objcmp_selftest.py: self-test for objcmp without a compiler. Takes ~20 real functions of
// <pe> (from Ghidra's index.json, or found heuristically from call targets without it), turns every original
// .reloc fixup inside each into a DIR32 relocation (alternately addend 0 with zeroed field, and in-place addend
// against a rounded base symbol; IAT slots become __imp__<name>) and every E8/E9 rel32 to a known function start
// outside the function into a REL32 relocation to an external symbol, writes /Gy-style, non-/Gy and /bigobj
// objects with write_obj, reads them back and checks: round trip, every function identical (with and without
// an address map), a mutated byte reported at its offset, a wrong REL32 / DIR32 map entry reported,
// inconsistent targets, truncation, missing relocation, padding with an explicit size, report mode with
// annotations (identical / ambiguous / unmapped), and the CLI exit codes (of objcmp.mjs). Exit 0 when every
// check passes. Same output as the Python script.
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, writeFileSync, openSync, closeSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as objcmp from './objcmp.mjs'
import { pyRepr, pyStr, pyFloatStr, splitlines, pyStrip, cmpStr, PyTuple, pathJoin, unpack_from, runMain, isMainModule } from './objcmp.mjs'
import { dumps, load as loadJson } from './lib/pyjson.mjs'
import { ArgumentParser, ArgExit } from './lib/pyargparse.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const OBJCMP = join(HERE, 'objcmp.mjs')
const RESULTS = []
const print = (s = '') => process.stdout.write(s + '\n')
const hex = objcmp.hex
const x08 = (n) => n.toString(16).padStart(8, '0')
const isPad = (b) => b === 0xCC || b === 0x90
const truthy = (v) => !(v === null || v === undefined || v === false || v === 0 || v === '' || (Array.isArray(v) && !v.length))
const cpSlice = (s, a, b) => Array.from(s).slice(a, b).join('')

function check(name, ok, detail = '') {
  ok = !!ok
  RESULTS.push([name, ok])
  print(`${ok ? 'PASS' : 'FAIL'}  ${name}` + (truthy(detail) ? `  (${pyStr(detail)})` : ''))
  return ok
}

// subprocess.run([...], stdout=PIPE, stderr=STDOUT, universal_newlines=True): one pipe for both streams
let capDir = null
function cli(...args) {
  capDir ||= mkdtempSync(join(tmpdir(), 'objcmp_selftest_cli_'))
  const cap = join(capDir, 'out.txt')
  const fd = openSync(cap, 'w+')
  let p
  try {
    p = spawnSync(process.execPath, [OBJCMP, ...args.map(String)], { stdio: ['inherit', fd, fd] })
  } finally {
    closeSync(fd)
  }
  const out = readFileSync(cap, 'utf8').replace(/\r\n?/g, '\n')
  return [p.status, out]
}

const s32 = (v) => ((v & 0x80000000) ? v - 0x100000000 : v)

// without index.json: call targets in executable sections preceded by CC/90, ending at ret + CC/90
function heuristic_functions(pe) {
  const starts = new Map()
  for (const [, sva, vsize, rawsize, , ch] of pe.sections) {
    if (!((ch & (objcmp.SCN_EXEC | objcmp.SCN_CNT_CODE)) >>> 0)) continue
    const base = pe.image_base + sva
    const blob = pe.read(base, Math.min(vsize, rawsize))
    for (let p = 0; p < blob.length - 5; p++) {
      if (blob[p] === 0xE8) {
        const t = base + p + 5 + s32(blob.readUInt32LE(p + 1))
        if (base < t && t < base + blob.length && isPad(blob[t - base - 1])) starts.set(t, (starts.get(t) || 0) + 1)
      }
    }
  }
  const out = new Map()
  for (const [t, n] of starts) {
    if (n < 2) continue
    const b = pe.read(t, 4096)
    for (let k = 0; k < b.length - 3; k++) {
      if (b[k] === 0xC3 && isPad(b[k + 1])) { out.set(t, k + 1); break }
      if (b[k] === 0xC2 && isPad(b[k + 3]) && b[k + 2] === 0) { out.set(t, k + 3); break }
    }
  }
  return out
}

// bytes + relocation list + map entries for one original function
function build_function(pe, va, size, starts, impBySlot, styleCounter) {
  const b = Buffer.from(pe.read(va, size))
  const rels = [], amap = new Map()
  const covered = new Set()
  for (const f of pe.fixups_in(va, size)) {
    const o = f - va
    if (o < 0 || o + 4 > size) return null
    const tgt = unpack_from('<I', b, o)[0]
    for (let k = o; k < o + 4; k++) covered.add(k)
    if (impBySlot.has(tgt)) {
      const nm = impBySlot.get(tgt)
      const sym = nm.startsWith('?') ? '__imp_' + nm : '__imp__' + nm
      rels.push({ offset: o, type: 'DIR32', symbol: sym })
      b.writeUInt32LE(0, o)
      continue
    }
    styleCounter[0] += 1
    if (styleCounter[0] % 2) {
      const sym = starts.has(tgt) ? `_fn_${x08(tgt)}` : `_g_${x08(tgt)}`
      rels.push({ offset: o, type: 'DIR32', symbol: sym })
      b.writeUInt32LE(0, o)                                 // addend 0, field zeroed
      amap.set(sym, tgt)
    } else {
      const base = (tgt & ~0xFF) >>> 0
      const sym = `_g_${x08(base)}`
      rels.push({ offset: o, type: 'DIR32', symbol: sym })
      b.writeUInt32LE(tgt - base, o)                        // MSVC style: addend stored in place
      amap.set(sym, base)
    }
  }
  let p = 0
  while (p + 5 <= size) {
    if ((b[p] === 0xE8 || b[p] === 0xE9) && ![p, p + 1, p + 2, p + 3, p + 4].some((k) => covered.has(k))) {
      const t = (va + p + 5 + s32(unpack_from('<I', b, p + 1)[0])) >>> 0
      if (starts.has(t) && !(va <= t && t < va + size)) {
        const sym = `_fn_${x08(t)}`
        rels.push({ offset: p + 1, type: 'REL32', symbol: sym })
        b.writeUInt32LE(0, p + 1)
        amap.set(sym, t)
        for (let k = p; k < p + 5; k++) covered.add(k)
        p += 5
        continue
      }
    }
    p += 1
  }
  rels.sort((x, y) => x.offset - y.offset)
  return [b, rels, amap]
}

// adjacent functions [[va, next_va]] whose gaps are only CC/90 padding; prefers runs with internal calls
function find_run(pe, flist, want = 8, maxBytes = 6000) {
  const addrs = [...flist.keys()].filter((a) => pe.is_exec(a)).sort((a, b) => a - b)
  let best = [], bestScore = -1
  let i = 0
  while (i < addrs.length - want) {
    const run = []
    let ok = true
    for (let k = i; k < i + want; k++) {
      const va = addrs[k], nxt = addrs[k + 1]
      const size = flist.get(va)
      const gap = size ? pe.read(va + size, Math.max(0, nxt - va - size)) : Buffer.from('x')
      if (!size || nxt - va > maxBytes || [...gap].some((c) => !isPad(c))) { ok = false; break }
      run.push([va, nxt])
    }
    if (ok && run[run.length - 1][1] - run[0][0] <= maxBytes) {
      const lo = run[0][0], hi = run[run.length - 1][1]
      const blob = pe.read(lo, hi - lo)
      let score = 0
      for (let p = 0; p < blob.length - 5; p++) {
        if (blob[p] === 0xE8) {
          const t = lo + p + 5 + s32(blob.readUInt32LE(p + 1))
          score += (lo <= t && t < hi && flist.has(t)) ? 1 : 0
        }
      }
      if (score > bestScore) { best = run; bestScore = score }
      if (score >= 3) break
      i += want
    } else i += 1
  }
  return best
}

function pick(cands, n) {
  if (cands.length <= n) return cands
  const step = cands.length / n
  return Array.from({ length: n }, (_, i) => cands[Math.trunc(i * step)])
}

const USAGE = `usage: objcmp_selftest.py [-h] [--functions FUNCTIONS] [--work WORK]
                          [--count COUNT]
                          pe
`
const HELP = USAGE + `
positional arguments:
  pe

optional arguments:
  -h, --help            show this help message and exit
  --functions FUNCTIONS
                        Ghidra index.json (address, size)
  --work WORK           scratch directory (default: a new temp dir)
  --count COUNT
`

export function main(argv = process.argv.slice(2)) {
  const ap = new ArgumentParser({ prog: 'objcmp_selftest.py', usage: USAGE, help: HELP })
  ap.add_argument('pe')
  ap.add_argument('--functions')
  ap.add_argument('--work')
  ap.add_argument('--count', { type: 'int', default: 20 })
  let args
  try {
    args = ap.parse_args(argv)
  } catch (e) {
    if (e instanceof ArgExit) return e.code
    throw e
  }
  try {
    return run(args)
  } finally {
    if (capDir) rmSync(capDir, { recursive: true, force: true })
  }
}

function run(args) {
  const work = args.work || mkdtempSync(join(tmpdir(), 'objcmp_selftest_'))
  mkdirSync(work, { recursive: true })
  const pe = new objcmp.PEImage(args.pe)
  print(`PE ${args.pe}: base 0x${pe.image_base.toString(16)}, ${pe.sections.length} sections, ${pe.fixups.length} fixups, ` +
        `${pe.imports.size} imports; work dir ${work}`)
  const flist = args.functions ? objcmp.load_function_list(args.functions) : heuristic_functions(pe)
  const starts = new Set(flist.keys())
  const impBySlot = new Map()
  for (const [k, v] of pe.imports) if (!k.includes('#')) impBySlot.set(v, k)

  // ---- choose functions: small / medium / large, preferring ones with fixups and calls
  const style = [0]
  const buckets = { small: [], medium: [], large: [] }
  for (const [va, size] of [...flist].sort((a, b) => (a[0] - b[0]) || (a[1] - b[1]))) {
    if (size < 5 || size > 8000 || !pe.is_exec(va)) continue
    const after = pe.read(va + size, 1)
    if (!(starts.has(va + size) || (after.length && isPad(after[0])))) continue
    let rich = pe.fixups_in(va, size).length > 0
    if (rich) {
      const code = pe.read(va, size)
      rich = false
      for (let k = 0; k < size; k++) {
        if (k >= code.length) throw new objcmp.IndexError('index out of range')
        if (code[k] === 0xE8) { rich = true; break }
      }
    }
    const key = size <= 64 ? 'small' : size <= 600 ? 'medium' : 'large'
    buckets[key].push([!rich, va, size])
  }
  const n = args.count
  const chosen = []
  const fl = (a, b) => Math.floor(a / b)
  for (const [key, k] of [['small', fl(n * 3, 10)], ['medium', fl(n * 4, 10)], ['large', n - fl(n * 3, 10) - fl(n * 4, 10)]]) {
    const c = [...buckets[key]].sort((x, y) => (Number(x[0]) - Number(y[0])) || (x[1] - y[1]) || (x[2] - y[2]))
    const rich = c.filter((x) => !x[0])
    const poor = c.filter((x) => x[0])
    chosen.push(...pick(rich, Math.max(1, k - 1)), ...pick(poor, 1))
  }
  const funcs = [], gmap = new Map()
  for (const [, va, size] of chosen) {
    const r = build_function(pe, va, size, starts, impBySlot, style)
    if (r === null) continue
    const [b, rels, amap] = r
    funcs.push({ name: `_fn_${x08(va)}`, bytes: b, relocations: rels, va, size })
    for (const [k, v] of amap) gmap.set(k, v)
  }
  // C++ names for annotation mapping: one method, two overloads
  funcs[1].name = '?Update@CUnit@@QAEXXZ'
  funcs[2].name = '?Foo@@YAXH@Z'
  funcs[3].name = '?Foo@@YAXN@Z'
  for (const f of funcs) gmap.set(f.name, f.va)
  const nrel = funcs.reduce((s, f) => s + f.relocations.length, 0)
  const n32 = funcs.reduce((s, f) => s + f.relocations.filter((r) => r.type === 'REL32').length, 0)
  const nimp = funcs.reduce((s, f) => s + f.relocations.filter((r) => r.symbol.startsWith('__imp_')).length, 0)
  print(`chosen ${funcs.length} functions, sizes ${Math.min(...funcs.map((f) => f.size))}..${Math.max(...funcs.map((f) => f.size))} ` +
        `(total ${funcs.reduce((s, f) => s + f.size, 0)} bytes); ${nrel} relocations: ${nrel - n32} DIR32 ` +
        `(${nimp} to __imp_ IAT slots), ${n32} REL32`)
  const mapfile = pathJoin(work, 'addrmap.txt')

  const writerFuncs = (fs) => fs.map((f) => ({ name: f.name, bytes: f.bytes, relocations: f.relocations }))

  // non-/Gy translation unit: a run of adjacent original functions (padding belongs to the preceding one),
  // one .text section; calls inside the run resolve as same-section targets
  const runList = find_run(pe, flist)
  const runFuncs = []
  for (const [va, nxt] of runList) {
    const [b, rels, amap] = build_function(pe, va, nxt - va, starts, impBySlot, style)
    runFuncs.push({ name: `_fn_${x08(va)}`, bytes: b, relocations: rels, va, size: nxt - va })
    for (const [k, v] of amap) gmap.set(k, v)
  }
  for (const f of runFuncs) gmap.set(f.name, f.va)
  if (runFuncs.length) {
    const names = new Set(runFuncs.map((g) => g.name))
    const nin = runFuncs.reduce((s, f) => s + f.relocations.filter((r) => r.type === 'REL32' && names.has(r.symbol)).length, 0)
    print(`non-/Gy run: ${runFuncs.length} adjacent functions 0x${runList[0][0].toString(16)}..0x${runList[runList.length - 1][1].toString(16)} ` +
          `(${runList[runList.length - 1][1] - runList[0][0]} bytes incl. padding), ${nin} calls inside the run`)
  }
  writeFileSync(mapfile, [...gmap].sort((a, b) => cmpStr(a[0], b[0])).map(([k, v]) => `${k} 0x${x08(v)}\n`).join(''))

  const variants = { gy: { comdat: true }, nogy: { comdat: false }, bigobj: { comdat: true, bigobj: true } }
  const vfuncs = { gy: funcs, nogy: runFuncs, bigobj: funcs }
  const objs = {}
  for (const [tag, kw] of Object.entries(variants)) {
    if (!vfuncs[tag].length) {
      check(`${tag}: no suitable functions found`, false)
      continue
    }
    const p = pathJoin(work, `selftest_${tag}.obj`)
    objcmp.write_obj(p, writerFuncs(vfuncs[tag]), { absolutes: { '@comp.id': 0x00AB766F }, ...kw })
    objs[tag] = p
  }

  // ---- 1. round trip
  for (const [tag, p] of Object.entries(objs)) {
    const o = objcmp.read_coff(p)
    const bad = []
    for (const f of vfuncs[tag]) {
      const hit = o.find(f.name)
      if (hit.length !== 1) { bad.push(`${f.name}: ${hit.length} symbols`); continue }
      const s = hit[0]
      const [data, rels] = o.function_bytes(s)
      if (!data.equals(f.bytes) || s.size !== f.size) bad.push(`${f.name}: bytes/size differ (${s.size} vs ${f.size})`)
      const got = rels.map((r) => [r.offset, r.type_name, r.symbol.name].join('\u0000'))
      const want = f.relocations.map((r) => [r.offset, r.type, r.symbol].join('\u0000'))
      if (got.length !== want.length || got.some((g, i) => g !== want[i])) bad.push(`${f.name}: relocations differ`)
      if (variants[tag].comdat && (s.section.comdat !== 1 || s.section.checksum !== objcmp.jamcrc(data))) {
        bad.push(`${f.name}: COMDAT selection/checksum`)
      }
    }
    check(`round trip ${tag} (${o.bigobj ? 'bigobj' : 'COFF'}, ${o.sections.length} sections, ` +
          `${o.symbols.size} symbols)`, !bad.length && o.bigobj === (tag === 'bigobj'), bad.slice(0, 3).join('; '))
    const [rc, out] = cli('dump', p)
    check(`dump CLI ${tag}`, rc === 0 && vfuncs[tag].every((f) => out.includes(f.name)) && out.includes('REL32'),
          `exit ${rc}, ${splitlines(out).length} lines`)
  }

  // ---- 2. compare every function: with map, without map, per variant
  const compareAll = (path, amap, fs = funcs) => {
    const o = objcmp.read_coff(path)
    return fs.map((f) => objcmp.compare_function(o, o.find(f.name)[0], pe, f.va, null, amap, starts))
  }
  for (const tag of Object.keys(objs)) {
    const m = new objcmp.AddrMap(pe, false)
    m.load(mapfile)
    const res = compareAll(objs[tag], m, vfuncs[tag])
    const bad = res.filter((r) => !r.identical).map((r) => `${r.symbol}: ${objcmp.format_result(r, true)}`)
    const by = new Map()
    for (const r of res) for (const [k, v] of Object.entries(r.resolved_by)) by.set(k, (by.get(k) || 0) + v)
    check(`compare ${tag} with address map: ${res.filter((r) => r.identical).length}/${res.length} identical, ` +
          `${res.reduce((s, r) => s + r.relocs_checked, 0)}/${res.reduce((s, r) => s + r.relocs, 0)} relocs target-checked ` +
          `${pyRepr(by)}, ` +
          `${res.reduce((s, r) => s + r.orig_fixups, 0)} original fixups masked`, !bad.length, bad.length ? cpSlice(bad[0], 0, 600) : '')
  }
  let res = compareAll(objs.gy, new objcmp.AddrMap(pe, false))
  check(`compare gy without map: ${res.filter((r) => r.identical).length}/${res.length} identical, ` +
        `${res.reduce((s, r) => s + r.relocs_checked, 0)} checked (imports), ${res.reduce((s, r) => s + r.relocs_inferred, 0)} inferred`,
        res.every((r) => r.identical))
  const ratioOk = res.every((r) => r.ratio === 1.0 && r.first_diff === null)
  check('identical results have ratio 1.0 and no first_diff', ratioOk)

  // CLI compare: exit 0 on a few
  let okc = 0
  const ffile = pathJoin(work, 'functions.json')      // known starts for the CLI (index.json or heuristic)
  writeFileSync(ffile, dumps(new Map([['functions', [...flist].sort((a, b) => a[0] - b[0]).map(([a, z]) => new Map([['address', hex(a)], ['size', z]]))]])))
  const fopt = ['--functions', ffile]
  for (const f of [...funcs.slice(0, 3), ...funcs.slice(-2)]) {
    const [rc, out] = cli('compare', objs.bigobj, f.name, args.pe, hex(f.va), '--map', mapfile, ...fopt)
    okc += rc === 0 && out.includes('IDENTICAL') ? 1 : 0
  }
  check(`compare CLI exit 0 (${okc}/5)`, okc === 5)
  let [rc, out] = cli('compare', objs.gy, 'CUnit::Update', args.pe, hex(funcs[1].va), '--map', mapfile, ...fopt)
  check('compare CLI accepts undecorated Class::Method', rc === 0, out ? splitlines(out)[0] : '')
  ;[rc, out] = cli('compare', objs.gy, 'Foo', args.pe, hex(funcs[2].va))
  check('compare CLI refuses ambiguous Foo (exit 2)', rc === 2 && out.includes('ambiguous'), cpSlice(pyStrip(out), 0, 120))

  // ---- 3. mutation of a non-relocated byte
  let med = null
  for (const f of funcs) {
    if (f.size > 64 && f.size <= 600 && f.relocations.length && (med === null || f.relocations.length > med.relocations.length)) med = f
  }
  if (med === null) throw new Error('ValueError: max() arg is an empty sequence')
  const masked = new Set()
  for (const r of med.relocations) for (let k = r.offset; k < r.offset + 4; k++) masked.add(k)
  for (const fx of pe.fixups_in(med.va, med.size)) for (let k = fx - med.va; k < fx - med.va + 4; k++) masked.add(k)
  let k = -1
  for (let i = Math.floor(med.size / 2); i < med.size; i++) if (!masked.has(i)) { k = i; break }
  if (k < 0) throw new Error('StopIteration')
  const mb = Buffer.from(med.bytes)
  mb[k] ^= 0x01
  const mut = { ...med, bytes: mb }
  let p = pathJoin(work, 'mutated.obj')
  objcmp.write_obj(p, writerFuncs([mut]))
  let o = objcmp.read_coff(p)
  let r = objcmp.compare_function(o, o.find(med.name)[0], pe, med.va, null, null, starts)
  check(`mutated byte at +0x${k.toString(16)} of ${med.name} (${med.size} bytes) reported at +0x${r.first_diff.toString(16)}, ` +
        `ratio ${pyFloatStr(r.ratio)}`, !r.identical && r.first_diff === k && r.diff_bytes === 1)
  ;[rc, out] = cli('compare', p, med.name, args.pe, hex(med.va))
  check('compare CLI exit 1 on mutation with hex context', rc === 1 && out.includes(`+0x${k.toString(16)}`) && out.includes('^^'))
  print(splitlines(out).slice(0, 8).map((ln) => '      ' + ln).join('\n'))

  // ---- 4. wrong REL32 / DIR32 targets in the address map
  const wrongMap = (rtype) => {
    const f = funcs.find((f) => f.relocations.some((r) => r.type === rtype && !r.symbol.startsWith('__imp_')))
    const rr = f.relocations.find((r) => r.type === rtype && !r.symbol.startsWith('__imp_'))
    const m = new objcmp.AddrMap(pe, false)
    m.load(mapfile)
    m.names.set(rr.symbol, m.names.get(rr.symbol) + 0x10)
    const o = objcmp.read_coff(objs.gy)
    const res = objcmp.compare_function(o, o.find(f.name)[0], pe, f.va, null, m, starts)
    const iss = res.issues.filter((i) => i.kind === 'target_mismatch')
    return [f, rr, res, iss]
  }
  for (const rtype of ['REL32', 'DIR32']) {
    const [, rr, res, iss] = wrongMap(rtype)
    check(`wrong ${rtype} map entry (${rr.symbol} +0x10) reported at +0x${rr.offset.toString(16)}`,
          !res.identical && iss.length === 1 && iss[0].offset === rr.offset, iss.length ? iss[0].detail : res.issues)
  }

  // ---- 5. inconsistent targets without a map (two different callees under one symbol name)
  let f = funcs.find((f) => new Set(f.relocations.filter((r) => r.type === 'REL32').map((r) => r.symbol)).size >= 2)
  const r32 = f.relocations.filter((r) => r.type === 'REL32')
  const second = r32.find((r) => r.symbol !== r32[0].symbol)
  const rels = f.relocations.map((r) => (r === second ? { ...r, symbol: r32[0].symbol } : r))
  p = pathJoin(work, 'inconsistent.obj')
  objcmp.write_obj(p, [{ name: f.name, bytes: f.bytes, relocations: rels }])
  o = objcmp.read_coff(p)
  res = objcmp.compare_function(o, o.find(f.name)[0], pe, f.va, null, new objcmp.AddrMap(pe, false), starts)
  check('same symbol, two different original targets -> inconsistent_target',
        res.issues.some((i) => i.kind === 'inconsistent_target') && !res.identical)

  // ---- 6. truncated obj function, missing DIR32 relocation, explicit size with padding
  const t = funcs[0]
  p = pathJoin(work, 'truncated.obj')
  objcmp.write_obj(p, [{ name: t.name, bytes: t.bytes.subarray(0, t.bytes.length - 1),
                         relocations: t.relocations.filter((r) => r.offset + 4 <= t.size - 1) }])
  o = objcmp.read_coff(p)
  res = objcmp.compare_function(o, o.find(t.name)[0], pe, t.va)
  check(`truncated obj (${t.size - 1} of ${t.size} bytes) -> size issue at +0x${(t.size - 1).toString(16)}`,
        !res.identical && res.first_diff === t.size - 1 && res.issues.some((i) => i.kind === 'size'))
  f = funcs.find((f) => f.relocations.some((r) => r.type === 'DIR32'))
  const rr = f.relocations.find((r) => r.type === 'DIR32')
  const fb = Buffer.from(f.bytes)
  pe.read(f.va + rr.offset, 4).copy(fb, rr.offset)
  p = pathJoin(work, 'noreloc.obj')
  objcmp.write_obj(p, [{ name: f.name, bytes: fb, relocations: f.relocations.filter((r) => r !== rr) }])
  o = objcmp.read_coff(p)
  res = objcmp.compare_function(o, o.find(f.name)[0], pe, f.va, null, new objcmp.AddrMap(pe, false), starts)
  check(`DIR32 removed (original bytes kept) -> fixup_without_reloc at +0x${rr.offset.toString(16)}`,
        !res.identical && res.first_diff === rr.offset && res.issues.some((i) => i.kind === 'fixup_without_reloc'))
  let padded = null
  for (const f of funcs) {
    const tail = pe.read(f.va + f.size, 16)
    let npad = 0
    if (tail.length && isPad(tail[0])) while (npad < tail.length && tail[npad] === tail[0]) npad++
    if (npad) { padded = [f, npad]; break }
  }
  if (padded) {
    const [f, npad] = padded
    const o = objcmp.read_coff(objs.gy)
    const m = new objcmp.AddrMap(pe, false)
    m.load(mapfile)
    const res = objcmp.compare_function(o, o.find(f.name)[0], pe, f.va, f.size + npad, m)
    const res2 = objcmp.compare_function(o, o.find(f.name)[0], pe, f.va, f.size + npad + 1, m)
    const nxt = pe.read(f.va + f.size + npad, 1)[0]
    check(`explicit size ${f.size}+${npad} padding bytes -> identical; size +1 more -> ` +
          `${!res2.identical ? 'different' : 'identical'} (next byte ${nxt.toString(16).padStart(2, '0')})`,
          res.identical && res.padding === npad && (res2.identical === isPad(nxt)))
  }
  try {
    new objcmp.CoffObj(Buffer.concat([Buffer.from([0, 0, 0xff, 0xff, 0x01, 0x00, 0x4c, 0x01]), Buffer.alloc(64)]), 'ltcg.obj')
    check('anonymous (/GL) object rejected', false)
  } catch (e) {
    if (!(e instanceof objcmp.CoffError)) throw e
    check('anonymous (/GL) object rejected with a clear error', e.message.includes('/GL'), cpSlice(e.message, 0, 60))
  }

  // ---- 7. report mode with annotations
  const src = pathJoin(work, 'src')
  mkdirSync(src, { recursive: true })
  let lines = ['// objcmp selftest sources', '']
  for (const f of funcs) {
    if (f.name === '?Update@CUnit@@QAEXXZ') {
      lines.push(`// FUNCTION: GAME 0x${f.va.toString(16)}`, 'void CUnit::Update()', '{', '}', '')
    } else if (f.name.startsWith('?Foo')) {
      continue
    } else if (f === funcs[4]) {
      lines.push(`// FUNCTION: GAME 0x${f.va.toString(16)} ${f.name}`, 'static int helper_with_other_name(int a) {', '}', '')
    } else if (f === funcs[5]) {
      lines.push(`// FUNCTION: 0x${f.va.toString(16)}`, `int __stdcall ${f.name.slice(1)}(int a, int b) { return 0; }`, '')
    } else {
      lines.push(`// FUNCTION: GAME 0x${f.va.toString(16)}`, `int ${f.name.slice(1)}(void)`, '{', '    return 0;', '}', '')
    }
  }
  let gsym
  for (const f of funcs) {
    if (!f.name.startsWith('_fn_')) continue
    const hit = f.relocations.find((r) => r.symbol.startsWith('_g_') && objcmp.pyInt(r.symbol.slice(3), 16) === gmap.get(r.symbol))
    if (hit) { gsym = hit.symbol; break }
  }
  if (gsym === undefined) throw new Error('StopIteration')
  lines.push(`// GLOBAL: GAME 0x${gmap.get(gsym).toString(16)}`, `extern int ${gsym.slice(1)};`, '',
             '// GLOBAL: GAME 0x4a0000', 'int g_counter = 0;', '',
             '// VTABLE: GAME 0x4b0000', 'class CUnit : public CBase {', '};', '',
             '// FUNCTION: OTHERMOD 0x401234', 'void other_module_function() {}', '')
  writeFileSync(pathJoin(src, 'game.cpp'), lines.join('\n'))
  const jout = pathJoin(work, 'report.json')
  ;[rc, out] = cli('report', '--pe', args.pe, '--src', src, '--obj', objs.gy, '--module', 'GAME', '--json', jout, '-q', ...fopt)
  let rep = loadJson(jout)
  const sm = rep.get('summary')
  const expect = funcs.length - 2
  const fns = rep.get('functions')
  const relocsChecked = fns.reduce((s, f) => s + (f.get('relocs_checked') || 0), 0)
  const lastLine = (s) => { const l = splitlines(pyStrip(s)); if (!l.length) throw new objcmp.IndexError('list index out of range'); return l[l.length - 1] }
  check(`report (annotations only, no map): ${sm.get('identical')}/${sm.get('annotated_functions')} identical, bytes ` +
        `${sm.get('bytes_identical')}/${sm.get('bytes_total')}, relocs target-checked ` +
        `${relocsChecked}, exit ${rc}`,
        rc === 0 && sm.get('identical') === expect && expect === sm.get('annotated_functions'), lastLine(out))
  const data = rep.get('data')
  check(`report maps GLOBAL ${gsym}, lists ${data.length} GLOBAL/VTABLE and skips the other module`,
        data.length === 3 && data.some((d) => d.get('symbol') === gsym) && relocsChecked >= 1 &&
        fns.every((f) => f.get('module') !== 'OTHERMOD'))
  writeFileSync(pathJoin(src, 'bad.cpp'), `// FUNCTION: GAME 0x${funcs[2].va.toString(16)}\nvoid Foo(int x) {\n}\n\n` +
                `// FUNCTION: GAME 0x${funcs[3].va.toString(16)}\nvoid Missing::Thing() {\n}\n\n` +
                `// STUB: GAME 0x${(funcs[3].va + 0x1000).toString(16)}\nvoid fn_00000000() {\n}\n`)
  ;[rc, out] = cli('report', '--pe', args.pe, '--src', src, '--obj', objs.gy, '--module', 'GAME', '--json', jout, '-q', ...fopt)
  rep = loadJson(jout)
  const st = new Map(rep.get('functions').map((f) => [f.get('va'), f.get('status')]))
  const rsum = rep.get('summary')
  check(`report with ambiguous + unmapped + stub annotations -> exit ${rc}, ` +
        `${rsum.get('unmapped')} unmapped/ambiguous, ${rsum.get('stubs')} stub`,
        rc === 1 && st.get(hex(funcs[2].va)) === 'ambiguous' && st.get(hex(funcs[3].va)) === 'unmapped' && rsum.get('stubs') === 1,
        cpSlice(splitlines(out).filter((ln) => ln.includes('AMBIG') || ln.includes('UNMAPPED')).join('; '), 0, 300))
  print(cpSlice(splitlines(out).filter((ln) => !ln.startsWith('OK') && !ln.startsWith('STUB')).map((ln) => '      ' + ln).join('\n'), 0, 2000))

  // ---- 8. decorated-name <-> source-name mapping
  const cases = [['??0CUnit@@QAE@XZ', 'CUnit::CUnit()'], ['??1CUnit@@UAE@XZ', 'CUnit::~CUnit()'],
    ['??4CUnit@@QAEAAV0@ABV0@@Z', 'CUnit &CUnit::operator=(const CUnit &o)'],
    ['??8@YA_NABUX@@0@Z', 'bool operator==(const X &a, const X &b)'],
    ['?Update@Inner@Outer@@QAEXXZ', 'void Outer::Inner::Update()'],
    ['_foo', 'int foo(void)'], ['_WinMain@16', 'int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d)'],
    ['@fast@8', 'int __fastcall fast(int a, int b)'],
    ['?Bar@CFoo@@QAGHHPAD@Z', 'BOOL __declspec(dllexport) __stdcall CFoo::Bar(int a, char *b)'],
    ['?Get@CUnit@@QBEPAV1@XZ', 'CUnit *CUnit::Get() const'],
    ['??RFunctor@@QAEHH@Z', 'int Functor::operator()(int x)']]
  const eq = (a, b) => a !== null && b !== null && a.length === b.length && a.every((x, i) => x === b[i])
  const bad = cases.filter(([d, s]) => !eq(objcmp.name_parts(d), objcmp.source_parts(objcmp.parse_definition(s) || '')))
    .map(([d, s]) => PyTuple.from([d, s]))
  for (const d of ['??$Max@H@@YAHHH@Z', '?Get@?$Vec@H@@QAEHXZ']) {
    const np = objcmp.name_parts(d)
    if (np !== null && np.length) bad.push(PyTuple.from([d, 'None expected']))
  }
  const special = eq(objcmp.name_parts('??_7CUnit@@6B@'), ['CUnit', '<vftable>']) &&
    eq(objcmp.name_parts('??_GCUnit@@UAEPAXI@Z'), ['CUnit', '<sdtor>'])
  check(`name mapping: ${cases.length + 2 - bad.length}/${cases.length + 2} decorated/source pairs, vftable/sdtor`,
        !bad.length && special, pyRepr(bad.slice(0, 3)))

  const failed = RESULTS.filter(([, ok]) => !ok).map(([n]) => n)
  print(`\n${RESULTS.length - failed.length}/${RESULTS.length} checks passed` + (failed.length ? `; FAILED: ${pyRepr(failed)}` : ''))
  return failed.length ? 1 : 0
}

if (isMainModule(import.meta.url)) runMain(() => main())
