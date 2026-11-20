#!/usr/bin/env node
// JavaScript port of code_coverage_check.py (same CLI, coverage_check.json, stdout, exit code). Node built-ins only.
// One difference that cannot be matched: Python builds summary.gap_nonpad_bytes_by_kind by iterating a set of
// strings, whose order changes from run to run (hash randomization); this port uses first-occurrence order.
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dump, dumps, load } from './lib/pyjson.mjs'
import { ArgParser, cmp, hex, iterLines, pyInt, pySplit, readText, runMain } from './lib/pytools.mjs'
import { pyRound } from './lib/pycompat.mjs'

const nameOf = (b) => {
  let n = b.length
  while (n > 0 && b[n - 1] === 0) n--
  return b.subarray(0, n).toString('latin1')
}

export function pe_parse(d) {
  const pe = d.readUInt32LE(0x3c)
  const nsec = d.readUInt16LE(pe + 6)
  const optsz = d.readUInt16LE(pe + 20)
  const opt = pe + 24
  const entry = d.readUInt32LE(opt + 16)
  const base = d.readUInt32LE(opt + 28)
  const ndirs = d.readUInt32LE(opt + 92)
  const dirs = []
  for (let i = 0; i < ndirs; i++) dirs.push([d.readUInt32LE(opt + 96 + 8 * i), d.readUInt32LE(opt + 100 + 8 * i)])
  const secs = []
  for (let i = 0; i < nsec; i++) {
    const o = opt + optsz + 40 * i
    secs.push({ name: nameOf(d.subarray(o, o + 8)), va: d.readUInt32LE(o + 12), vsz: d.readUInt32LE(o + 8),
                rsz: d.readUInt32LE(o + 16), rptr: d.readUInt32LE(o + 20), exec: Boolean(d.readUInt32LE(o + 36) & 0x20000000) })
  }
  return [base, entry, dirs, secs]
}

export function rva_to_off(secs, rva) {
  for (const s of secs) {
    if (s.va <= rva && rva < s.va + Math.max(s.vsz, s.rsz)) return rva - s.va < s.rsz ? s.rptr + rva - s.va : null
  }
  return null
}

export function relocs(d, base, dirs, secs) {
  const [rva, size] = dirs.length > 5 ? dirs[5] : [0, 0]
  const out = new Map()                     // site VA -> target VA
  let off = size ? rva_to_off(secs, rva) : null
  if (off === null) return out              // no relocations (stripped: /FIXED exe)
  const end = off + size
  while (off < end) {
    const page = d.readUInt32LE(off), bsz = d.readUInt32LE(off + 4)
    if (bsz < 8) break
    for (let i = 0; i < Math.floor((bsz - 8) / 2); i++) {
      const e = d.readUInt16LE(off + 8 + 2 * i)
      if (e >> 12 === 3) {
        const site = page + (e & 0xfff)
        const so = rva_to_off(secs, site)
        if (so !== null) out.set(base + site, d.readUInt32LE(so))
      }
    }
    off += bsz
  }
  return out
}

export function exports(d, base, dirs, secs) {
  const [rva, size] = dirs[0]
  if (!size) return new Set()
  const o = rva_to_off(secs, rva)
  const nfun = d.readUInt32LE(o + 20)
  const afun = d.readUInt32LE(o + 28)
  const ao = rva_to_off(secs, afun)
  const out = new Set()
  for (let i = 0; i < nfun; i++) {
    const r = d.readUInt32LE(ao + 4 * i)
    if (r && !(rva <= r && r < rva + size)) out.add(base + r)   // skip forwarders
  }
  return out
}

// Sorted VA ranges [lo, hi) of bytes the loader (or a debugger) reads as PE structures: every data directory
// (except the certificate table, which is a file offset) plus what the import, export and debug directories point
// to. Linkers place these in .text when .rdata/.idata are merged into it (/MERGE).
export function pe_metadata(d, base, dirs, secs) {
  const out = []
  const add = (rva, n) => {
    if (rva && n > 0 && rva_to_off(secs, rva) !== null) out.push([base + rva, base + rva + n])
  }
  const u32 = (rva) => {
    const o = rva_to_off(secs, rva)
    return o !== null && o + 4 <= d.length ? d.readUInt32LE(o) : null
  }
  const cstr = (rva) => {                   // length of the C string at rva including its NUL, 0 if none
    const o = rva_to_off(secs, rva)
    if (o === null) return 0
    const e = d.subarray(0, Math.min(o + 4096, d.length)).indexOf(0, o)
    return e >= 0 ? e - o + 1 : 0
  }
  dirs.forEach(([rva, size], i) => { if (i !== 4) add(rva, size) })
  const [irva, isize] = dirs.length > 1 ? dirs[1] : [0, 0]
  for (let k = 0; k < (isize ? 4096 : 0); k++) {   // import descriptors, up to the all-zero one
    const o = rva_to_off(secs, irva + 20 * k)
    if (o === null || o + 20 > d.length) break
    const oft = d.readUInt32LE(o), name = d.readUInt32LE(o + 12), ft = d.readUInt32LE(o + 16)
    add(irva + 20 * k, 20)
    if (!(oft || name || ft)) break
    add(name, cstr(name))
    for (const arr of [oft, ft]) {
      for (let j = 0; j < (arr ? 65536 : 0); j++) {
        const v = u32(arr + 4 * j)
        if (v === null) break
        add(arr + 4 * j, 4)
        if (!v) break
        if (arr === (oft || ft) && !(v & 0x80000000)) add(v, 2 + cstr(v + 2))   // hint/name entry
      }
    }
  }
  const [erva, esize] = dirs.length ? dirs[0] : [0, 0]
  const eo = esize ? rva_to_off(secs, erva) : null
  if (eo !== null && eo + 40 <= d.length) {
    const r = (k) => d.readUInt32LE(eo + 12 + 4 * k)
    const name = r(0), nfun = r(2), nnames = r(3), afun = r(4), anames = r(5), aords = r(6)
    add(name, cstr(name)); add(afun, 4 * nfun); add(anames, 4 * nnames); add(aords, 2 * nnames)
    for (let j = 0; j < nnames; j++) {
      const v = u32(anames + 4 * j)
      if (v) add(v, cstr(v))
    }
  }
  const [drva, dsize] = dirs.length > 6 ? dirs[6] : [0, 0]
  for (let k = 0; k < Math.floor(dsize / 28); k++) {   // debug directory entries -> their data
    const o = rva_to_off(secs, drva + 28 * k)
    if (o !== null && o + 28 <= d.length) add(d.readUInt32LE(o + 20), d.readUInt32LE(o + 16))
  }
  return out.sort((x, y) => x[0] - y[0] || x[1] - y[1])
}

// instructions.tsv -> [calls, jumps, instr_func] ; functions.tsv -> sorted body ranges [[lo, hi, entry]]
export function load_listing(ddir) {
  const calls = new Set(), jumps = new Set(), ins_fn = new Map()
  const il = iterLines(readText(join(ddir, 'instructions.tsv')))
  if (!il.length) throw new Error('StopIteration')
  for (const line of il.slice(1)) {
    const f = pySplit(line, '\t', 5).slice(0, 5)
    if (f.length !== 5) throw new Error(`ValueError: not enough values to unpack (expected 5, got ${f.length})`)
    const [a, , fn, flow, targets] = f
    ins_fn.set(pyInt(a, 16), fn)
    if (targets && (flow === 'call' || flow === 'jump' || flow === 'cjump')) {
      for (const t of targets.split(',')) (flow === 'call' ? calls : jumps).add(pyInt(t, 16))
    }
  }
  const ranges = []
  const fl = iterLines(readText(join(ddir, 'functions.tsv')))
  if (!fl.length) throw new Error('StopIteration')
  for (const line of fl.slice(1)) {
    const f = line.replace(/\n+$/, '').split('\t')
    if (f.length !== 3) throw new Error(`ValueError: expected 3 values to unpack, got ${f.length}`)
    const [entry, , body] = f
    for (const r of body.split(',')) {
      if (r) {
        const lh = r.split('-')
        if (lh.length !== 2) throw new Error('ValueError: expected 2 values to unpack')
        ranges.push([pyInt(lh[0], 16), pyInt(lh[1], 16), pyInt(entry, 16)])
      }
    }
  }
  ranges.sort((x, y) => x[0] - y[0] || x[1] - y[1] || x[2] - y[2])
  return [calls, jumps, ins_fn, ranges]
}

export const PAD = new Set([0xcc, 0x90])

const zeros = (b, lo, hi) => { for (let i = lo; i < hi; i++) if (b[i] !== 0) return false; return true }

// Length of MSVC alignment filler at the start of b (same forms as padLen() in scripts/ghidra/*.java), else 0.
export function pad_len(b0) {
  const b = Buffer.alloc(9, 0xff)
  Buffer.from(b0.subarray(0, 9)).copy(b, 0)
  if (b[0] === 0xcc || b[0] === 0x90) return 1
  if (b[0] === 0x8b && [0xff, 0xc0, 0xc9, 0xd2, 0xdb, 0xf6].includes(b[1])) return 2
  if (b[0] === 0x66 && b[1] === 0x90) return 2
  if (b[0] === 0x8d) {
    const mod = b[1] >> 6, reg = (b[1] >> 3) & 7, rm = b[1] & 7
    if (reg === rm && rm !== 4 && mod === 1 && b[2] === 0) return 3
    if (reg === rm && rm !== 4 && mod === 2 && zeros(b, 2, 6)) return 6
    if (b[1] === 0x64 && b[2] === 0x24 && b[3] === 0x00) return 4
    if (b[1] === 0xa4 && b[2] === 0x24 && zeros(b, 3, 7)) return 7
  }
  const o = b[0] === 0x66 ? 1 : 0
  if (b[o] === 0x0f && b[o + 1] === 0x1f) {
    const m = b[o + 2]
    if (m === 0) return o + 3
    if (m === 0x40 && b[o + 3] === 0) return o + 4
    if (m === 0x44 && zeros(b, o + 3, o + 5)) return o + 5
    if (m === 0x80 && zeros(b, o + 3, o + 7)) return o + 7
    if (m === 0x84 && zeros(b, o + 3, o + 8)) return o + 8
  }
  return 0
}
export const MIN_REGION_NONFILL = 32768   // unreferenced_region: non-filler bytes without any relocation

// Shannon entropy of b in bits per byte (byte counts summed in ascending order, as the Python)
export function entropy(b) {
  const n = b.length
  if (!n) return 0
  const hist = new Array(256).fill(0)
  for (const c of b) hist[c]++
  hist.sort((x, y) => x - y)
  let t = 0
  for (const c of hist) if (c) t += c / n * Math.log2(c / n)
  return -t
}

// Python '%.2f': exact value rounded half to even (toFixed rounds 3.625 up), sign kept for -0.0
const fmt2 = (x) => (x < 0 || Object.is(x, -0) ? '-' : '') + pyRound(Math.abs(x), 2).toFixed(2)

export const PROLOGUES = ['558bec', '8bff55', '83ec', '81ec', '6a', '68', '53', '56',
  '57', '55', '8b4424', '8b4c24', '8b5424', 'a1', '8b0d',
  '33c0', 'b8', 'e9', 'ff25', '8bc1', '51', 'c3', 'c2', '8b01'].map((h) => Buffer.from(h, 'hex'))

function bisectRight(arr, x) {
  let lo = 0, hi = arr.length
  while (lo < hi) {
    const mid = (lo + hi) >> 1
    if (x < arr[mid]) hi = mid
    else lo = mid + 1
  }
  return lo
}

export function main(argv) {
  const ap = new ArgParser('code_coverage_check.py', [{ name: 'binary' }, { name: 'decompiled_dir' }])
  const a = ap.parse(argv)
  const d = readFileSync(a.binary)
  const [base, entry, dirs, secs] = pe_parse(d)
  const text = secs.filter((s) => s.exec)
  const in_text = (va) => text.some((s) => base + s.va <= va && va < base + s.va + s.vsz)
  const byte_at = (va) => {
    const o = rva_to_off(secs, va - base)
    return o !== null ? (o < d.length ? d[o] : (() => { throw new Error('IndexError: index out of range') })()) : null
  }
  const bytes_at = (va, n) => {             // clipped to the file data of va's section
    const o = rva_to_off(secs, va - base)
    if (o === null) return Buffer.alloc(0)
    const s = secs.find((x) => x.va <= va - base && va - base < x.va + Math.max(x.vsz, x.rsz))
    return d.subarray(o, Math.min(o + n, s.rptr + s.rsz))
  }
  const rel = relocs(d, base, dirs, secs)
  const has_rel = rel.size > 0
  const reloc_sites = rel
  const ptr_targets = new Set([...rel.values()].filter(in_text))
  const exp = exports(d, base, dirs, secs)
  exp.add(base + entry)
  let [calls, jumps, ins_fn, ranges] = load_listing(a.decompiled_dir)
  calls = new Set([...calls].filter(in_text))
  const meta = []                           // PE structures, merged into disjoint [lo, hi]
  for (const [lo, hi] of pe_metadata(d, base, dirs, secs)) {
    if (meta.length && lo <= meta[meta.length - 1][1]) meta[meta.length - 1][1] = Math.max(meta[meta.length - 1][1], hi)
    else meta.push([lo, hi])
  }
  const mstarts = meta.map((m) => m[0])
  const in_meta = (va) => {
    const i = bisectRight(mstarts, va) - 1
    return i >= 0 && va < meta[i][1]
  }
  // addresses in .text that instructions use as operands (op_refs: any operand, only needed without
  // relocations) and as memory operands, i.e. read or written as data (mem_refs: `movzx eax, byte [ecx + T]`)
  const ins_lens = new Map(), op_refs = new Set(), mem_refs = new Set(), fall_into = new Set()
  const il = iterLines(readText(join(a.decompiled_dir, 'instructions.tsv')))
  for (const line of il.slice(1)) {
    const f = pySplit(line, '\t', 2).slice(0, 2)
    if (f.length !== 2) throw new Error('ValueError: not enough values to unpack (expected 2)')
    ins_lens.set(pyInt(f[0], 16), pyInt(f[1]))
    const fields = line.replace(/\n+$/, '').split('\t')
    const txt = fields.at(-1)
    // continues at the next byte (Ghidra gives a tail-call JMP the flow "call": it does not)
    if (fields.length > 3 && ['fall', 'call', 'cjump', 'ccall'].includes(fields[3]) && !txt.startsWith('JMP')) {
      fall_into.add(pyInt(f[0], 16) + pyInt(f[1]))
    }
    for (const m of txt.matchAll(/\[[^\]]*0x([0-9a-f]+)\]/g)) {
      const v = parseInt(m[1], 16)
      if (in_text(v)) mem_refs.add(v)
    }
    if (!has_rel) {
      for (const m of txt.matchAll(/0x([0-9a-f]+)/g)) {
        const v = parseInt(m[1], 16)
        if (in_text(v)) op_refs.add(v)
      }
    }
  }
  const data_refs = has_rel ? new Set(rel.values()) : op_refs
  if (has_rel) for (const v of [...mem_refs]) if (!data_refs.has(v)) mem_refs.delete(v)   // real address operands are relocated
  const site_list = [...rel.keys()].sort((x, y) => x - y)
  const data_ptr_targets = new Set(rel.values())          // pointed to from data only
  for (const [x, t] of rel) if (in_text(x)) data_ptr_targets.delete(t)
  const u32_at = (va) => {
    const b = bytes_at(va, 4)
    return b.length === 4 ? b.readUInt32LE(0) : null
  }
  // A code pointer at va: a relocation site pointing into code; without relocations, a dword holding an
  // instruction start inside a function that continues a table, or starts a run of such dwords of which one
  // is at an address an instruction uses (`jmp [ecx*4 + T]`; T may be inside the table, as in memcpy's).
  const holds_code = (va) => {
    const v = u32_at(va)
    return v !== null && (ins_fn.get(v) ?? '-') !== '-'
  }
  const code_ptr = (va, in_table) => {
    if (has_rel) return reloc_sites.has(va) && in_text(rel.get(va))
    if (in_table) return holds_code(va)
    for (let k = va; holds_code(k); k += 4) if (op_refs.has(k)) return true
    return false
  }
  const str_len = (va) => {                 // length (with NUL) of a non-empty printable ASCII C string, else 0
    const b = bytes_at(va, 4096)
    let k = 0
    while (k < b.length && ((b[k] >= 0x20 && b[k] < 0x7f) || b[k] === 9 || b[k] === 10 || b[k] === 13)) k++
    return k && k < b.length && b[k] === 0 ? k + 1 : 0
  }
  const gcd = (a, b) => { while (b) [a, b] = [b, a % b]; return a }
  // Length of an array of fixed-size records at p (a relocation target pointed to from data only) whose pointer
  // slot - one dword per record at a fixed offset - holds a relocated pointer to non-executable data or NULL in
  // every record, with >= 3 such pointers (DirectInput c_dfDI* DIOBJECTDATAFORMAT tables); else 0.
  const record_table = (p, end) => {
    if (!data_ptr_targets.has(p)) return 0
    const sites = site_list.slice(bisectLeft(site_list, p), bisectLeft(site_list, end))
    if (sites.length < 3 || sites.some((x) => in_text(rel.get(x)))) return 0
    let st = 0
    for (let j = 0; j + 1 < sites.length; j++) st = gcd(st, sites[j + 1] - sites[j])
    const c = st ? (sites[0] - p) % st : 0
    if (st < 4 || st % 4 || c % 4) return 0
    let k = 0
    while (p + (k + 1) * st <= end && (reloc_sites.has(p + c + k * st) || u32_at(p + c + k * st) === 0)) k++
    if (p + k * st <= sites[sites.length - 1] ||
        bisectLeft(branch_targets, p) !== bisectLeft(branch_targets, p + k * st)) return 0
    return k * st
  }
  // relocation-free intervals of .text (between relocation sites/targets and exports) with >= MIN_REGION_NONFILL
  // non-filler bytes: compiled code cannot run that long without an absolute address
  const regions = []
  for (const s of has_rel ? text : []) {
    const lo = base + s.va, hi = base + s.va + Math.max(s.vsz, s.rsz)    // as Ghidra's memory block
    const aset = new Set()
    for (const x of rel.keys()) if (lo <= x && x < hi) for (let k = 0; k < 4; k++) aset.add(x + k)
    for (const t of rel.values()) if (lo <= t && t < hi) aset.add(t)
    for (const e of exp) if (lo <= e && e < hi) aset.add(e)
    const anchors = [...aset].sort((x, y) => x - y)
    let prev = lo
    for (const x of [...anchors, hi]) {
      if (x - prev >= MIN_REGION_NONFILL) {
        const raw = bytes_at(prev, x - prev)
        let nonfill = 0
        for (const c of raw) if (c !== 0 && c !== 0xcc && c !== 0x90) nonfill++
        if (nonfill >= MIN_REGION_NONFILL) regions.push({ start: hex(prev), len: x - prev, nonfill, entropy: fmt2(entropy(raw)) })
      }
      prev = Math.max(prev, x + 1)
    }
  }
  const rbounds = regions.map((r) => [pyInt(r.start, 16), pyInt(r.start, 16) + r.len])
  const branch_targets = [...new Set([...calls, ...jumps])].sort((x, y) => x - y)
  const branch_set = new Set(branch_targets)
  const entered = [...new Set([...branch_targets, ...fall_into])].sort((x, y) => x - y)   // branch or fall-through
  const bisectLeft = (arr, x) => {
    let lo = 0, hi = arr.length
    while (lo < hi) { const mid = (lo + hi) >> 1; if (arr[mid] < x) lo = mid + 1; else hi = mid }
    return lo
  }
  const rstarts = ranges.map((r) => r[0])
  const containing = (va) => {                // Ghidra function bodies never overlap
    const i = bisectRight(rstarts, va) - 1
    return i >= 0 && va <= ranges[i][1] ? ranges[i][2] : null
  }
  const idx = load(join(a.decompiled_dir, 'index.json')).get('functions')
  const funcs = idx.filter((f) => !(f.get('name').startsWith('thunk_') || f.get('name').startsWith('EXTERNAL')) &&
                                  in_text(pyInt(f.get('address'), 16)))
  const fset = new Set(idx.map((f) => pyInt(f.get('address'), 16)))
  const cls = { called: 0, pointer: 0, export_or_entry: 0, jump_only: 0, unreferenced: 0 }
  const unref = []
  for (const f of funcs) {
    const va = pyInt(f.get('address'), 16)
    let k
    if (calls.has(va)) k = 'called'
    else if (ptr_targets.has(va)) k = 'pointer'
    else if (exp.has(va)) k = 'export_or_entry'
    else if (jumps.has(va)) k = 'jump_only'
    else {
      k = 'unreferenced'
      const prev = byte_at(va - 1)
      const head = bytes_at(va, 4)
      unref.push({ address: hex(va), size: f.get('size'),
                   starts_with_filler: pad_len(Buffer.concat([head, bytes_at(va + 4, 5)])) > 0,
                   after_padding: PAD.has(prev) || prev === 0xc3 || prev === 0xc2 || prev === null,
                   prologue_like: PROLOGUES.some((p) => head.length >= p.length && head.subarray(0, p.length).equals(p)),
                   head: head.toString('hex') })
    }
    cls[k] += 1
  }
  const calls_not_start = [...calls].filter((t) => !fset.has(t)).map(hex).sort(cmp)
  const inc = (o, k, n = 1) => { o[k] = (o[k] ?? 0) + n }
  // gaps
  const gaps = [], records = []
  for (const line of iterLines(readText(join(a.decompiled_dir, 'coverage_gaps.txt')))) {
    const m = /^0x([0-9a-f]+) len=([0-9]+)/.exec(line)
    if (!m) continue
    const g = parseInt(m[1], 16), n = parseInt(m[2], 10)
    const raw = bytes_at(g, n)
    const region = rbounds.some(([lo, hi]) => lo <= g && g + n <= hi) &&
      bisectLeft(entered, g) === bisectLeft(entered, g + n)
    // walk: filler | relocated code pointers (jump table) | small bytes after a table (switch index) |
    // PE structures | referenced strings
    const parts = []
    let i = 0, seen_table = false, entries = 0, last = null
    while (i < n) {
      // a relocated pointer wins over filler: table entries can start with 0x90/0xCC/0x8B
      if (i + 4 <= n && code_ptr(g + i, last === 'jump_table')) {
        entries = last === 'jump_table' ? entries + 1 : 1
        parts.push(['jump_table', 4]); i += 4; seen_table = true; last = 'jump_table'; continue
      }
      const prev = last
      last = null
      if (i >= raw.length) { parts.push(['uninitialized', n - i]); break }   // past the section's file data
      if (in_meta(g + i)) { parts.push(['pe_metadata', 1]); i += 1; last = 'pe_metadata'; continue }
      const sl = data_refs.has(g + i) ? str_len(g + i) : 0
      if (sl && i + sl <= n) { parts.push(['string', sl]); i += sl; last = 'string'; continue }
      const pl = pad_len(raw.subarray(i))
      if (pl && i + pl <= n) {
        let anyReloc = false
        for (let k = 1; k < pl; k++) if (reloc_sites.has(g + i + k)) { anyReloc = true; break }
        if (!anyReloc) { parts.push(['filler', pl]); i += pl; continue }
      }
      if (seen_table && raw[i] < Math.max(entries, 1)) { parts.push(['index_bytes', 1]); i += 1; continue }   // switch index
      const rl = record_table(g + i, g + Math.min(n, raw.length))
      if (rl) { parts.push(['record_table', rl]); records.push([g + i, g + i + rl]); i += rl; continue }
      if (mem_refs.has(g + i) && !branch_set.has(g + i)) {   // read as data: up to the next reference
        let k = i + 1
        while (k < Math.min(n, raw.length) && !(mem_refs.has(g + k) || data_refs.has(g + k) || branch_set.has(g + k) ||
                                                 in_meta(g + k))) k++
        parts.push(['data_read', k - i]); i = k; last = 'data_read'; continue
      }
      if ((prev === 'pe_metadata' || prev === 'string' || prev === 'data_read') && raw[i] === 0) {   // zero padding after data
        parts.push([prev, 1]); i += 1; last = prev; continue
      }
      parts.push([region ? 'unreferenced_region' : 'other', 1]); i += 1
    }
    const tot = {}
    for (const [k, ln] of parts) inc(tot, k, ln)
    const other = tot.other ?? 0
    let kind = ['jump_table', 'index_bytes', 'pe_metadata', 'string', 'data_read', 'record_table', 'unreferenced_region',
      'uninitialized']
      .filter((k) => k in tot).join('+') || 'filler_only'
    if (other) kind = 'UNEXPLAINED(' + kind + ')'
    const nonpad = n - (tot.filler ?? 0)
    const detail = Object.entries(tot).sort((x, y) => cmp(x[0], y[0])).map(([k, v]) => `${k}=${v}`).join(' ')
    gaps.push({ address: hex(g), len: n, nonpad, kind, detail, hex: raw.subarray(0, 48).toString('hex') })
    if (region) gaps[gaps.length - 1].entropy = fmt2(entropy(raw))
  }
  const gap_unexplained = gaps.filter((g) => g.kind.startsWith('UNEXPLAINED')).length
  // every relocated pointer into code
  const pk = {}
  const ptr_unexplained = []
  for (const t of [...ptr_targets].sort((x, y) => x - y)) {
    if (fset.has(t)) inc(pk, 'function_start')
    else if (containing(t) !== null) inc(pk, 'inside_function')
    else if (rel.has(t) && in_text(rel.get(t))) inc(pk, 'jump_table_start')
    else if (rel.has(t - 4) && in_text(rel.get(t - 4))) inc(pk, 'index_table_start')
    else if (in_meta(t)) inc(pk, 'pe_metadata')
    else if (str_len(t)) inc(pk, 'string')
    else if (records.some(([lo, hi]) => lo <= t && t < hi)) inc(pk, 'record_table')
    else {
      inc(pk, 'UNEXPLAINED')
      ptr_unexplained.push({ target: hex(t), referenced_from: [...rel].filter(([, v]) => v === t).map(([x]) => hex(x)).slice(0, 4),
                             bytes: bytes_at(t, 16).toString('hex') })
    }
  }
  // jump tables Ghidra decoded as instructions
  const tsites = [...rel].filter(([x, v]) => in_text(v) && in_text(x)).map(([x]) => x).sort((x, y) => x - y)
  const runs = []
  let i = 0
  while (i < tsites.length) {
    let j = i
    while (j + 1 < tsites.length && tsites[j + 1] === tsites[j] + 4) j++
    if (j > i) runs.push([tsites[i], tsites[j] + 4])
    i = j + 1
  }
  const istarts = [...ins_lens.keys()].sort((x, y) => x - y)
  const table_as_code = []
  for (const [lo, hi] of runs) {
    let k = Math.max(bisectRight(istarts, lo) - 1, 0)
    const hit = []
    while (k < istarts.length && istarts[k] < hi) {
      if (istarts[k] + ins_lens.get(istarts[k]) > lo) hit.push(istarts[k])
      k++
    }
    if (hit.length) {
      table_as_code.push({ table: hex(lo), entries: Math.floor((hi - lo) / 4), instructions: hit.length,
                           function: hex(containing(hit[0]) || 0) })
    }
  }
  const gap_kinds = {}
  for (const g of gaps) inc(gap_kinds, g.kind)
  const gap_nonpad = {}
  for (const k of Object.keys(gap_kinds)) gap_nonpad[k] = gaps.filter((g) => g.kind === k).reduce((s, g) => s + g.nonpad, 0)
  const summ = {
    relocations: rel.size, functions: funcs.length, reach: cls,
    unreferenced_starting_with_filler: unref.filter((u) => u.starts_with_filler).length,
    unreferenced_prologue_like: unref.filter((u) => u.prologue_like).length,
    direct_call_targets: calls.size, direct_call_targets_not_function_start: calls_not_start.length,
    relocated_pointers_into_text: ptr_targets.size, pointers: pk,
    unreferenced_regions: regions.length, gaps: gaps.length, gap_kinds, gap_nonpad_bytes_by_kind: gap_nonpad,
  }
  summ.jump_tables_decoded_as_code = { tables: table_as_code.length,
                                       instructions: table_as_code.reduce((s, t) => s + t.instructions, 0) }
  const fails = { direct_call_targets_not_function_start: calls_not_start.length,
                  pointers_unexplained: pk.UNEXPLAINED ?? 0, gaps_unexplained: gap_unexplained,
                  unreferenced_starting_with_filler: summ.unreferenced_starting_with_filler }
  summ.must_be_zero = fails
  dump({ summary: summ, unreferenced: unref, calls_not_function_start: calls_not_start,
         jump_tables_decoded_as_code: table_as_code, pointers_unexplained: ptr_unexplained,
         unreferenced_regions: regions, gaps },
       join(a.decompiled_dir, 'coverage_check.json'), { indent: 1 })
  const bad = Object.entries(fails).filter(([, v]) => v).map(([k]) => k)
  process.stdout.write(dumps(summ, { indent: 1 }) + '\n')
  process.stdout.write((bad.length ? 'FAIL: ' + bad.join(', ') : 'PASS') + '\n')
  return bad.length ? 1 : 0
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(() => main(process.argv.slice(2)))
}
