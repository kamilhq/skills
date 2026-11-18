#!/usr/bin/env node
// relink.mjs - JavaScript port of relink.py (phase 6: relink a PE with the original linker, link.exe, from
// compiled objects + objects made from assembly). Same command line, stdout/stderr, files and exit codes:
//
//   relink.mjs prepare <reassembled_dir> <symbols.json> <decompiled_dir> <out_dir> [--cache <file>]
//                      [--libdir <dir>]... [--free]
//   relink.mjs link <out_dir> <original>          lib.exe / link.exe / mt.exe under Wine through ../msvc.sh
//   relink.mjs check <out_dir> <original> <symbols.json> <instructions.tsv> <functions index.json>
//   relink.mjs finish <out_dir> <original>        (RELINK_FACTS=rich,timestamp,iat_order,rsrc,checksum)
//
// See relink.py for the description. Library use: Coff, read_imports, import_rounds, prepare, rva_fields,
// reloc_vsize, read_resources, write_res, msvc_path, lib_imports, name_imports, link, pe_checksum, finish,
// check, main(argv). Python tuples are arrays, dicts Maps; (dll, name) dict keys are `${dll}\0${name}` strings.
// Deviation: the temp dir Python's prepare leaves behind (the phase-5b image) is removed.
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import * as objcmp from './objcmp.mjs'
import * as reassemble from './reassemble.mjs'
import { dump, dumps, load } from './lib/pyjson.mjs'
import { pyBasename, pyJoin, pySplitext } from './lib/pycompat.mjs'
import { cmp, iterLines, pyLstrip, pyStrip, readText, runMain, S, SysExit } from './lib/pytools.mjs'
import { bisectRight, dataLines, tsvFields } from './hybrid_link.mjs'

const HERE = reassemble.HERE
const DOC = "Phase 6: relink a PE with the original linker (link.exe) from compiled objects + objects made from assembly.\n\n  relink.py prepare <reassembled_dir> <symbols.json> <decompiled_dir> <out_dir> [--cache <file>]\n                    [--libdir <dir with import .lib files, e.g. the Windows SDK's Lib>]... [--free]\n      --free: build from source. The map may hold edited functions (hybrid_link.py map --all): each replaces\n      its original slot and the code after it moves; sections new to the original (literals, constants,\n      helpers) come from the units' objects, new code after the original code, new data after the original\n      data. Skips the .reloc calibration; `finish` does not apply.\n      Writes into <out_dir>:\n        code_NNN.obj     the code section as COMDAT pieces: every function hybrid_link.py mapped as identical\n                         (the COMPILER's bytes, its relocations retargeted to synthetic symbols _A_<va>) and the\n                         phase-5b assembly between them, split at every function start (absolute pointers ->\n                         DIR32, direct rel32 branches leaving a piece -> REL32)\n        round<k>.obj     pieces that use imports of link.exe's library-search pass k >= 2 (the CRT, SDL2main...),\n                         turned into round<k>.lib at link time and placed after the last import library of that\n                         pass, so link.exe pulls them - and their imports - in the same passes as the original\n        imports_order.obj  undefined symbols only: the first pass's imports in the original's hint/name order\n        imp_<dll>.def    import libraries to generate (DLLs that no --libdir library matches by name and hint)\n        data.obj         .rdata/.data(+.bss)/... as raw sections with DIR32 relocations; the export table as\n                         .edata, the load config as __load_config_used; IAT and import tables left out (link.exe\n                         builds them from the import libraries)\n        resources.res + manifest.xml  when the original's .rsrc was rewritten by mt.exe (PADDINGXX fill)\n        order.txt, link.rsp  /ORDER file (every code COMDAT in address order) and link.exe options from the header\n  relink.py link <out_dir> <original>\n      lib.exe for the .def/.obj libraries, link.exe, mt.exe for the manifest; measures the .reloc reserve once\n      and adds dropped.obj (a discarded COMDAT with the missing relocation count) and links again. Compares\n      with the original: SHA-256, section by section, data directories, header bytes (compare.json).\n  relink.py check <out_dir> <original> <symbols.json> <instructions.tsv> <functions index.json>\n      For a --free build: every direct branch and code pointer of the original (outside edited functions)\n      must reach its target's new address in the link map (relinked.map). Exit 0 when none misses.\n  relink.py finish <out_dir> <original>\n      Post-link facts the inputs cannot reproduce (Rich header, timestamp, IAT slot order inside each DLL,\n      Wine-vs-Windows UpdateResource bytes, checksum), taken from the original, applied to relinked.exe ->\n      final.exe with every patched byte counted per fact (facts.json). Exit 0 when final.exe is identical.\n\nSynthetic symbols: every relocation target gets `_A_<hex va>` defined in the piece that contains it; targets in\nthe headers use `___ImageBase`; IAT slots become `__imp_<symbol>` of the import library. Python stdlib + the\nuser's toolchain (link.exe, lib.exe, mt.exe under Wine) only.\n"

export const DIR32 = 0x6, DIR32NB = 0x7, REL32 = 0x14
export const SCN_CNT_CODE = 0x20, SCN_CNT_IDATA = 0x40, SCN_CNT_UDATA = 0x80
export const SCN_LNK_COMDAT = 0x1000, SCN_EXEC = 0x20000000, SCN_READ = 0x40000000, SCN_WRITE = 0x80000000
export const ALIGN1 = 0x00100000

const print = (...a) => process.stdout.write(a.join(' ') + '\n')
const hex = (n) => (n < 0 ? '-0x' + (-n).toString(16) : '0x' + n.toString(16))
const pyErr = (name, msg) => { const e = new Error(msg); e.name = name; return e }
function nextOf(it, pred) {
  for (const x of it) if (pred(x)) return x
  throw pyErr('StopIteration', '')
}
const k2 = (a, b) => `${a}\0${b}`
const numSort = (arr) => arr.sort((x, y) => x - y)
const u32 = (b, o) => b.readUInt32LE(o)
const u16 = (b, o) => b.readUInt16LE(o)
// the last n code points of a str (Python s[-n:])
function tail(s, n) {
  if (s.length <= n) return s
  const cps = Array.from(s)
  return cps.length <= n ? s : cps.slice(cps.length - n).join('')
}

export function sname(va) { return `_A_${va.toString(16)}` }

// Minimal i386 COFF writer: sections with several symbols, COMDATs, relocations
export class Coff {
  constructor() { this.secs = []; this.undefined = [] }

  section(name, ch, data, size = null, comdat = false) {
    this.secs.push({ name, ch, data, size: size !== null ? size : (data ? data.length : 0), relocs: [], syms: [], comdat })
    return this.secs.length          // 1-based section number
  }

  symbol(secnum, name, value, external = true) { this.secs[secnum - 1].syms.push([name, value, external]) }

  reloc(secnum, off, name, typ) { this.secs[secnum - 1].relocs.push([off, name, typ]) }

  write(path) {
    const strtab = [Buffer.alloc(4)]
    let strlen = 4
    const nm8 = (n) => {
      const b = Buffer.from(n, 'latin1')
      if (b.length <= 8) return Buffer.concat([b, Buffer.alloc(8 - b.length)])
      const off = strlen
      strtab.push(b, Buffer.alloc(1))
      strlen += b.length + 1
      const r = Buffer.alloc(8)
      r.writeUInt32LE(off, 4)
      return r
    }
    const syms = [], index = new Map()
    const rec = (name, value, secnum, type, storage, naux) => {
      const r = Buffer.alloc(18)
      nm8(name).copy(r, 0)
      r.writeUInt32LE(value >>> 0, 8); r.writeInt16LE(secnum, 12); r.writeUInt16LE(type, 14); r[16] = storage; r[17] = naux
      return r
    }
    // explicitly listed undefined symbols first (their order is the order link.exe meets them), then the
    // other relocation targets
    const defined = new Set(this.secs.flatMap((s) => s.syms.map((x) => x[0])))
    const undef = [...new Set(this.undefined)].filter((n) => !defined.has(n))
    const undefSet = new Set(undef)
    this.secs.forEach((s, k) => {
      const i = k + 1
      syms.push(rec(s.name, 0, i, 0, 3, 1))
      const aux = Buffer.alloc(18)
      if (s.relocs.length > 0xFFFF) throw pyErr('struct.error', "'H' format requires 0 <= number <= 65535")
      aux.writeUInt32LE(s.size, 0); aux.writeUInt16LE(s.relocs.length, 4); aux[14] = s.comdat ? 2 : 0
      syms.push(aux)
      for (const [n, v, ext] of s.syms) {
        index.set(n, syms.length)
        syms.push(rec(n, v, i, (s.ch & SCN_EXEC) ? 0x20 : 0, ext ? 2 : 3, 0))
      }
    })
    for (const s of this.secs) {
      for (const [, n] of s.relocs) if (!index.has(n) && !undefSet.has(n)) { undef.push(n); undefSet.add(n) }
    }
    for (const n of undef) {
      index.set(n, syms.length)
      syms.push(rec(n, 0, 0, 0, 2, 0))
    }
    const nsec = this.secs.length
    let off = 20 + 40 * nsec
    const layout = []
    for (const s of this.secs) {
      const dptr = s.data !== null ? off : 0
      off += s.data !== null ? s.data.length : 0
      const rptr = s.relocs.length ? off : 0
      off += 10 * s.relocs.length
      layout.push([dptr, rptr])
    }
    const parts = []
    const hdr = Buffer.alloc(20)
    hdr.writeUInt16LE(0x14c, 0); hdr.writeUInt16LE(nsec, 2); hdr.writeUInt32LE(off, 8); hdr.writeUInt32LE(syms.length, 12)
    parts.push(hdr)
    this.secs.forEach((s, k) => {
      const h = Buffer.alloc(40)
      nm8(s.name).copy(h, 0)
      h.writeUInt32LE(s.size, 16); h.writeUInt32LE(layout[k][0], 20); h.writeUInt32LE(layout[k][1], 24)
      h.writeUInt16LE(s.relocs.length, 32); h.writeUInt32LE(s.ch >>> 0, 36)
      parts.push(h)
    })
    for (const s of this.secs) {
      if (s.data !== null) parts.push(Buffer.from(s.data))
      for (const [o, n, t] of s.relocs) {
        const r = Buffer.alloc(10)
        r.writeUInt32LE(o, 0); r.writeUInt32LE(index.get(n), 4); r.writeUInt16LE(t, 8)
        parts.push(r)
      }
    }
    parts.push(...syms)
    const len = Buffer.alloc(4)
    len.writeUInt32LE(strlen, 0)
    parts.push(len, ...strtab.slice(1))
    writeFileSync(path, Buffer.concat(parts))
    return syms.length
  }
}

function offOf(secs, rva) {
  const x = nextOf(secs, (s) => s.va <= rva && rva < s.va + Math.max(s.vsize, s.raw_size))
  return x.raw_ptr + rva - x.va
}

// Import descriptors in file order: [[dll, [[hint, name, iat_rva]]]], plus the RVA span of the import data
// link.exe builds outside the IAT
export function read_imports(img, dirs, secs) {
  if (dirs.length < 2 || !dirs[1][1]) return [[], null]
  const off = (rva) => offOf(secs, rva)
  const cstr = (rva) => {
    const o = off(rva)
    const z = img.indexOf(0, o)
    if (z < 0) throw pyErr('ValueError', 'subsection not found')
    return img.subarray(o, z).toString('latin1')
  }
  const out = []
  let lo = dirs[1][0], hi = dirs[1][0], i = 0
  for (;;) {
    const d = off(dirs[1][0] + 20 * i)
    const oft = u32(img, d), name = u32(img, d + 12), ft = u32(img, d + 16)
    if (!oft && !name) {
      hi = Math.max(hi, dirs[1][0] + 20 * (i + 1))
      break
    }
    const dll = cstr(name)
    hi = Math.max(hi, name + dll.length + 1)
    const fns = []
    let k = 0
    for (;;) {
      const e = u32(img, off(oft + 4 * k))
      if (e === 0) break
      if (e & 0x80000000) throw new SysExit(1, `${dll}: import by ordinal not supported`)
      const hint = u16(img, off(e))
      const fn = cstr(e + 2)
      fns.push([hint, fn, ft + 4 * k])
      lo = Math.min(lo, oft, e)
      hi = Math.max(hi, oft + 4 * (k + 2), e + 2 + fn.length + 1)
      k++
    }
    out.push([dll, fns])
    i++
  }
  return [out, [lo, hi]]
}

// Split the imports into link.exe's library-search passes, from the order of the hint/name entries.
// Returns [[[dll, name]...] per pass, [dll in library order]]
export function import_rounds(img, dirs, secs, imports) {
  const off = (rva) => offOf(secs, rva)
  const entries = []
  imports.forEach(([dll, fns], i) => {
    const oft = u32(img, off(dirs[1][0] + 20 * i))
    fns.forEach(([, fn], k) => entries.push([u32(img, off(oft + 4 * k)), dll, fn]))
  })
  entries.sort((a, b) => a[0] - b[0] || cmp(a[1], b[1]) || cmp(a[2], b[2]))
  const lib_order = [...new Set(entries.map((e) => e[1]))]
  const rank = new Map(lib_order.map((d, i) => [d, i]))
  const rounds = [[]]
  let prev = null
  for (const [, dll, fn] of entries) {
    if (prev !== null && dll !== prev && rank.get(dll) < rank.get(prev)) rounds.push([])
    rounds[rounds.length - 1].push([dll, fn])
    prev = dll
  }
  return [rounds, lib_order]
}

export function prepare(reasm, map_path, ddir, outdir, cache = null, libdirs = [], free = false) {
  mkdirSync(outdir, { recursive: true })
  const m = load(map_path)
  const msyms = m.get('symbols')
  const getOr = (mp, k, d) => (mp.has(k) ? mp.get(k) : d)
  if (m.get('functions').some((f) => !getOr(f, 'identical', true)) && !free) {
    throw new SysExit(1, 'the map has edited functions: use --free (build from source, layout may change)')
  }
  if (free) writeFileSync(join(outdir, 'FREE'), 'build from source: layout may differ from the original\n')
  else if (existsSync(join(outdir, 'FREE'))) unlinkSync(join(outdir, 'FREE'))
  const new_secs = getOr(m, 'new_sections', new Map())
  const newKeys = [...new_secs.keys()].sort(cmp)
  const new_name = new Map(newKeys.map((nk, i) => [nk, `_N_${i}`]))
  const tmp = mkdtempSync(join(tmpdir(), 'tmp'))
  let img
  try {
    reassemble.build(reasm, join(tmp, 'img.bin'), cache)
    img = readFileSync(join(tmp, 'img.bin'))
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
  const [base, dirs, secs] = reassemble.pe_parse(img)
  const [rel, reloc_name] = reassemble.relocs_of(img, base, dirs, secs)
  const T = nextOf(secs, (s) => s.exec)
  const t0 = base + T.va
  const t_end = t0 + Math.min(T.vsize, T.raw_size)

  const raw = (va, n) => {
    const s = nextOf(secs, (x) => x.va <= va - base && va - base < x.va + Math.max(x.raw_size, x.vsize))
    const o = va - base - s.va
    const a = s.raw_ptr + o, e = s.raw_ptr + Math.min(o + n, s.raw_size)
    const b = img.subarray(Math.min(a, img.length), Math.max(Math.min(a, img.length), Math.min(e, img.length)))
    return Buffer.concat([b, Buffer.alloc(Math.max(0, n - b.length))])
  }
  // compiled functions. A target is an original VA (from the map), ['self', offset] or ['new', symbol, offset]
  const target_of = (o, t, own_secnum, own_value, edited) => {
    if (edited && own_secnum > 0 && t.secnum === own_secnum) return ['self', (t.is_section_sym ? 0 : t.value) - own_value]
    const bn = objcmp.basename(o.path)
    const base_key = (t.is_section_sym || (t.storage !== objcmp.CLASS_EXTERNAL && t.storage !== objcmp.CLASS_WEAK && t.secnum > 0))
      ? `${bn}#${t.name}#sec${t.secnum}` : t.name
    const qk = `${bn}@${base_key}`
    const v = msyms.has(qk) ? msyms.get(qk) : msyms.has(base_key) ? msyms.get(base_key) : null
    if (v instanceof Map) return ['new', new_name.get(v.get('new')), v.get('offset')]
    if (v === null) throw new SysExit(1, `${bn}: no address for ${base_key}`)
    return v
  }
  let funcs = []
  const objs = new Map()
  const getObj = (p) => { if (!objs.get(p)) objs.set(p, objcmp.read_coff(p)); return objs.get(p) }
  const edited_vas = new Set()
  for (const f of m.get('functions')) {
    const va = parseInt(f.get('va'), 16)
    const o = getObj(f.get('obj'))
    const sym = nextOf(o.symbols.values(), (s) => s.index === f.get('index') && s.name === f.get('symbol'))
    const [code, rels] = o.function_bytes(sym)
    const ed = !getOr(f, 'identical', true)
    if (ed) edited_vas.add(va)
    const tr = rels.filter((r) => r.type !== 0 && r.symbol !== null)
      .map((r) => [r.offset, r.type, target_of(o, r.symbol, sym.secnum, sym.value, ed)])
    funcs.push([va, Buffer.from(code), tr])
  }
  // sections taken from the units' objects for edited functions (new literals, constants, helpers)
  const new_pieces = []
  for (const nk of newKeys) {
    const ns = new_secs.get(nk)
    const o = getObj(ns.get('obj'))
    const sec = o.sections[ns.get('section') - 1]
    const tr = sec.relocs.filter((r) => r.type !== 0 && r.symbol !== null)
      .map((r) => [r.offset, r.type, target_of(o, r.symbol, ns.get('section'), 0, true)])
    new_pieces.push([new_name.get(nk), sec, tr])
  }
  funcs.sort((a, b) => a[0] - b[0] || Buffer.compare(a[1], b[1]))
  // pieces of the code section: compiled functions and the stretches between them
  let pieces = []          // [start, end, kind, payload]; end = the original extent
  const fstarts = numSort(load(join(ddir, 'index.json')).get('functions').map((f) => parseInt(f.get('address'), 16)))
  const fvas = funcs.map((f) => f[0])
  let cur = t0
  funcs.forEach(([va, code, tr], n_) => {
    if (va > cur) pieces.push([cur, va, 'asm', null])
    let end = va + code.length
    if (edited_vas.has(va)) {       // an edited function replaces its original extent (up to the next function)
      const bi = bisectRight(fstarts, va)
      const nxt = [bi < fstarts.length ? fstarts[bi] : null, n_ + 1 < fvas.length ? fvas[n_ + 1] : null, t_end].filter((x) => x !== null)
      end = Math.min(...nxt)
    }
    pieces.push([va, end, 'fn', [code, tr]])
    cur = end
  })
  if (cur < t_end) pieces.push([cur, t_end, 'asm', null])
  // assembly stretches are split at every function start
  const split = []
  for (const [ps, pe_, kind, payload] of pieces) {
    if (kind !== 'asm') { split.push([ps, pe_, kind, payload]); continue }
    const lo = bisectRight(fstarts, ps)
    let hi = lo
    while (hi < fstarts.length && fstarts[hi] < pe_) hi++
    const cuts_ = [ps, ...fstarts.slice(lo, hi), pe_]
    for (let k = 0; k + 1 < cuts_.length; k++) split.push([cuts_[k], cuts_[k + 1], 'asm', null])
  }
  pieces = split
  const starts = pieces.map((p) => p[0])
  // direct branches in asm stretches that leave the stretch
  const br = new Map()
  for (const line of dataLines(join(ddir, 'instructions.tsv'))) {
    const [a, ln, , flow, targets] = tsvFields(line)
    if ((flow === 'call' || flow === 'jump' || flow === 'cjump') && targets) {
      br.set(parseInt(a, 16), [parseInt(ln, 10), parseInt(targets.split(',')[0], 16)])
    }
  }
  // every relocation target needs a symbol in the piece / section that holds it
  const targets = new Set()
  for (const [, , tr] of funcs) for (const [, , t] of tr) if (!Array.isArray(t)) targets.add(t)
  for (const [, , tr] of new_pieces) for (const [, , t] of tr) if (!Array.isArray(t)) targets.add(t)
  // RVA fields the PE keeps without base relocations (SafeSEH table, export table): DIR32NB relocations
  const rva_sites = rva_fields(img, base, dirs, secs)
  for (const v of rva_sites.values()) targets.add(v)
  for (const v of rel.values()) targets.add(v)
  const _pe = u32(img, 0x3c)
  targets.add(u32(img, _pe + 24 + 16) + base)     // the entry point
  let data_secs = secs.filter((s) => !s.exec && s.name !== reloc_name)

  const where = (va) => {
    if (t0 <= va && va < t_end) return ['code', bisectRight(starts, va) - 1]
    for (let j = 0; j < data_secs.length; j++) {
      const s = data_secs[j]
      if (s.va <= va - base && va - base < s.va + Math.max(s.vsize, s.raw_size)) return ['data', j]
    }
    return ['header', null]
  }
  // imports: link.exe builds the IAT and the import tables from import libraries
  const [imports, imp_span] = read_imports(img, dirs, secs)
  const sdk = new Map()
  for (const ld of libdirs) {
    for (const fn_ of readdirSync(ld).sort(cmp)) {
      if (fn_.toLowerCase().endsWith('.lib')) {
        let li
        try {
          li = lib_imports(pyJoin(ld, fn_))
        } catch (e) {
          if (e instanceof LibFormatError || e instanceof RangeError) continue
          throw e
        }
        for (const [k, v] of li) if (!sdk.has(k)) sdk.set(k, [v[0], v[1], pyJoin(ld, fn_)])
      }
    }
  }
  const use_lib = new Map(), sym_of = new Map()
  for (const [dll, fns] of imports) {
    const hit = fns.map(([, fn]) => sdk.get(k2(dll.toUpperCase(), fn)))
    const libs_ = new Set(hit.filter(Boolean).map((h) => h[2]))
    if (hit.every((h, i) => h && h[0] === fns[i][0]) && libs_.size === 1) {
      use_lib.set(dll, [...libs_][0])
      hit.forEach((h, i) => sym_of.set(k2(dll, fns[i][1]), h[1]))
    } else {
      for (const [, fn] of fns) sym_of.set(k2(dll, fn), '_' + fn)
    }
  }
  const iat_name = new Map()
  for (const [dll, fns] of imports) for (const [, fn, rva] of fns) iat_name.set(base + rva, `__imp_${sym_of.get(k2(dll, fn))}`)
  const code_syms = new Map(), ext_name = new Map()
  let data_syms = new Map()
  const addTo = (mp, k, v) => { if (!mp.has(k)) mp.set(k, new Set()); mp.get(k).add(v) }
  for (const t of targets) {
    if (iat_name.has(t)) { ext_name.set(t, iat_name.get(t)); continue }
    const [kind, i] = where(t)
    if (kind === 'code') { addTo(code_syms, i, t); ext_name.set(t, sname(t)) }
    else if (kind === 'data') { addTo(data_syms, i, t); ext_name.set(t, sname(t)) }
    else ext_name.set(t, null)      // headers: ___ImageBase + addend
  }
  // pre-pass: direct rel32 branches in asm stretches whose target lies in another piece
  const branch_relocs = new Map()
  let rel8_cross = 0
  const rel8_pairs = []
  pieces.forEach(([s, e, kind], i) => {
    if (kind !== 'asm') return
    for (let a2 = s; a2 < e; a2++) {
      if (!br.has(a2)) continue
      const [ln, tgt] = br.get(a2)
      if (s <= tgt && tgt < e) continue
      const b = raw(a2, ln)
      let o
      if ((b[0] === 0xe8 || b[0] === 0xe9) && ln === 5) o = a2 - s + 1
      else if (b[0] === 0x0f && ln === 6 && 0x80 <= b[1] && b[1] <= 0x8f) o = a2 - s + 2
      else {
        rel8_cross++          // short branch across pieces: relies on identical layout
        rel8_pairs.push([a2, tgt])
        continue
      }
      const [kk, i2] = where(tgt)
      if (kk !== 'code') continue
      addTo(code_syms, i2, tgt)
      ext_name.set(tgt, sname(tgt))
      if (!branch_relocs.has(i)) branch_relocs.set(i, [])
      branch_relocs.get(i).push([o, tgt])
    }
  })
  if (edited_vas.size) {
    // an edited function moves everything after it: nothing may point into its old interior, and no short
    // branch between two other pieces may span it
    const bad = []
    const ranges = pieces.filter((p) => edited_vas.has(p[0])).map((p) => [p[0], p[1]]).sort((a, b) => a[0] - b[0] || a[1] - b[1])
    const rstarts = ranges.map((r) => r[0])
    const in_edited = (x) => { const k = bisectRight(rstarts, x) - 1; return k >= 0 && x < ranges[k][1] }
    const outside = new Set()
    for (const [site, v] of rel) if (!in_edited(site)) outside.add(v)
    for (const [site, v] of rva_sites) if (!in_edited(site)) outside.add(v)
    for (const [va_, , tr_] of funcs) if (!edited_vas.has(va_)) for (const [, , t] of tr_) if (!Array.isArray(t)) outside.add(t)
    for (const brs of branch_relocs.values()) for (const [, t] of brs) outside.add(t)
    outside.add(base + u32(img, u32(img, 0x3c) + 40))
    pieces.forEach((p_, i) => {
      if (!edited_vas.has(p_[0])) return
      for (const t of (code_syms.get(i) || [])) if (t !== p_[0] && outside.has(t)) bad.push(`${hex(t)} (inside ${hex(p_[0])})`)
      for (const [x, y] of rel8_pairs) {
        if ((Math.min(x, y) <= p_[0] && p_[0] < Math.max(x, y)) || (Math.min(x, y) < p_[1] && p_[1] <= Math.max(x, y))) {
          bad.push(`short branch ${hex(x)}->${hex(y)} spans ${hex(p_[0])}`)
        }
      }
    })
    if (bad.length) throw new SysExit(1, 'edited functions cannot move: ' + bad.slice(0, 10).join('; '))
  }
  const stats = { rel8_branches_across_pieces: rel8_cross, edited_functions: edited_vas.size, new_sections: new_pieces.length,
                  code_pieces: pieces.length, compiled: funcs.length, asm: pieces.filter((p) => p[2] === 'asm').length,
                  asm_rel32_relocs: 0, dir32_relocs: 0, header_targets: [...ext_name.values()].filter((v) => v === null).length }
  // Import passes: a piece that uses an import of pass k >= 2 goes into round<k>.lib
  const [rounds, lib_order] = import_rounds(img, dirs, secs, imports)
  const pass_of = new Map()
  rounds.forEach((names, r) => { for (const [dll, fn] of names) pass_of.set(sym_of.get(k2(dll, fn)), r + 1) })
  const piece_imports = pieces.map(([ps, pe_, kind, payload]) => {
    let tv
    if (kind === 'fn') tv = payload[1].map((x) => x[2])
    else { tv = []; for (let x = ps; x < pe_; x++) if (rel.has(x)) tv.push(rel.get(x)) }
    return tv.filter((t) => !Array.isArray(t) && iat_name.has(t)).map((t) => ext_name.get(t).slice(6))
  })
  const piece_pass = piece_imports.map((ims) => (ims.length ? Math.max(...ims.map((n) => pass_of.get(n))) : 1))
  const ppp = new Map()
  for (const k of numSort([...new Set(piece_pass)])) ppp.set(k, piece_pass.filter((x) => x === k).length)
  stats.pieces_per_pass = ppp

  const _emit = (c, sec, data, off, typ, tva, add) => {
    let nm = ext_name.has(tva) ? ext_name.get(tva) : null
    if (nm === null) {
      nm = '___ImageBase'
      add = tva - base + add
      data.writeInt32LE(add, off)
    }
    c.reloc(sec, off, nm, typ)
    if (typ === DIR32) stats.dir32_relocs++
  }
  const emit_targets = (c, sec, data, tr, self_name) => {
    for (const [off, typ, tva] of tr) {
      const add = data.readInt32LE(off)
      if (Array.isArray(tva)) {
        const [name, extra] = tva[0] === 'self' ? [self_name, tva[1]] : [tva[1], tva[2]]
        data.writeInt32LE(add + extra, off)
        c.reloc(sec, off, name, typ)
      } else _emit(c, sec, data, off, typ, tva, add)
    }
  }
  const write_piece = (c, i) => {
    const [s, e, kind, payload] = pieces[i]
    const data = kind === 'fn' ? Buffer.from(payload[0]) : raw(s, e - s)
    const sec = c.section('.text$mn', SCN_CNT_CODE | SCN_EXEC | SCN_READ | SCN_LNK_COMDAT | ALIGN1, data, null, true)
    c.symbol(sec, sname(s), 0)
    for (const t of numSort([...(code_syms.get(i) || [])])) if (t !== s) c.symbol(sec, sname(t), t - s)
    if (kind === 'fn') emit_targets(c, sec, data, payload[1], sname(s))
    else {
      for (let site = s; site < e; site++) {
        if (rel.has(site)) {
          data.writeUInt32LE(0, site - s)
          _emit(c, sec, data, site - s, DIR32, rel.get(site), 0)
        }
      }
      for (const [o, tgt] of (branch_relocs.get(i) || [])) {
        data.writeInt32LE(0, o)          // MSVC REL32: in-place addend 0
        c.reloc(sec, o, ext_name.get(tgt), REL32)
        stats.asm_rel32_relocs++
      }
    }
  }
  const order = pieces.map((p) => sname(p[0]))
  const plain = []
  piece_pass.forEach((p, i) => { if (p === 1) plain.push(i) })
  let nobj = 0
  const per_obj = 400
  const objName = (n) => `code_${String(n).padStart(3, '0')}.obj`
  for (let k = 0; k < plain.length; k += per_obj) {
    const c = new Coff()
    for (const i of plain.slice(k, k + per_obj)) write_piece(c, i)
    c.write(join(outdir, objName(nobj)))
    nobj++
  }
  stats.plain_pieces = plain.length
  let has_new_data = false
  if (new_pieces.length) {        // new code after the original code, new data after the original data
    const c = new Coff(), nd = new Coff()
    for (const [nm_, sec_, tr] of new_pieces) {
      let ch, name
      if (sec_.is_code) {
        ch = SCN_CNT_CODE | SCN_EXEC | SCN_READ | ALIGN1
        name = '.text$mn'
      } else {
        ch = sec_.characteristics & ~(0x00F00000 | SCN_LNK_COMDAT | 0x800 | 0x200)
        ch |= 0x00300000               // 4-byte alignment
        name = sec_.name.split('$')[0] || '.rdata'
      }
      const udata = Boolean(sec_.characteristics & SCN_CNT_UDATA)
      const data = udata ? null : Buffer.from(sec_.data.subarray(0, sec_.size))
      const cc = sec_.is_code ? c : nd
      const n_ = cc.section(name, ch, data, sec_.size)
      cc.symbol(n_, nm_, 0)
      if (data !== null) emit_targets(cc, n_, data, tr, nm_)
    }
    if (c.secs.length) { c.write(join(outdir, objName(nobj))); nobj++ }
    if (nd.secs.length) { nd.write(join(outdir, 'new_data.obj')); has_new_data = true }
  }
  // data sections
  const dd_rva = new Map()
  for (const k of [0, 1, 10, 12]) if (dirs.length > k && dirs[k][1]) dd_rva.set(k, dirs[k])
  // Resources (mt.exe-rewritten .rsrc -> resources.res + manifest.xml)
  const res = read_resources(img, dirs, secs)
  const rsrc_sec = data_secs.find((x) => dirs.length > 2 && dirs[2][1] && x.va === dirs[2][0]) ?? null
  let mt_manifest = null
  if (res.length && rsrc_sec !== null) {
    const tl = img.subarray(rsrc_sec.raw_ptr + rsrc_sec.vsize, rsrc_sec.raw_ptr + rsrc_sec.raw_size)
    const mans = res.filter((r) => r[0] === 24)
    if (tl.includes(Buffer.from('PADDINGXX', 'latin1')) && mans.length === 1 && mans[0][1] === 1) {
      for (const t of targets) {
        if (rsrc_sec.va <= t - base && t - base < rsrc_sec.va + rsrc_sec.vsize) {
          throw new SysExit(1, 'pointers into .rsrc: cannot rebuild it from a .res file')
        }
      }
      mt_manifest = mans[0][3]
      writeFileSync(join(outdir, 'manifest.xml'), mt_manifest)
      write_res(join(outdir, 'resources.res'), res.filter((r) => r[0] !== 24))
      data_secs = data_secs.filter((x) => x !== rsrc_sec)
      const ds = new Map()
      secs.filter((y) => !y.exec && y.name !== reloc_name).forEach((x, j_) => {
        if (data_secs.includes(x)) ds.set(data_secs.indexOf(x), data_syms.get(j_) || new Set())
      })
      data_syms = ds
    }
  }
  stats.resources = mt_manifest ? 'resources.res + mt.exe manifest' : 'raw .rsrc'
  const d = new Coff()
  data_secs.forEach((s, j) => {
    const n = s.name
    const rawb = s.raw_size ? Buffer.from(img.subarray(s.raw_ptr, s.raw_ptr + s.raw_size)) : Buffer.alloc(0)
    const vlen = s.vsize || s.raw_size
    const writable = n !== '.rdata' && n !== '.rsrc'
    const ch = SCN_CNT_IDATA | SCN_READ | (writable ? SCN_WRITE : 0) | ALIGN1
    const init_len = s.vsize ? Math.min(s.raw_size, s.vsize) : s.raw_size
    const cuts = new Map([[0, n]])
    cuts.set(init_len, null)
    if (n === '.rdata') {
      const sva = s.va
      const inside = (r) => sva <= r && r < sva + init_len
      if (dd_rva.has(0) && inside(dd_rva.get(0)[0])) cuts.set(dd_rva.get(0)[0] - sva, '.edata')
      // the IAT and the import tables are left out: link.exe builds them from the import libraries
      const spans = [...(dd_rva.has(12) ? [[dd_rva.get(12)[0], dd_rva.get(12)[0] + dd_rva.get(12)[1]]] : []), ...(imp_span ? [imp_span] : [])]
      for (const [lo_r, hi_r] of spans) {
        if (!inside(lo_r)) continue
        const gt = [...cuts.keys()].filter((c) => c > lo_r - sva)
        const nxt = gt.length ? Math.min(...gt) : init_len
        cuts.set(lo_r - sva, null)                      // skipped
        if (hi_r - sva < nxt && rawb.subarray(hi_r - sva, nxt).some((x) => x !== 0)) {
          if (!cuts.has(hi_r - sva)) cuts.set(hi_r - sva, '.rdata')
        }
      }
    }
    const pts = numSort([...cuts.keys()])
    for (let k = 0; k + 1 < pts.length; k++) {
      const lo = pts[k], hi = pts[k + 1]
      if (hi <= lo) continue
      const nm = cuts.get(lo)
      if (nm === null) {
        const bad = []
        for (const site of rel.keys()) if (lo <= site - base - s.va && site - base - s.va < hi) bad.push(hex(site))
        for (const t of (data_syms.get(j) || [])) if (lo <= t - base - s.va && t - base - s.va < hi) bad.push(hex(t))
        if (bad.length) throw new SysExit(1, `pointers into the import tables at [${bad.slice(0, 5).map((x) => `'${x}'`).join(', ')}]`)
        continue
      }
      // .edata keeps the original's alignment (link pads after the import tables to reach it)
      let al = ch
      if (nm === '.edata') {
        const ev = s.va + lo
        al = (ch & ~0x00F00000) | (ev % 16 === 0 ? 0x00500000 : ev % 4 === 0 ? 0x00300000 : ALIGN1)
      }
      const sec = d.section(nm, al, Buffer.from(rawb.subarray(lo, hi)))
      const sdata = d.secs[sec - 1].data
      d.symbol(sec, `_SEC_${pyStrip(nm, '.').replaceAll('$', '_')}_${lo.toString(16)}`, 0)
      for (const t of numSort([...(data_syms.get(j) || [])])) {
        const off = t - base - s.va
        if (lo <= off && off < hi) d.symbol(sec, sname(t), off - lo)
      }
      if (dd_rva.has(10) && s.va + lo <= dd_rva.get(10)[0] && dd_rva.get(10)[0] < s.va + hi) {
        d.symbol(sec, '__load_config_used', dd_rva.get(10)[0] - s.va - lo)
      }
      for (const [site, v] of rel) {
        const off = site - base - s.va
        if (lo <= off && off < hi) {
          sdata.writeUInt32LE(0, off - lo)
          _emit(d, sec, sdata, off - lo, DIR32, v, 0)
        }
      }
      for (const [site, v] of rva_sites) {
        const off = site - base - s.va
        if (lo <= off && off < hi) {
          sdata.writeUInt32LE(0, off - lo)
          d.reloc(sec, off - lo, ext_name.get(v), DIR32NB)
          stats.dir32nb_relocs = (stats.dir32nb_relocs || 0) + 1
        }
      }
    }
    if (vlen > init_len) {                 // zero-initialised tail -> .bss (merged into the section by link)
      const bsec = d.section('.bss', SCN_CNT_UDATA | SCN_READ | SCN_WRITE | ALIGN1, null, vlen - init_len)
      for (const t of numSort([...(data_syms.get(j) || [])])) {
        const off = t - base - s.va
        if (off >= init_len) d.symbol(bsec, sname(t), off - init_len)
      }
    }
  })
  d.write(join(outdir, 'data.obj'))
  const libs = []
  const stemOf = (dll) => pySplitext(dll)[0].toLowerCase()
  for (const [dll, fns] of imports) {
    if (use_lib.has(dll)) continue
    const stem = stemOf(dll)
    if (fns.some(([h]) => h === 0)) throw new SysExit(1, `${dll}: hint 0 cannot be written as a /DEF ordinal`)
    writeFileSync(join(outdir, `imp_${stem}.def`), `LIBRARY "${dll}"\nEXPORTS\n` + fns.map(([h, fn]) => `  ${fn} @${h} DATA\n`).join(''))
    libs.push(`imp_${stem}`)
  }
  // Import order (see relink.py): imports_order.obj names the first pass's imports in order; the pieces using
  // pass-k imports form the one member of round<k>.lib, placed after the last import library of that pass
  const lib_for = new Map(imports.map(([dll]) => [dll, use_lib.get(dll) || `imp_${stemOf(dll)}.lib`]))
  const rank = new Map(lib_order.map((dll, i) => [dll, i]))
  const ordered = (names) => names.map(([dll, fn]) => `__imp_${sym_of.get(k2(dll, fn))}`)
  const io = new Coff()
  io.undefined = ordered(rounds[0])
  io.write(join(outdir, 'imports_order.obj'))
  const slot_libs = new Map(lib_order.map((dll) => [dll, []]))
  const round_libs = []
  const owner = new Map()
  pieces.forEach((p_, i) => { for (const t of [p_[0], ...numSort([...(code_syms.get(i) || [])])]) owner.set(sname(t), i) })
  for (let k = 2; k <= rounds.length; k++) {
    const members = []
    piece_pass.forEach((p, i) => { if (p === k) members.push(i) })
    if (!members.length) continue
    const c = new Coff()
    const mine = new Set(members.flatMap((i) => piece_imports[i]))
    c.undefined = [...ordered(rounds[k - 1]).filter((x) => mine.has(x.slice(6)))]
    for (let kk = k - 1; kk > 0; kk--) c.undefined.push(...ordered(rounds[kk - 1]).filter((x) => mine.has(x.slice(6))))
    for (const i of members) write_piece(c, i)
    c.write(join(outdir, `round${k}.obj`))
    round_libs.push(`round${k}`)
    let last = null
    for (const [dll, fn] of rounds[k - 1]) {
      if (mine.has(sym_of.get(k2(dll, fn))) && (last === null || rank.get(dll) > rank.get(last))) last = dll
    }
    if (last === null) throw pyErr('ValueError', 'max() arg is an empty sequence')
    slot_libs.get(last).push(`round${k}.lib`)
    // a member of a pass >= 3 must not be referenced by anything linked before its pass
    if (k >= 3) {
      const ms = new Set(members)
      const early = new Set()
      for (let i = 0; i < pieces.length; i++) {
        if (!(piece_pass[i] < k - 1)) continue
        for (const r of _piece_refs(pieces[i], rel, branch_relocs.get(i) || [], ext_name)) {
          if (owner.has(r[1]) && ms.has(owner.get(r[1]))) early.add(owner.get(r[1]))
        }
      }
      if (early.size) {
        (stats.warnings ||= []).push(`round${k}: referenced from earlier pieces [${numSort([...early]).slice(0, 5).join(', ')}]`)
      }
    }
  }
  stats.import_passes = rounds.map((r) => r.length)
  writeFileSync(join(outdir, 'order.txt'), order.map((o) => o.slice(1)).join('\n') + '\n')
  // options from the PE header
  const pe = u32(img, 0x3c)
  const opt = pe + 24
  const entry = u32(img, opt + 16) + base
  const subsystem = u16(img, opt + 68)
  const dllch = u16(img, opt + 70)
  const ssmaj = u16(img, opt + 48), ssmin = u16(img, opt + 50)
  const stack_res = u32(img, opt + 72), stack_com = u32(img, opt + 76), heap_res = u32(img, opt + 80), heap_com = u32(img, opt + 84)
  const falign = u32(img, opt + 36)
  const salign = u32(img, opt + 32)
  const opts = ['/NOLOGO', '/MACHINE:X86', `/BASE:0x${base.toString(16)}`, `/ENTRY:A_${entry.toString(16)}`, '/NODEFAULTLIB',
    `/SUBSYSTEM:${subsystem === 2 ? 'WINDOWS' : 'CONSOLE'},${ssmaj}.${String(ssmin).padStart(2, '0')}`,
    `/STACK:0x${stack_res.toString(16)},0x${stack_com.toString(16)}`, `/HEAP:0x${heap_res.toString(16)},0x${heap_com.toString(16)}`,
    ...(salign !== 0x1000 ? [`/ALIGN:${salign}`] : []), `/FILEALIGN:${falign}`, '/ORDER:@order.txt', '/OPT:REF', '/OPT:NOICF',
    '/INCREMENTAL:NO', '/MANIFEST:NO', '/SAFESEH:NO',
    (dllch & 0x40) ? '/DYNAMICBASE' : '/DYNAMICBASE:NO', (dllch & 0x100) ? '/NXCOMPAT' : '/NXCOMPAT:NO',
    '/OUT:relinked.exe', '/MAP:relinked.map', 'imports_order.obj',
    ...Array.from({ length: nobj }, (_, i) => objName(i)), 'data.obj',
    ...(has_new_data ? ['new_data.obj'] : []),
    ...(mt_manifest ? ['resources.res'] : []),
    ...lib_order.flatMap((d_) => [use_lib.has(d_) ? msvc_path(lib_for.get(d_)) : lib_for.get(d_), ...slot_libs.get(d_)])]
  writeFileSync(join(outdir, 'libs.txt'), libs.map((x) => `def ${x}\n`).join('') + round_libs.map((x) => `obj ${x}\n`).join(''))
  // /OPT:REF drops the jump thunks of the SDK's code imports; every piece is kept by an /INCLUDE of its symbol
  for (const i of plain) opts.push(`/INCLUDE:${sname(pieces[i][0])}`)
  writeFileSync(join(outdir, 'link.rsp'), opts.join('\n') + '\n')
  stats.objects = nobj + 1
  stats.import_libs = { existing: new Map([...use_lib].map(([d_, v]) => [d_, pyBasename(v)])), generated: libs }
  print(dumps(stats, { indent: 1 }))
  return 0
}

// {field VA: target VA} for RVAs stored without base relocations: SafeSEH handler table entries and the
// export table
export function rva_fields(img, base, dirs, secs) {
  const off = (rva) => offOf(secs, rva)
  const out = new Map()
  if (dirs.length > 10 && dirs[10][1] && u32(img, off(dirs[10][0])) >= 72) {
    const lc = off(dirs[10][0])
    const tab = u32(img, lc + 64), cnt = u32(img, lc + 68)
    if (tab && cnt) for (let i = 0; i < cnt; i++) out.set(tab + 4 * i, u32(img, off(tab - base) + 4 * i) + base)
  }
  if (dirs.length && dirs[0][1]) {
    const [e0, esz] = dirs[0]
    const e = off(e0)
    const name = u32(img, e + 12), nfun = u32(img, e + 20), nnames = u32(img, e + 24)
    const afun = u32(img, e + 28), anames = u32(img, e + 32), aords = u32(img, e + 36)
    for (const [k, v] of [[12, name], [28, afun], [32, anames], [36, aords]]) if (v) out.set(base + e0 + k, base + v)
    for (let i = 0; i < nfun; i++) {
      const v = u32(img, off(afun) + 4 * i)
      if (v && !(e0 <= v && v < e0 + esz)) out.set(base + afun + 4 * i, base + v)
    }
    for (let i = 0; i < nnames; i++) out.set(base + anames + 4 * i, base + u32(img, off(anames) + 4 * i))
  }
  return out
}

export function reloc_vsize(img) {
  const [, dirs, secs] = reassemble.pe_parse(img)
  if (dirs.length < 6 || !dirs[5][1]) return 0
  const x = secs.find((s) => s.va === dirs[5][0])
  return x ? x.vsize : 0
}

// [[type, name, lang, data]] from the resource directory; type/name are numbers or strings
export function read_resources(img, dirs, secs) {
  if (dirs.length < 3 || !dirs[2][1]) return []
  const sec = nextOf(secs, (x) => x.va <= dirs[2][0] && dirs[2][0] < x.va + Math.max(x.vsize, x.raw_size))
  const R = img.subarray(sec.raw_ptr + dirs[2][0] - sec.va, sec.raw_ptr + sec.raw_size)
  const out = []
  const ident = (v) => {
    if (v & 0x80000000) {
      const o = v & 0x7FFFFFFF
      const n = u16(R, o)
      return R.subarray(o + 2, o + 2 + 2 * n).toString('utf16le')
    }
    return v
  }
  const walk = (o, path) => {
    const n1 = u16(R, o + 12), n2 = u16(R, o + 14)
    for (let i = 0; i < n1 + n2; i++) {
      const nm = u32(R, o + 16 + 8 * i), off = u32(R, o + 20 + 8 * i)
      if (off & 0x80000000) walk(off & 0x7FFFFFFF, [...path, ident(nm)])
      else {
        const drva = u32(R, off), sz = u32(R, off + 4)
        const o2 = sec.raw_ptr + drva - sec.va
        out.push([path[0], path[1], ident(nm), img.subarray(o2, o2 + sz)])
      }
    }
  }
  walk(0, [])
  return out
}

// A Win32 .res file (what rc.exe writes) for link.exe / cvtres
export function write_res(path, res) {
  const idb = (v) => {
    if (typeof v === 'number') { const b = Buffer.alloc(4); b.writeUInt16LE(0xFFFF, 0); b.writeUInt16LE(v, 2); return b }
    return Buffer.concat([Buffer.from(v.toUpperCase(), 'utf16le'), Buffer.alloc(2)])
  }
  const parts = []
  const head = Buffer.alloc(32)
  head.writeUInt32LE(32, 4); head.writeUInt16LE(0xFFFF, 8); head.writeUInt16LE(0xFFFF, 12)
  parts.push(head)
  for (const [typ, name, lang, data] of res) {
    let h = Buffer.concat([idb(typ), idb(name)])
    h = Buffer.concat([h, Buffer.alloc((4 - (h.length % 4)) % 4)])
    const t = Buffer.alloc(16)
    t.writeUInt16LE(0x1030, 4); t.writeUInt16LE(lang, 6)
    h = Buffer.concat([h, t])
    const sz = Buffer.alloc(8)
    sz.writeUInt32LE(data.length, 0); sz.writeUInt32LE(8 + h.length, 4)
    parts.push(sz, h, data, Buffer.alloc((4 - (data.length % 4)) % 4))
  }
  writeFileSync(path, Buffer.concat(parts))
}

export function _piece_refs(piece, rel, branches, ext_name) {
  const [s, e, kind, payload] = piece
  const g = (t) => (ext_name.has(t) ? ext_name.get(t) : null)
  if (kind === 'fn') return payload[1].map(([o, , t]) => [o, Array.isArray(t) ? null : g(t)])
  const out = []
  for (let x = s; x < e; x++) if (rel.has(x)) out.push([x - s, g(rel.get(x))])
  for (const [o, t] of branches) out.push([o, g(t)])
  return out
}

// A host path inside a Wine prefix's drive_c as a Windows path for link.exe; other paths unchanged
export function msvc_path(p) {
  const i = p.indexOf('/drive_c/')
  return i >= 0 ? '"C:\\' + p.slice(i + 9).replaceAll('/', '\\') + '"' : p
}

class LibFormatError extends Error { get name() { return 'ValueError' } }
const strictUtf8 = new TextDecoder('utf-8', { fatal: true })
// int(b[o+48:o+58].decode().strip()) of an archive member header
function memberSize(b, o) {
  let s
  try { s = strictUtf8.decode(b.subarray(o + 48, o + 58)) } catch { throw new LibFormatError('invalid utf-8 in member size') }
  const t = pyStrip(s)
  const m = /^([+-]?)(\d(?:_?\d)*)$/.exec(t)
  if (!m) throw new LibFormatError(`invalid literal for int() with base 10: '${t}'`)
  const v = Number(m[2].replaceAll('_', ''))
  return m[1] === '-' ? -v : v
}

// {(DLL upper, import name): [hint, symbol]} for the short import members of an import library
export function lib_imports(lib_path) {
  const b = readFileSync(lib_path)
  let o = 8
  const out = new Map()
  while (o + 60 <= b.length) {
    const size = memberSize(b, o)
    const m = o + 60
    if (u16(b, m) === 0 && u16(b, m + 2) === 0xFFFF) {
      const hint = u16(b, m + 16), t = u16(b, m + 18)
      const n = u32(b, m + 12)
      const parts = []
      const blob = b.subarray(m + 20, m + 20 + n)
      let i = 0
      for (;;) {
        const z = blob.indexOf(0, i)
        if (z < 0) { parts.push(blob.subarray(i)); break }
        parts.push(blob.subarray(i, z)); i = z + 1
      }
      if (parts.length < 2) throw new LibFormatError('not enough values to unpack (expected 2, got 1)')
      const sym = parts[0].toString('latin1'), dll = parts[1].toString('latin1')
      const nt = t >> 2
      const name = nt === 3 ? pyLstrip(sym, '_?@').split('@')[0] : nt === 2 ? sym.slice(1) : sym
      if (nt) out.set(k2(dll.toUpperCase(), name), [hint, sym])
    }
    o = m + size + (size & 1)
  }
  return out
}

// lib.exe /DEF turns `name @n` into an import by ordinal n: every short import member gets name type
// NAME_NOPREFIX; the hint stays in the Ordinal/Hint field
export function name_imports(lib_path) {
  const b = Buffer.from(readFileSync(lib_path))
  if (!b.subarray(0, 8).equals(Buffer.from('!<arch>\n', 'latin1'))) throw pyErr('AssertionError', '')
  let o = 8, n = 0
  while (o + 60 <= b.length) {
    const size = memberSize(b, o)
    const m = o + 60
    if (u16(b, m) === 0 && u16(b, m + 2) === 0xFFFF) {
      const t = u16(b, m + 18)
      b.writeUInt16LE((t & 3) | (2 << 2), m + 18)
      n++
    }
    o = m + size + (size & 1)
  }
  writeFileSync(lib_path, b)
  return n
}

// subprocess.run([...], cwd, capture_output=True, text=True): returncode, stdout + stderr (universal newlines)
function run(args, cwd) {
  const p = spawnSync(args[0], args.slice(1), { cwd, maxBuffer: 1 << 30 })
  if (p.error) throw p.error
  const dec = (b) => new TextDecoder('utf-8').decode(b).replace(/\r\n?/g, '\n')
  return { rc: p.status, text: dec(p.stdout) + dec(p.stderr) }
}

export function link(outdir, original) {
  const sk = join(HERE, 'msvc.sh')
  const libs_txt = join(outdir, 'libs.txt')
  const lines = existsSync(libs_txt) ? readFileSync(libs_txt, 'utf8').split(/\r\n|\r|\n/).filter((x, i, a) => i < a.length - 1 || x !== '') : []
  for (const line of lines) {
    const [kind, x] = line.trim().split(/\s+/)
    const src = kind === 'def' ? `/DEF:${x}.def` : `${x}.obj`
    const p = run(['sh', sk, 'lib', '/NOLOGO', '/MACHINE:X86', src, `/OUT:${x}.lib`], outdir)
    if (p.rc) { print(p.text); return 2 }
    if (kind === 'def') name_imports(join(outdir, `${x}.lib`))
  }
  const out = join(outdir, 'relinked.exe')
  const run_link = () => {
    if (existsSync(out)) unlinkSync(out)
    const p = run(['sh', sk, 'link', '@link.rsp'], outdir)
    print(tail(p.text, 3000))
    return existsSync(out)
  }
  if (!run_link()) return 2
  // .reloc: one discarded COMDAT with the original's missing relocation count (dropped.obj)
  const rsp = join(outdir, 'link.rsp')
  if (!readFileSync(rsp, 'utf8').includes('dropped.obj') && !existsSync(join(outdir, 'FREE'))) {
    const ro = reloc_vsize(readFileSync(original))
    const rn = reloc_vsize(readFileSync(out))
    if (ro && rn && ro > rn && (ro - rn) % 2 === 0) {
      const c = new Coff()
      const k = (ro - rn) / 2
      const sec = c.section('.text$mn', SCN_CNT_CODE | SCN_EXEC | SCN_READ | SCN_LNK_COMDAT | ALIGN1, Buffer.alloc(4 * k), null, true)
      c.symbol(sec, '_relink_discarded_relocations', 0)
      for (let i = 0; i < k; i++) c.reloc(sec, 4 * i, '___ImageBase', DIR32)
      c.write(join(outdir, 'dropped.obj'))
      const txt = readFileSync(rsp, 'utf8').replace('data.obj\n', 'data.obj\ndropped.obj\n')
      writeFileSync(rsp, txt)
      print(`.reloc: ${k} discarded relocations added (dropped.obj); linking again`)
      if (!run_link()) return 2
    }
  }
  if (existsSync(join(outdir, 'manifest.xml'))) {
    const p = run(['sh', sk, 'mt', '-nologo', '-manifest', 'manifest.xml', '-outputresource:relinked.exe;#1'], outdir)
    print(tail(p.text, 2000))
    if (p.rc) return 2
  }
  const a = readFileSync(original), b = readFileSync(out)
  print('SHA-256', a.equals(b) ? 'IDENTICAL' : 'DIFFERENT', `(original ${a.length} bytes, relinked ${b.length})`)
  const [, da, sa] = reassemble.pe_parse(a)
  const [, db, sb] = reassemble.pe_parse(b)
  const rows = []
  for (const s of sa) {
    const t = sb.find((x) => x.name === s.name)
    if (!t) { rows.push({ section: s.name, status: 'missing' }); continue }
    const x = a.subarray(s.raw_ptr, s.raw_ptr + s.raw_size), y = b.subarray(t.raw_ptr, t.raw_ptr + t.raw_size)
    const n = Math.min(x.length, y.length)
    let first = null, diff = 0
    for (let i = 0; i < n; i++) if (x[i] !== y[i]) { if (first === null) first = i; diff++ }
    rows.push({ section: s.name, va: hex(s.va), va_relinked: hex(t.va), vsize: hex(s.vsize), vsize_relinked: hex(t.vsize),
                raw: x.length, raw_relinked: y.length, identical: x.equals(y), first_diff: first === null ? null : hex(first),
                differing_bytes: diff })
  }
  const names = new Set(sa.map((s) => s.name))
  const extra = sb.filter((x) => !names.has(x.name)).map((x) => x.name)
  const dd = []
  for (let i = 0; i < Math.min(da.length, db.length); i++) {
    if (da[i][0] !== db[i][0] || da[i][1] !== db[i][1]) dd.push({ index: i, original: da[i].map(hex), relinked: db[i].map(hex) })
  }
  const ha = a.subarray(0, sa[0].raw_ptr), hb = b.subarray(0, sb[0].raw_ptr)
  let hdiff = 0
  for (let i = 0; i < Math.min(ha.length, hb.length); i++) if (ha[i] !== hb[i]) hdiff++
  const res = { sections: rows, extra_sections: extra, data_directories_differing: dd, header_bytes_differing: hdiff }
  dump(res, join(outdir, 'compare.json'), { indent: 1 })
  print(dumps(res, { indent: 1 }).slice(0, 6000))
  return a.equals(b) ? 0 : 1
}

export function pe_checksum(img, csum_off) {
  let s = 0
  const n = img.length
  const data = n % 2 ? Buffer.concat([img, Buffer.alloc(1)]) : img
  for (let i = 0; i < data.length; i += 2) {
    if (i === csum_off || i === csum_off + 2) continue
    s += data[i] | (data[i + 1] << 8)
    s = (s & 0xFFFF) + Math.floor(s / 0x10000)
  }
  s = (s & 0xFFFF) + Math.floor(s / 0x10000)
  return (s + n) >>> 0
}

// Post-link facts (see relink.py finish): relinked.exe -> final.exe, facts.json
export function finish(outdir, original) {
  const a = readFileSync(original)
  let b = Buffer.from(readFileSync(join(outdir, 'relinked.exe')))
  const facts = new Map(), patched = new Map()
  const only = new Set((process.env.RELINK_FACTS ?? 'rich,timestamp,iat_order,rsrc,checksum').split(','))
  const count = (k, before, after) => {
    let n = 0
    const m = Math.min(before.length, after.length)
    for (let i = 0; i < m; i++) if (before[i] !== after[i]) n++
    patched.set(k, (patched.get(k) || 0) + n + Math.abs(before.length - after.length))
  }
  // 1. Rich header / stub; the PE headers move to the original's e_lfanew
  let la = u32(a, 0x3c)
  const lb = u32(b, 0x3c)
  let [, , sb] = reassemble.pe_parse(b)
  const hdr_end = sb[0].raw_ptr
  const nsec = u16(b, lb + 6)
  const pe_len = 24 + u16(b, lb + 20) + 40 * nsec
  let newh = Buffer.concat([a.subarray(0, la), b.subarray(lb, lb + pe_len)])
  newh = Buffer.concat([newh, Buffer.alloc(Math.max(0, hdr_end - newh.length))])
  if (!only.has('rich')) {
    newh = Buffer.from(b.subarray(0, hdr_end))
    la = lb
  }
  facts.set('rich', { e_lfanew: la, stub_and_rich: a.subarray(0x40, Math.max(0x40, la)).toString('hex') })
  count('rich', b.subarray(0, hdr_end), newh)
  b = Buffer.concat([newh, b.subarray(hdr_end)])
  const pe = la
  // 2. timestamp
  const ts = u32(only.has('timestamp') ? a : b, pe + 8)
  facts.set('timestamp', ts)
  let before = Buffer.from(b.subarray(pe + 8, pe + 12))
  b.writeUInt32LE(ts, pe + 8)
  count('timestamp', before, b.subarray(pe + 8, pe + 12))
  // 3. IAT order
  const [base, da, sa] = reassemble.pe_parse(a)
  let db
  ;[, db, sb] = reassemble.pe_parse(b)
  const [ia] = read_imports(a, da, sa)
  const [ib] = read_imports(b, db, sb)
  const slot_a = new Map(), slot_b = new Map()
  for (const [d, fs] of ia) for (const [, fn, r] of fs) slot_a.set(k2(d, fn), r)
  for (const [d, fs] of ib) for (const [, fn, r] of fs) slot_b.set(k2(d, fn), r)
  if (slot_a.size !== slot_b.size || [...slot_a.keys()].some((k) => !slot_b.has(k))) throw new SysExit(1, 'import sets differ')
  facts.set('iat_order', new Map(ia.map(([d, fs]) => [d, [...fs].sort((x, y) => x[2] - y[2]).map((f) => f[1])])))
  const move = new Map()
  for (const k of slot_a.keys()) move.set(base + slot_b.get(k), base + slot_a.get(k))
  if ([...move].some(([k, v]) => k !== v) && only.has('iat_order')) {
    before = Buffer.from(b)
    const hn = new Map()
    ib.forEach(([d, fs], i) => {
      const oft = u32(b, offOf(sb, db[1][0] + 20 * i))
      fs.forEach(([, fn], k) => hn.set(k2(d, fn), u32(b, offOf(sb, oft + 4 * k))))
    })
    ib.forEach(([d, fs], i) => {
      const dsc = offOf(sb, db[1][0] + 20 * i)
      const oft = u32(b, dsc), ft = u32(b, dsc + 16)
      const order = [...fs].sort((x, y) => slot_a.get(k2(d, x[1])) - slot_a.get(k2(d, y[1])))
      order.forEach(([, fn], k) => {
        b.writeUInt32LE(hn.get(k2(d, fn)), offOf(sb, oft + 4 * k))
        b.writeUInt32LE(hn.get(k2(d, fn)), offOf(sb, ft + 4 * k))
      })
    })
    const [rel] = reassemble.relocs_of(b, base, db, sb)
    for (const [site, v] of rel) if (move.has(v)) b.writeUInt32LE(move.get(v), offOf(sb, site - base))
    count('iat_order', before, b)
  }
  // 4. .rsrc bytes and VirtualSize (Wine vs Windows UpdateResource)
  if (da.length > 2 && da[2][1]) {
    const xa = nextOf(sa, (s) => s.va === da[2][0])
    const xb = nextOf(sb, (s) => s.va === db[2][0])
    const ra = a.subarray(xa.raw_ptr, xa.raw_ptr + xa.raw_size), rb = b.subarray(xb.raw_ptr, xb.raw_ptr + xb.raw_size)
    if (ra.length === rb.length && only.has('rsrc')) {
      const diffs = []
      for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) diffs.push([i, ra[i]])
      facts.set('rsrc', { bytes: diffs, vsize: xa.vsize })
      before = Buffer.from(b)
      for (const [i, v] of diffs) b[xb.raw_ptr + i] = v
      const k = sb.indexOf(xb)
      const sh = pe + 24 + u16(b, pe + 20) + 40 * k
      b.writeUInt32LE(xa.vsize, sh + 8)
      count('rsrc', before, b)
    }
  }
  // 5. checksum
  const csum = pe + 24 + 64
  before = Buffer.from(b.subarray(csum, csum + 4))
  b.writeUInt32LE(pe_checksum(b, csum), csum)
  count('checksum', before, b.subarray(csum, csum + 4))
  dump(facts, join(outdir, 'facts.json'), { indent: 1 })
  writeFileSync(join(outdir, 'final.exe'), b)
  const same = b.equals(a)
  let total = 0
  for (const v of patched.values()) total += v
  print(dumps({ patched_bytes: patched, total_patched: total, file_bytes: b.length,
                sha256: createHash('sha256').update(b).digest('hex'), identical: same }, { indent: 1 }))
  if (!same) {
    let first = null
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) { first = i; break }
    print('first difference at', first !== null ? hex(first) : 'length')
  }
  return same ? 0 : 1
}

const MAP_LINE = new RegExp(`^${S}*[^${S.slice(1, -1)}]+${S}+_A_([0-9a-f]+)${S}+([0-9a-f]{8})`, 'u')

// Differential check of a moved (--free) build (see relink.py check)
export function check(outdir, original, map_path, listing, index_path) {
  const m = load(map_path)
  const edited = numSort(m.get('functions').filter((f) => f.has('identical') && !f.get('identical')).map((f) => parseInt(f.get('va'), 16)))
  const fst = numSort(load(index_path).get('functions').map((f) => parseInt(f.get('address'), 16)))
  const ext = edited.map((e) => { const i = bisectRight(fst, e); return [e, i < fst.length ? fst[i] : e + 1] })
  const in_edited = (va) => ext.some(([x, y]) => x <= va && va < y)
  const O = readFileSync(original)
  const E = readFileSync(join(outdir, 'relinked.exe'))
  const sym = new Map()
  for (const ln of iterLines(readText(join(outdir, 'relinked.map'), { errors: 'replace' }))) {
    const mm = MAP_LINE.exec(ln)
    if (mm) sym.set(parseInt(mm[1], 16), parseInt(mm[2], 16))
  }
  const xs = numSort([...sym.keys()])
  const nw = (va) => {
    let i = bisectRight(xs, va) - 1
    if (i < 0) i += xs.length
    return sym.get(xs[i]) + va - xs[i]
  }
  const [bo, do_, so] = reassemble.pe_parse(O)
  const [be, , se] = reassemble.pe_parse(E)
  const off = (secs, va, base) => {
    const x = nextOf(secs, (s) => s.va <= va - base && va - base < s.va + Math.max(s.vsize, s.raw_size))
    return x.raw_ptr + va - base - x.va
  }
  const T = nextOf(so, (s) => s.exec)
  const t0 = bo + T.va, t1 = bo + T.va + T.vsize
  const n = { branches: 0, pointers: 0 }
  const bad = []
  for (const line of dataLines(listing)) {
    let [a, ln, , flow, tg, text] = tsvFields(line)
    a = parseInt(a, 16); ln = parseInt(ln, 10)
    if (!tg || !['call', 'jump', 'cjump', 'ccall', 'cjmp'].includes(flow) || in_edited(a)) continue
    const oa = off(so, a, bo)
    const b = O.subarray(oa, oa + ln)
    let k
    if ((b[0] === 0xe8 || b[0] === 0xe9) && ln === 5) k = 1
    else if (b[0] === 0x0f && ln === 6 && 0x80 <= b[1] && b[1] <= 0x8f) k = 2
    else if (ln === 2 && (b[0] === 0xeb || (0x70 <= b[0] && b[0] <= 0x7f) || [0xe0, 0xe1, 0xe2, 0xe3].includes(b[0]))) k = 1
    else continue
    const t = parseInt(tg.split(',')[0], 16)
    if (!(t0 <= t && t < t1)) continue
    const na = nw(a), nt = nw(t)
    const oe = off(se, na, be)
    const eb = E.subarray(oe, oe + ln)
    const rel = ln - k === 4 ? eb.readInt32LE(k) : eb.readInt8(k)
    n.branches++
    if (!eb.subarray(0, k).equals(b.subarray(0, k)) || na + ln + rel !== nt) bad.push(`branch ${hex(a)} ${text}`)
  }
  const [rel] = reassemble.relocs_of(O, bo, do_, so)
  for (const [site, v] of rel) {
    if (in_edited(site) || !(t0 <= v && v < t1)) continue
    let ns
    if (t0 <= site && site < t1) ns = nw(site)
    else {
      const sa = so.find((x) => x.va <= site - bo && site - bo < x.va + x.vsize) ?? null
      const sb = se.find((x) => sa && x.name === sa.name) ?? null
      if (sb === null) continue
      ns = site - sa.va + sb.va
    }
    n.pointers++
    if (u32(E, off(se, ns, be)) !== nw(v)) bad.push(`pointer at ${hex(site)} -> ${hex(v)}`)
  }
  print(dumps({ edited_functions: edited.length, checked: n, mismatches: bad.length, first: bad.slice(0, 10) }, { indent: 1 }))
  return bad.length ? 1 : 0
}

export function main(argv = process.argv.slice(2)) {
  const A = ['relink.py', ...argv]          // sys.argv
  if (A.length >= 2 && A[1] === 'prepare' && A.length >= 6) {
    const at = (i) => { if (i >= A.length) throw pyErr('IndexError', 'list index out of range'); return A[i] }
    const cache = A.includes('--cache') ? at(A.indexOf('--cache') + 1) : null
    const libdirs = []
    A.forEach((x, i) => { if (x === '--libdir') libdirs.push(at(i + 1)) })
    return prepare(A[2], A[3], A[4], A[5], cache, libdirs, A.includes('--free'))
  }
  if (A.length === 7 && A[1] === 'check') return check(...A.slice(2, 7))
  if (A.length === 4 && A[1] === 'finish') return finish(A[2], A[3])
  if (A.length === 4 && A[1] === 'link') return link(A[2], A[3])
  process.stderr.write(DOC + '\n')
  return 2
}

if (objcmp.isMainModule(import.meta.url)) runMain(() => main())
