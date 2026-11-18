#!/usr/bin/env node
// hybrid_link.mjs - JavaScript port of hybrid_link.py (phase 6 hybrid build: the whole binary with every matched
// function taken from the compiler's .obj). Same command line, stdout/stderr, symbols.json and exit codes:
//
//   hybrid_link.mjs map  --pe <original> --src <dir|file>... --obj <dir|file>... [--module M]
//                        [--functions index.json] [--instructions instructions.tsv] --out symbols.json [--all]
//   hybrid_link.mjs link <reassembled_dir> <symbols.json> <out_binary> [--cache <file>]
//   hybrid_link.mjs verify <original> <reassembled_dir> <symbols.json> [--cache <file>]
//
// See hybrid_link.py for the description. Library use: sym_key, demangle_simple, cmd_map(args), resolve_edited,
// cmd_link(reasm_dir, map_path, out_path, cache), main(argv). Python None is null, tuples are arrays, the
// symbols dict is a Map (insertion order kept). Deviation: the temp dirs Python leaves behind (link's phase-5b
// image, verify's identical rebuild) are removed; a DIFFERENT rebuild is kept and its path printed, as in Python.
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as objcmp from './objcmp.mjs'
import * as reassemble from './reassemble.mjs'
import { SequenceMatcher } from './lib/difflib.mjs'
import { ArgExit, ArgumentParser } from './lib/pyargparse.mjs'
import { dump, dumps, load, pyFloat } from './lib/pyjson.mjs'
import { pyRound } from './lib/pycompat.mjs'
import { iterLines, readText, runMain, SysExit } from './lib/pytools.mjs'

const { DIR32, DIR32NB, REL32, CLASS_EXTERNAL, CLASS_STATIC, CLASS_WEAK, basename, relpath, hex } = objcmp

const out = (s) => process.stdout.write(s)
const err = (s) => process.stderr.write(s)

// bisect.bisect_right / bisect_left on a sorted number array
export function bisectRight(a, x) {
  let lo = 0, hi = a.length
  while (lo < hi) { const m = (lo + hi) >> 1; if (x < a[m]) hi = m; else lo = m + 1 }
  return lo
}
export function bisectLeft(a, x) {
  let lo = 0, hi = a.length
  while (lo < hi) { const m = (lo + hi) >> 1; if (a[m] < x) lo = m + 1; else hi = m }
  return lo
}

// line.rstrip('\n').split('\t', 5) unpacked into six fields (ValueError otherwise, like Python's unpacking)
export function tsvFields(line) {
  const s = line.replace(/\n+$/, '')
  const parts = []
  let i = 0
  while (parts.length < 5) {
    const j = s.indexOf('\t', i)
    if (j < 0) break
    parts.push(s.slice(i, j))
    i = j + 1
  }
  parts.push(s.slice(i))
  if (parts.length !== 6) {
    const e = new Error(`not enough values to unpack (expected 6, got ${parts.length})`)
    e.name = 'ValueError'
    throw e
  }
  return parts
}

// the lines of a text file after the first (for line in fh after next(fh))
export function dataLines(path) {
  const lines = iterLines(readText(path))
  if (!lines.length) { const e = new Error(''); e.name = 'StopIteration'; throw e }
  return lines.slice(1)
}

// Externals by name; statics qualified by object and section (several objects have the same statics)
export function sym_key(obj_path, sym) {
  if (sym.storage !== CLASS_EXTERNAL && sym.storage !== CLASS_WEAK && sym.secnum > 0) {
    return `${basename(obj_path)}#${sym.name}#sec${sym.secnum}`
  }
  return sym.name
}

function keyOf(obj, t) {
  return !t.is_section_sym ? sym_key(obj.path, t) : `${basename(obj.path)}#${t.name}#sec${t.secnum}`
}

const isInt = (v) => typeof v === 'number'

export function cmd_map(a) {
  const pe = new objcmp.PEImage(a.pe)
  const objs = objcmp.collect_objs(a.obj).map((f) => objcmp.read_coff(f))
  const amap = new objcmp.AddrMap(pe)
  const flist = a.functions ? objcmp.load_function_list(a.functions) : new Map()
  const annots = objcmp.scan_annotations(a.src, a.module)
  const all_names = []
  for (const o of objs) {
    for (const s of o.symbols.values()) {
      if (!s.is_section_sym && (s.storage === CLASS_EXTERNAL || s.storage === CLASS_STATIC || s.storage === CLASS_WEAK)) {
        all_names.push([o, s])
      }
    }
  }
  for (const an of annots) {
    if (an.kind === 'STRING') continue
    objcmp.map_annotation(an, objs, all_names)
    if (an.status === 'mapped') amap.add(an.symbol, an.va, `${an.file}:${an.line}`)
  }
  const known_starts = new Set([...flist.keys(), ...annots.map((an) => an.va)])
  const by_path = new Map(objs.map((o) => [o.path, o]))
  const functions = [], symbols = new Map(), conflicts = [], inobj = [], edited = []
  let skipped = 0
  for (const an of annots) {
    if (an.kind !== 'FUNCTION' || an.status !== 'mapped') continue
    const obj = by_path.get(an.objpath)
    const syms = obj ? obj.find(an.symbol) : []
    if (!syms.length) { skipped++; continue }
    const sym = syms[0]
    const r = objcmp.compare_function(obj, sym, pe, an.va, null, amap, known_starts)
    if (!r.identical) {
      if (a.all) edited.push([an, obj, sym])
      else skipped++
      continue
    }
    const [code, rels] = obj.function_bytes(sym)
    const orig = pe.read(an.va, code.length)
    for (const rel of rels) {
      const t = rel.symbol
      if (rel.type === 0 || t === null) continue
      if (rel.type !== DIR32 && rel.type !== DIR32NB && rel.type !== REL32) {
        throw new SysExit(1, `${obj.path} ${sym.name}: relocation type ${rel.type_name} not supported`)
      }
      const p = an.va + rel.offset
      const add = code.readInt32LE(rel.offset)
      const field = orig.readUInt32LE(rel.offset)
      let tva
      if (rel.type === DIR32) tva = (field - add) >>> 0
      else if (rel.type === DIR32NB) tva = (field + pe.image_base - add) >>> 0
      else tva = (field + p + 4 - add) >>> 0
      const k = keyOf(obj, t)
      if (symbols.has(k) && symbols.get(k) !== tva) {
        conflicts.push({ symbol: k, addresses: [hex(symbols.get(k)), hex(tva)], at: hex(p), obj: basename(obj.path) })
      }
      if (!symbols.has(k)) symbols.set(k, tva)
      // per-object view: units may declare a global with different layouts (or name two different copies,
      // e.g. two operator delete / two __real constants); each object resolves through its own
      const qk = `${basename(obj.path)}@${k}`
      if (symbols.has(qk) && symbols.get(qk) !== tva) {
        inobj.push({ symbol: qk, addresses: [hex(symbols.get(qk)), hex(tva)], at: hex(p) })
      }
      if (!symbols.has(qk)) symbols.set(qk, tva)
    }
    functions.push({ va: hex(an.va), obj: relpath(obj.path), symbol: sym.name, index: sym.index, size: code.length })
  }
  const nw = new Map(), unresolved = []
  if (edited.length) resolve_edited(edited, symbols, amap, functions, nw, unresolved, a.functions, a.instructions ?? null)
  const res = { image_base: pe.image_base, functions, symbols, conflicts, conflicts_within_object: inobj,
                new_sections: nw, unresolved }
  dump(res, a.out, { indent: 1 })
  if (unresolved.length) for (const u of unresolved.slice(0, 30)) err(`UNRESOLVED ${u}\n`)
  out(dumps({ functions: functions.length, edited: functions.filter((f) => f.identical === false).length,
              new_sections: nw.size, unresolved: unresolved.length, symbols: symbols.size,
              cross_object_conflicts: conflicts.length, conflict_symbols: new Set(conflicts.map((c) => c.symbol)).size,
              within_object_conflicts: inobj.length, not_identical_or_unmapped: skipped }, { indent: 1 }) + '\n')
  const by_sym = new Map()
  for (const c of conflicts) by_sym.set(c.symbol, (by_sym.get(c.symbol) || 0) + 1)
  for (const [k, n] of [...by_sym].sort((x, y) => y[1] - x[1]).slice(0, 30)) err(`CONFLICT ${k}: ${n} site(s)\n`)
  return inobj.length || unresolved.length ? 1 : 0
}

// MSVC `?name@Scope@...@@...` -> 'Scope::name' (plain names only; operators/ctors -> null); C `_name` -> 'name'
export function demangle_simple(name) {
  if (name.startsWith('?')) {
    if (name.startsWith('??')) return null
    const head = name.slice(1).split('@@')[0]
    const parts = head.split('@')
    return parts.slice(1).reverse().join('::') + (parts.length > 1 ? '::' : '') + parts[0]
  }
  if (name.startsWith('_')) return name.slice(1).split('@')[0]
  return name
}

// Build-from-source mode (--all): see hybrid_link.py resolve_edited()
export function resolve_edited(edited, symbols, amap, functions, nw, unresolved, index_path = null, listing = null) {
  const todo = []
  // direct calls to imported functions (`call _SDL_Foo`) go through link.exe's jump thunks: jmp [IAT slot]
  const pe = amap.pe
  const slots = new Set(pe.imports.values())
  const thunk = new Map()
  const FF25 = Buffer.from([0xff, 0x25])
  for (const [, va, vsize, rawsize, rawptr, ch] of pe.sections) {
    if (ch & 0x20000000) {
      const d = pe.data.subarray(rawptr, rawptr + Math.min(vsize, rawsize))
      let i = d.indexOf(FF25)
      while (i >= 0) {
        if (i + 6 <= d.length) {
          const slot = d.readUInt32LE(i + 2)
          if (slots.has(slot) && !thunk.has(slot)) thunk.set(slot, pe.image_base + va + i)
        }
        i = d.indexOf(FF25, i + 1)
      }
    }
  }
  // read-only constants by content (string literals, floating-point constants)
  const ro = []
  const iat = pe.dirs.length > 12 ? pe.dirs[12] : [0, 0]
  const imp = pe.dirs.length > 1 ? pe.dirs[1] : [0, 0]
  for (const [, va, vsize, rawsize, rawptr, ch] of pe.sections) {
    if (!(ch & 0x20000000) && !(ch & 0x80000000) && (ch & 0x40)) {
      ro.push([pe.image_base + va, pe.data.subarray(rawptr, rawptr + Math.min(vsize, rawsize))])
    }
  }

  function by_content(obj, t) {
    if (!(t.name.startsWith('??_C@') || t.name.startsWith('__real@') || t.name.startsWith('__xmm@'))) return null
    const sec = t.section !== null ? t.section : obj.sections[t.secnum - 1]
    const want = sec.data.subarray(Math.min(t.value, sec.data.length), Math.min(sec.size, sec.data.length))
    if (!want.length || sec.relocs.length) return null
    const align = t.name.startsWith('__real@') ? 8 : t.name.startsWith('__xmm@') ? 16 : 1
    for (const [base_va, d] of ro) {
      let i = d.indexOf(want)
      while (i >= 0) {
        const v = base_va + i
        const rva = v - pe.image_base
        let clash = false
        for (let x = v - 3; x < v + want.length; x++) if (pe.fixups_set.has(x)) { clash = true; break }
        clash = clash || (iat[0] <= rva && rva < iat[0] + iat[1]) || (imp[0] <= rva && rva < imp[0] + imp[1])
        if (!clash && v % align === 0) return v
        i = d.indexOf(want, i + 1)
      }
    }
    return null
  }

  // names from the named function index (phase 5): unique qualified names only
  const by_name = new Map()
  const fstarts = []
  if (index_path) {
    const idx = load(index_path)
    for (const f of (idx.has('functions') ? idx.get('functions') : [])) {
      const addr = parseInt(f.get('address'), 16)
      fstarts.push(addr)
      const nm = f.has('name') ? f.get('name') : ''
      const n = nm.startsWith('FID_conflict:') ? nm.split(':')[1] : nm
      if (!by_name.has(n)) by_name.set(n, new Set())
      by_name.get(n).add(addr)
    }
  }
  fstarts.sort((x, y) => x - y)

  function index_name(name) {
    const q = demangle_simple(name)
    for (const cand of [q, q ? q.replace(/^_+/, '') : null, name]) {
      if (cand && by_name.has(cand) && by_name.get(cand).size === 1) return by_name.get(cand).values().next().value
    }
    return null
  }
  // the original function's direct calls in order (Ghidra listing), to pair calls nothing else names
  const calls_of = new Map()
  if (listing && existsSync(listing)) {
    for (const line of dataLines(listing)) {
      const [, , fn, flow, tg, text] = tsvFields(line)
      if ((flow === 'call' || flow === 'ccall') && tg && text.startsWith('CALL 0x')) {
        const f = parseInt(fn, 16)
        if (!calls_of.has(f)) calls_of.set(f, [])
        calls_of.get(f).push(parseInt(tg.split(',')[0], 16))
      }
    }
  }

  function import_thunk(name) {
    if (name.startsWith('__imp_') || !name.startsWith('_')) return null
    const [va, src] = amap.resolve('__imp_' + name)
    if (src !== 'import') return null
    return thunk.has(va) ? thunk.get(va) : null
  }

  function resolve(obj, t, own_secnum) {
    if (t.secnum === own_secnum && own_secnum > 0) return 'self'
    const k = keyOf(obj, t)
    const qk = `${basename(obj.path)}@${k}`
    if (symbols.has(qk) || symbols.has(k)) return 'map'
    if (!t.is_section_sym && t.secnum <= 0) {
      const [va] = amap.resolve(t.name)
      if (va !== null) { symbols.set(k, va); return 'map' }
    }
    if (!t.is_section_sym && (t.storage === CLASS_EXTERNAL || t.storage === CLASS_WEAK)) {
      const [va] = amap.resolve(t.name)
      if (va !== null) { symbols.set(k, va); return 'map' }
    }
    if (!t.is_section_sym && t.secnum <= 0) {
      const va = import_thunk(t.name)
      if (va !== null) { symbols.set(k, va); return 'map' }
    }
    if (!t.is_section_sym && t.secnum <= 0) {
      const va = index_name(t.name)
      if (va !== null) { symbols.set(k, va); return 'map' }
    }
    if (t.secnum > 0 && !t.is_section_sym) {
      const va = by_content(obj, t)
      if (va !== null) { symbols.set(qk, va); return 'map' }
    }
    if (t.secnum > 0) {
      const nk = `${basename(obj.path)}#sec${t.secnum}`
      if (!nw.has(nk)) {
        const sec = t.section !== null ? t.section : obj.sections[t.secnum - 1]
        nw.set(nk, { obj: relpath(obj.path), section: t.secnum, name: sec.name, code: Boolean(sec.is_code), size: sec.size })
        todo.push([obj, t.secnum])
      }
      symbols.set(qk, { new: nk, offset: !t.is_section_sym ? t.value : 0 })
      return 'new'
    }
    unresolved.push(`${basename(obj.path)}: ${t.name}`)
    return null
  }

  function known(obj, t) {
    const k = keyOf(obj, t)
    const qk = `${basename(obj.path)}@${k}`
    const v = symbols.has(qk) ? symbols.get(qk) : symbols.has(k) ? symbols.get(k) : null
    if (isInt(v)) return v
    if (t.secnum <= 0) {
      const r = amap.resolve(t.name)[0]
      return r !== null ? r : (import_thunk(t.name) || index_name(t.name))
    }
    return t.is_section_sym ? null : by_content(obj, t)
  }

  const seqOf = (vals) => vals.map((v, i) => (v !== null ? v : ['?', i]))

  // unresolved call targets of an edited function, paired with the original function's calls in order
  function pair_calls(va, obj, sym, rels) {
    const orig = calls_of.get(va)
    if (!orig || !orig.length) return
    const code = obj.function_bytes(sym)[0]
    const mine = rels.filter((r) => r.type === REL32 && r.symbol !== null && r.offset >= 1 && code[r.offset - 1] === 0xE8 &&
                                    r.symbol.secnum <= 0 && !r.symbol.is_section_sym)
    const vals = mine.map((r) => known(obj, r.symbol))
    const sm = new SequenceMatcher(null, seqOf(vals), orig, false)
    let prev_a = 0, prev_b = 0
    for (const blk of sm.get_matching_blocks()) {
      const ga = blk.a - prev_a, gb = blk.b - prev_b
      if (ga === gb) {
        for (let k = 0; k < ga; k++) {
          const r = mine[prev_a + k], v = vals[prev_a + k]
          if (v === null) {
            const key = sym_key(obj.path, r.symbol)
            if (!symbols.has(key)) symbols.set(key, orig[prev_b + k])
          }
        }
      }
      prev_a = blk.a + blk.size; prev_b = blk.b + blk.size
    }
  }

  // statics of the unit an edited function uses are the original's variables: pair its DIR32 references with
  // the original function's relocated pointers around the references that already agree
  function pair_data(va, obj, sym, rels) {
    const i = bisectRight(fstarts, va)
    const end = i < fstarts.length ? fstarts[i] : va + 0x10000
    let orig = pe.fixups.filter((x) => va <= x && x < end).map((x) => pe.read(x, 4).readUInt32LE(0))
    orig = orig.filter((v) => !(va <= v && v < end))          // its own jump tables / labels
    const code = obj.function_bytes(sym)[0]
    const mine = rels.filter((r) => r.type === DIR32 && r.symbol !== null && r.symbol.secnum !== sym.secnum)
    const adds = mine.map((r) => code.readInt32LE(r.offset))
    const vals = mine.map((r, j) => {
      const v = known(obj, r.symbol)
      return v === null ? null : (v + adds[j]) >>> 0
    })
    const sm = new SequenceMatcher(null, seqOf(vals), orig, false)
    let prev_a = 0, prev_b = 0
    for (const blk of sm.get_matching_blocks()) {
      const ga = blk.a - prev_a, gb = blk.b - prev_b
      if (ga === gb) {
        for (let k = 0; k < ga; k++) {
          const r = mine[prev_a + k], v = vals[prev_a + k]
          const t = r.symbol
          if (v === null && t.secnum > 0 && !t.is_section_sym && t.storage === CLASS_STATIC) {
            const sec = t.section !== null ? t.section : obj.sections[t.secnum - 1]
            if (sec.is_code) continue
            const addr = (orig[prev_b + k] - adds[prev_a + k]) >>> 0
            const qk = `${basename(obj.path)}@${sym_key(obj.path, t)}`
            if (symbols.has(qk) && symbols.get(qk) !== addr) unresolved.push(`${basename(obj.path)}: ${t.name} pairs with two addresses`)
            symbols.set(qk, addr)
          }
        }
      }
      prev_a = blk.a + blk.size; prev_b = blk.b + blk.size
    }
  }

  for (const [an, obj, sym] of edited) {
    const [code, rels] = obj.function_bytes(sym)
    pair_calls(an.va, obj, sym, rels)
    pair_data(an.va, obj, sym, rels)
    for (const rel of rels) if (rel.type !== 0 && rel.symbol !== null) resolve(obj, rel.symbol, sym.secnum)
    functions.push({ va: hex(an.va), obj: relpath(obj.path), symbol: sym.name, index: sym.index, size: code.length, identical: false })
  }
  while (todo.length) {
    const [obj, secnum] = todo.pop()
    for (const rel of obj.sections[secnum - 1].relocs) {
      if (rel.type !== 0 && rel.symbol !== null) resolve(obj, rel.symbol, secnum)
    }
  }
}

function nextOf(arr, pred) {
  for (const x of arr) if (pred(x)) return x
  const e = new Error(''); e.name = 'StopIteration'; throw e
}
const getOr = (m, k, d) => (m.has(k) ? m.get(k) : d)

export function cmd_link(reasm_dir, map_path, out_path, cache = null) {
  const m = load(map_path)
  const tmp = mkdtempSync(join(tmpdir(), 'tmp'))
  const base_img = join(tmp, 'phase5b.bin')
  let img
  try {
    reassemble.build(reasm_dir, base_img, cache)          // the full image from text (everything in assembly)
    img = Buffer.from(readFileSync(base_img))
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
  const [base, dirs, secs] = reassemble.pe_parse(img)
  const [rel5b, reloc_name] = reassemble.relocs_of(img, base, dirs, secs)
  const off = (va) => {
    const s = nextOf(secs, (x) => x.va <= va - base && va - base < x.va + x.raw_size)
    return s.raw_ptr + va - base - s.va
  }
  const objs = new Map()
  const replaced = [], sites = new Set()
  let nbytes = 0
  const funcs = m.get('functions'), msyms = m.get('symbols')
  if (funcs.some((f) => !getOr(f, 'identical', true))) {
    throw new SysExit(1, 'the map has edited functions (--all): link them with relink.py --free, not here')
  }
  for (const f of funcs) {
    const va = parseInt(f.get('va'), 16)
    const fo = f.get('obj')
    if (!objs.get(fo)) objs.set(fo, objcmp.read_coff(fo))
    const obj = objs.get(fo)
    const sym = nextOf(obj.symbols.values(), (s) => s.index === f.get('index') && s.name === f.get('symbol'))
    const [code0, rels] = obj.function_bytes(sym)
    const code = Buffer.from(code0)
    const o = off(va)
    img.fill(0xcc, o, o + code.length)          // the slot is filled only from the object below
    for (const rel of rels) {
      const t = rel.symbol
      if (rel.type === 0 || t === null) continue
      const k = keyOf(obj, t)
      const qk = `${basename(obj.path)}@${k}`
      const tva = msyms.has(qk) ? msyms.get(qk) : msyms.has(k) ? msyms.get(k) : null
      if (tva === null) throw new SysExit(1, `${fo} ${f.get('symbol')}: no address for symbol ${k}`)
      const add = code.readInt32LE(rel.offset)
      const p = va + rel.offset
      let v
      if (rel.type === DIR32) { v = tva + add; sites.add(p - base) }
      else if (rel.type === DIR32NB) v = tva - base + add
      else v = tva + add - (p + 4)
      code.writeUInt32LE(v >>> 0, rel.offset)
    }
    code.copy(img, o)
    replaced.push([va, va + code.length])
    nbytes += code.length
  }
  replaced.sort((x, y) => x[0] - y[0] || x[1] - y[1])
  const starts = replaced.map((r) => r[0])
  const in_replaced = (va) => {
    const i = bisectRight(starts, va) - 1
    return i >= 0 && va < replaced[i][1]
  }
  for (const site of rel5b.keys()) if (!in_replaced(site)) sites.add(site - base)
  const rs = nextOf(secs, (s) => s.name === reloc_name)
  const r = reassemble.make_reloc([...sites])
  if (r.length > rs.raw_size) throw new SysExit(1, '.reloc grew beyond its raw size')
  r.copy(img, rs.raw_ptr)
  img.fill(0, rs.raw_ptr + r.length, rs.raw_ptr + rs.raw_size)
  writeFileSync(out_path, img)
  const text = nextOf(secs, (s) => s.exec)
  out(dumps({ functions_from_objects: funcs.length, code_bytes_from_objects: nbytes, text_bytes: text.vsize,
              share: pyFloat(pyRound(nbytes / text.vsize, 4)), relocation_sites: sites.size }, { indent: 1 }) + '\n')
  return 0
}

const MAIN_HELP = 'usage: hybrid_link.py [-h] {map,link,verify} ...\n\npositional arguments:\n  {map,link,verify}\n\noptional arguments:\n  -h, --help         show this help message and exit\n'
const MAP_HELP = 'usage: hybrid_link.py map [-h] --pe PE --src SRC [SRC ...] --obj OBJ [OBJ ...]\n                          [--module MODULE] [--functions FUNCTIONS] --out OUT\n                          [--instructions INSTRUCTIONS] [--all]\n\noptional arguments:\n  -h, --help            show this help message and exit\n  --pe PE\n  --src SRC [SRC ...]\n  --obj OBJ [OBJ ...]\n  --module MODULE\n  --functions FUNCTIONS\n  --out OUT\n  --instructions INSTRUCTIONS\n                        Ghidra instruction listing (instructions.tsv) of the\n                        original: pairs calls of edited functions that nothing\n                        else names\n  --all                 also edited FUNCTIONs (not identical any more): build-\n                        from-source mode for relink.py\n'
const LINK_HELP = 'usage: hybrid_link.py link [-h] [--cache CACHE] reassembled map out\n\npositional arguments:\n  reassembled\n  map\n  out\n\noptional arguments:\n  -h, --help     show this help message and exit\n  --cache CACHE\n'
const VERIFY_HELP = 'usage: hybrid_link.py verify [-h] [--cache CACHE] original reassembled map\n\npositional arguments:\n  original\n  reassembled\n  map\n\noptional arguments:\n  -h, --help     show this help message and exit\n  --cache CACHE\n'
const usageOf = (help) => help.slice(0, help.indexOf('\n\n') + 1)

export function main(argv = process.argv.slice(2)) {
  const ap = new ArgumentParser({ prog: 'hybrid_link.py', usage: usageOf(MAIN_HELP), help: MAIN_HELP })
  const sub = ap.add_subparsers({ dest: 'cmd' })
  ap.actions[ap.actions.length - 1].required = true
  let p = sub.add_parser('map', { usage: usageOf(MAP_HELP), help: MAP_HELP })
  p.add_argument('--pe', { required: true })
  p.add_argument('--src', { nargs: '+', required: true })
  p.add_argument('--obj', { nargs: '+', required: true })
  p.add_argument('--module')
  p.add_argument('--functions')
  p.add_argument('--out', { required: true })
  p.add_argument('--instructions')
  p.add_argument('--all', { action: 'store_true' })
  p = sub.add_parser('link', { usage: usageOf(LINK_HELP), help: LINK_HELP })
  p.add_argument('reassembled')
  p.add_argument('map')
  p.add_argument('out')
  p.add_argument('--cache')
  p = sub.add_parser('verify', { usage: usageOf(VERIFY_HELP), help: VERIFY_HELP })
  p.add_argument('original')
  p.add_argument('reassembled')
  p.add_argument('map')
  p.add_argument('--cache')
  let a
  try {
    a = ap.parse_args(argv)
  } catch (e) {
    if (e instanceof ArgExit) return e.code
    throw e
  }
  if (a.cmd === 'map') return cmd_map(a)
  if (a.cmd === 'link') return cmd_link(a.reassembled, a.map, a.out, a.cache)
  const tmp = mkdtempSync(join(tmpdir(), 'tmp'))
  const o = join(tmp, 'hybrid.bin')
  cmd_link(a.reassembled, a.map, o, a.cache)
  const x = readFileSync(a.original), y = readFileSync(o)
  const sha = (b) => createHash('sha256').update(b).digest('hex')
  if (sha(x) === sha(y)) {
    out(`IDENTICAL ${sha(x)}\n`)
    rmSync(tmp, { recursive: true, force: true })
    return 0
  }
  const n = Math.min(x.length, y.length)
  let first = n
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) { first = i; break }
  out(`DIFFERENT: first difference at file offset 0x${first.toString(16)}; rebuilt kept at ${o}\n`)
  return 1
}

if (objcmp.isMainModule(import.meta.url)) runMain(() => main())
