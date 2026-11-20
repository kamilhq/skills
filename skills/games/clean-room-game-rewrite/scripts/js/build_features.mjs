#!/usr/bin/env node
// JavaScript port of build_features.py (same CLI, output files, stdout/stderr text, exit codes). Node built-ins only.
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, unlinkSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dump, load, PyFloat } from './lib/pyjson.mjs'
import { cmp, decodeUtf8, hex, pyInt, pyStr, pyStrip, runMain, S, SysExit, universalNewlines, ValueError, W } from './lib/pytools.mjs'

const DOC = "Step 3b prep: per-function features, vtable/pointer tables, and naming chunks.\n\n  build_features.py <decomp_dir> <binary> <analysis_dir> [--chunk-lines 8200] [--force]\n\n<decomp_dir> is a run_recovery.sh output (functions/*.c + index.json). Use one <analysis_dir> per binary\n(e.g. analysis/<binary-stem>/): the output names are fixed, so the script refuses (exit 2) to write into a\ndirectory that already holds another binary's features unless --force. Writes into <analysis_dir>:\n  features.json        [{addr, name, size, lines, calls[], calls_ambiguous[], strings[], apis[], ncallers}]\n                       calls = callee addresses. Taken from index.json \"callees\" when the exporter wrote them\n                       (Ghidra's getCalledFunctions: direct calls, named or not); otherwise recovered from the\n                       pseudocode: FUN_/LAB_/thunk_FUN_ references plus calls written with an already-applied\n                       name (`Class::Method(`, or `Method(` inside the same class), resolved through the names\n                       in index.json. A name that several functions share goes to calls_ambiguous instead.\n                       apis = called names that are not functions of this binary (imports, externals) plus the\n                       import behind each called thunk (index.json \"thunk_of\"; else names of <= 8-byte functions).\n  pointer_tables.json  tables of code pointers in non-code sections (vtables, callback tables). A scanned run of\n                       consecutive code pointers is SPLIT at every address inside it that code references or that\n                       an exported vftable symbol (??_7Class@@6B@) names, because MSVC packs vtables back to back:\n                       {addr, section, run_start, slots[], slots_known, names[] (exported vftable names),\n                        installed_by[] (functions that take the table's address, `= &PTR_...`: ctors/dtors),\n                        referenced_by[] (every function that mentions the address)}\n                       Runs of >= 2 pointers are kept; a 1-slot table only when something references it.\n  chunk_NN.json        address-contiguous groups of functions, ~chunk-lines of pseudocode each (stale chunk files\n                       from an earlier run are removed)\n  chunks.json          [{id, start, end, functions, lines}]  -> pass this list (not a placeholder!) as Workflow args\n  features_meta.json   {binary, binary_sha256, decomp_dir, call_source (\"index\" | \"pseudocode\"), counts}\nStdlib only; run with -I.\n"

export const FUN = new RegExp(`(?<!${W})(?:FUN|LAB|thunk_FUN)_([0-9a-f]{8})(?!${W})`, 'gu')
export const STR = new RegExp(`(?<!${W})s_([A-Za-z0-9_]{1,60}?)_([0-9a-f]{8})(?!${W})`, 'gu')
// data references; Ghidra prefixes a leading '_' when the item is read as a value (_DAT_1000e280)
export const REF = new RegExp(`(&)?${S}*(?<!${W})_?(?:PTR_[A-Za-z0-9_]*?|DAT)_([0-9a-f]{8})(?!${W})`, 'gu')
// call sites: maximal identifier (qualified names, destructors) followed by '('
export const CALLTOK = new RegExp(`(?<![\\p{L}\\p{N}_:~$@?<>])([A-Za-z_~][\\p{L}\\p{N}_:~$@?<>]*)${S}*\\(`, 'gu')
// named vtable references as Ghidra prints a demangled `vftable' symbol
export const VTREF = new RegExp(`(&)?${S}*(?<!${W})((?:[A-Za-z_][\\p{L}\\p{N}_<>,]*::)+_?v[fb]table_?)(?!${W})`, 'gu')
export const SKIP = ['FUN_', 'LAB_', 'thunk_FUN', 'CONCAT', 'SUB', 'ZEXT', 'SEXT', 'CARRY', 'SCARRY', 'SBORROW', 'POPCOUNT',
  'NAN', 'ROUND', 'TRUNC', 'FLOAT', 'ABS', 'SQRT', 'undefined', 'sizeof', 'while', 'switch', 'return', 'if', 'for']
export const THUNK_MAX = 8      // a `jmp [iat]` stub is 6 bytes

export class PE {
  constructor(path) {
    const d = this.d = readFileSync(path)
    if (!(d[0] === 0x4d && d[1] === 0x5a) || d.length < 0x40) throw new SysExit(1, `${path}: not a PE file (no MZ header)`)
    const o = d.readUInt32LE(0x3c)
    if (!d.subarray(o, o + 4).equals(Buffer.from('PE\0\0', 'latin1'))) throw new SysExit(1, `${path}: not a PE file (no PE signature)`)
    const n = d.readUInt16LE(o + 6)
    const opt = o + 24
    if (d.readUInt16LE(opt) !== 0x10b) throw new SysExit(1, `${path}: not a 32-bit PE (PE32+ is out of scope)`)
    this.base = d.readUInt32LE(opt + 28)
    this.nrva = d.readUInt32LE(opt + 92)
    this.opt = opt
    const so = opt + d.readUInt16LE(o + 20)
    this.secs = []
    for (let i = 0; i < n; i++) {
      const p = so + 40 * i
      let k = 8
      while (k > 0 && d[p + k - 1] === 0) k--
      this.secs.push({ name: d.subarray(p, p + k).toString('latin1'), va: this.base + d.readUInt32LE(p + 12),
                       vs: d.readUInt32LE(p + 8), ro: d.readUInt32LE(p + 20), rs: d.readUInt32LE(p + 16),
                       code: Boolean(d.readUInt32LE(p + 36) & 0x20000000) })
    }
  }

  off(rva) {
    for (const s of this.secs) {
      const va = s.va - this.base
      if (va <= rva && rva < va + s.rs) return s.ro + rva - va
    }
    return null
  }

  cstr(rva) {
    const p = this.off(rva)
    if (p === null) return ''
    const z = this.d.indexOf(0, p)
    if (z < 0) throw new ValueError('subsection not found')
    return this.d.subarray(p, z).toString('latin1')
  }

  // [[va, name]] of named exports
  exports() {
    if (this.nrva < 1) return []
    const rva = this.d.readUInt32LE(this.opt + 96), size = this.d.readUInt32LE(this.opt + 100)
    const e = rva ? this.off(rva) : null
    if (e === null) return []
    const nn = this.d.readUInt32LE(e + 24), af = this.d.readUInt32LE(e + 28)
    const an = this.d.readUInt32LE(e + 32), ao = this.d.readUInt32LE(e + 36)
    const out = []
    for (let i = 0; i < nn; i++) {
      const nr = this.d.readUInt32LE(this.off(an) + 4 * i)
      const ordi = this.d.readUInt16LE(this.off(ao) + 2 * i)
      const fr = this.d.readUInt32LE(this.off(af) + 4 * ordi)
      if (!(rva <= fr && fr < rva + size)) out.push([this.base + fr, this.cstr(nr)])   // skip forwarders
    }
    return out
  }
}

// ??_7Inner@Outer@@6B@ -> Outer::Inner::_vftable_ ; ??_7C@@6BB@@@ -> C::_vftable_ (for B). null if not one.
export function vftable_name(mangled) {
  const m = new RegExp(`^\\?\\?_([78])((?:[A-Za-z_]${W}*@)+)@6B([^\\n]*)(?=\\n?$)`, 'u').exec(mangled)
  if (!m) return null
  const cls = m[2].split('@').slice(0, -1).reverse().join('::')
  const kind = m[1] === '7' ? '_vftable_' : '_vbtable_'
  const rest = m[3].replace(/@+$/, '')
  return `${cls}::${kind}` + (rest ? ` (for ${rest.split('@').reverse().join('::')})` : '')
}

// index.json callee entry -> {int: address}, or a str name for externals, or null
export function parse_callee(c) {
  if (c instanceof Map) {
    const a = c.has('address') ? c.get('address') : (c.has('addr') ? c.get('addr') : null)
    const r = a !== null && a !== undefined ? parse_callee(a) : null
    if (typeof r === 'number' || typeof r === 'boolean') return r
    const nm = c.has('name') ? c.get('name') : null
    return truthy(nm) ? nm : r
  }
  if (typeof c === 'boolean') return c                  // isinstance(True, int): a bool is an int in Python
  if (typeof c === 'number') return c
  if (typeof c === 'bigint') return Number.isSafeInteger(Number(c)) ? Number(c) : c
  if (typeof c === 'string') {
    const s = pyStrip(c)
    try {
      const v = pyInt(s, 16)
      return typeof v === 'bigint' ? v : v
    } catch (e) {
      if (!(e instanceof ValueError)) throw e
      if (s.toUpperCase().startsWith('EXTERNAL:')) return null     // Ghidra external space address: no name to report
      return s
    }
  }
  return null
}

function truthy(v) {
  if (v === null || v === undefined || v === false || v === 0 || v === '' || v === 0n) return false
  if (Array.isArray(v)) return v.length > 0
  if (v instanceof Map) return v.size > 0
  if (v instanceof PyFloat) return v.v !== 0
  return true
}

const pyBasename = (p) => p.slice(p.lastIndexOf('/') + 1)
function pySplitextRoot(p) {
  const base = pyBasename(p)
  const dot = base.lastIndexOf('.')
  if (dot <= 0) return p
  let k = 0
  while (k < dot && base[k] === '.') k++
  if (k === dot) return p
  return p.slice(0, p.length - (base.length - dot))
}

const defaultGet = (m, k, mk) => {
  let v = m.get(k)
  if (v === undefined) { v = mk(); m.set(k, v) }
  return v
}

export function main(argv0) {
  const args = argv0.filter((a) => a !== '--force')
  const force = argv0.includes('--force')
  let target = 8200
  const ci = args.indexOf('--chunk-lines')
  if (ci >= 0) {
    if (ci + 1 >= args.length) throw new Error('IndexError: list index out of range')
    target = pyInt(args[ci + 1])
    args.splice(ci, 2)
  }
  if (args.length !== 3) throw new SysExit(1, DOC)
  const [ddir, binary, adir] = args
  const pe = new PE(binary)
  const bsha = createHash('sha256').update(pe.d).digest('hex')

  mkdirSync(adir, { recursive: true })
  const meta_p = join(adir, 'features_meta.json')
  if (existsSync(meta_p) && !force) {
    const old = load(meta_p)
    const g = (k) => (old instanceof Map && old.has(k) ? old.get(k) : null)
    if (g('binary_sha256') !== bsha) {
      process.stderr.write(`${adir} already holds features of ${pyStr(g('binary'))} (another binary). Use one analysis dir per ` +
                           `binary, e.g. analysis/${pyBasename(pySplitextRoot(pyBasename(binary)))}/, or pass --force.\n`)
      throw new SysExit(2)
    }
  } else if (existsSync(join(adir, 'features.json')) && !force) {
    process.stderr.write(`note: overwriting features.json in ${adir} from an earlier run (no features_meta.json)\n`)
  }

  const idx = load(join(ddir, 'index.json')).get('functions')
  const funcs = new Map()
  for (const f of idx) {
    let a
    try {
      a = pyInt(f.get('address'), 16)
    } catch (e) {
      if (e instanceof ValueError || e instanceof TypeError) continue
      throw e
    }
    funcs.set(a, f)
  }
  const by_name = new Map(), by_suffix = new Map()
  for (const [a, f] of funcs) {
    defaultGet(by_name, f.get('name'), () => []).push(a)
    const parts = f.get('name').split('::')
    for (let k = 1; k < parts.length; k++) defaultGet(by_suffix, parts.slice(k).join('::'), () => []).push(a)
  }

  // Ghidra prints a callee's namespace only when it differs from the caller's, so try the name as
  // written, then inside the caller's namespace and its parents, then any unique qualified match.
  const resolveTok = (tok, caller) => {
    if (by_name.has(tok)) return by_name.get(tok)
    const ns = caller.split('::').slice(0, -1)
    while (ns.length) {
      const hit = by_name.get([...ns, tok].join('::'))
      if (hit && hit.length) return hit
      ns.pop()
    }
    return by_suffix.get(tok) ?? []
  }
  const use_index = idx.some((f) => f.has('callees'))
  const code_secs = pe.secs.filter((s) => s.code)
  let inside = 0
  for (const a of funcs.keys()) if (code_secs.some((s) => s.va <= a && a < s.va + s.vs)) inside++
  if (funcs.size && inside < 0.9 * funcs.size) {
    process.stderr.write(`${ddir} does not look like a decompile of ${binary}: only ${inside} of ${funcs.size} function addresses ` +
                         `fall in its code sections\n`)
    throw new SysExit(2)
  }

  // exported data symbols (vftables) -> address, and the names Ghidra prints for them
  const vt_named = new Map()          // address -> Set(display names)
  const vt_by_name = new Map()        // printed name -> Set(address)
  for (const [va, nm] of pe.exports()) {
    const v = vftable_name(nm)
    if (v) {
      defaultGet(vt_named, va, () => new Set()).add(v)
      defaultGet(vt_by_name, v.split(' (for ')[0], () => new Set()).add(va)
    }
  }

  const feat = [], callers = new Map()
  const refs = new Map(), installs = new Map()
  let n_amb = 0
  const fget = (f, k) => (f.has(k) ? f.get(k) : null)
  for (const a of [...funcs.keys()].sort((x, y) => x - y)) {
    const f = funcs.get(a)
    if (fget(f, 'status') !== 'written') continue
    const path = join(ddir, 'functions', f.get('address') + '.c')
    if (!existsSync(path)) continue
    const src = universalNewlines(decodeUtf8(readFileSync(path), 'replace'))
    const body = src.split('\n').filter((l) => !l.startsWith('//')).join('\n')
    let calls = new Set()
    const amb = new Set(), apis = new Set()
    if (use_index) {
      const cs = fget(f, 'callees')
      for (let c of truthy(cs) ? cs : []) {
        c = parse_callee(c)
        if (typeof c === 'boolean') c = Number(c)          // True == 1 for set and dict membership
        if (typeof c === 'number') {
          if (funcs.has(c)) calls.add(c)
        } else if (typeof c === 'bigint') {
          // a Python int too large to be a function address
        } else if (truthy(c)) apis.add(c)
      }
    } else {
      // LAB_ targets inside this function's own body are jump labels, not calls
      const size = Number(f.get('size'))
      for (const m of body.matchAll(FUN)) {
        const c = parseInt(m[1], 16)
        if (funcs.has(c) || !(a <= c && c < a + size)) calls.add(c)
      }
    }
    for (const m of body.matchAll(CALLTOK)) {
      const tok = m[1]
      if (SKIP.some((p) => tok.startsWith(p)) || tok === 'if' || tok === 'for' || tok === 'while') continue
      const hits = resolveTok(tok, f.get('name'))
      if (!hits.length) {
        if (!tok.startsWith('_')) apis.add(tok)
        continue
      }
      if (!use_index) {
        if (hits.length === 1) calls.add(hits[0])
        else if (!hits.includes(a)) amb.add(tok)
      }
    }
    calls.delete(a)
    for (const c of calls) {
      const g = funcs.get(c)
      if (g !== undefined) {
        const t = fget(g, 'thunk_of')
        if (typeof t === 'string' && t && !t.startsWith('0x')) apis.add(t)        // thunk of an import/external
        else if (!g.has('thunk_of') && Number(g.get('size')) <= THUNK_MAX &&
                 !['FUN_', 'thunk_FUN_', 'LAB_'].some((p) => g.get('name').startsWith(p))) apis.add(g.get('name'))
      }
      defaultGet(callers, c, () => new Set()).add(a)
    }
    n_amb += amb.size
    for (const m of body.matchAll(REF)) {
      const r = parseInt(m[2], 16)
      defaultGet(refs, r, () => new Set()).add(a)
      if (m[1]) defaultGet(installs, r, () => new Set()).add(a)
    }
    for (const m of body.matchAll(VTREF)) {
      for (const va of vt_by_name.get(m[2]) ?? []) {
        defaultGet(refs, va, () => new Set()).add(a)
        if (m[1]) defaultGet(installs, va, () => new Set()).add(a)
      }
    }
    const strs = new Set([...body.matchAll(STR)].map((m) => m[1]))
    feat.push({ addr: f.get('address'), name: f.get('name'), size: f.get('size'), lines: body.split('\n').length - 1,
                calls: [...calls].sort((x, y) => x - y).map((c) => '0x' + c.toString(16)), calls_ambiguous: [...amb].sort(cmp),
                strings: [...strs].sort(cmp).slice(0, 20), apis: [...apis].sort(cmp).slice(0, 15) })
  }
  for (const r of feat) r.ncallers = (callers.get(pyInt(r.addr, 16)) ?? new Set()).size
  dump(feat, join(adir, 'features.json'))

  const d = pe.d, secs = pe.secs
  const starts = new Set(feat.map((r) => pyInt(r.addr, 16)))
  const code = secs.filter((s) => s.code)
  const in_code = (v) => code.some((s) => s.va <= v && v < s.va + s.vs)
  const marks = new Set([...refs.keys(), ...vt_named.keys()])
  const marksSorted = [...marks].sort((x, y) => x - y)
  const firstAbove = (x) => {          // index of the first mark > x
    let lo = 0, hi = marksSorted.length
    while (lo < hi) { const mid = (lo + hi) >> 1; if (marksSorted[mid] <= x) lo = mid + 1; else hi = mid }
    return lo
  }
  const tables = []
  for (const s of secs) {
    if (s.code || !s.rs || ['.rsrc', '.reloc'].includes(s.name.toLowerCase())) continue
    let i = 0
    const size = Math.min(s.vs, s.rs)
    while (i + 4 <= size) {
      let j = i
      const slots = []
      while (j + 4 <= size) {
        const q = d.readUInt32LE(s.ro + j)
        if (in_code(q)) { slots.push(q); j += 4 } else break
      }
      const a = s.va + i
      if (slots.length >= 2 || (slots.length && marks.has(a))) {
        const cutSet = new Set([a])
        for (let k = firstAbove(a); k < marksSorted.length && marksSorted[k] < a + 4 * slots.length; k++) {
          if ((marksSorted[k] - a) % 4 === 0) cutSet.add(marksSorted[k])
        }
        const cuts = [...cutSet].sort((x, y) => x - y)
        cuts.forEach((c, k) => {
          const end = k + 1 < cuts.length ? cuts[k + 1] : a + 4 * slots.length
          const piece = slots.slice((c - a) / 4, (end - a) / 4)
          if (piece.length < 2 && !marks.has(c)) return
          const sortedHex = (m) => [...(m.get(c) ?? [])].sort((x, y) => x - y).map((x) => '0x' + x.toString(16))
          tables.push({ addr: hex(c), section: s.name, run_start: hex(a), slots: piece.map(hex),
                        slots_known: piece.filter((x) => starts.has(x)).length, names: [...(vt_named.get(c) ?? [])].sort(cmp),
                        installed_by: sortedHex(installs), referenced_by: sortedHex(refs) })
        })
        i = j
      } else i += 4
    }
  }
  dump(tables, join(adir, 'pointer_tables.json'), { indent: 0 })

  const chunks = []
  let cur = [], n = 0
  for (const r of feat) {
    cur.push(r); n += r.lines + 3
    if (n >= target) { chunks.push(cur); cur = []; n = 0 }
  }
  if (cur.length) chunks.push(cur)
  for (const old of readdirSync(adir)) {
    if (/^chunk_[\s\S]*\.json$/.test(old)) unlinkSync(join(adir, old))
  }
  const out = []
  chunks.forEach((c, i) => {
    const cid = String(i).padStart(chunks.length <= 100 ? 2 : 3, '0')
    dump(c, join(adir, `chunk_${cid}.json`))
    out.push({ id: cid, start: c[0].addr, end: c.at(-1).addr, functions: c.length, lines: c.reduce((t, r) => t + r.lines, 0) })
  })
  dump(out, join(adir, 'chunks.json'))
  const with_callers = feat.filter((r) => r.ncallers).length
  const counts = { functions: feat.length, lines: feat.reduce((t, r) => t + r.lines, 0), with_callers,
                   call_edges: feat.reduce((t, r) => t + r.calls.length, 0), ambiguous_call_names: n_amb,
                   pointer_tables: tables.length, tables_with_installer: tables.filter((t) => t.installed_by.length).length,
                   exported_vftables: [...vt_named.values()].reduce((t, v) => t + v.size, 0), chunks: out.length }
  dump({ binary: pyBasename(binary), binary_sha256: bsha, decomp_dir: resolve(ddir),
         call_source: use_index ? 'index' : 'pseudocode', counts }, meta_p, { indent: 1 })
  process.stdout.write(`${counts.functions} functions (${with_callers} with callers, calls from ` +
    `${use_index ? 'index.json callees' : 'pseudocode'}), ${counts.lines} lines, ` +
    `${tables.length} pointer tables (${counts.tables_with_installer} with installed_by), ${out.length} chunks\n`)
  return 0
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(() => {
    if (process.argv.length < 5) throw new SysExit(1, DOC)
    return main(process.argv.slice(2))
  })
}
