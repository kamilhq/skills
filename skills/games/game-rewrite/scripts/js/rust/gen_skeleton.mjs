#!/usr/bin/env node
// Port of ../../rust/gen_skeleton.py (same command line, output and files). Node built-ins only.
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import * as L from '../lib/rwlib.mjs'
import * as C from '../cpp/cppsplit.mjs'

const PROG = 'gen_skeleton'
const DOC = "Generate the skeleton of a Rust rewrite: one stub per game function, with its address and C++ head.\n\n  python3 -I gen_skeleton.py index --units DIR --out FUNCS.json [--cpp-config CFG.json] [--module NAME]\n                                   [--names INDEX.json] [--headers DIR]\n  python3 -I gen_skeleton.py generate --config RUST.json --index FUNCS.json --crate DIR [--names-out FILE]\n                                   [--dry-run]\n\nindex: reads matched units (decomp phase 6, split by ../cpp/cppsplit.py; --cpp-config gives \"module\",\n\"namespaces\", \"unit_exts\") and writes the function index: one record per `// FUNCTION` or `// STUB`\nannotation on a function definition or declaration (address, name from --names or the definition, C++\nhead, unit = file name without extension, class, namespace, annotation, nonmatching, body) and the\nfile-scope variables (definitions, and `extern` declarations nothing defines; name, type, array dimensions,\naddress from a `// GLOBAL:` annotation or a trailing `// 0x...` comment, unit, namespace, static) and the data\nmember names of every class defined in the units or in the --headers folder (for the cx analysis). Annotations\non variables (dynamic initializers) and on no code (fragments) are listed with \"code\" \"variable\" / \"none\";\nnames that are Ghidra defaults (FUN_...) give way to the definition's name. Constants are left out. An index\nmade another way (e.g. from pseudocode) works the same: only \"address\" and \"name\" are required.\n\ngenerate: places every function of the index by the config (skip rules, hand-written addresses, classes and\ntheir roles, namespaces, name prefixes, names, addresses, units, default module), maps its C++ head to a\nRust signature (built-in C types plus the config's types; `cx: &mut Cx` first where the function needs game\nstate) and writes under --crate:\n  src/<module>.rs, or src/<module>/mod.rs + src/<module>/<file>.rs: one stub per function, address order:\n      // 0x<address>\n      /// `<C++ head>`\n      pub fn <name>(<params>) -> <ret> {\n          stub!(0x<address>, \"<C++ name>\")\n      }\n    (methods of element classes inside `impl <Type>`);\n  src/state/statics.rs (config \"statics\"; only with globals in the index): one `<Module>Statics` struct\n    per module and `Statics` (cx.statics.<module>.<field>);\n  names.tsv (--names-out, default <crate>/tools/names.tsv; always rewritten): address, C++ name, Rust path,\n    Rust signature or skip reason, unit; globals as `global <name>` -> `cx.statics.<module>.<field>`.\nIt never overwrites a hand-edited file: <crate>/.gen_skeleton.json keeps the SHA-256 of every file it wrote,\nand an existing file is rewritten only while it still has that hash; files it did not write, and the\nconfig's \"keep\" list, are never touched. Afterwards it scans <crate>/src for `// 0x...` lines and\n`stub!(0x` calls. Prints a JSON summary (placed and skipped per module, unmapped C++ types, files new /\nupdated / same / kept, functions missing from the tree, stubs left). Exit 0, 2 on bad input.\nThe config keys are described in references/rust.md. Python standard library only.\nPort: ../js/rust/gen_skeleton.mjs."

const RUST_KEYWORDS = new Set(('as break const continue crate else enum extern false fn for if impl in let loop match mod ' +
  'move mut pub ref return self Self static struct super trait true type unsafe use where while ' +
  'async await dyn abstract become box do final macro override priv typeof unsized virtual ' +
  'yield try union').split(' '))
const BUILTIN_TYPES = [
  ['int', 'i32'], ['signed', 'i32'], ['signed int', 'i32'], ['long', 'i32'], ['long int', 'i32'], ['signed long', 'i32'],
  ['unsigned', 'u32'], ['unsigned int', 'u32'], ['unsigned long', 'u32'], ['short', 'i16'], ['short int', 'i16'],
  ['signed short', 'i16'], ['unsigned short', 'u16'], ['char', 'i8'], ['signed char', 'i8'], ['unsigned char', 'u8'],
  ['bool', 'bool'], ['float', 'f32'], ['double', 'f64'], ['long double', 'f64'], ['long long', 'i64'], ['__int64', 'i64'],
  ['unsigned long long', 'u64'], ['unsigned __int64', 'u64'], ['int8_t', 'i8'], ['uint8_t', 'u8'], ['int16_t', 'i16'],
  ['uint16_t', 'u16'], ['int32_t', 'i32'], ['uint32_t', 'u32'], ['int64_t', 'i64'], ['uint64_t', 'u64'], ['size_t', 'usize'],
  ['intptr_t', 'isize'], ['uintptr_t', 'usize'], ['ptrdiff_t', 'isize'], ['wchar_t', 'u16'], ['BOOL', 'i32'],
  ['BYTE', 'u8'], ['WORD', 'u16'], ['DWORD', 'u32'], ['std::string', 'String']
]
const SCALARS = new Set(['i8', 'u8', 'i16', 'u16', 'i32', 'u32', 'i64', 'u64', 'isize', 'usize', 'f32', 'f64', 'bool'])
const SIZES = { i8: 1, u8: 1, bool: 1, i16: 2, u16: 2, i32: 4, u32: 4, f32: 4, i64: 8, u64: 8, f64: 8, isize: 4, usize: 4 }
const NOT_CALLS = new Set(['if', 'while', 'for', 'switch', 'return', 'sizeof', 'static_cast', 'reinterpret_cast', 'const_cast',
  'dynamic_cast', 'defined', 'catch', 'throw', 'new', 'delete', 'case'])
const SPECIFIERS = ['static', 'inline', '__inline', '__forceinline', 'virtual', 'extern', '__cdecl', '__stdcall',
  '__fastcall', '__thiscall', 'SDLCALL', 'DECLSPEC', 'friend', 'explicit', 'WINAPI', 'APIENTRY']
const ADDR_LINE = /^[ \t]*\/\/[ \t]*(0x[0-9a-fA-F]+)[ \t]*$/gm

class BadInput extends Error {}
function compileRx (rx) {
  try { return new RegExp(rx) } catch (e) { throw new BadInput(`bad regex in the config: ${rx}`) }
}

// Python-style helpers: dict.get, truthiness, Maps from JSON objects
const hasOwn = (o, k) => o !== null && typeof o === 'object' && !Array.isArray(o) && Object.prototype.hasOwnProperty.call(o, k)
const get = (o, k, d) => (hasOwn(o, k) ? o[k] : d)
const truthy = x => {
  if (x === null || x === undefined || x === false || x === 0 || x === '') return false
  if (Array.isArray(x)) return x.length > 0
  if (x instanceof Map || x instanceof Set) return x.size > 0
  if (x instanceof L.PyFloat) return x.v !== 0
  if (typeof x === 'object') return Object.keys(x).length > 0
  return true
}
const isDict = o => o !== null && typeof o === 'object' && !Array.isArray(o) && !(o instanceof L.PyFloat)
const toMap = o => new Map(isDict(o) ? Object.entries(o) : [])
const isInt = v => typeof v === 'number' && Number.isInteger(v)
const pct = (fmt, ...a) => { let i = 0; return fmt.replace(/%[sd]/g, () => String(a[i++])) }
const normWs = s => s.split(/\s+/).filter(Boolean).join(' ')
const rstripChars = (s, chars) => { let e = s.length; while (e > 0 && chars.includes(s[e - 1])) e--; return s.slice(0, e) }
const isDisjoint = (a, b) => { for (const x of a) if (b.has(x)) return false; return true }
const sortStr = arr => [...arr].sort(L.cmp)
const cmpTuple = (a, b) => {
  for (let i = 0; i < a.length; i++) {
    const x = a[i]; const y = b[i]
    if (x === y) continue
    if (typeof x === 'number' && typeof y === 'number') return x - y
    return L.cmp(String(x), String(y))
  }
  return 0
}

// ------------------------------------------------------------------------------------------- naming
export function snake (name) {
  let s = name.replace(/^_+/, '')
  s = s.replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
  s = s.replace(/([a-z0-9])([A-Z])/g, '$1_$2')
  s = s.toLowerCase().replace(/_+/g, '_')
  if (!s) s = 'f'
  if (/[0-9]/.test(s[0])) s = '_' + s
  if (RUST_KEYWORDS.has(s)) s += '_'
  return s
}
const camel = name => name.split('_').filter(Boolean).map(p => p.slice(0, 1).toUpperCase() + p.slice(1)).join('')
function splitQual (name) {
  if (name.includes('::')) {
    const i = name.lastIndexOf('::')
    return [name.slice(0, i), name.slice(i + 2)]
  }
  return [null, name]
}
const addrInt = a => (typeof a === 'string' && /^(0[xX])?[0-9a-fA-F]+$/.test(a) ? parseInt(a.replace(/^0[xX]/, ''), 16) : -1)

// ------------------------------------------------------------------------------------------- C++ heads
function parseParam (p) {
  let dflt = null
  let depth = 0
  for (let k = 0; k < p.length; k++) {
    const c = p[k]
    if ('(<[{'.includes(c)) depth++
    else if (')>]}'.includes(c)) depth--
    else if (c === '=' && depth === 0) { dflt = p.slice(k + 1).trim(); p = p.slice(0, k); break }
  }
  p = normWs(p)
  if (p === 'void' || p === '...' || p === '') return [p, null, dflt]
  let m = /^(.*)\(\s*\*\s*(\w*)\s*\)\s*\((.*)\)$/.exec(p)
  if (m) return ['fnptr', m[2] || null, dflt]
  let arr = false
  m = /^(.*?)\s*((?:\[[^\]]*\])+)$/.exec(p)
  if (m) { arr = true; p = m[1] }
  m = /^(.*?[\s*&])(\w+)$/.exec(p)
  let ctype, name
  if (m && m[1].trim() && !['const', 'unsigned', 'signed', 'struct', 'enum', 'class', 'union'].includes(m[1].trim()) &&
      !['int', 'char', 'float', 'double', 'bool', 'long', 'short', 'unsigned', 'signed', 'const'].includes(m[2])) {
    ctype = m[1].trim(); name = m[2]
  } else { ctype = p; name = null }
  if (arr) ctype += '[]'
  return [ctype, name, dflt]
}

export function parseHead (head) {
  let h = normWs(head)
  h = h.replace(/\)\s*(const\s*)?throw\s*\(\s*\)\s*/g, (_, c) => ') ' + (c || '')).trim()
  const m0 = /\)\s*(?:const\s*)?:(?!:)/.exec(h)
  if (m0) h = h.slice(0, m0.index + 1) + h.slice(m0.index + 1, m0.index + m0[0].length - 1)
  const isConst = /\)\s*const\s*;?$/.test(h)
  h = h.replace(/\)\s*const\s*;?$/, ')')
  h = h.replace(/\)\s*;$/, ')')
  const end = h.lastIndexOf(')')
  if (end < 0) return null
  let depth = 0; let start = null
  for (let k = end; k >= 0; k--) {
    if (h[k] === ')') depth++
    else if (h[k] === '(') { depth--; if (depth === 0) { start = k; break } }
  }
  if (start === null) return null
  const pre = h.slice(0, start).trim()
  const m = /^(.*?)((?:[\w~]+\s*::\s*)*(?:operator\s*\S+|~?\w+))$/.exec(pre)
  if (!m) return null
  let ret = m[1].replace(/__declspec\s*\([^)]*\)/g, ' ')
  ret = ret.replace(/extern\s*"C(\+\+)?"/g, ' ')
  for (const kw of SPECIFIERS) ret = ret.replace(new RegExp('(^|\\s)' + C.reEscape(kw) + '(?=\\s|$)', 'g'), ' ')
  let params = []
  const ps = h.slice(start + 1, end)
  if (!['', 'void'].includes(ps.trim())) params = C.splitTop(ps).map(parseParam)
  return { ret: normWs(ret), qname: m[2].replace(/\s+/g, ''), params, const: isConst }
}

// ------------------------------------------------------------------------------------------- index
function headAndBody (text) {
  const s = C.stripComments(text)
  const pr = C.findParams(s)
  if (pr === null) return [normWs(rstripChars(s.trimEnd(), ';')), '']
  const b = s.indexOf('{', pr[1])
  if (b < 0) return [normWs(rstripChars(s.trimEnd(), ';')), '']
  return [normWs(s.slice(0, b)), s.slice(b).trim()]
}
const GHIDRA_NAME = /^(FUN|thunk_FUN|LAB|SUB|sub)_[0-9a-fA-F]+$/
const VAR_RE = /^([\s\S]*?)\b([A-Za-z_]\w*)\s*((?:\[[^\]]*\])*)\s*(=[\s\S]*|\([\s\S]*\))?;$/

function variable (text) {
  const s = C.stripComments(text).trim()
  const m = VAR_RE.exec(s)
  if (!m || !m[1].trim() || (m[1].includes(',') && !m[1].includes('<'))) return null
  let pre = m[1]; let name = m[2]
  const q = /((?:[A-Za-z_]\w*\s*::\s*)+)$/.exec(pre)
  if (q) { name = q[1].replace(/\s+/g, '') + name; pre = pre.slice(0, q.index) }
  const words = pre.replace(/extern\s*"C(\+\+)?"/g, ' ').split(/\s+/).filter(Boolean)
  const isStatic = words.includes('static')
  const ctype = normWs(words.filter(w => w !== 'static' && w !== 'extern').join(' '))
  if (!ctype || ['return', 'typedef', 'using'].includes(ctype) || ctype.includes('(') || ctype.includes('"')) return null
  if (m[4] && m[4].startsWith('(') && /^\s*extern\b/.test(s)) return null
  const dims = [...(m[3] || '').matchAll(/\[([^\]]*)\]/g)].map(x => normWs(x[1]))
  const init = m[4] && m[4].startsWith('=') ? normWs(m[4].slice(1)) : ''
  return { name, type: ctype, dims, static: isStatic, init }
}

function classFields (text) {
  const s = C.stripComments(text)
  const b = s.indexOf('{'); const e = s.lastIndexOf('}')
  if (b < 0 || e < b) return []
  const out = []; let cur = []; const nested = []
  for (const ch of s.slice(b + 1, e)) {
    if (ch === '{') {
      nested.push(cur.join('').includes('(') || (nested.length > 0 && nested[nested.length - 1]))
      cur = []
      continue
    }
    if (ch === '}') { if (nested.length) nested.pop(); cur = []; continue }
    if (ch === ';') {
      let stmt = cur.join('')
      cur = []
      if ((nested.length && nested[nested.length - 1]) || (stmt.includes('(') && !/\(\s*\*/.test(stmt))) continue
      stmt = stmt.replace(/^\s*((public|private|protected)\s*:\s*)+/, '').trim()
      if (!stmt || /^(typedef|using|friend|enum|class|struct|union|template)\b/.test(stmt)) continue
      for (let part of C.splitTop(stmt)) {
        part = part.replace(/=[\s\S]*$/, '')
        part = part.replace(/:\s*[0-9]+\s*$/, '')
        part = part.trim().replace(/(\[[^\]]*\]\s*)+$/, '')
        const m = /([A-Za-z_]\w*)\s*\)?\s*$/.exec(part)
        if (m && !out.includes(m[1])) out.push(m[1])
      }
      continue
    }
    cur.push(ch)
  }
  return out
}

function collectClasses (p, cppCfg, classes) {
  const [, rows] = C.loadUnit(p, cppCfg)
  for (const [, it, , , cls] of rows) {
    if (cls === 'typedef') {
      const name = C.typeName(it.text, cls)
      if (name && !classes.has(name)) {
        const fields = classFields(it.text)
        if (fields.length) classes.set(name, fields)
      }
    }
  }
}

function walkFiles (root, fn) {
  const names = L.listdirSorted(root)
  for (const f of names.filter(n => !L.isdir(L.join(root, n)))) fn(root, f)
  for (const d of names.filter(n => L.isdir(L.join(root, n)))) walkFiles(L.join(root, d), fn)
}

function buildIndex (units, cppCfg, module, names, headers) {
  const funcs = []; const globs = []; const gkeys = new Set(); const classes = new Map(); const externs = new Map()
  const counts = new Map([['files', 0], ['header_files', 0], ['duplicate_addresses', 0], ['skipped_constants', 0], ['extern_only_globals', 0]])
  const inc = k => counts.set(k, counts.get(k) + 1)
  const seen = new Set()
  if (headers) {
    walkFiles(headers, (dir, f) => {
      if (['.h', '.hpp', '.hh'].some(e => f.endsWith(e))) { inc('header_files'); collectClasses(L.join(dir, f), cppCfg, classes) }
    })
  }
  for (const p of C.unitFiles(units, cppCfg)) {
    inc('files')
    const unit = L.splitext(L.basename(p))[0]
    const [text, rows] = C.loadUnit(p, cppCfg, module)
    for (const [ns, it, anns, nonm, cls, fn] of rows) {
      if (cls === 'typedef') {
        const tn = C.typeName(it.text, cls)
        if (tn && !classes.has(tn)) {
          const fields = classFields(it.text)
          if (fields.length) classes.set(tn, fields)
        }
      }
      const isfn = (cls === 'funcdef' || cls === 'funcdecl') && fn !== null
      for (const [kind, addr, sym] of anns) {
        if (kind !== 'FUNCTION' && kind !== 'STUB') continue
        if (seen.has(addr)) { inc('duplicate_addresses'); continue }
        seen.add(addr)
        if (isfn) {
          const [head, body] = headAndBody(it.text)
          let nm = names.get(addr)
          if (!nm || GHIDRA_NAME.test(nm)) nm = fn.qual
          funcs.push(new Map([['address', addr], ['name', nm], ['signature', head], ['unit', unit], ['class', fn.cls],
            ['namespace', fn.ns.join('::') || null], ['annotation', kind], ['nonmatching', nonm],
            ['code', cls === 'funcdef' ? 'definition' : 'declaration'], ['body', cls === 'funcdef' ? body : '']]))
          continue
        }
        const vn = cls === 'vardef' ? variable(it.text) : null
        funcs.push(new Map([['address', addr], ['name', names.get(addr) || sym || (vn ? vn.name : '')], ['signature', null],
          ['unit', unit], ['class', null], ['namespace', ns.join('::') || null], ['annotation', kind], ['nonmatching', nonm],
          ['code', cls === 'vardef' ? 'variable' : 'none'], ['body', '']]))
      }
      if (cls === 'vardef' || cls === 'externdecl') {
        const v = variable(it.text)
        if (v === null) continue
        if (/^const\b/.test(v.type) && !v.type.includes('*')) { inc('skipped_constants'); continue }
        let addr = null
        for (const [kind, a] of anns) if (kind === 'GLOBAL') addr = a
        if (addr === null) {
          const end = it.start + it.text.length
          const m = /^[ \t]*\/\/[ \t]*(0x[0-9a-fA-F]+)/.exec(text.slice(end, end + 200))
          if (m) addr = m[1].toLowerCase()
        }
        const nsn = ns.join('::') || null
        const key = [v.static ? unit : '', nsn || '', v.name].join('\u0000')
        const rec = new Map([['address', addr], ['name', v.name], ['type', v.type], ['dims', v.dims], ['init', v.init],
          ['unit', unit], ['namespace', nsn], ['static', v.static]])
        if (cls === 'externdecl') {
          if (!externs.has(key)) externs.set(key, rec)
          else if (externs.get(key).get('address') === null) externs.get(key).set('address', addr)
          continue
        }
        if (gkeys.has(key)) continue
        gkeys.add(key)
        globs.push(rec)
      }
    }
  }
  for (const [key, rec] of externs) {
    if (!gkeys.has(key)) { rec.set('declared_only', true); globs.push(rec); inc('extern_only_globals') }
  }
  funcs.sort((a, b) => cmpTuple([addrInt(a.get('address')), a.get('unit')], [addrInt(b.get('address')), b.get('unit')]))
  const sortedClasses = new Map(sortStr(classes.keys()).map(k => [k, classes.get(k)]))
  return [funcs, globs, sortedClasses, counts]
}

function cmdIndex (a) {
  if (!a.units || !a.out) throw new BadInput('index needs --units and --out')
  let cppCfg = {}
  if (a.cpp_config) {
    try { cppCfg = C.loadConfig(a.cpp_config) } catch (e) { throw new BadInput(`cpp config cannot be read: ${a.cpp_config}`) }
  }
  if (!L.isdir(a.units)) throw new BadInput(`no such units folder: ${a.units}`)
  let names = new Map()
  if (a.names) {
    try {
      const d = L.pyParse(fs.readFileSync(a.names, 'utf8'))
      const fl = isDict(d) ? get(d, 'functions', []) : d
      names = new Map()
      for (const x of fl) if (isDict(x)) names.set(L.pyStr(get(x, 'address', '')).toLowerCase(), get(x, 'name', ''))
    } catch (e) { throw new BadInput(`names index cannot be read: ${a.names}`) }
  }
  const module = a.module || get(cppCfg, 'module', null)
  if (a.headers && !L.isdir(a.headers)) throw new BadInput(`no such headers folder: ${a.headers}`)
  const [funcs, globs, classes, counts] = buildIndex(a.units, cppCfg, module, names, a.headers)
  C.writeText(a.out, L.dumps(new Map([['units', a.units], ['module', module], ['functions', funcs], ['globals', globs], ['classes', classes]])) + '\n')
  const codes = new Map()
  for (const f of funcs) codes.set(f.get('code'), (codes.get(f.get('code')) || 0) + 1)
  const summary = new Map([['out', a.out], ['functions', funcs.length], ['code', new Map(sortStr(codes.keys()).map(k => [k, codes.get(k)]))],
    ['nonmatching', funcs.filter(f => f.get('nonmatching')).length], ['globals', globs.length],
    ['globals_with_address', globs.filter(g => g.get('address')).length], ['classes', classes.size]])
  for (const [k, v] of counts) summary.set(k, v)
  process.stdout.write(L.dumps(summary) + '\n')
  return 0
}

// ------------------------------------------------------------------------------------------- types
const baseType = t => normWs(t.replace(/\b(const|struct|enum|class|volatile|mutable|typename|union)\b/g, ' ')).replaceAll(' *', '*').replaceAll(' &', '&')
const isConstT = t => /\bconst\b/.test(t)

class Types {
  constructor (cfg) {
    this.types = new Map(BUILTIN_TYPES)
    for (const [k, v] of toMap(get(cfg, 'types', {}))) this.types.set(k, v)
    this.params = toMap(get(cfg, 'param_types', {}))
    this.rets = toMap(get(cfg, 'return_types', {}))
    this.drop = toMap(get(cfg, 'drop_params', {}))
    this.enums = toMap(get(cfg, 'enums', {}))
    this.classes = new Map([...toMap(get(cfg, 'classes', {}))].map(([k, v]) => [k, get(v, 'rust', k)]))
    this.varargs = get(cfg, 'varargs', '&[VArg]')
    this.consts = toMap(get(cfg, 'constants', {}))
    this.unmapped = new Map()
  }

  note (what) { this.unmapped.set(what, (this.unmapped.get(what) || 0) + 1) }

  named (bt) {
    const parts = bt.split('::')
    const last = parts[parts.length - 1]
    for (const table of [this.enums, this.classes]) {
      if (table.has(bt)) return table.get(bt)
      if (table.has(last)) return table.get(last)
    }
    return null
  }

  value (t) {
    const bt = baseType(t)
    if (this.types.has(bt)) return this.types.get(bt)
    if (bt === 'char*') return 'String'
    let m = /^std::vector<(.*)>$/.exec(bt)
    if (m) {
      const inner = this.value(m[1].trim())
      return inner ? `Vec<${inner}>` : null
    }
    m = /^std::map<(.*)>$/.exec(bt)
    if (m) {
      const kv = C.splitTop(m[1]).map(x => x.trim())
      if (kv.length === 2) {
        const k = this.value(kv[0]); const v = this.value(kv[1])
        if (k && v) return `BTreeMap<${k}, ${v}>`
      }
      return null
    }
    return this.named(bt)
  }

  param (ctype, name, body, nxt, idx) {
    const rn = name ? snake(name) : `arg${idx}`
    if (ctype === 'fnptr') {
      if (this.params.has('fnptr')) return [rn, this.params.get('fnptr'), null]
      this.note('param fnptr')
      return [rn, 'Unmapped /* function pointer */', null]
    }
    if (ctype === '...' || ctype === 'va_list') return ['args', this.varargs, null]
    let bt = baseType(ctype)
    const cnst = isConstT(ctype)
    const key = (cnst ? 'const ' : '') + bt
    for (const k of [key, bt]) {
      if (this.drop.has(k)) return [rn, null, this.drop.get(k)]
      if (this.params.has(k)) return [rn, this.params.get(k), null]
    }
    const nul = nullable(body, name)
    if (this.types.has(bt) && !bt.endsWith('*') && !bt.endsWith('&')) {
      if (bt === 'std::string') return [rn, '&str', null]
      return [rn, this.types.get(bt), null]
    }
    if (this.types.has(bt)) return [rn, this.types.get(bt), null]
    if (bt === 'char*' || bt === 'char[]') {
      if (!cnst && (bt === 'char[]' || (nxt && ['size_t', 'int', 'unsigned', 'unsigned int'].includes(baseType(nxt[0])) &&
          /size|len|max/.test(nxt[1] || '')))) return [rn, '&mut [u8]', null]
      return [rn, nul ? 'Option<&str>' : '&str', null]
    }
    if (bt.endsWith('[]')) {
      const inner = this.value(bt.slice(0, -2))
      if (inner !== null) return [rn, cnst ? `&[${inner}]` : `&mut [${inner}]`, null]
      bt = bt.slice(0, -2) + '*'
    }
    if (bt === 'std::string&') return [rn, cnst ? '&str' : '&mut String', null]
    if (bt === 'std::string*') return [rn, cnst ? (nul ? 'Option<&str>' : '&str') : (nul ? 'Option<&mut String>' : '&mut String'), null]
    let m = /^std::vector<(.*)>([&*]?)$/.exec(bt)
    if (m) {
      const inner = this.value(m[1].trim())
      if (inner === null) { this.note('param ' + key); return [rn, `Unmapped /* ${ctype} */`, null] }
      if (m[2] && cnst) return [rn, `&[${inner}]`, null]
      if (m[2]) return [rn, `&mut Vec<${inner}>`, null]
      return [rn, `Vec<${inner}>`, null]
    }
    if (bt === 'void*') return [rn, cnst ? '&[u8]' : 'usize', null]
    m = /^(.*?)([*&])$/.exec(bt)
    if (m && !m[1].endsWith('*') && !m[1].endsWith('&')) {
      const innerC = m[1]
      let inner = this.types.has(innerC) && innerC !== 'std::string' ? this.types.get(innerC) : null
      if (inner === null) inner = this.named(innerC)
      if (inner !== null) {
        if (m[2] === '*' && SCALARS.has(inner) && cnst) return [rn, `&[${inner}]`, null]
        const ref = cnst ? `&${inner}` : `&mut ${inner}`
        if (m[2] === '*' && nul) return [rn, `Option<${ref}>`, null]
        return [rn, ref, null]
      }
    }
    const named = this.named(bt)
    if (named) return [rn, named, null]
    this.note('param ' + key)
    return [rn, `Unmapped /* ${ctype} */`, null]
  }

  ret (ctype, body) {
    const t = normWs(ctype)
    const bt = baseType(t)
    if (bt === '' || bt === 'void') return null
    const key = (isConstT(t) ? 'const ' : '') + bt
    for (const k of [key, bt]) if (this.rets.has(k)) return this.rets.get(k)
    if (bt === 'char*') return /return\s+(NULL|nullptr|0)\s*;/.test(body || '') ? 'Option<String>' : 'String'
    const v = this.value(t)
    if (v !== null) return v
    this.note('return ' + key)
    return `Unmapped /* ${t} */`
  }

  dim (d) {
    const toks = d.match(/0x[0-9a-fA-F]+|[0-9]+|[A-Za-z_]\w*|[-+*/%()]|\S/g) || []
    let pos = 0
    const peek = () => (pos < toks.length ? toks[pos] : null)
    class Bad {}
    const atom = () => {
      const t = peek()
      pos++
      if (t === '(') {
        const v = expr()
        if (peek() !== ')') throw new Bad()
        pos++
        return v
      }
      if (t === '-') return -atom()
      if (t !== null && /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(t)) return t.startsWith('0x') ? parseInt(t.slice(2), 16) : parseInt(t, 10)
      const v = t !== null && this.consts.has(t) ? this.consts.get(t) : null
      if (isInt(v)) return v
      throw new Bad()
    }
    const term = () => {
      let v = atom()
      while (['*', '/', '%'].includes(peek())) {
        const op = peek()
        pos++
        const r = atom()
        if (op === '*') v = v * r
        else if (r === 0) throw new Bad()
        else {
          const q = Math.floor(Math.abs(v) / Math.abs(r)) * ((v < 0) === (r < 0) ? 1 : -1)
          v = op === '/' ? q : v - q * r
        }
      }
      return v
    }
    const expr = () => {
      let v = term()
      while (['+', '-'].includes(peek())) {
        const op = peek()
        pos++
        const r = term()
        v = op === '+' ? v + r : v - r
      }
      return v
    }
    let v
    try { v = expr() } catch (e) { if (e instanceof Bad) return null; throw e }
    return pos === toks.length && v >= 0 ? v : null
  }
}

function nullable (body, name) {
  if (!name || !body) return false
  const n = C.reEscape(name)
  return new RegExp(`\\b${n}\\s*[!=]=\\s*(?:NULL|nullptr|0)\\b|\\b(?:NULL|nullptr)\\s*[!=]=\\s*${n}\\b|!\\s*${n}\\b(?!\\s*[.\\[(-])|` +
    `\\(\\s*${n}\\s*\\)\\s*(?:\\?|&&|\\|\\|)|if\\s*\\(\\s*${n}\\s*\\)`).test(body)
}

// ------------------------------------------------------------------------------------------- placement
function dest (s, defaultFile = null) {
  if (s.includes('/')) { const i = s.indexOf('/'); return [s.slice(0, i), s.slice(i + 1)] }
  return [s, defaultFile]
}
function firstMatch (rules, unit) {
  for (const [rx, val] of rules) if (unit !== null && unit !== undefined && new RegExp(rx).test(unit)) return val
  return null
}

class Placer {
  constructor (cfg) {
    this.cfg = cfg
    this.default = get(cfg, 'default_module', 'app')
    this.classes = toMap(get(cfg, 'classes', {}))
    this.namespaces = toMap(get(cfg, 'namespaces', {}))
    this.prefixes = get(cfg, 'prefixes', [])
    this.names = toMap(get(cfg, 'names', {}))
    this.namePatterns = get(cfg, 'name_patterns', [])
    this.addresses = new Map([...toMap(get(cfg, 'addresses', {}))].map(([k, v]) => [k.toLowerCase(), v]))
    this.units = get(cfg, 'units', [])
    this.moduleFiles = toMap(get(cfg, 'module_files', {}))
    this.skip = get(cfg, 'skip', [])
    this.hand = new Map([...toMap(get(cfg, 'handwritten', {}))].map(([k, v]) => [k.toLowerCase(), v]))
    this.rename = new Map([...toMap(get(cfg, 'rename', {}))].map(([k, v]) => [k.toLowerCase(), v]))
    let rxs = []
    for (const r of this.skip) rxs.push(...get(r, 'names', []), ...get(r, 'units', []))
    rxs = rxs.concat(this.units.map(r => r[0]), this.namePatterns.map(r => r[0]))
    for (const rules of this.moduleFiles.values()) rxs.push(...rules.map(r => r[0]))
    for (const spec of this.classes.values()) rxs.push(...get(spec, 'files', []).map(r => r[0]))
    for (const rx of rxs) compileRx(rx)
  }

  classOf (f) {
    let cls = get(f, 'class', null)
    if (cls === null && !hasOwn(f, 'class')) {
      const [q] = splitQual(f.name)
      if (q !== null && !this.namespaces.has(q.split('::')[0])) cls = q
    }
    return cls
  }

  skipped (f, cls, base) {
    const unit = get(f, 'unit', null) || ''
    for (const r of this.skip) {
      if (get(r, 'names', []).some(rx => new RegExp(rx).test(f.name)) || get(r, 'units', []).some(rx => new RegExp(rx).test(unit)) ||
          get(r, 'bases', []).includes(base)) return get(r, 'reason', 'skipped by the config')
    }
    if (get(f, 'code', null) === 'variable') return 'annotation on a variable (dynamic initializer): the global itself'
    if (get(f, 'code', null) === 'none') return 'no code in the source (fragment of another function, library object)'
    if (base.startsWith('~')) return 'destructor: Drop'
    if (cls !== null) {
      const short = cls.split('::').pop()
      const spec = this.classes.get(short)
      if (truthy(spec) && get(spec, 'role', 'value') === 'value' && base === short) return 'constructor of a value type: Default'
    }
    return null
  }

  fileFor (module, given, unit) {
    if (given) return given
    const rules = this.moduleFiles.get(module)
    if (truthy(rules)) {
      const f = firstMatch(rules, unit)
      if (f) return f
    }
    return module
  }

  place (f) {
    const name = f.name; const addr = f.address.toLowerCase(); const unit = get(f, 'unit', null)
    const cls = this.classOf(f)
    const [q, base] = splitQual(name)
    const reason = this.skipped(f, cls, base)
    if (reason) return { skip: reason }
    if (this.hand.has(addr)) {
      const path = this.hand.get(addr)
      const [mod, rn] = path.includes('::') ? [path.slice(0, path.indexOf('::')), path.slice(path.indexOf('::') + 2)] : [this.default, path]
      return { module: mod, file: mod, rust_name: rn, style: 'handwritten' }
    }
    const p = this._place(f, cls, q, base, unit)
    if (this.addresses.has(addr)) {
      const [mod, fl] = dest(this.addresses.get(addr))
      p.module = mod; p.file = this.fileFor(mod, fl, unit)
    }
    if (this.rename.has(addr)) p.rust_name = this.rename.get(addr)
    return p
  }

  _place (f, cls, q, base, unit) {
    const free = (mod, fl, rn) => ({ module: mod, file: this.fileFor(mod, fl, unit), style: 'free', rust_name: rn })
    if (cls !== null) {
      const short = cls.split('::').pop()
      const spec = this.classes.get(short)
      if (truthy(spec)) return this._class(spec, short, base, unit)
      const ns = cls.split('::')[0]
      if (this.namespaces.has(ns)) { const [mod, fl] = dest(this.namespaces.get(ns)); return free(mod, fl, snake(base)) }
      return free(this.default, null, snake(f.name.replaceAll('::', '_')))
    }
    const nsn = get(f, 'namespace', null) || (q ? q.split('::')[0] : null)
    if (this.names.has(f.name)) { const [mod, fl] = dest(this.names.get(f.name)); return free(mod, fl, snake(base)) }
    let d = firstMatch(this.namePatterns, f.name)
    if (d) { const [mod, fl] = dest(d); return free(mod, fl, snake(base)) }
    if (nsn && this.namespaces.has(nsn.split('::')[0])) { const [mod, fl] = dest(this.namespaces.get(nsn.split('::')[0])); return free(mod, fl, snake(base)) }
    for (const [pre, dd, strip] of this.prefixes) {
      if (base.startsWith(pre)) {
        const [mod, fl] = dest(dd)
        return free(mod, fl, strip && base.length > pre.length ? snake(base.slice(pre.length)) : snake(base))
      }
    }
    d = firstMatch(this.units, unit)
    const [mod, fl] = d ? dest(d) : [this.default, null]
    return free(mod, fl, snake(base))
  }

  _class (spec, short, base, unit) {
    const role = get(spec, 'role', 'value')
    const rust = get(spec, 'rust', short)
    const mod = get(spec, 'module', this.default)
    const fl = get(spec, 'file', null) || firstMatch(get(spec, 'files', []), unit) || this.fileFor(mod, null, unit)
    if (role === 'element') {
      return { module: mod, file: fl, rust_name: base === short ? 'new' : snake(base), style: 'element', cls: short, rust_type: rust, ctor: base === short }
    }
    if (role === 'subobject') {
      const pre = get(spec, 'prefix', snake(short) + '_')
      return { module: mod, file: fl, rust_name: pre + snake(base), style: 'method', cls: short }
    }
    if (role === 'singleton') return { module: mod, file: fl, rust_name: snake(base), style: 'method', cls: short }
    return { module: mod, file: fl, rust_name: snake(short) + '_' + snake(base), style: 'free', cls: short }
  }
}

// ------------------------------------------------------------------------------------------- cx analysis
const CALL_RE = /(?<![\w.>])((?:\w+::)*~?\w+)\s*\(/g
const IDENT_RE = /(?<![\w.>:])([A-Za-z_]\w*)\b(?!\s*::)/g

function needsCx (funcs, places, cfg, globs, gmods, fields) {
  const cxc = get(cfg, 'cx', {})
  const mode = get(cxc, 'mode', 'all')
  const pure = new Set(get(cxc, 'pure', []))
  const needs = new Set(get(cxc, 'needs', []))
  const live = funcs.filter(f => !('skip' in places.get(f.address)))
  let out
  if (mode === 'all' || mode === 'none') {
    out = new Map(live.map(f => [f.address, mode === 'all']))
  } else {
    const state = get(cxc, 'state', []).map(compileRx)
    const gnames = new Set(); const byMod = new Map()
    if (truthy(get(cxc, 'globals', null))) {
      const ign = new Set(get(cxc, 'ignore_globals', []))
      for (const g of globs) {
        const short = splitQual(g.name)[1]
        const gm = gmods.has(g.name) ? gmods.get(g.name) : null
        if (!byMod.has(gm)) byMod.set(gm, new Set())
        byMod.get(gm).add(short)
        if (short.length >= get(cxc, 'global_min_len', 5) && !ign.has(short)) gnames.add(short)
      }
    }
    const alwaysMethods = get(cxc, 'methods', 'always') === 'always'
    const byQ = new Map(); const byBase = new Map()
    const push = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v) }
    for (const f of live) { push(byQ, f.name, f.address); push(byBase, splitQual(f.name)[1], f.address) }
    out = new Map(); const calls = new Map()
    const anyFields = truthy(fields)
    for (const f of live) {
      const p = places.get(f.address)
      const body = get(f, 'body', null) || ''
      const idents = (gnames.size || byMod.size || anyFields) ? new Set([...body.matchAll(IDENT_RE)].map(m => m[1])) : new Set()
      let direct = state.some(r => r.test(body)) || !isDisjoint(gnames, idents) || !isDisjoint(byMod.get(p.module) || new Set(), idents)
      if (p.style === 'method') {
        const own = idents.has('this') || !isDisjoint(new Set(get(fields, p.cls, [])), idents)
        direct = direct || alwaysMethods || own
      }
      out.set(f.address, direct)
      const cs = []
      const cls = p.cls
      for (const m of body.matchAll(CALL_RE)) {
        const c = m[1]
        if (NOT_CALLS.has(c)) continue
        let cands = byQ.get(c)
        if (!truthy(cands)) cands = cls ? byQ.get(cls + '::' + c) : null
        if (!truthy(cands)) cands = !c.includes('::') ? byBase.get(c) : byBase.get(c.split('::').pop())
        for (const a of cands || []) if (a !== f.address && !cs.includes(a)) cs.push(a)
      }
      calls.set(f.address, cs)
    }
    let changed = true
    while (changed) {
      changed = false
      for (const f of live) {
        const a = f.address
        if (!out.get(a) && !pure.has(f.name) && calls.get(a).some(c => out.get(c))) { out.set(a, true); changed = true }
      }
    }
  }
  for (const f of live) {
    if (needs.has(f.name)) out.set(f.address, true)
    if (pure.has(f.name)) out.set(f.address, false)
  }
  return out
}

// ------------------------------------------------------------------------------------------- emit
function rustSig (f, p, need, types, cxc) {
  const sig = get(f, 'signature', null) ? parseHead(f.signature) : null
  const params = []; const dropped = []
  if (p.style === 'element' && !p.ctor) params.push(sig && sig.const ? '&self' : '&mut self')
  if (need) params.push(`${get(cxc, 'name', 'cx')}: &mut ${get(cxc, 'type', 'Cx')}`)
  const used = new Set([get(cxc, 'name', 'cx'), 'self'])
  const plist = sig ? sig.params : []
  plist.forEach(([ct, nm, dv], i) => {
    if (ct === 'void' || ct === '') return
    const nxt = i + 1 < plist.length ? plist[i + 1] : null
    let [rn, rt, why] = types.param(ct, nm, get(f, 'body', null) || '', nxt, i)
    if (rt === null) { dropped.push(`${nm || 'arg' + i} (${why})`); return }
    if (used.has(rn)) rn = `${rn}_${i}`
    used.add(rn)
    params.push(`${rn}: ${rt}${dv ? ` /* = ${dv} */` : ''}`)
  })
  let ret = sig ? types.ret(sig.ret, get(f, 'body', null) || '') : null
  if (p.ctor) ret = 'Self'
  return [params, ret, dropped]
}

function emitStub (f, p, need, types, cfg) {
  const [params, ret, dropped] = rustSig(f, p, need, types, get(cfg, 'cx', {}))
  const macro = get(cfg, 'stub_macro', 'stub')
  let lines = [`// ${f.address}`,
    `/// \`${(get(f, 'signature', null) || f.name).replaceAll('`', "'")}\`${truthy(get(f, 'nonmatching', null)) ? ' (NONMATCHING in the matched source)' : ''}`]
  if (dropped.length) lines.push(`/// dropped parameter: ${dropped.join('; ')}`)
  lines.push(`pub fn ${p.rust_name}(${params.join(', ')})${ret ? ' -> ' + ret : ''} {`)
  lines.push(`    ${macro}!(${f.address}, "${f.name.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}")`)
  lines.push('}')
  if (p.style === 'element') lines = lines.map(x => '    ' + x)
  return [lines.join('\n'), `(${params.join(', ')})${ret ? ' -> ' + ret : ''}`]
}

function fileHeader (cfg, module, fl, units) {
  const doc = get(get(cfg, 'modules', {}), module, '')
  const out = [`//! Module \`${module}\`${fl !== module ? `, file \`${fl}\`` : ''}${doc ? ': ' + doc : ''}`,
    '//! Generated by gen_skeleton.py: one stub per C++ function, in address order, with its address and C++',
    '//! head. Fill in the bodies (references/rust.md); `stub!` logs the first call and returns Default.',
    `//! Units: ${units.length ? units.join(', ') : '-'}`,
    '#![allow(unused_variables, unused_imports, dead_code, clippy::all)]', '']
  out.push(...get(cfg, 'imports', ['use crate::cx::Cx;', 'use crate::state::*;', 'use crate::stub;']))
  return out.join('\n')
}

function staticsText (cfg, globs, types) {
  const byMod = new Map(); const rows = []
  for (const g of globs) { if (!byMod.has(g._module)) byMod.set(g._module, []); byMod.get(g._module).push(g) }
  const parts = ['//! File-scope globals of the C++ code, per module (`cx.statics.<module>.<field>`). Generated by',
    '//! gen_skeleton.py from the function index; edit freely afterwards (function-local statics are added',
    '//! by the translator of the function).',
    '#![allow(dead_code, clippy::all)]', '']
  parts.push(...get(cfg, 'statics_imports', ['use crate::cbuf::CBuf;', 'use crate::state::*;', 'use std::collections::BTreeMap;']))
  const mods = sortStr(byMod.keys())
  for (const mod of mods) {
    const sname = camel(mod) + 'Statics'
    const fields = []; const inits = []; const seen = new Set()
    for (const g of byMod.get(mod)) {
      let field = snake(splitQual(g.name)[1])
      if (seen.has(field)) field = `${field}_${(get(g, 'address', null) || 'x').slice(2)}`
      seen.add(field)
      const [t, init] = globalType(g, types)
      const where = [get(g, 'address', null), get(g, 'unit', null)].filter(x => x).join(' ')
      let initC = get(g, 'init', null) || ''
      if (initC.length > 40) initC = initC.slice(0, 37) + '...'
      const dims = get(g, 'dims', [])
      const cdecl = `${g.type} ${g.name}${dims.map(d => `[${d}]`).join('')}${initC ? ' = ' + initC : ''}`
      const addr = get(g, 'address', null) || '-'
      const unit = get(g, 'unit', null) || '-'
      if (t === null) {
        types.note('global ' + baseType(g.type) + dims.map(d => `[${d}]`).join(''))
        fields.push(`    // ${field}: ${cdecl} (${where}) -- type not mapped, add by hand`)
        rows.push([addr, 'global ' + g.name, `cx.statics.${mod}.${field}`, `Unmapped /* ${g.type} */`, unit])
        continue
      }
      fields.push(`    pub ${field}: ${t}, // ${cdecl} (${where})`)
      inits.push(`            ${field}: ${init},`)
      rows.push([addr, 'global ' + g.name, `cx.statics.${mod}.${field}`, t, unit])
    }
    parts.push('', `/// Globals of module \`${mod}\`.`, '#[derive(Clone, Debug)]', `pub struct ${sname} {`, ...fields, '}', '',
      `impl Default for ${sname} {`, '    fn default() -> Self {', '        Self {', ...inits, '        }', '    }', '}')
  }
  parts.push('', '/// All module globals: `cx.statics.<module>`.', '#[derive(Clone, Debug, Default)]', 'pub struct Statics {')
  for (const mod of mods) parts.push(`    pub ${mod}: ${camel(mod)}Statics,`)
  parts.push('}')
  return [parts.join('\n') + '\n', rows]
}

function globalType (g, types) {
  const dims = get(g, 'dims', [])
  const bt = baseType(g.type)
  if (bt === 'char' && dims.length === 1) {
    const n = types.dim(dims[0])
    return n !== null ? [`CBuf<${n}>`, 'CBuf::new()'] : [null, null]
  }
  const rt = types.value(g.type)
  if (rt === null) return [null, null]
  const zero = { f32: '0.0', f64: '0.0', bool: 'false' }[rt] || (SCALARS.has(rt) ? '0' : 'Default::default()')
  if (!dims.length) return [rt, zero]
  const sizes = dims.map(d => types.dim(d))
  if (sizes.some(s => s === null)) return [null, null]
  let t = rt; let init = zero
  for (const n of [...sizes].reverse()) t = `[${t}; ${n}]`
  let total = 1
  for (const n of sizes) total *= n
  if (SCALARS.has(rt)) for (const n of [...sizes].reverse()) init = `[${init}; ${n}]`
  else for (let k = 0; k < sizes.length; k++) init = `std::array::from_fn(|_| ${init})`
  if (total * (SIZES[rt] || 16) > 4096) return [`Box<${t}>`, `Box::new(${init})`]
  return [t, init]
}

function globalModule (g, placer, unitMod) {
  const gm = toMap(get(placer.cfg, 'global_modules', {}))
  if (gm.has(g.name)) return gm.get(g.name)
  const [q] = splitQual(g.name)
  if (q !== null && placer.classes.has(q.split('::').pop())) return get(placer.classes.get(q.split('::').pop()), 'module', placer.default)
  const ns = (get(g, 'namespace', null) || '').split('::')[0]
  if (ns && placer.namespaces.has(ns)) return dest(placer.namespaces.get(ns))[0]
  const counts = unitMod.get(get(g, 'unit', null))
  if (counts && counts.size) return [...counts.entries()].sort((a, b) => b[1] - a[1] || L.cmp(a[0], b[0]))[0][0]
  return placer.default
}

const sha256Text = text => createHash('sha256').update(text, 'utf8').digest('hex')

function scanTree (src, macro) {
  const addrs = new Set(); const stubs = []
  if (!L.isdir(src)) return [addrs, stubs]
  const re = new RegExp(`\\b${C.reEscape(macro)}!\\(\\s*(0x[0-9a-fA-F]+)`, 'g')
  walkFiles(src, (dir, f) => {
    if (!f.endsWith('.rs')) return
    const t = C.readText(L.join(dir, f))
    for (const m of t.matchAll(ADDR_LINE)) addrs.add(m[1].toLowerCase())
    for (const m of t.matchAll(re)) stubs.push(m[1].toLowerCase())
  })
  return [addrs, stubs]
}

function loadJson (p) { return L.pyParse(fs.readFileSync(p, 'utf8')) }

function cmdGenerate (a) {
  if (!a.config || !a.index || !a.crate) throw new BadInput('generate needs --config, --index and --crate')
  let cfg, idx
  try { cfg = loadJson(a.config); if (!isDict(cfg)) throw new Error() } catch (e) { throw new BadInput(`config cannot be read: ${a.config}`) }
  try { idx = loadJson(a.index) } catch (e) { throw new BadInput(`index cannot be read: ${a.index}`) }
  let funcs = isDict(idx) ? get(idx, 'functions', []) : idx
  let globs = isDict(idx) ? get(idx, 'globals', []) : []
  const fields = isDict(idx) ? get(idx, 'classes', {}) : {}
  if (!Array.isArray(globs) || !globs.every(g => isDict(g) && typeof get(g, 'name', null) === 'string' && typeof get(g, 'type', null) === 'string')) {
    throw new BadInput('index globals need "name" and "type"')
  }
  if (!isDict(fields)) throw new BadInput('index "classes" must be an object')
  if (!Array.isArray(funcs)) throw new BadInput('index "functions" must be a list')
  funcs.forEach((f, i) => {
    if (!isDict(f) || typeof get(f, 'address', null) !== 'string' || typeof get(f, 'name', null) !== 'string') {
      throw new BadInput(`index function without "address" and "name" (entry ${i})`)
    }
    f.address = f.address.toLowerCase()
  })
  funcs = [...funcs].sort((x, y) => cmpTuple([addrInt(x.address), get(x, 'unit', null) || ''], [addrInt(y.address), get(y, 'unit', null) || '']))
  const placer = new Placer(cfg)
  const types = new Types(cfg)
  const places = new Map()
  for (const f of funcs) places.set(f.address, placer.place(f))
  const unitMod = new Map()
  for (const f of funcs) {
    const p = places.get(f.address)
    if (!('skip' in p)) {
      const u = get(f, 'unit', null)
      if (!unitMod.has(u)) unitMod.set(u, new Map())
      const c = unitMod.get(u)
      c.set(p.module, (c.get(p.module) || 0) + 1)
    }
  }
  const sg = get(cfg, 'skip_globals', {})
  const sgn = get(sg, 'names', []).map(compileRx)
  const sgu = get(sg, 'units', []).map(compileRx)
  const nglobs = globs.length
  globs = globs.filter(g => !sgn.some(r => r.test((get(g, 'namespace', null) ? g.namespace + '::' : '') + g.name)) &&
    !sgu.some(r => r.test(get(g, 'unit', null) || '')))
  const gmods = new Map()
  for (const g of globs) {
    g._module = globalModule(g, placer, unitMod)
    if (!gmods.has(g.name)) gmods.set(g.name, g._module)
  }
  const need = needsCx(funcs, places, cfg, globs, gmods, fields)
  const seen = new Set()
  for (const f of funcs) {
    const p = places.get(f.address)
    if ('skip' in p || p.style === 'handwritten') continue
    const key = [p.module, p.style === 'element' ? p.rust_type : '\u0001', p.rust_name].join('\u0000')
    if (seen.has(key)) p.rust_name = `${p.rust_name.replace(/_+$/, '')}_${f.address.slice(2)}`
    seen.add(key)
  }
  let rows = []; const byFile = new Map(); const perMod = new Map(); const skipped = new Map()
  for (const f of funcs) {
    const p = places.get(f.address)
    const unit = get(f, 'unit', null) || '-'
    if ('skip' in p) {
      rows.push([f.address, f.name, '-', p.skip, unit])
      skipped.set(p.skip, (skipped.get(p.skip) || 0) + 1)
      continue
    }
    const mod = p.module
    if (!perMod.has(mod)) perMod.set(mod, new Map([['stubs', 0], ['handwritten', 0]]))
    const pm = perMod.get(mod)
    if (p.style === 'handwritten') {
      rows.push([f.address, f.name, `${mod}::${p.rust_name}`, '(hand-written)', unit])
      pm.set('handwritten', pm.get('handwritten') + 1)
      continue
    }
    const [text, sig] = emitStub(f, p, need.get(f.address) || false, types, cfg)
    const path = p.style === 'element' ? `${mod}::${p.rust_type}::${p.rust_name}` : `${mod}::${p.rust_name}`
    rows.push([f.address, f.name, path, sig, unit])
    const fk = mod + '\u0000' + p.file
    if (!byFile.has(fk)) byFile.set(fk, [])
    byFile.get(fk).push([f, p, text])
    pm.set('stubs', pm.get('stubs') + 1)
  }
  const out = new Map()
  const filesOf = new Map()
  for (const fk of byFile.keys()) {
    const [mod, fl] = fk.split('\u0000')
    if (!filesOf.has(mod)) filesOf.set(mod, [])
    filesOf.get(mod).push(fl)
  }
  const single = mod => filesOf.get(mod).length === 1 && filesOf.get(mod)[0] === mod
  const fileKeys = [...byFile.keys()].map(k => k.split('\u0000')).sort(cmpTuple)
  for (const [mod, fl] of fileKeys) {
    const items = byFile.get(mod + '\u0000' + fl)
    const units = sortStr(new Set(items.map(([f]) => get(f, 'unit', null)).filter(u => u)))
    const body = [fileHeader(cfg, mod, fl, units)]
    const impls = new Map()
    for (const [, p, text] of items) {
      if (p.style === 'element') { if (!impls.has(p.rust_type)) impls.set(p.rust_type, []); impls.get(p.rust_type).push(text) } else body.push(text)
    }
    for (const rt of sortStr(impls.keys())) body.push(`impl ${rt} {\n${impls.get(rt).join('\n\n')}\n}`)
    const rel = single(mod) ? `src/${mod}.rs` : `src/${mod}/${fl}.rs`
    out.set(rel, body.join('\n\n') + '\n')
  }
  for (const mod of sortStr(filesOf.keys())) {
    if (!single(mod)) {
      const doc = get(get(cfg, 'modules', {}), mod, '')
      const fls = sortStr(filesOf.get(mod))
      const lines = [`//! Module \`${mod}\`${doc ? ': ' + doc : ''}`, '//! (generated by gen_skeleton.py; the files group the C++ functions by origin)', '',
        ...fls.map(fl => `pub mod ${fl};`), '', ...fls.map(fl => `pub use ${fl}::*;`)]
      out.set(`src/${mod}/mod.rs`, lines.join('\n') + '\n')
    }
  }
  const staticsRel = get(cfg, 'statics', 'src/state/statics.rs')
  if (globs.length && truthy(staticsRel)) {
    const [text, grows] = staticsText(cfg, globs, types)
    out.set(staticsRel, text)
    rows = rows.concat(grows)
  }
  rows.sort((x, y) => cmpTuple([x[0] === '-' ? 1 : 0, addrInt(x[0]), x[1]], [y[0] === '-' ? 1 : 0, addrInt(y[0]), y[1]]))
  const tsv = ['# address\tC++ name\tRust path\tRust signature (or skip reason)\tunit', ...rows.map(r => r.join('\t'))].join('\n') + '\n'
  // ------------------------------------------------------------- write, never over a hand edit
  const crate = a.crate
  const manPath = L.join(crate, '.gen_skeleton.json')
  let manifest = new Map()
  if (L.isfile(manPath)) {
    let m
    try { m = loadJson(manPath) } catch (e) { throw new BadInput(`manifest cannot be read: ${manPath}`) }
    if (!isDict(m)) throw new BadInput(`manifest cannot be read: ${manPath}`)
    manifest = toMap(get(m, 'files', {}))
  }
  const keep = new Set(get(cfg, 'keep', []))
  const status = { new: [], updated: [], same: [], kept_edited: [], kept_not_generated: [], kept_config: [] }
  for (const rel of sortStr(out.keys())) {
    const text = out.get(rel)
    const p = L.join(crate, rel)
    if (keep.has(rel)) { status.kept_config.push(rel); continue }
    if (L.exists(p)) {
      const cur = L.isfile(p) ? sha256Text(C.readText(p)) : null
      if (!manifest.has(rel)) { status.kept_not_generated.push(rel); continue }
      if (cur !== manifest.get(rel)) { status.kept_edited.push(rel); continue }
      if (cur === sha256Text(text)) { status.same.push(rel); continue }
      status.updated.push(rel)
    } else status.new.push(rel)
    if (!a.dry_run) {
      C.writeText(p, text)
      manifest.set(rel, sha256Text(text))
    }
  }
  const namesOut = a.names_out || L.join(crate, 'tools', 'names.tsv')
  if (!a.dry_run) {
    C.writeText(namesOut, tsv)
    C.writeText(manPath, L.dumps(new Map([['generator', 'gen_skeleton.py'], ['files', new Map(sortStr(manifest.keys()).map(k => [k, manifest.get(k)]))]])) + '\n')
  }
  const macro = get(cfg, 'stub_macro', 'stub')
  const [tree, stubs] = scanTree(L.join(crate, 'src'), macro)
  const want = funcs.filter(f => !('skip' in places.get(f.address)) && places.get(f.address).style !== 'handwritten').map(f => f.address)
  const missing = want.filter(x => !tree.has(x))
  const sum = k => [...perMod.values()].reduce((s, m) => s + m.get(k), 0)
  const summary = new Map([
    ['functions', funcs.length],
    ['placed', sum('stubs')],
    ['handwritten', sum('handwritten')],
    ['skipped', [...skipped.values()].reduce((s, v) => s + v, 0)],
    ['skip_reasons', new Map(sortStr(skipped.keys()).map(k => [k, skipped.get(k)]))],
    ['modules', new Map(sortStr(perMod.keys()).map(k => [k, perMod.get(k)]))],
    ['need_cx', want.filter(x => need.get(x)).length],
    ['globals', globs.length],
    ['globals_skipped', nglobs - globs.length],
    ['names_rows', rows.length],
    ['names_out', namesOut],
    ['unmapped_types', new Map(sortStr(types.unmapped.keys()).map(k => [k, types.unmapped.get(k)]))],
    ['files', new Map([['new', status.new.length], ['updated', status.updated.length], ['same', status.same.length],
      ['kept_edited', status.kept_edited], ['kept_not_generated', status.kept_not_generated], ['kept_config', status.kept_config]])],
    ['dry_run', Boolean(a.dry_run)],
    ['tree', new Map([['address_lines', tree.size], ['missing', missing.length], ['first_missing', missing.slice(0, 20)], ['stubs_left', stubs.length]])]
  ])
  process.stdout.write(L.dumps(summary) + '\n')
  return 0
}

function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [
    ['--units', 'str', null], ['--out', 'str', null], ['--cpp-config', 'str', null], ['--module', 'str', null],
    ['--names', 'str', null], ['--headers', 'str', null], ['--config', 'str', null], ['--index', 'str', null], ['--crate', 'str', null],
    ['--names-out', 'str', null], ['--dry-run', 'flag', false]], [['command', '1']])
  try {
    if (a.command === 'index') return cmdIndex(a)
    if (a.command === 'generate') return cmdGenerate(a)
    throw new BadInput(`unknown command ${a.command} (index or generate)`)
  } catch (e) {
    if (e instanceof BadInput) { process.stdout.write(L.dumps({ error: e.message }) + '\n'); return 2 }
    throw e
  }
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
