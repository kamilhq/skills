#!/usr/bin/env node
// Port of ../../cpp/cppsplit.py (same command line and output; also the shared library of account.mjs and
// emit.mjs). Node built-ins only.
import fs from 'node:fs'
import * as L from '../lib/rwlib.mjs'

const PROG = 'cppsplit'
const DOC = "Split C++ translation units (matched decomp units) into top-level items, with their annotations.\n\n  python3 -I cppsplit.py UNIT.cpp... [--module NAME] [--items] [--json OUT]\n\nAn item is one top-level thing of the file: a preprocessor line (\"pp\", continuations included), a\ndeclaration or definition up to its ';' or closing '}' (\"code\"), a namespace or extern \"C\" block (\"ns\",\n\"externc\": their contents are split again, names get the namespace), or trailing comments (\"tail\"). The\ncomment lines directly above an item belong to it, so the reccmp-style annotation block of the decomp skill\n(`// FUNCTION: MODULE 0x401000 [symbol]`, `// STUB:`, `// GLOBAL:`, `// NONMATCHING ...`) travels with\nthe definition it annotates. Code items are classified: funcdef, funcdecl, vardef, externdecl, typedef\n(class/struct/union/enum definition), typedecl (typedef/using), fwdtype, instantiation.\n\nPrints a JSON summary per file: item counts by kind/class, annotations by kind, nonmatching count, and with\n--items one row per item (line, kind, class, name, signature key, annotations). --module keeps only the\nannotations of that module (others are ignored). Also the shared library of account.py and emit.py\n(splitting, classification, signature keys, identifier renames, the cpp config, placement).\nExit 0, or 2 on a usage error or an unreadable file. Python standard library only. Port: ../js/cpp/cppsplit.mjs."

const ANN_RE = /^\/\/\s*(FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY|GLOBAL|VTABLE|STRING)\s*:\s*(?:([A-Za-z_][A-Za-z0-9_]*)\s+)?(0x[0-9a-fA-F]+)(?:\s+(\S+))?/
const NONMATCHING_RE = /^\/\/\s*NONMATCHING\b/
const IDCHAR = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
const IDSTART = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'
const isId = c => c !== undefined && c !== '' && IDCHAR.includes(c)
const isStart = c => c !== undefined && c !== '' && IDSTART.includes(c)

export const STRERROR = { ENOENT: 'No such file or directory', EACCES: 'Permission denied', EISDIR: 'Is a directory', ENOTDIR: 'Not a directory' }
export class OSErr extends Error { constructor (e) { super(STRERROR[e.code] || e.message); this.strerror = this.message } }

export function readText (p) {
  let b
  try { b = fs.readFileSync(p) } catch (e) { throw new OSErr(e) }
  return b.toString('utf8').replaceAll('\r\n', '\n')
}
export function writeText (p, text) {
  const d = L.dirname(p)
  if (d) L.makedirs(d)
  fs.writeFileSync(p, text)
}

// ------------------------------------------------------------------------------------------- lexing
export function skipLit (text, i, n) {
  const c = text[i]
  if (c === '/' && i + 1 < n && text[i + 1] === '/') {
    const j = text.indexOf('\n', i)
    return j < 0 ? n : j
  }
  if (c === '/' && i + 1 < n && text[i + 1] === '*') {
    const j = text.indexOf('*/', i + 2)
    return j < 0 ? n : j + 2
  }
  if (c === '"' || c === "'") {
    let j = i + 1
    while (j < n) {
      if (text[j] === '\\') { j += 2; continue }
      if (text[j] === c) return j + 1
      if (text[j] === '\n') return j
      j += 1
    }
    return n
  }
  return null
}

export function stripComments (t) {
  const out = []
  let i = 0; const n = t.length; let start = 0
  while (i < n) {
    const c = t[i]
    if (c === '/' && i + 1 < n && '/*'.includes(t[i + 1])) {
      out.push(t.slice(start, i))
      const j = skipLit(t, i, n)
      if (t[i + 1] === '*') out.push(' ')
      i = start = j
      continue
    }
    if (c === '"' || c === "'") { i = skipLit(t, i, n); continue }
    i += 1
  }
  out.push(t.slice(start, n))
  return out.join('')
}

export function subIdents (text, mapping, members = false) {
  const has = k => mapping instanceof Map ? mapping.has(k) : Object.prototype.hasOwnProperty.call(mapping, k)
  const val = k => mapping instanceof Map ? mapping.get(k) : mapping[k]
  if (!mapping || (mapping instanceof Map ? !mapping.size : !Object.keys(mapping).length)) return text
  const out = []
  let i = 0; const n = text.length; let start = 0
  while (i < n) {
    const c = text[i]
    if ((c === '/' && i + 1 < n && '/*'.includes(text[i + 1])) || c === '"' || c === "'") { i = skipLit(text, i, n); continue }
    if (isStart(c) && (i === 0 || !isId(text[i - 1]))) {
      let j = i + 1
      while (j < n && isId(text[j])) j++
      const w = text.slice(i, j)
      if (has(w) && (members || i === 0 || !'.>:'.includes(text[i - 1]))) {
        out.push(text.slice(start, i)); out.push(val(w)); start = j
      }
      i = j
      continue
    }
    i += 1
  }
  out.push(text.slice(start, n))
  return out.join('')
}

export function identifiers (text) {
  const s = new Set()
  let i = 0; const n = text.length
  while (i < n) {
    const c = text[i]
    if ((c === '/' && i + 1 < n && '/*'.includes(text[i + 1])) || c === '"' || c === "'") { i = skipLit(text, i, n); continue }
    if (isStart(c) && (i === 0 || !isId(text[i - 1]))) {
      let j = i + 1
      while (j < n && isId(text[j])) j++
      s.add(text.slice(i, j))
      i = j
      continue
    }
    i += 1
  }
  return s
}

// -------------------------------------------------------------------------------------------- split
export class Item {
  constructor (kind, comments, text, start, line, children = null, head = null) {
    Object.assign(this, { kind, comments, text, start, line, children: children || [], head })
  }
}
const NS_RE = /^namespace(\s+[A-Za-z_]\w*)?\s*$/
const EXTERNC_RE = /^extern\s+"C(\+\+)?"\s*$/
const TYPEHEAD_RE = /^\s*(template\s*<[^>]*>\s*)?(typedef\s+)?(class|struct|union|enum)\b/
const EQ_END_RE = /=\s*$/

function lineOf (nl, pos) {
  let lo = 0; let hi = nl.length
  while (lo < hi) {
    const mid = (lo + hi) >> 1
    if (nl[mid] < pos) lo = mid + 1; else hi = mid
  }
  return lo + 1
}
export function split (text) {
  const nl = []
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') nl.push(i)
  return splitRange(text, 0, text.length, nl)
}
function ws (text, i, n) { while (i < n && ' \t\r'.includes(text[i])) i++; return i }
const rfind = (s, ch, end) => s.lastIndexOf(ch, end - 1)
const findIn = (s, sub, from, end) => { const j = s.indexOf(sub, from); return j < 0 || j + sub.length > end ? -1 : j }

function splitRange (text, i, n, nl) {
  const items = []
  let pending = []
  while (i < n) {
    i = ws(text, i, n)
    if (i >= n) break
    let c = text[i]
    if (c === '\n') { i += 1; continue }
    if (c === '/' && i + 1 < n && '/*'.includes(text[i + 1])) {
      const j = Math.min(skipLit(text, i, n), n)
      pending.push(text.slice(i, j))
      i = j
      continue
    }
    if (c === '#') {
      let j = i; let k
      for (;;) {
        k = findIn(text, '\n', j, n)
        if (k < 0) { k = n; break }
        if (text[k - 1] === '\\' || (text[k - 1] === '\r' && text[k - 2] === '\\')) { j = k + 1; continue }
        break
      }
      items.push(new Item('pp', pending, text.slice(i, k), i, lineOf(nl, i)))
      pending = []
      i = k
      continue
    }
    const start = i
    let depth = 0
    let done = false
    while (i < n) {
      const s = skipLit(text, i, n)
      if (s !== null) { i = Math.min(s, n); continue }
      c = text[i]
      if (c === '#' && depth > 0) {
        const ls = rfind(text, '\n', i)
        if (ls >= 0 && text.slice(ls + 1, i).trim() === '') {
          const k = findIn(text, '\n', i, n)
          i = k < 0 ? n : k
          continue
        }
      }
      if ('{(['.includes(c)) {
        if (c === '{' && depth === 0) {
          const hs = text.slice(start, i).trim()
          if (NS_RE.test(hs) || EXTERNC_RE.test(hs)) {
            let d2 = 1; let j = i + 1
            while (j < n && d2) {
              const s2 = skipLit(text, j, n)
              if (s2 !== null) { j = Math.min(s2, n); continue }
              if (text[j] === '{') d2++
              else if (text[j] === '}') d2--
              j++
            }
            const kind = hs.startsWith('namespace') ? 'ns' : 'externc'
            const kids = splitRange(text, i + 1, d2 === 0 ? j - 1 : j, nl)
            items.push(new Item(kind, pending, text.slice(start, j), start, lineOf(nl, start), kids, hs.replace(/\s+/g, ' ')))
            pending = []
            i = j
            const k = ws(text, i, n)
            if (k < n && text[k] === ';') i = k + 1
            done = true
            break
          }
        }
        depth++
      } else if ('})]'.includes(c)) {
        depth--
        if (c === '}' && depth === 0) {
          const j = i + 1
          let k = j
          while (k < n && ' \t\r\n'.includes(text[k])) k++
          const b = findIn(text, '{', start, n)
          const hb = b < 0 ? text.slice(start, text.length - 1) : text.slice(start, b)
          const isType = TYPEHEAD_RE.test(hb) && !stripComments(hb).includes('(')
          const hasEq = EQ_END_RE.test(hb)
          if (isType || hasEq || (k < n && text[k] === ';')) {
            while (k < n && text[k] !== ';') {
              const s3 = skipLit(text, k, n)
              if (s3 !== null) { k = Math.min(s3, n); continue }
              k++
            }
            i = Math.min(k + 1, n)
          } else i = j
          items.push(new Item('code', pending, text.slice(start, i), start, lineOf(nl, start)))
          pending = []
          done = true
          break
        }
      } else if (c === ';' && depth === 0) {
        i++
        items.push(new Item('code', pending, text.slice(start, i), start, lineOf(nl, start)))
        pending = []
        done = true
        break
      }
      i++
    }
    if (!done) {
      items.push(new Item('code', pending, text.slice(start, n), start, lineOf(nl, start)))
      pending = []
      i = n
    }
  }
  if (pending.length) items.push(new Item('tail', pending, '', n, lineOf(nl, n)))
  return items
}

export function * walk (items, ns = []) {
  for (const it of items) {
    if (it.kind === 'ns') {
      const parts = it.head.split(' ')
      yield * walk(it.children, [...ns, parts.length > 1 ? parts[1] : ''])
    } else if (it.kind === 'externc') yield * walk(it.children, ns)
    else yield [ns, it]
  }
}

// ------------------------------------------------------------------------------------- annotations
export function annotations (comments, module = null) {
  const anns = []
  let nonm = false
  for (const c of comments) {
    const m = ANN_RE.exec(c)
    if (m) {
      if (module && m[2] && m[2] !== module) continue
      anns.push([m[1], m[3].toLowerCase(), m[4] === undefined ? null : m[4]])
    } else if (NONMATCHING_RE.test(c)) nonm = true
  }
  return [anns, nonm]
}

// ---------------------------------------------------------------------------------- classification
const INST_RE = /^template\s+[^<\s]/
const TYPEDEF_RE = /^(template\s*<[^{]*?>\s*)?(typedef\s+)?(class|struct|union|enum)\b[^;(]*\{/
const TYPEDECL_RE = /^(typedef|using)\b/
const FWDTYPE_RE = /^(class|struct|union|enum)\b[^{;(]*;$/

export function classify (text) {
  const s = stripComments(text).trim()
  if (INST_RE.test(s)) return 'instantiation'
  const head = s.split('{')[0]
  if (TYPEDEF_RE.test(s) && !head.includes('(')) return 'typedef'
  if (TYPEDECL_RE.test(s)) return 'typedecl'
  if (FWDTYPE_RE.test(s)) return 'fwdtype'
  const hs = head.replaceAll('operator==', 'operatorEQEQ').replaceAll('operator=', 'operatorEQ')
  if (s.endsWith('}') && hs.includes('(') && !hs.split('(')[0].includes('=')) return 'funcdef'
  if (s.startsWith('extern') && !s.startsWith('extern "C" {')) return 'externdecl'
  if (s.endsWith(';') && !hs.split('(')[0].includes('=')) {
    const pr = findParams(hs)
    if (pr) {
      const rest = hs.slice(pr[1] + 1).trim()
      if (!hs.slice(pr[0] + 1).trimStart().startsWith('*') && [';', 'const;', 'const ;'].includes(rest)) return 'funcdecl'
    }
  }
  return 'vardef'
}

export function splitTop (s, sep = ',') {
  const parts = []; let depth = 0; let cur = []
  for (const ch of s) {
    if ('([{<'.includes(ch)) depth++
    else if (')]}>'.includes(ch)) depth--
    if (ch === sep && depth === 0) { parts.push(cur.join('')); cur = [] } else cur.push(ch)
  }
  if (cur.join('').trim()) parts.push(cur.join(''))
  return parts
}

const NAME_BEFORE_PAREN = /([A-Za-z_~][\w:~]*|operator\s*\S+)$/
function closeParen (s, i) {
  let d = 0
  for (let j = i; j < s.length; j++) {
    if (s[j] === '(') d++
    else if (s[j] === ')') { d--; if (d === 0) return j }
  }
  return null
}
export function findParams (s) {
  let depth = 0; let i = 0; const n = s.length
  while (i < n) {
    const ch = s[i]
    if (ch === '<') depth++
    else if (ch === '>') depth--
    else if (ch === '(' && depth <= 0) {
      const m = NAME_BEFORE_PAREN.exec(s.slice(0, i).trimEnd())
      const j = closeParen(s, i)
      if (j === null) return null
      if (m && !['__declspec', 'declspec', '__attribute__'].includes(m[1])) return [i, j]
      i = j
    }
    i++
  }
  return null
}

const DEFAULT_TYPE_ALIASES = {
  'unsigned int': 'unsigned', 'signed int': 'int', uint8_t: 'unsigned char', int8_t: 'signed char',
  uint16_t: 'unsigned short', int16_t: 'short', uint32_t: 'unsigned', int32_t: 'int', size_t: 'unsigned'
}
const PARAM_NAME_RE = /^(.*?[\s*&])([A-Za-z_]\w*)(\s*\[[^\]]*\])*$/
const reEscape = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
export { reEscape }

export function normType (p, cfg) {
  p = p.replace(/=[\s\S]*$/, '').trim()
  p = p.replace(/\s+/g, ' ')
  if (p === 'void' || p === '') return ''
  if (p === '...') return '...'
  const m = PARAM_NAME_RE.exec(p)
  if (m && !['', 'const', 'unsigned', 'signed', 'struct', 'enum', 'class', 'union'].includes(m[1].trim())) {
    p = m[1].trim() + (m[3] !== undefined ? '[]' : '')
  }
  p = p.replace(/\b(enum|struct|class|union)\s+/g, '')
  p = p.replaceAll(' *', '*').replaceAll(' &', '&').replaceAll('* ', '*').replaceAll('& ', '&')
  if (!p.includes('*') && !p.includes('&')) p = p.replace(/\bconst\b\s*/g, '').trim()
  p = p.replace(/\bconst$/, '').trim()
  for (const q of (cfg.strip_qualifiers || [])) p = p.replaceAll(q, '')
  const aliases = { ...DEFAULT_TYPE_ALIASES, ...(cfg.type_aliases || {}) }
  const keys = Object.keys(aliases).sort((a, b) => b.length - a.length || L.cmp(a, b))
  for (const k of keys) p = p.replace(new RegExp('(?<![A-Za-z0-9_])' + reEscape(k) + '(?![A-Za-z0-9_])', 'g'), () => aliases[k])
  return p
}

const FUNC_NAME_RE = /((?:[A-Za-z_]\w*\s*::\s*)*~?[A-Za-z_]\w*|(?:[A-Za-z_]\w*::)*operator\s*\S+?)\s*$/

export function parseFunction (text, ns, cfg) {
  const s = stripComments(text)
  const pr = findParams(s)
  if (!pr) return null
  const [a, b] = pr
  const pre = s.slice(0, a)
  const m = FUNC_NAME_RE.exec(pre)
  const name = m ? m[1].replace(/\s+/g, '') : '?'
  const after = s.slice(b + 1)
  const nss = new Set(cfg.namespaces || [])
  const parts = name.split('::')
  ns = [...ns]
  while (parts.length > 1 && nss.has(parts[0])) ns.push(parts.shift())
  const f = {}
  f.name = parts.join('::')
  f.ns = ns
  f.qual = [...ns, f.name].filter(x => x).join('::')
  const ptypes = splitTop(s.slice(a + 1, b)).map(x => normType(x, cfg))
  f.ptypes = ptypes.length === 1 && ptypes[0] === '' ? [] : ptypes.filter(x => x !== '')
  f.const = /^\s*const\b/.test(after)
  f.key = `${f.qual}(${f.ptypes.join(',')})${f.const ? ' const' : ''}`
  f.is_static = /\bstatic\b/.test(pre)
  f.is_member = f.name.includes('::')
  f.cls = f.is_member ? f.name.slice(0, f.name.lastIndexOf('::')) : null
  return f
}

const TYPE_NAME_RES = [/(\w+)\s*(\[[^\]]*\])?\s*;\s*$/, /\(\s*\*\s*(\w+)\s*\)/]
const TYPEDEF_NAME_RE = /^(?:template\s*<[^{]*?>\s*)?(?:typedef\s+)?(?:class|struct|union|enum)\s+(\w+)/
const TYPEDEF_TAIL_RE = /\}\s*(\w+)\s*;\s*$/

export function typeName (text, cls) {
  const s = stripComments(text).trim()
  if (cls === 'typedecl') {
    let m = /^using\s+(\w+)\s*=/.exec(s)
    if (m) return m[1]
    if (s.includes('(')) {
      m = TYPE_NAME_RES[1].exec(s)
      if (m) return m[1]
    }
    m = TYPE_NAME_RES[0].exec(s)
    return m ? m[1] : null
  }
  let m = TYPEDEF_NAME_RE.exec(s)
  if (m) return m[1]
  m = TYPEDEF_TAIL_RE.exec(s)
  return m ? m[1] : null
}

const VAR_RE = /^([\s\S]*?)\b([A-Za-z_]\w*)\s*((?:\[[^\]]*\])*)\s*(=[\s\S]*|\([\s\S]*\))?;$/
export function varName (text) {
  const s = stripComments(text).trim()
  const m = VAR_RE.exec(s)
  if (!m) return [null, false]
  return [m[2], /^\s*static\b/.test(s)]
}

// --------------------------------------------------------------------------------- config, units
export function loadConfig (p) {
  let t
  try { t = fs.readFileSync(p, 'utf8') } catch (e) { throw new OSErr(e) }
  const cfg = L.pyParse(t)
  if (cfg === null || typeof cfg !== 'object' || Array.isArray(cfg)) throw new SyntaxError('config is not a JSON object')
  return cfg
}
export function unitId (cfg, filename) {
  const stem = L.splitext(L.basename(filename))[0]
  const rx = cfg.unit_id
  if (rx) {
    const m = new RegExp('^(?:' + rx + ')').exec(stem)
    if (m) return m.length > 1 ? m[1] : m[0]
  }
  return stem
}
export function unitFiles (dir, cfg) {
  const exts = cfg.unit_exts || ['.cpp', '.c']
  return L.listdirSorted(dir).filter(f => exts.some(e => f.endsWith(e)) && L.isfile(L.join(dir, f))).map(f => L.join(dir, f))
}
export function fullRe (list) {
  if (!list || !list.length) return null
  return new RegExp('^(?:' + list.map(r => `(?:${r})`).join('|') + ')$')
}
export function unitDests (cfg) {
  const out = new Map()
  for (const [dest, units] of Object.entries(cfg.unit_dest || {})) for (const u of units) out.set(u, dest)
  return out
}
export class Placer {
  constructor (cfg) {
    this.addr = new Map(Object.entries(cfg.addr_dest || {}).map(([k, v]) => [k.toLowerCase(), v]))
    this.name = cfg.name_dest || {}
    this.cls = cfg.class_dest || {}
    this.unit = unitDests(cfg)
    this.default = cfg.default_dest === undefined ? null : cfg.default_dest
  }

  dest (unit, fn = null, addr = null) {
    const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k)
    if (addr && this.addr.has(addr)) return this.addr.get(addr)
    if (fn !== null && !fn.is_member && own(this.name, fn.name)) return this.name[fn.name]
    if (fn !== null && fn.is_member) {
      const c = fn.cls.split('::').pop()
      if (own(this.cls, c)) return this.cls[c]
    }
    return this.unit.has(unit) ? this.unit.get(unit) : this.default
  }
}

export function loadUnit (p, cfg, module = null, preRenames = null) {
  let text = readText(p)
  if (preRenames && Object.keys(preRenames).length) text = subIdents(text, preRenames, true)
  const rows = []
  for (const [ns, it] of walk(split(text))) {
    const [anns, nonm] = annotations(it.comments, module)
    const cls = it.kind === 'code' ? classify(it.text) : null
    const fn = ['funcdef', 'funcdecl'].includes(cls) ? parseFunction(it.text, [...ns], cfg) : null
    rows.push([[...ns], it, anns, nonm, cls, fn])
  }
  return [text, rows]
}

// ---------------------------------------------------------------------------------------------- CLI
function itemRow (ns, it, anns, nonm, cls, fn) {
  const r = new Map([['line', it.line], ['kind', it.kind], ['class', cls]])
  if (fn !== null) { r.set('name', fn.qual); r.set('key', fn.key) } else if (cls === 'typedef' || cls === 'typedecl') r.set('name', typeName(it.text, cls))
  else if (cls === 'vardef') r.set('name', varName(it.text)[0])
  else if (it.kind === 'pp') r.set('name', it.text.split('\n')[0].slice(0, 60))
  if (ns.length) r.set('ns', ns.join('::'))
  if (anns.length) r.set('annotations', anns.map(a => a.filter(x => x).join(' ')))
  if (nonm) r.set('nonmatching', true)
  return r
}

const sortedObj = o => new Map([...Object.entries(o)].sort((a, b) => L.cmp(a[0], b[0])))

export function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [['--module', 'str', null], ['--items', 'flag', false], ['--json', 'str', null]], [['files', '+']])
  const out = []
  for (const p of a.files) {
    let rows
    try {
      rows = loadUnit(p, {}, a.module)[1]
    } catch (e) {
      if (!(e instanceof OSErr)) throw e
      process.stderr.write(`${PROG}: error: ${p}: ${e.strerror}\n`)
      return 2
    }
    const kinds = {}; const anns = {}
    let nonm = 0
    for (const [, it, an, nm, cls] of rows) {
      const k = cls || it.kind
      kinds[k] = (kinds[k] || 0) + 1
      for (const x of an) anns[x[0]] = (anns[x[0]] || 0) + 1
      nonm += nm ? 1 : 0
    }
    const rec = new Map([['file', p], ['items', rows.length], ['kinds', sortedObj(kinds)], ['annotations', sortedObj(anns)], ['nonmatching', nonm]])
    if (a.items) rec.set('list', rows.map(r => itemRow(...r)))
    out.push(rec)
  }
  const js = L.dumps(out)
  if (a.json) writeText(a.json, js + '\n')
  process.stdout.write(js + '\n')
  return 0
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
