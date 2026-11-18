#!/usr/bin/env node
// Port of ../../cpp/emit.py (same command line, output and files). Node built-ins only.
import * as L from '../lib/rwlib.mjs'
import * as C from './cppsplit.mjs'

const PROG = 'emit'
const DOC = "Generate a first C++ source tree from matched decomp units (one-shot: then fix the tree by hand).\n\n  python3 -I emit.py --config CFG.json --out DIR [--units DIR] [--report REPORT.json] [--project DIR]\n\nEvery unit (*.cpp/*.c of the units folder, sorted) is split into top-level items (cppsplit.py). Library\nunits (\"library_units\": CRT, STL instances, library copies) contribute nothing. In the other units:\n  * every annotated function (// FUNCTION) goes to one destination file: \"addr_dest\" {address: file} >\n    \"name_dest\" {free function: file} > \"class_dest\" {class: file} > \"unit_dest\" {file: [unit ids]} >\n    \"default_dest\"; it is written with a `// 0x<address>` comment (`(NONMATCHING in the decomp)` added\n    when the unit tagged it), in address order;\n  * dropped: forward and extern declarations, forward type declarations, explicit instantiations, #include\n    and #pragma lines, // STUB items, lines matching \"drop.lines\" (e.g. // CLFLAGS), unannotated\n    definitions with the signature of an annotated function (stand-ins), helpers matching \"drop.functions\"\n    (regexes on the name) or \"drop.keys\" (signature keys), types defined in the shared \"headers\" or matching\n    \"drop.types\", macros matching \"drop.macros\"; \"drop.declspecs\" (e.g. noinline) and \"drop.keywords\"\n    {keyword: replacement} (e.g. __fastcall: \"\", __forceinline: \"inline\") are removed from the code;\n  * kept once per destination: unannotated helpers, file statics, macros, unit-local types (\"type_home\"\n    {type: header} moves a type into a header); globals once in the whole tree;\n  * renames: \"renames.members\" {old: new} on the whole text first (two names of one exe function),\n    \"renames.global\" and \"renames.units\" {unit: {old: new}} on identifiers (not after '.', '->', '::');\n  * constants: each unit's own object-like macros and enum constants are evaluated; where a unit's value\n    differs from the canonical value of the same name (\"constants.canonical\" {name: C expression}, plus\n    the enums and macros of \"constants.headers\" and the shared headers), the unit's uses are renamed to the\n    canonical name with that value in the same family (the prefix before the first '_', \"constants.families\"\n    maps prefixes), else to the number; \"constants.ignore\" (regexes) skips names. `#define A B` aliases\n    are resolved the same way.\nOutput: one .cpp per destination and a .h next to it (declarations of public free functions with their\ndefault arguments, extern declarations of public globals, moved types); the shared \"headers\" {unit header:\nout header} are copied with their stand-ins and #include \"...\" lines removed and get the declarations of the\n.cpp of the same name. Each file includes its own header, \"includes\" (lines for every .cpp), the system\nheaders of \"system_includes\" {header: regex} whose regex matches, and every generated header whose names it\nuses. A file static used by another file is made public. --report writes a JSON report (stats, stand-ins,\nscaffolding, renames, unplaced items, per-file manifest); a JSON summary is printed. Paths in the config are\nrelative to --project (default: the current folder). Exit 0, 1 when an annotated function has no destination,\n2 on bad input. Python standard library only. Port: ../js/cpp/emit.mjs."

// ------------------------------------------------------------------------------------ C constants
class EvalError extends Error {}
const TOK_RE = /\s*(?:(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*|('(?:\\x[0-9a-fA-F]+|\\.|[^'\\])')|([A-Za-z_][A-Za-z0-9_]*)|(<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%~!&|^<>?:(),]))/y
const ESC = { n: 10, r: 13, t: 9, 0: 0, '\\': 92, "'": 39, '"': 34, b: 8, a: 7, f: 12, v: 11 }
const BINARY = [['||'], ['&&'], ['|'], ['^'], ['&'], ['==', '!='], ['<', '<=', '>', '>='], ['<<', '>>'], ['+', '-'], ['*', '/', '%']]

function tokens (expr) {
  const toks = []
  let i = 0; const n = expr.length
  while (i < n) {
    if (expr.slice(i).trim() === '') break
    TOK_RE.lastIndex = i
    const m = TOK_RE.exec(expr)
    if (!m) throw new EvalError(expr)
    if (m[1]) {
      const s = m[1]
      let v
      if (s.slice(0, 2) === '0x' || s.slice(0, 2) === '0X') v = BigInt('0x' + s.slice(2))
      else if (s.length > 1 && s[0] === '0') {
        if (![...s].every(c => '01234567'.includes(c))) throw new EvalError(s)
        v = BigInt('0o' + s)
      } else v = BigInt(s)
      toks.push(['n', v])
    } else if (m[2]) {
      const s = m[2].slice(1, -1)
      let v
      if (s.startsWith('\\x')) v = BigInt('0x' + s.slice(2))
      else if (s.startsWith('\\')) v = BigInt(Object.prototype.hasOwnProperty.call(ESC, s[1]) ? ESC[s[1]] : s.codePointAt(1))
      else v = BigInt(s.codePointAt(0))
      toks.push(['n', v])
    } else if (m[3]) toks.push(['i', m[3]])
    else toks.push(['o', m[4]])
    i = TOK_RE.lastIndex
  }
  return toks
}
const envGet = (env, k) => (env.has(k) ? env.get(k) : null)
const isOp = (t, op) => t[0] === 'o' && t[1] === op
function stripCasts (toks, env) {
  const out = []
  let i = 0
  while (i < toks.length) {
    const t = toks[i]
    if (isOp(t, '(')) {
      let j = i + 1
      while (j < toks.length && toks[j][0] === 'i' && !env.has(toks[j][1])) j++
      if (j > i + 1 && j < toks.length && isOp(toks[j], ')') && j + 1 < toks.length) {
        const nx = toks[j + 1]
        if (nx[0] === 'n' || nx[0] === 'i' || ['(', '-', '+', '~', '!'].includes(nx[1])) { i = j + 1; continue }
      }
    }
    out.push(t)
    i++
  }
  return out
}
function cdiv (a, b) { if (b === 0n) throw new EvalError('division by zero'); return a / b }
const B = x => (x ? 1n : 0n)
function apply (op, a, b) {
  switch (op) {
    case '||': return B(a || b)
    case '&&': return B(a && b)
    case '|': return a | b
    case '^': return a ^ b
    case '&': return a & b
    case '==': return B(a === b)
    case '!=': return B(a !== b)
    case '<': return B(a < b)
    case '<=': return B(a <= b)
    case '>': return B(a > b)
    case '>=': return B(a >= b)
    case '<<': case '>>':
      if (b < 0n || b > 256n) throw new EvalError('shift')
      return op === '<<' ? a << b : a >> b
    case '+': return a + b
    case '-': return a - b
    case '*': return a * b
    case '/': return cdiv(a, b)
  }
  return a - b * cdiv(a, b)
}
class Parser {
  constructor (toks, env) { this.t = toks; this.i = 0; this.env = env }
  peek () { return this.i < this.t.length ? this.t[this.i] : ['e', null] }
  take (op) { if (!isOp(this.peek(), op)) throw new EvalError(op); this.i++ }
  cond () {
    const c = this.binary(0)
    if (isOp(this.peek(), '?')) {
      this.i++
      const a = this.cond()
      this.take(':')
      const b = this.cond()
      return c ? a : b
    }
    return c
  }

  binary (level) {
    if (level === BINARY.length) return this.unary()
    let v = this.binary(level + 1)
    while (this.peek()[0] === 'o' && BINARY[level].includes(this.peek()[1])) {
      const op = this.peek()[1]
      this.i++
      v = apply(op, v, this.binary(level + 1))
    }
    return v
  }

  unary () {
    const [k, v] = this.peek()
    if (k === 'o' && ['-', '+', '~', '!'].includes(v)) {
      this.i++
      const x = this.unary()
      return v === '-' ? -x : v === '+' ? x : v === '~' ? ~x : (x ? 0n : 1n)
    }
    if (k === 'o' && v === '(') {
      this.i++
      const x = this.cond()
      this.take(')')
      return x
    }
    if (k === 'n') { this.i++; return v }
    if (k === 'i' && envGet(this.env, v) !== null) { this.i++; return this.env.get(v) }
    throw new EvalError(String(v))
  }
}
export function cEval (expr, env) {
  try {
    const toks = stripCasts(tokens(C.stripComments(expr)), env)
    if (!toks.length) return null
    const p = new Parser(toks, env)
    const v = p.cond()
    if (p.i !== toks.length) return null
    return v
  } catch (e) {
    if (e instanceof EvalError) return null
    throw e
  }
}
const ENUM_RE = /\benum\s*(?:class\s+|struct\s+)?(\w*)\s*(?::\s*[\w\s]+?)?\s*\{([\s\S]*)\}/
export function parseEnum (text) {
  const m = ENUM_RE.exec(C.stripComments(text))
  if (!m) return [null, []]
  const out = []
  for (let part of C.splitTop(m[2])) {
    part = part.trim()
    const mm = /^([A-Za-z_]\w*)\s*(?:=\s*([\s\S]*))?$/.exec(part)
    if (mm) out.push([mm[1], mm[2] === undefined ? null : mm[2]])
  }
  return [m[1] || null, out]
}
export function evalEnum (consts, env) {
  const res = []
  let nxt = 0n
  for (const [n, ex] of consts) {
    const v = ex !== null ? cEval(ex, env) : nxt
    env.set(n, v)
    res.push([n, v])
    nxt = v !== null ? v + 1n : null
  }
  return res
}
const DEFINE_RE = /^#\s*define\s+([A-Za-z_]\w*)(\()?/
export function defineParts (text) {
  const m = DEFINE_RE.exec(text)
  if (!m) return null
  return [m[1], m[2] !== undefined, text.slice(m[0].length).replaceAll('\\\n', ' ').trim()]
}
const pyStrV = v => (v === null || v === undefined ? 'None' : String(v))

// ------------------------------------------------------------------------------- header symbols
const ENUM_HEAD = /^\s*(typedef\s+)?enum\b/
export function headerSymbols (text, cfg) {
  const s = { types: new Set(), consts: new Set(), macros: new Set(), flags: new Set(), funcs: new Set(), vars: new Set() }
  for (const [ns, it] of C.walk(C.split(text))) {
    if (it.kind === 'pp') {
      const d = defineParts(it.text)
      if (d) s[d[1] || d[2] ? 'macros' : 'flags'].add(d[0])
      continue
    }
    if (it.kind !== 'code') continue
    const cls = C.classify(it.text)
    if (cls === 'typedef' || cls === 'typedecl') {
      const nm = C.typeName(it.text, cls)
      if (nm) s.types.add(nm)
      if (ENUM_HEAD.test(C.stripComments(it.text))) for (const [n] of parseEnum(it.text)[1]) s.consts.add(n)
    } else if (cls === 'funcdecl' || cls === 'funcdef' || (cls === 'externdecl' && C.findParams(C.stripComments(it.text)))) {
      const fn = C.parseFunction(it.text, [...ns], cfg)
      if (fn) s.funcs.add(fn.name.split('::').pop())
    } else if (cls === 'externdecl' || cls === 'vardef') {
      const nm = C.varName(it.text)[0]
      if (nm) s.vars.add(nm)
    }
  }
  return s
}

// ----------------------------------------------------------------------------------- code edits
function cleanCode (text, cfg) {
  const d = cfg.drop || {}
  const specs = d.declspecs || []
  if (specs.length) text = text.replace(new RegExp('__declspec\\(\\s*(?:' + specs.map(C.reEscape).join('|') + ')\\s*\\)\\s*', 'g'), '')
  for (const [kw, rep] of Object.entries(d.keywords || {})) {
    text = text.replace(new RegExp('\\b' + C.reEscape(kw) + (rep === '' ? '\\b\\s*' : '\\b'), 'g'), () => rep)
  }
  return text
}
function rawBodyStart (text) {
  let i = 0; const n = text.length; let depth = 0; let seen = false
  while (i < n) {
    const c = text[i]
    if ((c === '/' && i + 1 < n && '/*'.includes(text[i + 1])) || c === '"' || c === "'") { i = C.skipLit(text, i, n); continue }
    if (c === '(') { depth++; seen = true } else if (c === ')') depth--
    else if (c === '{' && depth === 0 && seen) return i
    i++
  }
  return null
}
function defParts (text) {
  const j = rawBodyStart(text)
  if (j === null) return [C.stripComments(text).trim(), '', []]
  const head = C.stripComments(text.slice(0, j)).trim()
  const pr = C.findParams(head)
  if (!pr) return [head, text.slice(j), []]
  const ps = C.splitTop(head.slice(pr[0] + 1, pr[1]))
  return [head, text.slice(j), ps.map(p => (p.includes('=') ? p.slice(p.indexOf('=') + 1).trim() : null))]
}
function withParams (head, fnDefaults = null, strip = false) {
  const pr = C.findParams(head)
  if (!pr) return head
  const [a, b] = pr
  const ps = C.splitTop(head.slice(a + 1, b))
  const out = []
  ps.forEach((p, i) => {
    let base = p.includes('=') ? p.replace(/\s*=[\s\S]*$/, '') : p
    if (!strip && fnDefaults && i < fnDefaults.length && fnDefaults[i] !== null) base = base.trimEnd() + ' = ' + fnDefaults[i]
    out.push(base)
  })
  return head.slice(0, a + 1) + out.join(',') + head.slice(b)
}
function unqualify (sig, fn) {
  for (const n of fn.ns) if (n) sig = sig.replace(new RegExp('\\b' + C.reEscape(n) + '::(?=~?\\w+\\s*\\()'), '')
  return sig
}
const anyDef = dv => dv.some(x => x !== null)
function declOf (e, defaults, header = true) {
  let [head, , dv] = defParts(e.text)
  if (!anyDef(dv)) dv = defaults.has(e.fn.key) ? defaults.get(e.fn.key) : null
  let sig = unqualify(withParams(head, dv), e.fn)
  if (header) sig = sig.replace(/^\s*(?:(?:inline|__inline|static)\s+)+/, '')
  return sig.trim() + ';'
}
function stripStatic (text) {
  const end = text.indexOf('{')
  const head = end >= 0 ? text.slice(0, end) : text
  const m = /\bstatic\s+/.exec(head)
  if (!m) return text
  return text.slice(0, m.index) + text.slice(m.index + m[0].length)
}
function stripDefDefaults (text) {
  const [head, body, dv] = defParts(text)
  if (!anyDef(dv)) return text
  return withParams(head, null, true) + '\n' + body
}
function groupNs (items) {
  const out = []
  let cur = []
  const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])
  for (let [ns, text] of items) {
    ns = ns.filter(x => x !== null && x !== undefined)
    if (!same(ns, cur)) {
      if (cur.length) { out.push(cur.map(() => '}').join(' ')); out.push('') }
      if (ns.length) { out.push(ns.map(n => `namespace ${n} {`).join(' ')); out.push('') }
      cur = ns
    }
    out.push(...text.trimEnd().split('\n'))
    out.push('')
  }
  if (cur.length) { out.push(cur.map(() => '}').join(' ')); out.push('') }
  return out
}
const relinc = (frm, to) => L.relpath(to, L.dirname(frm) || '.')
const ws0 = s => s.replace(/\s+/g, '')
const getMap = (m, k, mk) => { if (!m.has(k)) m.set(k, mk()); return m.get(k) }
const own = (o, k) => o && Object.prototype.hasOwnProperty.call(o, k)
const hexInt = x => parseInt(x, 16)
const sortStr = a => [...a].sort(L.cmp)

// ------------------------------------------------------------------------------------------ main
function run (cfg, unitsDir, outRoot) {
  const stats = new Map(); const rep = new Map()
  const count = (k, n = 1) => stats.set(k, (stats.get(k) || 0) + n)
  const note = (k, s) => getMap(rep, k, () => []).push(s)
  const module = cfg.module || null
  const drop = cfg.drop || {}
  const lineRx = drop.lines && drop.lines.length ? new RegExp(drop.lines.map(r => `(?:${r})`).join('|')) : null
  const fnRx = C.fullRe(drop.functions || [])
  const typeRx = C.fullRe(drop.types || [])
  const macroRx = C.fullRe(drop.macros || [])
  const incRx = C.fullRe(drop.includes || [])
  const dropKeys = new Set(drop.keys || [])
  const renCfg = cfg.renames || {}
  const consts = cfg.constants || {}
  const ignRx = C.fullRe(consts.ignore || [])
  const families = consts.families || {}
  const libs = new Set(cfg.library_units || [])
  const placer = new C.Placer(cfg)
  const dropLines = text => (lineRx ? text.split('\n').filter(l => !lineRx.test(l)).join('\n') : text)

  const units = []
  for (const p of C.unitFiles(unitsDir, cfg)) {
    let text = dropLines(C.readText(p))
    text = C.subIdents(text, renCfg.members || {}, true)
    const rows = []
    for (const [ns, it] of C.walk(C.split(text))) {
      const [anns, nonm] = C.annotations(it.comments, module)
      const cls = it.kind === 'code' ? C.classify(it.text) : null
      const fn = cls === 'funcdef' || cls === 'funcdecl' ? C.parseFunction(it.text, [...ns], cfg) : null
      rows.push({ ns: [...ns], it, anns, nonm, cls, fn })
    }
    units.push([C.unitId(cfg, p), rows])
  }

  const shared = new Map()
  for (const [src, dst] of Object.entries(cfg.headers || {})) shared.set(dst, dropLines(C.readText(L.join(unitsDir, src))))
  const known = { types: new Set(), consts: new Set(), macros: new Set() }
  for (const text of shared.values()) {
    const hs = headerSymbols(text, cfg)
    for (const k of Object.keys(known)) for (const x of hs[k]) known[k].add(x)
    for (const x of hs.flags) known.macros.add(x)
  }

  const canon = new Map()
  for (const [n, ex] of Object.entries(consts.canonical || {})) canon.set(n, cEval(L.pyStr(ex), canon))
  const ctexts = (consts.headers || []).map(h => C.readText(h)).concat(sortStr(shared.keys()).map(d => shared.get(d)))
  for (const t of ctexts) {
    const env = new Map(canon)
    for (const [, it] of C.walk(C.split(t))) {
      if (it.kind === 'pp') {
        const d = defineParts(it.text)
        if (d && !d[1]) {
          const v = cEval(d[2], env)
          if (v !== null && !canon.has(d[0])) { canon.set(d[0], v); env.set(d[0], v) }
        }
      } else if (it.kind === 'code' && C.classify(it.text) === 'typedef' && ENUM_HEAD.test(C.stripComments(it.text))) {
        for (const [n, v] of evalEnum(parseEnum(it.text)[1], env)) if (v !== null && !canon.has(n)) canon.set(n, v)
      }
    }
  }
  const family = n => { const p = n.split('_')[0]; return own(families, p) ? families[p] : p }

  const unitRen = new Map(); const unitLocal = new Map()
  for (const [u, rows] of units) {
    if (libs.has(u)) continue
    const env = new Map(canon)
    const local = new Map(); const alias = new Map(); const undefs = new Set()
    for (const r of rows) {
      if (r.it.kind === 'pp') {
        const m = /^#\s*undef\s+(\w+)/.exec(r.it.text)
        if (m) undefs.add(m[1])
        const d = defineParts(r.it.text)
        if (d && !d[1] && d[2]) {
          const body = C.stripComments(d[2]).trim()
          if (/^[A-Za-z_]\w*$/.test(body)) { alias.set(d[0], body); continue }
          const v = cEval(body, env)
          if (v !== null) { local.set(d[0], v); env.set(d[0], v) }
        }
      } else if (r.cls === 'typedef' && ENUM_HEAD.test(C.stripComments(r.it.text))) {
        for (const [n, v] of evalEnum(parseEnum(r.it.text)[1], env)) if (v !== null) local.set(n, v)
      }
    }
    const ren = new Map(); const keep = new Set()
    for (const [n, v] of local) {
      if (ignRx && ignRx.test(n)) continue
      if (canon.has(n) && canon.get(n) === v) continue
      const fam = family(n)
      const cands = [...canon.keys()].filter(c => canon.get(c) === v && family(c) === fam)
      if (!canon.has(n) && !cands.length) { keep.add(n); continue }
      if (cands.length) { if (cands[0] !== n) ren.set(n, cands[0]) } else {
        ren.set(n, String(v))
        note('const_literal', `${u} ${n}=${v} (canonical ${pyStrV(canon.get(n))})`)
      }
    }
    for (const [k, b] of alias) if (!undefs.has(k)) ren.set(k, b)
    const uo = own(renCfg.units, u) ? renCfg.units[u] : {}
    for (const [k, v] of Object.entries(uo)) ren.set(k, v)
    unitRen.set(u, ren)
    unitLocal.set(u, keep)
    if (ren.size) note('renames', `${u} ` + [...ren].sort((a, b) => L.cmp(a[0], b[0]) || L.cmp(a[1], b[1])).map(([a, b]) => `${a}->${b}`).join(' '))
  }

  const defaults = new Map()
  for (const [, rows] of units) {
    for (const r of rows) {
      if (r.cls === 'funcdecl' && r.fn !== null) {
        const code = C.stripComments(r.it.text)
        const pr = C.findParams(code)
        const dv = C.splitTop(code.slice(pr[0] + 1, pr[1])).map(p => (p.includes('=') ? p.slice(p.indexOf('=') + 1).trim() : null))
        if (anyDef(dv) && !defaults.has(r.fn.key)) defaults.set(r.fn.key, dv)
      }
    }
  }

  const annotated = new Set()
  for (const [u, rows] of units) {
    if (libs.has(u)) continue
    for (const r of rows) if (r.fn !== null && r.cls === 'funcdef' && r.anns.some(a => a[0] === 'FUNCTION')) annotated.add(r.fn.key)
  }

  const dests = new Map()
  const dest = d => getMap(dests, d, () => ({ funcs: [], helpers: [], vars: [], types: [], macros: [], units: [] }))
  const seenHelper = new Map(); const seenVar = new Map(); const seenType = new Map(); const seenMacro = new Map(); const globalsDef = new Map()
  const homeTypes = new Map()

  for (const [u, rows] of units) {
    if (libs.has(u)) { count('library_unit_items', rows.length); continue }
    const ren = new Map(Object.entries(renCfg.global || {}))
    for (const [k, v] of unitRen.get(u) || []) ren.set(k, v)
    const udest = placer.unit.has(u) ? placer.unit.get(u) : placer.default
    const ulocal = unitLocal.get(u) || new Set()
    for (const r of rows) {
      const { it, cls, anns } = r
      if (it.kind === 'tail') continue
      if (it.kind === 'pp') {
        const t = it.text
        if (/^#\s*include\b/.test(t)) { count('include_dropped'); continue }
        if (/^#\s*pragma\b/.test(t)) { count('pragma_dropped'); continue }
        const d = defineParts(t)
        if (udest === null) { count('unplaced_pp'); continue }
        if (d) {
          const nm = d[0]
          if ((macroRx && macroRx.test(nm)) || ren.has(nm) || known.macros.has(nm)) { count('macro_dropped'); continue }
          if (canon.has(nm) && !ulocal.has(nm)) { count('macro_canonical'); continue }
          const body = C.subIdents(t, ren)
          const sm = getMap(seenMacro, udest, () => new Map())
          const prev = sm.get(nm)
          if (prev !== undefined) {
            if (ws0(C.stripComments(prev.text)) !== ws0(C.stripComments(body))) note('macro_conflict', `${udest} ${nm} (${prev.unit}, ${u})`)
            count('macro_dup')
            continue
          }
          const e = { name: nm, text: body, unit: u }
          sm.set(nm, e)
          dest(udest).macros.push(e)
          count('macros')
        } else {
          dest(udest).macros.push({ name: null, text: t, unit: u })
          count('pp_kept')
        }
        continue
      }
      if (['funcdecl', 'externdecl', 'fwdtype', 'instantiation'].includes(cls)) { count('dropped_' + cls); continue }
      if (anns.length && anns[0][0] === 'STUB') { count('stub_dropped'); continue }
      if (cls === 'funcdef') {
        const fn = r.fn
        const body = cleanCode(C.subIdents(it.text, ren), cfg)
        const fanns = anns.filter(a => a[0] === 'FUNCTION')
        if (fanns.length) {
          const addr = fanns[0][1]
          const d = placer.dest(u, fn, addr)
          if (d === null || d === undefined) { note('unplaced', `${u} ${addr} ${fn.qual}`); count('unplaced_functions'); continue }
          const b = dest(d)
          b.funcs.push({ addr, fn, text: body, unit: u, ns: r.ns, nonm: r.nonm })
          if (!b.units.includes(u)) b.units.push(u)
          count('functions')
          if (r.nonm) count('nonmatching_kept')
          continue
        }
        if (annotated.has(fn.key)) { count('standin_dropped'); note('standins', `${u} ${fn.key}`); continue }
        if ((fnRx && fnRx.test(fn.name.split('::').pop())) || dropKeys.has(fn.key)) { count('scaffold_dropped'); note('scaffold', `${u} ${fn.key}`); continue }
        const d = placer.dest(u, fn)
        if (d === null || d === undefined) { note('unplaced', `${u} helper ${fn.key}`); count('unplaced_helpers'); continue }
        const sh = getMap(seenHelper, d, () => new Map())
        if (sh.has(fn.key)) { count('helper_dup'); continue }
        const e = { fn, text: body, unit: u, ns: r.ns }
        sh.set(fn.key, e)
        dest(d).helpers.push(e)
        count('helpers')
        continue
      }
      if (cls === 'vardef') {
        const body = cleanCode(C.subIdents(it.text, ren), cfg)
        const [nm, isStatic] = C.varName(body)
        if (nm === null) { note('var_unparsed', `${u} ${C.stripComments(body).trim().slice(0, 80)}`); continue }
        const d = anns.length ? placer.dest(u, null, anns[0][1]) : udest
        if (d === null || d === undefined) { note('unplaced', `${u} variable ${nm}`); count('unplaced_vars'); continue }
        const qual = [...r.ns, nm].filter(x => x).join('::')
        if (!isStatic) {
          if (globalsDef.has(qual)) { count('global_dup'); continue }
          globalsDef.set(qual, d)
        } else if (getMap(seenVar, d, () => new Map()).has(qual)) { count('static_dup'); continue }
        getMap(seenVar, d, () => new Map()).set(qual, true)
        dest(d).vars.push({ name: nm, text: body, static: isStatic, ns: r.ns, unit: u, addr: anns.length ? anns[0][1] : null })
        count('vars')
        continue
      }
      if (cls === 'typedef' || cls === 'typedecl') {
        const nm = C.typeName(it.text, cls)
        if (nm && ((typeRx && typeRx.test(nm)) || known.types.has(nm))) { count('type_dropped'); continue }
        const s = C.stripComments(it.text)
        if (cls === 'typedef' && ENUM_HEAD.test(s)) {
          const names = parseEnum(s)[1].map(([n]) => (ren.has(n) ? ren.get(n) : n))
          if (names.length && names.every(n => /^-?[0-9]+$/.test(n) || ((canon.has(n) || known.consts.has(n)) && !ulocal.has(n)))) {
            count('enum_canonical')
            continue
          }
        }
        const body = cleanCode(C.subIdents(it.text, ren), cfg)
        const key = [...r.ns.filter(x => x), nm || ('<anonymous>' + s.trim().replace(/\s+/g, ' ').slice(0, 60))].join('::')
        const th = cfg.type_home || {}
        const home = own(th, nm || '') ? th[nm || ''] : null
        if (home) {
          const ht = getMap(homeTypes, home, () => new Map())
          const prev = ht.get(key)
          if (prev === undefined) { ht.set(key, { name: nm, text: body, ns: r.ns, unit: u }); count('types_moved') } else if (C.stripComments(body).length > C.stripComments(prev.text).length) prev.text = body
          continue
        }
        if (udest === null) { note('unplaced', `${u} type ${nm}`); continue }
        const st = getMap(seenType, udest, () => new Map())
        const prev = st.get(key)
        if (prev !== undefined) {
          if (ws0(C.stripComments(prev.text)) !== ws0(C.stripComments(body))) {
            note('type_variant', `${udest} ${key} (${prev.unit}, ${u})`)
            if (C.stripComments(body).length > C.stripComments(prev.text).length) prev.text = body
          }
          count('type_dup')
          continue
        }
        const e = { name: nm, text: body, ns: r.ns, unit: u }
        st.set(key, e)
        dest(udest).types.push(e)
        count('types')
        continue
      }
      note('unhandled', `${u} ${cls} ${C.stripComments(it.text).trim().slice(0, 60)}`)
    }
  }

  const defFiles = new Map()
  for (const [d, b] of dests) for (const e of [...b.funcs, ...b.helpers]) if (!e.fn.is_member) getMap(defFiles, e.fn.qual, () => new Set()).add(d)
  const idents = new Map([...dests].map(([d, b]) => [d, C.identifiers([...b.funcs, ...b.helpers, ...b.vars].map(e => e.text).join('\n'))]))
  const dnames = sortStr(dests.keys())
  for (const d of dnames) {
    const b = dests.get(d)
    for (const e of [...b.funcs, ...b.helpers]) {
      e.public = false
      if (e.fn.is_member) continue
      const nm = e.fn.name
      if (!e.fn.is_static) { e.public = true; continue }
      const users = dnames.filter(o => o !== d && idents.get(o).has(nm))
      const others = sortStr(defFiles.get(e.fn.qual) || []).filter(o => o !== d)
      if (users.length && !others.length && b.funcs.includes(e)) {
        e.text = stripStatic(e.text)
        e.public = true
        note('made_public', `${d} ${nm} (used in ${users.join(', ')})`)
      }
    }
    for (const e of b.vars) e.public = !e.static
  }
  return emitFiles(cfg, dests, shared, homeTypes, defaults, outRoot, stats, rep, incRx, units)
}

function emitFiles (cfg, dests, shared, homeTypes, defaults, outRoot, stats, rep, incRx, units) {
  const guardPrefix = cfg.guard_prefix || ''
  const banner = cfg.banner === undefined ? 'From the matched units {units}.' : cfg.banner
  const hset = new Set([...shared.keys(), ...homeTypes.keys(), ...[...dests.keys()].map(d => L.splitext(d)[0] + '.h')])
  const hdrPaths = sortStr(hset)
  const gen = new Map(hdrPaths.map(h => [h, []]))
  const decls = new Map(hdrPaths.map(h => [h, []]))
  for (const [h, types] of homeTypes) for (const e of types.values()) gen.get(h).push(...groupNs([[e.ns, e.text.trim()]]))
  const have = new Map()
  for (const [h, text] of shared) {
    const keys = new Set()
    for (const [ns, it] of C.walk(C.split(text))) {
      if (it.kind !== 'code') continue
      const cls = C.classify(it.text)
      if (['funcdecl', 'externdecl', 'vardef'].includes(cls)) {
        const fn = C.findParams(C.stripComments(it.text)) ? C.parseFunction(it.text, [...ns], cfg) : null
        if (fn !== null) keys.add(fn.key)
        else if (cls !== 'funcdecl') {
          const nm = C.varName(it.text)[0]
          if (nm) keys.add([...ns, nm].filter(x => x).join('::'))
        }
      }
    }
    have.set(h, keys)
  }
  for (const d of sortStr(dests.keys())) {
    const b = dests.get(d)
    const h = L.splitext(d)[0] + '.h'
    const knownDecls = have.get(h) || new Set()
    for (const e of [...b.funcs, ...b.helpers]) if (e.public && !e.fn.is_member && !knownDecls.has(e.fn.key)) decls.get(h).push([e.fn.ns, declOf(e, defaults)])
    for (const e of b.vars) {
      if (e.public && !knownDecls.has([...e.ns, e.name].filter(x => x).join('::'))) {
        let s = C.stripComments(e.text).trim()
        s = s.replace(/\s*=[\s\S]*;$/, ';')
        decls.get(h).push([e.ns, 'extern ' + s])
      }
    }
  }
  const htext = new Map()
  for (const h of hdrPaths) {
    const parts = [...gen.get(h)]
    if (decls.get(h).length) {
      parts.push(`/* defined in ${L.basename(L.splitext(h)[0])}.cpp */`)
      parts.push(...groupNs(decls.get(h)))
    }
    htext.set(h, parts.join('\n').trim())
  }

  const sharedClean = new Map()
  const typeRx = C.fullRe((cfg.drop || {}).types || [])
  for (const [h, text] of shared) {
    const cut = []
    for (const [, it] of C.walk(C.split(text))) {
      let gone = false
      if (it.kind === 'pp') {
        const m = /^#\s*include\s*([<"])([^>"]*)/.exec(it.text)
        if (/^#\s*pragma\b/.test(it.text)) gone = true
        else if (m && (m[1] === '"' || (incRx && incRx.test(m[2])))) gone = true
      } else if (it.kind === 'code') {
        const cls = C.classify(it.text)
        if (cls === 'typedef' || cls === 'typedecl') {
          const nm = C.typeName(it.text, cls)
          gone = !!(nm && typeRx && typeRx.test(nm))
        }
      }
      if (gone) cut.push([it.start, it.start + it.text.length])
    }
    cut.sort((a, b) => a[0] - b[0] || a[1] - b[1])
    const out = []; let pos = 0
    for (const [a, b] of cut) {
      out.push(text.slice(pos, a))
      pos = b
      if (pos < text.length && text[pos] === '\n') pos++
    }
    out.push(text.slice(pos))
    sharedClean.set(h, out.join('').replace(/\n{3,}/g, '\n\n'))
  }

  const full = new Map(hdrPaths.map(h => [h, (sharedClean.get(h) || '') + '\n' + htext.get(h)]))
  const exports = new Map(); const texports = new Map()
  for (const h of hdrPaths) {
    const s = headerSymbols(full.get(h), cfg)
    const t = new Set([...s.types, ...s.macros])
    texports.set(h, t)
    exports.set(h, new Set([...t, ...s.consts, ...s.funcs, ...s.vars]))
  }
  const sysinc = Object.entries(cfg.system_includes || {}).map(([k, v]) => [k, new RegExp(v)])
  const includes = (p, text, typesOnly) => {
    const ids = C.identifiers(text)
    const ownH = L.splitext(p)[0] + '.h'
    const res = []
    for (const h of hdrPaths) {
      if (h === p || h === ownH) continue
      const ex = typesOnly ? texports.get(h) : exports.get(h)
      if ([...ids].some(x => ex.has(x))) res.push(`#include "${relinc(p, h)}"`)
    }
    return res
  }
  const system = text => { const code = C.stripComments(text); return sysinc.filter(([, rx]) => rx.test(code)).map(([k]) => `#include ${k}`) }
  const written = []
  const write = (rel, text) => {
    C.writeText(L.join(outRoot, rel), text.replace(/\n{3,}/g, '\n\n').trimEnd() + '\n')
    written.push(rel)
  }

  for (const h of hdrPaths) {
    const body = htext.get(h)
    let inc = [...system(full.get(h)), ...includes(h, full.get(h), true)]
    if (sharedClean.has(h)) {
      const t = sharedClean.get(h).trimEnd()
      const present = new Set([...t.matchAll(/^#\s*include\s*([<"][^>"]*[>"])/gm)].map(m => m[1]))
      inc = inc.filter(x => !present.has(x.slice('#include '.length)))
      const ends = [...t.matchAll(/^#\s*endif\b.*$/gm)].map(m => m.index)
      const guard = /^#\s*ifndef\s+\w+\s*\n#\s*define\s+\w+[^\n]*\n/m.exec(t)
      const at = guard ? guard.index + guard[0].length : 0
      const tailAt = ends.length && guard ? ends[ends.length - 1] : t.length
      const mid = t.slice(at, tailAt).trimEnd()
      const out = t.slice(0, at) + (inc.length ? '\n' + inc.join('\n') + '\n' : '') + mid +
        (body ? '\n\n' + body + '\n' : '\n') + (tailAt < t.length ? '\n' + t.slice(tailAt) : '')
      write(h, out)
    } else {
      const g = guardPrefix + h.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()
      write(h, `#ifndef ${g}\n#define ${g}\n\n${inc.join('\n')}\n\n${body}\n\n#endif /* ${g} */\n`)
    }
  }

  const manifest = new Map()
  for (const d of sortStr(dests.keys())) {
    const b = dests.get(d)
    const lines = []
    for (const e of b.macros) lines.push(e.text.trim())
    if (b.macros.length) lines.push('')
    for (const e of b.types) lines.push(...groupNs([[e.ns, e.text.trim()]]))
    lines.push(...groupNs(b.vars.map(e => [e.ns, (e.addr ? `// ${e.addr}\n` : '') + e.text.trim()])))
    const fwd = []
    for (const e of [...b.helpers, ...b.funcs]) if (!e.public && !e.fn.is_member) fwd.push([e.fn.ns, declOf(e, defaults, false)])
    lines.push(...groupNs(fwd))
    const items = []
    for (const e of b.helpers) items.push([e.ns, stripDefDefaults(e.text.trim())])
    const fs2 = [...b.funcs].sort((x, y) => hexInt(x.addr) - hexInt(y.addr))
    for (const e of fs2) items.push([e.ns, `// ${e.addr}${e.nonm ? ' (NONMATCHING in the decomp)' : ''}\n${stripDefDefaults(e.text.trim())}`])
    lines.push(...groupNs(items))
    const body = lines.join('\n')
    const h = L.splitext(d)[0] + '.h'
    let head = [`// ${L.basename(d)}`, '//', '// ' + banner.replaceAll('{units}', b.units.join(', ') || '-'), '', `#include "${L.basename(h)}"`, '']
    head = head.concat(cfg.includes || [], system(body))
    head = head.concat([''], includes(d, body, false), [''])
    write(d, head.join('\n') + '\n' + body)
    manifest.set(d, new Map([['units', b.units], ['functions', b.funcs.length], ['helpers', b.helpers.length], ['vars', b.vars.length],
      ['types', b.types.length], ['macros', b.macros.length], ['addrs', b.funcs.map(e => e.addr).sort((x, y) => hexInt(x) - hexInt(y))]]))
  }
  const nsrc = written.filter(w => !w.endsWith('.h')).length
  const libs = new Set(cfg.library_units || [])
  const sortedMap = m => new Map([...m].sort((a, b) => L.cmp(a[0], b[0])))
  const summary = new Map([['units', units.length], ['library_units', units.filter(([u]) => libs.has(u)).length], ['sources', nsrc],
    ['headers', written.length - nsrc], ['stats', sortedMap(stats)], ['report_counts', new Map([...sortedMap(rep)].map(([k, v]) => [k, v.length]))]])
  return [summary, new Map([['stats', sortedMap(stats)], ['report', sortedMap(rep)], ['manifest', manifest]])]
}

function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [['--config', 'str', L.REQUIRED], ['--out', 'str', L.REQUIRED], ['--units', 'str', null],
    ['--report', 'str', null], ['--project', 'str', '.']])
  const err = msg => { process.stdout.write(L.dumps({ error: msg }) + '\n'); return 2 }
  let cfg
  try { cfg = C.loadConfig(a.config) } catch (e) {
    if (e instanceof C.OSErr || e instanceof SyntaxError) return err(`config cannot be read: ${a.config}`)
    throw e
  }
  const units = a.units || (cfg.units ? L.join(a.project, cfg.units) : null)
  if (!units || !L.isdir(units)) return err('no units folder (--units or "units" in the config)')
  const hdrs = (cfg.constants || {}).headers || []
  const missing = hdrs.filter(h => !L.isfile(L.join(a.project, h)))
  if (missing.length) return err(`constants header not found: ${missing[0]}`)
  cfg = { ...cfg, constants: { ...(cfg.constants || {}), headers: hdrs.map(h => L.join(a.project, h)) } }
  for (const h of Object.keys(cfg.headers || {})) if (!L.isfile(L.join(units, h))) return err(`shared header not found: ${h}`)
  const [summary, report] = run(cfg, units, a.out)
  if (a.report) C.writeText(a.report, L.dumps(report) + '\n')
  process.stdout.write(L.dumps(summary) + '\n')
  return summary.get('stats').get('unplaced_functions') ? 1 : 0
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
