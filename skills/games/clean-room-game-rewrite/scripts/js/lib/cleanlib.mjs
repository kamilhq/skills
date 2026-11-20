// cleanlib.mjs - port of ../../cleanlib.py: shared helpers of cleanroom and release_check (Node built-ins only).
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import * as L from './rwlib.mjs'

export const CODE_EXTS = ['.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh', '.hxx', '.inl', '.rs']
export const THRESHOLDS = {
  code_pct: 10, const_pct: 20, file_pct: 50, file_min: 20, names_pct: 30, names_min: 20, table_items: 1024,
  string_items: 64, string_bytes: 2048, min_string: 8, spec_overlap: 3, spec_code_lines: 3
}
export const CODE_K = 12; export const CONST_K = 5; export const RAW_K = 12; export const WINDOW = 4
export const KEYWORDS = new Set(['if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default', 'break', 'continue',
  'return', 'goto', 'match', 'loop', 'true', 'false'])
export const NOT_FN = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'sizeof', 'do', 'else', 'match', 'loop'])
export const FN_SKIP = new Set(['const', 'noexcept', 'override', 'final', 'volatile'])
export const SMALL = 32
export const GHIDRA_RE = new RegExp('\\b(?:(?:thunk_)?FUN_[0-9a-fA-F]{6,16}|DAT_[0-9a-fA-F]{6,16}|LAB_[0-9a-fA-F]{6,16}|' +
  'PTR_[A-Za-z0-9_]*_?[0-9a-fA-F]{6,16}|switchD_[0-9a-fA-F]{6,16}|undefined[1248]|' +
  '(?:in|extraout|unaff)_[A-Z]{2,3}|(?:[iubcsfdl]|p[a-z]{0,3}|a[a-z]{1,2})Var[0-9]+|local_[0-9a-f]+|param_[0-9]+|' +
  'CONCAT[0-9]{2}|SUB[0-9]{2}|ZEXT[0-9]{2}|SEXT[0-9]{2})\\b')
const ADDR = '0x(?:00)?[4-7][0-9a-fA-F]{5}\\b|0x1[0-9a-fA-F]{7}\\b'
export const ADDR_COMMENT_RE = new RegExp('(?:\\b(?:FUNCTION|STUB|LIBRARY|GLOBAL|VTABLE|SYNTHETIC|TEMPLATE|address|addr)\\b' +
  '[^\\n]*\\b(?:' + ADDR + ')|^(?://+!?|/\\*+)[ \\t]*(?:' + ADDR + '))')
export const STUB_RE = /\bstub![ \t]*\([ \t]*0x[0-9a-fA-F]+/
export const WS = ' \t\r\n\f\v'

const TOKEN_RE = new RegExp(
  '([ \\t\\r\\n\\f\\v]+)' +
  '|(//[^\\n]*|/\\*[\\s\\S]*?\\*/)' +
  '|("(?:[^"\\\\\\n]|\\\\[^\\n])*")' +
  "|('(?:[^'\\\\\\n]|\\\\[^\\n])')" +
  '|(0[xX][0-9A-Fa-f_]+[A-Za-z0-9_]*|[0-9][0-9_]*(?:\\.(?![.A-Za-z_])[0-9_]*)?(?:[eE][-+]?[0-9_]+)?[A-Za-z0-9_]*' +
  '|\\.[0-9][0-9_]*(?:[eE][-+]?[0-9_]+)?[A-Za-z0-9_]*)' +
  '|([A-Za-z_][A-Za-z0-9_]*)' +
  '|(::|->|=>|<<=|>>=|&&|\\|\\||<<|>>|\\+\\+|--|[-+*/%&|^!=<>]=|[^ \\t\\r\\n\\f\\v])', 'gu')
const KINDS = [null, 'ws', 'comment', 'string', 'char', 'number', 'ident', 'punct']
const HEX_RE = /^0[xX]([0-9A-Fa-f]*)/
const FLOAT_RE = /^([0-9]*\.[0-9]*(?:[eE][-+]?[0-9]+)?|[0-9]+[eE][-+]?[0-9]+)/
const INT_RE = /^([0-9]+)/

// Python str.strip(chars)
export function strip (s, chars = WS) {
  let a = 0; let b = s.length
  while (a < b && chars.includes(s[a])) a++
  while (b > a && chars.includes(s[b - 1])) b--
  return s.slice(a, b)
}
// Python len() and slicing by code points
export const cpLen = s => { let n = 0; for (const _ of s) n++; return n } // eslint-disable-line no-unused-vars
export const cpSlice = (s, n) => Array.from(s).slice(0, n).join('')

// ------------------------------------------------------------------------------------------------ settings
const pick = (o, k, d) => (o && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : d)
export function settings (project) {
  const [cfg, rw] = L.loadConfig(project)
  const cr = rw.cleanroom || {}
  const paths = cfg.paths || {}
  const bins = (cfg.binaries || []).filter(b => b !== null && typeof b === 'object' && !Array.isArray(b))
  const analysis = paths.analysis || 'analysis'
  const src = paths.src || null
  const priv = pick(cr, 'private', [])
  const derived = []
  for (const b of bins) for (const k of ['decompiled', 'named', 'reassembled']) if (b[k]) derived.push(b[k])
  if (src) derived.push(src)
  derived.push(analysis, paths.formats || 'tools/formats')
  if (L.get(rw, 'oracle.dir')) derived.push(L.get(rw, 'oracle.dir'))
  const reference = []
  for (const b of bins) for (const k of ['decompiled', 'named']) if (b[k]) reference.push(b[k])
  if (src) reference.push(src)
  reference.push(...priv)
  const names = bins.filter(b => b.name).map(b => analysis + '/' + b.name + '/names_apply.json')
  const d = pick(cr, 'dir', 'cleanroom')
  const th = { ...THRESHOLDS, ...(cr.thresholds || {}) }
  for (const k of Object.keys(th)) th[k] = L.num(th[k])
  return {
    dir: d,
    tree: pick(cr, 'tree', 'rewrite/clean'),
    specs: pick(cr, 'specs', d + '/specs'),
    log: pick(cr, 'log', d + '/log.jsonl'),
    allow: pick(cr, 'allow', d + '/allow.json'),
    forbidden: pick(cr, 'forbidden', [...derived, ...priv, '**/*.gpr', '**/*.rep']),
    reference: pick(cr, 'reference', reference),
    reference_exclude: pick(cr, 'reference_exclude', ['**/build/**', '**/target/**', '**/third_party/**', '**/.git/**']),
    tree_exclude: pick(cr, 'tree_exclude', ['third_party/**', 'vendor/**', 'target/**', 'build/**', '.git/**']),
    assets: pick(cr, 'assets', [paths.game || 'work/game', paths.extracted || 'extracted', paths.decoded || 'decoded']),
    names: pick(cr, 'names', names),
    libraries: rw.libraries === undefined ? null : rw.libraries,
    require_log: pick(cr, 'require_log', true),
    thresholds: th
  }
}

// ------------------------------------------------------------------------------------------------ paths
function globRe (pat) {
  const parts = pat.split('/')
  let out = ''
  parts.forEach((part, i) => {
    const last = i === parts.length - 1
    if (part === '**') { out += last ? '.*' : '(?:[^/]+/)*'; return }
    let seg = ''
    for (const ch of part) {
      if (ch === '*') seg += '[^/]*'
      else if (ch === '?') seg += '[^/]'
      else if ('.^$+{}()|[]\\-'.includes(ch)) seg += '\\' + ch
      else seg += ch
    }
    out += seg + (last ? '' : '/')
  })
  return new RegExp('^' + out + '$', 's')
}
const GLOBS = new Map()
export function globMatch (p, patterns) {
  const parts = p.split('/')
  const prefixes = parts.map((_, i) => parts.slice(0, i + 1).join('/'))
  for (let pat of patterns) {
    pat = strip(pat, '/')
    if (!GLOBS.has(pat)) GLOBS.set(pat, globRe(pat))
    const r = GLOBS.get(pat)
    for (const x of prefixes) if (r.test(x)) return pat
  }
  return null
}
export function rel (project, p) {
  const a = L.abspath(p)
  const r = L.relpath(a, L.abspath(project))
  if (r === '.' || r.startsWith('..')) return null
  return r
}
const lst = p => { try { return fs.lstatSync(p) } catch { return null } }
export function walk (project, root, exclude = []) {
  const out = []
  const top = L.join(project, root)
  const st = lst(top)
  if (st && st.isFile()) return [strip(root, '/')]
  if (!L.isdir(top)) return []
  const rec = (d) => {
    let names
    try { names = fs.readdirSync(d).sort(L.cmp) } catch { return }
    const rd = L.relpath(d, project)
    const dirs = []
    for (const n of names) {
      const s = lst(L.join(d, n))
      if (!s) continue
      if (s.isDirectory()) { if (!globMatch(rd + '/' + n, exclude)) dirs.push(n) } else if (s.isFile()) {
        const r = rd + '/' + n
        if (!globMatch(r, exclude)) out.push(r)
      }
    }
    for (const n of dirs) rec(L.join(d, n))
  }
  rec(top)
  return out.sort(L.cmp)
}
export function readText (p) { return fs.readFileSync(p).toString('utf8') }
export function isText (p, limit = 8192) {
  const fd = fs.openSync(p, 'r')
  try {
    const b = Buffer.alloc(limit)
    const n = fs.readSync(fd, b, 0, limit, 0)
    return !b.subarray(0, n).includes(0)
  } finally { fs.closeSync(fd) }
}
export const isCode = r => CODE_EXTS.some(e => r.toLowerCase().endsWith(e))

// ------------------------------------------------------------------------------------------------ tokens
export function tokens (text) {
  const out = []
  let line = 1
  for (const m of text.matchAll(TOKEN_RE)) {
    let g = 1
    while (m[g] === undefined) g++
    const t = m[g]
    if (g !== 1) out.push([KINDS[g], t, line])
    for (const c of t) if (c === '\n') line++
  }
  return out
}
const f64hex = v => { const b = Buffer.alloc(8); b.writeDoubleBE(v); return b.toString('hex') }
export function normNumber (tok) {
  const t = tok.replaceAll('_', '')
  let m = HEX_RE.exec(t)
  if (m) return 'i' + BigInt('0x' + (m[1] || '0')).toString()
  m = FLOAT_RE.exec(t)
  if (m) return 'f' + f64hex(Number(m[1]))
  m = INT_RE.exec(t)
  return m ? 'i' + BigInt(m[1]).toString() : 'i0'
}
export function significant (n) {
  if (n[0] === 'i') return BigInt(n.slice(1)) >= BigInt(SMALL)
  const v = Buffer.from(n.slice(1), 'hex').readDoubleBE(0)
  if (Number.isNaN(v) || !Number.isFinite(v)) return true
  return !(Math.abs(v) < SMALL && Number.isInteger(v * 4))
}
export function h48 (parts) {
  return createHash('sha1').update(parts.join('\x1f'), 'utf8').digest().readUIntBE(0, 6)
}
export function winnow (hashes, w = WINDOW) {
  if (hashes.length <= w) {
    if (!hashes.length) return []
    let m = hashes[0]; for (const h of hashes) if (h < m) m = h
    return [[hashes.lastIndexOf(m), m]]
  }
  const out = []
  let last = -1
  for (let s = 0; s + w <= hashes.length; s++) {
    let m = hashes[s]; let i = s
    for (let k = s; k < s + w; k++) if (hashes[k] <= m) { m = hashes[k]; i = k }
    if (i !== last) { out.push([i, m]); last = i }
  }
  return out
}
export function fileFingerprints (text, raw = false) {
  const toks = tokens(text)
  const codeToks = toks.filter(t => t[0] !== 'comment')
  const norm = []; const anchor = []; const lines = []; const consts = []; const strings = new Map()
  for (const [kind, t, ln] of codeToks) {
    let n; let a = 0
    if (kind === 'ident') n = KEYWORDS.has(t) ? t : 'I'
    else if (kind === 'number') {
      n = normNumber(t); a = significant(n) ? 1 : 0
      if (a) consts.push([ln, n])
    } else if (kind === 'string') {
      n = 'S' + t; a = 1
      if (!strings.has(t)) strings.set(t, ln)
    } else if (kind === 'char') n = 'C'
    else n = t
    norm.push(n); anchor.push(a); lines.push(ln)
  }
  const codeH = []; const codeLn = []
  let run = 0
  for (let k = 0; k < Math.min(CODE_K, anchor.length); k++) run += anchor[k]
  for (let i = 0; i + CODE_K <= norm.length; i++) {
    if (i) run += anchor[i + CODE_K - 1] - anchor[i - 1]
    if (run >= 2) { codeH.push(h48(norm.slice(i, i + CODE_K))); codeLn.push(lines[i]) }
  }
  const code = winnow(codeH).map(([i, h]) => [codeLn[i], h])
  const cv = consts.map(c => c[1])
  const constFp = []
  for (let i = 0; i + CONST_K <= cv.length; i++) constFp.push([consts[i][0], h48(cv.slice(i, i + CONST_K))])
  const out = { code, consts: constFp, strings, toks: codeToks }
  if (raw) {
    const rt = codeToks.map(([k, t]) => (k === 'number' ? normNumber(t) : t))
    const rh = []
    for (let i = 0; i + RAW_K <= rt.length; i++) rh.push(h48(rt.slice(i, i + RAW_K)))
    out.raw = winnow(rh).map(([i, h]) => [codeToks[i][2], h])
  }
  return out
}
export const stringValue = lit => lit.slice(1, -1)

export class Corpus {
  constructor (project, dirs, exclude, raw = false) {
    this.files = []; this.missing = []
    this.code = new Set(); this.consts = new Set(); this.strings = new Set(); this.raw = new Set()
    for (const d of dirs) {
      if (!fs.existsSync(L.join(project, d))) { this.missing.push(d); continue }
      for (const r of walk(project, d, exclude)) if (isCode(r)) this.files.push(r)
    }
    this.files = [...new Set(this.files)].sort(L.cmp)
    for (const r of this.files) {
      const fp = fileFingerprints(readText(L.join(project, r)), raw)
      for (const [, h] of fp.code) this.code.add(h)
      for (const [, h] of fp.consts) this.consts.add(h)
      for (const s of fp.strings.keys()) this.strings.add(stringValue(s))
      if (raw) for (const [, h] of fp.raw) this.raw.add(h)
    }
  }
}

// ------------------------------------------------------------------------------------------------ the log
export function nowIso () {
  const e = process.env.SOURCE_DATE_EPOCH
  const t = e && L.INT_RE.test(e) ? Number(e) : Math.floor(Date.now() / 1000)
  return new Date(t * 1000).toISOString().replace(/\.[0-9]+Z$/, 'Z')
}
function asciiStr (s) {
  let o = '"'
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    const ch = s[i]
    if (ch === '"') o += '\\"'
    else if (ch === '\\') o += '\\\\'
    else if (ch === '\n') o += '\\n'
    else if (ch === '\r') o += '\\r'
    else if (ch === '\t') o += '\\t'
    else if (ch === '\b') o += '\\b'
    else if (ch === '\f') o += '\\f'
    else if (c < 0x20 || c > 0x7e) o += '\\u' + c.toString(16).padStart(4, '0')
    else o += ch
  }
  return o + '"'
}
// json.dumps(obj, separators=(',', ':')) with ensure_ascii
export function compact (v) {
  if (v === null || v === undefined) return 'null'
  if (v === true) return 'true'
  if (v === false) return 'false'
  if (typeof v === 'number' || typeof v === 'bigint' || v instanceof L.PyFloat) return L.dumps(v)
  if (typeof v === 'string') return asciiStr(v)
  if (Array.isArray(v)) return '[' + v.map(compact).join(',') + ']'
  const ents = v instanceof Map ? [...v.entries()] : Object.entries(v)
  return '{' + ents.map(([k, x]) => asciiStr(String(k)) + ':' + compact(x)).join(',') + '}'
}
const sha256 = b => createHash('sha256').update(b).digest('hex')
function splitLines (data) {
  const out = []
  let s = 0
  for (let i = 0; i <= data.length; i++) {
    if (i === data.length || data[i] === 0x0a) { out.push(data.subarray(s, i)); s = i + 1 }
  }
  return out
}
const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v)
export function readLog (p) {
  const entries = []; const problems = []
  if (!fs.existsSync(p)) return [null, ['no clean-room log (run cleanroom.py init)'], null]
  const data = fs.readFileSync(p)
  let prev = '0'.repeat(64)
  const dec = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
  splitLines(data).forEach((raw, idx) => {
    const n = idx + 1
    if (!raw.length) return
    let e
    try { e = JSON.parse(dec.decode(raw)) } catch {
      problems.push(`line ${n}: not JSON`)
      prev = sha256(raw)
      return
    }
    if (!isObj(e)) problems.push(`line ${n}: not an object`)
    else {
      if (e.prev !== prev) problems.push(`line ${n}: prev does not match the line before (edited or removed lines)`)
      if (e.seq !== entries.length) problems.push(`line ${n}: seq ${L.pyStr(e.seq)}, expected ${entries.length}`)
      entries.push(e)
    }
    prev = sha256(raw)
  })
  return [entries, problems, entries.length || problems.length ? prev : null]
}
export function appendLog (p, entry) {
  let prev = '0'.repeat(64); let seq = 0
  if (fs.existsSync(p)) {
    const lines = splitLines(fs.readFileSync(p)).filter(x => x.length)
    if (lines.length) { prev = sha256(lines[lines.length - 1]); seq = lines.length }
  }
  const e = new Map([['seq', seq], ['recorded', nowIso()]])
  for (const [k, v] of (entry instanceof Map ? entry.entries() : Object.entries(entry))) e.set(k, v)
  e.set('prev', prev)
  fs.appendFileSync(p, compact(e) + '\n')
  return e
}
const truthy = v => !(v === null || v === undefined || v === false || v === 0 || v === '' ||
  (Array.isArray(v) && !v.length) || (isObj(v) && !Object.keys(v).length))
const pyLen = v => (typeof v === 'string' ? cpLen(v) : Array.isArray(v) ? v.length : isObj(v) ? Object.keys(v).length : 0)
export function verifyLog (p) {
  const [entries, problems, head] = readLog(p)
  const events = new Map(); const waves = new Map()
  for (const e of entries || []) {
    const ev = L.pyStr(e.event)
    events.set(ev, (events.get(ev) || 0) + 1)
    const w = e.wave
    if (truthy(w)) {
      const k = L.pyStr(w)
      if (!waves.has(k)) waves.set(k, new Map([['events', 0], ['inputs', 0]]))
      const s = waves.get(k)
      s.set('events', s.get('events') + 1)
      s.set('inputs', s.get('inputs') + (truthy(e.inputs) ? pyLen(e.inputs) : 0))
    }
  }
  if (entries !== null && !events.get('init')) problems.push('no init entry')
  const sortMap = m => new Map([...m.entries()].sort((a, b) => L.cmp(a[0], b[0])))
  return new Map([['entries', (entries || []).length], ['head', head], ['events', sortMap(events)],
    ['waves', sortMap(waves)], ['problems', problems], ['ok', entries !== null && !problems.length]])
}
export { path }
