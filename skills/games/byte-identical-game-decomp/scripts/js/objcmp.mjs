#!/usr/bin/env node
// objcmp.mjs - JavaScript port of objcmp.py: compare functions in MSVC COFF objects (cl.exe /c) with the
// original 32-bit PE, byte for byte. Same command line, output, JSON files and exit codes as the Python script:
//
//   objcmp.mjs compare <obj> <symbol> <pe> <va> [size] [--map F]... [--functions index.json] [--json OUT] [--all-diffs]
//   objcmp.mjs report --pe <pe> --src <dir|file>... --obj <dir|file>... [--module M] [--map F]...
//                     [--functions index.json] [--json OUT] [--verbose] [--quiet]
//   objcmp.mjs dump <obj> [--json OUT]
//
// See objcmp.py for the description of masking, address maps and exit codes.
//
// Library use (the Python module's API, snake_case kept so ported callers read the same):
//   read_coff(path) -> CoffObj {path, data, sections, symbols (Map index -> Symbol), by_name, bigobj, timestamp,
//                      functions(), find(name), function_bytes(sym) -> [Buffer, [Reloc]]}
//   new PEImage(path) {image_base, sections [[name, va, vsize, rawsize, rawptr, ch]], fixups, fixups_set,
//                      has_relocs, imports (Map), read(va, n), section_index(va), section_base(va), is_exec(va),
//                      fixups_in(va, n)}
//   new AddrMap(pe, auto_names) {names, source (Maps), conflicts, add, load, resolve(name) -> [va, src]}
//   compare_function(obj, sym, pe, va, size, amap, known_starts, max_diffs) -> result object
//   load_function_list(path) -> Map va -> size;  scan_annotations(paths, module);  map_annotation(a, objs, all)
//   collect_objs(paths);  write_obj(path, functions, {data, absolutes, bigobj, comdat, text_name, timestamp, align})
//   name_parts / source_parts / parse_definition / format_result / dump_obj / dump_json / jamcrc / main(argv)
// Python None is null; tuples are arrays; dicts with arbitrary keys are Maps; numbers are JS numbers (a result's
// ratio is a number; JSON output writes it as a Python float).
import { readFileSync, writeFileSync, statSync, lstatSync, readdirSync, realpathSync } from 'node:fs'
import { constants as osConstants } from 'node:os'
import { fileURLToPath } from 'node:url'
import { SequenceMatcher } from './lib/difflib.mjs'
import { dumps, parse as jsonParse, PyFloat, pyFloat, pyFloatRepr } from './lib/pyjson.mjs'
import { ArgumentParser, ArgExit } from './lib/pyargparse.mjs'

// ----------------------------------------------------------------------------------------------- errors

export class CoffError extends Error { get name() { return 'CoffError' } }
export class PEError extends Error { get name() { return 'PEError' } }
export class StructError extends Error { get name() { return 'struct.error' } }
export class ValueError extends Error { get name() { return 'ValueError' } }
export class KeyError extends Error { get name() { return 'KeyError' } }
export class IndexError extends Error { get name() { return 'IndexError' } }
export class OSError extends Error { get name() { return this.pyName || 'OSError' } }
export class AttributeError extends Error { get name() { return 'AttributeError' } }
const OSERROR_NAMES = { ENOENT: 'FileNotFoundError', EACCES: 'PermissionError', EPERM: 'PermissionError',
                        EISDIR: 'IsADirectoryError', ENOTDIR: 'NotADirectoryError', EEXIST: 'FileExistsError' }
// Python's type name of a parsed JSON value
export function pyTypeName(v) {
  if (v === null || v === undefined) return 'NoneType'
  if (typeof v === 'boolean') return 'bool'
  if (typeof v === 'number') return Number.isInteger(v) ? 'int' : 'float'
  if (typeof v === 'bigint') return 'int'
  if (typeof v === 'string') return 'str'
  if (v instanceof PyFloat) return 'float'
  if (Array.isArray(v)) return 'list'
  return 'dict'
}

const STRERROR = { ENOENT: 'No such file or directory', EACCES: 'Permission denied', EISDIR: 'Is a directory',
                   ENOTDIR: 'Not a directory', ELOOP: 'Too many levels of symbolic links', EPERM: 'Operation not permitted',
                   EMFILE: 'Too many open files', ENAMETOOLONG: 'File name too long', EEXIST: 'File exists',
                   ENOSPC: 'No space left on device', EROFS: 'Read-only file system', EIO: 'Input/output error' }

// a Node fs error as Python's str(OSError): "[Errno 2] No such file or directory: 'path'"
export function toOSError(e, path) {
  if (!e || !e.code || !(e.code in osConstants.errno)) return e
  const err = new OSError(`[Errno ${osConstants.errno[e.code]}] ${STRERROR[e.code] || e.code}: ${pyRepr(String(path))}`)
  err.code = e.code
  err.pyName = OSERROR_NAMES[e.code]
  return err
}
function readBytes(path) {
  try {
    return readFileSync(path)
  } catch (e) {
    throw toOSError(e, path)
  }
}
const utf8Replace = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true })
const utf8Strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
// open(path, 'r', encoding='utf-8', errors=...).read(): BOM kept, universal newlines
export function readText(path, errors = 'strict') {
  const b = readBytes(path)
  let t
  try {
    t = (errors === 'replace' ? utf8Replace : utf8Strict).decode(b)
  } catch (e) {
    throw new ValueError("'utf-8' codec can't decode bytes: invalid start byte")
  }
  return t.replace(/\r\n?/g, '\n')
}

// ----------------------------------------------------------------------------------------------- Python helpers

const WS = '\\t\\n\\x0b\\x0c\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000'
const S = `[${WS}]`                         // Python's Unicode \s
const W = '[\\p{L}\\p{N}_]'                 // Python's Unicode \w
const NOTW_AFTER = '(?![\\p{L}\\p{N}_])'    // \b after a word character
const NOTW_BEFORE = '(?<![\\p{L}\\p{N}_])'  // \b before a word character
const reLWS = new RegExp(`^${S}+`, 'u'), reRWS = new RegExp(`${S}+$`, 'u'), reWSRun = new RegExp(`${S}+`, 'gu')

export const pyStrip = (s) => s.replace(reLWS, '').replace(reRWS, '')
export const pyRstrip = (s) => s.replace(reRWS, '')
const pyLstrip = (s) => s.replace(reLWS, '')
const removeWS = (s) => s.replace(reWSRun, '')
// str.split() (no separator)
export function pySplitWS(s, maxsplit = -1) {
  const out = []
  let rest = pyLstrip(s)
  while (rest) {
    if (maxsplit >= 0 && out.length === maxsplit) { out.push(rest); break }
    const m = new RegExp(S, 'u').exec(rest)
    if (!m) { out.push(rest); break }
    out.push(rest.slice(0, m.index))
    rest = pyLstrip(rest.slice(m.index))
  }
  return out
}
// str.splitlines()
export function splitlines(s) {
  const out = []
  const re = /\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]/g
  let i = 0, m
  while ((m = re.exec(s))) { out.push(s.slice(i, m.index)); i = m.index + m[0].length }
  if (i < s.length) out.push(s.slice(i))
  return out
}
// Python string order (code points)
export function cmpStr(a, b) {
  if (a === b) return 0
  const x = Array.from(a), y = Array.from(b)
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    if (x[i] !== y[i]) return x[i].codePointAt(0) < y[i].codePointAt(0) ? -1 : 1
  }
  return x.length < y.length ? -1 : x.length > y.length ? 1 : 0
}
const sortedUnique = (it) => [...new Set(it)].sort(cmpStr)
const tupleEq = (a, b) => a !== null && b !== null && a.length === b.length && a.every((x, i) => x === b[i])

// repr() of a str
export function pyReprStr(s) {
  const q = s.includes("'") && !s.includes('"') ? '"' : "'"
  let out = q
  for (const ch of s) {
    const c = ch.codePointAt(0)
    if (ch === q || ch === '\\') out += '\\' + ch
    else if (ch === '\t') out += '\\t'
    else if (ch === '\n') out += '\\n'
    else if (ch === '\r') out += '\\r'
    else if (c < 0x20 || c === 0x7f) out += '\\x' + c.toString(16).padStart(2, '0')
    else if (c < 0x7f) out += ch
    else if (/^[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]$/u.test(ch)) {
      out += c <= 0xff ? '\\x' + c.toString(16).padStart(2, '0')
        : c <= 0xffff ? '\\u' + c.toString(16).padStart(4, '0') : '\\U' + c.toString(16).padStart(8, '0')
    } else out += ch
  }
  return out + q
}
// str() of a float
export function pyFloatStr(x) {
  if (Number.isNaN(x)) return 'nan'
  if (x === Infinity) return 'inf'
  if (x === -Infinity) return '-inf'
  return pyFloatRepr(x)
}
// repr() of a value: str, int, PyFloat, bool, None, list (array), tuple (PyTuple), dict (Map or plain object)
export class PyTuple extends Array {}
export const tuple = (...xs) => PyTuple.from(xs)
export function pyRepr(v) {
  if (typeof v === 'string') return pyReprStr(v)
  if (v === null || v === undefined) return 'None'
  if (v === true) return 'True'
  if (v === false) return 'False'
  if (typeof v === 'number') return Number.isInteger(v) && !Object.is(v, -0) ? String(v) : pyFloatStr(v)
  if (typeof v === 'bigint') return v.toString()
  if (v instanceof PyFloat) return pyFloatStr(v.v)
  if (v instanceof PyTuple) return '(' + v.map(pyRepr).join(', ') + (v.length === 1 ? ',)' : ')')
  if (Array.isArray(v)) return '[' + v.map(pyRepr).join(', ') + ']'
  if (Buffer.isBuffer(v)) return "b'" + [...v].map((c) => (c >= 0x20 && c < 0x7f && c !== 0x27 && c !== 0x5c ? String.fromCharCode(c) : '\\x' + c.toString(16).padStart(2, '0'))).join('') + "'"
  const entries = v instanceof Map ? [...v] : Object.entries(v)
  return '{' + entries.map(([k, x]) => pyRepr(k) + ': ' + pyRepr(x)).join(', ') + '}'
}
export const pyStr = (v) => (typeof v === 'string' ? v : pyRepr(v))

// hex(n)
export const hex = (n) => (n < 0 ? '-0x' + (-n).toString(16) : '0x' + n.toString(16))
const x08 = (n) => n.toString(16).padStart(8, '0')
// f'{n:+#x}'
const signedHex = (n) => (n < 0 ? '-0x' + (-n).toString(16) : '+0x' + n.toString(16))

// f'{x:.{nd}f}' (and the digits of round(x, nd)): exact decimal value, ties to even
export function pyFormatFixed(x, nd) {
  if (!Number.isFinite(x)) return pyFloatStr(x)
  const neg = x < 0 || Object.is(x, -0)
  const ax = Math.abs(x)
  if (ax >= 1e21) return (neg ? '-' : '') + BigInt(ax).toString() + (nd ? '.' + '0'.repeat(nd) : '')
  let s = ax.toFixed(nd)                   // exact, but rounds ties up
  const ex = ax.toFixed(100)               // exact digits for any value that can be a tie
  const dot = ex.indexOf('.')
  const frac = ex.slice(dot + 1)
  if (nd < 100 && frac[nd] === '5' && /^0*$/.test(frac.slice(nd + 1))) {
    const trunc = nd ? ex.slice(0, dot + 1 + nd) : ex.slice(0, dot)
    if (Number(trunc[trunc.length - 1]) % 2 === 0) s = trunc
  }
  return (neg ? '-' : '') + s
}
// round(x, nd) for a float
export const pyRound = (x, nd) => parseFloat(pyFormatFixed(x, nd))

// int(s, base) for a str
export function pyInt(s, base = 10) {
  const bad = () => new ValueError(`invalid literal for int() with base ${base}: ${pyReprStr(s)}`)
  let t = pyStrip(s)
  let neg = false
  if (t[0] === '+' || t[0] === '-') { neg = t[0] === '-'; t = t.slice(1) }
  if (base === 16 && /^0[xX]/.test(t)) { t = t.slice(2); if (t[0] === '_') t = t.slice(1) }
  const digit = base === 16 ? '[0-9a-fA-F]' : '[0-9]'
  if (!new RegExp(`^${digit}(?:_?${digit})*$`).test(t)) throw bad()
  const v = parseInt(t.replace(/_/g, ''), base)
  return neg ? -v : v
}
// int(v) for a JSON value
function pyIntOf(v) {
  if (typeof v === 'number') return Math.trunc(v)
  if (typeof v === 'bigint') return Number(v)
  if (typeof v === 'boolean') return v ? 1 : 0
  if (v instanceof PyFloat) {
    if (Number.isNaN(v.v)) throw new ValueError('cannot convert float NaN to integer')
    if (!Number.isFinite(v.v)) throw new Error('OverflowError: cannot convert float infinity to integer')
    return Math.trunc(v.v)
  }
  if (typeof v === 'string') return pyInt(v, 10)
  throw new TypeError(`int() argument must be a string, a bytes-like object or a number`)
}
const truthy = (v) => !(v === null || v === undefined || v === false || v === 0 || v === '' ||
  (v instanceof PyFloat && v.v === 0) || (Array.isArray(v) && !v.length) || (v instanceof Map && !v.size))

// os.path (posix)
export function pathJoin(a, ...rest) {
  let p = a
  for (const b of rest) {
    if (b.startsWith('/')) p = b
    else if (!p || p.endsWith('/')) p += b
    else p += '/' + b
  }
  return p
}
export const basename = (p) => p.slice(p.lastIndexOf('/') + 1)
export function splitext(p) {
  const sep = p.lastIndexOf('/')
  const dot = p.lastIndexOf('.')
  if (dot > sep) {
    let i = sep + 1
    while (i < dot) { if (p[i] !== '.') return [p.slice(0, dot), p.slice(dot)]; i++ }
  }
  return [p, '']
}
export function normpath(path) {
  if (!path) return '.'
  let initial = path.startsWith('/') ? 1 : 0
  if (initial && path.startsWith('//') && !path.startsWith('///')) initial = 2
  const comps = []
  for (const c of path.split('/')) {
    if (c === '' || c === '.') continue
    if (c !== '..' || (!initial && !comps.length) || (comps.length && comps[comps.length - 1] === '..')) comps.push(c)
    else if (comps.length) comps.pop()
  }
  return ('/'.repeat(initial) + comps.join('/')) || '.'
}
export const abspath = (p) => normpath(p.startsWith('/') ? p : pathJoin(process.cwd(), p))
export function relpath(path, start = '.') {
  if (!path) throw new ValueError('no path specified')
  const s = abspath(start).split('/').filter(Boolean), p = abspath(path).split('/').filter(Boolean)
  let i = 0
  while (i < s.length && i < p.length && s[i] === p[i]) i++
  const rel = [...Array(s.length - i).fill('..'), ...p.slice(i)]
  return rel.length ? pathJoin(...rel) : '.'
}
export function isdir(p) {
  try { return statSync(p).isDirectory() } catch { return false }
}
function islink(p) {
  try { return lstatSync(p).isSymbolicLink() } catch { return false }
}
// os.walk(top) (top-down; the caller may sort `dirs` in place before the walk descends)
export function* walk(top) {
  let entries
  try { entries = readdirSync(top, { withFileTypes: true }) } catch { return }
  const dirs = [], files = []
  for (const e of entries) {
    let d = e.isDirectory()
    if (!d && e.isSymbolicLink()) d = isdir(pathJoin(top, e.name))
    ;(d ? dirs : files).push(e.name)
  }
  yield [top, dirs, files]
  for (const d of dirs) {
    const p = pathJoin(top, d)
    if (!islink(p)) yield* walk(p)
  }
}

// struct: '<' formats with x B b H h I i s
const FMT_CACHE = new Map()
function parseFmt(fmt) {
  let f = FMT_CACHE.get(fmt)
  if (!f) {
    const items = []
    let size = 0
    for (const m of fmt.slice(1).matchAll(/(\d*)([xBbHhIis])/g)) {
      const c = m[1] ? Number(m[1]) : 1
      items.push([c, m[2]])
      size += c * ({ x: 1, B: 1, b: 1, H: 2, h: 2, I: 4, i: 4, s: 1 })[m[2]]
    }
    f = { items, size }
    FMT_CACHE.set(fmt, f)
  }
  return f
}
const structSize = (fmt) => parseFmt(fmt).size
export function unpack_from(fmt, buf, off = 0) {
  const { items, size } = parseFmt(fmt)
  if (off + size > buf.length) {
    throw new StructError(`unpack_from requires a buffer of at least ${off + size} bytes for unpacking ${size} bytes ` +
                          `at offset ${off} (actual buffer size is ${buf.length})`)
  }
  const out = []
  let p = off
  for (const [c, t] of items) {
    if (t === 's') { out.push(Buffer.from(buf.subarray(p, p + c))); p += c; continue }
    for (let k = 0; k < c; k++) {
      switch (t) {
        case 'x': p += 1; break
        case 'B': out.push(buf[p]); p += 1; break
        case 'b': out.push(buf.readInt8(p)); p += 1; break
        case 'H': out.push(buf.readUInt16LE(p)); p += 2; break
        case 'h': out.push(buf.readInt16LE(p)); p += 2; break
        case 'I': out.push(buf.readUInt32LE(p)); p += 4; break
        case 'i': out.push(buf.readInt32LE(p)); p += 4; break
      }
    }
  }
  return out
}
export function unpack(fmt, buf) {
  const size = structSize(fmt)
  if (buf.length !== size) throw new StructError(`unpack requires a buffer of ${size} bytes`)
  return unpack_from(fmt, buf, 0)
}
export function pack(fmt, ...vals) {
  const buf = Buffer.alloc(structSize(fmt))
  let p = 0, v = 0
  for (const [c, t] of parseFmt(fmt).items) {
    if (t === 's') {
      const b = Buffer.from(vals[v++])
      b.copy(buf, p, 0, Math.min(c, b.length))
      p += c
      continue
    }
    for (let k = 0; k < c; k++) {
      switch (t) {
        case 'x': p += 1; break
        case 'B': buf.writeUInt8(vals[v++], p); p += 1; break
        case 'b': buf.writeInt8(vals[v++], p); p += 1; break
        case 'H': buf.writeUInt16LE(vals[v++], p); p += 2; break
        case 'h': buf.writeInt16LE(vals[v++], p); p += 2; break
        case 'I': buf.writeUInt32LE(vals[v++], p); p += 4; break
        case 'i': buf.writeInt32LE(vals[v++], p); p += 4; break
      }
    }
  }
  return buf
}
const latin1 = (b) => Buffer.from(b).toString('latin1')
function encodeLatin1(s) {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0xff) {
      throw new ValueError(`'latin-1' codec can't encode character '\\u${s.charCodeAt(i).toString(16).padStart(4, '0')}' ` +
                           `in position ${i}: ordinal not in range(256)`)
    }
  }
  return Buffer.from(s, 'latin1')
}
function rstripNul(b) {
  let e = b.length
  while (e > 0 && b[e - 1] === 0) e--
  return b.subarray(0, e)
}
function bisectRight(arr, x) {
  let lo = 0, hi = arr.length
  while (lo < hi) { const mid = (lo + hi) >> 1; if (x < arr[mid]) hi = mid; else lo = mid + 1 }
  return lo
}
function bisectLeft(arr, x) {
  let lo = 0, hi = arr.length
  while (lo < hi) { const mid = (lo + hi) >> 1; if (arr[mid] < x) lo = mid + 1; else hi = mid }
  return lo
}

// ----------------------------------------------------------------------------------------------- constants

export const MACHINE_I386 = 0x14C
export const BIGOBJ_CLSID = Buffer.from('c7a1bad1eebaa94baf20faf66aa4dcb8', 'hex')

export const REL_NAMES = new Map([[0x0, 'ABSOLUTE'], [0x1, 'DIR16'], [0x2, 'REL16'], [0x6, 'DIR32'], [0x7, 'DIR32NB'],
  [0x9, 'SEG12'], [0xA, 'SECTION'], [0xB, 'SECREL'], [0xC, 'TOKEN'], [0xD, 'SECREL7'], [0x14, 'REL32']])
export const REL_BY_NAME = new Map([...REL_NAMES].map(([k, v]) => [v, k]))
export const REL_SIZE = new Map([[0x0, 0], [0x1, 2], [0x2, 2], [0x6, 4], [0x7, 4], [0x9, 2], [0xA, 2], [0xB, 4],
  [0xC, 4], [0xD, 1], [0x14, 4]])
export const DIR32 = 0x6, DIR32NB = 0x7, SECTION_REL = 0xA, SECREL = 0xB, REL32 = 0x14
export const SUPPORTED_RELS = new Set([0x0, DIR32, DIR32NB, SECTION_REL, SECREL, REL32])

export const SCN_CNT_CODE = 0x20, SCN_CNT_IDATA = 0x40, SCN_CNT_UDATA = 0x80
export const SCN_LNK_INFO = 0x200, SCN_LNK_REMOVE = 0x800, SCN_LNK_COMDAT = 0x1000
export const SCN_NRELOC_OVFL = 0x01000000, SCN_DISCARDABLE = 0x02000000
export const SCN_EXEC = 0x20000000, SCN_READ = 0x40000000, SCN_WRITE = 0x80000000
export const SCN_FLAG_NAMES = [[SCN_CNT_CODE, 'CODE'], [SCN_CNT_IDATA, 'IDATA'], [SCN_CNT_UDATA, 'UDATA'],
  [SCN_LNK_INFO, 'INFO'], [SCN_LNK_REMOVE, 'REMOVE'], [SCN_LNK_COMDAT, 'COMDAT'],
  [SCN_NRELOC_OVFL, 'NRELOC_OVFL'], [SCN_DISCARDABLE, 'DISCARD'], [SCN_EXEC, 'X'],
  [SCN_READ, 'R'], [SCN_WRITE, 'W']]
export const CLASS_EXTERNAL = 2, CLASS_STATIC = 3, CLASS_LABEL = 6, CLASS_WEAK = 105
export const CLASS_NAMES = new Map([[2, 'EXTERNAL'], [3, 'STATIC'], [6, 'LABEL'], [101, 'FUNCTION'], [103, 'FILE'],
  [104, 'SECTION'], [105, 'WEAK_EXTERNAL'], [107, 'CLR_TOKEN']])
export const COMDAT_NAMES = new Map([[1, 'NODUPLICATES'], [2, 'ANY'], [3, 'SAME_SIZE'], [4, 'EXACT_MATCH'],
  [5, 'ASSOCIATIVE'], [6, 'LARGEST']])
export const PAD_BYTES = [0xCC, 0x90]
const isPad = (b) => b === 0xCC || b === 0x90

// 'DIR32' / 'IMAGE_REL_I386_REL32' / 6 -> int
export function rel_type(t) {
  if (typeof t === 'number') return t
  t = t.toUpperCase().replace('IMAGE_REL_I386_', '')
  if (!REL_BY_NAME.has(t)) throw new ValueError(`unknown relocation type ${t}`)
  return REL_BY_NAME.get(t)
}

export function scn_flags(ch) {
  const names = SCN_FLAG_NAMES.filter(([bit]) => (ch & bit) >>> 0).map(([, n]) => n)
  const a = (ch >>> 20) & 0xF
  if (a) names.push(`ALIGN${1 << (a - 1)}`)
  return names.join('|')
}

// ----------------------------------------------------------------------------------------------- COFF reader

export class Section {
  constructor() {
    this.number = 0            // 1-based
    this.name = ''
    this.characteristics = 0
    this.data = Buffer.alloc(0) // raw data (empty for uninitialised data)
    this.size = 0              // SizeOfRawData
    this.relocs = []
    this.comdat = 0            // COMDAT selection (0 = not a COMDAT)
    this.assoc = 0             // associated section number (selection 5)
    this.checksum = 0
    this.nlinenums = 0
  }
  get is_code() { return !!((this.characteristics & (SCN_CNT_CODE | SCN_EXEC)) >>> 0) }
}

export class Symbol {
  constructor() {
    this.index = 0
    this.name = ''
    this.value = 0
    this.secnum = 0            // >0 section, 0 undefined/common, -1 absolute, -2 debug
    this.type = 0
    this.storage = 0
    this.naux = 0
    this.aux = []
    this.section = null
    this.is_section_sym = false
    this.is_function = false
    this.size = null           // function extent (bytes) when is_function
    this.weak_default = null   // weak external: default symbol index
  }
  get defined() { return this.secnum > 0 }
  // identity for address inference: externals by name, statics per section
  get key() {
    if (this.storage === CLASS_STATIC && this.secnum > 0) return `${this.name}#sec${this.secnum}`
    return this.name
  }
}

export class Reloc {
  constructor(offset, symidx, rtype, symbol = null) {
    this.offset = offset
    this.symidx = symidx
    this.type = rtype
    this.symbol = symbol
  }
  get size() { return REL_SIZE.has(this.type) ? REL_SIZE.get(this.type) : 4 }
  get type_name() { return REL_NAMES.has(this.type) ? REL_NAMES.get(this.type) : `0x${this.type.toString(16)}` }
}

// An i386 COFF object (regular or /bigobj)
export class CoffObj {
  constructor(data, path = '<obj>') {
    this.path = path
    this.data = data
    this.sections = []
    this.symbols = new Map()   // index -> Symbol (aux slots absent)
    this.by_name = new Map()
    this.strtab = Buffer.alloc(0)
    this._parse()
  }

  _parse() {
    const d = this.data
    if (d.length < 20) throw new CoffError('file too small for a COFF header')
    const [sig1, sig2] = unpack_from('<HH', d, 0)
    let machine, nsec, symptr, nsyms, hdr
    if (sig1 === 0 && sig2 === 0xFFFF) {
      let version
      ;[version, machine] = unpack_from('<HH', d, 4)
      if (version >= 2 && d.subarray(12, 28).equals(BIGOBJ_CLSID)) {
        if (d.length < 56) throw new CoffError('truncated bigobj header')
        this.bigobj = true
        this.timestamp = unpack_from('<I', d, 8)[0]
        ;[nsec, symptr, nsyms] = unpack_from('<III', d, 44)
        hdr = 56
      } else if (version === 0) {
        throw new CoffError('short import object (import-library member), not compiled code')
      } else {
        throw new CoffError('anonymous object header (likely /GL link-time code generation: IL, not machine ' +
                            'code); recompile without /GL')
      }
    } else {
      this.bigobj = false
      let optsize
      ;[machine, nsec, this.timestamp, symptr, nsyms, optsize] = unpack_from('<HHIIIHH', d, 0)
      hdr = 20 + optsize
    }
    if (machine !== MACHINE_I386) {
      throw new CoffError(`machine 0x${machine.toString(16).padStart(4, '0')} is not i386 (0x14c); not a 32-bit x86 COFF object`)
    }
    this.machine = machine
    this.symsize = this.bigobj ? 20 : 18
    const strpos = symptr + nsyms * this.symsize
    if (symptr && strpos + 4 <= d.length) {
      const n = unpack_from('<I', d, strpos)[0]
      this.strtab = d.subarray(strpos, strpos + Math.max(n, 4))
    }
    if (hdr + 40 * nsec > d.length) throw new CoffError('section table runs past end of file')
    for (let i = 0; i < nsec; i++) {
      const o = hdr + 40 * i
      const raw = d.subarray(o, o + 8)
      const [, , rawsize, rawptr, relptr, , nrel, nln, ch] = unpack_from('<IIIIIIHHI', d, o + 8)
      const s = new Section()
      s.number = i + 1; s.characteristics = ch; s.size = rawsize; s.nlinenums = nln
      s.name = this._section_name(raw)
      if (!(ch & SCN_CNT_UDATA) && rawptr) {
        if (rawptr + rawsize > d.length) throw new CoffError(`section ${s.name} data runs past end of file`)
        s.data = d.subarray(rawptr, rawptr + rawsize)
      }
      let count = nrel, rp = relptr
      if ((ch & SCN_NRELOC_OVFL) && nrel === 0xFFFF) {
        count = unpack_from('<I', d, relptr)[0] - 1
        rp = relptr + 10
      }
      if (rp + 10 * count > d.length) throw new CoffError(`section ${s.name} relocations run past end of file`)
      for (let k = 0; k < count; k++) {
        const p = rp + 10 * k
        s.relocs.push(new Reloc(d.readUInt32LE(p), d.readUInt32LE(p + 4), d.readUInt16LE(p + 8)))
      }
      this.sections.push(s)
    }
    const symfmt = this.bigobj ? '<8sIiHBB' : '<8sIhHBB'
    if (symptr && symptr + nsyms * this.symsize > d.length) throw new CoffError('symbol table runs past end of file')
    let i = 0
    while (i < nsyms) {
      const o = symptr + i * this.symsize
      const [raw, value, secnum, typ, storage, naux] = unpack_from(symfmt, d, o)
      const sym = new Symbol()
      sym.index = i; sym.value = value; sym.secnum = secnum; sym.type = typ; sym.storage = storage; sym.naux = naux
      sym.name = this._sym_name(raw)
      sym.aux = []
      for (let k = 0; k < naux; k++) {
        sym.aux.push(d.subarray(Math.min(o + this.symsize * (k + 1), d.length), o + this.symsize * (k + 2)))
      }
      if (secnum > 0 && secnum <= this.sections.length) sym.section = this.sections[secnum - 1]
      this.symbols.set(i, sym)
      if (!this.by_name.has(sym.name)) this.by_name.set(sym.name, [])
      this.by_name.get(sym.name).push(sym)
      i += 1 + naux
    }
    for (const sym of this.symbols.values()) {
      const sec = sym.section
      if (sec !== null && sym.storage === CLASS_STATIC && sym.naux && sym.value === 0 &&
          sym.name === sec.name && sym.type === 0) {
        sym.is_section_sym = true
        const a = sym.aux[0]
        let ck, num, sel
        if (this.bigobj) {
          let hi
          ;[, , , ck, num, sel, , hi] = unpack_from('<IHHIHBBH', a, 0)
          num = (num | (hi << 16)) >>> 0
        } else {
          ;[, , , ck, num, sel] = unpack_from('<IHHIHB', a, 0)
        }
        sec.checksum = ck
        if (sec.characteristics & SCN_LNK_COMDAT) { sec.comdat = sel; sec.assoc = num }
      }
      if (sym.storage === CLASS_WEAK && sym.aux.length) sym.weak_default = unpack_from('<I', sym.aux[0], 0)[0]
    }
    for (const s of this.sections) {
      for (const r of s.relocs) r.symbol = this.symbols.has(r.symidx) ? this.symbols.get(r.symidx) : null
    }
    // functions and their extents
    const perSec = new Map()
    for (const sym of this.symbols.values()) {
      const sec = sym.section
      if (sec === null || sym.is_section_sym || (sym.storage !== CLASS_EXTERNAL && sym.storage !== CLASS_STATIC)) continue
      if (sym.name.startsWith('$') || !sec.is_code) continue
      if (((sym.type >> 4) & 3) === 2 || sec.is_code) {
        sym.is_function = true
        if (!perSec.has(sec.number)) perSec.set(sec.number, [])
        perSec.get(sec.number).push(sym)
      }
    }
    for (const [secnum, syms] of perSec) {
      const sec = this.sections[secnum - 1]
      const starts = [...new Set(syms.map((s) => s.value))].sort((a, b) => a - b)
      for (const s of syms) {
        const k = bisectRight(starts, s.value)
        const end = k < starts.length ? starts[k] : sec.size
        s.size = Math.max(0, end - s.value)
      }
    }
  }

  _str(off) {
    if (off >= this.strtab.length) throw new CoffError(`string table offset ${off} out of range`)
    const end = this.strtab.indexOf(0, off)
    return latin1(this.strtab.subarray(off, end >= 0 ? end : this.strtab.length))
  }

  _sym_name(raw) {
    if (raw[0] === 0 && raw[1] === 0 && raw[2] === 0 && raw[3] === 0) return this._str(raw.readUInt32LE(4))
    return latin1(rstripNul(raw))
  }

  _section_name(raw) {
    if (raw[0] === 0x2f && raw[1] === 0x2f) {      // '//' base64 offset (very large string tables)
      const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
      let off = 0
      for (const c of latin1(rstripNul(raw.subarray(2)))) {
        const k = alpha.indexOf(c)
        if (k < 0) throw new ValueError('substring not found')
        off = off * 64 + k
      }
      return this._str(off)
    }
    const rest = latin1(rstripNul(raw.subarray(1)))
    if (raw[0] === 0x2f && /^[0-9]+$/.test(rest)) return this._str(parseInt(rest, 10))
    return latin1(rstripNul(raw))
  }

  functions() { return [...this.symbols.values()].filter((s) => s.is_function) }

  find(name) { return (this.by_name.get(name) || []).filter((s) => s.is_function) }

  // [bytes, [Reloc with offsets relative to the function start]] of a function symbol
  function_bytes(sym) {
    const sec = sym.section
    const start = sym.value, end = sym.value + (sym.size || 0)
    const data = sec.data.subarray(Math.min(start, sec.data.length), Math.min(end, sec.data.length))
    const rels = []
    for (const r of sec.relocs) {
      if (start <= r.offset && r.offset < end) rels.push(new Reloc(r.offset - start, r.symidx, r.type, r.symbol))
    }
    return [data, rels]
  }
}

export function read_coff(path) {
  return new CoffObj(readBytes(path), path)
}

// ----------------------------------------------------------------------------------------------- PE reader

// A 32-bit PE: sections, image base, .reloc fixups, imports, VA -> file offset
export class PEImage {
  constructor(path) {
    this.path = path
    this.data = readBytes(path)
    const d = this.data
    if (!(d[0] === 0x4d && d[1] === 0x5a) || d.length < 0x40) throw new PEError('no MZ header')
    const o = unpack_from('<I', d, 0x3C)[0]
    if (!d.subarray(o, o + 4).equals(Buffer.from('PE\0\0', 'latin1'))) throw new PEError('no PE signature')
    let nsec
    ;[this.machine, nsec] = unpack_from('<HH', d, o + 4)
    const optsize = unpack_from('<H', d, o + 20)[0]
    const opt = o + 24
    const magic = unpack_from('<H', d, opt)[0]
    if (magic !== 0x10B) throw new PEError(`optional header magic 0x${magic.toString(16)}: only PE32 (32-bit) is supported`)
    this.image_base = unpack_from('<I', d, opt + 28)[0]
    const nrva = unpack_from('<I', d, opt + 92)[0]
    this.dirs = []
    for (let k = 0; k < Math.min(nrva, 16); k++) this.dirs.push(unpack_from('<II', d, opt + 96 + 8 * k))
    this.sections = []
    const so = opt + optsize
    for (let i = 0; i < nsec; i++) {
      const [name, vsize, va, rawsize, rawptr] = unpack_from('<8sIIII', d, so + 40 * i)
      const ch = unpack_from('<I', d, so + 40 * i + 36)[0]
      this.sections.push([latin1(rstripNul(name)), va, vsize, rawsize, rawptr, ch])
    }
    this.fixups = this._relocs()
    this.fixups_set = new Set(this.fixups)
    this.has_relocs = this.fixups.length > 0 || (this.dirs.length > 5 && this.dirs[5][1] > 0)
    this.imports = this._imports()
  }

  section_index(va) {
    const rva = va - this.image_base
    for (let k = 0; k < this.sections.length; k++) {
      const [, sva, vsize, rawsize] = this.sections[k]
      if (sva <= rva && rva < sva + Math.max(vsize, rawsize)) return k
    }
    return null
  }

  section_base(va) {
    const k = this.section_index(va)
    return k === null ? null : this.image_base + this.sections[k][1]
  }

  is_exec(va) {
    const k = this.section_index(va)
    return k !== null && !!((this.sections[k][5] & (SCN_CNT_CODE | SCN_EXEC)) >>> 0)
  }

  // bytes at VA; virtual tails read as zero; stops at the section end
  read(va, n) {
    const k = this.section_index(va)
    if (k === null) throw new PEError(`0x${va.toString(16)} is not inside any section of ${this.path}`)
    const [, sva, vsize, rawsize, rawptr] = this.sections[k]
    const delta = va - this.image_base - sva
    n = Math.min(n, Math.max(vsize, rawsize) - delta)
    const d = this.data
    let filePart = Buffer.alloc(0)
    if (delta < rawsize) {
      const a = rawptr + delta, b = rawptr + Math.min(rawsize, delta + n)
      filePart = d.subarray(Math.min(a, d.length), Math.max(Math.min(b, d.length), Math.min(a, d.length)))
    }
    if (n - filePart.length <= 0) return filePart
    return Buffer.concat([filePart, Buffer.alloc(n - filePart.length)])
  }

  _rva_read(rva, n) { return this.read(this.image_base + rva, n) }

  _relocs() {
    if (this.dirs.length <= 5 || !this.dirs[5][0]) return []
    const [rva, size] = this.dirs[5]
    const blob = this._rva_read(rva, size)
    const out = new Set()
    let p = 0
    while (p + 8 <= blob.length) {
      const [page, bsize] = unpack_from('<II', blob, p)
      if (bsize < 8) break
      for (let k = 0; k < Math.floor((bsize - 8) / 2); k++) {
        const e = unpack_from('<H', blob, p + 8 + 2 * k)[0]
        const t = e >> 12, off = e & 0xFFF
        if (t !== 0) out.add(this.image_base + page + off)   // HIGHLOW; other types: still mask 4 bytes
      }
      p += bsize
    }
    return [...out].sort((a, b) => a - b)
  }

  // fixup VAs whose 4 bytes overlap [va, va+n)
  fixups_in(va, n) {
    const lo = bisectLeft(this.fixups, va - 3)
    const hi = bisectLeft(this.fixups, va + n)
    return this.fixups.slice(lo, hi)
  }

  _imports() {
    const out = new Map()
    if (this.dirs.length <= 1 || !this.dirs[1][0]) return out
    const setdefault = (k, v) => { if (!out.has(k)) out.set(k, v) }
    try {
      let rva = this.dirs[1][0]
      for (;;) {
        const [oft, , , nameRva, ft] = unpack('<IIIII', this._rva_read(rva, 20))
        if (!(oft || nameRva || ft)) break
        const dll = this._cstr(nameRva)
        const lookup = oft || ft
        let k = 0
        for (;;) {
          const ent = unpack('<I', this._rva_read(lookup + 4 * k, 4))[0]
          if (!ent) break
          const slot = this.image_base + ft + 4 * k
          if (ent & 0x80000000) setdefault(`${dll}#${ent & 0xFFFF}`, slot)
          else setdefault(this._cstr(ent + 2), slot)
          k++
        }
        rva += 20
      }
    } catch (e) {
      if (!(e instanceof PEError || e instanceof StructError)) throw e
    }
    return out
  }

  _cstr(rva) {
    const b = this._rva_read(rva, 512)
    const z = b.indexOf(0)
    return latin1(z >= 0 ? b.subarray(0, z) : b)
  }
}

// ----------------------------------------------------------------------------------------------- address map

export const GHIDRA_NAME = new RegExp('^[_@]?(?:FUN|DAT|LAB|PTR|SUB|sub|thunk_FUN|switchD|caseD|BYTE|WORD|DWORD|byte|word|dword|' +
                                      'off|unk|loc)_([0-9A-Fa-f]{8})(?:@\\p{Nd}+)?(?=\\n?$)', 'u')

// int, '0x401000', '401000' (hex by default) or decimal with hex_default=false
export function parse_int(v, hex_default = true) {
  if (typeof v === 'number' && Number.isInteger(v)) return v
  if (typeof v === 'boolean') return v ? 1 : 0
  if (typeof v === 'bigint') return Number(v)
  const s = pyStrip(typeof v === 'number' ? pyFloatStr(v) : pyStr(v))
  if (s.toLowerCase().startsWith('0x')) return pyInt(s, 16)
  return pyInt(s, hex_default ? 16 : 10)
}

// symbol name -> original VA. Sources: map files, annotations, PE imports, Ghidra default names
export class AddrMap {
  constructor(pe = null, auto_names = true) {
    this.names = new Map()
    this.source = new Map()
    this.conflicts = []
    this.pe = pe
    this.auto_names = auto_names
  }

  add(name, va, source) {
    const old = this.names.has(name) ? this.names.get(name) : null
    if (old !== null && old !== undefined && old !== va) {
      this.conflicts.push({ symbol: name, addresses: [hex(old), hex(va)], sources: [this.source.get(name), source] })
      return false
    }
    this.names.set(name, va)
    if (!this.source.has(name)) this.source.set(name, source)
    return true
  }

  load(path) {
    const text = readText(path, 'replace')
    const st = pyLstrip(text)
    if (st.startsWith('{') || st.startsWith('[')) {
      let obj = jsonLoads(text)
      if (obj instanceof Map && Array.isArray(obj.get('functions'))) obj = obj.get('functions')
      if (obj instanceof Map) {
        for (const [k, v] of obj) this.add(k, parse_int(v), path)
      } else {
        for (const e of obj) {
          if (!(e instanceof Map)) throw new AttributeError(`'${pyTypeName(e)}' object has no attribute 'get'`)
          const nm = truthy(e.get('name')) ? e.get('name') : e.get('symbol')
          if (nm !== null && nm !== undefined && e.get('address') !== null && e.get('address') !== undefined) {
            this.add(nm, parse_int(e.get('address')), path)
          }
        }
      }
      return
    }
    for (let ln of splitlines(text)) {
      ln = pyStrip(ln.split('#')[0])
      if (!ln) continue
      const parts = pySplitWS(ln, 1)
      const [a, b] = parts.length === 2 ? parts : [ln, '']
      if (/^0x[0-9a-fA-F]+$/.test(a)) this.add(pyStrip(b), pyInt(a, 16), path)
      else this.add(a, parse_int(b), path)
    }
  }

  resolve(name) {
    if (this.names.has(name)) return [this.names.get(name), this.source.get(name)]
    if (this.pe !== null && name.startsWith('__imp_')) {
      const raw = name.slice(6)
      const imp = this.pe.imports
      const first = raw.slice(0, 1)
      const cands = [raw, raw.startsWith('_') ? raw.slice(1) : null,
        (first === '' || '_@'.includes(first)) ? raw.slice(1).replace(/@\p{Nd}+(?=\n?$)/u, '') : null]
      for (const c of cands) if (c && imp.has(c)) return [imp.get(c), 'import']
    }
    if (this.auto_names) {
      const m = GHIDRA_NAME.exec(name)
      if (m) return [parseInt(m[1], 16), 'ghidra-name']
    }
    return [null, null]
  }
}

function jsonLoads(text) {
  try {
    return jsonParse(text)
  } catch (e) {
    if (e instanceof SyntaxError) throw new ValueError(e.message)
    throw e
  }
}

// Ghidra index.json -> Map va -> size
export function load_function_list(path) {
  const obj = jsonLoads(readText(path, 'strict'))
  let funcs = obj
  if (obj instanceof Map) {
    if (!obj.has('functions')) throw new KeyError("'functions'")
    funcs = obj.get('functions')
  }
  const out = new Map()
  if (typeof funcs === 'number' || typeof funcs === 'boolean' || funcs === null || funcs instanceof PyFloat) {
    throw new TypeError(`'${pyTypeName(funcs)}' object is not iterable`)
  }
  const items = funcs instanceof Map ? [...funcs.keys()] : typeof funcs === 'string' ? Array.from(funcs) : funcs
  for (const e of items) {
    // out[parse_int(e['address'])] = int(e.get('size') or 0): the right-hand side is evaluated first
    if (!(e instanceof Map)) throw new AttributeError(`'${pyTypeName(e)}' object has no attribute 'get'`)
    try {
      const size = e.get('size')
      const n = pyIntOf(truthy(size) ? size : 0)
      if (!e.has('address')) continue                            // KeyError
      out.set(parse_int(e.get('address')), n)
    } catch (err) {
      if (err instanceof ValueError || err instanceof TypeError) continue
      throw err
    }
  }
  return out
}

// ----------------------------------------------------------------------------------------------- compare

function _u32(b, o) {
  if (o + 4 > b.length) {
    throw new StructError(`unpack_from requires a buffer of at least ${o + 4} bytes for unpacking 4 bytes at offset ${o} ` +
                          `(actual buffer size is ${b.length})`)
  }
  return b.readUInt32LE(o)
}
export const _s32 = (v) => ((v & 0x80000000) ? v - 0x100000000 : v)
const U = (v) => v >>> 0      // & 0xFFFFFFFF

// Compare obj function `sym` with the original at `va`. Returns a result object (see 'identical').
export function compare_function(obj, sym, pe, va, size = null, amap = null, known_starts = null, max_diffs = 64) {
  amap = amap || new AddrMap(pe)
  const [ob, rels] = obj.function_bytes(sym)
  const nObj = ob.length
  const nOrig = size === null || size === undefined ? nObj : size
  const span = Math.max(nObj, nOrig)
  let orig
  try {
    orig = pe.read(va, span + 16)
  } catch (e) {
    if (!(e instanceof PEError)) throw e
    return { symbol: sym.name, obj: obj.path, va, identical: false, status: 'error', error: e.message }
  }
  const maskObj = new Uint8Array(span)
  const maskOrig = new Uint8Array(span)
  const issues = []
  const res = { symbol: sym.name, obj: obj.path, va, obj_size: nObj, orig_size: nOrig, size_given: size !== null && size !== undefined }

  // obj relocations: mask, resolve, check
  const relAt = new Map()
  let checked = 0, inferredOnly = 0
  const inferred = new Map()
  const sources = {}
  for (const r of rels) {
    const rs = r.size
    for (let k = r.offset; k < Math.min(r.offset + rs, span); k++) maskObj[k] = 1
    if (!SUPPORTED_RELS.has(r.type)) {
      issues.push({ offset: r.offset, kind: 'unsupported_reloc',
                    detail: `relocation type ${r.type_name} to ${r.symbol ? r.symbol.name : r.symidx} is not supported` })
      continue
    }
    if (r.type === 0) continue
    relAt.set(r.offset, r)
    if (r.offset + rs > orig.length || r.offset + rs > nObj) continue
    const tsym = r.symbol
    if (tsym === null) {
      issues.push({ offset: r.offset, kind: 'bad_reloc', detail: `symbol index ${r.symidx} missing` })
      continue
    }
    const addend = rs === 4 ? _s32(_u32(ob, r.offset)) : ob.readInt16LE(r.offset)
    let tva = null, src = null
    if (tsym.secnum === -1) { tva = tsym.value; src = 'absolute' }
    else if (tsym.section === sym.section && tsym.defined) { tva = va - sym.value + tsym.value; src = 'same-section' }
    if (tva === null && !tsym.is_section_sym) [tva, src] = amap.resolve(tsym.name)
    const p = va + r.offset
    const val = rs === 4 ? _u32(orig, r.offset) : orig.readUInt16LE(r.offset)
    const what = `${r.type_name} -> ${tsym.name}` + (addend ? signedHex(addend) : '')
    let want, gotTarget
    if (r.type === DIR32) {
      want = tva === null ? null : U(tva + addend)
      gotTarget = U(val - addend)
    } else if (r.type === DIR32NB) {
      want = tva === null ? null : U(tva - pe.image_base + addend)
      gotTarget = U(val + pe.image_base - addend)
    } else if (r.type === REL32) {
      want = tva === null ? null : U(tva + addend - (p + 4))
      gotTarget = U(val + p + 4 - addend)
    } else if (r.type === SECREL) {
      const base = tva === null ? null : pe.section_base(tva)
      want = base === null ? null : U(tva - base + addend)
      gotTarget = null
    } else {   // SECTION
      const k = tva === null ? null : pe.section_index(tva)
      want = k === null ? null : k + 1
      gotTarget = null
    }
    if (want !== null) {
      checked++
      const key = ['absolute', 'same-section', 'import', 'ghidra-name'].includes(src) ? src : 'map'
      sources[key] = (sources[key] || 0) + 1
      if (val !== want) {
        issues.push({ offset: r.offset, kind: 'target_mismatch',
                      detail: `${what}: target 0x${tva.toString(16)} (${pyStr(src)}) expects field 0x${x08(want)}, ` +
                              `original has 0x${x08(val)}` +
                              (gotTarget !== null ? ` (-> 0x${gotTarget.toString(16)})` : '') })
      }
    } else if (gotTarget !== null) {
      inferredOnly++
      const prev = inferred.has(tsym.key) ? inferred.get(tsym.key) : null
      if (prev !== null && prev[0] !== gotTarget) {
        issues.push({ offset: r.offset, kind: 'inconsistent_target',
                      detail: `${what}: original implies 0x${gotTarget.toString(16)} but +0x${prev[1].toString(16)} ` +
                              `implies 0x${prev[0].toString(16)} for the same symbol` })
      } else if (!inferred.has(tsym.key)) {
        inferred.set(tsym.key, [gotTarget, r.offset])
      }
    }
    // base-relocation agreement
    if (pe.has_relocs && r.type === DIR32) {
      const hasFix = pe.fixups_set.has(p)
      if (tsym.secnum === -1 && hasFix) {
        issues.push({ offset: r.offset, kind: 'fixup_mismatch',
                      detail: `${what}: absolute symbol, but the original has a base relocation here` })
      } else if (tsym.secnum !== -1 && !hasFix) {
        issues.push({ offset: r.offset, kind: 'reloc_without_fixup',
                      detail: `${what}: obj has an absolute address, original has no base relocation ` +
                              'here (a constant, or code shifted)' })
      }
    } else if (pe.has_relocs && (r.type === REL32 || r.type === DIR32NB || r.type === SECREL) && pe.fixups_set.has(p)) {
      issues.push({ offset: r.offset, kind: 'fixup_mismatch',
                    detail: `${what}: original has an absolute address (base relocation) here` })
    }
  }

  // original fixups: mask; each must coincide with an obj DIR32
  let nfix = 0
  for (const f of pe.fixups_in(va, span)) {
    nfix++
    const o = f - va
    for (let k = Math.max(0, o); k < Math.min(o + 4, span); k++) maskOrig[k] = 1
    if (o >= 0 && o + 4 <= Math.min(nObj, nOrig)) {
      const r = relAt.has(o) ? relAt.get(o) : null
      if (r === null || r.type !== DIR32) {
        issues.push({ offset: o, kind: 'fixup_without_reloc',
                      detail: `original has an absolute address 0x${x08(_u32(orig, o))} (base relocation) ` +
                              'here; obj has ' + (r ? `${r.type_name}` : 'no relocation') })
      }
    }
  }

  // bytes
  const diffs = []
  const common = Math.min(nObj, nOrig)
  for (let i = 0; i < common; i++) {
    if (!(maskObj[i] || maskOrig[i])) {
      if (i >= orig.length) throw new IndexError('index out of range')
      if (ob[i] !== orig[i]) diffs.push(i)
    }
  }
  let padding = 0
  let sizeIssue = null
  if (nOrig > nObj) {
    const tail = orig.subarray(nObj, nOrig)
    const bad = []
    for (let k = 0; k < tail.length; k++) if (!isPad(tail[k])) bad.push(k)
    if (bad.length) {
      sizeIssue = [nObj + bad[0], `original is ${nOrig} bytes, obj function only ${nObj}; original continues ` +
                                  `with non-padding bytes at +0x${(nObj + bad[0]).toString(16)}`]
    } else padding = tail.length
  } else if (nObj > nOrig) {
    const extra = []
    for (let k = 0; k < nObj - nOrig; k++) {
      if (nOrig + k >= orig.length || ob[nOrig + k] !== orig[nOrig + k]) extra.push(nOrig + k)
    }
    let nonPad = false
    for (let k = nOrig; k < nObj; k++) if (!isPad(ob[k])) { nonPad = true; break }
    if (extra.length || nonPad) sizeIssue = [nOrig, `obj function is ${nObj} bytes, original size is ${nOrig}`]
    else padding = nObj - nOrig
  }
  if ((size === null || size === undefined) && sizeIssue === null) {
    const nxt = va + nObj
    if (!(known_starts && known_starts.has(nxt))) {
      if (nObj >= orig.length || !isPad(orig[nObj])) {
        if (!(nObj >= orig.length && pe.section_index(nxt) === null)) {
          const nb = nObj < orig.length ? orig[nObj] : null
          sizeIssue = [nObj, `original continues after the obj function end (+0x${nObj.toString(16)} is ` +
                             `${nb !== null ? nb.toString(16).padStart(2, '0') : 'end'}, not CC/90 padding nor a known ` +
                             'function start); pass a size or --functions to confirm the boundary']
        }
      }
    }
  }
  if (sizeIssue) issues.push({ offset: sizeIssue[0], kind: 'size', detail: sizeIssue[1] })

  const offsets = [...diffs, ...issues.map((i) => i.offset)]
  const identical = !offsets.length
  res.identical = identical
  res.status = identical ? 'identical' : 'different'
  res.first_diff = identical ? null : offsets.reduce((a, b) => (b < a ? b : a))
  res.diff_bytes = diffs.length
  res.diff_ranges = _ranges(diffs).slice(0, max_diffs)
  res.issues = issues
  res.relocs = rels.length
  res.relocs_checked = checked
  res.relocs_inferred = inferredOnly
  res.resolved_by = sources
  res.orig_fixups = nfix
  let masked = 0
  for (let i = 0; i < span; i++) if (maskObj[i] || maskOrig[i]) masked++
  res.masked_bytes = masked
  res.padding = padding
  res.inferred = new Map([...inferred].map(([k, v]) => [k, hex(v[0])]))
  if (identical) {
    res.ratio = 1.0
  } else {
    res.ratio = pyRound(_ratio(ob, orig.subarray(0, nOrig), maskObj, maskOrig), 4)
    res.context = hex_context(ob, orig.subarray(0, Math.max(nOrig, Math.min(orig.length, nObj))), maskObj, maskOrig,
                              res.first_diff, va)
  }
  return res
}

export function _ranges(idx) {
  const out = []
  for (const i of idx) {
    if (out.length && out[out.length - 1][1] === i) out[out.length - 1][1] = i + 1
    else out.push([i, i + 1])
  }
  return out
}

export function _ratio(a, b, ma, mb) {
  const ta = new Int32Array(a.length), tb = new Int32Array(b.length)
  for (let i = 0; i < a.length; i++) ta[i] = (i < ma.length && (ma[i] || mb[i])) ? 256 : a[i]
  for (let i = 0; i < b.length; i++) tb[i] = (i < ma.length && (ma[i] || mb[i])) ? 256 : b[i]
  if (ta.length * tb.length > 64_000_000) {     // very large: aligned compare only
    let same = 0
    for (let i = 0; i < Math.min(ta.length, tb.length); i++) if (ta[i] === tb[i]) same++
    return ta.length || tb.length ? 2.0 * same / (ta.length + tb.length) : 1.0
  }
  return new SequenceMatcher(null, ta, tb, false).ratio()
}

export function hex_context(a, b, ma, mb, at, va, before = 16, after = 32) {
  const row0 = Math.floor(at / 16) * 16
  const start = Math.max(0, row0 - before)
  const end = Math.min(Math.max(a.length, b.length), row0 + after)
  const lines = []
  const cell = (buf, i) => {
    if (i >= buf.length) return '  '
    return (i < ma.length && (ma[i] || mb[i])) ? '..' : buf[i].toString(16).padStart(2, '0')
  }
  for (let row = start; row < end; row += 16) {
    const ra = [], rb = [], mk = []
    for (let i = row; i < Math.min(row + 16, end); i++) {
      const ca = cell(a, i), cb = cell(b, i)
      ra.push(ca); rb.push(cb); mk.push(ca !== cb ? '^^' : '  ')
    }
    lines.push(`  obj  +${row.toString(16).padStart(4, '0')}  ${ra.join(' ')}`)
    lines.push(`  orig ${x08(va + row)} ${rb.join(' ')}`)
    const mks = mk.join(' ')
    if (pyStrip(mks)) lines.push(pyRstrip(`               ${mks}`))
  }
  return lines.join('\n')
}

export function format_result(r, verbose = true, all_diffs = false) {
  const head = `${r.symbol} [${basename(r.obj)}] vs 0x${r.va.toString(16)}: `
  if (r.status === 'error') return head + 'ERROR ' + r.error
  if (r.identical) {
    let s = head + `IDENTICAL  ${r.obj_size} bytes, ${r.relocs} relocs (${r.relocs_checked} target-checked, ` +
            `${r.relocs_inferred} inferred), ${r.orig_fixups} original fixups`
    if (r.padding) s += `, ${r.padding} padding bytes`
    return s
  }
  const out = [head + `DIFFERENT  ratio ${pyFormatFixed(Number(r.ratio), 4)}, first difference at +0x${r.first_diff.toString(16)} ` +
               `(0x${(r.va + r.first_diff).toString(16)}); sizes obj ${r.obj_size} / orig ${r.orig_size}, ` +
               `${r.diff_bytes} differing unmasked bytes`]
  if (verbose) {
    for (const i of r.issues.slice(0, 20)) out.push(`  +0x${i.offset.toString(16).padStart(4, '0')} ${i.kind}: ${i.detail}`)
    if (r.issues.length > 20) out.push(`  ... ${r.issues.length - 20} more issues`)
    if (all_diffs && r.diff_ranges.length) {
      out.push('  differing ranges: ' + r.diff_ranges.map(([a, b]) => `+0x${a.toString(16)}..+0x${b.toString(16)}`).join(', '))
    }
    out.push(r.context === undefined ? '' : pyStr(r.context))
  }
  return out.join('\n')
}

// ----------------------------------------------------------------------------------------------- names

export const OPS = new Map(Object.entries({
  0: '<ctor>', 1: '<dtor>', 2: '<op new>', 3: '<op delete>', 4: '<op=>', 5: '<op>>>',
  6: '<op<<>', 7: '<op!>', 8: '<op==>', 9: '<op!=>', A: '<op[]>', B: '<opcast>', C: '<op->>',
  D: '<op*>', E: '<op++>', F: '<op-->', G: '<op->', H: '<op+>', I: '<op&>', J: '<op->*>',
  K: '<op/>', L: '<op%>', M: '<op<>', N: '<op<=>', O: '<op>>', P: '<op>=>', Q: '<op,>',
  R: '<op()>', S: '<op~>', T: '<op^>', U: '<op|>', V: '<op&&>', W: '<op||>', X: '<op*=>',
  Y: '<op+=>', Z: '<op-=>', _0: '<op/=>', _1: '<op%=>', _2: '<op>>=>', _3: '<op<<=>',
  _4: '<op&=>', _5: '<op|=>', _6: '<op^=>', _7: '<vftable>', _8: '<vbtable>', _E: '<vdtor>',
  _G: '<sdtor>', _U: '<op new[]>', _V: '<op delete[]>' }))

const reCName = new RegExp(`^(?:[_@]?([A-Za-z_$][\\p{L}\\p{N}_$]*?)(?:@\\p{Nd}+)?)$`, 'u')

// Qualified-name parts (outer -> inner) of a decorated symbol, or null (templates, unparsable).
// ?Update@CUnit@@QAEXXZ -> ['CUnit','Update']; ??0CUnit@@QAE@XZ -> ['CUnit','<ctor>']; _foo@8 -> ['foo']
export function name_parts(name) {
  if (name.startsWith('__imp_')) return null
  if (!name.startsWith('?')) {
    const m = reCName.exec(name)
    return m ? [m[1]] : null
  }
  const s = name.slice(1)
  const names = []
  let first, rest
  if (s.startsWith('?')) {
    const code = s.slice(1, 2) === '_' ? s.slice(1, 3) : s.slice(1, 2)
    first = OPS.get(code)
    if (first === undefined) return null
    rest = s.slice(1 + code.length)
  } else if (s.startsWith('$')) {
    return null
  } else {
    const i = s.indexOf('@')
    if (i <= 0) return null
    first = s.slice(0, i)
    names.push(first)
    rest = s.slice(i + 1)
  }
  const scopes = []
  for (;;) {
    if (rest.startsWith('@')) break
    if (!rest) return null
    const c = rest[0]
    if (/[0-9\u00b2\u00b3\u00b9]/.test(c)) {
      if (!/[0-9]/.test(c)) throw new ValueError(`invalid literal for int() with base 10: ${pyReprStr(c)}`)
      const k = Number(c)
      if (k >= names.length) return null
      scopes.push(names[k])
      rest = rest.slice(1)
      continue
    }
    if (c === '?') {
      if (rest.startsWith('?$')) return null
      const j = rest.indexOf('@')
      if (j < 0) return null
      scopes.push(rest.startsWith('?A') ? '<anon>' : rest.slice(1, j))
      rest = rest.slice(j + 1)
      continue
    }
    const j = rest.indexOf('@')
    if (j < 0) return null
    names.push(rest.slice(0, j))
    scopes.push(rest.slice(0, j))
    rest = rest.slice(j + 1)
  }
  return [...scopes.reverse(), first]
}

export const SKIP_CALLS = new Set(['__declspec', '__attribute__', 'alignas', 'decltype', '__pragma', '_Pragma', 'if', 'while',
  'for', 'switch', 'return', 'sizeof', 'DECOMP_SIZE_ASSERT', 'static_assert'])
export const QUAL_CALL = new RegExp(
  `((?:~?[A-Za-z_]${W}*${S}*::${S}*)*(?:operator${S}*(?:\\(${S}*\\)|\\[${S}*\\]|new${S}*\\[${S}*\\]|delete${S}*\\[${S}*\\]|` +
  `new${NOTW_AFTER}|delete${NOTW_AFTER}|->\\*|->|[\\-+*/%^&|~!=<>,]+)|~?[A-Za-z_]${W}*))${S}*\\(`, 'gu')

// 'CUnit::Update' -> ['CUnit','Update']; 'A::A' -> ['A','<ctor>']; 'A::~A' -> ['A','<dtor>']
export function source_parts(qual) {
  if (qual.includes('<')) return null
  const parts = qual.split('::').map(pyStrip)
  const last = parts[parts.length - 1]
  if (last.startsWith('operator')) {
    let op = removeWS(last.slice(8))
    if (['new', 'delete', 'new[]', 'delete[]'].includes(op)) op = ' ' + op
    parts[parts.length - 1] = `<op${op}>`
  } else if (last.startsWith('~')) {
    parts[parts.length - 1] = '<dtor>'
  } else if (parts.length >= 2 && last === parts[parts.length - 2]) {
    parts[parts.length - 1] = '<ctor>'
  }
  return parts
}

// qualified function name from a definition's text (up to '{' or ';')
export function parse_definition(text) {
  for (const m of text.matchAll(QUAL_CALL)) {
    const g = m[1]
    const q = !g.includes('operator') ? removeWS(g) : pyStrip(g)
    const qs = q.split('::')
    if (SKIP_CALLS.has(qs[qs.length - 1])) continue
    return q
  }
  return null
}

// ----------------------------------------------------------------------------------------------- annotations

export const ANNOT = new RegExp(`^${S}*//${S}*(FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY|GLOBAL|VTABLE|STRING)${S}*:${S}*` +
                                `(?:([A-Za-z_][A-Za-z0-9_]*)${S}+)?0x([0-9A-Fa-f]+)${NOTW_AFTER}${S}*(.*?)${S}*$`, 'u')
export const SRC_EXT = ['.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx', '.inl', '.inc']
const FUNC_KINDS = ['FUNCTION', 'STUB', 'TEMPLATE', 'SYNTHETIC', 'LIBRARY']

export function* iter_sources(paths) {
  for (const p of paths) {
    if (isdir(p)) {
      for (const [root, dirs, files] of walk(p)) {
        dirs.sort(cmpStr)
        for (const f of [...files].sort(cmpStr)) {
          const fl = f.toLowerCase()
          if (SRC_EXT.some((e) => fl.endsWith(e))) yield pathJoin(root, f)
        }
      }
    } else yield p
  }
}

const reBrace = /[{;]/
export function scan_annotations(paths, module = null) {
  const out = []
  for (const path of iter_sources(paths)) {
    const lines = splitlines(readText(path, 'replace'))
    let i = 0
    while (i < lines.length) {
      let m = ANNOT.exec(lines[i])
      if (!m) { i++; continue }
      const group = []
      while (i < lines.length && (m = ANNOT.exec(lines[i]))) {
        group.push({ kind: m[1], module: m[2] === undefined ? null : m[2], va: parseInt(m[3], 16),
                     explicit: m[4] || null, file: path, line: i + 1 })
        i++
      }
      // following comment lines (reccmp puts names of SYNTHETIC/TEMPLATE/LIBRARY there), then the declaration
      let commentName = null
      let j = i
      while (j < lines.length && (!pyStrip(lines[j]) || pyStrip(lines[j]).startsWith('//'))) {
        if (commentName === null && pyStrip(lines[j]).startsWith('//')) commentName = pyStrip(pyStrip(lines[j]).slice(2)) || null
        j++
      }
      const decl = []
      let k = j
      while (k < lines.length && k < j + 12) {
        decl.push(lines[k])
        if (reBrace.test(lines[k]) || ANNOT.test(lines[k])) break
        k++
      }
      let text = decl.join(' ')
      const b = text.search(reBrace)
      if (b >= 0) text = text.slice(0, b)
      for (const a of group) {
        if (module && a.module && a.module !== module) continue
        a.decl = pyStrip(text)
        a.comment_name = commentName
        out.push(a)
      }
    }
  }
  return out
}

const reVtable = new RegExp(`${NOTW_BEFORE}(?:class|struct)${S}+(?:__declspec\\([^)]*\\)${S}*)?([A-Za-z_]${W}*(?:${S}*::${S}*[A-Za-z_]${W}*)*)`, 'u')
const reGlobalFnPtr = new RegExp(`\\(${S}*\\*${S}*([A-Za-z_]${W}*(?:::[A-Za-z_]${W}*)*)${S}*\\)`, 'u')
const reGlobalVar = new RegExp(`((?:[A-Za-z_]${W}*${S}*::${S}*)*[A-Za-z_]${W}*)${S}*(?:\\[[^\\]]*\\]${S}*)*$`, 'u')
const cpSlice = (s, a, b) => Array.from(s).slice(a, b).join('')

// expected name parts for an annotation: [parts, qualified name] or [null, reason]
export function decl_parts(a) {
  const kind = a.kind
  if (kind === 'FUNCTION' || kind === 'STUB') {
    const q = parse_definition(a.decl)
    if (!q) return [null, `no function definition found after the annotation: ${pyReprStr(cpSlice(a.decl, 0, 80))}`]
    const p = source_parts(q)
    return p ? [p, q] : [null, `templates are not mapped automatically (${q}); add the decorated symbol`]
  }
  if (kind === 'TEMPLATE' || kind === 'SYNTHETIC' || kind === 'LIBRARY') {
    let nm = a.comment_name || ''
    nm = nm.replaceAll("`scalar deleting destructor'", '<sdtor>').replaceAll("`vector deleting destructor'", '<vdtor>')
    if (!nm) return [null, `${kind} needs the name on the next comment line or a decorated symbol`]
    if (nm.replaceAll('<sdtor>', '').replaceAll('<vdtor>', '').includes('<')) {
      return [null, `templates are not mapped automatically (${nm}); add the decorated symbol`]
    }
    const parts = nm.split('::').map(pyStrip)
    return [parts[parts.length - 1].startsWith('<') ? parts : source_parts(nm), nm]
  }
  if (kind === 'VTABLE') {
    const m = reVtable.exec(a.decl)
    if (!m) return [null, 'no class/struct after VTABLE annotation']
    const q = removeWS(m[1])
    return [[...q.split('::'), '<vftable>'], q]
  }
  if (kind === 'GLOBAL') {
    const t = a.decl.split('=')[0]
    const m = reGlobalFnPtr.exec(t) || reGlobalVar.exec(pyStrip(t))
    if (!m) return [null, 'no variable name found after GLOBAL annotation']
    const q = removeWS(m[1])
    return [q.split('::'), q]
  }
  return [null, `${kind} annotations are listed only`]
}

export const obj_stem = (path) => splitext(basename(path))[0].toLowerCase()

// fill a.symbol, a.objpath or a.status = 'unmapped'/'ambiguous' with a.error
export function map_annotation(a, objs, all_names) {
  const stem = obj_stem(a.file)
  const isFunc = FUNC_KINDS.includes(a.kind)
  const sameTu = objs.filter((o) => obj_stem(o.path) === stem)
  let pool
  if (isFunc) {
    pool = []
    for (const o of (sameTu.length ? sameTu : objs)) for (const s of o.functions()) pool.push([o, s])
    if (sameTu.length && a.explicit) {
      for (const o of objs) if (!sameTu.includes(o)) for (const s of o.functions()) pool.push([o, s])
    }
  } else pool = all_names.map(([o, s]) => [o, s])
  const explicit = a.explicit ? pySplitWS(a.explicit)[0] : null
  if (explicit && ('?_@'.includes(explicit[0]) || pool.some(([, s]) => s.name === explicit))) {
    const hits = pool.filter(([, s]) => s.name === explicit)
    if (!hits.length) {
      a.status = 'unmapped'; a.error = `explicit symbol ${explicit} not found in the objects`
      return
    }
    a.symbol = explicit; a.objpath = hits[0][0].path
    a.candidates_objs = sortedUnique(hits.map(([o]) => o.path))
    a.status = 'mapped'
    return
  }
  const [parts, q] = decl_parts(a)
  if (parts === null) {
    a.status = 'unmapped'; a.error = q
    return
  }
  a.source_name = q
  const want = parts
  let hits
  if (a.kind === 'VTABLE' && explicit) {
    const pre = '??_7' + want.slice(0, -1).reverse().join('@') + '@@6B'
    hits = pool.filter(([, s]) => s.name.startsWith(pre) && s.name.includes(`${explicit}@@`))
  } else {
    hits = pool.filter(([, s]) => tupleEq(name_parts(s.name), want))
  }
  const names = sortedUnique(hits.map(([, s]) => s.name))
  if (!names.length) {
    const last = want[want.length - 1]
    const near = sortedUnique(pool.filter(([, s]) => { const np = name_parts(s.name) || ['']; return np[np.length - 1] === last })
      .map(([, s]) => s.name)).slice(0, 6)
    a.status = 'unmapped'
    a.error = `no symbol for ${q} ` + (near.length ? `(same name in other scopes: ${near.join(', ')})`
      : `in ${(sameTu.length ? sameTu : objs).map((o) => basename(o.path)).join(', ') || 'no objects'}`)
    return
  }
  if (names.length > 1) {
    a.status = 'ambiguous'
    a.error = `${q} matches ${names.length} symbols: ${names.slice(0, 8).join(', ')}; put the decorated name on the ` +
              'annotation line'
    return
  }
  a.symbol = names[0]
  a.objpath = hits[0][0].path
  a.candidates_objs = sortedUnique(hits.map(([o]) => o.path))
  a.status = 'mapped'
}

export function collect_objs(paths) {
  const files = []
  for (const p of paths) {
    if (isdir(p)) {
      for (const [root, dirs, fs] of walk(p)) {
        dirs.sort(cmpStr)
        for (const f of [...fs].sort(cmpStr)) if (f.toLowerCase().endsWith('.obj')) files.push(pathJoin(root, f))
      }
    } else files.push(p)
  }
  return files
}

// ----------------------------------------------------------------------------------------------- output

let OUT = process.stdout                 // print() target (stderr while JSON goes to stdout)
const print = (s = '') => OUT.write(s + '\n')
const eprint = (s) => process.stderr.write(s + '\n')

// json.dumps(obj, indent=1, default=str): 'ratio' values are Python floats
function toPyJson(v, key = null) {
  if (key === 'ratio' && typeof v === 'number') return pyFloat(v)
  if (Array.isArray(v)) return v.map((x) => toPyJson(x))
  if (v instanceof Map) return new Map([...v].map(([k, x]) => [k, toPyJson(x, k)]))
  if (v !== null && typeof v === 'object' && !(v instanceof PyFloat) && !Buffer.isBuffer(v)) {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toPyJson(x, k)]))
  }
  return v
}
function _write_json(path, obj) {
  const text = dumps(toPyJson(obj), { indent: 1 })
  if (path === '-') process.stdout.write(text + '\n')
  else writeFileSync(path, text + '\n')
}

function run_report(args) {
  let pe
  try {
    pe = new PEImage(args.pe)
  } catch (e) {
    if (!(e instanceof OSError || e instanceof PEError)) throw e
    eprint(`objcmp: ${args.pe}: ${e.message}`)
    return 2
  }
  const objs = [], loadErrors = []
  for (const f of collect_objs(args.obj)) {
    try {
      objs.push(read_coff(f))
    } catch (e) {
      if (!(e instanceof OSError || e instanceof CoffError || e instanceof StructError)) throw e
      loadErrors.push(`${f}: ${e.message}`)
    }
  }
  for (const e of loadErrors) eprint(`objcmp: ${e}`)
  const amap = new AddrMap(pe, !args.no_auto_names)
  let flist
  try {
    for (const m of args.map || []) amap.load(m)
    flist = args.functions ? load_function_list(args.functions) : new Map()
  } catch (e) {
    if (!(e instanceof OSError || e instanceof ValueError || e instanceof KeyError)) throw e
    eprint(`objcmp: address map: ${e.message}`)
    return 2
  }
  const annots = scan_annotations(args.src, args.module)
  const allNames = []
  for (const o of objs) {
    for (const s of o.symbols.values()) {
      if (!s.is_section_sym && [CLASS_EXTERNAL, CLASS_STATIC, CLASS_WEAK].includes(s.storage)) allNames.push([o, s])
    }
  }
  const seenVa = new Map()
  for (const a of annots) {
    if (a.kind === 'STRING') { a.status = 'listed'; continue }
    map_annotation(a, objs, allNames)
    if (a.status === 'mapped') amap.add(a.symbol, a.va, `${a.file}:${a.line}`)
    if (FUNC_KINDS.includes(a.kind)) {
      const key = `${a.module === null ? '\u0000' : 's' + a.module}\u0001${a.va}`
      if (seenVa.has(key)) {
        a.status = 'error'
        a.error = `address 0x${a.va.toString(16)} already annotated at ${seenVa.get(key)}`
      } else seenVa.set(key, `${a.file}:${a.line}`)
    }
  }
  const knownStarts = new Set([...flist.keys(), ...annots.filter((a) => FUNC_KINDS.includes(a.kind)).map((a) => a.va)])
  const byPath = new Map(objs.map((o) => [o.path, o]))
  const funcs = [], globs = []
  const inferredAll = new Map()
  const get = (o, k) => (o[k] === undefined ? null : o[k])
  for (const a of annots) {
    if (!FUNC_KINDS.includes(a.kind)) {
      const g = {}
      for (const k of ['kind', 'module', 'file', 'line', 'symbol', 'status', 'error']) g[k] = get(a, k)
      g.va = hex(a.va)
      globs.push(g)
      continue
    }
    const e = { kind: a.kind, module: a.module, va: a.va, file: a.file, line: a.line, symbol: get(a, 'symbol'), status: a.status }
    if (a.kind === 'STUB' && a.status !== 'error') {
      e.status = 'stub'
      e.orig_size = flist.has(a.va) ? flist.get(a.va) : null
      funcs.push(e)
      continue
    }
    if (a.status !== 'mapped') {
      e.error = get(a, 'error')
      e.orig_size = flist.has(a.va) ? flist.get(a.va) : null
      funcs.push(e)
      continue
    }
    const o = byPath.get(a.objpath)
    const sym = o.find(a.symbol)[0]
    const r = compare_function(o, sym, pe, a.va, null, amap, knownStarts)
    for (const k of ['status', 'identical', 'ratio', 'obj_size', 'orig_size', 'first_diff', 'diff_bytes', 'issues', 'relocs',
                     'relocs_checked', 'relocs_inferred', 'orig_fixups', 'padding', 'error', 'context']) e[k] = get(r, k)
    e.obj = o.path
    if ((a.candidates_objs || []).length > 1) e.note = `symbol defined in ${a.candidates_objs.length} objects; compared ${o.path}`
    for (const [k, v] of (r.inferred || new Map())) {
      if (!inferredAll.has(k)) inferredAll.set(k, new Map())
      const m = inferredAll.get(k)
      if (!m.has(v)) m.set(v, [])
      m.get(v).push(hex(a.va))
    }
    funcs.push(e)
  }
  // summary
  const compared = funcs.filter((f) => f.status === 'identical' || f.status === 'different')
  const ident = compared.filter((f) => f.status === 'identical')
  const failed = funcs.filter((f) => f.status !== 'identical' && f.status !== 'stub')
  const bytesTotal = funcs.reduce((n, f) => n + (f.orig_size || 0), 0)
  const bytesIdent = ident.reduce((n, f) => n + f.orig_size, 0)
  const cross = new Map([...inferredAll].filter(([, v]) => v.size > 1))
  const summary = { annotated_functions: funcs.length, compared: compared.length, identical: ident.length,
                    different: compared.length - ident.length, stubs: funcs.filter((f) => f.status === 'stub').length,
                    unmapped: funcs.filter((f) => ['unmapped', 'ambiguous', 'error'].includes(f.status)).length,
                    bytes_identical: bytesIdent, bytes_total: bytesTotal, objects: objs.length,
                    object_errors: loadErrors, pe_has_relocs: pe.has_relocs }
  for (const f of funcs) {
    const tag = { identical: 'OK', different: 'DIFF', stub: 'STUB' }[f.status] || f.status.toUpperCase()
    const ratio = f.ratio !== null && f.ratio !== undefined ? pyFormatFixed(100 * f.ratio, 2).padStart(6) + '%' : '      -'
    const size = String(f.obj_size || f.orig_size || 0).padStart(6)
    let line = `${tag.padEnd(9)} 0x${x08(f.va)} ${ratio} ${size}  ${f.symbol || '-'}`
    if (f.status === 'different') {
      line += `  first diff +0x${f.first_diff.toString(16)}`
      if (f.issues && f.issues.length) line += ` (${f.issues[0].kind})`
    } else if (f.error) {
      line += `  ${f.error}`
    }
    const rp = relpath(f.file)
    line += `  [${rp.startsWith('..') ? f.file : rp}:${f.line}]`
    if (!args.quiet || f.status !== 'identical') print(line)
    if (args.verbose && f.status === 'different') {
      for (const i of f.issues.slice(0, 10)) print(`      +0x${i.offset.toString(16).padStart(4, '0')} ${i.kind}: ${i.detail}`)
      print(f.context === undefined ? '' : pyStr(f.context))
    }
  }
  for (const g of globs) {
    print(pyRstrip(`${g.kind.padEnd(9)} ${g.va.padStart(10)} ${g.symbol || '-'}  ${g.error || ''}`))
  }
  for (const c of amap.conflicts) {
    print(`CONFLICT  ${c.symbol}: ${c.addresses.join(', ')} from ${c.sources.map(pyStr).join(', ')}`)
  }
  for (const [k, v] of cross) {
    print(`WARNING   ${k} inferred at different addresses: ` + [...v].map(([t, fs]) => `${t} in ${fs.join(',')}`).join('; '))
  }
  const pct = (a, b) => (b ? `${pyFormatFixed(100.0 * a / b, 1)}%` : '-')
  print(`functions identical: ${ident.length}/${funcs.length} (${pct(ident.length, funcs.length)}), compared ${compared.length}, ` +
        `unmapped/ambiguous ${summary.unmapped}, stubs ${summary.stubs}; bytes identical: ${bytesIdent}/` +
        `${bytesTotal} (${pct(bytesIdent, bytesTotal)})`)
  if (!pe.has_relocs) print('note: the PE has no .reloc; original-side masking relies on obj relocations only')
  if (args.json) {
    const out = { pe: args.pe, module: args.module, summary, functions: funcs, data: globs,
                  address_conflicts: amap.conflicts,
                  inferred_symbols: new Map([...inferredAll].filter(([, v]) => v.size === 1).map(([k, v]) => [k, [...v.keys()][0]])),
                  inferred_conflicts: cross }
    for (const f of funcs) f.va = hex(f.va)
    _write_json(args.json, out)
  }
  const ok = !failed.length && !amap.conflicts.length && !loadErrors.length
  return ok ? 0 : 1
}

// ----------------------------------------------------------------------------------------------- dump

export function dump_obj(o) {
  const out = [`${o.path}: ${o.bigobj ? 'bigobj' : 'COFF'} i386, ${o.sections.length} sections, ` +
               `${o.symbols.size} symbols (+aux), timestamp 0x${x08(o.timestamp)}`, '', 'Sections:']
  for (const s of o.sections) {
    let c = ''
    if (s.comdat) {
      c = ` COMDAT ${COMDAT_NAMES.has(s.comdat) ? COMDAT_NAMES.get(s.comdat) : s.comdat}` + (s.comdat === 5 ? ` assoc=${s.assoc}` : '')
    }
    out.push(`  #${String(s.number).padEnd(3)} ${s.name.padEnd(12)} size ${String(s.size).padStart(6)} ` +
             `relocs ${String(s.relocs.length).padStart(4)} ${scn_flags(s.characteristics)}${c}`)
  }
  out.push('', 'Symbols:')
  for (const sym of o.symbols.values()) {
    const sec = { 0: 'UNDEF', '-1': 'ABS', '-2': 'DEBUG' }[sym.secnum] || `#${sym.secnum}`
    let extra = ''
    if (sym.is_function) extra = ` FUNCTION size ${sym.size}`
    else if (sym.is_section_sym) extra = ' (section)'
    else if (sym.weak_default !== null) extra = ` weak -> [${sym.weak_default}]`
    const cls = CLASS_NAMES.has(sym.storage) ? CLASS_NAMES.get(sym.storage) : String(sym.storage)
    out.push(`  [${String(sym.index).padStart(4)}] ${sec.padStart(6)} ${x08(sym.value)} type ${sym.type.toString(16).padStart(4, '0')} ` +
             `${cls.padEnd(9)} ${sym.name}${extra}`)
  }
  out.push('', 'Relocations:')
  for (const s of o.sections) {
    for (const r of s.relocs) {
      const nm = r.symbol ? r.symbol.name : `?${r.symidx}`
      const sz = r.size
      const inplace = s.data.length ? s.data.subarray(r.offset, r.offset + sz) : Buffer.alloc(0)
      const add = sz === 4 && inplace.length === 4 ? ` addend ${signedHex(_s32(inplace.readUInt32LE(0)))}` : ''
      const flag = SUPPORTED_RELS.has(r.type) ? '' : '  UNSUPPORTED'
      out.push(`  #${String(s.number).padEnd(3)} +${r.offset.toString(16).padStart(6, '0')} ${r.type_name.padEnd(8)} ` +
               `[${r.symidx}] ${nm}${add}${flag}`)
    }
  }
  return out.join('\n')
}

export function dump_json(o) {
  return { path: o.path, bigobj: o.bigobj, machine: o.machine,
           sections: o.sections.map((s) => ({ number: s.number, name: s.name, size: s.size, characteristics: s.characteristics,
                                               comdat: s.comdat, assoc: s.assoc, checksum: s.checksum,
                                               relocs: s.relocs.map((r) => ({ offset: r.offset, type: r.type_name,
                                                                              symbol: r.symbol ? r.symbol.name : r.symidx })) })),
           symbols: [...o.symbols.values()].map((s) => ({ index: s.index, name: s.name, value: s.value, section: s.secnum,
                                                          type: s.type, class: s.storage, naux: s.naux, function: s.is_function,
                                                          size: s.size })) }
}

// ----------------------------------------------------------------------------------------------- writer

function _align_flag(n) {
  if (n && (n & (n - 1)) === 0) return (Math.floor(Math.log2(n)) + 1) << 20
  return 0x00500000
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1
    t[n] = c >>> 0
  }
  return t
})()
export function jamcrc(data) {
  let c = 0xFFFFFFFF
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]) & 0xFF] ^ (c >>> 8)
  return c >>> 0           // crc32 ^ 0xFFFFFFFF
}

const has = (o, k) => o instanceof Map ? o.has(k) : Object.prototype.hasOwnProperty.call(o, k)
const getd = (o, k, d = null) => (has(o, k) ? (o instanceof Map ? o.get(k) : o[k]) : d)

// Write an i386 COFF object (see objcmp.py write_obj). functions: [{name, bytes, relocations: [{offset, type
// ('DIR32'|'REL32'|'DIR32NB'|'SECREL'|'SECTION'|int), symbol, addend}], static, selection, section, align}];
// options: {data, absolutes, bigobj = false, comdat = true, text_name, timestamp = 0, align = 16}.
// Returns the bytes written.
export function write_obj(path, functions = [], { data = [], absolutes = null, bigobj = false, comdat = true, text_name = null,
                                                  timestamp = 0, align = 16 } = {}) {
  absolutes = absolutes instanceof Map ? new Map(absolutes) : new Map(Object.entries(absolutes || {}))
  const secs = []
  if (comdat) {
    const tname = text_name || '.text$mn'
    for (const f of functions) {
      const al = getd(f, 'align', align)
      secs.push({ name: getd(f, 'section', tname),
                  ch: (SCN_CNT_CODE | SCN_LNK_COMDAT | SCN_EXEC | SCN_READ | _align_flag(al)) >>> 0,
                  data: Buffer.from(getd(f, 'bytes')), relocs: [], syms: [[getd(f, 'name'), 0, getd(f, 'static'), true]],
                  sel: getd(f, 'selection', 1) })
      for (const r of getd(f, 'relocations', [])) {
        secs[secs.length - 1].relocs.push([getd(r, 'offset'), getd(r, 'symbol'), rel_type(getd(r, 'type')), getd(r, 'addend')])
      }
    }
  } else if (functions.length) {
    const sec = { name: text_name || '.text', ch: (SCN_CNT_CODE | SCN_EXEC | SCN_READ | _align_flag(align)) >>> 0,
                  data: Buffer.alloc(0), relocs: [], syms: [], sel: 0 }
    for (const f of functions) {
      const base = sec.data.length
      sec.data = Buffer.concat([sec.data, Buffer.from(getd(f, 'bytes'))])
      sec.syms.push([getd(f, 'name'), base, getd(f, 'static'), true])
      for (const r of getd(f, 'relocations', [])) {
        sec.relocs.push([base + getd(r, 'offset'), getd(r, 'symbol'), rel_type(getd(r, 'type')), getd(r, 'addend')])
      }
    }
    secs.push(sec)
  }
  for (const dd of data) {
    const sname = getd(dd, 'section', '.data')
    const al = getd(dd, 'align', 4)
    if (sname.startsWith('.bss')) {
      const ch = (SCN_CNT_UDATA | SCN_READ | SCN_WRITE | _align_flag(al)) >>> 0
      secs.push({ name: sname, ch, data: null, size: getd(dd, 'size', getd(dd, 'bytes', Buffer.alloc(0)).length),
                  relocs: [], syms: [[getd(dd, 'name'), 0, getd(dd, 'static'), false]], sel: 0 })
      continue
    }
    const ch = (SCN_CNT_IDATA | SCN_READ | _align_flag(al) | (sname.startsWith('.rdata') ? 0 : SCN_WRITE)) >>> 0
    secs.push({ name: sname, ch, data: Buffer.from(getd(dd, 'bytes')), relocs: [],
                syms: [[getd(dd, 'name'), 0, getd(dd, 'static'), false]], sel: 0 })
    for (const r of getd(dd, 'relocations', [])) {
      secs[secs.length - 1].relocs.push([getd(r, 'offset'), getd(r, 'symbol'), rel_type(getd(r, 'type')), getd(r, 'addend')])
    }
  }

  // in-place addends
  for (const s of secs) {
    for (const [off, , t, add] of s.relocs) {
      if (add !== null && add !== undefined && s.data !== null) {
        if (REL_SIZE.get(t) === 4) { if (add < 0) s.data.writeInt32LE(add, off); else s.data.writeUInt32LE(add, off) }
        else if (REL_SIZE.get(t) === 2) { if (add < 0) s.data.writeInt16LE(add, off); else s.data.writeUInt16LE(add, off) }
      }
    }
  }

  const strtab = [Buffer.alloc(4)]
  let strLen = 4
  const strOff = new Map()
  const strref = (nm) => {
    if (!strOff.has(nm)) {
      strOff.set(nm, strLen)
      const b = Buffer.concat([encodeLatin1(nm), Buffer.alloc(1)])
      strtab.push(b)
      strLen += b.length
    }
    return strOff.get(nm)
  }
  const ljust8 = (b) => (b.length >= 8 ? b : Buffer.concat([b, Buffer.alloc(8 - b.length)]))
  const symName = (nm) => {
    const b = encodeLatin1(nm)
    return b.length <= 8 ? ljust8(b) : pack('<II', 0, strref(nm))
  }
  const secName = (nm) => {
    const b = encodeLatin1(nm)
    return b.length <= 8 ? ljust8(b) : ljust8(Buffer.from(`/${strref(nm)}`, 'ascii'))
  }

  const symsize = bigobj ? 20 : 18
  const symfmt = bigobj ? '<8sIiHBB' : '<8sIhHBB'
  const records = []
  const index = new Map()
  const addSym = (nm, value, secnum, typ, storage, aux = []) => {
    const idx = records.length
    records.push(pack(symfmt, symName(nm), U(value), secnum, typ, storage, aux.length))
    for (const a of aux) records.push(a.length >= symsize ? a : Buffer.concat([a, Buffer.alloc(symsize - a.length)]))
    return idx
  }

  // section symbols + defined symbols (the COMDAT symbol right after its section symbol)
  secs.forEach((s, k) => {
    const i = k + 1
    const raw = s.data !== null ? s.data : Buffer.alloc(0)
    const size = s.data !== null ? raw.length : s.size
    s.size = size
    const nrel = s.relocs.length
    const aux = bigobj ? pack('<IHHIHBBH', size, Math.min(nrel, 0xFFFF), 0, jamcrc(raw), 0, s.sel, 0, 0)
      : pack('<IHHIHB', size, Math.min(nrel, 0xFFFF), 0, jamcrc(raw), 0, s.sel)
    addSym(s.name, 0, i, 0, CLASS_STATIC, [aux])
    for (const [nm, off, isStatic, func] of s.syms) {
      if (index.has(nm)) throw new ValueError(`symbol ${nm} defined twice`)
      index.set(nm, addSym(nm, off, i, func ? 0x20 : 0, isStatic ? CLASS_STATIC : CLASS_EXTERNAL))
    }
  })
  for (const [nm, v] of absolutes) index.set(nm, addSym(nm, v, -1, 0, nm.startsWith('@') ? CLASS_STATIC : CLASS_EXTERNAL))
  for (const s of secs) {
    for (const [, nm, t] of s.relocs) {
      if (!index.has(nm)) index.set(nm, addSym(nm, 0, 0, t === REL32 ? 0x20 : 0, CLASS_EXTERNAL))
    }
  }

  const hdrSize = bigobj ? 56 : 20
  let pos = hdrSize + 40 * secs.length
  const layout = []
  for (const s of secs) {
    let rawptr = 0
    if (s.data !== null && s.size) { rawptr = pos; pos += s.size }
    let relptr = 0
    const nrel = s.relocs.length
    if (nrel) { relptr = pos; pos += 10 * (nrel + (nrel >= 0xFFFF ? 1 : 0)) }
    layout.push([rawptr, relptr])
  }
  const symptr = pos
  const nsyms = records.length

  const out = []
  let outLen = 0
  const emit = (b) => { out.push(b); outLen += b.length }
  if (bigobj) {
    emit(pack('<HHHHI16sIIII', 0, 0xFFFF, 2, MACHINE_I386, timestamp, BIGOBJ_CLSID, 0, 0, 0, 0))
    emit(pack('<III', secs.length, symptr, nsyms))
  } else {
    emit(pack('<HHIIIHH', MACHINE_I386, secs.length, timestamp, symptr, nsyms, 0, 0))
  }
  const secNames = secs.map((s) => secName(s.name))    // may extend strtab; fine (strtab written last)
  secs.forEach((s, k) => {
    const [rawptr, relptr] = layout[k]
    const nrel = s.relocs.length
    const ch = (s.ch | (nrel >= 0xFFFF ? SCN_NRELOC_OVFL : 0)) >>> 0
    emit(pack('<8sIIIIIIHHI', secNames[k], 0, 0, s.size, rawptr, relptr, 0, nrel >= 0xFFFF ? 0xFFFF : nrel, 0, ch))
  })
  secs.forEach((s, k) => {
    const [rawptr, relptr] = layout[k]
    if (rawptr) {
      if (outLen !== rawptr) throw new Error('AssertionError')
      emit(Buffer.from(s.data))
    }
    if (relptr) {
      if (outLen !== relptr) throw new Error('AssertionError')
      if (s.relocs.length >= 0xFFFF) emit(pack('<IIH', s.relocs.length + 1, 0, 0))
      for (const [off, nm, t] of s.relocs) emit(pack('<IIH', off, index.get(nm), t))
    }
  })
  if (outLen !== symptr) throw new Error('AssertionError')
  for (const rec of records) emit(rec)
  const st = Buffer.concat(strtab)
  st.writeUInt32LE(st.length, 0)
  emit(st)
  const bytes = Buffer.concat(out)
  writeFileSync(path, bytes)
  return bytes
}

// ----------------------------------------------------------------------------------------------- CLI

export function resolve_symbol(obj, spec) {
  const hits = obj.find(spec)
  if (hits.length) return [hits[0], null]
  const q = spec.includes('::') || new RegExp(`^[A-Za-z_]${W}*$`, 'u').test(spec) ? spec : null
  const want = q ? source_parts(q) : null
  if (want) {
    const cands = obj.functions().filter((s) => tupleEq(name_parts(s.name), want))
    const names = sortedUnique(cands.map((s) => s.name))
    if (names.length === 1) return [cands[0], null]
    if (cands.length) return [null, `${spec} is ambiguous: ` + names.join(', ')]
  }
  const fs = obj.functions()
  return [null, `no function symbol ${spec} in ${obj.path} (functions: ` + fs.slice(0, 12).map((s) => s.name).join(', ') +
                (fs.length > 12 ? ' ...' : '') + ')']
}

function run_compare(args) {
  let obj, pe, va, size, amap, flist
  try {
    obj = read_coff(args.obj)
    pe = new PEImage(args.pe)
    va = parse_int(args.va)
    size = args.size ? parse_int(args.size, false) : null
    amap = new AddrMap(pe, !args.no_auto_names)
    for (const m of args.map || []) amap.load(m)
    flist = args.functions ? load_function_list(args.functions) : new Map()
  } catch (e) {
    if (!(e instanceof OSError || e instanceof CoffError || e instanceof PEError || e instanceof ValueError ||
          e instanceof KeyError || e instanceof StructError)) throw e
    eprint(`objcmp: ${e.message}`)
    return 2
  }
  const [sym, err] = resolve_symbol(obj, args.symbol)
  if (sym === null) {
    eprint(`objcmp: ${err}`)
    return 2
  }
  const r = compare_function(obj, sym, pe, va, size, amap, new Set(flist.keys()))
  print(format_result(r, true, args.all_diffs))
  if (args.json) _write_json(args.json, r)
  if (r.status === 'error') return 2
  return r.identical ? 0 : 1
}

function run_dump(args) {
  let o
  try {
    o = read_coff(args.obj)
  } catch (e) {
    if (!(e instanceof OSError || e instanceof CoffError || e instanceof StructError)) throw e
    eprint(`objcmp: ${args.obj}: ${e.message}`)
    return 2
  }
  print(dump_obj(o))
  if (args.json) _write_json(args.json, dump_json(o))
  return 0
}

// argparse texts exactly as Python 3.9 prints them (80 columns)
const MAIN_USAGE = 'usage: objcmp.py [-h] {compare,report,dump} ...\n'
const MAIN_HELP = MAIN_USAGE + `
objcmp.py - compare functions in MSVC COFF objects (cl.exe /c) with the original 32-bit PE, byte for byte.

positional arguments:
  {compare,report,dump}
    compare             compare one obj function with the original at a VA
    report              compare every annotated function
    dump                sections, symbols and relocations of an object

optional arguments:
  -h, --help            show this help message and exit
`
const COMPARE_USAGE = `usage: objcmp.py compare [-h] [--map MAP] [--functions FUNCTIONS]
                         [--no-auto-names] [--json JSON] [--all-diffs]
                         obj symbol pe va [size]
`
const COMPARE_HELP = COMPARE_USAGE + `
positional arguments:
  obj
  symbol
  pe
  va
  size

optional arguments:
  -h, --help            show this help message and exit
  --map MAP             address map file (repeatable)
  --functions FUNCTIONS
                        Ghidra index.json: known function starts (end-of-
                        function checks)
  --no-auto-names       do not resolve FUN_/DAT_<hex> names
  --json JSON           write JSON results (- for stdout)
  --all-diffs           list every differing byte range
`
const REPORT_USAGE = `usage: objcmp.py report [-h] --pe PE --src SRC [SRC ...] --obj OBJ [OBJ ...]
                        [--module MODULE] [--verbose] [--quiet] [--map MAP]
                        [--functions FUNCTIONS] [--no-auto-names]
                        [--json JSON]
`
const REPORT_HELP = REPORT_USAGE + `
optional arguments:
  -h, --help            show this help message and exit
  --pe PE
  --src SRC [SRC ...]
  --obj OBJ [OBJ ...]
  --module MODULE
  --verbose, -v         issues and hex context for each difference
  --quiet, -q           do not list identical functions
  --map MAP             address map file (repeatable)
  --functions FUNCTIONS
                        Ghidra index.json: known function starts (end-of-
                        function checks)
  --no-auto-names       do not resolve FUN_/DAT_<hex> names
  --json JSON           write JSON results (- for stdout)
`
const DUMP_USAGE = 'usage: objcmp.py dump [-h] [--json JSON] obj\n'
const DUMP_HELP = DUMP_USAGE + `
positional arguments:
  obj

optional arguments:
  -h, --help   show this help message and exit
  --json JSON
`

export function main(argv = process.argv.slice(2)) {
  const ap = new ArgumentParser({ prog: 'objcmp.py', usage: MAIN_USAGE, help: MAIN_HELP })
  const sub = ap.add_subparsers({ dest: 'cmd' })
  const c = sub.add_parser('compare', { usage: COMPARE_USAGE, help: COMPARE_HELP })
  c.add_argument('obj')
  c.add_argument('symbol')
  c.add_argument('pe')
  c.add_argument('va')
  c.add_argument('size', { nargs: '?' })
  const r = sub.add_parser('report', { usage: REPORT_USAGE, help: REPORT_HELP })
  r.add_argument('--pe', { required: true })
  r.add_argument('--src', { nargs: '+', required: true })
  r.add_argument('--obj', { nargs: '+', required: true })
  r.add_argument('--module')
  r.add_argument('--verbose', '-v', { action: 'store_true' })
  r.add_argument('--quiet', '-q', { action: 'store_true' })
  for (const p of [c, r]) {
    p.add_argument('--map', { action: 'append' })
    p.add_argument('--functions')
    p.add_argument('--no-auto-names', { action: 'store_true' })
    p.add_argument('--json')
  }
  c.add_argument('--all-diffs', { action: 'store_true' })
  const d = sub.add_parser('dump', { usage: DUMP_USAGE, help: DUMP_HELP })
  d.add_argument('obj')
  d.add_argument('--json')
  let args
  try {
    args = ap.parse_args(argv)
  } catch (e) {
    if (e instanceof ArgExit) return e.code ? 2 : 0
    throw e
  }
  const runner = { compare: run_compare, report: run_report, dump: run_dump }[args.cmd]
  if (runner) {
    if (args.json === '-') {          // JSON on stdout, text to stderr
      OUT = process.stderr
      try { return runner(args) } finally { OUT = process.stdout }
    }
    return runner(args)
  }
  ap.print_help()
  return 2
}

// an uncaught exception: Python prints a traceback and exits 1
export function runMain(fn) {
  try {
    process.exitCode = fn()
  } catch (e) {
    process.stderr.write('Traceback (most recent call last):\n  (JavaScript port)\n' +
                         `${e && e.name ? e.name : 'Error'}: ${e && e.message !== undefined ? e.message : e}\n`)
    if (process.env.OBJCMP_DEBUG) process.stderr.write(String(e && e.stack) + '\n')
    process.exitCode = 1
  }
}

export function isMainModule(url) {
  try {
    return !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(url))
  } catch {
    return false
  }
}
if (isMainModule(import.meta.url)) runMain(() => main())
