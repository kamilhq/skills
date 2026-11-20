// Python behaviour used by the intake ports (inno, intake, inventory, extract_archives, completeness).
// Node built-ins only.
//
//   out(s) / err(s)        write to fd 1 / 2 synchronously (pipes included), so output order and exit codes
//                          behave like Python's
//   pyRepr(s)              repr(str);  pyBytesRepr(buf)  repr(bytes)
//   osErrorStr(e)          str(OSError) for a Node fs error: "[Errno 2] No such file or directory: 'x'"
//   realpath/abspath/normpath/dirname/basename/splitext/join   os.path (posix) semantics
//   walk(top)              os.walk (top-down, followlinks=False), entries in raw readdir order like os.scandir
//   listdir(p)             os.listdir order (raw readdir order)
//   fnmatchcase(name, pat) fnmatch.fnmatchcase (fnmatch.translate rules)
//   fixed(x, n)            '%.nf' / f'{x:.nf}' (correctly rounded, ties to even on the exact binary value)
//   ljust/rjust            str.ljust/rjust (width in code points); cmpStr: Python string order (code points)
//   pyStrip(s)             str.strip() (Python's whitespace set)
//   crc32(buf, v)          zlib.crc32
//   StructError, u8/u16/u32/i32/u64/i64 readers raising struct.error messages

import fs from 'node:fs'
import zlib from 'node:zlib'

// ---------------------------------------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------------------------------------
function writeAll(fd, s) {
  const b = Buffer.from(s, 'utf8')
  let off = 0
  while (off < b.length) {
    try {
      off += fs.writeSync(fd, b, off, b.length - off)
    } catch (e) {
      if (e.code === 'EAGAIN') { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2); continue }
      if (e.code === 'EPIPE') return
      throw e
    }
  }
}
export const out = (s) => writeAll(1, s)
export const err = (s) => writeAll(2, s)
export const print = (...a) => out(a.join(' ') + '\n')
export const eprint = (...a) => err(a.join(' ') + '\n')

// ---------------------------------------------------------------------------------------------------------
// repr
// ---------------------------------------------------------------------------------------------------------
const NONPRINT = /[\p{C}\p{Z}]/u
export function pyRepr(s) {
  const q = s.includes("'") && !s.includes('"') ? '"' : "'"
  let r = q
  for (const ch of s) {
    const c = ch.codePointAt(0)
    if (ch === q || ch === '\\') r += '\\' + ch
    else if (ch === '\t') r += '\\t'
    else if (ch === '\n') r += '\\n'
    else if (ch === '\r') r += '\\r'
    else if (c < 0x20 || c === 0x7f) r += '\\x' + c.toString(16).padStart(2, '0')
    else if (c < 0x7f) r += ch
    else if (ch !== ' ' && NONPRINT.test(ch)) {
      if (c < 0x100) r += '\\x' + c.toString(16).padStart(2, '0')
      else if (c < 0x10000) r += '\\u' + c.toString(16).padStart(4, '0')
      else r += '\\U' + c.toString(16).padStart(8, '0')
    } else r += ch
  }
  return r + q
}
export function pyBytesRepr(buf) {
  let hasS = false, hasD = false
  for (const b of buf) { if (b === 0x27) hasS = true; if (b === 0x22) hasD = true }
  const q = hasS && !hasD ? '"' : "'"
  let r = 'b' + q
  for (const b of buf) {
    if (b === q.charCodeAt(0) || b === 0x5c) r += '\\' + String.fromCharCode(b)
    else if (b === 9) r += '\\t'
    else if (b === 10) r += '\\n'
    else if (b === 13) r += '\\r'
    else if (b < 0x20 || b >= 0x7f) r += '\\x' + b.toString(16).padStart(2, '0')
    else r += String.fromCharCode(b)
  }
  return r + q
}

// ---------------------------------------------------------------------------------------------------------
// OSError text (macOS errno numbers and strerror texts)
// ---------------------------------------------------------------------------------------------------------
const STRERROR = {
  EPERM: [1, 'Operation not permitted'], ENOENT: [2, 'No such file or directory'], EIO: [5, 'Input/output error'],
  EBADF: [9, 'Bad file descriptor'], ENOMEM: [12, 'Cannot allocate memory'], EACCES: [13, 'Permission denied'],
  EBUSY: [16, 'Resource busy'], EEXIST: [17, 'File exists'], EXDEV: [18, 'Cross-device link'],
  ENOTDIR: [20, 'Not a directory'], EISDIR: [21, 'Is a directory'], EINVAL: [22, 'Invalid argument'],
  EMFILE: [24, 'Too many open files'], EFBIG: [27, 'File too large'], ENOSPC: [28, 'No space left on device'],
  EROFS: [30, 'Read-only file system'], EPIPE: [32, 'Broken pipe'], ELOOP: [62, 'Too many levels of symbolic links'],
  ENAMETOOLONG: [63, 'File name too long'], ENOTEMPTY: [66, 'Directory not empty'], EDQUOT: [69, 'Disc quota exceeded'],
}
export function isOSError(e) { return e && typeof e.code === 'string' && typeof e.syscall === 'string' }
export function osErrorStr(e) {
  const [no, msg] = STRERROR[e.code] ?? [e.errno !== undefined ? -e.errno : 0, e.message]
  let s = `[Errno ${no}] ${msg}`
  if (e.path !== undefined) {
    s += ': ' + pyRepr(e.path)
    if (e.dest !== undefined) s += ' -> ' + pyRepr(e.dest)
  }
  return s
}
// Python exception class name for an fs error (FileNotFoundError, ...)
export function osErrorClass(e) {
  return ({ ENOENT: 'FileNotFoundError', EEXIST: 'FileExistsError', EACCES: 'PermissionError', EPERM: 'PermissionError',
    ENOTDIR: 'NotADirectoryError', EISDIR: 'IsADirectoryError' })[e.code] ?? 'OSError'
}

// ---------------------------------------------------------------------------------------------------------
// os.path (posix)
// ---------------------------------------------------------------------------------------------------------
export function normpath(p) {
  if (p === '') return '.'
  const initial = p.startsWith('/') ? (p.startsWith('//') && !p.startsWith('///') ? 2 : 1) : 0
  const comps = []
  for (const c of p.split('/')) {
    if (c === '' || c === '.') continue
    if (c !== '..' || (!initial && !comps.length) || (comps.length && comps[comps.length - 1] === '..')) comps.push(c)
    else if (comps.length) comps.pop()
  }
  const s = '/'.repeat(initial) + comps.join('/')
  return s || '.'
}
export function join(a, ...rest) {
  let p = a
  for (const b of rest) {
    if (b.startsWith('/')) p = b
    else if (!p || p.endsWith('/')) p += b
    else p += '/' + b
  }
  return p
}
export const abspath = (p) => normpath(p.startsWith('/') ? p : join(process.cwd(), p))
export const basename = (p) => p.slice(p.lastIndexOf('/') + 1)
export function dirname(p) {
  const i = p.lastIndexOf('/') + 1
  let head = p.slice(0, i)
  if (head && head !== '/'.repeat(head.length)) head = head.replace(/\/+$/, '')
  return head
}
export function splitext(p) {
  const sepIndex = p.lastIndexOf('/')
  const dotIndex = p.lastIndexOf('.')
  if (dotIndex > sepIndex) {
    for (let i = sepIndex + 1; i < dotIndex; i++) if (p[i] !== '.') return [p.slice(0, dotIndex), p.slice(dotIndex)]
  }
  return [p, '']
}
export function relpath(p, start) {
  const a = abspath(p).split('/').filter(Boolean), b = abspath(start).split('/').filter(Boolean)
  let i = 0
  while (i < a.length && i < b.length && a[i] === b[i]) i++
  const r = [...Array(b.length - i).fill('..'), ...a.slice(i)]
  return r.length ? r.join('/') : '.'
}
export function isfile(p) { try { return fs.statSync(p).isFile() } catch { return false } }
export function isdir(p) { try { return fs.statSync(p).isDirectory() } catch { return false } }
export function islink(p) { try { return fs.lstatSync(p).isSymbolicLink() } catch { return false } }
export function exists(p) { try { fs.statSync(p); return true } catch { return false } }
export function getsize(p) { return fs.statSync(p).size }

// os.path.split (posix)
export function split(p) {
  const i = p.lastIndexOf('/') + 1
  let head = p.slice(0, i)
  const tail = p.slice(i)
  if (head && head !== '/'.repeat(head.length)) head = head.replace(/\/+$/, '')
  return [head, tail]
}
// os.path.realpath (Python 3.9 posixpath._joinrealpath)
export function realpath(filename) {
  const seen = new Map()
  function joinreal(p, rest) {
    if (rest.startsWith('/')) { rest = rest.slice(1); p = '/' }
    while (rest) {
      const i = rest.indexOf('/')
      const name = i < 0 ? rest : rest.slice(0, i)
      rest = i < 0 ? '' : rest.slice(i + 1)
      if (!name || name === '.') continue
      if (name === '..') {
        if (p) {
          let nm
          ;[p, nm] = split(p)
          if (nm === '..') p = join(p, '..', '..')
        } else p = '..'
        continue
      }
      const newpath = join(p, name)
      if (!islink(newpath)) { p = newpath; continue }
      if (seen.has(newpath)) {
        const v = seen.get(newpath)
        if (v !== null) { p = v; continue }
        return [join(newpath, rest), false]
      }
      seen.set(newpath, null)
      let ok
      ;[p, ok] = joinreal(p, fs.readlinkSync(newpath))
      if (!ok) return [join(p, rest), false]
      seen.set(newpath, p)
    }
    return [p, true]
  }
  return abspath(joinreal('', filename)[0])
}

// raw readdir order, like os.scandir / os.listdir
export function listdir(p) {
  const d = fs.opendirSync(p)
  const names = []
  try {
    let e
    while ((e = d.readSync()) !== null) names.push(e.name)
  } finally { d.closeSync() }
  return names
}
// os.walk(top): yields [dirpath, dirnames, filenames]; dirnames may be modified in place (sort) before recursion
export function* walk(top) {
  let names
  try { names = listdir(top) } catch { return }
  const dirs = [], files = []
  for (const n of names) {
    let isDir = false
    try { isDir = fs.statSync(join(top, n)).isDirectory() } catch { isDir = false }
    ;(isDir ? dirs : files).push(n)
  }
  yield [top, dirs, files]
  for (const d of dirs) {
    const np = join(top, d)
    if (!islink(np)) yield* walk(np)
  }
}

// ---------------------------------------------------------------------------------------------------------
// fnmatch
// ---------------------------------------------------------------------------------------------------------
const reEsc = (c) => c.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&')
function classItem(c) { return c === '\\' || c === ']' || c === '[' || c === '^' || c === '-' ? '\\' + c : c }
export function translate(pat) {
  let res = ''
  let i = 0
  const n = pat.length
  let lastStar = false
  while (i < n) {
    const c = pat[i++]
    if (c === '*') { if (!lastStar) res += '[\\s\\S]*'; lastStar = true; continue }
    lastStar = false
    if (c === '?') res += '[\\s\\S]'
    else if (c === '[') {
      let j = i
      if (j < n && pat[j] === '!') j++
      if (j < n && pat[j] === ']') j++
      while (j < n && pat[j] !== ']') j++
      if (j >= n) { res += '\\['; continue }
      let stuff = pat.slice(i, j)
      i = j + 1
      let neg = false
      if (stuff[0] === '!') { neg = true; stuff = stuff.slice(1) }
      // ranges a-b; a '-' first or last is literal
      let cls = ''
      let k = 0
      const chars = Array.from(stuff)
      while (k < chars.length) {
        if (k + 2 < chars.length && chars[k + 1] === '-') {
          const a = chars[k].codePointAt(0), b = chars[k + 2].codePointAt(0)
          if (a <= b) cls += classItem(chars[k]) + '-' + classItem(chars[k + 2])
          k += 3
        } else { cls += classItem(chars[k]); k++ }
      }
      if (neg) res += cls ? `[^${cls}]` : '[\\s\\S]'
      else res += cls ? `[${cls}]` : '(?!)'
    } else res += reEsc(c)
  }
  return new RegExp('^(?:' + res + ')$', 'u')
}
const fnCache = new Map()
export function fnmatchcase(name, pat) {
  let re = fnCache.get(pat)
  if (!re) { re = translate(pat); fnCache.set(pat, re) }
  return re.test(name)
}

// ---------------------------------------------------------------------------------------------------------
// formatting / strings
// ---------------------------------------------------------------------------------------------------------
export function fixed(x, n) {
  if (!Number.isFinite(x)) return x > 0 ? 'inf' : x < 0 ? '-inf' : 'nan'
  const neg = x < 0 || Object.is(x, -0)
  const ax = Math.abs(x)
  let s = ax.toFixed(n)
  if (ax < 1e21) {
    const exact = ax.toFixed(Math.min(100, n + 60))
    const [, fp] = exact.split('.')
    const tail = fp.slice(n)
    if (/^50*$/.test(tail)) {        // exact tie: Python rounds half to even, toFixed rounds half up
      const digits = exact.replace('.', '').slice(0, exact.indexOf('.') + n)
      let big = BigInt(digits)
      if (big % 2n === 1n) big += 1n
      let t = big.toString().padStart(n + 1, '0')
      s = n ? t.slice(0, t.length - n) + '.' + t.slice(t.length - n) : t
    }
  }
  return (neg ? '-' : '') + s
}
export const cpLen = (s) => { let n = 0; for (const _ of s) n++; return n }
export const ljust = (s, w) => { s = String(s); const l = cpLen(s); return l >= w ? s : s + ' '.repeat(w - l) }
export const rjust = (s, w) => { s = String(s); const l = cpLen(s); return l >= w ? s : ' '.repeat(w - l) + s }
export function cmpStr(a, b) {
  if (a === b) return 0
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) {
    const x = a.charCodeAt(i), y = b.charCodeAt(i)
    if (x !== y) {
      const xs = x >= 0xd800 && x <= 0xdfff, ys = y >= 0xd800 && y <= 0xdfff
      if (xs !== ys) return xs ? 1 : -1       // surrogate (code point >= 0x10000) sorts after BMP chars
      return x < y ? -1 : 1
    }
  }
  return a.length - b.length
}
const PY_SPACE = new Set([9, 10, 11, 12, 13, 28, 29, 30, 31, 32, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003,
  0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000])
export function pyStrip(s) {
  let a = 0, b = s.length
  while (a < b && PY_SPACE.has(s.charCodeAt(a))) a++
  while (b > a && PY_SPACE.has(s.charCodeAt(b - 1))) b--
  return s.slice(a, b)
}
export const cpSlice = (s, a, b) => Array.from(s).slice(a, b).join('')

// ---------------------------------------------------------------------------------------------------------
// crc32 / struct
// ---------------------------------------------------------------------------------------------------------
let CRC_T = null
export function crc32(buf, v = 0) {
  if (zlib.crc32) return zlib.crc32(buf, v) >>> 0
  if (!CRC_T) {
    CRC_T = new Int32Array(256)
    for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; CRC_T[i] = c }
  }
  let c = ~v
  for (let i = 0; i < buf.length; i++) c = CRC_T[(c ^ buf[i]) & 0xff] ^ (c >>> 8)
  return (~c) >>> 0
}
export function adler32(buf, v = 1) {
  let a = v & 0xffff, b = (v >>> 16) & 0xffff
  for (let i = 0; i < buf.length; i++) { a = (a + buf[i]) % 65521; b = (b + a) % 65521 }
  return ((b << 16) | a) >>> 0
}

export class StructError extends Error { constructor(m) { super(m); this.name = 'struct.error' } }
function need(buf, off, size) {
  if (off < 0 || off + size > buf.length) {
    throw new StructError(`unpack_from requires a buffer of at least ${off + size} bytes for unpacking ${size} ` +
      `bytes at offset ${off} (actual buffer size is ${buf.length})`)
  }
}
export const u16 = (b, o) => { need(b, o, 2); return b.readUInt16LE(o) }
export const u32 = (b, o) => { need(b, o, 4); return b.readUInt32LE(o) }
export const i32 = (b, o) => { need(b, o, 4); return b.readInt32LE(o) }
export const u64 = (b, o) => { need(b, o, 8); return b.readBigUInt64LE(o) }
export const i64 = (b, o) => { need(b, o, 8); return b.readBigInt64LE(o) }
// struct.unpack (whole buffer must have exactly the size)
export function unpackExact(b, size) {
  if (b.length !== size) throw new StructError(`unpack requires a buffer of ${size} bytes`)
}

// Python's uncaught-exception report (the traceback frames cannot be reproduced; the last line can)
export function traceback(cls, msg) {
  err('Traceback (most recent call last):\n  (JavaScript port)\n' + cls + (msg === undefined ? '' : ': ' + msg) + '\n')
}

// cp1252 / cp437 decoding with errors='replace' / strict tables
const CP1252_UNDEF = new Set([0x81, 0x8d, 0x8f, 0x90, 0x9d])
const W1252 = new TextDecoder('windows-1252')
export function decodeCp1252Replace(buf) {
  let s = ''
  const t = W1252.decode(buf)
  for (let i = 0; i < buf.length; i++) s += CP1252_UNDEF.has(buf[i]) ? '�' : t[i]
  return s
}
const CP437_HI = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀' +
  'αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ '
export function decodeCp437(buf) {
  let s = ''
  for (const b of buf) s += b < 0x80 ? String.fromCharCode(b) : CP437_HI[b - 0x80]
  return s
}
// UnicodeDecodeError text of bytes.decode('utf-8') for invalid input (null when the bytes are valid UTF-8),
// as CPython's decoder reports the first error: start/end positions and reason
export function utf8DecodeError(buf) {
  const n = buf.length
  let i = 0
  while (i < n) {
    const c = buf[i]
    if (c < 0x80) { i++; continue }
    let need, lo = 0x80, hi = 0xBF
    if (c >= 0xC2 && c <= 0xDF) need = 1
    else if (c >= 0xE0 && c <= 0xEF) { need = 2; if (c === 0xE0) lo = 0xA0; if (c === 0xED) hi = 0x9F }
    else if (c >= 0xF0 && c <= 0xF4) { need = 3; if (c === 0xF0) lo = 0x90; if (c === 0xF4) hi = 0x8F }
    else return fmtUtf8Err(buf, i, i + 1, 'invalid start byte')
    let k = 1
    for (; k <= need; k++) {
      if (i + k >= n) return fmtUtf8Err(buf, i, n, 'unexpected end of data')
      const b = buf[i + k]
      const l = k === 1 ? lo : 0x80, u = k === 1 ? hi : 0xBF
      if (b < l || b > u) return fmtUtf8Err(buf, i, i + k, 'invalid continuation byte')
    }
    i += need + 1
  }
  return null
}
function fmtUtf8Err(buf, start, end, reason) {
  if (end - start === 1) {
    return `'utf-8' codec can't decode byte 0x${buf[start].toString(16).padStart(2, '0')} in position ${start}: ${reason}`
  }
  return `'utf-8' codec can't decode bytes in position ${start}-${end - 1}: ${reason}`
}
// bytes.decode('utf-8') strict: returns null when invalid
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
export function decodeUtf8Strict(buf) {
  try { return UTF8.decode(buf) } catch { return null }
}

// ---------------------------------------------------------------------------------------------------------
// argparse (Python 3.9) parsing algorithm for simple parsers: optionals with action help / store_true /
// store_false / store (nargs None, optional choices) and positionals with nargs None or PARSER (subcommands).
// Same classification (prefix abbreviations, '--opt=value', '--', negative numbers), same consume order and
// the same error texts as argparse.ArgumentParser.parse_known_args. Help/usage texts are given verbatim.
//   parser = {options: [{strings: ['-h', '--help'], kind: 'help'}, {strings: ['--json'], dest: 'json',
//             kind: 'store_true'}, ...], positionals: [{dest: 'setup'}, {dest: 'cmd', nargs: 'PARSER',
//             choices: {name: subparser}}]}
//   parseKnownArgs(parser, args, ns) -> extras; throws ArgError(message) or ArgHelp(parser)
// ---------------------------------------------------------------------------------------------------------
export class ArgError extends Error {}
export class ArgHelp extends Error { constructor(parser) { super('help'); this.parser = parser } }

const actionName = (a) => (a.strings ? a.strings.join('/') : a.dest)
function argErr(a, msg) { throw new ArgError(a ? `argument ${actionName(a)}: ${msg}` : msg) }

function optionMap(p) {
  const m = new Map()
  for (const a of p.options) for (const s of a.strings) m.set(s, a)
  return m
}
function parseOptionalArg(p, s) {
  const m = optionMap(p)
  if (!s || s[0] !== '-') return null
  if (m.has(s)) return [m.get(s), s, null]
  if (s.length === 1) return null
  if (s.includes('=')) {
    const i = s.indexOf('=')
    if (m.has(s.slice(0, i))) return [m.get(s.slice(0, i)), s.slice(0, i), s.slice(i + 1)]
  }
  const tuples = []
  if (s[1] === '-') {
    let prefix = s, explicit = null
    if (s.includes('=')) { const i = s.indexOf('='); prefix = s.slice(0, i); explicit = s.slice(i + 1) }
    for (const [os, a] of m) if (os.startsWith(prefix)) tuples.push([a, os, explicit])
  } else {
    const sp = s.slice(0, 2), se = s.slice(2)
    for (const [os, a] of m) {
      if (os === sp) tuples.push([a, os, se])
      else if (os.startsWith(s)) tuples.push([a, os, null])
    }
  }
  if (tuples.length > 1) argErr(null, `ambiguous option: ${s} could match ${tuples.map((t) => t[1]).join(', ')}`)
  if (tuples.length === 1) return tuples[0]
  if (/^-\d+$|^-\d*\.\d+$/.test(s)) return null
  if (s.includes(' ')) return null
  return [null, s, null]
}

const nargsPattern = (a, optional) => {
  if (optional) return a.kind === 'store' ? '(A)' : '()'
  return a.nargs === 'PARSER' ? '(-*A[-AO]*)' : '(-*A-*)'
}

export function parseKnownArgs(p, args, ns) {
  for (const a of p.options) if (a.dest && !(a.dest in ns)) ns[a.dest] = a.default ?? (a.kind === 'store_true' ? false : a.kind === 'store_false' ? true : null)
  for (const a of p.positionals) if (!(a.dest in ns)) ns[a.dest] = null
  const optIdx = new Map()
  const pat = []
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--') {
      pat.push('-')
      for (i++; i < args.length; i++) pat.push('A')
      break
    }
    const t = parseOptionalArg(p, args[i])
    if (t === null) pat.push('A')
    else { optIdx.set(i, t); pat.push('O') }
  }
  const pattern = pat.join('')
  const extras = []
  const positionals = p.positionals.slice()
  const seen = new Set()
  let subExtras = []

  const takeAction = (a, argStrings) => {
    seen.add(a)
    if (a.nargs !== 'PARSER') { const k = argStrings.indexOf('--'); if (k >= 0) argStrings.splice(k, 1) }
    if (a.kind === 'help') throw new ArgHelp(p)
    if (a.kind === 'store_true') { ns[a.dest] = true; return }
    if (a.kind === 'store_false') { ns[a.dest] = false; return }
    if (a.nargs === 'PARSER') {
      const name = argStrings[0]
      if (!a.choices[name]) {
        argErr(a, `invalid choice: ${pyRepr(name)} (choose from ${Object.keys(a.choices).map(pyRepr).join(', ')})`)
      }
      ns[a.dest] = name
      const sub = a.choices[name]
      subExtras = parseKnownArgs(sub, argStrings.slice(1), ns)
      return
    }
    const v = argStrings[0]
    if (a.choices && !a.choices.includes(v)) {
      argErr(a, `invalid choice: ${pyRepr(v)} (choose from ${a.choices.map(pyRepr).join(', ')})`)
    }
    ns[a.dest] = v
  }

  const consumeOptional = (start) => {
    let [a, optStr, explicit] = optIdx.get(start)
    const tuples = []
    let stop
    for (;;) {
      if (a === null) { extras.push(args[start]); return start + 1 }
      if (explicit !== null) {
        const argCount = a.kind === 'store' ? 1 : 0
        if (argCount === 0 && optStr[1] !== '-') {
          tuples.push([a, [], optStr])
          const ch = optStr[0]
          optStr = ch + explicit[0]
          const ne = explicit.slice(1) || null
          const m = optionMap(p)
          if (m.has(optStr)) { a = m.get(optStr); explicit = ne }
          else argErr(a, `ignored explicit argument ${pyRepr(explicit)}`)
        } else if (argCount === 1) {
          stop = start + 1
          tuples.push([a, [explicit], optStr])
          break
        } else argErr(a, `ignored explicit argument ${pyRepr(explicit)}`)
      } else {
        const st = start + 1
        const m = new RegExp('^' + nargsPattern(a, true)).exec(pattern.slice(st))
        if (!m) argErr(a, 'expected one argument')
        const n = m[1].length
        stop = st + n
        tuples.push([a, args.slice(st, stop), optStr])
        break
      }
    }
    for (const [x, as] of tuples) takeAction(x, as)
    return stop
  }

  const consumePositionals = (start) => {
    const sel = pattern.slice(start)
    let counts = []
    for (let i = positionals.length; i > 0; i--) {
      const re = new RegExp('^' + positionals.slice(0, i).map((a) => nargsPattern(a, false)).join(''))
      const m = re.exec(sel)
      if (m) { counts = m.slice(1).map((g) => g.length); break }
    }
    counts.forEach((n, k) => {
      const as = args.slice(start, start + n)
      start += n
      takeAction(positionals[k], as)
    })
    positionals.splice(0, counts.length)
    return start
  }

  let start = 0
  const maxOpt = optIdx.size ? Math.max(...optIdx.keys()) : -1
  while (start <= maxOpt) {
    const next = Math.min(...[...optIdx.keys()].filter((i) => i >= start))
    if (start !== next) {
      const end = consumePositionals(start)
      if (end > start) { start = end; continue }
      start = end
    }
    if (!optIdx.has(start)) { extras.push(...args.slice(start, next)); start = next }
    start = consumeOptional(start)
  }
  const stop = consumePositionals(start)
  extras.push(...args.slice(stop))
  const missing = p.positionals.filter((a) => !seen.has(a) && a.nargs !== 'PARSER').map((a) => a.dest)
  if (missing.length) argErr(null, `the following arguments are required: ${missing.join(', ')}`)
  return extras.concat(subExtras)
}
