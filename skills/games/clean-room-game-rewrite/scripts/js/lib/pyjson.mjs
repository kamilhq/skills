// Python-compatible JSON for the JavaScript ports (Node built-ins only).
//
// The Python scripts write JSON with json.dump(s); the ports must produce the same bytes, and read what
// either side wrote without losing information. JavaScript's own JSON differs in three ways that matter:
//   - floats: Python writes 1.0 / 1e-05 / 1e+16, JS loses the int/float distinction and formats differently
//   - big integers (> 2^53) lose precision in JS numbers
//   - object key order: JS puts integer-like keys first
// So:
//   parse(text)  -> plain objects are Map-free JS objects EXCEPT that every object is returned as a PyDict
//                   (a Map subclass, insertion order kept); integers beyond 2^53 are BigInt; numbers written
//                   with '.', 'e' or 'E' are PyFloat (valueOf() gives the number)
//   dumps(value, {indent, ensureAscii=true, separators}) -> exactly json.dumps(value, indent=..., ...)
//                   accepts PyDict/Map, plain objects (insertion order as JS gives it - use PyDict when keys
//                   may look like integers), arrays, strings, booleans, null/undefined (null), numbers
//                   (integers print as ints; non-integers as Python float repr), BigInt, PyFloat
//   pyFloat(x)   -> mark a number to print as a Python float (1 -> 1.0)
//   pyFloatRepr(x) -> Python's repr() of a float

export class PyFloat {
  constructor(v) { this.v = Number(v) }
  valueOf() { return this.v }
  toJSON() { return this.v }
}
export const pyFloat = (v) => new PyFloat(v)

export class PyDict extends Map {
  // convenience accessors so ported code can read like a plain dict
  get_(k, d = undefined) { return this.has(k) ? this.get(k) : d }
  toObject() { return Object.fromEntries(this) }
}
export const pyDict = (entries = []) => new PyDict(entries)

// Python float repr: shortest round-trip digits (same digits as JS), formatted like Python's float_repr_style
export function pyFloatRepr(x) {
  if (Number.isNaN(x)) return 'NaN'
  if (x === Infinity) return 'Infinity'
  if (x === -Infinity) return '-Infinity'
  if (x === 0) return Object.is(x, -0) ? '-0.0' : '0.0'
  // digits and exponent from JS's shortest representation
  let s = Math.abs(x).toExponential()            // d.ddde+N  (shortest round-trip digits)
  let [mant, exp] = s.split('e')
  let e = parseInt(exp, 10)
  const digits = mant.replace('.', '')
  const sign = x < 0 ? '-' : ''
  // Python repr uses scientific notation when exp < -4 or exp >= 16
  if (e < -4 || e >= 16) {
    let m = digits.length > 1 ? digits[0] + '.' + digits.slice(1) : digits
    const es = (e < 0 ? '-' : '+') + String(Math.abs(e)).padStart(2, '0')
    return sign + m + 'e' + es
  }
  let out
  if (e >= 0) {
    if (digits.length <= e + 1) out = digits + '0'.repeat(e + 1 - digits.length) + '.0'
    else out = digits.slice(0, e + 1) + '.' + digits.slice(e + 1)
  } else {
    out = '0.' + '0'.repeat(-e - 1) + digits
  }
  return sign + out
}

function escapeString(s, ensureAscii) {
  let out = '"'
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    const ch = s[i]
    if (ch === '"') out += '\\"'
    else if (ch === '\\') out += '\\\\'
    else if (ch === '\n') out += '\\n'
    else if (ch === '\r') out += '\\r'
    else if (ch === '\t') out += '\\t'
    else if (ch === '\b') out += '\\b'
    else if (ch === '\f') out += '\\f'
    else if (c < 0x20 || (ensureAscii && c > 0x7e)) {
      out += '\\u' + c.toString(16).padStart(4, '0')
    } else out += ch
  }
  return out + '"'
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Map) &&
    !(v instanceof PyFloat) && !(typeof v === 'bigint')
}

export function dumps(value, opts = {}) {
  const indent = opts.indent ?? null
  const ensureAscii = opts.ensureAscii ?? true
  const itemSep = opts.separators ? opts.separators[0] : (indent === null ? ', ' : ',')
  const keySep = opts.separators ? opts.separators[1] : ': '
  const ind = indent === null ? null : (typeof indent === 'number' ? ' '.repeat(indent) : indent)

  function num(v) {
    if (v instanceof PyFloat) return pyFloatRepr(v.v)
    if (typeof v === 'bigint') return v.toString()
    if (Number.isInteger(v) && !Object.is(v, -0)) return String(v)
    return pyFloatRepr(v)
  }
  function key(k) {
    if (typeof k === 'string') return escapeString(k, ensureAscii)
    if (typeof k === 'number' || typeof k === 'bigint' || k instanceof PyFloat) return '"' + num(k) + '"'
    if (k === true) return '"true"'
    if (k === false) return '"false"'
    if (k === null || k === undefined) return '"null"'
    throw new TypeError('keys must be str, int, float, bool or None, not ' + typeof k)
  }
  function enc(v, level) {
    if (v === null || v === undefined) return 'null'
    if (v === true) return 'true'
    if (v === false) return 'false'
    if (typeof v === 'string') return escapeString(v, ensureAscii)
    if (typeof v === 'number' || typeof v === 'bigint' || v instanceof PyFloat) return num(v)
    if (Array.isArray(v) || ArrayBuffer.isView(v)) {
      const arr = Array.from(v)
      if (!arr.length) return '[]'
      if (ind === null) return '[' + arr.map((x) => enc(x, level + 1)).join(itemSep) + ']'
      const pad = '\n' + ind.repeat(level + 1)
      return '[' + pad + arr.map((x) => enc(x, level + 1)).join(itemSep + pad) + '\n' + ind.repeat(level) + ']'
    }
    let entries
    if (v instanceof Map) entries = [...v.entries()]
    else if (isPlainObject(v)) entries = Object.entries(v)
    else throw new TypeError('not JSON serializable: ' + Object.prototype.toString.call(v))
    if (!entries.length) return '{}'
    const parts = entries.map(([k, x]) => key(k) + keySep + enc(x, level + 1))
    if (ind === null) return '{' + parts.join(itemSep) + '}'
    const pad = '\n' + ind.repeat(level + 1)
    return '{' + pad + parts.join(itemSep + pad) + '\n' + ind.repeat(level) + '}'
  }
  return enc(value, 0)
}

// json.loads equivalent that keeps what Python keeps: object key order (PyDict), int vs float, big ints
export function parse(text) {
  let i = 0
  const n = text.length
  const ws = () => { while (i < n && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++ }
  function err(m) { throw new SyntaxError(`${m} at ${i}`) }
  function value() {
    ws()
    const c = text[i]
    if (c === '{') {
      i++; const d = new PyDict(); ws()
      if (text[i] === '}') { i++; return d }
      for (;;) {
        ws(); if (text[i] !== '"') err('expected key')
        const k = str(); ws(); if (text[i++] !== ':') err('expected :')
        d.set(k, value()); ws()
        if (text[i] === ',') { i++; continue }
        if (text[i] === '}') { i++; return d }
        err('expected , or }')
      }
    }
    if (c === '[') {
      i++; const a = []; ws()
      if (text[i] === ']') { i++; return a }
      for (;;) {
        a.push(value()); ws()
        if (text[i] === ',') { i++; continue }
        if (text[i] === ']') { i++; return a }
        err('expected , or ]')
      }
    }
    if (c === '"') return str()
    if (text.startsWith('true', i)) { i += 4; return true }
    if (text.startsWith('false', i)) { i += 5; return false }
    if (text.startsWith('null', i)) { i += 4; return null }
    if (text.startsWith('NaN', i)) { i += 3; return new PyFloat(NaN) }
    if (text.startsWith('Infinity', i)) { i += 8; return new PyFloat(Infinity) }
    if (text.startsWith('-Infinity', i)) { i += 9; return new PyFloat(-Infinity) }
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i, i + 400))
    if (!m) err('unexpected character')
    i += m[0].length
    if (m[2] || m[3]) return new PyFloat(parseFloat(m[0]))
    const v = Number(m[0])
    return Number.isSafeInteger(v) ? v : BigInt(m[0])
  }
  function str() {
    i++
    let out = ''
    for (;;) {
      const c = text[i++]
      if (c === undefined) err('unterminated string')
      if (c === '"') return out
      if (c === '\\') {
        const e = text[i++]
        if (e === 'u') { out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16)); i += 4 }
        else out += ({ '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' })[e] ?? err('bad escape')
      } else out += c
    }
  }
  const v = value(); ws()
  if (i !== n) err('extra data')
  return v
}

// plain-JS view of a parsed value: PyDict -> object, PyFloat -> number, BigInt kept (for code that only reads)
export function plain(v) {
  if (v instanceof PyFloat) return v.v
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [k, plain(x)]))
  if (Array.isArray(v)) return v.map(plain)
  return v
}

import { readFileSync, writeFileSync } from 'node:fs'
export const load = (path) => parse(readFileSync(path, 'utf8'))
// json.dump(obj, open(path, 'w'), indent=...) - Python writes no trailing newline
export const dump = (value, path, opts = {}) => writeFileSync(path, dumps(value, opts))
