// Python standard-library behaviour the ports need and JavaScript does not give directly (Node built-ins only).
//
//   pyRound(x, n)        round(float, n): correctly rounded, ties to even on the exact binary value
//   pySplitext(p)        os.path.splitext (posix): leading dots of the last component are not an extension
//   pyBasename(p)        os.path.basename (posix): text after the last '/', '' for 'a/'
//   pyJoin(a, ...p)      os.path.join (posix)
//   pyNormpath(p)        os.path.normpath (posix)
//   pyIsSpace(ch)        str.isspace for one character; pyStrip(s) = str.strip()
//   pyInt(s)             int(str) -> BigInt: whitespace, sign, '_' between digits, any Unicode decimal digit;
//                        throws (like ValueError) otherwise
//   pyFromHex(s)         bytes.fromhex: ASCII whitespace between pairs allowed, throws on anything else
//   cmpStr(a, b)         Python string order (code points), for Array.prototype.sort
//   pyDecode / pyEncode  bytes.decode / str.encode, strict, for 'utf-8', 'ascii', 'latin-1', 'cp1252'
//   ValueError           Error subclass used where Python raises ValueError

export class ValueError extends Error {
  constructor(m) { super(m); this.name = 'ValueError' }
}

export function pyRound(x, n = 0) {
  if (!Number.isFinite(x) || x === 0) return x
  const neg = x < 0
  const ax = Math.abs(x)
  if (ax >= 1e21) return x                        // already an integer at every n >= 0
  const s = ax.toFixed(100)                       // exact decimal expansion (to 1e-100)
  const [ip, fp] = s.split('.')
  const digits = ip + fp.slice(0, n)
  const first = fp[n]
  const tail = fp.slice(n + 1)
  let up = false
  if (first > '5') up = true
  else if (first === '5') up = /[1-9]/.test(tail) || (Number(digits[digits.length - 1]) & 1) === 1
  let big = BigInt(digits)
  if (up) big += 1n
  const str = big.toString().padStart(n + 1, '0')
  const r = Number(str.slice(0, str.length - n) + '.' + str.slice(str.length - n))
  return neg ? -r : r
}

export function pySplitext(p) {
  const sepIndex = p.lastIndexOf('/')
  const dotIndex = p.lastIndexOf('.')
  if (dotIndex > sepIndex) {
    for (let i = sepIndex + 1; i < dotIndex; i++) {
      if (p[i] !== '.') return [p.slice(0, dotIndex), p.slice(dotIndex)]
    }
  }
  return [p, '']
}

export const pyBasename = (p) => p.slice(p.lastIndexOf('/') + 1)

export function pyJoin(a, ...rest) {
  let path = a
  for (const b of rest) {
    if (b.startsWith('/')) path = b
    else if (!path || path.endsWith('/')) path += b
    else path += '/' + b
  }
  return path
}

export function pyNormpath(path) {
  if (!path) return '.'
  let initial = path.startsWith('/') ? 1 : 0
  if (initial && path.startsWith('//') && !path.startsWith('///')) initial = 2
  const out = []
  for (const comp of path.split('/')) {
    if (comp === '' || comp === '.') continue
    if (comp !== '..' || (!initial && !out.length) || (out.length && out[out.length - 1] === '..')) out.push(comp)
    else if (out.length) out.pop()
  }
  const p = '/'.repeat(initial) + out.join('/')
  return p || '.'
}

// str.isspace: bidi class WS/B/S or category Zs
const SPACE = new Set([0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000])
export const pyIsSpace = (ch) => SPACE.has(ch.codePointAt(0))
export function pyStrip(s) {
  const a = [...s]
  let i = 0, j = a.length
  while (i < j && pyIsSpace(a[i])) i++
  while (j > i && pyIsSpace(a[j - 1])) j--
  return a.slice(i, j).join('')
}

const ND = /^\p{Nd}$/u
function decimalValue(cp) {
  // Unicode decimal digits come in contiguous runs of ten, starting at zero
  let s = cp
  while (s > 0 && ND.test(String.fromCodePoint(s - 1))) s--
  return (cp - s) % 10
}

export function pyInt(s) {
  // as int(str): each Unicode space -> ' ', each decimal digit -> its ASCII digit, then the ASCII grammar
  let t = ''
  for (const ch of String(s)) {
    const cp = ch.codePointAt(0)
    if (cp < 128) t += ch
    else if (pyIsSpace(ch)) t += ' '
    else if (ND.test(ch)) t += String(decimalValue(cp))
    else t += '?'
  }
  t = t.replace(/^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g, '')
  if (!/^[+-]?[0-9]+(_[0-9]+)*$/.test(t)) {
    throw new ValueError(`invalid literal for int() with base 10: '${s}'`)
  }
  return BigInt(t.replace(/_/g, ''))
}

export function pyFromHex(s) {
  const out = []
  const isSp = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\v' || c === '\f' || c === '\r'
  const hv = (c) => (c !== undefined && /^[0-9a-fA-F]$/.test(c) ? parseInt(c, 16) : -1)
  let i = 0
  while (i < s.length) {
    if (isSp(s[i])) {
      while (i < s.length && isSp(s[i])) i++
      if (i >= s.length) break
    }
    const top = hv(s[i])
    if (top < 0) throw new ValueError(`non-hexadecimal number found in fromhex() arg at position ${i}`)
    const bot = hv(s[i + 1])
    if (bot < 0) throw new ValueError(`non-hexadecimal number found in fromhex() arg at position ${i + 1}`)
    out.push(top * 16 + bot)
    i += 2
  }
  return Buffer.from(out)
}

export function cmpStr(a, b) {
  // code point order = UTF-8 byte order
  if (a === b) return 0
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))
}

// ---------------------------------------------------------------- codecs (strict)
const CP1252_HIGH = [
  0x20ac, -1, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, -1, 0x017d, -1,
  -1, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, -1, 0x017e, 0x0178]
const CP1252_REV = new Map()
for (let b = 0; b < 256; b++) {
  const u = b >= 0x80 && b < 0xa0 ? CP1252_HIGH[b - 0x80] : b
  if (u >= 0) CP1252_REV.set(u, b)
}

function normEnc(enc) {
  const e = enc.toLowerCase().replace(/_/g, '-')
  if (e === 'utf-8' || e === 'utf8') return 'utf-8'
  if (e === 'ascii' || e === 'us-ascii') return 'ascii'
  if (e === 'latin-1' || e === 'latin1' || e === 'iso-8859-1' || e === 'iso8859-1') return 'latin-1'
  if (e === 'cp1252' || e === 'windows-1252') return 'cp1252'
  throw new Error(`unknown encoding: ${enc}`)
}

export class UnicodeError extends ValueError {
  constructor(m) { super(m); this.name = 'UnicodeError' }
}

export function pyDecode(buf, enc) {
  const e = normEnc(enc)
  if (e === 'utf-8') {
    try {
      return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buf)
    } catch {
      throw new UnicodeError("'utf-8' codec can't decode bytes")
    }
  }
  let s = ''
  const parts = []
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]
    let u = b
    if (e === 'ascii' && b >= 0x80) throw new UnicodeError(`'ascii' codec can't decode byte 0x${b.toString(16)} in position ${i}`)
    if (e === 'cp1252' && b >= 0x80 && b < 0xa0) {
      u = CP1252_HIGH[b - 0x80]
      if (u < 0) throw new UnicodeError(`'charmap' codec can't decode byte 0x${b.toString(16)} in position ${i}`)
    }
    s += String.fromCharCode(u)
    if (s.length >= 8192) { parts.push(s); s = '' }
  }
  parts.push(s)
  return parts.join('')
}

export function pyEncode(str, enc) {
  const e = normEnc(enc)
  if (e === 'utf-8') {
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i)
      if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        const d = str.charCodeAt(i + 1)
        if (d >= 0xdc00 && d <= 0xdfff) { i++; continue }
      }
      if (c >= 0xd800 && c <= 0xdfff) throw new UnicodeError("'utf-8' codec can't encode surrogate")
    }
    return Buffer.from(str, 'utf8')
  }
  const out = Buffer.alloc(str.length)
  let n = 0
  for (const ch of str) {
    const u = ch.codePointAt(0)
    let b
    if (e === 'ascii') b = u < 0x80 ? u : -1
    else if (e === 'latin-1') b = u < 0x100 ? u : -1
    else b = CP1252_REV.has(u) ? CP1252_REV.get(u) : -1
    if (b < 0) throw new UnicodeError(`'${e === 'cp1252' ? 'charmap' : e}' codec can't encode character`)
    out[n++] = b
  }
  return out.subarray(0, n)
}
