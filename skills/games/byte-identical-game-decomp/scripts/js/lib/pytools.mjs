// Small Python-semantics helpers shared by the PE-tool ports (reassemble, peek, rich_header, phase6_skeleton,
// code_coverage_check, build_features). Node built-ins only.
//   readText(path, {errors})  open(path).read(): UTF-8 (strict, or errors='replace'), BOM kept, universal newlines
//   iterLines(text)           `for line in f` over already-read text: lines keep their '\n'
//   pySplit(s, sep, max)      str.split(sep, maxsplit) (JS split's limit truncates instead)
//   pyStrip / pyRstrip        str.strip() / rstrip() with Python's whitespace set (or given chars)
//   pyInt(s, base)            int(s, base) for str, with Python's prefix/underscore/sign rules (ValueError)
//   pyRepr(s)                 repr() of a str;  pyStr(v): str() of a JSON-ish value
//   cmp / sortStr             Python string ordering (code points), number ordering
//   W, NW, S                  regex fragments for Python's Unicode \w, \W and \s (use with the u flag)
//   ArgParser                 the argparse subset the ports use (usage/help/error text as Python 3.9 prints)
//   runMain(fn)               run a main(): an exit code or SysExit sets the exit code; other errors print a
//                             Python-style last line to stderr and exit 1 (like an uncaught exception)
import { readFileSync } from 'node:fs'

export class SysExit extends Error {
  constructor(code, message) { super(message ?? ''); this.code = code }
}
export class ValueError extends Error { get name() { return 'ValueError' } }

// sys.exit(msg): message to stderr, exit 1;  sys.exit(n): exit n
export function sysExit(arg) {
  if (typeof arg === 'string') throw new SysExit(1, arg)
  throw new SysExit(arg ?? 0)
}

export function runMain(fn) {
  const done = (code) => { process.exitCode = code }
  let r
  try {
    r = fn()
  } catch (e) {
    return handle(e)
  }
  if (r && typeof r.then === 'function') r.then((c) => done(c ?? 0), handle)
  else done(r ?? 0)
  function handle(e) {
    if (e instanceof SysExit) {
      if (e.message) process.stderr.write(e.message + '\n')
      return done(e.code)
    }
    process.stderr.write('Traceback (most recent call last):\n  (JavaScript port)\n' +
      `${e && e.name ? e.name : 'Error'}: ${e && e.message !== undefined ? e.message : e}\n`)
    if (process.env.PYTOOLS_DEBUG) process.stderr.write(String(e && e.stack) + '\n')
    done(1)
  }
}

const strictDec = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const replDec = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true })
export function decodeUtf8(buf, errors = 'strict') {
  try {
    return (errors === 'replace' ? replDec : strictDec).decode(buf)
  } catch (e) {
    throw new ValueError("'utf-8' codec can't decode bytes: invalid UTF-8")
  }
}
export const universalNewlines = (s) => s.replace(/\r\n?/g, '\n')
export function readText(path, { errors = 'strict' } = {}) {
  return universalNewlines(decodeUtf8(readFileSync(path), errors))
}
export function iterLines(text) {
  const out = []
  let i = 0
  while (i < text.length) {
    const j = text.indexOf('\n', i)
    if (j < 0) { out.push(text.slice(i)); break }
    out.push(text.slice(i, j + 1))
    i = j + 1
  }
  return out
}

export function pySplit(s, sep, maxsplit = -1) {
  if (maxsplit < 0) return s.split(sep)
  const out = []
  let i = 0
  while (out.length < maxsplit) {
    const j = s.indexOf(sep, i)
    if (j < 0) break
    out.push(s.slice(i, j))
    i = j + sep.length
  }
  out.push(s.slice(i))
  return out
}

const WS = '\\t\\n\\v\\f\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000'
export const S = `[${WS}]`
export const W = '[\\p{L}\\p{N}_]'
export const NW = '[^\\p{L}\\p{N}_]'
const reWsL = new RegExp(`^${S}+`, 'u'), reWsR = new RegExp(`${S}+$`, 'u')
const escCls = (chars) => chars.replace(/[\\\]\[^-]/g, '\\$&')
export function pyStrip(s, chars) {
  if (chars === undefined) return s.replace(reWsL, '').replace(reWsR, '')
  return pyRstrip(pyLstrip(s, chars), chars)
}
export function pyLstrip(s, chars) {
  if (chars === undefined) return s.replace(reWsL, '')
  if (!chars) return s
  return s.replace(new RegExp(`^[${escCls(chars)}]+`, 'u'), '')
}
export function pyRstrip(s, chars) {
  if (chars === undefined) return s.replace(reWsR, '')
  if (!chars) return s
  return s.replace(new RegExp(`[${escCls(chars)}]+$`, 'u'), '')
}

// int(s, base) for a str argument (ASCII digits)
export function pyInt(s, base = 10) {
  if (typeof s !== 'string') {
    const e = new TypeError("int() can't convert non-string with explicit base")
    throw e
  }
  const bad = () => new ValueError(`invalid literal for int() with base ${base}: ${pyRepr(s)}`)
  let t = pyStrip(s)
  let neg = false
  if (t[0] === '+' || t[0] === '-') { neg = t[0] === '-'; t = t.slice(1) }
  let b = base
  const pre = t.slice(0, 2).toLowerCase()
  let prefixed = false
  if (b === 0) {
    if (pre === '0x') b = 16
    else if (pre === '0o') b = 8
    else if (pre === '0b') b = 2
    else b = 10
    if (b !== 10) { t = t.slice(2); prefixed = true }
  } else if ((b === 16 && pre === '0x') || (b === 8 && pre === '0o') || (b === 2 && pre === '0b')) {
    t = t.slice(2); prefixed = true
  }
  if (prefixed && t[0] === '_') t = t.slice(1)
  if (!t || t[0] === '_' || t[t.length - 1] === '_' || t.includes('__')) throw bad()
  const digits = t.replace(/_/g, '')
  const valid = '0123456789abcdefghijklmnopqrstuvwxyz'.slice(0, b)
  for (const c of digits.toLowerCase()) if (!valid.includes(c)) throw bad()
  if (base === 0 && b === 10 && digits.length > 1 && digits[0] === '0' && /[^0]/.test(digits)) throw bad()
  let v = 0
  for (const c of digits.toLowerCase()) v = v * b + valid.indexOf(c)
  if (!Number.isSafeInteger(v)) {
    let bv = 0n
    for (const c of digits.toLowerCase()) bv = bv * BigInt(b) + BigInt(valid.indexOf(c))
    return neg ? -bv : bv
  }
  return neg ? -v : v
}

// Python 3.9's str.isprintable() (Unicode 13.0.0), as ranges 'start+length' (hex) of printable code points.
// Generated with: python3 -I -c "[c for c in range(0x110000) if chr(c).isprintable()]" (run-length encoded).
// Used instead of Node's own Unicode tables, which are newer, so repr() matches Python 3.9 exactly.
const PRINTABLE_RANGES = [
  '20+5f,a1+c,ae+2ca,37a+6,384+7,38c+1,38e+14,3a3+18d,531+26,559+32,58d+3,591+37,5d0+1b,5ef+6,606+16,61e+bf,6de+30,',
  '710+3b,74d+65,7c0+3b,7fd+31,830+f,840+1c,85e+1,860+b,8a0+15,8b6+12,8d3+f,8e3+a1,985+8,98f+2,993+16,9aa+7,9b2+1,9',
  'b6+4,9bc+9,9c7+2,9cb+4,9d7+1,9dc+2,9df+5,9e6+19,a01+3,a05+6,a0f+2,a13+16,a2a+7,a32+2,a35+2,a38+2,a3c+1,a3e+5,a47',
  '+2,a4b+3,a51+1,a59+4,a5e+1,a66+11,a81+3,a85+9,a8f+3,a93+16,aaa+7,ab2+2,ab5+5,abc+a,ac7+3,acb+3,ad0+1,ae0+4,ae6+c',
  ',af9+7,b01+3,b05+8,b0f+2,b13+16,b2a+7,b32+2,b35+5,b3c+9,b47+2,b4b+3,b55+3,b5c+2,b5f+5,b66+12,b82+2,b85+6,b8e+3,b',
  '92+4,b99+2,b9c+1,b9e+2,ba3+2,ba8+3,bae+c,bbe+5,bc6+3,bca+4,bd0+1,bd7+1,be6+15,c00+d,c0e+3,c12+17,c2a+10,c3d+8,c4',
  '6+3,c4a+4,c55+2,c58+3,c60+4,c66+a,c77+16,c8e+3,c92+17,caa+a,cb5+5,cbc+9,cc6+3,cca+4,cd5+2,cde+1,ce0+4,ce6+a,cf1+',
  '2,d00+d,d0e+3,d12+33,d46+3,d4a+6,d54+10,d66+1a,d81+3,d85+12,d9a+18,db3+9,dbd+1,dc0+7,dca+1,dcf+6,dd6+1,dd8+8,de6',
  '+a,df2+3,e01+3a,e3f+1d,e81+2,e84+1,e86+5,e8c+18,ea5+1,ea7+17,ec0+5,ec6+1,ec8+6,ed0+a,edc+4,f00+48,f49+24,f71+27,',
  'f99+24,fbe+f,fce+d,1000+c6,10c7+1,10cd+1,10d0+179,124a+4,1250+7,1258+1,125a+4,1260+29,128a+4,1290+21,12b2+4,12b8',
  '+7,12c0+1,12c2+4,12c8+f,12d8+39,1312+4,1318+43,135d+20,1380+1a,13a0+56,13f8+6,1400+280,1681+1c,16a0+59,1700+d,17',
  '0e+7,1720+17,1740+14,1760+d,176e+3,1772+2,1780+5e,17e0+a,17f0+a,1800+e,1810+a,1820+59,1880+2b,18b0+46,1900+1f,19',
  '20+c,1930+c,1940+1,1944+2a,1970+5,1980+2c,19b0+1a,19d0+b,19de+3e,1a1e+41,1a60+1d,1a7f+b,1a90+a,1aa0+e,1ab0+11,1b',
  '00+4c,1b50+2d,1b80+74,1bfc+3c,1c3b+f,1c4d+3c,1c90+2b,1cbd+b,1cd0+2b,1d00+fa,1dfb+11b,1f18+6,1f20+26,1f48+6,1f50+',
  '8,1f59+1,1f5b+1,1f5d+1,1f5f+1f,1f80+35,1fb6+f,1fc6+e,1fd6+6,1fdd+13,1ff2+3,1ff6+9,2010+18,2030+2f,2070+2,2074+1b',
  ',2090+d,20a0+20,20d0+21,2100+8c,2190+297,2440+b,2460+714,2b76+20,2b97+98,2c30+2f,2c60+94,2cf9+2d,2d27+1,2d2d+1,2',
  'd30+38,2d6f+2,2d7f+18,2da0+7,2da8+7,2db0+7,2db8+7,2dc0+7,2dc8+7,2dd0+7,2dd8+7,2de0+73,2e80+1a,2e9b+59,2f00+d6,2f',
  'f0+c,3001+3f,3041+56,3099+67,3105+2b,3131+5e,3190+54,31f0+2f,3220+6ddd,a000+48d,a490+37,a4d0+15c,a640+b8,a700+c0',
  ',a7c2+9,a7f5+38,a830+a,a840+38,a880+46,a8ce+c,a8e0+74,a95f+1e,a980+4e,a9cf+b,a9de+21,aa00+37,aa40+e,aa50+a,aa5c+',
  '67,aadb+1c,ab01+6,ab09+6,ab11+6,ab20+7,ab28+7,ab30+3c,ab70+7e,abf0+a,ac00+2ba4,d7b0+17,d7cb+31,f900+16e,fa70+6a,',
  'fb00+7,fb13+5,fb1d+1a,fb38+5,fb3e+1,fb40+2,fb43+2,fb46+7c,fbd3+16d,fd50+40,fd92+36,fdf0+e,fe00+1a,fe20+33,fe54+1',
  '3,fe68+4,fe70+5,fe76+87,ff01+be,ffc2+6,ffca+6,ffd2+6,ffda+3,ffe0+7,ffe8+7,fffc+2,10000+c,1000d+1a,10028+13,1003c',
  '+2,1003f+f,10050+e,10080+7b,10100+3,10107+2d,10137+58,10190+d,101a0+1,101d0+2e,10280+1d,102a0+31,102e0+1c,10300+',
  '24,1032d+1e,10350+2b,10380+1e,1039f+25,103c8+e,10400+9e,104a0+a,104b0+24,104d8+24,10500+28,10530+34,1056f+1,1060',
  '0+137,10740+16,10760+8,10800+6,10808+1,1080a+2c,10837+2,1083c+1,1083f+17,10857+48,108a7+9,108e0+13,108f4+2,108fb',
  '+21,1091f+1b,1093f+1,10980+38,109bc+14,109d2+32,10a05+2,10a0c+8,10a15+3,10a19+1d,10a38+3,10a3f+a,10a50+9,10a60+4',
  '0,10ac0+27,10aeb+c,10b00+36,10b39+1d,10b58+1b,10b78+1a,10b99+4,10ba9+7,10c00+49,10c80+33,10cc0+33,10cfa+2e,10d30',
  '+a,10e60+1f,10e80+2a,10eab+3,10eb0+2,10f00+28,10f30+2a,10fb0+1c,10fe0+17,11000+4e,11052+1e,1107f+3e,110be+4,110d',
  '0+19,110f0+a,11100+35,11136+12,11150+27,11180+60,111e1+14,11200+12,11213+2c,11280+7,11288+1,1128a+4,1128f+f,1129',
  'f+b,112b0+3b,112f0+a,11300+4,11305+8,1130f+2,11313+16,1132a+7,11332+2,11335+5,1133b+a,11347+2,1134b+3,11350+1,11',
  '357+1,1135d+7,11366+7,11370+5,11400+5c,1145d+5,11480+48,114d0+a,11580+36,115b8+26,11600+45,11650+a,11660+d,11680',
  '+39,116c0+a,11700+1b,1171d+f,11730+10,11800+3c,118a0+53,118ff+8,11909+1,1190c+8,11915+2,11918+1e,11937+2,1193b+c',
  ',11950+a,119a0+8,119aa+2e,119da+b,11a00+48,11a50+53,11ac0+39,11c00+9,11c0a+2d,11c38+e,11c50+1d,11c70+20,11c92+16',
  ',11ca9+e,11d00+7,11d08+2,11d0b+2c,11d3a+1,11d3c+2,11d3f+9,11d50+a,11d60+6,11d67+2,11d6a+25,11d90+2,11d93+6,11da0',
  '+a,11ee0+19,11fb0+1,11fc0+32,11fff+39b,12400+6f,12470+5,12480+c4,13000+42f,14400+247,16800+239,16a40+1f,16a60+a,',
  '16a6e+2,16ad0+1e,16af0+6,16b00+46,16b50+a,16b5b+7,16b63+15,16b7d+13,16e40+5b,16f00+4b,16f4f+39,16f8f+11,16fe0+5,',
  '16ff0+2,17000+17f8,18800+4d6,18d00+9,1b000+11f,1b150+3,1b164+4,1b170+18c,1bc00+6b,1bc70+d,1bc80+9,1bc90+a,1bc9c+',
  '4,1d000+f6,1d100+27,1d129+4a,1d17b+6e,1d200+46,1d2e0+14,1d300+57,1d360+19,1d400+55,1d456+47,1d49e+2,1d4a2+1,1d4a',
  '5+2,1d4a9+4,1d4ae+c,1d4bb+1,1d4bd+7,1d4c5+41,1d507+4,1d50d+8,1d516+7,1d51e+1c,1d53b+4,1d540+5,1d546+1,1d54a+7,1d',
  '552+154,1d6a8+124,1d7ce+2be,1da9b+5,1daa1+f,1e000+7,1e008+11,1e01b+7,1e023+2,1e026+5,1e100+2d,1e130+e,1e140+a,1e',
  '14e+2,1e2c0+3a,1e2ff+1,1e800+c5,1e8c7+10,1e900+4c,1e950+a,1e95e+2,1ec71+44,1ed01+3d,1ee00+4,1ee05+1b,1ee21+2,1ee',
  '24+1,1ee27+1,1ee29+a,1ee34+4,1ee39+1,1ee3b+1,1ee42+1,1ee47+1,1ee49+1,1ee4b+1,1ee4d+3,1ee51+2,1ee54+1,1ee57+1,1ee',
  '59+1,1ee5b+1,1ee5d+1,1ee5f+1,1ee61+2,1ee64+1,1ee67+4,1ee6c+7,1ee74+4,1ee79+4,1ee7e+1,1ee80+a,1ee8b+11,1eea1+3,1e',
  'ea5+5,1eeab+11,1eef0+2,1f000+2c,1f030+64,1f0a0+f,1f0b1+f,1f0c1+f,1f0d1+25,1f100+ae,1f1e6+1d,1f210+2c,1f240+9,1f2',
  '50+2,1f260+6,1f300+3d8,1f6e0+d,1f6f0+d,1f700+74,1f780+59,1f7e0+c,1f800+c,1f810+38,1f850+a,1f860+28,1f890+1e,1f8b',
  '0+2,1f900+79,1f97a+52,1f9cd+87,1fa60+e,1fa70+5,1fa78+3,1fa80+7,1fa90+19,1fab0+7,1fac0+3,1fad0+7,1fb00+93,1fb94+3',
  '7,1fbf0+a,20000+a6de,2a700+1035,2b740+de,2b820+1682,2ceb0+1d31,2f800+21e,30000+134b,e0100+f0',
].join('').split(',').map((x) => x.split('+').map((h) => parseInt(h, 16)))
const PR_START = PRINTABLE_RANGES.map((x) => x[0])
export function isPrintable(ch) {
  const c = ch.codePointAt(0)
  let lo = 0, hi = PR_START.length
  while (lo < hi) { const mid = (lo + hi) >> 1; if (PR_START[mid] <= c) lo = mid + 1; else hi = mid }
  return lo > 0 && c < PRINTABLE_RANGES[lo - 1][0] + PRINTABLE_RANGES[lo - 1][1]
}
export function pyRepr(s) {
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
    else if (isPrintable(ch)) out += ch
    else if (c <= 0xff) out += '\\x' + c.toString(16).padStart(2, '0')
    else if (c <= 0xffff) out += '\\u' + c.toString(16).padStart(4, '0')
    else out += '\\U' + c.toString(16).padStart(8, '0')
  }
  return out + q
}

// str() of values that come from JSON (pyjson.parse)
export function pyStr(v) {
  if (v === null || v === undefined) return 'None'
  if (v === true) return 'True'
  if (v === false) return 'False'
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'bigint') return String(v)
  if (typeof v === 'object' && v !== null && 'v' in v && typeof v.valueOf() === 'number') {
    return reprFloat(v.valueOf())
  }
  return pyReprValue(v)
}
function reprFloat(x) {
  if (Number.isNaN(x)) return 'nan'
  if (x === Infinity) return 'inf'
  if (x === -Infinity) return '-inf'
  return floatRepr(x)
}
import { pyFloatRepr as floatRepr, PyFloat } from './pyjson.mjs'
export function pyReprValue(v) {
  if (typeof v === 'string') return pyRepr(v)
  if (v instanceof PyFloat) return reprFloat(v.v)
  if (Array.isArray(v)) return '[' + v.map(pyReprValue).join(', ') + ']'
  if (v instanceof Map) return '{' + [...v].map(([k, x]) => pyReprValue(k) + ': ' + pyReprValue(x)).join(', ') + '}'
  return pyStr(v)
}

// Python ordering: strings by code point, numbers numerically
export function cmp(a, b) {
  if (typeof a === 'string' && typeof b === 'string') {
    if (a === b) return 0
    const n = Math.min(a.length, b.length)
    for (let i = 0; i < n; i++) {
      const x = a.charCodeAt(i), y = b.charCodeAt(i)
      if (x !== y) {
        // a surrogate (astral code point) sorts after every BMP code unit above it
        const hx = x >= 0xd800 && x <= 0xdfff, hy = y >= 0xd800 && y <= 0xdfff
        if (hx !== hy) {
          const cx = a.codePointAt(i), cy = b.codePointAt(i)
          return cx < cy ? -1 : 1
        }
        return x < y ? -1 : 1
      }
    }
    return a.length - b.length < 0 ? -1 : a.length === b.length ? 0 : 1
  }
  return a < b ? -1 : a > b ? 1 : 0
}
export const sortStr = (arr) => arr.sort(cmp)
export const sortNum = (arr) => arr.sort((a, b) => a - b)
// lexicographic comparison of arrays (Python tuple order)
export function cmpTuple(a, b) {
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) {
    const c = cmp(a[i], b[i])
    if (c) return c
  }
  return a.length - b.length
}

// hex(n) / '%x'
export const hex = (n) => (n < 0 ? '-0x' + (-n).toString(16) : '0x' + n.toString(16))
// slice by code points (Python s[a:b])
export const cpSlice = (s, a, b) => Array.from(s).slice(a, b).join('')

// ------------------------------------------------------------------------------------- argparse (subset)
function terminalWidth() {
  const c = parseInt(process.env.COLUMNS ?? '', 10)
  if (c > 0) return c
  if (process.stdout.isTTY && process.stdout.columns) return process.stdout.columns
  return 80
}

export class ArgParser {
  // prog: the Python script name; args: [{name, required, default, help}] in add_argument order;
  // a name starting with '--' is an optional with one value, else a positional
  constructor(prog, args) {
    this.prog = prog
    this.actions = [{ name: '-h', flags: ['-h', '--help'], help: true, optional: true }]
    for (const a of args) {
      if (a.name.startsWith('-')) {
        this.actions.push({ ...a, flags: [a.name], optional: true, dest: a.name.replace(/^-+/, '').replace(/-/g, '_'),
                            metavar: a.name.replace(/^-+/, '').replace(/-/g, '_').toUpperCase() })
      } else this.actions.push({ ...a, optional: false, dest: a.name, metavar: a.name })
    }
  }
  _width() { return terminalWidth() - 2 }
  formatUsage() {
    const width = this._width()
    const prefix = 'usage: '
    const optParts = [], posParts = []
    for (const a of this.actions) {
      if (!a.optional) { posParts.push(a.metavar); continue }
      const part = a.help ? '-h' : `${a.flags[0]} ${a.metavar}`
      if (a.required) optParts.push(...part.split(' '))
      else optParts.push('[' + part + ']')
    }
    const prog = this.prog
    let usage = [prog, ...optParts, ...posParts].join(' ')
    if (prefix.length + usage.length > width) {
      const getLines = (parts, indent, pfx) => {
        const lines = []
        let line = []
        let lineLen = pfx !== undefined ? pfx.length - 1 : indent.length - 1
        for (const part of parts) {
          if (lineLen + 1 + part.length > width && line.length) {
            lines.push(indent + line.join(' '))
            line = []
            lineLen = indent.length - 1
          }
          line.push(part)
          lineLen += part.length + 1
        }
        if (line.length) lines.push(indent + line.join(' '))
        if (pfx !== undefined) lines[0] = lines[0].slice(indent.length)
        return lines
      }
      let lines
      if (prefix.length + prog.length <= 0.75 * width) {
        const indent = ' '.repeat(prefix.length + prog.length + 1)
        if (optParts.length) {
          lines = getLines([prog, ...optParts], indent, prefix)
          lines.push(...getLines(posParts, indent))
        } else if (posParts.length) lines = getLines([prog, ...posParts], indent, prefix)
        else lines = [prog]
      } else {
        const indent = ' '.repeat(prefix.length)
        lines = getLines([...optParts, ...posParts], indent)
        if (lines.length > 1) lines = [...getLines(optParts, indent), ...getLines(posParts, indent)]
        lines = [prog, ...lines]
      }
      usage = lines.join('\n')
    }
    return prefix + usage + '\n'
  }
  formatHelp() {
    const width = this._width()
    const inv = (a) => (a.help ? '-h, --help' : a.optional ? `${a.flags[0]} ${a.metavar}` : a.metavar)
    const maxLen = Math.max(...this.actions.map((a) => inv(a).length + 2))
    const helpPos = Math.min(maxLen + 2, Math.min(24, Math.max(width - 20, 4)))
    const item = (a) => {
      const s = inv(a)
      if (!a.help) return '  ' + s + '\n'
      // textwrap.wrap(help, max(width - help_position, 11)): greedy on spaces (the help text has no long words)
      const helpWidth = Math.max(width - helpPos, 11)
      const wrapped = []
      for (const w of 'show this help message and exit'.split(' ')) {
        if (wrapped.length && wrapped.at(-1).length + 1 + w.length <= helpWidth) wrapped[wrapped.length - 1] += ' ' + w
        else wrapped.push(w)
      }
      const rest = wrapped.slice(1).map((l) => ' '.repeat(helpPos) + l + '\n').join('')
      const actionWidth = helpPos - 2 - 2
      if (s.length <= actionWidth) return '  ' + s.padEnd(actionWidth) + '  ' + wrapped[0] + '\n' + rest
      return '  ' + s + '\n' + ' '.repeat(helpPos) + wrapped[0] + '\n' + rest
    }
    let out = this.formatUsage() + '\n'
    const pos = this.actions.filter((a) => !a.optional), opt = this.actions.filter((a) => a.optional)
    if (pos.length) out += '\npositional arguments:\n' + pos.map(item).join('') + '\n'
    if (opt.length) out += '\noptional arguments:\n' + opt.map(item).join('') + '\n'
    out = out.replace(/\n\n\n+/g, '\n\n')
    return out.replace(/^\n+|\n+$/g, '') + '\n'
  }
  error(msg) {
    throw new SysExit(2, this.formatUsage() + `${this.prog}: error: ${msg}`)
  }
  parse(argv) {
    const ns = {}
    for (const a of this.actions) if (!a.help) ns[a.dest] = a.optional ? (a.default ?? null) : undefined
    const seen = new Set()
    const extras = []
    const positionals = this.actions.filter((a) => !a.optional)
    let pi = 0
    const opts = this.actions.filter((a) => a.optional)
    const negLike = /^-\d+$|^-\d*\.\d+$/
    const isOptStr = (s) => s.length > 1 && s[0] === '-' && !negLike.test(s) &&
      !(s.includes(' ') && !opts.some((a) => a.flags.includes(s.split('=')[0])))
    const findOpt = (s) => {
      let name = s, val
      if (s.startsWith('--') && s.includes('=')) { name = s.slice(0, s.indexOf('=')); val = s.slice(s.indexOf('=') + 1) }
      for (const a of opts) if (a.flags.includes(name)) return [a, val]
      if (s.startsWith('--')) {
        const m = opts.filter((a) => a.flags.some((f) => f.startsWith('--') && f.startsWith(name)))
        if (m.length > 1) {
          this.error(`ambiguous option: ${name} could match ${m.map((a) => a.flags.find((f) => f.startsWith(name))).join(', ')}`)
        }
        if (m.length === 1) return [m[0], val]
      }
      return [null, val]
    }
    let i = 0, dd = false
    while (i < argv.length) {
      const s = argv[i]
      if (!dd && s === '--') { dd = true; i++; continue }
      if (!dd && isOptStr(s)) {
        const [a, val] = findOpt(s)
        if (!a) { extras.push(s); i++; continue }
        if (a.help) {
          process.stdout.write(this.formatHelp())
          throw new SysExit(0)
        }
        let v = val
        if (v === undefined) {
          const nx = argv[i + 1]
          if (nx === undefined || (isOptStr(nx) && !(dd)) || nx === '--') this.error(`argument ${a.flags.join('/')}: expected one argument`)
          v = nx
          i++
        }
        ns[a.dest] = v
        seen.add(a)
        i++
        continue
      }
      if (pi < positionals.length) { ns[positionals[pi].dest] = s; seen.add(positionals[pi]); pi++ } else extras.push(s)
      i++
    }
    const missing = this.actions.filter((a) => (a.required || !a.optional) && !seen.has(a))
    if (missing.length) {
      this.error('the following arguments are required: ' + missing.map((a) => (a.optional ? a.flags.join('/') : a.metavar)).join(', '))
    }
    if (extras.length) this.error('unrecognized arguments: ' + extras.join(' '))
    return ns
  }
}

// str(OSError) for a Node fs error: "[Errno 2] No such file or directory: 'path'"
const ERRNO = {
  ENOENT: [2, 'No such file or directory'], EACCES: [13, 'Permission denied'], EISDIR: [21, 'Is a directory'],
  ENOTDIR: [20, 'Not a directory'], EPERM: [1, 'Operation not permitted'], ELOOP: [62, 'Too many levels of symbolic links'],
  ENAMETOOLONG: [63, 'File name too long'], EMFILE: [24, 'Too many open files'],
}
export function isOSError(e) { return e && typeof e.code === 'string' && typeof e.syscall === 'string' }
export function osErrorStr(e, path) {
  const [n, msg] = ERRNO[e.code] ?? [e.errno !== undefined ? -e.errno : 0, e.message]
  return path === undefined ? `[Errno ${n}] ${msg}` : `[Errno ${n}] ${msg}: ${pyRepr(path)}`
}
