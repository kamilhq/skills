#!/usr/bin/env node
// Port of ../../cpp/gen_data.py (same command line, output and files). Node built-ins only.
import fs from 'node:fs'
import * as L from '../lib/rwlib.mjs'
import * as C from './cppsplit.mjs'

const PROG = 'gen_data'
const DOC = "Write C++ definitions of data the matched units only declared `extern`, from the original exe's sections.\n\n  python3 -I gen_data.py --config CFG.json [--pe EXE] [--only NAME[,NAME]] [--out FILE] [--project DIR]\n\nMatched units often declare tables as `extern` and match against the original's data; a rewrite needs real\ndefinitions. The config (a JSON file, or the \"data\" section of the cpp config) lists them:\n  \"pe\": \"work/game/Game.exe\",\n  \"symbols\": [{\"base\": \"0x623660\", \"stride\": 5, \"count\": 55, \"expr\": \"glyph[{i}]\"}],\n  \"items\": [{\"name\": \"areamusic\", \"va\": \"0x51bfb0\", \"type\": \"int32\", \"count\": 400, \"per_line\": 20,\n             \"width\": 2, \"decl\": \"static const int areamusic[20 * 20]\", \"file\": \"music/Music.cpp\"}, ...]\nItem keys: \"name\", \"va\" (virtual address with the image base), \"type\", \"count\" (elements) or \"dims\"\n([rows, columns, ...]: nested braces, one innermost row per line), \"per_line\" (default 16, strings 1),\n\"width\" (right-justify numbers), \"format\" (\"dec\", \"hex\" or \"hexN\": 0x%0NX), \"decl\" (the text before\n` = {`; default `<C type> <name>[<count>]`), \"file\" (where it goes, shown in the comment), \"stride\" (bytes\nper element, default the type's size), \"fields\" (type \"struct\": [\"uint32:hex4\", \"bool\", ...], read in order).\nTypes: int8 uint8 int16 uint16 int32 uint32 int64 uint64 float32 float64 bool, cstr (a pointer to a\nNUL-terminated string: a C literal, NULL, or a \"symbols\" expression), ptr (a \"symbols\" expression, NULL,\nor (void*)0x...). Floats are written with the fewest digits that read back to the same bits.\nAn item whose bytes all lie past its section's raw data (.bss) becomes a zero definition (`<decl>;`); one\nthat is partly initialised reads the rest as zeros.\nWithout --out the C++ text goes to stdout; with --out it goes to the file and a JSON summary to stdout\n(items, zero_initialised, unresolved_pointers). Exit 0, 2 on bad input (address outside every section,\nunknown type or format, missing key, bad number, non-finite float). Python standard library only. Port: ../js/cpp/gen_data.mjs."
const TYPES = {
  int8: ['b', 1, 'signed char'], uint8: ['B', 1, 'unsigned char'], int16: ['h', 2, 'short'], uint16: ['H', 2, 'unsigned short'],
  int32: ['i', 4, 'int'], uint32: ['I', 4, 'unsigned int'], int64: ['q', 8, 'long long'], uint64: ['Q', 8, 'unsigned long long'],
  float32: ['f', 4, 'float'], float64: ['d', 8, 'double'], bool: ['B', 1, 'bool'], cstr: ['I', 4, 'const char*'], ptr: ['I', 4, 'const void*']
}
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k)
class DataError extends Error {}
class KeyErr extends Error {}
const req = (o, k) => { if (!has(o, k)) throw new KeyErr(`'${k}'`); return o[k] }

function unpack (buf, off, code) {
  switch (code) {
    case 'b': return buf.readInt8(off)
    case 'B': return buf.readUInt8(off)
    case 'h': return buf.readInt16LE(off)
    case 'H': return buf.readUInt16LE(off)
    case 'i': return buf.readInt32LE(off)
    case 'I': return buf.readUInt32LE(off)
    case 'q': return buf.readBigInt64LE(off)
    case 'Q': return buf.readBigUInt64LE(off)
    case 'f': return buf.readFloatLE(off)
    case 'd': return buf.readDoubleLE(off)
  }
  throw new Error(code)
}

class PE {
  constructor (p) {
    const d = this.data = fs.readFileSync(p)
    if (d.length < 0x40 || d[0] !== 0x4d || d[1] !== 0x5a) throw new DataError(`${p}: not a PE file`)
    const pe = d.readUInt32LE(0x3c)
    if (!(d.length >= pe + 4 && d[pe] === 0x50 && d[pe + 1] === 0x45 && d[pe + 2] === 0 && d[pe + 3] === 0) || d.length < pe + 24 + 2) throw new DataError(`${p}: not a PE file`)
    const nsec = d.readUInt16LE(pe + 6)
    const optsz = d.readUInt16LE(pe + 20)
    const magic = d.readUInt16LE(pe + 24)
    if (d.length < pe + 24 + optsz + 40 * nsec || optsz < 0x20) throw new DataError(`${p}: truncated PE headers`)
    this.ptrSize = magic === 0x20b ? 8 : 4
    this.base = magic === 0x20b ? Number(d.readBigUInt64LE(pe + 24 + 24)) : d.readUInt32LE(pe + 24 + 28)
    this.sections = []
    let off = pe + 24 + optsz
    for (let i = 0; i < nsec; i++) {
      let e = off + 8
      while (e > off && d[e - 1] === 0) e--
      const name = d.subarray(off, e).toString('latin1')
      const [vsize, va, rawsize, rawptr] = [0, 4, 8, 12].map(k => d.readUInt32LE(off + 8 + k))
      this.sections.push([name, this.base + va, vsize, rawptr, rawsize])
      off += 40
    }
  }

  section (va) {
    for (const s of this.sections) if (s[1] <= va && va < s[1] + Math.max(s[2], s[4])) return s
    return null
  }

  read (va, n) {
    const s = this.section(va)
    if (s === null || va + n > s[1] + Math.max(s[2], s[4])) throw new DataError(`address range 0x${va.toString(16)}+${n} is not inside one section`)
    const o = va - s[1]
    const raw = Math.max(0, Math.min(n, s[4] - o))
    const b = Buffer.alloc(n)
    if (raw > 0) this.data.copy(b, 0, s[3] + o, Math.min(s[3] + o + raw, this.data.length))
    return [b, raw]
  }

  cstr (va) {
    const out = []
    for (;;) {
      const b = this.read(va + out.length, 1)[0][0]
      if (b === 0) return Buffer.from(out)
      out.push(b)
    }
  }
}

function cString (b) {
  const out = []
  for (const ch of b) {
    if (ch === 0x22) out.push('\\"')
    else if (ch === 0x5c) out.push('\\\\')
    else if (ch === 0x0a) out.push('\\n')
    else if (ch === 0x09) out.push('\\t')
    else if (ch >= 32 && ch < 127) out.push(String.fromCharCode(ch))
    else out.push('\\x' + ch.toString(16).padStart(2, '0'))
  }
  const s = out.join('').replace(/(\\x[0-9a-f]{2})(?=[0-9a-fA-F])/g, '$1""')
  return '"' + s + '"'
}

// Python's '%.{p}g' % x: exact decimal expansion of the double, rounded half to even
function pyG (x, p) {
  if (x === 0) return Object.is(x, -0) ? '-0' : '0'
  const neg = x < 0
  const dv = new DataView(new ArrayBuffer(8))
  dv.setFloat64(0, Math.abs(x))
  const hi = dv.getUint32(0); const lo = dv.getUint32(4)
  const ex = (hi >>> 20) & 0x7ff
  let m = (BigInt(hi & 0xfffff) << 32n) | BigInt(lo)
  let e
  if (ex === 0) e = -1074
  else { m |= 1n << 52n; e = ex - 1075 }
  let digits; let s
  if (e >= 0) { digits = (m << BigInt(e)).toString(); s = 0 } else { digits = (m * 5n ** BigInt(-e)).toString(); s = e }
  let X = digits.length - 1 + s
  let keep
  if (digits.length > p) {
    keep = digits.slice(0, p)
    const rest = digits.slice(p)
    let up = false
    if (rest[0] > '5') up = true
    else if (rest[0] === '5') up = /[1-9]/.test(rest.slice(1)) || (parseInt(keep[keep.length - 1], 10) % 2 === 1)
    if (up) {
      const k = (BigInt(keep) + 1n).toString()
      if (k.length > p) { keep = k.slice(0, p); X += 1 } else keep = k
    }
  } else keep = digits.padEnd(p, '0')
  let out
  if (X < -4 || X >= p) {
    const frac = keep.slice(1).replace(/0+$/, '')
    out = keep[0] + (frac ? '.' + frac : '') + 'e' + (X < 0 ? '-' : '+') + String(Math.abs(X)).padStart(2, '0')
  } else if (X >= 0) {
    const frac = keep.slice(X + 1).replace(/0+$/, '')
    out = keep.slice(0, X + 1) + (frac ? '.' + frac : '')
  } else {
    const frac = ('0'.repeat(-X - 1) + keep).replace(/0+$/, '')
    out = '0' + (frac ? '.' + frac : '')
  }
  return (neg ? '-' : '') + out
}
function fmtFloat (v, single) {
  if (!Number.isFinite(v)) throw new DataError('non-finite float value')
  let s
  for (let p = 1; p < 18; p++) {
    s = pyG(v, p)
    const back = single ? Math.fround(parseFloat(s)) : parseFloat(s)
    if (back === v) break
  }
  if (!/[.e]/.test(s)) s += '.0'
  return s + (single ? 'f' : '')
}
const hexU = v => v.toString(16).toUpperCase()
function fmtInt (v, fmt) {
  if (!/^(dec|hex|hex[0-9]+)$/.test(fmt)) throw new DataError(`unknown format ${fmt}`)
  if (fmt === 'hex' || (fmt.startsWith('hex') && v < 0)) return v >= 0 ? '0x' + hexU(v) : '-0x' + hexU(-v)
  if (fmt.startsWith('hex')) return '0x' + hexU(v).padStart(parseInt(fmt.slice(3), 10), '0')
  return String(v)
}
function intVal (n) {
  if (typeof n === 'number' && Number.isInteger(n)) return n
  if (typeof n === 'bigint') return Number(n)
  if (typeof n !== 'string') throw new DataError('bad number (not an integer or a string)')
  const m = /^(-?)(0[xX][0-9a-fA-F]+|[0-9]+)$/.exec(n)
  if (!m) throw new DataError(`bad number: ${n}`)
  const v = /^0[xX]/.test(m[2]) ? parseInt(m[2].slice(2), 16) : parseInt(m[2], 10)
  return m[1] ? -v : v
}

class Gen {
  constructor (pe, symbols) {
    this.pe = pe
    this.symbols = symbols.map(s => [intVal(req(s, 'base')), intVal(has(s, 'stride') ? s.stride : 1), intVal(has(s, 'count') ? s.count : 1), req(s, 'expr')])
    this.unresolved = 0
  }

  symbol (p) {
    for (const [base, stride, count, expr] of this.symbols) {
      if (base <= p && p < base + stride * count && (p - base) % stride === 0) return expr.replaceAll('{i}', String((p - base) / stride))
    }
    return null
  }

  value (va, typ, fmt) {
    if (!has(TYPES, typ)) throw new DataError(`unknown type ${typ}`)
    let [code, size] = TYPES[typ]
    if ((typ === 'cstr' || typ === 'ptr') && this.pe.ptrSize === 8) { code = 'Q'; size = 8 }
    const [b] = this.pe.read(va, size)
    let v = unpack(b, 0, code)
    if (typ === 'cstr' || typ === 'ptr') {
      v = Number(v)
      if (v === 0) return 'NULL'
      const sym = this.symbol(v)
      if (sym !== null) return sym
      if (typ === 'cstr') return cString(this.pe.cstr(v))
      this.unresolved++
      return '(void*)0x' + hexU(v)
    }
    if (typ === 'bool') return v ? 'true' : 'false'
    if (typ === 'float32' || typ === 'float64') return fmtFloat(v, typ === 'float32')
    return fmtInt(v, fmt)
  }

  element (va, item) {
    const typ = item.type
    if (typ === 'struct') {
      const vals = []; let off = 0
      for (const f of req(item, 'fields')) {
        const i = f.indexOf(':')
        const t = i < 0 ? f : f.slice(0, i); const fm = i < 0 ? '' : f.slice(i + 1)
        vals.push(this.value(va + off, t, fm || 'dec'))
        off += this.sizeOf(t)
      }
      return '{' + vals.join(', ') + '}'
    }
    return this.value(va, typ, has(item, 'format') ? item.format : 'dec')
  }

  sizeOf (typ) {
    if (!has(TYPES, typ)) throw new DataError(`unknown type ${typ}`)
    return typ === 'cstr' || typ === 'ptr' ? this.pe.ptrSize : TYPES[typ][1]
  }

  item (item) {
    const name = req(item, 'name')
    const va = intVal(req(item, 'va'))
    const typ = req(item, 'type')
    const dims = item.dims && item.dims.length ? item.dims.map(intVal) : [intVal(has(item, 'count') ? item.count : 1)]
    if (dims.some(x => x < 1)) throw new DataError(`${name}: count and dims must be at least 1`)
    const total = dims.reduce((a, b) => a * b, 1)
    let stride
    if (typ === 'struct') {
      if (!has(item, 'stride')) throw new DataError(`${name}: a struct item needs "stride"`)
      stride = intVal(item.stride)
    } else {
      const size = this.sizeOf(typ)
      stride = intVal(has(item, 'stride') ? item.stride : size)
    }
    const [, raw] = this.pe.read(va, stride * total)
    const sec = this.pe.section(va)[0]
    const decl = item.decl || `${has(TYPES, typ) ? TYPES[typ][2] : 'struct'} ${name}${dims.map(x => `[${x}]`).join('')}`
    const head = `// ${name}: 0x${va.toString(16)} (${sec}), ${total} x ${typ}${item.file ? ', for ' + item.file : ''}`
    if (raw === 0) return [head + `, zero-initialised (no raw data)\n${decl};\n`, true]
    const width = intVal(has(item, 'width') ? item.width : 0)
    const vals = []
    for (let i = 0; i < total; i++) vals.push(this.element(va + i * stride, item).padStart(width))
    const per = intVal(has(item, 'per_line') ? item.per_line : (typ === 'cstr' || typ === 'struct' ? 1 : 16))
    if (per < 1) throw new DataError(`${name}: per_line must be at least 1`)
    let body
    if (dims.length > 1) body = this.nest(vals, dims, 1)
    else {
      const rows = []
      for (let i = 0; i < vals.length; i += per) rows.push('    ' + vals.slice(i, i + per).join(', ') + ',')
      body = rows.join('\n')
    }
    return [`${head}\n${decl} = {\n${body}\n};\n`, false]
  }

  nest (vals, dims, depth) {
    const ind = '    '.repeat(depth)
    const n = Math.floor(vals.length / dims[0])
    const lines = []
    for (let i = 0; i < dims[0]; i++) {
      const sub = vals.slice(i * n, (i + 1) * n)
      if (dims.length === 2) lines.push(ind + '{' + sub.join(', ') + '},')
      else lines.push(ind + '{\n' + this.nest(sub, dims.slice(1), depth + 1) + '\n' + ind + '},')
    }
    return lines.join('\n')
  }
}

function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [['--config', 'str', L.REQUIRED], ['--pe', 'str', null], ['--only', 'str', null], ['--out', 'str', null], ['--project', 'str', '.']])
  const err = msg => { process.stdout.write(L.dumps({ error: msg }) + '\n'); return 2 }
  let cfg
  try {
    cfg = L.pyParse(fs.readFileSync(a.config, 'utf8'))
    if (cfg === null || typeof cfg !== 'object' || Array.isArray(cfg)) throw new SyntaxError('not an object')
    cfg = has(cfg, 'data') ? cfg.data : cfg
  } catch (e) {
    return err(`config cannot be read: ${a.config}`)
  }
  const pePath = a.pe || (cfg.pe ? L.join(a.project, cfg.pe) : null)
  if (!pePath) return err('no exe (--pe or "pe" in the config)')
  const only = a.only ? a.only.split(',').filter(x => x) : null
  const items = (cfg.items || []).filter(it => only === null || only.includes(it.name))
  if (only && only.length) {
    const missing = only.filter(n => !items.map(it => it.name).includes(n))
    if (missing.length) return err(`no such item: ${missing[0]}`)
  }
  let g; const out = []; const zero = []
  try {
    let pe
    try { pe = new PE(pePath) } catch (e) {
      if (e.code) return err(`${pePath}: ${C.STRERROR[e.code] || e.message}`)
      throw e
    }
    g = new Gen(pe, cfg.symbols || [])
    for (const it of items) {
      const [text, z] = g.item(it)
      out.push(text)
      if (z) zero.push(it.name)
    }
  } catch (e) {
    if (e instanceof DataError) return err(e.message)
    if (e instanceof KeyErr) return err(`missing key: ${e.message}`)
    throw e
  }
  const text = out.join('\n')
  if (a.out) {
    C.writeText(a.out, text)
    process.stdout.write(L.dumps(new Map([['items', items.length], ['zero_initialised', zero], ['unresolved_pointers', g.unresolved], ['out', a.out]])) + '\n')
  } else process.stdout.write(text)
  return 0
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
