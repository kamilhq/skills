// JavaScript port of scripts/formats/fmt_zip.py: ZIP archives (.zip, GOG's goggame-*.hashdb; add other ZIP-based
// extensions to EXTS) -> member files + manifest; rebuilt byte-identically.
//
// Decoded layout (outdir):
//     zip.json            manifest: every field of every local header, central record and the EOCD,
//                         decoded (DOS date/time fields, attributes, extra fields, per-member codec)
//     members/<path>      every member as an ordinary file (directory entries as directories)
//     raw_streams/<n>.deflate   only for members whose deflate stream no known encoder reproduces
//                         (counted as opaque); used only while members/<path> still equals its content
//
// CRC-32, compressed/uncompressed sizes, local header offsets, central directory size/offset and entry
// counts are recomputed on encode; a stored value is kept only if it disagrees with the recomputation.
// Deflate encoders tried: zlib profiles and the 7-Zip port (fmt_zip_7zdeflate); see formats/README.md. The zlib profiles need the same zlib build as Python's (1.2.12 here).
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'

import { dump, load, PyDict } from '../lib/pyjson.mjs'
import * as p7 from './fmt_zip_7zdeflate.mjs'

export const EXTS = ['.zip', '.hashdb']

const SIG_LOCAL = 0x04034b50
const SIG_CENTRAL = 0x02014b50
const SIG_EOCD = 0x06054b50

const HOST_NAMES = { 0: 'MS-DOS/FAT', 3: 'Unix', 10: 'NTFS', 11: 'VFAT', 19: 'OS X' }
const DOS_BITS = [[0x01, 'READONLY'], [0x02, 'HIDDEN'], [0x04, 'SYSTEM'], [0x08, 'VOLUME'], [0x10, 'DIRECTORY'],
  [0x20, 'ARCHIVE'], [0x8000, 'UNIX_EXTENSION']]   // 0x8000: p7zip FILE_ATTRIBUTE_UNIX_EXTENSION

// Deflate profiles tried on decode, in order. Each is a dict stored verbatim in the manifest.
const P7ZIP_PROFILES = [
  { encoder: 'p7zip-9.20-deflate', passes: 3, fast_bytes: 64, mf_cycles: 0 },    // 7z a -tzip -mx=7
  { encoder: 'p7zip-9.20-deflate', passes: 10, fast_bytes: 128, mf_cycles: 0 },  // -mx=9
]
const ZLIB_PROFILES = []
for (const lv of [6, 9, 1, 2, 3, 4, 5, 7, 8]) {
  for (const ml of [8, 9]) ZLIB_PROFILES.push({ encoder: 'zlib', level: lv, mem_level: ml, wbits: -15 })
}

// ---------------------------------------------------------------- small helpers
const g = (d, k) => (d instanceof Map ? d.get(k) : d[k])
const has = (d, k) => (d instanceof Map ? d.has(k) : Object.prototype.hasOwnProperty.call(d, k))
const num = (v) => (typeof v === 'bigint' ? v : Number(v))

function hex(buf) { return Buffer.from(buf.buffer, buf.byteOffset, buf.length).toString('hex') }
function fromHex(s) {      // bytes.fromhex: whitespace between bytes allowed
  const t = s.replace(/\s/g, '')
  if (t.length % 2 || /[^0-9a-fA-F]/.test(t)) throw new Error('ValueError: non-hexadecimal number found in fromhex()')
  return Buffer.from(t, 'hex')
}

let crcTable = null
function crc32(buf) {
  if (typeof zlib.crc32 === 'function') return zlib.crc32(buf) >>> 0
  if (!crcTable) {
    crcTable = new Int32Array(256)
    for (let i = 0; i < 256; i++) {
      let r = i
      for (let j = 0; j < 8; j++) r = (r & 1) ? ((r >>> 1) ^ 0xEDB88320) : (r >>> 1)
      crcTable[i] = r
    }
  }
  let c = -1
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xFF] ^ (c >>> 8)
  return (c ^ -1) >>> 0
}

// CP437 (Python's 'cp437' codec: 0x00-0x7F map to ASCII)
const CP437_HIGH = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀' +
  'αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ '
const CP437_REV = new Map([...CP437_HIGH].map((ch, i) => [ch, 0x80 + i]))
function cp437Decode(raw) {
  let s = ''
  for (const b of raw) s += b < 0x80 ? String.fromCharCode(b) : CP437_HIGH[b - 0x80]
  return s
}
function cp437Encode(s) {
  const out = []
  for (const ch of s) {
    const c = ch.codePointAt(0)
    if (c < 0x80) out.push(c)
    else if (CP437_REV.has(ch)) out.push(CP437_REV.get(ch))
    else throw new Error("UnicodeEncodeError: 'charmap' codec can't encode character")
  }
  return Buffer.from(out)
}
function latin1Encode(s) {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0xFF) throw new Error("UnicodeEncodeError: 'latin-1' codec can't encode character")
  }
  return Buffer.from(s, 'latin1')
}
function utf8Encode(s) {
  for (let i = 0; i < s.length; i++) {      // Python refuses lone surrogates; Buffer would write U+FFFD
    const c = s.charCodeAt(i)
    if (c >= 0xD800 && c <= 0xDBFF) {
      const d = s.charCodeAt(i + 1)
      if (d >= 0xDC00 && d <= 0xDFFF) { i++; continue }
      throw new Error("UnicodeEncodeError: 'utf-8' codec can't encode character: surrogates not allowed")
    }
    if (c >= 0xDC00 && c <= 0xDFFF) throw new Error("UnicodeEncodeError: 'utf-8' codec can't encode character")
  }
  return Buffer.from(s, 'utf8')
}
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

function pyStrRepr(s) {  // repr() of an ASCII-ish str, enough for the notes
  return s.includes("'") && !s.includes('"') ? '"' + s + '"' : "'" + s.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'"
}

// ---------------------------------------------------------------- codecs
function zlibCompress(data, prof) {
  const level = num(g(prof, 'level')), memLevel = num(g(prof, 'mem_level')), wbits = num(g(prof, 'wbits'))
  if (wbits < 0) return zlib.deflateRawSync(data, { level, memLevel, windowBits: -wbits })
  if (wbits >= 8 && wbits <= 15) return zlib.deflateSync(data, { level, memLevel, windowBits: wbits })
  throw new Error('NotImplementedError: zlib wbits ' + wbits + ' (gzip container) not ported')
}

export function compress(data, prof) {
  const enc = g(prof, 'encoder')
  if (enc === 'zlib') return zlibCompress(data, prof)
  if (enc === 'p7zip-9.20-deflate') {
    return p7.deflate_7z(data, num(g(prof, 'passes')), num(g(prof, 'fast_bytes')), num(g(prof, 'mf_cycles')))
  }
  throw new Error('ValueError: unknown encoder ' + pyStrRepr(String(enc)))
}

export function inflate(stream) {
  let res
  try {
    res = zlib.inflateRawSync(stream, { info: true })
  } catch (e) {
    throw new Error('ValueError: deflate stream does not end exactly at the compressed size (' + e.message + ')')
  }
  if (res.engine.bytesWritten !== stream.length) {
    throw new Error('ValueError: deflate stream does not end exactly at the compressed size')
  }
  return res.buffer
}

// ---------------------------------------------------------------- field helpers
function dosTimeDec(t, d) {
  return { year: 1980 + (d >> 9), month: (d >> 5) & 15, day: d & 31, hour: t >> 11, minute: (t >> 5) & 63,
    second: (t & 31) * 2 }
}

function dosTimeEnc(x) {
  const second = num(g(x, 'second'))
  if (second & 1) throw new Error('ValueError: DOS time seconds must be even')
  const d = ((num(g(x, 'year')) - 1980) << 9) | (num(g(x, 'month')) << 5) | num(g(x, 'day'))
  const t = (num(g(x, 'hour')) << 11) | (num(g(x, 'minute')) << 5) | (second >> 1)
  return [t, d]
}

function verDec(v) {
  return { version: `${Math.floor((v & 0xFF) / 10)}.${(v & 0xFF) % 10}`, host: v >> 8,
    host_name: HOST_NAMES[v >> 8] ?? 'unknown' }
}

function verEnc(x) {
  const [a, b] = g(x, 'version').split('.')
  return (num(g(x, 'host')) << 8) | (parseInt(a, 10) * 10 + parseInt(b, 10))
}

function attrDec(ext) {
  const low = ext & 0xFFFF
  const names = DOS_BITS.filter(([bit]) => low & bit).map(([, nm]) => nm)
  let known = 0
  for (const [bit] of DOS_BITS) known |= bit
  const r = { unix_mode: '0' + (ext >>> 16).toString(8), dos_attributes: names }
  if (low & ~known) r.dos_other_bits = low & ~known
  return r
}

function attrEnc(x) {
  let low = has(x, 'dos_other_bits') ? num(g(x, 'dos_other_bits')) : 0
  const bits = Object.fromEntries(DOS_BITS.map(([bit, nm]) => [nm, bit]))
  for (const nm of g(x, 'dos_attributes')) {
    if (!(nm in bits)) throw new Error('KeyError: ' + pyStrRepr(nm))
    low |= bits[nm]
  }
  return ((parseInt(g(x, 'unix_mode'), 8) << 16) | low) >>> 0
}

// Parse extra field into a list of blocks. Unknown blocks are kept as hex and counted opaque.
function extraDec(raw, opaque) {
  const out = []
  let p = 0
  while (p < raw.length) {
    if (p + 4 > raw.length) {
      out.push({ trailing_hex: hex(raw.subarray(p)) })
      opaque[0] += raw.length - p
      break
    }
    const hid = raw.readUInt16LE(p), sz = raw.readUInt16LE(p + 2)
    const body = raw.subarray(p + 4, p + 4 + sz)
    let blk = null
    if (hid === 0x000a && body.length >= 4 && sz === body.length) {
      const reserved = body.readUInt32LE(0)
      const tags = []
      let q = 4
      let ok = true
      while (q < body.length) {
        if (q + 4 > body.length) { ok = false; break }
        const tag = body.readUInt16LE(q), tsz = body.readUInt16LE(q + 2)
        const tb = body.subarray(q + 4, q + 4 + tsz)
        if (tag === 1 && tsz === 24) {
          if (tb.length !== 24) throw new Error('struct.error: unpack requires a buffer of 24 bytes')
          tags.push({ tag: 1, mtime_filetime: tb.readBigUInt64LE(0), atime_filetime: tb.readBigUInt64LE(8),
            ctime_filetime: tb.readBigUInt64LE(16) })
        } else { ok = false; break }
        q += 4 + tsz
      }
      if (ok) blk = { id: '0x000a', name: 'NTFS', reserved, tags }
    }
    if (blk === null) {
      blk = { id: '0x' + hid.toString(16).padStart(4, '0'), size: sz, data_hex: hex(body) }
      opaque[0] += body.length
    }
    out.push(blk)
    p += 4 + sz
  }
  return out
}

function u16(v) { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b }
function u32(v) { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b }
function u64(v) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b }

function extraEnc(blocks) {
  const parts = []
  for (const blk of blocks) {
    if (has(blk, 'trailing_hex')) { parts.push(fromHex(g(blk, 'trailing_hex'))); continue }
    const hid = parseInt(g(blk, 'id'), 16)
    if (has(blk, 'name') && g(blk, 'name') === 'NTFS') {
      const bp = [u32(num(g(blk, 'reserved')))]
      for (const t of g(blk, 'tags')) {
        bp.push(u16(1), u16(24), u64(g(t, 'mtime_filetime')), u64(g(t, 'atime_filetime')), u64(g(t, 'ctime_filetime')))
      }
      const body = Buffer.concat(bp)
      parts.push(u16(hid), u16(body.length), body)
    } else {
      const body = fromHex(g(blk, 'data_hex'))
      parts.push(u16(hid), u16(num(g(blk, 'size'))), body)
    }
  }
  return Buffer.concat(parts)
}

function nameDec(raw, utf8) {
  if (utf8) {
    try {
      const s = UTF8_STRICT.decode(raw)
      if (Buffer.from(s, 'utf8').equals(raw)) return [s, null]
    } catch (e) { /* UnicodeError */ }
  } else {
    return [cp437Decode(raw), null]          // every byte maps, and the mapping round-trips
  }
  return [raw.toString('latin1'), hex(raw)]
}

// os.path.join(*parts) of the cleaned member name, with '/' separators
function safeRel(name) {
  const parts = name.replace(/\\/g, '/').split('/').filter((x) => x !== '' && x !== '.')
  if (parts.some((x) => x === '..') || !parts.length) throw new Error('ValueError: unsafe member name ' + pyStrRepr(name))
  return parts.join('/')
}

function writeFile(p, data) { fs.writeFileSync(p, data) }

// ---------------------------------------------------------------- decode
export function decode_to_dir(data, outdir) {
  data = Buffer.isBuffer(data) ? data : Buffer.from(data)
  const opaque = [0]
  const notes = []
  const e = data.lastIndexOf(Buffer.from('PK\x05\x06', 'latin1'))
  if (e < 0) throw new Error('ValueError: no EOCD')
  if (e + 22 > data.length) throw new Error('struct.error: unpack_from requires a buffer of at least 22 bytes')
  const disk = data.readUInt16LE(e + 4), cdDisk = data.readUInt16LE(e + 6), nDisk = data.readUInt16LE(e + 8)
  const nTotal = data.readUInt16LE(e + 10), cdSize = data.readUInt32LE(e + 12), cdOff = data.readUInt32LE(e + 16)
  const clen = data.readUInt16LE(e + 20)
  if (nTotal === 0xFFFF || cdOff === 0xFFFFFFFF) throw new Error('NotImplementedError: zip64')
  const comment = data.subarray(e + 22, e + 22 + clen)
  const trailing = data.subarray(Math.min(e + 22 + clen, data.length))
  // central directory
  const entries = []
  let p = cdOff
  for (let idx = 0; idx < nTotal; idx++) {
    if (p + 46 > data.length) throw new Error('struct.error: unpack_from requires a buffer of at least 46 bytes')
    if (data.readUInt32LE(p) !== SIG_CENTRAL) throw new Error('ValueError: bad central signature at ' + p)
    const ce = {
      made_by: data.readUInt16LE(p + 4), need: data.readUInt16LE(p + 6), flags: data.readUInt16LE(p + 8),
      method: data.readUInt16LE(p + 10), mt: data.readUInt16LE(p + 12), md: data.readUInt16LE(p + 14),
      crc: data.readUInt32LE(p + 16), csz: data.readUInt32LE(p + 20), usz: data.readUInt32LE(p + 24),
    }
    const nl = data.readUInt16LE(p + 28), xl = data.readUInt16LE(p + 30), cl = data.readUInt16LE(p + 32)
    ce.dstart = data.readUInt16LE(p + 34)
    ce.iattr = data.readUInt16LE(p + 36)
    ce.eattr = data.readUInt32LE(p + 38)
    ce.loff = data.readUInt32LE(p + 42)
    ce.name_raw = data.subarray(p + 46, p + 46 + nl)
    ce.extra = data.subarray(p + 46 + nl, p + 46 + nl + xl)
    ce.comment = data.subarray(p + 46 + nl + xl, p + 46 + nl + xl + cl)
    entries.push(ce)
    p += 46 + nl + xl + cl
  }
  if (p !== e) throw new Error(`ValueError: central directory does not end at EOCD (${p} != ${e})`)

  const membersDir = path.join(outdir, 'members')
  fs.mkdirSync(membersDir, { recursive: true })
  const order = entries.map((_, i) => i).sort((a, b) => entries[a].loff - entries[b].loff)
  const manEntries = new Array(entries.length).fill(null)
  const lis = new Array(entries.length)
  let pos = 0
  const gaps = []
  for (let li = 0; li < order.length; li++) {
    const i = order[li]
    const ce = entries[i]
    const o = ce.loff
    if (o !== pos) {
      if (o < pos) throw new Error('ValueError: overlapping local records')
      gaps.push({ before_local_index: li, hex: hex(data.subarray(pos, o)) })
      opaque[0] += o - pos
    }
    if (o + 30 > data.length) throw new Error('struct.error: unpack_from requires a buffer of at least 30 bytes')
    if (data.readUInt32LE(o) !== SIG_LOCAL) throw new Error('ValueError: bad local signature at ' + o)
    const lNeed = data.readUInt16LE(o + 4), lFlags = data.readUInt16LE(o + 6), lMethod = data.readUInt16LE(o + 8)
    const lMt = data.readUInt16LE(o + 10), lMd = data.readUInt16LE(o + 12), lCrc = data.readUInt32LE(o + 14)
    const lCsz = data.readUInt32LE(o + 18), lUsz = data.readUInt32LE(o + 22)
    const lNl = data.readUInt16LE(o + 26), lXl = data.readUInt16LE(o + 28)
    const lName = data.subarray(o + 30, o + 30 + lNl)
    const lExtra = data.subarray(o + 30 + lNl, o + 30 + lNl + lXl)
    const ds = o + 30 + lNl + lXl
    if ((lFlags | ce.flags) & 0x0008) throw new Error('NotImplementedError: data descriptors')
    const csz = ce.csz
    const stream = data.subarray(ds, ds + csz)
    pos = ds + csz

    const utf8 = Boolean(ce.flags & 0x0800)
    const [name, nameHex] = nameDec(ce.name_raw, utf8)
    const m = new PyDict([['name', name]])
    if (nameHex) m.set('name_raw_hex', nameHex)
    const isDir = name.endsWith('/')
    m.set('is_dir', isDir)
    m.set('central', {
      made_by: verDec(ce.made_by), version_needed: verDec(ce.need), flags: ce.flags,
      method: ce.method, mtime: dosTimeDec(ce.mt, ce.md),
      disk_start: ce.dstart, internal_attr: ce.iattr, external_attr: attrDec(ce.eattr),
      extra: extraDec(ce.extra, opaque), comment: ce.comment.toString('latin1'),
    })
    const local = {
      version_needed: verDec(lNeed), flags: lFlags, method: lMethod,
      mtime: dosTimeDec(lMt, lMd), extra: extraDec(lExtra, opaque),
    }
    m.set('local', local)
    if (!lName.equals(ce.name_raw)) local.name_raw_hex = hex(lName)
    if (ce.method !== lMethod) throw new Error('ValueError: local/central method mismatch')

    // content
    let content
    if (ce.method === 0) content = stream
    else if (ce.method === 8) content = inflate(stream)
    else throw new Error('NotImplementedError: method ' + ce.method)
    const crc = crc32(content)
    // sizes/CRC: recomputed on encode; keep overrides only where the header disagrees
    const ov = new PyDict()
    for (const [k, v, want] of [['central_crc', ce.crc, crc], ['local_crc', lCrc, crc],
      ['central_usize', ce.usz, content.length], ['local_usize', lUsz, content.length],
      ['local_csize', lCsz, csz]]) {
      if (v !== want) ov.set(k, v)
    }
    if (ov.size) {
      m.set('header_overrides', ov)
      const keys = [...ov.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
      notes.push(`${name}: header values differ from recomputation: [${keys.map(pyStrRepr).join(', ')}]`)
    }

    if (isDir) {
      if (content.length) throw new Error('ValueError: directory entry with data')
      fs.mkdirSync(path.join(membersDir, safeRel(name)), { recursive: true })
    } else {
      const fp = path.join(membersDir, safeRel(name))
      fs.mkdirSync(path.dirname(fp), { recursive: true })
      writeFile(fp, content)
    }
    m.set('path', isDir ? null : 'members/' + safeRel(name))

    if (ce.method === 8) m.set('codec', findCodec(content, stream, ce, m, outdir, opaque, notes, li))
    manEntries[i] = m
    lis[i] = li
  }

  if (pos !== cdOff) {
    if (cdOff < pos) throw new Error('ValueError: central directory overlaps member data')
    gaps.push({ before_central_directory: true, hex: hex(data.subarray(pos, cdOff)) })
    opaque[0] += cdOff - pos
  }

  const localOrder = lis
  const eocd = new PyDict([['disk', disk], ['cd_disk', cdDisk], ['comment', comment.toString('latin1')]])
  if (nDisk !== nTotal || nTotal !== entries.length) eocd.set('entries_on_disk', nDisk)
  if (cdSize !== e - cdOff) eocd.set('cd_size_override', cdSize)
  const man = new PyDict([['format', 'zip'], ['entries', manEntries], ['eocd', eocd]])
  if (localOrder.some((v, k) => v !== k)) man.set('local_order', localOrder)
  if (gaps.length) man.set('gaps', gaps)
  if (trailing.length) {
    man.set('trailing_hex', hex(trailing))
    opaque[0] += trailing.length
  }
  dump(man, path.join(outdir, 'zip.json'), { indent: 1, ensureAscii: false })
  return { opaque_bytes: opaque[0], notes }
}

function findCodec(content, stream, ce, m, outdir, opaque, notes, li) {
  const host = ce.made_by >> 8, ver = ce.made_by & 0xFF
  const order = (host === 3 && ver === 63) ? [...P7ZIP_PROFILES, ...ZLIB_PROFILES] : [...ZLIB_PROFILES, ...P7ZIP_PROFILES]
  for (const prof of order) {
    if (prof.encoder === 'p7zip-9.20-deflate' && content.length > 4_000_000 && prof.passes !== 3) continue
    if (compress(content, prof).equals(stream)) return { ...prof }
  }
  // not reproduced: keep the raw stream (opaque) beside the member file
  fs.mkdirSync(path.join(outdir, 'raw_streams'), { recursive: true })
  const rel = 'raw_streams/' + String(li).padStart(3, '0') + '.deflate'
  writeFile(path.join(outdir, rel), stream)
  opaque[0] += stream.length
  notes.push(`${m.get('name')}: deflate stream (${stream.length} bytes) not reproduced by any known encoder; kept raw in ${rel}`)
  return { encoder: 'raw', raw_stream: rel,
    fallback_if_member_edited: { encoder: 'zlib', level: 6, mem_level: 8, wbits: -15 } }
}

// ---------------------------------------------------------------- encode
export function encode_from_dir(outdir) {
  const man = load(path.join(outdir, 'zip.json'))
  const ents = man.get('entries')
  const n = ents.length
  const localOrder = man.has('local_order') ? man.get('local_order').map(num) : [...Array(n).keys()]
  const byLocal = [...Array(n).keys()].sort((a, b) => localOrder[a] - localOrder[b])
  const gapsBefore = new Map()
  let gapCd = Buffer.alloc(0)
  for (const gp of (man.has('gaps') ? man.get('gaps') : [])) {
    if (has(gp, 'before_central_directory') && g(gp, 'before_central_directory')) gapCd = fromHex(g(gp, 'hex'))
    else gapsBefore.set(num(g(gp, 'before_local_index')), fromHex(g(gp, 'hex')))
  }
  const out = []
  let outLen = 0
  const push = (b) => { out.push(b); outLen += b.length }
  const info = new Array(n)
  for (let li = 0; li < byLocal.length; li++) {
    const i = byLocal[li]
    const m = ents[i]
    if (gapsBefore.has(li)) push(gapsBefore.get(li))
    const c = m.get('central'), l = m.get('local')
    const utf8 = Boolean(num(c.get('flags')) & 0x0800)
    const nameRaw = m.has('name_raw_hex') ? fromHex(m.get('name_raw_hex'))
      : (utf8 ? utf8Encode(m.get('name')) : cp437Encode(m.get('name')))
    const lName = l.has('name_raw_hex') ? fromHex(l.get('name_raw_hex')) : nameRaw
    const content = m.get('is_dir') ? Buffer.alloc(0) : fs.readFileSync(path.join(outdir, m.get('path')))
    const method = num(c.get('method'))
    let stream
    if (method === 0) stream = content
    else {
      const codec = m.get('codec')
      if (codec.get('encoder') === 'raw') {
        const raw = fs.readFileSync(path.join(outdir, codec.get('raw_stream')))
        stream = inflate(raw).equals(content) ? raw : compress(content, codec.get('fallback_if_member_edited'))
      } else stream = compress(content, codec)
    }
    const crc = crc32(content)
    const ov = m.has('header_overrides') ? m.get('header_overrides') : new PyDict()
    const ovg = (k, d) => (ov.has(k) ? num(ov.get(k)) : d)
    const lExtra = extraEnc(l.get('extra'))
    const [lt, ld] = dosTimeEnc(l.get('mtime'))
    const offset = outLen
    const h = Buffer.alloc(30)
    h.writeUInt32LE(SIG_LOCAL, 0)
    h.writeUInt16LE(verEnc(l.get('version_needed')), 4)
    h.writeUInt16LE(num(l.get('flags')), 6)
    h.writeUInt16LE(num(l.get('method')), 8)
    h.writeUInt16LE(lt, 10)
    h.writeUInt16LE(ld, 12)
    h.writeUInt32LE(ovg('local_crc', crc), 14)
    h.writeUInt32LE(ovg('local_csize', stream.length), 18)
    h.writeUInt32LE(ovg('local_usize', content.length), 22)
    h.writeUInt16LE(lName.length, 26)
    h.writeUInt16LE(lExtra.length, 28)
    push(h); push(lName); push(lExtra); push(stream)
    info[i] = [offset, crc, stream.length, content.length, nameRaw]
  }
  push(gapCd)
  const cdOff = outLen
  for (let i = 0; i < n; i++) {
    const m = ents[i]
    const c = m.get('central')
    const [offset, crc, csz, usz, nameRaw] = info[i]
    const ov = m.has('header_overrides') ? m.get('header_overrides') : new PyDict()
    const ovg = (k, d) => (ov.has(k) ? num(ov.get(k)) : d)
    const cx = extraEnc(c.get('extra'))
    const cc = latin1Encode(c.get('comment'))
    const [ct, cdd] = dosTimeEnc(c.get('mtime'))
    const h = Buffer.alloc(46)
    h.writeUInt32LE(SIG_CENTRAL, 0)
    h.writeUInt16LE(verEnc(c.get('made_by')), 4)
    h.writeUInt16LE(verEnc(c.get('version_needed')), 6)
    h.writeUInt16LE(num(c.get('flags')), 8)
    h.writeUInt16LE(num(c.get('method')), 10)
    h.writeUInt16LE(ct, 12)
    h.writeUInt16LE(cdd, 14)
    h.writeUInt32LE(ovg('central_crc', crc), 16)
    h.writeUInt32LE(csz, 20)
    h.writeUInt32LE(ovg('central_usize', usz), 24)
    h.writeUInt16LE(nameRaw.length, 28)
    h.writeUInt16LE(cx.length, 30)
    h.writeUInt16LE(cc.length, 32)
    h.writeUInt16LE(num(c.get('disk_start')), 34)
    h.writeUInt16LE(num(c.get('internal_attr')), 36)
    h.writeUInt32LE(attrEnc(c.get('external_attr')), 38)
    h.writeUInt32LE(offset, 42)
    push(h); push(nameRaw); push(cx); push(cc)
  }
  const cdSize = outLen - cdOff
  const eo = man.get('eocd')
  const com = latin1Encode(eo.get('comment'))
  const h = Buffer.alloc(22)
  h.writeUInt32LE(SIG_EOCD, 0)
  h.writeUInt16LE(num(eo.get('disk')), 4)
  h.writeUInt16LE(num(eo.get('cd_disk')), 6)
  h.writeUInt16LE(eo.has('entries_on_disk') ? num(eo.get('entries_on_disk')) : n, 8)
  h.writeUInt16LE(n, 10)
  h.writeUInt32LE(eo.has('cd_size_override') ? num(eo.get('cd_size_override')) : cdSize, 12)
  h.writeUInt32LE(cdOff, 16)
  h.writeUInt16LE(com.length, 20)
  push(h); push(com)
  if (man.has('trailing_hex')) push(fromHex(man.get('trailing_hex')))
  return Buffer.concat(out, outLen)
}
