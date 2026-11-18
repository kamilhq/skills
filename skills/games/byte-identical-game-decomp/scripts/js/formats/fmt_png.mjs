// PNG decoder/encoder (byte-identical round trip). Port of fmt_png.py.
//
// Decoded directory:
//   png.json        IHDR fields, every chunk in file order with its fields decoded, the zlib profile that
//                   regenerates the IDAT stream, IDAT split policy, row-filter policy (+ per-row exceptions),
//                   non-zero padding bits of low-bit-depth rows.
//   pixels.png      8-bit canonical image (L / LA / RGB / RGBA). Source of truth for non-palette images
//                   (low-bit gray is scaled to 0..255: 1-bit -> 0/255, 2-bit -> x85, 4-bit -> x17).
//                   For palette images it is an RGBA preview only (not read by the encoder).
//   indices.png     palette images: 8-bit L image of palette indices (source of truth).
//   palette.json    palette images: RGBA entries (PLTE rgb + tRNS alpha) and how many alphas tRNS carries.
//   NN_iCCP.icc     decompressed ICC profile of an iCCP chunk (NN = chunk index); its zlib profile is in png.json.
//   NN_eXIf.exif    the eXIf chunk body (TIFF-structured Exif, source of truth) + NN_eXIf.json (parsed IFD0).
// Encode reads only these files; lengths and CRCs are recomputed.
import { readFileSync, writeFileSync } from 'node:fs'
import { dump, load, plain, pyDict, pyFloat } from '../lib/pyjson.mjs'
import { pyFromHex, pyEncode, pyInt, pyJoin, pyRound } from '../lib/pycompat.mjs'
import { compress as zcompress, crc32, decompress as zdecompress, decompressAll, ZLIB_RUNTIME_VERSION }
  from '../lib/pyzlib.mjs'
import * as pngio from './pngio.mjs'
import * as fmt_png_zlib from './fmt_png_zlib.mjs'

export const EXTS = ['.png']
const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
const CHANNELS = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }
const CT_NAMES = { 0: 'gray', 2: 'rgb', 3: 'palette', 4: 'gray_alpha', 6: 'rgba' }
const CANON_MODE = { 0: 'L', 2: 'RGB', 4: 'LA', 6: 'RGBA' }
const ADAM7 = [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]]
const SRGB_INTENTS = ['perceptual', 'relative_colorimetric', 'saturation', 'absolute_colorimetric']
const CHRM_FIELDS = ['white_x', 'white_y', 'red_x', 'red_y', 'green_x', 'green_y', 'blue_x', 'blue_y']
export const FILTER_NAMES = ['none', 'sub', 'up', 'average', 'paeth']
const ABS_TABLE = Uint8Array.from({ length: 256 }, (_, v) => (v < 128 ? v : 256 - v))

const latin = (b) => Buffer.from(b).toString('latin1')
const fdiv = (a, b) => Math.floor(a / b)
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k)

function toBytes(arr) {
  // Python bytes(list): every value must be in range(0, 256)
  for (const v of arr) {
    if (!Number.isInteger(v) || v < 0 || v > 255) throw new Error('ValueError: bytes must be in range(0, 256)')
  }
  return Buffer.from(arr)
}

function u32be(...vals) {
  const b = Buffer.alloc(4 * vals.length)
  vals.forEach((v, i) => {
    if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) throw new Error("struct.error: argument out of range for 'I'")
    b.writeUInt32BE(v, 4 * i)
  })
  return b
}

function u16be(v) {
  if (!Number.isInteger(v) || v < 0 || v > 0xffff) throw new Error("struct.error: argument out of range for 'H'")
  const b = Buffer.alloc(2)
  b.writeUInt16BE(v)
  return b
}

// ------------------------------------------------------------------ geometry / rows
// [[x0, y0, dx, dy, pass_w, pass_h]] for the non-empty passes.
export function passes(w, h, interlace) {
  if (!interlace) return [[0, 0, 1, 1, w, h]]
  const out = []
  for (const [x0, y0, dx, dy] of ADAM7) {
    const pw = w > x0 ? fdiv(w - x0 + dx - 1, dx) : 0
    const ph = h > y0 ? fdiv(h - y0 + dy - 1, dy) : 0
    if (pw && ph) out.push([x0, y0, dx, dy, pw, ph])
  }
  return out
}

function paeth(a, b, c) {
  const pa = Math.abs(b - c), pb = Math.abs(a - c), pc = Math.abs(a + b - 2 * c)
  return pa <= pb && pa <= pc ? a : (pb <= pc ? b : c)
}

export function unfilter(ft, line, prev, bpp) {
  const n = line.length
  const out = Buffer.from(line)
  if (ft === 0) return out
  if (ft === 2) {
    const m = Math.min(n, prev.length)
    const r = Buffer.alloc(m)
    for (let i = 0; i < m; i++) r[i] = (line[i] + prev[i]) & 255
    return r
  }
  if (ft === 1) {
    for (let i = bpp; i < n; i++) out[i] = (out[i] + out[i - bpp]) & 255
  } else if (ft === 3) {
    for (let i = 0; i < n; i++) {
      const a = i >= bpp ? out[i - bpp] : 0
      out[i] = (out[i] + ((a + prev[i]) >> 1)) & 255
    }
  } else if (ft === 4) {
    for (let i = 0; i < n; i++) {
      if (i >= bpp) out[i] = (out[i] + paeth(out[i - bpp], prev[i], prev[i - bpp])) & 255
      else out[i] = (out[i] + prev[i]) & 255
    }
  } else {
    throw new Error(`ValueError: bad filter type ${ft}`)
  }
  return out
}

export function filter_row(ft, line, prev, bpp) {
  const n = line.length
  if (ft === 0) return Buffer.from(line)
  const out = Buffer.alloc(n)
  if (ft === 1) {
    for (let i = 0; i < n; i++) out[i] = i < bpp ? line[i] : (line[i] - line[i - bpp]) & 255
  } else if (ft === 2) {
    for (let i = 0; i < n; i++) out[i] = (line[i] - prev[i]) & 255
  } else if (ft === 3) {
    for (let i = 0; i < n; i++) {
      const a = i >= bpp ? line[i - bpp] : 0
      out[i] = (line[i] - ((a + prev[i]) >> 1)) & 255
    }
  } else if (ft === 4) {
    for (let i = 0; i < n; i++) {
      if (i >= bpp) out[i] = (line[i] - paeth(line[i - bpp], prev[i], prev[i - bpp])) & 255
      else out[i] = (line[i] - prev[i]) & 255
    }
  } else {
    throw new Error(`ValueError: bad filter type ${ft}`)
  }
  return out
}

function absSum(r) {
  let s = 0
  for (let i = 0; i < r.length; i++) s += ABS_TABLE[r[i]]
  return s
}

// libpng png_write_find_filter with all five filters enabled: minimum sum of |signed byte|,
// candidates tried in order none, sub, up, average, paeth; a later one wins only if strictly smaller.
export function minsum_filter(line, prev, bpp) {
  let bestFt = 0
  let bestSum = absSum(line)
  let bestRow = null
  for (const ft of [1, 2, 3, 4]) {
    const r = filter_row(ft, line, prev, bpp)
    const s = absSum(r)
    if (s < bestSum) {
      bestFt = ft
      bestSum = s
      bestRow = r
    }
  }
  return [bestFt, bestRow !== null ? bestRow : Buffer.from(line)]
}

// ------------------------------------------------------------------ sample packing
// row bytes -> [n samples as bytes, padding value]
export function unpack_row(row, bd, n) {
  if (bd === 8) return [Buffer.from(row), 0]
  const per = 8 / bd
  const mask = (1 << bd) - 1
  const s = Buffer.alloc(Math.min(n, row.length * per))
  for (let i = 0; i < s.length; i++) {
    const b = row[Math.floor(i / per)]
    const k = i % per
    s[i] = (b >> (8 - bd * (k + 1))) & mask
  }
  const rem = (n * bd) % 8
  const pad = rem ? row[row.length - 1] & ((1 << (8 - rem)) - 1) : 0
  return [s, pad]
}

export function pack_row(samples, bd, pad) {
  if (bd === 8) return Buffer.from(samples)
  const per = 8 / bd
  const out = Buffer.alloc(Math.ceil(samples.length / per))
  for (let i = 0, o = 0; i < samples.length; i += per, o++) {
    let v = 0
    const end = Math.min(i + per, samples.length)
    for (let k = 0; k < end - i; k++) v |= (samples[i + k] & ((1 << bd) - 1)) << (8 - bd * (k + 1))
    out[o] = v
  }
  if ((samples.length * bd) % 8) {
    const v = out[out.length - 1] | pad
    if (v > 255 || v < 0) throw new Error('ValueError: byte must be in range(0, 256)')
    out[out.length - 1] = v
  }
  return out
}

// ------------------------------------------------------------------ chunks
function mkChunk(t, body, crc = null) {
  const tb = Buffer.from(t, 'latin1')
  const c = crc === null ? crc32(Buffer.concat([tb, body])) : crc
  return Buffer.concat([u32be(body.length), tb, body, u32be(c)])
}

export function parse_chunks(data) {
  if (!data.subarray(0, 8).equals(SIG)) throw new Error('ValueError: not a PNG')
  let pos = 8
  const out = []
  while (pos + 12 <= data.length) {
    const ln = data.readUInt32BE(pos)
    const t = latin(data.subarray(pos + 4, pos + 8))
    if (pos + 12 + ln > data.length) break
    const body = data.subarray(pos + 8, pos + 8 + ln)
    const crc = data.readUInt32BE(pos + 8 + ln)
    out.push([t, body, crc])
    pos += 12 + ln
    if (t === 'IEND') break
  }
  return [out, data.subarray(pos)]
}

// Parse a TIFF-structured Exif blob's IFD0. Returns [json, bytes_accounted_for].
export function parse_exif(b) {
  const bo = latin(b.subarray(0, 2))
  if (b.length < 8 || (bo !== 'II' && bo !== 'MM')) return [{ error: 'not TIFF-structured' }, 0]
  const le = bo === 'II'
  const H = (o) => (le ? b.readUInt16LE(o) : b.readUInt16BE(o))
  const I = (o) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o))
  const magic = H(2)
  const ifd = I(4)
  const info = { byte_order: bo, magic, ifd0_offset: ifd, ifd0: [] }
  let covered = 8
  if (ifd + 2 > b.length) return [info, covered]
  const n = H(ifd)
  covered += 2
  const sizes = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 }
  for (let i = 0; i < n; i++) {
    const o = ifd + 2 + 12 * i
    if (o + 12 > b.length) return [info, covered]
    const tag = H(o)
    const typ = H(o + 2)
    const cnt = I(o + 4)
    const size = (sizes[typ] ?? 1) * cnt
    let val
    if (size <= 4) val = b.subarray(o + 8, o + 8 + size)
    else {
      const off = I(o + 8)
      val = b.subarray(Math.min(off, b.length), Math.min(off + size, b.length))
      covered += val.length
    }
    info.ifd0.push({ tag, type: typ, count: cnt, value_hex: val.toString('hex') })
    covered += 12
  }
  if (ifd + 2 + 12 * n + 4 <= b.length) {
    info.next_ifd = I(ifd + 2 + 12 * n)
    covered += 4
  }
  return [info, Math.min(covered, b.length)]
}

// ------------------------------------------------------------------ decode
export function decode_to_dir(data, outdir) {
  const [chunks, trailing] = parse_chunks(data)
  const notes = []
  let opaque = 0
  const ihc = chunks.find(([t]) => t === 'IHDR')
  if (!ihc) throw new Error('StopIteration')
  const ih = ihc[1]
  if (ih.length !== 13) throw new Error('struct.error: unpack requires a buffer of 13 bytes')
  const w = ih.readUInt32BE(0), h = ih.readUInt32BE(4)
  const [bd, ct, cm, fm, il] = [ih[8], ih[9], ih[10], ih[11], ih[12]]
  if (bd === 16 || !hasOwn(CHANNELS, ct)) throw new Error(`NotImplementedError: bit depth ${bd} / color type ${ct} not supported`)
  const ch = CHANNELS[ct]
  const bits = bd * ch
  const bpp = Math.max(1, fdiv(bits, 8))
  const meta = { format: 'PNG', chunks: [], zlib_runtime_used_for_check: ZLIB_RUNTIME_VERSION }
  let paletteRgb = null
  let trns = null

  // --- chunks
  const idatSizes = []
  let idatSeen = false
  chunks.forEach(([t, body, crc], idx) => {
    let ent = { type: t }
    let good = true
    if (t === 'IHDR' && body.length === 13) {
      Object.assign(ent, { width: w, height: h, bit_depth: bd, color_type: ct, color_type_name: CT_NAMES[ct],
        compression_method: cm, filter_method: fm, interlace_method: il,
        interlace_name: il === 1 ? 'adam7' : (il === 0 ? 'none' : 'unknown') })
    } else if (t === 'IDAT') {
      idatSizes.push(body.length)
      if (idatSeen) {
        if (meta.chunks[meta.chunks.length - 1].type !== 'IDAT') throw new Error('ValueError: non-consecutive IDAT chunks')
        if (crc !== crc32(Buffer.concat([Buffer.from('IDAT'), body]))) throw new Error('ValueError: IDAT CRC mismatch')
        return
      }
      idatSeen = true
    } else if (t === 'IEND' && !body.length) {
      // nothing
    } else if (t === 'gAMA' && body.length === 4) {
      const g = body.readUInt32BE(0)
      Object.assign(ent, { gamma: g, gamma_float: pyFloat(g / 100000) })
    } else if (t === 'cHRM' && body.length === 32) {
      const vals = CHRM_FIELDS.map((_, i) => body.readUInt32BE(4 * i))
      CHRM_FIELDS.forEach((k, i) => { ent[k] = vals[i] })
      ent.float = Object.fromEntries(CHRM_FIELDS.map((k, i) => [k, pyFloat(vals[i] / 100000)]))
    } else if (t === 'sRGB' && body.length === 1 && body[0] < 4) {
      Object.assign(ent, { intent: body[0], intent_name: SRGB_INTENTS[body[0]] })
    } else if (t === 'pHYs' && body.length === 9) {
      const x = body.readUInt32BE(0), y = body.readUInt32BE(4), u = body[8]
      Object.assign(ent, { pixels_per_unit_x: x, pixels_per_unit_y: y, unit: u,
        unit_name: { 0: 'unknown', 1: 'metre' }[u] ?? 'unknown' })
      if (u === 1) {
        ent.dpi_x = pyFloat(pyRound(x * 0.0254, 3))
        ent.dpi_y = pyFloat(pyRound(y * 0.0254, 3))
      }
    } else if (t === 'tIME' && body.length === 7) {
      Object.assign(ent, { year: body.readUInt16BE(0), month: body[2], day: body[3], hour: body[4], minute: body[5],
        second: body[6] })
    } else if (t === 'tEXt' && body.includes(0)) {
      const i = body.indexOf(0)
      Object.assign(ent, { keyword: latin(body.subarray(0, i)), text: latin(body.subarray(i + 1)) })
    } else if (t === 'iCCP' && body.subarray(0, 80).includes(0) && body.indexOf(0) + 2 <= body.length) {
      const i = body.indexOf(0)
      const name = body.subarray(0, i), method = body[i + 1], stream = body.subarray(i + 2)
      Object.assign(ent, { profile_name: latin(name), compression_method: method })
      let icc
      try {
        const r = decompressAll(stream)
        icc = r.out
        if (!r.eof || r.unused) throw new Error('zlib.error: trailing data')
      } catch {
        good = false
      }
      if (good) {
        const fn = `${String(idx).padStart(2, '0')}_iCCP.icc`
        writeFileSync(pyJoin(outdir, fn), icc)
        ent.profile_file = fn
        let prof = fmt_png_zlib.find_profile(stream, icc)
        if (prof === null) {
          const zf = `${String(idx).padStart(2, '0')}_iCCP.zlib`
          writeFileSync(pyJoin(outdir, zf), stream)
          prof = { engine: 'raw', file: zf }
          opaque += stream.length
          notes.push(`iCCP zlib stream kept raw (${stream.length} bytes, encoder not identified)`)
        }
        ent.zlib = prof
        notes.push(`iCCP "${latin(name)}": ${icc.length}-byte ICC profile, ${fmt_png_zlib.describe(prof)}`)
      }
    } else if (t === 'eXIf') {
      const fn = `${String(idx).padStart(2, '0')}_eXIf.exif`
      writeFileSync(pyJoin(outdir, fn), body)
      const [info, cov] = parse_exif(body)
      dump(info, pyJoin(outdir, fn.slice(0, -5) + '.json'), { indent: 1 })
      Object.assign(ent, { file: fn, parsed: fn.slice(0, -5) + '.json' })
      opaque += body.length - cov
      notes.push(`eXIf: ${body.length}-byte TIFF Exif kept as ${fn} (source of truth), IFD0 parsed to JSON; ` +
        `${body.length - cov} bytes not covered by the parse`)
    } else if (t === 'PLTE' && body.length % 3 === 0 && ct === 3) {
      paletteRgb = []
      for (let i = 0; i < body.length; i += 3) paletteRgb.push([body[i], body[i + 1], body[i + 2]])
      ent.source = 'palette.json'
    } else if (t === 'PLTE' && body.length % 3 === 0) {
      ent.entries = []
      for (let i = 0; i < body.length; i += 3) ent.entries.push([body[i], body[i + 1], body[i + 2]])
    } else if (t === 'tRNS' && ct === 3 && paletteRgb !== null && body.length <= paletteRgb.length) {
      trns = body
      ent.source = 'palette.json'
    } else if (t === 'tRNS' && ct === 0 && body.length === 2) {
      ent.gray = body.readUInt16BE(0)
    } else if (t === 'tRNS' && ct === 2 && body.length === 6) {
      ent.rgb = [body.readUInt16BE(0), body.readUInt16BE(2), body.readUInt16BE(4)]
    } else {
      good = false
    }
    if (!good) {
      ent = { type: t, data_hex: body.toString('hex'), opaque: true }
      opaque += body.length
      notes.push(`chunk ${t} (${body.length} bytes) kept as hex`)
    }
    if (crc !== crc32(Buffer.concat([Buffer.from(t, 'latin1'), body]))) {
      ent.crc_hex = crc.toString(16).padStart(8, '0')
      opaque += 4
      notes.push(`chunk ${t}: stored CRC does not match, kept`)
    }
    meta.chunks.push(ent)
  })
  if (trailing.length) {
    meta.trailing_hex = trailing.toString('hex')
    opaque += trailing.length
    notes.push(`${trailing.length} bytes after IEND kept as hex`)
  }

  // --- image data
  const stream = Buffer.concat(chunks.filter(([t]) => t === 'IDAT').map(([, b]) => b))
  const dres = decompressAll(stream)
  const raw = dres.out
  if (!dres.eof || dres.unused) throw new Error('ValueError: IDAT zlib stream has trailing data or is truncated')
  const pl = passes(w, h, il)
  const U = bd === 8 ? ch : 1                       // bytes per pixel in the unit buffer
  const units = Buffer.alloc(w * h * U)
  const filters = []
  const padding = pyDict()
  const actualPolicyRows = []                       // [line, prev] for the policy check
  let p = 0
  let rowno = 0
  for (const [x0, y0, dx, dy, pw, ph] of pl) {
    const rb = fdiv(pw * bits + 7, 8)
    let prev = Buffer.alloc(rb)
    for (let py = 0; py < ph; py++) {
      const ft = raw[p]
      if (ft === undefined) throw new Error('IndexError: index out of range')
      const line = unfilter(ft, raw.subarray(p + 1, p + 1 + rb), prev, bpp)
      p += 1 + rb
      filters.push(ft)
      actualPolicyRows.push([line, prev])
      const [samples, pad] = unpack_row(line, bd, pw * ch)
      if (pad) padding.set(String(rowno), pad)
      const y = y0 + py * dy
      if (dx === 1) {
        if (samples.length !== pw * U) throw new Error('ValueError: short row')
        samples.copy(units, y * w * U)
      } else {
        for (let px = 0; px < pw; px++) {
          const x = x0 + px * dx
          samples.copy(units, (y * w + x) * U, px * U, (px + 1) * U)
        }
      }
      prev = line
      rowno += 1
    }
  }
  if (p !== raw.length) throw new Error(`ValueError: IDAT payload has ${raw.length - p} extra bytes`)
  if (padding.size) {
    meta.padding_bits = padding
    opaque += padding.size
    notes.push(`${padding.size} rows with non-zero padding bits kept (counted 1 opaque byte each)`)
  }

  // --- filter policy
  const cand = new Map([['none', new Array(filters.length).fill(0)]])
  if (filters.some((f) => f)) cand.set('libpng_minsum', actualPolicyRows.map(([l, pv]) => minsum_filter(l, pv, bpp)[0]))
  const mism = (k) => filters.reduce((s, f, i) => s + (f !== cand.get(k)[i] ? 1 : 0), 0)
  let best = null
  let bestKey = null
  for (const k of cand.keys()) {
    const key = [mism(k), k !== 'none' ? 1 : 0]
    if (bestKey === null || key[0] < bestKey[0] || (key[0] === bestKey[0] && key[1] < bestKey[1])) {
      best = k
      bestKey = key
    }
  }
  const exc = pyDict()
  filters.forEach((f, i) => { if (f !== cand.get(best)[i]) exc.set(String(i), f) })
  if (exc.size * 4 > filters.length) {
    meta.filters = { policy: 'explicit', per_row: filters.join('') }
    notes.push('row filters not predictable: stored as an explicit per-row list (encoder choice, not opaque)')
  } else {
    meta.filters = { policy: best, exceptions: exc }
    notes.push(`row filters: ${best} policy, ${exc.size} exceptions`)
  }

  // --- zlib profile + IDAT split
  let prof = fmt_png_zlib.find_profile(stream, raw)
  if (prof === null) {
    writeFileSync(pyJoin(outdir, 'idat.zlib'), stream)
    prof = { engine: 'raw', file: 'idat.zlib' }
    opaque += stream.length
    notes.push(`IDAT zlib stream kept raw (${stream.length} bytes): encoder not identified; used only while it ` +
      'still decompresses to the rebuilt scanlines')
  } else {
    notes.push(`IDAT: ${fmt_png_zlib.describe(prof)}`)
  }
  let split
  if (idatSizes.length === 1) split = { policy: 'single' }
  else if (idatSizes.slice(0, -1).every((s) => s === idatSizes[0]) && idatSizes[idatSizes.length - 1] <= idatSizes[0]) {
    split = { policy: 'max_chunk', max: idatSizes[0] }
  } else split = { policy: 'explicit' }
  split.sizes = idatSizes
  meta.idat = { zlib: prof, split }

  // --- pixel files
  let img
  if (ct === 3) {
    const pal = (paletteRgb ?? []).map((c) => [...c, 255])
    if (trns !== null) trns.forEach((a, i) => { pal[i][3] = a })
    dump({ entries: pal, trns_count: trns !== null ? trns.length : 0,
      comment: 'RGBA per index; PLTE = rgb of every entry, tRNS = alpha of the first trns_count ' +
        'entries (extended automatically if a later alpha is not 255)' },
    pyJoin(outdir, 'palette.json'), { indent: 1 })
    pngio.write_png(pyJoin(outdir, 'indices.png'), w, h, 'L', units)
    const rgba = Buffer.alloc(units.length * 4)
    units.forEach((v, i) => { if (v < pal.length) rgba.set(pal[v], i * 4) })
    pngio.write_png(pyJoin(outdir, 'pixels.png'), w, h, 'RGBA', rgba)
    img = { indices: 'indices.png', palette: 'palette.json', preview: 'pixels.png' }
    notes.push(`palette image (${pal.length} entries, ${bd}-bit indices): indices.png + palette.json are the ` +
      'source; pixels.png is an RGBA preview the encoder ignores')
  } else {
    const mode = CANON_MODE[ct]
    let buf = units
    if (bd < 8) {
      const scale = fdiv(255, (1 << bd) - 1)
      buf = Buffer.from(units.map((v) => v * scale))
      notes.push(`${bd}-bit gray scaled x${scale} into 8-bit L pixels.png`)
    }
    pngio.write_png(pyJoin(outdir, 'pixels.png'), w, h, mode, buf)
    img = { pixels: 'pixels.png', mode }
  }
  meta.image = img
  dump(meta, pyJoin(outdir, 'png.json'), { indent: 1 })
  return { opaque_bytes: opaque, notes }
}

// ------------------------------------------------------------------ encode
function recompress(outdir, raw, prof) {
  if (prof.engine === 'raw') {
    const stream = readFileSync(pyJoin(outdir, prof.file))
    try {
      if (zdecompress(stream).equals(raw)) return stream
    } catch {
      // payload was edited or stream broken
    }
    return zcompress(raw, 9)                     // payload was edited: the kept stream no longer applies
  }
  return fmt_png_zlib.compress(raw, prof)
}

export function encode_from_dir(outdir) {
  const meta = plain(load(pyJoin(outdir, 'png.json')))
  const ihdr = meta.chunks.find((c) => c.type === 'IHDR')
  if (!ihdr) throw new Error('StopIteration')
  const bd = ihdr.bit_depth, ct = ihdr.color_type, il = ihdr.interlace_method
  if (!hasOwn(CHANNELS, ct)) throw new Error(`KeyError: ${ct}`)
  const ch = CHANNELS[ct]
  const bits = bd * ch
  const bpp = Math.max(1, fdiv(bits, 8))
  const img = meta.image
  let pal = null
  let tcount = 0
  let w, h, mode, units
  if (ct === 3) {
    [w, h, mode, units] = pngio.read_png(pyJoin(outdir, img.indices))
    if (mode !== 'L') throw new Error('ValueError: indices.png must be 8-bit L')
    const pj = plain(load(pyJoin(outdir, img.palette)))
    pal = pj.entries
    const limit = Math.min(pal.length, 2 ** bd)
    let bad = 0
    for (const v of units) if (v > bad) bad = v
    if (bad >= limit) {
      throw new Error(`ValueError: indices.png uses palette index ${bad}, but only 0..${limit - 1} are valid ` +
        `(${pal.length} palette entries, ${bd}-bit indices)`)
    }
    tcount = pj.trns_count ?? 0
    pal.forEach((e, i) => { if (e.length > 3 && e[3] !== 255) tcount = Math.max(tcount, i + 1) })
  } else {
    [w, h, mode, units] = pngio.read_png(pyJoin(outdir, img.pixels))
    if (mode !== CANON_MODE[ct]) throw new Error(`ValueError: pixels.png must be ${CANON_MODE[ct]}, got ${mode}`)
    if (bd < 8) {
      const mx = (1 << bd) - 1
      units = Buffer.from(units.map((v) => fdiv(v * mx + 127, 255)))
    }
  }
  const U = bd === 8 ? ch : 1
  const padding = meta.padding_bits ?? {}
  const fp = meta.filters
  const exc = new Map(Object.entries(fp.exceptions ?? {}).map(([k, v]) => [Number(pyInt(k)), v]))
  const perRow = fp.per_row ?? null

  const out = []
  let rowno = 0
  for (const [x0, y0, dx, dy, pw, ph] of passes(w, h, il)) {
    const rb = fdiv(pw * bits + 7, 8)
    let prev = Buffer.alloc(rb)
    for (let py = 0; py < ph; py++) {
      const y = y0 + py * dy
      let samples
      if (dx === 1) samples = units.subarray(y * w * U, (y * w + pw) * U)
      else {
        samples = Buffer.alloc(pw * U)
        for (let px = 0; px < pw; px++) {
          const o = (y * w + x0 + px * dx) * U
          units.copy(samples, px * U, o, o + U)
        }
      }
      const line = pack_row(samples, bd, padding[String(rowno)] ?? 0)
      let ft
      if (perRow !== null && rowno < perRow.length) ft = Number(pyInt(perRow[rowno]))
      else if (exc.has(rowno)) ft = exc.get(rowno)
      else if (fp.policy === 'libpng_minsum') {
        const [f, frow] = minsum_filter(line, prev, bpp)
        out.push(Buffer.from([f]), frow)
        prev = line
        rowno += 1
        continue
      } else ft = 0
      out.push(toBytes([ft]), filter_row(ft, line, prev, bpp))
      prev = line
      rowno += 1
    }
  }
  const raw = Buffer.concat(out)
  const stream = recompress(outdir, raw, meta.idat.zlib)
  const split = meta.idat.split
  const sizes = split.sizes ?? []
  let parts
  if (split.policy === 'explicit' && sizes.reduce((a, b) => a + b, 0) === stream.length) {
    parts = []
    let o = 0
    for (const s of sizes) {
      parts.push(stream.subarray(o, o + s))
      o += s
    }
  } else if (split.policy === 'max_chunk') {
    const m = split.max
    if (m === 0) throw new Error('ValueError: range() arg 3 must not be zero')
    parts = []
    if (m > 0) for (let i = 0; i < stream.length; i += m) parts.push(stream.subarray(i, i + m))
    if (!parts.length) parts = [Buffer.alloc(0)]
  } else {
    parts = [stream]
  }

  const chunkList = [...meta.chunks]
  if (ct === 3 && tcount && !chunkList.some((c) => c.type === 'tRNS')) {
    // palette.json gained a non-opaque alpha: tRNS goes right after PLTE
    const i = chunkList.findIndex((c) => c.type === 'PLTE')
    if (i < 0) throw new Error('StopIteration')
    chunkList.splice(i + 1, 0, { type: 'tRNS', source: 'palette.json' })
  }
  const res = [SIG]
  for (const c of chunkList) {
    const t = c.type
    const crc = 'crc_hex' in c ? Number(BigInt('0x' + c.crc_hex)) : null
    let body
    if ('data_hex' in c) body = pyFromHex(c.data_hex)
    else if (t === 'IHDR') {
      body = Buffer.concat([u32be(w, h), toBytes([bd, ct, c.compression_method, c.filter_method, il])])
    } else if (t === 'IDAT') {
      for (const part of parts) res.push(mkChunk('IDAT', part))
      continue
    } else if (t === 'IEND') body = Buffer.alloc(0)
    else if (t === 'gAMA') body = u32be(c.gamma)
    else if (t === 'cHRM') body = u32be(...CHRM_FIELDS.map((k) => c[k]))
    else if (t === 'sRGB') body = toBytes([c.intent])
    else if (t === 'pHYs') body = Buffer.concat([u32be(c.pixels_per_unit_x, c.pixels_per_unit_y), toBytes([c.unit])])
    else if (t === 'tIME') {
      body = Buffer.concat([u16be(c.year), toBytes([c.month, c.day, c.hour, c.minute, c.second])])
    } else if (t === 'tEXt') {
      body = Buffer.concat([pyEncode(c.keyword, 'latin-1'), Buffer.alloc(1), pyEncode(c.text, 'latin-1')])
    } else if (t === 'iCCP') {
      const icc = readFileSync(pyJoin(outdir, c.profile_file))
      body = Buffer.concat([pyEncode(c.profile_name, 'latin-1'), Buffer.alloc(1), toBytes([c.compression_method]),
        recompress(outdir, icc, c.zlib)])
    } else if (t === 'eXIf') body = readFileSync(pyJoin(outdir, c.file))
    else if (t === 'PLTE' && c.source === 'palette.json') body = Buffer.concat(pal.map((e) => toBytes(e.slice(0, 3))))
    else if (t === 'PLTE') body = Buffer.concat(c.entries.map((e) => toBytes(e)))
    else if (t === 'tRNS' && c.source === 'palette.json') {
      body = toBytes(pal.slice(0, tcount).map((e) => (e.length > 3 ? e[3] : 255)))
    } else if (t === 'tRNS' && 'gray' in c) body = u16be(c.gray)
    else if (t === 'tRNS' && 'rgb' in c) body = Buffer.concat(c.rgb.map(u16be))
    else throw new Error(`ValueError: cannot rebuild chunk ${t}`)
    res.push(mkChunk(t, body, crc))
  }
  res.push(pyFromHex(meta.trailing_hex ?? ''))
  return Buffer.concat(res)
}
