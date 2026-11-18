// Minimal PNG writer/reader (8-bit, non-interlaced) shared by format decoders. Port of pngio.py.
//
// writePng(path, width, height, mode, pixels)   mode in {'L','LA','RGB','RGBA'}; pixels = bytes, row-major
// readPng(path) -> [width, height, mode, pixels]  supports all 5 filter types, so images edited
//                                                  and re-saved by ordinary tools still load.
// (write_png / read_png are exported too, under the Python names.)
// Self-contained (node: built-ins only, no lib/ import) so the same file can be copied into a project's
// formats directory, as pngio.py is. zlib.compress(raw, 6) = deflateSync level 6 (default windowBits 15,
// memLevel 8, strategy): for levels > 0 the output does not depend on output-buffer sizes.
import { readFileSync, writeFileSync } from 'node:fs'
import zlib from 'node:zlib'

let CRC_TABLE = null
function crc32(data) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Int32Array(256)
    for (let n = 0; n < 256; n++) {
      let c = n
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
      CRC_TABLE[n] = c
    }
  }
  let c = -1
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]) & 255] ^ (c >>> 8)
  return ~c >>> 0
}

const CT = { L: [0, 1], LA: [4, 2], RGB: [2, 3], RGBA: [6, 4] }
const CT_REV = new Map(Object.entries(CT).map(([k, v]) => [v[0], [k, v[1]]]))
const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])

function chunk(t, d) {
  const td = Buffer.concat([Buffer.from(t, 'latin1'), d])
  const head = Buffer.alloc(4)
  head.writeUInt32BE(d.length)
  const tail = Buffer.alloc(4)
  tail.writeUInt32BE(crc32(td))
  return Buffer.concat([head, td, tail])
}

export function writePng(path, width, height, mode, pixels) {
  if (!(mode in CT)) throw new Error(`KeyError: '${mode}'`)
  const [ct, bpp] = CT[mode]
  const stride = width * bpp
  if (pixels.length !== stride * height) {
    throw new Error(`ValueError: pixel buffer ${pixels.length} != ${stride}*${height}`)
  }
  const raw = Buffer.alloc((stride + 1) * height)
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0
    raw.set(pixels.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1)
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr[8] = 8
  ihdr[9] = ct
  writeFileSync(path, Buffer.concat([SIG, chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 6 })),
    chunk('IEND', Buffer.alloc(0))]))
}

export function readPng(path) {
  const data = readFileSync(path)
  if (!data.subarray(0, 8).equals(SIG)) throw new Error('ValueError: not a PNG')
  let pos = 8
  const idat = []
  let hdr = null
  while (pos < data.length) {
    if (pos + 8 > data.length) throw new Error('struct.error: unpack requires a buffer of 8 bytes')
    const ln = data.readUInt32BE(pos)
    const t = data.toString('latin1', pos + 4, pos + 8)
    const body = data.subarray(pos + 8, pos + 8 + ln)
    if (t === 'IHDR') {
      if (body.length !== 13) throw new Error('struct.error: unpack requires a buffer of 13 bytes')
      hdr = [body.readUInt32BE(0), body.readUInt32BE(4), body[8], body[9], body[10], body[11], body[12]]
    } else if (t === 'IDAT') idat.push(body)
    else if (t === 'IEND') break
    pos += 12 + ln
  }
  if (hdr === null) throw new Error('TypeError: cannot unpack non-iterable NoneType object')
  const [w, h, depth, ct, , , interlace] = hdr
  if (depth !== 8 || interlace !== 0 || !CT_REV.has(ct)) {
    throw new Error(`ValueError: unsupported PNG (depth=${depth}, colortype=${ct}, interlace=${interlace})`)
  }
  const [mode, bpp] = CT_REV.get(ct)
  const raw = zlib.inflateSync(Buffer.concat(idat))     // zlib.decompress: data after the stream is ignored
  const stride = w * bpp
  const out = Buffer.alloc(stride * h)
  let prev = Buffer.alloc(stride)
  let p = 0
  for (let y = 0; y < h; y++) {
    const ft = raw[p]
    if (ft === undefined) throw new Error('IndexError: index out of range')
    // a truncated last row: the Python version fails or returns a short buffer; fail here
    if (p + 1 + stride > raw.length) throw new Error('IndexError: bytearray index out of range')
    const line = Buffer.from(raw.subarray(p + 1, p + 1 + stride))
    p += 1 + stride
    for (let i = 0; i < stride; i++) {
      const a = i >= bpp ? line[i - bpp] : 0
      const b = prev[i]
      const c = i >= bpp ? prev[i - bpp] : 0
      if (ft === 1) line[i] = (line[i] + a) & 255
      else if (ft === 2) line[i] = (line[i] + b) & 255
      else if (ft === 3) line[i] = (line[i] + ((a + b) >> 1)) & 255
      else if (ft === 4) {
        const pa = Math.abs(b - c), pb = Math.abs(a - c), pc = Math.abs(a + b - 2 * c)
        line[i] = (line[i] + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c)) & 255
      }
    }
    line.copy(out, y * stride)
    prev = line
  }
  return [w, h, mode, out]
}

export const write_png = writePng
export const read_png = readPng
