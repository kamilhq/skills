// Python's zlib module on top of node:zlib (Node built-ins only), byte for byte.
//
//   compressobj(level, method, wbits, memLevel, strategy) -> {compress(data), flush(mode)}
//   compress(data, level, wbits)            zlib.compress
//   decompress(data)                        zlib.decompress (trailing data after the stream is ignored)
//   decompressAll(data) -> {out, eof, unused}   one decompressobj().decompress(data): eof / unused_data
//   crc32(data, value), adler32(data, value)    unsigned results
//   Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH, DEFLATED, MAX_WBITS, DEF_MEM_LEVEL, ZLIB_RUNTIME_VERSION
//
// Deflate output depends on the zlib build (compare ZLIB_RUNTIME_VERSION with Python's) and, for level 0
// (stored blocks), on how much output space each deflate() call gets. compressobj/compress therefore drive
// the zlib handle the way CPython 3.9's zlibmodule.c does: first call with 16 KiB of output space, the
// buffer then doubles (avail_out 16K, 16K, 32K, 64K, ...), and flush() starts again at 16 KiB. node:zlib's
// public sync API cannot make several calls on one stream (it closes the handle after each call), so this
// uses the stream's handle (handle.writeSync + _writeState), which is what node:zlib's own sync code calls.
import zlib from 'node:zlib'

export const { Z_NO_FLUSH, Z_PARTIAL_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH } = zlib.constants
export const DEFLATED = 8
export const MAX_WBITS = 15
export const DEF_MEM_LEVEL = 8
export const DEF_BUF_SIZE = 16384
export const ZLIB_RUNTIME_VERSION = process.versions.zlib

export class ZlibError extends Error {
  constructor(m) { super(m); this.name = 'zlib.error' }
}

function makeDeflate(level, wbits, memLevel, strategy) {
  const opts = { level, memLevel, strategy }
  let z
  if (wbits < 0) z = zlib.createDeflateRaw({ ...opts, windowBits: -wbits })
  else if (wbits > 15) z = zlib.createGzip({ ...opts, windowBits: wbits - 16 })
  else z = zlib.createDeflate({ ...opts, windowBits: wbits })
  z.on('error', () => {})                  // errors are read synchronously from z.errored
  if (!z._handle || typeof z._handle.writeSync !== 'function' || !z._writeState) {
    throw new Error('pyzlib: this Node.js version does not expose the zlib handle (handle.writeSync)')
  }
  return z
}

class CompressObj {
  constructor(level = -1, method = DEFLATED, wbits = MAX_WBITS, memLevel = DEF_MEM_LEVEL, strategy = 0) {
    if (method !== DEFLATED) throw new ZlibError('Invalid initialization option')
    this.z = makeDeflate(level, wbits, memLevel, strategy)
    this.done = false
  }

  _run(input, flush) {
    if (this.done) throw new ZlibError('Error -2 while compressing data: inconsistent stream state')
    const h = this.z._handle
    const st = this.z._writeState
    let length = DEF_BUF_SIZE
    let occupied = 0
    let inOff = 0
    let inLen = input.length
    const outs = []
    let availOut
    do {
      if (occupied === length) length *= 2
      const avail = length - occupied
      const out = Buffer.allocUnsafe(avail)
      h.writeSync(flush, input, inOff, inLen, out, 0, avail)
      if (this.z.errored) throw new ZlibError(`Error while compressing data: ${this.z.errored.message}`)
      availOut = st[0]
      const availIn = st[1]
      outs.push(out.subarray(0, avail - availOut))
      occupied += avail - availOut
      inOff += inLen - availIn
      inLen = availIn
    } while (availOut === 0)
    return Buffer.concat(outs)
  }

  compress(data) {
    return this._run(Buffer.from(data.buffer, data.byteOffset, data.byteLength), Z_NO_FLUSH)
  }

  flush(mode = Z_FINISH) {
    if (mode === Z_NO_FLUSH) return Buffer.alloc(0)
    const out = this._run(Buffer.alloc(0), mode)
    if (mode === Z_FINISH) {
      this.done = true
      this.z.close()
    }
    return out
  }
}

export const compressobj = (level = -1, method = DEFLATED, wbits = MAX_WBITS, memLevel = DEF_MEM_LEVEL,
  strategy = 0) => new CompressObj(level, method, wbits, memLevel, strategy)

export function compress(data, level = -1, wbits = MAX_WBITS) {
  // zlib.compress: deflate(Z_FINISH) with all the input, output buffer from 16 KiB doubling
  const c = new CompressObj(level, DEFLATED, wbits, DEF_MEM_LEVEL, 0)
  const out = c._run(Buffer.from(data.buffer, data.byteOffset, data.byteLength), Z_FINISH)
  c.done = true
  c.z.close()
  return out
}

export function decompressAll(data) {
  // decompressobj().decompress(data) for a zlib stream: eof = stream end reached, unused = bytes after it
  const buf = Buffer.from(data.buffer, data.byteOffset, data.byteLength)
  try {
    const r = zlib.inflateSync(buf, { info: true })
    return { out: r.buffer, eof: true, unused: buf.length - r.engine.bytesWritten }
  } catch (e) {
    if (e.code !== 'Z_BUF_ERROR') throw new ZlibError(`Error while decompressing data: ${e.message}`)
  }
  const out = zlib.inflateSync(buf, { finishFlush: Z_SYNC_FLUSH })   // truncated: the part that decodes
  return { out, eof: false, unused: 0 }
}

export function decompress(data) {
  const r = decompressAll(data)
  if (!r.eof) throw new ZlibError('Error -5 while decompressing data: incomplete or truncated stream')
  return r.out
}

let CRC_TABLE = null
export function crc32(data, value = 0) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Int32Array(256)
    for (let n = 0; n < 256; n++) {
      let c = n
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
      CRC_TABLE[n] = c
    }
  }
  let c = ~value
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]) & 255] ^ (c >>> 8)
  return ~c >>> 0
}

export function adler32(data, value = 1) {
  let a = value & 0xffff
  let b = (value >>> 16) & 0xffff
  const n = data.length
  let i = 0
  while (i < n) {
    const end = Math.min(n, i + 3800)          // keep sums below 2^53 / exact in doubles
    for (; i < end; i++) { a += data[i]; b += a }
    a %= 65521
    b %= 65521
  }
  return ((b << 16) | a) >>> 0
}
