// Reading half of Python 3.9's zipfile module (Node built-ins only), for the intake ports.
//
//   const z = new ZipFile(pathOrBuffer)   // BadZipFile('File is not a zip file'), central directory checks
//   z.infolist()                          // ZipInfo: filename, orig_filename, flag_bits, compress_type, CRC,
//                                         //   compress_size, file_size, header_offset, extra, comment, is_dir()
//   z.read(info)                          // member bytes; CRC-32 checked (BadZipFile 'Bad CRC-32 for file ...')
//   z.close()
//
// Same results and error texts as zipfile for: end-of-central-directory search (comment, prepended data),
// ZIP64 records, cp437 / UTF-8 (flag 0x800) names, NUL-truncated names, local header checks (signature,
// name mismatch), encryption (RuntimeError), unsupported methods (NotImplementedError), stored, deflate (-15
// window, node:zlib), bzip2 (lib/bzip2.mjs) and LZMA (lib/lzma.mjs, zip's 4-byte header + props), output
// cut at file_size, truncated data (EOFError).

import fs from 'node:fs'
import zlib from 'node:zlib'
import { BZ2Decompressor } from './bzip2.mjs'
import { LZMADecompressor, FORMAT_RAW, FILTER_LZMA1 } from './lzma.mjs'
import { decodeCp437, decodeUtf8Strict, crc32, pyRepr, pyBytesRepr } from './pyshim.mjs'

export class BadZipFile extends Error { constructor(m) { super(m); this.name = 'zipfile.BadZipFile' } }
export class ZipNotImplemented extends Error { constructor(m) { super(m); this.name = 'NotImplementedError' } }
export class ZipRuntimeError extends Error { constructor(m) { super(m); this.name = 'RuntimeError' } }
export class ZipEOFError extends Error { constructor(m = '') { super(m); this.name = 'EOFError' } }
export class ZipZlibError extends Error { constructor(m) { super(m); this.name = 'zlib.error' } }
export class ZipUnicodeError extends Error { constructor(m) { super(m); this.name = 'UnicodeDecodeError' } }

const sizeEndCentDir = 22, sizeEndCentDir64 = 56, sizeEndCentDir64Locator = 20, sizeCentralDir = 46
const sizeFileHeader = 30
const SIG_END = 0x06054b50, SIG_END64 = 0x06064b50, SIG_LOC64 = 0x07064b50, SIG_CD = 0x02014b50, SIG_FH = 0x04034b50
const MAX_EXTRACT_VERSION = 63

class Source {
  constructor(src) {
    if (Buffer.isBuffer(src)) { this.buf = src; this.size = src.length; this.fd = null }
    else { this.fd = fs.openSync(src, 'r'); this.size = fs.fstatSync(this.fd).size; this.buf = null }
  }
  read(pos, n) {
    if (pos >= this.size || n <= 0) return Buffer.alloc(0)
    n = Math.min(n, this.size - pos)
    if (this.buf) return this.buf.subarray(pos, pos + n)
    const b = Buffer.allocUnsafe(n)
    let got = 0
    while (got < n) {
      const k = fs.readSync(this.fd, b, got, Math.min(n - got, 1 << 30), pos + got)
      if (!k) break
      got += k
    }
    return got === n ? b : b.subarray(0, got)
  }
  close() { if (this.fd !== null) { fs.closeSync(this.fd); this.fd = null } }
}

function decodeName(raw, flags) {
  if (flags & 0x800) {
    const s = decodeUtf8Strict(raw)
    if (s === null) throw new ZipUnicodeError("'utf-8' codec can't decode bytes")
    return s
  }
  return decodeCp437(raw)
}

export class ZipInfo {
  constructor(filename) {
    this.orig_filename = filename
    const nul = filename.indexOf('\0')
    this.filename = nul >= 0 ? filename.slice(0, nul) : filename
  }
  is_dir() { return this.filename.endsWith('/') }
  // ZipInfo.__repr__ (Python 3.9)
  repr() {
    let r = `<ZipInfo filename=${pyRepr(this.filename)}`
    if (this.compress_type !== 0) r += ` compress_type=${COMPRESSOR_NAMES[this.compress_type] ?? this.compress_type}`
    const hi = Math.floor(this.external_attr / 65536), lo = this.external_attr & 0xFFFF
    if (hi) r += ` filemode=${pyRepr(filemode(hi))}`
    if (lo) r += ` external_attr=0x${lo.toString(16)}`
    const isdir = this.is_dir()
    if (!isdir || this.file_size) r += ` file_size=${this.file_size}`
    if ((!isdir || this.compress_size) && (this.compress_type !== 0 || this.file_size !== this.compress_size)) {
      r += ` compress_size=${this.compress_size}`
    }
    return r + '>'
  }
}

const COMPRESSOR_NAMES = { 0: 'store', 1: 'shrink', 2: 'reduce', 3: 'reduce', 4: 'reduce', 5: 'reduce', 6: 'implode',
  7: 'tokenize', 8: 'deflate', 9: 'deflate64', 10: 'implode', 12: 'bzip2', 14: 'lzma', 18: 'terse', 19: 'lz77',
  97: 'wavpack', 98: 'ppmd' }

// stat.filemode (CPython's C implementation, macOS file types)
function filemode(mode) {
  const fmt = mode & 0o170000
  const t = { 0o100000: '-', 0o040000: 'd', 0o120000: 'l', 0o060000: 'b', 0o020000: 'c', 0o010000: 'p', 0o140000: 's',
    0o160000: 'w' }[fmt] ?? '?'
  const b = (m, c) => (mode & m ? c : '-')
  const x = (xm, sm, s1, s2) => (mode & sm ? (mode & xm ? s1 : s2) : (mode & xm ? 'x' : '-'))
  return t + b(0o400, 'r') + b(0o200, 'w') + x(0o100, 0o4000, 's', 'S') + b(0o040, 'r') + b(0o020, 'w') +
    x(0o010, 0o2000, 's', 'S') + b(0o004, 'r') + b(0o002, 'w') + x(0o001, 0o1000, 't', 'T')
}

function endRecData64(src, offset, endrec) {
  // offset: negative, relative to the end of the file (as zipfile passes it)
  const pos = src.size + offset - sizeEndCentDir64Locator
  if (pos < 0) return endrec          // zipfile: fpin.seek raises OSError -> return endrec
  const data = src.read(pos, sizeEndCentDir64Locator)
  if (data.length !== sizeEndCentDir64Locator) return endrec
  if (data.readUInt32LE(0) !== SIG_LOC64) return endrec
  const diskno = data.readUInt32LE(4), disks = data.readUInt32LE(16)
  if (diskno !== 0 || disks > 1) throw new BadZipFile('zipfiles that span multiple disks are not supported')
  const pos2 = src.size + offset - sizeEndCentDir64Locator - sizeEndCentDir64
  if (pos2 < 0) return endrec
  const d = src.read(pos2, sizeEndCentDir64)
  if (d.length !== sizeEndCentDir64) return endrec
  if (d.readUInt32LE(0) !== SIG_END64) return endrec
  endrec.signature = SIG_END64
  endrec.disk_number = d.readUInt32LE(16)
  endrec.disk_number_start = d.readUInt32LE(20)
  endrec.entries_this_disk = Number(d.readBigUInt64LE(24))
  endrec.entries_total = Number(d.readBigUInt64LE(32))
  endrec.size = Number(d.readBigUInt64LE(40))
  endrec.offset = Number(d.readBigUInt64LE(48))
  return endrec
}

function parseEnd(rec) {
  return { signature: rec.readUInt32LE(0), disk_number: rec.readUInt16LE(4), disk_number_start: rec.readUInt16LE(6),
    entries_this_disk: rec.readUInt16LE(8), entries_total: rec.readUInt16LE(10), size: rec.readUInt32LE(12),
    offset: rec.readUInt32LE(16), comment_size: rec.readUInt16LE(20) }
}

function endRecData(src) {
  const filesize = src.size
  if (filesize >= sizeEndCentDir) {
    const data = src.read(filesize - sizeEndCentDir, sizeEndCentDir)
    if (data.length === sizeEndCentDir && data.readUInt32LE(0) === SIG_END && data[20] === 0 && data[21] === 0) {
      const endrec = parseEnd(data)
      endrec.comment = Buffer.alloc(0)
      endrec.location = filesize - sizeEndCentDir
      return endRecData64(src, -sizeEndCentDir, endrec)
    }
  }
  const maxCommentStart = Math.max(filesize - (1 << 16) - sizeEndCentDir, 0)
  const data = src.read(maxCommentStart, filesize - maxCommentStart)
  const start = data.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]))
  if (start >= 0) {
    const recData = data.subarray(start, start + sizeEndCentDir)
    if (recData.length !== sizeEndCentDir) return null
    const endrec = parseEnd(recData)
    endrec.comment = data.subarray(start + sizeEndCentDir, start + sizeEndCentDir + endrec.comment_size)
    endrec.location = maxCommentStart + start
    return endRecData64(src, maxCommentStart + start - filesize, endrec)
  }
  return null
}

export class ZipFile {
  constructor(file) {
    this.src = new Source(file)
    this.filelist = []
    this.NameToInfo = new Map()
    try {
      this._realGetContents()
    } catch (e) {
      this.src.close()
      throw e
    }
  }

  _realGetContents() {
    const src = this.src
    const endrec = endRecData(src)
    if (!endrec) throw new BadZipFile('File is not a zip file')
    const sizeCd = endrec.size, offsetCd = endrec.offset
    this.comment = endrec.comment
    let concat = endrec.location - sizeCd - offsetCd
    if (endrec.signature === SIG_END64) concat -= sizeEndCentDir64 + sizeEndCentDir64Locator
    this.start_dir = offsetCd + concat
    if (this.start_dir < 0) throw new BadZipFile('Bad offset for central directory')
    const data = src.read(this.start_dir, sizeCd)
    let p = 0
    let total = 0
    while (total < sizeCd) {
      const cd = data.subarray(p, p + sizeCentralDir)
      if (cd.length !== sizeCentralDir) throw new BadZipFile('Truncated central directory')
      p += sizeCentralDir
      if (cd.readUInt32LE(0) !== SIG_CD) throw new BadZipFile('Bad magic number for central directory')
      const nameLen = cd.readUInt16LE(28), extraLen = cd.readUInt16LE(30), commentLen = cd.readUInt16LE(32)
      const rawName = data.subarray(p, p + nameLen); p += rawName.length
      const flags = cd.readUInt16LE(8)
      const x = new ZipInfo(decodeName(rawName, flags))
      x.extra = data.subarray(p, p + extraLen); p += x.extra.length
      x.comment = data.subarray(p, p + commentLen); p += x.comment.length
      x.header_offset = cd.readUInt32LE(42)
      x.create_version = cd[4]; x.create_system = cd[5]; x.extract_version = cd[6]; x.reserved = cd[7]
      x.flag_bits = flags; x.compress_type = cd.readUInt16LE(10)
      x._raw_time = cd.readUInt16LE(12); x._raw_date = cd.readUInt16LE(14)
      x.CRC = cd.readUInt32LE(16); x.compress_size = cd.readUInt32LE(20); x.file_size = cd.readUInt32LE(24)
      if (x.extract_version > MAX_EXTRACT_VERSION) {
        throw new ZipNotImplemented(`zip file version ${(x.extract_version / 10).toFixed(1)}`)
      }
      x.volume = cd.readUInt16LE(34); x.internal_attr = cd.readUInt16LE(36); x.external_attr = cd.readUInt32LE(38)
      this._decodeExtra(x)
      x.header_offset += concat
      this.filelist.push(x)
      this.NameToInfo.set(x.filename, x)
      total += sizeCentralDir + nameLen + extraLen + commentLen
    }
  }

  _decodeExtra(x) {
    let extra = x.extra
    while (extra.length >= 4) {
      const tp = extra.readUInt16LE(0), ln = extra.readUInt16LE(2)
      if (ln + 4 > extra.length) {
        throw new BadZipFile(`Corrupt extra field ${tp.toString(16).padStart(4, '0')} (size=${ln})`)
      }
      if (tp === 0x0001) {
        let data = extra.subarray(4, ln + 4)
        let field
        const q = () => {
          if (data.length < 8) throw new BadZipFile(`Corrupt zip64 extra field. ${field} not found.`)
          const v = Number(data.readBigUInt64LE(0)); data = data.subarray(8); return v
        }
        if (x.file_size === 0xFFFFFFFF) { field = 'File size'; x.file_size = q() }
        if (x.compress_size === 0xFFFFFFFF) { field = 'Compress size'; x.compress_size = q() }
        if (x.header_offset === 0xFFFFFFFF) { field = 'Header offset'; x.header_offset = q() }
      }
      extra = extra.subarray(ln + 4)
    }
  }

  infolist() { return this.filelist }
  namelist() { return this.filelist.map((x) => x.filename) }

  getinfo(name) {
    const i = this.NameToInfo.get(name)
    if (!i) throw new Error(`There is no item named ${pyRepr(name)} in the archive`)
    return i
  }

  read(info) {
    const nameRepr = typeof info === 'string' ? pyRepr(info) : info.repr()     // ZipFile.open's %r of its argument
    if (typeof info === 'string') info = this.getinfo(info)
    const src = this.src
    const fh = src.read(info.header_offset, sizeFileHeader)
    if (fh.length !== sizeFileHeader) throw new BadZipFile('Truncated file header')
    if (fh.readUInt32LE(0) !== SIG_FH) throw new BadZipFile('Bad magic number for file header')
    const nameLen = fh.readUInt16LE(26), extraLen = fh.readUInt16LE(28)
    const fname = src.read(info.header_offset + sizeFileHeader, nameLen)
    const dataStart = info.header_offset + sizeFileHeader + nameLen + extraLen
    if (info.flag_bits & 0x20) throw new ZipNotImplemented('compressed patched data (flag bit 5)')
    if (info.flag_bits & 0x40) throw new ZipNotImplemented('strong encryption (flag bit 6)')
    const fnameStr = decodeName(fname, fh.readUInt16LE(6))
    if (fnameStr !== info.orig_filename) {
      throw new BadZipFile(`File name in directory ${pyRepr(info.orig_filename)} and header ${pyBytesRepr(fname)} differ.`)
    }
    if (info.flag_bits & 0x1) {
      throw new ZipRuntimeError(`File ${nameRepr} is encrypted, password required for extraction`)
    }
    const ct = info.compress_type
    if (![0, 8, 12, 14].includes(ct)) throw new ZipNotImplemented('That compression method is not supported')
    let raw = src.read(dataStart, info.compress_size)
    let data
    const fileSize = info.file_size
    if (ct === 0) {
      if (raw.length < info.compress_size && fileSize > raw.length) throw new ZipEOFError()
      data = raw.subarray(0, fileSize)
    } else if (ct === 8) {
      data = inflateCapped(raw, fileSize, raw.length < info.compress_size)
    } else if (ct === 12) {
      const d = new BZ2Decompressor()
      data = d.decompress(raw)
      if (!d.eof && raw.length < info.compress_size) throw new ZipEOFError()
      data = data.subarray(0, fileSize)
    } else {
      if (raw.length < 4) throw new ZipEOFError()
      const psize = raw.readUInt16LE(2)
      if (raw.length < 4 + psize) throw new ZipEOFError()
      const props = raw.subarray(4, 4 + psize)
      if (props.length !== 5) throw new Error('Invalid or unsupported options')
      let b = props[0]
      const pb = Math.floor(b / 45); b -= pb * 45
      const lp = Math.floor(b / 9), lc = b - lp * 9
      const d = new LZMADecompressor({ format: FORMAT_RAW, filters: [{ id: FILTER_LZMA1, dict_size: props.readUInt32LE(1), lc, lp, pb }] })
      data = d.decompress(raw.subarray(4 + psize))
      if (!d.eof && raw.length < info.compress_size) throw new ZipEOFError()
      data = data.subarray(0, fileSize)
    }
    if (crc32(data) !== info.CRC) throw new BadZipFile(`Bad CRC-32 for file ${pyRepr(info.filename)}`)
    return Buffer.from(data)
  }

  close() { this.src.close() }
}

// raw deflate of a member: output cut at fileSize (zipfile stops reading there); errors like zlib.error
function inflateCapped(raw, fileSize, truncated) {
  const z = zlib.createInflateRaw()
  z.on('error', () => {})
  const h = z._handle, st = z._writeState
  const outs = []
  let got = 0
  let inOff = 0, inLen = raw.length
  try {
    while (got < fileSize || fileSize === 0) {
      const room = Math.max(1 << 16, Math.min(fileSize - got, 1 << 24))
      const o = Buffer.allocUnsafe(room)
      h.writeSync(zlib.constants.Z_SYNC_FLUSH, raw, inOff, inLen, o, 0, room)
      if (z.errored) {
        const e = z.errored
        throw new ZipZlibError(`Error ${e.errno} while decompressing data: ${e.message}`)
      }
      const availOut = st[0], availIn = st[1]
      if (room - availOut) { outs.push(o.subarray(0, room - availOut)); got += room - availOut }
      inOff += inLen - availIn
      inLen = availIn
      if (availOut !== 0) break           // input used up, or stream ended
      if (fileSize === 0) break
    }
  } finally {
    try { z.close() } catch { /* closed */ }
  }
  if (truncated && got < fileSize) throw new ZipEOFError()
  return Buffer.concat(outs).subarray(0, fileSize)
}
