#!/usr/bin/env node
// inno.mjs - JavaScript (Node.js) port of inno.py: extractor for GOG Inno Setup installers.
// Same command line, stdout/stderr, exit codes and output tree as inno.py (see inno.py's docstring):
//
//   inno.mjs info    <setup.exe> [--json]
//   inno.mjs list    <setup.exe> [--json] [--include-temp] [--language L]
//   inno.mjs extract <setup.exe> <out_dir> [--language L] [--include-temp]
//                    [--collisions overwrite|error|rename] [--no-mtime] [--quiet]
//   inno.mjs verify  <setup.exe>
//
// Exit codes: 0 ok; 1 extraction / verification / I/O error; 2 bad arguments or unsupported installer.
// Messages keep the name "inno.py" so both scripts print the same bytes.
// LZMA1/LZMA2 and bzip2 come from lib/lzma.mjs and lib/bzip2.mjs; zlib from node:zlib (same zlib library
// version as Python's on the reference machine: 1.2.12).

import fs from 'node:fs'
import crypto from 'node:crypto'
import zlib from 'node:zlib'
import { LZMADecompressor, LZMAError, FORMAT_RAW, FILTER_LZMA1, FILTER_LZMA2 } from './lib/lzma.mjs'
import { BZ2Decompressor, BZ2Error } from './lib/bzip2.mjs'
import { dumps, pyFloat } from './lib/pyjson.mjs'
import {
  out, err, pyRepr, pyBytesRepr, osErrorStr, isOSError, realpath, abspath, normpath, join, dirname, basename,
  splitext, isfile, isdir, islink, exists, crc32, adler32, StructError, u16, u32, traceback,
  decodeCp1252Replace, cmpStr, parseKnownArgs, ArgError, ArgHelp,
} from './lib/pyshim.mjs'

const EXIT_OK = 0, EXIT_FAIL = 1, EXIT_UNSUPPORTED = 2
const TESTED_VERSIONS = new Set(['5,5,7', '5,6,2'])

class InnoError extends Error { get exitCode() { return EXIT_FAIL } }
class Unsupported extends InnoError { get exitCode() { return EXIT_UNSUPPORTED } }
class PathEscape extends InnoError {}
// Python exceptions the script does not catch (printed as a traceback, exit 1)
class PyUncaught extends Error { constructor(cls, msg) { super(msg); this.cls = cls } }
class ZlibError extends Error {}

const V = (a, b, c, d = 0) => [a, b, c, d]
function vcmp(x, y) {
  for (let i = 0; i < 4; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1
  return 0
}
const ge = (v, a, b, c, d = 0) => vcmp(v, [a, b, c, d]) >= 0
const lt = (v, a, b, c, d = 0) => vcmp(v, [a, b, c, d]) < 0
const vstr = (v) => (v[3] ? v : v.slice(0, 3)).join('.')
const hex = (n) => n.toString(16)

// Python-like file object
class PyFile {
  constructor(p) { this.fd = fs.openSync(p, 'r'); this.pos = 0; this.size = fs.fstatSync(this.fd).size }
  seek(off, whence = 0) { this.pos = whence === 0 ? off : whence === 2 ? this.size + off : this.pos + off }
  tell() { return this.pos }
  read(n = -1) {
    if (n < 0) n = Math.max(0, this.size - this.pos)
    const b = Buffer.allocUnsafe(n)
    let got = 0
    while (got < n) {
      const k = fs.readSync(this.fd, b, got, Math.min(n - got, 1 << 30), this.pos + got)
      if (!k) break
      got += k
    }
    this.pos += got
    return got === n ? b : b.subarray(0, got)
  }
  close() { if (this.fd !== null) { fs.closeSync(this.fd); this.fd = null } }
}

// ---------------------------------------------------------------------------------------------------------
// PE resource lookup + setup loader offset table
// ---------------------------------------------------------------------------------------------------------
const LOADER_MAGICS = [
  [Buffer.from('rDlPtS02\x87eVx', 'latin1'), V(1, 2, 10)],
  [Buffer.from('rDlPtS04\x87eVx', 'latin1'), V(4, 0, 0)],
  [Buffer.from('rDlPtS05\x87eVx', 'latin1'), V(4, 0, 3)],
  [Buffer.from('rDlPtS06\x87eVx', 'latin1'), V(4, 0, 10)],
  [Buffer.from('rDlPtS07\x87eVx', 'latin1'), V(4, 1, 6)],
  [Buffer.from('rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a', 'latin1'), V(5, 1, 5)],
  [Buffer.from('nS5W7dT\x83\xaa\x1b\x0f\x6a', 'latin1'), V(5, 1, 5)],
]

function peRcdata(f, resId = 11111, resType = 10) {
  f.seek(0)
  const mz = f.read(64)
  if (mz.length < 64 || mz[0] !== 0x4d || mz[1] !== 0x5a) return null
  const pe = u32(mz, 0x3C)
  f.seek(pe)
  const h = f.read(24)
  if (h.length < 24 || !h.subarray(0, 4).equals(Buffer.from('PE\0\0', 'latin1'))) return null
  const nsec = u16(h, 6)
  const optsz = u16(h, 20)
  const opt = f.read(optsz)
  const magic = u16(opt, 0)
  const ddoff = magic === 0x10B ? 96 : 112
  if (opt.length < ddoff + 24) return null
  const rsrcRva = u32(opt, ddoff + 16), rsrcSize = u32(opt, ddoff + 20)
  if (!rsrcRva) return null
  const secs = []
  const sdata = f.read(40 * nsec)
  for (let i = 0; i < nsec; i++) {
    const vsize = u32(sdata, i * 40 + 8), va = u32(sdata, i * 40 + 12)
    const rawsize = u32(sdata, i * 40 + 16), rawptr = u32(sdata, i * 40 + 20)
    secs.push([va, Math.max(vsize, rawsize), rawptr])
  }
  const rva2off = (rva) => {
    for (const [va, sz, raw] of secs) if (va <= rva && rva < va + sz) return rva - va + raw
    return null
  }
  const base = rva2off(rsrcRva)
  if (base === null) return null
  f.seek(base)
  const blob = f.read(Math.max(rsrcSize, 16))
  function* entries(off) {
    const nn = u16(blob, off + 12), ni = u16(blob, off + 14)
    for (let k = 0; k < nn + ni; k++) yield [u32(blob, off + 16 + 8 * k), u32(blob, off + 20 + 8 * k)]
  }
  try {
    for (const [name, ptr] of entries(0)) {
      if (name === resType && ptr & 0x80000000) {
        for (const [name2, ptr2] of entries(ptr & 0x7FFFFFFF)) {
          if (name2 === resId && ptr2 & 0x80000000) {
            for (const [, ptr3] of entries(ptr2 & 0x7FFFFFFF)) {
              if (ptr3 & 0x80000000) continue
              const rva = u32(blob, ptr3)
              u32(blob, ptr3 + 4)
              return rva2off(rva)
            }
          }
        }
      }
    }
  } catch (e) {
    if (e instanceof StructError) return null
    throw e
  }
  return null
}

function parseOffsetTable(f, pos) {
  f.seek(pos)
  const data = f.read(64)
  if (data.length < 12) return null
  let ver = null
  for (const [magic, v] of LOADER_MAGICS) {
    if (data.subarray(0, 12).equals(magic)) { ver = v; break }
  }
  if (ver === null) return null
  let p = 12
  const rd = () => { const v = u32(data, p); p += 4; return v }
  const o = { loader_version: ver }
  if (ge(ver, 5, 1, 5)) o.revision = rd()
  rd()
  o.exe_offset = rd()
  if (lt(ver, 4, 1, 6)) rd()
  o.exe_uncompressed_size = rd()
  o.exe_crc = rd()
  if (lt(ver, 4, 0, 0)) rd()
  o.header_offset = rd()
  o.data_offset = rd()
  if (ge(ver, 4, 0, 10)) {
    const crcEnd = p
    const expected = rd()
    if (crc32(data.subarray(0, crcEnd)) !== expected) {
      throw new InnoError(`setup loader offset table CRC32 mismatch at 0x${hex(pos)}`)
    }
  }
  return o
}

function findOffsets(f) {
  const off = peRcdata(f)
  if (off !== null) {
    const o = parseOffsetTable(f, off)
    if (o) return o
  }
  f.seek(0x30)
  const h = f.read(12)
  if (h.length === 12 && h.subarray(0, 4).toString('latin1') === 'Inno') {
    const a = u32(h, 4), b = u32(h, 8)
    if (a === ((~b) >>> 0)) {
      const o = parseOffsetTable(f, a)
      if (o) return o
    }
  }
  f.seek(0)
  const blob = f.read(32 << 20)
  for (const [magic] of LOADER_MAGICS) {
    let i = blob.indexOf(magic)
    while (i >= 0) {
      try {
        const o = parseOffsetTable(f, i)
        if (o) return o
      } catch (e) {
        if (!(e instanceof InnoError)) throw e
      }
      i = blob.indexOf(magic, i + 1)
    }
  }
  return null
}

// ---------------------------------------------------------------------------------------------------------
// Compressed header blocks
// ---------------------------------------------------------------------------------------------------------
function lzma1Decompressor(props5) {
  if (!props5.length) throw new PyUncaught('IndexError', 'index out of range')
  let d = props5[0]
  if (d >= 9 * 5 * 5) throw new InnoError(`bad LZMA1 properties byte ${d}`)
  const lc = d % 9
  d = Math.floor(d / 9)
  const lp = d % 5
  const pb = Math.floor(d / 5)
  const dictSize = u32(props5, 1)
  return new LZMADecompressor({ format: FORMAT_RAW, filters: [{ id: FILTER_LZMA1, dict_size: Math.max(dictSize, 4096), lc, lp, pb }] })
}

function lzma2Decompressor(prop) {
  if (prop > 40) throw new InnoError(`bad LZMA2 dictionary property ${prop}`)
  const ds = prop === 40 ? 0xFFFFFFFF : (2 | (prop & 1)) * 2 ** (Math.floor(prop / 2) + 11)
  return new LZMADecompressor({ format: FORMAT_RAW, filters: [{ id: FILTER_LZMA2, dict_size: ds }] })
}

function zlibMessage(e, what) {
  // Python: "Error %d %s: %.200s" (zlib's msg, or a fixed text when zlib gives none)
  const no = e.errno ?? -3
  let msg = e.message
  if (e.code === 'Z_BUF_ERROR' || no === -5) msg = 'incomplete or truncated stream'
  else if (no === 2) return `Error 2 ${what}`
  return `Error ${no} ${what}: ${msg.slice(0, 200)}`
}

function zlibDecompress(data) {        // zlib.decompress
  try {
    return zlib.inflateSync(data)
  } catch (e) {
    throw new ZlibError(zlibMessage(e, 'while decompressing data'))
  }
}

function readBlock(f, version) {
  const start = f.tell()
  let storedSize, comp
  if (ge(version, 4, 0, 9)) {
    const h = f.read(9)
    if (h.length < 9) throw new InnoError(`truncated header block at 0x${hex(start)}`)
    const expected = h.readUInt32LE(0), sz = h.readUInt32LE(4), compressed = h[8]
    if (crc32(h.subarray(4, 9)) !== expected) throw new InnoError(`header block CRC32 mismatch at 0x${hex(start)}`)
    storedSize = sz
    comp = compressed ? (ge(version, 4, 1, 6) ? 'lzma1' : 'zlib') : 'stored'
  } else {
    const h = f.read(12)
    if (h.length !== 12) throw new StructError('unpack requires a buffer of 12 bytes')
    const expected = h.readUInt32LE(0), csize = h.readUInt32LE(4), usize = h.readUInt32LE(8)
    if (crc32(h.subarray(4, 12)) !== expected) throw new InnoError(`header block CRC32 mismatch at 0x${hex(start)}`)
    if (csize === 0xFFFFFFFF) { storedSize = usize; comp = 'stored' } else { storedSize = csize; comp = 'zlib' }
    storedSize += Math.ceil(storedSize / 4096) * 4
  }
  const raw = f.read(storedSize)
  if (raw.length !== storedSize) throw new InnoError(`truncated header block at 0x${hex(start)}`)
  const parts = []
  let p = 0, n = 0
  while (p < raw.length) {
    if (raw.length - p < 5) throw new InnoError(`bad header block chunk size at 0x${hex(start + p)}`)
    const crc = raw.readUInt32LE(p)
    const chunk = raw.subarray(p + 4, p + 4 + 4096)
    if (crc32(chunk) !== crc) throw new InnoError(`header block chunk ${n} CRC32 mismatch (block at 0x${hex(start)})`)
    parts.push(chunk)
    p += 4 + chunk.length
    n++
  }
  const data = Buffer.concat(parts)
  if (comp === 'stored') return data
  if (comp === 'zlib') return zlibDecompress(data)
  const dec = lzma1Decompressor(data.subarray(0, 5))
  return dec.decompress(data.subarray(5))
}

// ---------------------------------------------------------------------------------------------------------
// Record reader
// ---------------------------------------------------------------------------------------------------------
class Reader {
  constructor(b, unicode) { this.b = b; this.p = 0; this.unicode = unicode }
  need(n) { if (this.p + n > this.b.length) throw new InnoError('header data truncated (record parse overran block)') }
  u8() { this.need(1); return this.b[this.p++] }
  u16() { this.need(2); const v = this.b.readUInt16LE(this.p); this.p += 2; return v }
  i16() { this.need(2); const v = this.b.readInt16LE(this.p); this.p += 2; return v }
  u32() { this.need(4); const v = this.b.readUInt32LE(this.p); this.p += 4; return v }
  i32() { this.need(4); const v = this.b.readInt32LE(this.p); this.p += 4; return v }
  u64() { this.need(8); const v = this.b.readBigUInt64LE(this.p); this.p += 8; return Number(v) }
  i64() { this.need(8); const v = this.b.readBigInt64LE(this.p); this.p += 8; return v }
  raw(n) { this.need(n); const v = Buffer.from(this.b.subarray(this.p, this.p + n)); this.p += n; return v }
  bstr() {
    const n = this.u32()
    if (n > this.b.length - this.p) throw new InnoError(`implausible string length ${n} at 0x${hex(this.p - 4)}`)
    return this.raw(n)
  }
  s() {
    const b = this.bstr()
    if (this.unicode) {
      if (b.length & 1) throw new InnoError(`odd-length UTF-16 string at 0x${hex(this.p)}`)
      return b.toString('utf16le')
    }
    return decodeCp1252Replace(b)
  }
  a() { return decodeCp1252Replace(this.bstr()) }
  flags(names) {
    const nb = (names.length + 7) >> 3
    const raw = this.raw(nb)
    if (nb === 3) this.u8()
    const set = new Set()
    names.forEach((nm, i) => { if (nm && (raw[i >> 3] >> (i & 7)) & 1) set.add(nm) })
    return set
  }
}

function parseVersion(s) {
  const m = /\((\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\)/.exec(s)
  if (!m) return [null, false]
  const v = [1, 2, 3, 4].map((k) => parseInt(m[k] || '0', 10))
  const unicode = /\((u|U)\)/.test(s) || ge(v, 6, 3, 0)
  return [v, unicode]
}

// ---------------------------------------------------------------------------------------------------------
// Setup info parsing
// ---------------------------------------------------------------------------------------------------------
const winver = (r, v) => r.raw(ge(v, 1, 3, 19) ? 20 : 16)

function conditions(r, v, e) {
  e.components = ge(v, 2, 0, 0) ? r.s() : ''
  e.tasks = ge(v, 2, 0, 0) ? r.s() : ''
  e.languages = ge(v, 4, 0, 1) ? r.s() : ''
  e.check = ge(v, 3, 0, 8) ? r.s() : ''
  if (ge(v, 4, 1, 0)) { e.after_install = r.s(); e.before_install = r.s() } else e.after_install = e.before_install = ''
}

function parseHeader(r, v) {
  const h = {}
  const S = () => r.s()
  h.app_name = S(); h.app_versioned_name = S(); h.app_id = S(); h.app_copyright = S(); h.app_publisher = S()
  h.app_publisher_url = S()
  if (ge(v, 5, 1, 13)) h.app_support_phone = S()
  h.app_support_url = S(); h.app_updates_url = S(); h.app_version = S(); h.default_dir_name = S()
  h.default_group_name = S()
  if (lt(v, 3, 0, 0)) r.a()
  h.base_filename = S()
  if (lt(v, 5, 2, 5)) { r.a(); r.a(); r.a() }
  h.uninstall_files_dir = S(); h.uninstall_name = S(); h.uninstall_icon = S(); h.app_mutex = S()
  if (ge(v, 3, 0, 0)) { S(); S() }
  if (ge(v, 4, 0, 0)) S()
  if (ge(v, 4, 0, 0) && lt(v, 5, 0, 4)) r.bstr()
  if (ge(v, 4, 2, 4)) { S(); S(); S(); S() }
  if (ge(v, 5, 3, 8)) S()
  if (ge(v, 5, 3, 10)) S()
  if (ge(v, 5, 5, 0)) S()
  if (ge(v, 5, 5, 6)) S()
  if (ge(v, 5, 6, 1)) { S(); S() }
  if (ge(v, 6, 3, 0)) throw new Unsupported(`Inno Setup ${vstr(v)} header layout is not implemented`)
  if (ge(v, 5, 2, 5)) { r.a(); r.a(); r.a() }
  if (ge(v, 5, 2, 1) && lt(v, 5, 3, 10)) S()
  if (ge(v, 5, 2, 5)) r.bstr()
  if (!r.unicode) r.raw(32)
  h.language_count = ge(v, 4, 0, 0) ? r.u32() : 1
  h.message_count = ge(v, 4, 2, 1) ? r.u32() : 0
  h.permission_count = ge(v, 4, 1, 0) ? r.u32() : 0
  h.type_count = r.u32()
  h.component_count = r.u32()
  h.task_count = r.u32()
  for (const k of ['directory_count', 'file_count', 'data_entry_count', 'icon_count', 'ini_entry_count',
    'registry_entry_count', 'delete_entry_count', 'uninstall_delete_entry_count', 'run_entry_count',
    'uninstall_run_entry_count']) h[k] = r.u32()
  winver(r, v)
  r.u32(); r.u32()
  if (lt(v, 5, 5, 7)) r.u32()
  if (ge(v, 2, 0, 0) && lt(v, 5, 0, 4)) r.u32()
  if (ge(v, 6, 0, 0)) { r.u8(); r.u32(); r.u32() }
  if (ge(v, 5, 5, 7)) r.u8()
  if (lt(v, 4, 2, 0)) r.u32()
  else if (lt(v, 5, 3, 9)) r.raw(16)
  else r.raw(20)
  if (ge(v, 4, 2, 2)) r.raw(8)
  r.i64()
  h.slices_per_disk = r.u32()
  if (lt(v, 5, 0, 0)) r.u8()
  r.u8(); r.u8(); r.u8()
  if (ge(v, 5, 7, 0)) r.u8()
  r.u8(); r.u8()
  h.compression = r.u8()
  r.u8(); r.u8()
  if (ge(v, 5, 2, 1) && lt(v, 5, 3, 10)) { r.u32(); r.u32() }
  if (ge(v, 5, 3, 3)) { r.u8(); r.u8() }
  if (ge(v, 5, 5, 0)) r.u64()
  else if (ge(v, 5, 3, 6)) r.u32()
  const names = ['DisableStartupPrompt']
  if (lt(v, 5, 3, 10)) names.push('Uninstallable')
  names.push('CreateAppDir')
  if (lt(v, 5, 3, 3)) names.push('DisableDirPage')
  if (lt(v, 5, 3, 3)) names.push('DisableProgramGroupPage')
  names.push('AllowNoIcons', 'AlwaysRestart', 'AlwaysUsePersonalGroup', 'WindowVisible', 'WindowShowCaption',
    'WindowResizable', 'WindowStartMaximized', 'EnableDirDoesntExistWarning')
  if (lt(v, 4, 1, 2)) names.push('DisableAppendDir')
  names.push('Password', 'AllowRootDirectory', 'DisableFinishedPage')
  if (lt(v, 3, 0, 4)) names.push('AdminPrivilegesRequired')
  if (lt(v, 5, 6, 1)) names.push('ChangesAssociations')
  if (lt(v, 5, 3, 8)) names.push('CreateUninstallRegKey')
  names.push('UsePreviousAppDir', 'BackColorHorizontal', 'UsePreviousGroup', 'UpdateUninstallLogAppName',
    'UsePreviousSetupType', 'DisableReadyMemo', 'AlwaysShowComponentsList', 'FlatComponentsList',
    'ShowComponentSizes', 'UsePreviousTasks', 'DisableReadyPage', 'AlwaysShowDirOnReadyPage',
    'AlwaysShowGroupOnReadyPage')
  if (lt(v, 4, 1, 5)) names.push('BzipUsed')
  names.push('AllowUNCPath', 'UserInfoPage', 'UsePreviousUserInfo', 'UninstallRestartComputer',
    'RestartIfNeededByRun', 'ShowTasksTreeLines')
  if (lt(v, 4, 0, 10)) names.push('ShowLanguageDialog', 'DetectLanguageUsingLocale')
  if (ge(v, 4, 0, 9)) names.push('AllowCancelDuringInstall')
  if (ge(v, 4, 1, 3)) names.push('WizardImageStretch')
  if (ge(v, 4, 1, 8)) names.push('AppendDefaultDirName', 'AppendDefaultGroupName')
  if (ge(v, 4, 2, 2)) names.push('EncryptionUsed')
  if (ge(v, 5, 0, 4) && lt(v, 5, 6, 1)) names.push('ChangesEnvironment')
  if (ge(v, 5, 1, 7) && !r.unicode) names.push('ShowUndisplayableLanguages')
  if (ge(v, 5, 1, 13)) names.push('SetupLogging')
  if (ge(v, 5, 2, 1)) names.push('SignedUninstaller')
  if (ge(v, 5, 3, 8)) names.push('UsePreviousLanguage')
  if (ge(v, 5, 3, 9)) names.push('DisableWelcomePage')
  if (ge(v, 5, 5, 0)) names.push('CloseApplications', 'RestartApplications', 'AllowNetworkDrive')
  if (ge(v, 5, 5, 7)) names.push('ForceCloseApplications')
  if (ge(v, 6, 0, 0)) names.push('AppNameHasConsts', 'UsePreviousPrivileges', 'WizardResizable')
  h.options = r.flags(names)
  return h
}

function parseLanguage(r, v) {
  const e = {}
  e.name = ge(v, 4, 0, 0) ? r.s() : 'default'
  e.language_name = r.s()
  r.s(); r.s(); r.s(); r.s()
  if (ge(v, 4, 0, 0)) r.bstr()
  if (ge(v, 4, 0, 1)) { r.a(); r.a(); r.a() }
  e.language_id = r.u32()
  if (ge(v, 4, 2, 2) && !r.unicode) e.codepage = r.u32()
  else if (r.unicode && lt(v, 5, 3, 0)) r.u32()
  if (ge(v, 2, 0, 1)) r.u32()
  if (lt(v, 4, 1, 0)) r.u32()
  r.u32(); r.u32(); r.u32()
  if (ge(v, 5, 2, 3)) r.u8()
  return e
}
const parseMessage = (r) => { r.s(); r.bstr(); r.i32() }
const parsePermission = (r) => { r.bstr() }

function parseType(r, v) {
  const e = { name: r.s(), description: r.s() }
  if (ge(v, 4, 0, 1)) e.languages = r.s()
  if (ge(v, 3, 0, 8)) e.check = r.s()
  winver(r, v)
  r.flags(['CustomSetupType'])
  if (ge(v, 4, 0, 3)) r.u8()
  e.size = ge(v, 4, 0, 0) ? r.u64() : r.u32()
  return e
}

function parseComponent(r, v) {
  const e = { name: r.s(), description: r.s(), types: r.s() }
  if (ge(v, 4, 0, 1)) e.languages = r.s()
  if (ge(v, 3, 0, 8)) e.check = r.s()
  if (ge(v, 4, 0, 0)) r.u64(); else r.u32()
  if (ge(v, 4, 0, 0)) { e.level = r.i32(); r.u8() }
  winver(r, v)
  const nm = ['Fixed', 'Restart', 'DisableNoUninstallWarning', 'Exclusive']
  if (ge(v, 4, 2, 3)) nm.push('DontInheritCheck')
  e.options = r.flags(nm)
  e.size = ge(v, 4, 0, 0) ? r.u64() : r.u32()
  return e
}

function parseTask(r, v) {
  const e = { name: r.s(), description: r.s(), group_description: r.s(), components: r.s() }
  if (ge(v, 4, 0, 1)) e.languages = r.s()
  if (ge(v, 3, 0, 8)) e.check = r.s()
  if (ge(v, 4, 0, 0)) { r.i32(); r.u8() }
  winver(r, v)
  const nm = ['Exclusive', 'Unchecked', 'Restart', 'CheckedOnce']
  if (ge(v, 4, 2, 3)) nm.push('DontInheritCheck')
  r.flags(nm)
  return e
}

function parseDirectory(r, v) {
  const e = { name: r.s() }
  conditions(r, v, e)
  if (ge(v, 4, 0, 11) && lt(v, 4, 1, 0)) r.bstr()
  e.attributes = r.u32()
  winver(r, v)
  if (ge(v, 4, 1, 0)) r.i16()
  const nm = ['NeverUninstall', 'DeleteAfterInstall', 'AlwaysUninstall']
  if (ge(v, 5, 2, 0)) nm.push('SetNtfsCompression', 'UnsetNtfsCompression')
  e.options = r.flags(nm)
  return e
}

const FILE_FLAGS_CACHE = new Map()
function fileFlagNames(v) {
  const nm = ['ConfirmOverwrite', 'NeverUninstall', 'RestartReplace', 'DeleteAfterInstall', 'RegisterServer',
    'RegisterTypeLib', 'SharedFile']
  if (lt(v, 2, 0, 0)) nm.push('IsReadmeFile')
  nm.push('CompareTimeStamp', 'FontIsNotTrueType', 'SkipIfSourceDoesntExist', 'OverwriteReadOnly',
    'OverwriteSameVersion', 'CustomDestName', 'OnlyIfDestFileExists', 'NoRegError', 'UninsRestartDelete',
    'OnlyIfDoesntExist', 'IgnoreVersion', 'PromptIfOlder', 'DontCopy')
  if (ge(v, 4, 0, 5)) nm.push('UninsRemoveReadOnly')
  if (ge(v, 4, 1, 8)) nm.push('RecurseSubDirsExternal')
  if (ge(v, 4, 2, 1)) nm.push('ReplaceSameVersionIfContentsDiffer')
  if (ge(v, 4, 2, 5)) nm.push('DontVerifyChecksum')
  if (ge(v, 5, 0, 3)) nm.push('UninsNoSharedFilePrompt')
  if (ge(v, 5, 1, 0)) nm.push('CreateAllSubDirs')
  if (ge(v, 5, 1, 2)) nm.push('Bits32', 'Bits64')
  if (ge(v, 5, 2, 0)) nm.push('ExternalSizePreset', 'SetNtfsCompression', 'UnsetNtfsCompression')
  if (ge(v, 5, 2, 5)) nm.push('GacInstall')
  return nm
}

function parseFile(r, v) {
  const e = { source: r.s(), destination: r.s(), install_font_name: r.s() }
  if (ge(v, 5, 2, 5)) e.strong_assembly_name = r.s()
  conditions(r, v, e)
  winver(r, v)
  e.location = r.u32()
  e.attributes = r.u32()
  e.external_size = ge(v, 4, 0, 0) ? r.u64() : r.u32()
  if (ge(v, 4, 1, 0)) r.i16()
  const key = v.join(',')
  let nm = FILE_FLAGS_CACHE.get(key)
  if (!nm) { nm = fileFlagNames(v); FILE_FLAGS_CACHE.set(key, nm) }
  e.options = r.flags(nm)
  e.file_type = r.u8()
  return e
}

function parseIcon(r, v) {
  const e = { name: r.s(), filename: r.s() }
  r.s(); r.s(); r.s(); r.s()
  conditions(r, v, e)
  if (ge(v, 5, 3, 5)) r.s()
  if (ge(v, 6, 1, 0)) r.raw(16)
  winver(r, v)
  r.i32(); r.i32(); r.u8(); r.u16()
  const nm = ['NeverUninstall', 'CreateOnlyIfFileExists', 'UseAppPaths']
  if (ge(v, 5, 0, 3)) nm.push('FolderShortcut')
  if (ge(v, 5, 4, 2)) nm.push('ExcludeFromShowInNewInstall')
  if (ge(v, 5, 5, 0)) nm.push('PreventPinning')
  if (ge(v, 6, 1, 0)) nm.push('HasAppUserModelToastActivatorCLSID')
  r.flags(nm)
  return e
}

function parseIni(r, v) {
  const e = { file: r.s(), section: r.s(), key: r.s(), value: r.s() }
  conditions(r, v, e)
  winver(r, v)
  r.flags(['CreateKeyIfDoesntExist', 'UninsDeleteEntry', 'UninsDeleteEntireSection', 'UninsDeleteSectionIfEmpty',
    'HasValue'])
  return e
}

function utf16Strict(b) {      // bytes.decode('utf-16-le'), null on UnicodeDecodeError
  if (b.length & 1) return null
  const s = b.toString('utf16le')
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0xD800 && c <= 0xDBFF) {
      const d = s.charCodeAt(i + 1)
      if (!(d >= 0xDC00 && d <= 0xDFFF)) return null
      i++
    } else if (c >= 0xDC00 && c <= 0xDFFF) return null
  }
  return s
}

function parseRegistry(r, v) {
  const e = { key: r.s(), name: r.s() }
  e.value_raw = r.bstr()
  conditions(r, v, e)
  if (ge(v, 4, 0, 11) && lt(v, 4, 1, 0)) r.bstr()
  winver(r, v)
  e.hive = r.u32() & 0x7FFFFFFF
  if (ge(v, 4, 1, 0)) r.i16()
  e.type = ge(v, 5, 2, 5) ? r.u8() : null
  const nm = ['CreateValueIfDoesntExist', 'UninsDeleteValue', 'UninsClearValue', 'UninsDeleteEntireKey',
    'UninsDeleteEntireKeyIfEmpty', 'PreserveStringType', 'DeleteKey', 'DeleteValue', 'NoError', 'DontCreateKey']
  if (ge(v, 5, 1, 0)) nm.push('Bits32', 'Bits64')
  r.flags(nm)
  if ((e.type === 1 || e.type === 2) && r.unicode) e.value = utf16Strict(e.value_raw)
  else if (e.type === 1 || e.type === 2) e.value = decodeCp1252Replace(e.value_raw)
  return e
}

let DATA_FLAGS = null
function dataFlagNames(v) {
  const nm = ['VersionInfoValid', 'VersionInfoNotValid']
  if (ge(v, 2, 0, 17) && lt(v, 4, 0, 1)) nm.push('BZipped')
  if (ge(v, 4, 0, 10)) nm.push('TimeStampInUTC')
  if (ge(v, 4, 1, 0)) nm.push('IsUninstallerExe')
  if (ge(v, 4, 1, 8)) nm.push('CallInstructionOptimized')
  if (ge(v, 4, 2, 0)) nm.push('Touch')
  if (ge(v, 4, 2, 2)) nm.push('ChunkEncrypted')
  if (ge(v, 4, 2, 5)) nm.push('ChunkCompressed')
  if (ge(v, 5, 1, 13)) nm.push('SolidBreak')
  if (ge(v, 5, 5, 7) && lt(v, 6, 3, 0)) nm.push('Sign', 'SignOnce')
  return nm
}

const COMPRESSION_NAMES = { 0: 'stored', 1: 'zlib', 2: 'bzip2', 3: 'lzma1', 4: 'lzma2' }
function headerCompression(v, c) {
  if (ge(v, 5, 3, 9)) return COMPRESSION_NAMES[c] ?? `unknown${c}`
  if (ge(v, 4, 2, 6)) return ({ 0: 'stored', 1: 'zlib', 2: 'bzip2', 3: 'lzma1' })[c] ?? `unknown${c}`
  if (ge(v, 4, 2, 5)) return ({ 0: 'zlib', 1: 'bzip2', 2: 'lzma1' })[c] ?? `unknown${c}`
  if (ge(v, 4, 1, 5)) return ({ 0: 'zlib', 1: 'bzip2', 2: 'lzma1' })[c] ?? `unknown${c}`
  return 'zlib'
}

function parseData(r, v, setup) {
  const d = {}
  d.first_slice = r.u32()
  d.last_slice = r.u32()
  if (lt(v, 4, 0, 0)) { d.first_slice -= 1; d.last_slice -= 1 }
  d.chunk_offset = r.u32()
  d.file_offset = ge(v, 4, 0, 1) ? r.u64() : 0
  if (ge(v, 4, 0, 0)) { d.size = r.u64(); d.chunk_size = r.u64() } else { d.size = r.u32(); d.chunk_size = r.u32() }
  if (ge(v, 5, 3, 9)) { d.checksum_type = 'sha1'; d.checksum = r.raw(20) }
  else if (ge(v, 4, 2, 0)) { d.checksum_type = 'md5'; d.checksum = r.raw(16) }
  else if (ge(v, 4, 0, 1)) { d.checksum_type = 'crc32'; d.checksum = r.raw(4) }
  else { d.checksum_type = 'adler32'; d.checksum = r.raw(4) }
  d.filetime = r.i64()
  d.version_ms = r.u32()
  d.version_ls = r.u32()
  const key = v.join(',')
  if (DATA_FLAGS === null || DATA_FLAGS[0] !== key) DATA_FLAGS = [key, dataFlagNames(v)]
  const opts = r.flags(DATA_FLAGS[1])
  if (lt(v, 4, 2, 5)) opts.add('ChunkCompressed')
  d.options = opts
  d.compression = opts.has('BZipped') ? 'bzip2' : opts.has('ChunkCompressed') ? setup.compression : 'stored'
  d.encrypted = opts.has('ChunkEncrypted')
  if (opts.has('CallInstructionOptimized')) {
    d.filter = lt(v, 5, 2, 0) ? 'x86_4108' : lt(v, 5, 3, 9) ? 'x86_5200' : 'x86_5309'
  } else d.filter = null
  return d
}

function loadList(r, v, n, fn, what) {
  const outl = []
  for (let i = 0; i < n; i++) {
    try {
      outl.push(fn(r, v))
    } catch (ex) {
      if (ex instanceof InnoError) throw new InnoError(`failed parsing ${what} entry ${i}/${n}: ${ex.message}`)
      throw ex
    }
  }
  return outl
}

function openSetup(p) {
  if (!isfile(p)) throw new Unsupported(`no such file: ${p}`)
  const f = new PyFile(p)
  try {
    const o = findOffsets(f)
    if (o === null) throw new Unsupported(`${p}: not an Inno Setup installer (no setup loader offset table)`)
    f.seek(o.header_offset)
    const vsRaw = f.read(64)
    const z = vsRaw.indexOf(0)
    const vs = (z >= 0 ? vsRaw.subarray(0, z) : vsRaw).toString('latin1')
    const [v, unicode] = parseVersion(vs)
    if (v === null || !vs.includes('Setup Data')) {
      throw new Unsupported(`${p}: unrecognised setup data version string ${pyRepr(vs)}`)
    }
    if (lt(v, 4, 0, 0)) throw new Unsupported(`Inno Setup ${vstr(v)} (< 4.0.0) is not supported`)
    if (ge(v, 6, 3, 0)) throw new Unsupported(`Inno Setup ${vstr(v)} (6.3+) header layout is not implemented`)
    const tested = TESTED_VERSIONS.has(v.slice(0, 3).join(','))
    const s = { path: p, offsets: o, version: v, version_string: vs, unicode, tested }
    try {
      const blk = readBlock(f, v)
      const r = new Reader(blk, unicode)
      const h = parseHeader(r, v)
      s.header = h
      s.compression = headerCompression(v, h.compression)
      s.languages = loadList(r, v, h.language_count, parseLanguage, 'language')
      loadList(r, v, h.message_count, parseMessage, 'message')
      loadList(r, v, h.permission_count, parsePermission, 'permission')
      s.types = loadList(r, v, h.type_count, parseType, 'type')
      s.components = loadList(r, v, h.component_count, parseComponent, 'component')
      s.tasks = loadList(r, v, h.task_count, parseTask, 'task')
      s.directories = loadList(r, v, h.directory_count, parseDirectory, 'directory')
      s.files = loadList(r, v, h.file_count, parseFile, 'file')
      s.registry = []
      s.tail_error = null
      try {
        loadList(r, v, h.icon_count, parseIcon, 'icon')
        loadList(r, v, h.ini_entry_count, parseIni, 'ini')
        s.registry = loadList(r, v, h.registry_entry_count, parseRegistry, 'registry')
      } catch (ex) {
        if (!(ex instanceof InnoError || ex instanceof StructError)) throw ex
        s.tail_error = ex.message
      }
      const blk2 = readBlock(f, v)
      const r2 = new Reader(blk2, unicode)
      s.data = []
      for (let i = 0; i < h.data_entry_count; i++) s.data.push(parseData(r2, v, s))
      if (r2.p !== blk2.length) {
        throw new InnoError(`data entry block has ${blk2.length - r2.p} trailing bytes (layout mismatch)`)
      }
      s.files.forEach((fe, i) => {
        const loc = fe.location
        if (loc !== 0xFFFFFFFF && loc >= s.data.length && !fe.source) {
          throw new InnoError(`file entry ${i} points at data entry ${loc} of ${s.data.length}`)
        }
      })
    } catch (ex) {
      if (!(ex instanceof InnoError || ex instanceof StructError || ex instanceof LZMAError ||
        ex instanceof ZlibError)) throw ex
      if (ex instanceof Unsupported) throw ex
      if (ex.message.includes('CRC32') || tested) throw new InnoError(`${p}: ${ex.message}`)
      throw new Unsupported(`${p}: setup data ${vstr(v)} could not be parsed (untested version): ${ex.message}`)
    }
    return s
  } finally {
    f.close()
  }
}

// ---------------------------------------------------------------------------------------------------------
// Expressions (Languages / Components / Tasks conditions), innoextract-style
// ---------------------------------------------------------------------------------------------------------
const PYWS = '\\t\\n\\v\\f\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000'
const TOK = new RegExp(`[${PYWS}]*(\\(|\\)|[^${PYWS}()]+)`, 'gu')

function expressionMatch(test, expr) {
  if (!expr.replace(new RegExp(`^[${PYWS}]+|[${PYWS}]+$`, 'gu'), '')) return true
  const toks = []
  for (const m of expr.matchAll(TOK)) toks.push(m[1])
  let pos = 0
  const testL = test.toLowerCase()
  const peek = () => (pos < toks.length ? toks[pos].toLowerCase() : null)
  function pOr() {
    let val = pAnd()
    for (;;) {
      const t = peek()
      if (t === 'or') { pos++; val = pAnd() || val }
      else if (t !== null && t !== ')' && t !== 'and') val = pAnd() || val
      else return val
    }
  }
  function pAnd() {
    let val = pNot()
    while (peek() === 'and') { pos++; val = pNot() && val }
    return val
  }
  function pNot() {
    const t = peek()
    if (t === 'not') { pos++; return !pNot() }
    if (t === '(') {
      pos++
      const val = pOr()
      if (peek() === ')') pos++
      return val
    }
    if (t === null) return false
    pos++
    return t === testL
  }
  return pOr()
}

// ---------------------------------------------------------------------------------------------------------
// Path mapping (innoextract filename_map::convert, default settings)
// ---------------------------------------------------------------------------------------------------------
const UNSAFE = new Set('<>:"|?*')
const safe = (s) => Array.from(s, (c) => (UNSAFE.has(c) || c.codePointAt(0) < 32 ? '$' : c)).join('')

function expand(p, i, close) {
  const o = []
  const n = p.length
  while (i < n) {
    let j = i
    while (j < n && p[j] !== '{' && p[j] !== '}') j++
    o.push(p.slice(i, j))
    i = j
    if (i >= n) break
    const c = p[i]
    i++
    if (close && c === '}') return [o.join(''), i]
    if (c === '}') { o.push('}'); continue }
    if (i < n && p[i] === '{') { o.push('{'); i++; continue }
    let key
    ;[key, i] = expand(p, i, true)
    o.push(safe(key))
  }
  return [o.join(''), i]
}

function convertPath(dest) {
  const [expanded] = expand(dest, 0, false)
  const res = []
  for (const seg of expanded.split(/[\\/]/)) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      if (!res.length) throw new PathEscape(`destination ${pyRepr(dest)} escapes the output directory`)
      res.pop()
      continue
    }
    res.push(seg)
  }
  return res.join('/')
}

// ---------------------------------------------------------------------------------------------------------
// Slices / chunk streams
// ---------------------------------------------------------------------------------------------------------
const SLICE_MAGICS = [Buffer.from('idska16\x1a', 'latin1'), Buffer.from('idska32\x1a', 'latin1')]
const RAR_MSG = (p) => `${p} is an old GOG RAR-based data part ('Rar!' signature). These are not ` +
  'supported by inno.py: install the game (e.g. with Wine) and use the installed game folder instead.'

class SliceSet {
  constructor(setup) {
    this.setup = setup
    this.dataOffset = setup.offsets.data_offset
    this.f = null
    this.cur = null
    this.sliceEnd = null
    this.dir = dirname(abspath(setup.path))
    const stem = splitext(basename(setup.path))[0]
    this.bases = [stem]
    const bf = setup.header.base_filename || ''
    if (bf && !this.bases.includes(bf)) this.bases.push(bf)
    this.spd = setup.header.slices_per_disk || 1
  }
  sliceNames(idx) {
    return this.bases.map((b) => (this.spd === 1 ? `${b}-${idx + 1}.bin`
      : `${b}-${Math.floor(idx / this.spd) + 1}${String.fromCharCode(97 + (idx % this.spd))}.bin`))
  }
  slicePath(idx) {
    for (const nm of this.sliceNames(idx)) {
      const p = join(this.dir, nm)
      if (isfile(p)) return p
    }
    throw new InnoError(`missing disk slice ${this.sliceNames(idx).join(' / ')} next to ${this.setup.path}`)
  }
  open(idx) {
    if (this.cur === idx && this.f) return
    if (this.f) this.f.close()
    this.f = null
    if (this.dataOffset) {
      if (idx !== 0) throw new InnoError(`single-file setup references slice ${idx}`)
      this.f = new PyFile(this.setup.path)
      this.sliceEnd = null
    } else {
      const p = this.slicePath(idx)
      const f = new PyFile(p)
      const magic = f.read(8)
      if (magic.subarray(0, 4).toString('latin1') === 'Rar!') { f.close(); throw new Unsupported(RAR_MSG(p)) }
      if (!SLICE_MAGICS.some((m) => m.equals(magic))) {
        f.close()
        throw new InnoError(`${p}: bad slice signature ${pyBytesRepr(magic)}`)
      }
      const sb = f.read(4)
      if (sb.length !== 4) { f.close(); throw new StructError('unpack requires a buffer of 4 bytes') }
      const size = sb.readUInt32LE(0)
      if (size > f.size || size < 12) { f.close(); throw new InnoError(`${p}: bad slice size ${size}`) }
      this.f = f
      this.sliceEnd = size
    }
    this.cur = idx
  }
  seek(idx, offset) { this.open(idx); this.f.seek(this.dataOffset + offset) }
  read(n) {
    const o = []
    while (n > 0) {
      if (this.sliceEnd === null) {
        const b = this.f.read(n)
        if (!b.length) break
        o.push(b); n -= b.length
        continue
      }
      const left = this.sliceEnd - this.f.tell()
      if (left <= 0) { this.open(this.cur + 1); this.f.seek(12); continue }
      const b = this.f.read(Math.min(n, left))
      if (!b.length) throw new InnoError(`unexpected end of slice ${this.cur}`)
      o.push(b); n -= b.length
    }
    return o.length === 1 ? o[0] : Buffer.concat(o)
  }
  close() { if (this.f) { this.f.close(); this.f = null } }
}

const CHUNK_MAGIC = Buffer.from('zlb\x1a', 'latin1')
const IN_BLOCK = 1 << 20
const OUT_BLOCK = 4 << 20

// Streaming zlib.decompressobj() on node:zlib's handle (the synchronous path node:zlib uses internally).
class Inflater {
  constructor() {
    this.z = zlib.createInflate()
    this.z.on('error', () => {})
    if (!this.z._handle || typeof this.z._handle.writeSync !== 'function' || !this.z._writeState) {
      throw new Error('inno.mjs: this Node.js version does not expose the zlib handle (handle.writeSync)')
    }
    this.eof = false
  }
  // returns output pieces for this input (zlib errors raise ZlibError with Python's message)
  *decompress(data) {
    if (this.eof || !data.length) return
    const h = this.z._handle, st = this.z._writeState
    let inOff = 0, inLen = data.length
    for (;;) {
      const o = Buffer.allocUnsafe(OUT_BLOCK)
      h.writeSync(zlib.constants.Z_SYNC_FLUSH, data, inOff, inLen, o, 0, OUT_BLOCK)
      if (this.z.errored) throw new ZlibError(zlibMessage(this.z.errored, 'while decompressing data'))
      const availOut = st[0], availIn = st[1]
      const got = OUT_BLOCK - availOut
      if (got) yield o.subarray(0, got)
      inOff += inLen - availIn
      inLen = availIn
      if (availOut === 0) continue          // output full: more may be pending
      if (availIn > 0) { this.eof = true; return }    // stopped consuming: end of stream
      return
    }
  }
  // decompressobj().eof after all input: is the stream complete?
  finish() {
    if (this.eof) return true
    const h = this.z._handle
    const o = Buffer.allocUnsafe(64)
    h.writeSync(zlib.constants.Z_FINISH, Buffer.alloc(0), 0, 0, o, 0, 64)
    if (this.z.errored) {
      if (this.z.errored.code === 'Z_BUF_ERROR') return false
      throw new ZlibError(zlibMessage(this.z.errored, 'while decompressing data'))
    }
    this.eof = true
    return true
  }
  close() { try { this.z.close() } catch { /* closed */ } }
}

function* chunkPieces(slices, d) {
  slices.seek(d.first_slice, d.chunk_offset)
  const magic = slices.read(4)
  if (!magic.equals(CHUNK_MAGIC)) {
    throw new InnoError(`bad chunk magic ${pyBytesRepr(magic)} at slice ${d.first_slice} offset 0x${hex(d.chunk_offset)}`)
  }
  if (d.encrypted) throw new Unsupported('encrypted chunks are not supported')
  let remaining = d.chunk_size
  const src = (n) => {
    n = Math.min(n, remaining)
    if (n <= 0) return Buffer.alloc(0)
    const b = slices.read(n)
    if (b.length !== n) throw new InnoError('chunk data truncated')
    remaining -= n
    return b
  }
  const comp = d.compression
  if (comp === 'stored') {
    for (;;) {
      const b = src(IN_BLOCK)
      if (!b.length) return
      yield b
    }
  }
  if (comp === 'zlib') {
    const dec = new Inflater()
    try {
      while (!dec.eof) {
        const pending = src(IN_BLOCK)
        if (!pending.length) return
        yield* dec.decompress(pending)
      }
    } finally { dec.close() }
    return
  }
  let dec
  if (comp === 'lzma1') dec = lzma1Decompressor(src(5))
  else if (comp === 'lzma2') {
    const b = src(1)
    if (!b.length) throw new PyUncaught('IndexError', 'index out of range')
    dec = lzma2Decompressor(b[0])
  } else if (comp === 'bzip2') dec = new BZ2Decompressor()
  else throw new Unsupported(`unknown chunk compression ${comp}`)
  while (!dec.eof) {
    let data
    if (dec.needs_input) {
      data = src(IN_BLOCK)
      if (!data.length) return
    } else data = Buffer.alloc(0)
    let o
    try {
      o = dec.decompress(data, OUT_BLOCK)
    } catch (ex) {
      if (ex instanceof LZMAError || ex instanceof BZ2Error || ex.name === 'EOFError') {
        throw new InnoError(`chunk decompression failed: ${ex.message}`)
      }
      throw ex
    }
    if (o.length) yield o
  }
}

class Cursor {
  constructor(gen) { this.gen = gen; this.buf = Buffer.alloc(0); this.bp = 0; this.pos = 0 }
  fill() {
    const r = this.gen.next()
    if (r.done) throw new InnoError(`chunk ended early at decompressed offset ${this.pos}`)
    this.buf = r.value
    this.bp = 0
  }
  *pieces(n) {
    while (n > 0) {
      if (this.bp >= this.buf.length) this.fill()
      const take = Math.min(n, this.buf.length - this.bp)
      const piece = this.bp || take !== this.buf.length ? this.buf.subarray(this.bp, this.bp + take) : this.buf
      this.bp += take
      this.pos += take
      n -= take
      yield piece
    }
  }
  skip(n) { for (const _ of this.pieces(n)) { /* discard */ } }
}

// ---------------------------------------------------------------------------------------------------------
// x86 call/jmp filters
// ---------------------------------------------------------------------------------------------------------
function x86Block5200(buf, addrOffset, flip) {
  const size = buf.length - 4
  if (size <= 0) return
  let i = 0
  for (;;) {
    let j = i
    while (j < size && buf[j] !== 0xE8 && buf[j] !== 0xE9) j++
    if (j >= size) return
    i = j + 1
    if (buf[i + 3] === 0 || buf[i + 3] === 0xFF) {
      const addr = (addrOffset + i + 4) % 0x1000000
      let rel = (buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16)) - addr
      rel = ((rel % 0x1000000) + 0x1000000) % 0x1000000
      if (flip && rel & 0x800000) buf[i + 3] ^= 0xFF
      buf[i] = rel & 0xFF
      buf[i + 1] = (rel >> 8) & 0xFF
      buf[i + 2] = rel >> 16
    }
    i += 4
  }
}

class X86Filter5200 {
  constructor(flip) { this.flip = flip; this.pending = Buffer.alloc(0); this.offset = 0 }
  feed(data) {
    this.pending = Buffer.concat([this.pending, data])
    const BLOCK = 0x10000
    const n = this.pending.length - (this.pending.length % BLOCK)
    if (!n) return Buffer.alloc(0)
    const o = Buffer.from(this.pending.subarray(0, n))
    this.pending = Buffer.from(this.pending.subarray(n))
    for (let s = 0; s < n; s += BLOCK) {
      x86Block5200(o.subarray(s, s + BLOCK), this.offset, this.flip)
      this.offset = (this.offset + BLOCK) % 0x100000000
    }
    return o
  }
  flush() {
    const o = this.pending
    this.pending = Buffer.alloc(0)
    x86Block5200(o, this.offset, this.flip)
    return o
  }
}

class X86Filter4108 {
  constructor() { this.addrOffset = 5; this.addr = 0; this.left = 0 }
  feed(data) {
    const buf = Buffer.from(data)
    const n = buf.length
    let i = 0
    let addr = this.addr, left = this.left, off = this.addrOffset
    while (i < n) {
      if (left === 0) {
        let j = i
        while (j < n && buf[j] !== 0xE8 && buf[j] !== 0xE9) j++
        if (j >= n) { off += n - i; i = n; break }
        off += j - i
        addr = ((-off % 0x100000000) + 0x100000000) % 0x100000000
        left = 4
        i = j + 1
        off += 1
      } else {
        addr += buf[i]
        buf[i] = addr & 0xFF
        addr = Math.floor(addr / 256)
        left -= 1
        i += 1
        off += 1
      }
    }
    this.addr = addr; this.left = left; this.addrOffset = off % 0x100000000
    return buf
  }
  flush() { return Buffer.alloc(0) }
}

function makeFilter(name) {
  if (name === null) return null
  if (name === 'x86_4108') return new X86Filter4108()
  return new X86Filter5200(name === 'x86_5309')
}

class Checker {
  constructor(ctype) {
    this.ctype = ctype
    if (ctype === 'sha1') this.h = crypto.createHash('sha1')
    else if (ctype === 'md5') this.h = crypto.createHash('md5')
    else if (ctype === 'crc32') this.v = 0
    else this.v = 1
  }
  update(data) {
    const t = this.ctype
    if (t === 'sha1' || t === 'md5') this.h.update(data)
    else if (t === 'crc32') this.v = crc32(data, this.v)
    else this.v = adler32(data, this.v)
  }
  digest() {
    const t = this.ctype
    if (t === 'sha1' || t === 'md5') return this.h.digest()
    const b = Buffer.alloc(4)
    b.writeUInt32LE(this.v >>> 0)
    return b
  }
}

const checksumHex = (d) => (d.checksum_type === 'crc32' || d.checksum_type === 'adler32'
  ? d.checksum.readUInt32LE(0).toString(16).padStart(8, '0') : d.checksum.toString('hex'))

// ---------------------------------------------------------------------------------------------------------
// GOG Galaxy split files
// ---------------------------------------------------------------------------------------------------------
const WS4 = ' \t\r\n'
function parseFunctionCall(code, name) {
  if (!code) return null
  const m = new RegExp(`^[${PYWS}]*([A-Za-z_][A-Za-z0-9_]*)[${PYWS}]*\\(`, 'u').exec(code)
  if (!m || m[1] !== name) return null
  let i = m[0].length
  const n = code.length
  const args = []
  for (;;) {
    while (i < n && WS4.includes(code[i])) i++
    if (i >= n) return null
    if (code[i] === ')' && !args.length) return args
    if (code[i] === "'" || code[i] === '"') {
      const q = code[i]
      i++
      const buf = []
      for (;;) {
        if (i >= n) return null
        if (code[i] === q) {
          if (i + 1 < n && code[i + 1] === q) { buf.push(q); i += 2; continue }
          i++
          break
        }
        buf.push(code[i])
        i++
      }
      args.push(buf.join(''))
    } else {
      let j = i
      while (j < n && !',) \t\r\n'.includes(code[j])) j++
      args.push(code.slice(i, j))
      i = j
    }
    while (i < n && WS4.includes(code[i])) i++
    if (i >= n) return null
    if (code[i] === ',') { i++; continue }
    if (code[i] === ')') return args
    return null
  }
}

function isGog(setup) {
  const h = setup.header
  return (h.app_publisher ?? '').toLowerCase().includes('gog.com') ||
    ['app_publisher_url', 'app_support_url', 'app_updates_url'].some((k) => (h[k] ?? '').toLowerCase().includes('www.gog.com'))
}

// Python int(str): whitespace, sign, underscores between digits; null on ValueError
function pyIntStr(s) {
  const t = s.replace(new RegExp(`^[${PYWS}]+|[${PYWS}]+$`, 'gu'), '')
  if (!/^[+-]?\p{Nd}+(_\p{Nd}+)*$/u.test(t)) return null
  let digits = ''
  for (const ch of t.replace(/_/g, '')) {
    if (ch === '+' || ch === '-') { digits += ch; continue }
    // any Unicode decimal digit: its value is its offset in its block of ten
    const c = ch.codePointAt(0)
    let v = c - 0x30
    if (v < 0 || v > 9) { let z = c; while (/\p{Nd}/u.test(String.fromCodePoint(z - 1))) z--; v = c - z }
    digits += String(v)
  }
  return Number(BigInt(digits))
}

function fromHex(s) {                     // bytes.fromhex
  const out = []
  let i = 0
  while (i < s.length) {
    if (' \t\n\v\f\r'.includes(s[i])) { i++; continue }
    const a = s[i], b = s[i + 1]
    if (!/^[0-9a-fA-F]$/.test(a)) throw new PyUncaught('ValueError', `non-hexadecimal number found in fromhex() arg at position ${i}`)
    if (b === undefined || !/^[0-9a-fA-F]$/.test(b)) {
      throw new PyUncaught('ValueError', `non-hexadecimal number found in fromhex() arg at position ${i + 1}`)
    }
    out.push(parseInt(a + b, 16))
    i += 2
  }
  return Buffer.from(out)
}

function effectiveFiles(setup) {
  const outl = []
  const galaxy = isGog(setup)
  let cur = null
  let remaining = 0
  setup.files.forEach((fe, idx) => {
    const e = { index: idx, destination: fe.destination, languages: fe.languages, components: fe.components,
      tasks: fe.tasks, options: fe.options, parts: null, md5: null, galaxy: false, arch: '' }
    let start = null, part = null, chk = null
    if (galaxy) {
      start = parseFunctionCall(fe.before_install, 'before_install')
      if (!start || !start.length) start = parseFunctionCall(fe.before_install, 'before_install_dependency')
      part = parseFunctionCall(fe.after_install, 'after_install')
      if (!part || !part.length) part = parseFunctionCall(fe.after_install, 'after_install_dependency')
      chk = parseFunctionCall(fe.check, 'check_if_install')
    }
    const truthy = (x) => x !== null && x.length > 0
    if (truthy(chk)) {
      const langs = chk.length > 0 ? chk[0].split('#').filter((x) => x) : []
      e.languages = langs.join(' or ')
      e.arch = chk.length > 1 ? chk[1] : ''
    }
    const hasData = fe.location < setup.data.length
    if (truthy(start)) {
      if (remaining) {
        throw new InnoError(`incomplete GOG Galaxy file ${pyRepr(cur.destination)} (${remaining} part(s) missing)`)
      }
      if (start.length < 3 || !/^[0-9a-fA-F]{32}\n?$/.test(start[0])) {
        throw new InnoError(`bad GOG Galaxy before_install arguments: ${pyRepr(fe.before_install)}`)
      }
      const cnt = pyIntStr(start[2])
      if (cnt === null) throw new InnoError(`bad GOG Galaxy part count in ${pyRepr(fe.before_install)}`)
      remaining = cnt
      e.destination = start[1]
      e.md5 = fromHex(start[0])
      e.parts = []
      e.galaxy = true
      cur = e
      outl.push(e)
    }
    if (truthy(part)) {
      if (!remaining || cur === null) {
        throw new InnoError(`GOG Galaxy file part without a start entry: ${pyRepr(fe.after_install)}`)
      }
      if (part.length < 3 || !hasData) throw new InnoError(`bad GOG Galaxy after_install entry: ${pyRepr(fe.after_install)}`)
      const usize = pyIntStr(part[2]), csize = pyIntStr(part[1])
      if (usize === null || csize === null) throw new InnoError(`bad GOG Galaxy part sizes in ${pyRepr(fe.after_install)}`)
      cur.parts.push({ loc: fe.location, kind: 'galaxy', md5: fromHex(part[0]), size: usize, stored_size: csize })
      remaining -= 1
      if (!remaining) cur = null
      return
    }
    if (truthy(start)) return
    if (!hasData) return
    const d = setup.data[fe.location]
    e.parts = [{ loc: fe.location, kind: 'raw', md5: null, size: d.size, stored_size: d.size }]
    outl.push(e)
  })
  if (remaining) throw new InnoError(`incomplete GOG Galaxy file ${pyRepr(cur.destination)} (${remaining} part(s) missing)`)
  return outl
}

function galaxyLanguages(setup) {
  const langs = []
  for (const e of effectiveFiles(setup)) {
    if (e.galaxy || e.arch) {
      for (const l of e.languages.split(new RegExp(`[${PYWS}]+or[${PYWS}]+`, 'u'))) {
        if (l && !langs.includes(l)) langs.push(l)
      }
    }
  }
  return langs
}

// ---------------------------------------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------------------------------------
function gogGameId(setup) {
  const pref = 'software\\gog.com\\games\\'
  let gid = ''
  for (const e of setup.registry) {
    const key = e.key
    if (!key.toLowerCase().startsWith(pref)) continue
    if (key.slice(pref.length).includes('\\')) continue
    if (e.name.toLowerCase() === 'gameid' && e.value) return e.value
    if (!gid) gid = key.slice(pref.length)
  }
  if (gid) return gid
  const re = /goggame-(\p{Nd}+)\.info(?![\p{L}\p{N}_])/iu
  for (const fe of setup.files) {
    for (const s of [fe.destination, fe.before_install]) {
      const m = re.exec(s)
      if (m) return m[1]
    }
  }
  return ''
}

function rarParts(setup) {
  const d = dirname(abspath(setup.path))
  const stems = [splitext(basename(setup.path))[0]]
  const bf = setup.header.base_filename
  if (bf && !stems.includes(bf)) stems.push(bf)
  const outl = []
  for (const stem of stems) {
    for (let i = 1; ; i++) {
      const p = join(d, `${stem}-${i}.bin`)
      if (!isfile(p)) break
      const f = new PyFile(p)
      try { if (f.read(4).toString('latin1') === 'Rar!') outl.push(p) } finally { f.close() }
    }
  }
  return outl
}

class Target {
  constructor(e, p) {
    this.entries = [e]
    this.paths = [p]
    this.parts = e.parts
    this.md5 = e.md5
    this.size = this.parts.reduce((a, x) => a + x.size, 0)
    this.offsets = []
    let o = 0
    for (const x of this.parts) { this.offsets.push(o); o += x.size }
    this.fd = null
    this.tmp = null
    this.written = this.parts.map(() => 0)
    this.done = new Set()
    this.nextPart = 0
    this.pending = new Map()
    this.hasher = this.md5 !== null ? crypto.createHash('md5') : null
    this.mtime = null
  }
  key() { return JSON.stringify([this.parts.map((x) => [x.loc, x.kind]), this.md5 ? this.md5.toString('hex') : null]) }
}

function plan(setup, includeTemp = false, language = null) {
  const sel = []
  for (const e of effectiveFiles(setup)) {
    if (!includeTemp && e.options.has('DeleteAfterInstall')) continue
    if (language && !expressionMatch(language, e.languages)) continue
    const p = convertPath(e.destination)
    if (!p) continue
    sel.push([e, p])
  }
  return sel
}

function planDirs(setup, includeTemp = false, language = null) {
  const o = []
  for (const de of setup.directories) {
    if (!includeTemp && de.options.has('DeleteAfterInstall')) continue
    if (language && !expressionMatch(language, de.languages)) continue
    const p = convertPath(de.name)
    if (p) o.push(p)
  }
  return o
}

function buildTargets(entries, mode) {
  const byPath = new Map()
  const order = []
  for (let [e, p] of entries) {
    let key = p.toLowerCase()
    if (byPath.has(key)) {
      if (mode === 'error') {
        throw new InnoError(`collision: ${p} (entries ${pyRepr(byPath.get(key)[0].destination)} and ${pyRepr(e.destination)})`)
      }
      if (mode === 'rename') {
        let k = 1
        while (byPath.has(`${p}$${k}`.toLowerCase())) k++
        p = `${p}$${k}`
        key = p.toLowerCase()
        order.push(key)
      }
    } else order.push(key)
    byPath.set(key, [e, p])
  }
  const targets = new Map()
  const tlist = []
  for (const key of order) {
    const [e, p] = byPath.get(key)
    const t = new Target(e, p)
    const k = t.key()
    if (targets.has(k)) { targets.get(k).paths.push(p); targets.get(k).entries.push(e) }
    else { targets.set(k, t); tlist.push(t) }
  }
  return tlist
}

const filetimeToUnix = (ft) => Number(ft) / 1e7 - 11644473600.0

// ---------------------------------------------------------------------------------------------------------
// Extraction engine
// ---------------------------------------------------------------------------------------------------------
function commonpath(a, b) {
  const x = a.split('/').filter((s) => s && s !== '.'), y = b.split('/').filter((s) => s && s !== '.')
  let i = 0
  while (i < x.length && i < y.length && x[i] === y[i]) i++
  return '/' + x.slice(0, i).join('/')
}

function safeJoin(root, rel) {
  const full = normpath(join(root, ...rel.split('/')))
  if (commonpath(root, full) !== root || full === root) throw new PathEscape(`refusing path outside output dir: ${rel}`)
  let cur = root
  for (const seg of rel.split('/').slice(0, -1)) {
    cur = join(cur, seg)
    if (islink(cur)) throw new PathEscape(`refusing to write through symlink ${cur}`)
  }
  return full
}

// os.makedirs(name, exist_ok=True)
function makedirs(name) {
  let [head, tail] = splitPath(name)
  if (!tail) [head, tail] = splitPath(head)
  if (head && tail && !exists(head)) {
    try { makedirs(head) } catch (e) { if (e.code !== 'EEXIST') throw e }
    if (tail === '.') return
  }
  try {
    fs.mkdirSync(name)
  } catch (e) {
    if (!isdir(name)) throw e
  }
}
function splitPath(p) {
  const i = p.lastIndexOf('/') + 1
  let head = p.slice(0, i)
  if (head && head !== '/'.repeat(head.length)) head = head.replace(/\/+$/, '')
  return [head, p.slice(i)]
}

function copyFile(src, dst) {               // shutil.copyfile: contents only
  const fi = fs.openSync(src, 'r')
  try {
    const fo = fs.openSync(dst, 'w')
    try {
      const b = Buffer.allocUnsafe(1 << 20)
      let pos = 0
      for (;;) {
        const n = fs.readSync(fi, b, 0, b.length, pos)
        if (!n) break
        let w = 0
        while (w < n) w += fs.writeSync(fo, b, w, n - w)
        pos += n
      }
    } finally { fs.closeSync(fo) }
  } finally { fs.closeSync(fi) }
}

const zlibHdrOk = (b) => b.length >= 2 && (b[0] & 0x0F) === 8 && ((b[0] << 8) | b[1]) % 31 === 0

class Engine {
  constructor(setup, targets, { outDir = null, setMtime = true, verifyAll = false, progress = null } = {}) {
    this.s = setup
    this.targets = targets
    this.outDir = outDir
    this.setMtime = setMtime
    this.verifyAll = verifyAll
    this.progress = progress
    this.uses = new Map()
    for (const t of targets) {
      if (outDir !== null) t.full = t.paths.map((p) => safeJoin(outDir, p))
      if (t.parts.length) t.mtime = filetimeToUnix(setup.data[t.parts[t.parts.length - 1].loc].filetime)
      t.parts.forEach((p, k) => {
        if (!this.uses.has(p.loc)) this.uses.set(p.loc, [])
        this.uses.get(p.loc).push([t, k])
      })
    }
    this.openTargets = new Set()
    this.stats = { data_entries_verified: 0, galaxy_parts_verified: 0, galaxy_files_verified: 0, files_written: 0,
      bytes_written: 0 }
  }

  openTmp(t) {
    t.tmp = t.full[0] + '.inno-partial'
    makedirs(dirname(t.tmp))
    t.fd = fs.openSync(t.tmp, 'w')
    this.openTargets.add(t)
  }

  write(t, k, data) {
    if (!data.length) return
    if (this.outDir !== null) {
      if (t.fd === null) this.openTmp(t)
      let w = 0
      const pos = t.offsets[k] + t.written[k]
      while (w < data.length) w += fs.writeSync(t.fd, data, w, data.length - w, pos + w)
    }
    t.written[k] += data.length
    if (t.hasher !== null) {
      if (k === t.nextPart) t.hasher.update(data)
      else {
        if (!t.pending.has(k)) t.pending.set(k, [])
        t.pending.get(k).push(Buffer.from(data))
      }
    }
  }

  partDone(t, k) {
    if (t.written[k] !== t.parts[k].size) {
      throw new InnoError(`${t.paths[0]}: part ${k} produced ${t.written[k]} bytes, expected ${t.parts[k].size}`)
    }
    t.done.add(k)
    while (t.done.has(t.nextPart)) {
      t.nextPart += 1
      if (t.hasher !== null) {
        for (const b of t.pending.get(t.nextPart) ?? []) t.hasher.update(b)
        t.pending.delete(t.nextPart)
      }
    }
    if (t.done.size === t.parts.length) this.finish(t)
  }

  finish(t) {
    if (t.hasher !== null) {
      const got = t.hasher.digest()
      if (!got.equals(t.md5)) {
        throw new InnoError(`MD5 mismatch for reassembled GOG file ${t.paths[0]}: expected ${t.md5.toString('hex')}, got ${got.toString('hex')}`)
      }
      this.stats.galaxy_files_verified += 1
    }
    if (this.outDir === null) return
    if (t.fd === null) this.openTmp(t)
    fs.closeSync(t.fd)
    t.fd = null
    for (const p of t.full.slice(1)) {
      makedirs(dirname(p))
      copyFile(t.tmp, p + '.inno-partial')
      fs.renameSync(p + '.inno-partial', p)
    }
    fs.renameSync(t.tmp, t.full[0])
    this.openTargets.delete(t)
    if (this.setMtime && t.mtime !== null) {
      for (const p of t.full) {
        try { fs.utimesSync(p, t.mtime, t.mtime) } catch { /* ignored like OSError/OverflowError */ }
      }
    }
    this.stats.files_written += t.full.length
    this.stats.bytes_written += t.size * t.full.length
  }

  abort() {
    for (const t of [...this.openTargets]) {
      try {
        if (t.fd !== null) { fs.closeSync(t.fd); t.fd = null }
        fs.unlinkSync(t.tmp)
      } catch { /* OSError ignored */ }
    }
    this.openTargets.clear()
  }

  process(idx, pieces) {
    const d = this.s.data[idx]
    const uses = this.uses.get(idx) ?? []
    const rawUses = uses.filter(([t, k]) => t.parts[k].kind === 'raw')
    const galUses = uses.filter(([t, k]) => t.parts[k].kind === 'galaxy')
    const chk = new Checker(d.checksum_type)
    const flt = makeFilter(d.filter)
    let dec = null
    const dmd5 = galUses.length ? crypto.createHash('md5') : null
    let first = true
    let gout = 0
    const emit = (piece) => {
      chk.update(piece)
      for (const [t, k] of rawUses) this.write(t, k, piece)
      if (galUses.length) {
        if (first) {
          first = false
          const p0 = galUses[0][0].parts[galUses[0][1]]
          if (p0.stored_size === p0.size && !zlibHdrOk(piece)) dec = false
          else dec = new Inflater()
        }
        let outs
        if (dec === false) outs = [piece]
        else {
          try {
            outs = [...dec.decompress(piece)]
          } catch (ex) {
            if (ex instanceof ZlibError) throw new InnoError(`GOG part zlib error (data entry ${idx}): ${ex.message}`)
            throw ex
          }
        }
        for (const o of outs) {
          if (!o.length) continue
          dmd5.update(o)
          gout += o.length
          for (const [t, k] of galUses) this.write(t, k, o)
        }
      }
    }
    try {
      for (let piece of pieces) {
        if (flt) piece = flt.feed(piece)
        if (piece.length) emit(piece)
      }
      if (flt) {
        const tail = flt.flush()
        if (tail.length) emit(tail)
      }
      const got = chk.digest()
      if (!got.equals(d.checksum)) {
        throw new InnoError(`${d.checksum_type.toUpperCase()} checksum mismatch for data entry ${idx} ` +
          `(${describeData(this.s, idx)}): stored ${checksumHex(d)}, computed ${got.toString('hex')}`)
      }
      this.stats.data_entries_verified += 1
      if (galUses.length) {
        if (dec !== null && dec !== false) {
          let complete
          try {
            complete = dec.finish()
          } catch (ex) {
            if (ex instanceof ZlibError) throw new InnoError(`GOG part zlib error (data entry ${idx}): ${ex.message}`)
            throw ex
          }
          if (!complete) throw new InnoError(`GOG part zlib stream truncated (data entry ${idx})`)
        }
        const pm = dmd5.digest()
        for (const [t, k] of galUses) {
          const p = t.parts[k]
          if (!pm.equals(p.md5) || gout !== p.size) {
            throw new InnoError(`GOG part MD5/size mismatch for ${t.paths[0]} part ${k}: expected ` +
              `${p.md5.toString('hex')}/${p.size}, got ${pm.toString('hex')}/${gout}`)
          }
        }
        this.stats.galaxy_parts_verified += 1
      }
    } finally {
      if (dec) dec.close()
    }
    for (const [t, k] of uses) this.partDone(t, k)
    if (this.progress) this.progress(idx, d)
  }

  run() {
    const s = this.s
    try {
      for (const t of this.targets) if (!t.parts.length) this.finish(t)
      const wanted = this.verifyAll ? s.data.map((_, i) => i) : [...this.uses.keys()].sort((a, b) => a - b)
      const chunks = new Map()
      for (const idx of wanted) {
        const d = s.data[idx]
        if (d.size === 0 && d.chunk_size === 0) { this.process(idx, []); continue }
        const key = `${d.first_slice},${d.chunk_offset}`
        if (!chunks.has(key)) chunks.set(key, [d.first_slice, d.chunk_offset, []])
        chunks.get(key)[2].push(idx)
      }
      const slices = new SliceSet(s)
      try {
        const keys = [...chunks.values()].sort((a, b) => (a[0] - b[0]) || (a[1] - b[1]))
        for (const [, , list] of keys) {
          const idxs = list.slice().sort((a, b) => (s.data[a].file_offset - s.data[b].file_offset) || (a - b))
          const d0 = s.data[idxs[0]]
          if (d0.encrypted) {
            throw new Unsupported(`data entry ${idxs[0]} is in an encrypted chunk; encrypted installers are not supported`)
          }
          let cur = null
          for (const idx of idxs) {
            const d = s.data[idx]
            if (d.size === 0) { this.process(idx, []); continue }
            if (cur === null || d.file_offset < cur.pos) cur = new Cursor(chunkPieces(slices, d0))
            cur.skip(d.file_offset - cur.pos)
            this.process(idx, cur.pieces(d.size))
          }
        }
      } finally {
        slices.close()
      }
      const left = this.targets.filter((t) => t.done.size !== t.parts.length)
      if (left.length) throw new InnoError(`${left.length} output files were not completed (e.g. ${left[0].paths[0]})`)
    } catch (ex) {
      this.abort()
      throw ex
    }
    return this.stats
  }
}

function describeData(setup, idx) {
  for (const fe of setup.files) if (fe.location === idx) return fe.destination
  return '?'
}

function preflight(setup) {
  const rars = rarParts(setup)
  if (rars.length) throw new Unsupported(RAR_MSG(rars[0]))
  if (setup.data.some((d) => d.encrypted)) throw new Unsupported('installer uses encrypted chunks (password protected); not supported')
}

const now = () => Date.now() / 1000
const round2 = (x) => pyFloat(Math.round(x * 100) / 100)

function doExtract(setup, outDir, { language = null, includeTemp = false, collisions = 'overwrite', setMtime = true,
  quiet = false } = {}) {
  preflight(setup)
  outDir = realpath(outDir)
  const targets = buildTargets(plan(setup, includeTemp, language), collisions)
  const dirs = planDirs(setup, includeTemp, language)
  for (const p of dirs) safeJoin(outDir, p + '/x')
  const t0 = now()
  const ndata = new Set(targets.flatMap((t) => t.parts.map((p) => p.loc))).size
  const done = [0, 0]
  const progress = (idx, d) => {
    done[0] += d.size
    done[1] += 1
    if (!quiet && done[1] % 1000 === 0) err(`  ${done[1]}/${ndata} data entries, ${(now() - t0).toFixed(0)}s\n`)
  }
  const eng = new Engine(setup, targets, { outDir, setMtime, progress })
  makedirs(outDir)
  for (const p of dirs) makedirs(join(outDir, ...p.split('/')))
  const st = eng.run()
  st.dirs_created = dirs.length
  st.seconds = round2(now() - t0)
  return st
}

// ---------------------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------------------
function infoDict(setup) {
  const h = setup.header
  const o = setup.offsets
  let sl = 0
  if (setup.data.length) sl = Math.max(...setup.data.map((d) => d.last_slice)) + 1
  const ss = new SliceSet(setup)
  let parts, layout
  if (o.data_offset) { parts = []; layout = `embedded in exe (data offset 0x${hex(o.data_offset)})` }
  else { parts = Array.from({ length: sl }, (_, i) => ss.sliceNames(i)[0]); layout = 'external disk slices' }
  const comps = [...new Set(setup.data.map((d) => d.compression))].sort(cmpStr)
  const filters = [...new Set(setup.data.filter((d) => d.filter).map((d) => d.filter))].sort(cmpStr)
  const eff = effectiveFiles(setup)
  const sel = plan(setup)
  return {
    inno_version: vstr(setup.version),
    version_string: setup.version_string,
    unicode: setup.unicode,
    tested_version: setup.tested,
    app_name: h.app_name,
    app_version: h.app_version,
    app_versioned_name: h.app_versioned_name,
    app_publisher: h.app_publisher,
    app_id: h.app_id,
    default_dir_name: h.default_dir_name,
    gog_game_id: gogGameId(setup),
    languages: setup.languages.map((l) => ({ name: l.name, language_name: l.language_name, id: l.language_id })),
    gog_languages: galaxyLanguages(setup),
    components: setup.components.map((c) => ({ name: c.name, description: c.description })),
    types: setup.types.map((t) => t.name),
    tasks: setup.tasks.map((t) => t.name),
    inno_file_entries: setup.files.length,
    data_entries: setup.data.length,
    gog_galaxy_files: eff.filter((e) => e.galaxy).length,
    gog_galaxy_parts: eff.filter((e) => e.galaxy).reduce((a, e) => a + e.parts.length, 0),
    files_to_extract: sel.length,
    bytes_to_extract: sel.reduce((a, [e]) => a + e.parts.reduce((b, p) => b + p.size, 0), 0),
    temp_files: eff.filter((e) => e.options.has('DeleteAfterInstall')).length,
    directories: setup.directories.length,
    compression: comps,
    x86_filters: filters,
    encrypted: setup.data.some((d) => d.encrypted),
    data_layout: layout,
    slices_needed: parts,
    slices_per_disk: h.slices_per_disk,
    rar_parts: rarParts(setup),
    unparsed_tail: setup.tail_error,
  }
}

const pyBool = (b) => (b ? 'True' : 'False')
const pdn = (n, w) => String(n).padStart(w)

function cmdInfo(a) {
  const s = openSetup(a.setup)
  const d = infoDict(s)
  if (a.json) { out(dumps(d, { indent: 2, ensureAscii: false }) + '\n'); return EXIT_OK }
  const L = []
  L.push(`Inno Setup data ${d.inno_version} (${d.unicode ? 'unicode' : 'ANSI'})${d.tested_version ? '' : '  [UNTESTED version]'}`)
  L.push(`App: ${d.app_name}  version ${d.app_version || '?'}  (${d.app_versioned_name})`)
  if (d.gog_game_id) L.push(`GOG.com game ID: ${d.gog_game_id}`)
  L.push(`Inno languages: ${d.languages.map((l) => `${l.name} (${l.language_name})`).join(', ')}`)
  if (d.gog_languages.length) L.push(`GOG file languages: ${d.gog_languages.join(', ')}`)
  if (d.components.length) L.push(`Components: ${d.components.map((c) => c.name).join(', ')}`)
  L.push(`Inno file entries: ${d.inno_file_entries}, data entries: ${d.data_entries}, [Dirs] entries: ${d.directories}`)
  if (d.gog_galaxy_files) {
    L.push(`GOG Galaxy split files: ${d.gog_galaxy_files} (from ${d.gog_galaxy_parts} parts), reassembled on extraction`)
  }
  L.push(`Files to extract: ${d.files_to_extract} (${d.bytes_to_extract} bytes), temp files skipped: ${d.temp_files}`)
  L.push(`Compression: ${d.compression.join(',') || '-'}; x86 filter: ${d.x86_filters.join(',') || 'none'}; encrypted: ${pyBool(d.encrypted)}`)
  L.push(`Data: ${d.data_layout}`)
  if (d.slices_needed.length) L.push(`Slices needed: ${d.slices_needed.join(', ')}`)
  if (d.rar_parts.length) L.push(`UNSUPPORTED: GOG RAR data parts present: ${d.rar_parts.join(', ')}`)
  out(L.join('\n') + '\n')
  return EXIT_OK
}

function cmdList(a) {
  const s = openSetup(a.setup)
  const rows = []
  for (const [e, p] of plan(s, a.include_temp, a.language)) {
    let ctype, csum
    if (e.galaxy) { ctype = 'md5'; csum = e.md5.toString('hex') }
    else { const d = s.data[e.parts[0].loc]; ctype = d.checksum_type; csum = checksumHex(d) }
    rows.push({ path: p, destination: e.destination, size: e.parts.reduce((x, q) => x + q.size, 0),
      checksum_type: ctype, checksum: csum, languages: e.languages, components: e.components, tasks: e.tasks,
      temp: e.options.has('DeleteAfterInstall'), gog_galaxy_parts: e.galaxy ? e.parts.length : 0,
      data_entries: e.parts.map((q) => q.loc) })
  }
  if (a.json) { out(dumps(rows, { indent: 1, ensureAscii: false }) + '\n'); return EXIT_OK }
  const L = []
  for (const r of rows) {
    const cond = []
    if (r.languages) cond.push('lang=' + r.languages)
    if (r.components) cond.push('comp=' + r.components)
    if (r.tasks) cond.push('task=' + r.tasks)
    if (r.temp) cond.push('temp')
    if (r.gog_galaxy_parts) cond.push(`galaxy parts=${r.gog_galaxy_parts}`)
    L.push(`${pdn(r.size, 12)}  ${r.checksum_type}:${r.checksum}  ${r.path}${cond.length ? '  [' + cond.join('; ') + ']' : ''}\n`)
  }
  out(L.join(''))
  err(`${rows.length} files, ${rows.reduce((x, r) => x + r.size, 0)} bytes\n`)
  return EXIT_OK
}

function cmdExtract(a) {
  const s = openSetup(a.setup)
  if (!s.tested && !a.quiet) err(`warning: Inno Setup ${vstr(s.version)} is not a tested version\n`)
  const res = doExtract(s, a.out_dir, { language: a.language, includeTemp: a.include_temp, collisions: a.collisions,
    setMtime: !a.no_mtime, quiet: a.quiet })
  res.out_dir = realpath(a.out_dir)
  res.inno_version = vstr(s.version)
  res.app_name = s.header.app_name
  res.gog_game_id = gogGameId(s)
  out(dumps(res, { indent: 2 }) + '\n')
  return EXIT_OK
}

function cmdVerify(a) {
  const s = openSetup(a.setup)
  preflight(s)
  const t0 = now()
  const targets = buildTargets(plan(s, true), 'rename')
  const st = new Engine(s, targets, { outDir: null, verifyAll: true }).run()
  delete st.files_written
  delete st.bytes_written
  st.data_entries = s.data.length
  st.seconds = round2(now() - t0)
  out(dumps(st, { indent: 2 }) + '\n')
  return st.data_entries_verified === s.data.length ? EXIT_OK : EXIT_FAIL
}

// ---- argparse (Python 3.9) for this command line ----
const TOP_USAGE = 'usage: inno.py [-h] {info,list,extract,verify} ...\n'
const TOP_HELP = TOP_USAGE + '\nPure-Python GOG Inno Setup extractor\n\npositional arguments:\n' +
  '  {info,list,extract,verify}\n\noptional arguments:\n  -h, --help            show this help message and exit\n'
const SUB_HELP = {
  info: 'usage: inno.py info [-h] [--json] setup\n\npositional arguments:\n  setup\n\noptional arguments:\n' +
    '  -h, --help  show this help message and exit\n  --json\n',
  list: 'usage: inno.py list [-h] [--json] [--include-temp] [--exclude-temp]\n' +
    '                    [--language LANGUAGE]\n                    setup\n\npositional arguments:\n  setup\n\n' +
    'optional arguments:\n  -h, --help           show this help message and exit\n  --json\n  --include-temp\n' +
    '  --exclude-temp\n  --language LANGUAGE\n',
  extract: 'usage: inno.py extract [-h] [--language LANGUAGE] [--include-temp]\n' +
    '                       [--exclude-temp]\n                       [--collisions {overwrite,error,rename}] [--no-mtime]\n' +
    '                       [--quiet]\n                       setup out_dir\n\npositional arguments:\n  setup\n  out_dir\n\n' +
    'optional arguments:\n  -h, --help            show this help message and exit\n  --language LANGUAGE\n' +
    '  --include-temp\n  --exclude-temp\n  --collisions {overwrite,error,rename}\n  --no-mtime\n  --quiet\n',
  verify: 'usage: inno.py verify [-h] setup\n\npositional arguments:\n  setup\n\noptional arguments:\n' +
    '  -h, --help  show this help message and exit\n',
}
const H = { strings: ['-h', '--help'], kind: 'help' }
const sub = (name, options, positionals) => ({ name, help: SUB_HELP[name], options: [H, ...options], positionals })
const LANG = { strings: ['--language'], dest: 'language', kind: 'store' }
const INCL = { strings: ['--include-temp'], dest: 'include_temp', kind: 'store_true' }
const EXCL = { strings: ['--exclude-temp'], dest: 'include_temp', kind: 'store_false' }
const SUBPARSERS = {
  info: sub('info', [{ strings: ['--json'], dest: 'json', kind: 'store_true' }], [{ dest: 'setup' }]),
  list: sub('list', [{ strings: ['--json'], dest: 'json', kind: 'store_true' }, INCL, { ...EXCL, default: false }, LANG],
    [{ dest: 'setup' }]),
  extract: sub('extract', [LANG, INCL, { ...EXCL, default: false },
    { strings: ['--collisions'], dest: 'collisions', kind: 'store', choices: ['overwrite', 'error', 'rename'], default: 'overwrite' },
    { strings: ['--no-mtime'], dest: 'no_mtime', kind: 'store_true' }, { strings: ['--quiet'], dest: 'quiet', kind: 'store_true' }],
  [{ dest: 'setup' }, { dest: 'out_dir' }]),
  verify: sub('verify', [], [{ dest: 'setup' }]),
}
const TOP = { help: TOP_HELP, options: [H], positionals: [{ dest: 'cmd', nargs: 'PARSER', choices: SUBPARSERS }] }

class ArgExit extends Error { constructor(code) { super('exit'); this.code = code } }

// ArgumentParser.parse_args with inno.py's error(): every error prints the top-level usage
function parseArgs(argv) {
  const ns = {}
  try {
    const extras = parseKnownArgs(TOP, argv, ns)
    if (extras.length) throw new ArgError(`unrecognized arguments: ${extras.join(' ')}`)
  } catch (e) {
    if (e instanceof ArgHelp) { out(e.parser.help); throw new ArgExit(0) }
    if (e instanceof ArgError) { err(TOP_USAGE + `inno.py: error: ${e.message}\n`); throw new ArgExit(EXIT_UNSUPPORTED) }
    throw e
  }
  return ns.cmd ? ns : null
}

function main(argv) {
  let a
  try {
    a = parseArgs(argv)
  } catch (e) {
    if (e instanceof ArgExit) return e.code
    throw e
  }
  if (a === null) { err(TOP_HELP); return EXIT_UNSUPPORTED }
  try {
    return { info: cmdInfo, list: cmdList, extract: cmdExtract, verify: cmdVerify }[a.cmd](a)
  } catch (ex) {
    if (ex instanceof InnoError) {
      err(`inno.py: ${ex.exitCode === EXIT_UNSUPPORTED ? 'unsupported: ' : 'error: '}${ex.message}\n`)
      return ex.exitCode
    }
    if (isOSError(ex)) { err(`inno.py: I/O error: ${osErrorStr(ex)}\n`); return EXIT_FAIL }
    if (ex instanceof PyUncaught) { traceback(ex.cls, ex.message); return EXIT_FAIL }
    if (ex instanceof StructError) { traceback('struct.error', ex.message); return EXIT_FAIL }
    if (ex instanceof LZMAError) { traceback('_lzma.LZMAError', ex.message); return EXIT_FAIL }
    if (ex instanceof ZlibError) { traceback('zlib.error', ex.message); return EXIT_FAIL }
    throw ex
  }
}

process.exitCode = main(process.argv.slice(2))
