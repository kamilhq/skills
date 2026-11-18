#!/usr/bin/env node
// inventory.mjs - JavaScript (Node.js) port of inventory.py (phase 2 census and archive extraction).
// Same command line, output, files written and exit codes as inventory.py:
//   inventory.mjs <game_dir> [--json out.json]
//   inventory.mjs <game_dir> --extract <out_dir> [--only GLOB ...] [--force] [--json out.json]
// ZIP reading: lib/zipfile.mjs (Python zipfile semantics, CRC-32 checked).

import fs from 'node:fs'
import { dumps } from './lib/pyjson.mjs'
import { ZipFile } from './lib/zipfile.mjs'
import {
  err, print, walk, join, dirname, splitext, relpath, isdir, getsize, cmpStr, fnmatchcase, fixed, ljust,
  rjust, traceback, isOSError, osErrorStr, osErrorClass,
} from './lib/pyshim.mjs'

const DOC = "Phase 2 census (and archive extraction): what a game tree contains, and which files are disguised.\n\n  inventory.py <game_dir> [--json out.json]\n  inventory.py <game_dir> --extract <out_dir> [--only GLOB ...] [--force] [--json out.json]\n\nCensus: for every file, extension, size, first 16 bytes, container/format detected by magic, and whether the\nfile is a known format hidden under a whole-file single-byte XOR (key reported). ZIP-based archives (even\nunder a non-.zip extension, even XORed) are opened and their members counted per archive and by extension;\n\"game archives\" (not .zip/.hashdb and not GOG/installer files) are totalled separately from other zips so the\nmember count can be checked against the extracted tree. Files no magic matched are listed as UNCLASSIFIED:\nthe phase-2 gate is that every one of them is explained.\n\n--extract: unpack every ZIP-based archive (after removing its XOR) into\n  <out_dir>/<archive path relative to game_dir, without extension>/      e.g. extracted/DATA/Textos/\n(if two archives would share that folder, the extension is kept: DATA/Textos_pak/). --only GLOB (repeatable,\nfnmatch on the relative path, case-insensitive) limits which archives, e.g. --only 'DATA/*.pak'. Every member's\nCRC-32 is checked while reading; names that are absolute, contain '..' or a drive letter, or that collide with\nanother member when case is ignored are refused and reported, never written. An existing non-empty target\nfolder is skipped unless --force. Writes <out_dir>/extract_report.json. Exit 0 ok, 1 any archive or member\nfailed, 2 bad arguments.\nStdlib only; run with -I.\n"

class SysExit extends Error { constructor(code, msg) { super(msg); this.code = code } }

const L1 = (s) => Buffer.from(s, 'latin1')
const MAGICS = [
  [L1('PK\x03\x04'), 'zip'], [L1('PK\x05\x06'), 'zip(empty)'], [L1('Rar!'), 'rar'], [L1('7z\xbc\xaf'), '7z'],
  [L1('MZ'), 'pe/mz'], [L1('RIFF'), 'riff'], [L1('OggS'), 'ogg'], [L1('BIK'), 'bink'], [L1('KB2'), 'bink2'],
  [L1('SMK2'), 'smacker'], [L1('DDS '), 'dds'], [L1('BM'), 'bmp'], [L1('\x89PNG'), 'png'], [L1('\xff\xd8\xff'), 'jpeg'],
  [L1('GIF8'), 'gif'], [L1('ID3'), 'mp3'], [L1('\xff\xfb'), 'mp3'], [L1('%PDF'), 'pdf'], [L1('\x1f\x8b'), 'gzip'],
  [L1('BZh'), 'bzip2'], [L1('\x00\x00\x01\x00'), 'ico'], [L1('\xef\xbb\xbf'), 'utf8-bom text'],
  [L1('\xff\xfe'), 'utf16le-bom text'], [L1('MThd'), 'midi'], [L1('FORM'), 'iff'], [L1('XPDS'), '?'],
]
const NOT_GAME_ARCHIVE = ['.zip', '.hashdb']

const startsWith = (h, m) => h.length >= m.length && h.subarray(0, m.length).equals(m)

function detect(head) {
  for (const [m, name] of MAGICS) if (startsWith(head, m)) return name
  if (head.length && [...head.subarray(0, 16)].every((c) => (c >= 32 && c < 127) || c === 9 || c === 10 || c === 13)) return 'text?'
  return null
}

function xorDetect(head) {
  if (head.length < 4) return null
  for (const [m, name] of MAGICS) {
    if (m.length < 3) continue
    const k = head[0] ^ m[0]
    if (k && [...m].every((b, i) => (head[i] ^ k) === b)) return [k, name]
  }
  return null
}

function openZip(p, xor) {
  if (!xor) return new ZipFile(p)
  const data = fs.readFileSync(p)
  for (let i = 0; i < data.length; i++) data[i] ^= xor
  return new ZipFile(data)
}

const hexSpaced = (b) => [...b].map((c) => c.toString(16).padStart(2, '0')).join(' ')
const extOf = (name) => splitext(name)[1].toLowerCase() || '(none)'

// collections.Counter(...).most_common(): count descending, ties in first-seen order
function counter(items) {
  const m = new Map()
  for (const k of items) m.set(k, (m.get(k) ?? 0) + 1)
  return m
}
const mostCommon = (m, n = Infinity) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n)

function readHead(p) {
  const fd = fs.openSync(p, 'r')
  try {
    const b = Buffer.alloc(16)
    const n = fs.readSync(fd, b, 0, 16, 0)
    return b.subarray(0, n)
  } finally { fs.closeSync(fd) }
}

function census(root) {
  const rows = [], archives = []
  for (const [r, ds, fs_] of walk(root)) {
    ds.sort(cmpStr)
    for (const f of fs_.slice().sort(cmpStr)) {
      const p = join(r, f)
      const head = readHead(p)
      let fmt = detect(head), xor = null
      if (!fmt) {
        const x = xorDetect(head)
        if (x) [xor, fmt] = x
      }
      const ext = splitext(f)[1].toLowerCase() || '(none)'
      const rel = relpath(p, root)
      rows.push(new Map([['path', rel], ['ext', ext], ['size', getsize(p)], ['head', hexSpaced(head)], ['format', fmt],
        ['xor_key', xor]]))
      if (fmt === 'zip') {
        const a = new Map([['path', rel], ['xor_key', xor],
          ['game', !NOT_GAME_ARCHIVE.includes(ext) && !f.toLowerCase().startsWith('goggame')], ['members', 0],
          ['by_ext', new Map()], ['error', null]])
        try {
          const z = openZip(p, xor)
          let c
          try { c = counter(z.infolist().filter((i) => !i.is_dir()).map((i) => extOf(i.filename))) } finally { z.close() }
          a.set('members', [...c.values()].reduce((x, y) => x + y, 0))
          a.set('by_ext', new Map(mostCommon(c)))
        } catch (e) {
          if (e && e.name === 'zipfile.BadZipFile') a.set('error', e.message)
          else if (isOSError(e)) a.set('error', osErrorStr(e))
          else if (e && e.name === 'OSError') a.set('error', e.message)
          else throw e
        }
        archives.push(a)
      }
    }
  }
  return [rows, archives]
}

function safeName(n) {
  n = n.replace(/\\/g, '/')
  const parts = n.split('/').filter((x) => x !== '' && x !== '.')
  if (n.startsWith('/') || n.includes(':') || parts.some((x) => x === '..') || !parts.length) return null
  return parts.join('/')
}

function makedirs(name) {          // os.makedirs(name, exist_ok=True)
  const i = name.lastIndexOf('/') + 1
  let head = name.slice(0, i), tail = name.slice(i)
  if (head && head !== '/'.repeat(head.length)) head = head.replace(/\/+$/, '')
  if (!tail) {
    const j = head.lastIndexOf('/') + 1
    tail = head.slice(j); head = head.slice(0, j)
    if (head && head !== '/'.repeat(head.length)) head = head.replace(/\/+$/, '')
  }
  if (head && tail && !fs.existsSync(head)) {
    try { makedirs(head) } catch (e) { if (e.code !== 'EEXIST') throw e }
    if (tail === '.') return
  }
  try { fs.mkdirSync(name) } catch (e) { if (!isdir(name)) throw e }
}

function listdirNonEmpty(p) {
  const d = fs.opendirSync(p)
  try { return d.readSync() !== null } finally { d.closeSync() }
}

function extract(root, archives, outDir, only, force) {
  const targets = new Map(), report = []
  let failed = false
  for (const a of archives) {
    if (only.length && !only.some((g) => fnmatchcase(a.get('path').toLowerCase(), g.toLowerCase()))) continue
    if (a.get('error')) {
      report.push(new Map([['archive', a.get('path')], ['xor_key', a.get('xor_key')], ['dest', null], ['members', 0],
        ['bytes', 0], ['refused', []], ['errors', ['unreadable archive: ' + a.get('error')]]]))
      print(`${ljust(a.get('path'), 40)} UNREADABLE: ${a.get('error')}`)
      failed = true
      continue
    }
    const key = splitext(a.get('path'))[0].toLowerCase()
    if (!targets.has(key)) targets.set(key, [])
    targets.get(key).push(a)
  }
  for (const [, group] of [...targets.entries()].sort((x, y) => cmpStr(x[0], y[0]))) {
    for (const a of group) {
      const [stem, ext] = splitext(a.get('path'))
      const dest = join(outDir, stem + (group.length > 1 ? '_' + ext.slice(1) : ''))
      const rec = new Map([['archive', a.get('path')], ['xor_key', a.get('xor_key')], ['dest', relpath(dest, outDir)],
        ['members', 0], ['bytes', 0], ['refused', []], ['errors', []]])
      report.push(rec)
      if (isdir(dest) && listdirNonEmpty(dest)) {
        if (!force) {
          rec.get('errors').push('destination exists and is not empty (use --force)')
          print(`${ljust(a.get('path'), 40)} -> ${ljust(rec.get('dest'), 32)} SKIPPED: destination exists and is not empty (--force)`)
          failed = true
          continue
        }
        fs.rmSync(dest, { recursive: true })
      }
      const seen = new Map()
      const z = openZip(join(root, a.get('path')), a.get('xor_key'))
      try {
        for (const i of z.infolist()) {
          const n = safeName(i.filename)
          if (n === null) { rec.get('refused').push(`${i.filename}: unsafe path`); continue }
          if (seen.has(n.toLowerCase()) && !i.is_dir()) {
            rec.get('refused').push(`${i.filename}: collides with ${seen.get(n.toLowerCase())} when case is ignored`)
            continue
          }
          const target = join(dest, ...n.split('/'))
          if (i.is_dir()) { makedirs(target); continue }
          seen.set(n.toLowerCase(), i.filename)
          let data
          try {
            data = z.read(i)
          } catch (e) {
            if (e && ['zipfile.BadZipFile', 'NotImplementedError', 'RuntimeError', 'OSError'].includes(e.name)) {
              rec.get('errors').push(`${i.filename}: ${e.message}`)
              continue
            }
            if (isOSError(e)) { rec.get('errors').push(`${i.filename}: ${osErrorStr(e)}`); continue }
            throw e
          }
          makedirs(dirname(target))
          fs.writeFileSync(target, data)
          rec.set('members', rec.get('members') + 1)
          rec.set('bytes', rec.get('bytes') + data.length)
        }
      } finally { z.close() }
      failed = failed || !!(rec.get('refused').length || rec.get('errors').length)
      print(`${ljust(a.get('path'), 40)} -> ${ljust(rec.get('dest'), 32)} ${rjust(rec.get('members'), 6)} members ` +
        `${rjust(fixed(rec.get('bytes') / 1e6, 2), 9)} MB` +
        (rec.get('refused').length ? `  REFUSED ${rec.get('refused').length}` : '') +
        (rec.get('errors').length ? `  ERRORS ${rec.get('errors').length}` : ''))
    }
  }
  makedirs(outDir)
  fs.writeFileSync(join(outDir, 'extract_report.json'), dumps(report, { indent: 1 }))
  print(`extracted ${report.reduce((s, r) => s + r.get('members'), 0)} members from ${report.length} archives into ${outDir}` +
    (failed ? '  (FAILURES: see extract_report.json)' : ''))
  return failed ? 1 : 0
}

function take(argv, name, multi = false) {
  const vals = []
  while (argv.includes(name)) {
    const i = argv.indexOf(name)
    if (i + 1 >= argv.length) throw new SysExit(1, `${name} needs a value`)
    vals.push(argv[i + 1])
    argv.splice(i, 2)
  }
  return multi ? vals : (vals.length ? vals[vals.length - 1] : null)
}

function main() {
  let argv = process.argv.slice(2)
  const force = argv.includes('--force')
  argv = argv.filter((a) => a !== '--force')
  const jpath = take(argv, '--json'), outDir = take(argv, '--extract'), only = take(argv, '--only', true)
  if (argv.length !== 1 || !isdir(argv[0])) { err(DOC + '\n'); return 2 }
  const root = argv[0]
  const [rows, archives] = census(root)
  const by = new Map()
  for (const x of rows) {
    if (!by.has(x.get('ext'))) by.set(x.get('ext'), [])
    by.get(x.get('ext')).push(x)
  }
  print(`${ljust('ext', 10)} ${rjust('files', 6)} ${rjust('MB', 9)}  format (xor)        example`)
  const sizeSum = (xs) => xs.reduce((s, x) => s + x.get('size'), 0)
  for (const [ext, xs] of [...by.entries()].sort((a, b) => sizeSum(b[1]) - sizeSum(a[1]))) {
    const fmts = counter(xs.map((x) => `${x.get('format') ?? 'None'}${x.get('xor_key') ? '^' + x.get('xor_key').toString(16).padStart(2, '0') : ''}`))
    print(`${ljust(ext, 10)} ${rjust(xs.length, 6)} ${rjust(fixed(sizeSum(xs) / 1e6, 2), 9)}  ` +
      `${ljust(mostCommon(fmts, 3).map(([k, v]) => `${k}:${v}`).join(','), 20)} ${xs[0].get('path')}`)
  }
  const members = new Map()
  if (archives.length) {
    print('\nzip-based archives (members per archive):')
    for (const a of archives) {
      const top = [...a.get('by_ext').entries()].slice(0, 4).map(([e, c]) => `${e}:${c}`).join(', ')
      const xk = a.get('xor_key') ? 'xor^' + a.get('xor_key').toString(16).padStart(2, '0') : ''
      print(`  ${ljust(a.get('path'), 40)} ${ljust(xk, 7)} ${rjust(a.get('members'), 6)}  ` +
        `${a.get('game') ? '' : '(not game data) '}${a.get('error') || top}`)
      if (a.get('game')) for (const [e, c] of a.get('by_ext')) members.set(e, (members.get(e) ?? 0) + c)
    }
    const g = archives.filter((a) => a.get('game'))
    print(`  game archives: ${g.length}, members: ${g.reduce((s, a) => s + a.get('members'), 0)}; other zips: ` +
      `${archives.length - g.length}, members: ${archives.filter((a) => !a.get('game')).reduce((s, a) => s + a.get('members'), 0)}`)
    print('\nmembers of game archives by extension:')
    for (const [e, c] of mostCommon(members)) print(`  ${ljust(e, 10)} ${c}`)
  }
  const unk = rows.filter((x) => x.get('format') === null)
  print(`\nUNCLASSIFIED (no known magic, not XORed): ${unk.length} file(s)`)
  for (const x of unk.slice(0, 20)) print(`  ${x.get('path')}  head=${x.get('head')}`)
  if (jpath) {
    fs.writeFileSync(jpath, dumps(new Map([['files', rows], ['archives', archives], ['archive_members', members],
      ['unclassified', unk.map((x) => x.get('path'))]]), { indent: 1 }))
  }
  if (outDir) {
    print()
    return extract(root, archives, outDir, only, force)
  }
  return 0
}

let rc
try {
  rc = main()
} catch (e) {
  if (e instanceof SysExit) { err(e.message + '\n'); rc = e.code }
  else if (isOSError(e)) { traceback(osErrorClass(e), osErrorStr(e)); rc = 1 }
  else if (e && /^(zipfile\.BadZipFile|NotImplementedError|RuntimeError|EOFError|zlib\.error|UnicodeDecodeError|LZMAError)$/.test(e.name)) {
    traceback(e.name, e.message); rc = 1
  } else throw e
}
process.exitCode = rc
