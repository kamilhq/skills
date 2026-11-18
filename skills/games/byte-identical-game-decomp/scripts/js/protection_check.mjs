#!/usr/bin/env node
// JavaScript port of protection_check.py (same CLI, output and exit codes). Node built-ins only.
import { openSync, readSync, closeSync, readFileSync, readdirSync, statSync, lstatSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { dumps } from './lib/pyjson.mjs'

const DOC = "protection_check.py <game_dir_or_file> [...] [--json OUT]\n\nPhase 1 gate: look for copy protection (DRM) and executable packers in a game before any analysis. Working\naround copy protection is unlawful in most countries even for a game you own (US DMCA 17 U.S.C. 1201, EU\nInfoSoc Directive art. 6), independently of copyright in the code, so the pipeline stops when it finds one.\n\nEvery file under each argument is checked (folders recursively, in sorted order):\n  - file names of known protection components (SafeDisc, StarForce, LaserLock, CD-Cops), any folder;\n  - in every PE file (MZ + PE signature): section names of known protections and packers (SafeDisc,\n    SecuROM, StarForce, the Steam DRM wrapper, UPX, ASPack, MPRESS, PECompact, Petite, NsPack, Themida /\n    WinLicense, VMProtect, Enigma), imported DLLs of known protections, the SafeDisc signature string;\n  - entry-point heuristics for unknown packers: entry point outside every section, in a writable code\n    section, or in a section whose raw data has entropy >= 7.2 bits per byte (packed or encrypted code).\nSteamworks (steam_api.dll) and GOG Galaxy imports are reported as \"info\": they are platform APIs, not DRM.\n\nPrints one JSON summary: scanned_files, pe_files, verdict (\"clean\", \"protected\" or \"review\"), findings\n[{file, kind, product, evidence}] with kind \"drm\", \"packer\", \"warning\" (heuristic) or \"info\".\n\"protected\" = a drm or packer finding: stop and tell the user (a GOG release of the same game is usually\nDRM-free). \"review\" = only heuristic warnings: show them to the user and continue only with their decision.\nExit 0 clean (info findings allowed), 1 protected or review, 2 bad arguments or nothing to scan.\nStdlib only; run with -I."

const FILE_NAMES = {
  '00000001.tmp': ['drm', 'SafeDisc'], 'clcd16.dll': ['drm', 'SafeDisc'], 'clcd32.dll': ['drm', 'SafeDisc'],
  'clokspl.exe': ['drm', 'SafeDisc'], 'dplayerx.dll': ['drm', 'SafeDisc'], 'drvmgt.dll': ['drm', 'SafeDisc'],
  'secdrv.sys': ['drm', 'SafeDisc'], 'protect.dll': ['drm', 'StarForce'], 'protect.exe': ['drm', 'StarForce'],
  'laserlok.in': ['drm', 'LaserLock'], 'laserlok.o10': ['drm', 'LaserLock'], 'laserlok.o11': ['drm', 'LaserLock'],
  'cdcops.dll': ['drm', 'CD-Cops']
}
const IMPORTS = { ...FILE_NAMES, 'steam_api.dll': ['info', 'Steamworks API'], 'galaxy.dll': ['info', 'GOG Galaxy API'] }
const SECTIONS = {
  stxt371: ['drm', 'SafeDisc'], stxt774: ['drm', 'SafeDisc'], '.stxt371': ['drm', 'SafeDisc'],
  '.stxt774': ['drm', 'SafeDisc'], '.securom': ['drm', 'SecuROM'], '.cms_t': ['drm', 'SecuROM'],
  '.cms_d': ['drm', 'SecuROM'], '.sforce': ['drm', 'StarForce'], '.sforce3': ['drm', 'StarForce'],
  '.bind': ['drm', 'Steam DRM wrapper'],
  upx0: ['packer', 'UPX'], upx1: ['packer', 'UPX'], upx2: ['packer', 'UPX'], '.aspack': ['packer', 'ASPack'],
  '.adata': ['packer', 'ASPack'], '.mpress1': ['packer', 'MPRESS'], '.mpress2': ['packer', 'MPRESS'],
  pec2: ['packer', 'PECompact'], pecompact2: ['packer', 'PECompact'], '.petite': ['packer', 'Petite'],
  '.nsp0': ['packer', 'NsPack'], '.nsp1': ['packer', 'NsPack'], '.themida': ['packer', 'Themida/WinLicense'],
  '.winlice': ['packer', 'Themida/WinLicense'], '.vmp0': ['packer', 'VMProtect'], '.vmp1': ['packer', 'VMProtect'],
  '.enigma1': ['packer', 'Enigma'], '.enigma2': ['packer', 'Enigma']
}
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k)
const STRINGS = [[Buffer.from('BoG_ *90.0&!!  Yy>', 'latin1'), 'drm', 'SafeDisc']]
const ENTROPY_LIMIT = 720
const SCN_EXEC = 0x20000000; const SCN_WRITE = 0x80000000
const USAGE = 'usage: protection_check.py <game_dir_or_file> [...] [--json OUT]\n'
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0)

export function entropy100 (b) {
  if (!b.length) return 0
  const counts = new Array(256).fill(0)
  for (const x of b) counts[x]++
  const n = b.length
  let e = 0.0
  for (const c of counts) {
    if (c) { const p = c / n; e -= p * Math.log2(p) }
  }
  return Math.trunc(e * 100)
}

export function parsePe (d) {
  if (d.length < 0x40 || d[0] !== 0x4d || d[1] !== 0x5a) return null
  const pe = d.readUInt32LE(0x3c)
  if (pe + 24 > d.length || d.toString('latin1', pe, pe + 4) !== 'PE\0\0') return null
  const nsec = d.readUInt16LE(pe + 6)
  const optsize = d.readUInt16LE(pe + 20)
  const opt = pe + 24
  if (opt + 2 > d.length) return null
  const magic = d.readUInt16LE(opt)
  const entry = opt + 20 <= d.length ? d.readUInt32LE(opt + 16) : 0
  const dd = opt + (magic === 0x10b ? 96 : 112)
  let impRva = 0
  if (dd + 16 <= opt + optsize && dd + 16 <= d.length) impRva = d.readUInt32LE(dd + 8)
  const sections = []
  const so = opt + optsize
  for (let i = 0; i < nsec; i++) {
    const o = so + 40 * i
    if (o + 40 > d.length) break
    let nb = d.subarray(o, o + 8)
    let k = nb.length
    while (k > 0 && nb[k - 1] === 0) k--
    nb = nb.subarray(0, k)
    sections.push([nb.toString('latin1'), d.readUInt32LE(o + 12), d.readUInt32LE(o + 8), d.readUInt32LE(o + 20),
      d.readUInt32LE(o + 16), d.readUInt32LE(o + 36)])
  }
  const off = (rva) => {
    for (const [, va, vs, rp, rs] of sections) {
      if (va <= rva && rva < va + Math.max(vs, rs) && rva - va < rs) return rp + rva - va
    }
    return null
  }
  const imports = []
  let o = impRva ? off(impRva) : null
  while (o !== null && o + 20 <= d.length && imports.length < 512) {
    const nameRva = d.readUInt32LE(o + 12)
    if (nameRva === 0) break
    const no = off(nameRva)
    if (no !== null) {
      const end = d.subarray(0, Math.min(no + 256, d.length)).indexOf(0, no)
      if (end > no) imports.push(d.toString('latin1', no, end))
    }
    o += 20
  }
  return { sections, entry, imports }
}

function readHead (p) {
  // the first 2 bytes; null when the file cannot be read
  let fd
  try {
    fd = openSync(p, 'r')
    const b = Buffer.alloc(2)
    const n = readSync(fd, b, 0, 2, 0)
    return b.subarray(0, n)
  } catch { return null } finally { if (fd !== undefined) closeSync(fd) }
}

export function checkFile (p, rel) {
  const found = []
  const bn = path.posix.basename(rel)
  const base = bn.toLowerCase()
  if (has(FILE_NAMES, base)) {
    const [kind, product] = FILE_NAMES[base]
    found.push({ file: rel, kind, product, evidence: 'file name ' + bn })
  }
  const head = readHead(p)
  if (head === null || head.length < 2 || head[0] !== 0x4d || head[1] !== 0x5a) return [found, false]
  let d
  try { d = readFileSync(p) } catch { return [found, false] }
  const pe = parsePe(d)
  if (pe === null) return [found, false]
  const seen = new Set()
  for (const [name] of pe.sections) {
    const lk = name.toLowerCase()
    if (has(SECTIONS, lk)) {
      const hit = SECTIONS[lk]
      const key = hit.join('\0') + '\0' + name
      if (!seen.has(key)) {
        seen.add(key)
        found.push({ file: rel, kind: hit[0], product: hit[1], evidence: 'section ' + name })
      }
    }
  }
  for (const dll of pe.imports) {
    const lk = dll.toLowerCase()
    if (has(IMPORTS, lk)) found.push({ file: rel, kind: IMPORTS[lk][0], product: IMPORTS[lk][1], evidence: 'imports ' + dll })
  }
  for (const [sig, kind, product] of STRINGS) {
    const at = d.indexOf(sig)
    if (at >= 0) found.push({ file: rel, kind, product, evidence: 'signature string at file offset 0x' + at.toString(16) })
  }
  const entry = pe.entry
  if (entry) {
    let sec = null
    for (const s of pe.sections) {
      if (s[1] <= entry && entry < s[1] + Math.max(s[2], s[4])) { sec = s; break }
    }
    if (sec === null) {
      found.push({ file: rel, kind: 'warning', product: 'unknown packer', evidence: `entry point 0x${entry.toString(16)} outside every section` })
    } else {
      const [name, , , rawptr, rawsize, chars] = sec
      if ((chars & SCN_WRITE) && (chars & SCN_EXEC)) {
        found.push({ file: rel, kind: 'warning', product: 'unknown packer', evidence: `entry point in writable code section ${name || '(unnamed)'}` })
      }
      if (rawsize >= 4096) {
        const e = entropy100(d.subarray(rawptr, rawptr + rawsize))
        if (e >= ENTROPY_LIMIT) {
          found.push({ file: rel, kind: 'warning', product: 'unknown packer',
            evidence: `entry point section ${name || '(unnamed)'} has entropy ${Math.floor(e / 100)}.${String(e % 100).padStart(2, '0')} bits/byte` })
        }
      }
    }
  }
  return [found, true]
}

function walk (top, files) {
  // os.walk(top) order: files of a folder (sorted), then its sub-folders (sorted); symlinks skipped
  const rec = (dir, relDir) => {
    let ents
    try { ents = readdirSync(dir, { withFileTypes: true }) } catch { return }
    const names = ents.map((e) => e.name).sort(cmp)
    const dirs = []
    for (const n of names) {
      const p = path.join(dir, n)
      let st
      try { st = lstatSync(p) } catch { continue }
      if (st.isDirectory()) dirs.push(n)
      else if (st.isFile()) files.push([p, relDir ? relDir + '/' + n : n])
    }
    for (const n of dirs) rec(path.join(dir, n), relDir ? relDir + '/' + n : n)
  }
  rec(top, '')
}

function isDir (p) { try { return statSync(p).isDirectory() } catch { return false } }
function isFile (p) { try { return statSync(p).isFile() } catch { return false } }

function main (argv) {
  const args = []; let out = null
  for (let i = 0; i < argv.length;) {
    const a = argv[i]
    if (a === '-h' || a === '--help') { process.stdout.write(DOC + '\n'); return 0 }
    if (a === '--json') {
      if (i + 1 >= argv.length) { process.stderr.write(USAGE + 'protection_check.py: error: --json needs a value\n'); return 2 }
      out = argv[i + 1]; i += 2; continue
    }
    if (a.startsWith('--')) { process.stderr.write(USAGE + `protection_check.py: error: unknown option ${a}\n`); return 2 }
    args.push(a); i++
  }
  if (!args.length) { process.stderr.write(USAGE + 'protection_check.py: error: nothing to scan\n'); return 2 }
  const files = []
  for (const a of args) {
    if (isDir(a)) walk(a, files)
    else if (isFile(a)) files.push([a, path.basename(a)])
    else { process.stderr.write(`protection_check.py: error: ${a}: no such file or folder\n`); return 2 }
  }
  let findings = []; let npe = 0
  for (const [p, rel] of files) {
    const [f, isPe] = checkFile(p, rel)
    findings = findings.concat(f)
    npe += isPe ? 1 : 0
  }
  const kinds = new Set(findings.map((f) => f.kind))
  const verdict = (kinds.has('drm') || kinds.has('packer')) ? 'protected' : (kinds.has('warning') ? 'review' : 'clean')
  const summary = { scanned_files: files.length, pe_files: npe, verdict, findings }
  for (const f of findings) {
    if (f.kind !== 'info') process.stderr.write(`${f.file}: ${f.kind} ${f.product} (${f.evidence})\n`)
  }
  const text = dumps(summary, { indent: 1 })
  if (out) writeFileSync(out, text + '\n')
  process.stdout.write(text + '\n')
  return verdict === 'clean' ? 0 : 1
}

process.exitCode = main(process.argv.slice(2))
