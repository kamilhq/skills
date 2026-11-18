#!/usr/bin/env node
// Parity test: relink.py vs js/relink.mjs (phase 6 relink with link.exe: prepare, link, finish, check).
//
//   node parity/relink.mjs [--root PROJECT] [--python python3] [--cache ASM_CACHE] [--libdir SDK_LIB]
//                          [--symbols-strict F] [--symbols-all F] [--module VVVVVV] [--skip-link] [--keep] [--tmp DIR]
//
// PROJECT (default: the current directory) must hold work/game/<MODULE>.exe, reassembled/<MODULE>, decompiled_exe
// (index.json, instructions.tsv) and, unless --symbols-* are given, what `hybrid_link.py map` needs (the maps are
// made once by Python: strict, and --all). --cache: a reassemble.py assembler cache (copied for every run); made
// by one Python build when absent (slow). --libdir: the Windows SDK's Lib in the Wine prefix (default
// $MSVC_PREFIX or ~/.wine-vs2010, drive_c/Program Files (x86)/Microsoft SDKs/Windows/v7.1/Lib).
// Each side runs prepare/link/finish/check in the SAME out_dir path (renamed afterwards), one Wine link at a
// time, with its own TMPDIR. link.exe and lib.exe stamp the time: relinked.exe is compared with TimeDateStamp and
// CheckSum masked, relinked.map with its "Timestamp is" line masked, .lib/.exp with their member/object
// timestamps masked; finish must give the original's SHA-256 on both sides.
// Cases:
//   prepare strict (identical map, --libdir)   every file of out_dir, stdout, stderr
//   link strict                                 stdout (lib/link/mt output, compare JSON), every file (masked)
//   finish strict, RELINK_FACTS=rich,timestamp,checksum and the default facts: stdout, facts.json, final.exe;
//                                               final.exe SHA-256 = the original (both sides)
//   check strict                                JSON, exit code
//   prepare/link/finish without --libdir         every import library generated from .def (name_imports)
//   prepare --free (--all map), link, check      check: exit 0, 0 mismatches expected
//   errors                                       the --all map without --free; usage (docstring) on bad argv
// Prints one JSON summary; exit 0 only when every case is identical.
import { cpSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { compareDirs, Parity, parseOpts, SK } from '../lib/peparity.mjs'

const opts = parseOpts(process.argv.slice(2), {
  root: undefined, python: undefined, cache: undefined, libdir: undefined, 'symbols-strict': undefined,
  'symbols-all': undefined, module: 'VVVVVV', 'skip-link': false, keep: false, tmp: undefined,
})
const P = new Parity('relink', opts)
const t = (...p) => P.tmpPath(...p)
const M = opts.module
const EXE = `work/game/${M}.exe`
const LIB = opts.libdir ?? join(process.env.MSVC_PREFIX || join(homedir(), '.wine-vs2010'), 'drive_c', 'Program Files (x86)',
                                'Microsoft SDKs', 'Windows', 'v7.1', 'Lib')
const sha = (f) => createHash('sha256').update(readFileSync(f)).digest('hex')
for (const p of [EXE, `reassembled/${M}`, 'decompiled_exe/index.json', 'decompiled_exe/instructions.tsv']) {
  if (!existsSync(P.path(p))) {
    process.stdout.write(JSON.stringify({ script: 'relink', error: `missing ${P.path(p)} (use --root)` }) + '\n')
    process.exit(2)
  }
}
for (const s of ['py', 'js']) mkdirSync(t(`tmp_${s}`))
const envOf = (s, extra = {}) => ({ TMPDIR: t(`tmp_${s}`), ...extra })

// inputs: assembler cache, the two maps
let cache = opts.cache
if (!cache) {
  cache = t('asm_cache.json')
  P.run('py', ['build', `reassembled/${M}`, t('cache_build.bin'), '--cache', cache], { pyScript: `${SK}/reassemble.py` })
}
let nc = 0
const cacheCopy = () => { const f = t(`cache_${nc++}.json`); cpSync(cache, f); return f }
const MAP = ['map', '--pe', EXE, '--src', `src_matched/${M}`, '--obj', 'src_matched/build', '--module', M,
             '--functions', 'decompiled_named_exe/index.json', '--instructions', 'decompiled_exe/instructions.tsv']
const maps = { strict: opts['symbols-strict'], all: opts['symbols-all'] }
for (const [k, extra] of [['strict', []], ['all', ['--all']]]) {
  if (maps[k]) continue
  maps[k] = t(`symbols_${k}.json`)
  const r = P.run('py', [...MAP, ...extra, '--out', maps[k]], { pyScript: `${SK}/hybrid_link.py` })
  if (r.rc !== 0) P.notes.push(`hybrid_link.py map ${k}: exit ${r.rc}`)
}

// timestamps of the toolchain's outputs
function maskPE(b) {
  if (b.length < 0x40 || b[0] !== 0x4d || b[1] !== 0x5a) return b
  const pe = b.readUInt32LE(0x3c)
  if (pe + 92 > b.length) return b
  b.fill(0, pe + 8, pe + 12)
  b.fill(0, pe + 88, pe + 92)
  return b
}
function maskCoff(b, m) {           // an i386 COFF object at m: header TimeDateStamp, .edata TimeDateStamp
  if (m + 20 > b.length || b.readUInt16LE(m) !== 0x14c) return
  b.fill(0, m + 4, m + 8)
  const nsec = b.readUInt16LE(m + 2), opt = b.readUInt16LE(m + 16)
  for (let i = 0; i < nsec; i++) {
    const h = m + 20 + opt + 40 * i
    if (h + 40 > b.length) break
    if (b.subarray(h, h + 8).toString('latin1').replace(/\0+$/, '') === '.edata') {
      const raw = m + b.readUInt32LE(h + 20)
      if (raw + 8 <= b.length) b.fill(0, raw + 4, raw + 8)
    }
  }
}
function maskLib(b) {               // archive: member header dates, short import / COFF member timestamps
  if (!b.subarray(0, 8).equals(Buffer.from('!<arch>\n', 'latin1'))) return b
  let o = 8
  while (o + 60 <= b.length) {
    const size = parseInt(b.subarray(o + 48, o + 58).toString('latin1').trim(), 10)
    if (!(size >= 0)) break
    b.fill(0x20, o + 16, o + 28)
    const m = o + 60
    if (m + 12 <= b.length && b.readUInt16LE(m) === 0 && b.readUInt16LE(m + 2) === 0xFFFF) b.fill(0, m + 8, m + 12)
    else maskCoff(b, m)
    o = m + size + (size & 1)
  }
  return b
}
function canon(f, buf) {
  const b = Buffer.from(buf)
  if (/relinked\.exe$/.test(f)) return maskPE(b)
  if (/relinked\.map$/.test(f)) return Buffer.from(b.toString('latin1').replace(/Timestamp is [0-9a-f]{8} \([^)]*\)/, 'Timestamp is <masked>'), 'latin1')
  if (/\.lib$/.test(f)) return maskLib(b)
  if (/\.exp$/.test(f)) { maskCoff(b, 0); return b }
  return b
}

// one side of one build: prepare (+ link, finish, check) in the shared out_dir path, then renamed
const W = t('out')
function side(s, name, prepArgs, { link = true, finish = false, map }) {
  rmSync(W, { recursive: true, force: true })
  const r = {}
  r.prepare = P.run(s, ['prepare', `reassembled/${M}`, map, 'decompiled_exe', W, ...prepArgs, '--cache', cacheCopy()], { env: envOf(s) })
  cpSync(W, t(`${name}_prep_${s}`), { recursive: true })
  if (link && !opts['skip-link']) {
    r.link = P.run(s, ['link', W, EXE], { env: envOf(s) })
    if (finish) {
      r.finish_subset = P.run(s, ['finish', W, EXE], { env: envOf(s, { RELINK_FACTS: 'rich,timestamp,checksum' }) })
      mkdirSync(t(`${name}_finsub_${s}`))
      for (const f of ['facts.json', 'final.exe']) if (existsSync(join(W, f))) cpSync(join(W, f), t(`${name}_finsub_${s}`, f))
      r.finish = P.run(s, ['finish', W, EXE], { env: envOf(s) })
    }
    r.check = P.run(s, ['check', W, EXE, map, 'decompiled_exe/instructions.tsv', 'decompiled_exe/index.json'], { env: envOf(s) })
  }
  renameSync(W, t(`${name}_${s}`))
  return r
}
function build(name, prepArgs, o) {
  const a = side('py', name, prepArgs, o), b = side('js', name, prepArgs, o)
  const tb = (r) => r.stderr.toString().startsWith('Traceback')
  P.compare(`${name}: prepare ${prepArgs.join(' ')}`, a.prepare, b.prepare, { stderr: !tb(a.prepare), dirs: [[t(`${name}_prep_py`), t(`${name}_prep_js`)]] })
  if (!a.link) return
  P.compare(`${name}: link (+ every file of out_dir, timestamps masked)`, a.link, b.link,
    { stderr: true, dirs: [[t(`${name}_py`), t(`${name}_js`)]], canon })
  if (o.finish) {
    P.compare(`${name}: finish RELINK_FACTS=rich,timestamp,checksum`, a.finish_subset, b.finish_subset,
      { stderr: true, dirs: [[t(`${name}_finsub_py`), t(`${name}_finsub_js`)]] })
    P.compare(`${name}: finish`, a.finish, b.finish, { stderr: true })
    for (const s of o.sha ? ['py', 'js'] : []) {
      const f = t(`${name}_${s}`, 'final.exe')
      P.record(`${name}: finish (${s}) final.exe SHA-256 equals ${EXE}`, existsSync(f) && sha(f) === sha(P.path(EXE)) ? [] : ['differs'])
    }
    P.notes.push(`${name}: link exit ${a.link.rc}, finish exit ${a.finish.rc}, final.exe ${sha(t(`${name}_py`, 'final.exe')) === sha(P.path(EXE)) ? 'identical to' : 'differs from'} ${EXE}`)
  }
  P.compare(`${name}: check`, a.check, b.check, { stderr: true })
  P.notes.push(`${name}: check exit ${a.check.rc}: ${a.check.stdout.toString().replace(/\s+/g, ' ').trim()}`)
  // the toolchain's outputs, unmasked: what differs is only the time stamps
  const raw = compareDirs(t(`${name}_py`), t(`${name}_js`))
  if (raw.length) P.notes.push(`${name}: unmasked differences (toolchain time stamps): ${raw.map((d) => d.replace(/^.*\//, '').replace(/:.*/, '')).join(', ')}`)
}

build('strict', ['--libdir', LIB], { finish: true, sha: true, map: maps.strict })
build('nolibdir', [], { finish: true, map: maps.strict })
build('free', ['--libdir', LIB, '--free'], { map: maps.all })

// errors
function both(name, args) {
  const a = P.run('py', args, { env: envOf('py') }), b = P.run('js', args, { env: envOf('js') })
  P.compare(name, a, b, { stderr: !a.stderr.toString().startsWith('Traceback') })
}
both('errors: --all map without --free', ['prepare', `reassembled/${M}`, maps.all, 'decompiled_exe', t('refused'), '--cache', cacheCopy()])
for (const args of [[], ['prepare'], ['prepare', 'a', 'b', 'c'], ['check', 'a'], ['link', 'a'], ['finish', 'a', 'b', 'c'],
                    ['bogus', 'a', 'b'], ['prepare', 'a', 'b', 'c', 'd', '--cache']]) {
  both(`errors: ${JSON.stringify(args)}`, args)
}
P.finish({ libdir_exists: existsSync(LIB) })
