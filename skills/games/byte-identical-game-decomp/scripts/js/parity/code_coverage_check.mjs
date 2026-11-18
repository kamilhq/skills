#!/usr/bin/env node
// Parity test: code_coverage_check.py vs js/code_coverage_check.mjs (tools/code_coverage_check.py is the same file).
//
//   node parity/code_coverage_check.mjs [--root PROJECT] [--python python3] [--keep] [--also OTHER_PROJECT]
//
// The script writes <decompiled_dir>/coverage_check.json, so every case runs on a temp copy (symlinks to
// index.json, coverage_gaps.txt, functions.tsv, instructions.tsv). Cases per binary of PROJECT/decomp.json (the
// file under paths.game with its decompiled dir; the test stops with exit 2 when PROJECT has no decomp.json):
// the real recovery; a damaged recovery (every 7th function
// dropped from index.json and every 5th body from functions.tsv: FAIL path, exit 1, unexplained pointers,
// calls into the middle of functions); extra synthetic gaps strided through .text (filler / table / index /
// UNEXPLAINED walks, gaps past the file data). Plus argparse paths (-h, missing and extra arguments).
// --also OTHER_PROJECT: the same three cases for every binary in OTHER_PROJECT/decomp.json (binaries[]: file
// under work/game, decompiled dir) whose recovery exists - e.g. a VC6 game with merged sections, no relocations,
// import thunk tables and unreferenced regions, which exercise rules a VS2010 game does not reach.
// Python's summary.gap_nonpad_bytes_by_kind is built by iterating a set of strings, so its key order changes
// from run to run (hash randomization, which -I does not let PYTHONHASHSEED fix). That one object is compared
// with its keys sorted, on both sides; every other byte of stdout and coverage_check.json is compared as is.
// `raw_identical` counts the cases that were identical even without that normalisation.
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { basename, join } from 'node:path'
import { compareFile, Parity, parseOpts, projectBinaries } from '../lib/peparity.mjs'
import { dumps, parse, PyDict } from '../lib/pyjson.mjs'
import { cmp } from '../lib/pytools.mjs'
import { pe_parse } from '../code_coverage_check.mjs'

const opts = parseOpts(process.argv.slice(2), { root: undefined, python: undefined, keep: false, also: undefined })
const P = new Parity('code_coverage_check', opts)
const FILES = ['index.json', 'coverage_gaps.txt', 'functions.tsv', 'instructions.tsv']
let rawIdentical = 0, n = 0

function sortKey(summary) {
  const g = summary.get('gap_nonpad_bytes_by_kind')
  if (g instanceof Map) summary.set('gap_nonpad_bytes_by_kind', new PyDict([...g].sort((x, y) => cmp(x[0], y[0]))))
}
function canon(what, buf) {
  const s = buf.toString('utf8')
  try {
    if (what === 'stdout') {
      const cut = s.lastIndexOf('\n', s.length - 2)
      if (cut < 0) return buf
      const j = parse(s.slice(0, cut)); sortKey(j)
      return dumps(j, { indent: 1 }) + s.slice(cut)
    }
    const j = parse(s); sortKey(j.get('summary'))
    return dumps(j, { indent: 1 })
  } catch { return buf }
}

function prepare(src, mutate = {}) {
  const k = n++
  const dirs = [P.tmpPath(`py_${k}`), P.tmpPath(`js_${k}`)]
  for (const d of dirs) {
    mkdirSync(d)
    for (const f of FILES) {
      if (mutate[f] !== undefined) writeFileSync(join(d, f), mutate[f])
      else symlinkSync(join(src, f), join(d, f))
    }
  }
  return dirs
}

function both(name, bin, dirs, extra = []) {
  const a = P.run('py', [bin, dirs[0], ...extra]), b = P.run('js', [bin, dirs[1], ...extra])
  // informational: identical even without normalising the set-ordered object?
  if (a.rc === b.rc && a.stdout.equals(b.stdout) &&
      !compareFile(join(dirs[0], 'coverage_check.json'), join(dirs[1], 'coverage_check.json')).length) rawIdentical++
  P.compare(name, a, b, { stderr: true, canon,
                          files: [[join(dirs[0], 'coverage_check.json'), join(dirs[1], 'coverage_check.json')]] })
}

const bins = projectBinaries(P.root, { script: 'code_coverage_check' })
const sets = bins.map((b) => [b.file, b.abs.exe, b.abs.decompiled])
if (opts.also) {
  const cfg = parse(readFileSync(join(opts.also, 'decomp.json'), 'utf8'))
  for (const b of cfg.get('binaries')) sets.push([b.get('file'), join(opts.also, 'work', 'game', b.get('file')), join(opts.also, b.get('decompiled'))])
}
for (const [bin, exe, src] of sets) {
  const dd = basename(src)
  if (!existsSync(exe) || !FILES.every((f) => existsSync(join(src, f)))) { P.notes.push(`${bin}/${dd}: inputs missing, skipped`); continue }
  both(`${bin} ${dd}`, exe, prepare(src))
  // damaged recovery
  const idx = parse(readFileSync(join(src, 'index.json'), 'utf8'))
  idx.set('functions', idx.get('functions').filter((_, i) => i % 7 !== 3))
  const ftsv = readFileSync(join(src, 'functions.tsv'), 'utf8').split('\n').filter((_, i) => i === 0 || i % 5 !== 2).join('\n')
  both(`${bin} damaged recovery`, exe, prepare(src, { 'index.json': dumps(idx), 'functions.tsv': ftsv }))
  // synthetic gaps
  const d = readFileSync(exe)
  const [base, , , secs] = pe_parse(d)
  let gaps = readFileSync(join(src, 'coverage_gaps.txt'), 'utf8')
  for (const s of secs.filter((x) => x.exec)) {
    for (let o = 0; o < s.vsz; o += Math.floor(s.vsz / 300)) gaps += `0x${(base + s.va + o).toString(16)} len=${1 + (o % 37)}\n`
    gaps += `0x${(base + s.va + s.rsz - 8).toString(16)} len=64\n`
  }
  gaps += 'not a gap line\n'
  both(`${bin} synthetic gaps`, exe, prepare(src, { 'coverage_gaps.txt': gaps }))
}
const exe = bins[0].abs.exe
for (const [name, args] of [['-h', ['-h']], ['no arguments', []], ['one argument', [exe]], ['three arguments', [exe, 'a', 'b']],
  ['unknown option', [exe, P.tmpPath('x'), '--zz']]]) {
  P.compare(`argparse: ${name}`, P.run('py', args), P.run('js', args), { stderr: true })
}
P.finish({ raw_identical: rawIdentical })
