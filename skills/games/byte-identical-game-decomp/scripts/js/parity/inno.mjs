#!/usr/bin/env node
// Parity test: inno.py vs js/inno.mjs.
//
//   node parity/inno.mjs --installer setup_x.exe [--installer ...] [--quick-installer other.exe ...]
//                        [--game work/game] [--python python3] [--keep]
//
// For every --installer: info / info --json / list variants (--json, --include-temp, --exclude-temp,
// --language) / verify; extract with several flag sets (default, --include-temp --no-mtime --collisions rename,
// --language, a language matching nothing, into a folder holding a symlink) - Python and JS extract to the
// same path one after the other, so stdout (timing values masked) and the trees (file bytes, modes, mtimes in
// ns, directories, leftovers) must be identical; the default extraction minus the installer-only folders must
// equal --game (work/game) byte for byte. For the first --installer also: truncated copies and copies with one
// corrupted byte (header block, LZMA2 chunk, stored chunk with GOG zlib parts) through verify and extract
// (error text, exit code, and which output files remain must match).
// --quick-installer: info / list / verify only.
// With --no-mtime the files keep the time they were written, so only that case skips the mtime comparison.
// Command-line handling: help texts, argparse errors, abbreviations, '--', missing / non-Inno / tiny inputs.
// Prints one JSON summary; exit 0 only when every case is identical.

import fs from 'node:fs'
import path from 'node:path'
import { Harness, argAll, argOpt, normTiming, snapshot, diffSnapshots, ROOT, SK, JS } from './intake_harness.mjs'

const h = new Harness('inno')
const installers = argAll(h.argv, '--installer')
const quick = argAll(h.argv, '--quick-installer')
const game = path.resolve(ROOT, argOpt(h.argv, '--game', 'work/game'))
const PY = path.join(SK, 'inno.py'), JSI = path.join(JS, 'inno.mjs')
const tmp = h.tmp('run')

function both(name, args, { cwd = ROOT, norm = normTiming } = {}) {
  const p = h.py(PY, args, { cwd }), j = h.js(JSI, args, { cwd })
  h.compareRuns(name, p, j, { norm })
  return [p, j]
}

// extraction into the same path for both sides; trees compared afterwards
function extractCase(name, setup, extraArgs = [], { prepare = null, mtime = !extraArgs.includes('--no-mtime') } = {}) {
  const x = path.join(tmp, 'x')
  const run = (side) => {
    fs.rmSync(x, { recursive: true, force: true })
    if (prepare) prepare(x)
    const r = side === 'py' ? h.py(PY, ['extract', setup, x, ...extraArgs]) : h.js(JSI, ['extract', setup, x, ...extraArgs])
    const dst = path.join(tmp, side)
    fs.rmSync(dst, { recursive: true, force: true })
    if (fs.existsSync(x)) fs.renameSync(x, dst)
    return [r, dst]
  }
  const [p, pd] = run('py')
  const [j, jd] = run('js')
  h.compareRuns(name, p, j, { norm: (s) => normTiming(s).split(path.join(tmp, 'x')).join('<OUT>'), trees: [[pd, jd, { mtime }]] })
  return [pd, jd]
}

function quickCases(tag, setup) {
  for (const args of [['info'], ['info', '--json'], ['list'], ['list', '--json'], ['list', '--include-temp'],
    ['list', '--include-temp', '--json'], ['list', '--exclude-temp'], ['list', '--language', 'en-US', '--json'],
    ['list', '--language', 'xx-XX'], ['verify']]) {
    both(`${tag}:${args.join(' ')}`, [args[0], setup, ...args.slice(1)])
  }
}

// ---- command-line handling (no installer needed)
const tiny = path.join(tmp, 'tiny.bin'); fs.writeFileSync(tiny, Buffer.from('MZ tiny'))
const notInno = path.join(game, 'SDL2.dll')
const cli = [
  [], ['-h'], ['--help'], ['--he'], ['info', '-h'], ['list', '-h'], ['extract', '-h'], ['verify', '-h'], ['verify', 'x', '--he'],
  ['foo'], ['info'], ['extract', 'x'], ['extract', 'a', 'b', '--collisions', 'x'], ['list', 'a', '--bogus'], ['--bogus'],
  ['list', 'a', '--json=1'], ['list', 'a', '--l'], ['list', 'a', '--lang=en', '/nonexist'], ['info', 'a', 'b'],
  ['list', 'a', '--'], ['list', '--', '-a'], ['list', 'a', '--language'], ['info', '-x', 'a'], ['-x', 'info', 'a'],
  ['list', '--include-temp'], ['-hx'], ['info', '-hx', 'a'], ['--', 'info', 'a'], ['list', 'a', '--language', '-1'],
  ['extract', 'a', 'b', '--collisions=rename', '--collisions', 'error', '--no-m', '--qu'],
  ['list', 'a', '--', 'b'], ['extract', '--', 'a', 'b', 'c'], ['list', 'a', 'b', '--'], ['list', '--', '--'],
  ['info', '--', '--', 'a'], ['list', 'a', '--json', '--', 'b'], ['list', 'a', '-hh'], ['list', 'a', '--language', '--', 'x'],
  ['list', 'a', '--language', 'x', '--'], ['extract', 'a', 'b', '--coll=bad'], ['--json'],
  ['info', '/nonexistent/setup.exe'], ['info', tmp], ['info', tiny], ['verify', tiny], ['list', tiny, '--json'],
]
if (fs.existsSync(notInno)) cli.push(['info', notInno], ['extract', notInno, path.join(tmp, 'none')])
cli.forEach((args, i) => both(`cli#${i}:${args.join(' ').split(tmp).join('<TMP>')}`, args))

// ---- installers
quick.forEach((setup, i) => quickCases(`quick${i}`, setup))
installers.forEach((setup, i) => {
  const tag = `installer${i}`
  quickCases(tag, setup)
  const [, jd] = extractCase(`${tag}:extract`, setup)
  // the game tree (installer-only folders left out) must equal --game
  if (fs.existsSync(game) && i === 0) {
    const gameOnly = path.join(tmp, 'gameonly')
    fs.rmSync(gameOnly, { recursive: true, force: true })
    fs.cpSync(jd, gameOnly, { recursive: true, preserveTimestamps: true })
    for (const d of ['__redist', 'app', 'commonappdata', 'tmp']) fs.rmSync(path.join(gameOnly, d), { recursive: true, force: true })
    const d = diffSnapshots(snapshot(game), snapshot(gameOnly), { mtime: false })
    h.record(`${tag}:js_game_tree_equals_${path.relative(ROOT, game)}`, d.length === 0, d.length ? d : null)
    fs.rmSync(gameOnly, { recursive: true, force: true })
  }
  extractCase(`${tag}:extract --include-temp --no-mtime --collisions rename --quiet`, setup,
    ['--include-temp', '--no-mtime', '--collisions', 'rename', '--quiet'])
  extractCase(`${tag}:extract --language en-US --collisions error`, setup, ['--language', 'en-US', '--collisions', 'error'])
  extractCase(`${tag}:extract --language xx-XX`, setup, ['--language', 'xx-XX'])
  extractCase(`${tag}:extract --include-temp --collisions error`, setup, ['--include-temp', '--collisions', 'error'])
  extractCase(`${tag}:extract through symlink`, setup, [], {
    prepare: (x) => {
      fs.mkdirSync(x, { recursive: true })
      fs.mkdirSync(path.join(tmp, 'elsewhere'), { recursive: true })
      fs.symlinkSync(path.join(tmp, 'elsewhere'), path.join(x, 'app'))
    },
  })
  extractCase(`${tag}:extract onto existing files`, setup, [], {
    prepare: (x) => {
      fs.mkdirSync(path.join(x, 'lang'), { recursive: true })
      fs.writeFileSync(path.join(x, 'readme.txt'), 'old')
      fs.writeFileSync(path.join(x, 'keep.me'), 'untouched')
      fs.utimesSync(path.join(x, 'keep.me'), 1000000000, 1000000000)      // same mtime on both sides
    },
  })
  if (i !== 0) return
  // ---- damaged copies of the first installer
  const layout = h.run(h.python, ['-I', '-c', String.raw`
import json, sys
sys.path.insert(0, sys.argv[1])
import inno
s = inno.open_setup(sys.argv[2])
ch = {}
for d in s.data:
    k = (d["first_slice"], d["chunk_offset"])
    ch.setdefault(k, {"offset": s.offsets.data_offset + d["chunk_offset"], "size": d["chunk_size"], "compression": d["compression"], "entries": 0})
    ch[k]["entries"] += 1
print(json.dumps({"header_offset": s.offsets.header_offset, "data_offset": s.offsets.data_offset, "chunks": sorted(ch.values(), key=lambda c: c["offset"])}))
`, SK, setup])
  if (layout.code !== 0) { h.record(`${tag}:layout`, false, layout.stderr.toString()); return }
  const L = JSON.parse(layout.stdout.toString())
  const size = fs.statSync(setup).size
  const lz = L.chunks.filter((c) => c.compression === 'lzma2').sort((a, b) => b.size - a.size)[0]
  const st = L.chunks.filter((c) => c.compression === 'stored').sort((a, b) => b.size - a.size)
  const damaged = [
    ['truncated_header', { cut: L.header_offset + 50 }],
    ['truncated_data_start', { cut: L.data_offset + 1000 }],
    ['truncated_half', { cut: Math.floor(size / 2) }],
    ['truncated_end', { cut: size - 10 }],
    ['flip_header_block', { flip: L.header_offset + 80 }],
    ['flip_loader_table', null],
  ]
  if (lz) damaged.push(['flip_lzma2_chunk', { flip: lz.offset + 4 + Math.floor(lz.size / 2) }], ['flip_lzma2_chunk_start', { flip: lz.offset + 4 + 7 }])
  if (st[0]) damaged.push(['flip_stored_chunk', { flip: st[0].offset + 4 + Math.floor(st[0].size / 3) }])
  if (st[1]) damaged.push(['flip_stored_chunk2', { flip: st[1].offset + 4 + 100 }], ['flip_chunk_magic', { flip: st[1].offset + 1 }])
  const copy = path.join(tmp, 'damaged_setup.exe')
  for (const [dname, how] of damaged) {
    if (!how) continue
    const buf = fs.readFileSync(setup)
    let b = buf
    if (how.cut !== undefined) b = buf.subarray(0, how.cut)
    if (how.flip !== undefined) b[how.flip] ^= 0x5A
    fs.writeFileSync(copy, b)
    both(`${tag}:damaged/${dname}:verify`, ['verify', copy], { norm: (s) => normTiming(s).split(copy).join('<SETUP>') })
    extractCase(`${tag}:damaged/${dname}:extract`, copy)
    fs.rmSync(copy, { force: true })
  }
})

h.finish({ installers: installers.length, quick_installers: quick.length })
