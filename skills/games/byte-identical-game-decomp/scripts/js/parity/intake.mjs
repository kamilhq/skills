#!/usr/bin/env node
// Parity test: intake.py vs js/intake.mjs.
//
//   node parity/intake.mjs [--installer setup_x.exe] [--game work/game] [--manifest manifests/game.json]
//                          [--python python3] [--keep]
//
// Cases (Python and JS run the same command; exit code, stdout, stderr and written files must match):
//   usage errors; extract (with --installer: same output path for both sides one after the other, timing values
//   masked; trees compared byte for byte with mtimes; --language/--collisions variants; a RAR '-1.bin' part next
//   to the installer; missing and non-Inno installers); manifest of --game, of both extracted trees, of a
//   synthetic tree (nested dirs, empty files, non-ASCII names, symlinks), of a non-directory; compare of
//   --game's manifest against --manifest (the committed reference) and against edited manifests (changed hash,
//   missing / extra / case-folded entries, --allow globs) and unreadable ones (missing file, directory, empty,
//   invalid JSON variants, non-UTF-8, BOM, no 'files' key, a list); verify-hashdb of --game, of a damaged copy
//   (changed, missing and extra files) and of a folder without hashdb.
// The JS manifests of the JS-extracted game tree and of --game must also equal the committed reference.
// Prints one JSON summary; exit 0 only when every case is identical.

import fs from 'node:fs'
import path from 'node:path'
import { Harness, argOpt, normTiming, ROOT, SK, JS } from './intake_harness.mjs'

const h = new Harness('intake')
const installer = argOpt(h.argv, '--installer')
const game = path.resolve(ROOT, argOpt(h.argv, '--game', 'work/game'))
const refManifest = path.resolve(ROOT, argOpt(h.argv, '--manifest', 'manifests/game.json'))
if (!fs.existsSync(game) || !fs.statSync(game).isDirectory()) {
  process.stdout.write(JSON.stringify({ script: 'intake', error: `${game} is not a folder: pass --game <the installed or ` +
    'extracted game folder> (and --installer setup_x.exe, --manifest <its committed manifest>); nothing game-specific is built into the test' }) + '\n')
  process.exit(2)
}
const PY = path.join(SK, 'intake.py'), JSI = path.join(JS, 'intake.mjs')
const tmp = h.tmp('run')

function both(name, args, { files = [], norm = (s) => s } = {}) {
  const p = h.py(PY, args)
  const saved = files.map(([a]) => (fs.existsSync(a) ? fs.readFileSync(a) : null))
  for (const [a] of files) fs.rmSync(a, { force: true })
  const j = h.js(JSI, args)
  // the commands write the same path: keep Python's copy next to JS's for the comparison
  const pairs = files.map(([a], k) => {
    const pyCopy = a + '.python'
    if (saved[k] !== null) fs.writeFileSync(pyCopy, saved[k]); else fs.rmSync(pyCopy, { force: true })
    return [pyCopy, a]
  })
  h.compareRuns(name, p, j, { norm, files: pairs })
  return [p, j]
}

// ---- usage
for (const args of [[], ['-h'], ['--help'], ['extract'], ['extract', 'a'], ['extract', 'a', 'b', '--collisions', 'x'],
  ['extract', 'a', 'b', '--language'], ['verify-hashdb'], ['verify-hashdb', 'a', 'b'], ['manifest', 'a'], ['compare', 'a'],
  ['bogus', 'x', 'y'], ['compare', 'a', 'b', '--allow'], ['compare', 'a', 'b', 'c'], ['-h', 'x']]) {
  both(`usage:${args.join(' ')}`, args)
}

// ---- extract
function extractCase(name, setup, extra = []) {
  const x = path.join(tmp, 'x')
  const run = (side) => {
    fs.rmSync(x, { recursive: true, force: true })
    const r = side === 'py' ? h.py(PY, ['extract', setup, x, ...extra]) : h.js(JSI, ['extract', setup, x, ...extra])
    const dst = path.join(tmp, 'ex_' + side)
    fs.rmSync(dst, { recursive: true, force: true })
    if (fs.existsSync(x)) fs.renameSync(x, dst)
    return [r, dst]
  }
  const [p, pd] = run('py')
  const [j, jd] = run('js')
  h.compareRuns(name, p, j, { norm: normTiming, trees: [[pd, jd, { mtime: true }]] })
  return [pd, jd]
}
both('extract:missing installer', ['extract', path.join(tmp, 'nope.exe'), path.join(tmp, 'o')])
const notInno = fs.readdirSync(game).sort().find((f) => /\.(dll|exe)$/i.test(f) && !/^unins/i.test(f))
if (notInno) extractCase('extract:not inno', path.join(game, notInno))
let pyTree = null, jsTree = null
if (installer) {
  ;[pyTree, jsTree] = extractCase('extract:default', installer)
  for (const d of [pyTree, jsTree]) fs.renameSync(d, d + '_kept')
  pyTree += '_kept'; jsTree += '_kept'
  extractCase('extract:--language en-US --collisions overwrite', installer, ['--language', 'en-US', '--collisions', 'overwrite'])
  extractCase('extract:--collisions=rename', installer, ['--collisions=rename'])
  // RAR part next to (a symlink to) the installer
  const rdir = path.join(tmp, 'rar')
  fs.mkdirSync(rdir)
  const link = path.join(rdir, 'setup_test.exe')
  fs.symlinkSync(path.resolve(installer), link)
  fs.writeFileSync(path.join(rdir, 'setup_test-1.bin'), Buffer.from('Rar!\x1a\x07\x00 fake part', 'latin1'))
  fs.writeFileSync(path.join(rdir, 'setup_test-2.bin'), Buffer.from('not rar'))
  extractCase('extract:rar part', link)
}

// ---- manifest
const mfile = (n) => path.join(tmp, n)
both('manifest:game', ['manifest', game, mfile('m_game.json')], { files: [[mfile('m_game.json')]] })
both('manifest:not a dir', ['manifest', path.join(tmp, 'nope'), mfile('m_x.json')], { files: [[mfile('m_x.json')]] })
const syn = path.join(tmp, 'syn')
fs.mkdirSync(path.join(syn, 'b', 'c'), { recursive: true })
fs.mkdirSync(path.join(syn, 'A'), { recursive: true })
fs.writeFileSync(path.join(syn, 'empty'), '')
fs.writeFileSync(path.join(syn, 'b', 'c', 'deep.txt'), 'deep')
fs.writeFileSync(path.join(syn, 'A', 'Zebra'), 'z')
fs.writeFileSync(path.join(syn, 'alpha'), 'lower case name')
fs.writeFileSync(path.join(syn, 'b', 'naïve-日本.txt'), 'unicode name')
fs.writeFileSync(path.join(syn, 'b', '\u{1F600}.bin'), Buffer.from([0, 1, 2]))
fs.symlinkSync('alpha', path.join(syn, 'link_to_alpha'))
fs.symlinkSync('b', path.join(syn, 'link_to_b'))
both('manifest:synthetic tree', ['manifest', syn, mfile('m_syn.json')], { files: [[mfile('m_syn.json')]] })
if (pyTree) {
  for (const [tag, d] of [['python_extracted', pyTree], ['js_extracted', jsTree]]) {
    const gameOnly = path.join(tmp, 'gameonly_' + tag)
    fs.cpSync(d, gameOnly, { recursive: true })
    for (const x of ['__redist', 'app', 'commonappdata']) fs.rmSync(path.join(gameOnly, x), { recursive: true, force: true })
    both(`manifest:${tag} game tree`, ['manifest', gameOnly, mfile(`m_${tag}.json`)], { files: [[mfile(`m_${tag}.json`)]] })
    if (fs.existsSync(refManifest)) {
      both(`compare:${tag} manifest vs reference`, ['compare', mfile(`m_${tag}.json`), refManifest])
      const r = h.js(JSI, ['compare', mfile(`m_${tag}.json`), refManifest])
      h.record(`reference:${tag} game tree PASSes against ${path.relative(ROOT, refManifest)}`, r.code === 0 && r.stdout.toString().endsWith('PASS\n'))
    }
    fs.rmSync(gameOnly, { recursive: true, force: true })
  }
}

// ---- compare
const base = JSON.parse(fs.readFileSync(mfile('m_game.json'), 'utf8'))
const files = Object.entries(base.files)
const write = (n, obj) => { fs.writeFileSync(mfile(n), typeof obj === 'string' || Buffer.isBuffer(obj) ? obj : JSON.stringify(obj, null, 1)); return mfile(n) }
if (fs.existsSync(refManifest)) {
  both('compare:game vs reference', ['compare', mfile('m_game.json'), refManifest])
  const r = h.js(JSI, ['compare', mfile('m_game.json'), refManifest])
  h.record(`reference:${path.relative(ROOT, game)} PASSes against ${path.relative(ROOT, refManifest)}`, r.code === 0)
}
const edited = { root_name: 'x', files: {} }
files.forEach(([k, v], i) => {
  if (i === 3) return                                                  // missing in B
  if (i === 5) { edited.files[k] = { ...v, sha256: '0'.repeat(64) }; return }   // changed
  if (i === 7) { edited.files[k.toUpperCase()] = v; return }         // case-folded match
  edited.files[k] = v
})
edited.files['extra/unins000.exe'] = { size: 1, sha256: 'ab' }
edited.files['Saves/slot1.sav'] = { size: 1, sha256: 'cd' }
const ed = write('edited.json', edited)
both('compare:edited', ['compare', mfile('m_game.json'), ed])
both('compare:edited reversed', ['compare', ed, mfile('m_game.json')])
both('compare:edited --allow', ['compare', mfile('m_game.json'), ed, '--allow', 'unins000.*', '--allow=saves/*', '--allow', files[3][0].toUpperCase()])
both('compare:allow classes', ['compare', mfile('m_game.json'), ed, '--allow', '[!x]*/slot?.sav', '--allow', 'e[a-z]tra/*'])
both('compare:same file', ['compare', ed, ed])
both('compare:missing file', ['compare', mfile('nope.json'), ed])
both('compare:directory', ['compare', tmp, ed])
for (const [n, content] of [['empty', ''], ['open_brace', '{'], ['no_value', '{"files": }'], ['list', '[1, 2]'],
  ['no_files', '{"root_name": "x"}'], ['trailing', '{"files": {}} x'], ['bad_key', "{'files': {}}"], ['comma', '{"files": {},}'],
  ['crlf_error', '{\r\n "files": {\r\n  "a": 1,\r\n }\r\n}'], ['bom', '﻿{"files": {}}'], ['ctrl', '{"files": {"a\tb": {}}}'],
  ['escape', '{"files": {"a\\qb": {}}}'], ['unterminated', '{"files": {"abc'], ['nan_ok', '{"files": {"a": {"sha256": NaN}}}'],
  ['dup_keys', '{"files": {"a": {"sha256": "1"}, "A": {"sha256": "2"}}, "files": {"b": {"sha256": "3"}}}']]) {
  both(`compare:unreadable ${n}`, ['compare', write(`bad_${n}.json`, content), ed])
}
both('compare:non-utf8', ['compare', write('bad_latin1.json', Buffer.from('{"files": {"\xe9": {}}}', 'latin1')), ed])
both('compare:non-utf8 truncated', ['compare', write('bad_trunc.json', Buffer.from([0x7b, 0xe2, 0x82])), ed])

// ---- verify-hashdb
both('verify-hashdb:game', ['verify-hashdb', game])
both('verify-hashdb:no hashdb', ['verify-hashdb', syn])
both('verify-hashdb:missing dir', ['verify-hashdb', path.join(tmp, 'nope')])
const dmg = path.join(tmp, 'damaged_game')
fs.cpSync(game, dmg, { recursive: true })
const listed = files.map(([k]) => k).filter((k) => !k.startsWith('goggame-'))
fs.appendFileSync(path.join(dmg, listed[0]), 'x')
fs.rmSync(path.join(dmg, listed[1]))
fs.writeFileSync(path.join(dmg, 'unlisted_extra.txt'), 'extra')
fs.mkdirSync(path.join(dmg, 'saves'))
fs.writeFileSync(path.join(dmg, 'saves', 'Slot.dat'), 'save')
both('verify-hashdb:damaged copy', ['verify-hashdb', dmg])
fs.rmSync(dmg, { recursive: true, force: true })

h.finish()
