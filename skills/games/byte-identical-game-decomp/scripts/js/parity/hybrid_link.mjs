#!/usr/bin/env node
// Parity test: hybrid_link.py vs js/hybrid_link.mjs (phase 6 hybrid build: linker map, link, verify).
//
//   node parity/hybrid_link.mjs [--root PROJECT] [--python python3] [--cache ASM_CACHE] [--module VVVVVV]
//                               [--keep] [--tmp DIR]
//
// PROJECT (default: the current directory) must hold work/game/<MODULE>.exe, reassembled/<MODULE>,
// src_matched/<MODULE> (annotated sources), src_matched/build (compiled objects), decompiled_named_exe/index.json
// and decompiled_exe/instructions.tsv. --cache is a reassemble.py assembler cache for reassembled/<MODULE>
// (copied for every run, never written); without it one Python `reassemble.py build --cache` makes it (slow).
// Both sides run from PROJECT with the same arguments and their own TMPDIR inside the test's temp dir.
// Cases:
//   map              identical functions only: symbols.json, stdout summary, stderr (CONFLICT lines), exit code
//   map --all        edited functions too (name index, import thunks, content lookup, call/static pairing)
//   map --all        without --functions and --instructions (no name index, no call pairing: UNRESOLVED lines)
//   link             the hybrid binary from the Python-written map: binary + stdout; SHA-256 = the original
//   link             with the --all map: refused (exit 1, message)
//   verify           IDENTICAL; and against another file (DIFFERENT; the kept temp path is normalised)
//   errors           argparse usage/help texts and errors
// Prints one JSON summary; exit 0 only when every case is identical.
import { copyFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { Parity, parseOpts, SK } from '../lib/peparity.mjs'

const opts = parseOpts(process.argv.slice(2), { root: undefined, python: undefined, cache: undefined, module: 'VVVVVV',
                                                keep: false, tmp: undefined })
const P = new Parity('hybrid_link', opts)
const t = (...p) => P.tmpPath(...p)
const M = opts.module
const EXE = `work/game/${M}.exe`
const sha = (f) => createHash('sha256').update(readFileSync(f)).digest('hex')
for (const p of [EXE, `reassembled/${M}`, `src_matched/${M}`, 'src_matched/build', 'decompiled_named_exe/index.json',
                 'decompiled_exe/instructions.tsv']) {
  if (!existsSync(P.path(p))) {
    process.stdout.write(JSON.stringify({ script: 'hybrid_link', error: `missing ${P.path(p)} (use --root)` }) + '\n')
    process.exit(2)
  }
}
for (const s of ['py', 'js']) mkdirSync(t(`tmp_${s}`))
const env = { py: { TMPDIR: t('tmp_py') }, js: { TMPDIR: t('tmp_js') } }

let cache = opts.cache
if (!cache) {
  cache = t('asm_cache.json')
  P.run('py', ['build', `reassembled/${M}`, t('cache_build.bin'), '--cache', cache], { pyScript: `${SK}/reassemble.py` })
}
let nc = 0
const cacheCopy = () => { const f = t(`cache_${nc++}.json`); copyFileSync(cache, f); return f }

function norm(r) {
  for (const k of ['stdout', 'stderr']) r[k] = Buffer.from(r[k].toString().replace(/rebuilt kept at .*/g, 'rebuilt kept at <tmp>'))
  return r
}
function both(name, pyArgs, jsArgs, { files = [], stderr = true } = {}) {
  const a = norm(P.run('py', pyArgs, { env: env.py })), b = norm(P.run('js', jsArgs, { env: env.js }))
  const tb = a.stderr.toString().startsWith('Traceback')
  P.compare(name, a, b, { stderr: stderr && !tb, files })
  return [a, b]
}

const MAP = ['map', '--pe', EXE, '--src', `src_matched/${M}`, '--obj', 'src_matched/build', '--module', M]
const IDX = ['--functions', 'decompiled_named_exe/index.json', '--instructions', 'decompiled_exe/instructions.tsv']
const maps = {}
for (const [name, extra] of [['strict', IDX], ['all', [...IDX, '--all']], ['all_noindex', ['--all']]]) {
  const [a] = both(`map ${name} (${extra.join(' ') || 'no options'})`,
    [...MAP, ...extra, '--out', t(`sym_${name}_py.json`)], [...MAP, ...extra, '--out', t(`sym_${name}_js.json`)],
    { files: [[t(`sym_${name}_py.json`), t(`sym_${name}_js.json`)]] })
  maps[name] = t(`sym_${name}_py.json`)
  P.notes.push(`map ${name}: exit ${a.rc}, ${a.stdout.toString().replace(/\s+/g, ' ').trim()}`)
}
// link / verify from the Python-written maps
both('link strict map', ['link', `reassembled/${M}`, maps.strict, t('hy_py.exe'), '--cache', cacheCopy()],
  ['link', `reassembled/${M}`, maps.strict, t('hy_js.exe'), '--cache', cacheCopy()], { files: [[t('hy_py.exe'), t('hy_js.exe')]] })
for (const s of ['py', 'js']) {
  const f = t(`hy_${s}.exe`)
  P.record(`link strict map (${s}): SHA-256 equals ${EXE}`, existsSync(f) && sha(f) === sha(P.path(EXE)) ? [] : ['differs'])
}
both('link --all map (refused)', ['link', `reassembled/${M}`, maps.all, t('hya_py.exe'), '--cache', cacheCopy()],
  ['link', `reassembled/${M}`, maps.all, t('hya_js.exe'), '--cache', cacheCopy()], { files: [[t('hya_py.exe'), t('hya_js.exe')]] })
both('verify strict map (IDENTICAL)', ['verify', EXE, `reassembled/${M}`, maps.strict, '--cache', cacheCopy()],
  ['verify', EXE, `reassembled/${M}`, maps.strict, '--cache', cacheCopy()])
both('verify against another file (DIFFERENT)', ['verify', 'work/game/SDL2.dll', `reassembled/${M}`, maps.strict, '--cache', cacheCopy()],
  ['verify', 'work/game/SDL2.dll', `reassembled/${M}`, maps.strict, '--cache', cacheCopy()])
// argparse
for (const args of [[], ['-h'], ['map', '-h'], ['link', '-h'], ['verify', '-h'], ['map'], ['link'], ['verify'], ['bogus'],
                    ['map', '--pe'], ['link', 'a', 'b', 'c', 'd'], ['verify', '--cache'], ['map', '--pe', 'x', '--src', 'y', '--obj', 'z', '--out']]) {
  both(`errors: ${JSON.stringify(args)}`, args, args)
}
P.finish()
