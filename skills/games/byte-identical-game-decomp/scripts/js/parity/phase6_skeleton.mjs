#!/usr/bin/env node
// Parity test: phase6_skeleton.py vs js/phase6_skeleton.mjs.
//
//   node parity/phase6_skeleton.mjs [--root PROJECT] [--python python3] [--keep]
//
// Cases: analysis/<binary>/names_final.json of every analysed binary with the default gap and with
// --gap 0x100 / 4096 / 0 / 0x10000, --decompiled <dir>, --opt=value and abbreviated options (--mod); a
// synthetic names file (unsorted addresses, missing/empty names, null and non-ASCII subsystems, long
// evidence with non-BMP characters, '::' names); argparse paths: -h (at COLUMNS 80, 120, 40, 25), missing
// arguments, unknown options, a missing option value, a bad --gap. Compares exit code, stdout, stderr and
// every file written (the .cpp units and units.json).
import { existsSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { Parity, parseOpts } from '../lib/peparity.mjs'
import { dumps } from '../lib/pyjson.mjs'

const opts = parseOpts(process.argv.slice(2), { root: undefined, python: undefined, keep: false })
const P = new Parity('phase6_skeleton', opts)
let n = 0
function both(name, args, env = {}) {
  const k = n++
  const a = P.run('py', args.map((x) => x.replace('@OUT@', P.tmpPath(`py_${k}`))), { env })
  const b = P.run('js', args.map((x) => x.replace('@OUT@', P.tmpPath(`js_${k}`))), { env })
  P.compare(name, a, b, { stderr: true, dirs: [[P.tmpPath(`py_${k}`), P.tmpPath(`js_${k}`)]] })
}

const names = []
if (existsSync(P.path('analysis'))) {
  for (const d of readdirSync(P.path('analysis')).sort()) {
    const f = P.path('analysis', d, 'names_final.json')
    if (existsSync(f)) names.push([d, f])
  }
}
for (const [mod, f] of names) {
  both(`${mod} default`, [f, '@OUT@', '--module', mod])
  for (const g of ['0x100', '4096', '0', '0x10000', '0o777', '0b1000000000']) both(`${mod} --gap ${g}`, [f, '@OUT@', '--module', mod, '--gap', g])
  both(`${mod} --decompiled`, ['--decompiled', `decompiled_named_${mod.toLowerCase()}`, f, '--module', mod, '@OUT@'])
  both(`${mod} --opt=value, abbreviations`, [f, '--mod=' + mod, '@OUT@', '--gap=0x200', '--dec', 'x/y'])
}
// synthetic names file
const syn = [
  { addr: '0x402000', name: 'B::two', kind: 'method', subsystem: 'render', confidence: 'high', evidence: 'x'.repeat(200) },
  { addr: '0x401000', name: 'A::one', kind: 'ctor', subsystem: 'render', confidence: 'low', evidence: 'été 😀'.repeat(40) },
  { addr: '0x401010', name: '', kind: 'method', subsystem: 'render' },
  { addr: '0x401020', name: 'free_fn', kind: 'free', subsystem: null, confidence: null },
  { addr: '0x401030', name: 'lib_fn', kind: 'crt', subsystem: 'crt' },
  { addr: '0x401040', name: 'C::D::e', kind: 'dtor', subsystem: 'sub sys/ü', evidence: '' },
  { addr: '0x401050', name: 'stub', kind: 'stub' },
  { addr: '0x0401060', name: 'Z::z', kind: 'method', subsystem: 'misc', confidence: 'medium', evidence: 'quote " and \\ and \t tab' },
  { addr: '0x401500', name: 'far', kind: 'method', subsystem: 'misc' },
  { addr: '0x401400', name: 'K::k', kind: 'method', subsystem: 'misc' },
]
writeFileSync(P.tmpPath('syn.json'), dumps(syn, { indent: 1 }))
both('synthetic default', [P.tmpPath('syn.json'), '@OUT@', '--module', 'SYN'])
both('synthetic --gap 0x10', [P.tmpPath('syn.json'), '@OUT@', '--module', 'SYN', '--gap', '0x10'])
writeFileSync(P.tmpPath('empty.json'), '[]')
both('empty names', [P.tmpPath('empty.json'), '@OUT@', '--module', 'E'])
// argparse
const f0 = names.length ? names[0][1] : P.tmpPath('syn.json')
for (const [name, args, env] of [
  ['-h', ['-h']], ['--help after args', [f0, '@OUT@', '--help']], ['-h COLUMNS=40', ['-h'], { COLUMNS: '40' }],
  ['-h COLUMNS=25', ['-h'], { COLUMNS: '25' }], ['-h COLUMNS=120', ['-h'], { COLUMNS: '120' }],
  ['no arguments', []], ['missing --module', [f0, '@OUT@']], ['missing out', [f0, '--module', 'M']],
  ['unknown option', [f0, '@OUT@', '--module', 'M', '--bogus']], ['extra positional', [f0, '@OUT@', 'extra', '--module', 'M']],
  ['--module without value', [f0, '@OUT@', '--module']], ['--gap followed by option', [f0, '@OUT@', '--gap', '--module', 'M']],
  ['bad --gap', [f0, '@OUT@', '--module', 'M', '--gap', 'zz']], ['bad --gap 010', [f0, '@OUT@', '--module', 'M', '--gap', '010']],
  ['-- separator', ['--module', 'M', '--', f0, '@OUT@']], ['missing names file', [P.tmpPath('nope.json'), '@OUT@', '--module', 'M']],
  ['usage wrap COLUMNS=60', [], { COLUMNS: '60' }],
]) {
  const k = n++
  const map = (side) => args.map((x) => x.replace('@OUT@', P.tmpPath(`${side}_${k}`)))
  const a = P.run('py', map('py'), { env }), b = P.run('js', map('js'), { env })
  // a traceback (uncaught exception) is compared by exit code and stdout only
  const tb = a.stderr.toString().startsWith('Traceback')
  P.compare(`argparse: ${name}`, a, b, { stderr: !tb, dirs: [[P.tmpPath(`py_${k}`), P.tmpPath(`js_${k}`)]] })
}
P.finish({ names_files: names.map(([m]) => m) })
