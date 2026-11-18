#!/usr/bin/env node
// Parity test: reassemble.py vs js/reassemble.mjs (phase 5b: PE <-> assembly text).
//
//   node parity/reassemble.mjs [--root PROJECT] [--python python3] [--only NAME] [--skip-cold] [--skip-split]
//                              [--skip-editcheck] [--caches DIR] [--keep] [--tmp DIR]
//
// Targets: every reassembled/<NAME> (layout.json) whose original is work/game/<NAME>.exe|.dll; split uses
// decompiled_<exe|sdl2|name> and analysis/<NAME>/names_apply.json when present. Cases per target:
//   cold build      `build reassembled/NAME out --cache <new file>` on both sides: no cache, so every line goes
//                   through Ghidra's assembler (scripts/ghidra/assemble.sh); compares the binary and the cache file
//                   written, and checks both binaries against the original's SHA-256
//   warm build      both sides from a copy of the Python-written cache (JS reads Python's cache), and Python from a
//                   copy of the JS-written cache (Python reads JS's cache): binaries and rewritten caches compared
//   REASM_DEBUG     the debug dump of a warm build
//   verify          `verify <original> reassembled/NAME --cache <copy>` (IDENTICAL) and against the other
//                   binary (DIFFERENT; the temp path in "rebuilt kept at" is normalised)
//   editcheck       `editcheck <original> reassembled/NAME <decompiled> --cache <copy>`: insert a NOP, rebuild
//                   (Ghidra assembles the moved label values), stdout and the updated cache compared
//   split           `split <original> <decompiled> <out> --names ...`: stdout and every file written (Ghidra
//                   choose mode); a note says whether the output equals the project's reassembled/NAME
//   library         pe_parse / relocs_of / make_reloc imported from both modules, on every PE under work/game
//   errors          argument errors (exit 2, docstring), a missing input dir (exit 1)
// --skip-cold uses caches from --caches DIR (cache_NAME.json, written by Python) or makes them with one
// Python cold build (not compared). Prints one JSON summary; exit 0 only when every case is identical.
import { copyFileSync, existsSync, readdirSync, readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { Parity, parseOpts, SK } from '../lib/peparity.mjs'
import { dumps, parse } from '../lib/pyjson.mjs'
import * as R from '../reassemble.mjs'

const opts = parseOpts(process.argv.slice(2), {
  root: undefined, python: undefined, only: undefined, 'skip-cold': false, 'skip-split': false,
  'skip-editcheck': false, caches: undefined, keep: false, tmp: undefined,
})
const P = new Parity('reassemble', opts)
const sha = (f) => createHash('sha256').update(readFileSync(f)).digest('hex')
const t = (...p) => P.tmpPath(...p)

const targets = []
if (existsSync(P.path('reassembled'))) {
  for (const name of readdirSync(P.path('reassembled')).sort()) {
    if (!existsSync(P.path('reassembled', name, 'layout.json'))) continue
    if (opts.only && opts.only !== name) continue
    const bin = ['.exe', '.dll'].map((e) => P.path('work', 'game', name + e)).find(existsSync)
    if (!bin) continue
    const dd = [`decompiled_${name.toLowerCase()}`, bin.endsWith('.exe') ? 'decompiled_exe' : null]
      .filter(Boolean).map((d) => P.path(d)).find((d) => existsSync(join(d, 'instructions.tsv')))
    const names = P.path('analysis', name, 'names_apply.json')
    targets.push({ name, bin, dd, names: existsSync(names) ? names : null, src: P.path('reassembled', name) })
  }
}

function norm(r) {
  for (const k of ['stdout', 'stderr']) r[k] = Buffer.from(r[k].toString().replace(/rebuilt kept at .*/g, 'rebuilt kept at <tmp>'))
  return r
}
function both(name, pyArgs, jsArgs, { files = [], dirs = [], env = {} } = {}) {
  const a = norm(P.run('py', pyArgs, { env: env.py ?? env })), b = norm(P.run('js', jsArgs, { env: env.js ?? env }))
  const tb = a.stderr.toString().startsWith('Traceback')
  P.compare(name, a, b, { stderr: !tb, files, dirs })
  return [a, b]
}
const copy = (from, to) => { copyFileSync(from, to); return to }

for (const T of targets) {
  const N = T.name, origSha = sha(T.bin), ext = T.bin.slice(-4)
  // 1. cold build
  let pyCache = opts.caches ? join(opts.caches, `cache_${N}.json`) : null
  if (!opts['skip-cold']) {
    both(`${N} cold build (Ghidra assembler, cache written)`,
      ['build', T.src, t(`${N}_cold_py${ext}`), '--cache', t(`${N}_cold_py.json`)],
      ['build', T.src, t(`${N}_cold_js${ext}`), '--cache', t(`${N}_cold_js.json`)],
      { files: [[t(`${N}_cold_py${ext}`), t(`${N}_cold_js${ext}`)], [t(`${N}_cold_py.json`), t(`${N}_cold_js.json`)]] })
    for (const s of ['py', 'js']) {
      const f = t(`${N}_cold_${s}${ext}`)
      P.record(`${N} cold build (${s}) SHA-256 equals ${T.bin}`, existsSync(f) && sha(f) === origSha ? [] : [`${existsSync(f) ? sha(f) : 'missing'} != ${origSha}`])
    }
    pyCache = t(`${N}_cold_py.json`)
  } else if (!pyCache || !existsSync(pyCache)) {
    pyCache = t(`${N}_made_py.json`)
    P.run('py', ['build', T.src, t(`${N}_made${ext}`), '--cache', pyCache])
  }
  const jsCache = existsSync(t(`${N}_cold_js.json`)) ? t(`${N}_cold_js.json`) : pyCache
  // 2. warm builds
  both(`${N} warm build from the Python-written cache`,
    ['build', T.src, t(`${N}_warm_py${ext}`), '--cache', copy(pyCache, t(`${N}_warm_py.json`))],
    ['build', T.src, t(`${N}_warm_js${ext}`), '--cache', copy(pyCache, t(`${N}_warm_js.json`))],
    { files: [[t(`${N}_warm_py${ext}`), t(`${N}_warm_js${ext}`)], [t(`${N}_warm_py.json`), t(`${N}_warm_js.json`)]] })
  P.record(`${N} warm build (js, Python's cache) SHA-256 equals ${T.bin}; cache file unchanged`,
    sha(t(`${N}_warm_js${ext}`)) === origSha && readFileSync(t(`${N}_warm_js.json`)).equals(readFileSync(pyCache)) ? [] : ['differs'])
  both(`${N} warm build, Python from the JS-written cache`,
    ['build', T.src, t(`${N}_x_py${ext}`), '--cache', copy(jsCache, t(`${N}_x_py.json`))],
    ['build', T.src, t(`${N}_x_js${ext}`), '--cache', copy(jsCache, t(`${N}_x_js.json`))],
    { files: [[t(`${N}_x_py${ext}`), t(`${N}_x_js${ext}`)], [t(`${N}_x_py.json`), t(`${N}_x_js.json`)]] })
  both(`${N} REASM_DEBUG dump`,
    ['build', T.src, t(`${N}_dbg_py${ext}`), '--cache', copy(pyCache, t(`${N}_dbg_py.json`))],
    ['build', T.src, t(`${N}_dbg_js${ext}`), '--cache', copy(pyCache, t(`${N}_dbg_js.json`))],
    { files: [[t(`${N}_dbgdump_py.json`), t(`${N}_dbgdump_js.json`)], [t(`${N}_dbg_py${ext}`), t(`${N}_dbg_js${ext}`)]],
      env: { py: { REASM_DEBUG: t(`${N}_dbgdump_py.json`) }, js: { REASM_DEBUG: t(`${N}_dbgdump_js.json`) } } })
  // 3. verify
  both(`${N} verify (IDENTICAL)`,
    ['verify', T.bin, T.src, '--cache', copy(pyCache, t(`${N}_v_py.json`))],
    ['verify', T.bin, T.src, '--cache', copy(pyCache, t(`${N}_v_js.json`))])
  const other = targets.find((x) => x !== T)?.bin ?? P.path('work', 'game', 'readme.txt')
  both(`${N} verify against another file (DIFFERENT)`,
    ['verify', other, T.src, '--cache', copy(pyCache, t(`${N}_vd_py.json`))],
    ['verify', other, T.src, '--cache', copy(pyCache, t(`${N}_vd_js.json`))])
  // 4. editcheck
  if (!opts['skip-editcheck'] && T.dd) {
    both(`${N} editcheck (insert a NOP, Ghidra assembles moved labels)`,
      ['editcheck', T.bin, T.src, T.dd, '--cache', copy(pyCache, t(`${N}_e_py.json`))],
      ['editcheck', T.bin, T.src, T.dd, '--cache', copy(pyCache, t(`${N}_e_js.json`))],
      { files: [[t(`${N}_e_py.json`), t(`${N}_e_js.json`)]] })
  }
  // 5. split
  if (!opts['skip-split'] && T.dd) {
    const extra = T.names ? ['--names', T.names] : []
    both(`${N} split (Ghidra choose mode)`,
      ['split', T.bin, T.dd, t(`${N}_split_py`), ...extra], ['split', T.bin, T.dd, t(`${N}_split_js`), ...extra],
      { dirs: [[t(`${N}_split_py`), t(`${N}_split_js`)]] })
    const same = spawnSync('diff', ['-rq', t(`${N}_split_py`), T.src]).status === 0
    P.notes.push(`${N}: split output ${same ? 'equals' : 'differs from'} the project's reassembled/${N}`)
  }
}

// library functions, imported from both modules
{
  const pes = existsSync(P.path('work', 'game')) ? readdirSync(P.path('work', 'game')).filter((f) => /\.(exe|dll)$/i.test(f)).sort().map((f) => P.path('work', 'game', f)) : []
  const code = `import hashlib, json, sys
sys.path.insert(0, sys.argv[1])
import reassemble as R
out = []
for p in sys.argv[2:]:
    d = open(p, 'rb').read()
    base, dirs, secs = R.pe_parse(d)
    rel, rs = R.relocs_of(d, base, dirs, secs)
    sites = [x - base for x in rel]
    out.append(dict(base=base, dirs=dirs, secs=secs, reloc_section=rs, relocs=len(rel),
                    relocs_sha=hashlib.sha256(json.dumps(list(rel.items())).encode()).hexdigest(),
                    make_reloc=hashlib.sha256(R.make_reloc(sites)).hexdigest(),
                    make_reloc_odd=R.make_reloc(sites[:3] + sites[:1] + [0x1fff, 0x1000]).hex(),
                    relax=R.relax([('label', 'a'), ('br', 'JMP', 'b', 0), ('fix', 130), ('label', 'b'), ('br', 'JZ', 'a', 0),
                                   ('br', 'LOOP', 'a', 0), ('br', 'CALL', 'D_401000', 0), ('br', 'JMP', 'A_10', 1), ('br', 'JNZ', 'b', 2)],
                                  0x401000, R.fixed_label_value)[0],
                    sanitize=[R.sanitize(n, 0x401000, set()) for n in ['A::b', '9x', 'L_401000', '', 'a\\u00e9b', 'ok']],
                    branch_kind=[R.branch_kind(bytes([b, 0x85])) for b in (0xe8, 0xe9, 0xeb, 0x74, 0x0f, 0xe2, 0x90)]))
sys.stdout.write(json.dumps(out))`
  const tp = process.hrtime.bigint()
  const py = spawnSync(P.python, ['-I', '-c', code, SK, ...pes], { maxBuffer: 1 << 28 })
  P.pySec += Number(process.hrtime.bigint() - tp) / 1e9
  const tj = process.hrtime.bigint()
  const out = []
  for (const p of pes) {
    const d = readFileSync(p)
    const [base, dirs, secs] = R.pe_parse(d)
    const [rel, rs] = R.relocs_of(d, base, dirs, secs)
    const sites = [...rel.keys()].map((x) => x - base)
    out.push({ base, dirs, secs, reloc_section: rs, relocs: rel.size,
               relocs_sha: createHash('sha256').update(dumps([...rel])).digest('hex'),
               make_reloc: createHash('sha256').update(R.make_reloc(sites)).digest('hex'),
               make_reloc_odd: R.make_reloc([...sites.slice(0, 3), ...sites.slice(0, 1), 0x1fff, 0x1000]).toString('hex'),
               relax: R.relax([['label', 'a'], ['br', 'JMP', 'b', 0], ['fix', 130], ['label', 'b'], ['br', 'JZ', 'a', 0],
                               ['br', 'LOOP', 'a', 0], ['br', 'CALL', 'D_401000', 0], ['br', 'JMP', 'A_10', 1], ['br', 'JNZ', 'b', 2]],
                              0x401000, R.fixed_label_value)[0],
               sanitize: ['A::b', '9x', 'L_401000', '', 'aéb', 'ok'].map((n) => R.sanitize(n, 0x401000, new Set())),
               branch_kind: [0xe8, 0xe9, 0xeb, 0x74, 0x0f, 0xe2, 0x90].map((b) => R.branch_kind(Buffer.from([b, 0x85]))) })
  }
  P.jsSec += Number(process.hrtime.bigint() - tj) / 1e9
  const pj = py.status === 0 ? parse(py.stdout.toString()) : []
  const jj = parse(dumps(out))
  pes.forEach((p, i) => P.record(`library pe_parse/relocs_of/make_reloc/relax/sanitize/branch_kind on ${p}`,
    pj[i] && dumps(pj[i]) === dumps(jj[i]) ? [] : [py.status === 0 ? 'differs' : 'python failed: ' + py.stderr.toString().slice(-300)]))
}

// errors
const T0 = targets[0]
for (const [name, args] of [
  ['no arguments', []], ['-h', ['-h']], ['--help', ['--help']], ['unknown subcommand', ['bogus', 'a', 'b']],
  ['build with one argument', ['build', 'x']], ['verify with three arguments', ['verify', 'a', 'b', 'c']],
  ['build of a missing dir', ['build', t('nope'), t('nope.bin')]], ['--cache without value', ['build', 'x', 'y', '--cache']],
  ['split of a non-PE', ['split', P.path('work', 'game', 'readme.txt'), T0?.dd ?? 'x', t('nosplit')]],
]) both(`errors: ${name}`, args, args)
P.finish({ targets: targets.map((x) => x.name) })
