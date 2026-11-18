#!/usr/bin/env node
// Parity test: js/objcmp.mjs against objcmp.py on the project's real inputs.
//
//   node parity/objcmp.mjs [--root PROJECT] [--python python3] [--jobs N] [--quick] [--binary NAME]
//                          [--module NAME] [--obj DIR]
//
// PROJECT (default: the current directory) must have a decomp.json whose binary --binary (default: the first
// with "matching": true) has its exe, its named decompile (index.json), its matched sources (<paths.src>/<name>/
// *.cpp) and their compiled objects (--obj, default <paths.build>/obj/<name>/<unit>.obj); --module is the
// annotations' module name (default the binary's name). Without them the test stops with exit 2 and says what
// is missing. Both implementations run from PROJECT with the same arguments; stdout, stderr, exit code and every
// JSON file written are compared byte for byte.
// Cases:
//   - report on every unit as a project match script runs it (absolute --src, -v, --functions)
//   - report on every unit with relative paths, -q and --json FILE
//   - report on the whole source directory and the whole build directory at once (-v, --json), and from
//     another working directory (paths printed absolute)
//   - report --json - (JSON on stdout, text on stderr), --map files (text, JSON dict, JSON list, Ghidra
//     index.json, a conflicting entry), --no-auto-names, objects that fail to load
//   - compare on a sample of annotated functions (every DIFF one and a spread of OK ones): with --functions,
//     without it, with an explicit size, --all-diffs, --json FILE, undecorated Class::Method names
//   - dump (text and --json FILE) on a sample of objects
//   - argparse and input errors (usage texts, unknown/ambiguous options, missing files, bad numbers)
// Prints one JSON summary; exit 0 only when every case is identical.
import { spawn } from 'node:child_process'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync, readdirSync, mkdirSync } from 'node:fs'
import { tmpdir, availableParallelism } from 'node:os'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { load as loadJson } from '../lib/pyjson.mjs'
import { projectBinaries } from '../lib/peparity.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const SK = resolve(HERE, '..', '..')
const PY_SCRIPT = join(SK, 'objcmp.py'), JS_SCRIPT = join(SK, 'js', 'objcmp.mjs')
const argv = process.argv.slice(2)
const opt = (name, def) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : def }
const ROOT = resolve(opt('--root', process.cwd()))
const PY = opt('--python', 'python3')
const JOBS = Number(opt('--jobs', String(Math.max(2, Math.min(12, availableParallelism())))))
const QUICK = argv.includes('--quick')

const BIN = projectBinaries(ROOT, { script: 'objcmp', select: opt('--binary'), matching: !opt('--binary') })[0]
const EXE = BIN.exe, FUNCS = join(BIN.named, 'index.json')
const SRC = BIN.src, BUILD = opt('--obj', BIN.obj), MODULE = opt('--module', BIN.name)
for (const p of [EXE, FUNCS, SRC, BUILD]) {
  if (!existsSync(join(ROOT, p))) {
    process.stdout.write(JSON.stringify({ script: 'objcmp', error: `missing ${join(ROOT, p)} (use --root, --binary, --obj)` }) + '\n')
    process.exit(2)
  }
}
const TMP = mkdtempSync(join(tmpdir(), 'parity_objcmp_'))
const env = { ...process.env }
delete env.COLUMNS
delete env.LINES

function run(cmd, args, cwd) {
  return new Promise((res) => {
    const t0 = process.hrtime.bigint()
    const p = spawn(cmd, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] })
    const out = [], err = []
    p.stdout.on('data', (b) => out.push(b))
    p.stderr.on('data', (b) => err.push(b))
    p.on('close', (code) => res({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err),
                                  seconds: Number(process.hrtime.bigint() - t0) / 1e9 }))
  })
}

// a case: args (with {OUT} replaced by a per-implementation output file), cwd, files to compare
const cases = []
let nid = 0
const tracebacks = []      // cases where both crash with the same exception (compared without the frames)
function addCase(name, args, { cwd = ROOT, out = null } = {}) { cases.push({ name, args, cwd, out, id: nid++ }) }

async function runCase(c) {
  const sub = (impl) => c.args.map((a) => (typeof a === 'string' ? a.replaceAll('{OUT}', join(TMP, impl, `${c.id}.${c.out}`)) : a))
  const [py, js] = await Promise.all([run(PY, ['-I', PY_SCRIPT, ...sub('py')], c.cwd), run(process.execPath, [JS_SCRIPT, ...sub('js')], c.cwd)])
  const diffs = []
  if (py.code !== js.code) diffs.push(`exit ${py.code} vs ${js.code}`)
  if (!py.stdout.equals(js.stdout)) diffs.push(`stdout differs (${firstDiff(py.stdout, js.stdout)})`)
  if (!py.stderr.equals(js.stderr)) {
    // an uncaught exception: Python's traceback frames cannot match; the text before the traceback and its
    // last line (exception type and message) must
    const tb = Buffer.from('Traceback (most recent call last):\n')
    const ip = py.stderr.indexOf(tb), ij = js.stderr.indexOf(tb)
    const last = (b) => b.toString('utf8').trimEnd().split('\n').pop()
    if (ip >= 0 && ij >= 0 && py.stderr.subarray(0, ip).equals(js.stderr.subarray(0, ij)) && last(py.stderr) === last(js.stderr)) {
      tracebacks.push(c.name)
    } else diffs.push(`stderr differs (${firstDiff(py.stderr, js.stderr)})`)
  }
  if (c.out) {
    const fp = join(TMP, 'py', `${c.id}.${c.out}`), fj = join(TMP, 'js', `${c.id}.${c.out}`)
    const a = existsSync(fp) ? readFileSync(fp) : null, b = existsSync(fj) ? readFileSync(fj) : null
    if ((a === null) !== (b === null)) diffs.push(`output file: ${a === null ? 'only js' : 'only python'} wrote it`)
    else if (a && !a.equals(b)) diffs.push(`output file differs (${firstDiff(a, b)})`)
  }
  return { c, py, js, diffs }
}
function firstDiff(a, b) {
  let i = 0
  while (i < a.length && i < b.length && a[i] === b[i]) i++
  const ctx = (x) => JSON.stringify(x.subarray(Math.max(0, i - 40), i + 40).toString('utf8'))
  return `byte ${i}: py ${ctx(a)} / js ${ctx(b)}`
}
async function runAll(list) {
  const results = new Array(list.length)
  let next = 0
  async function worker() {
    while (next < list.length) {
      const k = next++
      results[k] = await runCase(list[k])
    }
  }
  await Promise.all(Array.from({ length: JOBS }, worker))
  return results
}

mkdirSync(join(TMP, 'py'))
mkdirSync(join(TMP, 'js'))
const units = readdirSync(join(ROOT, SRC)).filter((f) => f.endsWith('.cpp')).map((f) => f.slice(0, -4)).sort()
  .filter((u) => existsSync(join(ROOT, BUILD, `${u}.obj`)))
const unitList = QUICK ? units.filter((_, i) => i % 20 === 0) : units

// ---- 1. report per unit, as a project match script runs it, and with relative paths + --json
for (const u of unitList) {
  addCase(`report ${u} (match script)`, ['report', '--pe', EXE, '--src', join(ROOT, SRC, `${u}.cpp`), '--obj', `${BUILD}/${u}.obj`,
                                     '--module', MODULE, '--functions', FUNCS, '-v'])
  addCase(`report ${u} -q --json`, ['report', '--pe', EXE, '--src', `${SRC}/${u}.cpp`, '--obj', `${BUILD}/${u}.obj`,
                                    '--module', MODULE, '--functions', FUNCS, '-q', '--json', '{OUT}'], { out: 'json' })
}
// ---- 2. whole directories, other cwd, JSON on stdout
addCase('report whole src dir + whole build dir -v --json', ['report', '--pe', EXE, '--src', SRC, '--obj', BUILD, '--module', MODULE,
                                                             '--functions', FUNCS, '-v', '--json', '{OUT}'], { out: 'json' })
addCase('report all units (file list) + build dir, no --module', ['report', '--pe', EXE, '--src', ...unitList.slice(0, 40).map((u) => `${SRC}/${u}.cpp`),
                                                                  '--obj', BUILD, '--functions', FUNCS])
addCase('report from another cwd (absolute paths)', ['report', '--pe', join(ROOT, EXE), '--src', join(ROOT, SRC, `${units[56] || units[0]}.cpp`),
                                                     '--obj', join(ROOT, BUILD, `${units[56] || units[0]}.obj`), '--functions', join(ROOT, FUNCS), '-v'],
        { cwd: TMP })
for (const u of unitList.slice(0, 6)) {
  addCase(`report ${u} --json -`, ['report', '--pe', EXE, '--src', `${SRC}/${u}.cpp`, '--obj', `${BUILD}/${u}.obj`, '--functions', FUNCS,
                                   '--json', '-', '-v'])
}

// ---- 3. map files
const index = loadJson(join(ROOT, FUNCS))
const ifuncs = index.get('functions')
const mapText = ['# text map from index.json', '']
const mapDict = {}, mapList = []
ifuncs.slice(0, 3000).forEach((f, k) => {
  const nm = f.get('name'), addr = f.get('address')
  if (k % 3 === 0) mapText.push(`${nm} ${addr}   # comment`)
  else if (k % 3 === 1) mapText.push(`${addr}\t${nm}`)
  else mapText.push(`  ${nm}   ${parseInt(addr, 16)}`)
  if (k % 2) mapDict[nm] = addr; else mapDict[nm] = parseInt(addr, 16)
  mapList.push({ name: nm, address: addr })
})
writeFileSync(join(TMP, 'map.txt'), mapText.join('\n') + '\n')
writeFileSync(join(TMP, 'map.json'), JSON.stringify(mapDict))
writeFileSync(join(TMP, 'maplist.json'), JSON.stringify(mapList))
writeFileSync(join(TMP, 'conflict.txt'), `${ifuncs[5].get('name')} 0x401000\n${ifuncs[5].get('name')} 0x401010\n`)
writeFileSync(join(TMP, 'badmap.txt'), 'foo 0xzz\n')
writeFileSync(join(TMP, 'badfuncs.json'), '{"nofunctions": []}')
writeFileSync(join(TMP, 'weirdfuncs.json'), JSON.stringify({ functions: [{ address: '0x401000', size: '12' }, { address: 'zz' }, [1], 'x',
  { size: 3 }, { address: 4198400, size: 7.9 }, { address: '0x401010', size: '0x10' }, { address: null }, { address: true, size: false }] }))
const someUnits = unitList.filter((_, i) => i % 9 === 0)
for (const u of someUnits) {
  const base = ['report', '--pe', EXE, '--src', `${SRC}/${u}.cpp`, '--obj', `${BUILD}/${u}.obj`, '--module', MODULE]
  addCase(`report ${u} --map text`, [...base, '--map', join(TMP, 'map.txt'), '-v'])
  addCase(`report ${u} --map dict + list json, --no-auto-names`, [...base, '--map', join(TMP, 'map.json'), '--map', join(TMP, 'maplist.json'),
                                                                   '--no-auto-names', '-v', '--json', '{OUT}'], { out: 'json' })
  addCase(`report ${u} --map index.json --functions`, [...base, '--map', FUNCS, '--functions', FUNCS])
}
const u0 = units[0]
const base0 = ['report', '--pe', EXE, '--src', `${SRC}/${u0}.cpp`, '--obj', `${BUILD}/${u0}.obj`]
addCase('report conflicting map', [...base0, '--map', join(TMP, 'conflict.txt'), '--map', join(TMP, 'map.txt')])
addCase('report bad map', [...base0, '--map', join(TMP, 'badmap.txt')])
addCase('report missing map', [...base0, '--map', join(TMP, 'nonexistent.txt')])
addCase('report functions without key', [...base0, '--functions', join(TMP, 'badfuncs.json')])
addCase('report odd function list entries', [...base0, '--functions', join(TMP, 'weirdfuncs.json'), '--json', '{OUT}'], { out: 'json' })

// objects that fail to load / odd object sets
const objDir = join(TMP, 'objs')
mkdirSync(objDir)
const realObj = readFileSync(join(ROOT, BUILD, `${u0}.obj`))
writeFileSync(join(objDir, 'garbage.obj'), Buffer.from('this is not an object file at all'))
writeFileSync(join(objDir, 'ltcg.obj'), Buffer.concat([Buffer.from([0, 0, 0xff, 0xff, 1, 0, 0x4c, 1]), Buffer.alloc(64)]))
writeFileSync(join(objDir, 'truncated.obj'), realObj.subarray(0, 300))
writeFileSync(join(objDir, 'tiny.obj'), Buffer.from([1, 2, 3]))
writeFileSync(join(objDir, `${u0}.obj`), realObj)
addCase('report with unloadable objects', ['report', '--pe', EXE, '--src', `${SRC}/${u0}.cpp`, '--obj', objDir, '--functions', FUNCS])
addCase('report missing pe', ['report', '--pe', 'nonexistent.exe', '--src', SRC, '--obj', BUILD])
addCase('report pe is an obj', ['report', '--pe', `${BUILD}/${u0}.obj`, '--src', SRC, '--obj', BUILD])
addCase('dump garbage', ['dump', join(objDir, 'garbage.obj')])
addCase('dump ltcg', ['dump', join(objDir, 'ltcg.obj')])
addCase('dump truncated', ['dump', join(objDir, 'truncated.obj')])
addCase('dump tiny', ['dump', join(objDir, 'tiny.obj')])
addCase('dump exe', ['dump', EXE])
addCase('dump missing', ['dump', 'nonexistent.obj'])
addCase('dump directory', ['dump', BUILD])

// ---- 4. dump on a sample of objects
const allObjs = readdirSync(join(ROOT, BUILD)).filter((f) => f.toLowerCase().endsWith('.obj')).sort()
for (const f of allObjs.filter((_, i) => QUICK ? i % 40 === 0 : i % 8 === 0)) {
  addCase(`dump ${f}`, ['dump', `${BUILD}/${f}`, '--json', '{OUT}'], { out: 'json' })
}
addCase(`dump ${allObjs[0]} --json -`, ['dump', `${BUILD}/${allObjs[0]}`, '--json', '-'])

// ---- 5. argparse and input errors
const argCases = [[], ['-h'], ['--help'], ['bogus'], ['compare', '-h'], ['report', '-h'], ['dump', '-h'], ['report'], ['compare', 'a'],
  ['report', '--m', 'x'], ['report', '--pe'], ['report', '--src'], ['dump', 'a', 'b'], ['--foo', 'dump', 'a'], ['dump', '-q', 'a'],
  ['dump', '--json'], ['compare', 'a', 'b', 'c', 'd', 'e', 'f'], ['report', '--pe', 'x', '--src', 'y', '--obj', 'z', '--bogus'],
  ['report', '--pe=x', '--src', 'y', '--obj', 'z', '-vq', '--funct'], ['-vh'], ['--he', 'report'], ['report', '-h', '--pe'],
  ['report', '--pe', 'x', '--pe'], ['dump', '-'], ['compare', '--', 'a', 'b', 'c', 'd'], ['dump', '--json=x', 'a', '--json'],
  ['report', '--verbose=1', '--pe', 'x', '--src', 'y', '--obj', 'z'], ['report', '-vx'], ['compare', 'o', 's', 'p', 'v', '--json', 'x', '100'],
  ['report', '--src', 'a', '--obj', 'b'], ['report', '--pe', EXE, '--src', '--obj', 'b'], ['compare', '-x'], ['dump', '--js', '-', '-'],
  ['report', '--no', '--pe', 'x'], ['report', '--pe', 'x', '--src', 'y', '--obj', 'z', '--quiet=1'], ['report', '-qv', '-h'],
  ['report', '--pe', EXE, '--src', 'nonexistent.cpp', '--obj', `${BUILD}/${u0}.obj`]]
argCases.forEach((a, k) => addCase(`args#${k} ${JSON.stringify(a)}`, a))

async function main() {
  const t0 = Date.now()
  // first wave: everything above (the compare sample needs the per-unit JSON reports)
  let results = await runAll(cases)
  // ---- 6. compare on a sample of annotated functions, picked from Python's per-unit JSON reports
  const cmpCases = []
  const reports = results.filter((r) => r.c.name.endsWith('-q --json'))
  let okPick = 0
  for (const r of reports) {
    const f = join(TMP, 'py', `${r.c.id}.json`)
    if (!existsSync(f)) continue
    const rep = loadJson(f)
    for (const fn of rep.get('functions')) {
      const st = fn.get('status')
      if (st !== 'identical' && st !== 'different') continue
      if (st === 'identical' && okPick++ % (QUICK ? 40 : 12) !== 0) continue
      const obj = fn.get('obj'), sym = fn.get('symbol'), va = fn.get('va'), size = fn.get('orig_size')
      const k = cmpCases.length
      const add = (name, args, o = {}) => { cmpCases.push({ name, args, cwd: ROOT, out: o.out || null, id: nid++ }) }
      add(`compare ${sym} ${va}`, ['compare', obj, sym, EXE, va, '--functions', FUNCS, ...(k % 2 ? ['--all-diffs'] : []), '--json', '{OUT}'], { out: 'json' })
      if (k % 3 === 0) add(`compare ${sym} ${va} no --functions`, ['compare', obj, sym, EXE, va.slice(2)])
      if (k % 4 === 0) add(`compare ${sym} ${va} size ${size}`, ['compare', obj, sym, EXE, va, String(size), '--all-diffs'])
      if (k % 5 === 0) add(`compare ${sym} ${va} size+8`, ['compare', obj, sym, EXE, va, String(size + 8), '--map', FUNCS, '--no-auto-names'])
      if (k % 7 === 0) add(`compare ${sym} ${va} --json -`, ['compare', obj, sym, EXE, va, '--json', '-'])
      // undecorated names: ?Name@Class@@... -> Class::Name, ?Name@@... -> Name
      const m = /^\?([A-Za-z_]\w*)@(?:([A-Za-z_]\w*)@)?@/.exec(sym)
      if (m && k % 2 === 0) add(`compare undecorated ${sym}`, ['compare', obj, m[2] ? `${m[2]}::${m[1]}` : m[1], EXE, va, '--functions', FUNCS])
    }
  }
  const one = cmpCases[0]
  if (one) {
    const [, obj, sym] = one.args
    const add = (name, args) => cmpCases.push({ name, args, cwd: ROOT, out: null, id: nid++ })
    add('compare unknown symbol', ['compare', obj, 'no_such_function', EXE, '0x401000'])
    add('compare bad va', ['compare', obj, sym, EXE, 'zz'])
    add('compare va outside the image', ['compare', obj, sym, EXE, '0x10'])
    add('compare bad size', ['compare', obj, sym, EXE, '0x401000', '0x10'])
    add('compare missing obj', ['compare', 'nonexistent.obj', sym, EXE, '0x401000'])
    add('compare missing pe', ['compare', obj, sym, 'nonexistent.exe', '0x401000'])
    add('compare wrong va', ['compare', obj, sym, EXE, '0x401000', '--functions', FUNCS, '--all-diffs'])
    add('compare bad map', ['compare', obj, sym, EXE, '0x401000', '--map', join(TMP, 'badmap.txt')])
    add('compare functions without key', ['compare', obj, sym, EXE, '0x401000', '--functions', join(TMP, 'badfuncs.json')])
  }
  const cmpResults = await runAll(cmpCases)
  results = results.concat(cmpResults)
  const different = results.filter((r) => r.diffs.length).map((r) => `${r.c.name}: ${r.diffs.join('; ')}`)
  const pySec = results.reduce((s, r) => s + r.py.seconds, 0), jsSec = results.reduce((s, r) => s + r.js.seconds, 0)
  const exits = {}
  for (const r of results) exits[r.py.code] = (exits[r.py.code] || 0) + 1
  const summary = { script: 'objcmp', cases: results.length, identical: results.length - different.length, different: different.slice(0, 40),
                    units: unitList.length, uncaught_exception_cases: tracebacks, compare_cases: cmpCases.length, python_exit_codes: exits,
                    python_seconds: +pySec.toFixed(2), js_seconds: +jsSec.toFixed(2), wall_seconds: +((Date.now() - t0) / 1000).toFixed(1) }
  process.stdout.write(JSON.stringify(summary) + '\n')
  process.exitCode = different.length ? 1 : 0
}

main().finally(() => { if (!argv.includes('--keep')) rmSync(TMP, { recursive: true, force: true }) })
