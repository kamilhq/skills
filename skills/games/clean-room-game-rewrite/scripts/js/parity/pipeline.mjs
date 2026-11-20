#!/usr/bin/env node
// Parity test: pipeline.py vs js/pipeline.mjs (the runner: every phase from decomp.json).
//
//   node parity/pipeline.mjs [--root PROJECT] [--python python3] [--only NAME[,NAME]] [--keep] [--tmp DIR]
//
// PROJECT (default: the current directory) is a project with decomp.json at its root and its phase results
// (e.g. work/game, extracted, decoded, decompiled_*, analysis, tools/formats and tools/js/formats,
// reports/game, reports/extracted). Nothing in PROJECT is written: each scenario builds a temp project
// TMP/proj whose input folders are symlinks into PROJECT (the module reports are copied: decode/completeness
// rewrite them) and whose output folders (reports, decoded, extracted, analysis, ... as the command needs) are
// real and empty. Both sides run in that same path, one after the other, so their outputs are directly
// comparable: after every step the whole project (its real files; symlinks skipped) is copied aside, and the
// Python and JS copies are compared byte for byte. Masks: "seconds" (timings) in stdout and in JSON files.
// stderr (the log) is compared for the single-threaded commands with each '+ <interpreter> <script>' line
// reduced to the script's name.
// Scenarios (--only takes these names):
//   errors       argparse: -h, no command, unknown command, bad choices/ints, missing values (cwd = TMP)
//   status_root  status on PROJECT itself (read-only)
//   init         init in a missing folder, again (refused), --force, status; init with a game folder and a
//                .gitignore without a final newline, status
//   intake       intake <PROJECT/work/game> (installed folder) against the project's manifest, again (refused),
//                status; intake into a project whose manifest does not exist yet (written)
//   inventory    inventory, status
//   archives     archives, again (refused), --force
//   completeness completeness with every module report; with one report missing (problems)
//   decode       decode --module wav, --module png (game + extracted), --module nope (refused), status
//   features     features (both binaries) into an empty analysis folder
//   names        names without names_apply.json (rows report it; Ghidra is not started), recover --binary nope
// Prints one JSON summary (with per-command cases and seconds); exit 0 only when every case is identical.
import { constants, cpSync, existsSync, lstatSync, mkdirSync, readFileSync, rmSync, symlinkSync,
  writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { Parity, parseOpts, compareDirs, firstDiff } from '../lib/peparity.mjs'
import { dumps, parse } from '../lib/pyjson.mjs'

const opts = parseOpts(process.argv.slice(2), { root: undefined, python: undefined, only: undefined, keep: false,
  tmp: undefined })
const P = new Parity('pipeline', opts)
const ROOT = P.root
const PROJ = P.tmpPath('proj')
const only = opts.only ? new Set(opts.only.split(',')) : null
const want = (name) => !only || only.has(name)
const t = (...p) => P.tmpPath(...p)
for (const p of ['decomp.json', 'work/game', 'decoded', 'tools/formats']) {
  if (!existsSync(P.path(p))) {
    process.stdout.write(JSON.stringify({ script: 'pipeline', error: `missing ${P.path(p)} (use --root)` }) + '\n')
    process.exit(2)
  }
}
const CFG = readFileSync(P.path('decomp.json'), 'utf8')
const cfg = parse(CFG)
const BINS = cfg.get('binaries').map((b) => ({ name: b.get('name'), file: b.get('file') }))
const stats = new Map()

// ----------------------------------------------------------------------------------------------- masks
// timings
const maskJson = (s) => s.replace(/"seconds": -?[0-9][0-9.eE+-]*/g, '"seconds": <s>')
// '+ <python> -I <dir>/x.py args' and '+ <node> <dir>/x.mjs args' -> '+ x args'; timings in the log
const normLog = (s) => s.split('\n').map((l) => l.replace(/^\+ \S+ -I (\S*\/)?([^/\s]+)\.py\b/, '+ $2')
  .replace(/^\+ \S+ (\S*\/)?([^/\s]+)\.mjs\b/, '+ $2')).join('\n').replace(/\(\d+ s\)/g, '(<s> s)').replace(/"seconds": -?[0-9][0-9.eE+-]*/g, '"seconds": <s>').replace(/\(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\)/g, '(<time>)')
function canon(f, buf) {
  if (f === 'stdout') return Buffer.from(maskJson(buf.toString('utf8')))
  const b = Buffer.from(buf)
  if (/\.json$/.test(f)) return Buffer.from(maskJson(b.toString('utf8')))
  return b
}

// ----------------------------------------------------------------------------------------------- projects
// spec: links (PROJECT-relative paths symlinked), copies, dirs, cfg (decomp.json text; null = PROJECT's; false =
// none), files {rel: text}, noProject (the folder is not created), before(side)
function setup(spec) {
  rmSync(PROJ, { recursive: true, force: true })
  if (spec.noProject) return
  mkdirSync(PROJ, { recursive: true })
  for (const l of spec.links ?? []) {
    if (!existsSync(P.path(l))) continue
    mkdirSync(dirname(join(PROJ, l)), { recursive: true })
    symlinkSync(P.path(l), join(PROJ, l))
  }
  for (const c of spec.copies ?? []) {
    if (!existsSync(P.path(c))) continue
    cpSync(P.path(c), join(PROJ, c), { recursive: true, mode: constants.COPYFILE_FICLONE })
  }
  for (const d of spec.dirs ?? []) mkdirSync(join(PROJ, d), { recursive: true })
  if (spec.cfg !== false) writeFileSync(join(PROJ, 'decomp.json'), spec.cfg ?? CFG)
  for (const [rel, text] of Object.entries(spec.files ?? {})) {
    mkdirSync(dirname(join(PROJ, rel)), { recursive: true })
    writeFileSync(join(PROJ, rel), text)
  }
}
// the project's real files (symlinks left out) -> dst
function snapshot(dst) {
  rmSync(dst, { recursive: true, force: true })
  if (!existsSync(PROJ)) { mkdirSync(dst, { recursive: true }); return }
  cpSync(PROJ, dst, { recursive: true, mode: constants.COPYFILE_FICLONE, filter: (src) => !lstatSync(src).isSymbolicLink() })
}

function stat(cmd) {
  if (!stats.has(cmd)) stats.set(cmd, { cases: 0, identical: 0, python_seconds: 0, js_seconds: 0 })
  return stats.get(cmd)
}
const cmdOf = (args) => {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--project') { i++; continue }
    if (!args[i].startsWith('-')) return args[i]
  }
  return 'errors'
}

// one scenario: setup + steps on the Python side, then the same on the JS side, then every step compared.
// step: {args, name, stderr (compare the normalised log), env, cwd ('tmp' = TMP without --project)}
function scenario(title, spec, steps) {
  if (!want(title)) return
  process.stderr.write(`[pipeline parity] ${title}\n`)
  const res = { py: [], js: [] }
  for (const s of ['py', 'js']) {
    setup(spec)
    if (spec.before) spec.before(s)
    steps.forEach((st, i) => {
      const args = st.cwd === 'tmp' ? st.args : ['--project', 'proj', ...st.args]
      const r = P.run(s, args, { cwd: P.tmp, env: st.env ?? {} })
      const c = stat(st.cmd ?? cmdOf(st.args))
      c[s === 'py' ? 'python_seconds' : 'js_seconds'] += r.seconds
      if (!st.noSnap) snapshot(t('snap', `${title}_${i}_${s}`))
      res[s].push(r)
      if (process.env.PARITY_VERBOSE) process.stderr.write(`  ${s} ${args.join(' ')}: exit ${r.rc} (${r.seconds.toFixed(1)} s)\n`)
    })
  }
  rmSync(PROJ, { recursive: true, force: true })
  steps.forEach((st, i) => {
    const a = res.py[i], b = res.js[i]
    const diffs = []
    if (a.rc !== b.rc) diffs.push(`exit code python ${a.rc} js ${b.rc}`)
    const sa = canon('stdout', a.stdout), sb = canon('stdout', b.stdout)
    if (!sa.equals(sb)) diffs.push(`stdout differs at byte ${firstDiff(sa, sb)}: python ${JSON.stringify(sa.toString().slice(Math.max(0, firstDiff(sa, sb) - 40), firstDiff(sa, sb) + 60))} js ${JSON.stringify(sb.toString().slice(Math.max(0, firstDiff(sa, sb) - 40), firstDiff(sa, sb) + 60))}`)
    const ea = normLog(a.stderr.toString()), eb = normLog(b.stderr.toString())
    if (st.stderr && ea !== eb) diffs.push(`stderr differs at byte ${firstDiff(ea, eb)}: python ${JSON.stringify(ea.slice(firstDiff(ea, eb), firstDiff(ea, eb) + 120))} js ${JSON.stringify(eb.slice(firstDiff(ea, eb), firstDiff(ea, eb) + 120))}`)
    if (!st.noSnap) diffs.push(...compareDirs(t('snap', `${title}_${i}_py`), t('snap', `${title}_${i}_js`), canon))
    const name = `${title}: ${st.name ?? st.args.join(' ')}`
    P.record(name, diffs)
    const c = stat(st.cmd ?? cmdOf(st.args))
    c.cases++
    if (!diffs.length) c.identical++
    if (!st.stderr && ea !== eb) {
      const sorted = (x) => x.split('\n').sort().join('\n')
      P.notes.push(`${name}: the logs (stderr, not compared) ${sorted(ea) === sorted(eb) ? 'hold the same lines in another order (parallel jobs)' : 'differ'}`)
    }
  })
  if (!opts.keep) rmSync(t('snap'), { recursive: true, force: true })
}

// ----------------------------------------------------------------------------------------------- inputs
for (const b of BINS) {
  const e = cfg.get('binaries').find((x) => x.get('name') === b.name)
  b.decompiled = e.get('decompiled'); b.named = e.get('named')
}
const MODULE_REPORTS = ['reports/game', 'reports/extracted']
const without = (list, ...drop) => list.filter((x) => !drop.includes(x))
const linksAll = () => [...new Set(['work/game', 'manifests', 'tools', 'extracted', 'decoded', 'analysis',
  ...BINS.flatMap((b) => [b.decompiled, b.named])])]

// ----------------------------------------------------------------------------------------------- scenarios
scenario('errors', { noProject: true }, [
  ['-h'], [], ['bogus'], ['recover', '--bogus'], ['init', '-h'], ['recover', '-h'], ['features', '-h'], ['intake'],
  ['--project'], ['decode', '--jobs', 'x'], ['status', '--project', t('nonexistent')], ['status', 'extra'],
  [`--project=${t('nonexistent')}`, 'status'], ['init'], ['names', '--binary'],
].map((args) => ({ args, cwd: 'tmp', stderr: true, noSnap: true, cmd: 'errors', name: `argv ${JSON.stringify(args).replaceAll(P.tmp, 'TMP')}` })))

scenario('status_root', { noProject: true }, [{ args: ['--project', ROOT, 'status'], cwd: 'tmp', stderr: true, noSnap: true,
  name: 'status on PROJECT' }])

scenario('init', { noProject: true }, [
  { args: ['init', '--game', 'Game 1.0'], stderr: true, name: 'init in a missing folder' },
  { args: ['init', '--game', 'Other'], stderr: true, name: 'init again (refused)' },
  { args: ['init', '--force', '--game', 'Other 1.0'], stderr: true, name: 'init --force' },
  { args: ['status'], stderr: true, name: 'status of the new skeleton' },
])
scenario('init', { links: ['work/game'], cfg: false, files: { '.gitignore': '/build/\n# local\n*.log' } }, [
  { args: ['init', '--game', 'Game 1.0'], stderr: true, name: 'init with a game folder and a .gitignore' },
  { args: ['status'], stderr: true, name: 'status (game folder, no manifest, binaries listed)' },
])

const cfgWith = (fn) => { const c = parse(CFG); fn(c); return dumps(c, { indent: 1 }) }
scenario('intake', { links: ['manifests', 'tools'], dirs: ['work'] }, [
  { args: ['intake', P.path('work', 'game')], name: 'intake <installed folder> (manifest compared)' },
  { args: ['intake', P.path('work', 'game')], stderr: true, name: 'intake again (refused: game folder not empty)' },
  { args: ['status'], stderr: true },
])
scenario('intake', { links: ['tools'], dirs: ['work/game/x'],
  cfg: cfgWith((c) => c.get('paths').set('manifest', 'manifests/new/game.json')) }, [
  { args: ['intake', '--force', P.path('work', 'game')], name: 'intake --force, no manifest yet (written)' },
])

scenario('inventory', { links: ['work/game', 'tools'] }, [
  { args: ['inventory'], stderr: true },
  { args: ['status'], stderr: true },
])

scenario('archives', { links: ['work/game', 'tools'] }, [
  { args: ['archives'], stderr: true },
  { args: ['archives'], stderr: true, name: 'archives again (refused)' },
  { args: ['archives', '--force'], stderr: true },
])

scenario('completeness', { links: ['work/game', 'extracted', 'tools'], copies: MODULE_REPORTS }, [
  { args: ['completeness'], stderr: true },
])
scenario('completeness', { links: ['work/game', 'extracted', 'tools'], copies: MODULE_REPORTS,
  before: () => rmSync(join(PROJ, 'reports', 'extracted', 'wav.json')) }, [
  { args: ['completeness'], stderr: true, name: 'completeness with reports/extracted/wav.json missing' },
])

scenario('decode', { links: ['work/game', 'extracted', 'tools', 'manifests'], copies: MODULE_REPORTS }, [
  { args: ['decode', '--module', 'wav'] },
  { args: ['decode', '--module', 'png'] },
  { args: ['decode', '--module', 'nope'], stderr: true },
  { args: ['status'], stderr: true },
])

scenario('features', { links: without(linksAll(), 'analysis', 'decoded', 'extracted') }, [
  { args: ['features'], name: 'features (every binary) into an empty analysis folder' },
])

scenario('names', { links: without(linksAll(), 'analysis', 'decoded', 'extracted'), dirs: ['analysis'] }, [
  { args: ['names'], stderr: true, name: 'names without names_apply.json' },
  { args: ['recover', '--binary', 'nope'], stderr: true },
])

// ----------------------------------------------------------------------------------------------- end
const r2 = (x) => Math.round(x * 100) / 100
const perCommand = {}
for (const [k, v] of stats) perCommand[k] = { ...v, python_seconds: r2(v.python_seconds), js_seconds: r2(v.js_seconds) }
P.finish({ per_command: perCommand })
