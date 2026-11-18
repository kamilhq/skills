#!/usr/bin/env node
// Parity test: pipeline.py vs js/pipeline.mjs (the runner: every phase from decomp.json).
//
//   node parity/pipeline.mjs [--root PROJECT] [--python python3] [--quick] [--only NAME[,NAME]] [--run] [--keep]
//                            [--tmp DIR]
//
// PROJECT (default: the current directory) is a project with decomp.json at its root and its phase results
// (VVVVVV: work/game, extracted, decoded, decompiled_*, analysis, reassembled, src_matched, tools/formats and
// tools/js/formats, reports/game, reports/extracted). Nothing in PROJECT is written: each scenario builds a
// temp project TMP/proj whose input folders are symlinks into PROJECT (src_matched/<B> and the module reports
// are copied: the compiler's cwd must be a real folder, and decode/completeness rewrite reports) and whose
// output folders (build, reports, decoded, extracted, analysis, ... as the command needs) are real and empty.
// Both sides run in that same path, one after the other (the link step writes paths, and build/work is
// shared between steps), so their outputs are directly comparable: after every step the whole project (its
// real files; symlinks skipped) is copied aside, and the Python and JS copies are compared byte for byte.
// Masks: "seconds" (timings) in stdout and in JSON files, "finished" (time) in reports/build.json and at the end
// of status's build row, the COFF
// TimeDateStamp of .obj files (cl.exe), and link.exe's stamps as in parity/relink.mjs (relinked.exe
// TimeDateStamp + CheckSum, relinked.map "Timestamp is", .lib/.exp member stamps). stderr (the log) is compared
// for the single-threaded commands with each '+ <interpreter> <script>' line reduced to the script's name.
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
//   reassemble   reassemble --cache (both binaries; caches seeded: PROJECT/build/work/asm_cache_<B>.json, or one
//                cold Python build made once), --split (refused), --binary nope (refused), status
//   skeleton     skeleton into an empty src folder, again (refused)
//   features     features (both binaries) into an empty analysis folder
//   names        names without names_apply.json (rows report it; Ghidra is not started), recover --binary nope
//   match        match (the whole project), match --units with SHOW_STUBS=1, status
//   build        build --mode identical (the full data build: Python packs data.zip in about 6 minutes; with
//                --quick: --skip-data into a build folder holding the game's data files), then
//                build --mode identical --skip-data --no-original (+ --run with --run), verify, verify --out
//                missing (refused), status
// --run: the game is started under Wine by both sides (~/Documents/VVVVVV is backed up and restored).
// Prints one JSON summary (with per-command cases and seconds); exit 0 only when every case is identical.
import { spawnSync } from 'node:child_process'
import { constants, cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, symlinkSync,
  writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { Parity, parseOpts, SK, compareDirs, firstDiff } from '../lib/peparity.mjs'
import { dumps, parse } from '../lib/pyjson.mjs'

const opts = parseOpts(process.argv.slice(2), { root: undefined, python: undefined, quick: false, only: undefined,
  run: false, keep: false, tmp: undefined })
const P = new Parity('pipeline', opts)
const ROOT = P.root
const PROJ = P.tmpPath('proj')
const only = opts.only ? new Set(opts.only.split(',')) : null
const want = (name) => !only || only.has(name)
const t = (...p) => P.tmpPath(...p)
for (const p of ['decomp.json', 'work/game', 'reassembled', 'decoded', 'tools/formats']) {
  if (!existsSync(P.path(p))) {
    process.stdout.write(JSON.stringify({ script: 'pipeline', error: `missing ${P.path(p)} (use --root)` }) + '\n')
    process.exit(2)
  }
}
const CFG = readFileSync(P.path('decomp.json'), 'utf8')
const cfg = parse(CFG)
const BINS = cfg.get('binaries').map((b) => ({ name: b.get('name'), file: b.get('file'), src: b.get('src') ?? `src_matched/${b.get('name')}`,
  matching: Boolean(b.get('matching')) }))
const stats = new Map()

// ----------------------------------------------------------------------------------------------- masks
function maskPE(b) {
  if (b.length < 0x40 || b[0] !== 0x4d || b[1] !== 0x5a) return b
  const pe = b.readUInt32LE(0x3c)
  if (pe + 92 > b.length) return b
  b.fill(0, pe + 8, pe + 12)
  b.fill(0, pe + 88, pe + 92)
  return b
}
function maskCoff(b, m) {
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
function maskLib(b) {
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
// timings; build.json's "finished" time, also quoted at the end of status's build row
const maskTime = (s) => s.replace(/\(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\)/g, '(<time>)')
const maskJson = (s) => maskTime(s.replace(/"seconds": -?[0-9][0-9.eE+-]*/g, '"seconds": <s>').replace(/"finished": "[^"]*"/g, '"finished": <t>'))
// '+ <python> -I <dir>/x.py args' and '+ <node> <dir>/x.mjs args' -> '+ x args'; timings in the log
const normLog = (s) => s.split('\n').map((l) => l.replace(/^\+ \S+ -I (\S*\/)?([^/\s]+)\.py\b/, '+ $2')
  .replace(/^\+ \S+ (\S*\/)?([^/\s]+)\.mjs\b/, '+ $2')).join('\n').replace(/\(\d+ s\)/g, '(<s> s)').replace(/"seconds": -?[0-9][0-9.eE+-]*/g, '"seconds": <s>').replace(/\(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\)/g, '(<time>)')
function canon(f, buf) {
  if (f === 'stdout') return Buffer.from(maskJson(buf.toString('utf8')))
  const b = Buffer.from(buf)
  if (/\.obj$/.test(f)) { maskCoff(b, 0); return b }
  if (/relinked\.exe$/.test(f)) return maskPE(b)
  if (/relinked\.map$/.test(f)) return Buffer.from(b.toString('latin1').replace(/Timestamp is [0-9a-f]{8} \([^)]*\)/, 'Timestamp is <masked>'), 'latin1')
  if (/\.lib$/.test(f)) return maskLib(b)
  if (/\.exp$/.test(f)) { maskCoff(b, 0); return b }
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
  b.decompiled = e.get('decompiled'); b.named = e.get('named'); b.reassembled = e.get('reassembled')
}
const MODULE_REPORTS = ['reports/game', 'reports/extracted']
const without = (list, ...drop) => list.filter((x) => !drop.includes(x))
const linksAll = () => [...new Set(['work/game', 'manifests', 'tools', 'extracted', 'decoded', 'reassembled', 'analysis',
  ...BINS.flatMap((b) => [b.decompiled, b.named])])]

// assembler caches for reassemble --cache and build --no-original (made once by Python when the project has none)
const seeds = {}
function seedCache(b) {
  if (seeds[b.name]) return seeds[b.name]
  const have = P.path('build', 'work', `asm_cache_${b.name}.json`)
  if (existsSync(have)) {
    seeds[b.name] = t('seeds', `asm_cache_${b.name}.json`)
    mkdirSync(t('seeds'), { recursive: true })
    cpSync(have, seeds[b.name])
    return seeds[b.name]
  }
  mkdirSync(t('seeds'), { recursive: true })
  seeds[b.name] = t('seeds', `asm_cache_${b.name}.json`)
  process.stderr.write(`[pipeline parity] seeding the assembler cache of ${b.name} (one cold Python build)\n`)
  spawnSync(P.python, ['-I', join(SK, 'reassemble.py'), 'build', P.path(b.reassembled), t('seeds', b.file), '--cache', seeds[b.name]],
    { cwd: ROOT, stdio: ['ignore', 'ignore', 'inherit'] })
  return seeds[b.name]
}

// --run: the save folder of the game must end as it was
const SAVE = join(homedir(), 'Documents', 'VVVVVV')
let saveBackup = null
if (opts.run && existsSync(SAVE)) {
  saveBackup = t('save_backup')
  cpSync(SAVE, saveBackup, { recursive: true, preserveTimestamps: true })
}

// ----------------------------------------------------------------------------------------------- scenarios
scenario('errors', { noProject: true }, [
  ['-h'], [], ['bogus'], ['build', '--mode', 'x'], ['init', '-h'], ['build', '-h'], ['reassemble', '-h'], ['intake'],
  ['--project'], ['decode', '--jobs', 'x'], ['status', '--project', t('nonexistent')], ['status', 'extra'],
  [`--project=${t('nonexistent')}`, 'status'], ['init'], ['match', '--units'],
].map((args) => ({ args, cwd: 'tmp', stderr: true, noSnap: true, cmd: 'errors', name: `argv ${JSON.stringify(args).replaceAll(P.tmp, 'TMP')}` })))

scenario('status_root', { noProject: true }, [{ args: ['--project', ROOT, 'status'], cwd: 'tmp', stderr: true, noSnap: true,
  name: 'status on PROJECT' }])

scenario('init', { noProject: true }, [
  { args: ['init', '--game', 'VVVVVV 2.4.4'], stderr: true, name: 'init in a missing folder' },
  { args: ['init', '--game', 'Other'], stderr: true, name: 'init again (refused)' },
  { args: ['init', '--force', '--game', 'Other 1.0'], stderr: true, name: 'init --force' },
  { args: ['status'], stderr: true, name: 'status of the new skeleton' },
])
scenario('init', { links: ['work/game'], cfg: false, files: { '.gitignore': '/build/\n# local\n*.log' } }, [
  { args: ['init', '--game', 'VVVVVV 2.4.4'], stderr: true, name: 'init with a game folder and a .gitignore' },
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

if (want('reassemble')) {
  scenario('reassemble', { links: linksAll(), dirs: ['build/work/reassemble'],
    before: () => { for (const b of BINS) cpSync(seedCache(b), join(PROJ, 'build', 'work', 'reassemble', `asm_cache_${b.name}.json`)) } }, [
    { args: ['reassemble', '--cache'], name: 'reassemble --cache (every binary, seeded caches)' },
    { args: ['reassemble', '--split'], stderr: true, name: 'reassemble --split (refused)' },
    { args: ['reassemble', '--binary', 'nope'], stderr: true },
    { args: ['status'], stderr: true },
  ])
}

const matching = BINS.filter((b) => b.matching)
scenario('skeleton', { links: without(linksAll(), 'decoded', 'extracted') }, [
  { args: ['skeleton'], stderr: true, name: 'skeleton into an empty src folder' },
  { args: ['skeleton'], stderr: true, name: 'skeleton again (refused)' },
])

scenario('features', { links: without(linksAll(), 'analysis', 'decoded', 'extracted') }, [
  { args: ['features'], name: 'features (every binary) into an empty analysis folder' },
])

scenario('names', { links: without(linksAll(), 'analysis', 'decoded', 'extracted'), dirs: ['analysis'] }, [
  { args: ['names'], stderr: true, name: 'names without names_apply.json' },
  { args: ['recover', '--binary', 'nope'], stderr: true },
])

const srcCopies = matching.map((b) => b.src)
const someUnits = (b) => readdirSync(P.path(b.src)).filter((f) => f.endsWith('.cpp')).sort().slice(0, 2).map((f) => f.slice(0, -4))
scenario('match', { links: without(linksAll(), 'decoded', 'extracted'), copies: [...srcCopies, ...MODULE_REPORTS] }, [
  { args: ['match'], name: 'match (the whole project)' },
  ...matching.map((b) => ({ args: ['match', '--binary', b.name, '--units', someUnits(b).join(',')], env: { SHOW_STUBS: '1' },
    name: `match --binary ${b.name} --units (2 units) with SHOW_STUBS=1` })),
  { args: ['status'], stderr: true },
])

if (want('build')) {
  const gameData = () => {         // --quick: the game's data files in build/game (the binaries are built)
    const bins = new Set(BINS.map((b) => b.file))
    for (const f of readdirSync(P.path('work', 'game'))) {
      if (bins.has(f)) continue
      cpSync(P.path('work', 'game', f), join(PROJ, 'build', 'game', f), { recursive: true, mode: constants.COPYFILE_FICLONE })
    }
  }
  scenario('build', { links: linksAll(), copies: [...srcCopies, ...MODULE_REPORTS], dirs: ['build/work', 'build/game'],
    before: () => {
      for (const b of matching) cpSync(seedCache(b), join(PROJ, 'build', 'work', `asm_cache_${b.name}.json`))
      if (opts.quick) gameData()
    } }, [
    opts.quick ? { args: ['build', '--mode', 'identical', '--skip-data'], name: 'build --mode identical --skip-data (game data present)' }
      : { args: ['build', '--mode', 'identical'], name: 'build --mode identical (with the data build)' },
    { args: ['build', '--mode', 'identical', '--skip-data', '--no-original', ...(opts.run ? ['--run'] : [])] },
    { args: ['verify'], stderr: true },
    { args: ['verify', '--out', 'build/missing'], stderr: true },
    { args: ['status'], stderr: true },
  ])
}

// ----------------------------------------------------------------------------------------------- end
if (saveBackup) {
  const same = spawnSync('diff', ['-r', saveBackup, SAVE]).status === 0
  if (!same) {
    rmSync(SAVE, { recursive: true, force: true })
    cpSync(saveBackup, SAVE, { recursive: true, preserveTimestamps: true })
  }
  P.notes.push(`~/Documents/VVVVVV ${same ? 'unchanged by the runs' : 'changed by the game runs: restored from the backup'}`)
}
const r2 = (x) => Math.round(x * 100) / 100
const perCommand = {}
for (const [k, v] of stats) perCommand[k] = { ...v, python_seconds: r2(v.python_seconds), js_seconds: r2(v.js_seconds) }
P.finish({ quick: opts.quick, per_command: perCommand })
