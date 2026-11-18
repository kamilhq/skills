#!/usr/bin/env node
// Port of ../build_oracle.py (same command line, output and files). Runs the decomp skill's pipeline.mjs.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import * as L from './lib/rwlib.mjs'

const PROG = 'build_oracle'
const DOC = "Build the ORACLE: the original game rebuilt from its matched source plus the test hooks.\n\n  python3 -I build_oracle.py [--project DIR] [--out DIR] [--prepare-only]\n\nConfigured by decomp.json rewrite.oracle:\n  binary   the decomp.json binaries[].name that gets the hooks (default: the first with \"matching\": true)\n  dir      the oracle's own project folder (default build/oracle)\n  files    files to copy into the source copy (the hook code, e.g. a header built on harness/harness_core.h)\n  edits    a JSON file (or an inline list) of edits to the copied units:\n           [{\"unit\": \"217_main_loop.cpp\", \"desc\": \"...\", \"old\": \"exact text\", \"new\": \"replacement\",\n             \"count\": 1}]; every \"old\" must occur exactly \"count\" times (default 1), or nothing is built\n  exe      the built exe (default <dir>/game/<binary file>); record_oracle.py reads it\nSteps (the project's own source folder is never modified):\n  1. copy the binary's source (binaries[].src, else <paths.src>/<name>) to <dir>/src/<name>, add \"files\",\n     apply \"edits\" (line ends kept);\n  2. write <dir>/decomp.json: the project's config with every path pointing back to the project, except\n     the source of this binary (the copy), reports and build scratch (inside <dir>);\n  3. copy the game folder (paths.game) to --out (default <dir>/game) without the binary itself, and run the\n     decomp skill's `pipeline.py build --mode source --skip-data --project <dir> --out <out>`: edited\n     functions are linked from the copy's C++, everything else as in the source build.\nPrints a JSON summary (oracle exe, SHA-256, seconds, the pipeline's summary); exit 0 when the exe was built.\n--prepare-only stops after step 2. Python standard library only."
const PATH_DEFAULTS = {
  game: 'work/game', extracted: 'extracted', decoded: 'decoded', formats: 'tools/formats',
  analysis: 'analysis', work: 'work', manifest: 'manifests/game.json'
}
const REBASE_BIN = ['decompiled', 'named', 'reassembled', 'analysis', 'ghidra_project', 'src']
class Fail extends Error {}

function rebase (rel, p) { return L.expanduser(p).startsWith('/') ? p : L.normpath(L.join(rel, p)) }
function count (text, sub) { let n = 0; let i = 0; while ((i = text.indexOf(sub, i)) >= 0) { n++; i += sub.length } return n }

function prepare (project, cfg, rw, oracle) {
  const oc = rw.oracle || {}
  const bins = cfg.binaries || []
  const name = oc.binary || (bins.find(b => b.matching) || {}).name || null
  const binary = bins.find(b => b.name === name)
  if (!binary) throw new Fail(`no binary ${L.pyStr(name)} in decomp.json (rewrite.oracle.binary)`)
  const paths = cfg.paths || {}
  const srcDefault = paths.src || 'src_matched'
  const src = L.projectPath(project, binary.src || L.join(srcDefault, name))
  if (!L.isdir(src)) throw new Fail(`source folder ${src} not found`)
  const dst = L.join(oracle, 'src', name)
  if (fs.existsSync(dst)) L.rmtree(dst)
  L.copytree(src, dst)
  for (const f of oc.files || []) L.copy2(L.projectPath(project, f), L.join(dst, L.basename(f)))
  let edits = oc.edits || []
  if (typeof edits === 'string') edits = L.pyParse(fs.readFileSync(L.projectPath(project, edits), 'utf8'))
  const units = new Map()
  for (const e of edits) { if (!units.has(e.unit)) units.set(e.unit, []); units.get(e.unit).push(e) }
  for (const [unit, es] of units) {
    const p = L.join(dst, unit)
    if (!fs.existsSync(p)) throw new Fail(`edit unit ${unit} not found in ${src}`)
    let text = fs.readFileSync(p, 'utf8')
    const crlf = text.includes('\r\n')
    text = text.replaceAll('\r\n', '\n')
    for (const e of es) {
      const n = count(text, e.old)
      const want = e.count !== undefined ? e.count : 1
      if (n !== want) {
        throw new Fail(`edit "${e.desc !== undefined ? e.desc : e.old.slice(0, 40)}" in ${unit}: found ${n} times, expected ${want} (source changed?)`)
      }
      text = text.replaceAll(e.old, e.new)
    }
    if (crlf) text = text.replaceAll('\n', '\r\n')
    fs.writeFileSync(p, text)
  }
  const rel = L.relpath(L.abspath(project), L.abspath(oracle))
  const nw = L.pyParse(L.dumps(cfg))
  delete nw.rewrite
  const np = {}
  for (const [k, v] of Object.entries(paths)) np[k] = ['src', 'reports', 'build'].includes(k) ? v : rebase(rel, v)
  for (const [k, v] of Object.entries(PATH_DEFAULTS)) if (!(k in np)) np[k] = rebase(rel, v)
  np.src = 'src'; np.reports = 'reports'; np.build = 'build'
  nw.paths = np
  for (const b of nw.binaries || []) {
    for (const k of REBASE_BIN) if (k in b) b[k] = rebase(rel, b[k])
    if (b.name === name) b.src = 'src/' + name
    else if (!('src' in b)) b.src = rebase(rel, L.join(srcDefault, b.name))
  }
  fs.writeFileSync(L.join(oracle, 'decomp.json'), L.dumps(nw) + '\n')
  return [binary, dst, edits.length]
}

function walkFiles (dir, rel = '') {
  const out = []
  for (const n of fs.readdirSync(L.join(dir, rel) || '.')) {
    const r = rel ? L.join(rel, n) : n
    if (L.isdir(L.join(dir, r))) out.push(...walkFiles(dir, r))
    else out.push(r)
  }
  return out
}

export function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [['--project', 'str', '.'], ['--out', 'str', null], ['--prepare-only', 'flag', false]])
  const project = a.project
  const [cfg, rw] = L.loadConfig(project)
  const oc = rw.oracle || {}
  const oracle = L.projectPath(project, oc.dir || 'build/oracle')
  L.makedirs(oracle)
  let binary, dst, nedits
  try {
    [binary, dst, nedits] = prepare(project, cfg, rw, oracle)
  } catch (e) {
    if (!(e instanceof Fail)) throw e
    process.stderr.write(`${PROG}: ${e.message}\n`)
    return 1
  }
  process.stderr.write(`harness source set: ${L.relpath(dst, project)} (${nedits} edits)\n`)
  if (a.prepare_only) {
    process.stdout.write(L.dumps(new Map([['ok', true], ['prepared', L.relpath(oracle, project)], ['edits', nedits]])) + '\n')
    return 0
  }
  const out = L.abspath(a.out || L.join(oracle, 'game'))
  const game = L.projectPath(project, L.get(cfg, 'paths.game', 'work/game'))
  const exeName = binary.file
  for (const relp of walkFiles(game)) {
    if (relp === exeName) continue
    const s = L.join(game, relp); const d = L.join(out, relp)
    L.makedirs(L.dirname(d))
    if (!fs.existsSync(d) || fs.statSync(d).size !== fs.statSync(s).size) L.copy2(s, d)
  }
  const exe = L.join(out, exeName)
  if (fs.existsSync(exe)) fs.rmSync(exe)
  const ds = L.findDecompScripts(project, rw)
  if (!ds) {
    process.stderr.write(`${PROG}: byte-identical-game-decomp scripts not found (DECOMP_SCRIPTS)\n`)
    return 1
  }
  const t0 = Date.now()
  const c = spawnSync(process.execPath, [L.join(ds, 'js', 'pipeline.mjs'), 'build', '--mode', 'source', '--skip-data',
    '--project', oracle, '--out', out], { cwd: project, encoding: 'utf8', maxBuffer: 1 << 28 })
  fs.writeFileSync(L.join(oracle, 'build.log'), c.stderr || '')
  let res
  try { res = L.pyParse(c.stdout) } catch { res = new Map([['error', 'no JSON from pipeline.mjs'], ['stdout', (c.stdout || '').slice(-2000)]]) }
  const ok = c.status === 0 && fs.existsSync(exe)
  const summary = new Map([['oracle_exe', L.relpath(exe, project)], ['ok', ok], ['seconds', Math.round((Date.now() - t0) / 1000)],
    ['pipeline', res], ['log', L.relpath(L.join(oracle, 'build.log'), project)]])
  if (ok) summary.set('sha256', L.sha256File(exe))
  process.stdout.write(L.dumps(summary) + '\n')
  if (!ok) process.stderr.write((c.stderr || '').slice(-4000))
  return ok ? 0 : 1
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
