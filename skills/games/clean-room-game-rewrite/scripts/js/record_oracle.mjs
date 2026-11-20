#!/usr/bin/env node
// Port of ../record_oracle.py (same command line, output and exit codes). Node built-ins only.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import * as L from './lib/rwlib.mjs'
import { compare, parse } from './compare_traces.mjs'

const PROG = 'record_oracle'
const DOC = "Record the oracle's trace for every scenario and prove it is deterministic.\n\n  python3 -I record_oracle.py [--exe EXE] [--runs N] [--out DIR] [--game DIR] [--tries N] [--settle S]\n         [--runner wine|native] [--project DIR] [SCENARIO ...]\n\nEach scenario (default: every *.txt in rewrite.scenarios) runs --runs times (default 2; use 3 or more for the\nrecord) through run_scenario.py. Every run's trace and save folder must be byte-identical to the first run's.\nThen the first run's trace is written to <out>/<scenario>.trace and its save files to <out>/<scenario>.saves/,\nand <out>/determinism.json records, per scenario and run: frames, tries, seconds per try, SHA-256 of the\ntrace and of each save file, the comparison with run 1, and the oracle exe's SHA-256. Scenarios that are\nnot deterministic are not written (their entry says why). --exe defaults to rewrite.oracle.exe, --out to\nrewrite.oracle.traces (default: the \"oracle\" folder next to the scenarios folder).\nPrints a JSON summary {scenario: {deterministic, frames}}; exit 0 when every scenario is deterministic.\nPython standard library only."

function stamp () {
  const d = new Date()
  const p = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

export function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [
    ['--exe', 'str', null], ['--runs', 'int', 2], ['--out', 'str', null], ['--game', 'str', null],
    ['--tries', 'int', null], ['--settle', 'str', null], ['--runner', 'str', null], ['--project', 'str', '.']],
  [['scenarios', '*']])
  const project = a.project
  const rw = L.loadConfig(project)[1]
  const exe = a.exe || L.projectPath(project, L.get(rw, 'oracle.exe'))
  if (!exe || !L.isfile(exe)) {
    process.stdout.write(L.dumps({ error: `no oracle exe (--exe or rewrite.oracle.exe): ${L.pyStr(exe)}` }) + '\n')
    return 2
  }
  const scenDir = L.projectPath(project, rw.scenarios || 'rewrite/harness/scenarios')
  const scen = a.scenarios.length ? a.scenarios
    : (L.isdir(scenDir) ? L.listdirSorted(scenDir).filter(n => n.endsWith('.txt') && !n.startsWith('.')).map(n => L.join(scenDir, n)).sort(L.cmp) : [])
  if (!scen.length) {
    process.stdout.write(L.dumps({ error: `no scenarios in ${scenDir}` }) + '\n')
    return 2
  }
  const outdir = a.out || L.projectPath(project, L.get(rw, 'oracle.traces')) || L.join(L.dirname(scenDir), 'oracle')
  L.makedirs(outdir)
  const repPath = L.join(outdir, 'determinism.json')
  let report = {}
  if (fs.existsSync(repPath)) report = L.pyParse(fs.readFileSync(repPath, 'utf8'))
  report.exe_sha256 = L.sha256File(exe)
  if (!report.scenarios) report.scenarios = {}
  const passthru = ['--project', project]
  for (const k of ['game', 'tries', 'settle', 'runner']) if (a[k] !== null) passthru.push('--' + k, String(a[k]))
  let allOk = true
  const tmp = L.mkdtemp('rewrite_record_')
  try {
    for (const s of scen) {
      const name = L.splitext(L.basename(s))[0]
      const runs = []
      for (let r = 0; r < a.runs; r++) {
        const tr = L.join(tmp, `${name}.${r}.trace`)
        const sv = L.join(tmp, `${name}.${r}.saves`)
        const c = spawnSync(process.execPath, [L.join(L.JS_DIR, 'run_scenario.mjs'), '--exe', exe, '--scenario', s,
          '--out', tr, '--saves-out', sv, ...passthru], { encoding: 'utf8', maxBuffer: 1 << 28 })
        let res
        try { res = L.pyParse(c.stdout) } catch { res = { ok: false } }
        const triesList = res.tries || []
        const row = new Map([['ok', Boolean(res.ok)], ['tries', triesList.length],
          ['seconds', triesList.map(t => (t.seconds !== undefined ? t.seconds : null))]])
        if (row.get('ok')) {
          row.set('frames', parse(tr)[1].length)
          row.set('trace_sha256', L.sha256File(tr))
          const saves = new Map()
          if (L.isdir(sv)) for (const f of L.listdirSorted(sv)) saves.set(f, L.sha256File(L.join(sv, f)))
          row.set('saves', saves)
        } else row.set('error', res.error || (c.stderr || '').slice(-500))
        runs.push(row)
        process.stderr.write(`${name} run ${r + 1}: ${row.get('ok') ? `ok, ${row.get('frames')} frames` : 'FAILED'}\n`)
      }
      let ok = runs.every(x => x.get('ok'))
      let det = null
      if (ok) {
        const ref = L.join(tmp, `${name}.0.trace`)
        det = []
        const same = (x, y) => L.dumps(x) === L.dumps(y)
        for (let r = 1; r < a.runs; r++) {
          const summ = compare(ref, L.join(tmp, `${name}.${r}.trace`))[0]
          det.push(new Map([['run', r + 1], ['identical', summ.get('identical')], ['first_diff_frame', summ.get('first_diff_frame')],
            ['same_saves', same(runs[r].get('saves'), runs[0].get('saves'))]]))
        }
        ok = det.every(d => d.get('identical') && d.get('same_saves')) && new Set(runs.map(x => x.get('trace_sha256'))).size === 1
        if (ok) {
          L.copy2(ref, L.join(outdir, `${name}.trace`))
          const sd = L.join(outdir, `${name}.saves`)
          if (fs.existsSync(sd)) L.rmtree(sd)
          if (L.isdir(L.join(tmp, `${name}.0.saves`))) L.copytree(L.join(tmp, `${name}.0.saves`), sd)
        }
      }
      const rel = L.relpath(L.abspath(s), L.abspath(project))
      report.scenarios[name] = new Map([['scenario', rel], ['runs', runs], ['compared', det], ['deterministic', ok],
        ['recorded', stamp()]])
      allOk = allOk && ok
    }
  } finally {
    L.rmtree(tmp)
  }
  fs.writeFileSync(repPath, L.dumps(report) + '\n')
  const summary = new Map()
  for (const [k, v] of Object.entries(report.scenarios)) {
    const g = (o, key) => (o instanceof Map ? o.get(key) : o[key])
    summary.set(k, new Map([['deterministic', g(v, 'deterministic')],
      ['frames', g(v, 'runs').map(r => { const f = g(r, 'frames'); return f === undefined ? null : f })]]))
  }
  process.stdout.write(L.dumps(summary) + '\n')
  return allOk ? 0 : 1
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
