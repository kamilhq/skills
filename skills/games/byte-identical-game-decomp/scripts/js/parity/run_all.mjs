#!/usr/bin/env node
// Runs every parity test: the skill's (this folder) and the project's (PROJECT/tools/js/parity, when present),
// one after the other from PROJECT, and prints a combined summary. Exit 0 only when every test exits 0.
//
//   node parity/run_all.mjs [--root PROJECT] [--quick] [--only NAME ...] [--skip NAME ...] [--list]
//                           [--python python3] [--installer setup_x.exe ...]
//
// PROJECT defaults to the current directory. Not tests, so not run: intake_harness.mjs and formats_lib.mjs
// (helper modules), formats_all.mjs (runs text/png/wav/music/level/hashdb/png_deflate, which run_all runs
// itself) and run_all.mjs. NAME is a test's file name without .mjs, optionally prefixed "skill:" or "project:".
// --quick is passed to the tests that take it (their usage line shows [--quick]); --python to those that take
// --python; --installer (repeatable) to those that take --installer (inno, intake, lzma: without it they run their
// installer-free cases only). Each test's stdout (its JSON summary) is printed as it finishes; its stderr passes
// through (set PARITY_VERBOSE=1 for per-case lines). The last thing printed is the combined summary:
// {"script": "run_all", "tests": [...], "cases", "identical", "failed", "python_seconds", "js_seconds",
//  "seconds", "all_passed"}.
import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { dumps } from '../lib/pyjson.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const NOT_TESTS = new Set(['run_all.mjs', 'intake_harness.mjs', 'formats_lib.mjs', 'formats_all.mjs'])

function usage(msg) {
  process.stderr.write(`${msg}\nusage: run_all.mjs [--root PROJECT] [--quick] [--only NAME ...] [--skip NAME ...] ` +
    '[--list] [--python python3] [--installer setup_x.exe ...]\n')
  process.exit(2)
}

const a = { root: process.cwd(), quick: false, list: false, only: [], skip: [], python: null, installer: [] }
const argv = process.argv.slice(2)
for (let i = 0; i < argv.length; i++) {
  const k = argv[i]
  const val = () => (i + 1 < argv.length ? argv[++i] : usage(`${k} needs a value`))
  if (k === '--quick') a.quick = true
  else if (k === '--list') a.list = true
  else if (k === '--root') a.root = val()
  else if (k === '--python') a.python = val()
  else if (k === '--only') a.only.push(val())
  else if (k === '--skip') a.skip.push(val())
  else if (k === '--installer') a.installer.push(path.resolve(val()))
  else if (k === '-h' || k === '--help') { process.stdout.write(readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\nimport ')[0].replace(/^#!.*\n/, '').replace(/^\/\/ ?/gm, '')); process.exit(0) }
  else usage(`unknown argument ${k}`)
}
const ROOT = path.resolve(a.root)

const tests = []
for (const [group, dir] of [['skill', HERE], ['project', path.join(ROOT, 'tools', 'js', 'parity')]]) {
  if (!existsSync(dir) || (group === 'project' && path.resolve(dir) === HERE)) continue
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.mjs') && !NOT_TESTS.has(x)).sort()) {
    tests.push({ group, name: f.slice(0, -4), file: path.join(dir, f) })
  }
}
const matches = (t, names) => names.some((n) => n === t.name || n === `${t.group}:${t.name}`)
const selected = tests.filter((t) => (!a.only.length || matches(t, a.only)) && !matches(t, a.skip))
for (const n of [...a.only, ...a.skip]) {
  if (!tests.some((t) => matches(t, [n]))) usage(`no parity test named ${n}`)
}
if (a.list) {
  for (const t of selected) process.stdout.write(`${t.group}:${t.name}\t${path.relative(ROOT, t.file)}\n`)
  process.exit(0)
}

// the last JSON object a test printed (most print one line; some print several or an indented one)
function summaryOf(text) {
  const s = text.trim()
  try { return JSON.parse(s) } catch {}
  const lines = s.split('\n')
  for (let i = lines.length - 1; i >= 0; i--) {
    try { const v = JSON.parse(lines[i]); if (v && typeof v === 'object') return v } catch {}
  }
  for (let i = s.lastIndexOf('\n{'); i >= 0; i = s.lastIndexOf('\n{', i - 1)) {
    try { return JSON.parse(s.slice(i + 1)) } catch {}
    if (i === 0) break
  }
  return null
}

const results = []
const t0 = Date.now()
selected.forEach((t, k) => {
  const src = readFileSync(t.file, 'utf8')
  const args = []
  if (a.quick && /\[--quick\]|['"]--quick['"]/.test(src)) args.push('--quick')
  if (a.python && /--python\b/.test(src)) args.push('--python', a.python)
  if (/['"\[]--installer\b/.test(src)) for (const f of a.installer) args.push('--installer', f)
  process.stderr.write(`[${k + 1}/${selected.length}] ${t.group}:${t.name} ${args.join(' ')}\n`)
  const s0 = Date.now()
  const r = spawnSync(process.execPath, [t.file, ...args], { cwd: ROOT, stdio: ['ignore', 'pipe', 'inherit'],
    maxBuffer: 1 << 30, encoding: 'utf8' })
  const seconds = Math.round((Date.now() - s0) / 100) / 10
  process.stdout.write(r.stdout.endsWith('\n') || !r.stdout ? r.stdout : r.stdout + '\n')
  const s = summaryOf(r.stdout || '') || {}
  const passed = r.status === 0
  results.push({ test: `${t.group}:${t.name}`, args, exit: r.status, passed, cases: s.cases ?? null,
    identical: s.identical ?? null, python_seconds: s.python_seconds ?? null, js_seconds: s.js_seconds ?? null, seconds })
})
const tot = (key) => results.reduce((n, r) => n + Number(r[key] ?? 0), 0)
const r2 = (x) => Math.round(x * 100) / 100
const failed = results.filter((r) => !r.passed).map((r) => r.test)
process.stdout.write(dumps({ script: 'run_all', tests: results, cases: tot('cases'), identical: tot('identical'),
  failed, python_seconds: r2(tot('python_seconds')), js_seconds: r2(tot('js_seconds')),
  seconds: Math.round((Date.now() - t0) / 1000), all_passed: failed.length === 0 }, { indent: 1 }) + '\n')
process.exitCode = failed.length === 0 ? 0 : 1
