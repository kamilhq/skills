#!/usr/bin/env node
// Parity test: js/objcmp_selftest.mjs against objcmp_selftest.py.
//
//   node parity/objcmp_selftest.mjs [--root PROJECT] [--python python3]
//
// Runs both self-tests on PROJECT/work/game/VVVVVV.exe with the same arguments, each with its own --work
// directory (the Python one drives objcmp.py, the JS one objcmp.mjs). Compared: exit code, stdout and stderr
// (with the work directory path replaced by <WORK>), and every file left in the work directories (objects
// written by write_obj, address map, functions.json, generated sources, report.json) byte for byte, text files
// after the same path replacement. Configurations: Ghidra index.json (both function lists), several --count
// values, the heuristic function finder (no --functions), and argument errors.
// Prints one JSON summary; exit 0 only when every case is identical.
import { spawn } from 'node:child_process'
import { readFileSync, mkdtempSync, rmSync, existsSync, readdirSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname, resolve, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const SK = resolve(HERE, '..', '..')
const PY_SCRIPT = join(SK, 'objcmp_selftest.py'), JS_SCRIPT = join(SK, 'js', 'objcmp_selftest.mjs')
const argv = process.argv.slice(2)
const opt = (name, def) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : def }
const ROOT = resolve(opt('--root', process.cwd()))
const PY = opt('--python', 'python3')
const EXE = 'work/game/VVVVVV.exe'
if (!existsSync(join(ROOT, EXE))) {
  process.stdout.write(JSON.stringify({ script: 'objcmp_selftest', error: `missing ${join(ROOT, EXE)} (use --root)` }) + '\n')
  process.exit(2)
}
const TMP = mkdtempSync(join(tmpdir(), 'parity_objcmp_selftest_'))
const env = { ...process.env }
delete env.COLUMNS
delete env.LINES

function run(cmd, args) {
  return new Promise((res) => {
    const t0 = process.hrtime.bigint()
    const p = spawn(cmd, args, { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] })
    const out = [], err = []
    p.stdout.on('data', (b) => out.push(b))
    p.stderr.on('data', (b) => err.push(b))
    p.on('close', (code) => res({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err),
                                  seconds: Number(process.hrtime.bigint() - t0) / 1e9 }))
  })
}
const listFiles = (d) => {
  if (!existsSync(d)) return []
  const out = []
  const walk = (p) => { for (const f of readdirSync(p)) { const q = join(p, f); if (statSync(q).isDirectory()) walk(q); else out.push(relative(d, q)) } }
  walk(d)
  return out.sort()
}
const norm = (buf, work) => Buffer.from(buf.toString('latin1').replaceAll(work, '<WORK>'), 'latin1')

const configs = [
  ['index.json (decompiled_exe)', ['--functions', 'decompiled_exe/index.json']],
  ['index.json (decompiled_named_exe) --count 30', ['--functions', 'decompiled_named_exe/index.json', '--count', '30']],
  ['--count 8', ['--functions', 'decompiled_exe/index.json', '--count', '8']],
  ['--count 45', ['--functions', 'decompiled_exe/index.json', '--count', '45']],
  ['heuristic function finder', []],
  ['heuristic --count 12', ['--count', '12']],
]
const errorCases = [['no arguments', []], ['-h', ['-h']], ['bad --count', [EXE, '--count', 'z']], ['missing pe', ['nonexistent.exe']],
  ['unknown option', [EXE, '--bogus']]]

async function main() {
  const results = []
  let k = 0
  for (const [name, extra] of configs) {
    const wp = join(TMP, `py${k}`), wj = join(TMP, `js${k}`)
    k++
    const [py, js] = await Promise.all([run(PY, ['-I', PY_SCRIPT, EXE, ...extra, '--work', wp]),
                                        run(process.execPath, [JS_SCRIPT, EXE, ...extra, '--work', wj])])
    const diffs = []
    if (py.code !== js.code) diffs.push(`exit ${py.code} vs ${js.code}`)
    if (!norm(py.stdout, wp).equals(norm(js.stdout, wj))) diffs.push('stdout differs')
    if (!norm(py.stderr, wp).equals(norm(js.stderr, wj))) diffs.push('stderr differs')
    const fp = listFiles(wp), fj = listFiles(wj)
    if (fp.join('\n') !== fj.join('\n')) diffs.push(`work files differ: ${fp.join(',')} vs ${fj.join(',')}`)
    else {
      for (const f of fp) {
        const a = readFileSync(join(wp, f)), b = readFileSync(join(wj, f))
        if (!a.equals(b) && !norm(a, wp).equals(norm(b, wj))) diffs.push(`${f} differs`)
      }
    }
    const passLine = py.stdout.toString().trim().split('\n').pop()
    results.push({ name, py, js, diffs, files: fp.length, passLine })
  }
  for (let [name, a] of errorCases) {
    const [py, js] = await Promise.all([run(PY, ['-I', PY_SCRIPT, ...a]), run(process.execPath, [JS_SCRIPT, ...a])])
    const diffs = []
    if (py.code !== js.code) diffs.push(`exit ${py.code} vs ${js.code}`)
    if (!py.stdout.equals(js.stdout)) diffs.push('stdout differs')
    if (!py.stderr.equals(js.stderr)) {
      // an uncaught exception: compare the exception line, not the traceback frames
      const last = (b) => b.toString().trimEnd().split('\n').pop()
      const tb = (b) => b.toString().startsWith('Traceback (most recent call last):')
      if (!(tb(py.stderr) && tb(js.stderr) && last(py.stderr) === last(js.stderr))) diffs.push('stderr differs')
      else name += ' (uncaught exception, compared without traceback frames)'
    }
    results.push({ name, py, js, diffs })
  }
  const different = results.filter((r) => r.diffs.length).map((r) => `${r.name}: ${r.diffs.join('; ')}`)
  const summary = { script: 'objcmp_selftest', cases: results.length, identical: results.length - different.length, different,
                    selftest_results: results.filter((r) => r.passLine).map((r) => `${r.name}: ${r.passLine}, ${r.files} work files compared`),
                    error_cases: results.filter((r) => !r.passLine).map((r) => r.name),
                    python_seconds: +results.reduce((s, r) => s + r.py.seconds, 0).toFixed(2),
                    js_seconds: +results.reduce((s, r) => s + r.js.seconds, 0).toFixed(2) }
  process.stdout.write(JSON.stringify(summary) + '\n')
  process.exitCode = different.length ? 1 : 0
}

main().finally(() => { if (!argv.includes('--keep')) rmSync(TMP, { recursive: true, force: true }) })
