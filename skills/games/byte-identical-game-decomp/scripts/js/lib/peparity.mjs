// Shared helpers for the PE-tool parity tests (parity/reassemble.mjs, peek, rich_header, phase6_skeleton,
// code_coverage_check, build_features): run the Python script and the port, compare exit code, stdout,
// stderr (optional) and output files byte for byte, and print the one-line JSON summary.
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dumps } from './pyjson.mjs'

export const JS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const SK = resolve(JS_DIR, '..')

export function parseOpts(argv, defs) {
  const o = { ...defs }
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i]
    if (!k.startsWith('--')) continue
    const name = k.slice(2)
    if (typeof defs[name] === 'boolean') o[name] = true
    else o[name] = argv[++i]
  }
  return o
}

export class Parity {
  constructor(script, opts) {
    this.script = script
    this.root = resolve(opts.root ?? process.cwd())
    this.python = opts.python ?? 'python3'
    this.keep = Boolean(opts.keep)
    this.tmp = mkdtempSync(join(opts.tmp ?? tmpdir(), `parity_${script}_`))
    this.cases = 0
    this.identical = 0
    this.different = []
    this.notes = []
    this.pySec = 0
    this.jsSec = 0
  }
  path(...p) { return join(this.root, ...p) }
  tmpPath(...p) { return join(this.tmp, ...p) }

  // run one side; returns {rc, stdout, stderr, seconds}
  run(side, args, { env = {}, cwd = this.root, pyScript, jsScript } = {}) {
    const py = pyScript ?? join(SK, this.script + '.py')
    const js = jsScript ?? join(JS_DIR, this.script + '.mjs')
    const [cmd, argv] = side === 'py' ? [this.python, ['-I', py, ...args]] : [process.execPath, [js, ...args]]
    const t = process.hrtime.bigint()
    const p = spawnSync(cmd, argv, { cwd, env: { ...process.env, ...env }, maxBuffer: 1 << 30 })
    const seconds = Number(process.hrtime.bigint() - t) / 1e9
    if (side === 'py') this.pySec += seconds
    else this.jsSec += seconds
    if (p.error) throw p.error
    return { rc: p.status, stdout: p.stdout, stderr: p.stderr, seconds }
  }

  // record one case: diffs is a list of strings (empty = identical)
  record(name, diffs) {
    this.cases++
    if (!diffs.length) this.identical++
    else this.different.push({ case: name, diffs: diffs.slice(0, 20) })
    if (process.env.PARITY_VERBOSE) process.stderr.write(`${diffs.length ? 'DIFF' : 'ok  '} ${name}${diffs.length ? ': ' + diffs.slice(0, 3).join('; ') : ''}\n`)
  }

  // compare the results of both sides (and optionally output dirs/files)
  compare(name, a, b, { stderr = false, files = [], dirs = [], canon = null } = {}) {
    const diffs = []
    if (a.rc !== b.rc) diffs.push(`exit code python ${a.rc} js ${b.rc}`)
    const sa = canon ? canon('stdout', a.stdout) : a.stdout, sb = canon ? canon('stdout', b.stdout) : b.stdout
    if (!Buffer.from(sa).equals(Buffer.from(sb))) diffs.push(`stdout differs at byte ${firstDiff(sa, sb)}`)
    if (stderr && !a.stderr.equals(b.stderr)) diffs.push(`stderr differs at byte ${firstDiff(a.stderr, b.stderr)}`)
    for (const [fa, fb] of files) diffs.push(...compareFile(fa, fb, canon))
    for (const [da, db] of dirs) diffs.push(...compareDirs(da, db, canon))
    this.record(name, diffs)
    return diffs
  }

  finish(extra = {}) {
    if (!this.keep) rmSync(this.tmp, { recursive: true, force: true })
    const out = { script: this.script, cases: this.cases, identical: this.identical, different: this.different,
                  python_seconds: Math.round(this.pySec * 100) / 100, js_seconds: Math.round(this.jsSec * 100) / 100,
                  ...extra }
    if (this.notes.length) out.notes = this.notes
    if (this.keep) out.kept = this.tmp
    process.stdout.write(dumps(out) + '\n')
    process.exitCode = this.different.length || this.identical !== this.cases ? 1 : 0
  }
}

export function firstDiff(a, b) {
  const x = Buffer.from(a), y = Buffer.from(b)
  const n = Math.min(x.length, y.length)
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) return i
  return n
}

export function compareFile(fa, fb, canon = null) {
  const ea = existsSync(fa), eb = existsSync(fb)
  if (!ea || !eb) return ea === eb ? [] : [`${fa}: exists python ${ea} js ${eb}`]
  let a = readFileSync(fa), b = readFileSync(fb)
  if (canon) { a = Buffer.from(canon(fa, a)); b = Buffer.from(canon(fb, b)) }
  return a.equals(b) ? [] : [`${fb}: differs at byte ${firstDiff(a, b)} (python ${a.length} bytes, js ${b.length} bytes)`]
}

export function listFiles(dir) {
  const out = []
  const walk = (d, rel) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const r = rel ? rel + '/' + e.name : e.name
      if (e.isDirectory()) walk(join(d, e.name), r)
      else out.push(r)
    }
  }
  if (existsSync(dir) && statSync(dir).isDirectory()) walk(dir, '')
  return out.sort()
}

export function compareDirs(da, db, canon = null) {
  const fa = listFiles(da), fb = listFiles(db)
  const diffs = []
  const sb = new Set(fb), sa = new Set(fa)
  for (const f of fa) if (!sb.has(f)) diffs.push(`only python wrote ${f}`)
  for (const f of fb) if (!sa.has(f)) diffs.push(`only js wrote ${f}`)
  for (const f of fa) if (sb.has(f)) diffs.push(...compareFile(join(da, f), join(db, f), canon))
  return diffs
}
