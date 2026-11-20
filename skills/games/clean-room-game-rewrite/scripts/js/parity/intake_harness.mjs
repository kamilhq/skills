// Shared helpers for the intake-group parity tests (lzma, bzip2, inno, intake, inventory and the project's
// tools/js/parity/{extract_archives,completeness}.mjs). Node built-ins only.
//
//   const h = new Harness('inno')          // collects cases, prints the JSON summary, exit code
//   h.run(cmd, args, opts) -> {code, stdout, stderr, seconds}       (spawnSync, Buffers)
//   h.compareRuns(name, py, js, {norm, files: [[pyPath, jsPath], ...], trees: [[pyDir, jsDir, {mtime}]]})
//   h.record(name, identical, detail)      // a case decided by the caller
//   snapshot(dir) / diffSnapshots(a, b, {mtime})   byte-for-byte tree comparison (type, size, SHA-256, mode, mtime ns)
//   h.tmp(prefix) -> new temp dir under os.tmpdir(), removed by h.finish() unless --keep
//   h.finish()                              // prints {"script","cases","identical","different",...}, exits

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dumps } from '../lib/pyjson.mjs'

export const SK = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')      // scripts/
export const JS = path.join(SK, 'js')
export const ROOT = path.resolve(SK, '../../../..')                                       // project root
export const NODE = process.execPath

export function argOpt(argv, name, def = null) {
  const i = argv.indexOf(name)
  if (i < 0) return def
  const v = argv[i + 1]
  argv.splice(i, 2)
  return v
}
export function argAll(argv, name) {
  const vals = []
  for (let i = argv.indexOf(name); i >= 0; i = argv.indexOf(name)) { vals.push(argv[i + 1]); argv.splice(i, 2) }
  return vals
}
export function argFlag(argv, name) {
  const i = argv.indexOf(name)
  if (i < 0) return false
  argv.splice(i, 1)
  return true
}

export const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex')

// replace timing values so runs compare: "seconds": 0.47 -> "seconds": T ; progress "..., 3s" -> "..., Ts"
export function normTiming(s) {
  return s.replace(/("seconds": )[0-9.eE+-]+/g, '$1T').replace(/(data entries, )\d+s$/gm, '$1Ts')
}
// Python tracebacks cannot be reproduced frame by frame: keep the header and the exception line
export function normTraceback(s) {
  const i = s.indexOf('Traceback (most recent call last):\n')
  if (i < 0) return s
  const lines = s.slice(i).trimEnd().split('\n')
  return s.slice(0, i) + 'Traceback (most recent call last):\n  ...\n' + lines[lines.length - 1] + '\n'
}

export function snapshot(dir) {
  const m = new Map()
  const rec = (rel) => {
    const p = rel ? path.join(dir, rel) : dir
    const st = fs.lstatSync(p, { bigint: true })
    const e = { mode: Number(st.mode), mtimeNs: st.mtimeNs.toString() }
    if (st.isSymbolicLink()) { e.type = 'link'; e.target = fs.readlinkSync(p) }
    else if (st.isDirectory()) {
      e.type = 'dir'
      for (const n of fs.readdirSync(p).sort()) rec(rel ? rel + '/' + n : n)
    } else { e.type = 'file'; e.size = Number(st.size); e.sha256 = sha256(fs.readFileSync(p)) }
    m.set(rel || '.', e)
  }
  if (fs.existsSync(dir)) rec('')
  return m
}
// differences between two snapshots; mtime: compare file mtimes (directory mtimes never compared)
export function diffSnapshots(a, b, { mtime = true, limit = 20 } = {}) {
  const d = []
  for (const [k, x] of a) {
    const y = b.get(k)
    if (!y) { d.push(`only in python: ${k}`); continue }
    if (x.type !== y.type) { d.push(`type ${k}: ${x.type} vs ${y.type}`); continue }
    if (x.type === 'file') {
      if (x.sha256 !== y.sha256 || x.size !== y.size) d.push(`content ${k}`)
      if (x.mode !== y.mode) d.push(`mode ${k}: ${x.mode.toString(8)} vs ${y.mode.toString(8)}`)
      if (mtime && x.mtimeNs !== y.mtimeNs) d.push(`mtime ${k}: ${x.mtimeNs} vs ${y.mtimeNs}`)
    } else if (x.type === 'dir') {
      if (x.mode !== y.mode) d.push(`mode ${k}: ${x.mode.toString(8)} vs ${y.mode.toString(8)}`)
    } else if (x.target !== y.target) d.push(`link ${k}`)
  }
  for (const k of b.keys()) if (!a.has(k)) d.push(`only in js: ${k}`)
  return d.slice(0, limit).concat(d.length > limit ? [`... ${d.length - limit} more`] : [])
}

export class Harness {
  constructor(script, argv = process.argv.slice(2)) {
    this.script = script
    this.argv = argv
    this.keep = argFlag(argv, '--keep')
    this.python = argOpt(argv, '--python', 'python3')
    this.cases = 0
    this.identical = 0
    this.different = []
    this.pySec = 0
    this.jsSec = 0
    this.tmps = []
    this.extra = {}
  }
  tmp(prefix = 'parity') {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), `${this.script}-${prefix}-`))
    this.tmps.push(d)
    return d
  }
  run(cmd, args, { cwd = ROOT, input, side } = {}) {
    const t0 = process.hrtime.bigint()
    const r = spawnSync(cmd, args, { cwd, input, maxBuffer: 1 << 30, env: { ...process.env, COLUMNS: '80' } })
    const seconds = Number(process.hrtime.bigint() - t0) / 1e9
    if (side === 'py') this.pySec += seconds
    if (side === 'js') this.jsSec += seconds
    if (r.error) throw r.error
    return { code: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr, seconds }
  }
  py(script, args, opts = {}) { return this.run(this.python, ['-I', script, ...args], { ...opts, side: 'py' }) }
  js(script, args, opts = {}) { return this.run(NODE, [script, ...args], { ...opts, side: 'js' }) }

  record(name, identical, detail = null) {
    this.cases++
    if (identical) this.identical++
    else this.different.push(detail ? { case: name, detail } : { case: name })
  }

  // compare two process results (exit code, stdout, stderr, files, trees)
  compareRuns(name, p, j, { norm = (s) => s, stderr = true, files = [], trees = [] } = {}) {
    const diffs = []
    if (p.code !== j.code) diffs.push(`exit ${p.code} vs ${j.code}`)
    const ps = norm(p.stdout.toString('utf8')), jss = norm(j.stdout.toString('utf8'))
    if (ps !== jss) diffs.push({ stdout: firstDiff(ps, jss) })
    if (stderr) {
      const pe = normTraceback(norm(p.stderr.toString('utf8'))), je = normTraceback(norm(j.stderr.toString('utf8')))
      if (pe !== je) diffs.push({ stderr: firstDiff(pe, je) })
    }
    for (const [a, b] of files) {
      const ea = fs.existsSync(a), eb = fs.existsSync(b)
      if (ea !== eb) diffs.push(`file presence ${path.basename(a)}: ${ea} vs ${eb}`)
      else if (ea && !fs.readFileSync(a).equals(fs.readFileSync(b))) diffs.push(`file ${path.basename(a)} differs`)
    }
    for (const [a, b, o = {}] of trees) {
      const d = diffSnapshots(snapshot(a), snapshot(b), o)
      if (d.length) diffs.push({ tree: d })
    }
    this.record(name, diffs.length === 0, diffs.length ? diffs : null)
    return diffs.length === 0
  }

  finish(extra = {}) {
    if (!this.keep) for (const d of this.tmps) fs.rmSync(d, { recursive: true, force: true })
    const s = { script: this.script, cases: this.cases, identical: this.identical, different: this.different,
      python_seconds: +this.pySec.toFixed(2), js_seconds: +this.jsSec.toFixed(2), ...this.extra, ...extra }
    process.stdout.write(dumps(s, { indent: 1 }) + '\n')
    process.exitCode = this.cases > 0 && this.identical === this.cases ? 0 : 1
  }
}

export function firstDiff(a, b) {
  let i = 0
  while (i < a.length && i < b.length && a[i] === b[i]) i++
  return { at: i, python: a.slice(Math.max(0, i - 40), i + 80), js: b.slice(Math.max(0, i - 40), i + 80) }
}
