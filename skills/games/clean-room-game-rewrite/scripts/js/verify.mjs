#!/usr/bin/env node
// Round-trip verifier shared by every format decoder (step 3d). Port of verify.py.
//
// Contract for a format module  <formats_dir>/fmt_<name>.mjs :
//     export const EXTS = ['.ptx', ...]              // lower-case extensions handled (matched case-insensitively)
//     export function decode_to_dir(data, outdir)    // data: Buffer -> {opaque_bytes: N, notes: [...]}
//         Write the decoded, human-usable representation of `data` into `outdir`
//         (JSON / PNG / WAV / text / OBJ ...). N = number of source bytes stored without interpretation
//         (unknown fields kept as raw hex/blobs). N is reported, so be honest.
//     export function encode_from_dir(outdir)        // -> Buffer
//         Rebuild the original file using ONLY what is in `outdir`. Never read the original file, never
//         read outside outdir, never stash a hash or a whole copy of the original.
//
// Check: encode_from_dir(decode_to_dir(x)) == x for every file, byte for byte (SHA-256), decoding into a fresh
// directory each time. Writes <report>/<module>.json with per-file results and exits non-zero on any failure.
//
// Usage:
//     node verify.mjs <module> --src <dir> [--formats-dir tools/js/formats] [--out decoded] [--report reports]
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { dump, dumps, pyFloat } from './lib/pyjson.mjs'
import { cmpStr, pyInt, pyJoin, pyRound, pySplitext } from './lib/pycompat.mjs'

const USAGE = `usage: verify.mjs [-h] --src SRC [--formats-dir FORMATS_DIR] [--out OUT]
                  [--report REPORT] [--limit LIMIT]
                  module
`
const HELP = USAGE + `
positional arguments:
  module

optional arguments:
  -h, --help            show this help message and exit
  --src SRC             directory tree holding the original files
  --formats-dir FORMATS_DIR
  --out OUT
  --report REPORT
  --limit LIMIT         debug: only the first N files
`

function argError(msg) {
  process.stderr.write(USAGE + `verify.mjs: error: ${msg}\n`)
  process.exit(2)
}

function parseArgs(argv) {
  const opts = { '--src': null, '--formats-dir': 'tools/js/formats', '--out': 'decoded', '--report': 'reports',
    '--limit': '0' }
  const names = Object.keys(opts)
  const positional = []
  const extra = []
  let onlyPos = false
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (onlyPos || !a.startsWith('-') || a === '-') { positional.push(a); continue }
    if (a === '--') { onlyPos = true; continue }
    if (a === '-h' || a === '--help' || (a.length > 2 && '--help'.startsWith(a) &&
        !names.some((n) => n.startsWith(a)))) {
      process.stdout.write(HELP)
      process.exit(0)
    }
    const eq = a.indexOf('=')
    const key = eq >= 0 ? a.slice(0, eq) : a
    let name = names.includes(key) ? key : null
    if (!name && key.startsWith('--')) {
      const cands = names.filter((n) => n.startsWith(key))
      if (cands.length > 1) {
        argError(`ambiguous option: ${key} could match ${cands.join(', ')}`)
      }
      if (cands.length === 1) name = cands[0]
    }
    if (!name) { extra.push(a); continue }
    let val
    if (eq >= 0) val = a.slice(eq + 1)
    else {
      val = argv[i + 1]
      if (val === undefined || (val.startsWith('-') && val !== '-')) argError(`argument ${name}: expected one argument`)
      i++
    }
    opts[name] = val
  }
  if (positional.length > 1) extra.push(...positional.slice(1))
  const missing = []
  if (!positional.length) missing.push('module')
  if (opts['--src'] === null) missing.push('--src')
  if (missing.length) argError(`the following arguments are required: ${missing.join(', ')}`)
  if (extra.length) argError(`unrecognized arguments: ${extra.join(' ')}`)
  let limit
  try {
    limit = Number(pyInt(opts['--limit']))
  } catch {
    argError(`argument --limit: invalid int value: '${opts['--limit']}'`)
  }
  return { module: positional[0], src: opts['--src'], formats_dir: opts['--formats-dir'], out: opts['--out'],
    report: opts['--report'], limit }
}

async function loadModule(formatsDir, name) {
  const p = path.resolve(formatsDir, `fmt_${name}.mjs`)
  return import(pathToFileURL(p).href)
}

function walkFiles(top) {
  // os.walk(top) (followlinks=False): files of every directory, not descending into symlinked dirs
  const out = []
  const visit = (dir) => {
    let ents
    try { ents = readdirSync(dir, { withFileTypes: true }) } catch { return }
    for (const e of ents) {
      const p = pyJoin(dir, e.name)
      let isDir = e.isDirectory()
      if (e.isSymbolicLink()) {
        try { isDir = statSync(p).isDirectory() } catch { isDir = false }
        if (isDir) continue
      }
      if (isDir) visit(p)
      else out.push([dir, e.name])
    }
  }
  visit(top)
  return out
}

const sha256 = (b) => createHash('sha256').update(b).digest('hex')

async function main() {
  const a = parseArgs(process.argv.slice(2))
  const mod = await loadModule(a.formats_dir, a.module)
  const exts = new Set(mod.EXTS.map((e) => e.toLowerCase()))
  let files = walkFiles(a.src).filter(([, f]) => exts.has(pySplitext(f)[1].toLowerCase()))
    .map(([r, f]) => pyJoin(r, f)).sort(cmpStr)
  if (a.limit) files = files.slice(0, a.limit)
  const res = { module: a.module, exts: [...exts].sort(cmpStr), src: path.basename(path.resolve(a.src)),
    files: files.length, passed: 0, failed: 0, total_bytes: 0, opaque_bytes: 0, failures: [], per_file: [] }
  const t0 = Date.now()
  for (const p of files) {
    const rel = path.relative(a.src, p)
    const outdir = pyJoin(a.out, a.module, rel)
    if (existsSync(outdir)) rmSync(outdir, { recursive: true })
    mkdirSync(outdir, { recursive: true })
    const data = readFileSync(p)
    const digest = sha256(data)
    res.total_bytes += data.length
    try {
      const info = mod.decode_to_dir(data, outdir) || {}
      const rebuilt = mod.encode_from_dir(outdir)
      const ok = sha256(rebuilt) === digest
      const opv = 'opaque_bytes' in info ? info.opaque_bytes : 0       // int(info.get('opaque_bytes', 0))
      if (opv === null || opv === undefined || Number.isNaN(Number(opv))) throw new TypeError(`int() argument: ${opv}`)
      const op = Math.trunc(Number(opv))
      res.opaque_bytes += op
      res.per_file.push({ file: rel, bytes: data.length, opaque: op, ok, sha256: digest })
      if (ok) res.passed += 1
      else {
        res.failed += 1
        const n = Math.min(data.length, rebuilt.length)
        let first = 0
        while (first < n && data[first] === rebuilt[first]) first++
        res.failures.push({ file: rel, error: 'mismatch', orig_len: data.length, rebuilt_len: rebuilt.length,
          first_diff: first })
      }
    } catch (e) {
      res.failed += 1
      res.failures.push({ file: rel, error: String((e && e.stack) || e).slice(-1500) })
    }
  }
  res.seconds = pyFloat(pyRound((Date.now() - t0) / 1000, 1))
  res.opaque_ratio = res.total_bytes ? pyFloat(pyRound(res.opaque_bytes / res.total_bytes, 6)) : 0
  mkdirSync(a.report, { recursive: true })
  dump(res, pyJoin(a.report, `${a.module}.json`), { indent: 1 })
  const summary = Object.fromEntries(Object.entries(res).filter(([k]) => k !== 'per_file'))
  summary.failures = res.failures.slice(0, 5)
  process.stdout.write(dumps(summary, { indent: 1 }) + '\n')
  process.exitCode = res.failed === 0 && res.files > 0 ? 0 : 1
}

await main()
