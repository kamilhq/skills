#!/usr/bin/env node
// Port of ../compare_traces.py (same command line, output and exit codes). Node built-ins only.
import fs from 'node:fs'
import * as L from './lib/rwlib.mjs'

const PROG = 'compare_traces'
const DOC = "Compare two per-frame state traces (references/harness.md \"Trace format\") frame by frame.\n\n  python3 -I compare_traces.py A.trace B.trace [--ignore F1,F2] [--only F1,F2] [--json OUT] [--show N]\n         [--quiet] [--project DIR]\n\nA is the reference (the oracle), B the program under test (the rewrite). A trace is a header line, then one\nline per logic frame: fields \"name=value\" separated by single spaces, in a fixed order, the frame number\nfirst. The project's decomp.json \"rewrite.trace\" section (optional) gives:\n  header       the required first line (else: B's first line must equal A's)\n  frame_field  name of the frame-number field (default \"f\")\n  fields       the contract's field order without the frame field; when set, a trace whose fields differ\n               from it is reported in \"format_errors\" and is not identical\n  decode       {field: \"f32\" | \"f64\"}: values that are IEEE-754 bit patterns (hex, comma-separated) are also\n               shown as numbers in the report\nPrints the first differing frame with every field that differs there (to stderr), then a JSON summary:\n  identical, frames_a, frames_b, compared_fields, ignored, first_diff_frame, first_diff {field: [A, B]},\n  differing_frames, fields {field: {\"first\", \"count\"}}, only_in_a / only_in_b {\"first\", \"count\"},\n  unknown_fields (in one trace only), format_errors.\n--show N also prints the next N differing frames. Exit 0 identical, 1 different, 2 bad input.\nPython standard library only."

export class TraceError extends Error {}

const STRERROR = { ENOENT: 'No such file or directory', EACCES: 'Permission denied', EISDIR: 'Is a directory' }

export function parse (p, header = null, frameField = 'f') {
  let text
  try {
    text = fs.readFileSync(p).toString('utf8')
  } catch (e) {
    throw new TraceError(`${p}: ${STRERROR[e.code] || e.message}`)
  }
  const lines = text.split('\n')
  const head = lines.length ? lines[0].replace(/\r$/, '') : ''
  if (!head) throw new TraceError(`${p}: no header line`)
  if (header !== null && head !== header) throw new TraceError(`${p}: first line is not "${header}"`)
  const frames = []; const rows = new Map(); const order = []
  for (let idx = 1; idx < lines.length; idx++) {
    const n = idx + 1
    const line = lines[idx].replace(/\r$/, '')
    if (!line) continue
    const row = new Map()
    for (const tok of line.split(' ')) {
      const eq = tok.indexOf('=')
      if (eq < 0) throw new TraceError(`${p}:${n}: field without "=": ${tok}`)
      const k = tok.slice(0, eq); const v = tok.slice(eq + 1)
      if (row.has(k)) throw new TraceError(`${p}:${n}: field ${k} twice`)
      row.set(k, v)
      if (!order.includes(k)) order.push(k)
    }
    if (!row.has(frameField)) throw new TraceError(`${p}:${n}: no frame number (${frameField}=)`)
    if (!L.INT_RE.test(row.get(frameField))) throw new TraceError(`${p}:${n}: bad frame number ${row.get(frameField)}`)
    const f = parseInt(row.get(frameField), 10)
    if (rows.has(f)) throw new TraceError(`${p}:${n}: frame ${f} twice`)
    if (frames.length && f <= frames[frames.length - 1]) {
      throw new TraceError(`${p}:${n}: frame ${f} after frame ${frames[frames.length - 1]}`)
    }
    frames.push(f)
    rows.set(f, row)
  }
  return [head, frames, rows, order]
}

const HEX_RE = /^\s*([+-]?)(0[xX])?([0-9a-fA-F]+(?:_[0-9a-fA-F]+)*)\s*$/
function decode (kind, value) {
  if ((kind !== 'f32' && kind !== 'f64') || value === null || value === undefined || value === '-') return value
  const out = []
  for (const x of value.split(',')) {
    const m = HEX_RE.exec(x)
    if (!m) return value
    let n = BigInt('0x' + m[3].replaceAll('_', ''))
    if (m[1] === '-') n = -n
    const b = Buffer.alloc(8)
    if (kind === 'f32') {
      if (n < 0n || n > 0xffffffffn) return value
      b.writeUInt32LE(Number(n))
      out.push(L.floatRepr(b.readFloatLE(0)))
    } else {
      if (n < 0n || n > 0xffffffffffffffffn) return value
      b.writeBigUInt64LE(n)
      out.push(L.floatRepr(b.readDoubleLE(0)))
    }
  }
  return out.join(',')
}

function formatErrors (name, order, ff, fields) {
  const want = [ff, ...fields]
  if (order.length === want.length && order.every((x, i) => x === want[i])) return []
  for (let i = 0; i < Math.max(order.length, want.length); i++) {
    const got = i < order.length ? order[i] : '(none)'
    const exp = i < want.length ? want[i] : '(none)'
    if (got !== exp) return [`${name}: field ${i + 1} is ${got}, the contract says ${exp}`]
  }
  return []
}

export function compare (aPath, bPath, ignore = new Set(), only = null, rw = {}) {
  const header = L.get(rw, 'trace.header')
  const ff = L.get(rw, 'trace.frame_field', 'f')
  const [ha, fa, ra, oa] = parse(aPath, header, ff)
  const [, fb, rb, ob] = parse(bPath, header !== null ? header : ha, ff)
  const order = [...oa, ...ob.filter(k => !oa.includes(k))]
  const fields = order.filter(k => k !== ff && !ignore.has(k) && (only === null || only.has(k)))
  const common = fa.filter(f => rb.has(f))
  const onlyA = fa.filter(f => !rb.has(f))
  const onlyB = fb.filter(f => !ra.has(f))
  const per = new Map(); const diffs = []
  for (const f of common) {
    const d = new Map()
    for (const k of fields) {
      const x = ra.get(f).has(k) ? ra.get(f).get(k) : null
      const y = rb.get(f).has(k) ? rb.get(f).get(k) : null
      if (x !== y) {
        d.set(k, [x, y])
        if (!per.has(k)) per.set(k, new Map([['first', f], ['count', 0]]))
        per.get(k).set('count', per.get(k).get('count') + 1)
      }
    }
    if (d.size) diffs.push([f, d])
  }
  let first = diffs.length ? diffs[0][0] : null
  let firstD = diffs.length ? diffs[0][1] : new Map()
  const ends = [onlyA, onlyB].filter(x => x.length).map(x => x[0])
  if (ends.length && (first === null || Math.min(...ends) < first)) {
    first = Math.min(...ends)
    firstD = new Map([[ff, [ra.has(first) ? 'present' : 'missing', rb.has(first) ? 'present' : 'missing']]])
  }
  let errs = []
  const want = L.get(rw, 'trace.fields')
  if (want && want.length) errs = [...formatErrors('A', oa, ff, want), ...formatErrors('B', ob, ff, want)]
  const sa = new Set(oa); const sb = new Set(ob)
  const unknown = [...oa.filter(k => !sb.has(k)), ...ob.filter(k => !sa.has(k))].sort(L.cmp)
  const summary = new Map([
    ['a', aPath], ['b', bPath],
    ['identical', !diffs.length && !onlyA.length && !onlyB.length && !errs.length],
    ['frames_a', fa.length], ['frames_b', fb.length], ['compared_fields', fields], ['ignored', [...ignore].sort(L.cmp)],
    ['first_diff_frame', first], ['first_diff', firstD], ['differing_frames', diffs.length], ['fields', per],
    ['only_in_a', onlyA.length ? new Map([['first', onlyA[0]], ['count', onlyA.length]]) : null],
    ['only_in_b', onlyB.length ? new Map([['first', onlyB[0]], ['count', onlyB.length]]) : null],
    ['unknown_fields', unknown], ['format_errors', errs]])
  return [summary, diffs]
}

function showFrame (f, d, dec, out) {
  out.push(`frame ${f}:\n`)
  for (const [k, [x, y]] of d) {
    const dx = decode(dec[k], x); const dy = decode(dec[k], y)
    const extra = (dx !== x || dy !== y) ? `   (${L.pyStr(dx)} | ${L.pyStr(dy)})` : ''
    out.push(`  ${L.ljust(k, 7)} A=${L.pyStr(x)}  B=${L.pyStr(y)}${extra}\n`)
  }
}

export function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [
    ['--ignore', 'str', ''], ['--only', 'str', null], ['--json', 'str', null], ['--show', 'int', 0],
    ['--quiet', 'flag', false], ['--project', 'str', '.']], [['a', '1'], ['b', '1']])
  let rw
  try {
    rw = L.loadConfig(a.project)[1]
  } catch {
    process.stdout.write(L.dumps({ error: 'decomp.json cannot be read or is not valid JSON' }) + '\n')
    return 2
  }
  const ignore = new Set(a.ignore.split(',').filter(Boolean))
  const only = a.only ? new Set(a.only.split(',').filter(Boolean)) : null
  let summary, diffs
  try {
    [summary, diffs] = compare(a.a, a.b, ignore, only, rw)
  } catch (e) {
    if (!(e instanceof TraceError)) throw e
    process.stdout.write(L.dumps({ error: e.message }) + '\n')
    return 2
  }
  const dec = L.get(rw, 'trace.decode') || {}
  if (!a.quiet) {
    const err = []
    for (const e of summary.get('format_errors')) err.push(`format: ${e}\n`)
    if (summary.get('identical')) err.push(`identical: ${summary.get('frames_a')} frames\n`)
    else if (summary.get('first_diff_frame') !== null) {
      const f = summary.get('first_diff_frame')
      err.push(`first difference at frame ${f}\n`)
      if (diffs.length && diffs[0][0] === f) showFrame(f, diffs[0][1], dec, err)
      else {
        const ab = [...summary.get('first_diff').values()][0]
        err.push(`  frame ${f} is ${ab[0]} in A, ${ab[1]} in B\n`)
      }
      for (const [f2, d] of diffs.slice(1, 1 + a.show)) showFrame(f2, d, dec, err)
      err.push(`${summary.get('differing_frames')} differing frame(s); fields: ` +
        [...summary.get('fields')].map(([k, v]) => `${k} (from ${v.get('first')}, ${v.get('count')}x)`).join(', ') + '\n')
    }
    process.stderr.write(err.join(''))
  }
  const js = L.dumps(summary)
  if (a.json) fs.writeFileSync(a.json, js + '\n')
  process.stdout.write(js + '\n')
  return summary.get('identical') ? 0 : 1
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
