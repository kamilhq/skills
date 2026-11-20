#!/usr/bin/env node
// Parity test: peek.py vs js/peek.mjs.
//
//   node parity/peek.mjs [--root PROJECT] [--python python3] [--labels N] [--keep]
//
// Cases (per binary of PROJECT/decomp.json, with its named decompile; exit 2 without one): one invocation per
// address group, compared line by
// line: Ghidra labels taken from the decompiled pseudocode (s_..., u_..., DAT_..., PTR_..., up to --labels per
// binary; these hit the cp1252 string, UTF-16 and raw-byte branches), every section start/end/last byte, the
// uninitialised tail of sections whose virtual size exceeds their raw size, headers, addresses below the image
// base and outside every section, bare/0x hex forms. Plus the error paths: no arguments (exit 1, docstring),
// a missing file / a non-PE file / a truncated PE (exit 2), malformed addresses (exit 2).
// Plus one case for the Unicode table behind repr(): lib/pytools.mjs embeds Python 3.9's str.isprintable()
// (Unicode 13) because Node's own tables are newer (random bytes decoded as UTF-16 do hit code points assigned
// since); the case compares that table with the str.isprintable() of the Python used, for all code points.
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { Parity, parseOpts, projectBinaries } from '../lib/peparity.mjs'
import { sections } from '../peek.mjs'
import { isPrintable } from '../lib/pytools.mjs'

const opts = parseOpts(process.argv.slice(2), { root: undefined, python: undefined, labels: '600', keep: false })
const P = new Parity('peek', opts)
const NL = Number(opts.labels)

function labelsFrom(dir) {
  const out = new Set()
  const fdir = join(dir, 'functions')
  if (!existsSync(fdir)) return []
  const re = /(?<![\w])(?:s_[A-Za-z0-9_]{1,60}?_|u_[A-Za-z0-9_]{1,60}?_|DAT_|PTR_[A-Za-z0-9_]*?_)([0-9a-f]{8})(?![\w])/g
  for (const f of readdirSync(fdir).sort()) {
    if (!f.endsWith('.c')) continue
    for (const m of readFileSync(join(fdir, f), 'latin1').matchAll(re)) out.add(m[0])
    if (out.size >= NL) break
  }
  return [...out].slice(0, NL)
}

function cmpLines(name, a, b) {
  // one case per address line plus one for exit code / stderr
  const la = a.stdout.toString('utf8').split('\n'), lb = b.stdout.toString('utf8').split('\n')
  const n = Math.max(la.length, lb.length)
  for (let i = 0; i < n; i++) {
    if (la[i] === '' && lb[i] === '' && i === n - 1) continue
    P.record(`${name} line ${i}: ${(la[i] ?? lb[i] ?? '').split(' ')[0]}`, la[i] === lb[i] ? [] : [`python ${JSON.stringify(la[i])} js ${JSON.stringify(lb[i])}`])
  }
  P.compare(`${name} (exit code, whole stdout, stderr)`, a, b, { stderr: true })
}

const bins = projectBinaries(P.root, { script: 'peek' })
for (const { file: bin, abs } of bins) {
  const exe = abs.exe, dd = abs.named
  if (!existsSync(exe)) { P.notes.push(`${exe} missing: skipped`); continue }
  const d = readFileSync(exe)
  const [base, hdrs, secs] = sections(d)
  const lab = labelsFrom(dd)
  const addrs = []
  const hx = (v) => '0x' + v.toString(16)
  addrs.push(hx(base), hx(base + 0x3c), (base + 0x40).toString(16), hx(base + hdrs - 1), hx(base + hdrs), '0x10', '0', hx(base - 1))
  let top = 0
  for (const [, vs, sva, rs] of secs) {
    addrs.push(hx(base + sva), hx(base + sva + 1), hx(base + sva + rs - 1), hx(base + sva + rs), hx(base + sva + Math.max(vs, rs) - 1),
               hx(base + sva + Math.max(vs, rs)), hx(base + sva + 0x100), hx(base + sva + 0x1234))
    if (vs > rs) addrs.push(hx(base + sva + rs + 8))
    top = Math.max(top, sva + Math.max(vs, rs))
  }
  addrs.push(hx(base + top + 0x1000), 'ffffffff', '0xFFFFFFF0', `DAT_${(base + 0x1000).toString(16).padStart(8, '0')}`)
  // strided scan through every section: many short strings, UTF-16 runs and raw bytes
  for (const [, vs, sva, rs] of secs) for (let o = 0; o < Math.max(vs, rs); o += Math.max(0x40, Math.floor(Math.max(vs, rs) / 150))) addrs.push(hx(base + sva + o))
  const a = P.run('py', [exe, ...addrs]), b = P.run('js', [exe, ...addrs])
  cmpLines(`${bin} addresses`, a, b)
  if (lab.length) {
    const a2 = P.run('py', [exe, ...lab]), b2 = P.run('js', [exe, ...lab])
    cmpLines(`${bin} labels`, a2, b2)
  }
}
// error paths
const exe = bins[0].abs.exe
const textFile = P.tmpPath('readme.txt')
writeFileSync(textFile, 'a text file, not a PE\n')
const trunc = P.tmpPath('truncated.exe')
if (existsSync(exe)) writeFileSync(trunc, readFileSync(exe).subarray(0, 0x150))
const notpe = P.tmpPath('notpe.bin')
writeFileSync(notpe, Buffer.from('MZ' + '\0'.repeat(0x3a) + '\x40\0\0\0' + 'XXXX', 'latin1'))
for (const [name, args] of [
  ['no arguments', []], ['one argument', [exe]], ['missing file', [P.tmpPath('nope.exe'), '0x401000']],
  ['text file', [textFile, '0x401000']], ['no PE signature', [notpe, '0x401000']],
  ['truncated PE', [trunc, '0x401000', '0x400000', '0x400010']], ['bad addresses', [exe, 'zz', '0x401000', '123456789', 'DAT_1234']],
  ['label forms', [exe, 'FUN_00401000', 'LAB_00401010', 'x_y_00401000', '00401000', '0X401000']],
]) {
  const a = P.run('py', args), b = P.run('js', args)
  P.compare(`errors: ${name}`, a, b, { stderr: !['missing file', 'truncated PE'].includes(name) })
}
// Unicode tables behind repr(): count code points where Python 3.9's isprintable differs from this port's
const py = spawnSync(P.python, ['-I', '-c', 'import sys, unicodedata\nsys.stdout.write(sys.version.split()[0] + " " + unicodedata.unidata_version + "\\n" + "".join("1" if chr(c).isprintable() else "0" for c in range(0x110000)))'], { maxBuffer: 1 << 24 })
if (py.status === 0) {
  const [ver, s] = py.stdout.toString().split('\n')
  const [pyv, pyu] = ver.split(' ')
  let diff = 0, bmp = 0
  for (let c = 0; c < 0x110000; c++) {
    const j = isPrintable(String.fromCodePoint(c)) ? '1' : '0'
    if (j !== s[c]) { diff++; if (c < 0x10000) bmp++ }
  }
  P.record(`str.isprintable() table (Python ${pyv}, Unicode ${pyu}) for all 0x110000 code points`,
           diff ? [`${diff} code points differ, ${bmp} in the BMP`] : [])
}
P.finish()
