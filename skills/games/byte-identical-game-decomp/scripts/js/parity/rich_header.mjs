#!/usr/bin/env node
// Parity test: rich_header.py vs js/rich_header.mjs.
//
//   node parity/rich_header.mjs [--root PROJECT] [--python python3] [--keep]
//
// Cases: every PE found under PROJECT's work/, build/, reassembled/relink/ (the game exe/dll, rebuilt and relinked
// binaries, the installer's redistributables) decoded one per invocation and all together; --compare for every
// ordered pair of distinct files among them (capped) and a file with itself; synthetic files (truncated PE,
// MZ without PE signature, a PE whose Rich header is stripped, a Rich header with an unknown product id);
// errors: missing file, a text file, bad arguments. Compares exit code, stdout and stderr. The synthetic files are
// made from the first binary of PROJECT/decomp.json (else the first PE found); exit 2 when PROJECT has no PE.
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fail, Parity, parseOpts, projectBinaries } from '../lib/peparity.mjs'

const opts = parseOpts(process.argv.slice(2), { root: undefined, python: undefined, keep: false })
const P = new Parity('rich_header', opts)

const pes = []
const walk = (d) => {
  if (!existsSync(d)) return
  for (const e of readdirSync(d, { withFileTypes: true })) {
    const p = join(d, e.name)
    if (e.isDirectory()) walk(p)
    else if (/\.(exe|dll)$/i.test(e.name) && statSync(p).size >= 0x40) pes.push(p)
  }
}
for (const d of ['work', 'build', join('reassembled', 'relink')]) walk(P.path(d))
pes.sort()

// synthetic inputs
const bins = projectBinaries(P.root, { script: 'rich_header', required: false }).filter((b) => existsSync(b.abs.exe))
const game = bins.length ? bins[0].abs.exe : pes[0]
if (!game) fail('rich_header', `no PE file under ${P.path('work')}, ${P.path('build')} or ${P.path('reassembled', 'relink')}: run it from a decomp project (or pass --root PROJECT)`)
const textFile = P.tmpPath('readme.txt')
writeFileSync(textFile, 'a text file, not a PE\n')
const syn = []
if (existsSync(game)) {
  const d = readFileSync(game)
  const pe = d.readUInt32LE(0x3c)
  writeFileSync(P.tmpPath('truncated.exe'), d.subarray(0, pe + 20)); syn.push(P.tmpPath('truncated.exe'))
  const nosig = Buffer.from(d.subarray(0, 0x400)); nosig.write('XX', pe, 'latin1')
  writeFileSync(P.tmpPath('nosig.exe'), nosig); syn.push(P.tmpPath('nosig.exe'))
  const stripped = Buffer.from(d.subarray(0, 0x1000)); stripped.fill(0, 0x80, pe)
  writeFileSync(P.tmpPath('stripped.exe'), stripped); syn.push(P.tmpPath('stripped.exe'))
  // flip one entry's product id to an unknown value (XOR-keyed), keep the rest
  const rich = d.indexOf('Rich', 0x40)
  if (rich > 0) {
    const odd = Buffer.from(d.subarray(0, 0x1000))
    const key = odd.readUInt32LE(rich + 4)
    const k = rich - 8
    const comp = (odd.readUInt32LE(k) ^ key) >>> 0
    odd.writeUInt32LE((((comp & 0xffff) | (250 << 16)) ^ key) >>> 0, k)
    writeFileSync(P.tmpPath('unknown_prodid.exe'), odd); syn.push(P.tmpPath('unknown_prodid.exe'))
  }
  writeFileSync(P.tmpPath('short.bin'), d.subarray(0, 0x30)); syn.push(P.tmpPath('short.bin'))
}

const both = (name, args) => P.compare(name, P.run('py', args), P.run('js', args), { stderr: true })
for (const f of [...pes, ...syn]) both(`decode ${f}`, [f])
both('decode all at once', [...pes, ...syn])
let pairs = 0
for (const a of pes) {
  for (const b of pes) {
    if (pairs >= 80) break
    both(`--compare ${a} ${b}`, ['--compare', a, b]); pairs++
  }
}
for (const s of syn) both(`--compare game ${s}`, ['--compare', game, s])
for (const [name, args] of [
  ['missing file', [P.tmpPath('nope.exe')]], ['text file', [textFile]],
  ['missing + good', [P.tmpPath('nope.exe'), game]], ['--compare missing', ['--compare', game, P.tmpPath('nope.exe')]],
  ['no arguments', []], ['-h', ['-h']], ['--help', ['--help']], ['--compare one file', ['--compare', game]],
  ['--compare three files', ['--compare', game, game, game]], ['directory', [P.path('work')]],
]) both(`errors: ${name}`, args)
P.finish({ pe_files: pes.length })
