#!/usr/bin/env node
// Parity test: protection_check.py vs js/protection_check.mjs.
//
//   node parity/protection_check.mjs [--root PROJECT] [--python python3] [--keep]
//
// Cases: PROJECT's game folder (decomp.json paths.game, default work/game) and every PE in it on its own;
// synthetic copies of the project's first binary with a packer section name (UPX0), a DRM section name
// (.securom), the SafeDisc signature string, an import renamed to steam_api.dll, the entry point moved outside
// every section, a writable code section, a high-entropy entry section; a folder with protection file names in
// mixed case and a sub-folder; a truncated PE, MZ without PE, a text file; --json OUT (file compared); errors
// (no arguments, missing path, unknown option, --json without value, -h). Compares exit code, stdout, stderr
// and written files. Without a PE in PROJECT only the PE-free cases run.
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { Parity, parseOpts, projectBinaries } from '../lib/peparity.mjs'

const opts = parseOpts(process.argv.slice(2), { root: undefined, python: undefined, keep: false })
const P = new Parity('protection_check', opts)
const both = (name, args, files = []) => {
  const a = P.run('py', args)
  const pyFiles = files.map((f) => { const c = existsSync(f) ? readFileSync(f) : null; if (c) writeFileSync(f + '.python', c); return f })
  const b = P.run('js', args)
  P.compare(name, a, b, { stderr: true, files: pyFiles.map((f) => [f + '.python', f]) })
}

let gameDir = P.path('work', 'game')
try {
  const cfg = JSON.parse(readFileSync(P.path('decomp.json'), 'utf8'))
  if (cfg.paths && cfg.paths.game) gameDir = P.path(cfg.paths.game)
} catch {}
const pes = []
if (existsSync(gameDir)) {
  for (const n of readdirSync(gameDir).sort()) {
    const p = join(gameDir, n)
    if (/\.(exe|dll)$/i.test(n) && statSync(p).isFile()) pes.push(p)
  }
  both('game folder', [gameDir])
  for (const p of pes) both(`pe ${p}`, [p])
}
const bins = projectBinaries(P.root, { script: 'protection_check', required: false }).filter((b) => existsSync(b.abs.exe))
const src = bins.length ? bins[0].abs.exe : pes[0]

const syn = P.tmpPath('syn')
mkdirSync(syn)
if (src) {
  const d = readFileSync(src)
  const pe = d.readUInt32LE(0x3c)
  const opt = pe + 24
  const so = opt + d.readUInt16LE(pe + 20)
  const nsec = d.readUInt16LE(pe + 6)
  const variant = (name, edit) => { const c = Buffer.from(d); edit(c); writeFileSync(join(syn, name), c); return join(syn, name) }
  const files = [
    variant('upx.exe', (c) => { c.fill(0, so, so + 8); c.write('UPX0', so, 'latin1') }),
    variant('securom.exe', (c) => { c.fill(0, so + 40, so + 48); c.write('.securom', so + 40, 'latin1') }),
    variant('safedisc_sig.exe', (c) => { c.write('BoG_ *90.0&!!  Yy>', c.length - 64, 'latin1') }),
    variant('entry_outside.exe', (c) => { c.writeUInt32LE(0x7ff00000, opt + 16) }),
    variant('writable_code.exe', (c) => {
      // make the section holding the entry point writable
      const entry = c.readUInt32LE(opt + 16)
      for (let i = 0; i < nsec; i++) {
        const o = so + 40 * i
        const va = c.readUInt32LE(o + 12); const vs = c.readUInt32LE(o + 8); const rs = c.readUInt32LE(o + 16)
        if (va <= entry && entry < va + Math.max(vs, rs)) c.writeUInt32LE((c.readUInt32LE(o + 36) | 0x80000000) >>> 0, o + 36)
      }
    }),
    variant('entropy.exe', (c) => {
      const entry = c.readUInt32LE(opt + 16)
      for (let i = 0; i < nsec; i++) {
        const o = so + 40 * i
        const va = c.readUInt32LE(o + 12); const vs = c.readUInt32LE(o + 8); const rs = c.readUInt32LE(o + 16); const rp = c.readUInt32LE(o + 20)
        if (va <= entry && entry < va + Math.max(vs, rs)) randomBytes(Math.min(rs, c.length - rp)).copy(c, rp)
      }
    }),
    variant('steam.exe', (c) => {
      const at = c.indexOf(Buffer.from('KERNEL32.dll\0', 'latin1'))
      if (at >= 0) c.write('steam_api.dll\0', at, 'latin1')
    }),
    variant('truncated.exe', () => {}),
    variant('nosig.exe', (c) => { c.write('XX', pe, 'latin1') })
  ]
  writeFileSync(join(syn, 'truncated.exe'), d.subarray(0, pe + 20))
  writeFileSync(join(syn, 'mz_only.bin'), d.subarray(0, 0x30))
  for (const f of files) both(`synthetic ${f.slice(syn.length + 1)}`, [f])
}
const folder = P.tmpPath('folder')
mkdirSync(join(folder, 'Sub', 'deeper'), { recursive: true })
writeFileSync(join(folder, 'readme.txt'), 'not a PE\n')
writeFileSync(join(folder, 'Sub', 'CLCD32.DLL'), 'x')
writeFileSync(join(folder, 'Sub', 'deeper', 'laserlok.in'), 'x')
writeFileSync(join(folder, 'Protect.EXE'), 'MZ')
writeFileSync(join(folder, 'mz.bin'), 'MZ short')
both('folder with protection file names', [folder])
both('synthetic folder', [syn])
both('two arguments', [folder, syn])
both('--json', [folder, '--json', P.tmpPath('out.json')], [P.tmpPath('out.json')])
both('--json= form is a path', [folder, '--json=x'])
for (const [name, args] of [['no arguments', []], ['missing', [P.tmpPath('nope')]], ['missing after good', [folder, P.tmpPath('nope')]],
  ['unknown option', ['--bogus', folder]], ['--json no value', [folder, '--json']], ['-h', ['-h']], ['--help', ['--help']]]) {
  both(`errors: ${name}`, args)
}
P.finish({ pe_files: pes.length })
