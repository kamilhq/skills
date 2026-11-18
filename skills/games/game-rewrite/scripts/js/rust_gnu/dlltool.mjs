#!/usr/bin/env node
// Port of ../../rust_gnu/dlltool.py: the i686-w64-mingw32-dlltool stand-in rustc runs for raw-dylib imports.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import * as L from '../lib/rwlib.mjs'
import { archiveMembers, coffDefinedExternals } from '../wintools.mjs'

const IMPORT_NAME = 1

function parseArgs (argv) {
  const args = {}
  let i = 0
  while (i < argv.length) {
    if (['-d', '-D', '-l', '-m', '--temp-prefix'].includes(argv[i]) && i + 1 < argv.length) { args[argv[i]] = argv[i + 1]; i += 2 } else i += 1
  }
  return args
}
export function shortImport (body) {
  if (body.length < 20 || !(body[0] === 0 && body[1] === 0 && body[2] === 0xff && body[3] === 0xff)) return null
  const parts = body.subarray(20).toString('latin1').split('\0')
  return [parts[0], parts.length > 1 ? parts[1] : '', body.readUInt16LE(18)]
}
export function makeShortImport (body, newSym, nameType) {
  const hdr = Buffer.from(body.subarray(0, 20))
  const [, dll, typ] = shortImport(body)
  const rest = Buffer.concat([Buffer.from(newSym, 'utf8'), Buffer.from([0]), Buffer.from(dll, 'utf8'), Buffer.from([0])])
  hdr.writeUInt32LE(rest.length, 12)
  hdr.writeUInt16LE((typ & ~(7 << 2)) | (nameType << 2), 18)
  return Buffer.concat([hdr, rest])
}
export function writeGnuArchive (p, members) {
  let longnames = Buffer.alloc(0)
  const names = []
  for (const [name] of members) {
    const n = Buffer.from(name + '/', 'utf8')
    if (n.length > 16) { names.push(Buffer.from('/' + longnames.length)); longnames = Buffer.concat([longnames, n, Buffer.from('\n')]) } else names.push(n)
  }
  const pad = (b, w) => Buffer.concat([b, Buffer.alloc(Math.max(0, w - b.length), 0x20)])
  const header = (name, size) => Buffer.concat([pad(name, 16), pad(Buffer.from('0'), 12), pad(Buffer.from('0'), 6),
    pad(Buffer.from('0'), 6), pad(Buffer.from('644'), 8), pad(Buffer.from(String(size)), 10), Buffer.from('`\n')])
  const syms = []
  members.forEach(([, , ss], i) => { for (const s of ss) syms.push([s, i]) })
  const strtab = Buffer.concat(syms.map(([s]) => Buffer.concat([Buffer.from(s, 'utf8'), Buffer.from([0])])))
  const symsize = 4 + 4 * syms.length + strtab.length
  let pos = 8 + 60 + symsize + (symsize & 1)
  if (longnames.length) pos += 60 + longnames.length + (longnames.length & 1)
  const offsets = []
  for (const [, body] of members) { offsets.push(pos); pos += 60 + body.length + (body.length & 1) }
  const u32be = v => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b }
  const parts = [Buffer.from('!<arch>\n'), header(Buffer.from('/'), symsize), u32be(syms.length),
    ...syms.map(([, i]) => u32be(offsets[i])), strtab]
  if (symsize & 1) parts.push(Buffer.from('\n'))
  if (longnames.length) parts.push(header(Buffer.from('//'), longnames.length), longnames, Buffer.from(longnames.length & 1 ? '\n' : ''))
  members.forEach(([, body], k) => parts.push(header(names[k], body.length), body, Buffer.from(body.length & 1 ? '\n' : '')))
  fs.writeFileSync(p, Buffer.concat(parts))
}

export function main (argv) {
  const args = parseArgs(argv)
  if (!('-d' in args) || !('-l' in args)) { process.stderr.write('dlltool.py: need -d <def> and -l <output>\n'); return 2 }
  if ((args['-m'] || 'i386') !== 'i386') { process.stderr.write('dlltool.py: only -m i386 is supported\n'); return 2 }
  const dll = args['-D']
  const plain = new Set()
  const out = dll ? [`LIBRARY ${dll}`] : []
  for (const line of L.splitlines(fs.readFileSync(args['-d'], 'utf8'))) {
    let s = line.trim()
    if (!s || s.toUpperCase().startsWith('LIBRARY')) continue
    const m = /^([A-Za-z_]\w*)@(\d+)(\s.*)?$/s.exec(s)
    if (m) s = `_${m[1]}@${m[2]} == ${m[1]}${m[3] || ''}`
    else if (/^[A-Za-z_]\w*$/.test(s)) plain.add(s)
    out.push(s)
  }
  const lib = args['-l']
  const tmpDef = lib + '.tmp.def'
  fs.writeFileSync(tmpDef, out.join('\n') + '\n')
  const lld = process.env.RUST_GNU_LLD || 'rust-lld'
  const r = spawnSync(lld, ['-flavor', 'link', '/lib', '/machine:x86', '/def:' + tmpDef, '/out:' + lib], { stdio: 'inherit' })
  fs.rmSync(tmpDef)
  if (r.status) return r.status
  const members = []
  for (let [name, body] of archiveMembers(lib)) {
    const si = shortImport(body)
    if (si === null) { members.push([name, body, coffDefinedExternals(body)]); continue }
    let sym = si[0]
    if (sym.startsWith('_') && plain.has(sym.slice(1))) {
      sym = sym.slice(1)
      body = makeShortImport(body, sym, IMPORT_NAME)
    }
    members.push([name, body, [sym, '__imp_' + sym]])
  }
  writeGnuArchive(lib, members)
  return 0
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
