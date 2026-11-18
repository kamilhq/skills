#!/usr/bin/env node
// Port of ../wintools.py: PE export/import and COFF symbol readers (same command line and output).
import fs from 'node:fs'
import * as L from './lib/rwlib.mjs'

const DOC = "Small Windows-binary helpers for the rewrite toolchain (Python stdlib only; port: js/wintools.mjs).\n\n  pe_exports(path)            -> list of export names of a PE (DLL/EXE)\n  pe_imports(path)            -> {dll_name: [function names]} of a PE\n  coff_defined_externals(obj) -> external symbols defined by a COFF .obj (names as stored, e.g. \"_foo\")\n  archive_members(lib)        -> [(member name, bytes)] of an ar/.lib archive\n  write_def(path, dll, names) -> writes a module-definition (.def) file\n\nCommand line:\n  wintools.py exports <pe>             print the export names\n  wintools.py imports <pe>             print \"dll: function\" lines\n  wintools.py externals <obj|lib>...   print external symbols defined by objects / archive members\n  wintools.py def <pe> [<out.def>]     module-definition file of a DLL's exports (stdout or <out.def>), the\n                                       input of `lib /DEF:` or `rust-lld -flavor link /lib /def:` to make an\n                                       import library for a DLL that came without one"

function peSections (d) {
  if (d.length < 2 || d[0] !== 0x4d || d[1] !== 0x5a) throw new Error('not an MZ/PE file')
  const pe = d.readUInt32LE(0x3c)
  if (d.toString('latin1', pe, pe + 4) !== 'PE\0\0') throw new Error('no PE signature')
  const nsect = d.readUInt16LE(pe + 6)
  const optsize = d.readUInt16LE(pe + 20)
  const opt = pe + 24
  const magic = d.readUInt16LE(opt)
  const ddir = opt + (magic === 0x10b ? 96 : 112)
  const dirs = []
  for (let i = 0; i < 16; i++) dirs.push([d.readUInt32LE(ddir + 8 * i), d.readUInt32LE(ddir + 8 * i + 4)])
  const sects = []
  const sh = opt + optsize
  for (let i = 0; i < nsect; i++) {
    const o = sh + 40 * i
    const vsize = d.readUInt32LE(o + 8); const va = d.readUInt32LE(o + 12)
    const rawsize = d.readUInt32LE(o + 16); const rawptr = d.readUInt32LE(o + 20)
    sects.push([va, Math.max(vsize, rawsize), rawptr])
  }
  return [magic, dirs, sects]
}
function rva2off (sects, rva) {
  for (const [va, size, raw] of sects) if (va <= rva && rva < va + size) return rva - va + raw
  throw new Error(`rva 0x${rva.toString(16)} outside sections`)
}
function cstr (d, off) {
  const end = d.indexOf(0, off)
  if (end < 0) throw new Error('substring not found')
  return d.toString('latin1', off, end)
}

export function peExports (p) {
  const d = fs.readFileSync(p)
  const [, dirs, sects] = peSections(d)
  const [rva] = dirs[0]
  if (!rva) return []
  const off = rva2off(sects, rva)
  const nnames = d.readUInt32LE(off + 24)
  const namesRva = d.readUInt32LE(off + 32)
  const names = []
  const noff = nnames ? rva2off(sects, namesRva) : 0
  for (let i = 0; i < nnames; i++) names.push(cstr(d, rva2off(sects, d.readUInt32LE(noff + 4 * i))))
  return names
}

export function peImports (p) {
  const d = fs.readFileSync(p)
  const [magic, dirs, sects] = peSections(d)
  const [rva] = dirs[1]
  const out = new Map()
  if (!rva) return out
  let off = rva2off(sects, rva)
  const thunk = magic === 0x10b ? 4 : 8
  for (;;) {
    const oft = d.readUInt32LE(off); const nameRva = d.readUInt32LE(off + 12); const ft = d.readUInt32LE(off + 16)
    if (!nameRva) break
    const dll = cstr(d, rva2off(sects, nameRva))
    const funcs = []
    let t = rva2off(sects, oft || ft)
    for (;;) {
      const v = thunk === 4 ? BigInt(d.readUInt32LE(t)) : d.readBigUInt64LE(t)
      if (v === 0n) break
      const flag = 1n << BigInt(8 * thunk - 1)
      if (v & flag) funcs.push(`#${Number(v & 0xffffn)}`)
      else funcs.push(cstr(d, rva2off(sects, Number(v & 0x7fffffffn)) + 2))
      t += thunk
    }
    out.set(dll, funcs)
    off += 20
  }
  return out
}

// External symbols defined (section number > 0) in a COFF object; withKind: [name, isFunction] pairs.
export function coffDefinedExternals (d, withKind = false) {
  const machine = d.readUInt16LE(0)
  const symptr = d.readUInt32LE(8); const nsyms = d.readUInt32LE(12)
  if ((machine !== 0x14c && machine !== 0x8664) || !symptr) return []
  const strtab = symptr + 18 * nsyms
  const out = []
  let i = 0
  while (i < nsyms) {
    const o = symptr + 18 * i
    const raw = d.subarray(o, o + 8)
    let name
    if (raw.readUInt32LE(0) === 0) name = cstr(d, strtab + raw.readUInt32LE(4))
    else {
      let e = 8
      while (e > 0 && raw[e - 1] === 0) e--
      name = raw.toString('latin1', 0, e)
    }
    const secnum = d.readInt16LE(o + 12); const typ = d.readUInt16LE(o + 14)
    const sclass = d[o + 16]; const naux = d[o + 17]
    if (sclass === 2 && secnum > 0) out.push(withKind ? [name, (typ >> 4) === 2] : name)
    i += 1 + naux
  }
  return out
}

export function archiveMembers (p) {
  const d = fs.readFileSync(p)
  if (d.toString('latin1', 0, 8) !== '!<arch>\n') return [[p, d]]
  const out = []
  let off = 8
  let longnames = Buffer.alloc(0)
  while (off + 60 <= d.length) {
    const hdr = d.subarray(off, off + 60)
    let name = hdr.toString('latin1', 0, 16).trim()
    const size = parseInt(hdr.toString('latin1', 48, 58).trim(), 10)
    const body = d.subarray(off + 60, off + 60 + size)
    if (name === '//') longnames = body
    else if (!['/', '/SYM64/', '__.SYMDEF', '__.SYMDEF SORTED'].includes(name)) {
      if (name.startsWith('/') && /^\d+$/.test(name.slice(1))) {
        const s = parseInt(name.slice(1), 10)
        const nl = longnames.indexOf(0x0a, s)
        name = longnames.toString('latin1', s, nl >= 0 ? nl : longnames.length).replace(/\/+$/, '')
      }
      out.push([name.replace(/\/+$/, ''), body])
    }
    off += 60 + size + (size & 1)
  }
  return out
}

export function defText (dll, names) { return `LIBRARY ${dll}\nEXPORTS\n` + names.map(n => `    ${n}\n`).join('') }
export function writeDef (p, dll, names) { fs.writeFileSync(p, defText(dll, names)) }

export function main (argv) {
  if (argv.length < 3) {
    process.stdout.write(DOC.trim() + '\n')
    return 2
  }
  const cmd = argv[1]
  if (cmd === 'exports') {
    for (const n of peExports(argv[2])) process.stdout.write(n + '\n')
  } else if (cmd === 'imports') {
    for (const [dll, funcs] of peImports(argv[2])) for (const fn of funcs) process.stdout.write(`${dll}: ${fn}\n`)
  } else if (cmd === 'externals') {
    for (const p of argv.slice(2)) {
      for (const [, body] of archiveMembers(p)) for (const n of coffDefinedExternals(body)) process.stdout.write(n + '\n')
    }
  } else if (cmd === 'def') {
    const text = defText(L.basename(argv[2]), peExports(argv[2]))
    if (argv.length > 3) fs.writeFileSync(argv[3], text)
    else process.stdout.write(text)
  } else {
    process.stdout.write(DOC.trim() + '\n')
    return 2
  }
  return 0
}

if (L.isMain(import.meta.url)) process.exitCode = main(['wintools', ...process.argv.slice(2)])
