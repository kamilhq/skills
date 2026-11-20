#!/usr/bin/env node
// JavaScript port of peek.py (same CLI, output and exit codes). Node built-ins only.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { isOSError, osErrorStr, pyRepr, runMain, SysExit } from './lib/pytools.mjs'

const DOC = "peek.py <binary> <address> [<address> ...]\n\nPrint what is at each virtual address of a 32-bit PE: the full C string (cp1252), a UTF-16LE string, or\n32 raw bytes. Ghidra truncates string labels (s_Error_cargando_l_00712345) and leaves many strings as\nDAT_ references; naming agents use this to read the real text.\n\n<address> is a VA in hex with or without 0x (0x1000e280, 1000e280) or a Ghidra label that ends in one\n(DAT_1000e280, s_Error_cargando_l_00712345, PTR_FUN_1000e20c). Headers (VA below the first section) are\nfile-backed; .bss-style tails of a section print <uninitialised>. Exit 0 ok, 1 an address could not be\nread, 2 bad arguments or not a PE. Stdlib only; run with -I.\n"

class PeError extends Error {}

function u32(d, o) {
  if (o < 0 || o + 4 > d.length) {
    throw new PeError(`unpack_from requires a buffer of at least ${o + 4} bytes for unpacking 4 bytes at offset ${o} (actual buffer size is ${d.length})`)
  }
  return d.readUInt32LE(o)
}
function u16(d, o) {
  if (o < 0 || o + 2 > d.length) {
    throw new PeError(`unpack_from requires a buffer of at least ${o + 2} bytes for unpacking 2 bytes at offset ${o} (actual buffer size is ${d.length})`)
  }
  return d.readUInt16LE(o)
}

export function sections(d) {
  if (!(d[0] === 0x4d && d[1] === 0x5a) || d.length < 0x40) throw new PeError('no MZ header')
  const o = u32(d, 0x3c)
  if (!d.subarray(o, o + 4).equals(Buffer.from('PE\0\0', 'latin1'))) throw new PeError('no PE signature')
  const n = u16(d, o + 6)
  const opt = o + 24
  const base = u32(d, opt + 28)
  const hdrs = u32(d, opt + 60)          // SizeOfHeaders
  const so = opt + u16(d, o + 20)
  const secs = []
  for (let i = 0; i < n; i++) {
    const p = so + 40 * i
    if (p < 0 || p + 24 > d.length) {
      throw new PeError(`unpack_from requires a buffer of at least ${p + 24} bytes for unpacking 24 bytes at offset ${p} (actual buffer size is ${d.length})`)
    }
    secs.push([d.subarray(p, p + 8), d.readUInt32LE(p + 8), d.readUInt32LE(p + 12), d.readUInt32LE(p + 16), d.readUInt32LE(p + 20)])
  }
  return [base, hdrs, secs]
}

export function parse_addr(a) {
  const m = /^(?:0x)?([0-9a-fA-F]{1,8})$/.exec(a) || /^[^\n]*_([0-9a-fA-F]{8})$/.exec(a)
  return m ? parseInt(m[1], 16) : null
}

function rstripNul(b) {
  let n = b.length
  while (n > 0 && b[n - 1] === 0) n--
  return b.subarray(0, n)
}

const utf16 = new TextDecoder('utf-16le', { fatal: false, ignoreBOM: true })

export function main(argv) {
  let d, base, hdrs, secs
  try {
    d = readFileSync(argv[0])
    ;[base, hdrs, secs] = sections(d)
  } catch (e) {
    if (isOSError(e) || e instanceof PeError) {
      process.stderr.write(`${argv[0]}: not a readable PE (${isOSError(e) ? osErrorStr(e, argv[0]) : e.message})\n`)
      return 2
    }
    throw e
  }
  const addrs = argv.slice(1).map((a) => [a, parse_addr(a)])
  const bad = addrs.filter(([, v]) => v === null).map(([a]) => a)
  if (bad.length) {
    process.stderr.write('not an address (hex VA or a Ghidra label ending in _<8 hex digits>): ' + bad.join(' ') + '\n')
    return 2
  }
  let rc = 0
  const out = []
  for (const [a, va] of addrs) {
    const rva = va - base
    let p = null, why = null
    if (rva < 0) {
      why = `below the image base 0x${base.toString(16)} (pass a virtual address, not a file offset or RVA)`
    } else if (rva < hdrs) {
      p = rva                                                // headers are mapped 1:1
    } else {
      let found = false
      for (const [nm, vs, sva, rs, ro] of secs) {
        if (sva <= rva && rva < sva + Math.max(vs, rs)) {
          if (rva - sva < rs) p = ro + rva - sva
          else why = `<uninitialised: beyond the file data of ${rstripNul(nm).toString('latin1')}>`
          found = true
          break
        }
      }
      if (!found) why = '<outside every section>'
    }
    if (p === null || p >= d.length) {
      out.push(`${a} ${why || '<not backed by file bytes>'}`)
      rc = 1
      continue
    }
    const raw = d.subarray(p, p + 512)
    let z = raw.indexOf(0)
    const okChar = (c) => (c >= 32 && c < 127) || c === 9 || c === 10 || c === 13 || c >= 0xa0
    if (z > 1 && raw.subarray(0, z).every(okChar)) {
      // cp1252 = latin-1 for every byte the check above admits
      out.push(`${a} ${pyRepr(raw.subarray(0, z).toString('latin1'))}`)
    } else if (raw.length > 2 && raw[1] === 0 && raw[0] !== 0) {
      z = raw.indexOf(Buffer.from([0, 0]))
      z = z < 0 ? raw.length & ~1 : z
      out.push(`${a} utf16 ${pyRepr(utf16.decode(raw.subarray(0, z + (z & 1))))}`)
    } else {
      out.push(`${a} bytes ${[...raw.subarray(0, 32)].map((x) => x.toString(16).padStart(2, '0')).join(' ')}`)
    }
  }
  if (out.length) process.stdout.write(out.join('\n') + '\n')
  return rc
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(() => {
    if (process.argv.length < 4) throw new SysExit(1, DOC)
    return main(process.argv.slice(2))
  })
}
