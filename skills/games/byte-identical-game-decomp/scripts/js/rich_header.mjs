#!/usr/bin/env node
// JavaScript port of rich_header.py (same CLI, output and exit codes). Node built-ins only.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dumps } from './lib/pyjson.mjs'
import { cmpTuple, isOSError, osErrorStr, runMain } from './lib/pytools.mjs'

const DOC = "rich_header.py <pe> [<pe> ...]\n   rich_header.py --compare <original_pe> <your_build_pe>\n\nDecode the MSVC \"Rich\" header of each PE (the XOR-keyed list of build tools that produced its objects) and\nthe linker version from the optional header. Output: one JSON line per binary with the linker version and\nEVERY (product_id, build, count) entry in header order, plus `tool` = the product id's name from the public\n\"prodid\" enumeration (e.g. 10 Utc12_C = VC6 C compiler, 11 Utc12_CPP = VC6 C++ compiler, 14 Masm613,\n4 Linker600, 6 Cvtres500, 1 Import0 = imported symbols) and `largest_compiler` = the compiler (Utc*) entry\nwith the most objects.\nAlways quote the full entry list: the biggest C++ group is usually the game's own code, while small C/MASM\ngroups at another build are often the prebuilt CRT/libs.\n\nThe tool names come from a public table and the build -> service-pack mapping (e.g. 8966 = VC6 SP5) from public\nlists: label both as inferred. The `cl` banner does NOT print the Rich build (VC6 SP5/SP6 cl says 12.00.8804).\nTo confirm a toolchain, compile and link a trivial program with it and use --compare: it lists the\n(product_id, build) pairs of the original that your build reproduces and those it does not.\n\nExit 0 ok; 1 a file is not a PE / has no Rich header (reported in its JSON line); 2 bad arguments.\nStdlib only; run with -I.\n"

// Microsoft "prodid" enumeration, low values only (VC5-VC7.1 era); names from public Rich-header research.
export const PRODID = {
  0: 'Unknown', 1: 'Import0', 2: 'Linker510', 3: 'Cvtomf510', 4: 'Linker600', 5: 'Cvtomf600', 6: 'Cvtres500',
  7: 'Utc11_Basic', 8: 'Utc11_C', 9: 'Utc12_Basic', 10: 'Utc12_C', 11: 'Utc12_CPP', 12: 'AliasObj60',
  13: 'VisualBasic60', 14: 'Masm613', 15: 'Masm710', 16: 'Linker511', 17: 'Cvtomf511', 18: 'Masm614',
  19: 'Linker512', 20: 'Cvtomf512', 21: 'Utc12_C_Std', 22: 'Utc12_CPP_Std', 23: 'Utc12_C_Book',
  24: 'Utc12_CPP_Book', 25: 'Implib700', 26: 'Cvtomf700', 27: 'Utc13_Basic', 28: 'Utc13_C', 29: 'Utc13_CPP',
  30: 'Linker610', 31: 'Cvtomf610', 32: 'Linker601', 33: 'Cvtomf601', 34: 'Utc12_1_Basic', 35: 'Utc12_1_C',
  36: 'Utc12_1_CPP', 37: 'Linker620', 38: 'Cvtomf620', 39: 'AliasObj70', 40: 'Linker621', 41: 'Cvtomf621',
  42: 'Masm615', 43: 'Utc13_LTCG_C', 44: 'Utc13_LTCG_CPP', 45: 'Masm620', 46: 'ILAsm100', 47: 'Utc12_2_Basic',
  48: 'Utc12_2_C', 49: 'Utc12_2_CPP', 50: 'Utc12_2_C_Std', 51: 'Utc12_2_CPP_Std', 52: 'Utc12_2_C_Book',
  53: 'Utc12_2_CPP_Book', 54: 'Implib622', 55: 'Cvtomf622', 56: 'Cvtres501', 57: 'Utc13_C_Std',
  58: 'Utc13_CPP_Std', 59: 'Cvtpgd1300', 60: 'Linker622', 61: 'Linker700', 62: 'Export622', 63: 'Export700',
  64: 'Masm700', 65: 'Utc13_POGO_I_C', 66: 'Utc13_POGO_I_CPP', 67: 'Utc13_POGO_O_C', 68: 'Utc13_POGO_O_CPP',
  69: 'Cvtres700', 70: 'Cvtres710p', 71: 'Linker710p', 72: 'Cvtomf710p', 73: 'Export710p', 74: 'Implib710p',
  75: 'Masm710p', 76: 'Utc1310p_C', 77: 'Utc1310p_CPP',
}

export function rich(d, o) {
  // d.find(b'Rich', 0x40, o): the match must lie inside d[0x40:o]
  const lim = Math.min(Math.max(o, 0), d.length)
  const end = lim >= 0x40 ? d.subarray(0, lim).indexOf(Buffer.from('Rich', 'latin1'), 0x40) : -1
  if (end < 0) return [null, []]
  const key = d.subarray(end + 4, end + 8)
  const unx = (b) => Buffer.from([...b.subarray(0, Math.min(b.length, key.length))].map((x, i) => x ^ key[i]))
  let start = end - 4
  while (start >= 0x40 && !unx(d.subarray(start, start + 4)).equals(Buffer.from('DanS', 'latin1'))) start -= 4
  if (start < 0x40) return [null, []]
  const entries = []
  for (let k = start + 16; k < end; k += 8) {
    const b = Buffer.concat([unx(d.subarray(k, k + 4)), unx(d.subarray(k + 4, k + 8))])
    if (b.length !== 8) throw new Error('struct.error: unpack requires a buffer of 8 bytes')
    const comp = b.readUInt32LE(0), count = b.readUInt32LE(4)
    const pid = comp >>> 16
    entries.push({ product_id: pid, build: comp & 0xffff, count, tool: PRODID[pid] ?? `prodid_${pid} (not in table)` })
  }
  return [key.toString('hex'), entries]
}

export function decode(p) {
  let d
  try {
    d = readFileSync(p)
  } catch (e) {
    if (isOSError(e)) return { file: p, error: osErrorStr(e, p) }
    throw e
  }
  if (d.length < 0x40 || !(d[0] === 0x4d && d[1] === 0x5a)) return { file: p, error: 'not a PE file (no MZ header)' }
  const o = d.readUInt32LE(0x3c)
  if (o + 28 > d.length || !d.subarray(o, o + 4).equals(Buffer.from('PE\0\0', 'latin1'))) {
    return { file: p, error: 'not a PE file (MZ only, no PE signature)' }
  }
  const major = d[o + 24 + 2], minor = d[o + 24 + 3]
  const [key, entries] = rich(d, o)
  const r = { file: p, linker: `${major}.${String(minor).padStart(2, '0')}`, rich_key: key, entries }
  if (!entries.length) r.error = 'no Rich header (not MSVC-linked, or stripped)'
  else {
    const comp = entries.filter((e) => e.tool.startsWith('Utc'))
    let big = null
    for (const e of comp) if (big === null || e.count > big.count) big = e
    r.largest_compiler = big ? { product_id: big.product_id, build: big.build, count: big.count, tool: big.tool } : null
  }
  return r
}

export function main(argv) {
  if (argv.length && argv[0] === '--compare') {
    if (argv.length !== 3) {
      process.stderr.write(DOC + '\n')
      return 2
    }
    const a = decode(argv[1]), b = decode(argv[2])
    for (const r of [a, b]) {
      if (r.error) {
        process.stdout.write(dumps(r) + '\n')
        return 1
      }
    }
    const pairs = (r) => {
      const m = new Map()
      for (const e of r.entries) m.set(`${e.product_id},${e.build}`, [[e.product_id, e.build], e.tool])
      return m
    }
    const A = pairs(a), B = pairs(b)
    const fmt = (ks, src) => ks.map((k) => src.get(k)).sort((x, y) => cmpTuple(x[0], y[0]))
      .map(([[pid, build], tool]) => ({ product_id: pid, build, tool }))
    process.stdout.write(dumps({
      original: a.file, original_linker: a.linker, build: b.file, build_linker: b.linker,
      matched: fmt([...A.keys()].filter((k) => B.has(k)), A),
      only_in_original: fmt([...A.keys()].filter((k) => !B.has(k)), A),
      only_in_build: fmt([...B.keys()].filter((k) => !A.has(k)), B),
    }, { indent: 1 }) + '\n')
    return 0
  }
  let rc = 0
  for (const p of argv) {
    const r = decode(p)
    rc |= r.error ? 1 : 0
    process.stdout.write(dumps(r) + '\n')
  }
  return rc
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(() => {
    const argv = process.argv.slice(2)
    if (argv.length < 1 || argv[0] === '-h' || argv[0] === '--help') {
      process.stderr.write(DOC + '\n')
      return 2
    }
    return main(argv)
  })
}
