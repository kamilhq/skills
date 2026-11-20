#!/usr/bin/env node
// Port of ../../rust_gnu/gen_defs.py (same command line, output and files). Node built-ins only.
import fs from 'node:fs'
import * as L from '../lib/rwlib.mjs'
import { peExports, writeDef } from '../wintools.mjs'

const DOC = "Generate/extend the import-library .def files the i686-pc-windows-gnu link needs (Python stdlib only).\n\nThe Rust gnu target's prebuilt std links against MinGW import libraries (-lkernel32 -lntdll -lws2_32 ...),\nwhich we do not have (no MinGW install). This tool takes the \"undefined symbol\" lines of a failed rust-lld\nlink, finds which system DLL exports each function (by reading the export tables of the 32-bit DLLs in a\nWine prefix's syswow64 folder, or C:\\Windows\\SysWOW64), and adds the decorated names to <defs>/<lib>.def.\n`build_libs.py runtime --defs <defs>` turns those .def files into lib<lib>.a import libraries with\n`rust-lld -flavor link /lib /def:`.\n\nUsage: gen_defs.py <link-output.txt> [--defs DIR] [--syswow64 DIR]\n       --defs     default: rewrite/third_party/build/rust-gnu/defs (the runtime's copy of this skill's defs)\n       --syswow64 default: $WINEPREFIX or ~/.wine, + drive_c/windows/syswow64\nSymbols that crt_shim.c provides (startup, unwinder stubs) are skipped. Port: ../js/rust_gnu/gen_defs.mjs."
const LIBS = [
  ['kernel32', 'kernel32.dll'], ['msvcrt', 'msvcrt.dll'], ['ntdll', 'ntdll.dll'], ['ws2_32', 'ws2_32.dll'],
  ['userenv', 'userenv.dll'], ['synchronization', 'api-ms-win-core-synch-l1-2-0.dll'], ['advapi32', 'advapi32.dll'],
  ['user32', 'user32.dll']]
const LOOKUP = { 'api-ms-win-core-synch-l1-2-0.dll': 'kernelbase.dll' }
const SYNCH = new Set(['WaitOnAddress', 'WakeByAddressAll', 'WakeByAddressSingle'])
const SHIM = new Set(['mainCRTStartup', 'WinMainCRTStartup', '__main', 'atexit', '__register_frame_info', '__deregister_frame_info'])

export function undecorate (sym) {
  const s = sym.startsWith('_') ? sym.slice(1) : sym
  const m = /^(.*)@(\d+)$/s.exec(s)
  return m ? [m[1], `${sym} == ${m[1]}`] : [s, s]
}
function readDef (p) {
  const names = []
  if (fs.existsSync(p)) {
    for (let line of L.splitlines(fs.readFileSync(p, 'utf8'))) {
      line = line.trim()
      if (line && !['LIBRARY', 'EXPORTS', ';'].some(x => line.startsWith(x))) names.push(line)
    }
  }
  return names
}
const lowerKey = (a, b) => L.cmp(a.toLowerCase(), b.toLowerCase()) || L.cmp(a, b)

export function main (argv) {
  const a = L.parseArgs('gen_defs', DOC, argv, [
    ['--syswow64', 'str', null], ['--defs', 'str', L.join('rewrite', 'third_party', 'build', 'rust-gnu', 'defs')]],
  [['link_output', '1']])
  const sysdir = a.syswow64 || L.join(process.env.WINEPREFIX || L.expanduser('~/.wine'), 'drive_c', 'windows', 'syswow64')
  const exports = {}
  for (const [lib, dll] of LIBS) {
    const p = L.join(sysdir, LOOKUP[dll] || dll)
    exports[lib] = new Set(fs.existsSync(p) ? peExports(p) : [])
  }
  const text = fs.readFileSync(a.link_output, 'utf8')
  const found = [...text.matchAll(/undefined symbol: (\S+)/g)].map(m => m[1])
  const syms = [...new Set(found.length ? found : text.split(/\s+/).filter(Boolean))].sort(L.cmp)
  const defsdir = a.defs
  L.makedirs(defsdir)
  const added = new Map(); const unknown = []
  for (const sym of syms) {
    const [plain, entry] = undecorate(sym)
    if (SHIM.has(plain) || plain.startsWith('_Unwind_')) continue
    const lib = SYNCH.has(plain) ? 'synchronization' : ((LIBS.find(([l]) => exports[l].has(plain)) || [null])[0])
    if (lib === null) { unknown.push(sym); continue }
    if (!added.has(lib)) added.set(lib, new Set())
    added.get(lib).add(entry)
  }
  for (const [lib, dll] of LIBS) {
    const p = L.join(defsdir, lib + '.def')
    const old = readDef(p)
    const nw = [...new Set([...old, ...(added.get(lib) || [])])].sort(lowerKey)
    if (nw.length !== old.length || nw.some((x, i) => x !== old[i]) || !fs.existsSync(p)) {
      writeDef(p, dll, nw)
      const oldSet = new Set(old)
      process.stdout.write(`${L.ljust(lib + '.def', 16)} ${L.rjust(nw.length, 4)} entries (+${nw.filter(x => !oldSet.has(x)).length})\n`)
    }
  }
  if (unknown.length) {
    process.stdout.write(`not found in any DLL (provide them yourself): ${unknown.join(' ')}\n`)
    return 1
  }
  return 0
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
