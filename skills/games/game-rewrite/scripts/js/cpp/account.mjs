#!/usr/bin/env node
// Port of ../../cpp/account.py (same command line, output and files). Node built-ins only.
import fs from 'node:fs'
import * as L from '../lib/rwlib.mjs'
import * as C from './cppsplit.mjs'

const PROG = 'account'
const DOC = "Account for every function annotation of the matched units: where it went, or why it is not there.\n\n  python3 -I account.py --config CFG.json [--units DIR] [--tree DIR] [--names INDEX.json] [--map OUT.json]\n                        [--project DIR]\n\nReads every `// FUNCTION:` and `// STUB:` annotation of the units (cppsplit.py; other kinds are counted\nonly) and puts each in exactly one category:\n  thunk          a dynamic initializer / atexit thunk: symbol matching \"thunk_symbols\" (default ??__E/??__F),\n                 name (from --names) matching \"thunk_names\", or an annotation on a variable definition; the\n                 compiler makes it again from the global's definition\n  in_tree        --tree given: a comment `// 0x<address>` (or `/* 0x<address>`) at the start of a line of a\n                 .c/.cpp/.h file of the tree (the rewrite); the file is recorded\n  planned        no --tree: a function of a game unit with a destination file (emit.py's placement rules)\n  library_unit   in a unit of \"library_units\" (CRT, STL instances, library copies: not rewritten)\n  stub           a // STUB (Ghidra fragment of another function, CRT object, code the rewrite replaces)\n  dropped        listed in the config's \"dropped\" {address: reason}\n  not_a_definition  the annotation is not on a function definition (e.g. an implicit member)\n  unaccounted    none of the above: a function the rewrite lost (or one without a destination)\nNONMATCHING tags are counted, and how many of them are in the tree. Addresses that the tree has but no\nannotation has are listed as \"tree_only\" (functions written new, e.g. a rewritten WinMain).\n--names reads the decomp skill's function index ({\"functions\": [{\"address\", \"name\"}]}) for names and the\nthunk test. --map writes one row per annotation (address, name, unit, annotation, nonmatching, category,\nfile, reason). Prints a JSON summary. Exit 0, 1 when something is unaccounted, 2 on bad input.\nPython standard library only. Port: ../js/cpp/account.mjs."
const ADDR_LINE = /^[ \t]*(?:\/\/|\/\*)[ \t]*(0x[0-9a-fA-F]+)\b/
const EXTS = ['.c', '.cpp', '.h', '.hpp', '.cc', '.cxx']

function scanTree (root) {
  const found = new Map()
  const walk = dir => {
    const names = L.listdirSorted(dir)
    const dirs = names.filter(n => L.isdir(L.join(dir, n)))
    for (const f of names.filter(n => !L.isdir(L.join(dir, n)))) {
      if (!EXTS.some(e => f.endsWith(e))) continue
      const p = L.join(dir, f)
      const rel = L.relpath(p, root)
      for (const line of C.readText(p).split('\n')) {
        const m = ADDR_LINE.exec(line)
        if (m && !found.has(m[1].toLowerCase())) found.set(m[1].toLowerCase(), rel)
      }
    }
    for (const d of dirs) walk(L.join(dir, d))
  }
  walk(root)
  return found
}

function loadNames (p) {
  const d = L.pyParse(fs.readFileSync(p, 'utf8'))
  const fns = d && !Array.isArray(d) && typeof d === 'object' ? (d.functions || []) : d
  const out = new Map()
  for (const x of fns) if (x && typeof x === 'object' && !Array.isArray(x)) out.set(L.pyStr(x.address === undefined ? '' : x.address).toLowerCase(), x.name === undefined ? '' : x.name)
  return out
}

function account (cfg, unitsDir, tree, names) {
  const module = cfg.module || null
  const libs = new Set(cfg.library_units || [])
  const placer = new C.Placer(cfg)
  const thunkSym = new RegExp(cfg.thunk_symbols || '^\\?\\?__[EF]')
  const thunkName = new RegExp(cfg.thunk_names || '^(dynamic_initializer_for|dynamic_atexit_destructor_for)')
  const dropped = new Map(Object.entries(cfg.dropped || {}).map(([k, v]) => [k.toLowerCase(), v]))
  const pre = (cfg.renames || {}).members || {}
  const inTree = tree ? scanTree(tree) : new Map()
  const rows = []; const other = {}
  for (const p of C.unitFiles(unitsDir, cfg)) {
    const u = C.unitId(cfg, p)
    const [, items] = C.loadUnit(p, cfg, module, pre)
    for (const [, , anns, nonm, cls, fn] of items) {
      for (const [kind, addr, sym] of anns) {
        if (kind !== 'FUNCTION' && kind !== 'STUB') { other[kind] = (other[kind] || 0) + 1; continue }
        const name = names.get(addr) || (fn !== null ? fn.qual : (sym || ''))
        let cat = null; let f = null; let reason = null
        if ((sym && thunkSym.test(sym)) || thunkName.test(names.get(addr) || '') || cls === 'vardef') cat = 'thunk'
        else if (tree && inTree.has(addr)) { cat = 'in_tree'; f = inTree.get(addr) } else if (libs.has(u)) cat = 'library_unit'
        else if (kind === 'STUB') cat = 'stub'
        else if (dropped.has(addr)) { cat = 'dropped'; reason = dropped.get(addr) } else if (cls !== 'funcdef') cat = 'not_a_definition'
        else if (tree) { cat = 'unaccounted'; reason = 'not in the tree' } else {
          f = placer.dest(u, fn, addr)
          if (f === undefined) f = null
          cat = f ? 'planned' : 'unaccounted'
          reason = f ? null : 'no destination'
        }
        rows.push(new Map([['addr', addr], ['name', name], ['unit', u], ['annotation', kind], ['nonmatching', nonm], ['category', cat], ['file', f], ['reason', reason]]))
      }
    }
  }
  const hex = x => parseInt(x, 16)
  rows.sort((a, b) => hex(a.get('addr')) - hex(b.get('addr')) || L.cmp(a.get('unit'), b.get('unit')))
  const cats = {}; const byKind = {}; const files = {}
  for (const r of rows) {
    cats[r.get('category')] = (cats[r.get('category')] || 0) + 1
    const k = `${r.get('annotation')} ${r.get('category')}`
    byKind[k] = (byKind[k] || 0) + 1
    if (r.get('file')) files[r.get('file')] = (files[r.get('file')] || 0) + 1
  }
  const annotated = new Set(rows.map(r => r.get('addr')))
  const treeOnly = [...inTree.keys()].filter(a => !annotated.has(a)).sort((x, y) => hex(x) - hex(y))
  const un = rows.filter(r => r.get('category') === 'unaccounted')
  const so = o => new Map(Object.entries(o).sort((a, b) => L.cmp(a[0], b[0])))
  const placed = new Set(['in_tree', 'planned'])
  const summary = new Map([
    ['annotations', rows.length],
    ['functions', rows.filter(r => r.get('annotation') === 'FUNCTION').length],
    ['stubs', rows.filter(r => r.get('annotation') === 'STUB').length],
    ['other_annotations', so(other)],
    ['nonmatching', rows.filter(r => r.get('nonmatching')).length],
    ['nonmatching_placed', rows.filter(r => r.get('nonmatching') && placed.has(r.get('category'))).length],
    ['categories', so(cats)],
    ['by_annotation', so(byKind)],
    ['files', so(files)],
    ['tree_only', new Map([['count', treeOnly.length], ['addresses', treeOnly.slice(0, 50)]])],
    ['unaccounted', new Map([['count', un.length], ['first', un.slice(0, 50).map(r => `${r.get('addr')} ${r.get('name')} (${r.get('unit')}, ${L.pyStr(r.get('reason'))})`)]])]
  ])
  return [summary, rows]
}

function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [['--config', 'str', L.REQUIRED], ['--units', 'str', null], ['--tree', 'str', null],
    ['--names', 'str', null], ['--map', 'str', null], ['--project', 'str', '.']])
  const err = msg => { process.stdout.write(L.dumps({ error: msg }) + '\n'); return 2 }
  let cfg
  try { cfg = C.loadConfig(a.config) } catch (e) {
    if (e instanceof C.OSErr || e instanceof SyntaxError) return err(`config cannot be read: ${a.config}`)
    throw e
  }
  const units = a.units || (cfg.units ? L.join(a.project, cfg.units) : null)
  if (!units || !L.isdir(units)) return err('no units folder (--units or "units" in the config)')
  if (a.tree && !L.isdir(a.tree)) return err(`no such tree: ${a.tree}`)
  let names = new Map()
  if (a.names) {
    try { names = loadNames(a.names) } catch (e) { return err(`names index cannot be read: ${a.names}`) }
  }
  const [summary, rows] = account(cfg, units, a.tree, names)
  if (a.map) C.writeText(a.map, L.dumps(rows) + '\n')
  process.stdout.write(L.dumps(summary) + '\n')
  return summary.get('unaccounted').get('count') ? 1 : 0
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
