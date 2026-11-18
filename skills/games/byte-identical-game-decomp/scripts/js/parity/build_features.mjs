#!/usr/bin/env node
// Parity test: build_features.py vs js/build_features.mjs.
//
//   node parity/build_features.mjs [--root PROJECT] [--python python3] [--keep]
//
// Every output goes to a fresh temp analysis dir (never into the project's analysis/). Cases:
//   - each decompiled_* dir with its binary (index.json "callees" mode)
//   - pseudocode mode: the same dirs with "callees" removed from index.json (FUN_/LAB_ references, names
//     resolved through namespaces, ambiguous names)
//   - synthetic callee forms: {address}/{addr}/{name} objects, EXTERNAL: addresses, plain names, ints, thunk_of
//   - --chunk-lines 1000 (more than 100 chunks: 3-digit ids) and 50000
//   - a rerun into a dir with stale chunk files; a dir holding another binary's features (exit 2) and the same
//     with --force; features.json without features_meta.json (stderr note); a decompile of another binary
//     (exit 2); a non-PE binary (exit 1); bad argument counts (exit 1, docstring); --chunk-lines without value
//   - function level, against the Python module imported: vftable_name() on mangled names (these binaries
//     export no vftables, so the files never exercise it), parse_callee() on every callee form, and FUN/STR/
//     REF/CALLTOK/VTREF findall() on every 40th pseudocode file plus a synthetic one (vftable refs, non-ASCII)
// Compares exit code, stdout, stderr and every file in the analysis dir.
import { existsSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { Parity, parseOpts, projectBinaries, SK } from '../lib/peparity.mjs'
import { dumps, parse } from '../lib/pyjson.mjs'

const opts = parseOpts(process.argv.slice(2), { root: undefined, python: undefined, keep: false })
const P = new Parity('build_features', opts)
let n = 0
const newDirs = () => { const k = n++; return [P.tmpPath(`py_${k}`), P.tmpPath(`js_${k}`)] }

// run both sides: pre = list of arg lists run first on each side (setup), then the compared run
function both(name, args, { pre = [], prepare } = {}) {
  const [dp, dj] = newDirs()
  if (prepare) { prepare(dp); prepare(dj) }
  const map = (a, d) => a.map((x) => (x === '@A@' ? d : x))
  for (const p of pre) { P.run('py', map(p, dp)); P.run('js', map(p, dj)) }
  const a = P.run('py', map(args, dp)), b = P.run('js', map(args, dj))
  // the analysis dir differs per side: compare messages with it replaced by a placeholder
  for (const [r, d] of [[a, dp], [b, dj]]) for (const k of ['stdout', 'stderr']) r[k] = Buffer.from(r[k].toString().split(d).join('<analysis_dir>'))
  const tb = a.stderr.toString().startsWith('Traceback')
  P.compare(name, a, b, { stderr: !tb, dirs: [[dp, dj]] })
}

// a decompile dir whose index.json is rewritten (functions/ linked)
function variant(src, name, edit) {
  const d = P.tmpPath(`dec_${name}`)
  mkdirSync(d)
  symlinkSync(join(src, 'functions'), join(d, 'functions'))
  const idx = parse(readFileSync(join(src, 'index.json'), 'utf8'))
  edit(idx.get('functions'))
  writeFileSync(join(d, 'index.json'), dumps(idx))
  return d
}

// the decompile dirs of every binary of PROJECT/decomp.json (exit 2 without one): [dir, binary, named?]
const bins = projectBinaries(P.root, { script: 'build_features' })
const exeOf = new Map(bins.map((b) => [b.file, b.abs.exe]))
const pairs = bins.flatMap((b) => [[b.decompiled, b.file, false], [b.named, b.file, true]])
  .filter(([d, b]) => existsSync(P.path(d, 'index.json')) && existsSync(exeOf.get(b)))
for (const [dd, bin] of pairs) {
  const exe = exeOf.get(bin)
  both(`${dd} index mode`, [P.path(dd), exe, '@A@'])
  const pseudo = variant(P.path(dd), `${dd}_pseudo`, (fs) => { for (const f of fs) f.delete('callees') })
  both(`${dd} pseudocode mode`, [pseudo, exe, '@A@'])
}
if (pairs.length) {
  const [dd, bin] = pairs.find(([, , named]) => named) ?? pairs[0]
  const exe = exeOf.get(bin)
  const syn = variant(P.path(dd), 'callee_forms', (fs) => {
    fs.forEach((f, i) => {
      const cs = f.get('callees') ?? []
      const m = new Map()
      if (i % 6 === 0) f.set('callees', cs.map((c) => new Map([['address', c]])))
      else if (i % 6 === 1) f.set('callees', [...cs.map((c) => new Map([['addr', c], ['name', 'n_' + c]])), 'EXTERNAL:00000010', ' KERNEL32.DLL::Sleep ', ''])
      else if (i % 6 === 2) f.set('callees', [...cs, new Map([['name', 'ext_fn']]), new Map([['address', null], ['name', 'other']]), null, 4198400])
      else if (i % 6 === 3) f.set('callees', [...cs, 'external:abc', '0X' + (cs[0] ?? '0x1').slice(2), 'not hex'])
      else if (i % 6 === 4) f.set('callees', null)
      if (f.get('size') <= 8) {
        if (i % 3 === 0) f.set('thunk_of', 'KERNEL32.DLL::GetTickCount')
        else if (i % 3 === 1) f.set('thunk_of', '0x401000')
      }
      void m
    })
    fs.push(new Map([['address', 'EXTERNAL:00000001'], ['name', 'bad'], ['size', 1]]), new Map([['address', 7], ['name', 'int addr'], ['size', 1]]))
  })
  both('synthetic callee forms', [syn, exe, '@A@'])
  both('--chunk-lines 1000', [P.path(dd), exe, '@A@', '--chunk-lines', '1000'])
  both('--chunk-lines 50000 --force', ['--force', P.path(dd), exe, '@A@', '--chunk-lines', '50000'])
  both('rerun over stale chunks', [P.path(dd), exe, '@A@'], { pre: [[P.path(dd), exe, '@A@', '--chunk-lines', '1000']] })
  const other = pairs.find(([, b]) => b !== bin)
  if (other) {
    const oexe = exeOf.get(other[1])
    both('dir of another binary (exit 2)', [P.path(other[0]), oexe, '@A@'], { pre: [[P.path(dd), exe, '@A@']] })
    both('dir of another binary --force', [P.path(other[0]), oexe, '@A@', '--force'], { pre: [[P.path(dd), exe, '@A@']] })
    both('decompile of another binary (exit 2)', [P.path(other[0]), exe, '@A@'])
  }
  both('features.json without meta (note)', [P.path(dd), exe, '@A@'], { prepare: (d) => { mkdirSync(d); writeFileSync(join(d, 'features.json'), '[]') } })
  const textFile = P.tmpPath('readme.txt')
  writeFileSync(textFile, 'a text file, not a PE\n')
  both('not a PE (exit 1)', [P.path(dd), textFile, '@A@'])
  both('two arguments', [P.path(dd), exe])
  both('four arguments', [P.path(dd), exe, '@A@', 'extra'])
  both('--chunk-lines without value', [P.path(dd), exe, '@A@', '--chunk-lines'])
  both('no arguments', [])
}

// function level: vftable_name, parse_callee and the five regexes (findall) on pseudocode files + synthetic text
{
  const mangled = ['??_7Inner@Outer@@6B@', '??_7C@@6BB@@@', '??_8D@@7B@', '??_8D@@6BBase@NS@@@', '??_7A@@6B@\n', '??_7@@6B@',
                   '?foo@@YAXXZ', '??_7Tmpl@?$x@H@@6B@', '??_7a_b1@c@@6B@@@', '??_7X@@6Bjunk', '']
  const callees = ['0x401000', ' 0x401000 ', '401000', 'EXTERNAL:00000010', 'external:1', 'Sleep', '', '0x_1', '1_000', '-0x10', null, 5, true,
                   { address: '0x401000' }, { addr: '0x10', name: 'n' }, { name: 'only' }, { address: null, name: 'nm' }, { address: 'bad', name: '' },
                   { address: 'EXTERNAL:1' }, [1, 2]]
  const files = []
  for (const dd of [...new Set([...pairs.filter(([, , named]) => named), ...pairs.filter(([, , named]) => !named)].map(([d]) => d))]) {
    const fd = P.path(dd, 'functions')
    if (!existsSync(fd)) continue
    for (const f of readdirSync(fd).sort().filter((x, i) => x.endsWith('.c') && i % 40 === 0)) files.push(join(fd, f))
  }
  const synth = P.tmpPath('synthetic.c')
  writeFileSync(synth, 'void f(void)\n{\n  *this = &Outer::Inner::vftable;\n  p = & ns::C<int,2>::_vbtable_ ;\n  x = DAT_00401000 + _DAT_1000e280 + &PTR_FUN_1000e20c;\n' +
    '  s_Hello_world_00712345; s_\u00e9_00712345; \u00e9DAT_00401000; FUN_00401000(); thunk_FUN_00401000 (1);\n  ~Dtor(); A::B::c (x); __x(); \u00fcber(); if (a) while(b) CONCAT44(x);\n' +
    '  LAB_00401000: Ns::_vftable_x; Ns::vftable; Ns::vftable_ ;\r\n  bad\udcff\n}\n')
  files.push(synth)
  const listFile = P.tmpPath('files.json')
  writeFileSync(listFile, dumps({ mangled, callees, files }))
  const pyCode = `import json, sys
sys.path.insert(0, sys.argv[1])
import build_features as B
a = json.load(open(sys.argv[2]))
out = {'vftable_name': [B.vftable_name(m) for m in a['mangled']], 'parse_callee': [B.parse_callee(c) for c in a['callees']], 'files': []}
for p in a['files']:
    body = open(p, encoding='utf-8', errors='replace').read()
    out['files'].append({'FUN': B.FUN.findall(body), 'STR': B.STR.findall(body), 'REF': B.REF.findall(body),
                         'CALLTOK': B.CALLTOK.findall(body), 'VTREF': B.VTREF.findall(body)})
sys.stdout.write(json.dumps(out))`
  const t = process.hrtime.bigint()
  const py = spawnSync(P.python, ['-I', '-c', pyCode, SK, listFile], { maxBuffer: 1 << 28 })
  P.pySec += Number(process.hrtime.bigint() - t) / 1e9
  const t2 = process.hrtime.bigint()
  const B = await import('../build_features.mjs')
  const { decodeUtf8, universalNewlines } = await import('../lib/pytools.mjs')
  const toPy = (v) => (v instanceof Map ? new Map([...v].map(([k, x]) => [k, toPy(x)])) : Array.isArray(v) ? v.map(toPy) : v)
  const fa = (re, body) => [...body.matchAll(re)].map((m) => (m.length > 2 ? m.slice(1).map((x) => x ?? '') : m[1]))
  const js = { vftable_name: mangled.map(B.vftable_name),
               parse_callee: parse(dumps(callees)).map((c) => B.parse_callee(toPy(c))), files: [] }
  for (const p of files) {
    const body = universalNewlines(decodeUtf8(readFileSync(p), 'replace'))
    js.files.push({ FUN: fa(B.FUN, body), STR: fa(B.STR, body), REF: fa(B.REF, body), CALLTOK: fa(B.CALLTOK, body), VTREF: fa(B.VTREF, body) })
  }
  P.jsSec += Number(process.hrtime.bigint() - t2) / 1e9
  const pj = py.status === 0 ? parse(py.stdout.toString()) : null
  const jj = parse(dumps(js))
  P.record('vftable_name on mangled names', pj && dumps(pj.get('vftable_name')) === dumps(jj.get('vftable_name')) ? [] : ['differs: ' + py.stderr])
  P.record('parse_callee on callee forms', pj && dumps(pj.get('parse_callee')) === dumps(jj.get('parse_callee')) ? [] : ['differs'])
  files.forEach((f, i) => P.record(`regex findall on ${f}`, pj && dumps(pj.get('files')[i]) === dumps(jj.get('files')[i]) ? [] : ['differs']))
}
P.finish({ decompile_dirs: pairs.map(([d]) => d) })
