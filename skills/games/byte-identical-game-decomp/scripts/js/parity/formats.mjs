#!/usr/bin/env node
// Parity test: the skill's generic format modules, scripts/formats/fmt_<m>.py vs scripts/js/formats/fmt_<m>.mjs
// (text, png, wav, zip; with their helpers pngio, fmt_png_zlib, fmt_png_deflate, fmt_zip_7zdeflate), each run
// through its verify script (scripts/verify.py --formats-dir scripts/formats, js/verify.mjs --formats-dir
// js/formats) on the project's game files.
//
//   node parity/formats.mjs [--root PROJECT] [--python python3] [--quick] [--only MODULE] [--keep] [--tmp DIR]
//
// Trees (PROJECT = the current directory by default): text on work/game, png on work/game and
// extracted, wav on extracted, zip on work/game (the game's ZIP archives and the GOG .hashdb). --quick: zip on the
// .hashdb only (the 7-Zip deflate search of a large archive can take Python over ten minutes). Without
// PROJECT/work/game the test stops with exit 2.
// Cases, per (module, tree):
//   verify      exit code, stderr, stdout and the report JSON except their "seconds" field (timing)
//   per file    the decoded folder of the JS run is byte-identical to Python's (same files and directories);
//               JS encode_from_dir of the JS folder and of the Python folder give the original bytes; Python
//               encode_from_dir of the JS folder gives the original bytes (run when the two folders differ, or
//               for every module but zip: when they are identical it is the encode verify.py already checked)
// Prints one JSON summary; exit 0 only when every case is identical.
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, readFileSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { compareDirs, fail, JS_DIR, Parity, parseOpts, SK } from '../lib/peparity.mjs'
import { parse } from '../lib/pyjson.mjs'

const opts = parseOpts(process.argv.slice(2), { root: undefined, python: undefined, quick: false, only: undefined,
  keep: false, tmp: undefined })
const P = new Parity('formats', opts)
const t = (...p) => P.tmpPath(...p)
const PY_FMT = join(SK, 'formats'), JS_FMT = join(JS_DIR, 'formats')

if (!existsSync(P.path('work', 'game'))) fail('formats', `${P.path('work', 'game')} not found: run it from a decomp project (or pass --root PROJECT) whose work/game holds the game files`)
let zipSrc = P.path('work', 'game')
if (opts.quick) {          // a tree with the .hashdb only
  zipSrc = t('zip_quick')
  mkdirSync(zipSrc)
  for (const f of readdirSync(P.path('work', 'game')).filter((x) => x.toLowerCase().endsWith('.hashdb'))) {
    symlinkSync(P.path('work', 'game', f), join(zipSrc, f))
  }
}
const JOBS = [['text', P.path('work', 'game')], ['png', P.path('work', 'game')],
  ['png', P.path('extracted')], ['wav', P.path('extracted')], ['zip', zipSrc]]
  .filter(([m, s]) => (!opts.only || opts.only === m) && existsSync(s))

const PY_ENCODE = `
import importlib.util, json, os, sys
fd, name = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.abspath(fd))
spec = importlib.util.spec_from_file_location('fmt_' + name, os.path.join(fd, 'fmt_%s.py' % name))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
out = []
for d, orig in json.load(sys.stdin):
    try:
        out.append([mod.encode_from_dir(d) == open(orig, 'rb').read(), None])
    except Exception as e:
        out.append([False, repr(e)[:300]])
print(json.dumps(out))
`
// every directory below d (relative paths, sorted)
function dirsOf(d, rel = '', out = []) {
  if (!existsSync(d)) return out
  for (const e of readdirSync(d, { withFileTypes: true })) {
    if (e.isDirectory()) { out.push(rel + e.name); dirsOf(join(d, e.name), rel + e.name + '/', out) }
  }
  return rel ? out : out.sort()
}
const stripSeconds = (b) => Buffer.from(b.toString('utf8').replace(/\n "seconds": [^\n]*\n/, '\n'))
const modules = {}
const trees = []

for (const [k, [m, src]] of JOBS.entries()) {
  const T = t(String(k))
  const args = (fd, side) => [m, '--src', src, '--formats-dir', fd, '--out', join(T, side), '--report', join(T, `${side}rep`)]
  const a = P.run('py', args(PY_FMT, 'py'), { pyScript: join(SK, 'verify.py') })
  const b = P.run('js', args(JS_FMT, 'js'), { jsScript: join(JS_DIR, 'verify.mjs') })
  const name = `${m} on ${src === zipSrc && opts.quick ? 'work/game (the .hashdb only)' : src.startsWith(P.root) ? src.slice(P.root.length + 1) : src}`
  const canon = (f, buf) => (f === 'stdout' || /rep\/[^/]+\.json$/.test(f) ? stripSeconds(buf) : buf)
  P.compare(`${name}: verify (exit, stdout, stderr, report without seconds)`, a, b,
    { stderr: true, files: [[join(T, 'pyrep', `${m}.json`), join(T, 'jsrep', `${m}.json`)]], canon })
  const repFile = join(T, 'pyrep', `${m}.json`)
  if (!existsSync(repFile)) continue
  const rep = parse(readFileSync(repFile, 'utf8'))
  const rels = [...rep.get('per_file').map((f) => f.get('file')), ...rep.get('failures').map((f) => f.get('file'))]
  const tree = { module: m, src: name.split(' on ')[1], files: rels.length, python_verify_seconds: Number(rep.get('seconds')),
    js_verify_seconds: Number(parse(readFileSync(join(T, 'jsrep', `${m}.json`), 'utf8')).get('seconds')), identical: 0 }
  trees.push(tree)
  modules[m] ??= await import(pathToFileURL(join(JS_FMT, `fmt_${m}.mjs`)).href)
  const diffsOf = rels.map((rel) => compareDirs(join(T, 'py', m, rel), join(T, 'js', m, rel)))
  const pyNeed = rels.map((rel, i) => m !== 'zip' || diffsOf[i].length > 0)
  const pairs = rels.map((rel) => [join(T, 'js', m, rel), join(src, rel)]).filter((x, i) => pyNeed[i])
  let pyEnc = []
  if (pairs.length) {
    const t0 = process.hrtime.bigint()
    const r = spawnSync(P.python, ['-I', '-c', PY_ENCODE, PY_FMT, m], { input: JSON.stringify(pairs), maxBuffer: 1 << 30 })
    P.pySec += Number(process.hrtime.bigint() - t0) / 1e9
    pyEnc = r.status === 0 ? JSON.parse(r.stdout.toString()) : pairs.map(() => [false, r.stderr.toString().slice(-300)])
  }
  let q = 0
  rels.forEach((rel, i) => {
    const orig = readFileSync(join(src, rel))
    const bad = [...diffsOf[i]]
    const t0 = process.hrtime.bigint()
    for (const side of ['js', 'py']) {
      try {
        if (!Buffer.from(modules[m].encode_from_dir(join(T, side, m, rel))).equals(orig)) bad.push(`JS encode of the ${side} folder: not the original bytes`)
      } catch (e) { bad.push(`JS encode of the ${side} folder: ${String(e).slice(0, 200)}`) }
    }
    P.jsSec += Number(process.hrtime.bigint() - t0) / 1e9
    if (pyNeed[i]) {
      const [ok, why] = pyEnc[q++] ?? [false, 'missing']
      if (!ok) bad.push(`Python encode of the JS folder: ${why ?? 'not the original bytes'}`)
    }
    if (!bad.length) tree.identical++
    P.record(`${name}: ${rel} (decoded folder identical, encodes give the original)`, bad)
  })
  // the whole output trees (directories included) hold the same files
  const da = dirsOf(join(T, 'py', m)), db = dirsOf(join(T, 'js', m))
  P.record(`${name}: whole decoded trees (files and directories)`, [...compareDirs(join(T, 'py', m), join(T, 'js', m)),
    ...(da.join('\n') === db.join('\n') ? [] : ['directory sets differ'])].slice(0, 5))
}
P.finish({ trees, quick: opts.quick })
