#!/usr/bin/env node
// Port of ../release_check.py (same command line, output and exit codes). Node built-ins only.
import fs from 'node:fs'
import * as L from './lib/rwlib.mjs'
import * as C from './lib/cleanlib.mjs'

const PROG = 'release_check'
const DOC = "The release gate of a clean-room rewrite (references/cleanroom.md): may this source tree be published?\n\n  python3 -I release_check.py [TREE] [--project DIR] [--json OUT] [--quiet]\n\nTREE (default: decomp.json \"rewrite.cleanroom.tree\", else rewrite/clean) is the source that would be published.\nFiles matching \"tree_exclude\" (default third_party/, vendor/, target/, build/, .git/) are not checked. Settings\ncome from decomp.json \"rewrite.cleanroom\" (keys and defaults in references/cleanroom.md). Checks:\n  log         the clean-room log verifies (hash chain intact, an init and at least one pack entry)\n  assets      no file equals (SHA-256) a file of the game, extracted or decoded folders (\"assets\")\n  markers     no address annotations (// FUNCTION: 0x..., // 0x<address> lines), stub!(0x..), and no Ghidra\n              names (FUN_, DAT_, undefined4, iVar1, param_1, in_EAX ...) anywhere in a source file\n  tables      no embedded numeric table of >= table_items numbers or string table of >= string_items strings\n              (game data is read from the user's own files at run time)\n  strings     string literals of >= min_string characters shared with the reference: <= string_bytes in total\n  names       function definitions named like a phase-5 name of the original (\"names\" files): <= names_pct %\n              (applies from names_min definitions on)\n  similarity  fingerprints of the tree found in the reference code (decompiled, named, matched source and the\n              private rewrites: \"reference\"): code (token 12-grams, identifiers abstracted, with at least two\n              significant numbers or strings, winnowed) <= code_pct %, constant sequences (5-grams of numbers\n              >= 32 or non-trivial floats) <= const_pct %, and no file with >= file_min fingerprints above\n              file_pct %\n  notices     a LICENSE (or COPYING) and a README at the top of the tree; with libraries in\n              \"rewrite.libraries\", a third-party notice (THIRD_PARTY*, LICENSES*, NOTICE*)\nAn allow file (\"allow\", default cleanroom/allow.json: {\"findings\": [{\"check\", \"file\", \"line\"?, \"reason\"}]})\naccepts single findings with a written reason; they are listed under \"allowed\". Prints findings to stderr\n(unless --quiet) and a JSON summary: passed, tree, files, checks {name: {passed, findings_total, findings (the\nfirst 200), ...}}, allowed, manual (what no script can check).\nExit 0 passed, 1 failed, 2 bad input. Python standard library only."
const MANUAL = [
  'the name and the README do not suggest the rewrite is the original or endorsed by its owner; ' +
  'no logos or artwork of the original',
  'the README says that the original game is required and not included',
  'the licence of the rewrite covers only the rewrite\'s own code',
  'no game data, saves, screenshots or recordings of the original in the repository history either',
  'the clean-room log was kept for every implementer and the specs went through cleanroom.py lint'
]
const MAX_FINDINGS = 200
const CHECKS = ['log', 'assets', 'markers', 'tables', 'strings', 'names', 'similarity', 'notices']

class InputError extends Error {}
const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v)

function loadJson (project, p) {
  try { return L.pyParse(fs.readFileSync(L.join(project, p)).toString('utf8')) } catch { throw new InputError(`${p}: not a readable JSON file`) }
}
function loadAllow (project, p) {
  if (!fs.existsSync(L.join(project, p))) return []
  const d = loadJson(project, p)
  const items = isObj(d) ? d.findings : undefined
  if (!Array.isArray(items)) throw new InputError(`${p}: expected {"findings": [...]}`)
  items.forEach((a, i) => {
    if (!isObj(a) || !a.check || !a.file || !C.strip(a.reason === undefined || a.reason === null ? '' : L.pyStr(a.reason)).length) {
      throw new InputError(`${p}: finding ${i} needs "check", "file" and a non-empty "reason"`)
    }
  })
  return items
}
export const normalizeName = n => n.replaceAll('_', '').toLowerCase()
function loadNames (project, files) {
  const out = new Set()
  for (const f of files) {
    const p = L.join(project, f)
    if (!fs.existsSync(p)) continue
    const vals = []
    if (f.endsWith('.json')) {
      const d = loadJson(project, f)
      const items = isObj(d) ? Object.values(d) : (Array.isArray(d) ? d : [])
      for (let v of items) {
        if (isObj(v)) v = v.name
        if (typeof v === 'string') vals.push(v)
      }
    } else {
      for (const line of C.readText(p).split('\n')) {
        const cols = line.replace(/\r+$/, '').split('\t')
        if (cols.length >= 2) vals.push(cols[1])
      }
    }
    for (const v of vals) {
      if (['FUN_', 'thunk_', 'FID_conflict', 'LAB_', 'DAT_', 'switchD_'].some(x => v.startsWith(x))) continue
      const parts = v.split('::')
      const n = normalizeName(parts[parts.length - 1])
      if (C.cpLen(n) >= 6) out.add(n)
    }
  }
  return out
}
export function functionDefs (toks, rust) {
  const out = []
  const n = toks.length
  for (let i = 0; i < n; i++) {
    const [kind, t, ln] = toks[i]
    if (rust) {
      if (kind === 'ident' && t === 'fn' && i + 1 < n && toks[i + 1][0] === 'ident') out.push([toks[i + 1][1], toks[i + 1][2]])
      continue
    }
    if (kind !== 'ident' || C.NOT_FN.has(t) || i + 1 >= n || toks[i + 1][1] !== '(') continue
    if (i && ['.', '->', '=', 'new', 'return', 'else'].includes(toks[i - 1][1])) continue
    let depth = 0; let j = i + 1
    while (j < n) {
      const x = toks[j][1]
      if (x === '(') depth++
      else if (x === ')') { depth--; if (depth === 0) break } else if ((x === ';' || x === '{' || x === '}') && depth > 0) { j = n; break }
      j++
    }
    j++
    while (j < n && toks[j][0] === 'ident' && C.FN_SKIP.has(toks[j][1])) j++
    if (j < n && toks[j][1] === '{') out.push([t, ln])
  }
  return out
}
export function tables (toks, th) {
  const out = []
  const numOk = new Set([',', '-', '{', '}', '[', ']', '(', ')'])
  const strOk = new Set([',', '{', '}', '[', ']', '&'])
  for (const [kindName, item, ok, limit] of [['numbers', 'number', numOk, th.table_items], ['strings', 'string', strOk, th.string_items]]) {
    let count = 0; let start = null
    for (const [kind, t, ln] of [...toks, ['end', '', 0]]) {
      if (kind === item) { if (start === null) start = ln; count++ } else if (kind === 'punct' && ok.has(t)) continue
      else {
        if (count >= limit) out.push([kindName, count, start])
        count = 0; start = null
      }
    }
  }
  return out
}
const pct = (a, b) => (b ? Math.floor(a * 100 / b) : 0)
const loc = (f) => (f.line ? ':' + f.line : '')

function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [['--project', 'str', '.'], ['--json', 'str', null], ['--quiet', 'flag', false]], [['tree', '?']])
  const project = L.abspath(a.project)
  let s, th, allow, names
  try {
    s = C.settings(project)
    th = s.thresholds
    allow = loadAllow(project, s.allow)
    names = loadNames(project, s.names)
  } catch (e) {
    if (!(e instanceof InputError) && !(e instanceof SyntaxError)) throw e
    process.stderr.write(`${PROG}: error: ${e.message}\n`)
    return 2
  }
  const tree = a.tree !== null && a.tree !== undefined ? a.tree : s.tree
  const treeRel = C.rel(project, require_abs(project, tree))
  if (treeRel === null || !L.isdir(L.join(project, treeRel))) {
    process.stderr.write(`${PROG}: error: ${tree}: not a folder inside the project\n`)
    return 2
  }
  const hit = C.globMatch(treeRel, s.forbidden)
  const files = C.walk(project, treeRel, s.tree_exclude.map(x => treeRel + '/' + x))
  const checks = new Map(CHECKS.map(c => [c, new Map([['passed', true], ['findings', []]])]))
  const find = (check, file, line, detail) => checks.get(check).get('findings').push({ file, line, detail })
  const upd = (check, obj) => { for (const [k, v] of Object.entries(obj)) checks.get(check).set(k, v) }

  if (hit) find('log', treeRel, 0, `the tree is inside a forbidden area (${hit}): it is not a clean-room tree`)

  const v = C.verifyLog(L.join(project, s.log))
  upd('log', { entries: v.get('entries'), events: v.get('events'), waves: v.get('waves') })
  if (s.require_log) {
    for (const p of v.get('problems')) find('log', s.log, 0, p)
    if (v.get('entries') && !v.get('events').get('pack')) find('log', s.log, 0, 'no pack entry: no implementer workspace was recorded')
  }

  const sizes = new Map()
  for (const f of files) {
    const z = fs.statSync(L.join(project, f)).size
    if (!sizes.has(z)) sizes.set(z, [])
    sizes.get(z).push(f)
  }
  let assetFiles = 0
  const treeHash = new Map()
  for (const d of s.assets) {
    if (!fs.existsSync(L.join(project, d))) continue
    for (const g of C.walk(project, d)) {
      assetFiles++
      const size = fs.statSync(L.join(project, g)).size
      if (size === 0 || !sizes.has(size)) continue
      const gh = L.sha256File(L.join(project, g))
      for (const f of sizes.get(size)) {
        if (!treeHash.has(f)) treeHash.set(f, L.sha256File(L.join(project, f)))
        if (treeHash.get(f) === gh) find('assets', f, 0, `identical to ${g}`)
      }
    }
  }
  upd('assets', { asset_files: assetFiles })

  const corpus = new C.Corpus(project, s.reference, s.reference_exclude)
  upd('similarity', { reference_files: corpus.files.length, reference_missing: corpus.missing })
  const tot = { code: [0, 0], consts: [0, 0] }
  const perFile = []
  const sharedStrings = new Map()
  let defsTotal = 0; let defsShared = 0; const sharedExamples = []
  for (const f of files) {
    const p = L.join(project, f)
    if (!C.isCode(f) || !C.isText(p)) continue
    const text = C.readText(p)
    text.split('\n').forEach((line, i) => {
      let m = C.GHIDRA_RE.exec(line)
      if (m) find('markers', f, i + 1, `Ghidra name ${m[0]}`)
      m = C.STUB_RE.exec(line)
      if (m) find('markers', f, i + 1, `address stub ${m[0]}`)
    })
    const fp = C.fileFingerprints(text)
    for (const [kind, t, ln] of C.tokens(text)) {
      if (kind !== 'comment') continue
      t.split('\n').forEach((cl0, k) => {
        const cl = C.strip(cl0)
        if (C.ADDR_COMMENT_RE.test(cl)) find('markers', f, ln + k, `address annotation: ${C.cpSlice(cl, 80)}`)
      })
    }
    for (const [kind, count, ln] of tables(fp.toks, th)) find('tables', f, ln, `embedded table of ${count} ${kind}`)
    for (const [lit, ln] of fp.strings) {
      const sv = C.stringValue(lit)
      if (C.cpLen(sv) >= th.min_string && corpus.strings.has(sv) && !sharedStrings.has(sv)) sharedStrings.set(sv, [f, ln])
    }
    const fc = [fp.code.filter(([, h]) => corpus.code.has(h)).length, fp.code.length]
    const fk = [fp.consts.filter(([, h]) => corpus.consts.has(h)).length, fp.consts.length]
    tot.code[0] += fc[0]; tot.code[1] += fc[1]; tot.consts[0] += fk[0]; tot.consts[1] += fk[1]
    const nFp = fc[1] + fk[1]
    if (nFp) perFile.push(new Map([['file', f], ['fingerprints', nFp], ['shared', fc[0] + fk[0]], ['pct', pct(fc[0] + fk[0], nFp)]]))
    for (const [name, ln] of functionDefs(fp.toks, f.endsWith('.rs'))) {
      const nn = normalizeName(name)
      if (C.cpLen(nn) < 6) continue
      defsTotal++
      if (names.has(nn)) {
        defsShared++
        if (sharedExamples.length < 20) sharedExamples.push(`${f}:${ln} ${name}`)
      }
    }
  }

  let sb = 0
  for (const x of sharedStrings.keys()) sb += Buffer.byteLength(x, 'utf8')
  upd('strings', { shared_strings: sharedStrings.size, shared_bytes: sb })
  if (sb > th.string_bytes) {
    const items = [...sharedStrings.entries()].sort((x, y) => L.cmp(x[1][0], y[1][0]) || x[1][1] - y[1][1] || L.cmp(x[0], y[0]))
    for (const [sv, [f, ln]] of items.slice(0, 50)) find('strings', f, ln, `string shared with the reference: "${C.cpSlice(sv, 60)}"`)
    find('strings', treeRel, 0, `${sb} bytes of string literals shared with the reference (max ${th.string_bytes})`)
  }

  upd('names', { definitions: defsTotal, shared: defsShared, pct: pct(defsShared, defsTotal), examples: sharedExamples, names_known: names.size })
  if (defsTotal >= th.names_min && defsShared * 100 > th.names_pct * defsTotal) {
    find('names', treeRel, 0, `${defsShared} of ${defsTotal} function definitions (${pct(defsShared, defsTotal)}%) carry a name of the original (max ${th.names_pct}%)`)
  }

  perFile.sort((x, y) => (y.get('pct') - x.get('pct')) || L.cmp(x.get('file'), y.get('file')))
  upd('similarity', {
    code: new Map([['fingerprints', tot.code[1]], ['shared', tot.code[0]], ['pct', pct(...tot.code)]]),
    consts: new Map([['fingerprints', tot.consts[1]], ['shared', tot.consts[0]], ['pct', pct(...tot.consts)]]),
    top_files: perFile.slice(0, 10)
  })
  if (!corpus.files.length) find('similarity', treeRel, 0, `no reference code found (${s.reference.join(', ')}): nothing to compare against`)
  for (const [k, lim] of [['code', th.code_pct], ['consts', th.const_pct]]) {
    const [sh, n] = tot[k]
    if (sh * 100 > lim * n) find('similarity', treeRel, 0, `${k} fingerprints: ${sh} of ${n} (${pct(sh, n)}%) found in the reference (max ${lim}%)`)
  }
  for (const x of perFile) {
    if (x.get('fingerprints') >= th.file_min && x.get('shared') * 100 > th.file_pct * x.get('fingerprints')) {
      find('similarity', x.get('file'), 0, `${x.get('shared')} of ${x.get('fingerprints')} fingerprints (${x.get('pct')}%) found in the reference (max ${th.file_pct}%)`)
    }
  }

  const low = fs.readdirSync(L.join(project, treeRel)).sort(L.cmp).map(t => t.toLowerCase())
  if (!low.some(t => ['license', 'licence', 'copying', 'unlicense'].some(x => t.startsWith(x)))) find('notices', treeRel, 0, 'no LICENSE or COPYING file at the top of the tree')
  if (!low.some(t => t.startsWith('readme'))) find('notices', treeRel, 0, 'no README at the top of the tree')
  const libs = s.libraries
  let nlibs = 0
  if (libs && fs.existsSync(L.join(project, libs))) {
    try {
      const ld = L.pyParse(fs.readFileSync(L.join(project, libs)).toString('utf8'))
      nlibs = isObj(ld) && Array.isArray(ld.libraries) ? ld.libraries.length : (isObj(ld) && isObj(ld.libraries) ? Object.keys(ld.libraries).length : 0)
    } catch { nlibs = 0 }
  }
  upd('notices', { libraries: nlibs })
  if (nlibs && !low.some(t => ['third_party', 'third-party', 'thirdparty', 'licenses', 'notice'].some(x => t.startsWith(x)))) {
    find('notices', treeRel, 0, `${nlibs} libraries in ${libs} but no third-party notice (THIRD_PARTY*, LICENSES*, NOTICE*)`)
  }

  const allowed = []
  for (const c of CHECKS) {
    const keep = []
    for (const fnd of checks.get(c).get('findings')) {
      const ok = allow.find(al => al.check === c && al.file === fnd.file && (al.line === undefined ? fnd.line : L.num(al.line)) === fnd.line)
      if (ok) allowed.push({ check: c, file: fnd.file, line: fnd.line, detail: fnd.detail, reason: ok.reason })
      else keep.push(fnd)
    }
    const ch = checks.get(c)
    ch.set('passed', !keep.length)
    ch.set('findings_total', keep.length)
    ch.set('findings', keep.slice(0, MAX_FINDINGS))
  }
  const passed = CHECKS.every(c => checks.get(c).get('passed'))
  if (!a.quiet) {
    for (const c of CHECKS) {
      const ch = checks.get(c)
      if (ch.get('findings_total') > MAX_FINDINGS) process.stderr.write(`${c}: ${ch.get('findings_total')} findings, the first ${MAX_FINDINGS} shown\n`)
      for (const fnd of ch.get('findings')) process.stderr.write(`${c}: ${fnd.file}${loc(fnd)}: ${fnd.detail}\n`)
    }
    const failed = CHECKS.filter(c => !checks.get(c).get('passed'))
    process.stderr.write(`${PROG}: ${passed ? 'PASSED' : `FAILED (${failed.join(', ')})`}\n`)
  }
  const summary = new Map([['passed', passed], ['tree', treeRel], ['files', files.length], ['checks', checks], ['allowed', allowed], ['manual', MANUAL]])
  const text = L.dumps(summary)
  if (a.json) fs.writeFileSync(a.json, text + '\n')
  process.stdout.write(text + '\n')
  return passed ? 0 : 1
}

function require_abs (project, tree) { // eslint-disable-line camelcase
  return L.join(project, tree)
}

process.exitCode = main(process.argv.slice(2))
