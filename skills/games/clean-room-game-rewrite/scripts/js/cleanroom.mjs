#!/usr/bin/env node
// Port of ../cleanroom.py (same command line, output and exit codes). Node built-ins only.
import fs from 'node:fs'
import * as L from './lib/rwlib.mjs'
import * as C from './lib/cleanlib.mjs'

const PROG = 'cleanroom'
const DOC = "Clean-room bookkeeping of the rewrite (references/cleanroom.md).\n\n  python3 -I cleanroom.py init   [--project DIR]\n  python3 -I cleanroom.py lint   FILE... [--project DIR] [--json OUT]\n  python3 -I cleanroom.py pack   --wave NAME --out DIR INPUT... [--note TEXT] [--project DIR]\n  python3 -I cleanroom.py record --wave NAME --event KIND [--note TEXT] [FILE...] [--project DIR]\n  python3 -I cleanroom.py verify [--project DIR]\n\nTwo kinds of agent work on a clean-room rewrite: analysts, who read the decompilation and write behaviour\nspecs in their own words, and implementers, who write the rewrite from those specs, the format docs and the\noracle's traces without ever seeing code derived from the original. This script keeps the two apart and\nkeeps the record. Settings: decomp.json \"rewrite.cleanroom\" (dir, specs, log, tree, forbidden, reference, ...;\ndefaults in references/cleanroom.md).\n  init    creates <dir>/specs, <dir>/questions, <dir>/README.md and the log <dir>/log.jsonl with an \"init\"\n          entry (the forbidden areas and the reference folders at that time). Exit 1 if the log exists.\n  lint    checks spec files for copied code: Ghidra names (FUN_..., iVar1, param_1), fenced code blocks\n          tagged as C, C++, Rust or assembly, untagged blocks or loose text with >= spec_code_lines code-like\n          lines, and runs of tokens shared with the reference code (raw token 12-grams, winnowed; a file with\n          >= spec_overlap shared fingerprints fails). Exit 0 clean, 1 findings.\n  pack    builds an implementer's workspace: copies every INPUT (files, or folders recursively) to\n          DIR/<project-relative path>, with INPUTS.json (paths, SHA-256, sizes) and RULES.md. Refused, with\n          nothing copied, when an input lies outside the project or in a forbidden area (by its path or its\n          real path), or a .md/.txt input fails lint. Every pack, and every refusal, is a log entry.\n  record  appends another event to the log (question, answer, handoff, review ...), with the SHA-256 of\n          each FILE; the same checks as pack apply to the files.\n  verify  checks the log: every line JSON, \"seq\" consecutive, \"prev\" the SHA-256 of the previous line.\n          Prints entries, head (the SHA-256 of the last line: the chain cannot protect the last line, git\n          does), events and waves. Exit 0 intact, 1 broken, 2 no log.\nLog lines are compact JSON: seq, recorded (UTC; SOURCE_DATE_EPOCH when set), event, ..., prev. Keep the log\nin git: it is the evidence of the process. Prints a JSON summary. Exit 2 on bad input.\nPython standard library only."
const FENCE_RE = /^(```+|~~~+)[ \t]*([^ \t`~]*)/
const CODE_LINE_RE = /;$|^[{}][ \t]*;?$|\{$|^(?:if|for|while|switch|return|else)\b[^\n]*[;{(]/
const CODE_LANGS = new Set(['c', 'h', 'cpp', 'c++', 'cc', 'cxx', 'hpp', 'rust', 'rs', 'asm', 'nasm', 'masm', 'x86', 's',
  'pseudocode', 'pseudo', 'ghidra', 'decompiled'])
const EVENT_RE = /^[a-z][a-z0-9_-]*$/
const LINT_EXTS = ['.md', '.markdown', '.txt']

const README = `# Clean-room record

This folder holds the clean-room process of the rewrite (see the clean-room-game-rewrite skill,
references/cleanroom.md).

- \`specs/\`: behaviour specs written by analysts, in their own words. No code from the decompilation or the
  analysts' tools (format readers, the probe). Run \`cleanroom.py lint\` on every spec before it is handed over.
- \`questions/\`: implementers' written questions and the analysts' written answers.
- \`log.jsonl\`: every hand-over (\`cleanroom.py pack\` / \`record\`), hash-chained. Do not edit it.

Implementers never open the decompiled code, the Ghidra projects, the analysts' tools (format readers, the
probe), the names maps or the original executable's bytes. They work from their workspace (made by \`pack\`), the
traces of the oracle and the game's own data files, and write their own design.
`

const RULES = `# Rules for this workspace

You write the rewrite from the files in this folder: behaviour specs, format documents, traces of the
original game and answers to your questions. Nothing else from the project.

- Do not open, search, list or ask for: decompiled or disassembled code, Ghidra projects, the analysts'
  tools (format readers, the probe), names maps, or the original executable's bytes. If you come across any of
  them, stop and tell the coordinator.
- Ask questions in writing through the coordinator; answers come back as new spec files.
- Choose your own design, names and structure. The behaviour must match the traces; the code should not
  resemble anything you were not given.
- Do not put game data (levels, text, graphics, sound, tables) into the source: read it from the user's
  own game files at run time.
- Do not commit, download or publish anything.
`

class InputError extends Error {}

function relp (project, p) {
  const r = C.rel(project, p)
  return [r, r !== null ? r : p]
}

export function lintText (text, corpus, th) {
  const out = []
  const lines = text.split('\n')
  lines.forEach((line, i) => {
    const m = C.GHIDRA_RE.exec(line)
    if (m) out.push([i + 1, 'ghidra', `Ghidra name ${m[0]}`])
  })
  let fence = null
  const loose = []
  const close = (f) => {
    const [, lang, start, code] = f
    if (CODE_LANGS.has(lang)) out.push([start, 'code-block', `fenced ${lang} block`])
    else if (!['json', 'text', 'txt'].includes(lang) && code >= th.spec_code_lines) out.push([start, 'code-block', `block with ${code} code-like lines`])
  }
  lines.forEach((line, i) => {
    const n = i + 1
    const s = C.strip(line)
    if (fence === null) {
      const m = FENCE_RE.exec(s)
      if (m) { fence = [m[1], m[2].toLowerCase(), n, 0]; return }
      if (CODE_LINE_RE.test(s)) loose.push(n)
    } else {
      if (s.startsWith(fence[0]) && C.strip(s, '`~') === '') { close(fence); fence = null; return }
      if (CODE_LINE_RE.test(s)) fence[3]++
    }
  })
  if (fence !== null) close(fence)
  if (loose.length >= th.spec_code_lines) {
    out.push([loose[0], 'code-lines', `${loose.length} code-like lines outside code blocks (lines ${loose.slice(0, 10).join(', ')})`])
  }
  if (corpus !== null) {
    const fp = C.fileFingerprints(text, true)
    const hitSet = new Set(); let nHits = 0
    for (const [ln, h] of fp.raw) if (corpus.raw.has(h)) { hitSet.add(ln); nHits++ }
    const hits = [...hitSet].sort((a, b) => a - b)
    if (nHits >= th.spec_overlap) {
      out.push([hits[0], 'overlap', `${nHits} fingerprints shared with the reference code (lines ${hits.slice(0, 10).join(', ')})`])
    }
  }
  out.sort((a, b) => (a[0] - b[0]) || L.cmp(a[1], b[1]) || L.cmp(a[2], b[2]))
  return out
}

class Linter {
  constructor (project, s) { this.project = project; this.s = s; this.corpus = null }
  lint (p) {
    if (this.corpus === null) this.corpus = new C.Corpus(this.project, this.s.reference, this.s.reference_exclude, true)
    return lintText(C.readText(p), this.corpus, this.s.thresholds)
  }
}

const islink = p => { try { return fs.lstatSync(p).isSymbolicLink() } catch { return false } }
function realpath (p) { try { return fs.realpathSync(p) } catch { return L.abspath(p) } }

function checkInputs (project, s, paths, linter) {
  const files = []; const refused = []
  for (const p of paths) {
    const [r, shown] = relp(project, p)
    if (!fs.existsSync(p)) throw new InputError(`${shown}: no such file or folder`)
    if (r === null) { refused.push({ path: '<outside>/' + L.basename(L.abspath(p)), reason: 'outside the project' }); continue }
    const members = L.isdir(p) && !islink(p) ? C.walk(project, r) : [r]
    for (const m of members) {
      const a = L.join(project, m)
      let hit = C.globMatch(m, s.forbidden)
      const real = C.rel(project, realpath(a))
      if (!hit && real !== null) hit = C.globMatch(real, s.forbidden)
      if (hit) { refused.push({ path: m, reason: `forbidden area ${hit}` }); continue }
      if (real === null) { refused.push({ path: m, reason: 'its real path is outside the project' }); continue }
      if (LINT_EXTS.some(e => m.toLowerCase().endsWith(e))) {
        const found = linter.lint(a)
        if (found.length) {
          refused.push({ path: m, reason: 'lint: ' + found.slice(0, 5).map(f => `line ${f[0]} ${f[1]}: ${f[2]}`).join('; ') })
          continue
        }
      }
      files.push([m, a])
    }
  }
  const seen = new Set(); const uniq = []
  for (const [m, a] of files) if (!seen.has(m)) { seen.add(m); uniq.push([m, a]) }
  return [uniq, refused]
}
const entryInputs = files => files.map(([m, a]) => ({ path: m, sha256: L.sha256File(a), bytes: fs.statSync(a).size }))

function cmdInit (project, s) {
  const log = L.join(project, s.log)
  if (fs.existsSync(log)) {
    process.stderr.write(`${PROG}: error: ${s.log} exists: the clean room is already initialised\n`)
    return 1
  }
  const created = []
  for (const d of [s.dir, s.specs, s.dir + '/questions']) {
    if (!L.isdir(L.join(project, d))) { fs.mkdirSync(L.join(project, d), { recursive: true }); created.push(d + '/') }
  }
  const readme = L.join(project, s.dir, 'README.md')
  if (!fs.existsSync(readme)) { fs.writeFileSync(readme, README); created.push(s.dir + '/README.md') }
  fs.mkdirSync(L.dirname(log) || '.', { recursive: true })
  C.appendLog(log, new Map([['event', 'init'], ['tree', s.tree], ['forbidden', s.forbidden], ['reference', s.reference]]))
  created.push(s.log)
  process.stdout.write(L.dumps(new Map([['log', s.log], ['created', created]])) + '\n')
  return 0
}

function cmdLint (project, s, a) {
  if (!a.files.length) throw new InputError('lint needs at least one FILE')
  for (const p of a.files) if (!L.isfile(p)) throw new InputError(`${p}: not a file`)
  const linter = new Linter(project, s)
  const findings = []
  for (const p of a.files) {
    const shown = relp(project, p)[1]
    for (const [line, rule, detail] of linter.lint(p)) {
      findings.push(new Map([['file', shown], ['line', line], ['rule', rule], ['detail', detail]]))
      process.stderr.write(`${shown}:${line}: ${rule}: ${detail}\n`)
    }
  }
  const summary = new Map([['files', a.files.length], ['clean', !findings.length], ['findings', findings],
    ['reference_files', linter.corpus.files.length]])
  const text = L.dumps(summary)
  if (a.json) fs.writeFileSync(a.json, text + '\n')
  process.stdout.write(text + '\n')
  return findings.length ? 1 : 0
}

function needLog (project, s) {
  if (!fs.existsSync(L.join(project, s.log))) throw new InputError(`no clean-room log ${s.log}: run cleanroom.py init first`)
}

function refuse (project, s, a, event, refused) {
  C.appendLog(L.join(project, s.log), new Map([['event', 'refused'], ['for', event], ['wave', a.wave], ['note', a.note], ['refused', refused]]))
  for (const r of refused) process.stderr.write(`${PROG}: refused ${r.path}: ${r.reason}\n`)
  process.stdout.write(L.dumps(new Map([['event', event], ['wave', a.wave], ['refused', refused]])) + '\n')
  return 1
}

function cmdPack (project, s, a) {
  needLog(project, s)
  if (!a.inputs.length) throw new InputError('pack needs at least one INPUT')
  const out = a.out
  if (fs.existsSync(out) && (!L.isdir(out) || fs.readdirSync(out).length)) throw new InputError(`${out} exists and is not an empty folder`)
  const [outRel, outShown] = relp(project, out)
  if (outRel !== null && C.globMatch(outRel, s.forbidden)) throw new InputError(`${outShown} is inside a forbidden area`)
  const [files, refused] = checkInputs(project, s, a.inputs, new Linter(project, s))
  if (refused.length) return refuse(project, s, a, 'pack', refused)
  for (const [m, src] of files) {
    const dst = L.join(out, m)
    fs.mkdirSync(L.dirname(dst), { recursive: true })
    fs.copyFileSync(src, dst)
  }
  const inputs = entryInputs(files)
  fs.writeFileSync(L.join(out, 'INPUTS.json'), L.dumps(new Map([['wave', a.wave], ['note', a.note], ['inputs', inputs]])) + '\n')
  fs.writeFileSync(L.join(out, 'RULES.md'), RULES)
  const e = C.appendLog(L.join(project, s.log), new Map([['event', 'pack'], ['wave', a.wave], ['note', a.note],
    ['out', outRel !== null ? outRel : '<outside>/' + L.basename(L.abspath(out))], ['inputs', inputs]]))
  process.stdout.write(L.dumps(new Map([['event', 'pack'], ['seq', e.get('seq')], ['wave', a.wave], ['out', e.get('out')],
    ['files', inputs.length], ['bytes', inputs.reduce((t, x) => t + x.bytes, 0)]])) + '\n')
  return 0
}

function cmdRecord (project, s, a) {
  needLog(project, s)
  if (!EVENT_RE.test(a.event) || ['init', 'pack', 'refused'].includes(a.event)) {
    throw new InputError('--event: a lower-case word other than init, pack and refused, e.g. question, answer')
  }
  const [files, refused] = a.files.length ? checkInputs(project, s, a.files, new Linter(project, s)) : [[], []]
  if (refused.length) return refuse(project, s, a, a.event, refused)
  const inputs = entryInputs(files)
  const e = C.appendLog(L.join(project, s.log), new Map([['event', a.event], ['wave', a.wave], ['note', a.note], ['inputs', inputs]]))
  process.stdout.write(L.dumps(new Map([['event', a.event], ['seq', e.get('seq')], ['wave', a.wave], ['files', inputs.length]])) + '\n')
  return 0
}

function cmdVerify (project, s) {
  const p = L.join(project, s.log)
  const v = C.verifyLog(p)
  v.set('log', s.log)
  for (const x of v.get('problems')) process.stderr.write(`${s.log}: ${x}\n`)
  process.stdout.write(L.dumps(v) + '\n')
  if (!fs.existsSync(p)) return 2
  return v.get('ok') ? 0 : 1
}

const COMMANDS = {
  init: [cmdInit, [], []],
  lint: [cmdLint, [['--json', 'str', null]], [['files', '*']]],
  pack: [cmdPack, [['--wave', 'str', L.REQUIRED], ['--out', 'str', L.REQUIRED], ['--note', 'str', '']], [['inputs', '*']]],
  record: [cmdRecord, [['--wave', 'str', L.REQUIRED], ['--event', 'str', L.REQUIRED], ['--note', 'str', '']], [['files', '*']]],
  verify: [cmdVerify, [], []]
}

function main (argv) {
  if (!argv.length || argv[0] === '-h' || argv[0] === '--help') {
    if (argv.length) { process.stdout.write(DOC + '\n'); return 0 }
    process.stderr.write(`${PROG}: error: missing command (${Object.keys(COMMANDS).join(', ')})\n`)
    return 2
  }
  const cmd = argv[0]
  if (!Object.prototype.hasOwnProperty.call(COMMANDS, cmd)) {
    process.stderr.write(`${PROG}: error: unknown command ${cmd} (${Object.keys(COMMANDS).join(', ')})\n`)
    return 2
  }
  const [fn, opts, pos] = COMMANDS[cmd]
  const a = L.parseArgs(PROG, DOC, argv.slice(1), [['--project', 'str', '.'], ...opts], pos)
  const project = L.abspath(a.project)
  try {
    const s = C.settings(project)
    return fn(project, s, a)
  } catch (e) {
    if (!(e instanceof InputError) && !(e instanceof SyntaxError)) throw e
    process.stderr.write(`${PROG}: error: ${e.message}\n`)
    return 2
  }
}

process.exitCode = main(process.argv.slice(2))
