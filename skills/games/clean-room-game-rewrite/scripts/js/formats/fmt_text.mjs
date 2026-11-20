// Text files (template: set EXTS to the project's text extensions). Port of fmt_text.py.
//
// Decoded form (outdir):
//   text<ext>   the content as UTF-8 with LF line endings (open/edit with any editor)
//   text.json   encoding facts: original encoding, BOM, line-ending layout, so the exact bytes come back
//
// The line-ending layout is stored as runs of ("crlf"|"lf"|"cr", count) in file order, one entry per line
// break of the LF-normalised text; a uniform file is a single run. Nothing is kept uninterpreted, so
// opaque_bytes is 0. Encodings are tried in order utf-8, cp1252, latin-1; latin-1 accepts any byte, so a
// binary-looking file would decode as latin-1 text rather than fail: route only real text files here. The
// decoded text never contains CR (every CR is a recorded line ending), so an editor that re-saves it
// with CRLF does not change the rebuilt file.
import { readFileSync, writeFileSync } from 'node:fs'
import { dump, load, plain } from '../lib/pyjson.mjs'
import { pyDecode, pyEncode, pyNormpath, pySplitext, pyBasename, pyJoin } from '../lib/pycompat.mjs'

export const EXTS = ['.txt', '.xml', '.ini']      // edit: every text extension of the game (e.g. .cfg, .info, .fontmeta)

export const ENCODINGS = ['utf-8', 'cp1252', 'latin-1']     // first that round-trips wins; latin-1 always does
const BOM = Buffer.from([0xef, 0xbb, 0xbf])
const SEP = { crlf: '\r\n', lf: '\n', cr: '\r' }

// bytes -> [normalised string, facts]. Shared with fmt_level.
export function text_to_facts(data) {
  const bom = data.length >= 3 && data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf
  const body = bom ? data.subarray(3) : data
  let s = null
  let enc
  for (enc of ENCODINGS) {
    let t
    try {
      t = pyDecode(body, enc)
    } catch {
      continue
    }
    if (pyEncode(t, enc).equals(body)) { s = t; break }
  }
  if (s === null) throw new Error('ValueError: no encoding round-trips')   // unreachable: latin-1 decodes anything
  const runs = []
  const out = []
  const n = s.length
  let i = 0
  let start = 0
  while (i < n) {
    const c = s[i]
    if (c === '\r' || c === '\n') {
      out.push(s.slice(start, i))
      let kind
      if (c === '\r' && i + 1 < n && s[i + 1] === '\n') { kind = 'crlf'; i += 2 }
      else { kind = c === '\r' ? 'cr' : 'lf'; i += 1 }
      if (runs.length && runs[runs.length - 1][0] === kind) runs[runs.length - 1][1] += 1
      else runs.push([kind, 1])
      start = i
    } else i += 1
  }
  out.push(s.slice(start))
  const norm = out.join('\n')
  return [norm, { encoding: enc, bom, line_endings: runs }]
}

export function facts_to_bytes(norm, facts) {
  const lines = norm.split('\n')
  let seps = []
  for (const [kind, count] of facts.line_endings) {
    if (!(kind in SEP)) throw new Error(`KeyError: '${kind}'`)
    for (let k = 0; k < count; k++) seps.push(SEP[kind])
  }
  if (seps.length !== lines.length - 1) {
    // the text was edited and the number of lines changed: use the dominant ending for all
    const tot = new Map()
    for (const [kind, count] of facts.line_endings) tot.set(kind, (tot.get(kind) ?? 0) + count)
    let dom = 'lf'
    if (tot.size) {
      let best = -Infinity
      for (const [k, v] of tot) if (v > best) { best = v; dom = k }
    }
    if (!(dom in SEP)) throw new Error(`KeyError: '${dom}'`)
    seps = new Array(lines.length - 1).fill(SEP[dom])
  }
  const parts = []
  lines.forEach((line, i) => {
    parts.push(line)
    if (i < seps.length) parts.push(seps[i])
  })
  const raw = pyEncode(parts.join(''), facts.encoding)
  return facts.bom ? Buffer.concat([BOM, raw]) : raw
}

export function write_text(p, s) {
  writeFileSync(p, pyEncode(s, 'utf-8'))
}

// Decoded text as written by write_text; CRLF/CR from an editor are folded back to LF.
export function read_text(p) {
  return pyDecode(readFileSync(p), 'utf-8').replaceAll('\r\n', '\n').replaceAll('\r', '\n')
}

export function decode_to_dir(data, outdir, ext = '.txt') {
  const [norm, facts] = text_to_facts(data)
  // the harness passes only data; the extension is recovered from the decoded dir name it creates
  const base = pyBasename(pyNormpath(outdir))
  const e = pySplitext(base)[1].toLowerCase() || ext
  facts.file = 'text' + e
  write_text(pyJoin(outdir, facts.file), norm)
  dump(facts, pyJoin(outdir, 'text.json'), { indent: 1 })
  const notes = [`encoding ${facts.encoding}${facts.bom ? ' +BOM' : ''}`,
    'line endings ' + facts.line_endings.map(([k, c]) => `${k}x${c}`).join(', ')]
  return { opaque_bytes: 0, notes }
}

export function encode_from_dir(outdir) {
  const facts = plain(load(pyJoin(outdir, 'text.json')))
  return facts_to_bytes(read_text(pyJoin(outdir, facts.file)), facts)
}
