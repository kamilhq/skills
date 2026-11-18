#!/usr/bin/env node
// Port of ../../rust/replace_fn.py (same command line, output and files). Node built-ins only.
import fs from 'node:fs'
import * as L from '../lib/rwlib.mjs'

const PROG = 'replace_fn'
const DOC = "Replace functions in a Rust file by new versions, matched by their `// 0x<address>` line.\n\n  python3 -I replace_fn.py TARGET.rs NEW.rs [--dry-run]\n\nNEW.rs holds one or more functions, each starting at its address line (`// 0x401000` alone on a line, the\nconvention of gen_skeleton.py), with its doc comments and attributes below it; text before the first address\nline is ignored, and a block ends where the next address line starts (trailing blank lines dropped). In\nTARGET.rs each block replaces the function under the same address line: from that line through the first\nline after it that is exactly `}` at the address line's indentation (so a function inside an `impl` block is\nfound at its own indentation). The new block is re-indented to the target's indentation when its own differs.\nAddress lines compare case-insensitively. An address that occurs twice in TARGET.rs is not touched. Line ends\nof TARGET.rs (LF or CRLF) are kept. Prints a JSON summary (replaced, not_found, duplicates, written).\nExit 0 when every block was replaced, 1 when some were not (the others are still written unless\n--dry-run), 2 on bad input. Python standard library only. Port: ../js/rust/replace_fn.mjs."
const ADDR = /^([ \t]*)\/\/[ \t]*(0x[0-9a-fA-F]+)[ \t]*$/

function read (p) { return fs.readFileSync(p).toString('utf8') }

function blocks (text) {
  const out = []; let cur = null
  for (const line of text.split('\n')) {
    const m = ADDR.exec(line)
    if (m) { cur = [m[2].toLowerCase(), m[1], [line]]; out.push(cur) } else if (cur !== null) cur[2].push(line)
  }
  for (const b of out) while (b[2].length && !b[2][b[2].length - 1].trim()) b[2].pop()
  return out
}

function reindent (lines, old, neu) {
  if (old === neu) return [...lines]
  return lines.map(ln => !ln.trim() ? '' : ln.startsWith(old) ? neu + ln.slice(old.length) : neu + ln.replace(/^[ \t]+/, ''))
}

function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [['--dry-run', 'flag', false]], [['target', '1'], ['new', '1']])
  let raw, neu
  try { raw = read(a.target) } catch (e) { process.stdout.write(L.dumps({ error: `cannot read: ${a.target}` }) + '\n'); return 2 }
  try { neu = read(a.new).replaceAll('\r\n', '\n') } catch (e) { process.stdout.write(L.dumps({ error: `cannot read: ${a.new}` }) + '\n'); return 2 }
  const crlf = raw.includes('\r\n')
  const lines = raw.replaceAll('\r\n', '\n').split('\n')
  const bl = blocks(neu)
  if (!bl.length) { process.stdout.write(L.dumps({ error: `no \`// 0x<address>\` line in ${a.new}` }) + '\n'); return 2 }
  const replaced = []; const missing = []; const dups = []
  for (const [addr, ind, body] of bl) {
    const hits = []
    lines.forEach((ln, i) => { const m = ADDR.exec(ln); if (m && m[2].toLowerCase() === addr) hits.push(i) })
    if (hits.length > 1) { dups.push(addr); continue }
    if (!hits.length) { missing.push(addr); continue }
    const i = hits[0]
    const tind = ADDR.exec(lines[i])[1]
    let end = null
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].replace(/[ \t]+$/, '') === tind + '}') { end = j; break }
      if (j > i + 1 && ADDR.test(lines[j])) break
    }
    if (end === null) { missing.push(addr); continue }
    lines.splice(i, end + 1 - i, ...reindent(body, ind, tind))
    replaced.push(addr)
  }
  let text = lines.join('\n')
  if (crlf) text = text.replaceAll('\n', '\r\n')
  const written = replaced.length > 0 && !a.dry_run
  if (written) fs.writeFileSync(a.target, text)
  process.stdout.write(L.dumps(new Map([['target', a.target], ['blocks', bl.length], ['replaced', replaced],
    ['not_found', missing], ['duplicates', dups], ['written', written]])) + '\n')
  return !missing.length && !dups.length ? 0 : 1
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
