#!/usr/bin/env node
// JavaScript port of reassemble.py (same CLI, output, files, assembler cache format). Node built-ins only.
// Library use: import { build, pe_parse, relocs_of, make_reloc, ... } from './reassemble.mjs'. Every Python
// function and constant is exported under its Python name; return values map as: tuple -> array, dict -> Map
// keyed like Python (relocs_of -> [Map site->target, section name or null]; relax -> [addrs, Map label->value,
// longs, end]; ghidra_assemble -> Map id -> [hex_or_index, ncand]); pe_parse's sections are plain objects
// {name, va, vsize, raw_ptr, raw_size, exec}; bytes are Buffers. Errors are thrown (Python raises).
import { createHash } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dump, dumps, load } from './lib/pyjson.mjs'
import { iterLines, pyInt, pyRepr, pySplit, pyStrip, readText, runMain, S, W } from './lib/pytools.mjs'

const DOC = "Phase 5b: rebuild a PE32 (exe/dll) byte-identically from assembly text. Python stdlib + Ghidra only.\n\n  reassemble.py split <binary> <decompiled_dir> <out_dir> [--names names_apply.json]\n      Decode: <decompiled_dir> is run_recovery.sh output (instructions.tsv, functions.tsv). Writes\n        out_dir/text/NNNNN_<addr>_<name>.asm   .text as assembly, one file per function start, address order\n        out_dir/layout.json                    PE layout: sections, image base, label/fixup tables, stats\n        out_dir/raw/headers.bin, raw/<sec>.bin, raw/overlay.bin   non-code bytes (pointers into .text zeroed)\n      Every instruction's encoding is checked with Ghidra's assembler (scripts/ghidra/assemble.sh, choose\n      mode): the rule's choice needs nothing, another encoding gets `{enc:N}`, none -> `db` (pinned).\n  reassemble.py build <out_dir> <binary_out> [--cache <file>]\n      Encode from out_dir only: assemble every line (Ghidra for ordinary instructions, Python for direct\n      relative branches), lay out .text, resolve labels, write the data sections with code pointers filled\n      from labels, regenerate .reloc, write the PE. --cache reuses assembled bytes keyed by instruction text\n      (encodings of x86-32 non-branch instructions do not depend on their address); omit it for the gate.\n  reassemble.py verify <binary> <out_dir> [--cache <file>]      build to a temp file and compare SHA-256.\n  reassemble.py editcheck <binary> <out_dir> <decompiled_dir> [--cache <file>]\n      Editability proof (level 3): copy the text, insert a NOP after the first instruction of the first\n      function that has two, rebuild, and check against the original that every relocated pointer, every\n      .reloc entry and every direct branch moved consistently (targets after the insertion point +1).\n\nAssembly syntax (Ghidra's own instruction syntax; one item per line, `;` starts a comment):\n    label:                      code label (function names, L_<hex> branch/pointer targets)\n    MOV EAX,dword ptr [g_x]     instruction; labels may replace any numeric operand\n    JZ L_401e60                 direct branch: short/near chosen by distance; `{enc:1}` forces the long form\n    ADD EAX,ECX {enc:1}         use candidate 1 of Ghidra's encodings (rule order) instead of 0\n    db 8d,64,24,00              raw bytes (filler, data in .text, pinned instructions)\n    dd L_402a30                 32-bit absolute address of a label (jump tables) - always relocated\nLabels named D_<hex> are fixed absolute addresses (data outside .text). `label-0x<n>` is allowed wherever a\nlabel is (pointers into the middle of an instruction, e.g. a jump table whose unused entry 0 overlaps code).\nLimits: sections keep their addresses; .text may change size only within its raw size (a bigger .text\nwould need moving later sections). Exit 0 ok, 1 mismatch/assembly error, 2 bad arguments.\n"

export const HERE = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const ASM_SH = join(HERE, 'ghidra', 'assemble.sh')
export const HEX = new RegExp(`(?<!${W})0x[0-9a-fA-F]+`, 'gu')
export const IDENT = /^[A-Za-z_][A-Za-z0-9_]*\n?$/
export const JCC = {
  JO: 0, JNO: 1, JC: 2, JB: 2, JNAE: 2, JNC: 3, JAE: 3, JNB: 3, JZ: 4, JE: 4, JNZ: 5,
  JNE: 5, JBE: 6, JNA: 6, JA: 7, JNBE: 7, JS: 8, JNS: 9, JP: 10, JPE: 10, JNP: 11, JPO: 11,
  JL: 12, JNGE: 12, JGE: 13, JNL: 13, JLE: 14, JNG: 14, JG: 15, JNLE: 15,
}
export const REL8_ONLY = { LOOPNE: 0xe0, LOOPNZ: 0xe0, LOOPE: 0xe1, LOOPZ: 0xe1, LOOP: 0xe2, JECXZ: 0xe3 }
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k)

class RuntimeError extends Error { get name() { return 'RuntimeError' } }
class PyValueError extends Error { get name() { return 'ValueError' } }

// ----------------------------------------------------------------------------------------------- PE helpers
function nameOf(b) {
  let n = b.length
  while (n > 0 && b[n - 1] === 0) n--
  return b.subarray(0, n).toString('latin1')
}

export function pe_parse(d) {
  const pe = d.readUInt32LE(0x3c)
  if (!d.subarray(pe, pe + 4).equals(Buffer.from('PE\0\0', 'latin1')) || d.readUInt16LE(pe + 24) !== 0x10b) {
    throw new PyValueError('not a PE32 file')
  }
  const nsec = d.readUInt16LE(pe + 6)
  const optsz = d.readUInt16LE(pe + 20)
  const opt = pe + 24
  const base = d.readUInt32LE(opt + 28)
  const ndirs = d.readUInt32LE(opt + 92)
  const dirs = []
  for (let i = 0; i < ndirs; i++) dirs.push([d.readUInt32LE(opt + 96 + 8 * i), d.readUInt32LE(opt + 100 + 8 * i)])
  const secs = []
  for (let i = 0; i < nsec; i++) {
    const o = opt + optsz + 40 * i
    const vsz = d.readUInt32LE(o + 8), va = d.readUInt32LE(o + 12), rsz = d.readUInt32LE(o + 16), rptr = d.readUInt32LE(o + 20)
    const ch = d.readUInt32LE(o + 36)
    secs.push({ name: nameOf(d.subarray(o, o + 8)), va, vsize: vsz, raw_ptr: rptr, raw_size: rsz, exec: Boolean(ch & 0x20000000) })
  }
  return [base, dirs, secs]
}

function next(arr, pred) {
  for (const x of arr) if (pred(x)) return x
  throw new Error('StopIteration')
}

export function relocs_of(d, base, dirs, secs) {
  const [rva, size] = dirs.length > 5 ? dirs[5] : [0, 0]
  const out = new Map()
  if (!size) return [out, null]
  const sec = next(secs, (s) => s.va <= rva && rva < s.va + Math.max(s.vsize, s.raw_size))
  let off = sec.raw_ptr + rva - sec.va
  const end = off + size
  while (off < end) {
    const page = d.readUInt32LE(off), bsz = d.readUInt32LE(off + 4)
    if (bsz < 8) break
    for (let i = 0; i < Math.floor((bsz - 8) / 2); i++) {
      const e = d.readUInt16LE(off + 8 + 2 * i)
      if (e >> 12 === 3) {
        const site = base + page + (e & 0xfff)
        const s = next(secs, (x) => x.va <= site - base && site - base < x.va + x.raw_size)
        out.set(site, d.readUInt32LE(s.raw_ptr + site - base - s.va))
      } else if (e >> 12 !== 0) {
        throw new PyValueError(`relocation type ${e >> 12} not supported`)
      }
    }
    off += bsz
  }
  return [out, sec.name]
}

// IMAGE_BASE_RELOCATION blocks: pages ascending, offsets ascending, one ABSOLUTE pad when odd.
export function make_reloc(sites_rva) {
  const pages = new Map()
  for (const r of [...new Set(sites_rva)].sort((a, b) => a - b)) {
    const p = r - (r % 0x1000)
    if (!pages.has(p)) pages.set(p, [])
    pages.get(p).push(r % 0x1000)
  }
  const parts = []
  for (const p of [...pages.keys()].sort((a, b) => a - b)) {
    const ents = pages.get(p).map((o) => 0x3000 | o)
    if (ents.length & 1) ents.push(0)
    const b = Buffer.alloc(8 + 2 * ents.length)
    b.writeUInt32LE(p, 0)
    b.writeUInt32LE(8 + 2 * ents.length, 4)
    ents.forEach((e, i) => b.writeUInt16LE(e, 8 + 2 * i))
    parts.push(b)
  }
  return Buffer.concat(parts)
}

// ------------------------------------------------------------------------------------------ Ghidra assembler
// items: list of [id, text, enc(, orig_hex)]. Returns Map id -> [hex_or_index, ncand] or [ 'ERR', msg ].
export function ghidra_assemble(items, choose = false, tmp = null) {
  const out = new Map()
  if (!items.length) return out
  const d = mkdtempSync(join(tmp ?? tmpdir(), 'tmp'))
  const inp = join(d, 'in.tsv'), res = join(d, 'out.tsv')
  writeFileSync(inp, items.map((it) => it.map((x) => String(x)).join('\t') + '\n').join(''))
  const p = spawnSync('sh', [ASM_SH, inp, res, ...(choose ? ['choose'] : [])], { encoding: 'utf8', maxBuffer: 1 << 30 })
  if (p.status !== 0 || !existsSync(res)) {
    throw new RuntimeError('assemble.sh failed:\n' + (p.stdout ?? '').slice(-2000) + (p.stderr ?? '').slice(-2000))
  }
  for (const line of iterLines(readText(res))) {
    const f = pyRstripNl(line).split('\t')
    if (f.length < 3) throw new Error('IndexError: list index out of range')
    out.set(f[0], [f[1], f[2]])
  }
  return out
}
const pyRstripNl = (s) => s.replace(/\n+$/, '')

// ------------------------------------------------------------------------------------- branch size selection
export function br_len(mn, long_) {
  if (has(REL8_ONLY, mn)) return 2
  if (mn === 'CALL') return 5
  if (!long_) return 2
  return mn === 'JMP' ? 5 : 6
}

// MSVC-style branch sizing, shared by split (prediction) and build. seq items: ['label', name],
// ['fix', size], ['br', mn, target, force] with force 0 = choose, 1 = long, 2 = short. Returns
// [addresses per item, values per label (Map), long flag per item, end address].
export function relax(seq, t0, fixed_value) {
  const long_ = seq.map((it) => it[0] === 'br' && it[3] !== 2 && !has(REL8_ONLY, it[1]))
  for (;;) {
    let addr = t0
    const addrs = new Array(seq.length), values = new Map()
    for (let i = 0; i < seq.length; i++) {
      const it = seq[i]
      addrs[i] = addr
      if (it[0] === 'label') values.set(it[1], addr)
      else if (it[0] === 'fix') addr += it[1]
      else addr += br_len(it[1], long_[i])
    }
    let changed = false
    for (let i = 0; i < seq.length; i++) {
      const it = seq[i]
      if (it[0] === 'br' && long_[i] && it[3] === 0 && it[1] !== 'CALL') {
        const tgt = values.has(it[2]) ? values.get(it[2]) : fixed_value(it[2])
        if (tgt !== null && tgt !== undefined && -128 <= tgt - (addrs[i] + 2) && tgt - (addrs[i] + 2) <= 127) {
          long_[i] = false
          changed = true
        }
      }
    }
    if (!changed) return [addrs, values, long_, addr]
  }
}

const FIXED_RE = /^(D|A)_([0-9a-f]+)\n?$/
export function fixed_label_value(name) {
  const m = FIXED_RE.exec(name)
  return m ? parseInt(m[2], 16) : null
}

// --------------------------------------------------------------------------------------------- split (decode)
export function sanitize(name, addr, used) {
  let n = name.split('::').join('__').replace(/[^A-Za-z0-9_]/gu, '_')
  if (!n || !/^[A-Za-z_]/.test(n)) n = 'F_' + n
  if (used.has(n) || /^(D|A|L)_[0-9a-f]+\n?$/.test(n)) n = `${n}_${addr.toString(16)}`
  used.add(n)
  return n
}

// 'rel8'/'rel32'/'jcc8'/'jcc32'/'call'/'rel8only' for a direct relative branch without prefixes.
export function branch_kind(b) {
  if (b.length < 1) throw new Error('IndexError: index out of range')
  if (b[0] === 0xe8) return 'call'
  if (b[0] === 0xe9) return 'rel32'
  if (b[0] === 0xeb) return 'rel8'
  if (b[0] >= 0x70 && b[0] <= 0x7f) return 'jcc8'
  if (b[0] === 0x0f && b.length > 1 && b[1] >= 0x80 && b[1] <= 0x8f) return 'jcc32'
  if (b[0] >= 0xe0 && b[0] <= 0xe3) return 'rel8only'
  return null
}

function bisectRight(arr, x) {
  let lo = 0, hi = arr.length
  while (lo < hi) {
    const mid = (lo + hi) >> 1
    if (x < arr[mid]) hi = mid
    else lo = mid + 1
  }
  return lo
}

function truthy(v) {
  if (v === null || v === undefined || v === false || v === 0 || v === '' || v === 0n) return false
  if (Array.isArray(v)) return v.length > 0
  if (v instanceof Map) return v.size > 0
  if (typeof v === 'object' && typeof v.valueOf() === 'number') return v.valueOf() !== 0
  return true
}

function readTsv(path, nfields, maxsplit) {
  // `next(f)` then `for line in f: ... = line.rstrip('\n').split('\t'[, maxsplit])`
  const lines = iterLines(readText(path))
  if (!lines.length) throw new Error('StopIteration')
  const out = []
  for (let i = 1; i < lines.length; i++) {
    const f = pySplit(pyRstripNl(lines[i]), '\t', maxsplit)
    if (nfields && f.length !== nfields) {
      throw new PyValueError(f.length < nfields ? `not enough values to unpack (expected ${nfields}, got ${f.length})`
        : `too many values to unpack (expected ${nfields})`)
    }
    out.push(f)
  }
  return out
}

const hx2 = (x) => x.toString(16).padStart(2, '0')

export function split(binary, ddir, out, names_file = null) {
  const d = readFileSync(binary)
  const [base, dirs, secs] = pe_parse(d)
  const [rel, reloc_sec] = relocs_of(d, base, dirs, secs)
  const texts = secs.filter((s) => s.exec)
  if (texts.length !== 1) throw new PyValueError('expected exactly one executable section')
  const T = texts[0]
  const t0 = base + T.va, t_raw_end = base + T.va + T.raw_size
  const in_text = (v) => t0 <= v && v < t_raw_end
  // emit up to the section's virtual size; the zero file-alignment padding after it is added by build
  let t1 = T.vsize ? t0 + Math.min(T.vsize, T.raw_size) : t_raw_end
  while (t1 < t_raw_end && d.subarray(T.raw_ptr + t1 - t0, T.raw_ptr + T.raw_size).some((x) => x !== 0)) t1 = t_raw_end
  const ins = new Map()
  for (const [a_, ln, , flow, targets, text] of readTsv(join(ddir, 'instructions.tsv'), 6, 5)) {
    const a = pyInt(a_, 16)
    if (in_text(a)) ins.set(a, [pyInt(ln), flow, targets, text])
  }
  // Instructions that overlap a relocated dword they do not fully contain are data Ghidra disassembled
  const straddle = new Set()
  for (const site of rel.keys()) {
    for (let k = -14; k < 4; k++) {
      const a = site + k
      if (ins.has(a)) {
        const ln = ins.get(a)[0]
        if (a < site + 4 && site < a + ln && !(a <= site && site + 4 <= a + ln)) straddle.add(a)
      }
    }
  }
  // jump tables Ghidra decoded as instructions
  const tsites = [...rel].filter(([x, v]) => t0 <= v && v < t_raw_end && t0 <= x && x < t_raw_end).map(([x]) => x).sort((a, b) => a - b)
  const runs = []
  let i = 0
  while (i < tsites.length) {
    let j = i
    while (j + 1 < tsites.length && tsites[j + 1] === tsites[j] + 4) j++
    if (j > i) runs.push([tsites[i], tsites[j] + 4])
    i = j + 1
  }
  const ins_starts = [...ins.keys()].sort((a, b) => a - b)
  for (const [lo, hi] of runs) {
    let k = Math.max(bisectRight(ins_starts, lo) - 1, 0)
    while (k < ins_starts.length && ins_starts[k] < hi) {
      const a = ins_starts[k]
      if (a + ins.get(a)[0] > lo) straddle.add(a)
      k++
    }
  }
  for (const a of straddle) ins.delete(a)
  const fnames = new Map()
  for (const [e, n] of readTsv(join(ddir, 'functions.tsv'), 3)) {
    if (in_text(pyInt(e, 16))) {
      fnames.set(pyInt(e, 16), n.includes('::') && (n.startsWith('KERNEL') || n.startsWith('USER')) ? n.split('::').at(-1) : n)
    }
  }
  if (names_file) {
    const nm = load(names_file)
    const items = nm instanceof Map ? [...nm] : nm.map((x) => [x.get('address'), x.get('name')])
    for (const [a, n] of items) {
      if (fnames.has(pyInt(a, 16)) && truthy(n)) fnames.set(pyInt(a, 16), n)
    }
  }
  const raw_at = (va, n) => {
    const o = T.raw_ptr + va - t0
    return d.subarray(o, o + n)
  }
  const stats = {}
  const used = new Set(), labels = new Map()
  for (const a of [...fnames.keys()].sort((x, y) => x - y)) labels.set(a, sanitize(fnames.get(a), a, used))
  const code_targets = new Set()
  for (const [, [, flow, targets]] of ins) {
    if ((flow === 'call' || flow === 'jump' || flow === 'cjump') && targets) {
      for (const t of targets.split(',')) if (in_text(pyInt(t, 16))) code_targets.add(pyInt(t, 16))
    }
  }
  for (const v of rel.values()) if (in_text(v)) code_targets.add(v)
  // a label must sit at a line boundary: an instruction start or anywhere in a non-instruction run
  const covered = new Map()
  for (const [a, [ln]] of ins) for (let k = 1; k < ln; k++) covered.set(a + k, a)
  const label_for = (v) => {
    if (!in_text(v)) return `D_${v.toString(16)}`
    if (covered.has(v)) {
      const a = covered.get(v)
      const b = a + ins.get(a)[0]
      if (!labels.has(b)) labels.set(b, `L_${b.toString(16)}`)
      stats.label_offset_operands = (stats.label_offset_operands ?? 0) + 1
      return `${labels.get(b)}-0x${(b - v).toString(16)}`
    }
    if (!labels.has(v)) labels.set(v, `L_${v.toString(16)}`)
    return labels.get(v)
  }
  for (const v of [...code_targets].sort((a, b) => a - b)) label_for(v)
  Object.assign(stats, {
    instructions_as_data: straddle.size, instructions: 0, enc_pinned: 0, db_pinned_instructions: 0,
    db_pinned_bytes: 0, branches: 0, relabelled_operands: 0, data_bytes_in_text: 0,
  })
  // walk .text
  const lines = []
  const pending_choose = []
  let a = t0
  const order = [...ins.keys()].sort((x, y) => x - y)
  const emitted = new Set()
  const put_label = (at) => {
    if (labels.has(at) && !emitted.has(at)) {
      emitted.add(at)
      lines.push([at, 'label', labels.get(at)])
    }
  }
  const reWs = new RegExp(`${S}+`, 'u')
  while (a < t1) {
    put_label(a)
    if (ins.has(a) && a + ins.get(a)[0] <= t1) {
      const [ln, flow, targets, text] = ins.get(a)
      const b = raw_at(a, ln)
      stats.instructions += 1
      const sites = []
      for (let s = a; s < a + ln; s++) if (rel.has(s)) sites.push(s)
      const bk = branch_kind(b)
      if (bk && (flow === 'call' || flow === 'jump' || flow === 'cjump') && targets && !sites.length) {
        const t = pyInt(targets.split(',')[0], 16)
        if (in_text(t) && !covered.has(t)) {
          const parts = pyStrip(text).split(reWs)
          if (!parts[0]) throw new Error('IndexError: list index out of range')
          const mn = parts[0].toUpperCase()
          lines.push([a, 'br', [mn, label_for(t), 0, b.toString('hex'), bk === 'rel32' || bk === 'jcc32' || bk === 'call']])
          stats.branches += 1
          a += ln
          continue
        }
      }
      let neu = text
      let ok = true
      for (const s of sites) {
        const v = rel.get(s)
        const toks = [...neu.matchAll(HEX)].filter((m) => parseInt(m[0], 16) === v)
        if (!toks.length) { ok = false; break }
        const lab = label_for(v)
        neu = neu.replace(HEX, (m) => (parseInt(m, 16) === v ? lab : m))
        stats.relabelled_operands += 1
      }
      if (ok && !bk) {
        lines.push([a, 'ins', [neu, text, b.toString('hex'), 0]])
        pending_choose.push(lines.length - 1)
      } else {
        lines.push([a, 'pin', [text, b.toString('hex'), sites.map((s) => [s - a, label_for(rel.get(s))])]])
      }
      a += ln
      continue
    }
    // non-instruction run up to the next instruction start or section end
    const ii = bisectRight(order, a)
    let nxt = ii < order.length ? order[ii] : t1
    nxt = Math.min(nxt, t1)
    if (nxt <= a) nxt = a + 1
    let buf = []
    let p = a
    while (p < nxt) {
      if (labels.has(p) && !emitted.has(p)) {
        if (buf.length) { lines.push([a, 'db', Buffer.from(buf)]); buf = [] }
        put_label(p)
        a = p
      }
      if (rel.has(p) && p + 4 <= nxt) {
        if (buf.length) { lines.push([a, 'db', Buffer.from(buf)]); buf = [] }
        lines.push([p, 'dd', label_for(rel.get(p))])
        p += 4
        a = p
        continue
      }
      const rb = raw_at(p, 1)
      if (!rb.length) throw new Error('IndexError: index out of range')
      buf.push(rb[0])
      stats.data_bytes_in_text += 1
      p += 1
    }
    if (buf.length) lines.push([a, 'db', Buffer.from(buf)])
    a = nxt
  }
  // encoding choice for ordinary instructions (Ghidra, choose mode, deduplicated by text+bytes)
  const uniq = new Map()
  for (const li of pending_choose) {
    const [neu, text, bh] = lines[li][2]
    const key = text + '\0' + bh
    if (!uniq.has(key)) uniq.set(key, [String(uniq.size), text, bh])
  }
  const res = ghidra_assemble([...uniq.values()].map(([k, t, bh]) => [k, t, 0, bh]), true)
  for (const li of pending_choose) {
    const [a_, , [, text, bh]] = lines[li]
    const [idx] = res.get(uniq.get(text + '\0' + bh)[0]) ?? ['ERR', 'missing']
    if (idx === 'ERR' || pyInt(idx) < 0) {
      const sites = []
      for (let s = a_; s < a_ + Math.floor(bh.length / 2); s++) if (rel.has(s)) sites.push([s - a_, label_for(rel.get(s))])
      lines[li] = [a_, 'pin', [text, bh, sites]]
    } else if (pyInt(idx) > 0) {
      lines[li][2][3] = pyInt(idx)
      stats.enc_pinned += 1
    }
  }
  // branch sizes: predict with relax() on the original layout, force (enc 1 long / 2 short) where it differs
  const seq_of = () => lines.map(([, k_, p_]) => {
    if (k_ === 'label') return ['label', p_]
    if (k_ === 'br') return ['br', p_[0], p_[1], p_[2]]
    if (k_ === 'ins' || k_ === 'pin') return ['fix', Math.floor(p_[k_ === 'ins' ? 2 : 1].length / 2)]
    if (k_ === 'db') return ['fix', p_.length]
    return ['fix', 4]
  })
  for (let round = 0; round < 20; round++) {
    const [, , longs] = relax(seq_of(), t0, fixed_label_value)
    let wrong = 0
    lines.forEach(([, k_, p_], li) => {
      if (k_ === 'br' && !has(REL8_ONLY, p_[0]) && p_[0] !== 'CALL' && longs[li] !== p_[4]) {
        p_[2] = p_[4] ? 1 : 2
        wrong += 1
      }
    })
    if (wrong === 0) break
  }
  stats.branch_size_pinned = lines.filter(([, k_, p_]) => k_ === 'br' && p_[2]).length
  for (const [, k, p_] of lines) {
    if (k === 'pin') {
      stats.db_pinned_instructions += 1
      stats.db_pinned_bytes += Math.floor(p_[1].length / 2)
    }
  }
  // write text files: a new file at every function start
  mkdirSync(join(out, 'text'), { recursive: true })
  const files = []
  let cur = null, cur_name = null
  const flush = () => { if (cur !== null) files.push([cur_name, cur]) }
  for (const [a_, k, p_] of lines) {
    if (k === 'label' && fnames.has(a_) && labels.get(a_) === p_) {
      flush()
      cur = [`; FUNCTION 0x${a_.toString(16)} ${fnames.get(a_)}`]
      cur_name = `${String(files.length).padStart(5, '0')}_${a_.toString(16)}_${[...p_].slice(0, 60).join('')}.asm`
    }
    if (cur === null) {
      cur = ['; start of .text']
      cur_name = `${String(files.length).padStart(5, '0')}_${a_.toString(16)}_start.asm`
    }
    if (k === 'label') cur.push(`${p_}:`)
    else if (k === 'ins') {
      const [neu, , , enc] = p_
      cur.push('    ' + neu + (enc ? ` {enc:${enc}}` : ''))
    } else if (k === 'br') {
      const [mn, lab, enc] = p_
      cur.push(`    ${mn} ${lab}` + (enc ? ` {enc:${enc}}` : ''))
    } else if (k === 'pin') {
      const [text, bh, sites] = p_
      const b = Buffer.from(bh, 'hex')
      const parts = []
      let i2 = 0
      for (const [off, lab] of sites) {
        if (off > i2) parts.push('    db ' + [...b.subarray(i2, off)].map(hx2).join(','))
        parts.push(`    dd ${lab}`)
        i2 = off + 4
      }
      if (i2 < b.length) parts.push('    db ' + [...b.subarray(i2)].map(hx2).join(','))
      parts[0] += `    ; PINNED ${text}`
      cur.push(...parts)
    } else if (k === 'db') {
      for (let i2 = 0; i2 < p_.length; i2 += 16) cur.push('    db ' + [...p_.subarray(i2, i2 + 16)].map(hx2).join(','))
    } else if (k === 'dd') cur.push(`    dd ${p_}`)
  }
  flush()
  for (const [name, content] of files) writeFileSync(join(out, 'text', name), content.join('\n') + '\n')
  // non-code sections: raw bytes, pointers into .text replaced by label fixups (zeroed in the raw file)
  mkdirSync(join(out, 'raw'), { recursive: true })
  const withRaw = secs.filter((s) => s.raw_size)
  if (!withRaw.length) throw new PyValueError('min() arg is an empty sequence')
  const first_raw = Math.min(...withRaw.map((s) => s.raw_ptr))
  writeFileSync(join(out, 'raw', 'headers.bin'), d.subarray(0, first_raw))
  const sections = [], fixups = [], data_sites = []
  const stripDots = (s) => s.replace(/^\.+|\.+$/g, '')
  for (const s of secs) {
    const ent = { name: s.name, va: s.va, raw_ptr: s.raw_ptr, raw_size: s.raw_size }
    if (s === T) ent.kind = 'text'
    else if (s.name === reloc_sec) ent.kind = 'reloc'
    else {
      ent.kind = 'raw'
      let raw = Buffer.from(d.subarray(s.raw_ptr, s.raw_ptr + s.raw_size))
      for (const [site, v] of rel) {
        const o = site - base - s.va
        if (o >= 0 && o < s.raw_size) {
          if (in_text(v)) {
            fixups.push({ section: s.name, offset: o, label: label_for(v) })
            raw = sliceAssign(raw, o, o + 4, Buffer.alloc(4))
          } else data_sites.push(site - base)
        }
      }
      writeFileSync(join(out, 'raw', stripDots(s.name) + '.bin'), raw)
      ent.file = 'raw/' + stripDots(s.name) + '.bin'
    }
    sections.push(ent)
  }
  const end_raw = Math.max(...secs.map((s) => s.raw_ptr + s.raw_size))
  const gaps = []
  const spans = [[0, first_raw], ...withRaw.map((s) => [s.raw_ptr, s.raw_ptr + s.raw_size])]
    .sort((x, y) => x[0] - y[0] || x[1] - y[1])
  for (let k = 0; k + 1 < spans.length; k++) {
    const [, a1] = spans[k], [b0] = spans[k + 1]
    if (b0 > a1) gaps.push({ offset: a1, hex: d.subarray(a1, b0).toString('hex') })
  }
  writeFileSync(join(out, 'raw', 'overlay.bin'), d.subarray(end_raw))
  // check the .reloc convention now, so a build failure later is not a surprise
  const rs = secs.find((s) => s.name === reloc_sec)
  let reloc_note = null
  if (rs) {
    const regen = make_reloc([...rel.keys()].map((x) => x - base))
    const orig = d.subarray(rs.raw_ptr, rs.raw_ptr + rs.raw_size)
    const tail = orig.subarray(regen.length)
    reloc_note = {
      regenerated_equals_original: orig.subarray(0, regen.length).equals(regen) && !tail.some((x) => x !== 0),
      size: regen.length, dir_size: dirs[5][1],
    }
  }
  const layout = {
    image_base: base, text: { name: T.name, va: T.va, raw_size: T.raw_size },
    sections, fixups, data_reloc_sites: data_sites.sort((x, y) => x - y), gaps,
    overlay: 'raw/overlay.bin', reloc_section: reloc_sec, reloc_check: reloc_note,
    files: files.map(([n]) => n), stats,
  }
  dump(layout, join(out, 'layout.json'), { indent: 1 })
  process.stdout.write(dumps({ files: files.length, ...stats, reloc_check: reloc_note }, { indent: 1 }) + '\n')
  return 0
}

// ---------------------------------------------------------------------------------------------- build (encode)
export const LINE_ENC = new RegExp(`${S}*\\{enc:([0-9]+)\\}${S}*(?=\\n?$)`, 'u')

export function parse_files(out, layout) {
  const items = []
  for (const fn of (layout instanceof Map ? layout.get('files') : layout.files)) {
    for (const raw of iterLines(readText(join(out, 'text', fn)))) {
      let s = pyStrip(raw.split(';')[0])
      if (!s) continue
      if (s.endsWith(':') && IDENT.test(s.slice(0, -1))) {
        items.push({ k: 'label', name: s.slice(0, -1) })
        continue
      }
      let enc = 0
      const m = LINE_ENC.exec(s)
      if (m) {
        enc = pyInt(m[1])
        s = pyStrip(s.slice(0, m.index))
      }
      const sp = s.indexOf(' ')
      const head = sp < 0 ? s : s.slice(0, sp), rest = sp < 0 ? '' : s.slice(sp + 1)
      const up = head.toUpperCase()
      if (up === 'DB') {
        const vals = rest.split(' ').join('').split(',').map((x) => pyInt(x, 16))
        for (const v of vals) if (!(v >= 0 && v < 256)) throw new PyValueError('bytes must be in range(0, 256)')
        items.push({ k: 'db', b: Buffer.from(vals) })
      } else if (up === 'DD') {
        items.push({ k: 'dd', expr: pyStrip(rest) })
      } else if ((has(JCC, up) || has(REL8_ONLY, up) || up === 'JMP' || up === 'CALL') && IDENT.test(pyStrip(rest))) {
        // a direct branch only if the operand is a label (decided once all labels are known)
        items.push({ k: 'br?', mn: up, target: pyStrip(rest), enc, text: s })
      } else {
        items.push({ k: 'ins', text: s, enc })
      }
    }
  }
  return items
}

function packU32(v) {
  if (!(Number.isInteger(v) && v >= 0 && v <= 0xffffffff)) throw new Error("struct.error: 'I' format requires 0 <= number <= 4294967295")
  const b = Buffer.alloc(4)
  b.writeUInt32LE(v)
  return b
}
function packI32(v) {
  if (!(Number.isInteger(v) && v >= -0x80000000 && v <= 0x7fffffff)) throw new Error("struct.error: 'i' format requires -2147483648 <= number <= 2147483647")
  const b = Buffer.alloc(4)
  b.writeInt32LE(v)
  return b
}
// bytearray slice assignment buf[lo:hi] = val (may change the length, as in Python)
function sliceAssign(buf, lo, hi, val) {
  const n = buf.length
  lo = Math.max(0, Math.min(lo, n))
  hi = Math.max(lo, Math.min(hi, n))
  if (hi - lo === val.length) {
    val.copy(buf, lo)
    return buf
  }
  return Buffer.concat([buf.subarray(0, lo), val, buf.subarray(hi)])
}

export function build(out, binary_out, cache_file = null) {
  const layout = load(join(out, 'layout.json'))
  const base = layout.get('image_base')
  const T = layout.get('text')
  const t0 = base + T.get('va')
  const items = parse_files(out, layout)
  let cache = new Map()
  if (cache_file && existsSync(cache_file)) cache = load(cache_file)
  const fixed_value = fixed_label_value
  const LAB = `(?<!${W})([A-Za-z_][A-Za-z0-9_]*)(-0x[0-9a-fA-F]+)?(?!${W})`
  const lab_tok = new RegExp(LAB, 'gu')
  const lab_full = new RegExp(`^(?:${LAB})$`, 'u')
  const code_labels = new Set(items.filter((it) => it.k === 'label').map((it) => it.name))
  const labels_in = (text) => [...text.matchAll(lab_tok)]
    .filter((m) => code_labels.has(m[1]) || fixed_value(m[1]) !== null).map((m) => m[0])
  const value_of = (expr, values) => {
    const m = lab_full.exec(pyStrip(expr))
    if (!m) return null
    const v = values.has(m[1]) ? values.get(m[1]) : fixed_value(m[1])
    if (v === null || v === undefined) return null
    return m[2] ? v - pyInt(m[2].slice(1), 16) : v
  }
  for (const it of items) {
    if (it.k === 'br?') {
      if (code_labels.has(it.target) || fixed_value(it.target) !== null) it.k = 'br'
      else it.k = 'ins'                     // e.g. JMP EAX, CALL ESI
    }
  }
  // 1. size every ordinary instruction (label values do not change the length: always 32-bit)
  const resolveText = (text, values) => text.replace(lab_tok, (m0) => {
    const v = value_of(m0, values)
    return v !== null ? (v < 0 ? '0x-' + (-v).toString(16) : '0x' + v.toString(16)) : m0
  })
  const prov = new Map([...code_labels].map((n) => [n, 0x10000000]))
  let todo = new Map()
  for (const it of items) {
    if (it.k === 'ins') {
      it.prov = resolveText(it.text, prov)
      const key = `${it.prov}\0${it.enc}`
      if (!cache.has(key)) todo.set(key, [it.prov, it.enc])
    }
  }
  const run = (todo) => {
    if (!todo.size) return
    const keys = [...todo.keys()]
    const res = ghidra_assemble(keys.map((k, i) => [String(i), todo.get(k)[0], todo.get(k)[1]]))
    const bad = []
    keys.forEach((k, i) => {
      const [h, n] = res.get(String(i)) ?? ['ERR', 'missing']
      if (h === 'ERR') bad.push(`${pyRepr(todo.get(k)[0])}: ${n}`)
      else cache.set(k, h)
    })
    if (bad.length) throw new RuntimeError(`${bad.length} line(s) do not assemble, e.g.: ` + bad.slice(0, 5).join('; '))
  }
  run(todo)
  for (const it of items) if (it.k === 'ins') it.size = Math.floor(cache.get(`${it.prov}\0${it.enc}`).length / 2)
  // 2. layout: the same MSVC-style branch sizing split used to predict the original
  const seq = items.map((it) => {
    if (it.k === 'label') return ['label', it.name]
    if (it.k === 'br') return ['br', it.mn, it.target, it.enc]
    if (it.k === 'ins') return ['fix', it.size]
    if (it.k === 'db') return ['fix', it.b.length]
    return ['fix', 4]
  })
  const [addrs, values, longs, addr] = relax(seq, t0, fixed_value)
  items.forEach((it, i) => {
    it.addr = addrs[i]
    if (it.k === 'br') {
      it.long = longs[i]
      if (!longs[i] && !has(REL8_ONLY, it.mn) && it.mn !== 'CALL') {
        const tgt = values.has(it.target) ? values.get(it.target) : fixed_value(it.target)
        if (!(-128 <= tgt - (addrs[i] + 2) && tgt - (addrs[i] + 2) <= 127)) {
          throw new RuntimeError(`${it.mn} ${it.target} {enc:2}: target out of rel8 range`)
        }
      }
    }
  })
  const end = addr
  if (process.env.REASM_DEBUG) {
    dump({
      values,
      items: items.map((it) => [it.k, it.name || it.text || it.target || '', it.addr, it.size ?? null, it.long ?? null]),
    }, process.env.REASM_DEBUG)
  }
  if (end - t0 > T.get('raw_size')) {
    throw new RuntimeError(`.text grew to ${end - t0} bytes > raw size ${T.get('raw_size')}: moving sections is not supported`)
  }
  // 3. final bytes
  todo = new Map()
  for (const it of items) {
    if (it.k === 'ins') {
      it.final = resolveText(it.text, values)
      const key = `${it.final}\0${it.enc}`
      if (!cache.has(key)) todo.set(key, [it.final, it.enc])
    }
  }
  run(todo)
  const chunks = []
  let tlen = 0
  const code_sites = []
  for (const it of items) {
    const k = it.k
    if (k === 'label') continue
    let b
    if (k === 'ins') {
      b = Buffer.from(cache.get(`${it.final}\0${it.enc}`), 'hex')
      if (b.length !== it.size) throw new RuntimeError(`size changed after resolving labels: ${it.text}`)
      for (const lab of new Set(labels_in(it.text))) {
        const v = value_of(lab, values)
        const pat = packU32(v)
        const pos = []
        for (let i = 0; i < b.length - 3; i++) if (b[i] === pat[0] && b[i + 1] === pat[1] && b[i + 2] === pat[2] && b[i + 3] === pat[3]) pos.push(i)
        if (!pos.length) throw new RuntimeError(`label value of ${lab} not found in encoding of ${it.text}`)
        for (const p of pos) code_sites.push(it.addr + p - base)
      }
    } else if (k === 'db') {
      b = it.b
    } else if (k === 'dd') {
      const v = value_of(it.expr, values)
      if (v === null) throw new RuntimeError(`unknown label in dd ${it.expr}`)
      code_sites.push(it.addr - base)
      b = packU32(v)
    } else {
      const tgt = values.has(it.target) ? values.get(it.target) : fixed_value(it.target)
      const mn = it.mn, a = it.addr
      if (has(REL8_ONLY, mn)) b = Buffer.from([REL8_ONLY[mn], (tgt - (a + 2)) & 0xff])
      else if (!it.long) b = Buffer.from([mn === 'JMP' ? 0xeb : 0x70 | JCC[mn], (tgt - (a + 2)) & 0xff])
      else if (mn === 'CALL') b = Buffer.concat([Buffer.from([0xe8]), packI32(tgt - (a + 5))])
      else if (mn === 'JMP') b = Buffer.concat([Buffer.from([0xe9]), packI32(tgt - (a + 5))])
      else b = Buffer.concat([Buffer.from([0x0f, 0x80 | JCC[mn]]), packI32(tgt - (a + 6))])
    }
    chunks.push(b)
    tlen += b.length
  }
  if (T.get('raw_size') > tlen) chunks.push(Buffer.alloc(T.get('raw_size') - tlen))
  const text = Buffer.concat(chunks)
  // 4. PE
  let img = Buffer.from(readFileSync(join(out, 'raw', 'headers.bin')))
  const secdata = new Map()
  const sites = [...code_sites, ...layout.get('data_reloc_sites')]
  const sections = layout.get('sections')
  for (const s of sections) {
    if (s.get('kind') === 'text') secdata.set(s.get('name'), text)
    else if (s.get('kind') === 'raw') {
      let raw = Buffer.from(readFileSync(join(out, s.get('file'))))
      for (const fx of layout.get('fixups')) {
        if (fx.get('section') !== s.get('name')) continue
        const v = value_of(fx.get('label'), values)
        raw = sliceAssign(raw, fx.get('offset'), fx.get('offset') + 4, packU32(v))
        sites.push(s.get('va') + fx.get('offset'))
      }
      secdata.set(s.get('name'), raw)
    }
  }
  for (const s of sections) {
    if (s.get('kind') === 'reloc') {
      const r = make_reloc(sites)
      if (r.length > s.get('raw_size')) throw new RuntimeError('.reloc grew beyond its raw size')
      secdata.set(s.get('name'), Buffer.concat([r, Buffer.alloc(s.get('raw_size') - r.length)]))
    }
  }
  const total = Math.max(...sections.map((s) => s.get('raw_ptr') + s.get('raw_size')))
  if (total > img.length) img = Buffer.concat([img, Buffer.alloc(total - img.length)])
  for (const g of layout.get('gaps')) {
    const b = Buffer.from(g.get('hex'), 'hex')
    img = sliceAssign(img, g.get('offset'), g.get('offset') + b.length, b)
  }
  for (const s of sections) {
    if (s.get('raw_size')) {
      if (!secdata.has(s.get('name'))) throw new Error(`KeyError: ${pyRepr(s.get('name'))}`)
      img = sliceAssign(img, s.get('raw_ptr'), s.get('raw_ptr') + s.get('raw_size'), secdata.get(s.get('name')))
    }
  }
  img = Buffer.concat([img, readFileSync(join(out, layout.get('overlay')))])
  writeFileSync(binary_out, img)
  if (cache_file) dump(cache, cache_file)
  return 0
}

export function editcheck(binary, out, ddir, cache_file = null) {
  const tmp = mkdtempSync(join(tmpdir(), 'tmp'))
  const work = join(tmp, 'text_copy')
  cpSync(out, work, { recursive: true })
  const layout = load(join(work, 'layout.json'))
  const d = readFileSync(binary)
  const [base, dirs, secs] = pe_parse(d)
  const [rel] = relocs_of(d, base, dirs, secs)
  const T = next(secs, (x) => x.exec)
  const t0 = base + T.va, tend = base + T.va + T.raw_size
  // find the first function file with >= 2 instructions; insert after its first instruction
  const ins = new Map()
  for (const [a, ln, , flow, targets] of readTsv(join(ddir, 'instructions.tsv'), 6, 5)) {
    ins.set(pyInt(a, 16), [pyInt(ln), flow, targets])
  }
  let X = null
  for (const fn of (layout instanceof Map ? layout.get('files') : layout.files)) {
    const p = join(work, 'text', fn)
    const src = readText(p).split('\n')
    const idx = []
    src.forEach((l, i) => {
      const t = pyStrip(l).toLowerCase()
      if (l.startsWith('    ') && !(t.startsWith('db') || t.startsWith('dd'))) idx.push(i)
    })
    if (idx.length >= 2) {
      const fa = pyInt(fn.split('_')[1], 16)
      if (!ins.has(fa)) throw new Error(`KeyError: ${fa}`)
      X = fa + ins.get(fa)[0]
      src.splice(idx[0] + 1, 0, '    NOP')
      writeFileSync(p, src.join('\n'))
      break
    }
  }
  const outb = join(tmp, 'edited.bin')
  build(work, outb, cache_file)
  const e = readFileSync(outb)
  const shift = (v) => (t0 <= v && v < tend && v >= X ? v + 1 : v)
  const rd = (buf, va) => {
    const sec = next(secs, (x) => x.va <= va - base && va - base < x.va + x.raw_size)
    return buf.readUInt32LE(sec.raw_ptr + va - base - sec.va)
  }
  const wrong = []
  for (const [s_, v] of rel) if (rd(e, shift(s_)) !== shift(v)) wrong.push([s_, v, rd(e, shift(s_))])
  const bad_ptr = wrong.length
  const [erel] = relocs_of(e, base, dirs, secs)
  const shifted = new Set([...rel.keys()].map(shift))
  let bad_reloc = 0
  for (const k of erel.keys()) if (!shifted.has(k)) bad_reloc++
  for (const k of shifted) if (!erel.has(k)) bad_reloc++
  let bad_br = 0, checked = 0
  for (const [a, [ln, flow, targets]] of ins) {
    if (!(flow === 'call' || flow === 'jump' || flow === 'cjump') || !targets || !(t0 <= a && a < tend)) continue
    const b = d.subarray(T.raw_ptr + a - t0, T.raw_ptr + a - t0 + ln)
    const bk = branch_kind(b)
    if (!bk) continue
    const t = pyInt(targets.split(',')[0], 16)
    const a2 = shift(a)
    const o = T.raw_ptr + a2 - t0
    const nb = e.subarray(o, o + 6)
    let t2
    const i32 = (lo) => {
      if (nb.length < lo + 4) throw new Error('struct.error: unpack requires a buffer of 4 bytes')
      return nb.readInt32LE(lo)
    }
    if (nb[0] === 0xe8 || nb[0] === 0xe9) t2 = a2 + 5 + i32(1)
    else if (nb[0] === 0x0f) t2 = a2 + 6 + i32(2)
    else {
      if (nb.length < 2) throw new Error('struct.error: unpack requires a buffer of 1 bytes')
      t2 = a2 + 2 + nb.readInt8(1)
    }
    checked += 1
    bad_br += t2 !== shift(t) ? 1 : 0
  }
  const res = {
    inserted_after: '0x' + (X - 1).toString(16), relocated_pointers: rel.size, pointers_wrong: bad_ptr,
    reloc_entries_differing: bad_reloc, branches_checked: checked, branches_wrong: bad_br,
    size_equal: e.length === d.length,
    wrong_pointer_examples: wrong.slice(0, 10).map(([a, v, w]) => `site 0x${a.toString(16)}: original -> 0x${v.toString(16)}, edited -> 0x${w.toString(16)}`),
  }
  process.stdout.write(dumps(res, { indent: 1 }) + '\n')
  const ok = !bad_ptr && !bad_reloc && !bad_br
  process.stdout.write((ok ? 'EDITABLE' : 'NOT EDITABLE') + '\n')
  return ok ? 0 : 1
}

export function main(argv) {
  if (argv.length < 1 || argv[0] === '-h' || argv[0] === '--help') {
    process.stderr.write(DOC + '\n')
    return 2
  }
  const cmd = argv[0], rest = argv.slice(1)
  const opt = {}
  for (const flag of ['--names', '--cache']) {
    const i = rest.indexOf(flag)
    if (i >= 0) {
      if (i + 1 >= rest.length) throw new Error('IndexError: list index out of range')
      opt[flag] = rest[i + 1]
      rest.splice(i, 2)
    }
  }
  if (cmd === 'split' && rest.length === 3) return split(rest[0], rest[1], rest[2], opt['--names'] ?? null)
  if (cmd === 'build' && rest.length === 2) return build(rest[0], rest[1], opt['--cache'] ?? null)
  if (cmd === 'editcheck' && rest.length === 3) return editcheck(rest[0], rest[1], rest[2], opt['--cache'] ?? null)
  if (cmd === 'verify' && rest.length === 2) {
    const tmpd = mkdtempSync(join(tmpdir(), 'tmp'))
    const outb = join(tmpd, 'rebuilt.bin')
    build(rest[1], outb, opt['--cache'] ?? null)
    const x = readFileSync(rest[0]), y = readFileSync(outb)
    const a = createHash('sha256').update(x).digest('hex')
    const b = createHash('sha256').update(y).digest('hex')
    if (a === b) {
      process.stdout.write(`IDENTICAL ${a}\n`)
      return 0
    }
    const n = Math.min(x.length, y.length)
    let first = n
    for (let i = 0; i < n; i++) if (x[i] !== y[i]) { first = i; break }
    process.stdout.write(`DIFFERENT: original ${x.length} bytes, rebuilt ${y.length} bytes, first difference at file offset 0x${first.toString(16)}\n`)
    process.stdout.write(`rebuilt kept at ${outb}\n`)
    return 1
  }
  process.stderr.write(DOC + '\n')
  return 2
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(() => main(process.argv.slice(2)))
}
