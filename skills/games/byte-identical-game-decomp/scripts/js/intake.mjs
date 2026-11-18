#!/usr/bin/env node
// intake.mjs - JavaScript (Node.js) port of intake.py (phase 1: installer -> verified game tree + manifest).
// Same subcommands, output and exit codes as intake.py:
//   intake.mjs extract  <setup_xxx.exe> <out_dir> [--language LANG] [--collisions error|overwrite|rename]
//   intake.mjs verify-hashdb <game_dir>
//   intake.mjs manifest <game_dir> <manifest.json>
//   intake.mjs compare  <manifest_a.json> <manifest_b.json> [--allow GLOB ...]
// extract runs inno.mjs (the JavaScript port) where intake.py runs inno.py; both print the same text.

import fs from 'node:fs'
import crypto from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dumps } from './lib/pyjson.mjs'
import { ZipFile } from './lib/zipfile.mjs'
import {
  out, err, print, eprint, walk, listdir, join, dirname, basename, splitext, abspath, relpath, isfile, isdir, islink,
  getsize, cmpStr, pyStrip, cpSlice, fnmatchcase, traceback, decodeUtf8Strict, osErrorStr, osErrorClass, isOSError,
  utf8DecodeError,
} from './lib/pyshim.mjs'

const DOC = "Phase 1: turn a GOG installer (or an existing install folder) into a verified game tree + manifest.\n\n  intake.py extract  <setup_xxx.exe> <out_dir> [--language LANG] [--collisions error|overwrite|rename]\n        unpack the installer with scripts/inno.py (pure Python; its setup_xxx-N.bin parts must sit next to\n        it; every stored checksum is verified). Collisions default to `error`, so a multi-language installer\n        cannot silently overwrite one language's file with another's; on a collision error, list languages\n        with `inno.py info <setup.exe>` and rerun with --language. Exit 0 ok, 1 extraction/verification\n        error, 2 bad arguments / unsupported installer.\n  intake.py verify-hashdb <game_dir>\n        check every file listed in GOG's goggame-<id>.hashdb (MD5) - the phase-1 gate.\n  intake.py manifest <game_dir> <manifest.json>\n        SHA-256 + size of every file (symlinks skipped).\n  intake.py compare  <manifest_a.json> <manifest_b.json> [--allow GLOB ...]\n        Byte-identity gate between two trees (e.g. a fresh extraction vs the reference manifest a project\n        committed, or vs an installed copy). Paths are compared case-insensitively. A file present on\n        only one side FAILS the gate unless it matches an --allow glob (fnmatch, case-insensitive, tried\n        against the relative path and the basename; repeatable), e.g. --allow 'unins000.*' for the\n        uninstaller a real install adds, or saves/configs written after first run. Allowed files are listed\n        under \"allowed_only_in_a/b\". Prints JSON then PASS/FAIL. Exit 0 = PASS (no differing common file and\n        no unallowed one-sided file), 1 = FAIL, 2 = unreadable manifest.\n\ninno.py writes the game to <out_dir>/ for GOG Galaxy-era installers (<out_dir>/app/ for older ones), next to\ninstaller-only folders such as __redist/ and commonappdata/; extract prints which folder holds the game and\nwhich folders to leave out (or --allow) when comparing with an install. Galaxy-era installers can also have game\nfiles as plain {app} entries (inno.py: app/x): extract moves those the game's goggame-*.hashdb lists into the game\nfolder, where a real install puts them. Run with python3 -I. Stdlib only.\n"

class SysExit extends Error { constructor(code, msg) { super(msg); this.code = code } }
class PyUncaught extends Error { constructor(cls, msg) { super(msg); this.cls = cls } }
const HERE = dirname(fileURLToPath(import.meta.url))

function hashFile(p, algo) {
  const h = crypto.createHash(algo)
  const fd = fs.openSync(p, 'r')
  try {
    const b = Buffer.allocUnsafe(1 << 20)
    let pos = 0
    for (;;) {
      const n = fs.readSync(fd, b, 0, b.length, pos)
      if (!n) break
      h.update(b.subarray(0, n))
      pos += n
    }
  } finally { fs.closeSync(fd) }
  return h.digest('hex')
}

function manifest(root) {
  if (!isdir(root)) throw new SysExit(1, `not a directory: ${root}`)
  const files = []
  for (const [r, , fs_] of walk(root)) {
    for (const f of fs_) {
      const p = join(r, f)
      if (islink(p)) continue
      const rel = relpath(p, root)
      files.push([rel, { size: getsize(p), sha256: hashFile(p, 'sha256') }])
    }
  }
  // dict(files) then sorted(items): a repeated key keeps its last value
  const m = new Map()
  for (const [k, v] of files) m.set(k, v)
  const sorted = new Map([...m.entries()].sort((a, b) => cmpStr(a[0], b[0])))
  return new Map([['root_name', basename(abspath(root))], ['files', sorted]])
}

// glob.glob(glob.escape(stem) + '-*.bin'), sorted
function binParts(stem) {
  const d = dirname(stem), base = basename(stem)
  let names
  try { names = listdir(d || '.') } catch { return [] }
  const res = []
  for (const n of names) {
    if (n.startsWith('.') && !base.startsWith('.')) continue
    if (n.length >= base.length + 5 && n.startsWith(base + '-') && n.endsWith('.bin')) res.push(d ? join(d, n) : n)
  }
  return res.sort(cmpStr)
}

function textOutput(r) {     // subprocess.run(..., text=True): UTF-8 with universal newlines
  const conv = (b) => {
    const s = decodeUtf8Strict(b)
    if (s === null) throw new PyUncaught('UnicodeDecodeError', "'utf-8' codec can't decode subprocess output")
    return s.replace(/\r\n?/g, '\n')
  }
  return conv(r.stdout) + conv(r.stderr)
}

function runInno(args) {
  const r = spawnSync(process.execPath, [join(HERE, 'inno.mjs'), ...args], { maxBuffer: 1 << 30 })
  if (r.error) throw r.error
  return { text: textOutput(r), returncode: r.status ?? 1 }
}

function extract(installer, outDir, language = null, collisions = 'error') {
  if (!isfile(installer)) { eprint(`installer not found: ${installer}`); return 2 }
  const stem = splitext(installer)[0]
  const parts = binParts(stem)
  print('installer:', installer, `(${Math.floor(getsize(installer) / 1048576)} MB)`)
  print('parts    :', parts.length ? parts.map(basename).join(', ') : 'none (single-file installer)')
  const info = runInno(['info', installer])
  print(cpSlice(pyStrip(info.text), -1500))
  if (info.returncode) { eprint(hint(info.text, info.returncode)); return info.returncode }
  makedirs(outDir)
  const cmd = ['extract', installer, outDir, '--collisions', collisions, '--quiet']
  if (language) cmd.push('--language', language)
  print('running  : inno.py extract' + (language ? ` --language ${language}` : ''))
  const p = runInno(cmd)
  print(cpSlice(pyStrip(p.text), -2000))
  if (p.returncode) { eprint(hint(p.text, p.returncode)); return p.returncode }
  const moved = installAppFiles(outDir)
  if (moved.length) {
    print(`installed from app/ into the game folder (GOG hashdb lists them; a real install puts {app} files ` +
      `there): ${moved.length} file(s): ${moved.join(', ')}`)
  }
  print('game folder:', gameFolder(outDir))
  return 0
}

// {lowercase path: path} of every file a goggame-*.hashdb in gameDir lists (empty Map without one)
function hashdbListed(gameDir) {
  const res = new Map()
  let names = []
  try { names = listdir(gameDir) } catch { names = [] }
  for (const db of names.filter((n) => /^goggame-[\s\S]*\.hashdb$/.test(n)).map((n) => join(gameDir, n)).sort(cmpStr)) {
    let data
    try {
      const z = new ZipFile(db)
      const infos = z.infolist()
      data = z.read(infos[0])
      z.close()
    } catch { continue }
    if (!data || data.length < 12) continue
    const hsize = data.readUInt32LE(0), count = data.readUInt32LE(8)
    if (hsize !== 12 || data.length !== 12 + count * 1056) continue
    for (let i = 0; i < count; i++) {
      const r = data.subarray(12 + i * 1056, 12 + i * 1056 + 1024)
      const z0 = r.indexOf(0)
      const ps = decodeUtf8Strict(z0 >= 0 ? r.subarray(0, z0) : r)
      if (ps === null) continue
      const path = ps.replace(/\\/g, '/')
      if (!res.has(path.toLowerCase())) res.set(path.toLowerCase(), path)
    }
  }
  return res
}

// GOG Galaxy-era installers write their split files to <out>/ but plain {app} entries to <out>/app/; a real install
// puts both in one folder, so app/ files the game's own hashdb lists (and that are not in <out>/ yet) move there
function installAppFiles(o) {
  const app = join(o, 'app')
  const listed = isdir(app) ? hashdbListed(o) : new Map()
  const moved = []
  if (!listed.size) return moved
  const rows = [...walk(app)].sort((a, b) => cmpStr(a[0], b[0]))
  for (const [r, , fs_] of rows) {
    for (const f of [...fs_].sort(cmpStr)) {
      const src = join(r, f)
      const rel = relpath(src, app).split('\\').join('/')
      const want = listed.get(rel.toLowerCase())
      if (!want) continue
      const dst = join(o, ...want.split('/'))
      let exists = true
      try { fs.lstatSync(dst) } catch { exists = false }
      if (exists) continue
      fs.mkdirSync(dirname(dst), { recursive: true })
      fs.renameSync(src, dst)
      moved.push(want)
    }
  }
  return moved.sort(cmpStr)
}

function makedirs(name) {          // os.makedirs(name, exist_ok=True)
  const i = name.lastIndexOf('/') + 1
  let head = name.slice(0, i), tail = name.slice(i)
  if (head && head !== '/'.repeat(head.length)) head = head.replace(/\/+$/, '')
  if (!tail) {
    const j = head.lastIndexOf('/') + 1
    tail = head.slice(j); head = head.slice(0, j)
    if (head && head !== '/'.repeat(head.length)) head = head.replace(/\/+$/, '')
  }
  if (head && tail && !fs.existsSync(head)) {
    try { makedirs(head) } catch (e) { if (e.code !== 'EEXIST') throw e }
    if (tail === '.') return
  }
  try { fs.mkdirSync(name) } catch (e) { if (!isdir(name)) throw e }
}

const INSTALLER_ONLY = new Set(['__redist', 'commonappdata', 'tmp', '{tmp}', 'userappdata', 'userdocs', 'sys', 'win'])

function gameFolder(o) {
  const score = (d) => {
    let n = 0
    for (const e of listdir(d)) {
      if (INSTALLER_ONLY.has(e.toLowerCase()) || (d === o && e === 'app')) continue
      const p = join(d, e)
      if (isdir(p)) { for (const [, , fs_] of walk(p)) n += fs_.length } else n += 1
    }
    return n
  }
  const app = join(o, 'app')
  const best = isdir(app) && score(app) > score(o) ? app : o
  const extra = listdir(o).filter((e) => isdir(join(o, e)) && (INSTALLER_ONLY.has(e.toLowerCase()) || (best === o && e === 'app')))
    .map((e) => e + '/').sort(cmpStr)
  return best + (extra.length ? `  (installer-only, not part of the game tree: ${extra.join(' ')})` : '')
}

function hint(text, rc) {
  const t = text.toLowerCase()
  if (t.includes('rar')) {
    return 'The .bin parts are RAR archives (older multi-part GOG installers). They are not supported: copy an ' +
      'installed copy of the game instead and continue with verify-hashdb / manifest on that folder.'
  }
  if (t.includes('collision')) {
    return 'Two installer entries map to the same output path (usually per-language copies). List languages ' +
      'with `inno.py info <setup.exe>` and rerun with --language LANG, or pass --collisions rename.'
  }
  if (t.includes('unsupported') || rc === 2) {
    return 'inno.py does not support this installer (version, encryption or not Inno Setup; see its message). ' +
      'Use an installed copy of the game instead (references/intake.md).'
  }
  return `inno.py failed (exit ${rc}): a checksum/CRC/data error - corrupt download or a missing .bin part?`
}

// ---- json.load with Python's error messages (json.decoder) ----
class JSONDecodeError extends Error {}
function pyJsonLoads(s) {
  let i = 0
  const n = s.length
  const fail = (msg, pos) => {
    const before = s.slice(0, pos)
    const lineno = (before.match(/\n/g) || []).length + 1
    const colno = lineno === 1 ? pos + 1 : pos - before.lastIndexOf('\n')
    throw new JSONDecodeError(`${msg}: line ${lineno} column ${colno} (char ${pos})`)
  }
  const WS = ' \t\n\r'
  const skip = () => { while (i < n && WS.includes(s[i])) i++ }
  const NUM = /^(-?(?:0|[1-9]\d*))(\.\d+)?([eE][-+]?\d+)?/
  function scanString() {        // i at the char after the opening quote
    const begin = i - 1
    let o = ''
    for (;;) {
      let j = i
      while (j < n && s[j] !== '"' && s[j] !== '\\' && s.charCodeAt(j) >= 0x20) j++
      o += s.slice(i, j)
      if (j >= n) fail('Unterminated string starting at', begin)
      const c = s[j]
      if (c === '"') { i = j + 1; return o }
      if (c !== '\\') fail('Invalid control character at', j)
      const e = s[j + 1]
      if (e === undefined) fail('Unterminated string starting at', begin)
      if (e !== 'u') {
        const m = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[e]
        if (m === undefined) fail('Invalid \\escape', j)
        o += m
        i = j + 2
        continue
      }
      const hx = s.slice(j + 2, j + 6)
      if (!/^[0-9a-fA-F]{4}$/.test(hx)) fail('Invalid \\uXXXX escape', j + 1)
      let u = parseInt(hx, 16)
      i = j + 6
      if (u >= 0xd800 && u <= 0xdbff && s[i] === '\\' && s[i + 1] === 'u') {
        const h2 = s.slice(i + 2, i + 6)
        if (!/^[0-9a-fA-F]{4}$/.test(h2)) fail('Invalid \\uXXXX escape', i + 1)
        const u2 = parseInt(h2, 16)
        if (u2 >= 0xdc00 && u2 <= 0xdfff) { o += String.fromCharCode(u, u2); i += 6; continue }
      }
      o += String.fromCharCode(u)
    }
  }
  function value() {
    const c = s[i]
    if (c === '"') { i++; return scanString() }
    if (c === '{') {
      i++
      const d = new Map()
      skip()
      if (s[i] === '}') { i++; return d }
      if (s[i] !== '"') fail('Expecting property name enclosed in double quotes', i)
      for (;;) {
        i++
        const k = scanString()
        skip()
        if (s[i] !== ':') fail("Expecting ':' delimiter", i)
        i++
        skip()
        if (i >= n) fail('Expecting value', i)
        d.set(k, value())
        skip()
        if (s[i] === '}') { i++; return d }
        if (s[i] !== ',') fail("Expecting ',' delimiter", i)
        i++
        skip()
        if (s[i] !== '"') fail('Expecting property name enclosed in double quotes', i)
      }
    }
    if (c === '[') {
      i++
      const a = []
      skip()
      if (s[i] === ']') { i++; return a }
      for (;;) {
        if (i >= n) fail('Expecting value', i)
        a.push(value())
        skip()
        if (s[i] === ']') { i++; return a }
        if (s[i] !== ',') fail("Expecting ',' delimiter", i)
        i++
        skip()
      }
    }
    if (s.startsWith('null', i)) { i += 4; return null }
    if (s.startsWith('true', i)) { i += 4; return true }
    if (s.startsWith('false', i)) { i += 5; return false }
    if (s.startsWith('NaN', i)) { i += 3; return NaN }
    if (s.startsWith('Infinity', i)) { i += 8; return Infinity }
    if (s.startsWith('-Infinity', i)) { i += 9; return -Infinity }
    const m = NUM.exec(s.slice(i, i + 400))
    if (m) { i += m[0].length; return Number(m[0]) }
    fail('Expecting value', i)
  }
  skip()
  const v = value()
  skip()
  if (i !== n) fail('Extra data', i)
  return v
}

function loadManifest(p) {
  let text
  try {
    text = fs.readFileSync(p)
  } catch (e) {
    if (isOSError(e)) {
      if (e.path === undefined) e.path = p          // EISDIR comes from read(), Python's open() names the file
      throw new ReadError(osErrorStr(e))
    }
    throw e
  }
  // open(p) in text mode: UTF-8, universal newlines; json.loads rejects a BOM
  const bad = utf8DecodeError(text)
  if (bad !== null) throw new ReadError(bad)
  const s = text.toString('utf8').replace(/\r\n?/g, '\n')
  if (s.startsWith('\ufeff')) throw new ReadError('Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)')
  let v
  try { v = pyJsonLoads(s) } catch (e) { if (e instanceof JSONDecodeError) throw new ReadError(e.message); throw e }
  if (!(v instanceof Map)) {
    if (Array.isArray(v)) throw new PyUncaught('TypeError', 'list indices must be integers or slices, not str')
    throw new PyUncaught('TypeError', `'${v === null ? 'NoneType' : typeof v}' object is not subscriptable`)
  }
  if (!v.has('files')) throw new ReadError("'files'")
  return v.get('files')
}
class ReadError extends Error {}

function compare(a, b, allow = []) {
  let A, B
  try {
    A = loadManifest(a)
    B = loadManifest(b)
  } catch (e) {
    if (e instanceof ReadError) { eprint(`cannot read manifest: ${e.message}`); return 2 }
    throw e
  }
  const fold = (d) => {
    if (!(d instanceof Map)) throw new PyUncaught('AttributeError', `object has no attribute 'items'`)
    const m = new Map()
    for (const [k, v] of d) m.set(k.toLowerCase(), [k, v])
    return m
  }
  const FA = fold(A), FB = fold(B)
  const pats = allow.map((g) => g.toLowerCase())
  const allowed = (p) => pats.some((g) => fnmatchcase(p.toLowerCase(), g) || fnmatchcase(p.toLowerCase().split('/').pop(), g))
  const sha = (v) => (v instanceof Map ? v.get('sha256') : undefined)
  const onlyA = [...FA.keys()].filter((k) => !FB.has(k)).map((k) => FA.get(k)[0]).sort(cmpStr)
  const onlyB = [...FB.keys()].filter((k) => !FA.has(k)).map((k) => FB.get(k)[0]).sort(cmpStr)
  const common = [...FA.keys()].filter((k) => FB.has(k))
  const diff = common.filter((k) => !pyEq(sha(FA.get(k)[1]), sha(FB.get(k)[1]))).map((k) => FA.get(k)[0]).sort(cmpStr)
  const same = common.length - diff.length
  const res = new Map([['identical', same], ['different', diff], ['only_in_a', onlyA.filter((p) => !allowed(p))],
    ['only_in_b', onlyB.filter((p) => !allowed(p))], ['allowed_only_in_a', onlyA.filter(allowed)],
    ['allowed_only_in_b', onlyB.filter(allowed)], ['allow', [...allow]]])
  print(dumps(res, { indent: 1 }))
  const ok = !diff.length && !res.get('only_in_a').length && !res.get('only_in_b').length
  const why = []
  if (diff.length) why.push(`${diff.length} common file(s) differ`)
  if (res.get('only_in_a').length || res.get('only_in_b').length) {
    why.push(`${res.get('only_in_a').length} file(s) only in A, ${res.get('only_in_b').length} only in B (not matched by --allow)`)
  }
  print(ok ? 'PASS' : 'FAIL: ' + why.join('; '))
  return ok ? 0 : 1
}
function pyEq(x, y) {
  if (x instanceof Map || y instanceof Map || Array.isArray(x) || Array.isArray(y)) return JSON.stringify(x) === JSON.stringify(y)
  return x === y
}

function verifyHashdb(gameDir) {
  let names = []
  try { names = listdir(gameDir) } catch { names = [] }
  const dbs = names.filter((n) => /^goggame-[\s\S]*\.hashdb$/.test(n)).map((n) => join(gameDir, n)).sort(cmpStr)
  if (!dbs.length) {
    eprint(`no goggame-*.hashdb in ${gameDir} (not a GOG Galaxy-era game?): use \`compare\` against a ` +
      'reference manifest instead')
    return 2
  }
  let rc = 0
  for (const db of dbs) {
    const z = new ZipFile(db)
    const infos = z.infolist()
    if (!infos.length) throw new PyUncaught('IndexError', 'list index out of range')
    const data = z.read(infos[0])
    z.close()
    if (data.length < 12) {
      throw new PyUncaught('struct.error', `unpack_from requires a buffer of at least 12 bytes for unpacking 12 bytes at offset 0 (actual buffer size is ${data.length})`)
    }
    const hsize = data.readUInt32LE(0), version = data.readUInt32LE(4), count = data.readUInt32LE(8)
    if (hsize !== 12 || data.length !== 12 + count * 1056) {
      eprint(`${basename(db)}: unknown hashdb layout (header ${hsize}, version ${version}, ${data.length} bytes for ${count} records)`)
      return 2
    }
    const listed = new Set()
    let ok = 0
    const bad = [], missing = []
    for (let i = 0; i < count; i++) {
      const r = data.subarray(12 + i * 1056, 12 + (i + 1) * 1056)
      const z0 = r.subarray(0, 1024).indexOf(0)
      const pathRaw = z0 >= 0 ? r.subarray(0, z0) : r.subarray(0, 1024)
      const ps = decodeUtf8Strict(pathRaw)
      if (ps === null) throw new PyUncaught('UnicodeDecodeError', "'utf-8' codec can't decode hashdb path")
      const path = ps.replace(/\\/g, '/')
      const md5raw = r.subarray(1024)
      if (md5raw.some((c) => c > 0x7f)) throw new PyUncaught('UnicodeDecodeError', "'ascii' codec can't decode hashdb md5")
      const md5 = md5raw.toString('latin1')
      listed.add(path.toLowerCase())
      const p = join(gameDir, ...path.split('/'))
      if (!isfile(p)) { missing.push(path); continue }
      const hd = hashFile(p, 'md5')
      if (hd !== md5) bad.push(path)
      ok += hd === md5 ? 1 : 0
    }
    const unlisted = []
    for (const [r_, , fs_] of walk(gameDir)) {
      for (const f of fs_) {
        const rel = relpath(join(r_, f), gameDir)
        if (!listed.has(rel.toLowerCase()) && !f.toLowerCase().startsWith('goggame-')) unlisted.push(rel)
      }
    }
    print(dumps(new Map([['hashdb', basename(db)], ['version', version], ['records', count], ['md5_ok', ok],
      ['md5_mismatch', bad], ['missing', missing], ['not_listed (excluding goggame-*)', unlisted.sort(cmpStr)]]), { indent: 1 }))
    if (bad.length || missing.length) rc = 1
  }
  print(rc === 0 ? 'PASS' : 'FAIL')
  return rc
}

function opt(args, name, dflt = null, multi = false) {
  const vals = [], rest = []
  let i = 0
  while (i < args.length) {
    if (args[i] === name) {
      if (i + 1 >= args.length) throw new SysExit(1, `${name} needs a value`)
      vals.push(args[i + 1]); i += 2
    } else if (args[i].startsWith(name + '=')) {
      vals.push(args[i].slice(args[i].indexOf('=') + 1)); i += 1
    } else { rest.push(args[i]); i += 1 }
  }
  args.splice(0, args.length, ...rest)
  return multi ? vals : (vals.length ? vals[vals.length - 1] : dflt)
}

function usage() { err(DOC + '\n'); return 2 }

function main(argv) {
  if (argv.length < 2 || argv[0] === '-h' || argv[0] === '--help') return usage()
  const cmd = argv.shift()
  if (cmd === 'extract') {
    const lang = opt(argv, '--language')
    const coll = opt(argv, '--collisions', 'error')
    if (!['error', 'overwrite', 'rename'].includes(coll) || argv.length !== 2) return usage()
    return extract(argv[0], argv[1], lang, coll)
  } else if (cmd === 'verify-hashdb' && argv.length === 1) {
    return verifyHashdb(argv[0])
  } else if (cmd === 'manifest' && argv.length === 2) {
    const m = manifest(argv[0])
    fs.writeFileSync(argv[1], dumps(m, { indent: 1 }))
    print(m.get('files').size, 'files ->', argv[1])
    return 0
  } else if (cmd === 'compare') {
    const allow = opt(argv, '--allow', null, true)
    if (argv.length !== 2) return usage()
    return compare(argv[0], argv[1], allow)
  }
  return usage()
}

let rc
try {
  rc = main(process.argv.slice(2))
} catch (e) {
  if (e instanceof SysExit) { err(e.message + '\n'); rc = e.code }
  else if (e instanceof PyUncaught) { traceback(e.cls, e.message); rc = 1 }
  else if (isOSError(e)) { traceback(osErrorClass(e), osErrorStr(e)); rc = 1 }
  else if (e && /^(zipfile\.BadZipFile|NotImplementedError|RuntimeError|EOFError|zlib\.error|OSError)$/.test(e.name)) {
    traceback(e.name, e.message); rc = 1
  } else throw e
}
process.exitCode = rc

export { installAppFiles as install_app_files, hashdbListed as hashdb_listed }
