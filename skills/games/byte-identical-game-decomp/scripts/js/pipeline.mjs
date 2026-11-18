#!/usr/bin/env node
// pipeline.mjs - JavaScript (Node.js) port of pipeline.py: run the skill's phases on a project folder from one
// config file, decomp.json (references/pipeline.md). Same commands, options, decomp.json handling, JSON
// summaries, report files and exit codes as pipeline.py; the tools it runs are the JavaScript ports in this
// folder (intake.mjs, inventory.mjs, verify.mjs, reassemble.mjs, objcmp.mjs, hybrid_link.mjs, relink.mjs, ...),
// plus Ghidra's shell wrappers, msvc.sh and Wine like the Python.
//
//   node pipeline.mjs [--project DIR] <command> [options]      (commands: see pipeline.py)
//
// Format modules: where pipeline.py loads <paths.formats>/fmt_<m>.py, this loads fmt_<m>.mjs from the JS
// formats folder of the project: paths.formats_js when decomp.json sets it, else <parent>/js/<name> of
// paths.formats when that folder exists (tools/formats -> tools/js/formats, the skill's scripts/formats ->
// scripts/js/formats), else paths.formats itself (.mjs files next to the .py ones).
// `build --run` reads the macOS window list through osascript's JavaScript for Automation (Node has no FFI).
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { Worker, isMainThread, parentPort } from 'node:worker_threads'
import { dumps, parse, PyDict } from './lib/pyjson.mjs'
import { ArgumentParser, ArgExit } from './lib/pyargparse.mjs'
import { cmp, pyRepr, pyReprValue, pyStr, S } from './lib/pytools.mjs'
import { pyInt } from './lib/pycompat.mjs'
import {
  out as stdoutWrite, err as stderrWrite, walk, listdir, join, dirname, basename, splitext, abspath, normpath,
  relpath, isfile, isdir, islink, exists, getsize, fixed, osErrorStr, osErrorClass, isOSError,
} from './lib/pyshim.mjs'
import { ZipFile } from './lib/zipfile.mjs'

const SELF = fileURLToPath(import.meta.url)
const HERE = dirname(SELF)                        // scripts/js
const SK = dirname(HERE)                          // scripts (shell wrappers: ghidra/*.sh, msvc.sh)
const NODE = process.execPath
const DEFAULT_PATHS = {
  game: 'work/game', extracted: 'extracted', decoded: 'decoded', reports: 'reports', formats: 'tools/formats',
  analysis: 'analysis', src: 'src_matched', build: 'build', work: 'work', manifest: 'manifests/game.json',
}
const GITIGNORE = ['# Game-derived content (copyrighted; regenerate locally from your own installer)', '/extracted/',
  '/decoded/', '/previews/', '/decompiled*/', '/reassembled/', '/src_matched/', '/analysis/', '/work/',
  '/build/', '__pycache__/', '*.pyc', '.DS_Store']
const SIGS = [[Buffer.from('PK\x03\x04', 'latin1'), 'zip'], [Buffer.from('OggS', 'latin1'), 'ogg'],
  [Buffer.from('RIFF', 'latin1'), 'riff'], [Buffer.from('\x89PNG\r\n\x1a\n', 'latin1'), 'png']]
const MEMBERS_JSON = '_members.json'
const NS = '[^\\t\\n\\v\\f\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]'
const D = '\\p{Nd}'
const LINE = new RegExp(`(?<=^|\\n)(OK|DIFF|STUB|UNMAPPED|AMBIGUOUS|ERROR)${S}+0x([0-9a-f]+)${S}+(${NS}+)${S}+(${D}+|-)`, 'gu')
const SUM = new RegExp(`functions identical: (${D}+)/(${D}+)[^\\n]*?stubs (${D}+); bytes identical: (${D}+)/(${D}+)`, 'u')
const NONMATCH = new RegExp(`(?<=^|\\n)// FUNCTION: ${NS}+ (0x[0-9a-fA-F]+)${S}*\\n// NONMATCHING`, 'gu')
const CLFLAGS = /(?<=^|\n)\/\/ CLFLAGS: *([^\n]*)(?=\n|$)/u
const WS_SPLIT = new RegExp(`${S}+`, 'u')

// ---------------------------------------------------------------------------------------------- python bits
class ConfigError extends Error {}
class PyError extends Error {
  constructor(name, message) { super(message); this.pyName = name }
  get name() { return this.pyName }
}

const log = (...a) => stderrWrite(a.map((x) => (typeof x === 'string' ? x : pyStr(x))).join(' ') + '\n')
const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000))
const now = () => Date.now() / 1000
const pyRound0 = (x) => Number(fixed(x, 0))                       // round(x) -> int

function get(m, k, d = undefined) {
  if (m instanceof Map) return m.has(k) ? m.get(k) : d
  if (m && typeof m === 'object' && !Array.isArray(m)) return Object.prototype.hasOwnProperty.call(m, k) ? m[k] : d
  throw new PyError('AttributeError', `'${pyType(m)}' object has no attribute 'get'`)
}
function need(m, k) {
  if (m instanceof Map ? m.has(k) : (m && typeof m === 'object' && Object.prototype.hasOwnProperty.call(m, k))) {
    return m instanceof Map ? m.get(k) : m[k]
  }
  if (Array.isArray(m) && typeof k === 'string') throw new PyError('TypeError', 'list indices must be integers or slices, not str')
  throw new PyError('KeyError', pyRepr(String(k)))
}
const has = (m, k) => (m instanceof Map ? m.has(k) : Object.prototype.hasOwnProperty.call(m ?? {}, k))
function pyType(v) {
  if (v === null || v === undefined) return 'NoneType'
  if (Array.isArray(v)) return 'list'
  if (v instanceof Map) return 'dict'
  if (typeof v === 'string') return 'str'
  if (typeof v === 'boolean') return 'bool'
  if (typeof v === 'number' || typeof v === 'bigint') return 'int'
  return 'float'
}
function truthy(v) {
  if (v === null || v === undefined || v === false) return false
  if (typeof v === 'number') return v !== 0
  if (typeof v === 'bigint') return v !== 0n
  if (typeof v === 'string' || Array.isArray(v)) return v.length > 0
  if (v instanceof Map) return v.size > 0
  if (typeof v === 'object' && 'v' in v) return Number(v) !== 0          // PyFloat
  return true
}
function pyLen(v) {
  if (Array.isArray(v)) return v.length
  if (v instanceof Map) return v.size
  if (typeof v === 'string') return [...v].length
  throw new PyError('TypeError', `object of type '${pyType(v)}' has no len()`)
}
const num = (v) => (typeof v === 'object' && v !== null ? Number(v) : v)
function pySum(vals) {
  let s = 0
  for (const v of vals) {
    if (typeof v !== 'number' && typeof v !== 'bigint' && !(v && typeof v === 'object' && 'v' in v)) {
      throw new PyError('TypeError', `unsupported operand type(s) for +: 'int' and '${pyType(v)}'`)
    }
    s += Number(v)
  }
  return s
}
const sortStr = (a) => a.sort(cmp)
// str.ljust for f'{x:{w}}' (width in code points)
const ljust = (s, w) => { const n = [...s].length; return n >= w ? s : s + ' '.repeat(w - n) }

function expanduser(p) {
  if (!p.startsWith('~')) return p
  let i = p.indexOf('/', 1)
  if (i < 0) i = p.length
  let home
  if (i === 1) home = process.env.HOME !== undefined ? process.env.HOME : os.userInfo().homedir
  else {
    const name = p.slice(1, i)
    let info = null
    try { info = os.userInfo() } catch { info = null }
    if (!info || info.username !== name) return p
    home = info.homedir
  }
  home = home.replace(/\/+$/, '')
  return (home + p.slice(i)) || '/'
}
const isabs = (p) => p.startsWith('/')

function sha256File(p) {
  const h = createHash('sha256')
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
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex')

// Relative paths ('/'-separated) of every file under root, in os.walk order with sorted dirs and files
function walkFiles(root) {
  const out = []
  for (const [r, ds, fs_] of walk(root)) {
    ds.sort(cmp)
    for (const f of [...fs_].sort(cmp)) out.push(relpath(join(r, f), root))
  }
  return out
}

// glob.glob(join(d, '*.cpp')): names ending .cpp, hidden names left out, unsorted
function globCpp(d) {
  let names
  try { names = listdir(d) } catch { return [] }
  return names.filter((n) => !n.startsWith('.') && n.endsWith('.cpp')).map((n) => join(d, n))
}

function makedirs(p) { fs.mkdirSync(p, { recursive: true }) }
function rmtree(p) { fs.rmSync(p, { recursive: true }) }
function dumpJson(value, path) { fs.writeFileSync(path, dumps(value, { indent: 1 })) }
function loadJson(p) { return parse(readText(p)) }
function readText(p) { return fs.readFileSync(p, 'utf8') }
// open(p, errors='replace').read(): UTF-8 with replacement, universal newlines
const textOf = (buf) => new TextDecoder('utf-8', { fatal: false }).decode(buf).replace(/\r\n?/g, '\n')

// --------------------------------------------------------------------------------------------------- config
class Project {
  constructor(root, needConfig = true) {
    this.root = abspath(root)
    this.cfg_path = join(this.root, 'decomp.json')
    if (exists(this.cfg_path)) {
      let text
      try { text = readText(this.cfg_path) } catch (e) { throw e }
      try {
        this.cfg = parse(text)
      } catch (e) {
        throw new ConfigError(`decomp.json: ${e.message}`)
      }
    } else if (needConfig) {
      throw new ConfigError(`no decomp.json in ${this.root} (run \`pipeline.py init --game NAME\` first)`)
    } else {
      this.cfg = new PyDict()
    }
    const paths = new Map(Object.entries(DEFAULT_PATHS))
    for (const [k, v] of get(this.cfg, 'paths', new Map())) paths.set(k, v)
    this.p = {}
    for (const [k, v] of paths) this.p[k] = this.abs(v)
  }

  abs(p) { return normpath(join(this.root, expanduser(p))) }

  rel(p) {
    const r = relpath(p, this.root)
    return r === '..' || r.startsWith('../') ? p : r
  }

  report(...parts) { return join(this.p.reports, ...parts) }

  formats() {
    const out = []
    for (let f of get(this.cfg, 'formats', [])) {
      if (typeof f === 'string') f = new PyDict([['module', f], ['trees', ['game']]])
      if (!has(f, 'module')) throw new ConfigError(`formats entry without "module": ${pyReprValue(f)}`)
      const trees = get(f, 'trees', ['game'])
      for (const t of trees) {
        if (t !== 'game' && t !== 'extracted') {
          throw new ConfigError(`format ${pyStr(need(f, 'module'))}: unknown tree ${pyReprValue(t)} (game or extracted)`)
        }
      }
      const r = new PyDict(f)
      r.set('trees', trees)
      out.push(r)
    }
    return out
  }

  binaries(name = null, matchingOnly = false) {
    let out = []
    for (const b of get(this.cfg, 'binaries', [])) {
      if (!has(b, 'file')) throw new ConfigError(`binaries entry without "file": ${pyReprValue(b)}`)
      const file = need(b, 'file')
      const stem = splitext(basename(file))[0]
      const nm = get(b, 'name', stem)
      const low = stem.toLowerCase()
      out.push({
        name: nm, file, stem, matching: truthy(get(b, 'matching', false)),
        binary: join(this.p.game, file),
        decompiled: this.abs(get(b, 'decompiled', `decompiled_${low}`)),
        named: this.abs(get(b, 'named', `decompiled_named_${low}`)),
        reassembled: this.abs(get(b, 'reassembled', `reassembled/${nm}`)),
        src: has(b, 'src') ? this.abs(need(b, 'src')) : join(this.p.src, nm),
        analysis: has(b, 'analysis') ? this.abs(need(b, 'analysis')) : join(this.p.analysis, nm),
        project: has(b, 'ghidra_project') ? this.abs(need(b, 'ghidra_project')) : join(this.p.work, `ghidra_${stem}`),
      })
    }
    if (truthy(name)) {
      out = out.filter((b) => name === b.name || name === b.file || name === b.stem)
      if (!out.length) throw new ConfigError(`no binary ${pyRepr(name)} in decomp.json`)
    }
    if (matchingOnly) out = out.filter((b) => b.matching)
    return out
  }

  toolchain_env() {
    const tc = get(this.cfg, 'toolchain', new Map())
    const env = { ...process.env }
    const setdefault = (k, v) => { if (!(k in env)) env[k] = v }
    if (truthy(get(tc, 'wineprefix'))) setdefault('MSVC_PREFIX', expanduser(get(tc, 'wineprefix')))
    if (truthy(get(tc, 'vs'))) setdefault('MSVC_VS', get(tc, 'vs'))
    if (truthy(get(tc, 'sdk'))) setdefault('MSVC_SDK', get(tc, 'sdk'))
    return env
  }

  libdirs() {
    const tc = get(this.cfg, 'toolchain', new Map())
    const prefix = expanduser(get(tc, 'wineprefix', '~/.wine'))
    let libs = get(tc, 'sdk_lib', [])
    libs = typeof libs === 'string' ? [libs] : libs
    return libs.map((l) => (isabs(expanduser(l)) ? l : join(prefix, 'drive_c', l)))
  }

  // the JavaScript format modules (see the header)
  formats_js() {
    const set = get(get(this.cfg, 'paths', new Map()), 'formats_js')
    if (set !== undefined && set !== null) return this.abs(set)
    const f = this.p.formats
    const cand = join(dirname(f), 'js', basename(f))
    return isdir(cand) ? cand : f
  }
}

// a tool: [NODE, <script>.mjs, ...] or any other command; cwd = the project; its stdout goes to our stderr
function logCmd(cmd) {
  const n = cmd[0] === NODE ? 6 : 7                 // python shows [python, -I, script, 4 args]: the same args here
  log('+', cmd.slice(0, n).map(String).join(' ') + (cmd.length > n ? ' ...' : ''))
}
function spawnError(cmd, r) {
  if (r.error && r.error.code === 'ENOENT') {
    throw new PyError('FileNotFoundError', `[Errno 2] No such file or directory: ${pyRepr(String(cmd[0]))}`)
  }
  if (r.error) throw r.error
}
function run(cmd, proj, { env = null, capture = false, cwd = null } = {}) {
  logCmd(cmd)
  const opts = { cwd: cwd || proj.root, env: env || process.env, maxBuffer: 1 << 30 }
  if (capture) {
    const r = spawnSync(cmd[0], cmd.slice(1), { ...opts, stdio: ['inherit', 'pipe', 'pipe'] })
    spawnError(cmd, r)
    return { returncode: r.status ?? 1, stdout: textOf(r.stdout), stderr: textOf(r.stderr) }
  }
  const r = spawnSync(cmd[0], cmd.slice(1), { ...opts, stdio: ['inherit', 2, 'inherit'] })
  spawnError(cmd, r)
  return { returncode: r.status ?? 1 }
}
// subprocess.run without the '+' line (stdout to /dev/null or captured)
function runQuiet(cmd, { cwd, env, stdout = 'ignore' }) {
  const r = spawnSync(cmd[0], cmd.slice(1), { cwd, env, stdio: ['inherit', stdout, 'inherit'], maxBuffer: 1 << 30 })
  spawnError(cmd, r)
  return { returncode: r.status ?? 1 }
}
// async capture (thread pools of decode and match)
function runCapture(cmd, { cwd, env }) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd[0], cmd.slice(1), { cwd, env, stdio: ['inherit', 'pipe', 'pipe'] })
    const o = [], e = []
    p.stdout.on('data', (b) => o.push(b))
    p.stderr.on('data', (b) => e.push(b))
    p.on('error', (err) => {
      if (err.code === 'ENOENT') reject(new PyError('FileNotFoundError', `[Errno 2] No such file or directory: ${pyRepr(String(cmd[0]))}`))
      else reject(err)
    })
    p.on('close', (code) => resolve({ returncode: code ?? 1, stdout: textOf(Buffer.concat(o)), stderr: textOf(Buffer.concat(e)) }))
  })
}
// ThreadPoolExecutor(n).map(fn, items): results in input order; the first error (in input order) is raised
// after every item finished
async function pool(items, n, fn) {
  const res = new Array(items.length)
  const errs = new Array(items.length)
  let next = 0
  const worker = async () => {
    while (next < items.length) {
      const i = next++
      try { res[i] = await fn(items[i]) } catch (e) { errs[i] = e }
    }
  }
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker))
  for (let i = 0; i < items.length; i++) if (errs[i]) throw errs[i]
  return res
}
const tool = (name) => join(HERE, name)

const modules = new Map()
async function loadFormat(formatsDir, name) {
  const path = join(formatsDir, `fmt_${name}.mjs`)
  if (!exists(path)) throw new ConfigError(`format module not found: ${path}`)
  if (!modules.has(path)) modules.set(path, await import(pathToFileURL(path).href))
  return modules.get(path)
}

// ----------------------------------------------------------------------------------------------------- init
async function cmd_init(proj, a) {
  if (exists(proj.cfg_path) && !a.force) throw new ConfigError('decomp.json exists (use --force to overwrite)')
  const game = proj.p.game
  const binaries = []
  if (isdir(game)) {
    for (const rel of walkFiles(game)) {
      const p = join(game, rel)
      if (['.exe', '.dll', '.asi', '.flt', '.drv'].includes(splitext(rel)[1].toLowerCase()) && read2(p) === 'MZ') {
        const stem = splitext(basename(rel))[0]
        binaries.push({ name: stem, file: rel, decompiled: `decompiled_${stem.toLowerCase()}`,
          named: `decompiled_named_${stem.toLowerCase()}`, reassembled: `reassembled/${stem}`, matching: false })
      }
    }
  }
  const cfg = { game: a.game, paths: { ...DEFAULT_PATHS }, archives: [], formats: [], containers: [], binaries,
    toolchain: { compiler: 'msvc', version: '', flags: '/O2', wineprefix: '~/.wine-msvc', sdk_lib: [] },
    run: { wineprefix: '~/.wine', exe: binaries.find((x) => x.file.toLowerCase().endsWith('.exe'))?.file ?? '' } }
  makedirs(proj.root)
  dumpJson(cfg, proj.cfg_path)
  const gi = join(proj.root, '.gitignore')
  const have = exists(gi) ? splitlines(textOf(fs.readFileSync(gi))) : []
  const add = GITIGNORE.filter((l) => !have.includes(l))
  if (add.length) fs.appendFileSync(gi, (have.length && have[have.length - 1] !== '' ? '\n' : '') + add.join('\n') + '\n')
  for (const k of ['formats', 'reports', 'build', 'work']) makedirs(proj.p[k])
  makedirs(dirname(proj.p.manifest))
  return [true, { command: 'init', config: 'decomp.json', binaries: binaries.map((b) => b.file), gitignore_added: add,
    next: 'fill in archives/formats/containers/toolchain/run, then intake' }]
}
function read2(p) {
  const fd = fs.openSync(p, 'r')
  try {
    const b = Buffer.alloc(2)
    const n = fs.readSync(fd, b, 0, 2, 0)
    return b.subarray(0, n).toString('latin1')
  } finally { fs.closeSync(fd) }
}
// str.splitlines() (after universal-newline reading)
function splitlines(s) {
  const out = s.split(/\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]/)
  if (out.length && out[out.length - 1] === '') out.pop()
  return out
}

// --------------------------------------------------------------------------------------------------- intake
// intake.py's manifest() and game_folder(), as pipeline.py imports them
const INSTALLER_ONLY = new Set(['__redist', 'commonappdata', 'tmp', '{tmp}', 'userappdata', 'userdocs', 'sys', 'win'])
function manifest(root) {
  if (!isdir(root)) throw new PyError('SystemExit', `not a directory: ${root}`)
  const files = new Map()
  for (const [r, , fs_] of walk(root)) {
    for (const f of fs_) {
      const p = join(r, f)
      if (islink(p)) continue
      files.set(relpath(p, root), new PyDict([['size', getsize(p)], ['sha256', sha256File(p)]]))
    }
  }
  const sorted = new PyDict([...files.entries()].sort((x, y) => cmp(x[0], y[0])))
  return new PyDict([['root_name', basename(abspath(root))], ['files', sorted]])
}
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
    .map((e) => e + '/').sort(cmp)
  return best + (extra.length ? `  (installer-only, not part of the game tree: ${extra.join(' ')})` : '')
}

async function cmd_intake(proj, a) {
  const game = proj.p.game
  if (isdir(game) && listdir(game).length && !a.force) {
    throw new ConfigError(`${proj.rel(game)} is not empty (use --force to replace it)`)
  }
  const src = abspath(a.installer)
  let folder, how
  if (isdir(src)) {
    folder = src
    how = 'installed folder'
  } else {
    const inst = join(proj.p.work, 'installer')
    if (isdir(inst)) rmtree(inst)
    const cmd = [NODE, tool('intake.mjs'), 'extract', src, inst, ...(a.language ? ['--language', a.language] : [])]
    if (run(cmd, proj).returncode) return [false, { command: 'intake', error: 'extraction failed (see the log above)' }]
    folder = gameFolder(inst).split('  (')[0]
    how = 'installer'
  }
  if (isdir(game)) rmtree(game)
  const skip = (n) => isdir(join(folder, n)) && (INSTALLER_ONLY.has(n.toLowerCase()) || (n === 'app' && how === 'installer'))
  copytree(folder, game, (d, n) => d === folder && skip(n))
  log(`game folder: ${proj.rel(game)} (${walkFiles(game).length} files, from the ${how})`)
  const hp = run([NODE, tool('intake.mjs'), 'verify-hashdb', game], proj, { capture: true })
  log(hp.stdout + hp.stderr)
  const m = manifest(game)
  const res = { command: 'intake', source: how, game: proj.rel(game), files: m.get('files').size,
    hashdb: { 0: 'PASS', 1: 'FAIL', 2: 'no goggame-*.hashdb' }[hp.returncode] ?? hp.returncode }
  makedirs(proj.p.reports)
  const pc = run([NODE, tool('protection_check.mjs'), game, '--json', proj.report('protection.json')], proj, { capture: true })
  if (pc.stderr) log(pc.stderr.replace(/\n+$/, ''))
  res.protection = { 0: 'clean', 1: 'FOUND: copy protection or packer (reports/protection.json); stop' }[pc.returncode] ?? 'error'
  const man = proj.p.manifest
  let manOk
  if (exists(man)) {
    const tmp = join(proj.p.build, 'work', 'manifest_intake.json')
    makedirs(dirname(tmp))
    dumpJson(m, tmp)
    const cp = run([NODE, tool('intake.mjs'), 'compare', tmp, man], proj, { capture: true })
    log(cp.stdout)
    res.manifest = { path: proj.rel(man), compared: cp.returncode === 0 ? 'PASS' : 'FAIL' }
    manOk = cp.returncode === 0
  } else {
    makedirs(dirname(man))
    dumpJson(m, man)
    res.manifest = { path: proj.rel(man), written: true }
    manOk = true
  }
  const ok = manOk && (hp.returncode === 0 || (hp.returncode === 2 && 'compared' in res.manifest)) && pc.returncode === 0
  dumpJson({ ...res, ok }, proj.report('intake.json'))
  return [ok, res]
}
// shutil.copytree(src, dst, ignore=..., symlinks=True): symlinks copied as links, file times kept
function copytree(src, dst, ignore = null) {
  makedirs(dst)
  for (const n of listdir(src)) {
    if (ignore && ignore(src, n)) continue
    const s = join(src, n), d = join(dst, n)
    const st = fs.lstatSync(s)
    if (st.isSymbolicLink()) fs.symlinkSync(fs.readlinkSync(s), d)
    else if (st.isDirectory()) copytree(s, d)
    else {
      fs.copyFileSync(s, d)
      fs.chmodSync(d, st.mode & 0o7777)
      fs.utimesSync(d, st.atime, st.mtime)
    }
  }
  const st = fs.statSync(src)
  fs.chmodSync(dst, st.mode & 0o7777)
  fs.utimesSync(dst, st.atime, st.mtime)
}

// ------------------------------------------------------------------------------------------------ inventory
async function moduleExts(proj) {
  const out = new Map()
  for (const f of proj.formats()) {
    let mod
    try { mod = await loadFormat(proj.formats_js(), need(f, 'module')) } catch (e) {
      if (e instanceof ConfigError) continue
      throw e
    }
    for (const e of mod.EXTS) {
      const k = e.toLowerCase()
      if (!out.has(k)) out.set(k, [])
      out.get(k).push(need(f, 'module'))
    }
  }
  return out
}

async function inventoryGate(proj, inv) {
  const exts = await moduleExts(proj)
  const bins = new Set(proj.binaries().map((b) => b.file.toLowerCase().replaceAll('\\', '/')))
  return get(inv, 'unclassified', []).filter((p) => !exts.has(splitext(p)[1].toLowerCase()) &&
    !bins.has(p.toLowerCase().replaceAll('\\', '/')))
}

async function cmd_inventory(proj, a) {
  const out = proj.report('inventory.json')
  makedirs(dirname(out))
  const p = run([NODE, tool('inventory.mjs'), proj.p.game, '--json', out], proj)
  if (p.returncode || !exists(out)) return [false, { command: 'inventory', error: 'inventory.py failed' }]
  const inv = loadJson(out)
  const unexplained = await inventoryGate(proj, inv)
  const found = sortStr(get(inv, 'archives', []).map((x) => need(x, 'path')))
  const conf = get(proj.cfg, 'archives', [])
  return [unexplained.length === 0, { command: 'inventory', report: proj.rel(out), files: pyLen(need(inv, 'files')),
    unclassified: pyLen(get(inv, 'unclassified', [])), unexplained, zip_archives_found: found,
    archives_not_configured: found.filter((x) => !conf.includes(x)) }]
}

// ------------------------------------------------------------------------------------------------- archives
function safeRel(name) {
  const parts = name.replaceAll('\\', '/').split('/')
  if (name.startsWith('/') || parts.includes('..') || parts[0].includes(':')) {
    throw new PyError('ValueError', `unsafe member path: ${pyRepr(name)}`)
  }
  const keep = parts.filter(Boolean)
  if (!keep.length) throw new PyError('TypeError', 'join() missing 1 required positional argument: \'a\'')
  return join(...keep)
}

async function cmd_archives(proj, a) {
  const out = proj.p.extracted
  const report = new PyDict(), counts = new PyDict()
  for (const arc of get(proj.cfg, 'archives', [])) {
    const base = join(out, arc)
    if (isdir(base) && listdir(base).length) {
      if (!a.force) throw new ConfigError(`${proj.rel(base)} exists (use --force to extract again)`)
      rmtree(base)
    }
    const z = new ZipFile(join(proj.p.game, arc))
    const names = z.infolist().map((i) => i.filename)
    if (new Set(names).size !== names.length) throw new PyError('ValueError', `${arc}: duplicate member names`)
    const members = new PyDict()
    for (const i of z.infolist()) {
      const rel = safeRel(i.filename)
      if (i.is_dir()) {
        makedirs(join(base, rel))
        continue
      }
      const data = z.read(i)
      const dst = join(base, rel)
      makedirs(dirname(dst))
      fs.writeFileSync(dst, data)
      members.set(i.filename, new PyDict([['size', data.length], ['sha256', sha256(data)]]))
    }
    report.set(arc, members)
    counts.set(arc, members.size)
    log(`${arc}: ${members.size} files`)
  }
  makedirs(out)
  dumpJson(report, join(out, MEMBERS_JSON))
  return [true, { command: 'archives', out: proj.rel(out), members: counts, total: [...counts.values()].reduce((x, y) => x + y, 0) }]
}

// --------------------------------------------------------------------------------------------------- decode
const treeRoot = (proj, tree) => (tree === 'game' ? proj.p.game : proj.p.extracted)

async function cmd_decode(proj, a) {
  const jobs = []
  for (const f of proj.formats()) {
    if (truthy(a.module) && need(f, 'module') !== a.module) continue
    for (const t of need(f, 'trees')) jobs.push([need(f, 'module'), t])
  }
  if (truthy(a.module) && !jobs.length) throw new ConfigError(`no format module ${pyRepr(a.module)} in decomp.json`)
  const fdir = proj.formats_js()
  const one = async ([m, t]) => {
    const rep = proj.report(t)
    const cmd = [NODE, tool('verify.mjs'), m, '--src', treeRoot(proj, t), '--formats-dir', fdir, '--out',
      proj.p.decoded, '--report', rep]
    logCmd(cmd)
    const p = await runCapture(cmd, { cwd: proj.root, env: process.env })
    log(`[${t}/${m}] exit ${p.returncode}\n` + [...(p.stdout + p.stderr)].slice(-1500).join(''))
    const r = join(rep, `${m}.json`)
    const d = exists(r) ? loadJson(r) : new PyDict()
    return { module: m, tree: t, files: get(d, 'files', 0), passed: get(d, 'passed', 0), failed: get(d, 'failed', null),
      opaque_bytes: get(d, 'opaque_bytes', null), seconds: get(d, 'seconds', null), ok: p.returncode === 0 }
  }
  const t0 = now()
  const rows = await pool(jobs, Math.max(1, a.jobs), one)
  const [gateOk, comp] = completeness(proj)
  const sub = {}
  for (const k of ['files_seen', 'ok', 'out_of_scope', 'problems', 'unexpected_nested_signatures', 'opaque_bytes', 'bytes_ok']) sub[k] = comp[k]
  const res = { command: 'decode', modules: rows, seconds: pyRound0(now() - t0), completeness: sub }
  return [rows.every((r) => r.ok) && gateOk, res]
}

// The phase-3 gate (see pipeline.py)
function completeness(proj, write = true) {
  const trees = new Map([['game', proj.p.game]])
  if (isdir(proj.p.extracted)) trees.set('extracted', proj.p.extracted)
  const listed = new Map()                      // `${tree}\0${rel}` -> [[module, entry]]
  const missingReports = []
  for (const f of proj.formats()) {
    for (const t of need(f, 'trees')) {
      const rp = proj.report(t, `${need(f, 'module')}.json`)
      if (!exists(rp)) {
        missingReports.push(`${t}/${need(f, 'module')}.json`)
        continue
      }
      for (const e of need(loadJson(rp), 'per_file')) {
        const k = `${t}\0${need(e, 'file')}`
        if (!listed.has(k)) listed.set(k, [])
        listed.get(k).push([`${t}/${need(f, 'module')}`, e])
      }
    }
  }
  const bins = new Set(proj.binaries().map((b) => b.file.replaceAll('\\', '/').toLowerCase()))
  const containers = new Set(get(proj.cfg, 'containers', []))
  const rows = [], problems = [], nested = [], nestedBin = [], seen = new Set()
  for (const r of missingReports) problems.push({ report: r, problem: 'report missing (run decode)' })
  for (const [tree, root] of trees) {
    if (!isdir(root)) {
      problems.push({ tree, problem: `folder missing: ${proj.rel(root)}` })
      continue
    }
    for (const rel of walkFiles(root)) {
      if (tree === 'extracted' && rel === MEMBERS_JSON) continue
      seen.add(`${tree}\0${rel}`)
      const data = fs.readFileSync(join(root, rel))
      const sha = sha256(data)
      const isBin = tree === 'game' && bins.has(rel.toLowerCase())
      if (!containers.has(basename(rel)) && !containers.has(rel)) {
        for (const [sig, kind] of SIGS) {
          let pos = 0
          for (;;) {                                 // re.finditer: the first match away from offset 0
            const i = data.indexOf(sig, pos)
            if (i < 0) break
            if (i !== 0) {
              (isBin ? nestedBin : nested).push({ tree, file: rel, kind, offset: i })
              break
            }
            pos = i + sig.length
          }
        }
      }
      if (isBin) {
        rows.push({ tree, file: rel, status: 'out_of_scope' })
        continue
      }
      const ents = listed.get(`${tree}\0${rel}`) ?? []
      if (!ents.length) problems.push({ tree, file: rel, problem: 'no module report lists it' })
      else if (ents.length > 1) {
        problems.push({ tree, file: rel, problem: 'listed by several modules: ' + ents.map(([m]) => m).join(', ') })
      } else {
        const [mod, ent] = ents[0]
        if (!truthy(need(ent, 'ok'))) problems.push({ tree, file: rel, problem: `failed in ${mod}` })
        else if (need(ent, 'sha256') !== sha) problems.push({ tree, file: rel, problem: `stale report ${mod} (sha256 changed)` })
        else rows.push({ tree, file: rel, status: 'ok', module: mod, opaque: need(ent, 'opaque'), bytes: need(ent, 'bytes') })
      }
    }
  }
  const keys = [...listed.keys()].map((k) => k.split('\0')).sort((x, y) => cmp(x[0], y[0]) || cmp(x[1], y[1]))
  for (const [t, rel] of keys) {
    if (!seen.has(`${t}\0${rel}`) && trees.has(t)) {
      problems.push({ tree: t, file: rel, problem: 'in a report but no longer in the tree: ' +
        listed.get(`${t}\0${rel}`).map(([m]) => m).join(', ') })
    }
  }
  const ok = rows.filter((r) => r.status === 'ok')
  const perModule = new PyDict()
  for (const r of ok) {
    if (!perModule.has(r.module)) perModule.set(r.module, { files: 0, bytes: 0, opaque: 0 })
    const m = perModule.get(r.module)
    m.files += 1
    m.bytes += num(r.bytes)
    m.opaque += num(r.opaque)
  }
  const summary = {
    files_seen: rows.length + problems.filter((p) => 'file' in p && !p.problem.includes('no longer')).length,
    ok: ok.length, out_of_scope: rows.filter((r) => r.status === 'out_of_scope').map((r) => r.file),
    problems, unexpected_nested_signatures: nested, nested_signatures_in_binaries: nestedBin,
    opaque_bytes: pySum(ok.map((r) => r.opaque)), bytes_ok: pySum(ok.map((r) => r.bytes)), per_module: perModule,
  }
  const gate = !problems.length && !nested.length
  if (write) {
    makedirs(proj.p.reports)
    dumpJson({ ...summary, gate }, proj.report('completeness.json'))
  }
  return [gate, summary]
}

async function cmd_completeness(proj, a) {
  const [ok, s] = completeness(proj)
  return [ok, { command: 'completeness', ...s }]
}

// ---------------------------------------------------------------------------------------------- phases 4, 5
function orphanLine(logPath) {
  let last = null
  if (exists(logPath)) {
    for (const line of textOf(fs.readFileSync(logPath)).split('\n')) {
      const m = /ORPHANS round \p{Nd}+: orphan_instructions=(\p{Nd}+)/u.exec(line)
      if (m) last = Number(pyInt(m[1]))
    }
  }
  return last
}

function nfunctions(idx) {
  if (idx === null || idx === undefined) return null
  return pyLen(idx instanceof Map && idx.has('functions') ? idx.get('functions') : idx)
}

// [real failures, names already present at their address] of an apply_names.sh name_failures.txt
function nameFailures(path) {
  if (!exists(path)) return [null, 0]
  const lines = textOf(fs.readFileSync(path)).split(/(?<=\n)/).filter((l) => l.replace(new RegExp(`^${S}+|${S}+$`, 'gu'), ''))
  const same = lines.filter((l) => l.includes('already exists at this address'))
  return [lines.length - same.length, same.length]
}

async function cmd_recover(proj, a) {
  const rows = []
  let ok = true
  const env = a.force ? { ...process.env, FORCE: '1' } : null
  for (const b of proj.binaries(a.binary)) {
    const t0 = now()
    const p = run(['sh', join(SK, 'ghidra', 'run_recovery.sh'), b.binary, b.decompiled, b.project], proj, { env })
    const row = { binary: b.file, out: proj.rel(b.decompiled), recovery_exit: p.returncode }
    if (p.returncode === 0) {
      row.orphan_instructions = orphanLine(join(b.decompiled, 'recovery.log'))
      const idx = join(b.decompiled, 'index.json')
      row.functions = exists(idx) ? nfunctions(loadJson(idx)) : null
      const c = run([NODE, tool('code_coverage_check.mjs'), b.binary, b.decompiled], proj)
      row.coverage_check_exit = c.returncode
    }
    row.seconds = pyRound0(now() - t0)
    row.ok = p.returncode === 0 && row.orphan_instructions === 0 && row.coverage_check_exit === 0
    ok = ok && row.ok
    rows.push(row)
  }
  return [ok, { command: 'recover', binaries: rows }]
}

async function cmd_features(proj, a) {
  const rows = []
  for (const b of proj.binaries(a.binary)) {
    makedirs(b.analysis)
    const p = run([NODE, tool('build_features.mjs'), b.decompiled, b.binary, b.analysis, ...(a.force ? ['--force'] : [])], proj)
    const meta = join(b.analysis, 'features_meta.json')
    rows.push({ binary: b.file, out: proj.rel(b.analysis), ok: p.returncode === 0,
      counts: p.returncode === 0 && exists(meta) ? get(loadJson(meta), 'counts', null) : null })
  }
  return [rows.every((r) => r.ok), { command: 'features', binaries: rows }]
}

async function cmd_names(proj, a) {
  const rows = []
  for (const b of proj.binaries(a.binary)) {
    const names = join(b.analysis, 'names_apply.json')
    if (!exists(names)) {
      rows.push({ binary: b.file, ok: false, error: `${proj.rel(names)} missing (phase 5 naming)` })
      continue
    }
    const p = run(['sh', join(SK, 'ghidra', 'apply_names.sh'), b.binary, b.project, names, b.named], proj)
    const [nf, same] = nameFailures(join(b.named, 'name_failures.txt'))
    rows.push({ binary: b.file, out: proj.rel(b.named), exit: p.returncode, name_failures: nf, already_present: same,
      ok: (p.returncode === 0 || p.returncode === 3) && nf === 0 })
  }
  return [rows.every((r) => r.ok), { command: 'names', binaries: rows }]
}

// ------------------------------------------------------------------------------------------------ phase 5b
async function cmd_reassemble(proj, a) {
  const rows = []
  const work = join(proj.p.build, 'work', 'reassemble')
  makedirs(work)
  for (const b of proj.binaries(a.binary)) {
    const t0 = now()
    const row = { binary: b.file, text: proj.rel(b.reassembled) }
    const have = exists(join(b.reassembled, 'layout.json'))
    if (have && a.split && !a.force) {
      throw new ConfigError(`${proj.rel(b.reassembled)} exists: --split would overwrite it (add --force)`)
    }
    if (!have || a.split) {
      const names = join(b.analysis, 'names_apply.json')
      const p = run([NODE, tool('reassemble.mjs'), 'split', b.binary, b.decompiled, b.reassembled,
        ...(exists(names) ? ['--names', names] : [])], proj)
      row.split = p.returncode === 0
      if (p.returncode) {
        rows.push({ ...row, ok: false })
        continue
      }
    }
    const out = join(work, b.file)
    makedirs(dirname(out))                                       // binaries can live in subfolders
    const cache = a.cache ? ['--cache', join(work, `asm_cache_${b.name}.json`)] : []
    const p = run([NODE, tool('reassemble.mjs'), 'build', b.reassembled, out, ...cache], proj)
    const built = p.returncode === 0 && exists(out) ? sha256File(out) : null
    const orig = exists(b.binary) ? sha256File(b.binary) : null
    const lay = loadJson(join(b.reassembled, 'layout.json'))
    Object.assign(row, { built_sha256: built, original_sha256: orig, identical: Boolean(built) && built === orig,
      cached: Boolean(a.cache), stats: get(lay, 'stats', null), seconds: pyRound0(now() - t0) })
    row.ok = row.identical
    makedirs(proj.report('reassemble'))
    dumpJson(row, proj.report('reassemble', `${b.name}.json`))
    rows.push(row)
  }
  return [rows.every((r) => r.ok), { command: 'reassemble', binaries: rows }]
}

// --------------------------------------------------------------------------------------------------- phase 6
async function cmd_skeleton(proj, a) {
  const rows = []
  const bl = truthy(a.binary) ? proj.binaries(a.binary) : proj.binaries(null, true)
  for (const b of bl) {
    if (globCpp(b.src).length && !a.force) {
      throw new ConfigError(`${proj.rel(b.src)} already holds units (use --force to overwrite them)`)
    }
    const nf = join(b.analysis, 'names_final.json')
    const p = run([NODE, tool('phase6_skeleton.mjs'), nf, b.src, '--module', b.name, '--decompiled', b.named], proj)
    rows.push({ binary: b.file, out: proj.rel(b.src), ok: p.returncode === 0, units: globCpp(b.src).length })
  }
  return [rows.every((r) => r.ok), { command: 'skeleton', binaries: rows }]
}

const cpSliceEnd = (s, n) => { const a = [...s]; return a.slice(Math.max(0, a.length - n)).join('') }
const toInt = (s) => Number(pyInt(s))

// Compile one unit with the original compiler and compare its annotated functions
async function matchUnit(proj, b, unitPath, objDir, pe, env, defaultFlags, showStubs) {
  const name = [...basename(unitPath)].slice(0, -4).join('')
  const srcdir = dirname(unitPath)
  const obj = join(objDir, name + '.obj')
  if (exists(obj)) fs.unlinkSync(obj)
  const text = textOf(fs.readFileSync(unitPath))
  const m = CLFLAGS.exec(text)
  const flags = (m && m[1]) || env.CLFLAGS || defaultFlags
  const rel = relpath(objDir, srcdir).replaceAll('/', '\\')
  const cmd = ['sh', join(SK, 'msvc.sh'), 'cl', '/nologo', '/c', ...flags.split(WS_SPLIT).filter(Boolean),
    `/Fo${rel}\\${name}.obj`, basename(unitPath)]
  const c = await runCapture(cmd, { cwd: srcdir, env })
  let out = c.stdout + c.stderr
  if (c.returncode || !exists(obj)) {
    return { unit: name, compiled: false, error: cpSliceEnd(out + `COMPILE FAILED: ${name}\n`, 600) }
  }
  let repsrc = unitPath
  if (showStubs) {
    repsrc = join(objDir, name + '.withstubs.cpp')
    fs.writeFileSync(repsrc, text.replaceAll('// STUB: ', '// FUNCTION: '))
  }
  const r = await runCapture([NODE, tool('objcmp.mjs'), 'report', '--pe', pe, '--src', repsrc, '--obj', obj,
    '--module', b.name, '--functions', join(b.named, 'index.json'), '-v'], { cwd: proj.root, env })
  out += r.stdout + r.stderr
  const tagged = new Set([...text.matchAll(NONMATCH)].map((x) => parseInt(x[1], 16)))
  const rows = [...out.matchAll(LINE)].map((x) => ({ status: x[1], addr: '0x' + x[2].replace(/^0+/, ''), ratio: x[3], size: x[4] }))
  for (const x of rows) {
    if (x.status === 'DIFF') {
      if (x.addr === '0x') throw new PyError('ValueError', "invalid literal for int() with base 16: '0x'")
      if (tagged.has(parseInt(x.addr, 16))) x.status = 'NONMATCHING'
    }
  }
  const s = SUM.exec(out)
  const [ident, annotated, stubs, bok, btot] = s ? s.slice(1, 6).map(toInt) : [0, 0, 0, 0, 0]
  return { unit: name, compiled: true, identical: ident, annotated, stubs, bytes_identical: bok, bytes_total: btot,
    functions: rows }
}

async function matchBinary(proj, b, units = null, jobs = 4, pe = null) {
  const env = proj.toolchain_env()
  pe = pe || env.MATCH_PE || b.binary
  let files = globCpp(b.src).sort(cmp)
  if (units) files = files.filter((f) => units.has([...basename(f)].slice(0, -4).join('')))
  const objDir = join(proj.p.build, 'obj', b.name)
  makedirs(objDir)
  const flags = get(get(proj.cfg, 'toolchain', new Map()), 'flags', '/O2')
  const show = (env.SHOW_STUBS ?? '0') === '1'
  log(`match ${b.name}: ${files.length} units, compared with ${proj.rel(pe)}`)
  const res = await pool(files, Math.max(1, jobs), (f) => matchUnit(proj, b, f, objDir, pe, env, flags, show))
  const fns = (st) => res.reduce((n, r) => n + (r.functions ?? []).filter((f) => f.status === st).length, 0)
  const tot = { units: res.length, compile_failed: res.filter((r) => !r.compiled).length,
    functions_identical: res.reduce((n, r) => n + (r.identical ?? 0), 0),
    functions_stub: res.reduce((n, r) => n + (r.stubs ?? 0), 0),
    functions_diff: fns('DIFF'), functions_nonmatching: fns('NONMATCHING'),
    bytes_identical: res.reduce((n, r) => n + (r.bytes_identical ?? 0), 0) }
  makedirs(proj.report('match'))
  const status = { totals: tot, units: res }
  if (!units) dumpJson(status, proj.report('match', `${b.name}.json`))
  for (const r of res) if (!r.compiled) log('COMPILE FAILED', r.unit)
  return [status, objDir]
}

async function cmd_match(proj, a) {
  const bl = truthy(a.binary) ? proj.binaries(a.binary) : proj.binaries(null, true)
  const units = truthy(a.units) ? new Set(a.units.split(',')) : null
  const out = new PyDict()
  let ok = true
  const t0 = now()
  for (const b of bl) {
    const [st] = await matchBinary(proj, b, units, a.jobs)
    out.set(b.name, st.totals)
    ok = ok && st.totals.functions_diff === 0 && st.totals.compile_failed === 0
  }
  return [ok, { command: 'match', binaries: out, seconds: pyRound0(now() - t0),
    status_files: !units ? bl.map((b) => proj.rel(proj.report('match', `${b.name}.json`))) : [] }]
}

// ----------------------------------------------------------------------------------------------------- build
// Decoded entries of a module: directories decoded/<module>/<path of the file> (see pipeline.py)
function entries(decoded, module, exts) {
  const top = join(decoded, module)
  const out = []
  for (const [r, ds] of walk(top)) {
    const keep = []
    for (const d of ds) {
      const full = join(r, d)
      if (exts.has(splitext(d)[1].toLowerCase()) && listdir(full).some((x) => isfile(join(full, x)))) {
        out.push(relpath(full, top))
      } else keep.push(d)
    }
    ds.splice(0, ds.length, ...keep)
  }
  return out.sort(cmp)
}

async function encodeOne([formatsDir, module, src, dst]) {
  const data = (await loadFormat(formatsDir, module)).encode_from_dir(src)
  makedirs(dirname(dst))
  fs.writeFileSync(dst, data)
  return data.length
}

// ProcessPoolExecutor(jobs).map(encode_one, work) on worker threads; the first error (in input order) is raised
// after every item finished
function encodeAll(work, jobs) {
  return new Promise((resolve, reject) => {
    const res = new Array(work.length)
    let next = 0, done = 0, failed = false
    const n = Math.min(jobs, work.length)
    if (!n) return resolve(res)
    const workers = []
    const finish = () => {
      for (const w of workers) w.terminate()
      const e = res.find((r) => r && r.error)
      if (e) reject(e.error[0] === 'ConfigError' ? new ConfigError(e.error[1]) : new PyError(e.error[0], e.error[1]))
      else resolve(res.map((r) => r.n))
    }
    const feed = (w) => { if (next < work.length) { const i = next++; w.postMessage({ i, item: work[i] }) } }
    for (let k = 0; k < n; k++) {
      const w = new Worker(SELF)
      workers.push(w)
      w.on('message', (m) => {
        res[m.i] = m
        if (++done === work.length) finish()
        else feed(w)
      })
      w.on('error', (e) => { if (!failed) { failed = true; for (const x of workers) x.terminate(); reject(e) } })
      feed(w)
    }
  })
}

async function buildData(proj, out, jobs) {
  const fdir = proj.formats_js(), dec = proj.p.decoded
  const cfgArchives = new Set(get(proj.cfg, 'archives', []))
  const plan = [], archives = []
  for (const f of proj.formats()) {
    const exts = new Set((await loadFormat(fdir, need(f, 'module'))).EXTS.map((e) => e.toLowerCase()))
    for (const rel of entries(dec, need(f, 'module'), exts)) (cfgArchives.has(rel) ? archives : plan).push([need(f, 'module'), rel])
  }
  const membersDir = new Map(proj.formats().map((f) => [need(f, 'module'), get(f, 'members', 'members')]))
  const stage = fs.mkdtempSync(join(proj.p.build, 'work', 'archives_'))
  for (const [m, arc] of archives) fs.cpSync(join(dec, m, arc), join(stage, arc), { recursive: true, preserveTimestamps: true, dereference: true })
  const work = []
  for (const [m, rel] of plan) {
    const am = archives.find(([, a_]) => rel.startsWith(a_ + '/')) ?? null
    const dst = am ? join(stage, am[1], membersDir.get(am[0]), rel.slice(am[1].length + 1)) : join(out, rel)
    work.push([fdir, m, join(dec, m, rel), dst])
  }
  let t = now()
  const done = await encodeAll(work, Math.max(1, jobs))
  log(`data: ${done.length} files from ${proj.rel(dec)}/ (${fixed(now() - t, 0)} s)`)
  t = now()
  for (const [m, arc] of archives) {
    const data = (await loadFormat(fdir, m)).encode_from_dir(join(stage, arc))
    makedirs(dirname(join(out, arc)) || out)
    fs.writeFileSync(join(out, arc), data)
  }
  log(`data: ${archives.length} archives packed (${fixed(now() - t, 0)} s)`)
  rmtree(stage)
  return done.length + archives.length
}

function reassembleTo(proj, srcDir, dst, cache = null) {
  makedirs(dirname(dst))
  const p = run([NODE, tool('reassemble.mjs'), 'build', srcDir, dst, ...(cache ? ['--cache', cache] : [])], proj)
  return p.returncode === 0 && exists(dst)
}

// A matching binary: every unit compiled, link.exe through relink.mjs (see pipeline.py build_exe)
async function buildExe(proj, b, out, mode, work, jobs, ref = null, cache = null) {
  ref = ref || b.binary
  const [st, objDir] = await matchBinary(proj, b, null, jobs, ref)
  if (st.totals.compile_failed) {
    log(`compile: ${st.totals.compile_failed} units failed`)
    return null
  }
  log(`compile: every unit compiled (${st.totals.functions_identical} functions identical)`)
  const env = proj.toolchain_env()
  const R = (p) => relpath(p, proj.root)
  const symbols = join(work, `symbols_${b.name}.json`)
  let cmd = [NODE, tool('hybrid_link.mjs'), 'map', '--pe', R(ref), '--src', R(b.src), '--obj', R(objDir),
    '--module', b.name, '--functions', R(join(b.named, 'index.json')),
    '--instructions', R(join(b.decompiled, 'instructions.tsv')), '--out', R(symbols), ...(mode === 'source' ? ['--all'] : [])]
  if (run(cmd, proj, { env }).returncode) {
    log('map: FAILED (unresolved symbols or layout conflicts; see above)')
    return null
  }
  const ld = join(work, `relink_${b.name}`)
  cmd = [NODE, tool('relink.mjs'), 'prepare', R(b.reassembled), R(symbols), R(b.decompiled), R(ld)]
  for (const l of proj.libdirs()) cmd.push('--libdir', l)
  cmd.push(...(mode === 'source' ? ['--free'] : []), ...(cache ? ['--cache', R(cache)] : []))
  if (runQuiet(cmd, { cwd: proj.root, env }).returncode) {
    log('prepare: FAILED')
    return null
  }
  runQuiet([NODE, tool('relink.mjs'), 'link', R(ld), R(ref)], { cwd: proj.root, env })
  let exe = join(ld, 'relinked.exe')
  if (!exists(exe)) {
    log('link: FAILED; see', join(ld, 'link.rsp'))
    return null
  }
  if (mode === 'source') {
    const c = run([NODE, tool('relink.mjs'), 'check', R(ld), R(ref), R(symbols), R(join(b.decompiled, 'instructions.tsv')),
      R(join(b.decompiled, 'index.json'))], proj, { env })
    if (c.returncode) {
      log('check: FAILED')
      return null
    }
  } else {
    run([NODE, tool('relink.mjs'), 'finish', R(ld), R(ref)], proj, { env })
    exe = join(ld, 'final.exe')
  }
  const dst = join(out, b.file)
  makedirs(dirname(dst))
  fs.copyFileSync(exe, dst)
  fs.chmodSync(dst, fs.statSync(exe).mode & 0o7777)
  return { binary: b.file, functions_identical: st.totals.functions_identical,
    functions_nonmatching: st.totals.functions_nonmatching }
}

// Every file of the game folder against the build: identical / different / missing; plus extra files
function compareTrees(game, out) {
  const rows = []
  const gameFiles = walkFiles(game)
  for (const rel of gameFiles) {
    const p = join(out, rel)
    if (!exists(p)) rows.push([rel, 'missing'])
    else rows.push([rel, sha256File(join(game, rel)) === sha256File(p) ? 'identical' : 'different'])
  }
  const have = new Set(walkFiles(game))
  const extra = walkFiles(out).filter((r) => !have.has(r))
  return [rows, extra]
}

// Titles of on-screen windows whose owner starts with 'wine' (CoreGraphics window list, read through
// osascript's JavaScript for Automation; needs no screen-recording access). null when not on macOS.
const JXA = "ObjC.import('CoreGraphics');" +
  'var a = ObjC.deepUnwrap(ObjC.castRefToObject($.CGWindowListCopyWindowInfo(1 | 16, 0))) || [];' +
  'var out = [];' +
  'for (var i = 0; i < a.length; i++) {' +
  '  var o = a[i].kCGWindowOwnerName, n = a[i].kCGWindowName;' +
  "  if (String(o === undefined || o === null ? '' : o).toLowerCase().indexOf('wine') === 0)" +
  "    out.push(n === undefined || n === null ? '' : String(n));" +
  '}' +
  'JSON.stringify(out)'
export function windowTitles() {
  if (process.platform !== 'darwin') return null
  const r = spawnSync('osascript', ['-l', 'JavaScript', '-e', JXA], { encoding: 'utf8' })
  if (r.error || r.status !== 0) throw new PyError('OSError', `osascript failed: ${(r.stderr || '').trim()}`)
  return JSON.parse(r.stdout)
}

// Start the build under Wine and wait for its window (see pipeline.py run_game)
async function runGame(proj, out, tries = 3, wait = 30) {
  const rc = get(proj.cfg, 'run', new Map())
  const exe = get(rc, 'exe') || (proj.binaries().find((b) => b.file.toLowerCase().endsWith('.exe'))?.file ?? null)
  if (!truthy(exe)) throw new ConfigError('run.exe not set in decomp.json')
  const want = get(rc, 'window', splitext(basename(exe))[0])
  const prefix = process.env.WINEPREFIX || expanduser(get(rc, 'wineprefix', '~/.wine'))
  const env = { ...process.env, WINEPREFIX: prefix, WINEDEBUG: '-all' }
  const cwd = join(out, dirname(exe))
  const kill = () => { const r = spawnSync('wineserver', ['-k'], { env, stdio: 'pipe' }); spawnError(['wineserver'], r) }
  for (let t = 1; t <= tries; t++) {
    kill()
    await sleep(2)
    const p = spawn('wine', [basename(exe)], { cwd, env, stdio: 'ignore' })
    let running = true
    const exited = new Promise((resolve) => {
      p.on('exit', () => { running = false; resolve() })
      p.on('error', (e) => { running = false; resolve(e) })
    })
    let title = null, alive = false
    if (windowTitles() === null) {
      await sleep(wait)
      alive = running
      title = alive ? '(window not checked: no window list on this host)' : null
    } else {
      for (let i = 0; i < wait; i++) {
        await sleep(1)
        const ts = windowTitles()
        const hit = ts.filter((x) => x.startsWith(want))
        if (hit.length) {
          title = hit[0]
          break
        }
        if (ts.some((x) => x === 'Program Error' || x === 'Wine Debugger')) break
      }
      if (title) {
        await sleep(5)
        alive = windowTitles().some((x) => x.startsWith(want))
      }
    }
    kill()
    const e = await exited
    if (e instanceof Error) throw new PyError('FileNotFoundError', "[Errno 2] No such file or directory: 'wine'")
    log(`run ${t}: window ${title === null ? 'None' : pyRepr(title)}, still running 5 s later: ${alive ? 'True' : 'False'}`)
    if (title && alive) return [title, t]
  }
  return [null, tries]
}

function stamp() {
  const d = new Date()
  const p = (n) => String(n).padStart(2, '0')
  return `${String(d.getFullYear()).padStart(4, '0')}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

async function cmd_build(proj, a) {
  const out = a.out ? proj.abs(a.out) : join(proj.p.build, 'game')
  const work = join(proj.p.build, 'work')
  makedirs(out)
  makedirs(work)
  const t0 = now()
  const res = { command: 'build', mode: a.mode, out: proj.rel(out), no_original: a.no_original }
  if (!a.skip_data) res.data_files = await buildData(proj, out, a.jobs)
  res.binaries = []
  for (const b of proj.binaries()) {
    if (b.matching) continue
    if (!reassembleTo(proj, b.reassembled, join(out, b.file))) return [false, { ...res, error: `${b.file}: reassembly failed` }]
    log(`${b.file}: rebuilt from ${proj.rel(b.reassembled)}`)
    res.binaries.push({ binary: b.file, source: proj.rel(b.reassembled) })
  }
  for (const b of proj.binaries(null, true)) {
    let ref = null, cache = null
    if (a.no_original) {
      ref = join(work, 'reference', b.file)
      cache = join(work, `asm_cache_${b.name}.json`)
      if (!reassembleTo(proj, b.reassembled, ref, cache)) return [false, { ...res, error: `${b.file}: reference reassembly failed` }]
      log(`reference: ${b.file} assembled from ${proj.rel(b.reassembled)} (the game folder is not read)`)
    }
    const r = await buildExe(proj, b, out, a.mode, work, a.jobs, ref, cache)
    if (!r) return [false, { ...res, error: `${b.file}: build failed (see the log)` }]
    res.binaries.push(r)
  }
  let rows
  if (a.no_original) {
    res.files = { built: walkFiles(out).length, compared: 'no (--no-original)' }
    rows = []
  } else {
    let extra
    [rows, extra] = compareTrees(proj.p.game, out)
    const summary = new PyDict()
    for (const [, st] of rows) summary.set(st, (summary.get(st) ?? 0) + 1)
    res.files = summary
    res.different = rows.filter(([, st]) => st !== 'identical').map(([r]) => r)
    res.extra = extra
  }
  res.seconds = pyRound0(now() - t0)
  let ok = a.mode === 'source' || a.no_original || (rows.length > 0 && (res.files.get('identical') ?? 0) === rows.length)
  if (a.run) {
    const [title, tries] = await runGame(proj, out)
    res.game_window = title || 'NOT SHOWN'
    res.run_tries = tries
    ok = ok && Boolean(title)
  }
  res.ok = Boolean(ok)
  makedirs(proj.p.reports)
  dumpJson({ ...res, finished: stamp() }, proj.report('build.json'))
  return [Boolean(ok), res]
}

async function cmd_verify(proj, a) {
  const out = a.out ? proj.abs(a.out) : join(proj.p.build, 'game')
  if (!isdir(out)) throw new ConfigError(`no build folder ${proj.rel(out)}`)
  if (!isdir(proj.p.game)) throw new ConfigError(`no game folder ${proj.rel(proj.p.game)}`)
  const [rows, extra] = compareTrees(proj.p.game, out)
  const summary = new PyDict()
  for (const [, st] of rows) summary.set(st, (summary.get(st) ?? 0) + 1)
  const res = { command: 'verify', out: proj.rel(out), game: proj.rel(proj.p.game), files: summary,
    different: rows.filter(([, st]) => st === 'different').map(([r]) => r),
    missing: rows.filter(([, st]) => st === 'missing').map(([r]) => r), extra }
  const ok = rows.length > 0 && (summary.get('identical') ?? 0) === rows.length && !extra.length
  dumpJson({ ...res, ok }, proj.report('verify.json'))
  return [ok, res]
}

// ---------------------------------------------------------------------------------------------------- status
async function cmd_status(proj, a) {
  const rows = []
  const row = (phase, gate, detail) => rows.push({ phase, gate, detail })
  const jload = (p) => { try { return loadJson(p) } catch { return null } }
  const s = pyStr
  const game = proj.p.game
  // 1 intake
  if (!isdir(game)) row('1 intake', 'not run', `no game folder ${proj.rel(game)}`)
  else {
    const n = walkFiles(game).length
    const man = jload(proj.p.manifest)
    if (truthy(man)) {
      const cur = manifest(game).get('files')
      const mf = need(man, 'files')
      const same = cur.size === mf.size && [...cur.keys()].every((k) => mf.has(k)) &&
        [...cur.keys()].every((k) => need(cur.get(k), 'sha256') === need(mf.get(k), 'sha256'))
      row('1 intake', same ? 'ok' : 'FAIL', `${n} files; ${same ? 'identical to' : 'DIFFERENT from'} ${proj.rel(proj.p.manifest)}`)
    } else {
      const it = jload(proj.report('intake.json'))
      row('1 intake', truthy(it) ? (truthy(need(it, 'ok')) ? 'ok' : 'FAIL') : 'open', `${n} files; no manifest yet`)
    }
  }
  // 2 inventory, archives
  const inv = jload(proj.report('inventory.json'))
  if (truthy(inv)) {
    const un = await inventoryGate(proj, inv)
    row('2 inventory', !un.length ? 'ok' : 'FAIL', `${pyLen(need(inv, 'files'))} files, ${pyLen(get(inv, 'unclassified', []))} ` +
      `without magic, ${un.length} not handled by a configured module`)
  } else row('2 inventory', 'not run', '')
  const mem = jload(join(proj.p.extracted, MEMBERS_JSON))
  const arcs = get(proj.cfg, 'archives', [])
  if (mem !== null) {
    const miss = arcs.filter((x) => !has(mem, x))
    row('2 archives', !miss.length ? 'ok' : 'FAIL', [...mem].map(([k, v]) => `${k}: ${pyLen(v)} members`).join(', ') +
      (miss.length ? `; not extracted: ${pyReprValue(miss)}` : ''))
  } else row('2 archives', truthy(arcs) ? 'not run' : 'ok', truthy(arcs) ? '' : 'no archives configured')
  // 3 decode
  const mods = []
  for (const f of proj.formats()) {
    for (const t of need(f, 'trees')) mods.push([`${t}/${need(f, 'module')}`, jload(proj.report(t, `${need(f, 'module')}.json`))])
  }
  if (mods.length) {
    const done = mods.filter(([, r]) => truthy(r))
    const files = pySum(done.map(([, r]) => need(r, 'files')))
    const passed = pySum(done.map(([, r]) => need(r, 'passed')))
    const [gate, comp] = completeness(proj, false)
    row('3 decode', gate && done.length === mods.length && passed === files ? 'ok' : (done.length ? 'FAIL' : 'not run'),
      `${done.length}/${mods.length} module reports, ${passed}/${files} files identical, ` +
      `opaque ${pySum(done.map(([, r]) => need(r, 'opaque_bytes')))} bytes; completeness: ${comp.ok} ok, ` +
      `${comp.problems.length} problems, ${comp.unexpected_nested_signatures.length} nested signatures`)
  } else row('3 decode', 'not run', 'no formats configured')
  for (const b of proj.binaries()) {
    const nm = b.name
    const idx = jload(join(b.decompiled, 'index.json'))
    const orph = orphanLine(join(b.decompiled, 'recovery.log'))
    const cc = jload(join(b.decompiled, 'coverage_check.json'))
    const mbz = get(get(truthy(cc) ? cc : new Map(), 'summary', new Map()), 'must_be_zero', null)
    const mbzClean = mbz !== null && ![...mbz.values()].some(truthy)
    if (idx === null) row(`4 recover ${nm}`, 'not run', '')
    else {
      const good = orph === 0 && mbzClean
      row(`4 recover ${nm}`, good ? 'ok' : 'FAIL', `${s(nfunctions(idx))} functions, orphan instructions ${s(orph)}, coverage check ` +
        `${mbzClean ? 'clean' : (mbz === null ? 'not run' : pyReprValue(mbz))}`)
    }
    const fm = jload(join(b.analysis, 'features_meta.json'))
    row(`5 features ${nm}`, truthy(fm) ? 'ok' : 'not run',
      truthy(fm) ? `${s(need(need(fm, 'counts'), 'functions'))} functions, ${s(get(need(fm, 'counts'), 'chunks', null))} chunks` : '')
    const nidx = jload(join(b.named, 'index.json'))
    const apply = join(b.analysis, 'names_apply.json')
    const [nf, same] = nameFailures(join(b.named, 'name_failures.txt'))
    if (nidx === null) row(`5 names ${nm}`, 'not run', exists(apply) ? 'names_apply.json present' : '')
    else {
      const ap = exists(apply) ? jload(apply) : null
      const napplied = exists(apply) ? pyLen(truthy(ap) ? ap : new Map()) : 0
      row(`5 names ${nm}`, !nf ? 'ok' : 'FAIL', `${napplied} names in names_apply.json, ${nf || 0} ` +
        'failures' + (same ? ` (${same} already present at their address)` : ''))
    }
    const ra = jload(proj.report('reassemble', `${nm}.json`))
    if (truthy(ra)) {
      const ident = truthy(need(ra, 'identical'))
      const bs = need(ra, 'built_sha256')
      row(`5b reassemble ${nm}`, ident ? 'ok' : 'FAIL',
        `${ident ? 'identical' : 'DIFFERENT'} ${[...(truthy(bs) ? bs : '')].slice(0, 16).join('')}` +
        `${truthy(get(ra, 'cached')) ? ' (cached)' : ''}`)
    } else {
      const haveL = exists(join(b.reassembled, 'layout.json'))
      row(`5b reassemble ${nm}`, haveL ? 'open' : 'not run', haveL ? 'text present, not verified by the runner' : '')
    }
    if (b.matching) {
      const units = globCpp(b.src).length
      const st = jload(proj.report('match', `${nm}.json`))
      if (truthy(st)) {
        const t = need(st, 'totals')
        const v = (k) => s(need(t, k))
        row(`6 match ${nm}`, num(need(t, 'functions_diff')) === 0 && num(need(t, 'compile_failed')) === 0 ? 'ok' : 'FAIL',
          `${v('units')} units, ${v('functions_identical')} identical, ${v('functions_nonmatching')} ` +
          `nonmatching, ${v('functions_diff')} diff, ${v('functions_stub')} stubs, ` +
          `${v('compile_failed')} compile failures`)
      } else row(`6 match ${nm}`, 'not run', units ? `${units} units` : 'no units (skeleton)')
    }
  }
  const bj = jload(proj.report('build.json'))
  if (truthy(bj)) {
    row('build', truthy(get(bj, 'ok')) ? 'ok' : 'FAIL', `${s(need(bj, 'mode'))}${truthy(get(bj, 'no_original')) ? ' --no-original' : ''} ` +
      `-> ${s(need(bj, 'out'))}: ${s(get(bj, 'files', null))}${has(bj, 'game_window') ? '; window ' + need(bj, 'game_window') : ''} ` +
      `(${s(get(bj, 'finished', ''))})`)
  } else row('build', 'not run', '')
  const vj = jload(proj.report('verify.json'))
  row('verify', truthy(vj) ? (truthy(need(vj, 'ok')) ? 'ok' : 'FAIL') : 'not run',
    truthy(vj) ? `${s(need(vj, 'out'))}: ${s(need(vj, 'files'))}, extra ${pyLen(need(vj, 'extra'))}` : '')
  const order = ['1', '2', '3', '4', '5', '5b', '6', 'build', 'verify']
  const keyed = rows.map((r, i) => [order.indexOf(r.phase.split(' ')[0]), i, r])
  keyed.sort((x, y) => x[0] - y[0] || x[1] - y[1])
  const sorted = keyed.map((x) => x[2])
  const w = Math.max(...sorted.map((r) => [...r.phase].length))
  const gameName = s(get(proj.cfg, 'game', ''))
  log(`${gameName}\n${ljust('phase', w)}  ${ljust('gate', 8)} detail`)
  for (const r of sorted) log(`${ljust(r.phase, w)}  ${ljust(r.gate, 8)} ${r.detail}`)
  return [sorted.every((r) => r.gate === 'ok'), { command: 'status', game: get(proj.cfg, 'game', null), phases: sorted }]
}

// ------------------------------------------------------------------------------------------------------ main
const CHOICES = '{init,intake,inventory,archives,decode,completeness,recover,features,names,reassemble,skeleton,match,build,verify,status}'
const MAIN_USAGE = `usage: pipeline.py [-h] [--project PROJECT]\n                   ${CHOICES}\n                   ...\n`
const MAIN_HELP = MAIN_USAGE + "\nRun the skill's phases on a project folder from one config file, decomp.json\n(references/pipeline.md).\n\n" +
  `positional arguments:\n  ${CHOICES}\n\noptional arguments:\n  -h, --help            show this help message and exit\n  --project PROJECT\n`
const OPT = '\noptional arguments:\n'
const SUB = {
  init: ['usage: pipeline.py init [-h] --game GAME [--force]\n',
    OPT + '  -h, --help   show this help message and exit\n  --game GAME\n  --force\n'],
  intake: ['usage: pipeline.py intake [-h] [--language LANGUAGE] [--force] installer\n',
    '\npositional arguments:\n  installer\n' + OPT + '  -h, --help           show this help message and exit\n  --language LANGUAGE\n  --force\n'],
  inventory: ['usage: pipeline.py inventory [-h]\n', OPT + '  -h, --help  show this help message and exit\n'],
  archives: ['usage: pipeline.py archives [-h] [--force]\n', OPT + '  -h, --help  show this help message and exit\n  --force\n'],
  decode: ['usage: pipeline.py decode [-h] [--module MODULE] [--jobs JOBS]\n',
    OPT + '  -h, --help       show this help message and exit\n  --module MODULE\n  --jobs JOBS\n'],
  completeness: ['usage: pipeline.py completeness [-h]\n', OPT + '  -h, --help  show this help message and exit\n'],
  recover: ['usage: pipeline.py recover [-h] [--binary BINARY] [--force]\n',
    OPT + '  -h, --help       show this help message and exit\n  --binary BINARY\n  --force\n'],
  features: ['usage: pipeline.py features [-h] [--binary BINARY] [--force]\n',
    OPT + '  -h, --help       show this help message and exit\n  --binary BINARY\n  --force\n'],
  names: ['usage: pipeline.py names [-h] [--binary BINARY]\n',
    OPT + '  -h, --help       show this help message and exit\n  --binary BINARY\n'],
  reassemble: ['usage: pipeline.py reassemble [-h] [--binary BINARY] [--force] [--split]\n                              [--cache]\n',
    OPT + '  -h, --help       show this help message and exit\n  --binary BINARY\n  --force\n  --split\n  --cache\n'],
  skeleton: ['usage: pipeline.py skeleton [-h] [--binary BINARY] [--force]\n',
    OPT + '  -h, --help       show this help message and exit\n  --binary BINARY\n  --force\n'],
  match: ['usage: pipeline.py match [-h] [--binary BINARY] [--units UNITS] [--jobs JOBS]\n',
    OPT + '  -h, --help       show this help message and exit\n  --binary BINARY\n  --units UNITS\n  --jobs JOBS\n'],
  build: ['usage: pipeline.py build [-h] [--mode {source,identical}] [--out OUT]\n                         [--no-original] [--skip-data] [--jobs JOBS] [--run]\n',
    OPT + '  -h, --help            show this help message and exit\n  --mode {source,identical}\n  --out OUT\n' +
    '  --no-original\n  --skip-data\n  --jobs JOBS\n  --run\n'],
  verify: ['usage: pipeline.py verify [-h] [--out OUT]\n', OPT + '  -h, --help  show this help message and exit\n  --out OUT\n'],
  status: ['usage: pipeline.py status [-h]\n', OPT + '  -h, --help  show this help message and exit\n'],
}
const COMMANDS = { init: cmd_init, intake: cmd_intake, inventory: cmd_inventory, archives: cmd_archives,
  decode: cmd_decode, completeness: cmd_completeness, recover: cmd_recover, features: cmd_features,
  names: cmd_names, reassemble: cmd_reassemble, skeleton: cmd_skeleton, match: cmd_match, build: cmd_build,
  verify: cmd_verify, status: cmd_status }

async function main(argv) {
  const ap = new ArgumentParser({ prog: 'pipeline.py', usage: MAIN_USAGE, help: MAIN_HELP })
  ap.add_argument('--project', { default: '.' })
  const sp = ap.add_subparsers({ dest: 'cmd' })
  const P = (name) => sp.add_parser(name, { usage: SUB[name][0], help: SUB[name][0] + SUB[name][1] })
  let s = P('init'); s.add_argument('--game', { required: true }); s.add_argument('--force', { action: 'store_true' })
  s = P('intake'); s.add_argument('installer'); s.add_argument('--language')
  s.add_argument('--force', { action: 'store_true' })
  P('inventory')
  s = P('archives'); s.add_argument('--force', { action: 'store_true' })
  s = P('decode'); s.add_argument('--module'); s.add_argument('--jobs', { type: 'int', default: 4 })
  P('completeness')
  for (const c of ['recover', 'features', 'names', 'reassemble', 'skeleton']) {
    s = P(c); s.add_argument('--binary')
    if (c !== 'names') s.add_argument('--force', { action: 'store_true' })
    if (c === 'reassemble') { s.add_argument('--split', { action: 'store_true' }); s.add_argument('--cache', { action: 'store_true' }) }
  }
  s = P('match'); s.add_argument('--binary'); s.add_argument('--units')
  s.add_argument('--jobs', { type: 'int', default: 4 })
  s = P('build'); s.add_argument('--mode', { choices: new Map([['source', 1], ['identical', 1]]), default: 'source' })
  s.add_argument('--out'); s.add_argument('--no-original', { action: 'store_true' })
  s.add_argument('--skip-data', { action: 'store_true' }); s.add_argument('--jobs', { type: 'int', default: 6 })
  s.add_argument('--run', { action: 'store_true' })
  s = P('verify'); s.add_argument('--out')
  P('status')
  argv = [...argv]                                  // --project may come after the command too
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i]
    if (x === '--project' && i + 1 < argv.length) {
      argv = [...argv.slice(i, i + 2), ...argv.slice(0, i), ...argv.slice(i + 2)]
      break
    }
    if (x.startsWith('--project=')) {
      argv = [x, ...argv.slice(0, i), ...argv.slice(i + 1)]
      break
    }
  }
  const a = ap.parse_args(argv)
  if (!a.cmd) {
    stderrWrite(MAIN_HELP)
    return 2
  }
  let ok, res
  try {
    const proj = new Project(a.project, a.cmd !== 'init')
    ;[ok, res] = await COMMANDS[a.cmd](proj, a)
  } catch (e) {
    if (e instanceof ConfigError) {
      stdoutWrite(dumps({ command: a.cmd, error: e.message }, { indent: 1 }) + '\n')
      return 2
    }
    throw e
  }
  stdoutWrite(dumps(res, { indent: 1 }) + '\n')
  return ok ? 0 : 1
}

if (!isMainThread) {
  // build data worker: encode_one for each item the main thread sends
  parentPort.on('message', async ({ i, item }) => {
    try {
      parentPort.postMessage({ i, n: await encodeOne(item) })
    } catch (e) {
      const name = e instanceof ConfigError ? 'ConfigError' : isOSError(e) ? osErrorClass(e) : (e && e.name ? e.name : 'Error')
      const msg = isOSError(e) ? osErrorStr(e) : (e && e.message !== undefined ? e.message : String(e))
      parentPort.postMessage({ i, error: [name, msg] })
    }
  })
} else if (process.argv[1] && abspath(process.argv[1]) === SELF) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code }, (e) => {
    if (e instanceof ArgExit) { process.exitCode = e.code; return }
    if (e instanceof PyError && e.pyName === 'SystemExit') { stderrWrite(e.message + '\n'); process.exitCode = 1; return }
    const name = isOSError(e) ? osErrorClass(e) : (e && e.name ? e.name : 'Error')
    const msg = isOSError(e) ? osErrorStr(e) : (e && e.message !== undefined ? e.message : String(e))
    stderrWrite(`Traceback (most recent call last):\n  (JavaScript port)\n${name}: ${msg}\n`)
    if (process.env.PYTOOLS_DEBUG) stderrWrite(String(e && e.stack) + '\n')
    process.exitCode = 1
  })
}
