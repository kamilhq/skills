#!/usr/bin/env node
// pipeline.mjs - JavaScript (Node.js) port of pipeline.py: run the skill's phases on a project folder from one
// config file, decomp.json (references/pipeline.md). Same commands, options, decomp.json handling, JSON
// summaries, report files and exit codes as pipeline.py; the tools it runs are the JavaScript ports in this
// folder (intake.mjs, inventory.mjs, verify.mjs, code_coverage_check.mjs, build_features.mjs, ...), plus
// Ghidra's shell wrappers like the Python.
//
//   node pipeline.mjs [--project DIR] <command> [options]      (commands: see pipeline.py)
//
// Format modules: where pipeline.py loads <paths.formats>/fmt_<m>.py, this loads fmt_<m>.mjs from the JS
// formats folder of the project: paths.formats_js when decomp.json sets it, else <parent>/js/<name> of
// paths.formats when that folder exists (tools/formats -> tools/js/formats, the skill's scripts/formats ->
// scripts/js/formats), else paths.formats itself (.mjs files next to the .py ones).
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import { fileURLToPath, pathToFileURL } from 'node:url'
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
const SK = dirname(HERE)                          // scripts (shell wrappers: ghidra/*.sh)
const NODE = process.execPath
const DEFAULT_PATHS = {
  game: 'work/game', extracted: 'extracted', decoded: 'decoded', reports: 'reports', formats: 'tools/formats',
  analysis: 'analysis', build: 'build', work: 'work', manifest: 'manifests/game.json',
}
const GITIGNORE = ['# Game-derived content (copyrighted; regenerate locally from your own installer)', '/extracted/',
  '/decoded/', '/previews/', '/decompiled*/', '/analysis/', '/work/', '/build/',
  "# clean room: implementer workspaces (copies), the oracle's traces", '/cleanroom/workspaces/',
  '/rewrite/harness/oracle/', '__pycache__/', '*.pyc', '.DS_Store']
const SIGS = [[Buffer.from('PK\x03\x04', 'latin1'), 'zip'], [Buffer.from('OggS', 'latin1'), 'ogg'],
  [Buffer.from('RIFF', 'latin1'), 'riff'], [Buffer.from('\x89PNG\r\n\x1a\n', 'latin1'), 'png']]
const MEMBERS_JSON = '_members.json'

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

  binaries(name = null) {
    let out = []
    for (const b of get(this.cfg, 'binaries', [])) {
      if (!has(b, 'file')) throw new ConfigError(`binaries entry without "file": ${pyReprValue(b)}`)
      const file = need(b, 'file')
      const stem = splitext(basename(file))[0]
      const nm = get(b, 'name', stem)
      const low = stem.toLowerCase()
      out.push({
        name: nm, file, stem,
        binary: join(this.p.game, file),
        decompiled: this.abs(get(b, 'decompiled', `decompiled_${low}`)),
        named: this.abs(get(b, 'named', `decompiled_named_${low}`)),
        analysis: has(b, 'analysis') ? this.abs(need(b, 'analysis')) : join(this.p.analysis, nm),
        project: has(b, 'ghidra_project') ? this.abs(need(b, 'ghidra_project')) : join(this.p.work, `ghidra_${stem}`),
      })
    }
    if (truthy(name)) {
      out = out.filter((b) => name === b.name || name === b.file || name === b.stem)
      if (!out.length) throw new ConfigError(`no binary ${pyRepr(name)} in decomp.json`)
    }
    return out
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
          named: `decompiled_named_${stem.toLowerCase()}` })
      }
    }
  }
  const cfg = { game: a.game, paths: { ...DEFAULT_PATHS }, archives: [], formats: [], containers: [], binaries }
  makedirs(proj.root)
  dumpJson(cfg, proj.cfg_path)
  const gi = join(proj.root, '.gitignore')
  const have = exists(gi) ? splitlines(textOf(fs.readFileSync(gi))) : []
  const add = GITIGNORE.filter((l) => !have.includes(l))
  if (add.length) fs.appendFileSync(gi, (have.length && have[have.length - 1] !== '' ? '\n' : '') + add.join('\n') + '\n')
  for (const k of ['formats', 'reports', 'build', 'work']) makedirs(proj.p[k])
  makedirs(dirname(proj.p.manifest))
  return [true, { command: 'init', config: 'decomp.json', binaries: binaries.map((b) => b.file), gitignore_added: add,
    next: 'fill in archives/formats/containers, then intake' }]
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

// The step-3d gate (see pipeline.py)
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
  const archives = new Set(get(proj.cfg, 'archives', []))
  let members                      // archives extracted by `archives` (members CRC-checked) need no reader
  try { members = loadJson(join(proj.p.extracted, MEMBERS_JSON)) } catch { members = null }
  if (!(members instanceof Map)) members = new Map()
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
      if (!ents.length && tree === 'game' && archives.has(rel) && members.has(rel)) {
        rows.push({ tree, file: rel, status: 'extracted' })
        continue
      }
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
    archives_extracted: rows.filter((r) => r.status === 'extracted').map((r) => r.file),
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

// ---------------------------------------------------------------------------------------------- steps 3a, 3b
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
      rows.push({ binary: b.file, ok: false, error: `${proj.rel(names)} missing (step 3b naming)` })
      continue
    }
    const p = run(['sh', join(SK, 'ghidra', 'apply_names.sh'), b.binary, b.project, names, b.named], proj)
    const [nf, same] = nameFailures(join(b.named, 'name_failures.txt'))
    rows.push({ binary: b.file, out: proj.rel(b.named), exit: p.returncode, name_failures: nf, already_present: same,
      ok: (p.returncode === 0 || p.returncode === 3) && nf === 0 })
  }
  return [rows.every((r) => r.ok), { command: 'names', binaries: rows }]
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
    row('3d decode', gate && done.length === mods.length && passed === files ? 'ok' : (done.length ? 'FAIL' : 'not run'),
      `${done.length}/${mods.length} module reports, ${passed}/${files} files identical, ` +
      `opaque ${pySum(done.map(([, r]) => need(r, 'opaque_bytes')))} bytes; completeness: ${comp.ok} ok, ` +
      `${comp.problems.length} problems, ${comp.unexpected_nested_signatures.length} nested signatures`)
  } else row('3d decode', 'not run', 'no formats configured')
  for (const b of proj.binaries()) {
    const nm = b.name
    const idx = jload(join(b.decompiled, 'index.json'))
    const orph = orphanLine(join(b.decompiled, 'recovery.log'))
    const cc = jload(join(b.decompiled, 'coverage_check.json'))
    const mbz = get(get(truthy(cc) ? cc : new Map(), 'summary', new Map()), 'must_be_zero', null)
    const mbzClean = mbz !== null && ![...mbz.values()].some(truthy)
    if (idx === null) row(`3a recover ${nm}`, 'not run', '')
    else {
      const good = orph === 0 && mbzClean
      row(`3a recover ${nm}`, good ? 'ok' : 'FAIL', `${s(nfunctions(idx))} functions, orphan instructions ${s(orph)}, coverage check ` +
        `${mbzClean ? 'clean' : (mbz === null ? 'not run' : pyReprValue(mbz))}`)
    }
    const fm = jload(join(b.analysis, 'features_meta.json'))
    row(`3b features ${nm}`, truthy(fm) ? 'ok' : 'not run',
      truthy(fm) ? `${s(need(need(fm, 'counts'), 'functions'))} functions, ${s(get(need(fm, 'counts'), 'chunks', null))} chunks` : '')
    const nidx = jload(join(b.named, 'index.json'))
    const apply = join(b.analysis, 'names_apply.json')
    const [nf, same] = nameFailures(join(b.named, 'name_failures.txt'))
    if (nidx === null) row(`3b names ${nm}`, 'not run', exists(apply) ? 'names_apply.json present' : '')
    else {
      const ap = exists(apply) ? jload(apply) : null
      const napplied = exists(apply) ? pyLen(truthy(ap) ? ap : new Map()) : 0
      row(`3b names ${nm}`, !nf ? 'ok' : 'FAIL', `${napplied} names in names_apply.json, ${nf || 0} ` +
        'failures' + (same ? ` (${same} already present at their address)` : ''))
    }
  }
  const order = ['1', '2', '3a', '3b', '3d']
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
const CHOICES = '{init,intake,inventory,archives,decode,completeness,recover,features,names,status}'
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
  status: ['usage: pipeline.py status [-h]\n', OPT + '  -h, --help  show this help message and exit\n'],
}
const COMMANDS = { init: cmd_init, intake: cmd_intake, inventory: cmd_inventory, archives: cmd_archives,
  decode: cmd_decode, completeness: cmd_completeness, recover: cmd_recover, features: cmd_features,
  names: cmd_names, status: cmd_status }

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
  for (const c of ['recover', 'features', 'names']) {
    s = P(c); s.add_argument('--binary')
    if (c !== 'names') s.add_argument('--force', { action: 'store_true' })
  }
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

if (process.argv[1] && abspath(process.argv[1]) === SELF) {
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
