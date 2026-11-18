// rwlib.mjs - port of ../../rwlib.py: shared helpers of the game-rewrite scripts (Node built-ins only).
// Also holds the small Python-compatibility layer the ports need (json.dumps text, os.path, % formatting).
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const JS_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
export const SCRIPTS = path.dirname(JS_DIR)          // the Python scripts' folder (capi/, msvc_compat/, ...)

// ------------------------------------------------------------------------------------------- os.path
export function expanduser (p) {
  if (p === '~' || p.startsWith('~/')) return os.homedir() + p.slice(1)
  return p
}
export function normpath (p) {
  if (p === '') return '.'
  const abs = p.startsWith('/')
  const out = []
  for (const part of p.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..' && out.length && out[out.length - 1] !== '..') out.pop()
    else if (part === '..' && abs) continue
    else out.push(part)
  }
  const s = (abs ? '/' : '') + out.join('/')
  return s || (abs ? '/' : '.')
}
export function join (...parts) {
  let r = ''
  for (const p of parts) {
    if (p.startsWith('/')) r = p
    else if (r === '' || r.endsWith('/')) r += p
    else r += '/' + p
  }
  return r
}
export function abspath (p) { return normpath(path.isAbsolute(p) ? p : join(process.cwd(), p)) }
export function relpath (p, start = '.') {
  const r = path.relative(abspath(start), abspath(p))
  return r === '' ? '.' : r
}
export function dirname (p) {
  const i = p.lastIndexOf('/')
  if (i < 0) return ''
  const head = p.slice(0, i + 1)
  return /^\/+$/.test(head) ? head : head.replace(/\/+$/, '')
}
export function basename (p) { return p.slice(p.lastIndexOf('/') + 1) }
export function splitext (p) {
  const b = basename(p)
  let i = b.lastIndexOf('.')
  if (i <= 0 || /^\.+$/.test(b.slice(0, i + 1))) return [p, '']
  i = p.length - b.length + i
  return [p.slice(0, i), p.slice(i)]
}
export function commonpath (paths) {
  const split = paths.map(p => abspath(p).split('/').filter(Boolean))
  const first = split[0]
  let n = first.length
  for (const s of split) {
    let i = 0
    while (i < n && i < s.length && s[i] === first[i]) i++
    n = i
  }
  return '/' + first.slice(0, n).join('/')
}
export const exists = p => fs.existsSync(p)
export const isdir = p => { try { return fs.statSync(p).isDirectory() } catch { return false } }
export const isfile = p => { try { return fs.statSync(p).isFile() } catch { return false } }
export function makedirs (p) { fs.mkdirSync(p, { recursive: true }) }
export function rmtree (p) { fs.rmSync(p, { recursive: true, force: true }) }
export function listdirSorted (p) { return fs.readdirSync(p).sort(cmp) }
export const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0)
export function mkdtemp (prefix, dir = os.tmpdir()) { return fs.mkdtempSync(join(dir, prefix)) }

// ---------------------------------------------------------------------------------------------- config
export function loadConfig (project) {
  const p = join(project, 'decomp.json')
  if (!fs.existsSync(p)) return [{}, {}]
  const cfg = pyParse(fs.readFileSync(p, 'utf8'))
  return [cfg, cfg.rewrite || {}]
}
export function projectPath (project, p) {
  if (p === null || p === undefined) return null
  p = expanduser(p)
  return abspath(path.isAbsolute(p) ? p : join(project, p))
}
export function get (d, dotted, dflt = null) {
  for (const k of dotted.split('.')) {
    if (d === null || typeof d !== 'object' || Array.isArray(d) || !(k in d)) return dflt
    d = d[k]
  }
  return d
}
export function findDecompScripts (project, rw) {
  const cands = [process.env.DECOMP_SCRIPTS, projectPath(project, get(rw, 'toolchain.decomp_scripts')),
    join(SCRIPTS, '..', '..', 'byte-identical-game-decomp', 'scripts'),
    join(project, '.claude', 'skills', 'byte-identical-game-decomp', 'scripts')]
  for (const c of cands) if (c && isdir(c)) return normpath(c)
  return null
}

// ------------------------------------------------------------------------------------- C/C++ compiler
export function msvcSetup (project, cfg, rw) {
  const tc = Object.assign({}, cfg.toolchain || {}, get(rw, 'toolchain') || {})
  const mode = tc.cl_mode || (process.platform === 'win32' ? 'native' : 'wine')
  const env = Object.assign({}, process.env)
  if (tc.wineprefix && env.MSVC_PREFIX === undefined) env.MSVC_PREFIX = expanduser(tc.wineprefix)
  if (tc.vs && env.MSVC_VS === undefined) env.MSVC_VS = tc.vs
  if (tc.sdk && env.MSVC_SDK === undefined) env.MSVC_SDK = tc.sdk
  let msvcSh = process.env.MSVC_SH || projectPath(project, tc.msvc_sh)
  if (!msvcSh) {
    const ds = findDecompScripts(project, rw)
    msvcSh = ds ? join(ds, 'msvc.sh') : null
  }
  return { mode, msvc_sh: msvcSh, env, tc, machine: tc.machine || 'x86' }
}
export function msvcCmd (ms, tool, args) {
  return ms.mode === 'wine' ? ['sh', ms.msvc_sh, tool, ...args] : [tool, ...args]
}
const NOISE = new Set(['Generating Code...'])
export function runTool (cmd, cwd, env) {
  const r = spawnSync(cmd[0], cmd.slice(1), { cwd, env: env || process.env, encoding: 'utf8', maxBuffer: 1 << 28 })
  const text = (r.stdout || '') + (r.stderr || '')
  const lines = splitlines(text).filter(l => l.trim() && !NOISE.has(l.trim()) &&
    !['.c', '.cpp', '.cc', '.cxx'].some(e => l.trim().endsWith(e)) && !l.includes('Creating library'))
  return [r.error ? 127 : r.status, lines]
}
export function vsIncludeDirs (ms, project) {
  if (ms.tc.vs_include) return ms.tc.vs_include.map(p => projectPath(project, p))
  if (ms.mode === 'native') return (process.env.INCLUDE || '').split(';').filter(Boolean)
  const env = ms.env
  const prefix = env.MSVC_PREFIX !== undefined ? env.MSVC_PREFIX : expanduser('~/.wine-vs2010')
  const vs = env.MSVC_VS !== undefined ? env.MSVC_VS : 'C:\\Program Files (x86)\\Microsoft Visual Studio 10.0'
  const sdk = env.MSVC_SDK !== undefined ? env.MSVC_SDK : 'C:\\Program Files (x86)\\Microsoft SDKs\\Windows\\v7.1'
  const unix = p => join(prefix, 'drive_c', p.slice(3).replaceAll('\\', '/'))
  return [unix(vs) + '/VC/include', unix(sdk) + '/Include']
}
export function commonRoot (paths) { return commonpath(paths.map(abspath)) }
export function relwin (root, p) { return relpath(abspath(p), root).replaceAll('/', '\\') }

// ------------------------------------------------------------------------------------------- arguments
export const REQUIRED = Symbol('required')
const INT_RE = /^-?[0-9]+$/
const FLOAT_RE = /^-?[0-9]+(\.[0-9]+)?$/
export { INT_RE }
class ArgError extends Error {}

export function parseArgs (prog, doc, argv, options, positionals = []) {
  try {
    return parse(argv, options, positionals, doc)
  } catch (e) {
    if (!(e instanceof ArgError)) throw e
    process.stderr.write(`${prog}: error: ${e.message}\n`)
    process.exit(2)
  }
}
const keyOf = f => f.replace(/^-+/, '').replaceAll('-', '_')
function parse (argv, options, positionals, doc) {
  const spec = new Map(options.map(([f, k, d]) => [f, [k, d]]))
  const out = {}
  for (const [f, k, d] of options) out[keyOf(f)] = k === 'list' ? [] : k === 'flag' ? false : d === REQUIRED ? null : d
  const pos = []
  let i = 0
  while (i < argv.length) {
    const a = argv[i]
    if (a === '-h' || a === '--help') {
      process.stdout.write(doc.trim() + '\n')
      process.exit(0)
    }
    if (a.startsWith('--') && a.length > 2) {
      const eqi = a.indexOf('=')
      const flag = eqi < 0 ? a : a.slice(0, eqi)
      const eq = eqi >= 0
      let val = eq ? a.slice(eqi + 1) : null
      if (!spec.has(flag)) throw new ArgError(`unknown option ${flag}`)
      const kind = spec.get(flag)[0]
      const key = flag.slice(2).replaceAll('-', '_')
      if (kind === 'flag') {
        if (eq) throw new ArgError(`option ${flag} takes no value`)
        out[key] = true
        i += 1
        continue
      }
      if (!eq) {
        if (i + 1 >= argv.length) throw new ArgError(`option ${flag} needs a value`)
        val = argv[i + 1]
        i += 1
      }
      i += 1
      if (kind === 'int') {
        if (!INT_RE.test(val)) throw new ArgError(`option ${flag}: not an integer: ${val}`)
        val = parseInt(val, 10)
      } else if (kind === 'float') {
        if (!FLOAT_RE.test(val)) throw new ArgError(`option ${flag}: not a number: ${val}`)
        val = new PyFloat(parseFloat(val))
      }
      if (kind === 'list') out[key].push(val)
      else out[key] = val
      continue
    }
    pos.push(a)
    i += 1
  }
  for (const [f, , d] of options) if (d === REQUIRED && out[keyOf(f)] === null) throw new ArgError(`missing ${f}`)
  let n = 0
  for (const [name, nargs] of positionals) {
    if (nargs === '1') {
      if (n >= pos.length) throw new ArgError(`missing argument ${name}`)
      out[name] = pos[n++]
    } else if (nargs === '?') {
      out[name] = n < pos.length ? pos[n++] : null
    } else {
      const rest = pos.slice(n)
      if (nargs === '+' && !rest.length) throw new ArgError(`missing argument ${name}`)
      out[name] = rest
      n = pos.length
    }
  }
  if (n < pos.length) throw new ArgError(`too many arguments: ${pos.slice(n).join(' ')}`)
  return out
}

// ------------------------------------------------------------------------- Python-compatible values
// A float that must print as a Python float (17.0, not 17). Arithmetic: use .v.
export class PyFloat { constructor (v) { this.v = Number(v) } valueOf () { return this.v } }
export const num = x => (x instanceof PyFloat ? x.v : x)

export function floatRepr (x) {
  if (Number.isNaN(x)) return 'nan'
  if (x === Infinity) return 'inf'
  if (x === -Infinity) return '-inf'
  if (x === 0) return Object.is(x, -0) ? '-0.0' : '0.0'
  const m = x.toExponential().match(/^(-?)(\d)(?:\.(\d+))?e([+-]\d+)$/)
  const sign = m[1]; const digits = m[2] + (m[3] || ''); const e = parseInt(m[4], 10)
  if (e >= -4 && e < 16) {
    if (e < 0) return sign + '0.' + '0'.repeat(-e - 1) + digits
    if (digits.length <= e + 1) return sign + digits + '0'.repeat(e + 1 - digits.length) + '.0'
    return sign + digits.slice(0, e + 1) + '.' + digits.slice(e + 1)
  }
  const mant = digits.length > 1 ? digits[0] + '.' + digits.slice(1) : digits
  return sign + mant + 'e' + (e < 0 ? '-' : '+') + String(Math.abs(e)).padStart(2, '0')
}
// round(x, 1) as a Python float (only used for timings)
export const round1 = x => new PyFloat(Math.round(x * 10) / 10)

function jsonStr (s) {
  let out = '"'
  for (const ch of s) {
    const c = ch.codePointAt(0)
    if (ch === '"') out += '\\"'
    else if (ch === '\\') out += '\\\\'
    else if (ch === '\n') out += '\\n'
    else if (ch === '\r') out += '\\r'
    else if (ch === '\t') out += '\\t'
    else if (ch === '\b') out += '\\b'
    else if (ch === '\f') out += '\\f'
    else if (c >= 0x20 && c <= 0x7e) out += ch
    else if (c > 0xffff) {
      const v = c - 0x10000
      out += '\\u' + (0xd800 + (v >> 10)).toString(16).padStart(4, '0') + '\\u' + (0xdc00 + (v & 0x3ff)).toString(16).padStart(4, '0')
    } else out += '\\u' + c.toString(16).padStart(4, '0')
  }
  return out + '"'
}
// json.dumps(obj, indent=1)
export function dumps (obj, level = 0) {
  const ind = ' '.repeat(level + 1); const end = ' '.repeat(level)
  if (obj === null || obj === undefined) return 'null'
  if (obj === true) return 'true'
  if (obj === false) return 'false'
  if (obj instanceof PyFloat) return floatRepr(obj.v)
  if (typeof obj === 'number') return Number.isInteger(obj) ? String(obj) : floatRepr(obj)
  if (typeof obj === 'bigint') return obj.toString()
  if (typeof obj === 'string') return jsonStr(obj)
  if (Array.isArray(obj)) {
    if (!obj.length) return '[]'
    return '[\n' + obj.map(v => ind + dumps(v, level + 1)).join(',\n') + '\n' + end + ']'
  }
  const entries = obj instanceof Map ? [...obj.entries()] : Object.entries(obj)
  if (!entries.length) return '{}'
  return '{\n' + entries.map(([k, v]) => ind + jsonStr(String(k)) + ': ' + dumps(v, level + 1)).join(',\n') + '\n' + end + '}'
}
// JSON parser that keeps floats as PyFloat (so 17.0 prints back as 17.0)
export function pyParse (text) {
  let i = 0
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++ }
  const err = msg => { throw new SyntaxError(`${msg} at offset ${i}`) }
  function value () {
    ws()
    const c = text[i]
    if (c === '{') {
      i++; const o = {}; ws()
      if (text[i] === '}') { i++; return o }
      for (;;) {
        ws(); if (text[i] !== '"') err('expected string'); const k = str(); ws()
        if (text[i++] !== ':') err('expected :')
        o[k] = value(); ws()
        if (text[i] === ',') { i++; continue }
        if (text[i] === '}') { i++; return o }
        err('expected , or }')
      }
    }
    if (c === '[') {
      i++; const a = []; ws()
      if (text[i] === ']') { i++; return a }
      for (;;) {
        a.push(value()); ws()
        if (text[i] === ',') { i++; continue }
        if (text[i] === ']') { i++; return a }
        err('expected , or ]')
      }
    }
    if (c === '"') return str()
    if (text.startsWith('true', i)) { i += 4; return true }
    if (text.startsWith('false', i)) { i += 5; return false }
    if (text.startsWith('null', i)) { i += 4; return null }
    if (text.startsWith('NaN', i)) { i += 3; return new PyFloat(NaN) }
    if (text.startsWith('Infinity', i)) { i += 8; return new PyFloat(Infinity) }
    if (text.startsWith('-Infinity', i)) { i += 9; return new PyFloat(-Infinity) }
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i, i + 400))
    if (!m) err('unexpected character')
    i += m[0].length
    if (m[2] || m[3]) return new PyFloat(parseFloat(m[0]))
    const n = Number(m[0])
    return Number.isSafeInteger(n) ? n : BigInt(m[0])
  }
  function str () {
    i++
    let s = ''
    for (;;) {
      const c = text[i++]
      if (c === undefined) err('unterminated string')
      if (c === '"') return s
      if (c === '\\') {
        const e = text[i++]
        if (e === 'u') { s += String.fromCharCode(parseInt(text.slice(i, i + 4), 16)); i += 4 } else s += { b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', '"': '"', '\\': '\\', '/': '/' }[e]
      } else s += c
    }
  }
  const v = value(); ws()
  if (i < text.length) err('extra data')
  return v
}

// %-Ns / %Ns / %.1f helpers for the printf-style lines the Python side writes
export const ljust = (s, n) => String(s).padEnd(n)
export const rjust = (s, n) => String(s).padStart(n)
export const pyStr = v => v === null || v === undefined ? 'None' : v === true ? 'True' : v === false ? 'False'
  : v instanceof PyFloat ? floatRepr(v.v) : String(v)
export const f1 = x => num(x).toFixed(1)

export function sha256File (p) { return createHash('sha256').update(fs.readFileSync(p)).digest('hex') }

// ------------------------------------------------------------------------------------------- running
export function runnerMode (rw, arg = null) {
  return arg || get(rw, 'runner') || (process.platform === 'win32' ? 'native' : 'wine')
}
export function runEnv (project, rw, mode) {
  const env = Object.assign({}, process.env)
  if (mode === 'wine') {
    env.WINEPREFIX = process.env.WINEPREFIX || projectPath(project, get(rw, 'wineprefix', '~/.wine'))
    if (env.WINEDEBUG === undefined) env.WINEDEBUG = '-all'
    if (env.MVK_CONFIG_LOG_LEVEL === undefined) env.MVK_CONFIG_LOG_LEVEL = '0'
  }
  for (const [k, v] of Object.entries(get(rw, 'extra_env') || {})) env[k] = v
  return env
}
export function exeCommand (mode, exeName, cwd, args) {
  if (mode === 'wine') return [process.env.WINE || 'wine', exeName, ...args]
  return [join(cwd, exeName), ...args]
}
export function wineserverKill (mode, env) {
  if (mode === 'wine') spawnSync(process.env.WINESERVER || 'wineserver', ['-k'], { env, stdio: 'ignore' })
}

// --------------------------------------------------------------------------------------------- files
export function winpath (p, native = false) {
  p = abspath(p)
  return native ? p : 'Z:' + p.replaceAll('/', '\\')
}
export function clone (src, dst) {
  if (process.platform === 'darwin') {
    const r = spawnSync('cp', ['-c', src, dst], { stdio: 'ignore' })
    if (r.status === 0) return
  }
  fs.copyFileSync(src, dst)
  const st = fs.statSync(src)
  fs.utimesSync(dst, st.atime, st.mtime)
}
export function copy2 (src, dst) {
  if (isdir(dst)) dst = join(dst, basename(src))
  fs.copyFileSync(src, dst)
  const st = fs.statSync(src)
  fs.chmodSync(dst, st.mode & 0o7777)
  fs.utimesSync(dst, st.atime, st.mtime)
}
export function copytree (src, dst) {
  makedirs(dst)
  for (const n of listdirSorted(src)) {
    const s = join(src, n); const d = join(dst, n)
    if (isdir(s)) copytree(s, d)
    else copy2(s, d)
  }
}
export function copyTree (src, dst, skipExt = []) {
  const walk = (rel) => {
    const dir = rel === '.' ? src : join(src, rel)
    makedirs(rel === '.' ? dst : join(dst, rel))
    const names = listdirSorted(dir)
    for (const n of names) {
      const p = join(dir, n)
      const r = rel === '.' ? n : join(rel, n)
      if (isdir(p)) continue
      if (skipExt.length && skipExt.some(e => n.endsWith(e))) continue
      const d = join(dst, r)
      clone(p, d)
      fs.chmodSync(d, 0o644)
    }
    for (const n of names) {
      const r = rel === '.' ? n : join(rel, n)
      if (isdir(join(dir, n))) walk(r)
    }
  }
  walk('.')
}

// ---------------------------------------------------------------------------------- replay and trace
const META_RE = /^\s*#!\s*(\w+)\s*=\s*(\S+)/
export function scenarioMeta (p) {
  const meta = {}
  for (const line of fs.readFileSync(p, 'utf8').split(/(?<=\n)/)) {
    const m = META_RE.exec(line)
    if (m) meta[m[1]] = m[2]
  }
  return meta
}
export function traceFrames (p, header = null, frameField = 'f') {
  if (!fs.existsSync(p)) return [false, 0, -1]
  const lines = fs.readFileSync(p).toString('utf8').split('\n')
  const first = lines.length ? lines[0].replace(/\r$/, '') : ''
  const ok = Boolean(first) && (header === null || first === header)
  const pre = frameField + '='
  const body = lines.slice(1).filter(l => l.startsWith(pre))
  let last = -1
  if (body.length) {
    const sp = body[body.length - 1].indexOf(' ')
    const tok = (sp < 0 ? body[body.length - 1] : body[body.length - 1].slice(0, sp)).slice(pre.length).replace(/\r$/, '')
    last = INT_RE.test(tok) ? parseInt(tok, 10) : -1
  }
  return [ok, body.length, last]
}
export function splitlines (s) {
  const out = s.split(/\r\n|\r|\n/)
  if (out.length && out[out.length - 1] === '') out.pop()
  return out
}

// ------------------------------------------------------------------------------------------- windows
const JXA = `ObjC.import('CoreGraphics'); ObjC.import('Foundation');
var a = ObjC.castRefToObject($.CGWindowListCopyWindowInfo(17, 0)); var out = [];
for (var i = 0; i < a.count; i++) { var d = a.objectAtIndex(i);
  var o = d.objectForKey('kCGWindowOwnerName'); var n = d.objectForKey('kCGWindowName');
  out.push([o.isNil() ? '' : o.js, n.isNil() ? '' : n.js]); }
JSON.stringify(out)`
export function windowTitles (ownerPrefix = 'wine') {
  if (process.platform === 'darwin') {
    const r = spawnSync('osascript', ['-l', 'JavaScript', '-e', JXA], { encoding: 'utf8' })
    if (r.status !== 0) return []
    return JSON.parse(r.stdout).filter(([o]) => o.toLowerCase().startsWith(ownerPrefix)).map(([, n]) => n)
  }
  if (process.platform === 'win32') {
    const r = spawnSync('powershell', ['-NoProfile', '-Command',
      'Get-Process | Where-Object { $_.MainWindowTitle } | ForEach-Object { $_.MainWindowTitle }'], { encoding: 'utf8' })
    return splitlines(r.stdout || '')
  }
  return null
}

export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

// true when the module is the script node was started with
export function isMain (url) {
  try { return fs.realpathSync(fileURLToPath(url)) === fs.realpathSync(process.argv[1]) } catch { return false }
}
export function signalNumber (sig) { return os.constants.signals[sig] || 0 }
