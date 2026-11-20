#!/usr/bin/env node
// Port of ../build_libs.py (same commands, output and files). Node built-ins only.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import * as L from './lib/rwlib.mjs'
import { readTar, readZip } from './lib/archive.mjs'
import { coffDefinedExternals, peExports } from './wintools.mjs'

const PROG = 'build_libs'
const DOC = "Fetch, unpack and build the upstream libraries a rewrite links, at the versions pinned in step 1.\n\n  python3 -I build_libs.py list    [--project DIR] [--libraries FILE]\n  python3 -I build_libs.py fetch   [--only A,B] [--check]\n  python3 -I build_libs.py extract [--only A,B] [--force]\n  python3 -I build_libs.py build   [--flavour static|dll|all] [--only A,B] [--keep-obj]\n  python3 -I build_libs.py runtime [--defs DIR]\n\nThe libraries are listed in a JSON file (--libraries, else decomp.json rewrite.libraries, else\nrewrite/libraries.json; format: references/toolchains.md \"libraries.json\"). Folders come from\nrewrite.paths: downloads (default rewrite/third_party/downloads), src (rewrite/third_party/src), build\n(rewrite/third_party/build).\n  list     one line per library: name, version, commit, kind, archive, whether it is downloaded\n  fetch    download every missing archive from its url and check its sha256 (--check: only check what is\n           there). A library without a pinned sha256 is downloaded, reported \"unpinned\" with the digest,\n           and fails the command: pin it after checking the source. file:// URLs are copied.\n  extract  unpack each archive (.tar.gz/.tgz/.tar/.zip; any other file is copied as \"file\") into\n           <src>/<dir>, dropping a single top folder (\"strip\": \"auto\", or a number of path components);\n           refuses absolute paths and \"..\", skips links. Existing folders are kept unless --force.\n  build    flavour \"static\": one /MT .lib per library into <build>/static/{lib,include} (the C++ rewrite);\n           flavour \"dll\": one DLL per library with its own static CRT into <build>/dll/{bin,lib,include}\n           (the Rust rewrite binds them with raw-dylib). Prebuilt libraries are copied (static_libs,\n           dlls). \"c\"/\"c++\" sources compile with cl (through this skill's msvc.sh under Wine, or\n           directly on Windows), \"c99\" sources with clang --target=i686-pc-windows-msvc against the MSVC\n           headers (an old cl is C89).\n  runtime  the i686-pc-windows-gnu runtime for Rust without MinGW into <build>/rust-gnu/rtlib: crt_shim.c\n           (clang) as libmingw32.a, import libraries from the .def files in --defs (default\n           <build>/rust-gnu/defs, seeded from this skill's rust_gnu/defs), empty stand-ins for the rest.\nEnv: MSVC_SH, MSVC_PREFIX/MSVC_VS/MSVC_SDK (as msvc.sh), CLANG (default clang), RUST_LLD (else found\nthrough RUSTC / rustc). Exit 0 when everything asked for worked. Python standard library only."
const HERE = L.SCRIPTS
const CL_DEFAULT = ['/nologo', '/c', '/O2', '/MT', '/W0', '/DNDEBUG', '/DWIN32', '/D_WINDOWS', '/D_CRT_SECURE_NO_WARNINGS']
const CLANG_DEFAULT = ['-fms-compatibility-version=16.00', '-fms-runtime-lib=static', '-fno-addrsig', '-O2', '-c', '-w',
  '-DNDEBUG', '-DWIN32', '-D_WINDOWS', '-D_CRT_SECURE_NO_WARNINGS']
const DLL_LINK_DEFAULT = ['/nologo', '/DLL', '/OPT:REF', '/OPT:ICF', '/DYNAMICBASE', '/NXCOMPAT']
const DLL_SYSLIBS_DEFAULT = ['kernel32.lib', 'user32.lib', 'shell32.lib', 'advapi32.lib']
const EMPTY_RT = ['mingwex', 'gcc', 'gcc_eh', 'gcc_s', 'pthread', 'dbghelp', 'bcrypt', 'advapi32', 'user32', 'shell32', 'ole32']

class Fail extends Error {}
const log = msg => process.stdout.write(msg + '\n')
const relProj = (p, project) => L.relpath(p, project)

function archiveKind (name) {
  const n = name.toLowerCase()
  if (n.endsWith('.tar.gz') || n.endsWith('.tgz')) return 'tar.gz'
  if (n.endsWith('.tar')) return 'tar'
  if (n.endsWith('.zip')) return 'zip'
  return 'file'
}
function safeRel (name) {
  name = name.replaceAll('\\', '/')
  if (name.startsWith('/') || (name.length > 1 && name[1] === ':')) return null
  const parts = name.split('/').filter(p => p !== '' && p !== '.')
  if (parts.some(p => p === '..')) return null
  return parts
}

class Ctx {
  constructor (a) {
    this.project = a.project
    const [cfg, rw] = L.loadConfig(this.project)
    this.cfg = cfg; this.rw = rw
    const libFile = a.libraries || L.projectPath(this.project, rw.libraries || 'rewrite/libraries.json')
    if (!fs.existsSync(libFile)) throw new Fail(`no libraries file ${libFile} (--libraries or decomp.json rewrite.libraries)`)
    this.spec = L.pyParse(fs.readFileSync(libFile, 'utf8'))
    this.libs = this.spec.libraries || []
    const names = this.libs.map(l => l.name)
    if (a.only) {
      const want = a.only.split(',').map(x => x.trim()).filter(Boolean)
      for (const w of want) if (!names.includes(w)) throw new Fail(`unknown library ${w} (have: ${names.join(', ')})`)
      this.libs = this.libs.filter(l => want.includes(l.name))
    }
    const p = rw.paths || {}
    this.downloads = L.projectPath(this.project, p.downloads || 'rewrite/third_party/downloads')
    this.src = L.projectPath(this.project, p.src || 'rewrite/third_party/src')
    this.build = L.projectPath(this.project, p.build || 'rewrite/third_party/build')
    this.defaults = this.spec.defaults || {}
  }

  libdir (lib) { return L.join(this.src, lib.dir || lib.name) }
  expand (lib, p) {
    for (const [k, v] of [['{skill}', HERE], ['{src}', this.src], ['{project}', L.abspath(this.project)], ['{build}', this.build]]) {
      if (p.startsWith(k)) return L.normpath(v + p.slice(k.length))
    }
    return p.startsWith('/') ? p : L.normpath(L.join(this.libdir(lib), p))
  }

  archive (lib) {
    const name = lib.archive || lib.url.replace(/\/+$/, '').split('/').pop()
    return L.join(this.downloads, name)
  }
}

function cmdList (c) {
  const row = (...v) => log(`${L.ljust(v[0], 14)} ${L.ljust(v[1], 10)} ${L.ljust(v[2], 12)} ${L.ljust(v[3], 9)} ${L.ljust(v[4], 44)} ${v[5]}`)
  row('name', 'version', 'commit', 'kind', 'archive', 'downloaded')
  for (const lib of c.libs) {
    let kind = lib.kind || 'source'
    if (kind === 'source') kind = lib.lang || 'c'
    const arch = lib.url ? c.archive(lib) : null
    row(lib.name, lib.version || '-', (lib.commit || '-').slice(0, 12), kind, arch ? L.basename(arch) : '-',
      arch ? (fs.existsSync(arch) ? 'yes' : 'no') : '-')
  }
  return 0
}

async function download (url, dst) {
  const tmp = dst + '.part'
  if (url.startsWith('file://')) fs.copyFileSync(url.slice('file://'.length), tmp)
  else {
    const r = await fetch(url, { headers: { 'User-Agent': 'build_libs' }, signal: AbortSignal.timeout(120000) })
    if (!r.ok) throw new Error(`HTTP Error ${r.status}: ${r.statusText}`)
    fs.writeFileSync(tmp, Buffer.from(await r.arrayBuffer()))
  }
  fs.renameSync(tmp, dst)
}

async function cmdFetch (c, check) {
  L.makedirs(c.downloads)
  const rows = []; let ok = true
  for (const lib of c.libs) {
    if (!lib.url) continue
    const p = c.archive(lib)
    const row = new Map([['name', lib.name], ['archive', L.basename(p)]])
    if (!fs.existsSync(p)) {
      if (check) { row.set('status', 'missing'); ok = false; rows.push(row); continue }
      try {
        await download(lib.url, p)
      } catch (e) {
        row.set('status', `download failed: ${e.message}`); ok = false; rows.push(row); continue
      }
      row.set('downloaded', true)
    }
    const digest = L.sha256File(p)
    row.set('bytes', fs.statSync(p).size)
    row.set('sha256', digest)
    const want = lib.sha256
    if (!want) { row.set('status', 'unpinned'); ok = false } else if (want.toLowerCase() === digest) row.set('status', 'ok')
    else { row.set('status', `MISMATCH (pinned ${want})`); ok = false }
    rows.push(row)
  }
  log(L.dumps(new Map([['ok', ok], ['libraries', rows]])))
  return ok ? 0 : 1
}

function membersOf (p, kind) {
  const out = []; let skipped = 0
  const raw = fs.readFileSync(p)
  const items = kind === 'zip' ? readZip(raw) : readTar(raw, kind === 'tar.gz')
  for (const m of items) {
    const parts = safeRel(m.name)
    if (parts === null) throw new Fail(`${L.basename(p)}: unsafe member path ${m.name}`)
    if (m.kind === 'dir') out.push([parts, null])
    else if (m.kind === 'file') out.push([parts, m.data])
    else skipped++
  }
  return [out, skipped]
}
function stripCount (members, strip) {
  if (strip !== 'auto') return parseInt(String(strip), 10)
  const tops = new Set(members.filter(([p]) => p.length).map(([p]) => p[0]))
  const deep = members.filter(([p]) => p.length).every(([p, data]) => p.length > 1 || data === null)
  return tops.size === 1 && deep && members.some(([, data]) => data !== null) ? 1 : 0
}

function cmdExtract (c, force) {
  const rows = []; let ok = true
  for (const lib of c.libs) {
    if (!lib.url) continue
    const p = c.archive(lib); const dst = c.libdir(lib)
    const row = new Map([['name', lib.name], ['dir', L.relpath(dst, c.src)]])
    if (!fs.existsSync(p)) { row.set('status', 'missing archive'); ok = false; rows.push(row); continue }
    if (L.isdir(dst) && !force) { row.set('status', 'present'); rows.push(row); continue }
    if (L.isdir(dst)) L.rmtree(dst)
    L.makedirs(dst)
    const kind = archiveKind(p)
    if (kind === 'file') {
      fs.copyFileSync(p, L.join(dst, lib.file || L.basename(p)))
      row.set('status', 'copied'); row.set('files', 1); rows.push(row); continue
    }
    const [members, skipped] = membersOf(p, kind)
    const n = stripCount(members, lib.strip !== undefined ? lib.strip : 'auto')
    let files = 0
    for (let [parts, data] of members) {
      parts = parts.slice(n)
      if (!parts.length) continue
      const target = L.join(dst, ...parts)
      if (data === null) { L.makedirs(target); continue }
      L.makedirs(L.dirname(target))
      fs.writeFileSync(target, data)
      files++
    }
    row.set('status', 'extracted'); row.set('files', files); row.set('stripped', n); row.set('skipped_links', skipped)
    rows.push(row)
  }
  log(L.dumps(new Map([['ok', ok], ['libraries', rows]])))
  return ok ? 0 : 1
}

// glob with * and ? in the last path component only (what libraries.json header patterns use)
function globLast (pattern) {
  const dir = L.dirname(pattern) || '.'; const base = L.basename(pattern)
  if (!/[*?[]/.test(base)) return fs.existsSync(pattern) ? [pattern] : []
  if (!L.isdir(dir)) return []
  const re = new RegExp('^' + base.replace(/[.+^${}()|\\]/g, '\\$&').replaceAll('*', '.*').replaceAll('?', '.') + '$')
  return fs.readdirSync(dir).filter(n => re.test(n) && !(n.startsWith('.') && !base.startsWith('.'))).map(n => L.join(dir, n))
}

class Builder {
  constructor (c, keepObj) {
    this.c = c; this.keepObj = keepObj
    this.ms = L.msvcSetup(c.project, c.cfg, c.rw)
    if (this.ms.mode === 'wine' && !(this.ms.msvc_sh && fs.existsSync(this.ms.msvc_sh))) {
      throw new Fail('msvc.sh not found (set MSVC_SH or rewrite.toolchain.msvc_sh)')
    }
    this.root = L.commonRoot([c.src, c.build, HERE])
    this.clang = process.env.CLANG || 'clang'
    this.machine = this.ms.machine
    this.compat = L.join(HERE, 'msvc_compat')
  }

  rel (p) { return L.relwin(this.root, p) }
  tool (name, args) {
    const [rc, lines] = L.runTool(L.msvcCmd(this.ms, name, args), this.root, this.ms.env)
    if (lines.length) log(lines.join('\n'))
    if (rc !== 0) throw new Fail(`${name} failed (exit ${rc})`)
  }

  compile (lib, objdir, dll) {
    const c = this.c
    L.makedirs(objdir)
    const defines = [...(lib.defines || []), ...(lib[dll ? 'dll_defines' : 'static_defines'] || [])]
    let incs = [...(lib.incs || []).map(d => c.expand(lib, d)), ...(dll ? (lib.dll_incs || []).map(d => c.expand(lib, d)) : [])]
    const srcs = (lib.srcs || []).map(s => c.expand(lib, s))
    const extra = dll ? (lib.dll_srcs || []).map(s => c.expand(lib, s)) : []
    const seen = new Set()
    for (const s of [...srcs, ...extra]) {
      const stem = L.splitext(L.basename(s))[0].toLowerCase()
      if (seen.has(stem)) throw new Fail(`${lib.name}: two sources named ${stem} (objects would collide)`)
      seen.add(stem)
    }
    incs = [...incs, ...[...new Set([...srcs, ...extra].map(s => L.dirname(s)))].sort(L.cmp)]
    const all = [...srcs, ...extra]
    const objs = all.map(s => L.join(objdir, L.splitext(L.basename(s))[0] + '.obj'))
    const lang = lib.lang || 'c'
    if (lang === 'c99') {
      const target = this.machine === 'x64' ? 'x86_64-pc-windows-msvc' : 'i686-pc-windows-msvc'
      const cmd = [this.clang, '--target=' + target, ...(c.defaults.clang || CLANG_DEFAULT)]
      for (const d of L.vsIncludeDirs(this.ms, c.project)) cmd.push('-isystem', d)
      for (const i of incs) cmd.push('-I', i)
      cmd.push(...defines.map(d => '-D' + d))
      all.forEach((s, k) => {
        const [rc, lines] = L.runTool([...cmd, '-o', objs[k], s], this.root)
        if (lines.length) log(lines.join('\n'))
        if (rc !== 0) throw new Fail(`clang failed on ${L.basename(s)} (exit ${rc})`)
      })
      return objs
    }
    const flags = [...(c.defaults.cl || CL_DEFAULT), '/I' + this.rel(this.compat), ...incs.map(i => '/I' + this.rel(i)),
      ...defines.map(d => '/D' + d), '/Fo' + this.rel(objdir) + '\\']
    const groups = srcs.length ? [[{ c: '/TC', 'c++': '/TP' }[lang], srcs]] : []
    for (const s of extra) groups.push([['.cpp', '.cc', '.cxx'].some(e => s.endsWith(e)) ? '/TP' : '/TC', [s]])
    for (const [lf, files] of groups) this.tool('cl', [...flags, lf, ...(lf === '/TP' ? ['/EHsc'] : []), ...files.map(f => this.rel(f))])
    return objs
  }

  installHeaders (lib, incdir, dll) {
    const items = [...Object.entries(lib.headers || {}), ...(dll ? Object.entries(lib.dll_headers || {}) : [])]
    for (const [pattern, sub0] of items) {
      const [sub, newname] = Array.isArray(sub0) ? [sub0[0], sub0[1]] : [sub0, null]
      const dst = L.join(incdir, sub)
      L.makedirs(dst)
      for (const f of globLast(this.c.expand(lib, pattern)).sort(L.cmp)) fs.copyFileSync(f, L.join(dst, newname || L.basename(f)))
    }
  }

  generate (incdir) {
    for (const [name, lines] of Object.entries(this.c.spec.generate || {}).sort((x, y) => L.cmp(x[0], y[0]))) {
      fs.writeFileSync(L.join(incdir, name), lines.join('\n') + '\n')
    }
  }

  copyPrebuilt (lib, key, dst) {
    L.makedirs(dst)
    for (const p of lib[key] || []) fs.copyFileSync(this.c.expand(lib, p), L.join(dst, L.basename(p)))
  }

  buildStatic () {
    const base = L.join(this.c.build, 'static')
    const [libdir, incdir, bindir] = ['lib', 'include', 'bin'].map(x => L.join(base, x))
    for (const d of [libdir, incdir]) L.makedirs(d)
    for (const lib of this.c.libs) {
      if ((lib.kind || 'source') === 'prebuilt') {
        log(`[static] ${lib.name} (prebuilt)`)
        this.copyPrebuilt(lib, 'static_libs', libdir)
        this.copyPrebuilt(lib, 'dlls', bindir)
        continue
      }
      log(`[static] ${lib.name}`)
      if (lib.kind !== 'headers') {
        const objs = this.compile(lib, L.join(base, 'obj', lib.name), false)
        const out = L.join(libdir, lib.lib || lib.name + '.lib')
        this.tool('lib', ['/nologo', '/MACHINE:' + this.machine.toUpperCase(), '/OUT:' + this.rel(out), ...objs.map(o => this.rel(o))])
      }
      this.installHeaders(lib, incdir, false)
    }
    this.generate(incdir)
    if (!this.keepObj) L.rmtree(L.join(base, 'obj'))
    log(`[static] -> ${relProj(libdir, this.c.project)}`)
  }

  dllExports (lib, objs) {
    const exp = lib.exports !== undefined ? lib.exports : 'declspec'
    if (exp === 'declspec') return []
    const out = new Set()
    for (const o of objs) {
      for (const [sym, isFunc] of coffDefinedExternals(fs.readFileSync(o), true)) {
        if (exp.some(pre => sym.startsWith(pre))) {
          const name = this.machine === 'x86' && sym.startsWith('_') ? sym.slice(1) : sym
          out.add('/EXPORT:' + name + (isFunc ? '' : ',DATA'))
        }
      }
    }
    return [...out].sort(L.cmp)
  }

  buildDll () {
    const base = L.join(this.c.build, 'dll')
    const [bindir, libdir, incdir] = ['bin', 'lib', 'include'].map(x => L.join(base, x))
    for (const d of [bindir, libdir, incdir]) L.makedirs(d)
    const syslibs = this.c.defaults.dll_syslibs || DLL_SYSLIBS_DEFAULT
    for (const lib of this.c.libs) {
      const kind = lib.kind || 'source'
      if (kind === 'prebuilt') {
        log(`[dll] ${lib.name} (prebuilt)`)
        this.copyPrebuilt(lib, 'dlls', bindir)
        this.copyPrebuilt(lib, 'static_libs', libdir)
        continue
      }
      if (kind === 'headers') {
        log(`[dll] ${lib.name} (headers)`)
        this.installHeaders(lib, incdir, true)
        continue
      }
      const dllname = lib.dll || lib.name + '.dll'
      log(`[dll] ${lib.name} -> ${dllname}`)
      const objdir = L.join(base, 'obj', lib.name)
      const objs = this.compile(lib, objdir, true)
      const dll = L.join(bindir, dllname)
      const implib = L.join(libdir, L.splitext(dllname)[0] + '.lib')
      const args = [...(this.c.defaults.dll_link || DLL_LINK_DEFAULT), '/MACHINE:' + this.machine.toUpperCase(),
        '/OUT:' + this.rel(dll), '/IMPLIB:' + this.rel(implib), ...this.dllExports(lib, objs),
        ...objs.map(o => this.rel(o)), ...(lib.dll_libs || []).map(l => this.rel(this.c.expand(lib, l)))]
      this.tool('link', [...args, ...syslibs])
      const exp = L.splitext(implib)[0] + '.exp'
      if (fs.existsSync(exp)) fs.rmSync(exp)
      this.installHeaders(lib, incdir, true)
      log(`    exports: ${peExports(dll).length}`)
    }
    this.generate(incdir)
    if (!this.keepObj) L.rmtree(L.join(base, 'obj'))
    log(`[dll] -> ${relProj(bindir, this.c.project)}`)
  }
}

function rustLld () {
  if (process.env.RUST_LLD) return process.env.RUST_LLD
  const homeRustc = L.expanduser('~/.cargo/bin/rustc')
  const rustc = process.env.RUSTC || (fs.existsSync(homeRustc) ? homeRustc : 'rustc')
  const sysroot = spawnSync(rustc, ['--print', 'sysroot'], { encoding: 'utf8' }).stdout.trim()
  const host = spawnSync(rustc, ['-vV'], { encoding: 'utf8' }).stdout.split('\n').find(l => l.startsWith('host: ')).split(': ')[1]
  return L.join(sysroot, 'lib', 'rustlib', host, 'bin', 'rust-lld')
}

function cmdRuntime (c, defs) {
  const rtlib = L.join(c.build, 'rust-gnu', 'rtlib')
  defs = defs || L.join(c.build, 'rust-gnu', 'defs')
  if (!L.isdir(defs)) L.copytree(L.join(HERE, 'rust_gnu', 'defs'), defs)
  log(`[rust-gnu] runtime -> ${relProj(rtlib, c.project)}`)
  const lld = rustLld()
  const clang = process.env.CLANG || 'clang'
  if (L.isdir(rtlib)) L.rmtree(rtlib)
  L.makedirs(rtlib)
  const run = cmd => {
    const [rc, lines] = L.runTool(cmd, rtlib)
    if (lines.length) log(lines.join('\n'))
    if (rc) throw new Fail(`failed (exit ${rc}): ${cmd.join(' ')}`)
  }
  const shim = L.join(rtlib, 'crt_shim.o')
  run([clang, '--target=i686-w64-windows-gnu', '-c', '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
    '-Wall', '-o', shim, L.join(HERE, 'rust_gnu', 'crt_shim.c')])
  run([lld, '-flavor', 'link', '/lib', '/machine:x86', '/out:' + L.join(rtlib, 'libmingw32.a'), shim])
  fs.rmSync(shim)
  const made = ['mingw32']
  for (const d of globLast(L.join(defs, '*.def')).sort(L.cmp)) {
    const n = L.splitext(L.basename(d))[0]
    run([lld, '-flavor', 'link', '/lib', '/machine:x86', '/def:' + d, '/out:' + L.join(rtlib, `lib${n}.a`)])
    made.push(n)
  }
  for (const n of EMPTY_RT) {
    if (!made.includes(n)) {
      run([lld, '-flavor', 'link', '/lib', '/machine:x86', '/llvmlibempty', '/out:' + L.join(rtlib, `lib${n}.a`)])
      made.push(n)
    }
  }
  log(`    ${made.length} libraries: ${made.map(n => `lib${n}.a`).join(' ')}`)
  return 0
}

export async function main (argv) {
  const cmds = ['list', 'fetch', 'extract', 'build', 'runtime']
  if (!argv.length || !cmds.includes(argv[0])) {
    if (argv.length && (argv[0] === '-h' || argv[0] === '--help')) { process.stdout.write(DOC.trim() + '\n'); return 0 }
    process.stderr.write(`${PROG}: error: command must be one of: list, fetch, extract, build, runtime\n`)
    return 2
  }
  const cmd = argv[0]
  const a = L.parseArgs(PROG, DOC, argv.slice(1), [
    ['--project', 'str', '.'], ['--libraries', 'str', null], ['--only', 'str', null], ['--check', 'flag', false],
    ['--force', 'flag', false], ['--flavour', 'str', 'all'], ['--keep-obj', 'flag', false], ['--defs', 'str', null]])
  try {
    const c = new Ctx(a)
    if (cmd === 'list') return cmdList(c)
    if (cmd === 'fetch') return await cmdFetch(c, a.check)
    if (cmd === 'extract') return cmdExtract(c, a.force)
    if (cmd === 'runtime') return cmdRuntime(c, a.defs)
    if (!['static', 'dll', 'all'].includes(a.flavour)) throw new Fail('--flavour must be static, dll or all')
    const b = new Builder(c, a.keep_obj)
    if (a.flavour === 'static' || a.flavour === 'all') b.buildStatic()
    if (a.flavour === 'dll' || a.flavour === 'all') b.buildDll()
    return 0
  } catch (e) {
    if (!(e instanceof Fail)) throw e
    process.stderr.write(`${PROG}: ${e.message}\n`)
    return 1
  }
}

if (L.isMain(import.meta.url)) process.exitCode = await main(process.argv.slice(2))
