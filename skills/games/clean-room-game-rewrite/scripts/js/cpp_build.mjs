#!/usr/bin/env node
// Port of ../cpp_build.py (same command line, output and exit codes). Node built-ins only.
import fs from 'node:fs'
import * as L from './lib/rwlib.mjs'

const PROG = 'cpp_build'
const DOC = "Compile and link a C/C++ program with MSVC (cl/link through this skill's msvc.sh under Wine, or\ndirectly on Windows) against the libraries of `build_libs.py build --flavour static`.\n\n  python3 -I cpp_build.py --out OUT.exe [options] SOURCE...\n  --subsystem S          console (default) or windows; with windows the entry point stays main()\n                         (/ENTRY:mainCRTStartup) unless --winmain is given\n  --winmain              the program defines WinMain\n  --cflag F / --define D / --include DIR    extra cl flag, /D define, /I folder (repeatable)\n  --lib NAME             extra library to link (repeatable), e.g. winmm.lib\n  --no-default-libs      do not link the libraries of libraries.json\n  --debug                /Od /Z7 + /DEBUG instead of /O2\n  --obj-dir DIR          where objects go (default: a temporary folder next to the output, removed afterwards)\n  --project DIR / --libraries FILE    as build_libs.py\nDefault cl flags: /nologo /c /MT /GS /W3 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS /O2 (decomp.json\nrewrite.toolchain.cflags replaces them), .c files as C (/TC), others as C++ (/TP /EHsc); one cl run per\nlanguage (a Wine process start is slow), so two sources must not share a base name. Include folders:\n<build>/static/include, each prebuilt library's \"include\", this skill's msvc_compat. Linked: every library's\n.lib (libraries.json order, prebuilt \"static_libs\" by base name), then rewrite.toolchain.syslibs (default\nkernel32 user32 gdi32 shell32 advapi32 winmm ole32). link writes OUT.lib/OUT.exp when objects carry\ndllexport (libraries built with exported APIs): they are deleted. Prints the output path. Python stdlib only."
const HERE = L.SCRIPTS
const CFLAGS = ['/nologo', '/c', '/MT', '/GS', '/W3', '/DWIN32', '/D_WINDOWS', '/D_CRT_SECURE_NO_WARNINGS']
const SYSLIBS = ['kernel32.lib', 'user32.lib', 'gdi32.lib', 'shell32.lib', 'advapi32.lib', 'winmm.lib', 'ole32.lib']

export function main (argv) {
  const a = L.parseArgs(PROG, DOC, argv, [
    ['--out', 'str', L.REQUIRED], ['--subsystem', 'str', 'console'], ['--winmain', 'flag', false],
    ['--cflag', 'list', null], ['--define', 'list', null], ['--include', 'list', null], ['--lib', 'list', null],
    ['--no-default-libs', 'flag', false], ['--debug', 'flag', false], ['--obj-dir', 'str', null],
    ['--project', 'str', '.'], ['--libraries', 'str', null]], [['sources', '+']])
  if (!['console', 'windows'].includes(a.subsystem)) {
    process.stderr.write(`${PROG}: error: --subsystem must be console or windows\n`)
    return 2
  }
  const project = a.project
  const [cfg, rw] = L.loadConfig(project)
  const ms = L.msvcSetup(project, cfg, rw)
  if (ms.mode === 'wine' && !(ms.msvc_sh && fs.existsSync(ms.msvc_sh))) {
    process.stderr.write(`${PROG}: msvc.sh not found (set MSVC_SH or rewrite.toolchain.msvc_sh)\n`)
    return 1
  }
  const paths = rw.paths || {}
  const srcRoot = L.projectPath(project, paths.src || 'rewrite/third_party/src')
  const build = L.projectPath(project, paths.build || 'rewrite/third_party/build')
  const statik = L.join(build, 'static')
  const libFile = a.libraries || L.projectPath(project, rw.libraries || 'rewrite/libraries.json')
  let libs = []
  if (fs.existsSync(libFile)) libs = L.pyParse(fs.readFileSync(libFile, 'utf8')).libraries || []
  const incs = [...a.include.map(i => L.abspath(i)), L.join(statik, 'include')]
  const linkLibs = []
  for (const lib of libs) {
    const d = L.join(srcRoot, lib.dir || lib.name)
    if (lib.kind === 'prebuilt') {
      if (lib.include) incs.push(L.join(d, lib.include))
      linkLibs.push(...(lib.static_libs || []).map(p => L.basename(p)))
    } else if (lib.kind !== 'headers') linkLibs.push(lib.lib || lib.name + '.lib')
  }
  incs.push(L.join(HERE, 'msvc_compat'))
  const out = L.abspath(a.out)
  L.makedirs(L.dirname(out))
  const srcs = a.sources.map(s => L.abspath(s))
  const stems = srcs.map(s => L.splitext(L.basename(s))[0].toLowerCase())
  const dup = [...new Set(stems.filter(s => stems.indexOf(s) !== stems.lastIndexOf(s)))].sort(L.cmp)
  if (dup.length) {
    process.stderr.write(`${PROG}: sources share a base name (objects would collide): ${dup.join(', ')}\n`)
    return 1
  }
  const tmpObj = a.obj_dir === null
  const objdir = a.obj_dir ? L.abspath(a.obj_dir) : L.mkdtemp('.obj-', L.dirname(out))
  L.makedirs(objdir)
  const root = L.commonRoot([out, objdir, statik, HERE, ...srcs, ...incs])
  const rel = p => L.relwin(root, p)
  const tool = (name, args) => {
    const [rc, lines] = L.runTool(L.msvcCmd(ms, name, args), root, ms.env)
    if (lines.length) process.stdout.write(lines.join('\n') + '\n')
    if (rc !== 0) { process.stderr.write(`${PROG}: ${name} failed (exit ${rc})\n`); return false }
    return true
  }
  let ok = false
  try {
    const opt = a.debug ? ['/Od', '/Z7'] : ['/O2']
    const flags = [...(L.get(rw, 'toolchain.cflags') || CFLAGS), ...opt, ...incs.map(i => '/I' + rel(i)),
      ...a.define.map(d => '/D' + d), ...a.cflag, '/Fo' + rel(objdir) + '\\']
    const cSrcs = srcs.filter(s => s.endsWith('.c'))
    const cppSrcs = srcs.filter(s => !s.endsWith('.c'))
    let good = true
    if (cSrcs.length) good = tool('cl', [...flags, '/TC', ...cSrcs.map(rel)])
    if (good && cppSrcs.length) good = tool('cl', [...flags, '/TP', '/EHsc', ...cppSrcs.map(rel)])
    if (good) {
      const objs = srcs.map(s => L.join(objdir, L.splitext(L.basename(s))[0] + '.obj'))
      const libsArgs = a.no_default_libs ? [] : linkLibs.map(l => rel(L.join(statik, 'lib', l)))
      const largs = ['/nologo', '/MACHINE:' + ms.machine.toUpperCase(), '/SUBSYSTEM:' + a.subsystem.toUpperCase(),
        '/DYNAMICBASE', '/NXCOMPAT', '/OUT:' + rel(out), ...(a.debug ? ['/DEBUG'] : ['/OPT:REF', '/OPT:ICF'])]
      if (a.subsystem === 'windows' && !a.winmain) largs.push('/ENTRY:mainCRTStartup')
      const syslibs = L.get(rw, 'toolchain.syslibs') || SYSLIBS
      good = tool('link', [...largs, ...objs.map(rel), ...libsArgs, ...a.lib, ...syslibs])
    }
    if (good) { process.stdout.write(out + '\n'); ok = true }
  } finally {
    for (const ext of ['.lib', '.exp']) {
      const p = L.splitext(out)[0] + ext
      if (fs.existsSync(p)) fs.rmSync(p)
    }
    if (tmpObj) L.rmtree(objdir)
  }
  return ok ? 0 : 1
}

if (L.isMain(import.meta.url)) process.exitCode = main(process.argv.slice(2))
