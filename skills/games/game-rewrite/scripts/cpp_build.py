#!/usr/bin/env python3
"""Compile and link a C/C++ program with MSVC (cl/link through the decomp skill's msvc.sh under Wine, or
directly on Windows) against the libraries of `build_libs.py build --flavour static`.

  python3 -I cpp_build.py --out OUT.exe [options] SOURCE...
  --subsystem S          console (default) or windows; with windows the entry point stays main()
                         (/ENTRY:mainCRTStartup) unless --winmain is given
  --winmain              the program defines WinMain
  --cflag F / --define D / --include DIR    extra cl flag, /D define, /I folder (repeatable)
  --lib NAME             extra library to link (repeatable), e.g. winmm.lib
  --no-default-libs      do not link the libraries of libraries.json
  --debug                /Od /Z7 + /DEBUG instead of /O2
  --obj-dir DIR          where objects go (default: a temporary folder next to the output, removed afterwards)
  --project DIR / --libraries FILE    as build_libs.py
Default cl flags: /nologo /c /MT /GS /W3 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS /O2 (decomp.json
rewrite.toolchain.cflags replaces them), .c files as C (/TC), others as C++ (/TP /EHsc); one cl run per
language (a Wine process start is slow), so two sources must not share a base name. Include folders:
<build>/static/include, each prebuilt library's "include", this skill's msvc_compat. Linked: every library's
.lib (libraries.json order, prebuilt "static_libs" by base name), then rewrite.toolchain.syslibs (default
kernel32 user32 gdi32 shell32 advapi32 winmm ole32). link writes OUT.lib/OUT.exp when objects carry
dllexport (libraries built with exported APIs): they are deleted. Prints the output path. Python stdlib only.
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rwlib  # noqa: E402

PROG = 'cpp_build'
CFLAGS = ['/nologo', '/c', '/MT', '/GS', '/W3', '/DWIN32', '/D_WINDOWS', '/D_CRT_SECURE_NO_WARNINGS']
SYSLIBS = ['kernel32.lib', 'user32.lib', 'gdi32.lib', 'shell32.lib', 'advapi32.lib', 'winmm.lib', 'ole32.lib']


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [
        ('--out', 'str', rwlib.REQUIRED), ('--subsystem', 'str', 'console'), ('--winmain', 'flag', False),
        ('--cflag', 'list', None), ('--define', 'list', None), ('--include', 'list', None), ('--lib', 'list', None),
        ('--no-default-libs', 'flag', False), ('--debug', 'flag', False), ('--obj-dir', 'str', None),
        ('--project', 'str', '.'), ('--libraries', 'str', None)], [('sources', '+')])
    if a['subsystem'] not in ('console', 'windows'):
        sys.stderr.write('%s: error: --subsystem must be console or windows\n' % PROG)
        return 2
    project = a['project']
    cfg, rw = rwlib.load_config(project)
    ms = rwlib.msvc_setup(project, cfg, rw)
    if ms['mode'] == 'wine' and not (ms['msvc_sh'] and os.path.exists(ms['msvc_sh'])):
        sys.stderr.write('%s: msvc.sh not found (set MSVC_SH or rewrite.toolchain.msvc_sh)\n' % PROG)
        return 1
    paths = rw.get('paths') or {}
    src_root = rwlib.project_path(project, paths.get('src', 'rewrite/third_party/src'))
    build = rwlib.project_path(project, paths.get('build', 'rewrite/third_party/build'))
    static = os.path.join(build, 'static')
    lib_file = a['libraries'] or rwlib.project_path(project, rw.get('libraries') or 'rewrite/libraries.json')
    libs = []
    if os.path.exists(lib_file):
        with open(lib_file, encoding='utf-8') as f:
            libs = json.load(f).get('libraries', [])
    incs = [os.path.abspath(i) for i in a['include']] + [os.path.join(static, 'include')]
    link_libs = []
    for lib in libs:
        d = os.path.join(src_root, lib.get('dir', lib['name']))
        if lib.get('kind') == 'prebuilt':
            if lib.get('include'):
                incs.append(os.path.join(d, lib['include']))
            link_libs += [os.path.basename(p) for p in lib.get('static_libs', [])]
        elif lib.get('kind') != 'headers':
            link_libs.append(lib.get('lib', lib['name'] + '.lib'))
    incs.append(os.path.join(HERE, 'msvc_compat'))
    out = os.path.abspath(a['out'])
    os.makedirs(os.path.dirname(out), exist_ok=True)
    srcs = [os.path.abspath(s) for s in a['sources']]
    stems = [os.path.splitext(os.path.basename(s))[0].lower() for s in srcs]
    dup = sorted({s for s in stems if stems.count(s) > 1})
    if dup:
        sys.stderr.write('%s: sources share a base name (objects would collide): %s\n' % (PROG, ', '.join(dup)))
        return 1
    tmp_obj = a['obj_dir'] is None
    objdir = os.path.abspath(a['obj_dir']) if a['obj_dir'] else tempfile.mkdtemp(prefix='.obj-',
                                                                                 dir=os.path.dirname(out))
    os.makedirs(objdir, exist_ok=True)
    root = rwlib.common_root([out, objdir, static, HERE] + srcs + incs)

    def rel(p):
        return rwlib.relwin(root, p)

    def tool(name, args):
        rc, lines = rwlib.run_tool(rwlib.msvc_cmd(ms, name, args), root, ms['env'])
        if lines:
            sys.stdout.write('\n'.join(lines) + '\n')
        if rc != 0:
            sys.stderr.write('%s: %s failed (exit %d)\n' % (PROG, name, rc))
            return False
        return True

    ok = False
    try:
        opt = ['/Od', '/Z7'] if a['debug'] else ['/O2']
        flags = list(rwlib.get(rw, 'toolchain.cflags') or CFLAGS) + opt
        flags += ['/I' + rel(i) for i in incs] + ['/D' + d for d in a['define']] + a['cflag']
        flags += ['/Fo' + rel(objdir) + '\\']
        c_srcs = [s for s in srcs if s.endswith('.c')]
        cpp_srcs = [s for s in srcs if not s.endswith('.c')]
        good = True
        if c_srcs:
            good = tool('cl', flags + ['/TC'] + [rel(s) for s in c_srcs])
        if good and cpp_srcs:
            good = tool('cl', flags + ['/TP', '/EHsc'] + [rel(s) for s in cpp_srcs])
        if good:
            objs = [os.path.join(objdir, os.path.splitext(os.path.basename(s))[0] + '.obj') for s in srcs]
            libs_args = [] if a['no_default_libs'] else [rel(os.path.join(static, 'lib', l)) for l in link_libs]
            largs = ['/nologo', '/MACHINE:' + ms['machine'].upper(), '/SUBSYSTEM:' + a['subsystem'].upper(),
                     '/DYNAMICBASE', '/NXCOMPAT', '/OUT:' + rel(out)] + (['/DEBUG'] if a['debug'] else
                                                                        ['/OPT:REF', '/OPT:ICF'])
            if a['subsystem'] == 'windows' and not a['winmain']:
                largs.append('/ENTRY:mainCRTStartup')
            syslibs = rwlib.get(rw, 'toolchain.syslibs') or SYSLIBS
            good = tool('link', largs + [rel(o) for o in objs] + libs_args + a['lib'] + list(syslibs))
        if good:
            sys.stdout.write(out + '\n')
            ok = True
    finally:
        for ext in ('.lib', '.exp'):
            p = os.path.splitext(out)[0] + ext
            if os.path.exists(p):
                os.remove(p)
        if tmp_obj:
            shutil.rmtree(objdir, ignore_errors=True)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
