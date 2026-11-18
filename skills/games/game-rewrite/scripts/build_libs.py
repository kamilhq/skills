#!/usr/bin/env python3
"""Fetch, unpack and build the upstream libraries a rewrite links, at the versions pinned in step 1.

  python3 -I build_libs.py list    [--project DIR] [--libraries FILE]
  python3 -I build_libs.py fetch   [--only A,B] [--check]
  python3 -I build_libs.py extract [--only A,B] [--force]
  python3 -I build_libs.py build   [--flavour static|dll|all] [--only A,B] [--keep-obj]
  python3 -I build_libs.py runtime [--defs DIR]

The libraries are listed in a JSON file (--libraries, else decomp.json rewrite.libraries, else
rewrite/libraries.json; format: references/toolchains.md "libraries.json"). Folders come from
rewrite.paths: downloads (default rewrite/third_party/downloads), src (rewrite/third_party/src), build
(rewrite/third_party/build).
  list     one line per library: name, version, commit, kind, archive, whether it is downloaded
  fetch    download every missing archive from its url and check its sha256 (--check: only check what is
           there). A library without a pinned sha256 is downloaded, reported "unpinned" with the digest,
           and fails the command: pin it after checking the source. file:// URLs are copied.
  extract  unpack each archive (.tar.gz/.tgz/.tar/.zip; any other file is copied as "file") into
           <src>/<dir>, dropping a single top folder ("strip": "auto", or a number of path components);
           refuses absolute paths and "..", skips links. Existing folders are kept unless --force.
  build    flavour "static": one /MT .lib per library into <build>/static/{lib,include} (the C++ rewrite);
           flavour "dll": one DLL per library with its own static CRT into <build>/dll/{bin,lib,include}
           (the Rust rewrite binds them with raw-dylib). Prebuilt libraries are copied (static_libs,
           dlls). "c"/"c++" sources compile with cl (through the decomp skill's msvc.sh under Wine, or
           directly on Windows), "c99" sources with clang --target=i686-pc-windows-msvc against the MSVC
           headers (an old cl is C89).
  runtime  the i686-pc-windows-gnu runtime for Rust without MinGW into <build>/rust-gnu/rtlib: crt_shim.c
           (clang) as libmingw32.a, import libraries from the .def files in --defs (default
           <build>/rust-gnu/defs, seeded from this skill's rust_gnu/defs), empty stand-ins for the rest.
Env: MSVC_SH, MSVC_PREFIX/MSVC_VS/MSVC_SDK (as msvc.sh), CLANG (default clang), RUST_LLD (else found
through RUSTC / rustc). Exit 0 when everything asked for worked. Python standard library only.
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rwlib  # noqa: E402
import wintools  # noqa: E402

PROG = 'build_libs'
CL_DEFAULT = ['/nologo', '/c', '/O2', '/MT', '/W0', '/DNDEBUG', '/DWIN32', '/D_WINDOWS', '/D_CRT_SECURE_NO_WARNINGS']
CLANG_DEFAULT = ['-fms-compatibility-version=16.00', '-fms-runtime-lib=static', '-fno-addrsig', '-O2', '-c', '-w',
                 '-DNDEBUG', '-DWIN32', '-D_WINDOWS', '-D_CRT_SECURE_NO_WARNINGS']
DLL_LINK_DEFAULT = ['/nologo', '/DLL', '/OPT:REF', '/OPT:ICF', '/DYNAMICBASE', '/NXCOMPAT']
DLL_SYSLIBS_DEFAULT = ['kernel32.lib', 'user32.lib', 'shell32.lib', 'advapi32.lib']
EMPTY_RT = ['mingwex', 'gcc', 'gcc_eh', 'gcc_s', 'pthread', 'dbghelp', 'bcrypt', 'advapi32', 'user32', 'shell32', 'ole32']


class Fail(Exception):
    pass


def log(msg):
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()


def archive_kind(name):
    n = name.lower()
    if n.endswith(('.tar.gz', '.tgz')):
        return 'tar.gz'
    if n.endswith('.tar'):
        return 'tar'
    if n.endswith('.zip'):
        return 'zip'
    return 'file'


def safe_rel(name):
    """Member path -> list of components, or None when it is absolute or climbs out."""
    name = name.replace('\\', '/')
    if name.startswith('/') or (len(name) > 1 and name[1] == ':'):
        return None
    parts = [p for p in name.split('/') if p not in ('', '.')]
    if any(p == '..' for p in parts):
        return None
    return parts


class Ctx:
    def __init__(self, a):
        self.project = a['project']
        self.cfg, self.rw = rwlib.load_config(self.project)
        lib_file = a['libraries'] or rwlib.project_path(self.project, self.rw.get('libraries')
                                                        or 'rewrite/libraries.json')
        if not os.path.exists(lib_file):
            raise Fail('no libraries file %s (--libraries or decomp.json rewrite.libraries)' % lib_file)
        with open(lib_file, encoding='utf-8') as f:
            self.spec = json.load(f)
        self.libs = self.spec.get('libraries', [])
        names = [l['name'] for l in self.libs]
        if a.get('only'):
            want = [x.strip() for x in a['only'].split(',') if x.strip()]
            for w in want:
                if w not in names:
                    raise Fail('unknown library %s (have: %s)' % (w, ', '.join(names)))
            self.libs = [l for l in self.libs if l['name'] in want]
        p = self.rw.get('paths') or {}
        self.downloads = rwlib.project_path(self.project, p.get('downloads', 'rewrite/third_party/downloads'))
        self.src = rwlib.project_path(self.project, p.get('src', 'rewrite/third_party/src'))
        self.build = rwlib.project_path(self.project, p.get('build', 'rewrite/third_party/build'))
        self.defaults = self.spec.get('defaults', {})

    def libdir(self, lib):
        return os.path.join(self.src, lib.get('dir', lib['name']))

    def expand(self, lib, p):
        for k, v in (('{skill}', HERE), ('{src}', self.src), ('{project}', os.path.abspath(self.project)),
                     ('{build}', self.build)):
            if p.startswith(k):
                return os.path.normpath(v + p[len(k):])
        return p if os.path.isabs(p) else os.path.normpath(os.path.join(self.libdir(lib), p))

    def archive(self, lib):
        name = lib.get('archive') or lib['url'].rstrip('/').split('/')[-1]
        return os.path.join(self.downloads, name)


# ---------------------------------------------------------------------------------------------- list
def cmd_list(c):
    log('%-14s %-10s %-12s %-9s %-44s %s' % ('name', 'version', 'commit', 'kind', 'archive', 'downloaded'))
    for lib in c.libs:
        kind = lib.get('kind', 'source')
        if kind == 'source':
            kind = lib.get('lang', 'c')
        arch = c.archive(lib) if lib.get('url') else None
        log('%-14s %-10s %-12s %-9s %-44s %s' % (lib['name'], lib.get('version', '-'), (lib.get('commit') or '-')[:12],
                                                 kind, os.path.basename(arch) if arch else '-',
                                                 ('yes' if os.path.exists(arch) else 'no') if arch else '-'))
    return 0


# --------------------------------------------------------------------------------------------- fetch
def download(url, dst):
    tmp = dst + '.part'
    if url.startswith('file://'):
        shutil.copyfile(url[len('file://'):], tmp)
    else:
        req = urllib.request.Request(url, headers={'User-Agent': 'build_libs'})
        with urllib.request.urlopen(req, timeout=120) as r, open(tmp, 'wb') as f:
            shutil.copyfileobj(r, f)
    os.replace(tmp, dst)


def cmd_fetch(c, check):
    os.makedirs(c.downloads, exist_ok=True)
    rows, ok = [], True
    for lib in c.libs:
        if not lib.get('url'):
            continue
        path = c.archive(lib)
        row = {'name': lib['name'], 'archive': os.path.basename(path)}
        if not os.path.exists(path):
            if check:
                row['status'] = 'missing'
                ok = False
                rows.append(row)
                continue
            try:
                download(lib['url'], path)
            except Exception as e:     # noqa: BLE001 - any network or file error is reported per library
                row['status'] = 'download failed: %s' % e
                ok = False
                rows.append(row)
                continue
            row['downloaded'] = True
        digest = rwlib.sha256_file(path)
        row['bytes'] = os.path.getsize(path)
        row['sha256'] = digest
        want = lib.get('sha256')
        if not want:
            row['status'] = 'unpinned'
            ok = False
        elif want.lower() == digest:
            row['status'] = 'ok'
        else:
            row['status'] = 'MISMATCH (pinned %s)' % want
            ok = False
        rows.append(row)
    log(rwlib.dumps({'ok': ok, 'libraries': rows}))
    return 0 if ok else 1


# ------------------------------------------------------------------------------------------- extract
def members_of(path, kind):
    """[(path components, bytes or None for a folder)] in archive order; links and odd entries skipped."""
    out, skipped = [], 0
    if kind in ('tar', 'tar.gz'):
        with tarfile.open(path, 'r:gz' if kind == 'tar.gz' else 'r:') as t:
            for m in t.getmembers():
                parts = safe_rel(m.name)
                if parts is None:
                    raise Fail('%s: unsafe member path %s' % (os.path.basename(path), m.name))
                if m.isdir():
                    out.append((parts, None))
                elif m.isfile():
                    out.append((parts, t.extractfile(m).read()))
                else:
                    skipped += 1
    elif kind == 'zip':
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                parts = safe_rel(info.filename)
                if parts is None:
                    raise Fail('%s: unsafe member path %s' % (os.path.basename(path), info.filename))
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    skipped += 1
                elif info.filename.endswith('/'):
                    out.append((parts, None))
                else:
                    out.append((parts, z.read(info)))
    return out, skipped


def strip_count(members, strip):
    if strip != 'auto':
        return int(strip)
    tops = {p[0] for p, _ in members if p}
    deep = all(len(p) > 1 or data is None for p, data in members if p)
    return 1 if len(tops) == 1 and deep and any(data is not None for _, data in members) else 0


def cmd_extract(c, force):
    rows, ok = [], True
    for lib in c.libs:
        if not lib.get('url'):
            continue
        path, dst = c.archive(lib), c.libdir(lib)
        row = {'name': lib['name'], 'dir': os.path.relpath(dst, c.src).replace(os.sep, '/')}
        if not os.path.exists(path):
            row['status'] = 'missing archive'
            ok = False
            rows.append(row)
            continue
        if os.path.isdir(dst) and not force:
            row['status'] = 'present'
            rows.append(row)
            continue
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        os.makedirs(dst)
        kind = archive_kind(path)
        if kind == 'file':
            name = lib.get('file') or os.path.basename(path)
            shutil.copyfile(path, os.path.join(dst, name))
            row.update(status='copied', files=1)
            rows.append(row)
            continue
        members, skipped = members_of(path, kind)
        n = strip_count(members, lib.get('strip', 'auto'))
        files = 0
        for parts, data in members:
            parts = parts[n:]
            if not parts:
                continue
            target = os.path.join(dst, *parts)
            if data is None:
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, 'wb') as f:
                f.write(data)
            files += 1
        row.update(status='extracted', files=files, stripped=n, skipped_links=skipped)
        rows.append(row)
    log(rwlib.dumps({'ok': ok, 'libraries': rows}))
    return 0 if ok else 1


# --------------------------------------------------------------------------------------------- build
class Builder:
    def __init__(self, c, keep_obj):
        self.c = c
        self.keep_obj = keep_obj
        self.ms = rwlib.msvc_setup(c.project, c.cfg, c.rw)
        if self.ms['mode'] == 'wine' and not (self.ms['msvc_sh'] and os.path.exists(self.ms['msvc_sh'])):
            raise Fail('msvc.sh not found (set MSVC_SH or rewrite.toolchain.msvc_sh)')
        self.root = rwlib.common_root([c.src, c.build, HERE])
        self.clang = os.environ.get('CLANG', 'clang')
        self.machine = self.ms['machine']
        self.compat = os.path.join(HERE, 'msvc_compat')

    def rel(self, p):
        return rwlib.relwin(self.root, p)

    def tool(self, name, args):
        rc, lines = rwlib.run_tool(rwlib.msvc_cmd(self.ms, name, args), self.root, self.ms['env'])
        if lines:
            log('\n'.join(lines))
        if rc != 0:
            raise Fail('%s failed (exit %d)' % (name, rc))

    def compile(self, lib, objdir, dll):
        c = self.c
        os.makedirs(objdir, exist_ok=True)
        defines = list(lib.get('defines', [])) + list(lib.get('dll_defines' if dll else 'static_defines', []))
        incs = [c.expand(lib, d) for d in lib.get('incs', [])] + \
            ([c.expand(lib, d) for d in lib.get('dll_incs', [])] if dll else [])
        srcs = [c.expand(lib, s) for s in lib.get('srcs', [])]
        extra = [c.expand(lib, s) for s in lib.get('dll_srcs', [])] if dll else []
        seen = set()
        for s in srcs + extra:
            stem = os.path.splitext(os.path.basename(s))[0].lower()
            if stem in seen:
                raise Fail('%s: two sources named %s (objects would collide)' % (lib['name'], stem))
            seen.add(stem)
        incs += sorted({os.path.dirname(s) for s in srcs + extra})
        objs = [os.path.join(objdir, os.path.splitext(os.path.basename(s))[0] + '.obj') for s in srcs + extra]
        lang = lib.get('lang', 'c')
        if lang == 'c99':
            target = 'x86_64-pc-windows-msvc' if self.machine == 'x64' else 'i686-pc-windows-msvc'
            cmd = [self.clang, '--target=' + target] + list(c.defaults.get('clang', CLANG_DEFAULT))
            for d in rwlib.vs_include_dirs(self.ms, c.project):
                cmd += ['-isystem', d]
            for i in incs:
                cmd += ['-I', i]
            cmd += ['-D' + d for d in defines]
            for s, o in zip(srcs + extra, objs):
                rc, lines = rwlib.run_tool(cmd + ['-o', o, s], self.root)
                if lines:
                    log('\n'.join(lines))
                if rc != 0:
                    raise Fail('clang failed on %s (exit %d)' % (os.path.basename(s), rc))
            return objs
        flags = list(c.defaults.get('cl', CL_DEFAULT)) + ['/I' + self.rel(self.compat)] + \
            ['/I' + self.rel(i) for i in incs] + ['/D' + d for d in defines] + ['/Fo' + self.rel(objdir) + '\\']
        groups = [({'c': '/TC', 'c++': '/TP'}[lang], srcs)] if srcs else []
        for s in extra:
            groups.append(('/TP' if s.endswith(('.cpp', '.cc', '.cxx')) else '/TC', [s]))
        for lf, files in groups:
            self.tool('cl', flags + [lf] + (['/EHsc'] if lf == '/TP' else []) + [self.rel(f) for f in files])
        return objs

    def install_headers(self, lib, incdir, dll):
        items = list(lib.get('headers', {}).items()) + (list(lib.get('dll_headers', {}).items()) if dll else [])
        for pattern, sub in items:
            sub, newname = (sub[0], sub[1]) if isinstance(sub, list) else (sub, None)
            dst = os.path.join(incdir, sub)
            os.makedirs(dst, exist_ok=True)
            for f in sorted(glob.glob(self.c.expand(lib, pattern))):
                shutil.copyfile(f, os.path.join(dst, newname or os.path.basename(f)))

    def generate(self, incdir):
        for name, lines in sorted((self.c.spec.get('generate') or {}).items()):
            with open(os.path.join(incdir, name), 'w', encoding='utf-8', newline='\n') as f:
                f.write('\n'.join(lines) + '\n')

    def copy_prebuilt(self, lib, key, dst):
        os.makedirs(dst, exist_ok=True)
        for p in lib.get(key, []):
            shutil.copyfile(self.c.expand(lib, p), os.path.join(dst, os.path.basename(p)))

    def build_static(self):
        base = os.path.join(self.c.build, 'static')
        libdir, incdir, bindir = (os.path.join(base, x) for x in ('lib', 'include', 'bin'))
        for d in (libdir, incdir):
            os.makedirs(d, exist_ok=True)
        for lib in self.c.libs:
            if lib.get('kind', 'source') == 'prebuilt':
                log('[static] %s (prebuilt)' % lib['name'])
                self.copy_prebuilt(lib, 'static_libs', libdir)
                self.copy_prebuilt(lib, 'dlls', bindir)
                continue
            log('[static] %s' % lib['name'])
            if lib.get('kind') != 'headers':
                objs = self.compile(lib, os.path.join(base, 'obj', lib['name']), dll=False)
                out = os.path.join(libdir, lib.get('lib', lib['name'] + '.lib'))
                self.tool('lib', ['/nologo', '/MACHINE:' + self.machine.upper(), '/OUT:' + self.rel(out)] +
                          [self.rel(o) for o in objs])
            self.install_headers(lib, incdir, dll=False)
        self.generate(incdir)
        if not self.keep_obj:
            shutil.rmtree(os.path.join(base, 'obj'), ignore_errors=True)
        log('[static] -> %s' % os.path.relpath(libdir, self.c.project).replace(os.sep, '/'))

    def dll_exports(self, lib, objs):
        exp = lib.get('exports', 'declspec')
        if exp == 'declspec':
            return []
        out = []
        for o in objs:
            with open(o, 'rb') as f:
                data = f.read()
            for sym, is_func in wintools.coff_defined_externals(data, with_kind=True):
                if sym.startswith(tuple(exp)):
                    name = sym[1:] if self.machine == 'x86' and sym.startswith('_') else sym
                    out.append('/EXPORT:' + name + ('' if is_func else ',DATA'))
        return sorted(set(out))

    def build_dll(self):
        base = os.path.join(self.c.build, 'dll')
        bindir, libdir, incdir = (os.path.join(base, x) for x in ('bin', 'lib', 'include'))
        for d in (bindir, libdir, incdir):
            os.makedirs(d, exist_ok=True)
        syslibs = self.c.defaults.get('dll_syslibs', DLL_SYSLIBS_DEFAULT)
        for lib in self.c.libs:
            kind = lib.get('kind', 'source')
            if kind == 'prebuilt':
                log('[dll] %s (prebuilt)' % lib['name'])
                self.copy_prebuilt(lib, 'dlls', bindir)
                self.copy_prebuilt(lib, 'static_libs', libdir)
                continue
            if kind == 'headers':
                log('[dll] %s (headers)' % lib['name'])
                self.install_headers(lib, incdir, dll=True)
                continue
            dllname = lib.get('dll', lib['name'] + '.dll')
            log('[dll] %s -> %s' % (lib['name'], dllname))
            objdir = os.path.join(base, 'obj', lib['name'])
            objs = self.compile(lib, objdir, dll=True)
            dll = os.path.join(bindir, dllname)
            implib = os.path.join(libdir, os.path.splitext(dllname)[0] + '.lib')
            args = list(self.c.defaults.get('dll_link', DLL_LINK_DEFAULT)) + [
                '/MACHINE:' + self.machine.upper(), '/OUT:' + self.rel(dll), '/IMPLIB:' + self.rel(implib)]
            args += self.dll_exports(lib, objs)
            args += [self.rel(o) for o in objs] + [self.rel(self.c.expand(lib, l)) for l in lib.get('dll_libs', [])]
            self.tool('link', args + list(syslibs))
            exp = os.path.splitext(implib)[0] + '.exp'
            if os.path.exists(exp):
                os.remove(exp)
            self.install_headers(lib, incdir, dll=True)
            log('    exports: %d' % len(wintools.pe_exports(dll)))
        self.generate(incdir)
        if not self.keep_obj:
            shutil.rmtree(os.path.join(base, 'obj'), ignore_errors=True)
        log('[dll] -> %s' % os.path.relpath(bindir, self.c.project).replace(os.sep, '/'))


def rust_lld():
    if os.environ.get('RUST_LLD'):
        return os.environ['RUST_LLD']
    home_rustc = os.path.expanduser('~/.cargo/bin/rustc')
    rustc = os.environ.get('RUSTC') or (home_rustc if os.path.exists(home_rustc) else 'rustc')
    sysroot = subprocess.check_output([rustc, '--print', 'sysroot'], universal_newlines=True).strip()
    host = [l.split(': ')[1] for l in subprocess.check_output([rustc, '-vV'], universal_newlines=True).splitlines()
            if l.startswith('host: ')][0]
    return os.path.join(sysroot, 'lib', 'rustlib', host, 'bin', 'rust-lld')


def cmd_runtime(c, defs):
    rtlib = os.path.join(c.build, 'rust-gnu', 'rtlib')
    defs = defs or os.path.join(c.build, 'rust-gnu', 'defs')
    if not os.path.isdir(defs):
        shutil.copytree(os.path.join(HERE, 'rust_gnu', 'defs'), defs)
    log('[rust-gnu] runtime -> %s' % os.path.relpath(rtlib, c.project).replace(os.sep, '/'))
    lld = rust_lld()
    clang = os.environ.get('CLANG', 'clang')
    if os.path.isdir(rtlib):
        shutil.rmtree(rtlib)
    os.makedirs(rtlib)

    def run(cmd):
        rc, lines = rwlib.run_tool(cmd, rtlib)
        if lines:
            log('\n'.join(lines))
        if rc:
            raise Fail('failed (exit %d): %s' % (rc, ' '.join(cmd)))
    shim = os.path.join(rtlib, 'crt_shim.o')
    run([clang, '--target=i686-w64-windows-gnu', '-c', '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
         '-Wall', '-o', shim, os.path.join(HERE, 'rust_gnu', 'crt_shim.c')])
    run([lld, '-flavor', 'link', '/lib', '/machine:x86', '/out:' + os.path.join(rtlib, 'libmingw32.a'), shim])
    os.remove(shim)
    made = ['mingw32']
    for d in sorted(glob.glob(os.path.join(defs, '*.def'))):
        n = os.path.splitext(os.path.basename(d))[0]
        run([lld, '-flavor', 'link', '/lib', '/machine:x86', '/def:' + d, '/out:' + os.path.join(rtlib, 'lib%s.a' % n)])
        made.append(n)
    for n in EMPTY_RT:
        if n not in made:
            run([lld, '-flavor', 'link', '/lib', '/machine:x86', '/llvmlibempty',
                 '/out:' + os.path.join(rtlib, 'lib%s.a' % n)])
            made.append(n)
    log('    %d libraries: %s' % (len(made), ' '.join('lib%s.a' % n for n in made)))
    return 0


def main(argv):
    if not argv or argv[0] not in ('list', 'fetch', 'extract', 'build', 'runtime'):
        if argv and argv[0] in ('-h', '--help'):
            sys.stdout.write(__doc__.strip() + '\n')
            return 0
        sys.stderr.write('%s: error: command must be one of: list, fetch, extract, build, runtime\n' % PROG)
        return 2
    cmd = argv[0]
    a = rwlib.parse_args(PROG, __doc__, argv[1:], [
        ('--project', 'str', '.'), ('--libraries', 'str', None), ('--only', 'str', None), ('--check', 'flag', False),
        ('--force', 'flag', False), ('--flavour', 'str', 'all'), ('--keep-obj', 'flag', False), ('--defs', 'str', None)])
    try:
        c = Ctx(a)
        if cmd == 'list':
            return cmd_list(c)
        if cmd == 'fetch':
            return cmd_fetch(c, a['check'])
        if cmd == 'extract':
            return cmd_extract(c, a['force'])
        if cmd == 'runtime':
            return cmd_runtime(c, a['defs'])
        if a['flavour'] not in ('static', 'dll', 'all'):
            raise Fail('--flavour must be static, dll or all')
        b = Builder(c, a['keep_obj'])
        if a['flavour'] in ('static', 'all'):
            b.build_static()
        if a['flavour'] in ('dll', 'all'):
            b.build_dll()
        return 0
    except Fail as e:
        sys.stderr.write('%s: %s\n' % (PROG, e))
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
