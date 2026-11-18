"""Shared helpers of the game-rewrite scripts (Python standard library only).

Every script imports this module (the scripts insert their own folder into sys.path, so `python3 -I` works).
The JavaScript port is js/lib/rwlib.mjs; both must behave the same (js/parity/run_all.mjs checks it).

  load_config(project)        -> (decomp.json as a dict or {}, its "rewrite" section or {})
  project_path(project, p)    -> absolute path: p with ~ expanded, relative paths taken from the project folder
  parse_args(prog, doc, argv, options, positionals) -> dict      the small argument parser all scripts use
  dumps(obj)                  -> JSON text as json.dumps(obj, indent=1)
  sha256_file(path), winpath(path), copy_tree(src, dst), clone(src, dst)
  scenario_meta(path)         -> {key: value} of the "#! key=value" lines of a replay file
  trace_frames(path, header, frame_field) -> (header ok, frame lines, last frame)
  window_titles()             -> titles of on-screen windows (macOS: CoreGraphics, Windows: user32), or None
  find_decomp_scripts(project, rw) -> the byte-identical-game-decomp skill's scripts folder
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

SCRIPTS = os.path.dirname(os.path.abspath(__file__))


# ------------------------------------------------------------------------------------------------ config
def load_config(project):
    path = os.path.join(project, 'decomp.json')
    if not os.path.exists(path):
        return {}, {}
    with open(path, encoding='utf-8') as f:
        cfg = json.load(f)
    return cfg, cfg.get('rewrite') or {}


def project_path(project, p):
    if p is None:
        return None
    p = os.path.expanduser(p)
    return os.path.abspath(p if os.path.isabs(p) else os.path.join(project, p))


def get(d, dotted, default=None):
    """get(rw, 'trace.header') -> rw['trace']['header'] or default."""
    for k in dotted.split('.'):
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


def find_decomp_scripts(project, rw):
    """Folder of the byte-identical-game-decomp skill's scripts (msvc.sh, pipeline.py)."""
    cands = [os.environ.get('DECOMP_SCRIPTS'), project_path(project, get(rw, 'toolchain.decomp_scripts')),
             os.path.join(SCRIPTS, '..', '..', 'byte-identical-game-decomp', 'scripts'),
             os.path.join(project, '.claude', 'skills', 'byte-identical-game-decomp', 'scripts')]
    for c in cands:
        if c and os.path.isdir(c):
            return os.path.normpath(c)
    return None


# -------------------------------------------------------------------------------------- C/C++ compiler
def msvc_setup(project, cfg, rw):
    """How cl/link/lib are run: 'wine' through the decomp skill's msvc.sh (macOS/Linux) or 'native' (on
    Windows, from a developer prompt that set PATH/INCLUDE/LIB). rewrite.toolchain overrides the decomp
    config's toolchain (wineprefix -> MSVC_PREFIX, vs -> MSVC_VS, sdk -> MSVC_SDK)."""
    tc = dict(cfg.get('toolchain') or {})
    tc.update(get(rw, 'toolchain') or {})
    mode = tc.get('cl_mode') or ('native' if sys.platform == 'win32' else 'wine')
    env = dict(os.environ)
    if tc.get('wineprefix'):
        env.setdefault('MSVC_PREFIX', os.path.expanduser(tc['wineprefix']))
    if tc.get('vs'):
        env.setdefault('MSVC_VS', tc['vs'])
    if tc.get('sdk'):
        env.setdefault('MSVC_SDK', tc['sdk'])
    msvc_sh = os.environ.get('MSVC_SH') or project_path(project, tc.get('msvc_sh'))
    if not msvc_sh:
        ds = find_decomp_scripts(project, rw)
        msvc_sh = os.path.join(ds, 'msvc.sh') if ds else None
    return {'mode': mode, 'msvc_sh': msvc_sh, 'env': env, 'tc': tc,
            'machine': tc.get('machine', 'x86')}


def msvc_cmd(ms, tool, args):
    if ms['mode'] == 'wine':
        return ['sh', ms['msvc_sh'], tool] + list(args)
    return [tool] + list(args)


NOISE = ('Generating Code...',)


def run_tool(cmd, cwd, env=None):
    """Run a compiler/linker; returns (exit code, output lines without the file-name echo and noise)."""
    r = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True, errors='replace')
    lines = [l for l in r.stdout.splitlines() if l.strip() and l.strip() not in NOISE
             and not l.strip().endswith(('.c', '.cpp', '.cc', '.cxx')) and 'Creating library' not in l]
    return r.returncode, lines


def vs_include_dirs(ms, project):
    """Host paths of the MSVC and SDK include folders (for clang -isystem): rewrite.toolchain.vs_include,
    else derived from MSVC_PREFIX/MSVC_VS/MSVC_SDK (Wine), else the INCLUDE variable (native)."""
    if ms['tc'].get('vs_include'):
        return [project_path(project, p) for p in ms['tc']['vs_include']]
    if ms['mode'] == 'native':
        return [p for p in os.environ.get('INCLUDE', '').split(';') if p]
    env = ms['env']
    prefix = env.get('MSVC_PREFIX', os.path.expanduser('~/.wine-vs2010'))
    vs = env.get('MSVC_VS', r'C:\Program Files (x86)\Microsoft Visual Studio 10.0')
    sdk = env.get('MSVC_SDK', r'C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1')

    def unix(p):
        return os.path.join(prefix, 'drive_c', p[3:].replace('\\', '/'))
    return [unix(vs) + '/VC/include', unix(sdk) + '/Include']


def common_root(paths):
    """Folder the Wine tools run in: the common parent of every path (cl reads a leading '/' as an option,
    so the tools get paths relative to it)."""
    return os.path.commonpath([os.path.abspath(p) for p in paths])


def relwin(root, p):
    return os.path.relpath(os.path.abspath(p), root).replace('/', '\\')


# ------------------------------------------------------------------------------------------- arguments
class ArgError(Exception):
    pass


INT_RE = re.compile(r'^-?[0-9]+$')
FLOAT_RE = re.compile(r'^-?[0-9]+(\.[0-9]+)?$')


def parse_args(prog, doc, argv, options, positionals=()):
    """options: list of (flag, kind, default); kind is 'str', 'int', 'float', 'flag' (True when given) or
    'list' (repeatable). A default of REQUIRED makes the option required. positionals: list of (name, nargs)
    with nargs '1', '?', '*' or '+'. '-h'/'--help' prints doc. Errors print "<prog>: error: <msg>" and exit 2.
    Values are given as '--opt value' or '--opt=value'. Returns {name: value} (dashes -> underscores)."""
    try:
        return _parse(argv, options, positionals, doc)
    except ArgError as e:
        sys.stderr.write('%s: error: %s\n' % (prog, e))
        sys.exit(2)


REQUIRED = object()


def _parse(argv, options, positionals, doc):
    spec = {f: (k, d) for f, k, d in options}
    out = {}
    for f, k, d in options:
        out[f.lstrip('-').replace('-', '_')] = [] if k == 'list' else (False if k == 'flag' else
                                                                      (None if d is REQUIRED else d))
    pos = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ('-h', '--help'):
            sys.stdout.write(doc.strip() + '\n')
            sys.exit(0)
        if a.startswith('--') and len(a) > 2:
            flag, eq, val = a.partition('=')
            if flag not in spec:
                raise ArgError('unknown option %s' % flag)
            kind = spec[flag][0]
            key = flag[2:].replace('-', '_')
            if kind == 'flag':
                if eq:
                    raise ArgError('option %s takes no value' % flag)
                out[key] = True
                i += 1
                continue
            if not eq:
                if i + 1 >= len(argv):
                    raise ArgError('option %s needs a value' % flag)
                val = argv[i + 1]
                i += 1
            i += 1
            if kind == 'int':
                if not INT_RE.match(val):
                    raise ArgError('option %s: not an integer: %s' % (flag, val))
                val = int(val)
            elif kind == 'float':
                if not FLOAT_RE.match(val):
                    raise ArgError('option %s: not a number: %s' % (flag, val))
                val = float(val)
            if kind == 'list':
                out[key].append(val)
            else:
                out[key] = val
            continue
        pos.append(a)
        i += 1
    for f, k, d in options:
        if d is REQUIRED and out[f.lstrip('-').replace('-', '_')] is None:
            raise ArgError('missing %s' % f)
    n = 0
    for name, nargs in positionals:
        if nargs == '1':
            if n >= len(pos):
                raise ArgError('missing argument %s' % name)
            out[name] = pos[n]
            n += 1
        elif nargs == '?':
            out[name] = pos[n] if n < len(pos) else None
            n += 1 if n < len(pos) else 0
        else:
            rest = pos[n:]
            if nargs == '+' and not rest:
                raise ArgError('missing argument %s' % name)
            out[name] = rest
            n = len(pos)
    if n < len(pos):
        raise ArgError('too many arguments: %s' % ' '.join(pos[n:]))
    return out


# -------------------------------------------------------------------------------------------- output
def dumps(obj):
    return json.dumps(obj, indent=1)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


# ------------------------------------------------------------------------------------------- running
def runner_mode(rw, arg=None):
    """'wine' (macOS/Linux: run the exe under Wine) or 'native' (on Windows itself)."""
    return arg or get(rw, 'runner') or ('native' if sys.platform == 'win32' else 'wine')


def run_env(project, rw, mode):
    """Environment for the game process: under Wine WINEPREFIX (env, else rewrite.wineprefix, else ~/.wine)
    and WINEDEBUG=-all; plus rewrite.extra_env."""
    env = dict(os.environ)
    if mode == 'wine':
        env['WINEPREFIX'] = os.environ.get('WINEPREFIX') or project_path(project, get(rw, 'wineprefix', '~/.wine'))
        env.setdefault('WINEDEBUG', '-all')
        env.setdefault('MVK_CONFIG_LOG_LEVEL', '0')
    for k, v in (get(rw, 'extra_env') or {}).items():
        env[k] = v
    return env


def exe_command(mode, exe_name, cwd, args):
    if mode == 'wine':
        return [os.environ.get('WINE', 'wine'), exe_name] + list(args)
    return [os.path.join(cwd, exe_name)] + list(args)


def wineserver_kill(mode, env):
    """Stop every process of the prefix (between tries a crashed start can leave a hung process)."""
    if mode == 'wine':
        subprocess.run([os.environ.get('WINESERVER', 'wineserver'), '-k'], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# --------------------------------------------------------------------------------------------- files
def winpath(p, native=False):
    """A path the Windows program can open: under Wine the host path on drive Z: (Z: is / in a default
    prefix), on Windows the absolute path itself."""
    p = os.path.abspath(p)
    return p if native else 'Z:' + p.replace('/', '\\')


def clone(src, dst):
    """Copy a file; on macOS as an APFS clone (instant, no extra space) when possible."""
    if sys.platform == 'darwin' and subprocess.run(['cp', '-c', src, dst], stderr=subprocess.DEVNULL).returncode == 0:
        return
    shutil.copy2(src, dst)


def copy_tree(src, dst, skip_ext=()):
    """Copy a folder (file clones where possible); the copy is writable even if the source is read-only."""
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        rel = os.path.relpath(dirpath, src)
        os.makedirs(os.path.join(dst, rel), exist_ok=True)
        for f in sorted(filenames):
            if skip_ext and f.endswith(tuple(skip_ext)):
                continue
            p = os.path.join(dst, rel, f)
            clone(os.path.join(dirpath, f), p)
            os.chmod(p, 0o644)


# ------------------------------------------------------------------------------------ replay and trace
META_RE = re.compile(r'\s*#!\s*(\w+)\s*=\s*(\S+)')


def scenario_meta(path):
    meta = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            m = META_RE.match(line)
            if m:
                meta[m.group(1)] = m.group(2)
    return meta


def trace_frames(path, header=None, frame_field='f'):
    """(header ok, number of frame lines, last frame index). header None: any non-empty first line."""
    if not os.path.exists(path):
        return False, 0, -1
    with open(path, encoding='utf-8', errors='replace') as f:
        lines = f.read().split('\n')
    first = lines[0].rstrip('\r') if lines else ''
    ok = bool(first) and (header is None or first == header)
    pre = frame_field + '='
    body = [l for l in lines[1:] if l.startswith(pre)]
    last = -1
    if body:
        tok = body[-1].split(' ', 1)[0][len(pre):].rstrip('\r')
        last = int(tok) if INT_RE.match(tok) else -1
    return ok, len(body), last


# ------------------------------------------------------------------------------------------- windows
def window_titles(owner_prefix='wine'):
    """Titles of on-screen windows. macOS: windows whose owner starts with owner_prefix (CoreGraphics window
    list, no screen-recording permission needed). Windows: every visible top-level window. Else None."""
    if sys.platform == 'darwin':
        return _titles_macos(owner_prefix)
    if sys.platform == 'win32':
        return _titles_windows()
    return None


def _titles_macos(owner_prefix):
    import ctypes
    import ctypes.util
    cf = ctypes.cdll.LoadLibrary(ctypes.util.find_library('CoreFoundation'))
    cg = ctypes.cdll.LoadLibrary(ctypes.util.find_library('CoreGraphics'))
    V = ctypes.c_void_p
    cg.CGWindowListCopyWindowInfo.restype = V
    cg.CGWindowListCopyWindowInfo.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    cf.CFArrayGetCount.restype = ctypes.c_long
    cf.CFArrayGetCount.argtypes = [V]
    cf.CFArrayGetValueAtIndex.restype = V
    cf.CFArrayGetValueAtIndex.argtypes = [V, ctypes.c_long]
    cf.CFDictionaryGetValue.restype = V
    cf.CFDictionaryGetValue.argtypes = [V, V]
    cf.CFStringCreateWithCString.restype = V
    cf.CFStringCreateWithCString.argtypes = [V, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFStringGetCString.argtypes = [V, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
    cf.CFRelease.argtypes = [V]

    def s(x):
        return cf.CFStringCreateWithCString(None, x.encode(), 0x08000100)

    def text(v):
        buf = ctypes.create_string_buffer(1024)
        if v:
            cf.CFStringGetCString(v, buf, 1024, 0x08000100)
        return buf.value.decode('utf-8', 'replace')
    k_owner, k_name = s('kCGWindowOwnerName'), s('kCGWindowName')
    arr = cg.CGWindowListCopyWindowInfo(1 | 16, 0)        # on-screen only, excluding desktop elements
    out = []
    for i in range(cf.CFArrayGetCount(arr)):
        d = cf.CFArrayGetValueAtIndex(arr, i)
        if text(cf.CFDictionaryGetValue(d, k_owner)).lower().startswith(owner_prefix):
            out.append(text(cf.CFDictionaryGetValue(d, k_name)))
    cf.CFRelease(arr)
    cf.CFRelease(k_owner)
    cf.CFRelease(k_name)
    return out


def _titles_windows():
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    out = []
    proto = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def cb(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            n = user32.GetWindowTextLengthW(hwnd)
            if n:
                buf = ctypes.create_unicode_buffer(n + 1)
                user32.GetWindowTextW(hwnd, buf, n + 1)
                out.append(buf.value)
        return True
    user32.EnumWindows(proto(cb), 0)
    return out
